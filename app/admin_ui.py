from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
import sqlite3
from urllib.parse import urlencode

from fastapi import APIRouter, Depends, Form, HTTPException, Request, Response
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from app import admin_ops
from app.admin_auth import authenticate_admin
from app.admin_authorization import AdminActor, require_admin_ui_access, resolve_admin_actor
from app.admin_i18n import make_translate_for, resolve_locale
from app.admin_telegram_auth import (
    create_webapp_admin_token,
    consume_browser_login_token,
    create_browser_login_challenge,
    revoke_webapp_admin_token,
    resolve_linked_user_for_mini_app,
)
from app.admin_session import (
    clear_admin_session,
    get_admin_webapp_token,
    set_admin_oms_user_session,
    set_admin_session_username,
)
from app.config import get_settings
from app.db import get_db
from app.models import (
    AdminCreateEnrollTokenRequest,
    AdminCreateStoreRequest,
    AdminTelegramChallengeStartResponse,
    AdminTelegramMiniAppLoginRequest,
    AdminTelegramMiniAppLoginResponse,
    AdminUpsertStoreMembershipRequest,
    AdminUpdateStoreRequest,
    AdminUpdateUserBanRequest,
)
from app.staff_invite_policy import ALLOWED_STAFF_INVITE_ROLES
from app.tgbot_internal_client import verify_webapp_init_data_via_tgbot


router = APIRouter(prefix="/admin", tags=["admin-ui"])
templates = Jinja2Templates(directory=str(Path(__file__).resolve().parent.parent / "templates"))


def _render(
    request: Request,
    template_name: str,
    context: dict[str, object],
    status_code: int = 200,
) -> HTMLResponse:
    locale = resolve_locale(request)
    t = make_translate_for(locale)
    merged = {
        "request": request,
        "locale": locale,
        "html_lang": locale,
        "t": t,
        "_": t,
        "webapp_auth_mode": bool(getattr(request.state, "admin_webapp_auth_mode", False)),
        **context,
    }
    return templates.TemplateResponse(request, template_name, merged, status_code=status_code)


def _redirect(path: str, query: dict[str, object] | None = None) -> RedirectResponse:
    if query:
        filtered = {key: str(value) for key, value in query.items() if value is not None and value != ""}
        if filtered:
            path = f"{path}?{urlencode(filtered)}"
    return RedirectResponse(url=path, status_code=303)


def _combine_scopes(*scopes: frozenset[str] | None) -> frozenset[str] | None:
    combined: frozenset[str] | None = None
    for scope in scopes:
        if scope is None:
            continue
        combined = scope if combined is None else frozenset(combined & scope)
    return combined


def _has_any_store_permission(actor: AdminActor, permission: str) -> bool:
    scope = actor.scoped_store_ids_for_permission(permission)
    return scope is None or bool(scope)


def _has_all_permissions_in_any_store(actor: AdminActor, *permissions: str) -> bool:
    scope = _combine_scopes(*(actor.scoped_store_ids_for_permission(permission) for permission in permissions))
    return scope is None or bool(scope)


def _parse_optional_positive_int(raw_value: str) -> int | None:
    trimmed = raw_value.strip()
    if not trimmed:
        return None
    value = int(trimmed)
    if value < 1:
        raise ValueError("value must be >= 1")
    return value


def _parse_optional_datetime_local_to_utc_iso(raw_value: str) -> str | None:
    trimmed = raw_value.strip()
    if not trimmed:
        return None
    parsed = datetime.fromisoformat(trimmed)
    if parsed.tzinfo is None:
        parsed = parsed.astimezone()
    return parsed.astimezone(timezone.utc).isoformat()


def _nav_permissions(actor: AdminActor) -> dict[str, bool]:
    return {
        "users": _has_any_store_permission(actor, "users.manage"),
        "stores": _has_any_store_permission(actor, "stores.read")
        or _has_any_store_permission(actor, "stores.manage"),
        "devices": _has_all_permissions_in_any_store(actor, "devices.list", "devices.status.read"),
        "enroll_tokens": _has_any_store_permission(actor, "devices.manage"),
    }


def _telegram_login_error_message(detail: str, *, t) -> str:
    mapping = {
        "telegram_identity_not_linked": "error_telegram_not_linked",
        "user_banned": "error_telegram_user_banned",
        "admin_ui_access_required": "error_telegram_admin_access_required",
        "login_challenge_expired": "error_telegram_challenge_expired",
        "login_challenge_not_found": "error_telegram_challenge_invalid",
        "login_challenge_already_claimed": "error_telegram_challenge_invalid",
        "login_token_not_found": "error_telegram_token_invalid",
        "login_token_already_used": "error_telegram_token_used",
        "login_token_expired": "error_telegram_token_expired",
        "invalid_telegram_init_data": "error_telegram_init_invalid",
        "stale_telegram_init_data": "error_telegram_init_expired",
    }
    return t(mapping.get(detail, "error_telegram_login_failed"))


def _build_store_detail_context(
    *,
    request: Request,
    actor: AdminActor,
    connection: sqlite3.Connection,
    store_id: str,
    message: str = "",
    error: str = "",
    created_invite: dict[str, object] | None = None,
    invite_form: dict[str, str] | None = None,
) -> dict[str, object]:
    if not actor.has_store_scope(store_id):
        raise HTTPException(status_code=404, detail="Store not found")
    if not (
        actor.has_permission("stores.read", store_id=store_id)
        or actor.has_permission("stores.manage", store_id=store_id)
    ):
        raise HTTPException(status_code=403, detail="forbidden")

    settings = get_settings()
    detail = admin_ops.get_store_detail(
        connection,
        store_id=store_id,
        online_threshold_seconds=settings.online_threshold_seconds,
        scoped_store_ids=None if actor.is_global else actor.scoped_store_ids,
    )
    can_edit_store = actor.has_permission("stores.manage", store_id=store_id)
    can_manage_memberships = actor.has_permission("roles.manage", store_id=store_id)
    can_remove_memberships = actor.has_permission("roles.remove", store_id=store_id)
    can_create_invites = actor.has_permission("invites.create", store_id=store_id)
    can_revoke_invites = actor.has_permission("invites.revoke", store_id=store_id)
    can_manage_invites = can_create_invites or can_revoke_invites
    can_view_memberships = can_manage_memberships or can_remove_memberships
    can_view_devices = actor.has_permission("devices.list", store_id=store_id) and actor.has_permission(
        "devices.status.read",
        store_id=store_id,
    )
    if not can_view_memberships:
        detail["members"] = []
    if not can_view_devices:
        detail["devices"] = []
    invites = (
        admin_ops.list_staff_invites_for_store(
            connection,
            store_id=store_id,
            scoped_store_ids=None if actor.is_global else actor.scoped_store_ids,
        )
        if can_manage_invites
        else []
    )

    locale = resolve_locale(request)
    t = make_translate_for(locale)
    return {
        "page_title": t("page_title_store_detail", store_id=store_id),
        "admin_username": actor.display_name,
        "detail": detail,
        "can_edit_store": can_edit_store,
        "can_manage_memberships": can_manage_memberships,
        "can_remove_memberships": can_remove_memberships,
        "can_manage_invites": can_manage_invites,
        "can_create_invites": can_create_invites,
        "can_revoke_invites": can_revoke_invites,
        "can_view_devices": can_view_devices,
        "invites": invites,
        "created_invite": created_invite,
        "invite_form": invite_form or {
            "role": "operator",
            "expires_at": "",
            "max_uses": "1",
            "note": "",
        },
        "invite_role_options": tuple(sorted(ALLOWED_STAFF_INVITE_ROLES)),
        "is_bootstrap_actor": actor.is_bootstrap,
        "message": message,
        "error": error,
        "nav_permissions": _nav_permissions(actor),
    }


def _render_webapp_bootstrap(request: Request) -> HTMLResponse:
    locale = resolve_locale(request)
    t = make_translate_for(locale)
    return _render(
        request,
        "admin/webapp_bootstrap.html",
        {
            "page_title": t("page_title_login"),
            "login_error_message": t("error_telegram_login_failed"),
            "bootstrap_loading_message": t("telegram_webapp_bootstrap_loading"),
        },
    )


@router.get("/login", response_class=HTMLResponse)
def login_page(
    request: Request,
    connection: sqlite3.Connection = Depends(get_db),
) -> HTMLResponse:
    try:
        resolve_admin_actor(connection, request=request)
        return _redirect("/admin")
    except HTTPException as error:
        if error.status_code not in {303, 401, 403}:
            raise
    locale = resolve_locale(request)
    t = make_translate_for(locale)
    return _render(
        request,
        "admin/login.html",
        {
            "page_title": t("page_title_login"),
            "error": request.query_params.get("error", ""),
        },
    )


@router.post("/login", response_class=HTMLResponse)
def login_submit(
    request: Request,
    username: str = Form(default=""),
    password: str = Form(default=""),
    connection: sqlite3.Connection = Depends(get_db),
) -> HTMLResponse:
    account = authenticate_admin(connection, username=username, password=password)
    if account is None:
        locale = resolve_locale(request)
        t = make_translate_for(locale)
        return _render(
            request,
            "admin/login.html",
            {
                "page_title": t("page_title_login"),
                "error": t("error_invalid_credentials"),
                "username": username.strip(),
            },
            status_code=401,
        )
    set_admin_session_username(request, username=account.username)
    return _redirect("/admin")


@router.post("/auth/telegram/miniapp", response_model=AdminTelegramMiniAppLoginResponse)
def login_via_telegram_miniapp(
    payload: AdminTelegramMiniAppLoginRequest,
    request: Request,
    connection: sqlite3.Connection = Depends(get_db),
) -> AdminTelegramMiniAppLoginResponse:
    settings = get_settings()
    identity = verify_webapp_init_data_via_tgbot(
        init_data=payload.init_data,
        settings=settings,
    )
    linked_user = resolve_linked_user_for_mini_app(
        connection,
        provider_user_id=identity.provider_user_id,
    )
    webapp_token = create_webapp_admin_token(
        connection,
        user_id=linked_user.user_id,
        display_name=linked_user.display_name,
        secret_salt=settings.secret_salt,
        token_ttl_seconds=settings.admin_telegram_webapp_token_ttl_seconds,
    )
    clear_admin_session(request)
    return AdminTelegramMiniAppLoginResponse(
        redirect="/admin",
        webapp_token=webapp_token.token,
    )


@router.post("/auth/telegram/challenge/start", response_model=AdminTelegramChallengeStartResponse)
def start_telegram_browser_challenge(
    connection: sqlite3.Connection = Depends(get_db),
) -> AdminTelegramChallengeStartResponse:
    settings = get_settings()
    bot_username = settings.telegram_bot_username.strip().lstrip("@")
    if not bot_username:
        raise HTTPException(status_code=503, detail="telegram_bot_username_not_configured")

    challenge = create_browser_login_challenge(
        connection,
        challenge_ttl_seconds=settings.admin_telegram_login_challenge_ttl_seconds,
    )
    return AdminTelegramChallengeStartResponse(
        challenge_id=challenge.challenge_id,
        deep_link=f"https://t.me/{bot_username}?start=admin_login_{challenge.nonce}",
        expires_at=challenge.expires_at,
    )


@router.get("/login/telegram/complete")
def complete_telegram_browser_login(
    request: Request,
    token: str = "",
    connection: sqlite3.Connection = Depends(get_db),
) -> RedirectResponse:
    locale = resolve_locale(request)
    t = make_translate_for(locale)
    normalized_token = token.strip()
    if not normalized_token:
        return _redirect("/admin/login", {"error": t("error_telegram_token_invalid")})

    try:
        linked_user = consume_browser_login_token(
            connection,
            token=normalized_token,
            secret_salt=get_settings().secret_salt,
        )
    except HTTPException as error:
        return _redirect(
            "/admin/login",
            {"error": _telegram_login_error_message(str(error.detail), t=t)},
        )

    set_admin_oms_user_session(
        request,
        user_id=linked_user.user_id,
        display_name=linked_user.display_name,
        auth_method="telegram_browser",
    )
    return _redirect("/admin")


@router.get("/telegram-webapp", response_class=HTMLResponse)
def telegram_webapp_bootstrap(
    request: Request,
    connection: sqlite3.Connection = Depends(get_db),
) -> Response:
    try:
        resolve_admin_actor(connection, request=request)
        return _redirect("/admin")
    except HTTPException as error:
        if error.status_code != 303:
            raise
    return _render_webapp_bootstrap(request)


@router.post("/logout")
def logout(
    request: Request,
    connection: sqlite3.Connection = Depends(get_db),
) -> RedirectResponse:
    webapp_token = get_admin_webapp_token(request)
    if webapp_token is not None:
        revoke_webapp_admin_token(
            connection,
            token=webapp_token,
            secret_salt=get_settings().secret_salt,
        )
    clear_admin_session(request)
    return _redirect("/admin/login")


@router.get("", response_class=HTMLResponse)
def dashboard(
    request: Request,
    connection: sqlite3.Connection = Depends(get_db),
) -> HTMLResponse:
    try:
        actor = resolve_admin_actor(connection, request=request)
    except HTTPException as error:
        if error.status_code == 303:
            return _render_webapp_bootstrap(request)
        raise
    settings = get_settings()
    scoped_store_ids = None if actor.is_global else actor.scoped_store_ids
    counts = admin_ops.get_dashboard_counts(connection, scoped_store_ids=scoped_store_ids)
    devices = admin_ops.list_devices(
        connection,
        online_threshold_seconds=settings.online_threshold_seconds,
        store_id=None,
        scoped_store_ids=scoped_store_ids,
    )
    connected_devices = sum(1 for device in devices if device["connected"])
    online_devices = sum(1 for device in devices if device["online"])
    locale = resolve_locale(request)
    t = make_translate_for(locale)
    return _render(
        request,
        "admin/dashboard.html",
        {
            "page_title": t("page_title_dashboard"),
            "admin_username": actor.display_name,
            "counts": counts,
            "connected_devices": connected_devices,
            "online_devices": online_devices,
            "nav_permissions": _nav_permissions(actor),
        },
    )


@router.get("/users", response_class=HTMLResponse)
def users_list(
    request: Request,
    q: str = "",
    banned_only: bool = False,
    page: int = 1,
    actor: AdminActor = Depends(require_admin_ui_access),
    connection: sqlite3.Connection = Depends(get_db),
) -> HTMLResponse:
    scoped_store_ids = actor.scoped_store_ids_for_permission("users.manage")
    if scoped_store_ids is not None and not scoped_store_ids:
        raise HTTPException(status_code=403, detail="forbidden")
    normalized_page = max(1, page)
    result = admin_ops.list_users_directory(
        connection,
        query=q,
        banned_only=banned_only,
        page=normalized_page,
        page_size=25,
        scoped_store_ids=scoped_store_ids,
    )
    locale = resolve_locale(request)
    t = make_translate_for(locale)
    return _render(
        request,
        "admin/users_list.html",
        {
            "page_title": t("page_title_users"),
            "admin_username": actor.display_name,
            "result": result,
            "q": q,
            "banned_only": banned_only,
            "message": request.query_params.get("message", ""),
            "error": request.query_params.get("error", ""),
            "nav_permissions": _nav_permissions(actor),
        },
    )


@router.get("/users/{user_id}", response_class=HTMLResponse)
def user_detail(
    user_id: str,
    request: Request,
    actor: AdminActor = Depends(require_admin_ui_access),
    connection: sqlite3.Connection = Depends(get_db),
) -> HTMLResponse:
    users_scope = actor.scoped_store_ids_for_permission("users.manage")
    if users_scope is not None and not users_scope:
        raise HTTPException(status_code=403, detail="forbidden")
    roles_scope = actor.scoped_store_ids_for_permission("roles.manage")
    remove_scope = actor.scoped_store_ids_for_permission("roles.remove")
    can_manage_memberships = roles_scope is None or bool(roles_scope)
    can_remove_memberships = remove_scope is None or bool(remove_scope)
    detail = admin_ops.get_user_detail(
        connection,
        user_id=user_id,
        scoped_store_ids=users_scope,
    )
    for membership in detail["memberships"]:
        membership["can_remove"] = actor.has_permission(
            "roles.remove",
            store_id=membership["store_id"],
        )
    stores = admin_ops.list_stores_with_counts(
        connection,
        include_inactive=True,
        scoped_store_ids=roles_scope,
    )
    locale = resolve_locale(request)
    t = make_translate_for(locale)
    return _render(
        request,
        "admin/user_detail.html",
        {
            "page_title": t("page_title_user_detail", user_id=user_id),
            "admin_username": actor.display_name,
            "detail": detail,
            "stores": stores,
            "message": request.query_params.get("message", ""),
            "error": request.query_params.get("error", ""),
            "can_manage_memberships": can_manage_memberships,
            "can_remove_memberships": can_remove_memberships,
            "can_ban_user": actor.is_bootstrap,
            "nav_permissions": _nav_permissions(actor),
        },
    )


@router.post("/users/{user_id}/ban")
def update_user_ban(
    user_id: str,
    request: Request,
    is_banned: bool = Form(default=False),
    reason: str = Form(default=""),
    confirm: str = Form(default=""),
    actor: AdminActor = Depends(require_admin_ui_access),
    connection: sqlite3.Connection = Depends(get_db),
) -> RedirectResponse:
    locale = resolve_locale(request)
    t = make_translate_for(locale)
    if not actor.is_bootstrap:
        return _redirect(f"/admin/users/{user_id}", {"error": t("error_forbidden_action")})

    admin_ops.get_user_detail(connection, user_id=user_id, scoped_store_ids=None)
    if confirm != "yes":
        return _redirect(f"/admin/users/{user_id}", {"error": t("flash_confirm_required")})
    payload = AdminUpdateUserBanRequest(is_banned=is_banned, reason=reason)
    admin_ops.update_user_ban_state(connection, user_id=user_id, payload=payload)
    message = t("flash_user_banned") if is_banned else t("flash_user_unbanned")
    return _redirect(f"/admin/users/{user_id}", {"message": message})


@router.post("/users/{user_id}/memberships")
def upsert_user_membership(
    user_id: str,
    request: Request,
    store_id: str = Form(default=""),
    role: str = Form(default=""),
    set_active_store: bool = Form(default=False),
    confirm: str = Form(default=""),
    actor: AdminActor = Depends(require_admin_ui_access),
    connection: sqlite3.Connection = Depends(get_db),
) -> RedirectResponse:
    locale = resolve_locale(request)
    t = make_translate_for(locale)
    if not actor.has_permission("roles.manage", store_id=store_id):
        return _redirect(f"/admin/users/{user_id}", {"error": t("error_forbidden_action")})
    if confirm != "yes":
        return _redirect(f"/admin/users/{user_id}", {"error": t("error_confirm_role_change")})
    try:
        payload = AdminUpsertStoreMembershipRequest(role=role, set_active_store=set_active_store)
        admin_ops.upsert_user_store_membership(
            connection,
            user_id=user_id,
            store_id=store_id,
            payload=payload,
            note="admin_ui",
            actor_user_id=actor.user_id,
            actor_is_bootstrap=actor.is_bootstrap,
        )
        return _redirect(f"/admin/users/{user_id}", {"message": t("flash_membership_updated")})
    except Exception:
        # Surface a generic localized error instead of raw exception text
        return _redirect(f"/admin/users/{user_id}", {"error": t("error_confirm_role_change")})


@router.post("/users/{user_id}/memberships/revoke")
def revoke_user_membership(
    user_id: str,
    request: Request,
    store_id: str = Form(default=""),
    confirm: str = Form(default=""),
    actor: AdminActor = Depends(require_admin_ui_access),
    connection: sqlite3.Connection = Depends(get_db),
) -> RedirectResponse:
    locale = resolve_locale(request)
    t = make_translate_for(locale)
    if not actor.has_permission("roles.remove", store_id=store_id):
        return _redirect(f"/admin/users/{user_id}", {"error": t("error_forbidden_action")})
    if confirm != "yes":
        return _redirect(f"/admin/users/{user_id}", {"error": t("error_confirm_membership_revoke")})
    try:
        admin_ops.revoke_user_store_membership(
            connection,
            user_id=user_id,
            store_id=store_id,
            actor_user_id=actor.user_id,
            actor_is_bootstrap=actor.is_bootstrap,
        )
    except Exception:
        return _redirect(f"/admin/users/{user_id}", {"error": t("error_confirm_membership_revoke")})
    return _redirect(f"/admin/users/{user_id}", {"message": t("flash_membership_revoked")})


@router.get("/stores", response_class=HTMLResponse)
def stores_list(
    request: Request,
    include_inactive: bool = False,
    actor: AdminActor = Depends(require_admin_ui_access),
    connection: sqlite3.Connection = Depends(get_db),
) -> HTMLResponse:
    stores_scope = _combine_scopes(
        actor.scoped_store_ids_for_permission("stores.read"),
        actor.scoped_store_ids_for_permission("stores.manage"),
    )
    if stores_scope is not None and not stores_scope:
        stores_scope = frozenset()
    stores = admin_ops.list_stores_with_counts(
        connection,
        include_inactive=include_inactive,
        scoped_store_ids=stores_scope,
    )
    can_create_store = actor.has_permission("stores.manage")
    locale = resolve_locale(request)
    t = make_translate_for(locale)
    return _render(
        request,
        "admin/stores_list.html",
        {
            "page_title": t("page_title_stores"),
            "admin_username": actor.display_name,
            "stores": stores,
            "include_inactive": include_inactive,
            "can_create_store": can_create_store,
            "message": request.query_params.get("message", ""),
            "error": request.query_params.get("error", ""),
            "nav_permissions": _nav_permissions(actor),
        },
    )


@router.post("/stores")
def create_store_submit(
    request: Request,
    display_name: str = Form(default=""),
    address: str = Form(default=""),
    is_active_on: str | None = Form(default=None),
    actor: AdminActor = Depends(require_admin_ui_access),
    connection: sqlite3.Connection = Depends(get_db),
) -> RedirectResponse:
    if not actor.has_permission("stores.manage"):
        locale = resolve_locale(request)
        t = make_translate_for(locale)
        return _redirect("/admin/stores", {"error": t("error_forbidden_action")})
    is_active = is_active_on == "true"
    payload = AdminCreateStoreRequest(
        display_name=display_name,
        address=address,
        is_active=is_active,
    )
    store = admin_ops.create_store(connection, payload=payload)
    locale = resolve_locale(request)
    t = make_translate_for(locale)
    return _redirect(f"/admin/stores/{store.store_id}", {"message": t("flash_store_created")})


@router.get("/stores/{store_id}", response_class=HTMLResponse)
def store_detail(
    store_id: str,
    request: Request,
    actor: AdminActor = Depends(require_admin_ui_access),
    connection: sqlite3.Connection = Depends(get_db),
) -> HTMLResponse:
    context = _build_store_detail_context(
        request=request,
        actor=actor,
        connection=connection,
        store_id=store_id,
        message=request.query_params.get("message", ""),
        error=request.query_params.get("error", ""),
    )
    return _render(
        request,
        "admin/store_detail.html",
        context,
    )


@router.post("/stores/{store_id}/update")
def update_store_submit(
    store_id: str,
    request: Request,
    display_name: str = Form(default=""),
    address: str = Form(default=""),
    is_active_on: str | None = Form(default=None),
    confirm: str = Form(default=""),
    actor: AdminActor = Depends(require_admin_ui_access),
    connection: sqlite3.Connection = Depends(get_db),
) -> RedirectResponse:
    locale = resolve_locale(request)
    t = make_translate_for(locale)
    if not actor.has_permission("stores.manage", store_id=store_id):
        return _redirect(f"/admin/stores/{store_id}", {"error": t("error_forbidden_action")})
    if confirm != "yes":
        return _redirect(f"/admin/stores/{store_id}", {"error": t("error_confirm_store_update")})
    is_active = is_active_on == "true"
    payload = AdminUpdateStoreRequest(
        display_name=display_name,
        address=address,
        is_active=is_active,
    )
    admin_ops.update_store(connection, store_id=store_id, payload=payload)
    return _redirect(f"/admin/stores/{store_id}", {"message": t("flash_store_updated")})


@router.post("/stores/{store_id}/memberships")
def upsert_store_membership(
    store_id: str,
    request: Request,
    user_id: str = Form(default=""),
    role: str = Form(default=""),
    set_active_store: bool = Form(default=False),
    confirm: str = Form(default=""),
    actor: AdminActor = Depends(require_admin_ui_access),
    connection: sqlite3.Connection = Depends(get_db),
) -> RedirectResponse:
    locale = resolve_locale(request)
    t = make_translate_for(locale)
    if not actor.has_permission("roles.manage", store_id=store_id):
        return _redirect(f"/admin/stores/{store_id}", {"error": t("error_forbidden_action")})
    if confirm != "yes":
        return _redirect(f"/admin/stores/{store_id}", {"error": t("error_confirm_membership_change")})
    payload = AdminUpsertStoreMembershipRequest(role=role, set_active_store=set_active_store)
    admin_ops.upsert_user_store_membership(
        connection,
        user_id=user_id,
        store_id=store_id,
        payload=payload,
        note="admin_ui",
        actor_user_id=actor.user_id,
        actor_is_bootstrap=actor.is_bootstrap,
    )
    return _redirect(f"/admin/stores/{store_id}", {"message": t("flash_membership_updated")})


@router.post("/stores/{store_id}/memberships/revoke")
def revoke_store_membership(
    store_id: str,
    request: Request,
    user_id: str = Form(default=""),
    confirm: str = Form(default=""),
    actor: AdminActor = Depends(require_admin_ui_access),
    connection: sqlite3.Connection = Depends(get_db),
) -> RedirectResponse:
    locale = resolve_locale(request)
    t = make_translate_for(locale)
    if not actor.has_permission("roles.remove", store_id=store_id):
        return _redirect(f"/admin/stores/{store_id}", {"error": t("error_forbidden_action")})
    if confirm != "yes":
        return _redirect(f"/admin/stores/{store_id}", {"error": t("error_confirm_membership_revoke")})
    try:
        admin_ops.revoke_user_store_membership(
            connection,
            user_id=user_id,
            store_id=store_id,
            actor_user_id=actor.user_id,
            actor_is_bootstrap=actor.is_bootstrap,
        )
    except Exception:
        return _redirect(f"/admin/stores/{store_id}", {"error": t("error_confirm_membership_revoke")})
    return _redirect(f"/admin/stores/{store_id}", {"message": t("flash_membership_revoked")})


@router.post("/stores/{store_id}/invites/create", response_class=HTMLResponse)
def create_store_invite(
    store_id: str,
    request: Request,
    role: str = Form(default="operator"),
    note: str = Form(default=""),
    expires_at: str = Form(default=""),
    max_uses: str = Form(default=""),
    confirm: str = Form(default=""),
    actor: AdminActor = Depends(require_admin_ui_access),
    connection: sqlite3.Connection = Depends(get_db),
) -> HTMLResponse:
    locale = resolve_locale(request)
    t = make_translate_for(locale)
    if not actor.has_store_scope(store_id):
        raise HTTPException(status_code=404, detail="Store not found")
    if not actor.has_permission("invites.create", store_id=store_id):
        return _redirect(f"/admin/stores/{store_id}", {"error": t("error_forbidden_action")})

    invite_form = {
        "role": role.strip() or "operator",
        "expires_at": expires_at.strip(),
        "max_uses": max_uses.strip(),
        "note": note,
    }

    if confirm != "yes":
        context = _build_store_detail_context(
            request=request,
            actor=actor,
            connection=connection,
            store_id=store_id,
            error=t("error_confirm_invite_minting"),
            invite_form=invite_form,
        )
        return _render(request, "admin/store_detail.html", context, status_code=400)

    try:
        parsed_expires_at = _parse_optional_datetime_local_to_utc_iso(expires_at)
    except ValueError:
        context = _build_store_detail_context(
            request=request,
            actor=actor,
            connection=connection,
            store_id=store_id,
            error=t("error_invalid_invite_expires_at"),
            invite_form=invite_form,
        )
        return _render(request, "admin/store_detail.html", context, status_code=400)

    try:
        parsed_max_uses = _parse_optional_positive_int(max_uses)
    except ValueError:
        context = _build_store_detail_context(
            request=request,
            actor=actor,
            connection=connection,
            store_id=store_id,
            error=t("error_invalid_invite_max_uses"),
            invite_form=invite_form,
        )
        return _render(request, "admin/store_detail.html", context, status_code=400)

    if not actor.is_bootstrap and parsed_expires_at is None and parsed_max_uses is None:
        context = _build_store_detail_context(
            request=request,
            actor=actor,
            connection=connection,
            store_id=store_id,
            error=t("error_invite_requires_limit"),
            invite_form=invite_form,
        )
        return _render(request, "admin/store_detail.html", context, status_code=400)

    try:
        created_invite = admin_ops.create_staff_invite_for_admin_ui(
            connection,
            store_id=store_id,
            role=role,
            note=note,
            expires_at=parsed_expires_at,
            max_uses=parsed_max_uses,
            created_by_user_id=actor.user_id,
            secret_salt=get_settings().secret_salt,
            scoped_store_ids=None if actor.is_global else actor.scoped_store_ids,
        )
    except HTTPException as error:
        detail = str(error.detail)
        error_key = {
            "unknown_store": "error_unknown_store",
            "store_inactive": "error_store_inactive_for_invite_minting",
            "invalid_invite_role": "error_invalid_invite_role",
            "invalid_note": "error_invalid_invite_note",
            "invalid_max_uses": "error_invalid_invite_max_uses",
            "invalid_expires_at": "error_invalid_invite_expires_at",
        }.get(detail, "error_forbidden_action")
        context = _build_store_detail_context(
            request=request,
            actor=actor,
            connection=connection,
            store_id=store_id,
            error=t(error_key),
            invite_form=invite_form,
        )
        return _render(request, "admin/store_detail.html", context, status_code=error.status_code)

    context = _build_store_detail_context(
        request=request,
        actor=actor,
        connection=connection,
        store_id=store_id,
        message=t("flash_invite_minted"),
        created_invite=created_invite,
    )
    return _render(request, "admin/store_detail.html", context)


@router.post("/stores/{store_id}/invites/{invite_id}/revoke")
def revoke_store_invite(
    store_id: str,
    invite_id: str,
    request: Request,
    confirm: str = Form(default=""),
    actor: AdminActor = Depends(require_admin_ui_access),
    connection: sqlite3.Connection = Depends(get_db),
) -> RedirectResponse:
    locale = resolve_locale(request)
    t = make_translate_for(locale)
    if not actor.has_permission("invites.revoke", store_id=store_id):
        return _redirect(f"/admin/stores/{store_id}", {"error": t("error_forbidden_action")})
    if confirm != "yes":
        return _redirect(f"/admin/stores/{store_id}", {"error": t("error_confirm_invite_revoke")})
    try:
        admin_ops.revoke_staff_invite(
            connection,
            store_id=store_id,
            invite_id=invite_id,
            scoped_store_ids=None if actor.is_global else actor.scoped_store_ids,
        )
    except Exception:
        return _redirect(f"/admin/stores/{store_id}", {"error": t("error_confirm_invite_revoke")})
    return _redirect(f"/admin/stores/{store_id}", {"message": t("flash_invite_revoked")})


@router.get("/devices", response_class=HTMLResponse)
def devices_list(
    request: Request,
    store_id: str = "",
    actor: AdminActor = Depends(require_admin_ui_access),
    connection: sqlite3.Connection = Depends(get_db),
) -> HTMLResponse:
    devices_scope = _combine_scopes(
        actor.scoped_store_ids_for_permission("devices.list"),
        actor.scoped_store_ids_for_permission("devices.status.read"),
    )
    if devices_scope is not None and not devices_scope:
        raise HTTPException(status_code=403, detail="forbidden")
    if store_id and devices_scope is not None and store_id not in devices_scope:
        raise HTTPException(status_code=404, detail="Store not found")
    settings = get_settings()
    devices = admin_ops.list_devices(
        connection,
        online_threshold_seconds=settings.online_threshold_seconds,
        store_id=store_id or None,
        scoped_store_ids=devices_scope,
    )
    stores = admin_ops.list_stores_with_counts(
        connection,
        include_inactive=True,
        scoped_store_ids=devices_scope,
    )
    locale = resolve_locale(request)
    t = make_translate_for(locale)
    return _render(
        request,
        "admin/devices_list.html",
        {
            "page_title": t("page_title_devices"),
            "admin_username": actor.display_name,
            "devices": devices,
            "stores": stores,
            "store_id": store_id,
            "nav_permissions": _nav_permissions(actor),
        },
    )


@router.get("/devices/{device_id}", response_class=HTMLResponse)
def device_detail(
    device_id: str,
    request: Request,
    actor: AdminActor = Depends(require_admin_ui_access),
    connection: sqlite3.Connection = Depends(get_db),
) -> HTMLResponse:
    devices_scope = _combine_scopes(
        actor.scoped_store_ids_for_permission("devices.list"),
        actor.scoped_store_ids_for_permission("devices.status.read"),
    )
    if devices_scope is not None and not devices_scope:
        raise HTTPException(status_code=403, detail="forbidden")
    settings = get_settings()
    detail = admin_ops.get_device_detail(
        connection,
        device_id=device_id,
        online_threshold_seconds=settings.online_threshold_seconds,
        scoped_store_ids=devices_scope,
    )
    can_manage_device = actor.has_permission("devices.manage", store_id=detail["store_id"])
    locale = resolve_locale(request)
    t = make_translate_for(locale)
    return _render(
        request,
        "admin/device_detail.html",
        {
            "page_title": t("page_title_device_detail", device_id=device_id),
            "admin_username": actor.display_name,
            "detail": detail,
            "can_manage_device": can_manage_device,
            "nav_permissions": _nav_permissions(actor),
        },
    )


@router.post("/devices/{device_id}/decommission")
def decommission_device_submit(
    device_id: str,
    request: Request,
    confirm: str = Form(default=""),
    actor: AdminActor = Depends(require_admin_ui_access),
    connection: sqlite3.Connection = Depends(get_db),
) -> RedirectResponse:
    locale = resolve_locale(request)
    t = make_translate_for(locale)
    if confirm != "yes":
        return _redirect(f"/admin/devices/{device_id}", {"error": t("flash_confirm_required")})
    devices_scope = actor.scoped_store_ids_for_permission("devices.manage")
    if devices_scope is not None and not devices_scope:
        return _redirect(f"/admin/devices/{device_id}", {"error": t("error_forbidden_action")})

    try:
        admin_ops.decommission_device(
            connection,
            device_id=device_id,
            scoped_store_ids=devices_scope,
        )
    except Exception:
        return _redirect(f"/admin/devices/{device_id}", {"error": t("error_forbidden_action")})
    return _redirect(f"/admin/devices/{device_id}", {"message": t("flash_device_decommissioned")})


@router.get("/enroll-tokens", response_class=HTMLResponse)
def enroll_tokens_page(
    request: Request,
    actor: AdminActor = Depends(require_admin_ui_access),
    connection: sqlite3.Connection = Depends(get_db),
) -> HTMLResponse:
    scope = actor.scoped_store_ids_for_permission("devices.manage")
    if scope is not None and not scope:
        raise HTTPException(status_code=403, detail="forbidden")
    stores = admin_ops.list_stores_with_counts(
        connection,
        include_inactive=False,
        scoped_store_ids=scope,
    )
    tokens = admin_ops.list_enroll_tokens(connection, scoped_store_ids=scope)
    locale = resolve_locale(request)
    t = make_translate_for(locale)
    return _render(
        request,
        "admin/enroll_tokens.html",
        {
            "page_title": t("page_title_enroll_tokens"),
            "admin_username": actor.display_name,
            "stores": stores,
            "tokens": tokens,
            "created_token": None,
            "message": request.query_params.get("message", ""),
            "error": request.query_params.get("error", ""),
            "nav_permissions": _nav_permissions(actor),
        },
    )


@router.post("/enroll-tokens", response_class=HTMLResponse)
def enroll_tokens_submit(
    request: Request,
    store_id: str = Form(default=""),
    expires_in_sec: int = Form(default=600),
    max_uses: int = Form(default=1),
    note: str = Form(default=""),
    confirm: str = Form(default=""),
    actor: AdminActor = Depends(require_admin_ui_access),
    connection: sqlite3.Connection = Depends(get_db),
) -> HTMLResponse:
    scope = actor.scoped_store_ids_for_permission("devices.manage")
    if scope is not None and not scope:
        locale = resolve_locale(request)
        t = make_translate_for(locale)
        return _render(
            request,
            "admin/enroll_tokens.html",
            {
                "page_title": t("page_title_enroll_tokens"),
                "admin_username": actor.display_name,
                "stores": [],
                "tokens": [],
                "created_token": None,
                "error": t("error_forbidden_action"),
                "message": "",
                "nav_permissions": _nav_permissions(actor),
            },
            status_code=403,
        )
    stores = admin_ops.list_stores_with_counts(
        connection,
        include_inactive=False,
        scoped_store_ids=scope,
    )
    tokens = admin_ops.list_enroll_tokens(connection, scoped_store_ids=scope)
    locale = resolve_locale(request)
    t = make_translate_for(locale)
    if confirm != "yes":
        return _render(
            request,
            "admin/enroll_tokens.html",
            {
                "page_title": t("page_title_enroll_tokens"),
                "admin_username": actor.display_name,
                "stores": stores,
                "tokens": tokens,
                "created_token": None,
                "error": t("flash_confirm_token_minting"),
                "message": "",
                "nav_permissions": _nav_permissions(actor),
            },
            status_code=400,
        )
    payload = AdminCreateEnrollTokenRequest(
        store_id=store_id,
        expires_in_sec=expires_in_sec,
        max_uses=max_uses,
        note=note or None,
    )
    if not actor.has_permission("devices.manage", store_id=payload.store_id):
        return _render(
            request,
            "admin/enroll_tokens.html",
            {
                "page_title": t("page_title_enroll_tokens"),
                "admin_username": actor.display_name,
                "stores": stores,
                "tokens": tokens,
                "created_token": None,
                "error": t("error_forbidden_action"),
                "message": "",
                "nav_permissions": _nav_permissions(actor),
            },
            status_code=403,
        )
    created = admin_ops.create_enroll_token(
        connection,
        payload=payload,
        secret_salt=get_settings().secret_salt,
    )
    tokens = admin_ops.list_enroll_tokens(connection, scoped_store_ids=scope)
    return _render(
        request,
        "admin/enroll_tokens.html",
        {
            "page_title": t("page_title_enroll_tokens"),
            "admin_username": actor.display_name,
            "stores": stores,
            "tokens": tokens,
            "created_token": created.model_dump(),
            "message": t("flash_token_minted"),
            "error": "",
            "nav_permissions": _nav_permissions(actor),
        },
    )


@router.post("/enroll-tokens/{token_id}/revoke")
def revoke_enroll_token(
    token_id: str,
    request: Request,
    confirm: str = Form(default=""),
    actor: AdminActor = Depends(require_admin_ui_access),
    connection: sqlite3.Connection = Depends(get_db),
) -> RedirectResponse:
    locale = resolve_locale(request)
    t = make_translate_for(locale)
    scope = actor.scoped_store_ids_for_permission("devices.manage")
    if scope is not None and not scope:
        return _redirect("/admin/enroll-tokens", {"error": t("error_forbidden_action")})
    if confirm != "yes":
        return _redirect("/admin/enroll-tokens", {"error": t("error_confirm_token_revoke")})
    try:
        admin_ops.revoke_enroll_token(
            connection,
            token_id=token_id,
            scoped_store_ids=scope,
        )
    except Exception:
        return _redirect("/admin/enroll-tokens", {"error": t("error_confirm_token_revoke")})
    return _redirect("/admin/enroll-tokens", {"message": t("flash_token_revoked")})
