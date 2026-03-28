from __future__ import annotations

from pathlib import Path
import sqlite3
from urllib.parse import urlencode

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from app import admin_ops
from app.admin_auth import authenticate_admin
from app.admin_authorization import AdminActor, require_admin_ui_access
from app.admin_i18n import make_translate_for, resolve_locale
from app.admin_telegram_auth import (
    consume_browser_login_token,
    create_browser_login_challenge,
    resolve_linked_user_for_mini_app,
    verify_telegram_webapp_init_data,
)
from app.admin_session import (
    clear_admin_session,
    get_admin_session_username,
    require_admin_session,
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


def _nav_permissions(actor: AdminActor) -> dict[str, bool]:
    return {
        "users": actor.has_permission("users.manage"),
        "stores": actor.has_permission("stores.read") or actor.has_permission("stores.manage"),
        "devices": actor.has_permission("devices.list") and actor.has_permission("devices.status.read"),
        "enroll_tokens": actor.has_permission("devices.manage"),
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


@router.get("/login", response_class=HTMLResponse)
def login_page(request: Request) -> HTMLResponse:
    username = get_admin_session_username(request)
    if username is not None:
        return _redirect("/admin")
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
    identity = verify_telegram_webapp_init_data(
        init_data=payload.init_data,
        bot_token=settings.telegram_bot_token,
        max_age_seconds=settings.telegram_webapp_auth_max_age_seconds,
    )
    linked_user = resolve_linked_user_for_mini_app(
        connection,
        provider_user_id=identity.provider_user_id,
    )
    set_admin_oms_user_session(
        request,
        user_id=linked_user.user_id,
        display_name=linked_user.display_name,
        auth_method="telegram_miniapp",
    )
    return AdminTelegramMiniAppLoginResponse(redirect="/admin")


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


@router.post("/logout")
def logout(
    request: Request,
    _: str = Depends(require_admin_session),
) -> RedirectResponse:
    clear_admin_session(request)
    return _redirect("/admin/login")


@router.get("", response_class=HTMLResponse)
def dashboard(
    request: Request,
    actor: AdminActor = Depends(require_admin_ui_access),
    connection: sqlite3.Connection = Depends(get_db),
) -> HTMLResponse:
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
    if not actor.has_permission("users.manage"):
        raise HTTPException(status_code=403, detail="forbidden")
    scoped_store_ids = actor.scoped_store_ids_for_permission("users.manage")
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
    if not actor.has_permission("users.manage"):
        raise HTTPException(status_code=403, detail="forbidden")
    users_scope = actor.scoped_store_ids_for_permission("users.manage")
    roles_scope = actor.scoped_store_ids_for_permission("roles.manage")
    detail = admin_ops.get_user_detail(
        connection,
        user_id=user_id,
        scoped_store_ids=users_scope,
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
            "can_manage_user": actor.has_permission("users.manage"),
            "can_manage_memberships": actor.has_permission("roles.manage"),
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
    if not actor.has_permission("users.manage"):
        return _redirect(f"/admin/users/{user_id}", {"error": t("error_forbidden_action")})

    users_scope = actor.scoped_store_ids_for_permission("users.manage")
    admin_ops.get_user_detail(connection, user_id=user_id, scoped_store_ids=users_scope)
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
    can_view_devices = actor.has_permission("devices.list", store_id=store_id) and actor.has_permission(
        "devices.status.read",
        store_id=store_id,
    )
    if not can_manage_memberships:
        detail["members"] = []
    if not can_view_devices:
        detail["devices"] = []
    locale = resolve_locale(request)
    t = make_translate_for(locale)
    return _render(
        request,
        "admin/store_detail.html",
        {
            "page_title": t("page_title_store_detail", store_id=store_id),
            "admin_username": actor.display_name,
            "detail": detail,
            "can_edit_store": can_edit_store,
            "can_manage_memberships": can_manage_memberships,
            "can_view_devices": can_view_devices,
            "message": request.query_params.get("message", ""),
            "error": request.query_params.get("error", ""),
            "nav_permissions": _nav_permissions(actor),
        },
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
    locale = resolve_locale(request)
    t = make_translate_for(locale)
    return _render(
        request,
        "admin/device_detail.html",
        {
            "page_title": t("page_title_device_detail", device_id=device_id),
            "admin_username": actor.display_name,
            "detail": detail,
            "nav_permissions": _nav_permissions(actor),
        },
    )


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
    locale = resolve_locale(request)
    t = make_translate_for(locale)
    return _render(
        request,
        "admin/enroll_tokens.html",
        {
            "page_title": t("page_title_enroll_tokens"),
            "admin_username": actor.display_name,
            "stores": stores,
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
    created = admin_ops.create_enroll_token(
        connection,
        payload=payload,
        secret_salt=get_settings().secret_salt,
    )
    return _render(
        request,
        "admin/enroll_tokens.html",
        {
            "page_title": t("page_title_enroll_tokens"),
            "admin_username": actor.display_name,
            "stores": stores,
            "created_token": created.model_dump(),
            "message": t("flash_token_minted"),
            "error": "",
            "nav_permissions": _nav_permissions(actor),
        },
    )
