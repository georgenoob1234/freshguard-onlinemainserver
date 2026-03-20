from __future__ import annotations

from pathlib import Path
import sqlite3
from urllib.parse import urlencode

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from app import admin_ops
from app.admin_auth import authenticate_admin
from app.admin_i18n import make_translate_for, resolve_locale, translate
from app.admin_session import (
    clear_admin_session,
    get_admin_session_username,
    require_admin_session,
    set_admin_session_username,
)
from app.config import get_settings
from app.db import get_db
from app.models import (
    AdminCreateEnrollTokenRequest,
    AdminCreateStoreRequest,
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


@router.get("/login", response_class=HTMLResponse)
def login_page(request: Request) -> HTMLResponse:
    username = get_admin_session_username(request)
    if username is not None:
        return _redirect("/admin")
    locale = resolve_locale(request)
    t = make_translate_for(locale)
    return _render(request, "admin/login.html", {"page_title": t("page_title_login"), "error": None})


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
    admin_username: str = Depends(require_admin_session),
    connection: sqlite3.Connection = Depends(get_db),
) -> HTMLResponse:
    settings = get_settings()
    counts = admin_ops.get_dashboard_counts(connection)
    devices = admin_ops.list_devices(
        connection,
        online_threshold_seconds=settings.online_threshold_seconds,
        store_id=None,
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
            "admin_username": admin_username,
            "counts": counts,
            "connected_devices": connected_devices,
            "online_devices": online_devices,
        },
    )


@router.get("/users", response_class=HTMLResponse)
def users_list(
    request: Request,
    q: str = "",
    banned_only: bool = False,
    page: int = 1,
    admin_username: str = Depends(require_admin_session),
    connection: sqlite3.Connection = Depends(get_db),
) -> HTMLResponse:
    normalized_page = max(1, page)
    result = admin_ops.list_users_directory(
        connection,
        query=q,
        banned_only=banned_only,
        page=normalized_page,
        page_size=25,
    )
    locale = resolve_locale(request)
    t = make_translate_for(locale)
    return _render(
        request,
        "admin/users_list.html",
        {
            "page_title": t("page_title_users"),
            "admin_username": admin_username,
            "result": result,
            "q": q,
            "banned_only": banned_only,
            "message": request.query_params.get("message", ""),
            "error": request.query_params.get("error", ""),
        },
    )


@router.get("/users/{user_id}", response_class=HTMLResponse)
def user_detail(
    user_id: str,
    request: Request,
    admin_username: str = Depends(require_admin_session),
    connection: sqlite3.Connection = Depends(get_db),
) -> HTMLResponse:
    detail = admin_ops.get_user_detail(connection, user_id=user_id)
    stores = admin_ops.list_stores_with_counts(connection, include_inactive=True)
    locale = resolve_locale(request)
    t = make_translate_for(locale)
    return _render(
        request,
        "admin/user_detail.html",
        {
            "page_title": t("page_title_user_detail", user_id=user_id),
            "admin_username": admin_username,
            "detail": detail,
            "stores": stores,
            "message": request.query_params.get("message", ""),
            "error": request.query_params.get("error", ""),
        },
    )


@router.post("/users/{user_id}/ban")
def update_user_ban(
    user_id: str,
    request: Request,
    is_banned: bool = Form(default=False),
    reason: str = Form(default=""),
    confirm: str = Form(default=""),
    _: str = Depends(require_admin_session),
    connection: sqlite3.Connection = Depends(get_db),
) -> RedirectResponse:
    locale = resolve_locale(request)
    t = make_translate_for(locale)
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
    _: str = Depends(require_admin_session),
    connection: sqlite3.Connection = Depends(get_db),
) -> RedirectResponse:
    locale = resolve_locale(request)
    t = make_translate_for(locale)
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
        )
        return _redirect(f"/admin/users/{user_id}", {"message": t("flash_membership_updated")})
    except Exception:
        # Surface a generic localized error instead of raw exception text
        return _redirect(f"/admin/users/{user_id}", {"error": t("error_confirm_role_change")})


@router.get("/stores", response_class=HTMLResponse)
def stores_list(
    request: Request,
    include_inactive: bool = False,
    admin_username: str = Depends(require_admin_session),
    connection: sqlite3.Connection = Depends(get_db),
) -> HTMLResponse:
    stores = admin_ops.list_stores_with_counts(connection, include_inactive=include_inactive)
    locale = resolve_locale(request)
    t = make_translate_for(locale)
    return _render(
        request,
        "admin/stores_list.html",
        {
            "page_title": t("page_title_stores"),
            "admin_username": admin_username,
            "stores": stores,
            "include_inactive": include_inactive,
            "message": request.query_params.get("message", ""),
            "error": request.query_params.get("error", ""),
        },
    )


@router.post("/stores")
def create_store_submit(
    request: Request,
    display_name: str = Form(default=""),
    address: str = Form(default=""),
    is_active: bool = Form(default=True),
    _: str = Depends(require_admin_session),
    connection: sqlite3.Connection = Depends(get_db),
) -> RedirectResponse:
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
    admin_username: str = Depends(require_admin_session),
    connection: sqlite3.Connection = Depends(get_db),
) -> HTMLResponse:
    settings = get_settings()
    detail = admin_ops.get_store_detail(
        connection,
        store_id=store_id,
        online_threshold_seconds=settings.online_threshold_seconds,
    )
    locale = resolve_locale(request)
    t = make_translate_for(locale)
    return _render(
        request,
        "admin/store_detail.html",
        {
            "page_title": t("page_title_store_detail", store_id=store_id),
            "admin_username": admin_username,
            "detail": detail,
            "message": request.query_params.get("message", ""),
            "error": request.query_params.get("error", ""),
        },
    )


@router.post("/stores/{store_id}/update")
def update_store_submit(
    store_id: str,
    request: Request,
    display_name: str = Form(default=""),
    address: str = Form(default=""),
    is_active: bool = Form(default=True),
    confirm: str = Form(default=""),
    _: str = Depends(require_admin_session),
    connection: sqlite3.Connection = Depends(get_db),
) -> RedirectResponse:
    locale = resolve_locale(request)
    t = make_translate_for(locale)
    if confirm != "yes":
        return _redirect(f"/admin/stores/{store_id}", {"error": t("error_confirm_store_update")})
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
    _: str = Depends(require_admin_session),
    connection: sqlite3.Connection = Depends(get_db),
) -> RedirectResponse:
    locale = resolve_locale(request)
    t = make_translate_for(locale)
    if confirm != "yes":
        return _redirect(f"/admin/stores/{store_id}", {"error": t("error_confirm_membership_change")})
    payload = AdminUpsertStoreMembershipRequest(role=role, set_active_store=set_active_store)
    admin_ops.upsert_user_store_membership(
        connection,
        user_id=user_id,
        store_id=store_id,
        payload=payload,
        note="admin_ui",
    )
    return _redirect(f"/admin/stores/{store_id}", {"message": t("flash_membership_updated")})


@router.get("/devices", response_class=HTMLResponse)
def devices_list(
    request: Request,
    store_id: str = "",
    admin_username: str = Depends(require_admin_session),
    connection: sqlite3.Connection = Depends(get_db),
) -> HTMLResponse:
    settings = get_settings()
    devices = admin_ops.list_devices(
        connection,
        online_threshold_seconds=settings.online_threshold_seconds,
        store_id=store_id or None,
    )
    stores = admin_ops.list_stores_with_counts(connection, include_inactive=True)
    locale = resolve_locale(request)
    t = make_translate_for(locale)
    return _render(
        request,
        "admin/devices_list.html",
        {
            "page_title": t("page_title_devices"),
            "admin_username": admin_username,
            "devices": devices,
            "stores": stores,
            "store_id": store_id,
        },
    )


@router.get("/devices/{device_id}", response_class=HTMLResponse)
def device_detail(
    device_id: str,
    request: Request,
    admin_username: str = Depends(require_admin_session),
    connection: sqlite3.Connection = Depends(get_db),
) -> HTMLResponse:
    settings = get_settings()
    detail = admin_ops.get_device_detail(
        connection,
        device_id=device_id,
        online_threshold_seconds=settings.online_threshold_seconds,
    )
    locale = resolve_locale(request)
    t = make_translate_for(locale)
    return _render(
        request,
        "admin/device_detail.html",
        {
            "page_title": t("page_title_device_detail", device_id=device_id),
            "admin_username": admin_username,
            "detail": detail,
        },
    )


@router.get("/enroll-tokens", response_class=HTMLResponse)
def enroll_tokens_page(
    request: Request,
    admin_username: str = Depends(require_admin_session),
    connection: sqlite3.Connection = Depends(get_db),
) -> HTMLResponse:
    stores = admin_ops.list_stores_with_counts(connection, include_inactive=False)
    locale = resolve_locale(request)
    t = make_translate_for(locale)
    return _render(
        request,
        "admin/enroll_tokens.html",
        {
            "page_title": t("page_title_enroll_tokens"),
            "admin_username": admin_username,
            "stores": stores,
            "created_token": None,
            "message": request.query_params.get("message", ""),
            "error": request.query_params.get("error", ""),
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
    admin_username: str = Depends(require_admin_session),
    connection: sqlite3.Connection = Depends(get_db),
) -> HTMLResponse:
    stores = admin_ops.list_stores_with_counts(connection, include_inactive=False)
    locale = resolve_locale(request)
    t = make_translate_for(locale)
    if confirm != "yes":
        return _render(
            request,
            "admin/enroll_tokens.html",
            {
                "page_title": t("page_title_enroll_tokens"),
                "admin_username": admin_username,
                "stores": stores,
                "created_token": None,
                "error": t("flash_confirm_token_minting"),
                "message": "",
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
            "admin_username": admin_username,
            "stores": stores,
            "created_token": created.model_dump(),
            "message": t("flash_token_minted"),
            "error": "",
        },
    )
