from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from fastapi import HTTPException, Request


ADMIN_SESSION_USERNAME_KEY = "admin_username"
ADMIN_SESSION_PRINCIPAL_KIND_KEY = "admin_principal_kind"
ADMIN_SESSION_BOOTSTRAP_USERNAME_KEY = "admin_bootstrap_username"
ADMIN_SESSION_OMS_USER_ID_KEY = "admin_oms_user_id"
ADMIN_SESSION_DISPLAY_NAME_KEY = "admin_display_name"
ADMIN_SESSION_AUTH_METHOD_KEY = "admin_auth_method"

AdminPrincipalKind = Literal["bootstrap", "oms_user"]


@dataclass(frozen=True)
class AdminPrincipal:
    kind: AdminPrincipalKind
    display_name: str
    bootstrap_username: str | None = None
    user_id: str | None = None
    auth_method: str | None = None


def set_admin_session_username(request: Request, *, username: str) -> None:
    # Keep legacy key for backward compatibility with existing sessions/routes.
    request.session[ADMIN_SESSION_USERNAME_KEY] = username
    request.session[ADMIN_SESSION_PRINCIPAL_KIND_KEY] = "bootstrap"
    request.session[ADMIN_SESSION_BOOTSTRAP_USERNAME_KEY] = username
    request.session[ADMIN_SESSION_DISPLAY_NAME_KEY] = username
    request.session.pop(ADMIN_SESSION_OMS_USER_ID_KEY, None)
    request.session[ADMIN_SESSION_AUTH_METHOD_KEY] = "bootstrap"


def set_admin_bootstrap_session(
    request: Request,
    *,
    username: str,
    auth_method: str = "bootstrap",
) -> None:
    request.session[ADMIN_SESSION_USERNAME_KEY] = username
    request.session[ADMIN_SESSION_PRINCIPAL_KIND_KEY] = "bootstrap"
    request.session[ADMIN_SESSION_BOOTSTRAP_USERNAME_KEY] = username
    request.session[ADMIN_SESSION_DISPLAY_NAME_KEY] = username
    request.session.pop(ADMIN_SESSION_OMS_USER_ID_KEY, None)
    request.session[ADMIN_SESSION_AUTH_METHOD_KEY] = auth_method


def set_admin_oms_user_session(
    request: Request,
    *,
    user_id: str,
    display_name: str | None = None,
    auth_method: str,
) -> None:
    normalized_display_name = display_name.strip() if display_name else ""
    resolved_display_name = normalized_display_name or user_id
    request.session[ADMIN_SESSION_PRINCIPAL_KIND_KEY] = "oms_user"
    request.session[ADMIN_SESSION_OMS_USER_ID_KEY] = user_id
    request.session[ADMIN_SESSION_DISPLAY_NAME_KEY] = resolved_display_name
    request.session[ADMIN_SESSION_AUTH_METHOD_KEY] = auth_method
    request.session.pop(ADMIN_SESSION_BOOTSTRAP_USERNAME_KEY, None)
    # Keep legacy key populated so old template code remains functional.
    request.session[ADMIN_SESSION_USERNAME_KEY] = resolved_display_name


def clear_admin_session(request: Request) -> None:
    request.session.clear()


def _as_non_empty_string(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    normalized = value.strip()
    if not normalized:
        return None
    return normalized


def get_admin_principal(request: Request) -> AdminPrincipal | None:
    kind = _as_non_empty_string(request.session.get(ADMIN_SESSION_PRINCIPAL_KIND_KEY))
    auth_method = _as_non_empty_string(request.session.get(ADMIN_SESSION_AUTH_METHOD_KEY))
    display_name = _as_non_empty_string(request.session.get(ADMIN_SESSION_DISPLAY_NAME_KEY))

    if kind == "bootstrap":
        username = _as_non_empty_string(request.session.get(ADMIN_SESSION_BOOTSTRAP_USERNAME_KEY))
        if username is None:
            username = _as_non_empty_string(request.session.get(ADMIN_SESSION_USERNAME_KEY))
        if username is None:
            return None
        return AdminPrincipal(
            kind="bootstrap",
            bootstrap_username=username,
            display_name=display_name or username,
            auth_method=auth_method,
        )

    if kind == "oms_user":
        user_id = _as_non_empty_string(request.session.get(ADMIN_SESSION_OMS_USER_ID_KEY))
        if user_id is None:
            return None
        return AdminPrincipal(
            kind="oms_user",
            user_id=user_id,
            display_name=display_name or user_id,
            auth_method=auth_method,
        )

    # Backward compatibility: legacy sessions only had admin_username.
    legacy_username = _as_non_empty_string(request.session.get(ADMIN_SESSION_USERNAME_KEY))
    if legacy_username is None:
        return None
    return AdminPrincipal(
        kind="bootstrap",
        bootstrap_username=legacy_username,
        display_name=display_name or legacy_username,
        auth_method=auth_method or "bootstrap",
    )


def get_admin_session_username(request: Request) -> str | None:
    principal = get_admin_principal(request)
    if principal is None:
        return None
    return principal.display_name


def require_admin_session(request: Request) -> str:
    principal = get_admin_principal(request)
    if principal is None:
        raise HTTPException(status_code=303, headers={"Location": "/admin/login"})
    return principal.display_name


def require_admin_session_api(request: Request) -> str:
    principal = get_admin_principal(request)
    if principal is None:
        raise HTTPException(status_code=401, detail="Unauthorized")
    return principal.display_name
