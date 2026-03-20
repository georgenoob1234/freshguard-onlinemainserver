from __future__ import annotations

from fastapi import HTTPException, Request


ADMIN_SESSION_USERNAME_KEY = "admin_username"


def set_admin_session_username(request: Request, *, username: str) -> None:
    request.session[ADMIN_SESSION_USERNAME_KEY] = username


def clear_admin_session(request: Request) -> None:
    request.session.clear()


def get_admin_session_username(request: Request) -> str | None:
    username = request.session.get(ADMIN_SESSION_USERNAME_KEY)
    if not isinstance(username, str):
        return None
    return username


def require_admin_session(request: Request) -> str:
    username = get_admin_session_username(request)
    if username is None:
        raise HTTPException(status_code=303, headers={"Location": "/admin/login"})
    return username


def require_admin_session_api(request: Request) -> str:
    username = get_admin_session_username(request)
    if username is None:
        raise HTTPException(status_code=401, detail="Unauthorized")
    return username
