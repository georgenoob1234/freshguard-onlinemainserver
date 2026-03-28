from __future__ import annotations

from dataclasses import dataclass
import sqlite3

from fastapi import Depends, HTTPException, Request

from app.admin_session import AdminPrincipal, get_admin_principal
from app.db import get_db
from app.roles import is_permission_granted


@dataclass(frozen=True)
class AdminActor:
    principal: AdminPrincipal
    is_bootstrap: bool
    user_id: str | None
    store_roles: dict[str, tuple[str, ...]]
    scoped_store_ids: frozenset[str]
    is_global: bool

    @property
    def display_name(self) -> str:
        return self.principal.display_name

    def has_store_scope(self, store_id: str) -> bool:
        if self.is_bootstrap or self.is_global:
            return True
        return store_id in self.scoped_store_ids

    def has_permission(self, permission: str, *, store_id: str | None = None) -> bool:
        if self.is_bootstrap or self.is_global:
            return True

        if store_id is not None:
            if store_id not in self.scoped_store_ids:
                return False
            roles = self.store_roles.get(store_id, ())
            return any(is_permission_granted(role, permission) for role in roles)

        for scoped_store_id in self.scoped_store_ids:
            roles = self.store_roles.get(scoped_store_id, ())
            if any(is_permission_granted(role, permission) for role in roles):
                return True
        return False

    def ensure_permission(self, permission: str, *, store_id: str | None = None) -> None:
        if not self.has_permission(permission, store_id=store_id):
            raise HTTPException(status_code=403, detail="forbidden")

    def scoped_store_ids_for_permission(self, permission: str) -> frozenset[str] | None:
        if self.is_bootstrap or self.is_global:
            return None
        allowed = {
            store_id
            for store_id in self.scoped_store_ids
            if any(is_permission_granted(role, permission) for role in self.store_roles.get(store_id, ()))
        }
        return frozenset(allowed)


def _load_user_ban_state(connection: sqlite3.Connection, *, user_id: str) -> bool:
    row = connection.execute(
        """
        SELECT is_banned
        FROM users
        WHERE user_id = ?
        """,
        (user_id,),
    ).fetchone()
    if row is None:
        raise HTTPException(status_code=401, detail="user_not_found")
    return int(row["is_banned"]) == 1


def _load_store_roles(connection: sqlite3.Connection, *, user_id: str) -> dict[str, tuple[str, ...]]:
    rows = connection.execute(
        """
        SELECT store_id, role
        FROM store_memberships
        WHERE user_id = ? AND revoked_at IS NULL
        ORDER BY created_at ASC, membership_id ASC
        """,
        (user_id,),
    ).fetchall()

    grouped: dict[str, list[str]] = {}
    for row in rows:
        grouped.setdefault(row["store_id"], []).append(row["role"])

    return {store_id: tuple(roles) for store_id, roles in grouped.items()}


def resolve_admin_actor(
    connection: sqlite3.Connection,
    *,
    request: Request,
) -> AdminActor:
    principal = get_admin_principal(request)
    if principal is None:
        raise HTTPException(status_code=303, headers={"Location": "/admin/login"})

    if principal.kind == "bootstrap":
        return AdminActor(
            principal=principal,
            is_bootstrap=True,
            user_id=None,
            store_roles={},
            scoped_store_ids=frozenset(),
            is_global=True,
        )

    if principal.user_id is None:
        raise HTTPException(status_code=401, detail="invalid_admin_principal")

    if _load_user_ban_state(connection, user_id=principal.user_id):
        raise HTTPException(status_code=403, detail="user_banned")

    store_roles = _load_store_roles(connection, user_id=principal.user_id)
    is_root = any(role == "root" for roles in store_roles.values() for role in roles)
    if is_root:
        return AdminActor(
            principal=principal,
            is_bootstrap=False,
            user_id=principal.user_id,
            store_roles=store_roles,
            scoped_store_ids=frozenset(),
            is_global=True,
        )

    scoped_store_ids = {
        store_id
        for store_id, roles in store_roles.items()
        if any(is_permission_granted(role, "admin_ui.access") for role in roles)
    }
    actor = AdminActor(
        principal=principal,
        is_bootstrap=False,
        user_id=principal.user_id,
        store_roles=store_roles,
        scoped_store_ids=frozenset(scoped_store_ids),
        is_global=False,
    )

    if not actor.scoped_store_ids:
        raise HTTPException(status_code=403, detail="admin_ui_access_required")

    return actor


def require_admin_ui_access(
    request: Request,
    connection: sqlite3.Connection = Depends(get_db),
) -> AdminActor:
    return resolve_admin_actor(connection, request=request)
