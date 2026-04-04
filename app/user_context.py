from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import sqlite3


@dataclass(frozen=True)
class EffectiveUserContext:
    active_store_id: str | None
    active_store_display_name: str | None
    active_device_id: str | None


def get_user_context_row(
    connection: sqlite3.Connection,
    *,
    user_id: str,
) -> sqlite3.Row | None:
    return connection.execute(
        """
        SELECT active_store_id, active_device_id
        FROM user_context
        WHERE user_id = ?
        """,
        (user_id,),
    ).fetchone()


def upsert_user_context(
    connection: sqlite3.Connection,
    *,
    user_id: str,
    active_store_id: str | None,
    active_device_id: str | None,
    updated_at: str,
) -> None:
    connection.execute(
        """
        INSERT INTO user_context (
            user_id,
            active_store_id,
            active_device_id,
            updated_at
        )
        VALUES (?, ?, ?, ?)
        ON CONFLICT(user_id) DO UPDATE SET
            active_store_id = excluded.active_store_id,
            active_device_id = excluded.active_device_id,
            updated_at = excluded.updated_at
        """,
        (user_id, active_store_id, active_device_id, updated_at),
    )


def select_next_valid_membership_store_id(
    connection: sqlite3.Connection,
    *,
    user_id: str,
) -> str | None:
    row = connection.execute(
        """
        SELECT store_memberships.store_id
        FROM store_memberships
        JOIN stores ON stores.store_id = store_memberships.store_id
        WHERE store_memberships.user_id = ?
          AND store_memberships.revoked_at IS NULL
          AND stores.is_active = 1
        ORDER BY store_memberships.created_at ASC, store_memberships.membership_id ASC
        LIMIT 1
        """,
        (user_id,),
    ).fetchone()
    if row is None:
        return None
    return row["store_id"]


def resolve_effective_user_context(
    connection: sqlite3.Connection,
    *,
    user_id: str,
) -> EffectiveUserContext:
    context_row = get_user_context_row(connection, user_id=user_id)
    raw_store_id = context_row["active_store_id"] if context_row is not None else None
    raw_device_id = context_row["active_device_id"] if context_row is not None else None

    active_store_id: str | None = None
    active_store_display_name: str | None = None
    active_device_id: str | None = None

    if raw_store_id:
        membership_row = connection.execute(
            """
            SELECT
                stores.store_id,
                stores.is_active,
                COALESCE(NULLIF(TRIM(stores.display_name), ''), NULLIF(TRIM(stores.name), ''), stores.store_id) AS display_name
            FROM store_memberships
            JOIN stores ON stores.store_id = store_memberships.store_id
            WHERE store_memberships.user_id = ?
              AND store_memberships.store_id = ?
              AND store_memberships.revoked_at IS NULL
            ORDER BY store_memberships.created_at ASC, store_memberships.membership_id ASC
            LIMIT 1
            """,
            (user_id, raw_store_id),
        ).fetchone()
        if membership_row is not None and int(membership_row["is_active"]) == 1:
            active_store_id = membership_row["store_id"]
            active_store_display_name = membership_row["display_name"]

    if active_store_id and raw_device_id:
        device_row = connection.execute(
            """
            SELECT 1
            FROM devices
            WHERE device_id = ?
              AND store_id = ?
              AND decommissioned_at IS NULL
            """,
            (raw_device_id, active_store_id),
        ).fetchone()
        if device_row is not None:
            active_device_id = raw_device_id

    return EffectiveUserContext(
        active_store_id=active_store_id,
        active_store_display_name=active_store_display_name,
        active_device_id=active_device_id,
    )


def normalize_user_context(
    connection: sqlite3.Connection,
    *,
    user_id: str,
    updated_at: str | None = None,
) -> EffectiveUserContext:
    context_row = get_user_context_row(connection, user_id=user_id)
    raw_store_id = context_row["active_store_id"] if context_row is not None else None
    raw_device_id = context_row["active_device_id"] if context_row is not None else None
    effective = resolve_effective_user_context(connection, user_id=user_id)
    if (
        raw_store_id != effective.active_store_id
        or raw_device_id != effective.active_device_id
    ):
        upsert_user_context(
            connection,
            user_id=user_id,
            active_store_id=effective.active_store_id,
            active_device_id=effective.active_device_id,
            updated_at=updated_at or datetime.now(timezone.utc).isoformat(),
        )
    return effective


def normalize_user_context_after_membership_change(
    connection: sqlite3.Connection,
    *,
    user_id: str,
    revoked_store_id: str | None,
    updated_at: str | None = None,
) -> EffectiveUserContext:
    context_row = get_user_context_row(connection, user_id=user_id)
    raw_store_id = context_row["active_store_id"] if context_row is not None else None

    if revoked_store_id is not None and raw_store_id == revoked_store_id:
        next_store_id = select_next_valid_membership_store_id(connection, user_id=user_id)
        upsert_user_context(
            connection,
            user_id=user_id,
            active_store_id=next_store_id,
            active_device_id=None,
            updated_at=updated_at or datetime.now(timezone.utc).isoformat(),
        )

    return normalize_user_context(
        connection,
        user_id=user_id,
        updated_at=updated_at,
    )
