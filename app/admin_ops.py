from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import sqlite3
from typing import Literal
import uuid

from fastapi import HTTPException

from app.db import rollback_quietly
from app.device_status import compute_online, parse_db_utc_datetime, serialize_utc_datetime
from app.models import (
    AdminCreateEnrollTokenRequest,
    AdminCreateEnrollTokenResponse,
    AdminCreateStoreRequest,
    AdminLookupUserCandidate,
    AdminLookupUserResponse,
    AdminStore,
    AdminStoreDevicesResponse,
    AdminStoreListResponse,
    AdminStoreMembership,
    AdminUpsertStoreMembershipRequest,
    AdminUpsertStoreMembershipResponse,
    AdminUpdateStoreRequest,
    AdminUpdateUserBanRequest,
    AdminUpdateUserBanResponse,
    DeviceStatusResponse,
)
from app.realtime import connection_manager
from app.roles import get_role_priority, is_known_role, is_permission_granted
from app.security import generate_token, hash_token
from app.user_context import (
    get_user_context_row as _get_user_context_row,
    normalize_user_context_after_membership_change,
    upsert_user_context as _upsert_user_context,
)


@dataclass(frozen=True)
class LookupUserResult:
    user: AdminLookupUserResponse | None
    ambiguous_candidates: list[AdminLookupUserCandidate] | None


def _build_device_status_response(
    row: sqlite3.Row,
    *,
    now_utc: datetime,
    threshold_seconds: int,
) -> DeviceStatusResponse:
    last_seen_at = parse_db_utc_datetime(row["last_seen_at"])
    return DeviceStatusResponse(
        device_id=row["device_id"],
        label=row["label"],
        hostname=row["hostname"],
        os=row["os"],
        connector_version=row["connector_version"],
        connected=connection_manager.is_connected(row["device_id"]),
        last_seen_at=serialize_utc_datetime(last_seen_at),
        online=compute_online(
            last_seen_at=last_seen_at,
            now_utc=now_utc,
            threshold_seconds=threshold_seconds,
        ),
    )


def _store_row_to_model(row: sqlite3.Row) -> AdminStore:
    return AdminStore(
        store_id=row["store_id"],
        display_name=row["display_name"],
        address=row["address"],
        is_active=int(row["is_active"]) == 1,
        created_at=row["created_at"],
        updated_at=row["updated_at"],
    )


def _select_store_row(
    connection: sqlite3.Connection,
    *,
    store_id: str,
) -> sqlite3.Row | None:
    return connection.execute(
        """
        SELECT
            store_id,
            COALESCE(NULLIF(TRIM(display_name), ''), NULLIF(TRIM(name), ''), store_id) AS display_name,
            address,
            is_active,
            created_at,
            COALESCE(updated_at, created_at) AS updated_at
        FROM stores
        WHERE store_id = ?
        """,
        (store_id,),
    ).fetchone()


def require_store_row(
    connection: sqlite3.Connection,
    *,
    store_id: str,
) -> sqlite3.Row:
    row = _select_store_row(connection, store_id=store_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Store not found")
    return row


def _generate_store_id() -> str:
    return f"st_{uuid.uuid4().hex}"


def _normalize_lookup_username(username: str | None) -> str | None:
    if username is None:
        return None
    trimmed = username.strip()
    if not trimmed:
        return None
    return trimmed.lstrip("@").lower()


def _parse_iso_datetime(raw_value: str | None) -> datetime | None:
    if raw_value is None:
        return None
    parsed = datetime.fromisoformat(raw_value)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def _derive_lifecycle_status(
    *,
    revoked_at: str | None,
    expires_at: str,
    used_count: int,
    max_uses: int,
    now_utc: datetime,
) -> str:
    if revoked_at is not None:
        return "revoked"
    if used_count >= max_uses:
        return "exhausted"
    expires_at_dt = _parse_iso_datetime(expires_at)
    if expires_at_dt is not None and expires_at_dt <= now_utc:
        return "expired"
    return "active"


def _user_lookup_row_to_response(row: sqlite3.Row) -> AdminLookupUserResponse:
    return AdminLookupUserResponse(
        user_id=row["user_id"],
        provider=row["provider"],
        provider_user_id=row["provider_user_id"],
        provider_chat_id=row["provider_chat_id"],
        username=row["username"],
        display_name=row["display_name"],
        is_banned=int(row["is_banned"]) == 1,
        created_at=row["created_at"],
        last_seen_at=row["last_seen_at"],
    )


def _lookup_by_provider_user_id(
    connection: sqlite3.Connection,
    *,
    provider: str,
    provider_user_id: str,
) -> sqlite3.Row | None:
    return connection.execute(
        """
        SELECT
            users.user_id,
            users.is_banned,
            users.created_at,
            users.last_seen_at,
            user_identities.provider,
            user_identities.provider_user_id,
            user_identities.provider_chat_id,
            user_identities.username,
            user_identities.display_name
        FROM user_identities
        JOIN users ON users.user_id = user_identities.user_id
        WHERE user_identities.provider = ? AND user_identities.provider_user_id = ?
        """,
        (provider, provider_user_id),
    ).fetchone()


def _lookup_candidates_by_username(
    connection: sqlite3.Connection,
    *,
    provider: str,
    normalized_username: str,
) -> list[sqlite3.Row]:
    return connection.execute(
        """
        SELECT
            users.user_id,
            users.is_banned,
            users.created_at,
            users.last_seen_at,
            user_identities.provider,
            user_identities.provider_user_id,
            user_identities.provider_chat_id,
            user_identities.username,
            user_identities.display_name
        FROM user_identities
        JOIN users ON users.user_id = user_identities.user_id
        WHERE user_identities.provider = ?
          AND LOWER(LTRIM(TRIM(COALESCE(user_identities.username, '')), '@')) = ?
        ORDER BY users.last_seen_at DESC, users.created_at DESC
        LIMIT 10
        """,
        (provider, normalized_username),
    ).fetchall()


def _require_user_row(
    connection: sqlite3.Connection,
    *,
    user_id: str,
) -> sqlite3.Row:
    row = connection.execute(
        """
        SELECT user_id, is_banned
        FROM users
        WHERE user_id = ?
        """,
        (user_id,),
    ).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="user_not_found")
    return row


def _require_not_banned(user_row: sqlite3.Row) -> None:
    if int(user_row["is_banned"]) == 1:
        raise HTTPException(status_code=403, detail="user_banned")


def _normalize_membership_role(role_name: str) -> str:
    normalized = role_name.strip().lower()
    if not is_known_role(normalized):
        raise HTTPException(status_code=400, detail="unknown_role")
    return normalized


def _select_active_membership_row(
    connection: sqlite3.Connection,
    *,
    user_id: str,
    store_id: str,
) -> sqlite3.Row | None:
    return connection.execute(
        """
        SELECT
            membership_id,
            user_id,
            store_id,
            role,
            created_at,
            revoked_at,
            created_by_user_id,
            note
        FROM store_memberships
        WHERE user_id = ? AND store_id = ? AND revoked_at IS NULL
        ORDER BY created_at ASC, membership_id ASC
        LIMIT 1
        """,
        (user_id, store_id),
    ).fetchone()


def _select_user_active_roles_for_store(
    connection: sqlite3.Connection,
    *,
    user_id: str,
    store_id: str,
) -> tuple[str, ...]:
    rows = connection.execute(
        """
        SELECT role
        FROM store_memberships
        WHERE user_id = ? AND store_id = ? AND revoked_at IS NULL
        ORDER BY created_at ASC, membership_id ASC
        """,
        (user_id, store_id),
    ).fetchall()
    return tuple(row["role"] for row in rows)


def _assert_membership_update_allowed(
    connection: sqlite3.Connection,
    *,
    actor_user_id: str | None,
    actor_is_bootstrap: bool,
    target_user_id: str,
    store_id: str,
    target_role: str,
    existing_target_role: str | None,
) -> None:
    if actor_is_bootstrap:
        return
    if actor_user_id is None:
        raise HTTPException(status_code=403, detail="forbidden")

    actor_roles = _select_user_active_roles_for_store(
        connection,
        user_id=actor_user_id,
        store_id=store_id,
    )
    if not actor_roles:
        raise HTTPException(status_code=403, detail="forbidden")
    if not any(is_permission_granted(role_name, "roles.manage") for role_name in actor_roles):
        raise HTTPException(status_code=403, detail="forbidden")

    actor_priority = min(get_role_priority(role_name) for role_name in actor_roles)
    new_role_priority = get_role_priority(target_role)
    if new_role_priority <= actor_priority:
        raise HTTPException(status_code=403, detail="forbidden")

    if existing_target_role is not None:
        current_role_priority = get_role_priority(existing_target_role)
        if current_role_priority <= actor_priority:
            raise HTTPException(status_code=403, detail="forbidden")


def _assert_membership_revoke_allowed(
    connection: sqlite3.Connection,
    *,
    actor_user_id: str | None,
    actor_is_bootstrap: bool,
    target_role: str,
    store_id: str,
) -> None:
    if actor_is_bootstrap:
        return
    if actor_user_id is None:
        raise HTTPException(status_code=403, detail="forbidden")

    actor_roles = _select_user_active_roles_for_store(
        connection,
        user_id=actor_user_id,
        store_id=store_id,
    )
    if not actor_roles:
        raise HTTPException(status_code=403, detail="forbidden")
    if not any(is_permission_granted(role_name, "roles.remove") for role_name in actor_roles):
        raise HTTPException(status_code=403, detail="forbidden")

    actor_priority = min(get_role_priority(role_name) for role_name in actor_roles)
    target_priority = get_role_priority(target_role)
    if target_priority <= actor_priority:
        raise HTTPException(status_code=403, detail="forbidden")


def _select_membership_row_by_id(
    connection: sqlite3.Connection,
    *,
    membership_id: str,
) -> sqlite3.Row | None:
    return connection.execute(
        """
        SELECT
            membership_id,
            user_id,
            store_id,
            role,
            created_at,
            revoked_at,
            created_by_user_id,
            note
        FROM store_memberships
        WHERE membership_id = ?
        """,
        (membership_id,),
    ).fetchone()


def _membership_row_to_model(row: sqlite3.Row) -> AdminStoreMembership:
    return AdminStoreMembership(
        membership_id=row["membership_id"],
        user_id=row["user_id"],
        store_id=row["store_id"],
        role=row["role"],
        created_at=row["created_at"],
        revoked_at=row["revoked_at"],
        created_by_user_id=row["created_by_user_id"],
        note=row["note"],
    )


def _normalize_scoped_store_ids(
    scoped_store_ids: frozenset[str] | None,
) -> tuple[str, ...] | None:
    if scoped_store_ids is None:
        return None
    normalized = tuple(sorted(store_id for store_id in scoped_store_ids if store_id))
    return normalized


def create_store(
    connection: sqlite3.Connection,
    *,
    payload: AdminCreateStoreRequest,
) -> AdminStore:
    created_at = datetime.now(timezone.utc).isoformat()
    for _ in range(5):
        store_id = _generate_store_id()
        try:
            connection.execute(
                """
                INSERT INTO stores (
                    store_id,
                    display_name,
                    name,
                    address,
                    is_active,
                    created_at,
                    updated_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    store_id,
                    payload.display_name,
                    payload.display_name,
                    payload.address,
                    1 if payload.is_active else 0,
                    created_at,
                    created_at,
                ),
            )
            connection.commit()
            return _store_row_to_model(require_store_row(connection, store_id=store_id))
        except sqlite3.IntegrityError:
            continue
    raise HTTPException(status_code=500, detail="Failed to generate unique store_id")


def list_stores(
    connection: sqlite3.Connection,
    *,
    include_inactive: bool,
) -> AdminStoreListResponse:
    if include_inactive:
        rows = connection.execute(
            """
            SELECT
                store_id,
                COALESCE(NULLIF(TRIM(display_name), ''), NULLIF(TRIM(name), ''), store_id) AS display_name,
                address,
                is_active,
                created_at,
                COALESCE(updated_at, created_at) AS updated_at
            FROM stores
            ORDER BY created_at ASC
            """
        ).fetchall()
    else:
        rows = connection.execute(
            """
            SELECT
                store_id,
                COALESCE(NULLIF(TRIM(display_name), ''), NULLIF(TRIM(name), ''), store_id) AS display_name,
                address,
                is_active,
                created_at,
                COALESCE(updated_at, created_at) AS updated_at
            FROM stores
            WHERE is_active = 1
            ORDER BY created_at ASC
            """
        ).fetchall()
    return AdminStoreListResponse(items=[_store_row_to_model(row) for row in rows])


def read_store(
    connection: sqlite3.Connection,
    *,
    store_id: str,
) -> AdminStore:
    return _store_row_to_model(require_store_row(connection, store_id=store_id))


def update_store(
    connection: sqlite3.Connection,
    *,
    store_id: str,
    payload: AdminUpdateStoreRequest,
) -> tuple[AdminStore, bool]:
    existing = connection.execute(
        """
        SELECT is_active
        FROM stores
        WHERE store_id = ?
        """,
        (store_id,),
    ).fetchone()
    if existing is None:
        raise HTTPException(status_code=404, detail="Store not found")

    deactivating = payload.is_active is False and int(existing["is_active"]) == 1
    set_clauses: list[str] = []
    params: list[object] = []

    if payload.display_name is not None:
        set_clauses.append("display_name = ?")
        params.append(payload.display_name)
        set_clauses.append("name = ?")
        params.append(payload.display_name)
    if payload.address is not None:
        set_clauses.append("address = ?")
        params.append(payload.address)
    if payload.is_active is not None:
        set_clauses.append("is_active = ?")
        params.append(1 if payload.is_active else 0)

    set_clauses.append("updated_at = ?")
    params.append(datetime.now(timezone.utc).isoformat())
    params.append(store_id)

    connection.execute(
        f"UPDATE stores SET {', '.join(set_clauses)} WHERE store_id = ?",
        tuple(params),
    )
    connection.commit()
    return _store_row_to_model(require_store_row(connection, store_id=store_id)), deactivating


def count_store_devices(
    connection: sqlite3.Connection,
    *,
    store_id: str,
) -> int:
    row = connection.execute(
        """
        SELECT COUNT(*) AS device_count
        FROM devices
        WHERE store_id = ?
        """,
        (store_id,),
    ).fetchone()
    if row is None:
        return 0
    return int(row["device_count"])


def lookup_user(
    connection: sqlite3.Connection,
    *,
    provider: str,
    provider_user_id: str | None,
    username: str | None,
) -> LookupUserResult:
    normalized_provider = provider.strip().lower()
    if normalized_provider != "telegram":
        raise HTTPException(status_code=400, detail="unsupported_provider")

    normalized_provider_user_id = (provider_user_id or "").strip()
    normalized_username = _normalize_lookup_username(username)
    if not normalized_provider_user_id and normalized_username is None:
        raise HTTPException(status_code=400, detail="missing_identifier")

    if normalized_provider_user_id:
        provider_id_match = _lookup_by_provider_user_id(
            connection,
            provider=normalized_provider,
            provider_user_id=normalized_provider_user_id,
        )
        if provider_id_match is not None:
            return LookupUserResult(
                user=_user_lookup_row_to_response(provider_id_match),
                ambiguous_candidates=None,
            )

    if normalized_username is None:
        raise HTTPException(status_code=404, detail="user_not_found")

    username_matches = _lookup_candidates_by_username(
        connection,
        provider=normalized_provider,
        normalized_username=normalized_username,
    )
    if not username_matches:
        raise HTTPException(status_code=404, detail="user_not_found")
    if len(username_matches) > 1:
        return LookupUserResult(
            user=None,
            ambiguous_candidates=[
                AdminLookupUserCandidate(
                    user_id=row["user_id"],
                    provider_user_id=row["provider_user_id"],
                    username=row["username"],
                    display_name=row["display_name"],
                    last_seen_at=row["last_seen_at"],
                )
                for row in username_matches
            ],
        )
    return LookupUserResult(
        user=_user_lookup_row_to_response(username_matches[0]),
        ambiguous_candidates=None,
    )


def update_user_ban_state(
    connection: sqlite3.Connection,
    *,
    user_id: str,
    payload: AdminUpdateUserBanRequest,
) -> AdminUpdateUserBanResponse:
    existing_row = connection.execute(
        """
        SELECT user_id, is_banned, last_seen_at
        FROM users
        WHERE user_id = ?
        """,
        (user_id,),
    ).fetchone()
    if existing_row is None:
        raise HTTPException(status_code=404, detail="user_not_found")

    updated_at = datetime.now(timezone.utc).isoformat()
    connection.execute(
        """
        UPDATE users
        SET is_banned = ?, ban_reason = ?, updated_at = ?
        WHERE user_id = ?
        """,
        (
            1 if payload.is_banned else 0,
            payload.reason if payload.is_banned else None,
            updated_at,
            user_id,
        ),
    )
    connection.commit()

    updated_row = connection.execute(
        """
        SELECT user_id, is_banned, last_seen_at
        FROM users
        WHERE user_id = ?
        """,
        (user_id,),
    ).fetchone()
    if updated_row is None:
        raise HTTPException(status_code=404, detail="user_not_found")

    return AdminUpdateUserBanResponse(
        user_id=updated_row["user_id"],
        is_banned=int(updated_row["is_banned"]) == 1,
        last_seen_at=updated_row["last_seen_at"],
    )


def upsert_user_store_membership(
    connection: sqlite3.Connection,
    *,
    user_id: str,
    store_id: str,
    payload: AdminUpsertStoreMembershipRequest,
    note: str = "admin_api",
    actor_user_id: str | None = None,
    actor_is_bootstrap: bool = True,
) -> AdminUpsertStoreMembershipResponse:
    try:
        connection.execute("BEGIN IMMEDIATE")
        user_row = _require_user_row(connection, user_id=user_id)
        _require_not_banned(user_row)
        require_store_row(connection, store_id=store_id)
        normalized_role = _normalize_membership_role(payload.role)
        now = datetime.now(timezone.utc).isoformat()

        membership_row = _select_active_membership_row(
            connection,
            user_id=user_id,
            store_id=store_id,
        )
        _assert_membership_update_allowed(
            connection,
            actor_user_id=actor_user_id,
            actor_is_bootstrap=actor_is_bootstrap,
            target_user_id=user_id,
            store_id=store_id,
            target_role=normalized_role,
            existing_target_role=membership_row["role"] if membership_row is not None else None,
        )
        status: Literal["created", "updated"]
        if membership_row is None:
            membership_id = str(uuid.uuid4())
            connection.execute(
                """
                INSERT INTO store_memberships (
                    membership_id,
                    store_id,
                    user_id,
                    role,
                    created_at,
                    revoked_at,
                    created_by_user_id,
                    note
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (membership_id, store_id, user_id, normalized_role, now, None, None, note),
            )
            status = "created"
        else:
            connection.execute(
                """
                UPDATE store_memberships
                SET role = ?
                WHERE membership_id = ?
                """,
                (normalized_role, membership_row["membership_id"]),
            )
            status = "updated"

        context_row = _get_user_context_row(connection, user_id=user_id)
        if payload.set_active_store:
            _upsert_user_context(
                connection,
                user_id=user_id,
                active_store_id=store_id,
                active_device_id=None,
                updated_at=now,
            )
        elif context_row is None:
            _upsert_user_context(
                connection,
                user_id=user_id,
                active_store_id=store_id,
                active_device_id=None,
                updated_at=now,
            )

        membership_row = _select_active_membership_row(
            connection,
            user_id=user_id,
            store_id=store_id,
        )
        if membership_row is None:
            raise HTTPException(status_code=500, detail="Internal server error.")

        final_context_row = _get_user_context_row(connection, user_id=user_id)
        connection.commit()
    except HTTPException:
        rollback_quietly(connection)
        raise
    except Exception as error:
        rollback_quietly(connection)
        raise HTTPException(status_code=500, detail="Internal server error.") from error

    return AdminUpsertStoreMembershipResponse(
        status=status,
        membership=_membership_row_to_model(membership_row),
        active_store_id=(
            final_context_row["active_store_id"] if final_context_row is not None else None
        ),
        active_device_id=(
            final_context_row["active_device_id"] if final_context_row is not None else None
        ),
    )


def revoke_user_store_membership(
    connection: sqlite3.Connection,
    *,
    user_id: str,
    store_id: str,
    actor_user_id: str | None = None,
    actor_is_bootstrap: bool = True,
) -> dict[str, object]:
    try:
        connection.execute("BEGIN IMMEDIATE")
        _require_user_row(connection, user_id=user_id)
        require_store_row(connection, store_id=store_id)

        active_membership_row = _select_active_membership_row(
            connection,
            user_id=user_id,
            store_id=store_id,
        )
        if active_membership_row is None:
            raise HTTPException(status_code=404, detail="membership_not_found")

        _assert_membership_revoke_allowed(
            connection,
            actor_user_id=actor_user_id,
            actor_is_bootstrap=actor_is_bootstrap,
            target_role=active_membership_row["role"],
            store_id=store_id,
        )

        revoked_at = datetime.now(timezone.utc).isoformat()
        connection.execute(
            """
            UPDATE store_memberships
            SET revoked_at = ?
            WHERE membership_id = ? AND revoked_at IS NULL
            """,
            (revoked_at, active_membership_row["membership_id"]),
        )

        effective_context = normalize_user_context_after_membership_change(
            connection,
            user_id=user_id,
            revoked_store_id=store_id,
            updated_at=revoked_at,
        )
        membership_row = _select_membership_row_by_id(
            connection,
            membership_id=active_membership_row["membership_id"],
        )
        if membership_row is None:
            raise HTTPException(status_code=500, detail="Internal server error.")

        connection.commit()
    except HTTPException:
        rollback_quietly(connection)
        raise
    except Exception as error:
        rollback_quietly(connection)
        raise HTTPException(status_code=500, detail="Internal server error.") from error

    return {
        "membership": _membership_row_to_model(membership_row),
        "active_store_id": effective_context.active_store_id,
        "active_device_id": effective_context.active_device_id,
    }


def create_enroll_token(
    connection: sqlite3.Connection,
    *,
    payload: AdminCreateEnrollTokenRequest,
    secret_salt: str,
) -> AdminCreateEnrollTokenResponse:
    store_row = connection.execute(
        """
        SELECT is_active
        FROM stores
        WHERE store_id = ?
        """,
        (payload.store_id,),
    ).fetchone()
    if store_row is None:
        raise HTTPException(status_code=400, detail="unknown_store")
    if int(store_row["is_active"]) != 1:
        raise HTTPException(status_code=400, detail="store_inactive")

    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(seconds=payload.expires_in_sec)
    enroll_token = generate_token()
    token_id = str(uuid.uuid4())
    token_hash = hash_token(enroll_token, secret_salt)

    connection.execute(
        """
        INSERT INTO enroll_tokens (
            token_id,
            token_hash,
            store_id,
            created_at,
            expires_at,
            max_uses,
            uses,
            note
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            token_id,
            token_hash,
            payload.store_id,
            now.isoformat(),
            expires_at.isoformat(),
            payload.max_uses,
            0,
            payload.note,
        ),
    )
    connection.commit()

    return AdminCreateEnrollTokenResponse(
        enroll_token=enroll_token,
        token_id=token_id,
        expires_at=expires_at.isoformat(),
        max_uses=payload.max_uses,
    )


def list_enroll_tokens(
    connection: sqlite3.Connection,
    *,
    scoped_store_ids: frozenset[str] | None = None,
) -> list[dict[str, object]]:
    normalized_scope = _normalize_scoped_store_ids(scoped_store_ids)
    if normalized_scope is not None and not normalized_scope:
        return []

    query = f"""
        SELECT
            enroll_tokens.token_id,
            enroll_tokens.store_id,
            enroll_tokens.created_at,
            enroll_tokens.expires_at,
            enroll_tokens.max_uses,
            enroll_tokens.uses,
            enroll_tokens.note,
            enroll_tokens.revoked_at,
            COALESCE(NULLIF(TRIM(stores.display_name), ''), NULLIF(TRIM(stores.name), ''), stores.store_id) AS store_display_name
        FROM enroll_tokens
        LEFT JOIN stores ON stores.store_id = enroll_tokens.store_id
    """
    params: list[object] = []
    if normalized_scope is not None:
        placeholders = ", ".join(["?"] * len(normalized_scope))
        query += f" WHERE enroll_tokens.store_id IN ({placeholders})"
        params.extend(normalized_scope)
    query += " ORDER BY enroll_tokens.created_at DESC, enroll_tokens.token_id DESC"

    now_utc = datetime.now(timezone.utc)
    rows = connection.execute(query, tuple(params)).fetchall()
    return [
        {
            "token_id": row["token_id"],
            "store_id": row["store_id"],
            "store_display_name": row["store_display_name"] or row["store_id"] or "",
            "created_at": row["created_at"],
            "expires_at": row["expires_at"],
            "max_uses": int(row["max_uses"]),
            "uses": int(row["uses"]),
            "note": row["note"],
            "revoked_at": row["revoked_at"],
            "status": _derive_lifecycle_status(
                revoked_at=row["revoked_at"],
                expires_at=row["expires_at"],
                used_count=int(row["uses"]),
                max_uses=int(row["max_uses"]),
                now_utc=now_utc,
            ),
        }
        for row in rows
    ]


def revoke_enroll_token(
    connection: sqlite3.Connection,
    *,
    token_id: str,
    scoped_store_ids: frozenset[str] | None = None,
) -> dict[str, object]:
    normalized_scope = _normalize_scoped_store_ids(scoped_store_ids)
    row = connection.execute(
        """
        SELECT token_id, store_id, revoked_at
        FROM enroll_tokens
        WHERE token_id = ?
        """,
        (token_id,),
    ).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="token_not_found")
    if normalized_scope is not None:
        store_id = row["store_id"]
        if store_id is None or store_id not in normalized_scope:
            raise HTTPException(status_code=404, detail="token_not_found")

    revoked_at = row["revoked_at"]
    if revoked_at is None:
        revoked_at = datetime.now(timezone.utc).isoformat()
        connection.execute(
            """
            UPDATE enroll_tokens
            SET revoked_at = ?
            WHERE token_id = ? AND revoked_at IS NULL
            """,
            (revoked_at, token_id),
        )
        connection.commit()

    return {
        "token_id": row["token_id"],
        "store_id": row["store_id"],
        "revoked_at": revoked_at,
    }


def list_staff_invites_for_store(
    connection: sqlite3.Connection,
    *,
    store_id: str,
    scoped_store_ids: frozenset[str] | None = None,
) -> list[dict[str, object]]:
    normalized_scope = _normalize_scoped_store_ids(scoped_store_ids)
    if normalized_scope is not None and store_id not in normalized_scope:
        return []

    now_utc = datetime.now(timezone.utc)
    rows = connection.execute(
        """
        SELECT
            invite_id,
            store_id,
            role,
            created_by_user_id,
            created_at,
            expires_at,
            max_uses,
            used_count,
            revoked_at,
            note
        FROM staff_invites
        WHERE store_id = ?
        ORDER BY created_at DESC, invite_id DESC
        """,
        (store_id,),
    ).fetchall()
    return [
        {
            "invite_id": row["invite_id"],
            "store_id": row["store_id"],
            "role": row["role"],
            "created_by_user_id": row["created_by_user_id"],
            "created_at": row["created_at"],
            "expires_at": row["expires_at"],
            "max_uses": int(row["max_uses"]),
            "used_count": int(row["used_count"]),
            "revoked_at": row["revoked_at"],
            "note": row["note"],
            "status": _derive_lifecycle_status(
                revoked_at=row["revoked_at"],
                expires_at=row["expires_at"],
                used_count=int(row["used_count"]),
                max_uses=int(row["max_uses"]),
                now_utc=now_utc,
            ),
        }
        for row in rows
    ]


def revoke_staff_invite(
    connection: sqlite3.Connection,
    *,
    store_id: str,
    invite_id: str,
    scoped_store_ids: frozenset[str] | None = None,
) -> dict[str, object]:
    normalized_scope = _normalize_scoped_store_ids(scoped_store_ids)
    if normalized_scope is not None and store_id not in normalized_scope:
        raise HTTPException(status_code=404, detail="invite_not_found")

    row = connection.execute(
        """
        SELECT invite_id, store_id, revoked_at
        FROM staff_invites
        WHERE store_id = ? AND invite_id = ?
        """,
        (store_id, invite_id),
    ).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="invite_not_found")

    revoked_at = row["revoked_at"]
    if revoked_at is None:
        revoked_at = datetime.now(timezone.utc).isoformat()
        connection.execute(
            """
            UPDATE staff_invites
            SET revoked_at = ?
            WHERE store_id = ? AND invite_id = ? AND revoked_at IS NULL
            """,
            (revoked_at, store_id, invite_id),
        )
        connection.commit()

    return {
        "invite_id": row["invite_id"],
        "store_id": row["store_id"],
        "revoked_at": revoked_at,
    }


def list_store_devices(
    connection: sqlite3.Connection,
    *,
    store_id: str,
    online_threshold_seconds: int,
) -> AdminStoreDevicesResponse:
    rows = connection.execute(
        """
        SELECT
            device_id,
            label,
            hostname,
            os,
            connector_version,
            last_seen_at
        FROM devices
        WHERE store_id = ?
        ORDER BY created_at ASC
        """,
        (store_id,),
    ).fetchall()

    now_utc = datetime.now(timezone.utc)
    devices = [
        _build_device_status_response(
            row,
            now_utc=now_utc,
            threshold_seconds=online_threshold_seconds,
        )
        for row in rows
    ]
    return AdminStoreDevicesResponse(
        store_id=store_id,
        online_threshold_seconds=online_threshold_seconds,
        devices=devices,
    )


def get_device_status(
    connection: sqlite3.Connection,
    *,
    device_id: str,
    online_threshold_seconds: int,
) -> DeviceStatusResponse:
    row = connection.execute(
        """
        SELECT
            device_id,
            label,
            hostname,
            os,
            connector_version,
            last_seen_at
        FROM devices
        WHERE device_id = ?
        """,
        (device_id,),
    ).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="Device not found")
    return _build_device_status_response(
        row,
        now_utc=datetime.now(timezone.utc),
        threshold_seconds=online_threshold_seconds,
    )


def get_blob_metadata(connection: sqlite3.Connection, *, blob_id: str) -> sqlite3.Row:
    blob_row = connection.execute(
        """
        SELECT path, content_type
        FROM blobs
        WHERE blob_id = ?
        """,
        (blob_id,),
    ).fetchone()
    if blob_row is None:
        raise HTTPException(status_code=404, detail="Blob not found")
    return blob_row


def get_dashboard_counts(
    connection: sqlite3.Connection,
    *,
    scoped_store_ids: frozenset[str] | None = None,
) -> dict[str, int]:
    normalized_scope = _normalize_scoped_store_ids(scoped_store_ids)
    if normalized_scope is not None and not normalized_scope:
        return {
            "total_stores": 0,
            "total_users": 0,
            "banned_users": 0,
            "total_memberships": 0,
            "total_devices": 0,
        }

    if normalized_scope is None:
        row = connection.execute(
            """
            SELECT
                (SELECT COUNT(*) FROM stores) AS total_stores,
                (SELECT COUNT(*) FROM users) AS total_users,
                (SELECT COUNT(*) FROM users WHERE is_banned = 1) AS banned_users,
                (SELECT COUNT(*) FROM store_memberships WHERE revoked_at IS NULL) AS total_memberships,
                (SELECT COUNT(*) FROM devices) AS total_devices
            """
        ).fetchone()
    else:
        placeholders = ", ".join(["?"] * len(normalized_scope))
        row = connection.execute(
            f"""
            SELECT
                (
                    SELECT COUNT(*)
                    FROM stores
                    WHERE store_id IN ({placeholders})
                ) AS total_stores,
                (
                    SELECT COUNT(DISTINCT store_memberships.user_id)
                    FROM store_memberships
                    WHERE store_memberships.revoked_at IS NULL
                      AND store_memberships.store_id IN ({placeholders})
                ) AS total_users,
                (
                    SELECT COUNT(DISTINCT users.user_id)
                    FROM users
                    JOIN store_memberships ON store_memberships.user_id = users.user_id
                    WHERE users.is_banned = 1
                      AND store_memberships.revoked_at IS NULL
                      AND store_memberships.store_id IN ({placeholders})
                ) AS banned_users,
                (
                    SELECT COUNT(*)
                    FROM store_memberships
                    WHERE revoked_at IS NULL
                      AND store_id IN ({placeholders})
                ) AS total_memberships,
                (
                    SELECT COUNT(*)
                    FROM devices
                    WHERE store_id IN ({placeholders})
                ) AS total_devices
            """,
            (
                *normalized_scope,
                *normalized_scope,
                *normalized_scope,
                *normalized_scope,
                *normalized_scope,
            ),
        ).fetchone()
    if row is None:
        return {
            "total_stores": 0,
            "total_users": 0,
            "banned_users": 0,
            "total_memberships": 0,
            "total_devices": 0,
        }
    return {
        "total_stores": int(row["total_stores"]),
        "total_users": int(row["total_users"]),
        "banned_users": int(row["banned_users"]),
        "total_memberships": int(row["total_memberships"]),
        "total_devices": int(row["total_devices"]),
    }


def list_users_directory(
    connection: sqlite3.Connection,
    *,
    query: str,
    banned_only: bool,
    page: int,
    page_size: int,
    scoped_store_ids: frozenset[str] | None = None,
) -> dict[str, object]:
    normalized_query = query.strip().lower()
    offset = (page - 1) * page_size
    normalized_scope = _normalize_scoped_store_ids(scoped_store_ids)
    if normalized_scope is not None and not normalized_scope:
        return {
            "items": [],
            "total": 0,
            "page": page,
            "page_size": page_size,
            "has_next": False,
            "has_prev": page > 1,
        }

    where_clauses = ["1 = 1"]
    params: list[object] = []

    if banned_only:
        where_clauses.append("users.is_banned = 1")
    if normalized_query:
        like_query = f"%{normalized_query}%"
        where_clauses.append(
            """
            (
                LOWER(users.user_id) LIKE ?
                OR LOWER(COALESCE(user_identities.username, '')) LIKE ?
                OR LOWER(COALESCE(user_identities.provider_user_id, '')) LIKE ?
                OR LOWER(COALESCE(user_identities.display_name, '')) LIKE ?
            )
            """
        )
        params.extend([like_query, like_query, like_query, like_query])
    if normalized_scope is not None:
        placeholders = ", ".join(["?"] * len(normalized_scope))
        where_clauses.append(
            f"""
            EXISTS (
                SELECT 1
                FROM store_memberships scoped_memberships
                WHERE scoped_memberships.user_id = users.user_id
                  AND scoped_memberships.revoked_at IS NULL
                  AND scoped_memberships.store_id IN ({placeholders})
            )
            """
        )
        params.extend(normalized_scope)

    where_sql = " AND ".join(where_clauses)
    total_row = connection.execute(
        f"""
        SELECT COUNT(*) AS total
        FROM users
        LEFT JOIN user_identities ON user_identities.user_id = users.user_id
        WHERE {where_sql}
        """,
        tuple(params),
    ).fetchone()
    total = int(total_row["total"]) if total_row is not None else 0

    rows = connection.execute(
        f"""
        SELECT
            users.user_id,
            users.is_banned,
            users.ban_reason,
            users.created_at,
            users.last_seen_at,
            user_identities.provider,
            user_identities.provider_user_id,
            user_identities.username,
            user_identities.display_name
        FROM users
        LEFT JOIN user_identities ON user_identities.user_id = users.user_id
        WHERE {where_sql}
        ORDER BY users.last_seen_at DESC, users.created_at DESC
        LIMIT ? OFFSET ?
        """,
        (*params, page_size, offset),
    ).fetchall()

    items: list[dict[str, object]] = []
    for row in rows:
        items.append(
            {
                "user_id": row["user_id"],
                "provider": row["provider"] or "unknown",
                "provider_user_id": row["provider_user_id"] or "",
                "username": row["username"] or "",
                "display_name": row["display_name"] or "",
                "is_banned": int(row["is_banned"]) == 1,
                "ban_reason": row["ban_reason"],
                "created_at": row["created_at"],
                "last_seen_at": row["last_seen_at"],
            }
        )

    return {
        "items": items,
        "total": total,
        "page": page,
        "page_size": page_size,
        "has_next": (offset + len(items)) < total,
        "has_prev": page > 1,
    }


def get_user_detail(
    connection: sqlite3.Connection,
    *,
    user_id: str,
    scoped_store_ids: frozenset[str] | None = None,
) -> dict[str, object]:
    normalized_scope = _normalize_scoped_store_ids(scoped_store_ids)
    if normalized_scope is not None and not normalized_scope:
        raise HTTPException(status_code=404, detail="user_not_found")
    user_row = connection.execute(
        """
        SELECT
            user_id,
            is_banned,
            ban_reason,
            created_at,
            updated_at,
            last_seen_at
        FROM users
        WHERE user_id = ?
        """,
        (user_id,),
    ).fetchone()
    if user_row is None:
        raise HTTPException(status_code=404, detail="user_not_found")

    identity_rows = connection.execute(
        """
        SELECT
            provider,
            provider_user_id,
            provider_chat_id,
            username,
            display_name,
            created_at,
            updated_at
        FROM user_identities
        WHERE user_id = ?
        ORDER BY created_at ASC
        """,
        (user_id,),
    ).fetchall()

    scope_filter_sql = ""
    scope_params: tuple[str, ...] = ()
    if normalized_scope is not None:
        scope_filter_sql = "AND store_memberships.store_id IN ({})".format(
            ", ".join(["?"] * len(normalized_scope))
        )
        scope_params = normalized_scope

    membership_rows = connection.execute(
        f"""
        SELECT
            store_memberships.membership_id,
            store_memberships.store_id,
            store_memberships.role,
            store_memberships.created_at,
            store_memberships.revoked_at,
            stores.is_active,
            COALESCE(NULLIF(TRIM(stores.display_name), ''), NULLIF(TRIM(stores.name), ''), stores.store_id) AS store_display_name
        FROM store_memberships
        JOIN stores ON stores.store_id = store_memberships.store_id
        WHERE store_memberships.user_id = ?
          AND store_memberships.revoked_at IS NULL
          {scope_filter_sql}
        ORDER BY store_memberships.created_at ASC
        """,
        (user_id, *scope_params),
    ).fetchall()

    if normalized_scope is not None and not membership_rows:
        raise HTTPException(status_code=404, detail="user_not_found")

    return {
        "user": {
            "user_id": user_row["user_id"],
            "is_banned": int(user_row["is_banned"]) == 1,
            "ban_reason": user_row["ban_reason"],
            "created_at": user_row["created_at"],
            "updated_at": user_row["updated_at"],
            "last_seen_at": user_row["last_seen_at"],
        },
        "identities": [
            {
                "provider": row["provider"],
                "provider_user_id": row["provider_user_id"],
                "provider_chat_id": row["provider_chat_id"],
                "username": row["username"],
                "display_name": row["display_name"],
                "created_at": row["created_at"],
                "updated_at": row["updated_at"],
            }
            for row in identity_rows
        ],
        "memberships": [
            {
                "membership_id": row["membership_id"],
                "store_id": row["store_id"],
                "store_display_name": row["store_display_name"],
                "role": row["role"],
                "created_at": row["created_at"],
                "revoked_at": row["revoked_at"],
                "store_is_active": int(row["is_active"]) == 1,
            }
            for row in membership_rows
        ],
    }


def list_stores_with_counts(
    connection: sqlite3.Connection,
    *,
    include_inactive: bool,
    scoped_store_ids: frozenset[str] | None = None,
) -> list[dict[str, object]]:
    normalized_scope = _normalize_scoped_store_ids(scoped_store_ids)
    if normalized_scope is not None and not normalized_scope:
        return []

    query = """
        SELECT
            stores.store_id,
            COALESCE(NULLIF(TRIM(stores.display_name), ''), NULLIF(TRIM(stores.name), ''), stores.store_id) AS display_name,
            stores.address,
            stores.is_active,
            stores.created_at,
            COALESCE(stores.updated_at, stores.created_at) AS updated_at,
            (
                SELECT COUNT(*)
                FROM store_memberships
                WHERE store_memberships.store_id = stores.store_id
                  AND store_memberships.revoked_at IS NULL
            ) AS member_count,
            (
                SELECT COUNT(*)
                FROM devices
                WHERE devices.store_id = stores.store_id
            ) AS device_count
        FROM stores
    """
    filters: list[str] = []
    params: list[object] = []
    if not include_inactive:
        filters.append("stores.is_active = 1")
    if normalized_scope is not None:
        placeholders = ", ".join(["?"] * len(normalized_scope))
        filters.append(f"stores.store_id IN ({placeholders})")
        params.extend(normalized_scope)
    if filters:
        query += " WHERE " + " AND ".join(filters)
    query += " ORDER BY stores.created_at ASC"

    rows = connection.execute(query, tuple(params)).fetchall()
    return [
        {
            "store_id": row["store_id"],
            "display_name": row["display_name"],
            "address": row["address"],
            "is_active": int(row["is_active"]) == 1,
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
            "member_count": int(row["member_count"]),
            "device_count": int(row["device_count"]),
        }
        for row in rows
    ]


def get_store_detail(
    connection: sqlite3.Connection,
    *,
    store_id: str,
    online_threshold_seconds: int,
    scoped_store_ids: frozenset[str] | None = None,
) -> dict[str, object]:
    normalized_scope = _normalize_scoped_store_ids(scoped_store_ids)
    if normalized_scope is not None and store_id not in normalized_scope:
        raise HTTPException(status_code=404, detail="Store not found")
    store = read_store(connection, store_id=store_id)
    member_rows = connection.execute(
        """
        SELECT
            store_memberships.membership_id,
            store_memberships.user_id,
            store_memberships.role,
            store_memberships.created_at,
            users.is_banned,
            user_identities.username,
            user_identities.display_name
        FROM store_memberships
        JOIN users ON users.user_id = store_memberships.user_id
        LEFT JOIN user_identities ON user_identities.user_id = users.user_id
        WHERE store_memberships.store_id = ?
          AND store_memberships.revoked_at IS NULL
        ORDER BY store_memberships.created_at ASC
        """,
        (store_id,),
    ).fetchall()

    device_rows = connection.execute(
        """
        SELECT
            device_id,
            store_id,
            label,
            hostname,
            os,
            connector_version,
            created_at,
            last_seen_at,
            decommissioned_at
        FROM devices
        WHERE store_id = ?
        ORDER BY created_at ASC
        """,
        (store_id,),
    ).fetchall()
    now_utc = datetime.now(timezone.utc)
    devices = [
        {
            "device_id": row["device_id"],
            "label": row["label"],
            "hostname": row["hostname"],
            "os": row["os"],
            "connector_version": row["connector_version"],
            "created_at": row["created_at"],
            "connected": connection_manager.is_connected(row["device_id"]),
            "online": compute_online(
                last_seen_at=parse_db_utc_datetime(row["last_seen_at"]),
                now_utc=now_utc,
                threshold_seconds=online_threshold_seconds,
            ),
            "last_seen_at": serialize_utc_datetime(parse_db_utc_datetime(row["last_seen_at"])),
            "decommissioned_at": row["decommissioned_at"],
            "is_decommissioned": row["decommissioned_at"] is not None,
        }
        for row in device_rows
    ]

    return {
        "store": store.model_dump(),
        "members": [
            {
                "membership_id": row["membership_id"],
                "user_id": row["user_id"],
                "role": row["role"],
                "created_at": row["created_at"],
                "is_banned": int(row["is_banned"]) == 1,
                "username": row["username"],
                "display_name": row["display_name"],
            }
            for row in member_rows
        ],
        "devices": devices,
    }


def list_devices(
    connection: sqlite3.Connection,
    *,
    online_threshold_seconds: int,
    store_id: str | None,
    scoped_store_ids: frozenset[str] | None = None,
) -> list[dict[str, object]]:
    normalized_scope = _normalize_scoped_store_ids(scoped_store_ids)
    if normalized_scope is not None and not normalized_scope:
        return []

    params: list[object] = []
    query = """
        SELECT
            devices.device_id,
            devices.store_id,
            devices.label,
            devices.hostname,
            devices.os,
            devices.connector_version,
            devices.created_at,
            devices.last_seen_at,
            devices.decommissioned_at,
            COALESCE(NULLIF(TRIM(stores.display_name), ''), NULLIF(TRIM(stores.name), ''), stores.store_id) AS store_display_name
        FROM devices
        LEFT JOIN stores ON stores.store_id = devices.store_id
    """
    filters: list[str] = []
    if store_id:
        filters.append("devices.store_id = ?")
        params.append(store_id)
    if normalized_scope is not None:
        placeholders = ", ".join(["?"] * len(normalized_scope))
        filters.append(f"devices.store_id IN ({placeholders})")
        params.extend(normalized_scope)
    if filters:
        query += " WHERE " + " AND ".join(filters)
    query += " ORDER BY devices.created_at DESC"
    rows = connection.execute(query, tuple(params)).fetchall()

    now_utc = datetime.now(timezone.utc)
    items: list[dict[str, object]] = []
    for row in rows:
        last_seen = parse_db_utc_datetime(row["last_seen_at"])
        items.append(
            {
                "device_id": row["device_id"],
                "store_id": row["store_id"],
                "store_display_name": row["store_display_name"] or row["store_id"] or "",
                "label": row["label"],
                "hostname": row["hostname"],
                "os": row["os"],
                "connector_version": row["connector_version"],
                "created_at": row["created_at"],
                "connected": connection_manager.is_connected(row["device_id"]),
                "online": compute_online(
                    last_seen_at=last_seen,
                    now_utc=now_utc,
                    threshold_seconds=online_threshold_seconds,
                ),
                "last_seen_at": serialize_utc_datetime(last_seen),
                "decommissioned_at": row["decommissioned_at"],
                "is_decommissioned": row["decommissioned_at"] is not None,
            }
        )
    return items


def get_device_detail(
    connection: sqlite3.Connection,
    *,
    device_id: str,
    online_threshold_seconds: int,
    scoped_store_ids: frozenset[str] | None = None,
) -> dict[str, object]:
    normalized_scope = _normalize_scoped_store_ids(scoped_store_ids)
    row = connection.execute(
        """
        SELECT
            devices.device_id,
            devices.store_id,
            devices.label,
            devices.hostname,
            devices.os,
            devices.connector_version,
            devices.created_at,
            devices.last_seen_at,
            devices.decommissioned_at,
            COALESCE(NULLIF(TRIM(stores.display_name), ''), NULLIF(TRIM(stores.name), ''), stores.store_id) AS store_display_name
        FROM devices
        LEFT JOIN stores ON stores.store_id = devices.store_id
        WHERE devices.device_id = ?
        """,
        (device_id,),
    ).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="Device not found")
    if normalized_scope is not None:
        store_id = row["store_id"]
        if store_id is None or store_id not in normalized_scope:
            raise HTTPException(status_code=404, detail="Device not found")

    status = get_device_status(
        connection,
        device_id=device_id,
        online_threshold_seconds=online_threshold_seconds,
    )
    return {
        "device_id": row["device_id"],
        "store_id": row["store_id"],
        "store_display_name": row["store_display_name"] or row["store_id"] or "",
        "label": row["label"],
        "hostname": row["hostname"],
        "os": row["os"],
        "connector_version": row["connector_version"],
        "created_at": row["created_at"],
        "decommissioned_at": row["decommissioned_at"],
        "is_decommissioned": row["decommissioned_at"] is not None,
        "status": status.model_dump(),
    }


def decommission_device(
    connection: sqlite3.Connection,
    *,
    device_id: str,
    scoped_store_ids: frozenset[str] | None = None,
) -> dict[str, object]:
    normalized_scope = _normalize_scoped_store_ids(scoped_store_ids)
    row = connection.execute(
        """
        SELECT
            device_id,
            store_id,
            decommissioned_at
        FROM devices
        WHERE device_id = ?
        """,
        (device_id,),
    ).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="Device not found")
    if normalized_scope is not None:
        store_id = row["store_id"]
        if store_id is None or store_id not in normalized_scope:
            raise HTTPException(status_code=404, detail="Device not found")

    if row["decommissioned_at"] is None:
        decommissioned_at = datetime.now(timezone.utc).isoformat()
        connection.execute(
            """
            UPDATE devices
            SET decommissioned_at = ?
            WHERE device_id = ? AND decommissioned_at IS NULL
            """,
            (decommissioned_at, device_id),
        )
        connection.execute(
            """
            UPDATE user_context
            SET active_device_id = NULL, updated_at = ?
            WHERE active_device_id = ?
            """,
            (decommissioned_at, device_id),
        )
        connection.commit()

    refreshed = connection.execute(
        """
        SELECT device_id, store_id, decommissioned_at
        FROM devices
        WHERE device_id = ?
        """,
        (device_id,),
    ).fetchone()
    if refreshed is None:
        raise HTTPException(status_code=404, detail="Device not found")
    return {
        "device_id": refreshed["device_id"],
        "store_id": refreshed["store_id"],
        "decommissioned_at": refreshed["decommissioned_at"],
    }
