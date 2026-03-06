from __future__ import annotations

from datetime import datetime, timedelta, timezone
import logging
from pathlib import Path
import sqlite3
from typing import Any, Literal
import uuid

from fastapi import APIRouter, Depends, Header, HTTPException
from fastapi.responses import FileResponse, JSONResponse

from app.config import get_settings
from app.db import get_db, rollback_quietly
from app.device_status import compute_online, parse_db_utc_datetime, serialize_utc_datetime
from app.models import (
    AdminCreateEnrollTokenRequest,
    AdminCreateEnrollTokenResponse,
    AdminCreateStoreRequest,
    AdminDeviceCommandRequest,
    AdminLookupUserCandidate,
    AdminLookupUserResponse,
    AdminStoreMembership,
    AdminStore,
    AdminStoreDevicesResponse,
    AdminStoreListResponse,
    AdminUpsertStoreMembershipRequest,
    AdminUpsertStoreMembershipResponse,
    AdminUpdateUserBanRequest,
    AdminUpdateUserBanResponse,
    AdminUpdateStoreRequest,
    DeviceStatusResponse,
)
from app.realtime import CommandTimeoutError, connection_manager, send_command
from app.roles import is_known_role
from app.security import constant_time_equals, generate_token, hash_token


logger = logging.getLogger(__name__)
router = APIRouter(prefix="/admin/v1", tags=["admin"])


def _require_admin_key(x_admin_key: str | None) -> None:
    settings = get_settings()
    if (
        not settings.admin_key
        or x_admin_key is None
        or not constant_time_equals(x_admin_key, settings.admin_key)
    ):
        raise HTTPException(status_code=401, detail="Unauthorized")


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


def _require_store_row(
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


def _get_user_context_row(
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


def _upsert_user_context(
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


@router.post("/stores", response_model=AdminStore, status_code=201)
def create_store(
    payload: AdminCreateStoreRequest,
    x_admin_key: str | None = Header(default=None, alias="X-ADMIN-KEY"),
    connection: sqlite3.Connection = Depends(get_db),
) -> AdminStore:
    _require_admin_key(x_admin_key)

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
            logger.info("Admin store action=%s store_id=%s", "create", store_id)
            return _store_row_to_model(_require_store_row(connection, store_id=store_id))
        except sqlite3.IntegrityError:
            continue

    raise HTTPException(status_code=500, detail="Failed to generate unique store_id")


@router.get("/stores", response_model=AdminStoreListResponse)
def list_stores(
    include_inactive: bool = False,
    x_admin_key: str | None = Header(default=None, alias="X-ADMIN-KEY"),
    connection: sqlite3.Connection = Depends(get_db),
) -> AdminStoreListResponse:
    _require_admin_key(x_admin_key)

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


@router.get("/stores/{store_id}", response_model=AdminStore)
def read_store(
    store_id: str,
    x_admin_key: str | None = Header(default=None, alias="X-ADMIN-KEY"),
    connection: sqlite3.Connection = Depends(get_db),
) -> AdminStore:
    _require_admin_key(x_admin_key)
    return _store_row_to_model(_require_store_row(connection, store_id=store_id))


@router.patch("/stores/{store_id}", response_model=AdminStore)
def update_store(
    store_id: str,
    payload: AdminUpdateStoreRequest,
    x_admin_key: str | None = Header(default=None, alias="X-ADMIN-KEY"),
    connection: sqlite3.Connection = Depends(get_db),
) -> AdminStore:
    _require_admin_key(x_admin_key)

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
    params: list[Any] = []

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

    if deactivating:
        device_count = connection.execute(
            """
            SELECT COUNT(*) AS device_count
            FROM devices
            WHERE store_id = ?
            """,
            (store_id,),
        ).fetchone()["device_count"]
        logger.info("Admin store action=%s store_id=%s", "deactivate", store_id)
        if int(device_count) > 0:
            logger.warning(
                "Store deactivated while devices remain registered store_id=%s device_count=%s",
                store_id,
                int(device_count),
            )
    else:
        logger.info("Admin store action=%s store_id=%s", "update", store_id)

    return _store_row_to_model(_require_store_row(connection, store_id=store_id))


@router.get("/users/lookup", response_model=AdminLookupUserResponse)
def lookup_user(
    provider: str,
    provider_user_id: str | None = None,
    username: str | None = None,
    x_admin_key: str | None = Header(default=None, alias="X-ADMIN-KEY"),
    connection: sqlite3.Connection = Depends(get_db),
) -> AdminLookupUserResponse | JSONResponse:
    _require_admin_key(x_admin_key)

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
            return _user_lookup_row_to_response(provider_id_match)

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
        return JSONResponse(
            status_code=409,
            content={
                "detail": "ambiguous_username",
                "candidates": [
                    AdminLookupUserCandidate(
                        user_id=row["user_id"],
                        provider_user_id=row["provider_user_id"],
                        username=row["username"],
                        display_name=row["display_name"],
                        last_seen_at=row["last_seen_at"],
                    ).model_dump()
                    for row in username_matches
                ],
            },
        )
    return _user_lookup_row_to_response(username_matches[0])


@router.patch("/users/{user_id}", response_model=AdminUpdateUserBanResponse)
def update_user_ban_state(
    user_id: str,
    payload: AdminUpdateUserBanRequest,
    x_admin_key: str | None = Header(default=None, alias="X-ADMIN-KEY"),
    connection: sqlite3.Connection = Depends(get_db),
) -> AdminUpdateUserBanResponse:
    _require_admin_key(x_admin_key)

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

    logger.info(
        "user_ban_updated user_id=%s is_banned=%s",
        user_id,
        payload.is_banned,
    )
    return AdminUpdateUserBanResponse(
        user_id=updated_row["user_id"],
        is_banned=int(updated_row["is_banned"]) == 1,
        last_seen_at=updated_row["last_seen_at"],
    )


@router.put(
    "/users/{user_id}/stores/{store_id}/membership",
    response_model=AdminUpsertStoreMembershipResponse,
)
def upsert_user_store_membership(
    user_id: str,
    store_id: str,
    payload: AdminUpsertStoreMembershipRequest,
    x_admin_key: str | None = Header(default=None, alias="X-ADMIN-KEY"),
    connection: sqlite3.Connection = Depends(get_db),
) -> AdminUpsertStoreMembershipResponse:
    _require_admin_key(x_admin_key)

    try:
        connection.execute("BEGIN IMMEDIATE")
        user_row = _require_user_row(connection, user_id=user_id)
        _require_not_banned(user_row)
        _require_store_row(connection, store_id=store_id)
        normalized_role = _normalize_membership_role(payload.role)
        now = datetime.now(timezone.utc).isoformat()

        membership_row = _select_active_membership_row(
            connection,
            user_id=user_id,
            store_id=store_id,
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
                (membership_id, store_id, user_id, normalized_role, now, None, None, "admin_api"),
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
        logger.exception(
            "Unexpected failure while upserting admin membership user_id=%s store_id=%s",
            user_id,
            store_id,
        )
        raise HTTPException(status_code=500, detail="Internal server error.") from error

    logger.info(
        "Admin membership action=%s user_id=%s store_id=%s role=%s set_active_store=%s",
        status,
        user_id,
        store_id,
        membership_row["role"],
        payload.set_active_store,
    )
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


@router.post("/enroll_tokens", response_model=AdminCreateEnrollTokenResponse)
def create_enroll_token(
    payload: AdminCreateEnrollTokenRequest,
    x_admin_key: str | None = Header(default=None, alias="X-ADMIN-KEY"),
    connection: sqlite3.Connection = Depends(get_db),
) -> AdminCreateEnrollTokenResponse:
    settings = get_settings()
    _require_admin_key(x_admin_key)

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
    token_hash = hash_token(enroll_token, settings.secret_salt)

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


@router.post("/devices/{device_id}/commands")
async def send_device_command(
    device_id: str,
    payload: AdminDeviceCommandRequest,
    x_admin_key: str | None = Header(default=None, alias="X-ADMIN-KEY"),
) -> dict[str, Any]:
    _require_admin_key(x_admin_key)
    settings = get_settings()
    logger.info(
        "Admin command dispatch device_id=%s request_type=%s",
        device_id,
        payload.request_type,
    )
    try:
        return await send_command(
            device_id=device_id,
            request_type=payload.request_type,
            params=payload.params,
            timeout_s=settings.command_default_timeout_seconds,
        )
    except CommandTimeoutError as error:
        raise HTTPException(
            status_code=504,
            detail="Timed out waiting for connector response.",
        ) from error


@router.get(
    "/stores/{store_id}/devices",
    response_model=AdminStoreDevicesResponse,
)
def list_store_devices(
    store_id: str,
    x_admin_key: str | None = Header(default=None, alias="X-ADMIN-KEY"),
    connection: sqlite3.Connection = Depends(get_db),
) -> AdminStoreDevicesResponse:
    _require_admin_key(x_admin_key)
    settings = get_settings()

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
            threshold_seconds=settings.online_threshold_seconds,
        )
        for row in rows
    ]
    return AdminStoreDevicesResponse(
        store_id=store_id,
        online_threshold_seconds=settings.online_threshold_seconds,
        devices=devices,
    )


@router.get("/devices/{device_id}/status", response_model=DeviceStatusResponse)
def get_device_status(
    device_id: str,
    x_admin_key: str | None = Header(default=None, alias="X-ADMIN-KEY"),
    connection: sqlite3.Connection = Depends(get_db),
) -> DeviceStatusResponse:
    _require_admin_key(x_admin_key)
    settings = get_settings()

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
        threshold_seconds=settings.online_threshold_seconds,
    )


@router.get("/blobs/{blob_id}")
def get_blob(
    blob_id: str,
    x_admin_key: str | None = Header(default=None, alias="X-ADMIN-KEY"),
    connection: sqlite3.Connection = Depends(get_db),
) -> FileResponse:
    _require_admin_key(x_admin_key)

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

    blob_path = Path(blob_row["path"])
    if not blob_path.exists():
        raise HTTPException(status_code=404, detail="Blob bytes not found on disk")

    return FileResponse(
        path=blob_path,
        media_type=blob_row["content_type"],
        filename=blob_path.name,
    )
