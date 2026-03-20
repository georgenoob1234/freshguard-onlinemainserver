from __future__ import annotations

import logging
from pathlib import Path
import sqlite3
from typing import Any

from fastapi import APIRouter, Depends, Header, HTTPException
from fastapi.responses import FileResponse, JSONResponse

from app import admin_ops
from app.config import get_settings
from app.db import get_db
from app.models import (
    AdminCreateEnrollTokenRequest,
    AdminCreateEnrollTokenResponse,
    AdminCreateStoreRequest,
    AdminDeviceCommandRequest,
    AdminLookupUserResponse,
    AdminStore,
    AdminStoreDevicesResponse,
    AdminStoreListResponse,
    AdminUpsertStoreMembershipRequest,
    AdminUpsertStoreMembershipResponse,
    AdminUpdateStoreRequest,
    AdminUpdateUserBanRequest,
    AdminUpdateUserBanResponse,
    DeviceStatusResponse,
)
from app.realtime import CommandTimeoutError, send_command
from app.security import constant_time_equals


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


@router.post("/stores", response_model=AdminStore, status_code=201)
def create_store(
    payload: AdminCreateStoreRequest,
    x_admin_key: str | None = Header(default=None, alias="X-ADMIN-KEY"),
    connection: sqlite3.Connection = Depends(get_db),
) -> AdminStore:
    _require_admin_key(x_admin_key)
    store = admin_ops.create_store(connection, payload=payload)
    logger.info("Admin store action=%s store_id=%s", "create", store.store_id)
    return store


@router.get("/stores", response_model=AdminStoreListResponse)
def list_stores(
    include_inactive: bool = False,
    x_admin_key: str | None = Header(default=None, alias="X-ADMIN-KEY"),
    connection: sqlite3.Connection = Depends(get_db),
) -> AdminStoreListResponse:
    _require_admin_key(x_admin_key)
    return admin_ops.list_stores(connection, include_inactive=include_inactive)


@router.get("/stores/{store_id}", response_model=AdminStore)
def read_store(
    store_id: str,
    x_admin_key: str | None = Header(default=None, alias="X-ADMIN-KEY"),
    connection: sqlite3.Connection = Depends(get_db),
) -> AdminStore:
    _require_admin_key(x_admin_key)
    return admin_ops.read_store(connection, store_id=store_id)


@router.patch("/stores/{store_id}", response_model=AdminStore)
def update_store(
    store_id: str,
    payload: AdminUpdateStoreRequest,
    x_admin_key: str | None = Header(default=None, alias="X-ADMIN-KEY"),
    connection: sqlite3.Connection = Depends(get_db),
) -> AdminStore:
    _require_admin_key(x_admin_key)
    store, deactivating = admin_ops.update_store(
        connection,
        store_id=store_id,
        payload=payload,
    )
    if deactivating:
        device_count = admin_ops.count_store_devices(connection, store_id=store_id)
        logger.info("Admin store action=%s store_id=%s", "deactivate", store_id)
        if device_count > 0:
            logger.warning(
                "Store deactivated while devices remain registered store_id=%s device_count=%s",
                store_id,
                device_count,
            )
    else:
        logger.info("Admin store action=%s store_id=%s", "update", store_id)
    return store


@router.get("/users/lookup", response_model=AdminLookupUserResponse)
def lookup_user(
    provider: str,
    provider_user_id: str | None = None,
    username: str | None = None,
    x_admin_key: str | None = Header(default=None, alias="X-ADMIN-KEY"),
    connection: sqlite3.Connection = Depends(get_db),
) -> AdminLookupUserResponse | JSONResponse:
    _require_admin_key(x_admin_key)
    lookup_result = admin_ops.lookup_user(
        connection,
        provider=provider,
        provider_user_id=provider_user_id,
        username=username,
    )
    if lookup_result.ambiguous_candidates is not None:
        return JSONResponse(
            status_code=409,
            content={
                "detail": "ambiguous_username",
                "candidates": [candidate.model_dump() for candidate in lookup_result.ambiguous_candidates],
            },
        )
    if lookup_result.user is None:
        raise HTTPException(status_code=404, detail="user_not_found")
    return lookup_result.user


@router.patch("/users/{user_id}", response_model=AdminUpdateUserBanResponse)
def update_user_ban_state(
    user_id: str,
    payload: AdminUpdateUserBanRequest,
    x_admin_key: str | None = Header(default=None, alias="X-ADMIN-KEY"),
    connection: sqlite3.Connection = Depends(get_db),
) -> AdminUpdateUserBanResponse:
    _require_admin_key(x_admin_key)
    response = admin_ops.update_user_ban_state(connection, user_id=user_id, payload=payload)
    logger.info(
        "user_ban_updated user_id=%s is_banned=%s",
        user_id,
        payload.is_banned,
    )
    return response


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
    response = admin_ops.upsert_user_store_membership(
        connection,
        user_id=user_id,
        store_id=store_id,
        payload=payload,
        note="admin_api",
    )
    logger.info(
        "Admin membership action=%s user_id=%s store_id=%s role=%s set_active_store=%s",
        response.status,
        user_id,
        store_id,
        response.membership.role,
        payload.set_active_store,
    )
    return response


@router.post("/enroll_tokens", response_model=AdminCreateEnrollTokenResponse)
def create_enroll_token(
    payload: AdminCreateEnrollTokenRequest,
    x_admin_key: str | None = Header(default=None, alias="X-ADMIN-KEY"),
    connection: sqlite3.Connection = Depends(get_db),
) -> AdminCreateEnrollTokenResponse:
    settings = get_settings()
    _require_admin_key(x_admin_key)
    return admin_ops.create_enroll_token(
        connection,
        payload=payload,
        secret_salt=settings.secret_salt,
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
    return admin_ops.list_store_devices(
        connection,
        store_id=store_id,
        online_threshold_seconds=settings.online_threshold_seconds,
    )


@router.get("/devices/{device_id}/status", response_model=DeviceStatusResponse)
def get_device_status(
    device_id: str,
    x_admin_key: str | None = Header(default=None, alias="X-ADMIN-KEY"),
    connection: sqlite3.Connection = Depends(get_db),
) -> DeviceStatusResponse:
    _require_admin_key(x_admin_key)
    settings = get_settings()
    return admin_ops.get_device_status(
        connection,
        device_id=device_id,
        online_threshold_seconds=settings.online_threshold_seconds,
    )


@router.get("/blobs/{blob_id}")
def get_blob(
    blob_id: str,
    x_admin_key: str | None = Header(default=None, alias="X-ADMIN-KEY"),
    connection: sqlite3.Connection = Depends(get_db),
) -> FileResponse:
    _require_admin_key(x_admin_key)
    blob_row = admin_ops.get_blob_metadata(connection, blob_id=blob_id)

    blob_path = Path(blob_row["path"])
    if not blob_path.exists():
        raise HTTPException(status_code=404, detail="Blob bytes not found on disk")

    return FileResponse(
        path=blob_path,
        media_type=blob_row["content_type"],
        filename=blob_path.name,
    )
