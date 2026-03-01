from __future__ import annotations

from datetime import datetime, timedelta, timezone
import logging
from pathlib import Path
import sqlite3
from typing import Any
import uuid

from fastapi import APIRouter, Depends, Header, HTTPException
from fastapi.responses import FileResponse

from app.config import get_settings
from app.db import get_db
from app.models import (
    AdminDeviceCommandRequest,
    AdminCreateEnrollTokenRequest,
    AdminCreateEnrollTokenResponse,
)
from app.realtime import CommandTimeoutError, send_command
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


@router.post("/enroll_tokens", response_model=AdminCreateEnrollTokenResponse)
def create_enroll_token(
    payload: AdminCreateEnrollTokenRequest,
    x_admin_key: str | None = Header(default=None, alias="X-ADMIN-KEY"),
    connection: sqlite3.Connection = Depends(get_db),
) -> AdminCreateEnrollTokenResponse:
    settings = get_settings()
    _require_admin_key(x_admin_key)

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
