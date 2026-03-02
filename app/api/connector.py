from __future__ import annotations

import asyncio
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import logging
from pathlib import Path
import sqlite3
import uuid

from fastapi import (
    APIRouter,
    Depends,
    File,
    Form,
    HTTPException,
    UploadFile,
    WebSocket,
    WebSocketDisconnect,
    WebSocketException,
    status,
)
from fastapi.responses import JSONResponse

from app.auth import (
    Device,
    extract_bearer_token,
    resolve_authenticated_device,
    resolve_device_from_bearer_token,
)
from app.config import get_settings
from app.db import get_db, open_connection, rollback_quietly
from app.models import BlobUploadResponse, RegisterRequest, RegisterResponse
from app.realtime import command_broker, connection_manager
from app.security import generate_token, hash_token


logger = logging.getLogger(__name__)
router = APIRouter(prefix="/connector/v1", tags=["connector"])


@dataclass
class RegistrationError(Exception):
    error_code: str
    detail: str


def _error_response(error_code: str, detail: str, status_code: int) -> JSONResponse:
    return JSONResponse(
        status_code=status_code,
        content={"error_code": error_code, "detail": detail},
    )


def _update_device_presence(
    database_path: str,
    device_id: str,
    *,
    update_connected_at: bool = False,
) -> None:
    seen_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    connection = open_connection(database_path)
    try:
        if update_connected_at:
            connection.execute(
                """
                UPDATE devices
                SET last_seen_at = ?, connected_at = ?
                WHERE device_id = ?
                """,
                (seen_at, seen_at, device_id),
            )
        else:
            connection.execute(
                """
                UPDATE devices
                SET last_seen_at = ?
                WHERE device_id = ?
                """,
                (seen_at, device_id),
            )
        connection.commit()
    finally:
        connection.close()


@router.websocket("/ws")
async def connector_websocket(websocket: WebSocket) -> None:
    settings = get_settings()
    authorization = websocket.headers.get("Authorization")
    try:
        token = extract_bearer_token(authorization)
        auth_connection = open_connection(settings.database_path)
        try:
            device = resolve_device_from_bearer_token(token, auth_connection)
        finally:
            auth_connection.close()
    except HTTPException as error:
        raise WebSocketException(code=status.WS_1008_POLICY_VIOLATION) from error

    await connection_manager.connect(device.device_id, websocket)
    await asyncio.to_thread(
        _update_device_presence,
        settings.database_path,
        device.device_id,
        update_connected_at=True,
    )
    await websocket.accept()
    logger.info("Connector WS connected device_id=%s", device.device_id)

    try:
        while True:
            inbound_message = await websocket.receive_json()
            await connection_manager.mark_seen(device.device_id)
            await asyncio.to_thread(
                _update_device_presence,
                settings.database_path,
                device.device_id,
            )

            if not isinstance(inbound_message, dict):
                continue

            if inbound_message.get("type") != "response":
                continue

            payload = inbound_message.get("payload")
            if not isinstance(payload, dict):
                continue

            request_id = payload.get("request_id")
            if isinstance(request_id, str) and request_id:
                await command_broker.resolve_response(request_id, payload)
    except WebSocketDisconnect:
        pass
    finally:
        await connection_manager.disconnect(device.device_id, websocket)
        logger.info("Connector WS disconnected device_id=%s", device.device_id)


@router.post("/register", response_model=RegisterResponse)
def register_connector(
    payload: RegisterRequest,
    connection: sqlite3.Connection = Depends(get_db),
) -> RegisterResponse | JSONResponse:
    try:
        settings = get_settings()
        now = datetime.now(timezone.utc)
        enroll_token_hash = hash_token(payload.enroll_token, settings.secret_salt)
        connection.execute("BEGIN IMMEDIATE")

        enroll_token_row = connection.execute(
            """
            SELECT token_id, store_id, expires_at
            FROM enroll_tokens
            WHERE token_hash = ?
            """,
            (enroll_token_hash,),
        ).fetchone()

        if enroll_token_row is None:
            raise RegistrationError(
                error_code="TOKEN_INVALID",
                detail="Enroll token was not found.",
            )

        expires_at = datetime.fromisoformat(enroll_token_row["expires_at"])
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)
        if expires_at <= now:
            raise RegistrationError(
                error_code="TOKEN_EXPIRED",
                detail="Enroll token has expired.",
            )

        token_update = connection.execute(
            """
            UPDATE enroll_tokens
            SET uses = uses + 1
            WHERE token_id = ? AND uses < max_uses
            """,
            (enroll_token_row["token_id"],),
        )
        if token_update.rowcount != 1:
            raise RegistrationError(
                error_code="TOKEN_USED_UP",
                detail="Enroll token has no remaining uses.",
            )

        created_at = datetime.now(timezone.utc).isoformat()
        device_id = str(uuid.uuid4())
        device_token = generate_token()
        device_token_hash = hash_token(device_token, settings.secret_salt)

        connection.execute(
            """
            INSERT INTO devices (
                device_id,
                store_id,
                created_at,
                label,
                hostname,
                os,
                connector_version
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                device_id,
                enroll_token_row["store_id"],
                created_at,
                payload.device_info.label,
                payload.device_info.hostname,
                payload.device_info.os,
                payload.device_info.connector_version,
            ),
        )

        connection.execute(
            """
            INSERT INTO device_tokens (device_id, token_hash, created_at)
            VALUES (?, ?, ?)
            """,
            (device_id, device_token_hash, created_at),
        )

        connection.execute("COMMIT")

        return RegisterResponse(
            device_id=device_id,
            device_token=device_token,
            ws_url=None,
        )
    except RegistrationError as error:
        rollback_quietly(connection)
        return _error_response(error.error_code, error.detail, 400)
    except Exception:
        rollback_quietly(connection)
        logger.exception("Unexpected failure while registering connector.")
        return _error_response(
            error_code="INTERNAL_ERROR",
            detail="Internal server error.",
            status_code=500,
        )


@router.post("/blobs", response_model=BlobUploadResponse)
def upload_blob(
    file: UploadFile = File(...),
    image_id: str | None = Form(default=None),
    content_type: str | None = Form(default=None),
    sha256: str | None = Form(default=None),
    device: Device = Depends(resolve_authenticated_device),
    connection: sqlite3.Connection = Depends(get_db),
) -> BlobUploadResponse:
    _ = image_id
    settings = get_settings()
    max_blob_size = settings.max_blob_size_bytes
    blob_chunks: list[bytes] = []
    total_size = 0
    while True:
        chunk = file.file.read(64 * 1024)
        if not chunk:
            break
        total_size += len(chunk)
        if total_size > max_blob_size:
            raise HTTPException(status_code=413, detail="Blob too large")
        blob_chunks.append(chunk)
    blob_bytes = b"".join(blob_chunks)

    checksum = hashlib.sha256(blob_bytes).hexdigest()
    if sha256 is not None and sha256.strip().lower() != checksum:
        raise HTTPException(status_code=400, detail="sha256 mismatch")

    storage_dir = Path(settings.blob_storage_dir)
    storage_dir.mkdir(parents=True, exist_ok=True)
    blob_id = str(uuid.uuid4())
    blob_path = (storage_dir / blob_id).resolve()
    blob_path.write_bytes(blob_bytes)

    effective_content_type = (
        content_type.strip()
        if content_type is not None and content_type.strip()
        else (file.content_type or "application/octet-stream")
    )
    created_at = datetime.now(timezone.utc).isoformat()

    try:
        connection.execute(
            """
            INSERT INTO blobs (
                blob_id,
                device_id,
                path,
                content_type,
                size_bytes,
                sha256,
                created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                blob_id,
                device.device_id,
                str(blob_path),
                effective_content_type,
                len(blob_bytes),
                checksum,
                created_at,
            ),
        )
        connection.commit()
    except Exception as error:
        if blob_path.exists():
            blob_path.unlink()
        raise HTTPException(status_code=500, detail="Internal server error.") from error

    return BlobUploadResponse(
        blob_id=blob_id,
        size_bytes=len(blob_bytes),
        sha256=checksum,
        content_type=effective_content_type,
    )
