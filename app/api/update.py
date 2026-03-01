from __future__ import annotations

from datetime import datetime, timezone
import json
import logging
import sqlite3

from fastapi import APIRouter, Body, Depends, Header
from fastapi.encoders import jsonable_encoder
from fastapi.responses import JSONResponse
from pydantic import ValidationError

from app.auth import Device, resolve_authenticated_device
from app.db import get_db
from app.models import UpdateEnvelopeRequest, UpdateResponse


logger = logging.getLogger(__name__)
router = APIRouter(tags=["update"])


def _rollback_quietly(connection: sqlite3.Connection) -> None:
    try:
        connection.execute("ROLLBACK")
    except sqlite3.OperationalError:
        pass


@router.post("/update", response_model=UpdateResponse)
def ingest_update(
    raw_payload: dict = Body(...),
    device: Device = Depends(resolve_authenticated_device),
    connection: sqlite3.Connection = Depends(get_db),
    idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
) -> UpdateResponse | JSONResponse:
    try:
        envelope = UpdateEnvelopeRequest.model_validate(raw_payload)
    except ValidationError as error:
        return JSONResponse(
            status_code=400,
            content={
                "detail": "Invalid update envelope.",
                "errors": jsonable_encoder(error.errors()),
            },
        )

    if envelope.scan_result.image_id != envelope.image_id:
        return JSONResponse(
            status_code=400,
            content={"detail": "image_id mismatch between envelope and scan_result."},
        )

    if idempotency_key is not None and idempotency_key != envelope.image_id:
        return JSONResponse(
            status_code=400,
            content={"detail": "Idempotency-Key must match envelope image_id."},
        )

    received_at = datetime.now(timezone.utc).isoformat()
    sent_at = envelope.sent_at.isoformat() if envelope.sent_at is not None else None
    final_image_id = envelope.image_id

    try:
        connection.execute("BEGIN IMMEDIATE")
        connection.execute(
            """
            INSERT INTO scan_results (
                device_id,
                image_id,
                received_at,
                sent_at,
                scan_result_json
            )
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(device_id, image_id) DO NOTHING
            """,
            (
                device.device_id,
                final_image_id,
                received_at,
                sent_at,
                json.dumps(
                    envelope.scan_result.model_dump(),
                    separators=(",", ":"),
                    sort_keys=True,
                ),
            ),
        )
        inserted = connection.execute("SELECT changes() AS row_count").fetchone()[
            "row_count"
        ] == 1
        connection.execute("COMMIT")
    except Exception:
        _rollback_quietly(connection)
        return JSONResponse(status_code=500, content={"detail": "Internal server error."})

    duplicate = not inserted
    logger.info(
        "Ingestion accepted device_id=%s image_id=%s duplicate=%s",
        device.device_id,
        final_image_id,
        duplicate,
    )
    if duplicate:
        return JSONResponse(
            status_code=409,
            content=UpdateResponse(duplicate=True).model_dump(),
        )
    return UpdateResponse(duplicate=False)
