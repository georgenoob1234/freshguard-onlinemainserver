from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
from io import BytesIO
import logging
from pathlib import Path
import sqlite3
import uuid

from fastapi import HTTPException
from PIL import Image, ImageDraw

from app.db import open_connection, rollback_quietly
from app.notifications import utcnow_iso
from app.realtime import CommandTimeoutError, send_command


logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class ResultImageContext:
    result_id: str
    image_id: str
    device_id: str
    store_id: str


@dataclass(frozen=True)
class AnnotatedImageResult:
    path: Path
    content_type: str
    cache_hit: bool


def _parse_iso_utc(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def load_result_image_context(
    connection: sqlite3.Connection,
    *,
    result_id: str,
) -> ResultImageContext | None:
    row = connection.execute(
        """
        SELECT
            CAST(scan_results.id AS TEXT) AS result_id,
            scan_results.image_id,
            scan_results.device_id,
            devices.store_id
        FROM scan_results
        JOIN devices ON devices.device_id = scan_results.device_id
        WHERE CAST(scan_results.id AS TEXT) = ?
        """,
        (result_id,),
    ).fetchone()
    if row is None:
        return None
    return ResultImageContext(
        result_id=row["result_id"],
        image_id=row["image_id"],
        device_id=row["device_id"],
        store_id=row["store_id"],
    )


def _select_cached_row(
    connection: sqlite3.Connection,
    *,
    result_id: str,
) -> sqlite3.Row | None:
    return connection.execute(
        """
        SELECT
            annotated_image_cache.blob_id,
            annotated_image_cache.cached_until,
            blobs.path,
            blobs.content_type
        FROM annotated_image_cache
        JOIN blobs ON blobs.blob_id = annotated_image_cache.blob_id
        WHERE annotated_image_cache.result_id = ?
        """,
        (result_id,),
    ).fetchone()


def _cached_row_to_result(
    row: sqlite3.Row,
    *,
    now_utc: datetime,
) -> AnnotatedImageResult | None:
    cached_until_raw = row["cached_until"]
    if not isinstance(cached_until_raw, str):
        return None
    if _parse_iso_utc(cached_until_raw) <= now_utc:
        return None

    path = Path(row["path"])
    if not path.exists():
        return None
    return AnnotatedImageResult(
        path=path,
        content_type=row["content_type"],
        cache_hit=True,
    )


def _delete_cache_entry(connection: sqlite3.Connection, *, result_id: str) -> None:
    connection.execute(
        "DELETE FROM annotated_image_cache WHERE result_id = ?",
        (result_id,),
    )


def _load_blob_bytes(
    connection: sqlite3.Connection,
    *,
    blob_id: str,
) -> tuple[bytes, str]:
    row = connection.execute(
        """
        SELECT path, content_type
        FROM blobs
        WHERE blob_id = ?
        """,
        (blob_id,),
    ).fetchone()
    if row is None:
        raise RuntimeError("blob_not_found")
    blob_path = Path(row["path"])
    if not blob_path.exists():
        raise RuntimeError("blob_bytes_not_found")
    return blob_path.read_bytes(), row["content_type"]


def _annotate_image_bytes(
    raw_bytes: bytes,
    *,
    result_id: str,
    image_id: str,
) -> tuple[bytes, str]:
    with Image.open(BytesIO(raw_bytes)) as image:
        rendered = image.convert("RGB")
        draw = ImageDraw.Draw(rendered)
        width, _ = rendered.size
        banner_height = 44
        draw.rectangle(
            ((0, 0), (width, banner_height)),
            fill=(16, 16, 16),
        )
        draw.text(
            (10, 8),
            f"Defect alert result={result_id}",
            fill=(255, 255, 255),
        )
        draw.text(
            (10, 24),
            f"image_id={image_id}",
            fill=(210, 210, 210),
        )

        output = BytesIO()
        rendered.save(output, format="JPEG", quality=90)
        return output.getvalue(), "image/jpeg"


def _store_blob(
    connection: sqlite3.Connection,
    *,
    blob_storage_dir: str,
    device_id: str,
    blob_bytes: bytes,
    content_type: str,
) -> str:
    blob_id = str(uuid.uuid4())
    storage_dir = Path(blob_storage_dir)
    storage_dir.mkdir(parents=True, exist_ok=True)
    blob_path = (storage_dir / blob_id).resolve()
    blob_path.write_bytes(blob_bytes)
    checksum = hashlib.sha256(blob_bytes).hexdigest()
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
            device_id,
            str(blob_path),
            content_type,
            len(blob_bytes),
            checksum,
            utcnow_iso(),
        ),
    )
    return blob_id


def _upsert_cache_entry(
    connection: sqlite3.Connection,
    *,
    result_id: str,
    blob_id: str,
    cache_ttl_seconds: int,
) -> None:
    cached_until = (
        datetime.now(timezone.utc) + timedelta(seconds=cache_ttl_seconds)
    ).isoformat().replace("+00:00", "Z")
    now = utcnow_iso()
    connection.execute(
        """
        INSERT INTO annotated_image_cache (
            result_id,
            blob_id,
            cached_until,
            created_at
        )
        VALUES (?, ?, ?, ?)
        ON CONFLICT(result_id) DO UPDATE SET
            blob_id = excluded.blob_id,
            cached_until = excluded.cached_until
        """,
        (
            result_id,
            blob_id,
            cached_until,
            now,
        ),
    )


def load_cached_annotated_image(
    *,
    database_path: str,
    result_id: str,
) -> AnnotatedImageResult | None:
    now_utc = datetime.now(timezone.utc)
    connection = open_connection(database_path)
    try:
        row = _select_cached_row(connection, result_id=result_id)
        if row is None:
            return None
        image_result = _cached_row_to_result(row, now_utc=now_utc)
        if image_result is not None:
            return image_result
        _delete_cache_entry(connection, result_id=result_id)
        connection.commit()
        return None
    finally:
        connection.close()


async def get_or_create_annotated_image(
    *,
    database_path: str,
    blob_storage_dir: str,
    result_id: str,
    cache_ttl_seconds: int,
    request_timeout_seconds: float,
) -> AnnotatedImageResult:
    cached = load_cached_annotated_image(database_path=database_path, result_id=result_id)
    if cached is not None:
        logger.info("notification_image_cache_hit result_id=%s", result_id)
        return cached

    connection = open_connection(database_path)
    try:
        context = load_result_image_context(connection, result_id=result_id)
    finally:
        connection.close()
    if context is None:
        raise HTTPException(status_code=404, detail="result_not_found")

    try:
        response_payload = await send_command(
            device_id=context.device_id,
            request_type="request_image",
            params={"image_id": context.image_id, "result_id": context.result_id},
            timeout_s=request_timeout_seconds,
        )
    except CommandTimeoutError as error:
        raise HTTPException(status_code=504, detail="image_request_timeout") from error
    except HTTPException as error:
        raise HTTPException(status_code=404, detail="image_unavailable") from error

    status_value = (
        response_payload.get("status") if isinstance(response_payload, dict) else None
    )
    normalized_status = str(status_value or "").strip().lower()
    if normalized_status not in {"ok", "success", "succeeded"}:
        raise HTTPException(status_code=404, detail="image_unavailable")

    response_data = (
        response_payload.get("data") if isinstance(response_payload, dict) else None
    )
    blob_id = response_data.get("blob_id") if isinstance(response_data, dict) else None
    if not isinstance(blob_id, str) or not blob_id.strip():
        raise HTTPException(status_code=404, detail="image_unavailable")

    connection = open_connection(database_path)
    try:
        connection.execute("BEGIN IMMEDIATE")
        raw_bytes, _ = _load_blob_bytes(connection, blob_id=blob_id)
        annotated_bytes, annotated_content_type = _annotate_image_bytes(
            raw_bytes,
            result_id=context.result_id,
            image_id=context.image_id,
        )
        annotated_blob_id = _store_blob(
            connection,
            blob_storage_dir=blob_storage_dir,
            device_id=context.device_id,
            blob_bytes=annotated_bytes,
            content_type=annotated_content_type,
        )
        _upsert_cache_entry(
            connection,
            result_id=context.result_id,
            blob_id=annotated_blob_id,
            cache_ttl_seconds=cache_ttl_seconds,
        )
        connection.commit()

        final_row = connection.execute(
            """
            SELECT path, content_type
            FROM blobs
            WHERE blob_id = ?
            """,
            (annotated_blob_id,),
        ).fetchone()
        if final_row is None:
            raise RuntimeError("annotated_blob_missing")
        final_path = Path(final_row["path"])
        if not final_path.exists():
            raise RuntimeError("annotated_blob_bytes_missing")
        logger.info("notification_image_cache_miss result_id=%s", result_id)
        return AnnotatedImageResult(
            path=final_path,
            content_type=final_row["content_type"],
            cache_hit=False,
        )
    except HTTPException:
        rollback_quietly(connection)
        raise
    except Exception as error:
        rollback_quietly(connection)
        logger.exception("notification_image_generation_failed result_id=%s", result_id)
        raise HTTPException(status_code=404, detail="image_unavailable") from error
    finally:
        connection.close()
