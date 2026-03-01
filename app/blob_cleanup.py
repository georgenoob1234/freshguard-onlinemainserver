from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
import logging
from pathlib import Path

from app.db import open_connection


logger = logging.getLogger(__name__)


def cleanup_expired_blobs_once(
    database_path: str,
    retention_s: float,
    *,
    now: datetime | None = None,
) -> int:
    cutoff = (now or datetime.now(timezone.utc)) - timedelta(seconds=retention_s)
    cutoff_iso = cutoff.isoformat()

    connection = open_connection(database_path)
    try:
        expired_rows = connection.execute(
            """
            SELECT blob_id, path
            FROM blobs
            WHERE created_at < ?
            """,
            (cutoff_iso,),
        ).fetchall()
        if not expired_rows:
            return 0

        blob_ids: list[str] = []
        for row in expired_rows:
            blob_id = row["blob_id"]
            blob_path = Path(row["path"])
            blob_ids.append(blob_id)
            try:
                blob_path.unlink(missing_ok=True)
            except Exception:
                logger.warning(
                    "Failed to delete blob bytes blob_id=%s path=%s",
                    blob_id,
                    blob_path,
                    exc_info=True,
                )

        placeholders = ", ".join("?" for _ in blob_ids)
        connection.execute(
            f"DELETE FROM blobs WHERE blob_id IN ({placeholders})",
            blob_ids,
        )
        connection.commit()
        return len(blob_ids)
    finally:
        connection.close()


async def run_blob_cleanup_loop(
    database_path: str,
    interval_s: float,
    retention_s: float,
) -> None:
    while True:
        try:
            deleted_count = cleanup_expired_blobs_once(
                database_path=database_path,
                retention_s=retention_s,
            )
            if deleted_count > 0:
                logger.info("Blob cleanup deleted_count=%s", deleted_count)
            await asyncio.sleep(interval_s)
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception("Blob cleanup loop iteration failed")
