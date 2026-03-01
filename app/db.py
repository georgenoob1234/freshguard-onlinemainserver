from __future__ import annotations

from pathlib import Path
import sqlite3
from typing import Iterator

from app.config import get_settings


def _ensure_database_directory(database_path: str) -> None:
    db_file = Path(database_path)
    if db_file.parent and str(db_file.parent) not in {"", "."}:
        db_file.parent.mkdir(parents=True, exist_ok=True)


def open_connection(database_path: str) -> sqlite3.Connection:
    _ensure_database_directory(database_path)
    connection = sqlite3.connect(database_path, timeout=10)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


def _get_table_columns(connection: sqlite3.Connection, table_name: str) -> set[str]:
    rows = connection.execute(f"PRAGMA table_info({table_name})").fetchall()
    return {row["name"] for row in rows}


def _migrate_scan_results_scan_id_to_image_id(connection: sqlite3.Connection) -> None:
    columns = _get_table_columns(connection, "scan_results")
    if not columns or "scan_id" not in columns:
        return

    if "image_id" in columns:
        image_id_expr = "COALESCE(image_id, scan_id)"
    else:
        image_id_expr = "scan_id"

    connection.executescript(
        f"""
        CREATE TABLE IF NOT EXISTS scan_results_v2 (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            device_id TEXT NOT NULL,
            image_id TEXT NOT NULL,
            received_at TEXT NOT NULL,
            sent_at TEXT NULL,
            scan_result_json TEXT NOT NULL,
            FOREIGN KEY(device_id) REFERENCES devices(device_id) ON DELETE CASCADE,
            UNIQUE(device_id, image_id)
        );

        INSERT INTO scan_results_v2 (
            id,
            device_id,
            image_id,
            received_at,
            sent_at,
            scan_result_json
        )
        SELECT
            id,
            device_id,
            {image_id_expr},
            received_at,
            sent_at,
            scan_result_json
        FROM scan_results;

        DROP TABLE scan_results;
        ALTER TABLE scan_results_v2 RENAME TO scan_results;
        """
    )


def init_db(database_path: str) -> None:
    connection = open_connection(database_path)
    try:
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS enroll_tokens (
                token_id TEXT PRIMARY KEY,
                token_hash TEXT NOT NULL UNIQUE,
                store_id TEXT NULL,
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                max_uses INTEGER NOT NULL,
                uses INTEGER NOT NULL DEFAULT 0,
                note TEXT NULL
            );

            CREATE TABLE IF NOT EXISTS devices (
                device_id TEXT PRIMARY KEY,
                store_id TEXT NULL,
                created_at TEXT NOT NULL,
                label TEXT NULL,
                hostname TEXT NULL,
                os TEXT NULL,
                connector_version TEXT NULL
            );

            CREATE TABLE IF NOT EXISTS device_tokens (
                device_id TEXT PRIMARY KEY,
                token_hash TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY(device_id) REFERENCES devices(device_id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS scan_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                device_id TEXT NOT NULL,
                image_id TEXT NOT NULL,
                received_at TEXT NOT NULL,
                sent_at TEXT NULL,
                scan_result_json TEXT NOT NULL,
                FOREIGN KEY(device_id) REFERENCES devices(device_id) ON DELETE CASCADE,
                UNIQUE(device_id, image_id)
            );

            CREATE TABLE IF NOT EXISTS blobs (
                blob_id TEXT PRIMARY KEY,
                device_id TEXT NOT NULL,
                path TEXT NOT NULL,
                content_type TEXT NOT NULL,
                size_bytes INTEGER NOT NULL,
                sha256 TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY(device_id) REFERENCES devices(device_id) ON DELETE CASCADE
            );
            """
        )
        _migrate_scan_results_scan_id_to_image_id(connection)
        connection.commit()
    finally:
        connection.close()


def get_db() -> Iterator[sqlite3.Connection]:
    settings = get_settings()
    connection = open_connection(settings.database_path)
    try:
        yield connection
    finally:
        connection.close()
