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


def rollback_quietly(connection: sqlite3.Connection) -> None:
    try:
        connection.execute("ROLLBACK")
    except sqlite3.OperationalError:
        pass


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


def _migrate_devices_presence_columns(connection: sqlite3.Connection) -> None:
    columns = _get_table_columns(connection, "devices")
    if not columns:
        return

    has_legacy_last_seen = "last_seen_ts" in columns
    if "last_seen_at" not in columns:
        connection.execute("ALTER TABLE devices ADD COLUMN last_seen_at TEXT NULL")
        if has_legacy_last_seen:
            connection.execute(
                """
                UPDATE devices
                SET last_seen_at = last_seen_ts
                WHERE last_seen_at IS NULL AND last_seen_ts IS NOT NULL
                """
            )

    if "connected_at" not in columns:
        connection.execute("ALTER TABLE devices ADD COLUMN connected_at TEXT NULL")


def _migrate_stores_columns(connection: sqlite3.Connection) -> None:
    columns = _get_table_columns(connection, "stores")
    if not columns:
        return

    if "display_name" not in columns:
        connection.execute("ALTER TABLE stores ADD COLUMN display_name TEXT NULL")
    if "name" not in columns:
        connection.execute("ALTER TABLE stores ADD COLUMN name TEXT NULL")
    if "updated_at" not in columns:
        connection.execute("ALTER TABLE stores ADD COLUMN updated_at TEXT NULL")

    refreshed_columns = _get_table_columns(connection, "stores")
    has_name = "name" in refreshed_columns
    has_display_name = "display_name" in refreshed_columns

    if has_display_name and has_name:
        connection.execute(
            """
            UPDATE stores
            SET display_name = COALESCE(
                NULLIF(TRIM(display_name), ''),
                NULLIF(TRIM(name), ''),
                store_id
            )
            WHERE display_name IS NULL OR TRIM(display_name) = ''
            """
        )
        connection.execute(
            """
            UPDATE stores
            SET name = display_name
            WHERE (name IS NULL OR TRIM(name) = '') AND display_name IS NOT NULL
            """
        )
    elif has_display_name:
        connection.execute(
            """
            UPDATE stores
            SET display_name = COALESCE(NULLIF(TRIM(display_name), ''), store_id)
            WHERE display_name IS NULL OR TRIM(display_name) = ''
            """
        )

    if "updated_at" in refreshed_columns:
        connection.execute(
            """
            UPDATE stores
            SET updated_at = COALESCE(updated_at, created_at)
            WHERE updated_at IS NULL
            """
        )


def init_db(database_path: str) -> None:
    connection = open_connection(database_path)
    try:
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS stores (
                store_id TEXT PRIMARY KEY,
                display_name TEXT NULL,
                name TEXT NULL,
                address TEXT NULL,
                is_active INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL,
                updated_at TEXT NULL
            );

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
                connector_version TEXT NULL,
                last_seen_at TEXT NULL,
                connected_at TEXT NULL
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

            CREATE TABLE IF NOT EXISTS users (
                user_id TEXT PRIMARY KEY,
                is_banned INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL,
                last_seen_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS user_identities (
                provider TEXT NOT NULL,
                provider_user_id TEXT NOT NULL,
                provider_chat_id TEXT NOT NULL,
                username TEXT NULL,
                display_name TEXT NULL,
                user_id TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                PRIMARY KEY (provider, provider_user_id),
                FOREIGN KEY(user_id) REFERENCES users(user_id) ON DELETE CASCADE
            );

            CREATE INDEX IF NOT EXISTS idx_user_identities_user_id
            ON user_identities(user_id);

            CREATE TABLE IF NOT EXISTS user_context (
                user_id TEXT PRIMARY KEY,
                active_store_id TEXT NULL,
                active_device_id TEXT NULL,
                updated_at TEXT NOT NULL,
                FOREIGN KEY(user_id) REFERENCES users(user_id) ON DELETE CASCADE
            );
            """
        )
        _migrate_scan_results_scan_id_to_image_id(connection)
        _migrate_devices_presence_columns(connection)
        _migrate_stores_columns(connection)
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
