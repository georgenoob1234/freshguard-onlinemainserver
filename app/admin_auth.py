from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import logging
import sqlite3
import uuid

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHash, VerifyMismatchError, VerificationError

from app.db import open_connection


logger = logging.getLogger(__name__)
_password_hasher = PasswordHasher()


@dataclass(frozen=True)
class AdminAccount:
    admin_id: str
    username: str
    password_hash: str
    created_at: str
    updated_at: str


def normalize_admin_username(username: str) -> str:
    return username.strip().lower()


def hash_admin_password(password: str) -> str:
    return _password_hasher.hash(password)


def verify_admin_password(password_hash: str, password: str) -> bool:
    try:
        return _password_hasher.verify(password_hash, password)
    except (VerifyMismatchError, VerificationError, InvalidHash):
        return False


def get_admin_by_username(
    connection: sqlite3.Connection,
    *,
    username: str,
) -> AdminAccount | None:
    normalized_username = normalize_admin_username(username)
    if not normalized_username:
        return None
    row = connection.execute(
        """
        SELECT
            admin_id,
            username,
            password_hash,
            created_at,
            COALESCE(updated_at, created_at) AS updated_at
        FROM admin_accounts
        WHERE username = ?
        """,
        (normalized_username,),
    ).fetchone()
    if row is None:
        return None
    return AdminAccount(
        admin_id=row["admin_id"],
        username=row["username"],
        password_hash=row["password_hash"],
        created_at=row["created_at"],
        updated_at=row["updated_at"],
    )


def authenticate_admin(
    connection: sqlite3.Connection,
    *,
    username: str,
    password: str,
) -> AdminAccount | None:
    account = get_admin_by_username(connection, username=username)
    if account is None:
        return None
    if not verify_admin_password(account.password_hash, password):
        return None
    return account


def bootstrap_admin_account_if_needed(
    *,
    database_path: str,
    username: str,
    password: str,
) -> str:
    connection = open_connection(database_path)
    try:
        count_row = connection.execute(
            "SELECT COUNT(*) AS admin_count FROM admin_accounts"
        ).fetchone()
        if count_row is None:
            return "noop"
        if int(count_row["admin_count"]) > 0:
            return "already_present"
        normalized_username = normalize_admin_username(username)
        if not normalized_username or not password:
            return "missing_bootstrap_credentials"

        now = datetime.now(timezone.utc).isoformat()
        connection.execute(
            """
            INSERT INTO admin_accounts (
                admin_id,
                username,
                password_hash,
                created_at,
                updated_at
            )
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                str(uuid.uuid4()),
                normalized_username,
                hash_admin_password(password),
                now,
                now,
            ),
        )
        connection.commit()
        logger.info("Admin bootstrap account created username=%s", normalized_username)
        return "created"
    finally:
        connection.close()
