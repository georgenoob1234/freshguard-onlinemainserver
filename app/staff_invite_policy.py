from __future__ import annotations

from datetime import datetime, timezone
import secrets
import sqlite3

from fastapi import HTTPException

from app.roles import is_known_role
from app.security import hash_token


ALLOWED_STAFF_INVITE_ROLES = frozenset({"operator", "viewer"})
INVITE_CODE_DIGITS = 6
MAX_INVITE_CODE_GENERATION_ATTEMPTS = 32


def _parse_iso_datetime(raw_value: str | None) -> datetime | None:
    if raw_value is None:
        return None
    parsed = datetime.fromisoformat(raw_value)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def normalize_staff_invite_role(role_name: str) -> str:
    normalized = role_name.strip().lower()
    if not is_known_role(normalized):
        raise HTTPException(status_code=400, detail="unknown_role")
    if normalized not in ALLOWED_STAFF_INVITE_ROLES:
        raise HTTPException(status_code=400, detail="invalid_invite_role")
    return normalized


def _is_active_collision(row: sqlite3.Row, *, now_utc: datetime) -> bool:
    if row["revoked_at"] is not None:
        return False

    max_uses = row["max_uses"]
    if max_uses is not None and int(row["used_count"]) >= int(max_uses):
        return False

    expires_at = _parse_iso_datetime(row["expires_at"])
    if expires_at is not None and expires_at <= now_utc:
        return False

    return True


def generate_unique_staff_invite_code(
    connection: sqlite3.Connection,
    *,
    secret_salt: str,
    now_utc: datetime,
) -> tuple[str, str]:
    for _ in range(MAX_INVITE_CODE_GENERATION_ATTEMPTS):
        invite_code = f"{secrets.randbelow(10**INVITE_CODE_DIGITS):0{INVITE_CODE_DIGITS}d}"
        code_hash = hash_token(invite_code, secret_salt)
        prior_rows = connection.execute(
            """
            SELECT expires_at, max_uses, used_count, revoked_at
            FROM staff_invites
            WHERE code_hash = ?
            """,
            (code_hash,),
        ).fetchall()
        has_active_collision = any(
            _is_active_collision(row, now_utc=now_utc)
            for row in prior_rows
        )
        if not has_active_collision:
            return invite_code, code_hash

    raise HTTPException(status_code=500, detail="invite_code_generation_failed")
