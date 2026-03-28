from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import json
import secrets
import sqlite3
from urllib.parse import parse_qsl
import uuid

from fastapi import HTTPException

from app.roles import is_permission_granted
from app.security import hash_token


@dataclass(frozen=True)
class TelegramMiniAppIdentity:
    provider_user_id: str
    username: str | None
    display_name: str | None


@dataclass(frozen=True)
class TelegramAdminUser:
    user_id: str
    display_name: str


@dataclass(frozen=True)
class LoginChallengeResult:
    challenge_id: str
    nonce: str
    expires_at: str


@dataclass(frozen=True)
class CompletionTokenResult:
    token: str
    expires_at: str
    user_id: str
    display_name: str


def _parse_iso_datetime(raw_value: str) -> datetime:
    parsed = datetime.fromisoformat(raw_value)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def verify_telegram_webapp_init_data(
    *,
    init_data: str,
    bot_token: str,
    max_age_seconds: int,
) -> TelegramMiniAppIdentity:
    if not bot_token:
        raise HTTPException(status_code=503, detail="telegram_auth_not_configured")

    parsed_pairs = parse_qsl(init_data, keep_blank_values=True)
    payload = dict(parsed_pairs)
    raw_hash = payload.pop("hash", "").strip()
    if not raw_hash:
        raise HTTPException(status_code=400, detail="invalid_telegram_init_data")

    data_check_string = "\n".join(
        f"{key}={value}"
        for key, value in sorted(payload.items(), key=lambda item: item[0])
    )
    secret_key = hmac.new(
        b"WebAppData",
        bot_token.encode("utf-8"),
        hashlib.sha256,
    ).digest()
    expected_hash = hmac.new(
        secret_key,
        data_check_string.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    if not hmac.compare_digest(expected_hash, raw_hash):
        raise HTTPException(status_code=401, detail="invalid_telegram_init_data")

    auth_date_raw = payload.get("auth_date", "").strip()
    if not auth_date_raw.isdigit():
        raise HTTPException(status_code=400, detail="invalid_telegram_init_data")
    auth_date = datetime.fromtimestamp(int(auth_date_raw), tz=timezone.utc)
    age_seconds = (_utcnow() - auth_date).total_seconds()
    if age_seconds < 0 or age_seconds > max_age_seconds:
        raise HTTPException(status_code=401, detail="stale_telegram_init_data")

    user_raw = payload.get("user")
    if not isinstance(user_raw, str):
        raise HTTPException(status_code=400, detail="invalid_telegram_init_data")
    try:
        user_payload = json.loads(user_raw)
    except json.JSONDecodeError as error:
        raise HTTPException(status_code=400, detail="invalid_telegram_init_data") from error

    user_id = user_payload.get("id")
    if not isinstance(user_id, int):
        raise HTTPException(status_code=400, detail="invalid_telegram_init_data")

    username = user_payload.get("username")
    display_name_parts = [
        user_payload.get("first_name") if isinstance(user_payload.get("first_name"), str) else "",
        user_payload.get("last_name") if isinstance(user_payload.get("last_name"), str) else "",
    ]
    display_name = " ".join(part.strip() for part in display_name_parts if part and part.strip()).strip()
    return TelegramMiniAppIdentity(
        provider_user_id=str(user_id),
        username=username.strip() if isinstance(username, str) and username.strip() else None,
        display_name=display_name or None,
    )


def _resolve_linked_admin_user(
    connection: sqlite3.Connection,
    *,
    provider_user_id: str,
) -> TelegramAdminUser:
    row = connection.execute(
        """
        SELECT
            users.user_id,
            users.is_banned,
            user_identities.username,
            user_identities.display_name
        FROM user_identities
        JOIN users ON users.user_id = user_identities.user_id
        WHERE user_identities.provider = 'telegram' AND user_identities.provider_user_id = ?
        """,
        (provider_user_id,),
    ).fetchone()
    if row is None:
        raise HTTPException(status_code=403, detail="telegram_identity_not_linked")
    if int(row["is_banned"]) == 1:
        raise HTTPException(status_code=403, detail="user_banned")

    roles = connection.execute(
        """
        SELECT role
        FROM store_memberships
        WHERE user_id = ? AND revoked_at IS NULL
        """,
        (row["user_id"],),
    ).fetchall()
    if not roles:
        raise HTTPException(status_code=403, detail="admin_ui_access_required")
    if not any(is_permission_granted(role_row["role"], "admin_ui.access") for role_row in roles):
        raise HTTPException(status_code=403, detail="admin_ui_access_required")

    display_name = row["display_name"] or row["username"] or row["user_id"]
    return TelegramAdminUser(
        user_id=row["user_id"],
        display_name=display_name,
    )


def create_browser_login_challenge(
    connection: sqlite3.Connection,
    *,
    challenge_ttl_seconds: int,
) -> LoginChallengeResult:
    now = _utcnow()
    expires_at = now + timedelta(seconds=challenge_ttl_seconds)
    challenge_id = str(uuid.uuid4())
    nonce = secrets.token_urlsafe(24)
    connection.execute(
        """
        INSERT INTO telegram_admin_login_challenges (
            challenge_id,
            nonce,
            created_at,
            expires_at,
            status,
            claimed_user_id,
            claimed_provider_user_id,
            claimed_at,
            completed_at
        )
        VALUES (?, ?, ?, ?, 'pending', NULL, NULL, NULL, NULL)
        """,
        (challenge_id, nonce, now.isoformat(), expires_at.isoformat()),
    )
    connection.commit()
    return LoginChallengeResult(
        challenge_id=challenge_id,
        nonce=nonce,
        expires_at=expires_at.isoformat(),
    )


def claim_browser_login_challenge(
    connection: sqlite3.Connection,
    *,
    nonce: str,
    provider_user_id: str,
    secret_salt: str,
    token_ttl_seconds: int,
) -> CompletionTokenResult:
    now = _utcnow()
    linked_user = _resolve_linked_admin_user(
        connection,
        provider_user_id=provider_user_id,
    )
    challenge_row = connection.execute(
        """
        SELECT challenge_id, status, expires_at
        FROM telegram_admin_login_challenges
        WHERE nonce = ?
        """,
        (nonce,),
    ).fetchone()
    if challenge_row is None:
        raise HTTPException(status_code=404, detail="login_challenge_not_found")
    if _parse_iso_datetime(challenge_row["expires_at"]) <= now:
        raise HTTPException(status_code=400, detail="login_challenge_expired")
    if challenge_row["status"] != "pending":
        raise HTTPException(status_code=409, detail="login_challenge_already_claimed")

    token = secrets.token_urlsafe(32)
    token_hash = hash_token(token, secret_salt)
    expires_at = now + timedelta(seconds=token_ttl_seconds)
    token_id = str(uuid.uuid4())
    try:
        connection.execute("BEGIN IMMEDIATE")
        connection.execute(
            """
            UPDATE telegram_admin_login_challenges
            SET status = 'claimed',
                claimed_user_id = ?,
                claimed_provider_user_id = ?,
                claimed_at = ?
            WHERE challenge_id = ? AND status = 'pending'
            """,
            (
                linked_user.user_id,
                provider_user_id,
                now.isoformat(),
                challenge_row["challenge_id"],
            ),
        )
        connection.execute(
            """
            INSERT INTO telegram_admin_login_completion_tokens (
                token_id,
                challenge_id,
                token_hash,
                created_at,
                expires_at,
                used_at
            )
            VALUES (?, ?, ?, ?, ?, NULL)
            """,
            (
                token_id,
                challenge_row["challenge_id"],
                token_hash,
                now.isoformat(),
                expires_at.isoformat(),
            ),
        )
        connection.commit()
    except Exception as error:
        connection.execute("ROLLBACK")
        raise HTTPException(status_code=500, detail="login_claim_failed") from error

    return CompletionTokenResult(
        token=token,
        expires_at=expires_at.isoformat(),
        user_id=linked_user.user_id,
        display_name=linked_user.display_name,
    )


def consume_browser_login_token(
    connection: sqlite3.Connection,
    *,
    token: str,
    secret_salt: str,
) -> TelegramAdminUser:
    token_hash = hash_token(token, secret_salt)
    now = _utcnow()
    try:
        connection.execute("BEGIN IMMEDIATE")
        row = connection.execute(
            """
            SELECT
                telegram_admin_login_completion_tokens.token_id,
                telegram_admin_login_completion_tokens.expires_at AS token_expires_at,
                telegram_admin_login_completion_tokens.used_at,
                telegram_admin_login_challenges.challenge_id,
                telegram_admin_login_challenges.claimed_user_id,
                telegram_admin_login_challenges.claimed_provider_user_id,
                telegram_admin_login_challenges.status
            FROM telegram_admin_login_completion_tokens
            JOIN telegram_admin_login_challenges
              ON telegram_admin_login_challenges.challenge_id = telegram_admin_login_completion_tokens.challenge_id
            WHERE telegram_admin_login_completion_tokens.token_hash = ?
            """,
            (token_hash,),
        ).fetchone()
        if row is None:
            raise HTTPException(status_code=404, detail="login_token_not_found")
        if row["used_at"] is not None:
            raise HTTPException(status_code=409, detail="login_token_already_used")
        if _parse_iso_datetime(row["token_expires_at"]) <= now:
            raise HTTPException(status_code=400, detail="login_token_expired")
        if row["status"] != "claimed" or row["claimed_user_id"] is None:
            raise HTTPException(status_code=400, detail="login_token_invalid_state")

        linked_user = _resolve_linked_admin_user(
            connection,
            provider_user_id=row["claimed_provider_user_id"],
        )
        if linked_user.user_id != row["claimed_user_id"]:
            raise HTTPException(status_code=400, detail="login_token_invalid_state")

        connection.execute(
            """
            UPDATE telegram_admin_login_completion_tokens
            SET used_at = ?
            WHERE token_id = ? AND used_at IS NULL
            """,
            (now.isoformat(), row["token_id"]),
        )
        connection.execute(
            """
            UPDATE telegram_admin_login_challenges
            SET status = 'completed',
                completed_at = ?
            WHERE challenge_id = ?
            """,
            (now.isoformat(), row["challenge_id"]),
        )
        connection.commit()
    except HTTPException:
        connection.execute("ROLLBACK")
        raise
    except Exception as error:
        connection.execute("ROLLBACK")
        raise HTTPException(status_code=500, detail="login_token_consume_failed") from error

    return linked_user


def resolve_linked_user_for_mini_app(
    connection: sqlite3.Connection,
    *,
    provider_user_id: str,
) -> TelegramAdminUser:
    return _resolve_linked_admin_user(connection, provider_user_id=provider_user_id)
