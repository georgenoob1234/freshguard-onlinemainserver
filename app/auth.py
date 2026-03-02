from __future__ import annotations

from dataclasses import dataclass
import logging
import sqlite3

from fastapi import Depends, Header, HTTPException

from app.config import get_settings
from app.db import get_db
from app.security import constant_time_equals, hash_token


logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class Device:
    device_id: str


@dataclass(frozen=True)
class BotService:
    name: str = "tgbot"


def extract_bearer_token(authorization: str | None) -> str:
    if authorization is None:
        raise HTTPException(status_code=401, detail="Unauthorized")
    scheme, _, token = authorization.partition(" ")
    if scheme.lower() != "bearer" or not token.strip():
        raise HTTPException(status_code=401, detail="Unauthorized")
    return token.strip()


def _raise_bot_service_unauthorized(reason: str) -> None:
    logger.warning("Bot auth failed reason=%s", reason)
    raise HTTPException(status_code=401, detail="bot_service_unauthorized")


def resolve_device_from_bearer_token(
    token: str,
    connection: sqlite3.Connection,
) -> Device:
    settings = get_settings()
    token_hash = hash_token(token, settings.secret_salt)
    row = connection.execute(
        """
        SELECT devices.device_id
        FROM device_tokens
        JOIN devices ON devices.device_id = device_tokens.device_id
        WHERE device_tokens.token_hash = ?
        """,
        (token_hash,),
    ).fetchone()

    if row is None:
        raise HTTPException(status_code=401, detail="Unauthorized")

    return Device(device_id=row["device_id"])


def resolve_authenticated_device(
    authorization: str | None = Header(default=None, alias="Authorization"),
    connection: sqlite3.Connection = Depends(get_db),
) -> Device:
    token = extract_bearer_token(authorization)
    return resolve_device_from_bearer_token(token, connection)


def resolve_authenticated_bot_service(
    authorization: str | None = Header(default=None, alias="Authorization"),
) -> BotService:
    settings = get_settings()
    if not settings.tgbot_service_token:
        _raise_bot_service_unauthorized("service_token_not_configured")

    if authorization is None:
        _raise_bot_service_unauthorized("missing_authorization_header")

    scheme, _, token = authorization.partition(" ")
    if scheme.lower() != "bearer" or not token.strip():
        _raise_bot_service_unauthorized("invalid_bearer_header")

    if not constant_time_equals(token.strip(), settings.tgbot_service_token):
        _raise_bot_service_unauthorized("token_mismatch")

    return BotService()
