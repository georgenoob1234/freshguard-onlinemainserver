from __future__ import annotations

from dataclasses import dataclass
import sqlite3

from fastapi import Depends, Header, HTTPException

from app.config import get_settings
from app.db import get_db
from app.security import constant_time_equals, hash_token


@dataclass(frozen=True)
class Device:
    device_id: str


def extract_bearer_token(authorization: str | None) -> str:
    if authorization is None:
        raise HTTPException(status_code=401, detail="Unauthorized")
    scheme, _, token = authorization.partition(" ")
    if scheme.lower() != "bearer" or not token.strip():
        raise HTTPException(status_code=401, detail="Unauthorized")
    return token.strip()


def resolve_device_from_bearer_token(
    token: str,
    connection: sqlite3.Connection,
) -> Device:
    settings = get_settings()
    token_hash = hash_token(token, settings.secret_salt)
    row = connection.execute(
        """
        SELECT devices.device_id, device_tokens.token_hash
        FROM device_tokens
        JOIN devices ON devices.device_id = device_tokens.device_id
        WHERE device_tokens.token_hash = ?
        """,
        (token_hash,),
    ).fetchone()

    if row is None or not constant_time_equals(row["token_hash"], token_hash):
        raise HTTPException(status_code=401, detail="Unauthorized")

    return Device(device_id=row["device_id"])


def resolve_authenticated_device(
    authorization: str | None = Header(default=None, alias="Authorization"),
    connection: sqlite3.Connection = Depends(get_db),
) -> Device:
    token = extract_bearer_token(authorization)
    return resolve_device_from_bearer_token(token, connection)
