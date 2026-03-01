from __future__ import annotations

import hashlib
import hmac
import secrets


TOKEN_ENTROPY_BYTES = 48


def generate_token() -> str:
    return secrets.token_urlsafe(TOKEN_ENTROPY_BYTES)


def hash_token(token: str, salt: str) -> str:
    payload = f"{token}{salt}".encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def constant_time_equals(left: str, right: str) -> bool:
    return hmac.compare_digest(left, right)
