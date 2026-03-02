from __future__ import annotations

from datetime import datetime
from pathlib import Path
import sqlite3
import time

import pytest
from fastapi.testclient import TestClient

from app.main import app


@pytest.fixture()
def client_and_db(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    database_path = tmp_path / "onlinemainserver.db"
    monkeypatch.setenv("ADMIN_KEY", "admin-test-key")
    monkeypatch.setenv("SECRET_SALT", "secret-test-salt")
    monkeypatch.setenv("TGBOT_SERVICE_TOKEN", "bot-service-token")
    monkeypatch.setenv("DATABASE_PATH", str(database_path))

    with TestClient(app) as client:
        yield client, database_path


def _bot_headers(token: str = "bot-service-token") -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _ensure_payload(
    *,
    provider: str = "telegram",
    provider_user_id: str = "telegram-user-1",
    provider_chat_id: str = "telegram-chat-1",
    username: str | None = "sample_username",
    display_name: str | None = "Sample User",
) -> dict[str, str | None]:
    payload: dict[str, str | None] = {
        "provider": provider,
        "provider_user_id": provider_user_id,
        "provider_chat_id": provider_chat_id,
    }
    if username is not None:
        payload["username"] = username
    if display_name is not None:
        payload["display_name"] = display_name
    return payload


def test_bot_session_ensure_requires_valid_service_token(client_and_db):
    client, _ = client_and_db
    payload = _ensure_payload()

    missing = client.post("/bot/v1/session/ensure", json=payload)
    assert missing.status_code == 401
    assert missing.json() == {"detail": "bot_service_unauthorized"}

    invalid = client.post(
        "/bot/v1/session/ensure",
        json=payload,
        headers=_bot_headers("wrong-token"),
    )
    assert invalid.status_code == 401
    assert invalid.json() == {"detail": "bot_service_unauthorized"}


def test_bot_health_requires_auth_and_returns_ok(client_and_db):
    client, _ = client_and_db

    unauthorized = client.get("/bot/v1/health")
    assert unauthorized.status_code == 401
    assert unauthorized.json() == {"detail": "bot_service_unauthorized"}

    authorized = client.get("/bot/v1/health", headers=_bot_headers())
    assert authorized.status_code == 200
    assert authorized.json() == {"ok": True}


def test_bot_session_ensure_creates_user_and_identity(client_and_db):
    client, database_path = client_and_db
    payload = _ensure_payload(
        provider_user_id="telegram-user-create-1",
        provider_chat_id="telegram-chat-create-1",
    )

    response = client.post(
        "/bot/v1/session/ensure",
        json=payload,
        headers=_bot_headers(),
    )
    assert response.status_code == 200
    body = response.json()
    assert body["user_id"]
    assert body["is_banned"] is False
    assert body["is_linked"] is False
    assert body["active_store_id"] is None
    assert body["active_device_id"] is None

    with sqlite3.connect(database_path) as connection:
        user_row = connection.execute(
            """
            SELECT user_id, is_banned, last_seen_at
            FROM users
            WHERE user_id = ?
            """,
            (body["user_id"],),
        ).fetchone()
        identity_row = connection.execute(
            """
            SELECT provider, provider_user_id, provider_chat_id, username, display_name, user_id
            FROM user_identities
            WHERE provider = ? AND provider_user_id = ?
            """,
            (payload["provider"], payload["provider_user_id"]),
        ).fetchone()

    assert user_row is not None
    assert user_row[0] == body["user_id"]
    assert user_row[1] == 0
    assert user_row[2]

    assert identity_row is not None
    assert identity_row[0] == "telegram"
    assert identity_row[1] == payload["provider_user_id"]
    assert identity_row[2] == payload["provider_chat_id"]
    assert identity_row[3] == payload["username"]
    assert identity_row[4] == payload["display_name"]
    assert identity_row[5] == body["user_id"]


def test_bot_session_ensure_updates_chat_id_when_changed(client_and_db):
    client, database_path = client_and_db
    provider_user_id = "telegram-user-chat-update-1"

    first = client.post(
        "/bot/v1/session/ensure",
        json=_ensure_payload(
            provider_user_id=provider_user_id,
            provider_chat_id="telegram-chat-old-1",
        ),
        headers=_bot_headers(),
    )
    assert first.status_code == 200

    second = client.post(
        "/bot/v1/session/ensure",
        json=_ensure_payload(
            provider_user_id=provider_user_id,
            provider_chat_id="telegram-chat-new-1",
            username=None,
            display_name=None,
        ),
        headers=_bot_headers(),
    )
    assert second.status_code == 200

    with sqlite3.connect(database_path) as connection:
        row = connection.execute(
            """
            SELECT provider_chat_id
            FROM user_identities
            WHERE provider = ? AND provider_user_id = ?
            """,
            ("telegram", provider_user_id),
        ).fetchone()

    assert row is not None
    assert row[0] == "telegram-chat-new-1"


def test_bot_session_ensure_updates_last_seen(client_and_db):
    client, database_path = client_and_db
    payload = _ensure_payload(provider_user_id="telegram-user-last-seen-1")

    first = client.post("/bot/v1/session/ensure", json=payload, headers=_bot_headers())
    assert first.status_code == 200
    user_id = first.json()["user_id"]

    with sqlite3.connect(database_path) as connection:
        first_seen = connection.execute(
            "SELECT last_seen_at FROM users WHERE user_id = ?",
            (user_id,),
        ).fetchone()[0]

    time.sleep(0.02)
    second = client.post("/bot/v1/session/ensure", json=payload, headers=_bot_headers())
    assert second.status_code == 200

    with sqlite3.connect(database_path) as connection:
        second_seen = connection.execute(
            "SELECT last_seen_at FROM users WHERE user_id = ?",
            (user_id,),
        ).fetchone()[0]

    assert datetime.fromisoformat(second_seen) > datetime.fromisoformat(first_seen)


def test_bot_session_ensure_rejects_unsupported_provider(client_and_db):
    client, _ = client_and_db
    payload = _ensure_payload(provider="discord")

    response = client.post(
        "/bot/v1/session/ensure",
        json=payload,
        headers=_bot_headers(),
    )
    assert response.status_code == 400
    assert response.json() == {"detail": "unsupported_provider"}


def test_bot_session_ensure_returns_banned_user_with_200(client_and_db):
    client, database_path = client_and_db
    payload = _ensure_payload(provider_user_id="telegram-user-banned-1")

    first = client.post("/bot/v1/session/ensure", json=payload, headers=_bot_headers())
    assert first.status_code == 200
    user_id = first.json()["user_id"]

    with sqlite3.connect(database_path) as connection:
        connection.execute(
            "UPDATE users SET is_banned = 1 WHERE user_id = ?",
            (user_id,),
        )
        connection.commit()

    banned_response = client.post(
        "/bot/v1/session/ensure",
        json=payload,
        headers=_bot_headers(),
    )
    assert banned_response.status_code == 200
    assert banned_response.json()["is_banned"] is True
