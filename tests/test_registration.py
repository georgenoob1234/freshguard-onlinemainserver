from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
import sqlite3

import pytest
from fastapi.testclient import TestClient

from app.main import app


@pytest.fixture()
def client_and_db(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    database_path = tmp_path / "onlinemainserver.db"
    monkeypatch.setenv("ADMIN_KEY", "admin-test-key")
    monkeypatch.setenv("SECRET_SALT", "secret-test-salt")
    monkeypatch.setenv("DATABASE_PATH", str(database_path))

    with TestClient(app) as client:
        yield client, database_path


def _create_enroll_token(
    client: TestClient,
    *,
    expires_in_sec: int = 600,
    max_uses: int = 1,
    store_id: str | None = None,
    note: str | None = None,
) -> str:
    response = client.post(
        "/admin/v1/enroll_tokens",
        json={
            "store_id": store_id,
            "expires_in_sec": expires_in_sec,
            "max_uses": max_uses,
            "note": note,
        },
        headers={"X-ADMIN-KEY": "admin-test-key"},
    )
    assert response.status_code == 200
    return response.json()["enroll_token"]


def _register_payload(enroll_token: str) -> dict:
    return {
        "enroll_token": enroll_token,
        "device_info": {
            "label": "Kitchen Display",
            "hostname": "kiosk-01",
            "os": "linux",
            "connector_version": "1.0.0",
        },
    }


def test_create_enroll_token_works_and_fails_without_valid_admin_key(client_and_db):
    client, _ = client_and_db

    success = client.post(
        "/admin/v1/enroll_tokens",
        json={
            "store_id": "store-a",
            "expires_in_sec": 600,
            "max_uses": 1,
            "note": "first connector",
        },
        headers={"X-ADMIN-KEY": "admin-test-key"},
    )
    assert success.status_code == 200
    body = success.json()
    assert "enroll_token" in body
    assert "token_id" in body
    assert "expires_at" in body
    assert body["max_uses"] == 1

    forbidden = client.post(
        "/admin/v1/enroll_tokens",
        json={
            "store_id": "store-a",
            "expires_in_sec": 600,
            "max_uses": 1,
            "note": None,
        },
        headers={"X-ADMIN-KEY": "wrong-key"},
    )
    assert forbidden.status_code == 401


def test_register_succeeds_with_valid_token(client_and_db):
    client, _ = client_and_db
    enroll_token = _create_enroll_token(client)

    response = client.post("/connector/v1/register", json=_register_payload(enroll_token))
    assert response.status_code == 200
    body = response.json()
    assert body["device_id"]
    assert body["device_token"]
    assert body["ws_url"] is None


def test_register_fails_token_invalid(client_and_db):
    client, _ = client_and_db

    response = client.post("/connector/v1/register", json=_register_payload("invalid-token"))
    assert response.status_code == 400
    assert response.json()["error_code"] == "TOKEN_INVALID"


def test_register_fails_token_expired(client_and_db):
    client, database_path = client_and_db
    enroll_token = _create_enroll_token(client)

    expired_time = (datetime.now(timezone.utc) - timedelta(seconds=10)).isoformat()
    with sqlite3.connect(database_path) as connection:
        connection.execute("UPDATE enroll_tokens SET expires_at = ?", (expired_time,))
        connection.commit()

    response = client.post("/connector/v1/register", json=_register_payload(enroll_token))
    assert response.status_code == 400
    assert response.json()["error_code"] == "TOKEN_EXPIRED"


def test_register_fails_token_used_up(client_and_db):
    client, _ = client_and_db
    enroll_token = _create_enroll_token(client, max_uses=1)

    first = client.post("/connector/v1/register", json=_register_payload(enroll_token))
    assert first.status_code == 200

    second = client.post("/connector/v1/register", json=_register_payload(enroll_token))
    assert second.status_code == 400
    assert second.json()["error_code"] == "TOKEN_USED_UP"
