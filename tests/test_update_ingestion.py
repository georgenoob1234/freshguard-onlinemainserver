from __future__ import annotations

import sqlite3
from pathlib import Path

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


def _create_enroll_token(client: TestClient) -> str:
    response = client.post(
        "/admin/v1/enroll_tokens",
        json={
            "store_id": "store-a",
            "expires_in_sec": 600,
            "max_uses": 1,
            "note": "connector pairing",
        },
        headers={"X-ADMIN-KEY": "admin-test-key"},
    )
    assert response.status_code == 200
    return response.json()["enroll_token"]


def _register_device(client: TestClient) -> tuple[str, str]:
    enroll_token = _create_enroll_token(client)
    response = client.post(
        "/connector/v1/register",
        json={
            "enroll_token": enroll_token,
            "device_info": {
                "label": "Kitchen Display",
                "hostname": "kiosk-01",
                "os": "linux",
                "connector_version": "1.0.0",
            },
        },
    )
    assert response.status_code == 200
    body = response.json()
    return body["device_id"], body["device_token"]


def _valid_update_payload(image_id: str) -> dict:
    return {
        "envelope_version": "v1",
        "sent_at": "2026-03-01T23:40:00Z",
        "image_id": image_id,
        "scan_result": {
            "session_id": "session-1",
            "image_id": image_id,
            "timestamp": "2026-03-01T23:39:59Z",
            "weight_grams": 120.5,
            "fruits": [{"name": "apple", "weight_grams": 120.5}],
            "future_extra_field": {"allowed": True},
        },
    }


def test_update_unauthorized_for_missing_or_invalid_bearer_token(client_and_db):
    client, _ = client_and_db
    payload = _valid_update_payload("image-unauthorized-1")

    missing_token = client.post("/update", json=payload)
    assert missing_token.status_code == 401

    invalid_token = client.post(
        "/update",
        json=payload,
        headers={"Authorization": "Bearer invalid-device-token"},
    )
    assert invalid_token.status_code == 401


def test_update_valid_request_inserts_row(client_and_db):
    client, database_path = client_and_db
    device_id, device_token = _register_device(client)
    payload = _valid_update_payload("image-insert-1")

    response = client.post(
        "/update",
        json=payload,
        headers={
            "Authorization": f"Bearer {device_token}",
            "Idempotency-Key": payload["image_id"],
        },
    )
    assert response.status_code == 200
    assert response.json() == {"status": "ok", "duplicate": False}

    with sqlite3.connect(database_path) as connection:
        count = connection.execute(
            """
            SELECT COUNT(*)
            FROM scan_results
            WHERE device_id = ? AND image_id = ?
            """,
            (device_id, payload["image_id"]),
        ).fetchone()[0]
    assert count == 1


def test_update_duplicate_request_returns_duplicate_true(client_and_db):
    client, database_path = client_and_db
    device_id, device_token = _register_device(client)
    payload = _valid_update_payload("image-duplicate-1")
    headers = {"Authorization": f"Bearer {device_token}"}

    first = client.post("/update", json=payload, headers=headers)
    second = client.post("/update", json=payload, headers=headers)

    assert first.status_code == 200
    assert first.json() == {"status": "ok", "duplicate": False}
    assert second.status_code == 409
    assert second.json() == {"status": "ok", "duplicate": True}

    with sqlite3.connect(database_path) as connection:
        count = connection.execute(
            """
            SELECT COUNT(*)
            FROM scan_results
            WHERE device_id = ? AND image_id = ?
            """,
            (device_id, payload["image_id"]),
        ).fetchone()[0]
    assert count == 1


def test_update_rejects_image_id_mismatch(client_and_db):
    client, _ = client_and_db
    _, device_token = _register_device(client)
    payload = _valid_update_payload("image-envelope-1")
    payload["scan_result"]["image_id"] = "image-inner-different"

    response = client.post(
        "/update",
        json=payload,
        headers={"Authorization": f"Bearer {device_token}"},
    )
    assert response.status_code == 400
    assert "mismatch" in response.json()["detail"]


def test_update_rejects_legacy_scan_id_contract(client_and_db):
    client, _ = client_and_db
    _, device_token = _register_device(client)
    legacy_payload = {
        "envelope_version": "v1",
        "sent_at": "2026-03-01T23:40:00Z",
        "scan_id": "legacy-scan-id-1",
        "scan_result": {
            "session_id": "session-1",
            "scan_id": "legacy-scan-id-1",
            "timestamp": "2026-03-01T23:39:59Z",
            "weight_grams": 120.5,
            "fruits": [],
        },
    }

    response = client.post(
        "/update",
        json=legacy_payload,
        headers={"Authorization": f"Bearer {device_token}"},
    )
    assert response.status_code == 400


def test_update_logs_do_not_include_bearer_token(client_and_db, caplog: pytest.LogCaptureFixture):
    client, _ = client_and_db
    _, device_token = _register_device(client)
    payload = _valid_update_payload("image-logging-1")
    caplog.set_level("INFO", logger="app.api.update")

    response = client.post(
        "/update",
        json=payload,
        headers={"Authorization": f"Bearer {device_token}"},
    )
    assert response.status_code == 200
    assert device_token not in caplog.text
