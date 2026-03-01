from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
import sqlite3
import time
import uuid

import pytest
from fastapi.testclient import TestClient

from app.device_status import compute_online, parse_db_utc_datetime
from app.main import app
from app.realtime import connection_manager


@pytest.fixture()
def client_and_db(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    database_path = tmp_path / "onlinemainserver.db"
    blob_storage_path = tmp_path / "blobs"
    monkeypatch.setenv("ADMIN_KEY", "admin-test-key")
    monkeypatch.setenv("SECRET_SALT", "secret-test-salt")
    monkeypatch.setenv("DATABASE_PATH", str(database_path))
    monkeypatch.setenv("BLOB_STORAGE_DIR", str(blob_storage_path))
    monkeypatch.setenv("ONLINE_THRESHOLD_SECONDS", "60")
    connection_manager.clear()

    with TestClient(app) as client:
        yield client, database_path

    connection_manager.clear()


def _create_enroll_token(
    client: TestClient,
    *,
    store_id: str = "store-a",
    max_uses: int = 1,
) -> str:
    response = client.post(
        "/admin/v1/enroll_tokens",
        json={
            "store_id": store_id,
            "expires_in_sec": 600,
            "max_uses": max_uses,
            "note": "connector pairing",
        },
        headers={"X-ADMIN-KEY": "admin-test-key"},
    )
    assert response.status_code == 200
    return response.json()["enroll_token"]


def _register_device(client: TestClient, *, store_id: str = "store-a") -> tuple[str, str]:
    enroll_token = _create_enroll_token(client, store_id=store_id)
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


def _read_last_seen_at(database_path: Path, device_id: str) -> datetime | None:
    with sqlite3.connect(database_path) as connection:
        row = connection.execute(
            """
            SELECT last_seen_at
            FROM devices
            WHERE device_id = ?
            """,
            (device_id,),
        ).fetchone()
    if row is None:
        return None
    return parse_db_utc_datetime(row[0])


def test_compute_online_null_last_seen_is_offline():
    now_utc = datetime.now(timezone.utc)
    assert compute_online(last_seen_at=None, now_utc=now_utc, threshold_seconds=60) is False


def test_compute_online_within_threshold_is_online():
    now_utc = datetime.now(timezone.utc)
    last_seen_at = now_utc - timedelta(seconds=30)
    assert (
        compute_online(
            last_seen_at=last_seen_at,
            now_utc=now_utc,
            threshold_seconds=60,
        )
        is True
    )


def test_compute_online_beyond_threshold_is_offline():
    now_utc = datetime.now(timezone.utc)
    last_seen_at = now_utc - timedelta(seconds=61)
    assert (
        compute_online(
            last_seen_at=last_seen_at,
            now_utc=now_utc,
            threshold_seconds=60,
        )
        is False
    )


def test_websocket_inbound_message_updates_last_seen(client_and_db):
    client, database_path = client_and_db
    device_id, device_token = _register_device(client)

    with client.websocket_connect(
        "/connector/v1/ws",
        headers={"Authorization": f"Bearer {device_token}"},
    ) as websocket:
        connected_seen = _read_last_seen_at(database_path, device_id)
        assert connected_seen is not None

        time.sleep(0.02)
        websocket.send_json(
            {
                "type": "heartbeat",
                "ts": "2026-03-01T23:50:00Z",
                "message_id": str(uuid.uuid4()),
                "payload": {"uptime_sec": 123},
            }
        )

        updated_seen: datetime | None = None
        deadline = time.time() + 2.0
        while time.time() < deadline:
            candidate = _read_last_seen_at(database_path, device_id)
            if candidate is not None and candidate > connected_seen:
                updated_seen = candidate
                break
            time.sleep(0.05)

        assert updated_seen is not None


def test_admin_store_devices_returns_online_and_offline(client_and_db):
    client, database_path = client_and_db
    online_device_id, _ = _register_device(client, store_id="store-a")
    offline_device_id, _ = _register_device(client, store_id="store-a")

    now_utc = datetime.now(timezone.utc)
    old_utc = now_utc - timedelta(seconds=120)
    with sqlite3.connect(database_path) as connection:
        connection.execute(
            "UPDATE devices SET last_seen_at = ? WHERE device_id = ?",
            (now_utc.isoformat(), online_device_id),
        )
        connection.execute(
            "UPDATE devices SET last_seen_at = ? WHERE device_id = ?",
            (old_utc.isoformat(), offline_device_id),
        )
        connection.commit()

    response = client.get(
        "/admin/v1/stores/store-a/devices",
        headers={"X-ADMIN-KEY": "admin-test-key"},
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["store_id"] == "store-a"
    assert payload["online_threshold_seconds"] == 60

    devices_by_id = {item["device_id"]: item for item in payload["devices"]}
    assert devices_by_id[online_device_id]["online"] is True
    assert devices_by_id[offline_device_id]["online"] is False
    assert devices_by_id[online_device_id]["connected"] is False
    assert devices_by_id[offline_device_id]["connected"] is False


def test_admin_device_status_endpoint_returns_device_status(client_and_db):
    client, database_path = client_and_db
    device_id, _ = _register_device(client, store_id="store-a")

    now_utc = datetime.now(timezone.utc)
    with sqlite3.connect(database_path) as connection:
        connection.execute(
            "UPDATE devices SET last_seen_at = ? WHERE device_id = ?",
            (now_utc.isoformat(), device_id),
        )
        connection.commit()

    response = client.get(
        f"/admin/v1/devices/{device_id}/status",
        headers={"X-ADMIN-KEY": "admin-test-key"},
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["device_id"] == device_id
    assert payload["online"] is True

    missing = client.get(
        "/admin/v1/devices/missing-device/status",
        headers={"X-ADMIN-KEY": "admin-test-key"},
    )
    assert missing.status_code == 404
