from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
import sqlite3
import threading
import uuid

import pytest
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from app.blob_cleanup import cleanup_expired_blobs_once
from app.main import app
from app.realtime import connection_manager


def _seed_store(database_path: Path, *, store_id: str, is_active: bool) -> None:
    with sqlite3.connect(database_path) as connection:
        connection.execute(
            """
            INSERT OR REPLACE INTO stores (store_id, name, address, is_active, created_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                store_id,
                f"Store {store_id}",
                None,
                1 if is_active else 0,
                datetime.now(timezone.utc).isoformat(),
            ),
        )
        connection.commit()


@pytest.fixture()
def client_and_paths(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    database_path = tmp_path / "onlinemainserver.db"
    blob_storage_path = tmp_path / "blobs"
    monkeypatch.setenv("ADMIN_KEY", "admin-test-key")
    monkeypatch.setenv("SECRET_SALT", "secret-test-salt")
    monkeypatch.setenv("DATABASE_PATH", str(database_path))
    monkeypatch.setenv("BLOB_STORAGE_DIR", str(blob_storage_path))
    monkeypatch.setenv("COMMAND_DEFAULT_TIMEOUT_SECONDS", "2")
    connection_manager.clear()

    with TestClient(app) as client:
        _seed_store(database_path, store_id="store-a", is_active=True)
        yield client, database_path, blob_storage_path

    connection_manager.clear()


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


def test_ws_connect_fails_without_authorization_header(client_and_paths):
    client, _, _ = client_and_paths

    with pytest.raises(WebSocketDisconnect) as error:
        with client.websocket_connect("/connector/v1/ws"):
            pass

    assert error.value.code == 1008


def test_ws_connect_with_valid_token_registers_connection(client_and_paths):
    client, _, _ = client_and_paths
    device_id, device_token = _register_device(client)

    with client.websocket_connect(
        "/connector/v1/ws",
        headers={"Authorization": f"Bearer {device_token}"},
    ):
        assert connection_manager.is_connected(device_id)
        assert connection_manager.get_last_seen(device_id) is not None

    assert not connection_manager.is_connected(device_id)


def test_send_command_returns_response_when_test_connector_replies(client_and_paths):
    client, _, _ = client_and_paths
    device_id, device_token = _register_device(client)
    admin_result: dict[str, object] = {}

    def _dispatch_admin_command() -> None:
        response = client.post(
            f"/admin/v1/devices/{device_id}/commands",
            headers={"X-ADMIN-KEY": "admin-test-key"},
            json={"request_type": "ping", "params": {"nonce": "abc"}},
        )
        admin_result["status_code"] = response.status_code
        admin_result["body"] = response.json()

    with client.websocket_connect(
        "/connector/v1/ws",
        headers={"Authorization": f"Bearer {device_token}"},
    ) as websocket:
        worker = threading.Thread(target=_dispatch_admin_command, daemon=True)
        worker.start()

        outbound_request = websocket.receive_json()
        assert outbound_request["type"] == "request"
        assert outbound_request["device_id"] == device_id
        assert outbound_request["payload"]["request_type"] == "ping"
        request_id = outbound_request["payload"]["request_id"]

        websocket.send_json(
            {
                "type": "ack",
                "ts": "2026-03-01T12:00:01Z",
                "message_id": str(uuid.uuid4()),
                "device_id": device_id,
                "payload": {
                    "request_id": request_id,
                    "accepted": True,
                    "reason": None,
                },
            }
        )
        websocket.send_json(
            {
                "type": "response",
                "ts": "2026-03-01T12:00:02Z",
                "message_id": str(uuid.uuid4()),
                "device_id": device_id,
                "payload": {
                    "request_id": request_id,
                    "status": "ok",
                    "data": {"pong": True},
                    "error": None,
                },
            }
        )
        worker.join(timeout=5)

    assert not worker.is_alive()
    assert admin_result["status_code"] == 200
    body = admin_result["body"]
    assert isinstance(body, dict)
    assert body["status"] == "ok"
    assert body["data"] == {"pong": True}


def test_blob_upload_stores_blob_and_returns_blob_id(client_and_paths):
    client, database_path, blob_storage_path = client_and_paths
    device_id, device_token = _register_device(client)
    blob_bytes = b"fake-image-bytes-for-testing"

    response = client.post(
        "/connector/v1/blobs",
        headers={"Authorization": f"Bearer {device_token}"},
        data={"image_id": "image-blob-1"},
        files={"file": ("capture.jpg", blob_bytes, "image/jpeg")},
    )
    assert response.status_code == 200
    body = response.json()
    blob_id = body["blob_id"]
    assert body["size_bytes"] == len(blob_bytes)
    assert body["content_type"] == "image/jpeg"
    assert body["sha256"]

    with sqlite3.connect(database_path) as connection:
        row = connection.execute(
            """
            SELECT device_id, path, content_type, size_bytes, sha256
            FROM blobs
            WHERE blob_id = ?
            """,
            (blob_id,),
        ).fetchone()

    assert row is not None
    assert row[0] == device_id
    stored_path = Path(row[1])
    assert stored_path.exists()
    assert stored_path.parent == blob_storage_path.resolve()
    assert stored_path.read_bytes() == blob_bytes
    assert row[2] == "image/jpeg"
    assert row[3] == len(blob_bytes)
    assert row[4] == body["sha256"]


def test_blob_download_returns_stored_bytes_admin_only(client_and_paths):
    client, _, _ = client_and_paths
    _, device_token = _register_device(client)
    blob_bytes = b"blob-download-test-data"

    upload_response = client.post(
        "/connector/v1/blobs",
        headers={"Authorization": f"Bearer {device_token}"},
        files={"file": ("capture.jpg", blob_bytes, "image/jpeg")},
    )
    assert upload_response.status_code == 200
    blob_id = upload_response.json()["blob_id"]

    unauthorized = client.get(f"/admin/v1/blobs/{blob_id}")
    assert unauthorized.status_code == 401

    authorized = client.get(
        f"/admin/v1/blobs/{blob_id}",
        headers={"X-ADMIN-KEY": "admin-test-key"},
    )
    assert authorized.status_code == 200
    assert authorized.content == blob_bytes


def test_blob_cleanup_deletes_expired_blobs(client_and_paths):
    client, database_path, _ = client_and_paths
    _, device_token = _register_device(client)

    expired_upload = client.post(
        "/connector/v1/blobs",
        headers={"Authorization": f"Bearer {device_token}"},
        files={"file": ("expired.jpg", b"expired-bytes", "image/jpeg")},
    )
    assert expired_upload.status_code == 200
    expired_blob_id = expired_upload.json()["blob_id"]

    fresh_upload = client.post(
        "/connector/v1/blobs",
        headers={"Authorization": f"Bearer {device_token}"},
        files={"file": ("fresh.jpg", b"fresh-bytes", "image/jpeg")},
    )
    assert fresh_upload.status_code == 200
    fresh_blob_id = fresh_upload.json()["blob_id"]

    now = datetime.now(timezone.utc)
    old_created_at = (now - timedelta(seconds=90000)).isoformat()
    with sqlite3.connect(database_path) as connection:
        connection.execute(
            "UPDATE blobs SET created_at = ? WHERE blob_id = ?",
            (old_created_at, expired_blob_id),
        )
        connection.commit()
        expired_path = Path(
            connection.execute(
                "SELECT path FROM blobs WHERE blob_id = ?",
                (expired_blob_id,),
            ).fetchone()[0]
        )
        fresh_path = Path(
            connection.execute(
                "SELECT path FROM blobs WHERE blob_id = ?",
                (fresh_blob_id,),
            ).fetchone()[0]
        )

    deleted_count = cleanup_expired_blobs_once(
        database_path=str(database_path),
        retention_s=86400.0,
        now=now,
    )
    assert deleted_count == 1

    with sqlite3.connect(database_path) as connection:
        expired_row = connection.execute(
            "SELECT blob_id FROM blobs WHERE blob_id = ?",
            (expired_blob_id,),
        ).fetchone()
        fresh_row = connection.execute(
            "SELECT blob_id FROM blobs WHERE blob_id = ?",
            (fresh_blob_id,),
        ).fetchone()

    assert expired_row is None
    assert fresh_row is not None
    assert not expired_path.exists()
    assert fresh_path.exists()
