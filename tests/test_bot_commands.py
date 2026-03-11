from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
import sqlite3
import threading
import uuid

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.realtime import connection_manager
from app.roles import clear_roles_cache


@pytest.fixture()
def client_and_db(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    database_path = tmp_path / "onlinemainserver.db"
    blob_storage_path = tmp_path / "blobs"
    monkeypatch.setenv("ADMIN_KEY", "admin-test-key")
    monkeypatch.setenv("SECRET_SALT", "secret-test-salt")
    monkeypatch.setenv("TGBOT_SERVICE_TOKEN", "bot-service-token")
    monkeypatch.setenv("DATABASE_PATH", str(database_path))
    monkeypatch.setenv("BLOB_STORAGE_DIR", str(blob_storage_path))
    monkeypatch.setenv("COMMAND_DEFAULT_TIMEOUT_SECONDS", "2")
    clear_roles_cache()
    connection_manager.clear()

    with TestClient(app) as client:
        yield client, database_path

    connection_manager.clear()
    clear_roles_cache()


def _admin_headers() -> dict[str, str]:
    return {"X-ADMIN-KEY": "admin-test-key"}


def _bot_headers() -> dict[str, str]:
    return {"Authorization": "Bearer bot-service-token"}


def _ensure_user(
    client: TestClient,
    *,
    provider_user_id: str,
    provider_chat_id: str,
    username: str,
    display_name: str = "Sample User",
) -> dict:
    response = client.post(
        "/bot/v1/session/ensure",
        json={
            "provider": "telegram",
            "provider_user_id": provider_user_id,
            "provider_chat_id": provider_chat_id,
            "username": username,
            "display_name": display_name,
        },
        headers=_bot_headers(),
    )
    assert response.status_code == 200
    return response.json()


def _create_store(client: TestClient, *, display_name: str) -> dict:
    response = client.post(
        "/admin/v1/stores",
        json={"display_name": display_name, "is_active": True},
        headers=_admin_headers(),
    )
    assert response.status_code == 201
    return response.json()


def _seed_membership(
    database_path: Path,
    *,
    store_id: str,
    user_id: str,
    role: str,
) -> None:
    with sqlite3.connect(database_path) as connection:
        connection.execute(
            """
            INSERT INTO store_memberships (
                membership_id,
                store_id,
                user_id,
                role,
                created_at,
                revoked_at,
                created_by_user_id,
                note
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                str(uuid.uuid4()),
                store_id,
                user_id,
                role,
                datetime.now(timezone.utc).isoformat(),
                None,
                None,
                None,
            ),
        )
        connection.commit()


def _set_user_context(
    database_path: Path,
    *,
    user_id: str,
    active_store_id: str,
) -> None:
    with sqlite3.connect(database_path) as connection:
        connection.execute(
            """
            INSERT OR REPLACE INTO user_context (
                user_id,
                active_store_id,
                active_device_id,
                updated_at
            )
            VALUES (?, ?, ?, ?)
            """,
            (
                user_id,
                active_store_id,
                None,
                datetime.now(timezone.utc).isoformat(),
            ),
        )
        connection.commit()


def _create_enroll_token(client: TestClient, *, store_id: str) -> str:
    response = client.post(
        "/admin/v1/enroll_tokens",
        json={
            "store_id": store_id,
            "expires_in_sec": 600,
            "max_uses": 1,
            "note": "connector pairing",
        },
        headers=_admin_headers(),
    )
    assert response.status_code == 200
    return response.json()["enroll_token"]


def _register_device(client: TestClient, *, store_id: str) -> tuple[str, str]:
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


def test_bot_command_tare_succeeds_and_persists(client_and_db):
    client, database_path = client_and_db
    user = _ensure_user(
        client,
        provider_user_id="telegram-command-user-1",
        provider_chat_id="telegram-command-chat-1",
        username="command_user",
    )
    store = _create_store(client, display_name="Command Store")
    _seed_membership(database_path, store_id=store["store_id"], user_id=user["user_id"], role="operator")
    _set_user_context(database_path, user_id=user["user_id"], active_store_id=store["store_id"])
    device_id, device_token = _register_device(client, store_id=store["store_id"])

    result_holder: dict[str, object] = {}

    def _dispatch_command() -> None:
        response = client.post(
            f"/bot/v1/devices/{device_id}/commands",
            json={
                "provider": "telegram",
                "provider_user_id": "telegram-command-user-1",
                "request_type": "tare",
                "params": {"mode": "set"},
                "wait_timeout_ms": 1500,
            },
            headers=_bot_headers(),
        )
        result_holder["status_code"] = response.status_code
        result_holder["body"] = response.json()

    with client.websocket_connect(
        "/connector/v1/ws",
        headers={"Authorization": f"Bearer {device_token}"},
    ) as websocket:
        worker = threading.Thread(target=_dispatch_command, daemon=True)
        worker.start()

        outbound_request = websocket.receive_json()
        request_id = outbound_request["payload"]["request_id"]
        websocket.send_json(
            {
                "type": "response",
                "ts": "2026-03-01T12:01:00Z",
                "message_id": str(uuid.uuid4()),
                "device_id": device_id,
                "payload": {
                    "request_id": request_id,
                    "status": "ok",
                    "data": {"accepted": True},
                    "error": None,
                },
            }
        )
        worker.join(timeout=5)

    assert result_holder["status_code"] == 200
    body = result_holder["body"]
    assert body["status"] == "succeeded"
    assert body["result"] == {"accepted": True}
    command_id = body["command_id"]

    with sqlite3.connect(database_path) as connection:
        connection.row_factory = sqlite3.Row
        command_row = connection.execute(
            "SELECT status, result_json FROM device_commands WHERE command_id = ?",
            (command_id,),
        ).fetchone()

    assert command_row is not None
    assert command_row["status"] == "succeeded"
    assert json.loads(command_row["result_json"]) == {"accepted": True}


def test_bot_command_status_returns_persisted_row(client_and_db):
    client, database_path = client_and_db
    user = _ensure_user(
        client,
        provider_user_id="telegram-command-user-2",
        provider_chat_id="telegram-command-chat-2",
        username="command_user_2",
    )
    store = _create_store(client, display_name="Status Store")
    _seed_membership(database_path, store_id=store["store_id"], user_id=user["user_id"], role="operator")
    _set_user_context(database_path, user_id=user["user_id"], active_store_id=store["store_id"])
    device_id, _ = _register_device(client, store_id=store["store_id"])

    command_id = str(uuid.uuid4())
    request_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc).isoformat()
    with sqlite3.connect(database_path) as connection:
        connection.execute(
            """
            INSERT INTO device_commands (
                command_id,
                request_id,
                device_id,
                store_id,
                user_id,
                request_type,
                params_json,
                status,
                result_json,
                error_code,
                blob_id,
                created_at,
                sent_at,
                completed_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                command_id,
                request_id,
                device_id,
                store["store_id"],
                user["user_id"],
                "tare",
                json.dumps({"mode": "set"}),
                "succeeded",
                json.dumps({"accepted": True}),
                None,
                None,
                now,
                now,
                now,
            ),
        )
        connection.commit()

    response = client.get(
        f"/bot/v1/commands/{command_id}",
        params={"provider": "telegram", "provider_user_id": "telegram-command-user-2"},
        headers=_bot_headers(),
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["command_id"] == command_id
    assert payload["status"] == "succeeded"
    assert payload["result"] == {"accepted": True}


def test_bot_command_photo_returns_blob_bytes(client_and_db):
    client, database_path = client_and_db
    user = _ensure_user(
        client,
        provider_user_id="telegram-command-user-3",
        provider_chat_id="telegram-command-chat-3",
        username="command_user_3",
    )
    store = _create_store(client, display_name="Photo Store")
    _seed_membership(database_path, store_id=store["store_id"], user_id=user["user_id"], role="operator")
    _set_user_context(database_path, user_id=user["user_id"], active_store_id=store["store_id"])
    device_id, device_token = _register_device(client, store_id=store["store_id"])

    upload_response = client.post(
        "/connector/v1/blobs",
        headers={"Authorization": f"Bearer {device_token}"},
        files={"file": ("capture.jpg", b"photo-bytes", "image/jpeg")},
    )
    assert upload_response.status_code == 200
    blob_id = upload_response.json()["blob_id"]

    command_id = str(uuid.uuid4())
    request_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc).isoformat()
    with sqlite3.connect(database_path) as connection:
        connection.execute(
            """
            INSERT INTO device_commands (
                command_id,
                request_id,
                device_id,
                store_id,
                user_id,
                request_type,
                params_json,
                status,
                result_json,
                error_code,
                blob_id,
                created_at,
                sent_at,
                completed_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                command_id,
                request_id,
                device_id,
                store["store_id"],
                user["user_id"],
                "camera.capture",
                json.dumps({}),
                "succeeded",
                json.dumps({"blob_id": blob_id}),
                None,
                blob_id,
                now,
                now,
                now,
            ),
        )
        connection.commit()

    response = client.get(
        f"/bot/v1/commands/{command_id}/photo",
        params={"provider": "telegram", "provider_user_id": "telegram-command-user-3"},
        headers=_bot_headers(),
    )
    assert response.status_code == 200
    assert response.content == b"photo-bytes"
