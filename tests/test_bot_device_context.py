from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import sqlite3
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
    monkeypatch.setenv("ONLINE_THRESHOLD_SECONDS", "60")
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


def _bot_params(provider_user_id: str) -> dict[str, str]:
    return {"provider": "telegram", "provider_user_id": provider_user_id}


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


def _create_store(
    client: TestClient,
    *,
    display_name: str,
    is_active: bool = True,
) -> dict:
    response = client.post(
        "/admin/v1/stores",
        json={"display_name": display_name, "is_active": is_active},
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
    active_store_id: str | None,
    active_device_id: str | None = None,
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
                active_device_id,
                datetime.now(timezone.utc).isoformat(),
            ),
        )
        connection.commit()


def _fetch_one(database_path: Path, query: str, params: tuple = ()) -> sqlite3.Row | None:
    with sqlite3.connect(database_path) as connection:
        connection.row_factory = sqlite3.Row
        return connection.execute(query, params).fetchone()


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


def _register_device(
    client: TestClient,
    *,
    store_id: str,
    label: str,
    hostname: str,
) -> str:
    enroll_token = _create_enroll_token(client, store_id=store_id)
    response = client.post(
        "/connector/v1/register",
        json={
            "enroll_token": enroll_token,
            "device_info": {
                "label": label,
                "hostname": hostname,
                "os": "linux",
                "connector_version": "1.0.0",
            },
        },
    )
    assert response.status_code == 200
    return response.json()["device_id"]


def _set_device_last_seen(
    database_path: Path,
    *,
    device_id: str,
    last_seen_at: datetime | None,
) -> None:
    with sqlite3.connect(database_path) as connection:
        connection.execute(
            "UPDATE devices SET last_seen_at = ? WHERE device_id = ?",
            (last_seen_at.isoformat() if last_seen_at is not None else None, device_id),
        )
        connection.commit()


def _seed_scan_result(
    database_path: Path,
    *,
    device_id: str,
    image_id: str,
    sent_at: str | None,
    received_at: str,
    weight_grams: float,
    fruits: list[dict[str, object]],
) -> None:
    payload = {
        "session_id": f"session-{image_id}",
        "image_id": image_id,
        "timestamp": sent_at or received_at,
        "weight_grams": weight_grams,
        "fruits": fruits,
    }
    with sqlite3.connect(database_path) as connection:
        connection.execute(
            """
            INSERT INTO scan_results (
                device_id,
                image_id,
                received_at,
                sent_at,
                scan_result_json
            )
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                device_id,
                image_id,
                received_at,
                sent_at,
                json.dumps(payload, separators=(",", ":"), sort_keys=True),
            ),
        )
        connection.commit()


def test_list_store_devices_returns_device_summaries_for_member(client_and_db):
    client, database_path = client_and_db
    user = _ensure_user(
        client,
        provider_user_id="telegram-list-devices-1",
        provider_chat_id="telegram-chat-list-devices-1",
        username="list_devices_user",
    )
    store = _create_store(client, display_name="Device Listing Store")
    _seed_membership(
        database_path,
        store_id=store["store_id"],
        user_id=user["user_id"],
        role="viewer",
    )
    online_device_id = _register_device(
        client,
        store_id=store["store_id"],
        label="Front Counter",
        hostname="front-counter-1",
    )
    offline_device_id = _register_device(
        client,
        store_id=store["store_id"],
        label="Back Room",
        hostname="back-room-1",
    )
    now_utc = datetime.now(timezone.utc)
    _set_device_last_seen(database_path, device_id=online_device_id, last_seen_at=now_utc)
    _set_device_last_seen(
        database_path,
        device_id=offline_device_id,
        last_seen_at=now_utc - timedelta(seconds=120),
    )

    response = client.get(
        f"/bot/v1/stores/{store['store_id']}/devices",
        params=_bot_params("telegram-list-devices-1"),
        headers=_bot_headers(),
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["store_id"] == store["store_id"]

    items = {item["device_id"]: item for item in payload["items"]}
    assert items[online_device_id] == {
        "device_id": online_device_id,
        "display_name": "Front Counter",
        "online": True,
    }
    assert items[offline_device_id] == {
        "device_id": offline_device_id,
        "display_name": "Back Room",
        "online": False,
    }


def test_set_active_device_updates_user_context(client_and_db):
    client, database_path = client_and_db
    user = _ensure_user(
        client,
        provider_user_id="telegram-active-device-1",
        provider_chat_id="telegram-chat-active-device-1",
        username="active_device_user",
    )
    store = _create_store(client, display_name="Active Device Store")
    _seed_membership(
        database_path,
        store_id=store["store_id"],
        user_id=user["user_id"],
        role="viewer",
    )
    _set_user_context(
        database_path,
        user_id=user["user_id"],
        active_store_id=store["store_id"],
    )
    device_id = _register_device(
        client,
        store_id=store["store_id"],
        label="Scale A",
        hostname="scale-a-1",
    )

    response = client.post(
        "/bot/v1/context/active_device",
        json={
            "provider": "telegram",
            "provider_user_id": "telegram-active-device-1",
            "device_id": device_id,
        },
        headers=_bot_headers(),
    )
    assert response.status_code == 200
    assert response.json() == {
        "active_store_id": store["store_id"],
        "active_device_id": device_id,
    }

    context_row = _fetch_one(
        database_path,
        """
        SELECT active_store_id, active_device_id
        FROM user_context
        WHERE user_id = ?
        """,
        (user["user_id"],),
    )
    assert context_row is not None
    assert context_row["active_store_id"] == store["store_id"]
    assert context_row["active_device_id"] == device_id


def test_set_active_device_rejects_device_outside_active_store(client_and_db):
    client, database_path = client_and_db
    user = _ensure_user(
        client,
        provider_user_id="telegram-active-device-outside-1",
        provider_chat_id="telegram-chat-active-device-outside-1",
        username="active_device_outside_user",
    )
    active_store = _create_store(client, display_name="Selected Store")
    other_store = _create_store(client, display_name="Other Store")
    _seed_membership(
        database_path,
        store_id=active_store["store_id"],
        user_id=user["user_id"],
        role="viewer",
    )
    _set_user_context(
        database_path,
        user_id=user["user_id"],
        active_store_id=active_store["store_id"],
    )
    device_id = _register_device(
        client,
        store_id=other_store["store_id"],
        label="Other Scale",
        hostname="other-scale-1",
    )

    response = client.post(
        "/bot/v1/context/active_device",
        json={
            "provider": "telegram",
            "provider_user_id": "telegram-active-device-outside-1",
            "device_id": device_id,
        },
        headers=_bot_headers(),
    )
    assert response.status_code == 404
    assert response.json() == {"detail": "device_not_in_active_store"}


def test_bot_device_status_returns_status_for_device_in_active_store(client_and_db):
    client, database_path = client_and_db
    user = _ensure_user(
        client,
        provider_user_id="telegram-device-status-1",
        provider_chat_id="telegram-chat-device-status-1",
        username="device_status_user",
    )
    store = _create_store(client, display_name="Status Store")
    _seed_membership(
        database_path,
        store_id=store["store_id"],
        user_id=user["user_id"],
        role="viewer",
    )
    _set_user_context(
        database_path,
        user_id=user["user_id"],
        active_store_id=store["store_id"],
    )
    device_id = _register_device(
        client,
        store_id=store["store_id"],
        label="Counter Scale",
        hostname="counter-scale-1",
    )
    now_utc = datetime.now(timezone.utc)
    _set_device_last_seen(database_path, device_id=device_id, last_seen_at=now_utc)

    response = client.get(
        f"/bot/v1/devices/{device_id}/status",
        params=_bot_params("telegram-device-status-1"),
        headers=_bot_headers(),
    )
    assert response.status_code == 200
    assert response.json() == {
        "device_id": device_id,
        "display_name": "Counter Scale",
        "connected": False,
        "last_seen_at": now_utc.isoformat().replace("+00:00", "Z"),
        "online": True,
        "actions": {
            "show_photo": False,
            "show_tare": False,
            "show_tare_set": False,
            "show_tare_reset": False,
        },
    }


def test_store_last_result_requires_active_store(client_and_db):
    client, _ = client_and_db
    _ensure_user(
        client,
        provider_user_id="telegram-store-last-no-context-1",
        provider_chat_id="telegram-chat-store-last-no-context-1",
        username="store_last_no_context_user",
    )

    response = client.get(
        "/bot/v1/results/last",
        params=_bot_params("telegram-store-last-no-context-1"),
        headers=_bot_headers(),
    )
    assert response.status_code == 400
    assert response.json() == {"detail": "no_active_store"}


def test_store_last_result_returns_latest_detection_from_active_store(client_and_db):
    client, database_path = client_and_db
    user = _ensure_user(
        client,
        provider_user_id="telegram-store-last-1",
        provider_chat_id="telegram-chat-store-last-1",
        username="store_last_user",
    )
    store = _create_store(client, display_name="Result Store")
    _seed_membership(
        database_path,
        store_id=store["store_id"],
        user_id=user["user_id"],
        role="viewer",
    )
    _set_user_context(
        database_path,
        user_id=user["user_id"],
        active_store_id=store["store_id"],
    )
    older_device_id = _register_device(
        client,
        store_id=store["store_id"],
        label="Older Scale",
        hostname="older-scale-1",
    )
    latest_device_id = _register_device(
        client,
        store_id=store["store_id"],
        label="Latest Scale",
        hostname="latest-scale-1",
    )
    older_sent_at = datetime(2026, 3, 1, 12, 0, tzinfo=timezone.utc).isoformat()
    latest_sent_at = datetime(2026, 3, 1, 12, 5, tzinfo=timezone.utc).isoformat()
    _seed_scan_result(
        database_path,
        device_id=older_device_id,
        image_id="image-older-1",
        sent_at=older_sent_at,
        received_at=older_sent_at,
        weight_grams=111.0,
        fruits=[{"name": "apple", "weight_grams": 111.0}],
    )
    _seed_scan_result(
        database_path,
        device_id=latest_device_id,
        image_id="image-latest-1",
        sent_at=latest_sent_at,
        received_at=latest_sent_at,
        weight_grams=222.0,
        fruits=[
            {
                "name": "banana",
                "weight_grams": 222.0,
                "defects": [{"type": "defect", "confidence": 0.42}],
            }
        ],
    )

    response = client.get(
        "/bot/v1/results/last",
        params=_bot_params("telegram-store-last-1"),
        headers=_bot_headers(),
    )
    assert response.status_code == 200
    assert response.json() == {
        "device_id": latest_device_id,
        "device_display_name": "Latest Scale",
        "image_id": "image-latest-1",
        "sent_at": latest_sent_at,
        "received_at": latest_sent_at,
        "weight_grams": 222.0,
        "fruits": [
            {
                "name": "banana",
                "weight_grams": 222.0,
                "defects": [{"type": "defect", "confidence": 0.42}],
            }
        ],
        "defect": {"value": True, "type": "defect"},
    }


def test_store_last_result_denies_roles_without_last_result_permission(client_and_db):
    client, database_path = client_and_db
    user = _ensure_user(
        client,
        provider_user_id="telegram-store-last-auditor-1",
        provider_chat_id="telegram-chat-store-last-auditor-1",
        username="store_last_auditor_user",
    )
    store = _create_store(client, display_name="Auditor Store")
    _seed_membership(
        database_path,
        store_id=store["store_id"],
        user_id=user["user_id"],
        role="auditor",
    )
    _set_user_context(
        database_path,
        user_id=user["user_id"],
        active_store_id=store["store_id"],
    )
    device_id = _register_device(
        client,
        store_id=store["store_id"],
        label="Auditor Scale",
        hostname="auditor-scale-1",
    )
    sent_at = datetime(2026, 3, 1, 13, 0, tzinfo=timezone.utc).isoformat()
    _seed_scan_result(
        database_path,
        device_id=device_id,
        image_id="image-auditor-1",
        sent_at=sent_at,
        received_at=sent_at,
        weight_grams=300.0,
        fruits=[],
    )

    response = client.get(
        "/bot/v1/results/last",
        params=_bot_params("telegram-store-last-auditor-1"),
        headers=_bot_headers(),
    )
    assert response.status_code == 403
    assert response.json() == {"detail": "permission_denied"}


def test_store_last_result_returns_store_has_no_devices_when_store_is_empty(client_and_db):
    client, database_path = client_and_db
    user = _ensure_user(
        client,
        provider_user_id="telegram-store-last-empty-1",
        provider_chat_id="telegram-chat-store-last-empty-1",
        username="store_last_empty_user",
    )
    store = _create_store(client, display_name="Empty Store")
    _seed_membership(
        database_path,
        store_id=store["store_id"],
        user_id=user["user_id"],
        role="viewer",
    )
    _set_user_context(
        database_path,
        user_id=user["user_id"],
        active_store_id=store["store_id"],
    )

    response = client.get(
        "/bot/v1/results/last",
        params=_bot_params("telegram-store-last-empty-1"),
        headers=_bot_headers(),
    )
    assert response.status_code == 404
    assert response.json() == {"detail": "store_has_no_devices"}


def test_device_last_result_returns_latest_detection_for_requested_device(client_and_db):
    client, database_path = client_and_db
    user = _ensure_user(
        client,
        provider_user_id="telegram-device-last-1",
        provider_chat_id="telegram-chat-device-last-1",
        username="device_last_user",
    )
    store = _create_store(client, display_name="Device Result Store")
    _seed_membership(
        database_path,
        store_id=store["store_id"],
        user_id=user["user_id"],
        role="viewer",
    )
    _set_user_context(
        database_path,
        user_id=user["user_id"],
        active_store_id=store["store_id"],
    )
    target_device_id = _register_device(
        client,
        store_id=store["store_id"],
        label="Target Scale",
        hostname="target-scale-1",
    )
    other_device_id = _register_device(
        client,
        store_id=store["store_id"],
        label="Other Scale",
        hostname="other-scale-1",
    )
    older_target_sent_at = datetime(2026, 3, 1, 14, 0, tzinfo=timezone.utc).isoformat()
    latest_target_sent_at = datetime(2026, 3, 1, 14, 5, tzinfo=timezone.utc).isoformat()
    other_device_sent_at = datetime(2026, 3, 1, 14, 10, tzinfo=timezone.utc).isoformat()
    _seed_scan_result(
        database_path,
        device_id=target_device_id,
        image_id="image-target-old-1",
        sent_at=older_target_sent_at,
        received_at=older_target_sent_at,
        weight_grams=101.0,
        fruits=[{"name": "apple", "weight_grams": 101.0}],
    )
    _seed_scan_result(
        database_path,
        device_id=target_device_id,
        image_id="image-target-latest-1",
        sent_at=latest_target_sent_at,
        received_at=latest_target_sent_at,
        weight_grams=202.0,
        fruits=[{"name": "orange", "weight_grams": 202.0}],
    )
    _seed_scan_result(
        database_path,
        device_id=other_device_id,
        image_id="image-other-1",
        sent_at=other_device_sent_at,
        received_at=other_device_sent_at,
        weight_grams=303.0,
        fruits=[{"name": "pear", "weight_grams": 303.0}],
    )

    response = client.get(
        f"/bot/v1/devices/{target_device_id}/results/last",
        params=_bot_params("telegram-device-last-1"),
        headers=_bot_headers(),
    )
    assert response.status_code == 200
    assert response.json() == {
        "device_id": target_device_id,
        "device_display_name": "Target Scale",
        "image_id": "image-target-latest-1",
        "sent_at": latest_target_sent_at,
        "received_at": latest_target_sent_at,
        "weight_grams": 202.0,
        "fruits": [{"name": "orange", "weight_grams": 202.0}],
        "defect": {"value": False, "type": None},
    }


def test_device_last_result_returns_not_found_when_device_has_no_results(client_and_db):
    client, database_path = client_and_db
    user = _ensure_user(
        client,
        provider_user_id="telegram-device-last-empty-1",
        provider_chat_id="telegram-chat-device-last-empty-1",
        username="device_last_empty_user",
    )
    store = _create_store(client, display_name="No Results Store")
    _seed_membership(
        database_path,
        store_id=store["store_id"],
        user_id=user["user_id"],
        role="viewer",
    )
    _set_user_context(
        database_path,
        user_id=user["user_id"],
        active_store_id=store["store_id"],
    )
    device_id = _register_device(
        client,
        store_id=store["store_id"],
        label="No Results Scale",
        hostname="no-results-scale-1",
    )

    response = client.get(
        f"/bot/v1/devices/{device_id}/results/last",
        params=_bot_params("telegram-device-last-empty-1"),
        headers=_bot_headers(),
    )
    assert response.status_code == 404
    assert response.json() == {"detail": "result_not_found"}
