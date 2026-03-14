from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
from io import BytesIO
import json
from pathlib import Path
import sqlite3
import uuid

from PIL import Image
import pytest
from fastapi.testclient import TestClient

from app.db import init_db, open_connection
from app.main import app
from app.notification_delivery_worker import (
    NotificationDeliveryWorker,
    cleanup_stale_notification_deliveries_once,
)
from app.notification_images import (
    get_or_create_annotated_image,
)
from app.notification_status_monitor import NotificationStatusMonitor
from app.notifications import (
    EVENT_DEFECT_DETECTED,
    EVENT_DEVICE_OFFLINE,
    EVENT_DEVICE_ONLINE,
    create_event_with_deliveries,
    resolve_eligible_recipients,
)
from app.realtime import connection_manager
from app.roles import clear_roles_cache


def _setup_env(
    monkeypatch: pytest.MonkeyPatch,
    *,
    database_path: Path,
    blob_storage_path: Path,
) -> None:
    monkeypatch.setenv("ADMIN_KEY", "admin-test-key")
    monkeypatch.setenv("SECRET_SALT", "secret-test-salt")
    monkeypatch.setenv("TGBOT_SERVICE_TOKEN", "bot-service-token")
    monkeypatch.setenv("DATABASE_PATH", str(database_path))
    monkeypatch.setenv("BLOB_STORAGE_DIR", str(blob_storage_path))
    monkeypatch.setenv("NOTIFICATIONS_ENABLED", "true")
    monkeypatch.setenv("NOTIFICATION_STARTUP_GRACE_SECONDS", "120")
    monkeypatch.setenv("DEFECT_NOTIFICATION_DEDUP_SECONDS", "10")
    monkeypatch.setenv("NOTIFICATION_PUSH_BATCH_SIZE", "10")
    monkeypatch.setenv("ANNOTATED_IMAGE_CACHE_TTL_SECONDS", "43200")
    monkeypatch.setenv("NOTIFICATION_PUSH_BASE_URL", "")
    monkeypatch.setenv("NOTIFICATION_PUSH_ENDPOINT_PATH", "/internal/notifications/push")
    monkeypatch.setenv("NOTIFICATION_PUSH_TIMEOUT_SECONDS", "10")
    monkeypatch.setenv("NOTIFICATION_PUSH_POLL_INTERVAL_SECONDS", "2")
    monkeypatch.setenv("NOTIFICATION_STATUS_POLL_INTERVAL_SECONDS", "2")


@pytest.fixture()
def client_and_paths(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    database_path = tmp_path / "onlinemainserver.db"
    blob_storage_path = tmp_path / "blobs"
    _setup_env(
        monkeypatch,
        database_path=database_path,
        blob_storage_path=blob_storage_path,
    )
    clear_roles_cache()
    connection_manager.clear()
    with TestClient(app) as client:
        yield client, database_path, blob_storage_path
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
) -> dict:
    response = client.post(
        "/bot/v1/session/ensure",
        json={
            "provider": "telegram",
            "provider_user_id": provider_user_id,
            "provider_chat_id": provider_chat_id,
            "username": username,
            "display_name": username,
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


def _register_device(client: TestClient, *, store_id: str) -> tuple[str, str]:
    enroll_response = client.post(
        "/admin/v1/enroll_tokens",
        json={
            "store_id": store_id,
            "expires_in_sec": 600,
            "max_uses": 1,
            "note": "pairing",
        },
        headers=_admin_headers(),
    )
    assert enroll_response.status_code == 200
    enroll_token = enroll_response.json()["enroll_token"]
    register_response = client.post(
        "/connector/v1/register",
        json={
            "enroll_token": enroll_token,
            "device_info": {
                "label": "Scale 1",
                "hostname": "scale-1",
                "os": "linux",
                "connector_version": "1.0.0",
            },
        },
    )
    assert register_response.status_code == 200
    payload = register_response.json()
    return payload["device_id"], payload["device_token"]


def _defect_update_payload(
    *,
    image_id: str,
    sent_at: str,
    fruit_name: str,
    defect_type: str,
) -> dict:
    return {
        "envelope_version": "v1",
        "sent_at": sent_at,
        "image_id": image_id,
        "scan_result": {
            "session_id": f"session-{image_id}",
            "image_id": image_id,
            "timestamp": sent_at,
            "weight_grams": 100.0,
            "fruits": [
                {
                    "name": fruit_name,
                    "weight_grams": 100.0,
                    "defects": [{"type": defect_type}],
                }
            ],
        },
    }


def test_notification_preferences_and_eligibility_filters(client_and_paths):
    client, database_path, _ = client_and_paths
    store = _create_store(client, display_name="Notify Store")

    user_ok = _ensure_user(
        client,
        provider_user_id="notif-ok",
        provider_chat_id="notif-ok-chat",
        username="notif_ok",
    )
    user_no_perm = _ensure_user(
        client,
        provider_user_id="notif-no-perm",
        provider_chat_id="notif-no-perm-chat",
        username="notif_no_perm",
    )
    user_banned = _ensure_user(
        client,
        provider_user_id="notif-banned",
        provider_chat_id="notif-banned-chat",
        username="notif_banned",
    )
    user_disabled = _ensure_user(
        client,
        provider_user_id="notif-disabled",
        provider_chat_id="notif-disabled-chat",
        username="notif_disabled",
    )

    _seed_membership(
        database_path,
        store_id=store["store_id"],
        user_id=user_ok["user_id"],
        role="operator",
    )
    _seed_membership(
        database_path,
        store_id=store["store_id"],
        user_id=user_no_perm["user_id"],
        role="no_notification_role",
    )
    _seed_membership(
        database_path,
        store_id=store["store_id"],
        user_id=user_banned["user_id"],
        role="operator",
    )
    _seed_membership(
        database_path,
        store_id=store["store_id"],
        user_id=user_disabled["user_id"],
        role="operator",
    )
    _set_user_context(
        database_path,
        user_id=user_disabled["user_id"],
        active_store_id=store["store_id"],
    )

    with sqlite3.connect(database_path) as connection:
        connection.execute(
            "UPDATE users SET is_banned = 1 WHERE user_id = ?",
            (user_banned["user_id"],),
        )
        connection.commit()

    update_response = client.put(
        "/bot/v1/notifications/preferences",
        json={
            "provider": "telegram",
            "provider_user_id": "notif-disabled",
            "notifications_enabled": False,
        },
        headers=_bot_headers(),
    )
    assert update_response.status_code == 200
    assert update_response.json()["notifications_enabled"] is False

    read_response = client.get(
        "/bot/v1/notifications/preferences",
        params={"provider": "telegram", "provider_user_id": "notif-disabled"},
        headers=_bot_headers(),
    )
    assert read_response.status_code == 200
    assert read_response.json()["notifications_enabled"] is False

    connection = open_connection(str(database_path))
    try:
        recipients = resolve_eligible_recipients(
            connection,
            store_id=store["store_id"],
            event_type=EVENT_DEFECT_DETECTED,
        )
    finally:
        connection.close()
    provider_ids = sorted(recipient.provider_user_id for recipient in recipients)
    assert provider_ids == ["notif-ok"]


def test_defect_notifications_dedup_and_payload_shape(client_and_paths):
    client, database_path, _ = client_and_paths
    store = _create_store(client, display_name="Defect Store")
    user = _ensure_user(
        client,
        provider_user_id="defect-user",
        provider_chat_id="defect-user-chat",
        username="defect_user",
    )
    _seed_membership(
        database_path,
        store_id=store["store_id"],
        user_id=user["user_id"],
        role="operator",
    )
    _set_user_context(
        database_path,
        user_id=user["user_id"],
        active_store_id=store["store_id"],
    )
    device_id, device_token = _register_device(client, store_id=store["store_id"])
    _ = device_id

    sent_at = datetime(2026, 3, 1, 12, 0, tzinfo=timezone.utc)
    update_1 = client.post(
        "/update",
        json=_defect_update_payload(
            image_id="img-defect-1",
            sent_at=sent_at.isoformat().replace("+00:00", "Z"),
            fruit_name="banana",
            defect_type="bruise",
        ),
        headers={"Authorization": f"Bearer {device_token}"},
    )
    update_2 = client.post(
        "/update",
        json=_defect_update_payload(
            image_id="img-defect-2",
            sent_at=(sent_at + timedelta(seconds=5)).isoformat().replace("+00:00", "Z"),
            fruit_name="banana",
            defect_type="bruise",
        ),
        headers={"Authorization": f"Bearer {device_token}"},
    )
    update_3 = client.post(
        "/update",
        json=_defect_update_payload(
            image_id="img-defect-3",
            sent_at=(sent_at + timedelta(seconds=6)).isoformat().replace("+00:00", "Z"),
            fruit_name="apple",
            defect_type="spot",
        ),
        headers={"Authorization": f"Bearer {device_token}"},
    )
    assert update_1.status_code == 200
    assert update_2.status_code == 200
    assert update_3.status_code == 200

    with sqlite3.connect(database_path) as connection:
        connection.row_factory = sqlite3.Row
        event_rows = connection.execute(
            """
            SELECT notification_event_id, fruit_name
            FROM notification_events
            WHERE event_type = ?
            ORDER BY created_at ASC
            """,
            (EVENT_DEFECT_DETECTED,),
        ).fetchall()
        delivery_rows = connection.execute(
            """
            SELECT payload_json
            FROM notification_deliveries
            ORDER BY created_at ASC
            """,
        ).fetchall()

    assert len(event_rows) == 2
    assert [row["fruit_name"] for row in event_rows] == ["banana", "apple"]
    assert len(delivery_rows) == 2

    for row in delivery_rows:
        payload = json.loads(row["payload_json"])
        assert payload["event_type"] == EVENT_DEFECT_DETECTED
        assert "store_name" in payload
        assert "device_display_name" in payload
        assert "occurred_at" in payload
        assert "fruit_name" in payload
        assert "defect_type" in payload
        assert "result_id" in payload
        assert payload["can_show_image"] is True
        assert "store_id" not in payload
        assert "device_id" not in payload


def test_status_monitor_startup_grace_and_restart_behavior(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    database_path = tmp_path / "onlinemainserver.db"
    blob_storage_path = tmp_path / "blobs"
    _setup_env(
        monkeypatch,
        database_path=database_path,
        blob_storage_path=blob_storage_path,
    )
    init_db(str(database_path))
    now = datetime.now(timezone.utc)

    connection = open_connection(str(database_path))
    try:
        connection.execute(
            """
            INSERT INTO stores (store_id, display_name, name, address, is_active, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "store-a",
                "Store A",
                "Store A",
                None,
                1,
                now.isoformat(),
                now.isoformat(),
            ),
        )
        connection.execute(
            """
            INSERT INTO devices (
                device_id,
                store_id,
                created_at,
                label,
                hostname,
                os,
                connector_version,
                last_seen_at,
                connected_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "device-a",
                "store-a",
                now.isoformat(),
                "Scale A",
                "scale-a",
                "linux",
                "1.0.0",
                (now - timedelta(seconds=300)).isoformat(),
                now.isoformat(),
            ),
        )
        connection.execute(
            """
            INSERT INTO device_notification_state (device_id, last_known_online, updated_at)
            VALUES (?, ?, ?)
            """,
            ("device-a", 1, now.isoformat()),
        )
        connection.commit()
    finally:
        connection.close()

    monitor = NotificationStatusMonitor(
        database_path=str(database_path),
        online_threshold_seconds=60,
        startup_grace_seconds=120,
        poll_interval_seconds=2.0,
        enabled=True,
    )
    monitor._started_at_utc = now

    created_during_grace = monitor.run_once(now_utc=now + timedelta(seconds=10))
    assert created_during_grace == 0

    with sqlite3.connect(database_path) as connection:
        state_after_grace_run = connection.execute(
            "SELECT last_known_online FROM device_notification_state WHERE device_id = ?",
            ("device-a",),
        ).fetchone()[0]
    assert state_after_grace_run == 1

    created_after_grace = monitor.run_once(now_utc=now + timedelta(seconds=130))
    assert created_after_grace == 1

    with sqlite3.connect(database_path) as connection:
        offline_count = connection.execute(
            "SELECT COUNT(*) FROM notification_events WHERE event_type = ?",
            (EVENT_DEVICE_OFFLINE,),
        ).fetchone()[0]
    assert offline_count == 1

    with sqlite3.connect(database_path) as connection:
        connection.execute(
            "UPDATE devices SET last_seen_at = ? WHERE device_id = ?",
            ((now + timedelta(seconds=131)).isoformat(), "device-a"),
        )
        connection.commit()

    created_online = monitor.run_once(now_utc=now + timedelta(seconds=131))
    assert created_online == 1
    with sqlite3.connect(database_path) as connection:
        online_count = connection.execute(
            "SELECT COUNT(*) FROM notification_events WHERE event_type = ?",
            (EVENT_DEVICE_ONLINE,),
        ).fetchone()[0]
    assert online_count == 1


def test_delivery_worker_retries_temporary_then_fails_permanent(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    database_path = tmp_path / "onlinemainserver.db"
    blob_storage_path = tmp_path / "blobs"
    _setup_env(
        monkeypatch,
        database_path=database_path,
        blob_storage_path=blob_storage_path,
    )
    clear_roles_cache()
    init_db(str(database_path))
    now = datetime.now(timezone.utc).isoformat()

    connection = open_connection(str(database_path))
    try:
        connection.execute(
            """
            INSERT INTO stores (store_id, display_name, name, address, is_active, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            ("store-a", "Store A", "Store A", None, 1, now, now),
        )
        connection.execute(
            """
            INSERT INTO devices (
                device_id,
                store_id,
                created_at,
                label,
                hostname,
                os,
                connector_version,
                last_seen_at,
                connected_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "device-a",
                "store-a",
                now,
                "Scale A",
                "scale-a",
                "linux",
                "1.0.0",
                now,
                now,
            ),
        )
        connection.execute(
            """
            INSERT INTO users (user_id, is_banned, ban_reason, created_at, updated_at, last_seen_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            ("user-a", 0, None, now, now, now),
        )
        connection.execute(
            """
            INSERT INTO user_identities (
                provider,
                provider_user_id,
                provider_chat_id,
                username,
                display_name,
                user_id,
                created_at,
                updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            ("telegram", "worker-user", "worker-chat", "worker", "Worker", "user-a", now, now),
        )
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
            (str(uuid.uuid4()), "store-a", "user-a", "operator", now, None, None, None),
        )
        connection.commit()

        _, _ = create_event_with_deliveries(
            connection,
            event_type=EVENT_DEFECT_DETECTED,
            store_id="store-a",
            device_id="device-a",
            occurred_at=now,
            payload={
                "event_type": EVENT_DEFECT_DETECTED,
                "store_name": "Store A",
                "device_display_name": "Scale A",
                "occurred_at": now,
                "fruit_name": "banana",
                "defect_type": "bruise",
                "result_id": "1",
                "can_show_image": True,
            },
            result_id="1",
            fruit_name="banana",
            defect_type="bruise",
        )
        _, _ = create_event_with_deliveries(
            connection,
            event_type=EVENT_DEFECT_DETECTED,
            store_id="store-a",
            device_id="device-a",
            occurred_at=now,
            payload={
                "event_type": EVENT_DEFECT_DETECTED,
                "store_name": "Store A",
                "device_display_name": "Scale A",
                "occurred_at": now,
                "fruit_name": "apple",
                "defect_type": "spot",
                "result_id": "2",
                "can_show_image": True,
            },
            result_id="2",
            fruit_name="apple",
            defect_type="spot",
        )
        connection.commit()
    finally:
        connection.close()

    worker = NotificationDeliveryWorker(
        database_path=str(database_path),
        push_base_url="http://tgbot.internal",
        push_endpoint_path="/internal/notifications/push",
        batch_size=10,
        timeout_seconds=5.0,
        poll_interval_seconds=1.0,
        enabled=True,
    )

    with sqlite3.connect(database_path) as connection:
        connection.row_factory = sqlite3.Row
        delivery_ids = [
            row["notification_delivery_id"]
            for row in connection.execute(
                """
                SELECT notification_delivery_id
                FROM notification_deliveries
                ORDER BY created_at ASC, notification_delivery_id ASC
                """
            ).fetchall()
        ]
    first_id, second_id = delivery_ids

    async def _first_push_batch(*, batch_id: str, deliveries):
        _ = batch_id
        _ = deliveries
        return {
            "batch_id": "b1",
            "results": [
                {"notification_delivery_id": first_id, "status": "sent"},
                {
                    "notification_delivery_id": second_id,
                    "status": "failed",
                    "failure_reason": "transport_timeout",
                },
            ],
        }

    worker._push_batch = _first_push_batch  # type: ignore[method-assign]
    asyncio.run(worker.run_once())

    with sqlite3.connect(database_path) as connection:
        connection.row_factory = sqlite3.Row
        first_row = connection.execute(
            "SELECT status FROM notification_deliveries WHERE notification_delivery_id = ?",
            (first_id,),
        ).fetchone()
        second_row = connection.execute(
            "SELECT status, failure_reason FROM notification_deliveries WHERE notification_delivery_id = ?",
            (second_id,),
        ).fetchone()
    assert first_row is not None and first_row["status"] == "sent"
    assert second_row is not None
    assert second_row["status"] == "pending"
    assert second_row["failure_reason"] == "transport_timeout"

    async def _second_push_batch(*, batch_id: str, deliveries):
        _ = batch_id
        _ = deliveries
        return {
            "batch_id": "b2",
            "results": [
                {
                    "notification_delivery_id": second_id,
                    "status": "failed",
                    "failure_reason": "telegram_forbidden",
                }
            ],
        }

    worker._push_batch = _second_push_batch  # type: ignore[method-assign]
    asyncio.run(worker.run_once())

    with sqlite3.connect(database_path) as connection:
        connection.row_factory = sqlite3.Row
        second_final = connection.execute(
            "SELECT status, failure_reason FROM notification_deliveries WHERE notification_delivery_id = ?",
            (second_id,),
        ).fetchone()
    assert second_final is not None
    assert second_final["status"] == "failed"
    assert second_final["failure_reason"] == "telegram_forbidden"
    clear_roles_cache()


def test_cleanup_stale_notification_deliveries_marks_rows_failed(tmp_path: Path):
    database_path = tmp_path / "onlinemainserver.db"
    init_db(str(database_path))
    now = datetime.now(timezone.utc).isoformat()
    with sqlite3.connect(database_path) as connection:
        connection.execute(
            """
            INSERT INTO notification_events (
                notification_event_id,
                event_type,
                store_id,
                device_id,
                occurred_at,
                result_id,
                fruit_name,
                defect_type,
                created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "event-1",
                EVENT_DEFECT_DETECTED,
                "store-a",
                "device-a",
                now,
                "1",
                "banana",
                "bruise",
                now,
            ),
        )
        for delivery_id, status, provider_user_id in [
            ("del-pending", "pending", "cleanup-user-1"),
            ("del-sending", "sending", "cleanup-user-2"),
            ("del-sent", "sent", "cleanup-user-3"),
        ]:
            connection.execute(
                """
                INSERT INTO notification_deliveries (
                    notification_delivery_id,
                    notification_event_id,
                    provider_user_id,
                    payload_json,
                    status,
                    failure_reason,
                    last_attempt_at,
                    sent_at,
                    created_at,
                    updated_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    delivery_id,
                    "event-1",
                    provider_user_id,
                    "{}",
                    status,
                    None,
                    None,
                    None,
                    now,
                    now,
                ),
            )
        connection.commit()

    changed = cleanup_stale_notification_deliveries_once(str(database_path))
    assert changed == 2
    with sqlite3.connect(database_path) as connection:
        pending_row = connection.execute(
            "SELECT status, failure_reason FROM notification_deliveries WHERE notification_delivery_id = ?",
            ("del-pending",),
        ).fetchone()
        sending_row = connection.execute(
            "SELECT status, failure_reason FROM notification_deliveries WHERE notification_delivery_id = ?",
            ("del-sending",),
        ).fetchone()
        sent_row = connection.execute(
            "SELECT status FROM notification_deliveries WHERE notification_delivery_id = ?",
            ("del-sent",),
        ).fetchone()

    assert pending_row == ("failed", "oms_restart_stale_delivery")
    assert sending_row == ("failed", "oms_restart_stale_delivery")
    assert sent_row == ("sent",)


def test_annotated_image_cache_miss_then_hit(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    database_path = tmp_path / "onlinemainserver.db"
    blob_storage_path = tmp_path / "blobs"
    init_db(str(database_path))
    now = datetime.now(timezone.utc).isoformat()

    image = Image.new("RGB", (32, 24), color=(240, 180, 120))
    input_buffer = BytesIO()
    image.save(input_buffer, format="JPEG")
    source_bytes = input_buffer.getvalue()

    source_blob_id = "source-blob-1"
    source_blob_path = blob_storage_path / source_blob_id
    blob_storage_path.mkdir(parents=True, exist_ok=True)
    source_blob_path.write_bytes(source_bytes)

    with sqlite3.connect(database_path) as connection:
        connection.execute(
            """
            INSERT INTO stores (store_id, display_name, name, address, is_active, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            ("store-a", "Store A", "Store A", None, 1, now, now),
        )
        connection.execute(
            """
            INSERT INTO devices (
                device_id,
                store_id,
                created_at,
                label,
                hostname,
                os,
                connector_version,
                last_seen_at,
                connected_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "device-a",
                "store-a",
                now,
                "Scale A",
                "scale-a",
                "linux",
                "1.0.0",
                now,
                now,
            ),
        )
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
                "device-a",
                "image-1",
                now,
                now,
                json.dumps(
                    {
                        "session_id": "s1",
                        "image_id": "image-1",
                        "timestamp": now,
                        "weight_grams": 123.0,
                        "fruits": [],
                    }
                ),
            ),
        )
        connection.execute(
            """
            INSERT INTO blobs (
                blob_id,
                device_id,
                path,
                content_type,
                size_bytes,
                sha256,
                created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                source_blob_id,
                "device-a",
                str(source_blob_path.resolve()),
                "image/jpeg",
                len(source_bytes),
                "dummy",
                now,
            ),
        )
        connection.commit()

    send_command_calls: list[str] = []

    async def _fake_send_command(*, device_id: str, request_type: str, params: dict, timeout_s: float):
        _ = params
        _ = timeout_s
        send_command_calls.append(device_id)
        assert request_type == "request_image"
        return {"status": "ok", "data": {"blob_id": source_blob_id}}

    monkeypatch.setattr("app.notification_images.send_command", _fake_send_command)

    first_result = asyncio.run(
        get_or_create_annotated_image(
            database_path=str(database_path),
            blob_storage_dir=str(blob_storage_path),
            result_id="1",
            cache_ttl_seconds=3600,
            request_timeout_seconds=3.0,
        )
    )
    assert first_result.cache_hit is False
    assert first_result.path.exists()
    assert len(send_command_calls) == 1

    async def _send_command_should_not_run(*, device_id: str, request_type: str, params: dict, timeout_s: float):
        _ = device_id
        _ = request_type
        _ = params
        _ = timeout_s
        raise AssertionError("send_command should not be called on cache hit")

    monkeypatch.setattr("app.notification_images.send_command", _send_command_should_not_run)
    second_result = asyncio.run(
        get_or_create_annotated_image(
            database_path=str(database_path),
            blob_storage_dir=str(blob_storage_path),
            result_id="1",
            cache_ttl_seconds=3600,
            request_timeout_seconds=3.0,
        )
    )
    assert second_result.cache_hit is True
    assert second_result.path.exists()
