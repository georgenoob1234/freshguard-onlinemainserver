from __future__ import annotations

from datetime import datetime, timezone
import os
from pathlib import Path
import sqlite3
import uuid

import pytest
from fastapi.testclient import TestClient

from app.main import app


def _admin_headers() -> dict[str, str]:
    return {"X-ADMIN-KEY": "admin-test-key"}


def _bot_headers() -> dict[str, str]:
    return {"Authorization": "Bearer bot-service-token"}


@pytest.fixture()
def client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    database_path = tmp_path / "onlinemainserver.db"
    monkeypatch.setenv("ADMIN_KEY", "admin-test-key")
    monkeypatch.setenv("SECRET_SALT", "secret-test-salt")
    monkeypatch.setenv("TGBOT_SERVICE_TOKEN", "bot-service-token")
    monkeypatch.setenv("DATABASE_PATH", str(database_path))

    with TestClient(app) as test_client:
        yield test_client


def _database_path() -> Path:
    return Path(os.environ["DATABASE_PATH"])


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


def _create_bot_user(
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


def _seed_membership(
    *,
    user_id: str,
    store_id: str,
    role: str,
) -> str:
    membership_id = str(uuid.uuid4())
    with sqlite3.connect(_database_path()) as connection:
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
                membership_id,
                store_id,
                user_id,
                role,
                datetime.now(timezone.utc).isoformat(),
                None,
                None,
                "seeded",
            ),
        )
        connection.commit()
    return membership_id


def _seed_user_context(
    *,
    user_id: str,
    active_store_id: str | None,
    active_device_id: str | None,
) -> None:
    with sqlite3.connect(_database_path()) as connection:
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
            (user_id, active_store_id, active_device_id, datetime.now(timezone.utc).isoformat()),
        )
        connection.commit()


def _fetch_active_membership(*, user_id: str, store_id: str) -> sqlite3.Row | None:
    with sqlite3.connect(_database_path()) as connection:
        connection.row_factory = sqlite3.Row
        return connection.execute(
            """
            SELECT
                membership_id,
                user_id,
                store_id,
                role,
                created_at,
                revoked_at,
                created_by_user_id,
                note
            FROM store_memberships
            WHERE user_id = ? AND store_id = ? AND revoked_at IS NULL
            """,
            (user_id, store_id),
        ).fetchone()


def _count_active_memberships(*, user_id: str, store_id: str) -> int:
    with sqlite3.connect(_database_path()) as connection:
        return int(
            connection.execute(
                """
                SELECT COUNT(*) AS membership_count
                FROM store_memberships
                WHERE user_id = ? AND store_id = ? AND revoked_at IS NULL
                """,
                (user_id, store_id),
            ).fetchone()[0]
        )


def _fetch_user_context(*, user_id: str) -> sqlite3.Row | None:
    with sqlite3.connect(_database_path()) as connection:
        connection.row_factory = sqlite3.Row
        return connection.execute(
            """
            SELECT active_store_id, active_device_id
            FROM user_context
            WHERE user_id = ?
            """,
            (user_id,),
        ).fetchone()


def test_upsert_membership_requires_admin_auth(client: TestClient):
    response = client.put(
        "/admin/v1/users/user-1/stores/store-1/membership",
        json={"role": "viewer"},
    )
    assert response.status_code == 401
    assert response.json() == {"detail": "Unauthorized"}


def test_upsert_membership_returns_user_not_found_for_unknown_user(client: TestClient):
    store = _create_store(client, display_name="Lookup Store")

    response = client.put(
        f"/admin/v1/users/user-does-not-exist/stores/{store['store_id']}/membership",
        json={"role": "viewer"},
        headers=_admin_headers(),
    )

    assert response.status_code == 404
    assert response.json() == {"detail": "user_not_found"}


def test_upsert_membership_rejects_banned_user(client: TestClient):
    user = _create_bot_user(
        client,
        provider_user_id="telegram-membership-ban-1",
        provider_chat_id="telegram-membership-chat-ban-1",
        username="membership_ban_user",
    )
    store = _create_store(client, display_name="Ban Store")

    ban_response = client.patch(
        f"/admin/v1/users/{user['user_id']}",
        json={"is_banned": True},
        headers=_admin_headers(),
    )
    assert ban_response.status_code == 200

    response = client.put(
        f"/admin/v1/users/{user['user_id']}/stores/{store['store_id']}/membership",
        json={"role": "viewer"},
        headers=_admin_headers(),
    )

    assert response.status_code == 403
    assert response.json() == {"detail": "user_banned"}


def test_upsert_membership_returns_store_not_found_for_unknown_store(client: TestClient):
    user = _create_bot_user(
        client,
        provider_user_id="telegram-membership-store-1",
        provider_chat_id="telegram-membership-chat-store-1",
        username="membership_store_user",
    )

    response = client.put(
        f"/admin/v1/users/{user['user_id']}/stores/st_missing/membership",
        json={"role": "viewer"},
        headers=_admin_headers(),
    )

    assert response.status_code == 404
    assert response.json() == {"detail": "Store not found"}


def test_upsert_membership_rejects_unknown_role(client: TestClient):
    user = _create_bot_user(
        client,
        provider_user_id="telegram-membership-role-1",
        provider_chat_id="telegram-membership-chat-role-1",
        username="membership_role_user",
    )
    store = _create_store(client, display_name="Role Store")

    response = client.put(
        f"/admin/v1/users/{user['user_id']}/stores/{store['store_id']}/membership",
        json={"role": "does_not_exist"},
        headers=_admin_headers(),
    )

    assert response.status_code == 400
    assert response.json() == {"detail": "unknown_role"}


def test_upsert_membership_creates_membership_and_initializes_context(client: TestClient):
    user = _create_bot_user(
        client,
        provider_user_id="telegram-membership-create-1",
        provider_chat_id="telegram-membership-chat-create-1",
        username="membership_create_user",
    )
    store = _create_store(client, display_name="Create Store")

    response = client.put(
        f"/admin/v1/users/{user['user_id']}/stores/{store['store_id']}/membership",
        json={"role": "store_admin"},
        headers=_admin_headers(),
    )

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "created"
    assert body["membership"]["user_id"] == user["user_id"]
    assert body["membership"]["store_id"] == store["store_id"]
    assert body["membership"]["role"] == "store_admin"
    assert body["membership"]["created_at"]
    assert body["membership"]["revoked_at"] is None
    assert body["membership"]["created_by_user_id"] is None
    assert body["membership"]["note"] == "admin_api"
    assert body["active_store_id"] == store["store_id"]
    assert body["active_device_id"] is None

    membership_row = _fetch_active_membership(user_id=user["user_id"], store_id=store["store_id"])
    assert membership_row is not None
    assert membership_row["membership_id"] == body["membership"]["membership_id"]
    assert membership_row["role"] == "store_admin"
    assert membership_row["note"] == "admin_api"

    context_row = _fetch_user_context(user_id=user["user_id"])
    assert context_row is not None
    assert context_row["active_store_id"] == store["store_id"]
    assert context_row["active_device_id"] is None


def test_upsert_membership_updates_existing_role_in_place(client: TestClient):
    user = _create_bot_user(
        client,
        provider_user_id="telegram-membership-update-1",
        provider_chat_id="telegram-membership-chat-update-1",
        username="membership_update_user",
    )
    store = _create_store(client, display_name="Update Store")

    first_response = client.put(
        f"/admin/v1/users/{user['user_id']}/stores/{store['store_id']}/membership",
        json={"role": "viewer"},
        headers=_admin_headers(),
    )
    assert first_response.status_code == 200
    first_body = first_response.json()

    second_response = client.put(
        f"/admin/v1/users/{user['user_id']}/stores/{store['store_id']}/membership",
        json={"role": "operator"},
        headers=_admin_headers(),
    )
    assert second_response.status_code == 200
    second_body = second_response.json()

    assert second_body["status"] == "updated"
    assert second_body["membership"]["membership_id"] == first_body["membership"]["membership_id"]
    assert second_body["membership"]["created_at"] == first_body["membership"]["created_at"]
    assert second_body["membership"]["role"] == "operator"
    assert _count_active_memberships(user_id=user["user_id"], store_id=store["store_id"]) == 1

    membership_row = _fetch_active_membership(user_id=user["user_id"], store_id=store["store_id"])
    assert membership_row is not None
    assert membership_row["membership_id"] == first_body["membership"]["membership_id"]
    assert membership_row["role"] == "operator"


def test_upsert_membership_set_active_store_true_overwrites_context(client: TestClient):
    user = _create_bot_user(
        client,
        provider_user_id="telegram-membership-active-1",
        provider_chat_id="telegram-membership-chat-active-1",
        username="membership_active_user",
    )
    current_store = _create_store(client, display_name="Current Store")
    target_store = _create_store(client, display_name="Target Store")
    _seed_membership(user_id=user["user_id"], store_id=current_store["store_id"], role="root")
    _seed_user_context(
        user_id=user["user_id"],
        active_store_id=current_store["store_id"],
        active_device_id="dev_existing",
    )

    response = client.put(
        f"/admin/v1/users/{user['user_id']}/stores/{target_store['store_id']}/membership",
        json={"role": "viewer", "set_active_store": True},
        headers=_admin_headers(),
    )

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "created"
    assert body["active_store_id"] == target_store["store_id"]
    assert body["active_device_id"] is None

    context_row = _fetch_user_context(user_id=user["user_id"])
    assert context_row is not None
    assert context_row["active_store_id"] == target_store["store_id"]
    assert context_row["active_device_id"] is None


def test_upsert_membership_set_active_store_false_preserves_existing_context(client: TestClient):
    user = _create_bot_user(
        client,
        provider_user_id="telegram-membership-preserve-1",
        provider_chat_id="telegram-membership-chat-preserve-1",
        username="membership_preserve_user",
    )
    active_store = _create_store(client, display_name="Active Context Store")
    target_store = _create_store(client, display_name="Secondary Store")
    _seed_membership(user_id=user["user_id"], store_id=active_store["store_id"], role="root")
    _seed_user_context(
        user_id=user["user_id"],
        active_store_id=active_store["store_id"],
        active_device_id="dev_keep_me",
    )

    response = client.put(
        f"/admin/v1/users/{user['user_id']}/stores/{target_store['store_id']}/membership",
        json={"role": "auditor", "set_active_store": False},
        headers=_admin_headers(),
    )

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "created"
    assert body["membership"]["store_id"] == target_store["store_id"]
    assert body["membership"]["role"] == "auditor"
    assert body["active_store_id"] == active_store["store_id"]
    assert body["active_device_id"] == "dev_keep_me"

    context_row = _fetch_user_context(user_id=user["user_id"])
    assert context_row is not None
    assert context_row["active_store_id"] == active_store["store_id"]
    assert context_row["active_device_id"] == "dev_keep_me"
