from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
import sqlite3
import uuid

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.roles import clear_roles_cache
from app.security import hash_token


@pytest.fixture()
def client_and_db(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    database_path = tmp_path / "onlinemainserver.db"
    monkeypatch.setenv("ADMIN_KEY", "admin-test-key")
    monkeypatch.setenv("SECRET_SALT", "secret-test-salt")
    monkeypatch.setenv("TGBOT_SERVICE_TOKEN", "bot-service-token")
    monkeypatch.setenv("DATABASE_PATH", str(database_path))
    clear_roles_cache()

    with TestClient(app) as client:
        yield client, database_path

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
    created_by_user_id: str | None = None,
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
                created_by_user_id,
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


def _fetch_count(database_path: Path, query: str, params: tuple = ()) -> int:
    row = _fetch_one(database_path, query, params)
    assert row is not None
    return int(row[0])


def _prepare_store_admin(
    client: TestClient,
    database_path: Path,
    *,
    provider_user_id: str,
    provider_chat_id: str,
    username: str,
    store_display_name: str,
) -> tuple[dict, dict]:
    user = _ensure_user(
        client,
        provider_user_id=provider_user_id,
        provider_chat_id=provider_chat_id,
        username=username,
    )
    store = _create_store(client, display_name=store_display_name)
    _seed_membership(
        database_path,
        store_id=store["store_id"],
        user_id=user["user_id"],
        role="store_admin",
    )
    _set_user_context(
        database_path,
        user_id=user["user_id"],
        active_store_id=store["store_id"],
    )
    return user, store


def test_invite_creation_success(client_and_db):
    client, database_path = client_and_db
    inviter, store = _prepare_store_admin(
        client,
        database_path,
        provider_user_id="telegram-admin-create-1",
        provider_chat_id="telegram-chat-admin-create-1",
        username="admin_create_user",
        store_display_name="Invite Source Store",
    )

    response = client.post(
        "/bot/v1/invites/create",
        json={
            "provider": "telegram",
            "provider_user_id": "telegram-admin-create-1",
        },
        headers=_bot_headers(),
    )
    assert response.status_code == 200
    body = response.json()
    assert body["invite_id"]
    assert body["invite_code"].isdigit()
    assert len(body["invite_code"]) == 6
    assert body["store_id"] == store["store_id"]
    assert body["role"] == "operator"
    assert body["max_uses"] == 1

    invite_row = _fetch_one(
        database_path,
        """
        SELECT code_hash, role, created_by_user_id, max_uses, used_count
        FROM staff_invites
        WHERE invite_id = ?
        """,
        (body["invite_id"],),
    )
    assert invite_row is not None
    assert invite_row["code_hash"] != body["invite_code"]
    assert invite_row["role"] == "operator"
    assert invite_row["created_by_user_id"] == inviter["user_id"]
    assert int(invite_row["max_uses"]) == 1
    assert int(invite_row["used_count"]) == 0


def test_invite_redeem_success_updates_membership_and_context(client_and_db):
    client, database_path = client_and_db
    _, store = _prepare_store_admin(
        client,
        database_path,
        provider_user_id="telegram-admin-redeem-1",
        provider_chat_id="telegram-chat-admin-redeem-1",
        username="admin_redeem_user",
        store_display_name="Redeem Store",
    )
    invite_response = client.post(
        "/bot/v1/invites/create",
        json={
            "provider": "telegram",
            "provider_user_id": "telegram-admin-redeem-1",
            "role": "operator",
        },
        headers=_bot_headers(),
    )
    assert invite_response.status_code == 200
    invite_code = invite_response.json()["invite_code"]

    invitee = _ensure_user(
        client,
        provider_user_id="telegram-invitee-redeem-1",
        provider_chat_id="telegram-chat-invitee-redeem-1",
        username="invitee_redeem_user",
    )
    redeem_response = client.post(
        "/bot/v1/invites/redeem",
        json={
            "provider": "telegram",
            "provider_user_id": "telegram-invitee-redeem-1",
            "invite_code": invite_code,
        },
        headers=_bot_headers(),
    )
    assert redeem_response.status_code == 200
    body = redeem_response.json()
    assert body["status"] == "linked"
    assert body["already_linked"] is False
    assert body["store"]["store_id"] == store["store_id"]
    assert body["store"]["display_name"] == "Redeem Store"
    assert body["role"] == "operator"

    membership_row = _fetch_one(
        database_path,
        """
        SELECT role, revoked_at
        FROM store_memberships
        WHERE store_id = ? AND user_id = ?
        """,
        (store["store_id"], invitee["user_id"]),
    )
    assert membership_row is not None
    assert membership_row["role"] == "operator"
    assert membership_row["revoked_at"] is None

    context_row = _fetch_one(
        database_path,
        """
        SELECT active_store_id, active_device_id
        FROM user_context
        WHERE user_id = ?
        """,
        (invitee["user_id"],),
    )
    assert context_row is not None
    assert context_row["active_store_id"] == store["store_id"]
    assert context_row["active_device_id"] is None

    invite_row = _fetch_one(
        database_path,
        """
        SELECT used_count
        FROM staff_invites
        WHERE store_id = ?
        """,
        (store["store_id"],),
    )
    assert invite_row is not None
    assert int(invite_row["used_count"]) == 1


def test_redeem_same_store_twice_is_idempotent(client_and_db):
    client, database_path = client_and_db
    _, store = _prepare_store_admin(
        client,
        database_path,
        provider_user_id="telegram-admin-idempotent-1",
        provider_chat_id="telegram-chat-admin-idempotent-1",
        username="admin_idempotent_user",
        store_display_name="Idempotent Store",
    )
    invite_response = client.post(
        "/bot/v1/invites/create",
        json={
            "provider": "telegram",
            "provider_user_id": "telegram-admin-idempotent-1",
            "role": "operator",
            "max_uses": 2,
        },
        headers=_bot_headers(),
    )
    assert invite_response.status_code == 200
    invite_code = invite_response.json()["invite_code"]

    invitee = _ensure_user(
        client,
        provider_user_id="telegram-invitee-idempotent-1",
        provider_chat_id="telegram-chat-invitee-idempotent-1",
        username="invitee_idempotent_user",
    )

    first = client.post(
        "/bot/v1/invites/redeem",
        json={
            "provider": "telegram",
            "provider_user_id": "telegram-invitee-idempotent-1",
            "invite_code": invite_code,
        },
        headers=_bot_headers(),
    )
    assert first.status_code == 200
    assert first.json()["already_linked"] is False

    second = client.post(
        "/bot/v1/invites/redeem",
        json={
            "provider": "telegram",
            "provider_user_id": "telegram-invitee-idempotent-1",
            "invite_code": invite_code,
        },
        headers=_bot_headers(),
    )
    assert second.status_code == 200
    assert second.json()["already_linked"] is True
    assert second.json()["store"]["store_id"] == store["store_id"]

    membership_count = _fetch_count(
        database_path,
        """
        SELECT COUNT(*)
        FROM store_memberships
        WHERE store_id = ? AND user_id = ? AND revoked_at IS NULL
        """,
        (store["store_id"], invitee["user_id"]),
    )
    assert membership_count == 1

    invite_row = _fetch_one(
        database_path,
        """
        SELECT used_count
        FROM staff_invites
        WHERE store_id = ?
        """,
        (store["store_id"],),
    )
    assert invite_row is not None
    assert int(invite_row["used_count"]) == 1


def test_redeem_supports_unlimited_staff_invites(client_and_db):
    client, database_path = client_and_db
    inviter, store = _prepare_store_admin(
        client,
        database_path,
        provider_user_id="telegram-admin-unlimited-1",
        provider_chat_id="telegram-chat-admin-unlimited-1",
        username="admin_unlimited_user",
        store_display_name="Unlimited Invite Store",
    )
    invite_code = "999999"
    invite_id = str(uuid.uuid4())

    with sqlite3.connect(database_path) as connection:
        connection.execute(
            """
            INSERT INTO staff_invites (
                invite_id,
                store_id,
                code_hash,
                role,
                created_by_user_id,
                created_at,
                expires_at,
                max_uses,
                used_count,
                revoked_at,
                note
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                invite_id,
                store["store_id"],
                hash_token(invite_code, "secret-test-salt"),
                "viewer",
                inviter["user_id"],
                datetime.now(timezone.utc).isoformat(),
                None,
                None,
                0,
                None,
                "unlimited invite for redeem test",
            ),
        )
        connection.commit()

    invitee = _ensure_user(
        client,
        provider_user_id="telegram-invitee-unlimited-1",
        provider_chat_id="telegram-chat-invitee-unlimited-1",
        username="invitee_unlimited_user",
    )
    redeem_response = client.post(
        "/bot/v1/invites/redeem",
        json={
            "provider": "telegram",
            "provider_user_id": "telegram-invitee-unlimited-1",
            "invite_code": invite_code,
        },
        headers=_bot_headers(),
    )
    assert redeem_response.status_code == 200
    body = redeem_response.json()
    assert body["status"] == "linked"
    assert body["already_linked"] is False
    assert body["store"]["store_id"] == store["store_id"]
    assert body["role"] == "viewer"

    membership_row = _fetch_one(
        database_path,
        """
        SELECT role, revoked_at
        FROM store_memberships
        WHERE store_id = ? AND user_id = ?
        """,
        (store["store_id"], invitee["user_id"]),
    )
    assert membership_row is not None
    assert membership_row["role"] == "viewer"
    assert membership_row["revoked_at"] is None

    invite_row = _fetch_one(
        database_path,
        """
        SELECT used_count, max_uses, expires_at
        FROM staff_invites
        WHERE invite_id = ?
        """,
        (invite_id,),
    )
    assert invite_row is not None
    assert int(invite_row["used_count"]) == 1
    assert invite_row["max_uses"] is None
    assert invite_row["expires_at"] is None


@pytest.mark.parametrize(
    ("update_sql", "update_value", "expected_detail"),
    [
        (
            "UPDATE staff_invites SET expires_at = ?",
            (datetime.now(timezone.utc) - timedelta(minutes=5)).isoformat(),
            "invite_expired",
        ),
        (
            "UPDATE staff_invites SET revoked_at = ?",
            datetime.now(timezone.utc).isoformat(),
            "invite_revoked",
        ),
        (
            "UPDATE staff_invites SET used_count = max_uses",
            None,
            "invite_exhausted",
        ),
    ],
)
def test_redeem_rejects_invalid_invite_states(
    client_and_db,
    update_sql: str,
    update_value: str | None,
    expected_detail: str,
):
    client, database_path = client_and_db
    _, _store = _prepare_store_admin(
        client,
        database_path,
        provider_user_id=f"telegram-admin-invalid-{expected_detail}",
        provider_chat_id=f"telegram-chat-admin-invalid-{expected_detail}",
        username=f"admin_invalid_{expected_detail}",
        store_display_name=f"Invalid State Store {expected_detail}",
    )
    invite_response = client.post(
        "/bot/v1/invites/create",
        json={
            "provider": "telegram",
            "provider_user_id": f"telegram-admin-invalid-{expected_detail}",
        },
        headers=_bot_headers(),
    )
    assert invite_response.status_code == 200
    invite_code = invite_response.json()["invite_code"]

    _ensure_user(
        client,
        provider_user_id=f"telegram-invitee-invalid-{expected_detail}",
        provider_chat_id=f"telegram-chat-invitee-invalid-{expected_detail}",
        username=f"invitee_invalid_{expected_detail}",
    )

    with sqlite3.connect(database_path) as connection:
        if update_value is None:
            connection.execute(update_sql)
        else:
            connection.execute(update_sql, (update_value,))
        connection.commit()

    redeem_response = client.post(
        "/bot/v1/invites/redeem",
        json={
            "provider": "telegram",
            "provider_user_id": f"telegram-invitee-invalid-{expected_detail}",
            "invite_code": invite_code,
        },
        headers=_bot_headers(),
    )
    assert redeem_response.status_code == 400
    assert redeem_response.json() == {"detail": expected_detail}


def test_redeem_rejects_missing_and_malformed_codes(client_and_db):
    client, _database_path = client_and_db
    _ensure_user(
        client,
        provider_user_id="telegram-invitee-missing-1",
        provider_chat_id="telegram-chat-invitee-missing-1",
        username="invitee_missing_user",
    )

    missing_response = client.post(
        "/bot/v1/invites/redeem",
        json={
            "provider": "telegram",
            "provider_user_id": "telegram-invitee-missing-1",
            "invite_code": "123456",
        },
        headers=_bot_headers(),
    )
    assert missing_response.status_code == 404
    assert missing_response.json() == {"detail": "invite_not_found"}

    malformed_response = client.post(
        "/bot/v1/invites/redeem",
        json={
            "provider": "telegram",
            "provider_user_id": "telegram-invitee-missing-1",
            "invite_code": "12ab",
        },
        headers=_bot_headers(),
    )
    assert malformed_response.status_code == 422


def test_invite_creation_requires_permission(client_and_db):
    client, database_path = client_and_db
    user = _ensure_user(
        client,
        provider_user_id="telegram-operator-create-1",
        provider_chat_id="telegram-chat-operator-create-1",
        username="operator_create_user",
    )
    store = _create_store(client, display_name="Operator Store")
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

    response = client.post(
        "/bot/v1/invites/create",
        json={
            "provider": "telegram",
            "provider_user_id": "telegram-operator-create-1",
        },
        headers=_bot_headers(),
    )
    assert response.status_code == 403
    assert response.json() == {"detail": "permission_denied"}


def test_list_stores_and_select_active_store(client_and_db):
    client, database_path = client_and_db
    user = _ensure_user(
        client,
        provider_user_id="telegram-viewer-list-1",
        provider_chat_id="telegram-chat-viewer-list-1",
        username="viewer_list_user",
    )
    active_store = _create_store(client, display_name="Active Listed Store", is_active=True)
    inactive_store = _create_store(client, display_name="Inactive Listed Store", is_active=False)
    _seed_membership(
        database_path,
        store_id=active_store["store_id"],
        user_id=user["user_id"],
        role="viewer",
    )
    _seed_membership(
        database_path,
        store_id=inactive_store["store_id"],
        user_id=user["user_id"],
        role="viewer",
    )
    _set_user_context(
        database_path,
        user_id=user["user_id"],
        active_store_id=active_store["store_id"],
    )

    list_response = client.get(
        "/bot/v1/stores",
        params={
            "provider": "telegram",
            "provider_user_id": "telegram-viewer-list-1",
        },
        headers=_bot_headers(),
    )
    assert list_response.status_code == 200
    items = {item["store_id"]: item for item in list_response.json()["items"]}
    assert items[active_store["store_id"]]["is_active_store"] is True
    assert items[active_store["store_id"]]["store_is_active"] is True
    assert inactive_store["store_id"] not in items

    select_response = client.post(
        "/bot/v1/context/active_store",
        json={
            "provider": "telegram",
            "provider_user_id": "telegram-viewer-list-1",
            "store_id": inactive_store["store_id"],
        },
        headers=_bot_headers(),
    )
    assert select_response.status_code == 404
    assert select_response.json() == {"detail": "store_not_available"}

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
    assert context_row["active_store_id"] == active_store["store_id"]
    assert context_row["active_device_id"] is None


def test_revoke_self_last_membership_clears_context(client_and_db):
    client, database_path = client_and_db
    user = _ensure_user(
        client,
        provider_user_id="telegram-revoke-last-1",
        provider_chat_id="telegram-chat-revoke-last-1",
        username="revoke_last_user",
    )
    store = _create_store(client, display_name="Single Membership Store")
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
        active_device_id="device-1",
    )

    response = client.post(
        "/bot/v1/memberships/revoke_self",
        json={
            "provider": "telegram",
            "provider_user_id": "telegram-revoke-last-1",
            "store_id": store["store_id"],
        },
        headers=_bot_headers(),
    )
    assert response.status_code == 200
    assert response.json() == {
        "status": "revoked",
        "revoked_store_id": store["store_id"],
        "active_store_id": None,
        "active_device_id": None,
    }

    membership_row = _fetch_one(
        database_path,
        """
        SELECT revoked_at
        FROM store_memberships
        WHERE store_id = ? AND user_id = ?
        """,
        (store["store_id"], user["user_id"]),
    )
    assert membership_row is not None
    assert membership_row["revoked_at"] is not None

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
    assert context_row["active_store_id"] is None
    assert context_row["active_device_id"] is None


def test_revoke_self_switches_to_remaining_store(client_and_db):
    client, database_path = client_and_db
    user = _ensure_user(
        client,
        provider_user_id="telegram-revoke-switch-1",
        provider_chat_id="telegram-chat-revoke-switch-1",
        username="revoke_switch_user",
    )
    first_store = _create_store(client, display_name="First Membership Store")
    second_store = _create_store(client, display_name="Second Membership Store")
    _seed_membership(
        database_path,
        store_id=first_store["store_id"],
        user_id=user["user_id"],
        role="viewer",
    )
    _seed_membership(
        database_path,
        store_id=second_store["store_id"],
        user_id=user["user_id"],
        role="viewer",
    )
    _set_user_context(
        database_path,
        user_id=user["user_id"],
        active_store_id=first_store["store_id"],
        active_device_id="device-1",
    )

    response = client.post(
        "/bot/v1/memberships/revoke_self",
        json={
            "provider": "telegram",
            "provider_user_id": "telegram-revoke-switch-1",
            "store_id": first_store["store_id"],
        },
        headers=_bot_headers(),
    )
    assert response.status_code == 200
    assert response.json() == {
        "status": "revoked",
        "revoked_store_id": first_store["store_id"],
        "active_store_id": second_store["store_id"],
        "active_device_id": None,
    }

    revoked_row = _fetch_one(
        database_path,
        """
        SELECT revoked_at
        FROM store_memberships
        WHERE store_id = ? AND user_id = ?
        """,
        (first_store["store_id"], user["user_id"]),
    )
    assert revoked_row is not None
    assert revoked_row["revoked_at"] is not None

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
    assert context_row["active_store_id"] == second_store["store_id"]
    assert context_row["active_device_id"] is None
