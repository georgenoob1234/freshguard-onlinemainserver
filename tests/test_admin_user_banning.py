from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.main import app


@pytest.fixture()
def client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    database_path = tmp_path / "onlinemainserver.db"
    monkeypatch.setenv("ADMIN_KEY", "admin-test-key")
    monkeypatch.setenv("SECRET_SALT", "secret-test-salt")
    monkeypatch.setenv("TGBOT_SERVICE_TOKEN", "bot-service-token")
    monkeypatch.setenv("DATABASE_PATH", str(database_path))

    with TestClient(app) as test_client:
        yield test_client


def _admin_headers() -> dict[str, str]:
    return {"X-ADMIN-KEY": "admin-test-key"}


def _bot_headers() -> dict[str, str]:
    return {"Authorization": "Bearer bot-service-token"}


def _ensure_payload(
    *,
    provider_user_id: str = "telegram-user-admin-1",
    provider_chat_id: str = "telegram-chat-admin-1",
    username: str = "sample_username",
    display_name: str = "Sample User",
) -> dict[str, str]:
    return {
        "provider": "telegram",
        "provider_user_id": provider_user_id,
        "provider_chat_id": provider_chat_id,
        "username": username,
        "display_name": display_name,
    }


def _create_bot_user(
    client: TestClient,
    *,
    provider_user_id: str,
    provider_chat_id: str,
    username: str,
    display_name: str = "Sample User",
) -> dict:
    ensure_response = client.post(
        "/bot/v1/session/ensure",
        json=_ensure_payload(
            provider_user_id=provider_user_id,
            provider_chat_id=provider_chat_id,
            username=username,
            display_name=display_name,
        ),
        headers=_bot_headers(),
    )
    assert ensure_response.status_code == 200
    return ensure_response.json()


def test_admin_endpoints_require_admin_auth(client: TestClient):
    unauthorized_lookup = client.get(
        "/admin/v1/users/lookup",
        params={"provider": "telegram", "provider_user_id": "telegram-user-unauth"},
    )
    assert unauthorized_lookup.status_code == 401

    unauthorized_patch = client.patch(
        "/admin/v1/users/some-user-id",
        json={"is_banned": True},
    )
    assert unauthorized_patch.status_code == 401


def test_lookup_identifier_rules(client: TestClient):
    missing_identifier = client.get(
        "/admin/v1/users/lookup",
        params={"provider": "telegram"},
        headers=_admin_headers(),
    )
    assert missing_identifier.status_code == 400
    assert missing_identifier.json() == {"detail": "missing_identifier"}

    unsupported_provider = client.get(
        "/admin/v1/users/lookup",
        params={"provider": "discord", "provider_user_id": "discord-user-1"},
        headers=_admin_headers(),
    )
    assert unsupported_provider.status_code == 400
    assert unsupported_provider.json() == {"detail": "unsupported_provider"}


def test_lookup_by_provider_user_id(client: TestClient):
    created = _create_bot_user(
        client,
        provider_user_id="telegram-id-lookup-1",
        provider_chat_id="telegram-chat-lookup-1",
        username="lookup_by_id_user",
    )

    found = client.get(
        "/admin/v1/users/lookup",
        params={"provider": "telegram", "provider_user_id": "telegram-id-lookup-1"},
        headers=_admin_headers(),
    )
    assert found.status_code == 200
    body = found.json()
    assert body["user_id"] == created["user_id"]
    assert body["provider"] == "telegram"
    assert body["provider_user_id"] == "telegram-id-lookup-1"
    assert body["provider_chat_id"] == "telegram-chat-lookup-1"
    assert body["username"] == "lookup_by_id_user"
    assert body["is_banned"] is False
    assert body["created_at"]
    assert body["last_seen_at"]

    not_found = client.get(
        "/admin/v1/users/lookup",
        params={"provider": "telegram", "provider_user_id": "missing-id"},
        headers=_admin_headers(),
    )
    assert not_found.status_code == 404
    assert not_found.json() == {"detail": "user_not_found"}


def test_lookup_falls_back_to_username_when_id_misses(client: TestClient):
    created = _create_bot_user(
        client,
        provider_user_id="telegram-id-fallback-1",
        provider_chat_id="telegram-chat-fallback-1",
        username="fallback_user",
    )

    found = client.get(
        "/admin/v1/users/lookup",
        params={
            "provider": "telegram",
            "provider_user_id": "missing-id",
            "username": "@Fallback_User",
        },
        headers=_admin_headers(),
    )
    assert found.status_code == 200
    assert found.json()["user_id"] == created["user_id"]


def test_lookup_by_username_single_not_found_and_ambiguous(client: TestClient):
    single = _create_bot_user(
        client,
        provider_user_id="telegram-id-username-single-1",
        provider_chat_id="telegram-chat-username-single-1",
        username="UniqueLookupUser",
    )

    single_match = client.get(
        "/admin/v1/users/lookup",
        params={"provider": "telegram", "username": "@uniquelookupuser"},
        headers=_admin_headers(),
    )
    assert single_match.status_code == 200
    assert single_match.json()["user_id"] == single["user_id"]

    missing = client.get(
        "/admin/v1/users/lookup",
        params={"provider": "telegram", "username": "no_such_user"},
        headers=_admin_headers(),
    )
    assert missing.status_code == 404
    assert missing.json() == {"detail": "user_not_found"}

    _create_bot_user(
        client,
        provider_user_id="telegram-id-ambiguous-1",
        provider_chat_id="telegram-chat-ambiguous-1",
        username="DuplicateUser",
    )
    _create_bot_user(
        client,
        provider_user_id="telegram-id-ambiguous-2",
        provider_chat_id="telegram-chat-ambiguous-2",
        username="duplicateuser",
    )

    ambiguous = client.get(
        "/admin/v1/users/lookup",
        params={"provider": "telegram", "username": "@DUPLICATEUSER"},
        headers=_admin_headers(),
    )
    assert ambiguous.status_code == 409
    ambiguous_body = ambiguous.json()
    assert ambiguous_body["detail"] == "ambiguous_username"
    assert isinstance(ambiguous_body["candidates"], list)
    assert len(ambiguous_body["candidates"]) >= 2
    assert len(ambiguous_body["candidates"]) <= 10
    candidate = ambiguous_body["candidates"][0]
    assert "user_id" in candidate
    assert "provider_user_id" in candidate
    assert "username" in candidate
    assert "display_name" in candidate
    assert "last_seen_at" in candidate


def test_patch_user_ban_unban_persists(client: TestClient):
    created = _create_bot_user(
        client,
        provider_user_id="telegram-id-patch-1",
        provider_chat_id="telegram-chat-patch-1",
        username="patch_user",
    )
    user_id = created["user_id"]

    ban_response = client.patch(
        f"/admin/v1/users/{user_id}",
        json={"is_banned": True, "reason": "policy_violation"},
        headers=_admin_headers(),
    )
    assert ban_response.status_code == 200
    assert ban_response.json()["user_id"] == user_id
    assert ban_response.json()["is_banned"] is True
    assert ban_response.json()["last_seen_at"]

    lookup_banned = client.get(
        "/admin/v1/users/lookup",
        params={"provider": "telegram", "provider_user_id": "telegram-id-patch-1"},
        headers=_admin_headers(),
    )
    assert lookup_banned.status_code == 200
    assert lookup_banned.json()["is_banned"] is True

    unban_response = client.patch(
        f"/admin/v1/users/{user_id}",
        json={"is_banned": False},
        headers=_admin_headers(),
    )
    assert unban_response.status_code == 200
    assert unban_response.json()["is_banned"] is False

    lookup_unbanned = client.get(
        "/admin/v1/users/lookup",
        params={"provider": "telegram", "provider_user_id": "telegram-id-patch-1"},
        headers=_admin_headers(),
    )
    assert lookup_unbanned.status_code == 200
    assert lookup_unbanned.json()["is_banned"] is False


def test_patch_returns_user_not_found_for_unknown_user(client: TestClient):
    response = client.patch(
        "/admin/v1/users/user-does-not-exist",
        json={"is_banned": True},
        headers=_admin_headers(),
    )
    assert response.status_code == 404
    assert response.json() == {"detail": "user_not_found"}


def test_integration_ban_then_session_ensure_returns_is_banned_true(client: TestClient):
    ensure_first = client.post(
        "/bot/v1/session/ensure",
        json=_ensure_payload(
            provider_user_id="telegram-id-integration-1",
            provider_chat_id="telegram-chat-integration-1",
            username="integration_user",
        ),
        headers=_bot_headers(),
    )
    assert ensure_first.status_code == 200
    user_id = ensure_first.json()["user_id"]
    assert ensure_first.json()["is_banned"] is False

    ban = client.patch(
        f"/admin/v1/users/{user_id}",
        json={"is_banned": True},
        headers=_admin_headers(),
    )
    assert ban.status_code == 200
    assert ban.json()["is_banned"] is True

    ensure_after_ban = client.post(
        "/bot/v1/session/ensure",
        json=_ensure_payload(
            provider_user_id="telegram-id-integration-1",
            provider_chat_id="telegram-chat-integration-1",
            username="integration_user",
        ),
        headers=_bot_headers(),
    )
    assert ensure_after_ban.status_code == 200
    assert ensure_after_ban.json()["user_id"] == user_id
    assert ensure_after_ban.json()["is_banned"] is True
