from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from urllib.parse import parse_qs, urlparse

import pytest
from fastapi.testclient import TestClient

from app.main import app


def _admin_headers() -> dict[str, str]:
    return {"X-ADMIN-KEY": "admin-test-key"}


def _bot_headers() -> dict[str, str]:
    return {"Authorization": "Bearer bot-service-token"}


def _webapp_headers(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture()
def client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    database_path = tmp_path / "onlinemainserver.db"
    monkeypatch.setenv("ADMIN_KEY", "admin-test-key")
    monkeypatch.setenv("SECRET_SALT", "secret-test-salt")
    monkeypatch.setenv("TGBOT_SERVICE_TOKEN", "bot-service-token")
    monkeypatch.setenv("TGBOT_INTERNAL_BASE_URL", "http://tgbot-internal")
    monkeypatch.setenv("TGBOT_INTERNAL_AUTH_TOKEN", "internal-auth-token")
    monkeypatch.setenv("TELEGRAM_BOT_USERNAME", "freshguard_test_bot")
    monkeypatch.setenv("PUBLIC_BASE_URL", "http://testserver")
    monkeypatch.setenv("DATABASE_PATH", str(database_path))
    monkeypatch.setenv("OMS_ADMIN_BOOTSTRAP_USERNAME", "superadmin")
    monkeypatch.setenv("OMS_ADMIN_BOOTSTRAP_PASSWORD", "super-password")
    with TestClient(app) as test_client:
        yield test_client


def _create_store(client: TestClient, *, display_name: str) -> dict:
    response = client.post(
        "/admin/v1/stores",
        json={"display_name": display_name, "is_active": True},
        headers=_admin_headers(),
    )
    assert response.status_code == 201
    return response.json()


def _ensure_bot_user(
    client: TestClient,
    *,
    provider_user_id: str,
    provider_chat_id: str,
    username: str,
    display_name: str,
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


def _assign_membership(
    client: TestClient,
    *,
    user_id: str,
    store_id: str,
    role: str,
) -> None:
    response = client.put(
        f"/admin/v1/users/{user_id}/stores/{store_id}/membership",
        json={"role": role, "set_active_store": False},
        headers=_admin_headers(),
    )
    assert response.status_code == 200


def _login_via_miniapp(
    client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
    *,
    provider_user_id: str,
    username: str,
) -> str:
    def _fake_verify(*, init_data: str, settings):
        _ = init_data
        _ = settings
        return SimpleNamespace(
            provider_user_id=provider_user_id,
            username=username,
            display_name=username,
        )

    monkeypatch.setattr(
        "app.admin_ui.verify_webapp_init_data_via_tgbot",
        _fake_verify,
    )
    response = client.post(
        "/admin/auth/telegram/miniapp",
        json={"init_data": "test-init-data"},
    )
    assert response.status_code == 200
    payload = response.json()
    token = payload.get("webapp_token", "")
    assert isinstance(token, str)
    assert token.strip()
    return token


def test_miniapp_login_creates_session_and_applies_store_scope(
    client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
):
    scoped_store = _create_store(client, display_name="Scoped Store")
    hidden_store = _create_store(client, display_name="Hidden Store")
    user = _ensure_bot_user(
        client,
        provider_user_id="12345",
        provider_chat_id="chat-12345",
        username="scope_admin",
        display_name="Scope Admin",
    )
    _assign_membership(
        client,
        user_id=user["user_id"],
        store_id=scoped_store["store_id"],
        role="store_admin",
    )

    webapp_token = _login_via_miniapp(
        client,
        monkeypatch,
        provider_user_id="12345",
        username="scope_admin",
    )

    stores_response = client.get("/admin/stores?include_inactive=true", headers=_webapp_headers(webapp_token))
    assert stores_response.status_code == 200
    assert "Scoped Store" in stores_response.text
    assert "Hidden Store" not in stores_response.text

    hidden_detail = client.get(
        f"/admin/stores/{hidden_store['store_id']}",
        headers=_webapp_headers(webapp_token),
    )
    assert hidden_detail.status_code == 404


def test_browser_telegram_challenge_login_and_single_use_token(client: TestClient):
    store = _create_store(client, display_name="Challenge Store")
    user = _ensure_bot_user(
        client,
        provider_user_id="67890",
        provider_chat_id="chat-67890",
        username="challenge_admin",
        display_name="Challenge Admin",
    )
    _assign_membership(
        client,
        user_id=user["user_id"],
        store_id=store["store_id"],
        role="store_admin",
    )

    start_response = client.post("/admin/auth/telegram/challenge/start")
    assert start_response.status_code == 200
    payload = start_response.json()
    deep_link = payload["deep_link"]
    start_param = parse_qs(urlparse(deep_link).query)["start"][0]
    nonce = start_param.removeprefix("admin_login_")

    claim_response = client.post(
        "/bot/v1/admin-ui/login/claim",
        json={"nonce": nonce, "provider_user_id": "67890"},
        headers=_bot_headers(),
    )
    assert claim_response.status_code == 200
    completion_url = claim_response.json()["completion_url"]
    parsed_completion = urlparse(completion_url)
    completion_path = parsed_completion.path
    if parsed_completion.query:
        completion_path = f"{completion_path}?{parsed_completion.query}"

    complete_response = client.get(completion_path, follow_redirects=False)
    assert complete_response.status_code == 303
    assert complete_response.headers["location"] == "/admin"

    dashboard = client.get("/admin")
    assert dashboard.status_code == 200

    replay_response = client.get(completion_path, follow_redirects=False)
    assert replay_response.status_code == 303
    assert replay_response.headers["location"].startswith("/admin/login?")


def test_store_admin_cannot_assign_same_or_higher_priority_role(
    client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
):
    store = _create_store(client, display_name="Hierarchy Store")
    actor = _ensure_bot_user(
        client,
        provider_user_id="24680",
        provider_chat_id="chat-24680",
        username="hierarchy_actor",
        display_name="Hierarchy Actor",
    )
    target = _ensure_bot_user(
        client,
        provider_user_id="24681",
        provider_chat_id="chat-24681",
        username="hierarchy_target",
        display_name="Hierarchy Target",
    )
    _assign_membership(
        client,
        user_id=actor["user_id"],
        store_id=store["store_id"],
        role="store_admin",
    )
    _assign_membership(
        client,
        user_id=target["user_id"],
        store_id=store["store_id"],
        role="operator",
    )
    webapp_token = _login_via_miniapp(
        client,
        monkeypatch,
        provider_user_id="24680",
        username="hierarchy_actor",
    )

    elevate_response = client.post(
        f"/admin/stores/{store['store_id']}/memberships",
        data={
            "user_id": target["user_id"],
            "role": "store_admin",
            "set_active_store": "false",
            "confirm": "yes",
        },
        headers=_webapp_headers(webapp_token),
        follow_redirects=False,
    )
    assert elevate_response.status_code == 403


def test_miniapp_logout_revokes_webapp_token(
    client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
):
    store = _create_store(client, display_name="Logout Store")
    user = _ensure_bot_user(
        client,
        provider_user_id="33333",
        provider_chat_id="chat-33333",
        username="logout_admin",
        display_name="Logout Admin",
    )
    _assign_membership(
        client,
        user_id=user["user_id"],
        store_id=store["store_id"],
        role="store_admin",
    )
    webapp_token = _login_via_miniapp(
        client,
        monkeypatch,
        provider_user_id="33333",
        username="logout_admin",
    )

    logout_response = client.post(
        "/admin/logout",
        headers=_webapp_headers(webapp_token),
        follow_redirects=False,
    )
    assert logout_response.status_code == 303
    assert logout_response.headers["location"] == "/admin/login"

    stores_response = client.get(
        "/admin/stores",
        headers=_webapp_headers(webapp_token),
        follow_redirects=False,
    )
    assert stores_response.status_code == 303
    assert stores_response.headers["location"] == "/admin/login"
