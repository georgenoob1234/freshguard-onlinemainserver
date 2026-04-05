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


def _login_bootstrap(client: TestClient) -> None:
    response = client.post(
        "/admin/login",
        data={"username": "superadmin", "password": "super-password"},
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert response.headers["location"] == "/admin"


def _register_device(client: TestClient, *, store_id: str) -> str:
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
                "label": "Scope Device",
                "hostname": "scope-device",
                "os": "linux",
                "connector_version": "1.0.0",
            },
        },
    )
    assert register_response.status_code == 200
    return register_response.json()["device_id"]


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


def test_store_admin_cannot_revoke_same_priority_membership(
    client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
):
    store = _create_store(client, display_name="Revoke Hierarchy Store")
    actor = _ensure_bot_user(
        client,
        provider_user_id="24690",
        provider_chat_id="chat-24690",
        username="revoke_hierarchy_actor",
        display_name="Revoke Hierarchy Actor",
    )
    target = _ensure_bot_user(
        client,
        provider_user_id="24691",
        provider_chat_id="chat-24691",
        username="revoke_hierarchy_target",
        display_name="Revoke Hierarchy Target",
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
        role="store_admin",
    )
    actor_token = _login_via_miniapp(
        client,
        monkeypatch,
        provider_user_id="24690",
        username="revoke_hierarchy_actor",
    )

    revoke_response = client.post(
        f"/admin/stores/{store['store_id']}/memberships/revoke",
        data={"user_id": target["user_id"], "confirm": "yes"},
        headers=_webapp_headers(actor_token),
        follow_redirects=False,
    )
    assert revoke_response.status_code == 303
    assert revoke_response.headers["location"].startswith(f"/admin/stores/{store['store_id']}?error=")

    target_token = _login_via_miniapp(
        client,
        monkeypatch,
        provider_user_id="24691",
        username="revoke_hierarchy_target",
    )
    target_store_detail = client.get(
        f"/admin/stores/{store['store_id']}",
        headers=_webapp_headers(target_token),
    )
    assert target_store_detail.status_code == 200


def test_store_root_can_revoke_lower_priority_membership(
    client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
):
    store = _create_store(client, display_name="Revoke Success Store")
    actor = _ensure_bot_user(
        client,
        provider_user_id="24700",
        provider_chat_id="chat-24700",
        username="revoke_success_actor",
        display_name="Revoke Success Actor",
    )
    target = _ensure_bot_user(
        client,
        provider_user_id="24701",
        provider_chat_id="chat-24701",
        username="revoke_success_target",
        display_name="Revoke Success Target",
    )
    _assign_membership(
        client,
        user_id=actor["user_id"],
        store_id=store["store_id"],
        role="root",
    )
    _assign_membership(
        client,
        user_id=target["user_id"],
        store_id=store["store_id"],
        role="store_admin",
    )
    actor_token = _login_via_miniapp(
        client,
        monkeypatch,
        provider_user_id="24700",
        username="revoke_success_actor",
    )

    revoke_response = client.post(
        f"/admin/stores/{store['store_id']}/memberships/revoke",
        data={"user_id": target["user_id"], "confirm": "yes"},
        headers=_webapp_headers(actor_token),
        follow_redirects=False,
    )
    assert revoke_response.status_code == 303
    assert revoke_response.headers["location"].startswith(f"/admin/stores/{store['store_id']}?message=")

    def _fake_verify_target(*, init_data: str, settings):
        _ = init_data
        _ = settings
        return SimpleNamespace(
            provider_user_id="24701",
            username="revoke_success_target",
            display_name="revoke_success_target",
        )

    monkeypatch.setattr(
        "app.admin_ui.verify_webapp_init_data_via_tgbot",
        _fake_verify_target,
    )
    denied_login = client.post(
        "/admin/auth/telegram/miniapp",
        json={"init_data": "test-init-data"},
    )
    assert denied_login.status_code == 403


def test_store_admin_can_revoke_staff_invite_from_admin_ui(
    client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
):
    store = _create_store(client, display_name="Invite Revoke Store")
    actor = _ensure_bot_user(
        client,
        provider_user_id="24710",
        provider_chat_id="chat-24710",
        username="invite_revoke_actor",
        display_name="Invite Revoke Actor",
    )
    target = _ensure_bot_user(
        client,
        provider_user_id="24711",
        provider_chat_id="chat-24711",
        username="invite_revoke_target",
        display_name="Invite Revoke Target",
    )
    _assign_membership(
        client,
        user_id=actor["user_id"],
        store_id=store["store_id"],
        role="store_admin",
    )

    invite_create = client.post(
        "/bot/v1/invites/create",
        json={
            "provider": "telegram",
            "provider_user_id": "24710",
            "role": "viewer",
            "expires_in_sec": 900,
            "max_uses": 1,
        },
        headers=_bot_headers(),
    )
    assert invite_create.status_code == 200
    invite_payload = invite_create.json()

    actor_token = _login_via_miniapp(
        client,
        monkeypatch,
        provider_user_id="24710",
        username="invite_revoke_actor",
    )
    revoke_response = client.post(
        f"/admin/stores/{store['store_id']}/invites/{invite_payload['invite_id']}/revoke",
        data={"confirm": "yes"},
        headers=_webapp_headers(actor_token),
        follow_redirects=False,
    )
    assert revoke_response.status_code == 303
    assert revoke_response.headers["location"].startswith(f"/admin/stores/{store['store_id']}?message=")

    redeem_response = client.post(
        "/bot/v1/invites/redeem",
        json={
            "provider": "telegram",
            "provider_user_id": "24711",
            "invite_code": invite_payload["invite_code"],
        },
        headers=_bot_headers(),
    )
    assert target["user_id"]
    assert redeem_response.status_code == 400
    assert redeem_response.json() == {"detail": "invite_revoked"}


def test_store_admin_invite_minting_requires_limit_for_oms_user(
    client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
):
    store = _create_store(client, display_name="Invite Limit Store")
    actor = _ensure_bot_user(
        client,
        provider_user_id="25710",
        provider_chat_id="chat-25710",
        username="invite_limit_actor",
        display_name="Invite Limit Actor",
    )
    _assign_membership(
        client,
        user_id=actor["user_id"],
        store_id=store["store_id"],
        role="store_admin",
    )
    actor_token = _login_via_miniapp(
        client,
        monkeypatch,
        provider_user_id="25710",
        username="invite_limit_actor",
    )
    headers = _webapp_headers(actor_token)

    invalid_response = client.post(
        f"/admin/stores/{store['store_id']}/invites/create",
        data={
            "role": "viewer",
            "expires_at": "",
            "max_uses": "",
            "note": "",
            "confirm": "yes",
        },
        headers=headers,
    )
    assert invalid_response.status_code == 400
    assert 'id="invite-code-display"' not in invalid_response.text

    valid_response = client.post(
        f"/admin/stores/{store['store_id']}/invites/create",
        data={
            "role": "viewer",
            "expires_at": "",
            "max_uses": "2",
            "note": "from admin ui",
            "confirm": "yes",
        },
        headers=headers,
    )
    assert valid_response.status_code == 200
    assert 'id="invite-code-display"' in valid_response.text


def test_store_root_invite_minting_is_not_global_unlimited(
    client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
):
    store = _create_store(client, display_name="Store Root Invite Limit")
    actor = _ensure_bot_user(
        client,
        provider_user_id="25720",
        provider_chat_id="chat-25720",
        username="invite_root_actor",
        display_name="Invite Root Actor",
    )
    _assign_membership(
        client,
        user_id=actor["user_id"],
        store_id=store["store_id"],
        role="root",
    )
    actor_token = _login_via_miniapp(
        client,
        monkeypatch,
        provider_user_id="25720",
        username="invite_root_actor",
    )
    response = client.post(
        f"/admin/stores/{store['store_id']}/invites/create",
        data={
            "role": "viewer",
            "expires_at": "",
            "max_uses": "",
            "note": "",
            "confirm": "yes",
        },
        headers=_webapp_headers(actor_token),
    )
    assert response.status_code == 400
    assert 'id="invite-code-display"' not in response.text


def test_bootstrap_admin_can_mint_fully_unlimited_staff_invite(client: TestClient):
    store = _create_store(client, display_name="Bootstrap Unlimited Invite Store")
    _login_bootstrap(client)

    response = client.post(
        f"/admin/stores/{store['store_id']}/invites/create",
        data={
            "role": "viewer",
            "expires_at": "",
            "max_uses": "",
            "note": "bootstrap unlimited",
            "confirm": "yes",
        },
    )
    assert response.status_code == 200
    assert 'id="invite-code-display"' in response.text
    assert "Без ограничений" in response.text or "Unlimited" in response.text
    assert "Никогда" in response.text or "Never" in response.text


def test_invite_minting_rejects_inactive_store(
    client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
):
    store = _create_store(client, display_name="Inactive Invite Store")
    actor = _ensure_bot_user(
        client,
        provider_user_id="25730",
        provider_chat_id="chat-25730",
        username="invite_inactive_actor",
        display_name="Invite Inactive Actor",
    )
    _assign_membership(
        client,
        user_id=actor["user_id"],
        store_id=store["store_id"],
        role="store_admin",
    )
    deactivate = client.patch(
        f"/admin/v1/stores/{store['store_id']}",
        json={"is_active": False},
        headers=_admin_headers(),
    )
    assert deactivate.status_code == 200

    actor_token = _login_via_miniapp(
        client,
        monkeypatch,
        provider_user_id="25730",
        username="invite_inactive_actor",
    )
    response = client.post(
        f"/admin/stores/{store['store_id']}/invites/create",
        data={
            "role": "viewer",
            "expires_at": "",
            "max_uses": "1",
            "note": "inactive store should fail",
            "confirm": "yes",
        },
        headers=_webapp_headers(actor_token),
    )
    assert response.status_code == 400
    assert 'id="invite-code-display"' not in response.text


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


def test_store_root_is_scoped_and_cannot_access_other_store_resources(
    client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
):
    store_a = _create_store(client, display_name="Scoped Root Store A")
    store_b = _create_store(client, display_name="Hidden Store B")
    actor = _ensure_bot_user(
        client,
        provider_user_id="55501",
        provider_chat_id="chat-55501",
        username="root_scope_actor",
        display_name="Root Scope Actor",
    )
    target = _ensure_bot_user(
        client,
        provider_user_id="55502",
        provider_chat_id="chat-55502",
        username="root_scope_target",
        display_name="Root Scope Target",
    )
    _assign_membership(
        client,
        user_id=actor["user_id"],
        store_id=store_a["store_id"],
        role="root",
    )
    _assign_membership(
        client,
        user_id=target["user_id"],
        store_id=store_b["store_id"],
        role="operator",
    )
    device_b_id = _register_device(client, store_id=store_b["store_id"])

    webapp_token = _login_via_miniapp(
        client,
        monkeypatch,
        provider_user_id="55501",
        username="root_scope_actor",
    )
    headers = _webapp_headers(webapp_token)

    stores_response = client.get("/admin/stores?include_inactive=true", headers=headers)
    assert stores_response.status_code == 200
    assert "Scoped Root Store A" in stores_response.text
    assert "Hidden Store B" not in stores_response.text

    hidden_store_detail = client.get(f"/admin/stores/{store_b['store_id']}", headers=headers)
    assert hidden_store_detail.status_code == 404

    membership_update = client.post(
        f"/admin/stores/{store_b['store_id']}/memberships",
        data={
            "user_id": target["user_id"],
            "role": "viewer",
            "set_active_store": "false",
            "confirm": "yes",
        },
        headers=headers,
        follow_redirects=False,
    )
    assert membership_update.status_code == 303
    assert membership_update.headers["location"].startswith(f"/admin/stores/{store_b['store_id']}?error=")

    device_detail = client.get(f"/admin/devices/{device_b_id}", headers=headers)
    assert device_detail.status_code == 404

    ban_response = client.post(
        f"/admin/users/{target['user_id']}/ban",
        data={
            "is_banned": "true",
            "reason": "forbidden",
            "confirm": "yes",
        },
        headers=headers,
        follow_redirects=False,
    )
    assert ban_response.status_code == 303
    assert ban_response.headers["location"].startswith(f"/admin/users/{target['user_id']}?error=")


def test_bootstrap_session_remains_global_superuser(client: TestClient):
    store_a = _create_store(client, display_name="Bootstrap Store A")
    store_b = _create_store(client, display_name="Bootstrap Store B")
    target = _ensure_bot_user(
        client,
        provider_user_id="66602",
        provider_chat_id="chat-66602",
        username="bootstrap_target",
        display_name="Bootstrap Target",
    )
    _assign_membership(
        client,
        user_id=target["user_id"],
        store_id=store_b["store_id"],
        role="operator",
    )
    device_b_id = _register_device(client, store_id=store_b["store_id"])

    _login_bootstrap(client)

    stores_response = client.get("/admin/stores?include_inactive=true")
    assert stores_response.status_code == 200
    assert "Bootstrap Store A" in stores_response.text
    assert "Bootstrap Store B" in stores_response.text

    store_b_detail = client.get(f"/admin/stores/{store_b['store_id']}")
    assert store_b_detail.status_code == 200

    device_detail = client.get(f"/admin/devices/{device_b_id}")
    assert device_detail.status_code == 200

    ban_response = client.post(
        f"/admin/users/{target['user_id']}/ban",
        data={
            "is_banned": "true",
            "reason": "bootstrap global action",
            "confirm": "yes",
        },
        follow_redirects=False,
    )
    assert ban_response.status_code == 303
    assert ban_response.headers["location"].startswith(f"/admin/users/{target['user_id']}?message=")


def test_multi_store_memberships_are_limited_to_assigned_stores(
    client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
):
    store_a = _create_store(client, display_name="Scope Store A")
    store_b = _create_store(client, display_name="Scope Store B")
    store_c = _create_store(client, display_name="Scope Store C")
    actor = _ensure_bot_user(
        client,
        provider_user_id="77701",
        provider_chat_id="chat-77701",
        username="multi_scope_actor",
        display_name="Multi Scope Actor",
    )
    _assign_membership(
        client,
        user_id=actor["user_id"],
        store_id=store_a["store_id"],
        role="store_admin",
    )
    _assign_membership(
        client,
        user_id=actor["user_id"],
        store_id=store_b["store_id"],
        role="store_admin",
    )
    device_b_id = _register_device(client, store_id=store_b["store_id"])
    device_c_id = _register_device(client, store_id=store_c["store_id"])

    webapp_token = _login_via_miniapp(
        client,
        monkeypatch,
        provider_user_id="77701",
        username="multi_scope_actor",
    )
    headers = _webapp_headers(webapp_token)

    stores_response = client.get("/admin/stores?include_inactive=true", headers=headers)
    assert stores_response.status_code == 200
    assert "Scope Store A" in stores_response.text
    assert "Scope Store B" in stores_response.text
    assert "Scope Store C" not in stores_response.text

    store_a_detail = client.get(f"/admin/stores/{store_a['store_id']}", headers=headers)
    assert store_a_detail.status_code == 200

    store_c_detail = client.get(f"/admin/stores/{store_c['store_id']}", headers=headers)
    assert store_c_detail.status_code == 404

    device_b_detail = client.get(f"/admin/devices/{device_b_id}", headers=headers)
    assert device_b_detail.status_code == 200

    device_c_detail = client.get(f"/admin/devices/{device_c_id}", headers=headers)
    assert device_c_detail.status_code == 404


def test_store_scoped_admin_cannot_mint_enroll_tokens_for_other_store(
    client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
):
    store_a = _create_store(client, display_name="Enroll Scope A")
    store_b = _create_store(client, display_name="Enroll Scope B")
    actor = _ensure_bot_user(
        client,
        provider_user_id="88801",
        provider_chat_id="chat-88801",
        username="enroll_scope_actor",
        display_name="Enroll Scope Actor",
    )
    _assign_membership(
        client,
        user_id=actor["user_id"],
        store_id=store_a["store_id"],
        role="store_admin",
    )

    webapp_token = _login_via_miniapp(
        client,
        monkeypatch,
        provider_user_id="88801",
        username="enroll_scope_actor",
    )
    response = client.post(
        "/admin/enroll-tokens",
        data={
            "store_id": store_b["store_id"],
            "expires_in_sec": "600",
            "max_uses": "1",
            "note": "",
            "confirm": "yes",
        },
        headers=_webapp_headers(webapp_token),
    )
    assert response.status_code == 403
