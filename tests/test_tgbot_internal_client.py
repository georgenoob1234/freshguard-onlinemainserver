from __future__ import annotations

from dataclasses import dataclass

import pytest
from fastapi import HTTPException

from app.config import get_settings
from app.tgbot_internal_client import verify_webapp_init_data_via_tgbot


@dataclass(frozen=True)
class _DummyResponse:
    status_code: int
    payload: dict[str, object]

    def json(self) -> dict[str, object]:
        return self.payload


def _configure_base_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ADMIN_KEY", "admin-test-key")
    monkeypatch.setenv("SECRET_SALT", "secret-test-salt")
    monkeypatch.setenv("TGBOT_INTERNAL_BASE_URL", "http://tgbot-internal:8081")
    monkeypatch.setenv("TGBOT_INTERNAL_AUTH_TOKEN", "internal-auth-token")


def test_verify_webapp_init_data_via_tgbot_success(monkeypatch: pytest.MonkeyPatch) -> None:
    _configure_base_env(monkeypatch)
    captured_headers: dict[str, str] = {}

    def _fake_post(url: str, *, json: dict[str, object], headers: dict[str, str], timeout):  # noqa: A002
        assert url == "http://tgbot-internal:8081/internal/admin-ui/verify-webapp-init"
        assert json == {"init_data": "signed-init-data"}
        _ = timeout
        captured_headers.update(headers)
        return _DummyResponse(
            status_code=200,
            payload={
                "ok": True,
                "provider": "telegram",
                "provider_user_id": "123456",
                "username": "scope_admin",
                "display_name": "Scope Admin",
            },
        )

    monkeypatch.setattr("app.tgbot_internal_client.httpx.post", _fake_post)
    settings = get_settings()

    identity = verify_webapp_init_data_via_tgbot(
        init_data="signed-init-data",
        settings=settings,
    )

    assert identity.provider_user_id == "123456"
    assert identity.username == "scope_admin"
    assert identity.display_name == "Scope Admin"
    assert captured_headers["Authorization"] == "Bearer internal-auth-token"


def test_verify_webapp_init_data_via_tgbot_maps_invalid_payload(monkeypatch: pytest.MonkeyPatch) -> None:
    _configure_base_env(monkeypatch)

    def _fake_post(url: str, *, json: dict[str, object], headers: dict[str, str], timeout):  # noqa: A002
        _ = url
        _ = json
        _ = headers
        _ = timeout
        return _DummyResponse(
            status_code=200,
            payload={"ok": False, "reason": "invalid_telegram_init_data"},
        )

    monkeypatch.setattr("app.tgbot_internal_client.httpx.post", _fake_post)
    settings = get_settings()

    with pytest.raises(HTTPException) as error_info:
        verify_webapp_init_data_via_tgbot(
            init_data="bad-init-data",
            settings=settings,
        )

    assert error_info.value.status_code == 401
    assert error_info.value.detail == "invalid_telegram_init_data"


def test_verify_webapp_init_data_requires_internal_base_url(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ADMIN_KEY", "admin-test-key")
    monkeypatch.setenv("SECRET_SALT", "secret-test-salt")
    monkeypatch.delenv("TGBOT_INTERNAL_BASE_URL", raising=False)
    settings = get_settings()

    with pytest.raises(HTTPException) as error_info:
        verify_webapp_init_data_via_tgbot(
            init_data="signed-init-data",
            settings=settings,
        )

    assert error_info.value.status_code == 503
    assert error_info.value.detail == "telegram_internal_verifier_not_configured"
