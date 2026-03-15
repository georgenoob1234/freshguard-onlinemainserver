from __future__ import annotations

from app.config import get_settings


def test_notification_push_base_url_defaults_to_localhost(monkeypatch):
    monkeypatch.setenv("ADMIN_KEY", "admin-test-key")
    monkeypatch.setenv("SECRET_SALT", "secret-test-salt")
    monkeypatch.delenv("NOTIFICATION_PUSH_BASE_URL", raising=False)

    settings = get_settings()

    assert settings.notification_push_base_url == "http://127.0.0.1:8081"


def test_notification_push_base_url_uses_explicit_value(monkeypatch):
    monkeypatch.setenv("ADMIN_KEY", "admin-test-key")
    monkeypatch.setenv("SECRET_SALT", "secret-test-salt")
    monkeypatch.setenv("NOTIFICATION_PUSH_BASE_URL", "http://custom-tgbot:9000")

    settings = get_settings()

    assert settings.notification_push_base_url == "http://custom-tgbot:9000"
