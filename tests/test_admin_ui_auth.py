from __future__ import annotations

import os
from pathlib import Path
import sqlite3

import pytest
from fastapi.testclient import TestClient

from app.main import app


@pytest.fixture()
def client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    database_path = tmp_path / "onlinemainserver.db"
    monkeypatch.setenv("ADMIN_KEY", "admin-test-key")
    monkeypatch.setenv("SECRET_SALT", "secret-test-salt")
    monkeypatch.setenv("DATABASE_PATH", str(database_path))
    monkeypatch.setenv("OMS_ADMIN_SESSION_SECRET", "session-test-secret")
    monkeypatch.setenv("OMS_ADMIN_BOOTSTRAP_USERNAME", "superadmin")
    monkeypatch.setenv("OMS_ADMIN_BOOTSTRAP_PASSWORD", "super-password")

    with TestClient(app) as test_client:
        yield test_client


def test_bootstrap_admin_account_created(client: TestClient):
    # Default locale (Russian) should be served without Accept-Language header
    response = client.get("/admin/login")
    assert response.status_code == 200
    assert 'lang="ru"' in response.text
    database_path = Path(os.environ["DATABASE_PATH"])
    with sqlite3.connect(database_path) as connection:
        row = connection.execute("SELECT COUNT(*) FROM admin_accounts").fetchone()
    assert row is not None
    assert int(row[0]) == 1


def test_admin_pages_require_login_redirect(client: TestClient):
    response = client.get("/admin")
    assert response.status_code == 200
    assert "/admin/auth/telegram/miniapp" in response.text

    gated_response = client.get("/admin/users", follow_redirects=False)
    assert gated_response.status_code == 303
    assert gated_response.headers["location"] == "/admin/login"


def test_login_and_logout_flow(client: TestClient):
    # Request English locale via header to match legacy assertions
    headers = {"Accept-Language": "en"}

    login_fail = client.post(
        "/admin/login",
        data={"username": "superadmin", "password": "wrong-password"},
        headers=headers,
    )
    assert login_fail.status_code == 401
    assert "Invalid username or password" in login_fail.text

    login_ok = client.post(
        "/admin/login",
        data={"username": "superadmin", "password": "super-password"},
        headers=headers,
        follow_redirects=False,
    )
    assert login_ok.status_code == 303
    assert login_ok.headers["location"] == "/admin"

    # Use the language cookie set during login
    dashboard = client.get("/admin", headers=headers)
    assert dashboard.status_code == 200
    assert "Dashboard" in dashboard.text

    logout = client.post("/admin/logout", headers=headers, follow_redirects=False)
    assert logout.status_code == 303
    assert logout.headers["location"] == "/admin/login"

    requires_auth_again = client.get("/admin/users", headers=headers, follow_redirects=False)
    assert requires_auth_again.status_code == 303
    assert requires_auth_again.headers["location"] == "/admin/login"


def test_russian_default_locale(client: TestClient):
    """Test that Russian is the default locale when no Accept-Language header is provided."""
    response = client.get("/admin/login")
    assert response.status_code == 200
    assert 'lang="ru"' in response.text
    assert "Вход в панель управления" in response.text


def test_english_via_accept_language(client: TestClient):
    """Test that English is served when Accept-Language header requests it."""
    response = client.get("/admin/login", headers={"Accept-Language": "en-US,en;q=0.9"})
    assert response.status_code == 200
    assert 'lang="en"' in response.text
    assert "Admin Login" in response.text


def test_language_switch_endpoint(client: TestClient):
    """Test the language switching endpoint sets cookie and redirects."""
    # Switch to English
    response = client.get("/admin/set-language?lang=en&next=/admin/login", follow_redirects=False)
    assert response.status_code == 303
    assert response.headers["location"] == "/admin/login"
    assert "oms_admin_ui_lang" in response.cookies
    assert response.cookies["oms_admin_ui_lang"] == "en"

    # Follow redirect and verify English is shown
    dashboard = client.get("/admin/login", cookies={"oms_admin_ui_lang": "en"})
    assert dashboard.status_code == 200
    assert 'lang="en"' in dashboard.text


def test_language_persistence_after_logout(client: TestClient):
    """Test that language preference persists after logout (cookie-based, not session)."""
    # Set language to English via cookie before login
    client.cookies.set("oms_admin_ui_lang", "en")

    # Verify login page is in English
    response = client.get("/admin/login")
    assert response.status_code == 200
    assert 'lang="en"' in response.text
    assert "Sign In" in response.text

    # Login
    login = client.post(
        "/admin/login",
        data={"username": "superadmin", "password": "super-password"},
        follow_redirects=False,
    )
    assert login.status_code == 303

    # Verify dashboard is in English
    dashboard = client.get("/admin")
    assert dashboard.status_code == 200
    assert "Dashboard" in dashboard.text

    # Logout
    logout = client.post("/admin/logout", follow_redirects=False)
    assert logout.status_code == 303

    # Verify login page is still in English after logout (cookie persists)
    login_page = client.get("/admin/login")
    assert login_page.status_code == 200
    assert 'lang="en"' in login_page.text


def test_russian_explicit_via_query_param(client: TestClient):
    """Test Russian can be explicitly requested via query param."""
    # First set English cookie
    client.cookies.set("oms_admin_ui_lang", "en")

    # Override with query param to Russian
    response = client.get("/admin/login?lang=ru")
    assert response.status_code == 200
    assert 'lang="ru"' in response.text
    assert "Вход в панель управления" in response.text


def test_login_page_shows_telegram_login_button(client: TestClient):
    response = client.get("/admin/login")
    assert response.status_code == 200
    assert "Войти через Telegram" in response.text
