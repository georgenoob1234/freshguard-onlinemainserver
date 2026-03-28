from __future__ import annotations

import json
from pathlib import Path

import pytest

from app.roles import (
    RolesConfigError,
    clear_roles_cache,
    get_role_priority,
    get_role_permissions,
    is_known_role,
    is_permission_granted,
    load_roles_config,
)


@pytest.fixture(autouse=True)
def _base_env(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("ADMIN_KEY", "admin-test-key")
    monkeypatch.setenv("SECRET_SALT", "secret-test-salt")
    clear_roles_cache()
    yield
    clear_roles_cache()


def _write_json(path: Path, payload: dict) -> None:
    path.write_text(json.dumps(payload), encoding="utf-8")


def test_roles_loader_loads_valid_roles(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    roles_path = tmp_path / "roles.json"
    _write_json(
        roles_path,
        {
            "roles": {
                "root": {
                    "priority": 0,
                    "permissions": ["*"],
                },
                "operator": {
                    "priority": 20,
                    "permissions": ["devices.list", "devices.status.read"],
                },
                "viewer": {
                    "priority": 40,
                    "permissions": ["devices.status.read"],
                },
            }
        },
    )
    monkeypatch.setenv("ROLES_CONFIG_PATH", str(roles_path))

    loaded = load_roles_config()
    assert loaded["root"] == frozenset({"*"})
    assert get_role_permissions("operator") == {"devices.list", "devices.status.read"}
    assert get_role_permissions("missing-role") == set()
    assert is_known_role("operator") is True
    assert is_known_role("missing-role") is False
    assert is_permission_granted("operator", "devices.list") is True
    assert is_permission_granted("operator", "devices.delete") is False
    assert is_permission_granted("root", "anything") is True
    assert get_role_priority("operator") == 20


def test_roles_loader_fails_when_roles_key_is_missing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    roles_path = tmp_path / "roles.json"
    _write_json(roles_path, {"not_roles": {}})
    monkeypatch.setenv("ROLES_CONFIG_PATH", str(roles_path))

    with pytest.raises(RolesConfigError, match='top-level "roles"'):
        load_roles_config()


@pytest.mark.parametrize(
    ("payload", "expected_error"),
    [
        (
            {
                "roles": {
                    "operator": {
                        "priority": 10,
                        "permissions": ["devices.list"],
                    },
                }
            },
            'define a "root" role',
        ),
        (
            {
                "roles": {
                    "root": {
                        "priority": 0,
                        "permissions": ["devices.list"],
                    },
                }
            },
            'must include "\\*"',
        ),
        (
            {
                "roles": {
                    "root": {
                        "priority": 10,
                        "permissions": ["*"],
                    },
                }
            },
            'must have priority 0',
        ),
    ],
)
def test_roles_loader_fails_when_root_is_missing_or_invalid(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    payload: dict,
    expected_error: str,
):
    roles_path = tmp_path / "roles.json"
    _write_json(roles_path, payload)
    monkeypatch.setenv("ROLES_CONFIG_PATH", str(roles_path))

    with pytest.raises(RolesConfigError, match=expected_error):
        load_roles_config()


def test_default_roles_config_includes_milestone_2_permissions(monkeypatch: pytest.MonkeyPatch):
    roles_path = Path(__file__).resolve().parents[1] / "config" / "roles.json"
    monkeypatch.setenv("ROLES_CONFIG_PATH", str(roles_path))

    loaded = load_roles_config()
    assert "store_admin" in loaded
    assert "auditor" in loaded
    assert is_known_role("store_admin") is True
    assert is_permission_granted("store_admin", "invites.create") is True
    assert is_permission_granted("operator", "memberships.revoke.self") is True
    assert is_permission_granted("viewer", "bot.user_context.read") is True
    assert is_permission_granted("auditor", "results.read.history") is True
    assert is_permission_granted("operator", "notifications.access") is True
    assert is_permission_granted("operator", "notifications.defect_detected") is True
    assert is_permission_granted("store_admin", "admin_ui.access") is True
    assert is_permission_granted("operator", "admin_ui.access") is False
    assert get_role_priority("root") == 0
    assert get_role_priority("store_admin") == 10
    assert get_role_priority("operator") == 20
