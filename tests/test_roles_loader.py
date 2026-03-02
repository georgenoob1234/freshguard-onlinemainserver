from __future__ import annotations

import json
from pathlib import Path

import pytest

from app.roles import (
    RolesConfigError,
    clear_roles_cache,
    get_role_permissions,
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
                "root": ["*"],
                "operator": ["devices.list", "devices.status.read"],
                "viewer": ["devices.status.read"],
            }
        },
    )
    monkeypatch.setenv("ROLES_CONFIG_PATH", str(roles_path))

    loaded = load_roles_config()
    assert loaded["root"] == frozenset({"*"})
    assert get_role_permissions("operator") == {"devices.list", "devices.status.read"}
    assert get_role_permissions("missing-role") == set()
    assert is_permission_granted("operator", "devices.list") is True
    assert is_permission_granted("operator", "devices.delete") is False
    assert is_permission_granted("root", "anything") is True


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
                    "operator": ["devices.list"],
                }
            },
            'define a "root" role',
        ),
        (
            {
                "roles": {
                    "root": ["devices.list"],
                }
            },
            'must include "\\*"',
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
