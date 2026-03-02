from __future__ import annotations

from functools import lru_cache
import json
from pathlib import Path

from app.config import get_settings


class RolesConfigError(RuntimeError):
    pass


def _read_roles_payload(roles_config_path: str) -> object:
    roles_path = Path(roles_config_path)
    try:
        raw_payload = roles_path.read_text(encoding="utf-8")
    except FileNotFoundError as error:
        raise RolesConfigError(f"Roles config file not found: {roles_path}") from error
    except OSError as error:
        raise RolesConfigError(f"Unable to read roles config file: {roles_path}") from error

    try:
        return json.loads(raw_payload)
    except json.JSONDecodeError as error:
        raise RolesConfigError(
            f"Invalid JSON in roles config file {roles_path}: {error.msg}"
        ) from error


def _validate_roles_payload(payload: object) -> dict[str, frozenset[str]]:
    if not isinstance(payload, dict):
        raise RolesConfigError("Roles config must be a JSON object.")

    roles_payload = payload.get("roles")
    if not isinstance(roles_payload, dict):
        raise RolesConfigError('Roles config must include a top-level "roles" object.')

    parsed_roles: dict[str, frozenset[str]] = {}
    for role_name, permissions in roles_payload.items():
        if not isinstance(role_name, str) or not role_name:
            raise RolesConfigError("Role names must be non-empty strings.")
        if not isinstance(permissions, list):
            raise RolesConfigError(f'Role "{role_name}" must map to a list of strings.')
        if not all(isinstance(permission, str) for permission in permissions):
            raise RolesConfigError(f'Role "{role_name}" must map to a list of strings.')
        parsed_roles[role_name] = frozenset(permissions)

    root_permissions = parsed_roles.get("root")
    if root_permissions is None:
        raise RolesConfigError('Roles config must define a "root" role.')
    if "*" not in root_permissions:
        raise RolesConfigError('Roles config "root" role must include "*".')

    return parsed_roles


@lru_cache(maxsize=1)
def _load_roles_cached(roles_config_path: str) -> dict[str, frozenset[str]]:
    payload = _read_roles_payload(roles_config_path)
    return _validate_roles_payload(payload)


def load_roles_config(roles_config_path: str | None = None) -> dict[str, frozenset[str]]:
    settings = get_settings()
    config_path = roles_config_path or settings.roles_config_path
    return _load_roles_cached(config_path)


def get_role_permissions(role_name: str) -> set[str]:
    role_permissions = load_roles_config().get(role_name)
    if role_permissions is None:
        return set()
    return set(role_permissions)


def is_permission_granted(role_name: str, permission: str) -> bool:
    role_permissions = get_role_permissions(role_name)
    return "*" in role_permissions or permission in role_permissions


def clear_roles_cache() -> None:
    _load_roles_cached.cache_clear()
