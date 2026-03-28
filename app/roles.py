from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
import json
from pathlib import Path

from app.config import get_settings


class RolesConfigError(RuntimeError):
    pass


@dataclass(frozen=True)
class RoleDefinition:
    priority: int
    permissions: frozenset[str]


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
        raise RolesConfigError(f"Invalid JSON in roles config file {roles_path}: {error.msg}") from error


def _parse_legacy_roles_payload(roles_payload: dict[object, object]) -> dict[str, RoleDefinition]:
    parsed_roles: dict[str, RoleDefinition] = {}
    next_priority = 10
    for raw_role_name, permissions_payload in roles_payload.items():
        if not isinstance(raw_role_name, str) or not raw_role_name:
            raise RolesConfigError("Role names must be non-empty strings.")
        if not isinstance(permissions_payload, list):
            raise RolesConfigError(
                "Legacy roles format requires each role to map to a list of strings."
            )
        if not all(isinstance(permission, str) for permission in permissions_payload):
            raise RolesConfigError(f'Role "{raw_role_name}" must map to a list of strings.')

        role_name = raw_role_name.strip()
        if role_name == "root":
            priority = 0
        else:
            priority = next_priority
            next_priority += 10
        parsed_roles[role_name] = RoleDefinition(
            priority=priority,
            permissions=frozenset(permissions_payload),
        )
    return parsed_roles


def _validate_roles_payload(payload: object) -> dict[str, RoleDefinition]:
    if not isinstance(payload, dict):
        raise RolesConfigError("Roles config must be a JSON object.")

    roles_payload = payload.get("roles")
    if not isinstance(roles_payload, dict):
        raise RolesConfigError('Roles config must include a top-level "roles" object.')

    if roles_payload and all(isinstance(role_payload, list) for role_payload in roles_payload.values()):
        parsed_roles = _parse_legacy_roles_payload(roles_payload)
    else:
        parsed_roles = {}
        seen_priorities: set[int] = set()
        for raw_role_name, role_payload in roles_payload.items():
            if not isinstance(raw_role_name, str) or not raw_role_name:
                raise RolesConfigError("Role names must be non-empty strings.")
            role_name = raw_role_name.strip()
            if not isinstance(role_payload, dict):
                raise RolesConfigError(
                    f'Role "{role_name}" must be an object with "priority" and "permissions".'
                )

            priority = role_payload.get("priority")
            permissions = role_payload.get("permissions")
            if not isinstance(priority, int) or priority < 0:
                raise RolesConfigError(f'Role "{role_name}" priority must be a non-negative integer.')
            if priority in seen_priorities:
                raise RolesConfigError(f'Role priority {priority} is duplicated.')
            seen_priorities.add(priority)

            if not isinstance(permissions, list):
                raise RolesConfigError(f'Role "{role_name}" permissions must be a list of strings.')
            if not all(isinstance(permission, str) for permission in permissions):
                raise RolesConfigError(f'Role "{role_name}" permissions must be a list of strings.')

            parsed_roles[role_name] = RoleDefinition(
                priority=priority,
                permissions=frozenset(permissions),
            )

    for role_name in parsed_roles:
        if not isinstance(role_name, str) or not role_name:
            raise RolesConfigError("Role names must be non-empty strings.")

    root_role = parsed_roles.get("root")
    if root_role is None:
        raise RolesConfigError('Roles config must define a "root" role.')
    if root_role.priority != 0:
        raise RolesConfigError('Roles config "root" role must have priority 0.')
    if "*" not in root_role.permissions:
        raise RolesConfigError('Roles config "root" role must include "*".')

    return parsed_roles


@lru_cache(maxsize=1)
def _load_roles_cached(roles_config_path: str) -> dict[str, RoleDefinition]:
    payload = _read_roles_payload(roles_config_path)
    return _validate_roles_payload(payload)


def _load_role_definitions(roles_config_path: str | None = None) -> dict[str, RoleDefinition]:
    settings = get_settings()
    config_path = roles_config_path or settings.roles_config_path
    return _load_roles_cached(config_path)


def load_roles_config(roles_config_path: str | None = None) -> dict[str, frozenset[str]]:
    return {
        role_name: role_definition.permissions
        for role_name, role_definition in _load_role_definitions(roles_config_path).items()
    }


def get_role_permissions(role_name: str) -> set[str]:
    role_definition = _load_role_definitions().get(role_name)
    if role_definition is None:
        return set()
    return set(role_definition.permissions)


def get_role_priority(role_name: str) -> int:
    role_definition = _load_role_definitions().get(role_name)
    if role_definition is None:
        raise RolesConfigError(f'Unknown role "{role_name}" has no priority.')
    return role_definition.priority


def is_known_role(role_name: str) -> bool:
    return role_name in _load_role_definitions()


def is_permission_granted(role_name: str, permission: str) -> bool:
    role_permissions = get_role_permissions(role_name)
    return "*" in role_permissions or permission in role_permissions


def clear_roles_cache() -> None:
    _load_roles_cached.cache_clear()
