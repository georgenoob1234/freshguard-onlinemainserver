from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
import logging
from pathlib import Path
import secrets
import sqlite3
import uuid

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import FileResponse

from app.auth import BotService, resolve_authenticated_bot_service
from app.config import get_settings
from app.db import get_db, open_connection, rollback_quietly
from app.device_status import compute_online, parse_db_utc_datetime, serialize_utc_datetime
from app.models import (
    BotDefectSummary,
    BotDeviceStatusResponse,
    BotDeviceSummary,
    BotDeviceCommandRequest,
    BotDeviceCommandResponse,
    BotHealthResponse,
    BotInviteCreateRequest,
    BotInviteCreateResponse,
    BotInviteRedeemRequest,
    BotInviteRedeemResponse,
    BotInviteRedeemStore,
    BotLatestResultResponse,
    BotCommandStatusResponse,
    BotRevokeSelfMembershipRequest,
    BotRevokeSelfMembershipResponse,
    BotNotificationPreferencesResponse,
    BotNotificationSettingsCapabilities,
    BotNotificationSettingsPreferences,
    BotNotificationSettingsStoreSummary,
    BotNotificationSettingsStoresResponse,
    BotStoreNotificationSettingsResponse,
    BotUpdateNotificationPreferencesRequest,
    BotUpdateStoreNotificationSettingsRequest,
    BotSessionEnsureRequest,
    BotSessionEnsureResponse,
    BotSetActiveDeviceRequest,
    BotSetActiveDeviceResponse,
    BotSetActiveStoreRequest,
    BotSetActiveStoreResponse,
    BotStoreDevicesResponse,
    BotStoreSummary,
    BotStoresResponse,
)
from app.notifications import (
    EVENT_DEFECT_DETECTED,
    build_notification_preference_view,
    load_notification_preferences,
    upsert_notification_preferences,
)
from app.notification_images import (
    get_or_create_annotated_image,
    load_result_image_context,
)
from app.realtime import CommandTimeoutError, connection_manager, send_command
from app.roles import is_known_role, is_permission_granted
from app.security import hash_token


logger = logging.getLogger(__name__)
router = APIRouter(prefix="/bot/v1", tags=["bot"])
ALLOWED_BOT_INVITE_ROLES = frozenset({"operator", "viewer"})
INVITE_CODE_DIGITS = 6
MAX_INVITE_CODE_GENERATION_ATTEMPTS = 32


def _store_display_name_expr(table_alias: str) -> str:
    return (
        f"COALESCE(NULLIF(TRIM({table_alias}.display_name), ''), "
        f"NULLIF(TRIM({table_alias}.name), ''), {table_alias}.store_id)"
    )


def _device_display_name_expr(table_alias: str) -> str:
    return (
        f"COALESCE(NULLIF(TRIM({table_alias}.label), ''), "
        f"NULLIF(TRIM({table_alias}.hostname), ''), {table_alias}.device_id)"
    )


def _parse_iso_datetime(raw_value: str) -> datetime:
    parsed = datetime.fromisoformat(raw_value)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def _require_supported_provider(provider: str) -> str:
    normalized = provider.strip().lower()
    if normalized != "telegram":
        raise HTTPException(status_code=400, detail="unsupported_provider")
    return normalized


def _require_known_user(
    connection: sqlite3.Connection,
    *,
    provider: str,
    provider_user_id: str,
) -> sqlite3.Row:
    normalized_provider_user_id = provider_user_id.strip()
    if not normalized_provider_user_id:
        raise HTTPException(status_code=400, detail="provider_user_id_required")

    row = connection.execute(
        """
        SELECT
            users.user_id,
            users.is_banned,
            users.ban_reason
        FROM user_identities
        JOIN users ON users.user_id = user_identities.user_id
        WHERE user_identities.provider = ? AND user_identities.provider_user_id = ?
        """,
        (provider, normalized_provider_user_id),
    ).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="user_not_found")
    return row


def _require_not_banned(user_row: sqlite3.Row) -> None:
    if int(user_row["is_banned"]) == 1:
        raise HTTPException(status_code=403, detail="user_banned")


def _get_user_context_row(
    connection: sqlite3.Connection,
    *,
    user_id: str,
) -> sqlite3.Row | None:
    return connection.execute(
        """
        SELECT active_store_id, active_device_id
        FROM user_context
        WHERE user_id = ?
        """,
        (user_id,),
    ).fetchone()


def _upsert_user_context(
    connection: sqlite3.Connection,
    *,
    user_id: str,
    active_store_id: str | None,
    active_device_id: str | None,
    updated_at: str,
) -> None:
    connection.execute(
        """
        INSERT INTO user_context (
            user_id,
            active_store_id,
            active_device_id,
            updated_at
        )
        VALUES (?, ?, ?, ?)
        ON CONFLICT(user_id) DO UPDATE SET
            active_store_id = excluded.active_store_id,
            active_device_id = excluded.active_device_id,
            updated_at = excluded.updated_at
        """,
        (user_id, active_store_id, active_device_id, updated_at),
    )


def _build_bot_device_summary(
    row: sqlite3.Row,
    *,
    now_utc: datetime,
    threshold_seconds: int,
) -> BotDeviceSummary:
    last_seen_at = parse_db_utc_datetime(row["last_seen_at"])
    return BotDeviceSummary(
        device_id=row["device_id"],
        display_name=row["display_name"],
        online=compute_online(
            last_seen_at=last_seen_at,
            now_utc=now_utc,
            threshold_seconds=threshold_seconds,
        ),
    )


def _build_bot_device_status_response(
    row: sqlite3.Row,
    *,
    now_utc: datetime,
    threshold_seconds: int,
    can_request_photo: bool,
    can_tare: bool,
) -> BotDeviceStatusResponse:
    last_seen_at = parse_db_utc_datetime(row["last_seen_at"])
    return BotDeviceStatusResponse(
        device_id=row["device_id"],
        display_name=row["display_name"],
        connected=connection_manager.is_connected(row["device_id"]),
        last_seen_at=serialize_utc_datetime(last_seen_at),
        online=compute_online(
            last_seen_at=last_seen_at,
            now_utc=now_utc,
            threshold_seconds=threshold_seconds,
        ),
        actions={
            "show_photo": can_request_photo,
            "show_tare": can_tare,
            "show_tare_set": can_tare,
            "show_tare_reset": can_tare,
        },
    )


def _load_session_state(
    connection: sqlite3.Connection,
    *,
    user_id: str,
) -> dict[str, str | int | None]:
    memberships_count = int(
        connection.execute(
            """
            SELECT COUNT(*) AS memberships_count
            FROM store_memberships
            WHERE user_id = ? AND revoked_at IS NULL
            """,
            (user_id,),
        ).fetchone()["memberships_count"]
    )

    context_row = _get_user_context_row(connection, user_id=user_id)
    active_store_id = None
    active_device_id = None
    active_store_display_name = None

    if context_row is not None:
        active_store_id = context_row["active_store_id"]
        active_device_id = context_row["active_device_id"]

    if active_store_id is not None:
        store_row = connection.execute(
            f"""
            SELECT {_store_display_name_expr("stores")} AS display_name
            FROM stores
            WHERE store_id = ?
            """,
            (active_store_id,),
        ).fetchone()
        if store_row is not None:
            active_store_display_name = store_row["display_name"]

    return {
        "memberships_count": memberships_count,
        "active_store_id": active_store_id,
        "active_store_display_name": active_store_display_name,
        "active_device_id": active_device_id,
    }


def _select_active_membership_row(
    connection: sqlite3.Connection,
    *,
    user_id: str,
    store_id: str,
) -> sqlite3.Row | None:
    return connection.execute(
        f"""
        SELECT
            store_memberships.membership_id,
            store_memberships.store_id,
            store_memberships.role,
            store_memberships.created_at,
            store_memberships.created_by_user_id,
            store_memberships.note,
            stores.address,
            stores.is_active AS store_is_active,
            {_store_display_name_expr("stores")} AS store_display_name
        FROM store_memberships
        JOIN stores ON stores.store_id = store_memberships.store_id
        WHERE store_memberships.user_id = ?
          AND store_memberships.store_id = ?
          AND store_memberships.revoked_at IS NULL
        """,
        (user_id, store_id),
    ).fetchone()


def _select_active_membership_rows(
    connection: sqlite3.Connection,
    *,
    user_id: str,
) -> list[sqlite3.Row]:
    return connection.execute(
        f"""
        SELECT
            store_memberships.membership_id,
            store_memberships.store_id,
            store_memberships.role,
            store_memberships.created_at,
            stores.address,
            stores.is_active AS store_is_active,
            {_store_display_name_expr("stores")} AS store_display_name
        FROM store_memberships
        JOIN stores ON stores.store_id = store_memberships.store_id
        WHERE store_memberships.user_id = ?
          AND store_memberships.revoked_at IS NULL
        ORDER BY store_memberships.created_at ASC, store_memberships.membership_id ASC
        """,
        (user_id,),
    ).fetchall()


def _require_membership_row(
    connection: sqlite3.Connection,
    *,
    user_id: str,
    store_id: str,
    detail: str = "membership_not_found",
) -> sqlite3.Row:
    membership_row = _select_active_membership_row(
        connection,
        user_id=user_id,
        store_id=store_id,
    )
    if membership_row is None:
        raise HTTPException(status_code=404, detail=detail)
    return membership_row


def _select_next_active_membership(
    connection: sqlite3.Connection,
    *,
    user_id: str,
) -> sqlite3.Row | None:
    return connection.execute(
        """
        SELECT store_id
        FROM store_memberships
        WHERE user_id = ? AND revoked_at IS NULL
        ORDER BY created_at ASC, membership_id ASC
        LIMIT 1
        """,
        (user_id,),
    ).fetchone()


def _require_active_store_membership_row(
    connection: sqlite3.Connection,
    *,
    user_id: str,
) -> sqlite3.Row:
    context_row = _get_user_context_row(connection, user_id=user_id)
    active_store_id = context_row["active_store_id"] if context_row is not None else None
    if active_store_id is None:
        raise HTTPException(status_code=400, detail="no_active_store")

    membership_row = _select_active_membership_row(
        connection,
        user_id=user_id,
        store_id=active_store_id,
    )
    if membership_row is None:
        raise HTTPException(status_code=400, detail="no_active_store")
    return membership_row


def _is_store_active(membership_row: sqlite3.Row) -> bool:
    return int(membership_row["store_is_active"]) == 1


def _is_notification_settings_membership_eligible(membership_row: sqlite3.Row) -> bool:
    return _is_store_active(membership_row) and is_permission_granted(
        membership_row["role"],
        "notifications.access",
    )


def _select_notification_settings_membership_rows(
    connection: sqlite3.Connection,
    *,
    user_id: str,
) -> list[sqlite3.Row]:
    memberships = _select_active_membership_rows(connection, user_id=user_id)
    return [
        membership
        for membership in memberships
        if _is_notification_settings_membership_eligible(membership)
    ]


def _require_notification_settings_membership_row(
    connection: sqlite3.Connection,
    *,
    user_id: str,
    store_id: str,
) -> sqlite3.Row:
    membership_row = _select_active_membership_row(
        connection,
        user_id=user_id,
        store_id=store_id,
    )
    if membership_row is None or not _is_store_active(membership_row):
        logger.warning(
            "Bot notification settings denied unavailable store user_id=%s store_id=%s",
            user_id,
            store_id,
        )
        raise HTTPException(status_code=404, detail="store_not_available")

    if not is_permission_granted(membership_row["role"], "notifications.access"):
        logger.warning(
            "Bot notification settings denied missing access permission user_id=%s store_id=%s role=%s",
            user_id,
            store_id,
            membership_row["role"],
        )
        raise HTTPException(status_code=403, detail="notifications_not_available")
    return membership_row


def _require_active_notification_settings_membership_row(
    connection: sqlite3.Connection,
    *,
    user_id: str,
) -> sqlite3.Row:
    active_membership_row = _require_active_store_membership_row(
        connection,
        user_id=user_id,
    )
    return _require_notification_settings_membership_row(
        connection,
        user_id=user_id,
        store_id=active_membership_row["store_id"],
    )


def _build_store_notification_settings_response(
    *,
    store_id: str,
    store_name: str,
    preferences_view,
) -> BotStoreNotificationSettingsResponse:
    return BotStoreNotificationSettingsResponse(
        store_id=store_id,
        store_name=store_name,
        preferences=BotNotificationSettingsPreferences(
            notifications_enabled=preferences_view.preferences.notifications_enabled,
            device_status_enabled=preferences_view.preferences.device_status_enabled,
            defect_detected_enabled=preferences_view.preferences.defect_detected_enabled,
        ),
        capabilities=BotNotificationSettingsCapabilities(
            can_access_notifications=preferences_view.can_access_notifications,
            can_subscribe_device_status=preferences_view.can_subscribe_device_status,
            can_subscribe_defect_detected=preferences_view.can_subscribe_defect_detected,
        ),
    )


def _load_store_notification_settings_response(
    connection: sqlite3.Connection,
    *,
    user_id: str,
    membership_row: sqlite3.Row,
) -> BotStoreNotificationSettingsResponse:
    preferences_view = _load_notification_preference_view(
        connection,
        user_id=user_id,
        membership_row=membership_row,
    )
    return _build_store_notification_settings_response(
        store_id=membership_row["store_id"],
        store_name=membership_row["store_display_name"],
        preferences_view=preferences_view,
    )


def _load_notification_preference_view(
    connection: sqlite3.Connection,
    *,
    user_id: str,
    membership_row: sqlite3.Row,
):
    preferences = load_notification_preferences(
        connection,
        user_id=user_id,
        store_id=membership_row["store_id"],
    )
    return build_notification_preference_view(
        user_id=user_id,
        store_id=membership_row["store_id"],
        role=membership_row["role"],
        preferences=preferences,
    )


def _validate_notification_settings_update_allowed(
    *,
    user_id: str,
    store_id: str,
    provider_user_id: str,
    preferences_view,
    notifications_enabled: bool | None,
    device_status_enabled: bool | None,
    defect_detected_enabled: bool | None,
) -> None:
    if not preferences_view.can_access_notifications:
        logger.warning(
            "Bot notification settings update denied no access user_id=%s provider_user_id=%s store_id=%s",
            user_id,
            provider_user_id,
            store_id,
        )
        raise HTTPException(status_code=403, detail="notifications_not_available")

    if device_status_enabled is not None and not preferences_view.can_subscribe_device_status:
        logger.warning(
            "Bot notification settings update denied device_status capability user_id=%s provider_user_id=%s store_id=%s",
            user_id,
            provider_user_id,
            store_id,
        )
        raise HTTPException(status_code=403, detail="notification_option_not_available")

    if defect_detected_enabled is not None and not preferences_view.can_subscribe_defect_detected:
        logger.warning(
            "Bot notification settings update denied defect capability user_id=%s provider_user_id=%s store_id=%s",
            user_id,
            provider_user_id,
            store_id,
        )
        raise HTTPException(status_code=403, detail="notification_option_not_available")


def _update_store_notification_settings(
    connection: sqlite3.Connection,
    *,
    user_id: str,
    provider_user_id: str,
    membership_row: sqlite3.Row,
    notifications_enabled: bool | None,
    device_status_enabled: bool | None,
    defect_detected_enabled: bool | None,
) -> BotStoreNotificationSettingsResponse:
    preferences_view = _load_notification_preference_view(
        connection,
        user_id=user_id,
        membership_row=membership_row,
    )
    _validate_notification_settings_update_allowed(
        user_id=user_id,
        store_id=membership_row["store_id"],
        provider_user_id=provider_user_id,
        preferences_view=preferences_view,
        notifications_enabled=notifications_enabled,
        device_status_enabled=device_status_enabled,
        defect_detected_enabled=defect_detected_enabled,
    )
    updated_preferences = upsert_notification_preferences(
        connection,
        user_id=user_id,
        store_id=membership_row["store_id"],
        notifications_enabled=notifications_enabled,
        device_status_enabled=device_status_enabled,
        defect_detected_enabled=defect_detected_enabled,
    )
    updated_view = build_notification_preference_view(
        user_id=user_id,
        store_id=membership_row["store_id"],
        role=membership_row["role"],
        preferences=updated_preferences,
    )
    return _build_store_notification_settings_response(
        store_id=membership_row["store_id"],
        store_name=membership_row["store_display_name"],
        preferences_view=updated_view,
    )


def _to_legacy_notification_preferences_response(
    settings_view: BotStoreNotificationSettingsResponse,
) -> BotNotificationPreferencesResponse:
    return BotNotificationPreferencesResponse(
        store_id=settings_view.store_id,
        notifications_enabled=settings_view.preferences.notifications_enabled,
        device_status_enabled=settings_view.preferences.device_status_enabled,
        defect_detected_enabled=settings_view.preferences.defect_detected_enabled,
        can_access_notifications=settings_view.capabilities.can_access_notifications,
        can_access_device_status=settings_view.capabilities.can_subscribe_device_status,
        can_access_defect_detected=settings_view.capabilities.can_subscribe_defect_detected,
    )


def _select_store_device_rows(
    connection: sqlite3.Connection,
    *,
    store_id: str,
) -> list[sqlite3.Row]:
    return connection.execute(
        f"""
        SELECT
            device_id,
            {_device_display_name_expr("devices")} AS display_name,
            last_seen_at
        FROM devices
        WHERE store_id = ?
        ORDER BY created_at ASC, device_id ASC
        """,
        (store_id,),
    ).fetchall()


def _select_store_device_row(
    connection: sqlite3.Connection,
    *,
    store_id: str,
    device_id: str,
) -> sqlite3.Row | None:
    return connection.execute(
        f"""
        SELECT
            device_id,
            store_id,
            {_device_display_name_expr("devices")} AS display_name,
            last_seen_at
        FROM devices
        WHERE store_id = ? AND device_id = ?
        """,
        (store_id, device_id),
    ).fetchone()


def _require_store_device_row(
    connection: sqlite3.Connection,
    *,
    store_id: str,
    device_id: str,
    detail: str,
) -> sqlite3.Row:
    device_row = _select_store_device_row(
        connection,
        store_id=store_id,
        device_id=device_id,
    )
    if device_row is None:
        raise HTTPException(status_code=404, detail=detail)
    return device_row


def _store_has_devices(
    connection: sqlite3.Connection,
    *,
    store_id: str,
) -> bool:
    row = connection.execute(
        """
        SELECT 1
        FROM devices
        WHERE store_id = ?
        LIMIT 1
        """,
        (store_id,),
    ).fetchone()
    return row is not None


def _select_latest_store_result_row(
    connection: sqlite3.Connection,
    *,
    store_id: str,
) -> sqlite3.Row | None:
    return connection.execute(
        f"""
        SELECT
            scan_results.device_id,
            scan_results.image_id,
            scan_results.sent_at,
            scan_results.received_at,
            scan_results.scan_result_json,
            {_device_display_name_expr("devices")} AS device_display_name
        FROM scan_results
        JOIN devices ON devices.device_id = scan_results.device_id
        WHERE devices.store_id = ?
        ORDER BY
            COALESCE(scan_results.sent_at, scan_results.received_at) DESC,
            scan_results.received_at DESC,
            scan_results.id DESC
        LIMIT 1
        """,
        (store_id,),
    ).fetchone()


def _select_latest_device_result_row(
    connection: sqlite3.Connection,
    *,
    store_id: str,
    device_id: str,
) -> sqlite3.Row | None:
    return connection.execute(
        f"""
        SELECT
            scan_results.device_id,
            scan_results.image_id,
            scan_results.sent_at,
            scan_results.received_at,
            scan_results.scan_result_json,
            {_device_display_name_expr("devices")} AS device_display_name
        FROM scan_results
        JOIN devices ON devices.device_id = scan_results.device_id
        WHERE devices.store_id = ? AND scan_results.device_id = ?
        ORDER BY
            COALESCE(scan_results.sent_at, scan_results.received_at) DESC,
            scan_results.received_at DESC,
            scan_results.id DESC
        LIMIT 1
        """,
        (store_id, device_id),
    ).fetchone()


def _summarize_defect(scan_result_payload: dict[str, object]) -> BotDefectSummary:
    fruits = scan_result_payload.get("fruits")
    if not isinstance(fruits, list):
        return BotDefectSummary(value=False, type=None)

    saw_defect_entry = False
    for fruit in fruits:
        if not isinstance(fruit, dict):
            continue

        defects = fruit.get("defects")
        if not isinstance(defects, list) or not defects:
            continue

        saw_defect_entry = True
        for defect in defects:
            if not isinstance(defect, dict):
                continue

            defect_type = defect.get("type")
            if isinstance(defect_type, str):
                normalized_type = defect_type.strip()
                if normalized_type:
                    return BotDefectSummary(value=True, type=normalized_type)

    if saw_defect_entry:
        return BotDefectSummary(value=True, type=None)
    return BotDefectSummary(value=False, type=None)


def _result_row_to_model(row: sqlite3.Row) -> BotLatestResultResponse:
    try:
        scan_result_payload = json.loads(row["scan_result_json"])
    except json.JSONDecodeError as error:
        logger.exception(
            "Unexpected invalid scan_result_json for image_id=%s.",
            row["image_id"],
        )
        raise HTTPException(status_code=500, detail="Internal server error.") from error

    if not isinstance(scan_result_payload, dict):
        logger.error(
            "Unexpected non-object scan_result_json for image_id=%s.",
            row["image_id"],
        )
        raise HTTPException(status_code=500, detail="Internal server error.")

    defect_summary = _summarize_defect(scan_result_payload)
    return BotLatestResultResponse(
        device_id=row["device_id"],
        device_display_name=row["device_display_name"],
        image_id=row["image_id"],
        sent_at=row["sent_at"],
        received_at=row["received_at"],
        weight_grams=scan_result_payload.get("weight_grams"),
        fruits=scan_result_payload.get("fruits"),
        defect=defect_summary,
    )


def _role_has_all_permissions(role_name: str, *permissions: str) -> bool:
    return all(is_permission_granted(role_name, permission) for permission in permissions)


def _require_role_permissions(role_name: str, *permissions: str) -> None:
    if not _role_has_all_permissions(role_name, *permissions):
        raise HTTPException(status_code=403, detail="permission_denied")


def _normalize_invite_role(role_name: str) -> str:
    normalized = role_name.strip().lower()
    if not is_known_role(normalized):
        raise HTTPException(status_code=400, detail="unknown_role")
    if normalized not in ALLOWED_BOT_INVITE_ROLES:
        raise HTTPException(status_code=400, detail="invalid_invite_role")
    return normalized


def _normalize_request_type(request_type: str) -> str:
    normalized = request_type.strip().lower()
    if normalized not in {"camera.capture", "tare"}:
        raise HTTPException(status_code=400, detail="unsupported_request_type")
    return normalized


def _normalize_command_status(status: str | None) -> str:
    normalized = (status or "").strip().lower()
    if normalized in {"ok", "success", "succeeded"}:
        return "succeeded"
    if normalized in {"error", "failed", "failure"}:
        return "failed"
    return "failed"


def _require_request_permissions(role_name: str, request_type: str) -> None:
    if request_type == "camera.capture":
        _require_role_permissions(role_name, "commands.submit", "commands.device.request_scan")
        return
    if request_type == "tare":
        _require_role_permissions(role_name, "commands.submit", "commands.device.tare")
        return
    raise HTTPException(status_code=400, detail="unsupported_request_type")


def _generate_unique_invite_code(
    connection: sqlite3.Connection,
    *,
    secret_salt: str,
    now_utc: datetime,
) -> tuple[str, str]:
    for _ in range(MAX_INVITE_CODE_GENERATION_ATTEMPTS):
        invite_code = f"{secrets.randbelow(10**INVITE_CODE_DIGITS):0{INVITE_CODE_DIGITS}d}"
        code_hash = hash_token(invite_code, secret_salt)
        prior_rows = connection.execute(
            """
            SELECT expires_at, max_uses, used_count, revoked_at
            FROM staff_invites
            WHERE code_hash = ?
            """,
            (code_hash,),
        ).fetchall()
        has_active_collision = any(
            row["revoked_at"] is None
            and int(row["used_count"]) < int(row["max_uses"])
            and _parse_iso_datetime(row["expires_at"]) > now_utc
            for row in prior_rows
        )
        if not has_active_collision:
            return invite_code, code_hash

    raise HTTPException(status_code=500, detail="invite_code_generation_failed")


def _select_command_row(
    connection: sqlite3.Connection,
    *,
    command_id: str,
) -> sqlite3.Row | None:
    return connection.execute(
        """
        SELECT
            command_id,
            request_id,
            device_id,
            store_id,
            user_id,
            request_type,
            params_json,
            status,
            result_json,
            error_code,
            blob_id,
            created_at,
            sent_at,
            completed_at
        FROM device_commands
        WHERE command_id = ?
        """,
        (command_id,),
    ).fetchone()


def _command_row_to_status_response(row: sqlite3.Row) -> BotCommandStatusResponse:
    result_payload: object | None
    if row["result_json"] is None:
        result_payload = None
    else:
        try:
            result_payload = json.loads(row["result_json"])
        except json.JSONDecodeError:
            result_payload = None

    return BotCommandStatusResponse(
        command_id=row["command_id"],
        device_id=row["device_id"],
        store_id=row["store_id"],
        request_type=row["request_type"],
        status=row["status"],
        result=result_payload,
        error_code=row["error_code"],
        created_at=row["created_at"],
        completed_at=row["completed_at"],
    )


def _select_invite_row_by_code_hash(
    connection: sqlite3.Connection,
    *,
    code_hash: str,
) -> sqlite3.Row:
    row = connection.execute(
        f"""
        SELECT
            staff_invites.invite_id,
            staff_invites.store_id,
            staff_invites.role,
            staff_invites.created_by_user_id,
            staff_invites.created_at,
            staff_invites.expires_at,
            staff_invites.max_uses,
            staff_invites.used_count,
            staff_invites.revoked_at,
            staff_invites.note,
            stores.is_active AS store_is_active,
            {_store_display_name_expr("stores")} AS store_display_name
        FROM staff_invites
        JOIN stores ON stores.store_id = staff_invites.store_id
        WHERE staff_invites.code_hash = ?
        ORDER BY staff_invites.created_at DESC, staff_invites.invite_id DESC
        LIMIT 1
        """,
        (code_hash,),
    ).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="invite_not_found")
    return row


@router.get("/health", response_model=BotHealthResponse)
def bot_health(
    _: BotService = Depends(resolve_authenticated_bot_service),
) -> BotHealthResponse:
    return BotHealthResponse(ok=True)


@router.post("/session/ensure", response_model=BotSessionEnsureResponse)
def ensure_bot_session(
    payload: BotSessionEnsureRequest,
    _: BotService = Depends(resolve_authenticated_bot_service),
    connection: sqlite3.Connection = Depends(get_db),
) -> BotSessionEnsureResponse:
    normalized_provider = _require_supported_provider(payload.provider)

    now = datetime.now(timezone.utc).isoformat()
    user_id: str
    is_banned: bool
    session_state: dict[str, str | int | None]

    try:
        connection.execute("BEGIN IMMEDIATE")
        identity_row = connection.execute(
            """
            SELECT
                user_id,
                provider_chat_id
            FROM user_identities
            WHERE provider = ? AND provider_user_id = ?
            """,
            (normalized_provider, payload.provider_user_id),
        ).fetchone()

        if identity_row is None:
            user_id = str(uuid.uuid4())
            connection.execute(
                """
                INSERT INTO users (
                    user_id,
                    is_banned,
                    ban_reason,
                    created_at,
                    updated_at,
                    last_seen_at
                )
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (user_id, 0, None, now, now, now),
            )
            connection.execute(
                """
                INSERT INTO user_identities (
                    provider,
                    provider_user_id,
                    provider_chat_id,
                    username,
                    display_name,
                    user_id,
                    created_at,
                    updated_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    normalized_provider,
                    payload.provider_user_id,
                    payload.provider_chat_id,
                    payload.username,
                    payload.display_name,
                    user_id,
                    now,
                    now,
                ),
            )
        else:
            user_id = identity_row["user_id"]
            set_clauses: list[str] = []
            params: list[str] = []

            if payload.provider_chat_id != identity_row["provider_chat_id"]:
                set_clauses.append("provider_chat_id = ?")
                params.append(payload.provider_chat_id)
            if "username" in payload.model_fields_set and payload.username is not None:
                set_clauses.append("username = ?")
                params.append(payload.username)
            if "display_name" in payload.model_fields_set and payload.display_name is not None:
                set_clauses.append("display_name = ?")
                params.append(payload.display_name)

            if set_clauses:
                set_clauses.append("updated_at = ?")
                params.append(now)
                params.extend([normalized_provider, payload.provider_user_id])
                connection.execute(
                    f"""
                    UPDATE user_identities
                    SET {", ".join(set_clauses)}
                    WHERE provider = ? AND provider_user_id = ?
                    """,
                    tuple(params),
                )

            connection.execute(
                """
                UPDATE users
                SET last_seen_at = ?, updated_at = ?
                WHERE user_id = ?
                """,
                (now, now, user_id),
            )

        user_row = connection.execute(
            """
            SELECT is_banned
            FROM users
            WHERE user_id = ?
            """,
            (user_id,),
        ).fetchone()
        if user_row is None:
            raise HTTPException(status_code=500, detail="Internal server error.")

        session_state = _load_session_state(connection, user_id=user_id)
        connection.execute("COMMIT")
        is_banned = int(user_row["is_banned"]) == 1
    except HTTPException:
        rollback_quietly(connection)
        raise
    except Exception as error:
        rollback_quietly(connection)
        logger.exception("Unexpected failure while ensuring bot session.")
        raise HTTPException(status_code=500, detail="Internal server error.") from error

    logger.info(
        "Bot session ensured provider_user_id=%s user_id=%s",
        payload.provider_user_id,
        user_id,
    )
    return BotSessionEnsureResponse(
        user_id=user_id,
        is_banned=is_banned,
        is_linked=int(session_state["memberships_count"] or 0) > 0,
        memberships_count=int(session_state["memberships_count"] or 0),
        active_store_id=session_state["active_store_id"],
        active_store_display_name=session_state["active_store_display_name"],
        active_device_id=session_state["active_device_id"],
    )


@router.post("/invites/create", response_model=BotInviteCreateResponse)
def create_bot_invite(
    payload: BotInviteCreateRequest,
    _: BotService = Depends(resolve_authenticated_bot_service),
    connection: sqlite3.Connection = Depends(get_db),
) -> BotInviteCreateResponse:
    settings = get_settings()
    normalized_provider = _require_supported_provider(payload.provider)
    invite_role = _normalize_invite_role(payload.role)
    invite_id = str(uuid.uuid4())
    invite_code: str
    expires_at: str
    user_id: str
    active_store_id: str

    try:
        connection.execute("BEGIN IMMEDIATE")
        user_row = _require_known_user(
            connection,
            provider=normalized_provider,
            provider_user_id=payload.provider_user_id,
        )
        _require_not_banned(user_row)
        user_id = user_row["user_id"]

        context_row = _get_user_context_row(connection, user_id=user_id)
        active_store_id = context_row["active_store_id"] if context_row is not None else None
        if active_store_id is None:
            raise HTTPException(status_code=400, detail="no_active_store")

        membership_row = _select_active_membership_row(
            connection,
            user_id=user_id,
            store_id=active_store_id,
        )
        if membership_row is None:
            raise HTTPException(status_code=400, detail="no_active_store")
        if int(membership_row["store_is_active"]) != 1:
            raise HTTPException(status_code=400, detail="store_inactive")

        _require_role_permissions(membership_row["role"], "invites.create")

        now_utc = datetime.now(timezone.utc)
        created_at = now_utc.isoformat()
        expires_at = (now_utc + timedelta(seconds=payload.expires_in_sec)).isoformat()
        invite_code, code_hash = _generate_unique_invite_code(
            connection,
            secret_salt=settings.secret_salt,
            now_utc=now_utc,
        )

        connection.execute(
            """
            INSERT INTO staff_invites (
                invite_id,
                store_id,
                code_hash,
                role,
                created_by_user_id,
                created_at,
                expires_at,
                max_uses,
                used_count,
                revoked_at,
                note
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                invite_id,
                active_store_id,
                code_hash,
                invite_role,
                user_id,
                created_at,
                expires_at,
                payload.max_uses,
                0,
                None,
                payload.note,
            ),
        )
        connection.execute("COMMIT")
    except HTTPException:
        rollback_quietly(connection)
        raise
    except Exception as error:
        rollback_quietly(connection)
        logger.exception("Unexpected failure while creating bot invite.")
        raise HTTPException(status_code=500, detail="Internal server error.") from error

    logger.info(
        "Bot invite created user_id=%s store_id=%s invite_id=%s role=%s",
        user_id,
        active_store_id,
        invite_id,
        invite_role,
    )
    return BotInviteCreateResponse(
        invite_id=invite_id,
        invite_code=invite_code,
        store_id=active_store_id,
        role=invite_role,
        expires_at=expires_at,
        max_uses=payload.max_uses,
    )


@router.post("/invites/redeem", response_model=BotInviteRedeemResponse)
def redeem_bot_invite(
    payload: BotInviteRedeemRequest,
    _: BotService = Depends(resolve_authenticated_bot_service),
    connection: sqlite3.Connection = Depends(get_db),
) -> BotInviteRedeemResponse:
    settings = get_settings()
    normalized_provider = _require_supported_provider(payload.provider)
    already_linked = False
    role: str
    store_id: str
    store_display_name: str
    user_id: str

    try:
        connection.execute("BEGIN IMMEDIATE")
        user_row = _require_known_user(
            connection,
            provider=normalized_provider,
            provider_user_id=payload.provider_user_id,
        )
        _require_not_banned(user_row)
        user_id = user_row["user_id"]

        invite_row = _select_invite_row_by_code_hash(
            connection,
            code_hash=hash_token(payload.invite_code, settings.secret_salt),
        )
        now_utc = datetime.now(timezone.utc)
        if invite_row["revoked_at"] is not None:
            raise HTTPException(status_code=400, detail="invite_revoked")
        if _parse_iso_datetime(invite_row["expires_at"]) <= now_utc:
            raise HTTPException(status_code=400, detail="invite_expired")
        if int(invite_row["used_count"]) >= int(invite_row["max_uses"]):
            raise HTTPException(status_code=400, detail="invite_exhausted")
        if int(invite_row["store_is_active"]) != 1:
            raise HTTPException(status_code=400, detail="store_inactive")

        store_id = invite_row["store_id"]
        store_display_name = invite_row["store_display_name"]
        membership_row = _select_active_membership_row(
            connection,
            user_id=user_id,
            store_id=store_id,
        )
        if membership_row is None:
            created_at = now_utc.isoformat()
            connection.execute(
                """
                INSERT INTO store_memberships (
                    membership_id,
                    store_id,
                    user_id,
                    role,
                    created_at,
                    revoked_at,
                    created_by_user_id,
                    note
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    str(uuid.uuid4()),
                    store_id,
                    user_id,
                    invite_row["role"],
                    created_at,
                    None,
                    invite_row["created_by_user_id"],
                    f"invite:{invite_row['invite_id']}",
                ),
            )
            connection.execute(
                """
                UPDATE staff_invites
                SET used_count = used_count + 1
                WHERE invite_id = ? AND used_count < max_uses
                """,
                (invite_row["invite_id"],),
            )
            role = invite_row["role"]
        else:
            already_linked = True
            role = membership_row["role"]

        _upsert_user_context(
            connection,
            user_id=user_id,
            active_store_id=store_id,
            active_device_id=None,
            updated_at=now_utc.isoformat(),
        )
        connection.execute("COMMIT")
    except HTTPException:
        rollback_quietly(connection)
        raise
    except Exception as error:
        rollback_quietly(connection)
        logger.exception("Unexpected failure while redeeming bot invite.")
        raise HTTPException(status_code=500, detail="Internal server error.") from error

    logger.info(
        "Bot invite redeemed user_id=%s store_id=%s already_linked=%s",
        user_id,
        store_id,
        already_linked,
    )
    return BotInviteRedeemResponse(
        already_linked=already_linked,
        store=BotInviteRedeemStore(
            store_id=store_id,
            display_name=store_display_name,
        ),
        role=role,
    )


@router.get("/stores", response_model=BotStoresResponse)
def list_bot_stores(
    provider: str = Query(..., min_length=1),
    provider_user_id: str = Query(..., min_length=1),
    _: BotService = Depends(resolve_authenticated_bot_service),
    connection: sqlite3.Connection = Depends(get_db),
) -> BotStoresResponse:
    normalized_provider = _require_supported_provider(provider)
    user_row = _require_known_user(
        connection,
        provider=normalized_provider,
        provider_user_id=provider_user_id,
    )
    _require_not_banned(user_row)

    memberships = _select_active_membership_rows(connection, user_id=user_row["user_id"])
    if not memberships:
        return BotStoresResponse(items=[])

    permitted_memberships = [
        membership
        for membership in memberships
        if _role_has_all_permissions(membership["role"], "bot.user_context.read", "stores.read")
    ]
    if not permitted_memberships:
        raise HTTPException(status_code=403, detail="permission_denied")

    context_row = _get_user_context_row(connection, user_id=user_row["user_id"])
    active_store_id = context_row["active_store_id"] if context_row is not None else None

    return BotStoresResponse(
        items=[
            BotStoreSummary(
                store_id=membership["store_id"],
                display_name=membership["store_display_name"],
                address=membership["address"],
                role=membership["role"],
                store_is_active=int(membership["store_is_active"]) == 1,
                is_active_store=membership["store_id"] == active_store_id,
            )
            for membership in permitted_memberships
        ]
    )


@router.get("/stores/{store_id}/devices", response_model=BotStoreDevicesResponse)
def list_bot_store_devices(
    store_id: str,
    provider: str = Query(..., min_length=1),
    provider_user_id: str = Query(..., min_length=1),
    _: BotService = Depends(resolve_authenticated_bot_service),
    connection: sqlite3.Connection = Depends(get_db),
) -> BotStoreDevicesResponse:
    normalized_provider = _require_supported_provider(provider)
    user_row = _require_known_user(
        connection,
        provider=normalized_provider,
        provider_user_id=provider_user_id,
    )
    _require_not_banned(user_row)

    membership_row = _require_membership_row(
        connection,
        user_id=user_row["user_id"],
        store_id=store_id,
    )
    _require_role_permissions(membership_row["role"], "stores.read", "devices.list")

    settings = get_settings()
    now_utc = datetime.now(timezone.utc)
    device_rows = _select_store_device_rows(connection, store_id=store_id)
    return BotStoreDevicesResponse(
        store_id=store_id,
        items=[
            _build_bot_device_summary(
                row,
                now_utc=now_utc,
                threshold_seconds=settings.online_threshold_seconds,
            )
            for row in device_rows
        ],
    )


@router.post("/context/active_store", response_model=BotSetActiveStoreResponse)
def set_active_store(
    payload: BotSetActiveStoreRequest,
    _: BotService = Depends(resolve_authenticated_bot_service),
    connection: sqlite3.Connection = Depends(get_db),
) -> BotSetActiveStoreResponse:
    normalized_provider = _require_supported_provider(payload.provider)
    user_id: str

    try:
        connection.execute("BEGIN IMMEDIATE")
        user_row = _require_known_user(
            connection,
            provider=normalized_provider,
            provider_user_id=payload.provider_user_id,
        )
        _require_not_banned(user_row)
        user_id = user_row["user_id"]

        membership_row = _select_active_membership_row(
            connection,
            user_id=user_id,
            store_id=payload.store_id,
        )
        if membership_row is None:
            raise HTTPException(status_code=404, detail="membership_not_found")

        _require_role_permissions(membership_row["role"], "bot.store.select")
        _upsert_user_context(
            connection,
            user_id=user_id,
            active_store_id=payload.store_id,
            active_device_id=None,
            updated_at=datetime.now(timezone.utc).isoformat(),
        )
        connection.execute("COMMIT")
    except HTTPException:
        rollback_quietly(connection)
        raise
    except Exception as error:
        rollback_quietly(connection)
        logger.exception("Unexpected failure while selecting active store.")
        raise HTTPException(status_code=500, detail="Internal server error.") from error

    logger.info("Bot active store selected user_id=%s store_id=%s", user_id, payload.store_id)
    return BotSetActiveStoreResponse(active_store_id=payload.store_id, active_device_id=None)


@router.post("/context/active_device", response_model=BotSetActiveDeviceResponse)
def set_active_device(
    payload: BotSetActiveDeviceRequest,
    _: BotService = Depends(resolve_authenticated_bot_service),
    connection: sqlite3.Connection = Depends(get_db),
) -> BotSetActiveDeviceResponse:
    normalized_provider = _require_supported_provider(payload.provider)
    user_id: str
    active_store_id: str

    try:
        connection.execute("BEGIN IMMEDIATE")
        user_row = _require_known_user(
            connection,
            provider=normalized_provider,
            provider_user_id=payload.provider_user_id,
        )
        _require_not_banned(user_row)
        user_id = user_row["user_id"]

        membership_row = _require_active_store_membership_row(connection, user_id=user_id)
        active_store_id = membership_row["store_id"]
        _require_role_permissions(membership_row["role"], "devices.list")
        _require_store_device_row(
            connection,
            store_id=active_store_id,
            device_id=payload.device_id,
            detail="device_not_in_active_store",
        )

        _upsert_user_context(
            connection,
            user_id=user_id,
            active_store_id=active_store_id,
            active_device_id=payload.device_id,
            updated_at=datetime.now(timezone.utc).isoformat(),
        )
        connection.execute("COMMIT")
    except HTTPException:
        rollback_quietly(connection)
        raise
    except Exception as error:
        rollback_quietly(connection)
        logger.exception("Unexpected failure while selecting active device.")
        raise HTTPException(status_code=500, detail="Internal server error.") from error

    logger.info(
        "Bot active device selected user_id=%s store_id=%s device_id=%s",
        user_id,
        active_store_id,
        payload.device_id,
    )
    return BotSetActiveDeviceResponse(
        active_store_id=active_store_id,
        active_device_id=payload.device_id,
    )


@router.get(
    "/notifications/settings/stores",
    response_model=BotNotificationSettingsStoresResponse,
)
def list_bot_notification_settings_stores(
    provider: str = Query(..., min_length=1),
    provider_user_id: str = Query(..., min_length=1),
    _: BotService = Depends(resolve_authenticated_bot_service),
    connection: sqlite3.Connection = Depends(get_db),
) -> BotNotificationSettingsStoresResponse:
    normalized_provider = _require_supported_provider(provider)
    user_row = _require_known_user(
        connection,
        provider=normalized_provider,
        provider_user_id=provider_user_id,
    )
    _require_not_banned(user_row)
    memberships = _select_notification_settings_membership_rows(
        connection,
        user_id=user_row["user_id"],
    )
    response = BotNotificationSettingsStoresResponse(
        items=[
            BotNotificationSettingsStoreSummary(
                store_id=membership["store_id"],
                store_name=membership["store_display_name"],
            )
            for membership in memberships
        ]
    )
    logger.info(
        "Bot notification settings stores listed user_id=%s provider_user_id=%s eligible_count=%s",
        user_row["user_id"],
        provider_user_id,
        len(response.items),
    )
    return response


@router.get(
    "/notifications/settings/stores/{store_id}",
    response_model=BotStoreNotificationSettingsResponse,
)
def get_bot_store_notification_settings(
    store_id: str,
    provider: str = Query(..., min_length=1),
    provider_user_id: str = Query(..., min_length=1),
    _: BotService = Depends(resolve_authenticated_bot_service),
    connection: sqlite3.Connection = Depends(get_db),
) -> BotStoreNotificationSettingsResponse:
    normalized_provider = _require_supported_provider(provider)
    user_row = _require_known_user(
        connection,
        provider=normalized_provider,
        provider_user_id=provider_user_id,
    )
    _require_not_banned(user_row)
    membership_row = _require_notification_settings_membership_row(
        connection,
        user_id=user_row["user_id"],
        store_id=store_id,
    )
    response = _load_store_notification_settings_response(
        connection,
        user_id=user_row["user_id"],
        membership_row=membership_row,
    )
    logger.info(
        "Bot notification settings loaded user_id=%s provider_user_id=%s store_id=%s",
        user_row["user_id"],
        provider_user_id,
        store_id,
    )
    return response


@router.put(
    "/notifications/settings/stores/{store_id}",
    response_model=BotStoreNotificationSettingsResponse,
)
def update_bot_store_notification_settings(
    store_id: str,
    payload: BotUpdateStoreNotificationSettingsRequest,
    _: BotService = Depends(resolve_authenticated_bot_service),
    connection: sqlite3.Connection = Depends(get_db),
) -> BotStoreNotificationSettingsResponse:
    normalized_provider = _require_supported_provider(payload.provider)
    user_id: str
    response: BotStoreNotificationSettingsResponse
    try:
        connection.execute("BEGIN IMMEDIATE")
        user_row = _require_known_user(
            connection,
            provider=normalized_provider,
            provider_user_id=payload.provider_user_id,
        )
        _require_not_banned(user_row)
        user_id = user_row["user_id"]
        membership_row = _require_notification_settings_membership_row(
            connection,
            user_id=user_id,
            store_id=store_id,
        )
        response = _update_store_notification_settings(
            connection,
            user_id=user_id,
            provider_user_id=payload.provider_user_id,
            membership_row=membership_row,
            notifications_enabled=payload.notifications_enabled,
            device_status_enabled=payload.device_status_enabled,
            defect_detected_enabled=payload.defect_detected_enabled,
        )
        connection.execute("COMMIT")
    except HTTPException:
        rollback_quietly(connection)
        raise
    except Exception as error:
        rollback_quietly(connection)
        logger.exception("Unexpected failure while updating bot notification settings.")
        raise HTTPException(status_code=500, detail="Internal server error.") from error

    logger.info(
        "Bot notification settings updated user_id=%s provider_user_id=%s store_id=%s",
        user_id,
        payload.provider_user_id,
        store_id,
    )
    return response


@router.get(
    "/notifications/preferences",
    response_model=BotNotificationPreferencesResponse,
)
def get_bot_notification_preferences(
    provider: str = Query(..., min_length=1),
    provider_user_id: str = Query(..., min_length=1),
    _: BotService = Depends(resolve_authenticated_bot_service),
    connection: sqlite3.Connection = Depends(get_db),
) -> BotNotificationPreferencesResponse:
    normalized_provider = _require_supported_provider(provider)
    user_row = _require_known_user(
        connection,
        provider=normalized_provider,
        provider_user_id=provider_user_id,
    )
    _require_not_banned(user_row)
    membership_row = _require_active_notification_settings_membership_row(
        connection,
        user_id=user_row["user_id"],
    )
    settings_view = _load_store_notification_settings_response(
        connection,
        user_id=user_row["user_id"],
        membership_row=membership_row,
    )
    return _to_legacy_notification_preferences_response(settings_view)


@router.put(
    "/notifications/preferences",
    response_model=BotNotificationPreferencesResponse,
)
def update_bot_notification_preferences(
    payload: BotUpdateNotificationPreferencesRequest,
    _: BotService = Depends(resolve_authenticated_bot_service),
    connection: sqlite3.Connection = Depends(get_db),
) -> BotNotificationPreferencesResponse:
    normalized_provider = _require_supported_provider(payload.provider)
    user_id: str
    updated_response: BotStoreNotificationSettingsResponse
    try:
        connection.execute("BEGIN IMMEDIATE")
        user_row = _require_known_user(
            connection,
            provider=normalized_provider,
            provider_user_id=payload.provider_user_id,
        )
        _require_not_banned(user_row)
        user_id = user_row["user_id"]
        membership_row = _require_active_notification_settings_membership_row(
            connection,
            user_id=user_id,
        )
        updated_response = _update_store_notification_settings(
            connection,
            user_id=user_id,
            provider_user_id=payload.provider_user_id,
            membership_row=membership_row,
            notifications_enabled=payload.notifications_enabled,
            device_status_enabled=payload.device_status_enabled,
            defect_detected_enabled=payload.defect_detected_enabled,
        )
        connection.execute("COMMIT")
    except HTTPException:
        rollback_quietly(connection)
        raise
    except Exception as error:
        rollback_quietly(connection)
        logger.exception("Unexpected failure while updating bot notification preferences.")
        raise HTTPException(status_code=500, detail="Internal server error.") from error

    logger.info(
        "Bot notification preferences updated user_id=%s store_id=%s",
        user_id,
        updated_response.store_id,
    )
    return _to_legacy_notification_preferences_response(updated_response)


@router.get("/devices/{device_id}/status", response_model=BotDeviceStatusResponse)
def get_bot_device_status(
    device_id: str,
    provider: str = Query(..., min_length=1),
    provider_user_id: str = Query(..., min_length=1),
    _: BotService = Depends(resolve_authenticated_bot_service),
    connection: sqlite3.Connection = Depends(get_db),
) -> BotDeviceStatusResponse:
    normalized_provider = _require_supported_provider(provider)
    user_row = _require_known_user(
        connection,
        provider=normalized_provider,
        provider_user_id=provider_user_id,
    )
    _require_not_banned(user_row)

    membership_row = _require_active_store_membership_row(
        connection,
        user_id=user_row["user_id"],
    )
    _require_role_permissions(membership_row["role"], "devices.status.read")
    device_row = _require_store_device_row(
        connection,
        store_id=membership_row["store_id"],
        device_id=device_id,
        detail="device_not_in_active_store",
    )

    can_request_photo = _role_has_all_permissions(
        membership_row["role"],
        "commands.submit",
        "commands.device.request_scan",
    )
    can_tare = _role_has_all_permissions(
        membership_row["role"],
        "commands.submit",
        "commands.device.tare",
    )

    settings = get_settings()
    return _build_bot_device_status_response(
        device_row,
        now_utc=datetime.now(timezone.utc),
        threshold_seconds=settings.online_threshold_seconds,
        can_request_photo=can_request_photo,
        can_tare=can_tare,
    )


@router.get("/results/last", response_model=BotLatestResultResponse)
def get_bot_store_last_result(
    provider: str = Query(..., min_length=1),
    provider_user_id: str = Query(..., min_length=1),
    _: BotService = Depends(resolve_authenticated_bot_service),
    connection: sqlite3.Connection = Depends(get_db),
) -> BotLatestResultResponse:
    normalized_provider = _require_supported_provider(provider)
    user_row = _require_known_user(
        connection,
        provider=normalized_provider,
        provider_user_id=provider_user_id,
    )
    _require_not_banned(user_row)

    membership_row = _require_active_store_membership_row(
        connection,
        user_id=user_row["user_id"],
    )
    _require_role_permissions(membership_row["role"], "results.read.last")
    if not _store_has_devices(connection, store_id=membership_row["store_id"]):
        raise HTTPException(status_code=404, detail="store_has_no_devices")

    result_row = _select_latest_store_result_row(
        connection,
        store_id=membership_row["store_id"],
    )
    if result_row is None:
        raise HTTPException(status_code=404, detail="result_not_found")
    return _result_row_to_model(result_row)


@router.get("/devices/{device_id}/results/last", response_model=BotLatestResultResponse)
def get_bot_device_last_result(
    device_id: str,
    provider: str = Query(..., min_length=1),
    provider_user_id: str = Query(..., min_length=1),
    _: BotService = Depends(resolve_authenticated_bot_service),
    connection: sqlite3.Connection = Depends(get_db),
) -> BotLatestResultResponse:
    normalized_provider = _require_supported_provider(provider)
    user_row = _require_known_user(
        connection,
        provider=normalized_provider,
        provider_user_id=provider_user_id,
    )
    _require_not_banned(user_row)

    membership_row = _require_active_store_membership_row(
        connection,
        user_id=user_row["user_id"],
    )
    _require_role_permissions(membership_row["role"], "results.read.last")
    _require_store_device_row(
        connection,
        store_id=membership_row["store_id"],
        device_id=device_id,
        detail="device_not_in_active_store",
    )

    result_row = _select_latest_device_result_row(
        connection,
        store_id=membership_row["store_id"],
        device_id=device_id,
    )
    if result_row is None:
        raise HTTPException(status_code=404, detail="result_not_found")
    return _result_row_to_model(result_row)


@router.post("/devices/{device_id}/commands", response_model=BotDeviceCommandResponse)
async def submit_bot_device_command(
    device_id: str,
    payload: BotDeviceCommandRequest,
    _: BotService = Depends(resolve_authenticated_bot_service),
) -> BotDeviceCommandResponse:
    settings = get_settings()
    connection = open_connection(settings.database_path)
    try:
        normalized_provider = _require_supported_provider(payload.provider)
        user_row = _require_known_user(
            connection,
            provider=normalized_provider,
            provider_user_id=payload.provider_user_id,
        )
        _require_not_banned(user_row)

        membership_row = _require_active_store_membership_row(
            connection,
            user_id=user_row["user_id"],
        )
        device_row = _require_store_device_row(
            connection,
            store_id=membership_row["store_id"],
            device_id=device_id,
            detail="device_not_in_active_store",
        )

        request_type = _normalize_request_type(payload.request_type)
        _require_request_permissions(membership_row["role"], request_type)

        now = datetime.now(timezone.utc).isoformat()
        command_id = str(uuid.uuid4())
        request_id = str(uuid.uuid4())
        params_payload = json.dumps(payload.params, separators=(",", ":"), sort_keys=True)

        try:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                """
                INSERT INTO device_commands (
                    command_id,
                    request_id,
                    device_id,
                    store_id,
                    user_id,
                    request_type,
                    params_json,
                    status,
                    result_json,
                    error_code,
                    blob_id,
                    created_at,
                    sent_at,
                    completed_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    command_id,
                    request_id,
                    device_id,
                    membership_row["store_id"],
                    user_row["user_id"],
                    request_type,
                    params_payload,
                    "queued",
                    None,
                    None,
                    None,
                    now,
                    None,
                    None,
                ),
            )
            connection.execute("COMMIT")
        except HTTPException:
            rollback_quietly(connection)
            raise
        except Exception as error:
            rollback_quietly(connection)
            logger.exception("Unexpected failure while storing bot command.")
            raise HTTPException(status_code=500, detail="Internal server error.") from error

        if payload.wait_timeout_ms is not None:
            timeout_s = payload.wait_timeout_ms / 1000.0
        else:
            timeout_s = 12.0 if request_type == "camera.capture" else 6.0
        timeout_s = max(0.0, timeout_s)

        try:
            connection.execute(
                "UPDATE device_commands SET status = ?, sent_at = ? WHERE command_id = ?",
                ("sent", datetime.now(timezone.utc).isoformat(), command_id),
            )
            connection.commit()
        except Exception as error:
            logger.exception("Failed to mark bot command sent.")
            raise HTTPException(status_code=500, detail="Internal server error.") from error

        try:
            response_payload = await send_command(
                device_id=device_row["device_id"],
                request_type=request_type,
                params=payload.params,
                timeout_s=timeout_s,
            )
        except CommandTimeoutError:
            connection.execute(
                "UPDATE device_commands SET status = ? WHERE command_id = ?",
                ("running", command_id),
            )
            connection.commit()
            return BotDeviceCommandResponse(
                command_id=command_id,
                device_id=device_row["device_id"],
                store_id=membership_row["store_id"],
                request_type=request_type,
                status="running",
                result=None,
                error_code=None,
                created_at=now,
                completed_at=None,
            )
        except HTTPException:
            connection.execute(
                """
                UPDATE device_commands
                SET status = ?, error_code = ?, completed_at = ?
                WHERE command_id = ?
                """,
                (
                    "failed",
                    "connector_offline",
                    datetime.now(timezone.utc).isoformat(),
                    command_id,
                ),
            )
            connection.commit()
            raise HTTPException(status_code=409, detail="connector_offline")

        response_status = _normalize_command_status(
            response_payload.get("status") if isinstance(response_payload, dict) else None
        )
        response_data = (
            response_payload.get("data") if isinstance(response_payload, dict) else None
        )
        response_error = (
            response_payload.get("error") if isinstance(response_payload, dict) else None
        )
        blob_id = None
        if isinstance(response_data, dict):
            blob_candidate = response_data.get("blob_id")
            if isinstance(blob_candidate, str) and blob_candidate:
                blob_id = blob_candidate

        result_json = json.dumps(response_data, separators=(",", ":"), sort_keys=True)
        completed_at = datetime.now(timezone.utc).isoformat()
        error_code = None
        if response_status != "succeeded":
            error_code = "command_failed"
            if isinstance(response_error, str) and response_error.strip():
                error_code = response_error.strip()

        connection.execute(
            """
            UPDATE device_commands
            SET status = ?, result_json = ?, error_code = ?, blob_id = ?, completed_at = ?
            WHERE command_id = ?
            """,
            (
                response_status,
                result_json,
                error_code,
                blob_id,
                completed_at,
                command_id,
            ),
        )
        connection.commit()

        return BotDeviceCommandResponse(
            command_id=command_id,
            device_id=device_row["device_id"],
            store_id=membership_row["store_id"],
            request_type=request_type,
            status=response_status,
            result=response_data,
            error_code=error_code,
            created_at=now,
            completed_at=completed_at,
        )
    finally:
        connection.close()


@router.get("/commands/{command_id}", response_model=BotCommandStatusResponse)
def get_bot_command_status(
    command_id: str,
    provider: str = Query(..., min_length=1),
    provider_user_id: str = Query(..., min_length=1),
    _: BotService = Depends(resolve_authenticated_bot_service),
    connection: sqlite3.Connection = Depends(get_db),
) -> BotCommandStatusResponse:
    normalized_provider = _require_supported_provider(provider)
    user_row = _require_known_user(
        connection,
        provider=normalized_provider,
        provider_user_id=provider_user_id,
    )
    _require_not_banned(user_row)

    command_row = _select_command_row(connection, command_id=command_id)
    if command_row is None:
        raise HTTPException(status_code=404, detail="command_not_found")
    if command_row["user_id"] != user_row["user_id"]:
        raise HTTPException(status_code=403, detail="permission_denied")

    membership_row = _require_membership_row(
        connection,
        user_id=user_row["user_id"],
        store_id=command_row["store_id"],
        detail="command_not_found",
    )
    _ = membership_row

    return _command_row_to_status_response(command_row)


@router.get("/commands/{command_id}/photo")
def get_bot_command_photo(
    command_id: str,
    provider: str = Query(..., min_length=1),
    provider_user_id: str = Query(..., min_length=1),
    _: BotService = Depends(resolve_authenticated_bot_service),
    connection: sqlite3.Connection = Depends(get_db),
) -> FileResponse:
    normalized_provider = _require_supported_provider(provider)
    user_row = _require_known_user(
        connection,
        provider=normalized_provider,
        provider_user_id=provider_user_id,
    )
    _require_not_banned(user_row)

    command_row = _select_command_row(connection, command_id=command_id)
    if command_row is None:
        raise HTTPException(status_code=404, detail="command_not_found")
    if command_row["user_id"] != user_row["user_id"]:
        raise HTTPException(status_code=403, detail="permission_denied")

    _require_membership_row(
        connection,
        user_id=user_row["user_id"],
        store_id=command_row["store_id"],
        detail="command_not_found",
    )

    if command_row["request_type"] != "camera.capture":
        raise HTTPException(status_code=400, detail="command_has_no_photo")
    if command_row["status"] != "succeeded":
        raise HTTPException(status_code=409, detail="photo_not_ready")
    blob_id = command_row["blob_id"]
    if not blob_id:
        raise HTTPException(status_code=404, detail="photo_not_found")

    blob_row = connection.execute(
        """
        SELECT path, content_type
        FROM blobs
        WHERE blob_id = ?
        """,
        (blob_id,),
    ).fetchone()
    if blob_row is None:
        raise HTTPException(status_code=404, detail="photo_not_found")

    blob_path = Path(blob_row["path"])
    if not blob_path.exists():
        raise HTTPException(status_code=404, detail="photo_not_found")

    return FileResponse(
        path=blob_path,
        media_type=blob_row["content_type"],
        filename=blob_path.name,
    )


@router.get("/notifications/results/{result_id}/image")
async def get_bot_notification_result_image(
    result_id: str,
    provider: str = Query(..., min_length=1),
    provider_user_id: str = Query(..., min_length=1),
    _: BotService = Depends(resolve_authenticated_bot_service),
) -> FileResponse:
    settings = get_settings()
    normalized_provider = _require_supported_provider(provider)
    normalized_provider_user_id = provider_user_id.strip()
    connection = open_connection(settings.database_path)
    try:
        user_row = _require_known_user(
            connection,
            provider=normalized_provider,
            provider_user_id=provider_user_id,
        )
        _require_not_banned(user_row)

        result_context = load_result_image_context(connection, result_id=result_id)
        if result_context is None:
            raise HTTPException(status_code=404, detail="result_not_found")

        membership_row = _require_membership_row(
            connection,
            user_id=user_row["user_id"],
            store_id=result_context.store_id,
            detail="result_not_found",
        )
        _require_role_permissions(
            membership_row["role"],
            "notifications.access",
            "notifications.defect_detected",
        )

        delivery_row = connection.execute(
            """
            SELECT notification_deliveries.notification_delivery_id
            FROM notification_events
            JOIN notification_deliveries
              ON notification_deliveries.notification_event_id = notification_events.notification_event_id
            WHERE notification_events.event_type = ?
              AND notification_events.result_id = ?
              AND notification_deliveries.provider_user_id = ?
            ORDER BY notification_events.created_at DESC
            LIMIT 1
            """,
            (
                EVENT_DEFECT_DETECTED,
                result_id,
                normalized_provider_user_id,
            ),
        ).fetchone()
        if delivery_row is None:
            raise HTTPException(status_code=403, detail="image_access_denied")
    finally:
        connection.close()

    image_result = await get_or_create_annotated_image(
        database_path=settings.database_path,
        blob_storage_dir=settings.blob_storage_dir,
        result_id=result_id,
        cache_ttl_seconds=settings.annotated_image_cache_ttl_seconds,
        request_timeout_seconds=settings.command_default_timeout_seconds,
    )
    return FileResponse(
        path=image_result.path,
        media_type=image_result.content_type,
        filename=image_result.path.name,
    )


@router.post("/memberships/revoke_self", response_model=BotRevokeSelfMembershipResponse)
def revoke_self_membership(
    payload: BotRevokeSelfMembershipRequest,
    _: BotService = Depends(resolve_authenticated_bot_service),
    connection: sqlite3.Connection = Depends(get_db),
) -> BotRevokeSelfMembershipResponse:
    normalized_provider = _require_supported_provider(payload.provider)
    user_id: str
    active_store_id: str | None
    active_device_id: str | None

    try:
        connection.execute("BEGIN IMMEDIATE")
        user_row = _require_known_user(
            connection,
            provider=normalized_provider,
            provider_user_id=payload.provider_user_id,
        )
        _require_not_banned(user_row)
        user_id = user_row["user_id"]

        membership_row = _select_active_membership_row(
            connection,
            user_id=user_id,
            store_id=payload.store_id,
        )
        if membership_row is None:
            raise HTTPException(status_code=404, detail="membership_not_found")

        _require_role_permissions(membership_row["role"], "memberships.revoke.self")
        revoked_at = datetime.now(timezone.utc).isoformat()
        connection.execute(
            """
            UPDATE store_memberships
            SET revoked_at = ?
            WHERE membership_id = ? AND revoked_at IS NULL
            """,
            (revoked_at, membership_row["membership_id"]),
        )

        context_row = _get_user_context_row(connection, user_id=user_id)
        active_store_id = context_row["active_store_id"] if context_row is not None else None
        active_device_id = context_row["active_device_id"] if context_row is not None else None

        if active_store_id == payload.store_id:
            next_membership_row = _select_next_active_membership(connection, user_id=user_id)
            active_store_id = (
                next_membership_row["store_id"] if next_membership_row is not None else None
            )
            active_device_id = None
            _upsert_user_context(
                connection,
                user_id=user_id,
                active_store_id=active_store_id,
                active_device_id=active_device_id,
                updated_at=revoked_at,
            )

        connection.execute("COMMIT")
    except HTTPException:
        rollback_quietly(connection)
        raise
    except Exception as error:
        rollback_quietly(connection)
        logger.exception("Unexpected failure while revoking self membership.")
        raise HTTPException(status_code=500, detail="Internal server error.") from error

    logger.info("Bot membership revoked user_id=%s store_id=%s", user_id, payload.store_id)
    return BotRevokeSelfMembershipResponse(
        revoked_store_id=payload.store_id,
        active_store_id=active_store_id,
        active_device_id=active_device_id,
    )
