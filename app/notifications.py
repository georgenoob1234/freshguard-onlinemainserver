from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import json
import logging
import sqlite3
from typing import Any
import uuid

from app.device_status import compute_online, parse_db_utc_datetime
from app.roles import is_permission_granted


logger = logging.getLogger(__name__)

EVENT_DEVICE_OFFLINE = "device_offline"
EVENT_DEVICE_ONLINE = "device_online"
EVENT_DEFECT_DETECTED = "defect_detected"

VALID_NOTIFICATION_EVENT_TYPES = frozenset(
    {
        EVENT_DEVICE_OFFLINE,
        EVENT_DEVICE_ONLINE,
        EVENT_DEFECT_DETECTED,
    }
)

DELIVERY_STATUS_PENDING = "pending"
DELIVERY_STATUS_SENDING = "sending"
DELIVERY_STATUS_SENT = "sent"
DELIVERY_STATUS_FAILED = "failed"

DELIVERY_TEMPORARY_FAILURES = frozenset(
    {
        "transport_timeout",
        "transport_error",
    }
)

DELIVERY_PERMANENT_FAILURES = frozenset(
    {
        "telegram_forbidden",
        "telegram_chat_not_found",
        "telegram_bad_request",
    }
)

DEFAULT_FAILURE_REASON = "internal_error"
RESTART_STALE_FAILURE_REASON = "oms_restart_stale_delivery"
KNOWN_FAILURE_REASONS = frozenset(
    {
        "telegram_forbidden",
        "telegram_chat_not_found",
        "telegram_bad_request",
        "transport_timeout",
        "transport_error",
        "internal_error",
        RESTART_STALE_FAILURE_REASON,
    }
)


def utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def normalize_event_type(event_type: str) -> str:
    normalized = event_type.strip().lower()
    if normalized not in VALID_NOTIFICATION_EVENT_TYPES:
        raise ValueError(f"unsupported notification event_type: {event_type}")
    return normalized


def get_event_permission(event_type: str) -> str:
    normalized = normalize_event_type(event_type)
    if normalized in {EVENT_DEVICE_OFFLINE, EVENT_DEVICE_ONLINE}:
        return "notifications.device_status"
    if normalized == EVENT_DEFECT_DETECTED:
        return "notifications.defect_detected"
    raise ValueError(f"unsupported notification event_type: {event_type}")


def get_event_toggle_column(event_type: str) -> str:
    normalized = normalize_event_type(event_type)
    if normalized in {EVENT_DEVICE_OFFLINE, EVENT_DEVICE_ONLINE}:
        return "device_status_enabled"
    if normalized == EVENT_DEFECT_DETECTED:
        return "defect_detected_enabled"
    raise ValueError(f"unsupported notification event_type: {event_type}")


def _int_to_bool(value: Any) -> bool:
    return int(value) == 1


def _bool_to_int(value: bool) -> int:
    return 1 if value else 0


@dataclass(frozen=True)
class NotificationPreferenceState:
    notifications_enabled: bool
    device_status_enabled: bool
    defect_detected_enabled: bool

    def is_enabled_for_event(self, event_type: str) -> bool:
        if not self.notifications_enabled:
            return False
        toggle_column = get_event_toggle_column(event_type)
        if toggle_column == "device_status_enabled":
            return self.device_status_enabled
        return self.defect_detected_enabled


@dataclass(frozen=True)
class NotificationPreferenceView:
    user_id: str
    store_id: str
    preferences: NotificationPreferenceState
    can_access_notifications: bool
    can_access_device_status: bool
    can_access_defect_detected: bool


@dataclass(frozen=True)
class NotificationRecipient:
    user_id: str
    provider_user_id: str


@dataclass(frozen=True)
class NotificationEvent:
    notification_event_id: str
    event_type: str
    store_id: str
    device_id: str
    occurred_at: str
    result_id: str | None
    fruit_name: str | None
    defect_type: str | None
    created_at: str


@dataclass(frozen=True)
class NotificationDeviceContext:
    store_id: str
    store_name: str
    device_id: str
    device_display_name: str


def default_notification_preferences() -> NotificationPreferenceState:
    return NotificationPreferenceState(
        notifications_enabled=True,
        device_status_enabled=True,
        defect_detected_enabled=True,
    )


def _parse_preferences_row(row: sqlite3.Row | None) -> NotificationPreferenceState:
    if row is None:
        return default_notification_preferences()
    return NotificationPreferenceState(
        notifications_enabled=_int_to_bool(row["notifications_enabled"]),
        device_status_enabled=_int_to_bool(row["device_status_enabled"]),
        defect_detected_enabled=_int_to_bool(row["defect_detected_enabled"]),
    )


def load_notification_preferences(
    connection: sqlite3.Connection,
    *,
    user_id: str,
    store_id: str,
) -> NotificationPreferenceState:
    row = connection.execute(
        """
        SELECT
            notifications_enabled,
            device_status_enabled,
            defect_detected_enabled
        FROM notification_preferences
        WHERE user_id = ? AND store_id = ?
        """,
        (user_id, store_id),
    ).fetchone()
    return _parse_preferences_row(row)


def upsert_notification_preferences(
    connection: sqlite3.Connection,
    *,
    user_id: str,
    store_id: str,
    notifications_enabled: bool | None = None,
    device_status_enabled: bool | None = None,
    defect_detected_enabled: bool | None = None,
) -> NotificationPreferenceState:
    existing = load_notification_preferences(connection, user_id=user_id, store_id=store_id)
    merged = NotificationPreferenceState(
        notifications_enabled=(
            existing.notifications_enabled
            if notifications_enabled is None
            else notifications_enabled
        ),
        device_status_enabled=(
            existing.device_status_enabled
            if device_status_enabled is None
            else device_status_enabled
        ),
        defect_detected_enabled=(
            existing.defect_detected_enabled
            if defect_detected_enabled is None
            else defect_detected_enabled
        ),
    )
    now = utcnow_iso()
    connection.execute(
        """
        INSERT INTO notification_preferences (
            user_id,
            store_id,
            notifications_enabled,
            device_status_enabled,
            defect_detected_enabled,
            created_at,
            updated_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(user_id, store_id) DO UPDATE SET
            notifications_enabled = excluded.notifications_enabled,
            device_status_enabled = excluded.device_status_enabled,
            defect_detected_enabled = excluded.defect_detected_enabled,
            updated_at = excluded.updated_at
        """,
        (
            user_id,
            store_id,
            _bool_to_int(merged.notifications_enabled),
            _bool_to_int(merged.device_status_enabled),
            _bool_to_int(merged.defect_detected_enabled),
            now,
            now,
        ),
    )
    return merged


def build_notification_preference_view(
    *,
    user_id: str,
    store_id: str,
    role: str,
    preferences: NotificationPreferenceState,
) -> NotificationPreferenceView:
    return NotificationPreferenceView(
        user_id=user_id,
        store_id=store_id,
        preferences=preferences,
        can_access_notifications=is_permission_granted(role, "notifications.access"),
        can_access_device_status=is_permission_granted(role, "notifications.device_status"),
        can_access_defect_detected=is_permission_granted(role, "notifications.defect_detected"),
    )


def _normalize_provider_user_id(provider_user_id: Any) -> str | None:
    if not isinstance(provider_user_id, str):
        return None
    normalized = provider_user_id.strip()
    if not normalized:
        return None
    return normalized


def resolve_eligible_recipients(
    connection: sqlite3.Connection,
    *,
    store_id: str,
    event_type: str,
) -> list[NotificationRecipient]:
    normalized_event_type = normalize_event_type(event_type)
    required_permission = get_event_permission(normalized_event_type)
    toggle_column = get_event_toggle_column(normalized_event_type)

    preference_rows = connection.execute(
        """
        SELECT
            user_id,
            notifications_enabled,
            device_status_enabled,
            defect_detected_enabled
        FROM notification_preferences
        WHERE store_id = ?
        """,
        (store_id,),
    ).fetchall()
    preferences_by_user = {
        row["user_id"]: _parse_preferences_row(row) for row in preference_rows
    }

    membership_rows = connection.execute(
        """
        SELECT
            store_memberships.user_id,
            store_memberships.role,
            users.is_banned,
            user_identities.provider_user_id
        FROM store_memberships
        JOIN users ON users.user_id = store_memberships.user_id
        LEFT JOIN user_identities
            ON user_identities.user_id = store_memberships.user_id
           AND user_identities.provider = 'telegram'
        WHERE store_memberships.store_id = ?
          AND store_memberships.revoked_at IS NULL
        ORDER BY store_memberships.created_at ASC, store_memberships.membership_id ASC
        """,
        (store_id,),
    ).fetchall()

    recipients: list[NotificationRecipient] = []
    seen_provider_user_ids: set[str] = set()
    for row in membership_rows:
        provider_user_id = _normalize_provider_user_id(row["provider_user_id"])
        if provider_user_id is None:
            continue
        if provider_user_id in seen_provider_user_ids:
            continue
        if int(row["is_banned"]) == 1:
            continue
        role = row["role"]
        if not is_permission_granted(role, "notifications.access"):
            continue
        if not is_permission_granted(role, required_permission):
            continue

        user_id = row["user_id"]
        preferences = preferences_by_user.get(user_id, default_notification_preferences())
        if not preferences.notifications_enabled:
            continue
        if toggle_column == "device_status_enabled" and not preferences.device_status_enabled:
            continue
        if toggle_column == "defect_detected_enabled" and not preferences.defect_detected_enabled:
            continue
        recipients.append(
            NotificationRecipient(
                user_id=user_id,
                provider_user_id=provider_user_id,
            )
        )
        seen_provider_user_ids.add(provider_user_id)

    return recipients


def load_device_notification_context(
    connection: sqlite3.Connection,
    *,
    device_id: str,
) -> NotificationDeviceContext | None:
    row = connection.execute(
        """
        SELECT
            devices.device_id,
            devices.store_id,
            COALESCE(NULLIF(TRIM(stores.display_name), ''), NULLIF(TRIM(stores.name), ''), stores.store_id) AS store_name,
            COALESCE(NULLIF(TRIM(devices.label), ''), NULLIF(TRIM(devices.hostname), ''), devices.device_id) AS device_display_name
        FROM devices
        JOIN stores ON stores.store_id = devices.store_id
        WHERE devices.device_id = ?
        """,
        (device_id,),
    ).fetchone()
    if row is None:
        return None
    return NotificationDeviceContext(
        store_id=row["store_id"],
        store_name=row["store_name"],
        device_id=row["device_id"],
        device_display_name=row["device_display_name"],
    )


def build_status_payload(
    *,
    event_type: str,
    context: NotificationDeviceContext,
    occurred_at: str,
) -> dict[str, Any]:
    normalized_event_type = normalize_event_type(event_type)
    return {
        "event_type": normalized_event_type,
        "store_name": context.store_name,
        "device_display_name": context.device_display_name,
        "occurred_at": occurred_at,
    }


def build_defect_payload(
    *,
    context: NotificationDeviceContext,
    occurred_at: str,
    fruit_name: str,
    defect_type: str | None,
    result_id: str,
    can_show_image: bool,
) -> dict[str, Any]:
    return {
        "event_type": EVENT_DEFECT_DETECTED,
        "store_name": context.store_name,
        "device_display_name": context.device_display_name,
        "occurred_at": occurred_at,
        "fruit_name": fruit_name,
        "defect_type": defect_type,
        "result_id": result_id,
        "can_show_image": can_show_image,
    }


def create_notification_event(
    connection: sqlite3.Connection,
    *,
    event_type: str,
    store_id: str,
    device_id: str,
    occurred_at: str,
    result_id: str | None = None,
    fruit_name: str | None = None,
    defect_type: str | None = None,
) -> NotificationEvent:
    normalized_event_type = normalize_event_type(event_type)
    created_at = utcnow_iso()
    notification_event_id = str(uuid.uuid4())
    connection.execute(
        """
        INSERT INTO notification_events (
            notification_event_id,
            event_type,
            store_id,
            device_id,
            occurred_at,
            result_id,
            fruit_name,
            defect_type,
            created_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            notification_event_id,
            normalized_event_type,
            store_id,
            device_id,
            occurred_at,
            result_id,
            fruit_name,
            defect_type,
            created_at,
        ),
    )
    return NotificationEvent(
        notification_event_id=notification_event_id,
        event_type=normalized_event_type,
        store_id=store_id,
        device_id=device_id,
        occurred_at=occurred_at,
        result_id=result_id,
        fruit_name=fruit_name,
        defect_type=defect_type,
        created_at=created_at,
    )


def create_deliveries_for_event(
    connection: sqlite3.Connection,
    *,
    notification_event_id: str,
    recipients: list[NotificationRecipient],
    payload: dict[str, Any],
) -> int:
    payload_json = json.dumps(payload, separators=(",", ":"), sort_keys=True)
    created_count = 0
    for recipient in recipients:
        delivery_id = str(uuid.uuid4())
        now = utcnow_iso()
        cursor = connection.execute(
            """
            INSERT OR IGNORE INTO notification_deliveries (
                notification_delivery_id,
                notification_event_id,
                provider_user_id,
                payload_json,
                status,
                failure_reason,
                last_attempt_at,
                sent_at,
                created_at,
                updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                delivery_id,
                notification_event_id,
                recipient.provider_user_id,
                payload_json,
                DELIVERY_STATUS_PENDING,
                None,
                None,
                None,
                now,
                now,
            ),
        )
        if cursor.rowcount == 1:
            created_count += 1
    return created_count


def create_event_with_deliveries(
    connection: sqlite3.Connection,
    *,
    event_type: str,
    store_id: str,
    device_id: str,
    occurred_at: str,
    payload: dict[str, Any],
    result_id: str | None = None,
    fruit_name: str | None = None,
    defect_type: str | None = None,
) -> tuple[NotificationEvent, int]:
    event = create_notification_event(
        connection,
        event_type=event_type,
        store_id=store_id,
        device_id=device_id,
        occurred_at=occurred_at,
        result_id=result_id,
        fruit_name=fruit_name,
        defect_type=defect_type,
    )
    recipients = resolve_eligible_recipients(
        connection,
        store_id=store_id,
        event_type=event.event_type,
    )
    created_count = create_deliveries_for_event(
        connection,
        notification_event_id=event.notification_event_id,
        recipients=recipients,
        payload=payload,
    )
    logger.info(
        "notification_event_created event_id=%s event_type=%s recipients=%s",
        event.notification_event_id,
        event.event_type,
        created_count,
    )
    return event, created_count


def _parse_iso_utc(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def normalize_fruit_identity(fruit_payload: dict[str, Any]) -> str:
    candidate_fields = (
        "fruit_id",
        "fruit_identity",
        "class_id",
        "name",
        "class_name",
        "label",
        "type",
    )
    for field_name in candidate_fields:
        value = fruit_payload.get(field_name)
        if isinstance(value, str):
            normalized = value.strip()
            if normalized:
                return normalized
        if isinstance(value, (int, float)):
            return str(value)
    return "unknown"


def extract_defect_candidates(scan_result_payload: dict[str, Any]) -> list[tuple[str, str | None]]:
    fruits = scan_result_payload.get("fruits")
    if not isinstance(fruits, list):
        return []

    candidates: list[tuple[str, str | None]] = []
    for fruit in fruits:
        if not isinstance(fruit, dict):
            continue
        defects = fruit.get("defects")
        if not isinstance(defects, list) or not defects:
            continue
        fruit_name = normalize_fruit_identity(fruit)
        defect_type: str | None = None
        for defect in defects:
            if not isinstance(defect, dict):
                continue
            candidate = defect.get("type")
            if isinstance(candidate, str) and candidate.strip():
                defect_type = candidate.strip()
                break
        candidates.append((fruit_name, defect_type))

    return candidates


def should_suppress_defect_duplicate(
    connection: sqlite3.Connection,
    *,
    device_id: str,
    fruit_name: str,
    occurred_at: str,
    dedup_seconds: int,
) -> bool:
    occurred_at_utc = _parse_iso_utc(occurred_at)
    dedup_cutoff = (occurred_at_utc - timedelta(seconds=dedup_seconds)).isoformat().replace(
        "+00:00",
        "Z",
    )
    row = connection.execute(
        """
        SELECT notification_event_id
        FROM notification_events
        WHERE event_type = ?
          AND device_id = ?
          AND fruit_name = ?
          AND occurred_at >= ?
        ORDER BY occurred_at DESC
        LIMIT 1
        """,
        (
            EVENT_DEFECT_DETECTED,
            device_id,
            fruit_name,
            dedup_cutoff,
        ),
    ).fetchone()
    return row is not None


def get_device_notification_state(
    connection: sqlite3.Connection,
    *,
    device_id: str,
) -> bool | None:
    row = connection.execute(
        """
        SELECT last_known_online
        FROM device_notification_state
        WHERE device_id = ?
        """,
        (device_id,),
    ).fetchone()
    if row is None:
        return None
    return int(row["last_known_online"]) == 1


def upsert_device_notification_state(
    connection: sqlite3.Connection,
    *,
    device_id: str,
    last_known_online: bool,
    updated_at: str | None = None,
) -> None:
    connection.execute(
        """
        INSERT INTO device_notification_state (
            device_id,
            last_known_online,
            updated_at
        )
        VALUES (?, ?, ?)
        ON CONFLICT(device_id) DO UPDATE SET
            last_known_online = excluded.last_known_online,
            updated_at = excluded.updated_at
        """,
        (
            device_id,
            _bool_to_int(last_known_online),
            updated_at or utcnow_iso(),
        ),
    )


def normalize_failure_reason(raw_failure_reason: str | None) -> str:
    normalized = (raw_failure_reason or "").strip().lower()
    if normalized in KNOWN_FAILURE_REASONS:
        return normalized
    return DEFAULT_FAILURE_REASON


def is_temporary_failure(failure_reason: str) -> bool:
    return normalize_failure_reason(failure_reason) in DELIVERY_TEMPORARY_FAILURES


def is_device_online_for_notifications(
    *,
    last_seen_at_raw: str | None,
    now_utc: datetime,
    online_threshold_seconds: int,
) -> bool:
    last_seen_at = parse_db_utc_datetime(last_seen_at_raw)
    return compute_online(
        last_seen_at=last_seen_at,
        now_utc=now_utc,
        threshold_seconds=online_threshold_seconds,
    )


def create_defect_notifications_from_scan_result(
    connection: sqlite3.Connection,
    *,
    device_id: str,
    result_id: str,
    occurred_at: str,
    scan_result_payload: dict[str, Any],
    dedup_seconds: int,
) -> int:
    context = load_device_notification_context(connection, device_id=device_id)
    if context is None:
        return 0

    defect_candidates = extract_defect_candidates(scan_result_payload)
    if not defect_candidates:
        return 0

    created_events = 0
    for fruit_name, defect_type in defect_candidates:
        if should_suppress_defect_duplicate(
            connection,
            device_id=device_id,
            fruit_name=fruit_name,
            occurred_at=occurred_at,
            dedup_seconds=dedup_seconds,
        ):
            continue

        payload = build_defect_payload(
            context=context,
            occurred_at=occurred_at,
            fruit_name=fruit_name,
            defect_type=defect_type,
            result_id=result_id,
            can_show_image=True,
        )
        create_event_with_deliveries(
            connection,
            event_type=EVENT_DEFECT_DETECTED,
            store_id=context.store_id,
            device_id=device_id,
            occurred_at=occurred_at,
            payload=payload,
            result_id=result_id,
            fruit_name=fruit_name,
            defect_type=defect_type,
        )
        created_events += 1
    return created_events
