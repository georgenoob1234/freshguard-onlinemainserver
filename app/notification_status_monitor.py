from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
import logging

from app.db import open_connection, rollback_quietly
from app.notifications import (
    EVENT_DEVICE_OFFLINE,
    EVENT_DEVICE_ONLINE,
    build_status_payload,
    create_event_with_deliveries,
    is_device_online_for_notifications,
    load_device_notification_context,
    upsert_device_notification_state,
    utcnow_iso,
    get_device_notification_state,
)


logger = logging.getLogger(__name__)


class NotificationStatusMonitor:
    def __init__(
        self,
        *,
        database_path: str,
        online_threshold_seconds: int,
        startup_grace_seconds: int,
        poll_interval_seconds: float,
        enabled: bool,
    ) -> None:
        self._database_path = database_path
        self._online_threshold_seconds = online_threshold_seconds
        self._startup_grace_seconds = startup_grace_seconds
        self._poll_interval_seconds = poll_interval_seconds
        self._enabled = enabled
        self._started_at_utc = datetime.now(timezone.utc)

    def _is_within_startup_grace(self, now_utc: datetime) -> bool:
        grace_deadline = self._started_at_utc + timedelta(
            seconds=self._startup_grace_seconds,
        )
        return now_utc < grace_deadline

    def run_once(self, *, now_utc: datetime | None = None) -> int:
        if not self._enabled:
            return 0

        effective_now_utc = now_utc or datetime.now(timezone.utc)
        within_grace = self._is_within_startup_grace(effective_now_utc)
        occurred_at = effective_now_utc.isoformat().replace("+00:00", "Z")
        created_events = 0

        connection = open_connection(self._database_path)
        try:
            device_rows = connection.execute(
                """
                SELECT device_id, last_seen_at
                FROM devices
                ORDER BY created_at ASC, device_id ASC
                """
            ).fetchall()

            for row in device_rows:
                device_id = row["device_id"]
                current_online = is_device_online_for_notifications(
                    last_seen_at_raw=row["last_seen_at"],
                    now_utc=effective_now_utc,
                    online_threshold_seconds=self._online_threshold_seconds,
                )
                prior_online = get_device_notification_state(
                    connection,
                    device_id=device_id,
                )
                if prior_online is None:
                    # Initialize baseline without emitting.
                    upsert_device_notification_state(
                        connection,
                        device_id=device_id,
                        last_known_online=current_online,
                        updated_at=utcnow_iso(),
                    )
                    continue

                if prior_online == current_online:
                    continue

                if within_grace:
                    # During grace, suppress transition notifications.
                    # Keep prior online=True when current is offline so we can emit
                    # a single restart-aware offline event after grace if it never recovers.
                    if prior_online and not current_online:
                        continue

                    upsert_device_notification_state(
                        connection,
                        device_id=device_id,
                        last_known_online=current_online,
                        updated_at=utcnow_iso(),
                    )
                    continue

                context = load_device_notification_context(connection, device_id=device_id)
                if context is None:
                    upsert_device_notification_state(
                        connection,
                        device_id=device_id,
                        last_known_online=current_online,
                        updated_at=utcnow_iso(),
                    )
                    continue

                event_type = EVENT_DEVICE_ONLINE if current_online else EVENT_DEVICE_OFFLINE
                payload = build_status_payload(
                    event_type=event_type,
                    context=context,
                    occurred_at=occurred_at,
                )
                create_event_with_deliveries(
                    connection,
                    event_type=event_type,
                    store_id=context.store_id,
                    device_id=device_id,
                    occurred_at=occurred_at,
                    payload=payload,
                )
                created_events += 1

                upsert_device_notification_state(
                    connection,
                    device_id=device_id,
                    last_known_online=current_online,
                    updated_at=utcnow_iso(),
                )

            connection.commit()
            return created_events
        except Exception:
            rollback_quietly(connection)
            logger.exception("Notification status monitor iteration failed")
            return 0
        finally:
            connection.close()

    async def run_forever(self) -> None:
        while True:
            try:
                created = await asyncio.to_thread(self.run_once)
                if created > 0:
                    logger.info("Notification status monitor created_events=%s", created)
                await asyncio.sleep(self._poll_interval_seconds)
            except asyncio.CancelledError:
                raise
            except Exception:
                logger.exception("Notification status monitor loop failed")
                await asyncio.sleep(self._poll_interval_seconds)
