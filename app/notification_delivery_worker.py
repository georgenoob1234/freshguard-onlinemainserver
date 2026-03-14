from __future__ import annotations

import asyncio
from dataclasses import dataclass
import json
import logging
import sqlite3
from typing import Any
import uuid

import httpx

from app.db import open_connection, rollback_quietly
from app.notifications import (
    DEFAULT_FAILURE_REASON,
    DELIVERY_STATUS_FAILED,
    DELIVERY_STATUS_PENDING,
    DELIVERY_STATUS_SENDING,
    DELIVERY_STATUS_SENT,
    RESTART_STALE_FAILURE_REASON,
    is_temporary_failure,
    normalize_failure_reason,
    utcnow_iso,
)


logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class PendingDelivery:
    notification_delivery_id: str
    provider_user_id: str
    payload: dict[str, Any]


class NotificationDeliveryWorker:
    def __init__(
        self,
        *,
        database_path: str,
        push_base_url: str,
        push_endpoint_path: str,
        batch_size: int,
        timeout_seconds: float,
        poll_interval_seconds: float,
        enabled: bool,
    ) -> None:
        self._database_path = database_path
        self._push_base_url = push_base_url.rstrip("/")
        self._push_endpoint_path = (
            push_endpoint_path
            if push_endpoint_path.startswith("/")
            else f"/{push_endpoint_path}"
        )
        self._batch_size = batch_size
        self._timeout_seconds = timeout_seconds
        self._poll_interval_seconds = poll_interval_seconds
        self._enabled = enabled
        self._attempts_by_delivery: dict[str, int] = {}
        self._max_attempts = 3

    def _push_url(self) -> str:
        return f"{self._push_base_url}{self._push_endpoint_path}"

    def _increment_attempt(self, delivery_id: str) -> int:
        next_attempt = self._attempts_by_delivery.get(delivery_id, 0) + 1
        self._attempts_by_delivery[delivery_id] = next_attempt
        return next_attempt

    def _finalize_attempt_tracking(self, delivery_id: str) -> None:
        self._attempts_by_delivery.pop(delivery_id, None)

    def _should_retry(self, delivery_id: str, failure_reason: str) -> bool:
        if not is_temporary_failure(failure_reason):
            return False
        attempt_count = self._attempts_by_delivery.get(delivery_id, 0)
        return attempt_count < self._max_attempts

    def _claim_pending_batch(
        self,
        connection: sqlite3.Connection,
    ) -> list[PendingDelivery]:
        pending_rows = connection.execute(
            """
            SELECT
                notification_delivery_id,
                provider_user_id,
                payload_json
            FROM notification_deliveries
            WHERE status = ?
            ORDER BY created_at ASC, notification_delivery_id ASC
            LIMIT ?
            """,
            (DELIVERY_STATUS_PENDING, self._batch_size),
        ).fetchall()
        if not pending_rows:
            return []

        now = utcnow_iso()
        delivery_ids = [row["notification_delivery_id"] for row in pending_rows]
        placeholders = ", ".join("?" for _ in delivery_ids)
        connection.execute(
            f"""
            UPDATE notification_deliveries
            SET
                status = ?,
                last_attempt_at = ?,
                updated_at = ?
            WHERE notification_delivery_id IN ({placeholders})
              AND status = ?
            """,
            (
                DELIVERY_STATUS_SENDING,
                now,
                now,
                *delivery_ids,
                DELIVERY_STATUS_PENDING,
            ),
        )

        sending_rows = connection.execute(
            f"""
            SELECT
                notification_delivery_id,
                provider_user_id,
                payload_json
            FROM notification_deliveries
            WHERE notification_delivery_id IN ({placeholders})
              AND status = ?
            ORDER BY created_at ASC, notification_delivery_id ASC
            """,
            (*delivery_ids, DELIVERY_STATUS_SENDING),
        ).fetchall()

        claimed: list[PendingDelivery] = []
        for row in sending_rows:
            payload_json = row["payload_json"]
            try:
                payload = json.loads(payload_json)
            except json.JSONDecodeError:
                payload = {}
            if not isinstance(payload, dict):
                payload = {}
            claimed.append(
                PendingDelivery(
                    notification_delivery_id=row["notification_delivery_id"],
                    provider_user_id=row["provider_user_id"],
                    payload=payload,
                )
            )
        return claimed

    async def _push_batch(
        self,
        *,
        batch_id: str,
        deliveries: list[PendingDelivery],
    ) -> dict[str, Any]:
        request_payload = {
            "batch_id": batch_id,
            "deliveries": [
                {
                    "notification_delivery_id": delivery.notification_delivery_id,
                    "provider_user_id": delivery.provider_user_id,
                    "payload": delivery.payload,
                }
                for delivery in deliveries
            ],
        }
        timeout = httpx.Timeout(self._timeout_seconds)
        async with httpx.AsyncClient(timeout=timeout) as client:
            response = await client.post(self._push_url(), json=request_payload)
            response.raise_for_status()
            payload = response.json()
            if not isinstance(payload, dict):
                raise ValueError("invalid tgbot push response")
            return payload

    def _mark_delivery_sent(
        self,
        connection: sqlite3.Connection,
        *,
        delivery_id: str,
    ) -> None:
        now = utcnow_iso()
        connection.execute(
            """
            UPDATE notification_deliveries
            SET
                status = ?,
                failure_reason = NULL,
                sent_at = ?,
                updated_at = ?
            WHERE notification_delivery_id = ?
            """,
            (
                DELIVERY_STATUS_SENT,
                now,
                now,
                delivery_id,
            ),
        )
        self._finalize_attempt_tracking(delivery_id)

    def _mark_delivery_retry_or_failed(
        self,
        connection: sqlite3.Connection,
        *,
        delivery_id: str,
        failure_reason: str,
    ) -> None:
        normalized_reason = normalize_failure_reason(failure_reason)
        now = utcnow_iso()
        if self._should_retry(delivery_id, normalized_reason):
            connection.execute(
                """
                UPDATE notification_deliveries
                SET
                    status = ?,
                    failure_reason = ?,
                    updated_at = ?
                WHERE notification_delivery_id = ?
                """,
                (
                    DELIVERY_STATUS_PENDING,
                    normalized_reason,
                    now,
                    delivery_id,
                ),
            )
            return

        connection.execute(
            """
            UPDATE notification_deliveries
            SET
                status = ?,
                failure_reason = ?,
                updated_at = ?
            WHERE notification_delivery_id = ?
            """,
            (
                DELIVERY_STATUS_FAILED,
                normalized_reason,
                now,
                delivery_id,
            ),
        )
        self._finalize_attempt_tracking(delivery_id)

    def _handle_transport_failure(
        self,
        connection: sqlite3.Connection,
        *,
        deliveries: list[PendingDelivery],
        failure_reason: str,
    ) -> None:
        for delivery in deliveries:
            self._increment_attempt(delivery.notification_delivery_id)
            self._mark_delivery_retry_or_failed(
                connection,
                delivery_id=delivery.notification_delivery_id,
                failure_reason=failure_reason,
            )

    def _process_push_results(
        self,
        connection: sqlite3.Connection,
        *,
        deliveries: list[PendingDelivery],
        response_payload: dict[str, Any],
    ) -> None:
        response_results = response_payload.get("results")
        results_by_id: dict[str, dict[str, Any]] = {}
        if isinstance(response_results, list):
            for result in response_results:
                if not isinstance(result, dict):
                    continue
                delivery_id = result.get("notification_delivery_id")
                if not isinstance(delivery_id, str) or not delivery_id:
                    continue
                results_by_id[delivery_id] = result

        for delivery in deliveries:
            delivery_id = delivery.notification_delivery_id
            self._increment_attempt(delivery_id)
            result_payload = results_by_id.get(delivery_id)
            if result_payload is None:
                self._mark_delivery_retry_or_failed(
                    connection,
                    delivery_id=delivery_id,
                    failure_reason=DEFAULT_FAILURE_REASON,
                )
                continue

            normalized_status = str(result_payload.get("status", "")).strip().lower()
            if normalized_status == DELIVERY_STATUS_SENT:
                self._mark_delivery_sent(connection, delivery_id=delivery_id)
                continue

            failure_reason = normalize_failure_reason(
                result_payload.get("failure_reason")
                if isinstance(result_payload.get("failure_reason"), str)
                else None
            )
            self._mark_delivery_retry_or_failed(
                connection,
                delivery_id=delivery_id,
                failure_reason=failure_reason,
            )

    async def run_once(self) -> int:
        if not self._enabled:
            return 0
        if not self._push_base_url:
            return 0

        connection = open_connection(self._database_path)
        try:
            connection.execute("BEGIN IMMEDIATE")
            deliveries = self._claim_pending_batch(connection)
            connection.commit()
        except Exception:
            rollback_quietly(connection)
            logger.exception("Failed claiming notification batch")
            connection.close()
            return 0

        if not deliveries:
            connection.close()
            return 0

        batch_id = str(uuid.uuid4())
        logger.info(
            "notification_push_attempt_started batch_id=%s delivery_count=%s",
            batch_id,
            len(deliveries),
        )

        try:
            response_payload = await self._push_batch(
                batch_id=batch_id,
                deliveries=deliveries,
            )
        except httpx.TimeoutException:
            connection.execute("BEGIN IMMEDIATE")
            self._handle_transport_failure(
                connection,
                deliveries=deliveries,
                failure_reason="transport_timeout",
            )
            connection.commit()
            connection.close()
            return len(deliveries)
        except Exception:
            connection.execute("BEGIN IMMEDIATE")
            self._handle_transport_failure(
                connection,
                deliveries=deliveries,
                failure_reason="transport_error",
            )
            connection.commit()
            connection.close()
            return len(deliveries)

        try:
            connection.execute("BEGIN IMMEDIATE")
            self._process_push_results(
                connection,
                deliveries=deliveries,
                response_payload=response_payload,
            )
            connection.commit()
            logger.info(
                "notification_push_response_processed batch_id=%s delivery_count=%s",
                batch_id,
                len(deliveries),
            )
            return len(deliveries)
        except Exception:
            rollback_quietly(connection)
            logger.exception("Failed reconciling notification batch batch_id=%s", batch_id)
            return 0
        finally:
            connection.close()

    async def run_forever(self) -> None:
        while True:
            try:
                await self.run_once()
                await asyncio.sleep(self._poll_interval_seconds)
            except asyncio.CancelledError:
                raise
            except Exception:
                logger.exception("Notification delivery worker loop failed")
                await asyncio.sleep(self._poll_interval_seconds)


def cleanup_stale_notification_deliveries_once(database_path: str) -> int:
    connection = open_connection(database_path)
    now = utcnow_iso()
    try:
        connection.execute("BEGIN IMMEDIATE")
        connection.execute(
            """
            UPDATE notification_deliveries
            SET
                status = ?,
                failure_reason = ?,
                updated_at = ?
            WHERE status IN (?, ?)
            """,
            (
                DELIVERY_STATUS_FAILED,
                RESTART_STALE_FAILURE_REASON,
                now,
                DELIVERY_STATUS_PENDING,
                DELIVERY_STATUS_SENDING,
            ),
        )
        changed_rows = int(
            connection.execute("SELECT changes() AS row_count").fetchone()["row_count"]
        )
        connection.commit()
        return changed_rows
    except Exception:
        rollback_quietly(connection)
        logger.exception("Failed stale notification delivery cleanup")
        return 0
    finally:
        connection.close()
