from __future__ import annotations

from datetime import datetime, timedelta, timezone


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def parse_db_utc_datetime(value: str | None) -> datetime | None:
    if value is None:
        return None
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    return _as_utc(parsed)


def serialize_utc_datetime(value: datetime | None) -> str | None:
    if value is None:
        return None
    normalized = _as_utc(value)
    return normalized.isoformat().replace("+00:00", "Z")


def compute_online(
    last_seen_at: datetime | None,
    now_utc: datetime,
    threshold_seconds: int,
) -> bool:
    if last_seen_at is None:
        return False

    normalized_last_seen = _as_utc(last_seen_at)
    normalized_now = _as_utc(now_utc)
    return (normalized_now - normalized_last_seen) <= timedelta(
        seconds=threshold_seconds,
    )
