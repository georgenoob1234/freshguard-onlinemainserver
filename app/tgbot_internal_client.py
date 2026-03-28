from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import httpx
from fastapi import HTTPException

from app.config import Settings


@dataclass(frozen=True)
class VerifiedTelegramIdentity:
    provider_user_id: str
    username: str | None
    display_name: str | None


def verify_webapp_init_data_via_tgbot(
    *,
    init_data: str,
    settings: Settings,
) -> VerifiedTelegramIdentity:
    base_url = settings.tgbot_internal_base_url.strip().rstrip("/")
    if not base_url:
        raise HTTPException(status_code=503, detail="telegram_internal_verifier_not_configured")

    endpoint_path = settings.tgbot_webapp_verify_endpoint_path.strip() or "/internal/admin-ui/verify-webapp-init"
    if not endpoint_path.startswith("/"):
        endpoint_path = f"/{endpoint_path}"
    url = f"{base_url}{endpoint_path}"

    headers: dict[str, str] = {}
    internal_auth_token = settings.tgbot_internal_auth_token.strip()
    if internal_auth_token:
        headers["Authorization"] = f"Bearer {internal_auth_token}"

    timeout = httpx.Timeout(settings.tgbot_webapp_verify_timeout_seconds)
    try:
        response = httpx.post(
            url,
            json={"init_data": init_data},
            headers=headers,
            timeout=timeout,
        )
    except httpx.HTTPError as error:
        raise HTTPException(status_code=503, detail="telegram_internal_verifier_unavailable") from error

    if response.status_code in {401, 403}:
        raise HTTPException(status_code=503, detail="telegram_internal_verifier_unauthorized")
    if response.status_code >= 500:
        raise HTTPException(status_code=503, detail="telegram_internal_verifier_unavailable")
    if response.status_code >= 400:
        raise HTTPException(status_code=400, detail="invalid_telegram_init_data")

    payload = _parse_json_object(response)
    if payload.get("ok") is True:
        provider = str(payload.get("provider", "")).strip().lower()
        provider_user_id = str(payload.get("provider_user_id", "")).strip()
        if provider != "telegram" or not provider_user_id:
            raise HTTPException(status_code=503, detail="telegram_internal_verifier_bad_response")
        username = _as_optional_string(payload.get("username"))
        display_name = _as_optional_string(payload.get("display_name"))
        return VerifiedTelegramIdentity(
            provider_user_id=provider_user_id,
            username=username,
            display_name=display_name,
        )

    reason = _as_optional_string(payload.get("reason")) or "invalid_telegram_init_data"
    if reason in {"invalid_telegram_init_data", "stale_telegram_init_data"}:
        raise HTTPException(status_code=401, detail=reason)
    raise HTTPException(status_code=401, detail="invalid_telegram_init_data")


def _parse_json_object(response: httpx.Response) -> dict[str, Any]:
    try:
        payload = response.json()
    except ValueError as error:
        raise HTTPException(status_code=503, detail="telegram_internal_verifier_bad_response") from error
    if not isinstance(payload, dict):
        raise HTTPException(status_code=503, detail="telegram_internal_verifier_bad_response")
    return payload


def _as_optional_string(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    normalized = value.strip()
    if not normalized:
        return None
    return normalized
