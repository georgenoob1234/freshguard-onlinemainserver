from __future__ import annotations

from datetime import datetime
from typing import Any, Literal, Optional

from pydantic import BaseModel, Field, field_validator, model_validator


class StrictModel(BaseModel):
    class Config:
        extra = "forbid"


class DeviceInfo(StrictModel):
    label: Optional[str] = None
    hostname: Optional[str] = None
    os: Optional[str] = None
    connector_version: Optional[str] = None


class RegisterRequest(StrictModel):
    enroll_token: str = Field(min_length=1)
    device_info: DeviceInfo


class RegisterResponse(StrictModel):
    device_id: str
    device_token: str
    ws_url: Optional[str] = None


class ErrorResponse(StrictModel):
    error_code: str
    detail: str


class AdminCreateEnrollTokenRequest(StrictModel):
    store_id: str = Field(min_length=1)
    expires_in_sec: int = Field(default=600, ge=1)
    max_uses: int = Field(default=1, ge=1)
    note: Optional[str] = None


class AdminCreateEnrollTokenResponse(StrictModel):
    enroll_token: str
    token_id: str
    expires_at: str
    max_uses: int


class AdminStore(StrictModel):
    store_id: str
    display_name: str
    address: Optional[str] = None
    is_active: bool
    created_at: str
    updated_at: str


class AdminStoreListResponse(StrictModel):
    items: list[AdminStore]


class AdminCreateStoreRequest(StrictModel):
    display_name: str
    address: Optional[str] = None
    is_active: bool = True

    @field_validator("display_name")
    @classmethod
    def validate_display_name(cls, value: str) -> str:
        trimmed = value.strip()
        if not trimmed:
            raise ValueError("display_name must not be empty")
        if len(trimmed) > 200:
            raise ValueError("display_name must be at most 200 characters")
        return trimmed

    @field_validator("address")
    @classmethod
    def validate_address(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return None
        trimmed = value.strip()
        if len(trimmed) > 500:
            raise ValueError("address must be at most 500 characters")
        return trimmed or None


class AdminUpdateStoreRequest(StrictModel):
    display_name: Optional[str] = None
    address: Optional[str] = None
    is_active: Optional[bool] = None

    @field_validator("display_name")
    @classmethod
    def validate_display_name(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return None
        trimmed = value.strip()
        if not trimmed:
            raise ValueError("display_name must not be empty")
        if len(trimmed) > 200:
            raise ValueError("display_name must be at most 200 characters")
        return trimmed

    @field_validator("address")
    @classmethod
    def validate_address(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return None
        trimmed = value.strip()
        if len(trimmed) > 500:
            raise ValueError("address must be at most 500 characters")
        return trimmed or None


class AdminLookupUserCandidate(StrictModel):
    user_id: str
    provider_user_id: str
    username: Optional[str] = None
    display_name: Optional[str] = None
    last_seen_at: str


class AdminLookupUserResponse(StrictModel):
    user_id: str
    provider: str
    provider_user_id: str
    provider_chat_id: str
    username: Optional[str] = None
    display_name: Optional[str] = None
    is_banned: bool
    created_at: str
    last_seen_at: str


class AdminUpdateUserBanRequest(StrictModel):
    is_banned: bool
    reason: Optional[str] = None

    @field_validator("reason")
    @classmethod
    def validate_reason(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return None
        trimmed = value.strip()
        return trimmed or None


class AdminUpdateUserBanResponse(StrictModel):
    user_id: str
    is_banned: bool
    last_seen_at: str


class BotSessionEnsureRequest(StrictModel):
    provider: str = Field(min_length=1)
    provider_user_id: str = Field(min_length=1)
    provider_chat_id: str = Field(min_length=1)
    username: Optional[str] = None
    display_name: Optional[str] = None

    @field_validator("provider", "provider_user_id", "provider_chat_id")
    @classmethod
    def validate_required_strings(cls, value: str) -> str:
        trimmed = value.strip()
        if not trimmed:
            raise ValueError("value must not be empty")
        return trimmed

    @field_validator("username", "display_name")
    @classmethod
    def validate_optional_strings(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return None
        trimmed = value.strip()
        return trimmed or None


class BotSessionEnsureResponse(StrictModel):
    user_id: str
    is_banned: bool
    is_linked: bool
    active_store_id: Optional[str] = None
    active_device_id: Optional[str] = None


class BotHealthResponse(StrictModel):
    ok: bool


class ScanResultPayload(BaseModel):
    session_id: Any
    image_id: str = Field(min_length=1)
    timestamp: Any
    weight_grams: Any
    fruits: Any

    class Config:
        extra = "allow"

    @model_validator(mode="before")
    @classmethod
    def reject_legacy_scan_id(cls, value: Any) -> Any:
        if isinstance(value, dict) and "scan_id" in value:
            raise ValueError("scan_id is not supported. Use image_id.")
        return value


class UpdateEnvelopeRequest(StrictModel):
    envelope_version: Literal["v1"]
    sent_at: Optional[datetime] = None
    image_id: str = Field(min_length=1)
    scan_result: ScanResultPayload


class UpdateResponse(StrictModel):
    status: Literal["ok"] = "ok"
    duplicate: bool


CommandRequestType = Literal["ping", "device.info", "connector.stats", "camera.capture"]


class AdminDeviceCommandRequest(StrictModel):
    request_type: CommandRequestType
    params: dict[str, Any] = Field(default_factory=dict)


class DeviceStatusResponse(StrictModel):
    device_id: str
    label: Optional[str] = None
    hostname: Optional[str] = None
    os: Optional[str] = None
    connector_version: Optional[str] = None
    connected: bool
    last_seen_at: Optional[str] = None
    online: bool


class AdminStoreDevicesResponse(StrictModel):
    store_id: str
    online_threshold_seconds: int
    devices: list[DeviceStatusResponse]


class BlobUploadResponse(StrictModel):
    blob_id: str
    size_bytes: int
    sha256: str
    content_type: str
