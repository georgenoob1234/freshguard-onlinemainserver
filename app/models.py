from __future__ import annotations

from datetime import datetime
from typing import Any, Literal, Optional

from pydantic import BaseModel, Field, model_validator


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
    store_id: Optional[str] = None
    expires_in_sec: int = Field(default=600, ge=1)
    max_uses: int = Field(default=1, ge=1)
    note: Optional[str] = None


class AdminCreateEnrollTokenResponse(StrictModel):
    enroll_token: str
    token_id: str
    expires_at: str
    max_uses: int


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


class BlobUploadResponse(StrictModel):
    blob_id: str
    size_bytes: int
    sha256: str
    content_type: str
