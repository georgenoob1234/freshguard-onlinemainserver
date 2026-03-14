from __future__ import annotations

from dataclasses import dataclass
import os


@dataclass(frozen=True)
class Settings:
    admin_key: str
    secret_salt: str
    tgbot_service_token: str
    database_path: str
    roles_config_path: str
    blob_storage_dir: str
    max_blob_size_bytes: int
    online_threshold_seconds: int
    ws_heartbeat_timeout_seconds: float
    command_default_timeout_seconds: float
    blob_retention_seconds: float
    blob_cleanup_interval_seconds: float
    notifications_enabled: bool
    notification_startup_grace_seconds: int
    defect_notification_dedup_seconds: int
    notification_push_batch_size: int
    annotated_image_cache_ttl_seconds: int
    notification_push_base_url: str
    notification_push_endpoint_path: str
    notification_push_timeout_seconds: float
    notification_push_poll_interval_seconds: float
    notification_status_poll_interval_seconds: float


def _read_positive_float_env(var_name: str, default: float) -> float:
    raw_value = os.getenv(var_name, "")
    if not raw_value:
        return default

    try:
        parsed_value = float(raw_value)
    except ValueError as error:
        raise RuntimeError(f"{var_name} must be a number") from error

    if parsed_value <= 0:
        raise RuntimeError(f"{var_name} must be greater than 0")

    return parsed_value


def _read_positive_int_env(var_name: str, default: int) -> int:
    raw_value = os.getenv(var_name, "")
    if not raw_value:
        return default

    try:
        parsed_value = int(raw_value)
    except ValueError as error:
        raise RuntimeError(f"{var_name} must be an integer") from error

    if parsed_value <= 0:
        raise RuntimeError(f"{var_name} must be greater than 0")

    return parsed_value


def _read_bool_env(var_name: str, default: bool) -> bool:
    raw_value = os.getenv(var_name, "")
    if not raw_value:
        return default

    normalized = raw_value.strip().lower()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off"}:
        return False
    raise RuntimeError(f"{var_name} must be a boolean")


def get_settings() -> Settings:
    admin_key = os.getenv("ADMIN_KEY", "")
    if not admin_key:
        raise RuntimeError("ADMIN_KEY environment variable is required")

    secret_salt = os.getenv("SECRET_SALT", "")
    if not secret_salt:
        raise RuntimeError("SECRET_SALT environment variable is required")

    runtime_environment = os.getenv("APP_ENV", os.getenv("ENVIRONMENT", "")).strip().lower()
    tgbot_service_token = os.getenv("TGBOT_SERVICE_TOKEN", "")
    if runtime_environment in {"prod", "production"} and not tgbot_service_token:
        raise RuntimeError("TGBOT_SERVICE_TOKEN environment variable is required in production")

    return Settings(
        admin_key=admin_key,
        secret_salt=secret_salt,
        tgbot_service_token=tgbot_service_token,
        database_path=os.getenv("DATABASE_PATH", "./data/onlinemainserver.db"),
        roles_config_path=os.getenv("ROLES_CONFIG_PATH", "./config/roles.json"),
        blob_storage_dir=os.getenv("BLOB_STORAGE_DIR", "./data/blobs"),
        max_blob_size_bytes=_read_positive_int_env(
            "MAX_BLOB_SIZE_BYTES",
            50 * 1024 * 1024,
        ),
        online_threshold_seconds=_read_positive_int_env(
            "ONLINE_THRESHOLD_SECONDS",
            60,
        ),
        ws_heartbeat_timeout_seconds=_read_positive_float_env(
            "WS_HEARTBEAT_TIMEOUT_SECONDS",
            60.0,
        ),
        command_default_timeout_seconds=_read_positive_float_env(
            "COMMAND_DEFAULT_TIMEOUT_SECONDS",
            15.0,
        ),
        blob_retention_seconds=_read_positive_float_env(
            "BLOB_RETENTION_SECONDS",
            86400.0,
        ),
        blob_cleanup_interval_seconds=_read_positive_float_env(
            "BLOB_CLEANUP_INTERVAL_SECONDS",
            300.0,
        ),
        notifications_enabled=_read_bool_env("NOTIFICATIONS_ENABLED", True),
        notification_startup_grace_seconds=_read_positive_int_env(
            "NOTIFICATION_STARTUP_GRACE_SECONDS",
            120,
        ),
        defect_notification_dedup_seconds=_read_positive_int_env(
            "DEFECT_NOTIFICATION_DEDUP_SECONDS",
            10,
        ),
        notification_push_batch_size=_read_positive_int_env(
            "NOTIFICATION_PUSH_BATCH_SIZE",
            10,
        ),
        annotated_image_cache_ttl_seconds=_read_positive_int_env(
            "ANNOTATED_IMAGE_CACHE_TTL_SECONDS",
            43200,
        ),
        notification_push_base_url=os.getenv("NOTIFICATION_PUSH_BASE_URL", "").strip(),
        notification_push_endpoint_path=os.getenv(
            "NOTIFICATION_PUSH_ENDPOINT_PATH",
            "/internal/notifications/push",
        ).strip()
        or "/internal/notifications/push",
        notification_push_timeout_seconds=_read_positive_float_env(
            "NOTIFICATION_PUSH_TIMEOUT_SECONDS",
            10.0,
        ),
        notification_push_poll_interval_seconds=_read_positive_float_env(
            "NOTIFICATION_PUSH_POLL_INTERVAL_SECONDS",
            2.0,
        ),
        notification_status_poll_interval_seconds=_read_positive_float_env(
            "NOTIFICATION_STATUS_POLL_INTERVAL_SECONDS",
            2.0,
        ),
    )
