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
    )
