from __future__ import annotations

from dataclasses import dataclass
import os


@dataclass(frozen=True)
class Settings:
    admin_key: str
    secret_salt: str
    database_path: str
    blob_storage_dir: str
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
    secret_salt = os.getenv("SECRET_SALT", "")
    if not secret_salt:
        raise RuntimeError("SECRET_SALT environment variable is required")

    return Settings(
        admin_key=os.getenv("ADMIN_KEY", ""),
        secret_salt=secret_salt,
        database_path=os.getenv("DATABASE_PATH", "./data/onlinemainserver.db"),
        blob_storage_dir=os.getenv("BLOB_STORAGE_DIR", "./data/blobs"),
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
