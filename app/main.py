from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager, suppress
import logging
import os
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.sessions import SessionMiddleware

from app.admin_auth import bootstrap_admin_account_if_needed
from app.admin_i18n import router as admin_i18n_router
from app.admin_ui import router as admin_ui_router
from app.api.admin import router as admin_router
from app.api.bot import router as bot_router
from app.blob_cleanup import run_blob_cleanup_loop
from app.api.connector import router as connector_router
from app.api.update import router as update_router
from app.config import get_settings
from app.db import init_db
from app.notification_delivery_worker import (
    NotificationDeliveryWorker,
    cleanup_stale_notification_deliveries_once,
)
from app.notification_status_monitor import NotificationStatusMonitor
from app.roles import load_roles_config


logger = logging.getLogger(__name__)


def _is_production_runtime() -> bool:
    runtime_environment = os.getenv("APP_ENV", os.getenv("ENVIRONMENT", "")).strip().lower()
    return runtime_environment in {"prod", "production"}


@asynccontextmanager
async def lifespan(_: FastAPI):
    settings = get_settings()
    load_roles_config(settings.roles_config_path)
    init_db(settings.database_path)
    bootstrap_status = bootstrap_admin_account_if_needed(
        database_path=settings.database_path,
        username=settings.admin_bootstrap_username,
        password=settings.admin_bootstrap_password,
    )
    if bootstrap_status == "missing_bootstrap_credentials":
        logger.warning(
            "No admin bootstrap credentials configured; /admin UI login is unavailable until set."
        )
    cleanup_task = asyncio.create_task(
        run_blob_cleanup_loop(
            database_path=settings.database_path,
            interval_s=settings.blob_cleanup_interval_seconds,
            retention_s=settings.blob_retention_seconds,
        )
    )
    status_monitor = NotificationStatusMonitor(
        database_path=settings.database_path,
        online_threshold_seconds=settings.online_threshold_seconds,
        startup_grace_seconds=settings.notification_startup_grace_seconds,
        poll_interval_seconds=settings.notification_status_poll_interval_seconds,
        enabled=settings.notifications_enabled,
    )
    delivery_worker = NotificationDeliveryWorker(
        database_path=settings.database_path,
        push_base_url=settings.notification_push_base_url,
        push_endpoint_path=settings.notification_push_endpoint_path,
        batch_size=settings.notification_push_batch_size,
        timeout_seconds=settings.notification_push_timeout_seconds,
        poll_interval_seconds=settings.notification_push_poll_interval_seconds,
        enabled=settings.notifications_enabled,
    )
    stale_cleanup_count = cleanup_stale_notification_deliveries_once(settings.database_path)
    if stale_cleanup_count > 0:
        logger.info(
            "startup stale notification cleanup failed_count=%s",
            stale_cleanup_count,
        )
    status_monitor_task = asyncio.create_task(status_monitor.run_forever())
    delivery_worker_task = asyncio.create_task(delivery_worker.run_forever())
    try:
        yield
    finally:
        cleanup_task.cancel()
        status_monitor_task.cancel()
        delivery_worker_task.cancel()
        with suppress(asyncio.CancelledError):
            await cleanup_task
        with suppress(asyncio.CancelledError):
            await status_monitor_task
        with suppress(asyncio.CancelledError):
            await delivery_worker_task


app = FastAPI(title="OnlineMainServer", lifespan=lifespan)
session_secret = os.getenv("OMS_ADMIN_SESSION_SECRET", "").strip() or "dev-admin-session-secret"
app.add_middleware(
    SessionMiddleware,
    secret_key=session_secret,
    session_cookie="oms_admin_session",
    same_site="lax",
    https_only=_is_production_runtime(),
)
app.mount("/static", StaticFiles(directory=str(Path(__file__).resolve().parent.parent / "static")), name="static")
app.include_router(admin_ui_router)
app.include_router(admin_i18n_router)
app.include_router(admin_router)
app.include_router(bot_router)
app.include_router(connector_router)
app.include_router(update_router)


@app.exception_handler(RequestValidationError)
async def handle_request_validation_error(
    request: Request,
    error: RequestValidationError,
) -> JSONResponse:
    if request.url.path == "/update":
        return JSONResponse(
            status_code=400,
            content={"detail": "Invalid update envelope.", "errors": error.errors()},
        )

    return JSONResponse(status_code=422, content={"detail": error.errors()})

