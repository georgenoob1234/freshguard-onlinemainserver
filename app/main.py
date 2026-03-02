from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager, suppress

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from app.api.admin import router as admin_router
from app.api.bot import router as bot_router
from app.blob_cleanup import run_blob_cleanup_loop
from app.api.connector import router as connector_router
from app.api.update import router as update_router
from app.config import get_settings
from app.db import init_db
from app.roles import load_roles_config


@asynccontextmanager
async def lifespan(_: FastAPI):
    settings = get_settings()
    load_roles_config(settings.roles_config_path)
    init_db(settings.database_path)
    cleanup_task = asyncio.create_task(
        run_blob_cleanup_loop(
            database_path=settings.database_path,
            interval_s=settings.blob_cleanup_interval_seconds,
            retention_s=settings.blob_retention_seconds,
        )
    )
    try:
        yield
    finally:
        cleanup_task.cancel()
        with suppress(asyncio.CancelledError):
            await cleanup_task


app = FastAPI(title="OnlineMainServer", lifespan=lifespan)
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

