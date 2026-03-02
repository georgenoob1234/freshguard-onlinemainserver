from __future__ import annotations

from datetime import datetime, timezone
import logging
import sqlite3
import uuid

from fastapi import APIRouter, Depends, HTTPException

from app.auth import BotService, resolve_authenticated_bot_service
from app.db import get_db, rollback_quietly
from app.models import BotHealthResponse, BotSessionEnsureRequest, BotSessionEnsureResponse


logger = logging.getLogger(__name__)
router = APIRouter(prefix="/bot/v1", tags=["bot"])


@router.get("/health", response_model=BotHealthResponse)
def bot_health(
    _: BotService = Depends(resolve_authenticated_bot_service),
) -> BotHealthResponse:
    return BotHealthResponse(ok=True)


@router.post("/session/ensure", response_model=BotSessionEnsureResponse)
def ensure_bot_session(
    payload: BotSessionEnsureRequest,
    _: BotService = Depends(resolve_authenticated_bot_service),
    connection: sqlite3.Connection = Depends(get_db),
) -> BotSessionEnsureResponse:
    if payload.provider != "telegram":
        raise HTTPException(status_code=400, detail="unsupported_provider")

    now = datetime.now(timezone.utc).isoformat()
    user_id: str
    is_banned: bool
    active_store_id: str | None = None
    active_device_id: str | None = None

    try:
        connection.execute("BEGIN IMMEDIATE")
        identity_row = connection.execute(
            """
            SELECT
                user_id,
                provider_chat_id
            FROM user_identities
            WHERE provider = ? AND provider_user_id = ?
            """,
            (payload.provider, payload.provider_user_id),
        ).fetchone()

        if identity_row is None:
            user_id = str(uuid.uuid4())
            connection.execute(
                """
                INSERT INTO users (
                    user_id,
                    is_banned,
                    created_at,
                    last_seen_at
                )
                VALUES (?, ?, ?, ?)
                """,
                (user_id, 0, now, now),
            )
            connection.execute(
                """
                INSERT INTO user_identities (
                    provider,
                    provider_user_id,
                    provider_chat_id,
                    username,
                    display_name,
                    user_id,
                    created_at,
                    updated_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    payload.provider,
                    payload.provider_user_id,
                    payload.provider_chat_id,
                    payload.username,
                    payload.display_name,
                    user_id,
                    now,
                    now,
                ),
            )
        else:
            user_id = identity_row["user_id"]
            set_clauses: list[str] = []
            params: list[str] = []

            if payload.provider_chat_id != identity_row["provider_chat_id"]:
                set_clauses.append("provider_chat_id = ?")
                params.append(payload.provider_chat_id)
            if "username" in payload.model_fields_set and payload.username is not None:
                set_clauses.append("username = ?")
                params.append(payload.username)
            if "display_name" in payload.model_fields_set and payload.display_name is not None:
                set_clauses.append("display_name = ?")
                params.append(payload.display_name)

            if set_clauses:
                set_clauses.append("updated_at = ?")
                params.append(now)
                params.extend([payload.provider, payload.provider_user_id])
                connection.execute(
                    f"""
                    UPDATE user_identities
                    SET {", ".join(set_clauses)}
                    WHERE provider = ? AND provider_user_id = ?
                    """,
                    tuple(params),
                )

            connection.execute(
                """
                UPDATE users
                SET last_seen_at = ?
                WHERE user_id = ?
                """,
                (now, user_id),
            )

        user_row = connection.execute(
            """
            SELECT is_banned
            FROM users
            WHERE user_id = ?
            """,
            (user_id,),
        ).fetchone()
        if user_row is None:
            raise HTTPException(status_code=500, detail="Internal server error.")

        context_row = connection.execute(
            """
            SELECT active_store_id, active_device_id
            FROM user_context
            WHERE user_id = ?
            """,
            (user_id,),
        ).fetchone()
        if context_row is not None:
            active_store_id = context_row["active_store_id"]
            active_device_id = context_row["active_device_id"]

        connection.execute("COMMIT")
        is_banned = int(user_row["is_banned"]) == 1
    except HTTPException:
        rollback_quietly(connection)
        raise
    except Exception as error:
        rollback_quietly(connection)
        logger.exception("Unexpected failure while ensuring bot session.")
        raise HTTPException(status_code=500, detail="Internal server error.") from error

    logger.info(
        "Bot session ensured provider_user_id=%s user_id=%s",
        payload.provider_user_id,
        user_id,
    )
    return BotSessionEnsureResponse(
        user_id=user_id,
        is_banned=is_banned,
        is_linked=False,
        active_store_id=active_store_id,
        active_device_id=active_device_id,
    )
