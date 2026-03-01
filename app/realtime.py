from __future__ import annotations

import asyncio
from datetime import datetime, timezone
import threading
from typing import Any
import uuid

from fastapi import HTTPException, WebSocket


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class ConnectionManager:
    def __init__(self) -> None:
        self._connections: dict[str, WebSocket] = {}
        self._last_seen_ts: dict[str, str] = {}
        self._lock = threading.RLock()

    async def connect(self, device_id: str, websocket: WebSocket) -> None:
        old_websocket: WebSocket | None
        with self._lock:
            old_websocket = self._connections.get(device_id)
            self._connections[device_id] = websocket
            self._last_seen_ts[device_id] = _utcnow_iso()

        if old_websocket is not None and old_websocket is not websocket:
            await old_websocket.close(code=1000)

    async def disconnect(self, device_id: str, websocket: WebSocket) -> None:
        with self._lock:
            current = self._connections.get(device_id)
            if current is websocket:
                self._connections.pop(device_id, None)
                self._last_seen_ts.pop(device_id, None)

    def mark_seen(self, device_id: str) -> None:
        with self._lock:
            if device_id in self._connections:
                self._last_seen_ts[device_id] = _utcnow_iso()

    def get_connection(self, device_id: str) -> WebSocket | None:
        with self._lock:
            return self._connections.get(device_id)

    def is_connected(self, device_id: str) -> bool:
        with self._lock:
            return device_id in self._connections

    def get_last_seen(self, device_id: str) -> str | None:
        with self._lock:
            return self._last_seen_ts.get(device_id)

    def clear(self) -> None:
        with self._lock:
            self._connections.clear()
            self._last_seen_ts.clear()


class CommandTimeoutError(TimeoutError):
    pass


class CommandBroker:
    def __init__(self, manager: ConnectionManager) -> None:
        self._manager = manager
        self._pending: dict[str, asyncio.Future[dict[str, Any]]] = {}
        self._pending_lock = asyncio.Lock()

    async def _register_pending(
        self,
        request_id: str,
        future: asyncio.Future[dict[str, Any]],
    ) -> None:
        async with self._pending_lock:
            self._pending[request_id] = future

    async def _pop_pending(
        self,
        request_id: str,
    ) -> asyncio.Future[dict[str, Any]] | None:
        async with self._pending_lock:
            return self._pending.pop(request_id, None)

    async def _clear_pending(self, request_id: str) -> None:
        async with self._pending_lock:
            self._pending.pop(request_id, None)

    async def resolve_response(self, request_id: str, payload: dict[str, Any]) -> None:
        future = await self._pop_pending(request_id)
        if future is not None and not future.done():
            future.set_result(payload)

    async def send_command(
        self,
        device_id: str,
        request_type: str,
        params: dict[str, Any],
        timeout_s: float,
    ) -> dict[str, Any]:
        websocket = self._manager.get_connection(device_id)
        if websocket is None:
            raise HTTPException(
                status_code=404,
                detail=f"Device {device_id} is not connected.",
            )

        request_id = str(uuid.uuid4())
        message = {
            "type": "request",
            "ts": _utcnow_iso(),
            "message_id": str(uuid.uuid4()),
            "device_id": device_id,
            "payload": {
                "request_id": request_id,
                "request_type": request_type,
                "params": params,
            },
        }

        future: asyncio.Future[dict[str, Any]] = asyncio.get_running_loop().create_future()
        await self._register_pending(request_id, future)

        try:
            await websocket.send_json(message)
        except Exception as error:
            await self._clear_pending(request_id)
            raise HTTPException(
                status_code=409,
                detail=f"Device {device_id} disconnected before dispatch.",
            ) from error

        try:
            return await asyncio.wait_for(future, timeout=timeout_s)
        except asyncio.TimeoutError as error:
            raise CommandTimeoutError(
                f"Timed out waiting for response to request {request_id}.",
            ) from error
        finally:
            await self._clear_pending(request_id)


connection_manager = ConnectionManager()
command_broker = CommandBroker(connection_manager)


async def send_command(
    device_id: str,
    request_type: str,
    params: dict[str, Any],
    timeout_s: float,
) -> dict[str, Any]:
    return await command_broker.send_command(
        device_id=device_id,
        request_type=request_type,
        params=params,
        timeout_s=timeout_s,
    )
