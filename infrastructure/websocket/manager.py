"""WebSocket ConnectionManager for real-time prediction broadcasting."""

import asyncio
import logging

from fastapi import WebSocket, WebSocketDisconnect

log = logging.getLogger("horus-api")


class ConnectionManager:
    def __init__(self):
        self._active: list = []
        self._event_loop = None

    def set_event_loop(self, loop):
        self._event_loop = loop

    async def connect(self, ws: WebSocket):
        await ws.accept()
        self._active.append(ws)

    def disconnect(self, ws: WebSocket):
        try:
            self._active.remove(ws)
        except ValueError:
            pass

    async def broadcast(self, data: dict):
        dead = []
        for ws in list(self._active):
            try:
                await ws.send_json(data)
            except (WebSocketDisconnect, RuntimeError, ConnectionError):
                dead.append(ws)
        for ws in dead:
            self.disconnect(ws)

    def broadcast_from_thread(self, data: dict):
        if self._event_loop and self._active:
            asyncio.run_coroutine_threadsafe(self.broadcast(data), self._event_loop)
