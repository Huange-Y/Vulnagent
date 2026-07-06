"""WebSocket connection manager for real-time event streaming."""

from __future__ import annotations

import asyncio
import json
from typing import Any

from fastapi import WebSocket


class ConnectionManager:
    """Manages WebSocket connections and broadcasts events to all clients."""

    def __init__(self) -> None:
        self._connections: list[WebSocket] = []
        self._lock = asyncio.Lock()

    async def connect(self, ws: WebSocket) -> None:
        await ws.accept()
        async with self._lock:
            self._connections.append(ws)

    async def disconnect(self, ws: WebSocket) -> None:
        async with self._lock:
            if ws in self._connections:
                self._connections.remove(ws)

    async def broadcast(self, event: dict[str, Any]) -> None:
        """Send an event dict to all connected clients."""
        data = json.dumps(event, default=str)
        async with self._lock:
            dead: list[WebSocket] = []
            for ws in self._connections:
                try:
                    await ws.send_text(data)
                except Exception:
                    dead.append(ws)
            for ws in dead:
                self._connections.remove(ws)

    async def broadcast_event(self, agent_event: Any) -> None:
        """Broadcast an AgentEvent to all connected clients."""
        await self.broadcast(agent_event.to_dict())

    @property
    def active_count(self) -> int:
        return len(self._connections)


# Global singleton
manager = ConnectionManager()
