"""EventEmitter — pub/sub event bus for agent observability.

The single interface between Agent execution and ALL consumers (CLI, WebUI, logs).
Multiple subscribers can listen to events synchronously, and async consumers
can iterate over the event stream.

Design: Watchtower pattern — Agent logic never knows about consumers.
"""

from __future__ import annotations

import asyncio
import threading
from collections import defaultdict
from typing import Any, AsyncIterator, Callable

from vulnagent.events.types import AgentEvent, EventType


Subscriber = Callable[[AgentEvent], None]


class EventEmitter:
    """Thread-safe publish/subscribe event bus.

    Usage:
        emitter = EventEmitter()

        # Sync subscriber
        emitter.on(EventType.TOOL_CALLED, lambda e: print(f"Tool: {e.message}"))
        emitter.on("*", lambda e: print(f"[{e.type.value}] {e.agent_name}"))

        # In agent nodes
        emitter.emit(AgentEvent.tool_called("WebAgent", "nmap", {"target": "..."}))

        # Async streaming
        async for event in emitter.stream():
            yield event.to_dict()
    """

    def __init__(self) -> None:
        self._subscribers: dict[str, list[Subscriber]] = defaultdict(list)
        self._lock = threading.Lock()
        self._async_queues: list[asyncio.Queue[AgentEvent]] = []
        self._event_count: int = 0

    @property
    def event_count(self) -> int:
        return self._event_count

    def on(self, event_type: EventType | str, callback: Subscriber) -> None:
        """Register a callback for a specific event type or "*" for all events.

        Args:
            event_type: EventType enum, its string value, or "*" for wildcard.
            callback: Called synchronously when matching events are emitted.
        """
        key = event_type.value if isinstance(event_type, EventType) else event_type
        with self._lock:
            self._subscribers[key].append(callback)

    def off(self, event_type: EventType | str, callback: Subscriber) -> None:
        """Remove a previously registered callback."""
        key = event_type.value if isinstance(event_type, EventType) else event_type
        with self._lock:
            if key in self._subscribers:
                self._subscribers[key] = [cb for cb in self._subscribers[key] if cb is not callback]

    def emit(self, event: AgentEvent) -> None:
        """Emit an event to all matching subscribers.

        Calls matching type subscribers first, then "*" wildcard subscribers.
        Also pushes to any active async stream queues.

        Subscriber exceptions are caught and logged — one bad subscriber
        does not break the event bus.
        """
        self._event_count += 1
        key = event.type.value

        # Collect all matching callbacks
        callbacks: list[Subscriber] = []
        with self._lock:
            callbacks.extend(self._subscribers.get(key, []))
            callbacks.extend(self._subscribers.get("*", []))

        for cb in callbacks:
            try:
                cb(event)
            except Exception:
                pass  # never let a subscriber crash the pipeline

        # Push to async queues
        for q in self._async_queues:
            try:
                q.put_nowait(event)
            except asyncio.QueueFull:
                pass

    async def stream(self, event_types: list[EventType] | None = None) -> AsyncIterator[AgentEvent]:
        """Async generator that yields events as they are emitted.

        Args:
            event_types: Optional filter — only yield matching types. None = all events.

        Usage:
            async for event in emitter.stream():
                print(event.to_dict())
        """
        queue: asyncio.Queue[AgentEvent] = asyncio.Queue(maxsize=256)
        self._async_queues.append(queue)
        allowed = set(et.value for et in event_types) if event_types else None

        try:
            while True:
                event = await queue.get()
                if allowed is None or event.type.value in allowed:
                    yield event
        except asyncio.CancelledError:
            pass
        finally:
            self._async_queues.remove(queue)

    def clear(self) -> None:
        """Remove all subscribers and reset counters."""
        with self._lock:
            self._subscribers.clear()
        self._async_queues.clear()
        self._event_count = 0

    def subscriber_count(self) -> dict[str, int]:
        """Return counts of subscribers per event type."""
        with self._lock:
            return {k: len(v) for k, v in self._subscribers.items() if v}


# ── Built-in subscribers ──────────────────────────────────────────

def console_subscriber(event: AgentEvent) -> None:
    """Simple console subscriber for CLI verbose mode.

    Formats events as color-free single-line summaries.
    """
    prefix_map = {
        "reasoning.started": "🧠",
        "reasoning.token": " ",
        "reasoning.tool_call": "🔧",
        "reasoning.completed": "✅",
        "reasoning.error": "❌",
        "tool.called": "🔨",
        "tool.result": "📋",
        "tool.error": "💥",
        "compress.micro": "📦",
        "compress.mid": "🗜️",
        "compress.deep": "💾",
        "memory.retrieve_started": "🔍",
        "memory.retrieve_completed": "📚",
        "flashbulb.detected": "⚡",
        "verify.completed": "🏁",
        "token.budget": "💰",
        "node.enter": "→",
        "node.exit": "←",
        "agent.error": "🆘",
    }
    prefix = prefix_map.get(event.type.value, "•")
    msg = event.message or event.data.get("node", "")
    token_info = ""
    if event.tokens_used > 0:
        token_info = f" [{event.tokens_used}/{event.tokens_total}t]"
    print(f"  {prefix} [{event.agent_name}] {event.type.value} {msg}{token_info}")


def jsonl_subscriber(event: AgentEvent) -> None:
    """JSON-lines subscriber for log file output."""
    import json
    print(json.dumps(event.to_dict(), default=str))
