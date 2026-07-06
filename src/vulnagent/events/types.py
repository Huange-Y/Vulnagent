"""Event type definitions for the agent observability system.

All lifecycle events across reasoning, tools, compression, memory, flashbulb,
verification, and token tracking are represented as structured dataclasses.
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class EventType(str, Enum):
    """All agent lifecycle event types."""

    # ── Reasoning ──
    REASONING_STARTED = "reasoning.started"
    REASONING_TOKEN = "reasoning.token"
    REASONING_TOOL_CALL = "reasoning.tool_call"
    REASONING_COMPLETED = "reasoning.completed"
    REASONING_ERROR = "reasoning.error"

    # ── Tools ──
    TOOL_CALLED = "tool.called"
    TOOL_RESULT = "tool.result"
    TOOL_ERROR = "tool.error"

    # ── Compression ──
    COMPRESS_MICRO = "compress.micro"
    COMPRESS_MID = "compress.mid"
    COMPRESS_DEEP = "compress.deep"

    # ── Memory ──
    MEMORY_RETRIEVE_STARTED = "memory.retrieve_started"
    MEMORY_RETRIEVE_COMPLETED = "memory.retrieve_completed"
    MEMORY_STORED = "memory.stored"

    # ── Flashbulb ──
    FLASHBULB_DETECTED = "flashbulb.detected"

    # ── Verification ──
    VERIFY_STARTED = "verify.started"
    VERIFY_COMPLETED = "verify.completed"

    # ── Token budget ──
    TOKEN_BUDGET = "token.budget"

    # ── Agent control ──
    AGENT_PAUSED = "agent.paused"
    AGENT_RESUMED = "agent.resumed"
    AGENT_ERROR = "agent.error"
    AGENT_PHASE = "agent.phase"

    # ── Graph ──
    NODE_ENTER = "node.enter"
    NODE_EXIT = "node.exit"


@dataclass
class AgentEvent:
    """A structured event emitted during agent execution."""

    type: EventType
    agent_name: str = ""
    timestamp: float = field(default_factory=time.time)
    event_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])

    # ── Common payload fields ──
    message: str = ""
    data: dict[str, Any] = field(default_factory=dict)
    iteration: int = 0

    # ── Token tracking ──
    tokens_used: int = 0
    tokens_total: int = 0

    @property
    def tokens_remaining(self) -> int:
        return max(0, self.tokens_total - self.tokens_used)

    @property
    def usage_ratio(self) -> float:
        if self.tokens_total <= 0:
            return 0.0
        return self.tokens_used / self.tokens_total

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_id": self.event_id,
            "type": self.type.value,
            "agent_name": self.agent_name,
            "timestamp": self.timestamp,
            "message": self.message,
            "data": self.data,
            "iteration": self.iteration,
            "tokens_used": self.tokens_used,
            "tokens_total": self.tokens_total,
            "tokens_remaining": self.tokens_remaining,
            "usage_ratio": round(self.usage_ratio, 4),
        }

    # ── Factory methods ──────────────────────────────────────────

    @classmethod
    def reasoning_started(cls, agent_name: str, iteration: int = 0, **extra) -> "AgentEvent":
        return cls(type=EventType.REASONING_STARTED, agent_name=agent_name,
                   iteration=iteration, data=extra)

    @classmethod
    def reasoning_token(cls, agent_name: str, token_text: str, **extra) -> "AgentEvent":
        return cls(type=EventType.REASONING_TOKEN, agent_name=agent_name,
                   message=token_text, data=extra)

    @classmethod
    def reasoning_tool_call(cls, agent_name: str, tool_name: str, tool_args: dict, **extra) -> "AgentEvent":
        return cls(type=EventType.REASONING_TOOL_CALL, agent_name=agent_name,
                   message=tool_name, data={"tool_name": tool_name, "tool_args": tool_args, **extra})

    @classmethod
    def reasoning_completed(cls, agent_name: str, content: str, tokens_used: int = 0,
                            tokens_total: int = 0, **extra) -> "AgentEvent":
        return cls(type=EventType.REASONING_COMPLETED, agent_name=agent_name,
                   message=content[:200], tokens_used=tokens_used, tokens_total=tokens_total, data=extra)

    @classmethod
    def tool_called(cls, agent_name: str, tool_name: str, args: dict, **extra) -> "AgentEvent":
        return cls(type=EventType.TOOL_CALLED, agent_name=agent_name,
                   message=tool_name, data={"tool_name": tool_name, "arguments": args, **extra})

    @classmethod
    def tool_result(cls, agent_name: str, tool_name: str, output_preview: str,
                    raw_chars: int = 0, compressed_chars: int = 0, **extra) -> "AgentEvent":
        return cls(type=EventType.TOOL_RESULT, agent_name=agent_name,
                   message=f"{tool_name}: {output_preview[:150]}",
                   data={"tool_name": tool_name, "raw_chars": raw_chars,
                         "compressed_chars": compressed_chars, **extra})

    @classmethod
    def tool_error(cls, agent_name: str, tool_name: str, error: str, **extra) -> "AgentEvent":
        return cls(type=EventType.TOOL_ERROR, agent_name=agent_name,
                   message=f"{tool_name} error: {error}", data={"tool_name": tool_name, "error": error, **extra})

    @classmethod
    def compress_micro(cls, agent_name: str, msgs_before: int, msgs_after: int, **extra) -> "AgentEvent":
        return cls(type=EventType.COMPRESS_MICRO, agent_name=agent_name,
                   data={"msgs_before": msgs_before, "msgs_after": msgs_after, **extra})

    @classmethod
    def compress_mid(cls, agent_name: str, msgs_before: int, msgs_after: int,
                     sections_populated: int = 0, **extra) -> "AgentEvent":
        return cls(type=EventType.COMPRESS_MID, agent_name=agent_name,
                   data={"msgs_before": msgs_before, "msgs_after": msgs_after,
                         "sections_populated": sections_populated, **extra})

    @classmethod
    def memory_retrieve_started(cls, agent_name: str, **extra) -> "AgentEvent":
        return cls(type=EventType.MEMORY_RETRIEVE_STARTED, agent_name=agent_name, data=extra)

    @classmethod
    def memory_retrieve_completed(cls, agent_name: str, entries_found: int,
                                  layers: list[str] | None = None, **extra) -> "AgentEvent":
        return cls(type=EventType.MEMORY_RETRIEVE_COMPLETED, agent_name=agent_name,
                   data={"entries_found": entries_found, "layers": layers or [], **extra})

    @classmethod
    def flashbulb_detected(cls, agent_name: str, salience: float, narrative: str = "",
                           memory_id: str = "", **extra) -> "AgentEvent":
        return cls(type=EventType.FLASHBULB_DETECTED, agent_name=agent_name,
                   data={"salience": salience, "narrative": narrative, "memory_id": memory_id, **extra})

    @classmethod
    def verify_completed(cls, agent_name: str, success: bool, flag: str = "",
                         confidence: float = 0.0, **extra) -> "AgentEvent":
        return cls(type=EventType.VERIFY_COMPLETED, agent_name=agent_name,
                   message=f"verify: {'success' if success else 'failure'}",
                   data={"success": success, "flag": flag, "confidence": confidence, **extra})

    @classmethod
    def token_budget(cls, agent_name: str, used: int, total: int, **extra) -> "AgentEvent":
        return cls(type=EventType.TOKEN_BUDGET, agent_name=agent_name,
                   tokens_used=used, tokens_total=total, data=extra)

    @classmethod
    def node_enter(cls, agent_name: str, node: str, **extra) -> "AgentEvent":
        return cls(type=EventType.NODE_ENTER, agent_name=agent_name,
                   message=node, data={"node": node, **extra})

    @classmethod
    def node_exit(cls, agent_name: str, node: str, **extra) -> "AgentEvent":
        return cls(type=EventType.NODE_EXIT, agent_name=agent_name,
                   message=node, data={"node": node, **extra})

    @classmethod
    def agent_error(cls, agent_name: str, error: str, node: str = "", **extra) -> "AgentEvent":
        return cls(type=EventType.AGENT_ERROR, agent_name=agent_name,
                   message=error, data={"error": error, "node": node, **extra})
