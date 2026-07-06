"""Structured JSON-formatted logging for agent operations."""

from __future__ import annotations

import json
import time
from typing import Any


class StructuredLogger:
    """JSON-formatted structured logger for agent observability.

    Provides typed logging methods for common agent events:
    LLM calls, tool execution, memory operations, and compression.

    Usage:
        logger = StructuredLogger("WebAgent")
        logger.log_llm_call(model="gpt-4o", tokens_in=500, tokens_out=200)
    """

    def __init__(self, component: str, level: str = "INFO") -> None:
        self._component = component
        self._level = level

    def _emit(self, event: str, **kwargs: Any) -> None:
        record = {
            "component": self._component,
            "event": event,
            "timestamp": time.time(),
            **kwargs,
        }
        print(json.dumps(record, default=str), flush=True)

    def log_llm_call(
        self,
        model: str,
        tokens_in: int,
        tokens_out: int,
        duration_ms: float | None = None,
        **kwargs: Any,
    ) -> None:
        self._emit(
            "llm_call",
            model=model,
            prompt_tokens=tokens_in,
            completion_tokens=tokens_out,
            total_tokens=tokens_in + tokens_out,
            duration_ms=duration_ms,
            **kwargs,
        )

    def log_tool_exec(
        self,
        tool_name: str,
        command: str,
        return_code: int,
        duration_ms: float,
        tokens_raw: int | None = None,
        tokens_compressed: int | None = None,
        **kwargs: Any,
    ) -> None:
        self._emit(
            "tool_exec",
            tool_name=tool_name,
            command=command,
            return_code=return_code,
            duration_ms=duration_ms,
            tokens_raw=tokens_raw,
            tokens_compressed=tokens_compressed,
            **kwargs,
        )

    def log_memory_op(
        self,
        operation: str,
        layer: str | None = None,
        count: int | None = None,
        **kwargs: Any,
    ) -> None:
        self._emit(
            "memory_op",
            operation=operation,
            layer=layer,
            count=count,
            **kwargs,
        )

    def log_compaction(
        self,
        level: str,
        tokens_before: int,
        tokens_after: int,
        **kwargs: Any,
    ) -> None:
        self._emit(
            "compaction",
            level=level,
            tokens_before=tokens_before,
            tokens_after=tokens_after,
            compression_ratio=(
                (tokens_before - tokens_after) / tokens_before
                if tokens_before > 0
                else 0
            ),
            **kwargs,
        )

    def log_route(self, category: str, confidence: float, matched_rules: list[str]) -> None:
        self._emit(
            "route",
            category=category,
            confidence=confidence,
            matched_rules=matched_rules,
        )

    def log_verify(
        self, result: str, flag: str | None = None, confidence: float | None = None
    ) -> None:
        self._emit("verify", result=result, flag=flag, confidence=confidence)

    def info(self, message: str, **kwargs: Any) -> None:
        self._emit("info", message=message, **kwargs)

    def warning(self, message: str, **kwargs: Any) -> None:
        self._emit("warning", message=message, **kwargs)

    def error(self, message: str, **kwargs: Any) -> None:
        self._emit("error", message=message, **kwargs)
