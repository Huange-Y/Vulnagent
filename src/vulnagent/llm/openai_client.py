"""OpenAI LLM client implementation."""

from __future__ import annotations

import json
import re
from typing import Any, AsyncIterator

from openai import AsyncOpenAI, OpenAI

from vulnagent.llm.client import (
    LLMChunk,
    LLMClient,
    LLMResponse,
    TokenUsage,
    ToolCall,
    ToolCallDelta,
)


def _extract_string_payload_content(payload: str) -> str:
    text = str(payload or "")
    if "data:" not in text:
        return text

    content_parts: list[str] = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped.startswith("data:"):
            continue
        data = stripped[5:].strip()
        if not data or data == "[DONE]":
            continue
        try:
            event = json.loads(data)
        except json.JSONDecodeError:
            continue
        choices = event.get("choices") if isinstance(event, dict) else None
        if not isinstance(choices, list):
            continue
        for choice in choices:
            if not isinstance(choice, dict):
                continue
            delta = choice.get("delta")
            if isinstance(delta, dict):
                delta_content = delta.get("content")
                if isinstance(delta_content, str) and delta_content:
                    content_parts.append(delta_content)
            message = choice.get("message")
            if isinstance(message, dict):
                message_content = message.get("content")
                if isinstance(message_content, str) and message_content:
                    content_parts.append(message_content)

    if content_parts:
        return "".join(content_parts)
    return ""


class OpenAIClient(LLMClient):
    """LLM client for OpenAI-compatible APIs (OpenAI, vLLM, local models, etc.)."""

    def __init__(
        self,
        api_key: str,
        base_url: str | None = None,
        default_model: str = "gpt-4o",
    ) -> None:
        super().__init__(api_key, base_url)
        self._client = OpenAI(api_key=api_key, base_url=base_url)
        self._async_client = AsyncOpenAI(api_key=api_key, base_url=base_url)
        self.default_model = default_model

    def invoke(
        self,
        messages: list[dict[str, Any]],
        model: str = "",
        tools: list[dict[str, Any]] | None = None,
        tool_choice: str = "auto",
        max_tokens: int = 4096,
        temperature: float = 0.0,
        **kwargs: Any,
    ) -> LLMResponse:
        model = model or self.default_model

        params: dict[str, Any] = {
            "model": model,
            "messages": messages,
            "max_tokens": max_tokens,
            "temperature": temperature,
        }

        if tools:
            params["tools"] = tools
            params["tool_choice"] = tool_choice

        response = self._client.chat.completions.create(**params)
        if isinstance(response, str):
            content = _extract_string_payload_content(response)
            return LLMResponse(
                content=content,
                usage=TokenUsage(),
                finish_reason="stop",
                model=model,
            )
        choice = response.choices[0]
        message = choice.message

        tool_calls: list[ToolCall] = []
        if message.tool_calls:
            for tc in message.tool_calls:
                try:
                    args = json.loads(tc.function.arguments)
                except json.JSONDecodeError:
                    args = {}
                tool_calls.append(
                    ToolCall(id=tc.id, name=tc.function.name, arguments=args)
                )

        # Capture reasoning_content for provider thinking mode
        reasoning = getattr(message, "reasoning_content", "") or ""

        return LLMResponse(
            content=message.content or "",
            reasoning_content=reasoning,
            tool_calls=tool_calls,
            usage=TokenUsage(
                prompt_tokens=response.usage.prompt_tokens if response.usage else 0,
                completion_tokens=response.usage.completion_tokens if response.usage else 0,
                total_tokens=response.usage.total_tokens if response.usage else 0,
            ),
            finish_reason=choice.finish_reason or "stop",
            model=response.model,
        )

    async def stream(
        self,
        messages: list[dict[str, Any]],
        model: str = "",
        tools: list[dict[str, Any]] | None = None,
        max_tokens: int = 4096,
        temperature: float = 0.0,
        **kwargs: Any,
    ) -> AsyncIterator[LLMChunk]:
        model = model or self.default_model

        params: dict[str, Any] = {
            "model": model,
            "messages": messages,
            "max_tokens": max_tokens,
            "temperature": temperature,
            "stream": True,
        }

        if tools:
            params["tools"] = tools

        # Accumulate tool call deltas across chunks
        tc_accumulator: dict[int, ToolCallDelta] = {}

        stream = await self._async_client.chat.completions.create(**params)
        async for chunk in stream:
            delta = chunk.choices[0].delta if chunk.choices else None
            finish_reason = chunk.choices[0].finish_reason if chunk.choices else None

            content = delta.content if delta and delta.content else ""

            # Accumulate tool call deltas
            tool_deltas: list[ToolCallDelta] = []
            if delta and delta.tool_calls:
                for tc_delta in delta.tool_calls:
                    idx = tc_delta.index
                    if idx not in tc_accumulator:
                        tc_accumulator[idx] = ToolCallDelta(index=idx)
                    acc = tc_accumulator[idx]

                    if tc_delta.id:
                        acc.id = tc_delta.id
                    if tc_delta.function:
                        if tc_delta.function.name:
                            acc.name = tc_delta.function.name
                        if tc_delta.function.arguments:
                            acc.arguments += tc_delta.function.arguments

            # On finish, flush accumulated tool calls
            if finish_reason:
                tool_deltas = list(tc_accumulator.values())
                tc_accumulator.clear()

            yield LLMChunk(
                content=content,
                finish_reason=finish_reason,
                tool_call_deltas=tool_deltas,
                usage=(
                    TokenUsage(
                        prompt_tokens=chunk.usage.prompt_tokens,
                        completion_tokens=chunk.usage.completion_tokens,
                        total_tokens=chunk.usage.total_tokens,
                    )
                    if hasattr(chunk, "usage") and chunk.usage
                    else None
                ),
            )
