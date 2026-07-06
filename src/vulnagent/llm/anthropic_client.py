"""LLM API client for Anthropic provider."""

from __future__ import annotations

import json
from typing import Any, AsyncIterator

from anthropic import Anthropic

from vulnagent.llm.client import (
    LLMChunk,
    LLMClient,
    LLMResponse,
    TokenUsage,
    ToolCall,
)


class AnthropicClient(LLMClient):
    """LLM client implementation."""

    def __init__(
        self,
        api_key: str,
        base_url: str | None = None,
        default_model: str = "claude-sonnet-4-20250514",
    ) -> None:
        super().__init__(api_key, base_url)
        kwargs: dict[str, Any] = {"api_key": api_key}
        if base_url:
            kwargs["base_url"] = base_url
        self._client = Anthropic(**kwargs)
        self.default_model = default_model

    def _convert_messages(
        self, messages: list[dict[str, Any]]
    ) -> tuple[str | None, list[dict[str, Any]]]:
        """Convert OpenAI-format messages to Anthropic format.

        Returns (system_prompt, anthropic_messages).
        """
        system_parts: list[str] = []
        anthropic_messages: list[dict[str, Any]] = []

        for msg in messages:
            role = msg.get("role", "user")
            content = msg.get("content", "")

            if role == "system":
                system_parts.append(content if isinstance(content, str) else str(content))
            elif role == "tool":
                anthropic_messages.append({
                    "role": "user",
                    "content": [
                        {
                            "type": "tool_result",
                            "tool_use_id": msg.get("tool_call_id", ""),
                            "content": content if isinstance(content, str) else json.dumps(content),
                        }
                    ],
                })
            elif role == "assistant" and msg.get("tool_calls"):
                tool_blocks: list[dict[str, Any]] = []
                for tc in msg["tool_calls"]:
                    tool_blocks.append({
                        "type": "tool_use",
                        "id": tc["id"],
                        "name": tc["function"]["name"],
                        "input": json.loads(tc["function"]["arguments"])
                        if isinstance(tc["function"]["arguments"], str)
                        else tc["function"]["arguments"],
                    })
                anthropic_messages.append({"role": "assistant", "content": tool_blocks})
            else:
                anthropic_messages.append({"role": role, "content": content})

        system_text = "\n\n".join(system_parts) if system_parts else None
        return system_text, anthropic_messages

    def _convert_tools(
        self, tools: list[dict[str, Any]] | None
    ) -> list[dict[str, Any]] | None:
        """Convert OpenAI-format tools to Anthropic format."""
        if not tools:
            return None
        anthropic_tools: list[dict[str, Any]] = []
        for tool in tools:
            func = tool.get("function", tool)
            anthropic_tools.append({
                "name": func["name"],
                "description": func.get("description", ""),
                "input_schema": func.get("parameters", {"type": "object", "properties": {}}),
            })
        return anthropic_tools

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
        system_prompt, anthropic_msgs = self._convert_messages(messages)
        anthropic_tools = self._convert_tools(tools)

        params: dict[str, Any] = {
            "model": model,
            "messages": anthropic_msgs,
            "max_tokens": max_tokens,
            "temperature": temperature,
        }
        if system_prompt:
            params["system"] = system_prompt
        if anthropic_tools:
            params["tools"] = anthropic_tools

        response = self._client.messages.create(**params)

        content_text = ""
        tool_calls: list[ToolCall] = []

        for block in response.content:
            if block.type == "text":
                content_text += block.text
            elif block.type == "tool_use":
                tool_calls.append(
                    ToolCall(
                        id=block.id,
                        name=block.name,
                        arguments=block.input if isinstance(block.input, dict) else {},
                    )
                )

        return LLMResponse(
            content=content_text,
            tool_calls=tool_calls,
            usage=TokenUsage(
                prompt_tokens=response.usage.input_tokens if response.usage else 0,
                completion_tokens=response.usage.output_tokens if response.usage else 0,
                total_tokens=(
                    response.usage.input_tokens + response.usage.output_tokens
                    if response.usage
                    else 0
                ),
            ),
            finish_reason=response.stop_reason or "stop",
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
        system_prompt, anthropic_msgs = self._convert_messages(messages)
        anthropic_tools = self._convert_tools(tools)

        params: dict[str, Any] = {
            "model": model,
            "messages": anthropic_msgs,
            "max_tokens": max_tokens,
            "temperature": temperature,
        }
        if system_prompt:
            params["system"] = system_prompt
        if anthropic_tools:
            params["tools"] = anthropic_tools

        async with self._client.messages.stream(**params) as stream:
            async for event in stream:
                if event.type == "content_block_delta":
                    if event.delta.type == "text_delta":
                        yield LLMChunk(content=event.delta.text)
                elif event.type == "message_delta":
                    yield LLMChunk(
                        finish_reason=event.delta.stop_reason,
                        usage=(
                            TokenUsage(
                                prompt_tokens=event.usage.input_tokens,
                                completion_tokens=event.usage.output_tokens,
                            )
                            if hasattr(event, "usage") and event.usage
                            else None
                        ),
                    )
