"""LLM client abstraction layer — normalizes OpenAI and Anthropic into a common interface."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, AsyncIterator


@dataclass
class TokenUsage:
    """Token usage statistics for a single LLM call."""

    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0


@dataclass
class ToolCall:
    """A tool call requested by the LLM (normalized to OpenAI-compatible format)."""

    id: str
    name: str
    arguments: dict[str, Any]


@dataclass
class LLMResponse:
    """Normalized response from any LLM provider."""

    content: str = ""
    reasoning_content: str = ""  # Provider reasoning/thinking mode
    tool_calls: list[ToolCall] = field(default_factory=list)
    usage: TokenUsage = field(default_factory=TokenUsage)
    finish_reason: str = "stop"
    model: str = ""


@dataclass
class ToolCallDelta:
    """A single tool call being incrementally built during streaming."""

    index: int = 0
    id: str = ""
    name: str = ""
    arguments: str = ""  # accumulated JSON string


@dataclass
class LLMChunk:
    """A streaming chunk from the LLM."""

    content: str = ""
    finish_reason: str | None = None
    usage: TokenUsage | None = None
    tool_call_deltas: list[ToolCallDelta] = field(default_factory=list)


class LLMClient(ABC):
    """Abstract base class for all LLM providers.

    All provider-specific clients (OpenAI, Anthropic) implement this interface
    and normalize their outputs to the common LLMResponse / ToolCall format.

    Usage:
        client = OpenAIClient(api_key="...", base_url="...")
        response = client.invoke(
            messages=[{"role": "user", "content": "Hello"}],
            model="gpt-4o",
        )
        print(response.content)
    """

    def __init__(self, api_key: str, base_url: str | None = None) -> None:
        self._api_key = api_key
        self._base_url = base_url

    @abstractmethod
    def invoke(
        self,
        messages: list[dict[str, Any]],
        model: str,
        tools: list[dict[str, Any]] | None = None,
        tool_choice: str = "auto",
        max_tokens: int = 4096,
        temperature: float = 0.0,
        **kwargs: Any,
    ) -> LLMResponse:
        """Send messages to the LLM and get a complete response."""
        ...

    @abstractmethod
    async def stream(
        self,
        messages: list[dict[str, Any]],
        model: str,
        tools: list[dict[str, Any]] | None = None,
        max_tokens: int = 4096,
        temperature: float = 0.0,
        **kwargs: Any,
    ) -> AsyncIterator[LLMChunk]:
        """Stream messages to the LLM and yield chunks."""
        ...

    def count_tokens(self, text: str, model: str = "gpt-4o") -> int:
        """Estimate token count for a given text.

        Uses tiktoken with cl100k_base encoding as a reasonable default.
        Subclasses may override for provider-specific counting.
        """
        import tiktoken

        try:
            enc = tiktoken.get_encoding("cl100k_base")
        except Exception:
            return len(text) // 4  # rough fallback
        return len(enc.encode(text))

    def count_messages_tokens(
        self, messages: list[dict[str, Any]], model: str = "gpt-4o"
    ) -> int:
        """Estimate total tokens for a list of messages."""
        total = 0
        for msg in messages:
            content = msg.get("content", "")
            if isinstance(content, str):
                total += self.count_tokens(content, model)
            elif isinstance(content, list):
                for part in content:
                    if isinstance(part, dict) and "text" in part:
                        total += self.count_tokens(part["text"], model)
            # Account for message framing overhead (~4 tokens per message)
            total += 4
        return total + 2  # priming tokens

    def supports_tool_calling(self) -> bool:
        """Whether this provider supports native tool calling."""
        return True
