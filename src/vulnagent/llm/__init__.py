"""LLM provider abstraction — provider-agnostic, configuration-driven.

Usage:
    from vulnagent.llm import ModelRegistry, ModelRouter

    # Build from config
    registry = ModelRegistry()
    registry.add_provider_from_dict("deepseek", {
        "base_url": "https://api.deepseek.com/v1",
        "api_key_env": "DEEPSEEK_API_KEY",
        "models": ["deepseek-chat", "deepseek-reasoner"],
    })
    registry.set_purpose("reasoning", provider="deepseek", model="deepseek-reasoner")
    registry.set_purpose("routing", provider="deepseek", model="deepseek-chat")

    router = ModelRouter(registry)
    response = router.reason([{"role": "user", "content": "..."}])
"""

from vulnagent.llm.client import LLMChunk, LLMClient, LLMResponse, TokenUsage, ToolCall
from vulnagent.llm.openai_client import OpenAIClient
from vulnagent.llm.anthropic_client import AnthropicClient
from vulnagent.llm.model_registry import (
    ModelRegistry,
    ProviderConfig,
    PurposeConfig,
)
from vulnagent.llm.model_router import ModelRouter, RouterStats

__all__ = [
    # Base client
    "LLMClient",
    "LLMResponse",
    "LLMChunk",
    "TokenUsage",
    "ToolCall",
    "OpenAIClient",
    "AnthropicClient",
    # Dynamic configuration
    "ModelRegistry",
    "ModelRouter",
    "ProviderConfig",
    "PurposeConfig",
    "RouterStats",
]
