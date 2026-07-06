"""Model Registry — provider-agnostic, configuration-driven model management.

All modern LLM APIs are OpenAI-compatible (OpenRouter, DeepSeek, Groq, Together,
vLLM, Ollama, local models). This registry treats every provider uniformly:
any endpoint with a base_url + api_key is a first-class provider.

Each provider exposes a set of models. Purposes (reasoning/routing/critique/compress)
map to a specific (provider, model) pair with fallback chains.

Configuration is entirely driven by settings.yaml, not hardcoded:
    providers:
      deepseek:
        base_url: https://api.deepseek.com/v1
        api_key_env: DEEPSEEK_API_KEY
      openrouter:
        base_url: https://openrouter.ai/api/v1
        api_key_env: OPENROUTER_API_KEY
      local:
        base_url: http://localhost:11434/v1
        api_key: ollama

    purposes:
      reasoning:
        provider: openrouter
        model: openai/gpt-4o
        fallback_provider: deepseek
        fallback_model: deepseek-chat
      routing:
        provider: local
        model: qwen2.5:7b
      critique:
        provider: deepseek
        model: deepseek-chat
      compress:
        provider: deepseek
        model: deepseek-chat
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any

from vulnagent.llm.client import LLMClient


# ── Data classes ───────────────────────────────────────────────────────

@dataclass
class ProviderConfig:
    """Configuration for a model provider (any OpenAI-compatible endpoint).

    Examples:
        ProviderConfig("deepseek", "https://api.deepseek.com/v1",
                       api_key_env="DEEPSEEK_API_KEY")
        ProviderConfig("local", "http://localhost:11434/v1", api_key="ollama")
        ProviderConfig("openrouter", "https://openrouter.ai/api/v1",
                       api_key_env="OPENROUTER_API_KEY")
    """

    name: str
    base_url: str
    api_key: str = ""         # Direct key (takes priority over env)
    api_key_env: str = ""     # Environment variable name for the key
    models: list[str] = field(default_factory=list)

    def resolve_api_key(self) -> str:
        """Resolve the API key: direct value → environment variable."""
        if self.api_key:
            return self.api_key
        if self.api_key_env:
            return os.environ.get(self.api_key_env, "")
        return ""


@dataclass
class PurposeConfig:
    """Which (provider, model) to use for a specific purpose."""

    purpose: str
    provider: str
    model: str
    fallback_provider: str = ""
    fallback_model: str = ""
    max_tokens: int = 4096
    temperature: float = 0.0


# ── Registry ──────────────────────────────────────────────────────────

class ModelRegistry:
    """Provider-agnostic model registry.

    All providers are treated uniformly as OpenAI-compatible endpoints.
    Configuration is driven by settings.yaml, with sensible defaults.

    Usage:
        registry = ModelRegistry()

        # Register providers
        registry.add_provider(ProviderConfig(
            "deepseek", "https://api.deepseek.com/v1",
            api_key_env="DEEPSEEK_API_KEY",
            models=["deepseek-chat", "deepseek-reasoner"],
        ))
        registry.add_provider(ProviderConfig(
            "local", "http://localhost:11434/v1",
            api_key="ollama", models=["qwen2.5:7b", "llama3.1:8b"],
        ))

        # Set purposes
        registry.set_purpose("reasoning",
            provider="deepseek", model="deepseek-reasoner",
            fallback_provider="local", fallback_model="llama3.1:8b")
        registry.set_purpose("routing",
            provider="local", model="qwen2.5:7b")

        # Get client for reasoning
        client, model = registry.get_client_for_purpose("reasoning")
        response = client.invoke(messages=[...], model=model)
    """

    # Sensible built-in defaults — overridden by settings.yaml
    DEFAULT_PURPOSE_CONFIGS: dict[str, dict[str, Any]] = {
        "reasoning": {
            "provider": "openai", "model": "gpt-4o",
            "fallback_provider": "", "fallback_model": "",
            "max_tokens": 4096, "temperature": 0.0,
        },
        "routing": {
            "provider": "openai", "model": "gpt-4o-mini",
            "fallback_provider": "", "fallback_model": "",
            "max_tokens": 500, "temperature": 0.0,
        },
        "critique": {
            "provider": "openai", "model": "gpt-4o-mini",
            "fallback_provider": "", "fallback_model": "",
            "max_tokens": 500, "temperature": 0.0,
        },
        "compress": {
            "provider": "openai", "model": "gpt-4o-mini",
            "fallback_provider": "", "fallback_model": "",
            "max_tokens": 1000, "temperature": 0.0,
        },
        "default": {
            "provider": "openai", "model": "gpt-4o",
            "fallback_provider": "", "fallback_model": "",
            "max_tokens": 4096, "temperature": 0.0,
        },
    }

    def __init__(self) -> None:
        self._providers: dict[str, ProviderConfig] = {}
        self._purposes: dict[str, PurposeConfig] = {}
        self._clients: dict[str, LLMClient] = {}  # provider_name → cached client

        # Init default purposes
        for purpose, cfg in self.DEFAULT_PURPOSE_CONFIGS.items():
            self._purposes[purpose] = PurposeConfig(purpose=purpose, **cfg)

    # ── Provider management ───────────────────────────────────────────

    def add_provider(self, config: ProviderConfig) -> "ModelRegistry":
        """Register a provider. Returns self for chaining."""
        self._providers[config.name] = config
        # Clear cached client so it's recreated with new config
        self._clients.pop(config.name, None)
        return self

    def add_provider_from_dict(self, name: str, data: dict[str, Any]) -> "ModelRegistry":
        """Register a provider from a settings dict.

        data should have: base_url, and one of api_key / api_key_env.
        Optional: models (list of model names).
        """
        models = data.get("models", [])
        if isinstance(models, str):
            models = [m.strip() for m in models.split(",")]

        return self.add_provider(ProviderConfig(
            name=name,
            base_url=data.get("base_url", ""),
            api_key=data.get("api_key", ""),
            api_key_env=data.get("api_key_env", ""),
            models=models,
        ))

    def get_provider(self, name: str) -> ProviderConfig | None:
        return self._providers.get(name)

    def list_providers(self) -> list[str]:
        return list(self._providers.keys())

    def list_available_providers(self) -> list[dict[str, Any]]:
        """List providers that have a resolvable API key."""
        result: list[dict[str, Any]] = []
        for name, cfg in self._providers.items():
            key = cfg.resolve_api_key()
            result.append({
                "name": name,
                "base_url": cfg.base_url,
                "available": bool(key),
                "models": cfg.models,
            })
        return result

    # ── Purpose configuration ────────────────────────────────────────

    def set_purpose(
        self,
        purpose: str,
        provider: str,
        model: str,
        fallback_provider: str = "",
        fallback_model: str = "",
        max_tokens: int | None = None,
        temperature: float | None = None,
    ) -> "ModelRegistry":
        """Configure which (provider, model) to use for a purpose.

        Args:
            purpose: "reasoning" | "routing" | "critique" | "compress" | "default"
            provider: Provider name (must be registered)
            model: Model ID on that provider
            fallback_provider: Alternative provider if primary unavailable
            fallback_model: Alternative model if primary unavailable
        """
        existing = self._purposes.get(purpose)
        self._purposes[purpose] = PurposeConfig(
            purpose=purpose,
            provider=provider,
            model=model,
            fallback_provider=fallback_provider,
            fallback_model=fallback_model,
            max_tokens=max_tokens if max_tokens is not None else (
                existing.max_tokens if existing else 4096
            ),
            temperature=temperature if temperature is not None else (
                existing.temperature if existing else 0.0
            ),
        )
        return self

    def set_purpose_from_dict(
        self, purpose: str, data: dict[str, Any]
    ) -> "ModelRegistry":
        """Configure a purpose from a settings dict."""
        return self.set_purpose(
            purpose=purpose,
            provider=data.get("provider", ""),
            model=data.get("model", ""),
            fallback_provider=data.get("fallback_provider", ""),
            fallback_model=data.get("fallback_model", ""),
            max_tokens=data.get("max_tokens"),
            temperature=data.get("temperature"),
        )

    def get_purpose(self, purpose: str) -> PurposeConfig:
        """Get the configuration for a purpose. Falls back to 'default'."""
        if purpose in self._purposes:
            return self._purposes[purpose]
        return self._purposes.get("default", PurposeConfig(
            purpose="default", provider="", model="gpt-4o",
        ))

    # ── Bulk configuration from settings ──────────────────────────────

    def load_from_settings(self, settings: dict[str, Any]) -> "ModelRegistry":
        """Load providers and purposes from a settings dict.

        Expected structure:
        {
            "providers": {
                "deepseek": {"base_url": "...", "api_key_env": "...", "models": [...]},
                ...
            },
            "purposes": {
                "reasoning": {"provider": "...", "model": "...", ...},
                ...
            }
        }
        """
        # Load providers
        providers_data = settings.get("providers", {})
        if isinstance(providers_data, dict):
            for name, data in providers_data.items():
                if isinstance(data, dict):
                    self.add_provider_from_dict(name, data)

        # Load purposes
        purposes_data = settings.get("purposes", {})
        if isinstance(purposes_data, dict):
            for purpose, data in purposes_data.items():
                if isinstance(data, dict):
                    self.set_purpose_from_dict(purpose, data)

        return self

    # ── Client resolution ────────────────────────────────────────────

    def get_client_for_purpose(self, purpose: str) -> tuple[LLMClient, str]:
        """Get (client, model_id) for the given purpose.

        Resolution order:
        1. Primary (provider, model) — if provider is configured and has API key
        2. Fallback (provider, model) — if primary unavailable
        3. Search all providers for the model name
        4. Raise ValueError if nothing is available
        """
        purpose_cfg = self.get_purpose(purpose)

        # Try primary
        client_and_model = self._resolve(purpose_cfg.provider, purpose_cfg.model)
        if client_and_model:
            return client_and_model

        # Try fallback
        if purpose_cfg.fallback_provider and purpose_cfg.fallback_model:
            client_and_model = self._resolve(
                purpose_cfg.fallback_provider, purpose_cfg.fallback_model
            )
            if client_and_model:
                return client_and_model

        # Last resort: search all providers for the model name
        if purpose_cfg.model:
            for provider_name, provider_cfg in self._providers.items():
                if purpose_cfg.model in provider_cfg.models:
                    client_and_model = self._resolve(provider_name, purpose_cfg.model)
                    if client_and_model:
                        return client_and_model

        # Give a helpful error
        available = self.list_available_providers()
        available_names = [a["name"] for a in available if a["available"]]
        raise ValueError(
            f"No available model for purpose '{purpose}'. "
            f"Tried: provider={purpose_cfg.provider}, model={purpose_cfg.model}. "
            f"Available providers with keys: {available_names or 'none'}. "
            f"Configure via settings.yaml or set API key environment variables."
        )

    def get_client_for(self, provider: str, model: str) -> tuple[LLMClient, str] | None:
        """Get a client for a specific (provider, model) pair."""
        return self._resolve(provider, model)

    def _resolve(
        self, provider_name: str, model_id: str
    ) -> tuple[LLMClient, str] | None:
        """Attempt to create/resolve a (client, model_id) for a provider."""
        if not provider_name or not model_id:
            return None

        provider_cfg = self._providers.get(provider_name)
        if not provider_cfg:
            return None

        api_key = provider_cfg.resolve_api_key()
        if not api_key:
            return None

        # Cache clients per provider (lazy creation)
        if provider_name not in self._clients:
            self._clients[provider_name] = self._create_universal_client(
                provider_cfg, api_key
            )

        return self._clients[provider_name], model_id

    @staticmethod
    def _create_universal_client(
        provider_cfg: ProviderConfig, api_key: str
    ) -> LLMClient:
        """Create a client for any provider. All modern LLM APIs speak OpenAI protocol."""
        from vulnagent.llm.openai_client import OpenAIClient
        return OpenAIClient(
            api_key=api_key,
            base_url=provider_cfg.base_url.rstrip("/"),
        )

    # ── Status & introspection ────────────────────────────────────────

    def dump_config(self) -> dict[str, Any]:
        """Dump full configuration for debugging."""
        return {
            "providers": {
                name: {
                    "base_url": cfg.base_url,
                    "has_key": bool(cfg.resolve_api_key()),
                    "key_source": "direct" if cfg.api_key else (
                        f"env:{cfg.api_key_env}" if cfg.api_key_env else "none"
                    ),
                    "models": cfg.models,
                }
                for name, cfg in self._providers.items()
            },
            "purposes": {
                p: {
                    "provider": cfg.provider,
                    "model": cfg.model,
                    "fallback": f"{cfg.fallback_provider}/{cfg.fallback_model}" if cfg.fallback_provider else "none",
                    "max_tokens": cfg.max_tokens,
                }
                for p, cfg in self._purposes.items()
            },
        }

    def is_ready(self) -> bool:
        """Check if at least one provider is configured with an API key."""
        for cfg in self._providers.values():
            if cfg.resolve_api_key():
                return True
        return False
