"""Model Router — routes LLM calls to the appropriate (provider, model) by purpose.

All agent code calls THIS instead of LLMClient directly. The router:
1. Selects the right (provider, model) for each call purpose
2. Handles fallback chains when a provider/model is unavailable
3. Tracks per-purpose usage and cost estimates
4. Supports runtime overrides per call

Usage:
    router = ModelRouter(registry)

    # Reasoning → uses the provider/model configured for "reasoning" purpose
    response = router.reason(messages=[...], tools=[...])

    # Routing → cheap model via purpose config
    response = router.route(messages=[...])

    # Override per call
    response = router.invoke(messages=[...], purpose="reasoning",
                             provider_override="openrouter", model_override="gpt-4o")
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from vulnagent.llm.client import LLMResponse
from vulnagent.llm.model_registry import ModelRegistry, PurposeConfig


def _is_tool_calls_format_error(error_text: str) -> bool:
    """Detect tool_calls format errors that indicate a provider compatibility issue.

    DeepSeek and some other non-OpenAI providers require strict ordering of
    assistant(tool_calls) → tool(message) messages. When this check fails,
    we auto-switch to a GPT-compatible provider.
    """
    lowered = error_text.lower()
    # Unique DeepSeek message-format error — different from generic tool failures
    markers = [
        "insufficient tool messages following tool_calls",
        "an assistant message with 'tool_calls' must be followed",
        "tool_calls must be followed by tool messages responding",
    ]
    return any(marker in lowered for marker in markers)


@dataclass
class RouterStats:
    """Per-purpose usage and cost tracking."""
    calls: int = 0
    tokens_in: int = 0
    tokens_out: int = 0
    total_cost_estimate: float = 0.0
    providers_used: dict[str, int] = field(default_factory=dict)


class ModelRouter:
    """Routes LLM calls to the best model for each purpose.

    All agents, critics, compressors, and classifiers call this instead of
    calling LLMClient directly. The router transparently:
    - Selects the right provider and model for each purpose
    - Falls back to alternatives if primary is unavailable
    - Tracks per-purpose cost and usage
    - Allows per-call overrides

    Usage:
        router = ModelRouter(registry)

        # Different purposes → different models automatically
        router.reason([{"role": "user", "content": "Analyze this binary..."}])
        router.route([{"role": "user", "content": "Classify: web or crypto?"}])
        router.critique([{"role": "user", "content": "Why did the exploit fail?"}])
        router.compress([{"role": "user", "content": "Summarize this nmap output"}])
    """

    # Approximate cost per 1M input tokens for common models (USD)
    _COST_PER_M_INPUT: dict[str, float] = {
        "gpt-4o": 2.50,
        "gpt-4o-mini": 0.15,
        "o1": 15.00,
        "o3-mini": 1.10,
        "deepseek-chat": 0.27,
        "deepseek-reasoner": 0.55,
        "gpt-4o-mini": 3.00,
        "gpt-4o": 15.00,
        "gpt-4o-mini": 0.80,
    }
    _DEFAULT_COST_PER_M = 2.0  # fallback estimate

    def __init__(self, registry: ModelRegistry) -> None:
        self.registry = registry
        self._stats: dict[str, RouterStats] = {}

    @property
    def stats(self) -> dict[str, RouterStats]:
        return dict(self._stats)

    # ── Main invoke ─────────────────────────────────────────────────

    def invoke(
        self,
        messages: list[dict[str, Any]],
        *,
        purpose: str = "default",
        tools: list[dict[str, Any]] | None = None,
        tool_choice: str = "auto",
        max_tokens: int | None = None,
        temperature: float | None = None,
        provider_override: str = "",
        model_override: str = "",
        **kwargs: Any,
    ) -> LLMResponse:
        """Send messages using the best model for the given purpose.

        Args:
            messages: Chat messages in provider-neutral dict format
            purpose: "reasoning" | "routing" | "critique" | "compress" | "default"
            tools: Optional tool definitions for function calling
            provider_override: Use this provider instead of the purpose default
            model_override: Use this model instead of the purpose default

        Returns:
            LLMResponse with normalized content, tool_calls, usage.
        """
        purpose_cfg = self.registry.get_purpose(purpose)

        candidates = self._client_candidates(
            purpose=purpose,
            provider_override=provider_override,
            model_override=model_override,
        )

        last_error: Exception | None = None
        attempted: list[str] = []
        for provider_name, client, model_id in candidates:
            attempted.append(f"{provider_name}/{model_id}")
            try:
                response = client.invoke(
                    messages=messages,
                    model=model_id,
                    tools=tools,
                    tool_choice=tool_choice,
                    max_tokens=max_tokens or purpose_cfg.max_tokens,
                    temperature=(
                        temperature if temperature is not None else purpose_cfg.temperature
                    ),
                    **kwargs,
                )
            except Exception as exc:
                last_error = exc
                continue

            self._track(purpose, model_id, response)
            return response

        # Auto cross-provider fallback when tool_calls format errors occur
        # (e.g., DeepSeek requires strict tool_calls→tool_messages ordering).
        if last_error and tools and _is_tool_calls_format_error(str(last_error)):
            cross_candidates = self._cross_provider_candidates(purpose, attempted)
            for provider_name, client, model_id in cross_candidates:
                attempted.append(f"{provider_name}/{model_id} (retry)")
                try:
                    response = client.invoke(
                        messages=messages, model=model_id, tools=tools,
                        tool_choice=tool_choice,
                        max_tokens=max_tokens or purpose_cfg.max_tokens,
                        temperature=temperature if temperature is not None else purpose_cfg.temperature,
                        **kwargs,
                    )
                except Exception:
                    continue
                self._track(purpose, model_id, response)
                return response

        if last_error:
            attempted_text = ", ".join(attempted) or "none"
            raise RuntimeError(
                f"LLM call failed for purpose '{purpose}' after trying: "
                f"{attempted_text}. Last error: {last_error}"
            ) from last_error

        self.registry.get_client_for_purpose(purpose)
        raise RuntimeError(f"No LLM candidates available for purpose '{purpose}'")

    # ── Convenience methods ────────────────────────────────────────

    def reason(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None = None,
        **kwargs: Any,
    ) -> LLMResponse:
        """Call the reasoning model (strongest, most expensive)."""
        return self.invoke(messages, purpose="reasoning", tools=tools, **kwargs)

    def route(
        self,
        messages: list[dict[str, Any]],
        **kwargs: Any,
    ) -> LLMResponse:
        """Call the routing model (cheap, fast — for classification)."""
        return self.invoke(messages, purpose="routing", temperature=0.0, **kwargs)

    def critique(
        self,
        messages: list[dict[str, Any]],
        **kwargs: Any,
    ) -> LLMResponse:
        """Call the critique model (cheap — for failure analysis)."""
        return self.invoke(messages, purpose="critique", temperature=0.0, **kwargs)

    def compress(
        self,
        messages: list[dict[str, Any]],
        **kwargs: Any,
    ) -> LLMResponse:
        """Call the compression model (cheap — for summarization)."""
        return self.invoke(messages, purpose="compress", temperature=0.0, **kwargs)

    def _client_candidates(
        self,
        *,
        purpose: str,
        provider_override: str = "",
        model_override: str = "",
    ) -> list[tuple[str, Any, str]]:
        """Return runtime fallback candidates in resolution order."""
        purpose_cfg = self.registry.get_purpose(purpose)
        candidates: list[tuple[str, Any, str]] = []
        seen: set[tuple[str, str]] = set()

        def add(provider: str, model: str) -> None:
            if not provider or not model:
                return
            key = (provider, model)
            if key in seen:
                return
            resolved = self.registry.get_client_for(provider, model)
            if not resolved:
                return
            client, model_id = resolved
            candidates.append((provider, client, model_id))
            seen.add(key)

        if provider_override and model_override:
            add(provider_override, model_override)

        add(purpose_cfg.provider, purpose_cfg.model)
        add(purpose_cfg.fallback_provider, purpose_cfg.fallback_model)

        # Match ModelRegistry's last-resort behavior: search configured providers
        # for the requested model name. This keeps runtime fallback behavior in
        # sync with client resolution while still letting us catch invoke errors.
        providers = getattr(self.registry, "_providers", {})
        if purpose_cfg.model and isinstance(providers, dict):
            for provider_name, provider_cfg in providers.items():
                if purpose_cfg.model in getattr(provider_cfg, "models", []):
                    add(provider_name, purpose_cfg.model)

        return candidates

    # ── Runtime overrides ──────────────────────────────────────────

    def use_cheap_for_all(self) -> "ModelRouter":
        """Switch all purposes to the cheapest available models. For testing/debug."""
        # Find the cheapest available provider+model
        available = self.registry.list_available_providers()
        cheap_provider = ""
        cheap_model = ""

        for prov in available:
            if prov["available"] and prov["models"]:
                cheap_provider = prov["name"]
                cheap_model = prov["models"][0]
                break

        if cheap_provider:
            for purpose in ["reasoning", "routing", "critique", "compress", "default"]:
                self.registry.set_purpose(
                    purpose, provider=cheap_provider, model=cheap_model
                )

        return self

    # ── Stats ──────────────────────────────────────────────────────

    def usage_report(self) -> str:
        """Generate a human-readable usage report."""
        lines = ["=== Model Usage Report ==="]
        total_cost = 0.0
        for purpose, stats in self._stats.items():
            providers = ", ".join(
                f"{p}:{c}" for p, c in stats.providers_used.items()
            )
            lines.append(
                f"  {purpose}: {stats.calls} calls, "
                f"{stats.tokens_in}+{stats.tokens_out} tokens, "
                f"~${stats.total_cost_estimate:.4f} "
                f"[{providers}]"
            )
            total_cost += stats.total_cost_estimate
        lines.append(f"  TOTAL: ~${total_cost:.4f}")
        return "\n".join(lines)

    # ── Internal ───────────────────────────────────────────────────

    def _cross_provider_candidates(
        self,
        purpose: str,
        already_attempted: list[str],
    ) -> list[tuple[str, Any, str]]:
        """Find candidates from a different provider family (GPT-compatible).

        Used when tool_calls format errors occur on non-GPT providers.
        Scans all configured providers, skips already-attempted, and
        prefers GPT-native providers (codework/openai/local).
        """
        candidates: list[tuple[str, Any, str]] = []
        attempted_providers: set[str] = set()
        for entry in already_attempted:
            provider = entry.split("/")[0].lower() if "/" in entry else entry.lower()
            attempted_providers.add(provider)

        # Prefer GPT-native providers, then any other available
        gpt_preferred = ["codework", "openai", "local"]
        providers_cfg = getattr(self.registry, "_providers", {}) or {}
        ordered_names = list(gpt_preferred) + [n for n in providers_cfg if n not in gpt_preferred]

        for provider_name in ordered_names:
            if provider_name.lower() in attempted_providers:
                continue
            cfg = providers_cfg.get(provider_name)
            if not cfg:
                continue
            models = getattr(cfg, "models", []) or []
            for model in models:
                resolved = self.registry.get_client_for(provider_name, model)
                if resolved:
                    client, model_id = resolved
                    if model_id:
                        candidates.append((provider_name, client, model_id))
                    break  # One model per provider is enough for cross-fallback

        return candidates

    def _track(
        self, purpose: str, model_id: str, response: LLMResponse
    ) -> None:
        """Record usage for cost tracking."""
        if purpose not in self._stats:
            self._stats[purpose] = RouterStats()

        s = self._stats[purpose]
        s.calls += 1
        s.tokens_in += response.usage.prompt_tokens
        s.tokens_out += response.usage.completion_tokens

        # Per-provider tracking
        # Extract provider from model_id (heuristic)
        provider = model_id.split("/")[0] if "/" in model_id else model_id
        if provider not in s.providers_used:
            s.providers_used[provider] = 0
        s.providers_used[provider] += 1

        # Cost estimate
        cost_per_m = self._COST_PER_M_INPUT.get(model_id, self._DEFAULT_COST_PER_M)
        s.total_cost_estimate += (
            (response.usage.prompt_tokens / 1_000_000) * cost_per_m
            + (response.usage.completion_tokens / 1_000_000) * cost_per_m * 4
        )
