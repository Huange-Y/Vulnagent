"""Vulnerability research agent CLI entry point."""

from __future__ import annotations

# Suppress noisy langgraph serializer warnings before importing runtime modules.
import os as _os
import warnings as _warnings
try:
    from langchain_core._api.deprecation import (
        LangChainPendingDeprecationWarning as _LangChainPendingDeprecationWarning,
    )
except Exception:  # pragma: no cover - best effort import for warning suppression
    _LangChainPendingDeprecationWarning = PendingDeprecationWarning

_os.environ.setdefault("LANGGRAPH_ALLOWED_OBJECTS", "messages")
_warnings.filterwarnings("ignore", category=DeprecationWarning, module="langgraph")
_warnings.filterwarnings("ignore", category=PendingDeprecationWarning, module="langgraph")
_warnings.filterwarnings("ignore", category=_LangChainPendingDeprecationWarning)
_warnings.filterwarnings("ignore", message=".*allowed_objects.*")

import argparse
import json
import sys
from typing import Any

from vulnagent.paths import PROJECT_ROOT
from vulnagent.utils.dependency_check import print_dependency_report
from vulnagent.utils.settings import SettingsManager


def _ensure_workspace_root_on_path() -> None:
    workspace_root = str(PROJECT_ROOT.parent.resolve())
    if workspace_root not in sys.path:
        sys.path.insert(0, workspace_root)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Vuln Agent - Binary, firmware, and live-target research helper",
    )
    parser.add_argument("--target", default="", help="Target path, URL, host, or image to assess")
    parser.add_argument("--scope", default="", help="Operator-defined scope or intended environment")
    parser.add_argument("--max-iterations", type=int, default=None, help="Max iterations per agent")
    parser.add_argument("--token-budget", type=int, default=None, help="Token budget for the run")
    parser.add_argument("--model", default="", help="Override the reasoning model")
    parser.add_argument("--provider", default="", help="Override the reasoning provider")
    parser.add_argument(
        "--routing-model",
        default="",
        help="Override the routing, critique, and compression models",
    )
    parser.add_argument("--api-key", default="", help="API key for the primary provider")
    parser.add_argument("--verbose", action="store_true", help="Verbose output")
    parser.add_argument("--json", action="store_true", help="Output results as JSON")
    parser.add_argument("--status", action="store_true", help="Show provider/model configuration and exit")
    parser.add_argument(
        "--check-deps",
        action="store_true",
        help="Check external tool dependencies and exit",
    )
    parser.add_argument("--serve", action="store_true", help="Start the vulnagent Web workbench")
    parser.add_argument("--host", default="127.0.0.1", help="Host for --serve")
    parser.add_argument("--port", type=int, default=8080, help="Port for --serve")
    parser.add_argument("--no-sandbox", action="store_true", help="Skip Docker sandbox isolation")
    parser.add_argument("--emulation-mode", default="auto",
                        choices=["auto","agent","direct","off"],
                        help="Validation: auto/agent/direct/off")
    parser.add_argument("--no-angr", action="store_true", help="Skip angr symbolic execution (faster)")
    parser.add_argument("--auto-update-constraints", action="store_true",
                        help="Append new false positive patterns to constraints.yaml")
    parser.add_argument("--fuzz-timeout", type=int, default=300,
                        help="Timeout in seconds for fuzzing phase (default: 300)")
    parser.add_argument("--diff-with", default="",
                        help="Path to a second firmware image for differential analysis")
    parser.add_argument("--peripheral-profile", default="",
                        help="Force a specific peripheral profile for system-mode emulation")
    return parser


def _configure_registry(
    settings: SettingsManager,
    args: argparse.Namespace,
):
    registry = settings.create_model_registry()

    if args.api_key:
        primary_provider = (
            args.provider
            or settings.get("provider.primary", "")
            or registry.get_purpose("reasoning").provider
            or "openai"
        )
        provider = registry.get_provider(primary_provider)
        if provider is not None:
            provider.api_key = args.api_key

    if args.provider or args.model:
        _override_purpose(
            registry,
            "reasoning",
            provider=args.provider or None,
            model=args.model or None,
        )
        _override_purpose(
            registry,
            "default",
            provider=args.provider or None,
            model=args.model or None,
        )

    if args.routing_model:
        for purpose in ("routing", "critique", "compress"):
            _override_purpose(registry, purpose, model=args.routing_model)

    _prefer_available_provider(settings, registry, args)

    return registry


def _prefer_available_provider(
    settings: SettingsManager,
    registry,
    args: argparse.Namespace,
) -> None:
    if args.provider or args.model:
        return

    available = [item for item in registry.list_available_providers() if item.get("available")]
    if not available:
        return

    preferred_name = settings.get("provider.primary", "")
    selected = next((item for item in available if item.get("name") == preferred_name), available[0])

    for purpose in ("reasoning", "default", "routing", "critique", "compress"):
        current = registry.get_purpose(purpose)
        provider = registry.get_provider(current.provider)
        if provider is not None and provider.resolve_api_key():
            continue
        _override_purpose(
            registry,
            purpose,
            provider=selected["name"],
            model=_select_fallback_model(selected.get("models", []), purpose),
        )


def _select_fallback_model(models: list[str], purpose: str) -> str:
    if not models:
        return ""

    preference_map = {
        "reasoning": ("reason", "r1", "sonnet", "opus", "gpt-4"),
        "default": ("reason", "r1", "sonnet", "opus", "gpt-4"),
        "routing": ("mini", "chat", "haiku", "qwen"),
        "critique": ("mini", "chat", "haiku", "qwen"),
        "compress": ("mini", "chat", "haiku", "qwen"),
    }
    lowered = [(model, model.lower()) for model in models]
    for needle in preference_map.get(purpose, ()):
        for model, lowered_name in lowered:
            if needle in lowered_name:
                return model
    return models[0]


def _override_purpose(
    registry,
    purpose: str,
    *,
    provider: str | None = None,
    model: str | None = None,
) -> None:
    current = registry.get_purpose(purpose)
    registry.set_purpose(
        purpose,
        provider=provider or current.provider,
        model=model or current.model,
        fallback_provider=current.fallback_provider,
        fallback_model=current.fallback_model,
        max_tokens=current.max_tokens,
        temperature=current.temperature,
    )


def _print_status(settings: SettingsManager, registry) -> None:
    config = registry.dump_config()

    print("=== Provider Configuration ===")
    providers = config.get("providers", {})
    if providers:
        for name, provider in sorted(providers.items()):
            status = "READY" if provider.get("has_key") else "NO KEY"
            base_url = provider.get("base_url") or "(default)"
            key_source = provider.get("key_source") or "none"
            print(f"  {name}: {status} (key: {key_source}) -> {base_url}")
            models = provider.get("models", [])
            if models:
                print(f"    Models: {', '.join(models)}")
    else:
        print("  No providers configured.")

    print("\n=== Purpose Mapping ===")
    for purpose, mapping in sorted(config.get("purposes", {}).items()):
        fallback = mapping.get("fallback", "none")
        print(
            f"  {purpose}: {mapping.get('provider', '')}/{mapping.get('model', '')} "
            f"(max_tokens={mapping.get('max_tokens', 0)}, fallback={fallback})"
        )

    print("\n=== Config Paths ===")
    print(f"  project_root: {settings.project_root}")
    print(f"  project_config: {settings.project_config_file}")
    print(f"  project_local: {settings.project_local_config_file}")
    print(f"  user_config: {settings.user_config_file}")
    active_project = settings.find_config_file()
    print(f"  active_project_config: {active_project if active_project else '(not found)'}")
    if settings.legacy_workspace_config_file:
        print(f"  legacy_workspace: {settings.legacy_workspace_config_file}")
    print(f"  runtime_root: {PROJECT_ROOT / 'runtime' / 'vulnagent'}")
    print(f"  run_root: {settings.get('runtime.run_root', '')}")
    print(f"  execution_backend: {settings.get('runtime.execution_backend', 'local')}")
    remote_host = settings.get('remote.host', '')
    if remote_host:
        print(f"  remote_target: {remote_host}:{settings.get('remote.port', 22)}")

    ready = "yes" if registry.is_ready() else "no"
    print(f"\nReady: {ready}")


def _run_target(
    args: argparse.Namespace,
    settings: SettingsManager,
    registry,
) -> int:
    from vulnagent.llm import ModelRouter
    from vulnagent.orchestrator import VulnOrchestrator

    if not registry.is_ready():
        available = registry.list_available_providers()
        print("Error: No LLM provider configured with an API key.", file=sys.stderr)
        print("Configure via config/settings.yaml or environment variables.", file=sys.stderr)
        if available:
            print(
                f"Registered providers: {[item['name'] for item in available]}",
                file=sys.stderr,
            )
        print(
            "Set API keys via environment variables (for example OPENAI_API_KEY).",
            file=sys.stderr,
        )
        return 1

    if args.verbose:
        print(f"[Vuln Agent] target={args.target} scope={args.scope or '(none)'}")

    router = ModelRouter(registry)
    emulation_cfg = settings.get("emulation", {}) if args.emulation_mode != "off" else None
    result = VulnOrchestrator(
        router, use_sandbox=not args.no_sandbox,
        emulation_config=emulation_cfg,
    ).run(
        target=args.target,
        scope=args.scope,
        max_iterations=settings.get("agent.max_iterations", 5),
        token_limit=settings.get("agent.token_limit", 100000),
    )

    if args.json:
        print(json.dumps(result, indent=2, default=str))
        return 0

    if result.get("success"):
        print(result.get("report", ""))
        return 0

    if result.get("error"):
        print(str(result.get("error")), file=sys.stderr)
        return 1

    print("Vuln Agent: no report generated.", file=sys.stderr)
    return 1


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    settings = SettingsManager(project_root=PROJECT_ROOT).load()
    if args.verbose:
        settings.set("debug.verbose", True)
    if args.max_iterations is not None:
        settings.set("agent.max_iterations", args.max_iterations)
    if args.token_budget is not None:
        settings.set("agent.token_limit", args.token_budget)

    registry = _configure_registry(settings, args)

    if args.status:
        _print_status(settings, registry)
        return 0

    if args.check_deps:
        print_dependency_report()
        return 0

    if args.serve:
        _ensure_workspace_root_on_path()
        from vulnagent.server.app import start_server
        from vulnagent.llm import ModelRouter
        from vulnagent.orchestrator import VulnOrchestrator

        router = ModelRouter(registry)
        orchestrator = VulnOrchestrator(
            router, use_sandbox=not args.no_sandbox,
            emulation_config=settings.get("emulation", {}),
        )
        start_server(orchestrator, host=args.host, port=args.port, open_browser=not args.json)
        return 0

    if not args.target:
        parser.error("--target is required unless --status or --check-deps is used")

    return _run_target(args, settings, registry)


if __name__ == "__main__":
    raise SystemExit(main())
