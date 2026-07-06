"""Tool registry — manages tool definitions and generates LLM-compatible schemas."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable


@dataclass
class ToolDefinition:
    """A registered tool available to agents.

    Each tool has:
    - name/description: LLM-facing identity
    - parameters: JSON Schema for arguments
    - executor: callable that takes a params dict and returns ToolResult
    - compressor: optional output compressor (function from str → str)
    - category: "recon" | "web" | "crypto" | "binary" | "exploit" | "utility"
    - requires_network: whether the tool needs network access
    - risk_level: "safe" | "moderate" | "dangerous" — for sandbox decisions
    """

    name: str
    description: str
    parameters: dict[str, Any]
    executor: Callable[[dict[str, Any]], Any]  # ToolResult
    compressor: Callable[[str], str] | None = None
    category: str = "utility"
    requires_network: bool = False
    risk_level: str = "safe"


class ToolRegistry:
    """Registry for all tools available to agents.

    Usage:
        registry = ToolRegistry()
        registry.register(ToolDefinition(
            name="nmap_scan",
            description="Scan target with nmap for service discovery",
            parameters={...},
            executor=lambda params: ToolExecutor().execute(f"nmap {params['target']}"),
            compressor=micro_compressor.compress,
            category="recon",
            requires_network=True,
            risk_level="moderate",
        ))
        schema = registry.get_openai_schema(["nmap_scan"])
    """

    def __init__(self) -> None:
        self._tools: dict[str, ToolDefinition] = {}

    def register(self, tool: ToolDefinition) -> ToolRegistry:
        """Register a tool. Returns self for method chaining."""
        self._tools[tool.name] = tool
        return self

    def register_many(self, tools: list[ToolDefinition]) -> ToolRegistry:
        """Register multiple tools at once. Returns self for chaining."""
        for tool in tools:
            self._tools[tool.name] = tool
        return self

    def get(self, name: str) -> ToolDefinition | None:
        """Get a tool by name."""
        return self._tools.get(name)

    def list_all(self) -> list[ToolDefinition]:
        """Return all registered tools."""
        return list(self._tools.values())

    def list_by_category(self, category: str) -> list[ToolDefinition]:
        """Return tools filtered by category."""
        return [t for t in self._tools.values() if t.category == category]

    def list_safe(self) -> list[ToolDefinition]:
        """Return only tools with risk_level != 'dangerous'."""
        return [t for t in self._tools.values() if t.risk_level != "dangerous"]

    def list_names(self) -> list[str]:
        """Return all registered tool names."""
        return list(self._tools.keys())

    def get_openai_schema(
        self,
        names: list[str] | None = None,
    ) -> list[dict[str, Any]]:
        """Generate OpenAI-compatible function definitions for tools.

        Args:
            names: Specific tools to include. If None, includes ALL tools.

        Returns:
            List of {"type": "function", "function": {"name": ..., "description": ..., "parameters": ...}}
        """
        tools = [self._tools[n] for n in names] if names else list(self._tools.values())
        result: list[dict[str, Any]] = []
        for tool in tools:
            result.append({
                "type": "function",
                "function": {
                    "name": tool.name,
                    "description": tool.description,
                    "parameters": tool.parameters,
                },
            })
        return result

    def __len__(self) -> int:
        return len(self._tools)

    def __contains__(self, name: str) -> bool:
        return name in self._tools
