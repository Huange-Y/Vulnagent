"""Conditional edge helpers for graph framework routing."""

from __future__ import annotations

from typing import Callable

from vulnagent.core.state import AgentState


def create_conditional_edge(
    route_map: dict[str, str],
    key: str = "phase",
    default: str = "END",
) -> Callable[[AgentState], str]:
    """Create a routing function that maps a state key value to a node name.

    Usage:
        builder.add_conditional_edges(
            "source_node",
            create_conditional_edge({"routing": "router", "execution": "agent"}),
            {"router": "router_node", "agent": "agent_node", END: END},
        )
    """

    def route(state: AgentState) -> str:
        value = state.get(key, "")  # type: ignore[typeddict-unknown-key]
        return route_map.get(str(value), default)

    return route
