"""Core state schemas for the graph framework agent system.

All modules depend on these TypedDict contracts. Changes here impact everything.
"""

from __future__ import annotations

from typing import Annotated, Any, Sequence

from langgraph.graph.message import add_messages
from langchain_core.messages import BaseMessage
from typing_extensions import TypedDict


# ── Memory Block (Letta-inspired structured context unit) ──────────────

class MemoryBlock(TypedDict, total=False):
    """A size-limited, structured chunk of persistent context.

    Inspired by Letta's Memory Blocks: each block has a token_limit and
    priority that the CompactionScheduler uses to decide what to evict.
    """

    block_id: str
    label: str
    content: str
    token_limit: int
    priority: int  # 1-10, higher = keep longer


# ── Token Budget ────────────────────────────────────────────────────────

class TokenBudgetState(TypedDict):
    """Token budget tracking within AgentState."""

    total: int  # hard limit, e.g. 100000
    used: int  # consumed so far
    micro_threshold: float  # L1 trigger (default 0.6)
    mid_threshold: float  # L2 trigger (default 0.8)
    deep_threshold: float  # L3 trigger (default 0.95)


# ── Compaction State ────────────────────────────────────────────────────

class CompactionState(TypedDict, total=False):
    """Metadata tracking compaction lifecycle across an agent run."""

    compaction_count: int
    micro_compaction_count: int
    mid_compaction_count: int
    deep_compaction_count: int
    last_compaction_at_tokens: int
    micro_compact_threshold: float
    mid_compact_threshold: float
    deep_compact_threshold: float


# ── Agent State (the main graph state) ──────────────────────────────────

class AgentState(TypedDict, total=False):
    """The unified state object that flows through all graph framework nodes.

    Design decisions:
    - tool_outputs / compressed_outputs stored in state, NOT in messages[]
      (Watchtower pattern — avoids bloating the LLM context with raw tools)
    - memory_blocks for Letta-style structured persistent context
    - anchored_summary carries structured compression across compaction cycles
    - compaction tracks compression lifecycle metadata
    - executed_tools tracks tool call history independently of messages (survives compaction)
    """

    # ── graph framework built-in message list ──
    messages: Annotated[Sequence[BaseMessage], add_messages]

    # ── Task context ──
    task_description: str
    attachment_paths: list[str]

    # ── Tool results (stored here, not in messages[]) ──
    tool_outputs: dict[str, str]  # tool_name → raw output
    compressed_outputs: dict[str, str]  # tool_name → compressed output

    # ── Tool execution history (survives compaction - HackSynth pattern) ──
    executed_tools: list[dict[str, Any]]  # [{name, args_summary, result_summary, timestamp}]

    # ── Memory ──
    memory_blocks: dict[str, MemoryBlock]  # block_id → MemoryBlock
    memory_context: dict[str, list[dict[str, Any]]]  # {layer: [entries]}

    # ── Execution state ──
    current_agent: str  # which specialized agent is active
    iteration_count: int
    token_budget: TokenBudgetState
    phase: str  # routing | execution | compacting | verification | done
    final_result: str | None

    # ── Compaction ──
    compaction: CompactionState
    anchored_summary: dict[str, str]  # {scope, files, tools, decisions, findings, open, next}

    # ── Metadata ──
    metadata: dict[str, Any]
