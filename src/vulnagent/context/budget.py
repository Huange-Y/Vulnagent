"""Token budget tracking and dual-threshold compaction triggers.

The BudgetManager is the foundation for all compaction decisions.
It replaces simple token counting with context-aware scheduling.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class TokenBudget:
    """Configuration for token budget with three compaction thresholds.

    Inspired by the editor's micro-compact / full-compact model but
    with three tiers (L1/L2/L3) instead of two.
    """

    total_limit: int = 100000
    micro_threshold: float = 0.60  # L1: Smart Truncation of tool outputs
    mid_threshold: float = 0.80  # L2: Anchored Structured Summarization
    deep_threshold: float = 0.95  # L3: Session → persistent memory consolidation
    hard_stop: bool = True  # if True, refuse LLM calls when exceeded
    tokens_used: int = 0


class BudgetManager:
    """Tracks and enforces token budget across a graph execution.

    Key innovation: focuses on tokens-per-task (not tokens-per-request).
    Aggressive compression that forces re-work is worse than moderate compression.

    Usage:
        budget = TokenBudget(total_limit=100000)
        mgr = BudgetManager(budget)
        if mgr.can_call_llm(2000):
            mgr.record_usage(1500, 500)
        level = mgr.should_compact()
    """

    def __init__(self, budget: TokenBudget | None = None) -> None:
        self.budget = budget or TokenBudget()
        self._task_token_history: list[int] = []  # tokens per task

    def can_call_llm(self, estimated_input_tokens: int) -> bool:
        """Check if estimated tokens would exceed the hard limit."""
        remaining = self.budget.total_limit - self.budget.tokens_used
        return remaining > estimated_input_tokens

    def record_usage(self, prompt_tokens: int, completion_tokens: int) -> None:
        """Record token usage after an LLM call."""
        total = prompt_tokens + completion_tokens
        self.budget.tokens_used += total
        if self.budget.hard_stop and self.budget.tokens_used > self.budget.total_limit:
            from vulnagent.utils.errors import TokenBudgetExceeded
            raise TokenBudgetExceeded(
                used=self.budget.tokens_used,
                limit=self.budget.total_limit,
            )

    def record_per_task(self, total_tokens: int) -> None:
        """Record total tokens consumed for a completed task."""
        self._task_token_history.append(total_tokens)

    def should_compact(self) -> str:
        """Return the compaction level needed based on current usage.

        Returns: "micro_compact" | "mid_compact" | "deep_compact" | "none"
        """
        if self.budget.total_limit <= 0:
            return "none"
        ratio = self.budget.tokens_used / self.budget.total_limit

        if ratio >= self.budget.deep_threshold:
            return "deep_compact"
        if ratio >= self.budget.mid_threshold:
            return "mid_compact"
        if ratio >= self.budget.micro_threshold:
            return "micro_compact"
        return "none"

    def usage_ratio(self) -> float:
        """Return current usage ratio (0.0 to 1.0+)."""
        if self.budget.total_limit <= 0:
            return 0.0
        return self.budget.tokens_used / self.budget.total_limit

    def should_restore_files(self, count: int, tokens: int) -> bool:
        """Post-compaction rehydration budget (inspired by the editor).

        the editor restores max 5 files at 5K tokens each after compaction.
        We apply similar limits to prevent immediate re-compaction.
        """
        max_files = 5
        max_tokens_per_file = 5000
        max_total_restore = 50000
        return count <= max_files and tokens <= max_tokens_per_file * count and tokens <= max_total_restore

    def tokens_per_task_average(self) -> float:
        """Average tokens consumed per completed task."""
        if not self._task_token_history:
            return 0.0
        return sum(self._task_token_history) / len(self._task_token_history)

    def reset_for_new_task(self) -> None:
        """Reset usage counter for a new task (keep budget config)."""
        self.budget.tokens_used = 0

    def summarize(self) -> dict:
        """Return a summary of current budget state."""
        return {
            "used": self.budget.tokens_used,
            "limit": self.budget.total_limit,
            "ratio": round(self.usage_ratio(), 3),
            "level": self.should_compact(),
            "tasks_completed": len(self._task_token_history),
            "avg_tokens_per_task": round(self.tokens_per_task_average(), 0),
        }
