"""Context compression module — the core innovation of the agent system.

Three-tier compression architecture:
    L1 (Micro):  Smart Truncation — rule-based, zero LLM cost
    L2 (Mid):    Anchored Structured Summarization — LLM with structural guarantees
    L3 (Deep):   Memory Consolidation — session → persistent knowledge

Also includes:
    - SmartTruncator: security-domain keyword-based truncation
    - AnchoredSummary: structured summary management (Factory AI pattern)
    - CompactionPrompt: standard prompts for LLM compaction
"""

from vulnagent.context.budget import BudgetManager, TokenBudget
from vulnagent.context.compressor import (
    BaseCompressor,
    MicroCompressor,
    MidCompressor,
    DeepCompressor,
)
from vulnagent.context.smart_truncate import SmartTruncator
from vulnagent.context.anchored_summary import (
    AnchoredSummary,
    CompactionPrompt,
    extract_structured_summary,
)

__all__ = [
    "TokenBudget",
    "BudgetManager",
    "BaseCompressor",
    "MicroCompressor",
    "MidCompressor",
    "DeepCompressor",
    "SmartTruncator",
    "AnchoredSummary",
    "CompactionPrompt",
    "extract_structured_summary",
]
