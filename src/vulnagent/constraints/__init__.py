"""Vulnagent constraint system — external hard rules, not prompt suggestions.

Design principle (from article):
    Constraints > Teaching. Model already has security knowledge.
    External enforcement > Self-checking. LLM cannot grade its own exam.
"""

from .engine import ConstraintEngine
from .rules import (
    GarbageFindingList,
    DecisionTree,
    CheatCard,
    load_constraints,
)

__all__ = [
    "ConstraintEngine",
    "GarbageFindingList",
    "DecisionTree",
    "CheatCard",
    "load_constraints",
]
