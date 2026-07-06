"""Flashbulb memory — high-salience event detection and prioritized storage.

Innovation: a FIVE-DIMENSION salience model specifically for security operations,
not general conversation events. The five dimensions evaluate how "memorable"
a security event is from multiple perspectives.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

from vulnagent.memory.hierarchical import HierarchicalMemory, MemoryEntry


@dataclass
class SalienceScores:
    """Five security-specific salience dimensions.

    Each dimension is 0.0–1.0. Composite is a weighted sum.
    """

    surprise: float = 0.0
    risk: float = 0.0
    success: float = 0.0
    failure: float = 0.0
    novelty: float = 0.0

    # Weights tuned for security scenarios
    # risk has highest weight (dangerous ops are always worth remembering)
    # failure next (learning from mistakes)
    WEIGHTS: dict[str, float] = field(default_factory=lambda: {
        "risk": 1.2,
        "success": 1.0,
        "failure": 1.1,
        "surprise": 0.9,
        "novelty": 0.8,
    })

    @property
    def composite(self) -> float:
        """Weighted composite score (capped at 1.0).

        Uses active-dimension normalization: divides by the number of
        dimensions that fired (> 0), minimum 2. This prevents dilution
        when only 1-2 dimensions are triggered.
        """
        dims = [
            self.surprise * self.WEIGHTS["surprise"],
            self.risk * self.WEIGHTS["risk"],
            self.success * self.WEIGHTS["success"],
            self.failure * self.WEIGHTS["failure"],
            self.novelty * self.WEIGHTS["novelty"],
        ]
        raw = sum(dims)
        active = sum(1 for d in dims if d > 0.01)
        divisor = max(active, 2)  # at minimum divide by 2
        return min(raw / divisor, 1.0)


class SalienceDetector:
    """Detects emotional salience of execution events using rules + optional LLM.

    The rule-based detection works for most cases. LLM is optionally injected
    for complex narrative analysis.

    Innovation: security-specific salience cues rather than generic conversation cues.
    """

    # Security-specific pattern triggers
    SUCCESS_PATTERNS = [
        "flag{", "FLAG{", "CTF{",
        "successfully exploited", "exploit succeeded",
        "got shell", "reverse shell connected",
        "privilege escalation successful",
    ]
    FAILURE_PATTERNS = [
        "segfault", "Segmentation fault", "connection refused",
        "permission denied", "access denied", "not found",
        "no such file", "command not found", "error:",
    ]
    RISK_PATTERNS = [
        "buffer overflow", "stack smashing", "heap corruption",
        "use-after-free", "double free", "null pointer dereference",
        "arbitrary code execution", "remote code execution",
    ]
    SURPRISE_PATTERNS = [
        "unusual", "unexpected", "surprisingly", "interesting",
        "never seen before", "anomalous",
    ]

    def __init__(self, llm_client: Any | None = None) -> None:
        self._llm = llm_client

    def analyze(
        self,
        event_text: str,
        context: dict[str, Any] | None = None,
    ) -> SalienceScores:
        """Analyze an execution event and return salience scores.

        Args:
            event_text: The event to analyze (tool output, agent reasoning, etc.)
            context: Optional context including 'expected_output', 'known_techniques', etc.

        Returns:
            SalienceScores with all five dimensions scored 0.0–1.0.
        """
        context = context or {}
        event_lower = event_text.lower()

        scores = SalienceScores()

        # ── Success detection ──
        for pattern in self.SUCCESS_PATTERNS:
            if pattern.lower() in event_lower:
                scores.success += 0.3
        scores.success = min(scores.success, 1.0)

        # Boost: first-time success is more salient
        if context.get("is_first_success"):
            scores.success = min(scores.success + 0.4, 1.0)

        # ── Failure detection ──
        for pattern in self.FAILURE_PATTERNS:
            if pattern.lower() in event_lower:
                scores.failure += 0.15
        scores.failure = min(scores.failure, 1.0)

        # Boost: repeated failure on same target
        if context.get("is_repeated_failure"):
            scores.failure = min(scores.failure + 0.3, 1.0)

        # ── Risk detection ──
        for pattern in self.RISK_PATTERNS:
            if pattern.lower() in event_lower:
                scores.risk += 0.25
        scores.risk = min(scores.risk, 1.0)

        # Boost: dangerous tool usage
        if context.get("risk_level") == "dangerous":
            scores.risk = min(scores.risk + 0.2, 1.0)

        # ── Surprise detection ──
        expected = context.get("expected_output", "")
        if expected:
            # Simple heuristic: if output is very different from expected
            expected_words = set(expected.lower().split())
            actual_words = set(event_lower.split())
            overlap = len(expected_words & actual_words) / max(len(expected_words), 1)
            if overlap < 0.3:
                scores.surprise = 0.7
        for pattern in self.SURPRISE_PATTERNS:
            if pattern.lower() in event_lower:
                scores.surprise += 0.2
        scores.surprise = min(scores.surprise, 1.0)

        # ── Novelty detection ──
        known_techniques = context.get("known_techniques", [])
        if known_techniques:
            # Check if any technique in event is unknown
            event_tech_keywords = ["union select", "stack pivot", "rop chain",
                                   "format string", "heap spray", "type juggling"]
            for keyword in event_tech_keywords:
                if keyword in event_lower and keyword not in [t.lower() for t in known_techniques]:
                    scores.novelty += 0.4
        else:
            # First run — everything is novel
            scores.novelty = 0.3
        scores.novelty = min(scores.novelty, 1.0)

        # Boost: if context says this technique isn't in the knowledge graph
        if context.get("is_new_to_kgraph"):
            scores.novelty = min(scores.novelty + 0.5, 1.0)

        return scores


class FlashbulbMemory:
    """Flashbulb memory — stores high-salience events with boosted weight.

    When an event's composite salience exceeds FLASHBULB_THRESHOLD, it gets:
    1. Permanent storage (immune to automatic eviction)
    2. Weight boost
    3. Related memory strengthening (consolidation)
    4. Narrative tag generation (CAUTION/CONFIDENCE/HINT)
    """

    FLASHBULB_THRESHOLD = 0.6

    def __init__(
        self,
        memory: HierarchicalMemory,
        detector: SalienceDetector | None = None,
    ) -> None:
        self.memory = memory
        self.detector = detector or SalienceDetector()

    def process_event(
        self,
        event_text: str,
        context: dict[str, Any] | None = None,
    ) -> str | None:
        """Process an execution event through flashbulb detection.

        If the event's composite salience exceeds the threshold:
        1. Create a MemoryEntry with the content
        2. Mark it as flashbulb in HierarchicalMemory
        3. Boost related memories' weights
        4. Return the memory ID

        Returns memory_id if flashbulb created, None otherwise.
        """
        scores = self.detector.analyze(event_text, context)

        if scores.composite < self.FLASHBULB_THRESHOLD:
            return None

        # Create flashbulb entry
        entry = MemoryEntry(
            content=event_text[:8000],  # keep first 8K chars
            layer="mid_term",  # flashbulbs go to at least mid-term
            timestamp=time.time(),
            weight=2.0,  # double weight for flashbulbs
            emotional_salience=scores.composite,
            narrative=self._narrative_from_scores(scores),
            tags=self._tags_from_scores(scores, context),
            source_task_id=context.get("task_id", "") if context else "",
        )

        memory_id = self.memory.add_mid_term(entry)
        self.memory.mark_flashbulb(memory_id)

        # Strengthen related memories
        self.consolidate(memory_id, scores.composite)

        return memory_id

    def consolidate(self, memory_id: str, salience: float) -> None:
        """Strengthen related memories via weight boost.

        Finds top-5 related memories by tag similarity and boosts their weight.
        High salience (> 0.8) also promotes the flashbulb to long-term.
        """
        # Boost the flashbulb itself
        self.memory.boost_weight(memory_id, factor=1.0 + salience)

        entry = self.memory.get_by_id(memory_id)
        if not entry:
            return

        # Find related memories by shared tags
        related: list[MemoryEntry] = []
        for tag in entry.tags:
            related.extend(self.memory.get_by_tag(tag, limit=3))

        # Deduplicate and boost top-5
        seen: set[str] = {memory_id}
        boosted = 0
        for rel in related:
            if rel.id in seen:
                continue
            seen.add(rel.id)
            self.memory.boost_weight(rel.id, factor=1.1)
            boosted += 1
            if boosted >= 5:
                break

        # High salience → promote to long-term
        if salience > 0.8:
            entry.layer = "long_term"
            self.memory.add_long_term(entry)

    def retrieve_flashbacks(
        self,
        query: str,
        top_k: int = 3,
    ) -> list[dict[str, Any]]:
        """Retrieve flashbulb memories relevant to the query.

        Returns enriched dicts with content, narrative, and emotional tag.
        """
        entries = self.memory.get_flashbulbs(limit=20)
        results: list[dict[str, Any]] = []

        query_lower = query.lower()
        query_words = set(query_lower.split())

        for entry in entries:
            content_lower = (entry.content or "").lower()
            score = sum(1 for w in query_words if w in content_lower)
            if score > 0:
                results.append({
                    "id": entry.id,
                    "content": entry.content[:2000],
                    "narrative": entry.narrative,
                    "emotional_tag": self._emotional_tag(entry.emotional_salience),
                    "salience": entry.emotional_salience,
                    "score": score,
                })

        results.sort(key=lambda x: (x["salience"], x["score"]), reverse=True)
        return results[:top_k]

    # ── Helpers ────────────────────────────────────────────────────

    @staticmethod
    def _emotional_tag(salience: float) -> str:
        """Map salience to a human-readable emotional tag."""
        if salience > 0.8:
            return "CAUTION"  # very memorable, potential danger
        if salience > 0.6:
            return "CONFIDENCE"  # successful approach, worth reusing
        return "HINT"  # mildly interesting, worth noting

    @staticmethod
    def _narrative_from_scores(scores: SalienceScores) -> str:
        """Generate a short narrative string from salience scores."""
        parts: list[str] = []
        if scores.success > 0.5:
            parts.append("SUCCESS")
        if scores.failure > 0.5:
            parts.append("FAILURE")
        if scores.risk > 0.5:
            parts.append("RISK")
        if scores.surprise > 0.5:
            parts.append("SURPRISE")
        if scores.novelty > 0.5:
            parts.append("NOVEL")
        if not parts:
            parts.append("NEUTRAL")
        return "|".join(parts)

    @staticmethod
    def _tags_from_scores(
        scores: SalienceScores, context: dict[str, Any] | None
    ) -> list[str]:
        """Generate tags from salience scores and context."""
        tags: list[str] = []
        if scores.success > 0.3:
            tags.append("success")
        if scores.failure > 0.3:
            tags.append("failure")
        if scores.risk > 0.3:
            tags.append("risk")
        if scores.novelty > 0.3:
            tags.append("novel")
        if context:
            if context.get("category"):
                tags.append(context["category"])
            if context.get("tool_name"):
                tags.append(context["tool_name"])
        return tags
