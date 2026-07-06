"""Reflective retriever — proactive context evaluation (MemR3 pattern).

Innovation: Rather than just running a similarity search and hoping it's good enough,
the ReflectiveRetriever evaluates whether the retrieved context is SUFFICIENT for
the task at hand. If not, it triggers a broader, deeper search.

Also implements our Memory Pointer innovation: when information in context already
exists in better form in the knowledge graph, the retriever replaces raw text
with compact KG references (@kg:entity_id).
"""

from __future__ import annotations

from typing import Any

from vulnagent.core.state import AgentState
from vulnagent.memory.hierarchical import HierarchicalMemory, MemoryEntry


class ReflectiveRetriever:
    """Proactive memory retrieval that evaluates context sufficiency.

    Two-pass retrieval:
    1. First pass: keyword + tag search across all layers
    2. Evaluate: is this enough context for the task?
    3. If not → reflective pass: broader search, lower relevance threshold
    4. Memory Pointer optimization: replace long text with @kg references

    Usage:
        retriever = ReflectiveRetriever(memory, kg, llm)
        memory_context = retriever.retrieve(state)
    """

    def __init__(
        self,
        memory: HierarchicalMemory,
        kg: Any | None = None,  # KnowledgeGraph
        llm_client: Any | None = None,
    ) -> None:
        self.memory = memory
        self.kg = kg
        self._llm = llm_client

    def retrieve(self, state: AgentState) -> dict[str, list[dict[str, Any]]]:
        """Two-pass reflective retrieval for the given agent state.

        Returns:
            {
                "short_term": [{entry dicts}],
                "mid_term": [...],
                "long_term": [...],
                "flashbulb": [...],
            }
        """
        task = state.get("task_description", "")
        if not task:
            return {"short_term": [], "mid_term": [], "long_term": [], "flashbulb": []}

        # ── First pass ──
        st_entries = self.memory.retrieve(task, layers=["short_term"], top_k=5)
        mt_entries = self.memory.retrieve(task, layers=["mid_term"], top_k=10)
        lt_entries = self.memory.retrieve(task, layers=["long_term"], top_k=5)
        fb_entries = self.memory.get_flashbulbs(limit=5)

        result = {
            "short_term": self._entries_to_dicts(st_entries),
            "mid_term": self._entries_to_dicts(mt_entries),
            "long_term": self._entries_to_dicts(lt_entries),
            "flashbulb": self._entries_to_dicts(fb_entries),
        }

        # ── Evaluate sufficiency ──
        if self.is_context_sufficient(state, result):
            return result

        # ── Reflective pass: broader search ──
        return self.reflective_retrieve(state)

    def reflective_retrieve(
        self, state: AgentState
    ) -> dict[str, list[dict[str, Any]]]:
        """Broader, deeper search triggered when first pass is insufficient."""
        task = state.get("task_description", "")

        # Broader: lower relevance threshold, include more entries
        st_entries = self.memory.retrieve(task, layers=["short_term"], top_k=10)
        mt_entries = self.memory.retrieve(task, layers=["mid_term"], top_k=20)
        lt_entries = self.memory.retrieve(task, layers=["long_term"], top_k=10, min_salience=0.0)
        fb_entries = self.memory.get_flashbulbs(limit=10)

        # Also search by domain-relevant tags derived from the task
        enriched_mt = list(mt_entries)
        task_tags = self._extract_task_tags(task)
        for tag in task_tags:
            tag_matches = self.memory.get_by_tag(tag, limit=5)
            for entry in tag_matches:
                if entry not in enriched_mt:
                    enriched_mt.append(entry)

        # If we have a knowledge graph, also do path-based retrieval
        kg_context: list[dict[str, Any]] = []
        if self.kg:
            kg_context = self._retrieve_from_kg(task)

        result = {
            "short_term": self._entries_to_dicts(st_entries),
            "mid_term": self._entries_to_dicts(enriched_mt[:20]),
            "long_term": self._entries_to_dicts(lt_entries),
            "flashbulb": self._entries_to_dicts(fb_entries),
            "kg_context": kg_context,
        }

        return result

    def is_context_sufficient(
        self,
        state: AgentState,
        retrieved: dict[str, list[dict[str, Any]]],
    ) -> bool:
        """Evaluate whether retrieved context is sufficient for the task.

        Heuristic check (no LLM):
        - At least 3 entries total across layers
        - At least 1 flashbulb if task looks similar to known patterns

        LLM check (if available):
        - "Given this task and these retrieved memories, is more context needed?"
        """
        all_entries = (
            retrieved.get("short_term", [])
            + retrieved.get("mid_term", [])
            + retrieved.get("long_term", [])
        )
        if not all_entries:
            return False

        if self._llm and len(all_entries) <= 3:
            # Too few entries — let LLM decide if deeper search is needed
            try:
                task = state.get("task_description", "")
                entries_text = "\n".join(
                    e.get("content", "")[:200] for e in all_entries
                )
                response = self._llm.invoke(
                    messages=[
                        {"role": "system", "content": (
                            "You are evaluating memory retrieval quality. "
                            "Given the task and retrieved memories, answer ONLY 'yes' or 'no': "
                            "is the retrieved context sufficient to work on this task? "
                            "Answer 'no' only if clearly missing critical information."
                        )},
                        {"role": "user", "content": (
                            f"Task: {task}\n\nRetrieved memories:\n{entries_text}"
                        )},
                    ],
                    model="",
                    max_tokens=10,
                )
                return response.content.strip().lower().startswith("yes")
            except Exception:
                pass

        return len(all_entries) >= 3

    # ── Knowledge Graph integration (Memory Pointer innovation) ─────

    def resolve_memory_pointer(self, reference: str) -> str | None:
        """Resolve a @memory: or @kg: pointer to expanded content.

        Args:
            reference: A memory pointer string like "@kg:cve-2021-41773"
                      or "@memory:st_1712345678_abc123"

        Returns:
            Expanded content string if found, None otherwise.
        """
        if reference.startswith("@kg:") and self.kg:
            entity_id = reference[4:]
            entity = self.kg.get_entity(entity_id)
            if entity:
                neighbors = self.kg.get_neighbors(entity_id, radius=1)
                neighbor_text = ", ".join(
                    n.id for n in neighbors[:5]
                )
                return (
                    f"[{entity.type.upper()}] {entity.id}: "
                    f"{entity.properties} "
                    f"(related: {neighbor_text})"
                )

        if reference.startswith("@memory:"):
            memory_id = reference[8:]
            entry = self.memory.get_by_id(memory_id)
            if entry:
                return entry.content[:2000]

        return None

    # ── Helpers ────────────────────────────────────────────────────

    @staticmethod
    def _entries_to_dicts(entries: list[MemoryEntry]) -> list[dict[str, Any]]:
        """Convert MemoryEntry list to serializable dicts."""
        return [
            {
                "id": e.id,
                "content": e.content[:2000],
                "layer": e.layer,
                "weight": e.weight,
                "emotional_salience": e.emotional_salience,
                "narrative": e.narrative,
                "tags": e.tags,
                "timestamp": e.timestamp,
            }
            for e in entries
        ]

    @staticmethod
    def _extract_task_tags(task: str) -> list[str]:
        """Extract domain tags from the task description."""
        tags: list[str] = []
        task_lower = task.lower()

        tag_map = {
            "web": ["web", "http", "xss", "sql", "injection", "cookie", "session"],
            "crypto": ["crypto", "cipher", "encrypt", "xor", "rsa", "aes", "base64"],
            "pwn": ["pwn", "buffer", "overflow", "shellcode", "rop", "binary", "elf"],
            "reverse": ["reverse", "decompile", "disassemble", "ida", "ghidra"],
        }

        for tag, keywords in tag_map.items():
            if any(kw in task_lower for kw in keywords):
                tags.append(tag)
                for kw in keywords:
                    if kw in task_lower:
                        tags.append(kw)

        return list(set(tags))

    def _retrieve_from_kg(self, task: str) -> list[dict[str, Any]]:
        """Retrieve relevant knowledge from the knowledge graph."""
        if not self.kg:
            return []

        results: list[dict[str, Any]] = []

        # Search for matching entities
        entities = self.kg.search_entities(task, top_k=5)
        for entity in entities:
            attack_paths = self.kg.find_attack_paths(entity.id, target_type="payload")
            entity_data = {
                "entity_id": entity.id,
                "entity_type": entity.type,
                "properties": entity.properties,
                "attack_paths": [
                    {
                        "path": " → ".join(p["path"]),
                        "edges": p["edges"],
                        "payload_transfer": p["target_payload_transfer"],
                    }
                    for p in attack_paths[:3]
                ],
            }
            results.append(entity_data)

        return results


class RetrievalScorer:
    """Scores and ranks retrieval results for context window optimization.

    Used to decide which retrieved memories to actually inject into context
    when the total retrieved content exceeds the allocation budget.
    """

    @staticmethod
    def score_entry(
        entry: dict[str, Any],
        query: str,
        preference: str = "balanced",
    ) -> float:
        """Score a single entry for context inclusion priority.

        Args:
            entry: The memory entry dict
            query: The current task/query
            preference: "recent" | "salient" | "diverse" | "balanced"
        """
        score = 0.0
        query_words = set(query.lower().split())

        # Content relevance
        content = entry.get("content", "").lower()
        content_score = sum(1 for w in query_words if w in content) / max(len(query_words), 1)
        score += content_score * 3.0

        # Salience boost
        score += entry.get("emotional_salience", 0.0) * 2.0

        # Flashbulb boost
        if entry.get("emotional_salience", 0.0) > 0.6:
            score += 5.0

        # Recency
        timestamp = entry.get("timestamp", 0)
        if timestamp > 0:
            import time
            age_hours = (time.time() - timestamp) / 3600
            recency_score = max(0, 1.0 - age_hours / 168)  # decay over 7 days
            if preference == "recent":
                recency_score *= 2.0
            score += recency_score * 1.0

        # Weight
        score += entry.get("weight", 1.0) * 0.5

        return score
