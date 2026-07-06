"""Memory consolidator — compresses, abstracts, and promotes memories across tiers.

Handles:
- Short → Mid term compression (structured summarization)
- Mid → Long term abstraction (pattern extraction)
- Narrative generation for flashbulb memories
- Knowledge graph update from memory content
"""

from __future__ import annotations

import time
from typing import Any

from vulnagent.memory.hierarchical import HierarchicalMemory, MemoryEntry
from vulnagent.memory.kgraph import Entity, KnowledgeGraph, Relation


class MemoryConsolidator:
    """Handles memory promotion, compression, and narrative generation.

    Uses LLM for semantic compression but also includes rule-based
    extraction for structured knowledge graph updates.

    Usage:
        consolidator = MemoryConsolidator(llm, kgraph)
        compressed = consolidator.compress_for_mid_term([entry1, entry2, entry3])
        abstracted = consolidator.abstract_for_long_term([entry4, entry5])
    """

    def __init__(
        self,
        llm_client: Any | None = None,
        kg: KnowledgeGraph | None = None,
    ) -> None:
        self._llm = llm_client
        self.kg = kg

    def compress_for_mid_term(
        self,
        entries: list[MemoryEntry],
    ) -> MemoryEntry:
        """Compress multiple short-term entries into one structured mid-term entry.

        Extracts: goal, approach, key_findings, outcome, lessons.
        Uses LLM if available, otherwise heuristic compression.
        """
        if not entries:
            return MemoryEntry()

        combined_content = "\n\n---\n".join(
            e.content[:500] for e in entries
        )
        tags = list(set(tag for e in entries for tag in e.tags))

        if self._llm:
            summary = self._llm_summarize(
                combined_content,
                prompt=(
                    "You are a memory compressor for a CTF/security agent. "
                    "Compress the following tool execution traces into a structured summary. "
                    "Output exactly these fields, each on its own line:\n"
                    "GOAL: <what was being attempted>\n"
                    "APPROACH: <the method/strategy used>\n"
                    "KEY_FINDINGS: <critical discoveries — ports, vulnerabilities, flags>\n"
                    "OUTCOME: <success/failure/partial>\n"
                    "LESSONS: <what should be remembered for next time>\n"
                    "Keep the TOTAL output under 500 tokens. Be concise."
                ),
            )
        else:
            summary = self._heuristic_summarize(combined_content, entries)

        # Extract max salience
        max_salience = max((e.emotional_salience for e in entries), default=0.0)

        return MemoryEntry(
            content=summary,
            layer="mid_term",
            timestamp=time.time(),
            emotional_salience=max_salience,
            tags=tags,
            source_task_id=entries[0].source_task_id if entries else "",
        )

    def abstract_for_long_term(
        self,
        entries: list[MemoryEntry],
    ) -> MemoryEntry:
        """Abstract mid-term entries into a long-term knowledge entry.

        Extracts: technique_patterns, common_pitfalls, success_templates.
        """
        if not entries:
            return MemoryEntry()

        combined = "\n\n---\n".join(
            e.content[:300] for e in entries
        )
        tags = list(set(tag for e in entries for tag in e.tags))

        if self._llm:
            abstract = self._llm_summarize(
                combined,
                prompt=(
                    "You are a knowledge abstractor for a security agent. "
                    "Extract reusable security knowledge from these experiences. "
                    "Output exactly:\n"
                    "TECHNIQUE_PATTERNS: <recurring techniques and when they work>\n"
                    "COMMON_PITFALLS: <frequent mistakes or dead ends>\n"
                    "SUCCESS_TEMPLATES: <proven workflows for similar problems>\n"
                    "Keep under 300 tokens."
                ),
            )
        else:
            abstract = (
                f"TECHNIQUE_PATTERNS: {self._extract_keywords(combined)}\n"
                "COMMON_PITFALLS: (no LLM — heuristic only)\n"
                "SUCCESS_TEMPLATES: (no LLM — heuristic only)"
            )

        max_salience = max((e.emotional_salience for e in entries), default=0.0)

        return MemoryEntry(
            content=abstract,
            layer="long_term",
            timestamp=time.time(),
            ttl=None,  # long-term is permanent
            weight=1.0,
            emotional_salience=max_salience,
            tags=tags + ["abstracted"],
            source_task_id=entries[0].source_task_id if entries else "",
        )

    def generate_narrative(
        self,
        memory: MemoryEntry,
        related: list[MemoryEntry],
    ) -> str:
        """Generate a human-readable "story" for a flashbulb memory.

        Example output:
            "When exploiting PHP deserialization, always check __wakeup() first.
             During CTF X, missing this check cost 30 minutes."
        """
        if not self._llm:
            return memory.narrative or ""

        context = f"Current event:\n{memory.content[:1000]}\n\n"
        if related:
            context += f"Related experiences:\n"
            for r in related[:3]:
                context += f"- {r.content[:200]}\n"

        narrative = self._llm_summarize(
            context,
            prompt=(
                "Write a 1-2 sentence 'security story' that captures the lesson "
                "from this event. Make it specific enough to be useful as a future "
                "reference. Include concrete details (tool names, specific techniques)."
            ),
        )
        return narrative.strip()

    def update_knowledge_graph(self, memory: MemoryEntry) -> None:
        """Extract entities and relations from memory content and add to KG."""
        if not self.kg:
            return

        content = memory.content.lower()
        tags = memory.tags

        # Extract service:version entities
        version_patterns = [
            ("apache", r"apache[/\s](\d+\.\d+(?:\.\d+)?)"),
            ("nginx", r"nginx[/\s](\d+\.\d+(?:\.\d+)?)"),
            ("openssh", r"openssh[/\s_]([\d.]+)"),
            ("mysql", r"mysql[/\s](\d+\.\d+(?:\.\d+)?)"),
            ("php", r"php[/\s](\d+\.\d+(?:\.\d+)?)"),
        ]

        import re

        for service, pattern in version_patterns:
            match = re.search(pattern, memory.content.lower())
            if match:
                version = match.group(1)
                service_entity = f"service:{service}/{version}"
                self.kg.add_entity(Entity(service_entity, "service", {
                    "name": service,
                    "version": version,
                }))

                for tag in tags:
                    if tag.startswith("cve-") or tag.startswith("CVE-"):
                        cve_id = tag.upper()
                        self.kg.add_entity(Entity(cve_id, "vulnerability"))
                        self.kg.add_relation(
                            service_entity, "vulnerable_to", cve_id,
                            ttl=86400 * 365,  # 1 year TTL
                        )

    # ── Helpers ────────────────────────────────────────────────────

    def _llm_summarize(self, text: str, prompt: str) -> str:
        """Use LLM to summarize text according to the prompt."""
        try:
            response = self._llm.invoke(
                messages=[
                    {"role": "system", "content": prompt},
                    {"role": "user", "content": text},
                ],
                model="",  # use default
                max_tokens=500,
            )
            return response.content.strip() or "LLM returned empty summary"
        except Exception:
            return self._heuristic_summarize(text, [])

    @staticmethod
    def _heuristic_summarize(text: str, entries: list[MemoryEntry]) -> str:
        """Fallback heuristic compression without LLM."""
        lines = text.split("\n")
        key_lines = [l.strip() for l in lines if l.strip()]

        # Find lines with security signals
        signal_keywords = [
            "flag{", "CVE-", "vulnerability", "exploit", "injectable",
            "open", "SQL", "XSS", "success", "failure", "error",
        ]
        signal_lines = [
            l for l in key_lines
            if any(kw.lower() in l.lower() for kw in signal_keywords)
        ]

        goal = "Execute security tools" if entries else "Unknown task"
        approach = ", ".join(list(set(t for e in entries for t in e.tags)))[:3] or "N/A"
        findings = "; ".join(signal_lines[:5]) or "No significant findings"
        outcome = "Completed" if not any("error" in l.lower() for l in signal_lines) else "Partial"

        return (
            f"GOAL: {goal}\n"
            f"APPROACH: {approach}\n"
            f"KEY_FINDINGS: {findings}\n"
            f"OUTCOME: {outcome}\n"
            f"LESSONS: (use LLM for detailed lessons)"
        )

    @staticmethod
    def _extract_keywords(text: str) -> str:
        """Extract likely important keywords from text."""
        import re
        # Look for capitalized terms, technical identifiers
        tech_terms = re.findall(r'\b[A-Z][a-z]+(?:[A-Z][a-z]+)*\b', text)
        cve_terms = re.findall(r'CVE-\d{4}-\d+', text)
        result = list(set(tech_terms[:5] + cve_terms))
        return ", ".join(result) if result else "No patterns detected"
