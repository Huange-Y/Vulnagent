"""Anchored Structured Summary — the anti-drift compression mechanism.

Innovation: incremental merging of new content into a structured summary
with mandatory sections. This prevents the "summary of a summary" degradation
that plagues iterative summarization.

Inspired by Factory AI's anchored iterative summarization (3.70/5 best score).
"""

from __future__ import annotations

from typing import Any


class AnchoredSummary:
    """Manages structured summaries that persist across compaction cycles.

    The key insight from Factory AI: FORCING the compressor to populate
    explicit sections prevents silent information loss. Each section is
    mandatory — the LLM must write something or explicitly mark [EMPTY].

    For CTF/security, we add a [FINDINGS] section not present in Factory's
    original schema, specifically for vulnerability discoveries.

    Sections:
        scope      — Task goal + current progress
        files      — Files created/modified and their status
        tools      — Tools executed with key findings (Smart Truncated)
        decisions  — Decisions made and WHY
        findings   — Security findings (vulnerabilities, injection points, flags)
        open       — Unresolved issues
        next       — Next steps to take

    Usage:
        anchor = AnchoredSummary()
        new_content = {"scope": "Exploit SQL injection", "findings": "id parameter vulnerable"}
        anchor.merge(new_content)
        print(anchor.to_context_string())
    """

    SECTIONS = ["scope", "files", "tools", "decisions", "findings", "open", "next"]

    def __init__(self) -> None:
        self._sections: dict[str, str] = {s: "" for s in self.SECTIONS}
        self._version: int = 0  # incremented on each merge

    @property
    def sections(self) -> dict[str, str]:
        return dict(self._sections)

    @property
    def version(self) -> int:
        return self._version

    def merge(self, new_content: dict[str, str]) -> "AnchoredSummary":
        """Incrementally merge new content into the anchored summary.

        Key design: only ADDS new information, never re-generates from scratch.
        Each section is independently merged:
        - scope/next: replace (latest state, not cumulative)
        - files/tools/findings: append if new content differs
        - decisions/open: cumulative, avoid duplicates
        """
        for section in self.SECTIONS:
            new_value = new_content.get(section, "").strip()
            if not new_value or new_value == "[EMPTY]":
                continue

            if section in ("scope", "next"):
                # Replace: these describe current state
                self._sections[section] = new_value

            elif section in ("files", "tools", "findings"):
                # Append: accumulate across cycles (with dedup)
                if self._sections[section]:
                    if new_value not in self._sections[section]:
                        self._sections[section] += f"\n  + {new_value}"
                else:
                    self._sections[section] = new_value

            elif section in ("decisions", "open"):
                # Cumulative: only add if truly new
                if new_value not in self._sections[section]:
                    if self._sections[section]:
                        self._sections[section] += f"\n  - {new_value}"
                    else:
                        self._sections[section] = f"  - {new_value}"

        self._version += 1
        return self

    def update_from_llm(self, llm_output: str) -> "AnchoredSummary":
        """Parse LLM compaction output and merge it.

        Expected format (one section per line, section name in brackets):
        [SCOPE] Exploit SQL injection in login form
        [FILES] Created exploit.py
        [FINDINGS] id parameter is injectable (UNION query)
        [NEXT] Dump the flag table
        """
        new_content: dict[str, str] = {}

        for line in llm_output.split("\n"):
            line = line.strip()
            if not line:
                continue

            for section in self.SECTIONS:
                prefix = f"[{section.upper()}]"
                if line.upper().startswith(prefix):
                    value = line[len(prefix):].strip()
                    if value:
                        new_content[section] = value
                    break

        if new_content:
            self.merge(new_content)

        return self

    def to_context_string(self) -> str:
        """Render the anchored summary as a compact context string for LLM injection.

        Empty sections are marked [EMPTY] to maintain structural awareness.
        """
        parts: list[str] = ["[COMPACTED CONTEXT]"]
        for section in self.SECTIONS:
            content = self._sections.get(section, "").strip()
            label = section.upper()
            if content:
                parts.append(f"[{label}]\n{content}")
            else:
                parts.append(f"[{label}]\n[EMPTY]")
        return "\n\n".join(parts)

    def to_dict(self) -> dict[str, Any]:
        """Serialize for state storage."""
        return {
            "sections": self._sections,
            "version": self._version,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "AnchoredSummary":
        """Deserialize from state storage."""
        anchor = cls()
        anchor._sections = data.get("sections", {s: "" for s in cls.SECTIONS})
        anchor._version = data.get("version", 0)
        return anchor

    def is_empty(self) -> bool:
        """Check if the summary has any content."""
        return all(not v.strip() for v in self._sections.values())

    def estimated_tokens(self) -> int:
        """Rough token estimate (~4 chars per token)."""
        return len(self.to_context_string()) // 4

    def reset(self) -> None:
        """Clear all sections."""
        self._sections = {s: "" for s in self.SECTIONS}
        self._version = 0


class CompactionPrompt:
    """Standard prompts for LLM-driven compaction at each level."""

    MID_COMPACT_PROMPT = """You are a context compressor for a CTF/security agent.
Summarize the following conversation history into structured sections.
Follow these rules EXACTLY:

1. [SCOPE]: What is the current task and what progress has been made?
2. [FILES]: What files were created/modified? Include paths and status.
3. [TOOLS]: List tools executed with their KEY findings only (no noise):
   - For nmap: only open ports with service/version
   - For sqlmap: only injection points and payloads
   - For gobuster: only non-404 paths
   - For other tools: only results that changed the agent's understanding
4. [DECISIONS]: What decisions were made and WHY? Be specific.
5. [FINDINGS]: List all security discoveries (vulnerability types, affected parameters,
   CVEs, potential attack vectors, flag fragments).
6. [OPEN]: What questions or issues remain unresolved?
7. [NEXT]: What is the immediate next action?

FORMAT: Output exactly ONE line per section, with the section tag in brackets.
Example:
[SCOPE] Exploiting SQL injection in login form - identified vulnerable parameter
[TOOLS] sqlmap: id parameter UNION injection (MySQL 5.7). nmap: 22/ssh, 80/http(Apache 2.4.29), 443/https
[FINDINGS] id parameter vulnerable to UNION SELECT injection, MySQL 5.7 backend
[NEXT] Dump database tables and search for flag

If a section has no content, write [EMPTY].
Keep each section under 200 tokens. Preserve EXACT version numbers and port numbers."""

    DEEP_COMPACT_PROMPT = """You are a knowledge abstractor for a security agent.
Extract REUSABLE knowledge from these experiences.

Output exactly:
[TECHNIQUE_PATTERNS] Recurring techniques and when they work
[COMMON_PITFALLS] Frequent mistakes or dead ends to avoid
[SUCCESS_TEMPLATES] Proven workflows for similar problems
[TOOL_CHAINS] Effective sequences of tools

Keep under 300 tokens total. Include specific CVE numbers and version ranges."""


def extract_structured_summary(text: str) -> dict[str, str]:
    """Extract a structured summary from raw anchored summary text.

    Used to re-parse summaries that were stored as flat text.
    """
    result: dict[str, str] = {}
    for section in AnchoredSummary.SECTIONS:
        result[section] = ""

    current_section = ""
    for line in text.split("\n"):
        line = line.strip()
        if not line:
            continue

        for section in AnchoredSummary.SECTIONS:
            if line.upper().startswith(f"[{section.upper()}]"):
                current_section = section
                value = line[len(f"[{section.upper()}]"):].strip()
                result[section] = value
                break
        else:
            # Continuation of previous section
            if current_section and line:
                result[current_section] += " " + line

    return result
