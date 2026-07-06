"""Compression base classes and the three-tier compressor architecture.

Micro (L1): Smart Truncation for tool outputs — zero LLM cost
Mid (L2):   Anchored Structured Summarization — LLM-assisted with structural guarantees
Deep (L3):  Session → persistent memory consolidation

This module provides the ABSTRACT interfaces and base classes.
The concrete implementations are in Phase 3.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any


# ── Base Compressor ────────────────────────────────────────────────────

class BaseCompressor(ABC):
    """Abstract base for all compressors."""

    @abstractmethod
    def compress(self, text: str, context: dict[str, Any] | None = None) -> str:
        """Compress the given text. Concrete implementations define the strategy."""
        ...


# ── L1: Micro Compressor (Smart Truncation) ────────────────────────────

class MicroCompressor(BaseCompressor):
    """L1: Rule-based Smart Truncation for security tool outputs.

    Zero LLM cost — uses keyword filtering and structured parsing.
    Designed specifically for security tool outputs (nmap, sqlmap, etc.).

    Innovation: "Signal-Noise Protocol" — each tool type has defined
    signal extraction rules and noise discard rules.
    """

    # Priority-ordered security keywords for signal extraction
    SECURITY_SIGNALS: dict[str, list[str]] = {
        "critical": [
            "CVE-", "Critical", "flag{", "cube{", "CubeCTF{", "FLAG_CANDIDATES",
            "injectable", "Vulnerability found",
            "Remote Code Execution", "SQL injection", "Command injection",
            "[+]", "OSVDB", "exploitable",
        ],
        "high": [
            "HIGH", "open", "XSS", "LFI", "RFI", "CSRF",
            "authentication bypass", "arbitrary file read", "directory traversal",
        ],
        "info": [
            "MEDIUM", "LOW", "INFO", "Warning", "Interesting",
        ],
    }

    def compress(
        self,
        text: str,
        context: dict[str, Any] | None = None,
    ) -> str:
        """Smart-truncate tool output to preserve security signals, discard noise.

        Args:
            text: Raw tool output
            context: May contain 'tool_name' and 'max_tokens' keys

        Returns:
            Compressed text containing only security-relevant lines.
        """
        tool_name = context.get("tool_name", "") if context else ""
        max_tokens = context.get("max_tokens", 2000) if context else 2000

        # Route to tool-specific compressor if available
        tool_method = getattr(self, f"_compress_{tool_name}", None) if tool_name else None
        if tool_method:
            return tool_method(text, max_tokens)

        # Browser tools: keep content, don't security-filter
        if tool_name and tool_name.startswith("browser_"):
            return self._compress_browser(text, max_tokens)

        # Python/shell/file tools: keep content
        if tool_name in ("python_exec", "shell_exec", "file_read"):
            return text[:max_tokens * 4]

        return self._compress_generic(text, max_tokens)

    def _compress_generic(self, text: str, max_tokens: int) -> str:
        """Generic truncation: keep lines matching security signals."""
        if not text:
            return ""

        result_lines: list[str] = []
        for line in text.split("\n"):
            stripped = line.strip()
            if not stripped:
                continue

            signal_level = self._detect_signal_level(stripped)
            if signal_level is not None:
                result_lines.append(stripped)

        if not result_lines:
            # No security signals found — keep first and last 20% of lines
            all_lines = [l for l in text.split("\n") if l.strip()]
            keep_n = max(5, len(all_lines) // 5)
            result_lines = all_lines[:keep_n] + ["..."] + all_lines[-keep_n:]

        result = "\n".join(result_lines)
        return self._truncate_to_tokens(result, max_tokens)

    def _detect_signal_level(self, line: str) -> str | None:
        """Detect the security significance level of a line. Returns None if noise."""
        for level, keywords in self.SECURITY_SIGNALS.items():
            for kw in keywords:
                if kw.lower() in line.lower():
                    return level
        return None

    # ── Tool-specific compressors (extensible) ─────────────────────

    def _compress_browser(self, text: str, max_tokens: int) -> str:
        """Browser output: keep as much content as possible, just truncate."""
        # Browser tools return page content - don't filter by security signals
        if len(text) <= max_tokens * 4:
            return text
        # Keep first 60% and last 20%
        split_point = int(max_tokens * 3)
        return text[:split_point] + "\n...[truncated]...\n" + text[-int(max_tokens * 0.5):]

    def _compress_nmap(self, text: str, max_tokens: int) -> str:
        """Nmap: keep only open/filtered port lines + OS detection."""
        result: list[str] = []
        for line in text.split("\n"):
            s = line.strip()
            if not s:
                continue
            if any(kw in s for kw in ["/open", "/filtered", "OS CPE:", "Service Info:",
                                        "Nmap scan report for", "Host is up",
                                        "MAC Address:", "Device type:",
                                        "Aggressive OS guesses:"]):
                result.append(s)
            elif self._detect_signal_level(s):
                result.append(s)
        return self._truncate_to_tokens("\n".join(result), max_tokens)

    def _compress_gobuster(self, text: str, max_tokens: int) -> str:
        """Gobuster: keep non-404 responses only."""
        result: list[str] = []
        for line in text.split("\n"):
            s = line.strip()
            if not s:
                continue
            # Keep status lines — but not 404s
            if "Status:" in s and "404" not in s:
                result.append(s)
            elif self._detect_signal_level(s) == "critical":
                result.append(s)
        return self._truncate_to_tokens("\n".join(result), max_tokens)

    def _compress_sqlmap(self, text: str, max_tokens: int) -> str:
        """SQLMap: keep injection points, payloads, DB enumeration."""
        result: list[str] = []
        for line in text.split("\n"):
            s = line.strip()
            if not s:
                continue
            if any(kw in s for kw in ["[INFO]", "[WARNING]", "[CRITICAL]",
                                        "injectable", "payload:", "back-end DBMS",
                                        "parameter:", "database:", "table:"]):
                result.append(s)
        return self._truncate_to_tokens("\n".join(result), max_tokens)

    def _compress_nikto(self, text: str, max_tokens: int) -> str:
        """Nikto: keep vulnerability findings, drop server metadata."""
        result: list[str] = []
        for line in text.split("\n"):
            s = line.strip()
            if not s:
                continue
            if "+" in s and any(kw in s.lower() for kw in ["osvdb", "cve", "vulnerability"]):
                result.append(s)
            elif self._detect_signal_level(s) in ("critical", "high"):
                result.append(s)
        return self._truncate_to_tokens("\n".join(result), max_tokens)

    @staticmethod
    def _truncate_to_tokens(text: str, max_tokens: int) -> str:
        """Rough token-aware truncation (~4 chars per token)."""
        max_chars = max_tokens * 4
        if len(text) <= max_chars:
            return text
        return text[:max_chars] + f"\n... [truncated, original: {len(text)} chars]"


# ── L2: Mid Compressor (Anchored Summarization) ────────────────────────

class MidCompressor(BaseCompressor):
    """L2: Anchored Structured Summarization (Factory AI pattern).

    Uses LLM to compress conversation history into structured sections,
    then INCREMENTALLY merges new content (never re-summarizing from scratch).

    The ANCHOR_SECTIONS are mandatory — the LLM must populate each or
    explicitly mark it [EMPTY]. This structural requirement prevents
    silent information loss during compression.
    """

    ANCHOR_SECTIONS = [
        "scope",      # Task goal + current progress
        "files",      # Files created/modified and their status
        "tools",      # Tools executed with key findings (via Smart Truncation)
        "decisions",  # Decisions made and WHY
        "findings",   # Security findings (vulnerability types, injection points, payloads)
        "open",       # Unresolved issues
        "next",       # Next steps
    ]

    def __init__(self, llm_client: Any | None = None) -> None:
        self._llm = llm_client
        self._summary: dict[str, str] = {s: "" for s in self.ANCHOR_SECTIONS}

    @property
    def summary(self) -> dict[str, str]:
        return dict(self._summary)

    def compress(
        self,
        text: str,
        context: dict[str, Any] | None = None,
    ) -> str:
        """Compress text into the anchored summary. For full conversation history
        compression, use compress_messages() instead."""
        return text  # Stub — real implementation in Phase 3

    def compress_messages(
        self, new_messages: list[Any], existing_anchor: dict[str, str]
    ) -> dict[str, str]:
        """Incrementally merge new messages into the anchored summary.

        Key design: only summarizes NEW content, never re-summarizes
        the entire history. This prevents "summary of a summary" drift.

        If an LLM is configured, uses it for structured extraction.
        Otherwise falls back to heuristic extraction from message content.

        Returns updated anchor dict with all sections merged.
        """
        # Extract text from new messages
        new_text = self._extract_message_text(new_messages)
        if not new_text.strip():
            return existing_anchor

        # Try LLM-based extraction first
        if self._llm:
            try:
                new_sections = self._llm_extract_sections(new_text, existing_anchor)
            except Exception:
                new_sections = self._heuristic_extract(new_text)
        else:
            new_sections = self._heuristic_extract(new_text)

        # Merge new sections into existing anchor
        merged: dict[str, str] = {}
        for section in self.ANCHOR_SECTIONS:
            existing = existing_anchor.get(section, "").strip()
            incoming = new_sections.get(section, "").strip()
            if existing and incoming:
                # Incremental merge: append new info with a separator
                merged[section] = existing + "\n" + incoming
            elif incoming:
                merged[section] = incoming
            else:
                merged[section] = existing

        # Truncate each section to prevent unbounded growth
        for section in self.ANCHOR_SECTIONS:
            content = merged.get(section, "")
            if len(content) > 3000:
                merged[section] = content[:3000] + "\n... [trimmed]"

        self._summary = merged
        return merged

    def _extract_message_text(self, messages: list[Any]) -> str:
        """Extract text content from LLM chain library message objects."""
        parts: list[str] = []
        for msg in messages:
            msg_type = type(msg).__name__
            content = getattr(msg, "content", "") or ""

            if not content:
                continue

            if "System" in msg_type:
                parts.append(f"[SYSTEM] {content[:500]}")
            elif "Human" in msg_type:
                parts.append(f"[USER] {content[:500]}")
            elif "AI" in msg_type or "Assistant" in msg_type:
                parts.append(f"[ASSISTANT] {content[:1000]}")
            elif "Tool" in msg_type:
                name = getattr(msg, "name", "unknown")
                parts.append(f"[TOOL:{name}] {content[:800]}")
            else:
                parts.append(content[:500])

        return "\n\n".join(parts)

    def _llm_extract_sections(
        self, text: str, existing_anchor: dict[str, str]
    ) -> dict[str, str]:
        """Use LLM to extract structured sections from conversation text."""
        sections_list = "\n".join(
            f"- {s}: {existing_anchor.get(s, '[EMPTY]')[:200]}"
            for s in self.ANCHOR_SECTIONS
        )

        prompt = f"""You are summarizing a security agent's conversation into structured sections.

Existing summary (DO NOT repeat — only extract NEW information):
{sections_list}

New conversation to extract NEW information from:
{text[:6000]}

For each section below, output ONLY new information not already in the existing summary.
If no new information, output "[EMPTY]".

SECTIONS:
- SCOPE: Task goal + current progress
- FILES: Files created/modified and their status
- TOOLS: Tools executed with key findings
- DECISIONS: Decisions made and why
- FINDINGS: Security findings (vulnerability types, injection points, payloads)
- OPEN: Unresolved issues
- NEXT: Next steps

Output format (one per line):
SCOPE: <new info or [EMPTY]>
FILES: <new info or [EMPTY]>
..."""

        # Use ModelRouter if available, else direct LLM
        if hasattr(self._llm, "compress"):
            response = self._llm.compress(
                [{"role": "user", "content": prompt}],
            )
        elif hasattr(self._llm, "invoke"):
            response = self._llm.invoke(
                messages=[{"role": "user", "content": prompt}],
                model="",
                max_tokens=800,
            )
        else:
            return self._heuristic_extract(text)

        return self._parse_sections(response.content.strip())

    def _heuristic_extract(self, text: str) -> dict[str, str]:
        """Heuristic extraction: classify lines by keyword matching."""
        result: dict[str, str] = {s: "" for s in self.ANCHOR_SECTIONS}
        text_lower = text.lower()

        # Tools: look for tool execution patterns
        tool_keywords = ["nmap", "gobuster", "sqlmap", "nikto", "curl", "python_exec",
                         "shell_exec", "file_read", "netcat", "executed", "scan"]
        tools_lines: list[str] = []
        for line in text.split("\n"):
            if any(kw in line.lower() for kw in tool_keywords):
                tools_lines.append(line.strip())
        if tools_lines:
            result["tools"] = "\n".join(tools_lines[:10])

        # Findings: security signals
        finding_signals = ["vulnerability", "CVE-", "injectable", "flag{", "XSS",
                           "SQL injection", "open port", "exploit", "bypass"]
        finding_lines: list[str] = []
        for line in text.split("\n"):
            if any(s.lower() in line.lower() for s in finding_signals):
                finding_lines.append(line.strip())
        if finding_lines:
            result["findings"] = "\n".join(finding_lines[:10])

        # Decisions: look for decision indicators
        decision_keywords = ["decided", "chose", "selected", "will use", "approach",
                             "strategy", "plan:"]
        decision_lines: list[str] = []
        for line in text.split("\n"):
            if any(kw in line.lower() for kw in decision_keywords):
                decision_lines.append(line.strip())
        if decision_lines:
            result["decisions"] = "\n".join(decision_lines[:5])

        # Open issues: unresolved indicators
        open_keywords = ["TODO", "unresolved", "pending", "need to", "should try",
                         "not found", "failed", "error", "retry"]
        open_lines: list[str] = []
        for line in text.split("\n"):
            if any(kw in line.lower() for kw in open_keywords):
                open_lines.append(line.strip())
        if open_lines:
            result["open"] = "\n".join(open_lines[:8])

        # Next steps: action indicators
        next_keywords = ["next", "should", "will try", "plan to", "going to", "step"]
        next_lines: list[str] = []
        for line in text.split("\n"):
            if any(kw in line.lower() for kw in next_keywords):
                next_lines.append(line.strip())
        if next_lines:
            result["next"] = "\n".join(next_lines[:5])

        # Scope: first meaningful line or task description
        meaningful = [l for l in text.split("\n") if len(l.strip()) > 30]
        if meaningful:
            result["scope"] = meaningful[0][:500]

        return result

    @staticmethod
    def _parse_sections(text: str) -> dict[str, str]:
        """Parse LLM output with 'SECTION: content' format."""
        result: dict[str, str] = {}
        current_section = ""
        current_content: list[str] = []

        for line in text.split("\n"):
            line = line.strip()
            if not line:
                continue

            # Check for section header pattern: "SECTION: content" or "SECTION content"
            match_upper = line.upper()
            for section in ["SCOPE", "FILES", "TOOLS", "DECISIONS", "FINDINGS", "OPEN", "NEXT"]:
                prefix_patterns = [f"{section}:", f"{section} "]
                for prefix in prefix_patterns:
                    if match_upper.startswith(prefix):
                        if current_section:
                            result[current_section.lower()] = "\n".join(current_content)
                        current_section = section.lower()
                        content_after = line[len(prefix):].strip()
                        current_content = [content_after] if content_after and content_after != "[EMPTY]" else []
                        break
                else:
                    continue
                break
            else:
                if current_section:
                    current_content.append(line)

        if current_section:
            result[current_section.lower()] = "\n".join(current_content)

        # Ensure all sections present
        for s in ["scope", "files", "tools", "decisions", "findings", "open", "next"]:
            if s not in result:
                result[s] = ""

        return result

    def to_context_string(self) -> str:
        """Render the anchored summary as a compact context string."""
        parts: list[str] = ["[COMPACTED CONTEXT]"]
        for section in self.ANCHOR_SECTIONS:
            content = self._summary.get(section, "").strip()
            label = section.upper()
            parts.append(f"[{label}]\n{content if content else '[EMPTY]'}")
        return "\n\n".join(parts)

    def reset(self) -> None:
        self._summary = {s: "" for s in self.ANCHOR_SECTIONS}


# ── L3: Deep Compressor (Memory Consolidation) ─────────────────────────

class DeepCompressor(BaseCompressor):
    """L3: Session → persistent memory consolidation.

    Takes a complete agent execution trace and compresses it into
    MemoryEntry objects for the hierarchical memory system.

    Uses MemoryConsolidator for structured compression, narrative generation,
    and knowledge graph updates.
    """

    def __init__(
        self,
        llm_client: Any | None = None,
        kg: Any | None = None,
        memory: Any | None = None,
    ) -> None:
        self._llm = llm_client
        self.kg = kg
        self.memory = memory

    def compress(
        self,
        text: str,
        context: dict[str, Any] | None = None,
    ) -> str:
        """Compress full session trace into a structured summary string."""
        if not text.strip():
            return ""

        if self._llm:
            try:
                if hasattr(self._llm, "compress"):
                    response = self._llm.compress([
                        {"role": "user", "content": (
                            "Summarize this security agent session into a compact report. "
                            "Include: task, tools used, key findings, outcome, lessons learned. "
                            f"Keep under 400 tokens.\n\n{text[:8000]}"
                        )},
                    ])
                    return response.content.strip()
                elif hasattr(self._llm, "invoke"):
                    response = self._llm.invoke(
                        messages=[{"role": "user", "content": (
                            "Summarize this security agent session into a compact report. "
                            "Include: task, tools used, key findings, outcome, lessons learned. "
                            f"Keep under 400 tokens.\n\n{text[:8000]}"
                        )}],
                        model="",
                        max_tokens=400,
                    )
                    return response.content.strip()
            except Exception as e:
                import logging
                logging.getLogger(__name__).debug(f"LLM summarization failed, using heuristic: {e}")

        # Heuristic fallback
        lines = text.split("\n")
        key_lines = [l.strip() for l in lines if l.strip() and len(l) > 20]
        return "\n".join(key_lines[:20])

    def compress_to_memories(
        self, state: dict[str, Any], flashbulb: Any = None
    ) -> list[Any]:
        """Convert agent state into memory entries for persistent storage.

        Creates 2-3 MemoryEntry objects:
        1. Session summary (mid_term) — structured overview of the task
        2. Key findings (long_term) — patterns and techniques extracted
        3. Flashbulb entries (if any) — already created during execution

        Returns a list of MemoryEntry objects ready for insertion into HierarchicalMemory.
        """
        import time
        import uuid
        from vulnagent.memory.hierarchical import MemoryEntry
        from vulnagent.memory.consolidation import MemoryConsolidator

        entries: list[MemoryEntry] = []
        task_id = state.get("task_description", str(uuid.uuid4().hex[:8]))
        category = state.get("current_agent", "unknown")
        consolidator = MemoryConsolidator(self._llm, self.kg)

        # ── Build session trace text ──
        trace_parts: list[str] = []
        trace_parts.append(f"Task: {state.get('task_description', 'Unknown')}")
        trace_parts.append(f"Agent: {category}")
        trace_parts.append(f"Iterations: {state.get('iteration_count', 0)}")
        trace_parts.append(f"Phase: {state.get('phase', 'unknown')}")
        trace_parts.append(f"Final result: {state.get('final_result', 'None')}")

        # Tool outputs summary
        compressed = state.get("compressed_outputs", {})
        if compressed:
            trace_parts.append("\n--- Tool Results ---")
            for tool_name, output in compressed.items():
                trace_parts.append(f"[{tool_name}]\n{output[:1000]}")

        # Anchored summary
        anchored = state.get("anchored_summary", {})
        if anchored and any(v.strip() for v in anchored.values() if v):
            trace_parts.append("\n--- Anchored Summary ---")
            for section in ["findings", "decisions", "open", "next"]:
                content = anchored.get(section, "")
                if content.strip():
                    trace_parts.append(f"[{section.upper()}] {content[:500]}")

        # Messages (last few)
        messages = state.get("messages", [])
        if messages:
            trace_parts.append("\n--- Conversation (last 4) ---")
            for msg in messages[-4:]:
                content = getattr(msg, "content", "") or ""
                msg_type = type(msg).__name__
                trace_parts.append(f"[{msg_type}] {content[:500]}")

        session_trace = "\n".join(trace_parts)

        # ── Create session summary entry (mid_term) ──
        summary_text = self.compress(session_trace)

        tags: list[str] = [category, "session_summary"]
        if state.get("final_result"):
            from vulnagent.verification.flag_checker import FlagExtractor
            extractor = FlagExtractor()
            flags = extractor.extract(str(state.get("final_result", "")))
            if flags:
                tags.append("flag_found")

        # Extract security tags from findings
        findings = anchored.get("findings", "")
        for kw in ["sql", "xss", "cve", "rce", "lfi", "overflow", "injection"]:
            if kw in findings.lower():
                tags.append(kw)

        summary_entry = MemoryEntry(
            content=summary_text,
            layer="mid_term",
            timestamp=time.time(),
            ttl=86400 * 7,  # 7 days for session summaries
            weight=1.2,
            narrative=f"{category} session: {task_id[:80]}",
            tags=tags,
            source_task_id=task_id[:100],
        )
        entries.append(summary_entry)

        # ── Create technique/pattern entry (long_term) if findings exist ──
        if findings.strip() and findings.strip() != "[EMPTY]":
            pattern_text = consolidator.abstract_for_long_term([summary_entry])
            pattern_text.layer = "long_term"
            pattern_text.timestamp = time.time()
            pattern_text.ttl = None  # permanent
            if not pattern_text.source_task_id:
                pattern_text.source_task_id = task_id[:100]
            entries.append(pattern_text)

            # Update KG from the pattern
            if self.kg:
                try:
                    consolidator.update_knowledge_graph(pattern_text)
                except Exception as e:
                    import logging
                    logging.getLogger(__name__).debug(f"KG update from pattern failed: {e}")

        # ── Add flashbulb entries ──
        if flashbulb and self.memory:
            try:
                fb_entries = flashbulb.memory.get_flashbulbs(limit=5)
                for fb in fb_entries:
                    fb.source_task_id = task_id[:100]
                    entries.append(fb)
            except Exception as e:
                import logging
                logging.getLogger(__name__).debug(f"Failed to get flashbulb entries: {e}")

        # ── Insert into memory if available ──
        if self.memory:
            for entry in entries:
                try:
                    if entry.layer == "long_term":
                        self.memory.add_long_term(entry)
                    else:
                        self.memory.add_mid_term(entry)
                except Exception as e:
                    import logging
                    logging.getLogger(__name__).warning(f"Failed to add memory entry: {e}")

        return entries
