"""Structured XML tag extraction from agent outputs.

Ported from Anthropic defending-code-reference-harness (Apache 2.0).

Agents emit structured XML tags, then often a short final "Done!" message.
Naive last-message parsing returns the prose, not the tags. This module
provides helpers to scan backwards for the tags instead.
"""

from __future__ import annotations

import re
from typing import Any


def parse_xml_tag(text: str, tag: str) -> str | None:
    """Extract content of <tag>...</tag>. DOTALL so multiline traces work.

    Not a real XML parser — tags are markers in prose, not well-formed XML.
    """
    m = re.search(rf"<{re.escape(tag)}>(.*?)</{re.escape(tag)}>", text, re.DOTALL)
    return m.group(1).strip() if m else None


def find_tagged_message(messages: list[Any], tag: str) -> str:
    """Return the most-recent assistant message text containing <tag>.

    Agents emit structured tags, then often a short final "Done!" message.
    If you take the last message you get prose, not tags. Scan backwards
    instead. Falls back to the last assistant message.

    Works with both dict messages ({"role": "assistant", "content": "..."})
    and LLM chain library message objects.
    """
    needle = f"<{tag}>"
    last_assistant = ""
    for msg in reversed(messages):
        role = ""
        content = ""
        if isinstance(msg, dict):
            role = str(msg.get("role", "") or msg.get("type", "")).strip().lower()
            content = str(msg.get("content", "") or "")
        elif hasattr(msg, "content"):
            type_name = type(msg).__name__.lower()
            if "ai" in type_name or "assistant" in type_name:
                role = "assistant"
            content = str(getattr(msg, "content", "") or "")
        if role not in ("assistant", "") and role:
            continue
        if not last_assistant:
            last_assistant = content
        if needle in content:
            return content
    return last_assistant


def extract_finding_from_text(text: str) -> dict[str, str]:
    """Parse a structured finding from agent output XML tags.

    Returns dict with keys: finding, evidence, vuln_type, reachability,
    severity, dup_check, component_path.
    """
    return {
        "finding": parse_xml_tag(text, "finding") or "",
        "evidence": parse_xml_tag(text, "evidence") or "",
        "vuln_type": parse_xml_tag(text, "vuln_type") or "",
        "reachability": parse_xml_tag(text, "reachability") or "",
        "severity": parse_xml_tag(text, "severity") or "",
        "dup_check": parse_xml_tag(text, "dup_check") or "",
        "component_path": parse_xml_tag(text, "component_path") or "",
    }


def extract_verdict_from_text(text: str) -> dict[str, Any]:
    """Parse a grader verdict from agent output XML tags.

    Returns dict matching DCRH GraderVerdict: passed, score, criteria, evidence.
    """
    criteria: dict[str, bool] = {}
    for i in range(1, 6):
        val = parse_xml_tag(text, f"criterion_{i}")
        criteria[f"criterion_{i}"] = val is not None and val.upper().startswith("PASS")

    overall = parse_xml_tag(text, "overall")
    score_str = parse_xml_tag(text, "score")
    evidence = parse_xml_tag(text, "evidence") or ""

    try:
        score = float(str(score_str).strip()) if score_str else 0.0
    except ValueError:
        score = 0.0

    return {
        "passed": overall is not None and overall.upper().startswith("PASS"),
        "score": score,
        "criteria": criteria,
        "evidence": evidence,
    }


def extract_report_grading_from_text(text: str) -> dict[str, Any]:
    """Parse a report grader assessment from agent output XML tags."""
    section_scores: dict[str, int] = {}
    for key in ("primitive", "reachability", "heap_layout", "escalation_path", "constraints"):
        val = parse_xml_tag(text, key)
        try:
            section_scores[key] = int(val.strip()) if val else 0
        except ValueError:
            section_scores[key] = 0

    rubric_str = parse_xml_tag(text, "rubric_score")
    try:
        rubric_score = int(str(rubric_str).strip()) if rubric_str else 0
    except ValueError:
        rubric_score = 0

    severity = parse_xml_tag(text, "severity_rating") or "NOT_ASSESSED"

    return {
        "section_scores": section_scores,
        "rubric_score": rubric_score,
        "severity_rating": severity,
    }
