"""Deduplication and judge logic — mirrors DCRH judge agent.

Two-layer dedup (DCRH pattern):
1. Runtime: each agent self-polices via <dup_check> tag (already in prompts)
2. Post-hoc: cross-run dedup comparing findings by handler + CWE class

The Judge compares findings semantically, not by string match.
"""

from __future__ import annotations

import re
from typing import Any

from vulnagent.utils.xml_tags import parse_xml_tag


def build_judge_prompt(
    new_findings: list[dict[str, Any]],
    existing_findings: list[dict[str, Any]],
) -> str:
    """Build a judge prompt for deduplicating findings.

    Returns empty string if no existing findings to dedup against.
    """
    new_json = _findings_to_comparable(new_findings)
    existing_json = _findings_to_comparable(existing_findings)

    if not existing_json:
        return ""

    return f"""You are a deduplication judge. Compare each NEW finding against
the EXISTING findings and decide: is it genuinely novel, a better example of a
known issue, or a duplicate?

## Comparison Rules

- Match on **handler name + vulnerability class**, not exact wording
- Same CWE class + same handler/component = likely duplicate
- Same handler + different CWE class = potentially distinct
- Different handler + same CWE class = distinct finding
- If a new finding provides STRONGER evidence (better reproduction, clearer
  code path, confirmed reachability vs. just static analysis), flag it as
  DUP_BETTER — it should REPLACE the existing entry

## Output Format

For EACH new finding, emit:

<judge_verdict>
<finding_title>The new finding title</finding_title>
<verdict>NEW | DUP_BETTER | DUP_SKIP</verdict>
<matched_existing>The title of the existing finding it matches (or NONE)</matched_existing>
<reasoning>One sentence: why this verdict.</reasoning>
</judge_verdict>

## EXISTING findings (already confirmed)

{existing_json}

## NEW findings (to judge)

{new_json}
"""


def _findings_to_comparable(findings: list[dict[str, Any]]) -> str:
    items = []
    for i, f in enumerate(findings):
        if not isinstance(f, dict):
            continue
        items.append({
            "index": i,
            "title": str(f.get("title", ""))[:200],
            "handler": str(f.get("component_path", "")),
            "vuln_type": str(f.get("vuln_type", "")),
            "cwe_id": str(f.get("cwe_id", "")),
            "severity": str(f.get("severity", "")),
            "dup_check": str(f.get("dup_check", ""))[:300],
        })

    import json
    return json.dumps(items, indent=2)


def apply_judge_verdicts(
    new_findings: list[dict[str, Any]],
    verdicts: list[dict[str, str]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    """Apply judge verdicts to partition new findings.

    Returns (accepted, replaced, skipped).
    """
    accepted: list[dict[str, Any]] = []
    replaced: list[dict[str, Any]] = []
    skipped: list[dict[str, Any]] = []

    verdict_map: dict[str, str] = {}
    for v in verdicts:
        title = v.get("finding_title", "").strip()
        verdict = v.get("verdict", "").strip().upper()
        matched = v.get("matched_existing", "").strip()
        if title:
            verdict_map[title] = verdict
            if verdict in ("DUP_BETTER", "DUP_SKIP") and matched:
                verdict_map[f"{title}__matched"] = matched

    for f in new_findings:
        if not isinstance(f, dict):
            continue
        title = str(f.get("title", "")).strip()
        verdict = verdict_map.get(title, "NEW")

        if verdict == "DUP_SKIP":
            skipped.append(f)
        elif verdict == "DUP_BETTER":
            f["_replaces"] = verdict_map.get(f"{title}__matched", "")
            replaced.append(f)
        else:
            f.setdefault("_judge_verdict", "NEW")
            accepted.append(f)

    return accepted, replaced, skipped


def parse_judge_response(text: str) -> list[dict[str, str]]:
    """Parse <judge_verdict> blocks from a judge agent response."""
    verdicts: list[dict[str, str]] = []
    blocks = re.split(r"(?=<judge_verdict>)", text)
    for block in blocks:
        if "<judge_verdict>" not in block:
            continue
        verdicts.append({
            "finding_title": parse_xml_tag(block, "finding_title") or "",
            "verdict": parse_xml_tag(block, "verdict") or "NEW",
            "matched_existing": parse_xml_tag(block, "matched_existing") or "",
            "reasoning": parse_xml_tag(block, "reasoning") or "",
        })
    return verdicts
