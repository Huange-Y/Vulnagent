"""Patch generation prompts — firmware-adapted from DCRH harness/prompts/patch_prompt.py.

For IoT/embedded: configuration fixes, input validation, access control enforcement.
"""

from __future__ import annotations

from typing import Any

PATCH_AGENT_SYSTEM_PROMPT = """\
You are a firmware security patch engineer for IoT/embedded systems.
Generate a verified fix for a confirmed vulnerability.

## Patch Types
1. Config fix: Fix insecure defaults (disabled auth, open ports, hardcoded credentials)
2. Input validation: Add sanitization to CGI/handler endpoints
3. Access control: Enforce authentication on sensitive routes
4. Binary patch: Modify vulnerable code path (QEMU-verified)

## Output Format
<patch_summary>One-line fix description</patch_summary>
<patch_type>config|validation|access_control|binary</patch_type>
<patch_commands>Shell commands to apply the fix</patch_commands>
<verification_steps>How to verify the fix works</verification_steps>

## Constraints
- Never delete legitimate functionality
- Prefer configuration-level fixes over binary patches
- Document trade-offs

Target: {target}
Vulnerability:
{vulnerability_summary}
"""


def build_patch_prompt(
    finding: dict[str, Any],
    target: str,
    tool_evidence: str = "",
) -> str:
    title = str(finding.get("title", "unknown"))
    description = str(finding.get("description", ""))
    evidence = "\n".join(str(e) for e in (finding.get("evidence", []) or []))
    poc = str(finding.get("poc_path", "")) or str(finding.get("executable_command", ""))
    cwe = str(finding.get("cwe_id", ""))
    cvss = str(finding.get("cvss_score", ""))

    parts = [
        "## Patch Task",
        f"**Target:** {target}",
        f"**Vulnerability:** {title}",
    ]
    if cwe: parts.append(f"**CWE:** {cwe}")
    if cvss: parts.append(f"**CVSS:** {cvss}")
    parts.extend([
        "", "### Description", description or "(see evidence)",
        "", "### Evidence", evidence[:2000] or "(none)",
        "", "### PoC", poc or "(none)",
    ])
    if tool_evidence:
        parts.extend(["", "### Tool Evidence", tool_evidence[:3000]])
    parts.extend([
        "", "### Instructions",
        "1. Understand root cause from evidence",
        "2. Propose minimal fix addressing root cause",
        "3. Output in XML format",
        "4. Verify fix doesn't break core functionality",
        "", "Generate the patch.",
    ])
    return "\n".join(parts)


def build_patch_grade_prompt(
    finding: dict[str, Any],
    patch_summary: str,
    patch_commands: str,
    tier_results: dict[str, Any],
) -> str:
    parts = [
        "## Patch Grading Report",
        f"**Finding:** {finding.get('title', 'unknown')}",
        f"**Patch:** {patch_summary}",
        "", "### Tier Results",
    ]
    for tier_name in ("T0", "T1", "T2", "T3"):
        result = tier_results.get(tier_name, {})
        status = "PASS" if result.get("passed") else "FAIL"
        ev = str(result.get("evidence", ""))[:500]
        parts.append(f"- **{tier_name}**: {status}")
        if ev: parts.append(f"  {ev}")
    parts.extend([
        "", "### Overall",
        f"**Passed:** {tier_results.get('overall_passed', False)}",
    ])
    return "\n".join(parts)
