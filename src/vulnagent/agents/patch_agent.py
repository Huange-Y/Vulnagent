"""Patch Agent — generates fixes for confirmed vulnerabilities.

Port from DCRH harness/patch.py: patch agent writes fix, grader verifies T0-T3.
"""

from __future__ import annotations

import json
from typing import Any

from vulnagent.core.agent import BaseAgent
from vulnagent.core.state import AgentState
from vulnagent.prompts.patch_prompts import PATCH_AGENT_SYSTEM_PROMPT


class PatchAgent(BaseAgent):
    """Generate verified patches for confirmed firmware vulnerabilities.

    From DCRH: sandboxed agent outputs patch, graded by PatchGrader separately.
    """

    def get_system_prompt(self, state: AgentState) -> str:
        metadata = state.get("metadata", {}) or {}
        target_finding = metadata.get("_patch_target_finding", {})
        vuln_text = json.dumps(target_finding, indent=2) if target_finding else "none"
        return PATCH_AGENT_SYSTEM_PROMPT.format(
            target=metadata.get("target", "unknown"),
            vulnerability_summary=vuln_text,
        )

    def get_tools_schema(self, state: AgentState | None = None) -> list[dict[str, Any]]:
        return []
