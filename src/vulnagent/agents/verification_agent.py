"""Verification + Brainstorm agents — independent adversarial re-check of findings.

Mirrors DCRH's Grade phase: a separate agent in a clean context that takes
findings from prior stages and independently reproduces (or refutes) them.

BrainstormAgent: Codex-style "plan mode" — lightweight pre-scan survey before
heavy tools. Explore-first, act-second.
"""

from __future__ import annotations

import json
from typing import Any

from vulnagent.core.agent import BaseAgent
from vulnagent.core.assessment import (
    format_current_tool_evidence,
    format_recent_tool_history,
)
from vulnagent.core.state import AgentState
from vulnagent.prompts.untrusted import make_nonce, untrusted_block
from vulnagent.prompts.verification_prompts import (
    BRAINSTORM_AGENT_SYSTEM_PROMPT,
    VERIFICATION_AGENT_SYSTEM_PROMPT,
)


class BrainstormAgent(BaseAgent):
    """Lightweight pre-scan scout — surveys target, forms hypotheses, outputs attack plan.

    Mirrors Codex CLI "plan mode": explore-first, act-second. Runs BEFORE
    the heavy DiscoveryAgent to produce a structured hypothesis list and
    recommended tool sequence. Budget: ~15-20 turns — this is scouting, not
    deep analysis.
    """

    def get_system_prompt(self, state: AgentState) -> str:
        metadata = state.get("metadata", {}) or {}
        return BRAINSTORM_AGENT_SYSTEM_PROMPT.format(
            memory_context=json.dumps(state.get("memory_context", {}), indent=2),
            target=metadata.get("target", ""),
            provenance=metadata.get("provenance", ""),
            tokens_remaining=(
                state.get("token_budget", {}).get("total", 100000)
                - state.get("token_budget", {}).get("used", 0)
            ),
            current_tool_evidence=format_current_tool_evidence(
                dict(state.get("compressed_outputs", {}) or {})
            ),
        )

    def get_tools_schema(self, state: AgentState | None = None) -> list[dict[str, Any]]:
        # Lightweight tools only — no emulation, no heavy extraction.
        # When seed triage already ran, skip the basic tools completely.
        metadata = (state or {}).get("metadata", {}) or {}
        seed_ran = bool(
            metadata.get("fs_markers")
            or metadata.get("manifest_arch")
            or metadata.get("web_roots")
        )
        if seed_ran:
            # Seed triage already did file/binary scan — go straight to firmware tools
            tool_names = _filter_available([
                "firmware_runtime_manifest",
                "firmware_service_inventory",
                "firmware_read_path",
                "firmware_search",
                "firmware_web_surface_map",
            ])
        else:
            tool_names = _filter_available([
                "file_identify",
                "binwalk_scan",
                "strings_extract",
                "file_read",
            ])
        if self._is_firmware_container_target(state):
            tool_names = [n for n in tool_names if n != "file_read"]
        return self.tools.get_openai_schema(tool_names)


class VerificationAgent(BaseAgent):
    """Independent adversarial verifier — mirrors DCRH Grade phase.

    Runs AFTER ExploitAgent. Takes confirmed findings and independently
    re-validates each one using fresh firmware emulation sessions and
    the 5-criteria checklist. Findings are GUILTY UNTIL PROVEN INNOCENT.
    """

    def get_system_prompt(self, state: AgentState) -> str:
        metadata = state.get("metadata", {}) or {}

        # Collect findings that need verification
        findings_to_verify = (
            list(metadata.get("confirmed_findings", []))
            + list(metadata.get("validated_leads", []))
            + [
                f for f in list(metadata.get("candidate_findings", []))
                if str(f.get("severity", "")).upper() in ("CRITICAL", "HIGH")
            ]
        )

        findings_json = json.dumps(
            [
                {
                    "title": f.get("title", ""),
                    "severity": f.get("severity", "unknown"),
                    "vuln_type": f.get("vuln_type", f.get("cwe_id", "")),
                    "component_path": f.get("component_path", ""),
                    "evidence": f.get("evidence", [])[:3],
                }
                for f in findings_to_verify
                if isinstance(f, dict) and f.get("title")
            ],
            indent=2,
        )

        nonce = make_nonce()
        safe_findings = untrusted_block(findings_json, nonce)
        return VERIFICATION_AGENT_SYSTEM_PROMPT.format(
            memory_context=json.dumps(state.get("memory_context", {}), indent=2),
            target=metadata.get("target", ""),
            provenance=metadata.get("provenance", ""),
            findings_to_verify=safe_findings,
            current_tool_evidence=format_current_tool_evidence(
                dict(state.get("compressed_outputs", {}) or {})
            ),
            iteration=state.get("iteration_count", 0),
            max_iterations=self.config.get("max_iterations", 5),
            tokens_remaining=(
                state.get("token_budget", {}).get("total", 100000)
                - state.get("token_budget", {}).get("used", 0)
            ),
            recent_tool_history=format_recent_tool_history(
                list(state.get("executed_tools", []))
            ),
        )

    def get_tools_schema(self, state: AgentState | None = None) -> list[dict[str, Any]]:
        tool_names = _filter_available([
            "firmware_extract_summary",
            "firmware_runtime_manifest",
            "firmware_service_inventory",
            "firmware_emulation_prepare",
            "firmware_emulation_launch_user",
            "firmware_emulation_probe",
            "firmware_emulation_launch_system",
            "firmware_read_path",
            "firmware_search",
            "firmware_web_surface_map",
            "strings_extract",
            "curl_request",
            "nuclei_scan",
            "whatweb_scan",
        ])
        if self._is_firmware_container_target(state):
            tool_names = [n for n in tool_names if n not in {"strings_extract"}]
        if state and self._has_web_findings(state):
            for t in ("nikto_scan", "sslscan", "gobuster_scan"):
                if t not in tool_names:
                    tool_names.append(t)
        tool_names = self._hide_completed_targeted_tools(
            tool_names, state,
            {"firmware_extract_summary", "firmware_web_surface_map", "strings_extract"},
        )
        return self.tools.get_openai_schema(tool_names)

    @staticmethod
    def _has_web_findings(state: AgentState) -> bool:
        """Check if state contains web-type vulnerability findings."""
        findings = (
            state.get("metadata", {}).get("confirmed_findings", [])
            or state.get("metadata", {}).get("validated_leads", [])
            or []
        )
        web_types = {"xss", "sqli", "csrf", "ssrf", "path_traversal",
                      "open_redirect", "ssti", "idor", "command_injection"}
        for f in findings:
            if not isinstance(f, dict):
                continue
            vt = str(f.get("vuln_type", "")).lower().replace("-", "_").replace(" ", "_")
            if vt in web_types:
                return True
        return False


def _filter_available(tool_names: list[str]) -> list[str]:
    import shutil
    command_requirements: dict[str, str] = {}
    return [
        n for n in tool_names
        if n not in command_requirements or shutil.which(command_requirements[n])
    ]
