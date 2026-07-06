"""Report Generation Agent — single-pass, no tool loop."""

from __future__ import annotations

import json
from typing import Any

from langgraph.graph import StateGraph, END, START

from vulnagent.core.agent import BaseAgent
from vulnagent.core.assessment import build_report_sections
from vulnagent.core.state import AgentState
from vulnagent.prompts.remediation_prompts import remediation_context_for_findings
from vulnagent.prompts.report_prompts import REPORT_AGENT_SYSTEM_PROMPT
from vulnagent.prompts.untrusted import make_nonce, untrusted_block


class ReportAgent(BaseAgent):
    """Single-pass agent for generating vulnerability reports.

    Unlike other agents, this one does NOT use a tool loop.
    It takes findings and generates a formatted report in one LLM call.
    """

    def get_system_prompt(self, state: AgentState) -> str:
        metadata = state.get("metadata", {}) or {}
        findings = metadata.get("sub_agents_findings", [])
        anchor = state.get("anchored_summary", {})

        confirmed = list(metadata.get("confirmed_findings", []))
        validated = list(metadata.get("validated_leads", []))
        all_findings = confirmed + validated
        if not all_findings:
            all_findings = list(metadata.get("candidate_findings", []))
        remediation_context = remediation_context_for_findings(all_findings)

        outline = build_report_sections(
            target=metadata.get("target", ""),
            scope=metadata.get("scope", ""),
            provenance=metadata.get("provenance", ""),
            confirmed_findings=confirmed,
            validated_leads=validated,
            candidate_findings=list(metadata.get("candidate_findings", [])),
            evidence=list(metadata.get("evidence_log", [])),
            priority_targets=list(metadata.get("priority_targets", [])),
            next_steps=list(metadata.get("next_steps", [])),
            remediation_blocks=remediation_context,
        )
        nonce = make_nonce()
        safe_findings = untrusted_block(json.dumps(findings, indent=2), nonce)
        safe_remediation = untrusted_block(remediation_context, nonce)
        safe_anchor = untrusted_block(json.dumps(anchor, indent=2), nonce)
        return REPORT_AGENT_SYSTEM_PROMPT + (
            f"\n\n## Required Report Skeleton\n{outline}\n\n"
            f"\n\n## Findings\n{safe_findings}\n\n"
            f"## Context\n{safe_anchor}\n\n"
            f"## Remediation Reference\n{safe_remediation}"
        )

    def get_tools_schema(self, state: AgentState | None = None) -> list[dict[str, Any]]:
        return []  # Report agent uses no tools

    def build_graph(self) -> Any:
        """Override: single-pass graph, no tool loop."""
        builder = StateGraph(AgentState)

        builder.add_node("generate_report", self._reasoning_node)
        builder.add_edge(START, "generate_report")
        builder.add_edge("generate_report", END)

        return builder.compile()
