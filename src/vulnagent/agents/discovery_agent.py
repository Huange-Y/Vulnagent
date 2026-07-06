"""Vulnerability Discovery Agent."""

from __future__ import annotations

import json
import shutil
from typing import Any

from vulnagent.core.agent import BaseAgent
from vulnagent.core.assessment import format_current_tool_evidence, format_recent_tool_history
from vulnagent.core.state import AgentState
from vulnagent.prompts.discovery_prompts import DISCOVERY_AGENT_SYSTEM_PROMPT


class DiscoveryAgent(BaseAgent):
    """Agent for automated vulnerability discovery and scanning.

    Tools: nmap, gobuster, nikto, nuclei, whatweb, sslscan, curl, python_exec
    """

    def get_system_prompt(self, state: AgentState) -> str:
        metadata = state.get("metadata", {}) or {}
        return DISCOVERY_AGENT_SYSTEM_PROMPT.format(
            memory_context=json.dumps(state.get("memory_context", {}), indent=2),
            target=metadata.get("target", ""),
            provenance=metadata.get("provenance", ""),
            priority_targets=json.dumps(metadata.get("priority_targets", []), indent=2),
            preferred_tool_sequence=json.dumps(metadata.get("preferred_tool_sequence", []), indent=2),
            current_tool_evidence=format_current_tool_evidence(dict(state.get("compressed_outputs", {}) or {})),
            iteration=state.get("iteration_count", 0),
            max_iterations=self.config.get("max_iterations", 5),
            tokens_remaining=(
                state.get("token_budget", {}).get("total", 100000)
                - state.get("token_budget", {}).get("used", 0)
            ),
            phase=state.get("phase", "execution"),
            recent_tool_history=format_recent_tool_history(list(state.get("executed_tools", []))),
        )

    def get_tools_schema(self, state: AgentState | None = None) -> list[dict[str, Any]]:
        tool_names = _filter_available_tool_names([
            "file_identify",
            "binwalk_scan",
            "firmware_extract_summary",
            "firmware_extract_rootfs",
            "firmware_runtime_manifest",
            "firmware_service_inventory",
            "firmware_emulation_prepare",
            "firmware_emulation_launch_user",
            "firmware_emulation_probe",
            "firmware_emulation_launch_system",
            "firmware_read_path",
            "firmware_search",
            "firmware_web_surface_map",
            "readelf_headers",
            "strings_extract",
            "nmap_scan",
            "gobuster_scan",
            "nikto_scan",
            "nuclei_scan",
            "whatweb_scan",
            "sslscan",
            "curl_request",
            "python_exec",
            "file_read",
            "generate_poc",
        ])
        if self._is_firmware_container_target(state):
            tool_names = [
                name for name in tool_names
                if name not in {
                    "readelf_headers",
                    "file_read",
                    "nmap_scan",
                    "gobuster_scan",
                    "nikto_scan",
                    "nuclei_scan",
                    "whatweb_scan",
                    "sslscan",
                    "curl_request",
                }
            ]
            if not _firmware_probe_ready(state):
                tool_names = [name for name in tool_names if name != "firmware_emulation_probe"]
            if _firmware_probe_exhausted(state):
                tool_names = [name for name in tool_names if name != "firmware_emulation_probe"]
            if self._has_successful_artifact_search(state):
                tool_names = [name for name in tool_names if name != "firmware_search"]
            if not _firmware_emulation_prep_completed(state):
                tool_names = [name for name in tool_names if name != "firmware_read_path"]
        tool_names = self._hide_completed_targeted_tools(
            tool_names,
            state,
            {
                "file_identify",
                "readelf_headers",
                "strings_extract",
                "binwalk_scan",
                "firmware_extract_rootfs",
                "firmware_extract_summary",
                "firmware_web_surface_map",
            },
        )
        tool_names = self._hide_completed_targeted_tools(
            tool_names,
            state,
            {
                "firmware_runtime_manifest",
                "firmware_service_inventory",
            },
        )
        tool_names = _hide_attempted_targeted_tools(
            tool_names,
            state,
            {
                "firmware_emulation_prepare",
                "firmware_emulation_launch_user",
                "firmware_emulation_launch_system",
            },
        )
        if BaseAgent._target_tool_matches(
            state,
            {"firmware_runtime_manifest"},
            require_success=True,
        ):
            tool_names = [name for name in tool_names if name != "firmware_extract_rootfs"]
        if _firmware_readback_budget_exhausted(state):
            tool_names = [name for name in tool_names if name != "firmware_read_path"]
        return self.tools.get_openai_schema(tool_names)


def _filter_available_tool_names(tool_names: list[str]) -> list[str]:
    command_requirements = {
        "nmap_scan": "nmap",
        "gobuster_scan": "gobuster",
        "nikto_scan": "nikto",
        "nuclei_scan": "nuclei",
        "whatweb_scan": "whatweb",
        "sslscan": "sslscan",
        "curl_request": "curl",
    }
    filtered: list[str] = []
    for tool_name in tool_names:
        required_binary = command_requirements.get(tool_name)
        if required_binary and shutil.which(required_binary) is None:
            continue
        filtered.append(tool_name)
    return filtered


def _firmware_emulation_prep_completed(state: AgentState | None) -> bool:
    successful = BaseAgent._target_tool_matches(
        state,
        {"firmware_runtime_manifest", "firmware_service_inventory"},
        require_success=True,
    )
    attempted = BaseAgent._target_tool_matches(
        state,
        {"firmware_emulation_prepare", "firmware_emulation_launch_user", "firmware_emulation_launch_system"},
        require_success=False,
    )
    return (
        "firmware_runtime_manifest" in successful
        and "firmware_service_inventory" in successful
        and bool(attempted)
    )


def _firmware_probe_ready(state: AgentState | None) -> bool:
    if not state:
        return False
    current_agent = state.get("current_agent", "")
    launch_calls = [
        t for t in state.get("executed_tools", [])
        if isinstance(t, dict) and t.get("name") == "firmware_emulation_launch_user"
        and (
            t.get("agent", "") == current_agent
            or t.get("seeded") is True  # auto-validation during seed triage
        )
    ]
    if not launch_calls:
        return False
    return any(t.get("success") for t in launch_calls[-2:])


def _firmware_probe_exhausted(state: AgentState | None) -> bool:
    """Block firmware_emulation_probe after 8 attempts to prevent loops."""
    if not state:
        return False
    count = 0
    for entry in list(state.get("executed_tools", [])):
        if not isinstance(entry, dict):
            continue
        name = str(entry.get("name", "")).strip()
        if name == "firmware_emulation_probe" or name.startswith("firmware_emulation_probe#"):
            count += 1
    return count >= 8


def _hide_attempted_targeted_tools(
    tool_names: list[str],
    state: AgentState | None,
    candidate_names: set[str],
) -> list[str]:
    attempted = BaseAgent._target_tool_matches(
        state,
        candidate_names,
        require_success=False,
    )
    if not attempted:
        return list(tool_names)
    return [name for name in tool_names if name not in attempted]


def _firmware_readback_budget_exhausted(state: AgentState | None) -> bool:
    if not BaseAgent._is_firmware_container_target(state):
        return False

    attempted_emulation = BaseAgent._target_tool_matches(
        state,
        {"firmware_emulation_prepare", "firmware_emulation_launch_user", "firmware_emulation_launch_system"},
        require_success=False,
    )
    if not attempted_emulation:
        return False

    metadata = state.get("metadata", {}) or {}
    target = str(metadata.get("target", "")).strip()
    successful_reads = 0
    for entry in list(state.get("executed_tools", [])):
        if not isinstance(entry, dict):
            continue
        if str(entry.get("name", "")).strip() != "firmware_read_path":
            continue
        if not bool(entry.get("success", False)):
            continue
        args = BaseAgent._coerce_tool_args(entry.get("args"))
        if not isinstance(args, dict):
            continue
        if str(args.get("path", "")).strip() != target:
            continue
        successful_reads += 1
        if successful_reads >= 8:
            return True
    return False
