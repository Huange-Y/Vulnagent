"""Tests for vulnerability orchestrator public behavior."""

from __future__ import annotations

import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch, MagicMock

from langchain_core.messages import AIMessage, HumanMessage

from vulnagent.orchestrator import VulnOrchestrator
from vulnagent.tools.vuln_tools import _runtime_workspace_for_artifact


class FakeConfig:
    def __init__(self) -> None:
        self.values = {}

    def set(self, key: str, value) -> None:
        self.values[key] = value


class FakeAgent:
    def __init__(self, name: str, final_result: str = "") -> None:
        self.name = name
        self.final_result = final_result
        self.config = FakeConfig()
        self.seen_state = None
        self.messages = []
        self.tool_outputs = {}
        self.compressed_outputs = {}

    def invoke(self, state):
        self.seen_state = state
        findings = list(state.get("metadata", {}).get("sub_agents_findings", []))
        if self.final_result:
            findings.append({"agent": self.name, "result": self.final_result})
        return {
            **state,
            "final_result": self.final_result,
            "messages": self.messages,
            "tool_outputs": {**state.get("tool_outputs", {}), **self.tool_outputs},
            "compressed_outputs": {
                **state.get("compressed_outputs", {}),
                **self.compressed_outputs,
            },
            "metadata": {**state.get("metadata", {}), "sub_agents_findings": findings},
        }


class FakeRouter:
    def reason(self, *args, **kwargs):
        raise AssertionError("not used")


def _mock_agents(discovery: FakeAgent, exploit: FakeAgent, report: FakeAgent):
    """Return a callable side_effect for _get_agent that routes by name.

    Supports pipelines with optional brainstorm/verification phases —
    agents are always returned by name, not by position. Default agents
    for brainstorm and verification are created on demand.
    """
    brainstorm_agent = FakeAgent("brainstorm", "")
    verification_agent = FakeAgent("verification", "")

    def _get(name: str):
        return {
            "brainstorm": brainstorm_agent,
            "discovery": discovery,
            "exploit": exploit,
            "verification": verification_agent,
            "report": report,
        }[name]

    return _get


class TestVulnOrchestrator(unittest.TestCase):
    def test_run_executes_discovery_exploit_and_report_agents(self) -> None:
        orchestrator = VulnOrchestrator(FakeRouter(), memory_path=":memory:")
        discovery = FakeAgent("discovery", "open port 80")
        exploit = FakeAgent("exploit", "reflected xss")
        report = FakeAgent("report", "final report")

        with patch.object(orchestrator, "_get_agent", side_effect=_mock_agents(discovery, exploit, report)):
            result = orchestrator.run("https://example.test", scope="authorized test", max_iterations=2, token_limit=999)

        self.assertTrue(result["success"])
        self.assertIn("## Executive Summary", result["report"])
        self.assertIn("final report", result["report"])
        self.assertIn("## Scope", result["report"])
        self.assertEqual(result["target"], "https://example.test")
        self.assertEqual(discovery.seen_state["metadata"]["scope"], "authorized test")
        self.assertEqual(discovery.seen_state["token_budget"]["total"], 999)
        self.assertEqual(exploit.seen_state["metadata"]["sub_agents_findings"][0]["result"], "open port 80")

    def test_run_builds_fallback_report_when_report_agent_produces_no_report(self) -> None:
        orchestrator = VulnOrchestrator(FakeRouter(), memory_path=":memory:")
        discovery = FakeAgent("discovery", "open port 80")
        exploit = FakeAgent("exploit", "reflected xss")
        report = FakeAgent("report", "")

        with patch.object(orchestrator, "_get_agent", side_effect=_mock_agents(discovery, exploit, report)):
            result = orchestrator.run("https://example.test", scope="authorized test")

        self.assertTrue(result["success"])
        self.assertIn("Executive Summary", result["report"])
        self.assertIn("authorized test", result["report"])
        self.assertIn("Priority Targets", result["report"])
        self.assertIn("Validation Closure", result["report"])
        self.assertEqual(len(result["findings"]), 2)

    def test_run_seeds_provenance_metadata(self) -> None:
        orchestrator = VulnOrchestrator(FakeRouter(), memory_path=":memory:")
        discovery = FakeAgent("discovery", "found busybox")
        exploit = FakeAgent("exploit", "")
        report = FakeAgent("report", "final report")

        with tempfile.NamedTemporaryFile(suffix=".bin") as handle:
            with patch.object(orchestrator, "_get_agent", side_effect=_mock_agents(discovery, exploit, report)):
                orchestrator.run(handle.name, scope="filesystem triage")

        self.assertEqual(discovery.seen_state["metadata"]["target"], handle.name)
        self.assertEqual(discovery.seen_state["metadata"]["scope"], "filesystem triage")
        self.assertTrue(discovery.seen_state["metadata"]["provenance"])

    def test_run_registers_runtime_run_for_local_artifact(self) -> None:
        orchestrator = VulnOrchestrator(FakeRouter(), memory_path=":memory:")
        discovery = FakeAgent("discovery", "found busybox")
        exploit = FakeAgent("exploit", "")
        report = FakeAgent("report", "final report")

        with tempfile.NamedTemporaryFile(suffix=".img") as handle:
            with patch.object(orchestrator, "_get_agent", side_effect=_mock_agents(discovery, exploit, report)):
                result = orchestrator.run(handle.name, scope="integration-test", max_iterations=1, token_limit=2000)

        self.assertIn("run_id", result)
        self.assertTrue(result["run_id"])
        self.assertIn("runtime_root", result)
        self.assertTrue(str(result["runtime_root"]).endswith(result["run_id"]))

    def test_run_records_completed_agent_statuses_in_runtime_store(self) -> None:
        orchestrator = VulnOrchestrator(FakeRouter(), memory_path=":memory:")
        discovery = FakeAgent("discovery", "found busybox")
        exploit = FakeAgent("exploit", "")
        report = FakeAgent("report", "final report")

        with tempfile.NamedTemporaryFile(suffix=".img") as handle:
            with patch.object(orchestrator, "_get_agent", side_effect=_mock_agents(discovery, exploit, report)):
                result = orchestrator.run(handle.name, scope="integration-test", max_iterations=1, token_limit=2000)

        agents = orchestrator.runtime_store.list_run_agents(result["run_id"])
        status_by_name = {item["agent_name"]: item["status"] for item in agents}

        self.assertEqual(status_by_name["discovery"], "completed")
        self.assertEqual(status_by_name["exploit"], "completed")
        self.assertEqual(status_by_name["report"], "completed")

    def test_run_recovers_summary_from_ai_message_and_artifact_outputs(self) -> None:
        orchestrator = VulnOrchestrator(FakeRouter(), memory_path=":memory:")
        discovery = FakeAgent("discovery", "")
        discovery.messages = [
            AIMessage(content="BusyBox 1.19.4 and admin:admin were found in extracted firmware strings."),
            HumanMessage(content="[SYSTEM] You must call a tool to proceed."),
        ]
        discovery.tool_outputs = {
            "file_identify": "embedded signatures:\n  - 0x00000040: SquashFS filesystem",
            "strings_extract": "BusyBox v1.19.4\nadmin:admin\nGoAhead-Webs\n",
        }
        discovery.compressed_outputs = dict(discovery.tool_outputs)

        exploit = FakeAgent("exploit", "")
        report = FakeAgent("report", "")
        report.messages = [
            AIMessage(content="## Executive Summary\nRecovered findings from prior analysis."),
        ]

        with tempfile.NamedTemporaryFile(suffix=".bin") as handle:
            with patch.object(orchestrator, "_get_agent", side_effect=_mock_agents(discovery, exploit, report)):
                result = orchestrator.run(handle.name, scope="firmware triage")

        self.assertTrue(result["success"])
        self.assertIn("Recovered findings from prior analysis", result["report"])
        self.assertIn("admin:admin", result["report"])
        self.assertIn("Review default credential path and login handlers", result["report"])

    def test_run_projects_candidate_findings_into_runtime_store(self) -> None:
        orchestrator = VulnOrchestrator(FakeRouter(), memory_path=":memory:")
        discovery = FakeAgent("discovery", "")
        discovery.tool_outputs = {
            "file_identify": "embedded signatures:\n  - 0x00000040: SquashFS filesystem",
            "strings_extract": "BusyBox v1.19.4\nadmin:admin\nGoAhead-Webs\n",
        }
        discovery.compressed_outputs = dict(discovery.tool_outputs)

        exploit = FakeAgent("exploit", "")
        report = FakeAgent("report", "## Executive Summary\nRecovered findings from prior analysis.")

        with tempfile.NamedTemporaryFile(suffix=".bin") as handle:
            with patch.object(orchestrator, "_get_agent", side_effect=_mock_agents(discovery, exploit, report)):
                result = orchestrator.run(handle.name, scope="runtime projection")

        findings = orchestrator.runtime_store.list_findings(result["run_id"])
        self.assertTrue(findings)
        self.assertTrue(any("BusyBox" in item["title"] or "credential" in item["title"].lower() for item in findings))

    def test_run_applies_pending_run_intervention_to_discovery_phase(self) -> None:
        orchestrator = VulnOrchestrator(FakeRouter(), memory_path=":memory:")
        discovery = FakeAgent("discovery", "found busybox")
        exploit = FakeAgent("exploit", "")
        report = FakeAgent("report", "final report")

        original_create_run = orchestrator.runtime_store.create_run

        def create_run_with_intervention(**kwargs):
            record = original_create_run(**kwargs)
            orchestrator.runtime_store.create_intervention(
                run_id=record.run_id,
                scope_type="run",
                scope_id=record.run_id,
                instruction="Prioritize the telnetd path before any broad rescans.",
            )
            return record

        with tempfile.NamedTemporaryFile(suffix=".bin") as handle:
            with patch.object(orchestrator.runtime_store, "create_run", side_effect=create_run_with_intervention):
                with patch.object(orchestrator, "_get_agent", side_effect=_mock_agents(discovery, exploit, report)):
                    result = orchestrator.run(handle.name, scope="runtime intervention")

        self.assertTrue(result["success"])
        self.assertTrue(discovery.seen_state["messages"])
        self.assertIn("Prioritize the telnetd path", discovery.seen_state["messages"][0].content)

        interventions = orchestrator.runtime_store.list_run_interventions(result["run_id"])
        self.assertEqual(interventions[0]["status"], "applied")
        self.assertIn("discovery phase", interventions[0]["response_summary"])

        timeline = orchestrator.runtime_store.list_run_timeline(result["run_id"], limit=20)
        self.assertTrue(any(item["type"] == "intervention.applied" for item in timeline))

    def test_run_applies_agent_scoped_intervention_only_to_matching_phase(self) -> None:
        orchestrator = VulnOrchestrator(FakeRouter(), memory_path=":memory:")
        discovery = FakeAgent("discovery", "open port 80")
        exploit = FakeAgent("exploit", "validated command injection")
        report = FakeAgent("report", "final report")

        original_create_run = orchestrator.runtime_store.create_run

        def create_run_with_intervention(**kwargs):
            record = original_create_run(**kwargs)
            orchestrator.runtime_store.create_intervention(
                run_id=record.run_id,
                scope_type="agent",
                scope_id=f"{record.run_id}:exploit",
                instruction="Stop broad fuzzing and validate the authenticated command path first.",
            )
            return record

        with patch.object(orchestrator.runtime_store, "create_run", side_effect=create_run_with_intervention):
            with patch.object(orchestrator, "_get_agent", side_effect=_mock_agents(discovery, exploit, report)):
                result = orchestrator.run("https://example.test", scope="agent scoped intervention")

        self.assertTrue(result["success"])
        self.assertEqual(discovery.seen_state["messages"], [])
        self.assertTrue(exploit.seen_state["messages"])
        self.assertIn("authenticated command path", exploit.seen_state["messages"][0].content)

    def test_run_ignores_trivial_agent_acknowledgements_in_report_merging(self) -> None:
        orchestrator = VulnOrchestrator(FakeRouter(), memory_path=":memory:")
        discovery = FakeAgent("discovery", "")
        discovery.messages = [
            AIMessage(content="Great."),
        ]
        discovery.tool_outputs = {
            "file_identify": "embedded signatures:\n  - 0x00000040: SquashFS filesystem",
            "strings_extract": "admin:admin\nGoAhead-Webs\n",
        }
        discovery.compressed_outputs = dict(discovery.tool_outputs)

        exploit = FakeAgent("exploit", "")
        exploit.messages = [AIMessage(content="OK")]
        report = FakeAgent("report", "")
        report.messages = [AIMessage(content="## Executive Summary\nRecovered findings from prior analysis.")]

        with tempfile.NamedTemporaryFile(suffix=".bin") as handle:
            with patch.object(orchestrator, "_get_agent", side_effect=_mock_agents(discovery, exploit, report)):
                result = orchestrator.run(handle.name, scope="firmware triage")

        self.assertTrue(result["success"])
        self.assertNotIn("Great.", result["report"])
        self.assertNotIn("- OK", result["report"])

    def test_run_ignores_artifact_followup_pitch_in_discovery_summary(self) -> None:
        orchestrator = VulnOrchestrator(FakeRouter(), memory_path=":memory:")
        discovery = FakeAgent("discovery", "")
        discovery.messages = [
            AIMessage(
                content=(
                    "I'm ready to continue with the firmware analysis on firmware.bin.\n"
                    "Because repeated reads of the same inner_path are blocked, the next step is to inspect different files.\n"
                    "If you want, I can continue by checking likely high-value paths such as /etc/passwd and /etc/shadow."
                )
            ),
        ]
        discovery.tool_outputs = {
            "file_identify": "embedded signatures:\n  - 0x00000040: SquashFS filesystem",
            "strings_extract": "GoAhead-Webs\nform2Telnet.cgi\nadmin:admin\n",
        }
        discovery.compressed_outputs = dict(discovery.tool_outputs)

        exploit = FakeAgent("exploit", "")
        report = FakeAgent("report", "")

        with tempfile.NamedTemporaryFile(suffix=".bin") as handle:
            with patch.object(orchestrator, "_get_agent", side_effect=_mock_agents(discovery, exploit, report)):
                result = orchestrator.run(handle.name, scope="firmware triage")

        self.assertTrue(result["success"])
        self.assertNotIn("I'm ready to continue", result["report"])

    def test_run_does_not_echo_report_stage_summary_into_supporting_evidence(self) -> None:
        orchestrator = VulnOrchestrator(FakeRouter(), memory_path=":memory:")
        discovery = FakeAgent("discovery", "found busybox")
        exploit = FakeAgent("exploit", "")
        report = FakeAgent("report", "")
        report.messages = [
            AIMessage(content="## Executive Summary\nRecovered findings from prior analysis."),
        ]

        with tempfile.NamedTemporaryFile(suffix=".bin") as handle:
            with patch.object(orchestrator, "_get_agent", side_effect=_mock_agents(discovery, exploit, report)):
                result = orchestrator.run(handle.name, scope="firmware triage")

        self.assertTrue(result["success"])
        self.assertNotIn("- report:", result["report"])

    def test_run_does_not_promote_generic_exploit_summary_to_confirmed_finding(self) -> None:
        orchestrator = VulnOrchestrator(FakeRouter(), memory_path=":memory:")
        discovery = FakeAgent("discovery", "found goahead")
        exploit = FakeAgent("exploit", "Initial firmware triage looks promising.")
        report = FakeAgent("report", "")

        with patch.object(orchestrator, "_get_agent", side_effect=_mock_agents(discovery, exploit, report)):
            result = orchestrator.run("https://example.test", scope="authorized test")

        self.assertTrue(result["success"])
        self.assertNotIn("Initial firmware triage looks promising.", result["report"])

    def test_run_continues_into_exploit_phase_for_static_firmware_artifacts(self) -> None:
        orchestrator = VulnOrchestrator(FakeRouter(), memory_path=":memory:")
        discovery = FakeAgent("discovery", "")
        discovery.tool_outputs = {
            "firmware_runtime_manifest": "ARTIFACT_PATH: firmware.img\nARCHITECTURE: mips",
            "firmware_emulation_launch_system": "PACKAGE_PATH: E:/Temp/vulnagent/runs/demo/emulation/launch-system.txt",
        }
        discovery.compressed_outputs = dict(discovery.tool_outputs)
        exploit = FakeAgent("exploit", "Need to validate upload and telnet paths before concluding.")
        report = FakeAgent("report", "## Executive Summary\nStatic firmware triage only.")

        with tempfile.NamedTemporaryFile(suffix=".img") as handle:
            with patch.object(orchestrator, "_get_agent", side_effect=[discovery, exploit, FakeAgent("verification", ""), report]):
                result = orchestrator.run(handle.name, scope="firmware triage", max_iterations=1, token_limit=500)

        self.assertTrue(result["success"])
        self.assertIsNotNone(exploit.seen_state)
        self.assertEqual(exploit.seen_state["current_agent"], "exploit")
        self.assertIn("Static firmware triage only.", result["report"])

    def test_run_strips_leading_acknowledgement_lines_from_agent_summaries(self) -> None:
        orchestrator = VulnOrchestrator(FakeRouter(), memory_path=":memory:")
        discovery = FakeAgent("discovery", "")
        discovery.messages = [
            AIMessage(content="Got it.\n- /bin/goahead present\n- /etc_ro/web/d_telnet.asp present"),
        ]
        discovery.tool_outputs = {
            "file_identify": "embedded signatures:\n  - 0x00000040: SquashFS filesystem",
            "strings_extract": "GoAhead-Webs\nform2Telnet.cgi\n",
        }
        discovery.compressed_outputs = dict(discovery.tool_outputs)
        exploit = FakeAgent("exploit", "")
        report = FakeAgent("report", "")

        with tempfile.NamedTemporaryFile(suffix=".bin") as handle:
            with patch.object(orchestrator, "_get_agent", side_effect=_mock_agents(discovery, exploit, report)):
                result = orchestrator.run(handle.name, scope="firmware triage")

        self.assertTrue(result["success"])
        self.assertNotIn("Got it.", result["report"])
        self.assertIn("/bin/goahead present", result["report"])

    def test_report_stage_starts_with_clean_message_history(self) -> None:
        orchestrator = VulnOrchestrator(FakeRouter(), memory_path=":memory:")
        discovery = FakeAgent("discovery", "open port 80")
        exploit = FakeAgent("exploit", "reflected xss")
        exploit.messages = [HumanMessage(content="polluted tool-loop transcript")]
        report = FakeAgent("report", "final report")

        with patch.object(orchestrator, "_get_agent", side_effect=_mock_agents(discovery, exploit, report)):
            orchestrator.run("https://example.test", scope="authorized test")

        self.assertEqual(report.seen_state["messages"], [])

    def test_run_returns_missing_artifact_error_before_agent_execution(self) -> None:
        orchestrator = VulnOrchestrator(FakeRouter(), memory_path=":memory:")

        with patch.object(orchestrator, "_get_agent") as get_agent:
            result = orchestrator.run("missing_firmware.img", scope="firmware triage")

        self.assertFalse(result["success"])
        self.assertIn("missing_firmware.img", result["error"])
        self.assertEqual(result["report"], "")
        get_agent.assert_not_called()

    def test_run_returns_missing_artifact_error_for_plain_relative_artifact_name(self) -> None:
        orchestrator = VulnOrchestrator(FakeRouter(), memory_path=":memory:")

        with patch.object(orchestrator, "_get_agent") as get_agent:
            result = orchestrator.run("firmware.bin", scope="firmware triage")

        self.assertFalse(result["success"])
        self.assertIn("firmware.bin", result["error"])
        get_agent.assert_not_called()

    def test_run_rejects_empty_artifact_directory(self) -> None:
        orchestrator = VulnOrchestrator(FakeRouter(), memory_path=":memory:")

        with tempfile.TemporaryDirectory() as tmpdir:
            with patch.object(orchestrator, "_get_agent") as get_agent:
                result = orchestrator.run(tmpdir, scope="firmware triage")

        self.assertFalse(result["success"])
        self.assertIn("No firmware artifacts found", result["error"])
        get_agent.assert_not_called()

    def test_run_resolves_single_artifact_from_directory_target(self) -> None:
        orchestrator = VulnOrchestrator(FakeRouter(), memory_path=":memory:")
        discovery = FakeAgent("discovery", "found busybox")
        exploit = FakeAgent("exploit", "")
        report = FakeAgent("report", "final report")

        with tempfile.TemporaryDirectory() as tmpdir:
            artifact = tempfile.NamedTemporaryFile(dir=tmpdir, suffix=".bin", delete=False)
            artifact.close()
            with patch.object(orchestrator, "_get_agent", side_effect=_mock_agents(discovery, exploit, report)):
                result = orchestrator.run(tmpdir, scope="firmware triage")

        self.assertTrue(result["success"])
        self.assertEqual(result["target"], artifact.name)
        self.assertEqual(discovery.seen_state["metadata"]["target"], artifact.name)

    def test_run_prefers_firmware_like_artifact_over_json_report(self) -> None:
        orchestrator = VulnOrchestrator(FakeRouter(), memory_path=":memory:")
        discovery = FakeAgent("discovery", "found busybox")
        exploit = FakeAgent("exploit", "")
        report = FakeAgent("report", "final report")

        with tempfile.TemporaryDirectory() as tmpdir:
            report_file = tempfile.NamedTemporaryFile(dir=tmpdir, suffix=".json", delete=False)
            report_file.write(b"x" * 4096)
            report_file.close()
            artifact = tempfile.NamedTemporaryFile(dir=tmpdir, suffix=".bin", delete=False)
            artifact.write(b"x" * 512)
            artifact.close()
            with patch.object(orchestrator, "_get_agent", side_effect=_mock_agents(discovery, exploit, report)):
                result = orchestrator.run(tmpdir, scope="firmware triage")

        self.assertTrue(result["success"])
        self.assertEqual(result["target"], artifact.name)

    def test_run_seeds_local_artifact_triage_before_discovery_agent(self) -> None:
        orchestrator = VulnOrchestrator(FakeRouter(), memory_path=":memory:")
        discovery = FakeAgent("discovery", "found busybox")
        exploit = FakeAgent("exploit", "")
        report = FakeAgent("report", "final report")

        with tempfile.NamedTemporaryFile(suffix=".bin") as artifact:
            artifact.write(b"A" * 16 + b"hsqs" + b"B" * 16 + b"BusyBox v1.19.4\x00admin:admin\x00")
            artifact.flush()
            with patch.object(orchestrator, "_get_agent", side_effect=_mock_agents(discovery, exploit, report)):
                orchestrator.run(artifact.name, scope="firmware triage")

        seeded_tools = discovery.seen_state["tool_outputs"]
        self.assertIn("file_identify", seeded_tools)
        self.assertIn("binwalk_scan", seeded_tools)
        self.assertIn("strings_extract", seeded_tools)

    def test_run_seeded_firmware_workspace_reuses_primary_run_id(self) -> None:
        orchestrator = VulnOrchestrator(FakeRouter(), memory_path=":memory:")
        discovery = FakeAgent("discovery", "found busybox")
        exploit = FakeAgent("exploit", "")
        report = FakeAgent("report", "final report")

        identify_tool = orchestrator.tool_registry.get("file_identify")
        binwalk_tool = orchestrator.tool_registry.get("binwalk_scan")
        self.assertIsNotNone(identify_tool)
        self.assertIsNotNone(binwalk_tool)
        assert identify_tool is not None
        assert binwalk_tool is not None

        identify_tool.executor = lambda _params: SimpleNamespace(
            stdout="/tmp/demo.img: SquashFS filesystem image",
            stderr="",
            return_code=0,
        )
        binwalk_tool.executor = lambda _params: SimpleNamespace(
            stdout="0x00000010 SquashFS filesystem",
            stderr="",
            return_code=0,
        )

        prepare_tool = orchestrator.tool_registry.get("firmware_emulation_prepare")
        self.assertIsNotNone(prepare_tool)
        assert prepare_tool is not None

        captured_workspace_lines: list[str] = []

        def capturing_executor(params):
            workspace = _runtime_workspace_for_artifact(params["path"])
            output = f"WORKSPACE_ROOT: {workspace.root}"
            captured_workspace_lines.append(output)
            return SimpleNamespace(
                stdout=output,
                stderr="",
                return_code=0,
            )

        prepare_tool.executor = capturing_executor

        summary_tool = orchestrator.tool_registry.get("firmware_extract_summary")
        self.assertIsNotNone(summary_tool)
        assert summary_tool is not None
        summary_tool.executor = lambda _params: SimpleNamespace(
            stdout=(
                "SQUASHFS_FOUND offset=0x00000010\n"
                "INTERESTING_PATH: /bin/goahead\n"
                "TEXT_HIT: /etc_ro/rcS :: telnetd\n"
            ),
            stderr="",
            return_code=0,
        )

        with tempfile.NamedTemporaryFile(suffix=".img") as handle:
            handle.write(b"A" * 16 + b"hsqs" + b"B" * 16)
            handle.flush()
            with patch.object(orchestrator, "_get_agent", side_effect=[discovery, exploit, FakeAgent("verification", ""), report]):
                result = orchestrator.run(handle.name, scope="firmware triage", max_iterations=1, token_limit=2000)

        self.assertTrue(result["run_id"])
        self.assertTrue(captured_workspace_lines)
        self.assertTrue(any(result["run_id"] in line for line in captured_workspace_lines))

    def test_run_seeds_firmware_extract_summary_for_local_firmware_candidates(self) -> None:
        orchestrator = VulnOrchestrator(FakeRouter(), memory_path=":memory:")
        discovery = FakeAgent("discovery", "found goahead")
        exploit = FakeAgent("exploit", "")
        report = FakeAgent("report", "final report")

        tool = orchestrator.tool_registry.get("firmware_extract_summary")
        self.assertIsNotNone(tool)
        assert tool is not None
        tool.executor = lambda _params: SimpleNamespace(
            stdout=(
                "SQUASHFS_FOUND offset=0x00000010\n"
                "INTERESTING_PATH: /bin/goahead\n"
                "TEXT_HIT: /etc_ro/rcS :: telnetd\n"
            ),
            stderr="",
            return_code=0,
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            artifact = tempfile.NamedTemporaryFile(dir=tmpdir, suffix=".bin", delete=False)
            artifact.write(b"A" * 16 + b"hsqs" + b"B" * 16)
            artifact.close()
            with patch.object(orchestrator, "_get_agent", side_effect=_mock_agents(discovery, exploit, report)):
                orchestrator.run(artifact.name, scope="firmware triage")

        seeded_tools = discovery.seen_state["tool_outputs"]
        self.assertIn("firmware_extract_summary", seeded_tools)
        self.assertIn("SQUASHFS_FOUND", seeded_tools["firmware_extract_summary"])

    def test_run_seeds_targeted_firmware_file_reads_without_overwriting_outputs(self) -> None:
        orchestrator = VulnOrchestrator(FakeRouter(), memory_path=":memory:")
        discovery = FakeAgent("discovery", "found goahead")
        exploit = FakeAgent("exploit", "")
        report = FakeAgent("report", "final report")

        summary_tool = orchestrator.tool_registry.get("firmware_extract_summary")
        read_tool = orchestrator.tool_registry.get("firmware_read_path")
        search_tool = orchestrator.tool_registry.get("firmware_search")
        map_tool = orchestrator.tool_registry.get("firmware_web_surface_map")
        self.assertIsNotNone(summary_tool)
        self.assertIsNotNone(read_tool)
        self.assertIsNotNone(search_tool)
        self.assertIsNotNone(map_tool)
        assert summary_tool is not None
        assert read_tool is not None
        assert search_tool is not None
        assert map_tool is not None

        summary_tool.executor = lambda _params: SimpleNamespace(
            stdout=(
                "SQUASHFS_FOUND offset=0x00000010\n"
                "INTERESTING_PATH: /etc_ro/rcS\n"
                "INTERESTING_PATH: /etc_ro/web/d_telnet.asp\n"
                "INTERESTING_PATH: /bin/goahead\n"
                "INTERESTING_PATH: /etc_ro/web/cgi-bin/ExportSettings.sh\n"
                "INTERESTING_PATH: /etc_ro/web/dir_login.asp\n"
            ),
            stderr="",
            return_code=0,
        )

        def fake_read_executor(params):
            inner_path = params["inner_path"]
            if inner_path == "/etc_ro/web/d_telnet.asp":
                stdout = "<form action=\"/goform/form2Telnet.cgi\"></form>"
            elif inner_path == "/etc_ro/web/dir_login.asp":
                stdout = "<form action=\"goform/formLogin\"></form>"
            elif inner_path == "/bin/goahead":
                stdout = "showSystemCommandASP\nform2Telnet.cgi\ngoform/formLogin\ndoSystem"
            else:
                stdout = f"READ::{inner_path}"
            return SimpleNamespace(
                stdout=stdout,
                stderr="",
                return_code=0,
            )

        read_tool.executor = fake_read_executor
        search_tool.executor = lambda params: SimpleNamespace(
            stdout=f"SEARCH_PATTERN: {params['pattern']}\nMATCH: /bin/goahead [strings] :: {params['pattern']}",
            stderr="",
            return_code=0,
        )
        map_tool.executor = lambda _params: SimpleNamespace(
            stdout=(
                "TEXT_ROUTE: /etc_ro/web/d_telnet.asp -> /goform/form2Telnet.cgi\n"
                "TEXT_ROUTE: /etc_ro/web/dir_login.asp -> goform/formLogin\n"
                "TEXT_ROUTE: /etc_ro/web/d_saveconf.asp -> /cgi-bin/upload_settings.cgi\n"
                "TEXT_ROUTE: /etc_ro/web/d_upload.asp -> /cgi-bin/upload.cgi\n"
                "TEXT_ROUTE: /etc_ro/web/d_wl5wps_step1.asp -> /goform/fform2Wl5Wsc.cgi\n"
                "BINARY_ROUTE: /bin/goahead -> /cgi-bin/upload.cgi\n"
                "ROUTE_CORRELATION: /cgi-bin/upload.cgi :: web:/etc_ro/web/d_upload.asp | binary:/bin/goahead\n"
            ),
            stderr="",
            return_code=0,
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            artifact = tempfile.NamedTemporaryFile(dir=tmpdir, suffix=".bin", delete=False)
            artifact.write(b"A" * 16 + b"hsqs" + b"B" * 16)
            artifact.close()
            with patch.object(orchestrator, "_get_agent", side_effect=_mock_agents(discovery, exploit, report)):
                orchestrator.run(artifact.name, scope="firmware triage")

        seeded_tools = discovery.seen_state["tool_outputs"]
        self.assertIn("firmware_extract_summary", seeded_tools)
        self.assertIn("firmware_read_path:/etc_ro/rcS", seeded_tools)
        self.assertIn("firmware_read_path:/etc_ro/web/d_telnet.asp", seeded_tools)
        self.assertIn("firmware_read_path:/bin/goahead", seeded_tools)
        self.assertIn("firmware_read_path:/etc_ro/web/cgi-bin/ExportSettings.sh", seeded_tools)
        self.assertIn("firmware_read_path:/etc_ro/web/d_saveconf.asp", seeded_tools)
        self.assertIn("firmware_read_path:/etc_ro/web/d_upload.asp", seeded_tools)
        self.assertNotIn("firmware_read_path:/etc_ro/web/d_wl5wps_step1.asp", seeded_tools)
        self.assertIn("firmware_web_surface_map", seeded_tools)
        self.assertIn("firmware_search:form2Telnet.cgi", seeded_tools)
        self.assertIn("firmware_search:goform/formLogin", seeded_tools)

    def test_run_promotes_successful_firmware_probe_into_confirmed_report_output(self) -> None:
        orchestrator = VulnOrchestrator(FakeRouter(), memory_path=":memory:")
        discovery = FakeAgent("discovery", "")
        exploit = FakeAgent("exploit", "")
        report = FakeAgent("report", "")

        tool_outputs = {
            "firmware_runtime_manifest": SimpleNamespace(
                stdout="ROOTFS_PATH: /tmp/rootfs\nARCHITECTURE: mips\nENDIANNESS: little",
                stderr="",
                return_code=0,
            ),
            "firmware_service_inventory": SimpleNamespace(
                stdout=(
                    "SERVICE: http :: busybox :: /bin/busybox :: busybox httpd -f -p 8080\n"
                    "SERVICE_PROBE: busybox :: http :: http://127.0.0.1:8080/"
                ),
                stderr="",
                return_code=0,
            ),
            "firmware_emulation_prepare": SimpleNamespace(
                stdout="EXECUTION_BACKEND: local\nWORKSPACE_ROOT: E:/Temp/vulnagent/runs/demo",
                stderr="",
                return_code=0,
            ),
            "firmware_emulation_launch_user": SimpleNamespace(
                stdout=(
                    "EXECUTION_BACKEND: local\n"
                    "SERVICE_TYPE: http\n"
                    "PROBE_SERVICE_TYPE: http\n"
                    "PROBE_PORT: 8080\n"
                    "PROBE_SCHEME: http\n"
                    "PROBE_ENDPOINT: http://127.0.0.1:8080/\n"
                ),
                stderr="",
                return_code=0,
            ),
            "firmware_emulation_probe": SimpleNamespace(
                stdout=(
                    "SERVICE_TYPE: http\n"
                    "ENDPOINT: http://127.0.0.1:8080/\n"
                    "REACHABLE: true\n"
                    "SUMMARY: 200 OK\n"
                    "DETAILS: <html>login</html>\n"
                ),
                stderr="",
                return_code=0,
            ),
        }

        for tool_name, result in tool_outputs.items():
            tool = orchestrator.tool_registry.get(tool_name)
            self.assertIsNotNone(tool)
            assert tool is not None
            tool.executor = lambda _params, _result=result: _result

        with tempfile.NamedTemporaryFile(suffix=".img") as handle:
            handle.write(b"A" * 16 + b"hsqs" + b"B" * 16)
            handle.flush()
            with patch.object(orchestrator, "_get_agent", side_effect=_mock_agents(discovery, exploit, report)):
                result = orchestrator.run(handle.name, scope="firmware validation", max_iterations=1, token_limit=2000)

        self.assertTrue(result["success"])
        self.assertIn("Emulated firmware service reachable for validation", result["report"])
        self.assertIn("http://127.0.0.1:8080/", result["report"])

    def test_run_seeds_deeper_internet_script_read_for_nvram_account_flow(self) -> None:
        orchestrator = VulnOrchestrator(FakeRouter(), memory_path=":memory:")
        discovery = FakeAgent("discovery", "")
        exploit = FakeAgent("exploit", "")
        report = FakeAgent("report", "")

        summary_tool = orchestrator.tool_registry.get("firmware_extract_summary")
        read_tool = orchestrator.tool_registry.get("firmware_read_path")
        search_tool = orchestrator.tool_registry.get("firmware_search")
        map_tool = orchestrator.tool_registry.get("firmware_web_surface_map")
        self.assertIsNotNone(summary_tool)
        self.assertIsNotNone(read_tool)
        self.assertIsNotNone(search_tool)
        self.assertIsNotNone(map_tool)
        assert summary_tool is not None
        assert read_tool is not None
        assert search_tool is not None
        assert map_tool is not None

        summary_tool.executor = lambda _params: SimpleNamespace(
            stdout=(
                "SQUASHFS_FOUND offset=0x00000010\n"
                "INTERESTING_PATH: /etc_ro/rcS\n"
                "INTERESTING_PATH: /etc_ro/web/d_telnet.asp\n"
                "INTERESTING_PATH: /sbin/chpasswd.sh\n"
            ),
            stderr="",
            return_code=0,
        )

        def fake_read_executor(params):
            inner_path = params["inner_path"]
            max_bytes = int(params.get("max_bytes", 0))
            if inner_path == "/etc_ro/rcS":
                stdout = "telnetd\ngoahead&"
            elif inner_path == "/etc_ro/web/d_telnet.asp":
                stdout = "var telnet_en = \"<% getCfgGeneral(1, \\\"telnetEnabled\\\"); %>\";\n<form action=\"/goform/form2Telnet.cgi\">"
            elif inner_path == "/sbin/chpasswd.sh":
                stdout = "echo \"$1:$2\" > /tmp/tmpchpw\nchpasswd < /tmp/tmpchpw"
            elif inner_path == "/sbin/internet.sh":
                if max_bytes >= 16384:
                    stdout = (
                        "genSysFiles()\n"
                        "{\n"
                        "    login=`nvram_get 2860 Login`\n"
                        "    pass=`nvram_get 2860 Password`\n"
                        "    echo \"$login::0:0:Adminstrator:/:/bin/sh\" > /etc/passwd\n"
                        "    chpasswd.sh $login $pass\n"
                        "}\n"
                    )
                else:
                    stdout = "#!/bin/sh\n# truncated before genSysFiles\n"
            else:
                stdout = f"READ::{inner_path}"
            return SimpleNamespace(stdout=stdout, stderr="", return_code=0)

        read_tool.executor = fake_read_executor
        search_tool.executor = lambda params: SimpleNamespace(
            stdout=(
                f"SEARCH_PATTERN: {params['pattern']}\n"
                "MATCH: /sbin/internet.sh [text] :: echo \"$login::0:0:Adminstrator:/:/bin/sh\" > /etc/passwd\n"
                "MATCH_COUNT: 1\n"
            )
            if params["pattern"] in {"/etc/passwd", "chpasswd.sh"}
            else (
                f"SEARCH_PATTERN: {params['pattern']}\n"
                "MATCH: /etc_ro/Wireless/RT2860AP/RT2860_factory_vlan [text] :: telnetEnabled=1\n"
                "MATCH: /etc_ro/Wireless/RT2860AP/RT2860_default_vlan [text] :: telnetEnabled=0\n"
                "MATCH_COUNT: 2\n"
            ),
            stderr="",
            return_code=0,
        )
        map_tool.executor = lambda _params: SimpleNamespace(
            stdout="TEXT_ROUTE: /etc_ro/web/d_telnet.asp -> /goform/form2Telnet.cgi",
            stderr="",
            return_code=0,
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            artifact = tempfile.NamedTemporaryFile(dir=tmpdir, suffix=".bin", delete=False)
            artifact.write(b"A" * 16 + b"hsqs" + b"B" * 16)
            artifact.close()
            with patch.object(orchestrator, "_get_agent", side_effect=_mock_agents(discovery, exploit, report)):
                result = orchestrator.run(artifact.name, scope="firmware triage")

        self.assertIn(
            "Boot script materializes an administrator shell account from NVRAM credentials",
            result["report"],
        )

    def test_cli_uses_vuln_orchestrator(self) -> None:
        from vulnagent import cli

        fake_result = {
            "success": True,
            "report": "final report",
            "target": "https://example.test",
            "scope": "authorized test",
            "findings": [],
            "iterations": 0,
            "tokens_used": 0,
            "tools_called": [],
        }

        with patch("sys.argv", [
            "vuln-agent",
            "--target", "https://example.test",
            "--scope", "authorized test",
            "--api-key", "test-key",
        ]):
            with patch("vulnagent.orchestrator.VulnOrchestrator.run", return_value=fake_result) as run:
                with patch("vulnagent.llm.OpenAIClient", return_value=MagicMock()):
                    cli.main()

        run.assert_called_once()
        self.assertEqual(run.call_args.kwargs["target"], "https://example.test")
        self.assertEqual(run.call_args.kwargs["scope"], "authorized test")


def test_derive_search_hit_readback_paths_prioritizes_followup_files() -> None:
    from vulnagent.orchestrator import _derive_search_hit_readback_paths

    paths = _derive_search_hit_readback_paths({
        "firmware_search:/etc/passwd": (
            "SEARCH_PATTERN: /etc/passwd\n"
            "MATCH: /sbin/internet.sh [text] :: echo \"$login::0:0:Adminstrator:/:/bin/sh\" > /etc/passwd\n"
            "MATCH_COUNT: 1\n"
        ),
        "firmware_search:telnetEnabled": (
            "SEARCH_PATTERN: telnetEnabled\n"
            "MATCH: /etc_ro/Wireless/RT2860AP/RT2860_factory_vlan [text] :: telnetEnabled=1\n"
            "MATCH: /etc_ro/Wireless/RT2860AP/RT2860_default_vlan [text] :: telnetEnabled=0\n"
            "MATCH_COUNT: 2\n"
        ),
        "firmware_search:chpasswd.sh": (
            "SEARCH_PATTERN: chpasswd.sh\n"
            "MATCH: /sbin/chpasswd.sh [text] :: # usage: chpasswd.sh <user name> [<password>]\n"
            "MATCH: /sbin/internet.sh [text] :: chpasswd.sh $login $pass\n"
            "MATCH_COUNT: 2\n"
        ),
    })

    assert "/sbin/internet.sh" in paths
    assert "/sbin/chpasswd.sh" in paths
    assert "/etc_ro/Wireless/RT2860AP/RT2860_factory_vlan" in paths
    assert "/etc_ro/Wireless/RT2860AP/RT2860_default_vlan" in paths


def test_seed_local_artifact_triage_sets_emulation_hints_for_local_firmware() -> None:
    orchestrator = VulnOrchestrator(FakeRouter(), memory_path=":memory:")

    with tempfile.NamedTemporaryFile(suffix=".img") as handle:
        state = {
            "metadata": {},
            "tool_outputs": {},
            "compressed_outputs": {},
            "executed_tools": [],
        }

        seeded = orchestrator._seed_local_artifact_triage(state, handle.name)

    assert seeded["metadata"]["artifact_target"] == handle.name
    assert seeded["metadata"]["artifact_kind"] == "firmware"
    assert "firmware_runtime_manifest" in seeded["metadata"]["preferred_tool_sequence"]


if __name__ == "__main__":
    unittest.main()
