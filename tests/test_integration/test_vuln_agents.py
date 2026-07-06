"""Integration tests for all Vulnerability Discovery agents — Discovery, Exploit, Report."""

import json
import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock, patch
from langchain_core.messages import AIMessage, HumanMessage

from vulnagent.core.state import AgentState, TokenBudgetState, CompactionState
from vulnagent.tools.registry import ToolRegistry, ToolDefinition


def _make_state(**overrides) -> AgentState:
    budget = TokenBudgetState(total=100000, used=0, micro_threshold=0.6, mid_threshold=0.8, deep_threshold=0.95)
    compaction = CompactionState(compaction_count=0, last_compaction_at_tokens=0, micro_compact_threshold=0.6, mid_compact_threshold=0.8, deep_compact_threshold=0.95)
    state: AgentState = {
        "messages": [HumanMessage(content="Test target discovery")],
        "task_description": "Test target discovery", "attachment_paths": [],
        "tool_outputs": {}, "compressed_outputs": {},
        "memory_blocks": {}, "memory_context": {},
        "current_agent": "discovery", "iteration_count": 0,
        "token_budget": budget, "phase": "execution",
        "final_result": None, "compaction": compaction,
        "anchored_summary": {}, "metadata": {},
    }
    state.update(overrides)
    return state


def _dummy_exec(params):
    return "ok"


def _make_vuln_registry():
    """Create a registry with all tools needed for vuln agents."""
    from vulnagent.tools.vuln_tools import register_all_vuln_tools
    registry = ToolRegistry()
    register_all_vuln_tools(registry)
    return registry


class TestDiscoveryAgent(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        from vulnagent.agents.discovery_agent import DiscoveryAgent
        cls.AgentClass = DiscoveryAgent

    def setUp(self):
        self.registry = _make_vuln_registry()

    def test_initialization(self):
        agent = self.AgentClass(
            llm=MagicMock(), tools=MagicMock(),
            memory=MagicMock(), compressor=MagicMock(), config=MagicMock(),
        )
        self.assertIsNotNone(agent)
        from vulnagent.core.agent import BaseAgent
        self.assertIsInstance(agent, BaseAgent)

    def test_system_prompt_contains_discovery_keywords(self):
        agent = self.AgentClass(
            llm=MagicMock(), tools=MagicMock(),
            memory=MagicMock(), compressor=MagicMock(), config=MagicMock(),
        )
        prompt = agent.get_system_prompt(_make_state())
        self.assertGreater(len(prompt), 0)
        self.assertTrue("vulnerability" in prompt.lower() or "discovery" in prompt.lower() or "scan" in prompt.lower())

    def test_prompt_includes_iteration(self):
        agent = self.AgentClass(
            llm=MagicMock(), tools=MagicMock(),
            memory=MagicMock(), compressor=MagicMock(), config=MagicMock(),
        )
        prompt = agent.get_system_prompt(_make_state(iteration_count=3))
        self.assertIn("3", prompt)

    def test_tools_include_recon(self):
        agent = self.AgentClass(
            llm=MagicMock(), tools=self.registry,
            memory=MagicMock(), compressor=MagicMock(), config=MagicMock(),
        )
        with patch("vulnagent.agents.discovery_agent.shutil.which", side_effect=lambda name: f"C:/bin/{name}"):
            schema = agent.get_tools_schema()
        tool_names = {item["function"]["name"] for item in schema}
        for tool in ["nmap_scan", "gobuster_scan"]:
            self.assertIn(tool, tool_names, f"DiscoveryAgent should have {tool}")

    def test_discovery_agent_tools_include_artifact_triage(self):
        agent = self.AgentClass(
            llm=MagicMock(), tools=self.registry,
            memory=MagicMock(), compressor=MagicMock(), config=MagicMock(),
        )
        schema = agent.get_tools_schema()
        tool_names = {item["function"]["name"] for item in schema}
        for tool in [
            "file_identify",
            "readelf_headers",
            "strings_extract",
            "firmware_extract_summary",
            "firmware_runtime_manifest",
            "firmware_service_inventory",
            "firmware_emulation_prepare",
            "firmware_emulation_launch_user",
            "firmware_emulation_launch_system",
            "firmware_read_path",
            "firmware_search",
            "firmware_web_surface_map",
        ]:
            self.assertIn(tool, tool_names)

    def test_discovery_agent_hides_completed_broad_artifact_tools_from_schema(self):
        agent = self.AgentClass(
            llm=MagicMock(), tools=self.registry,
            memory=MagicMock(), compressor=MagicMock(), config=MagicMock(),
        )
        schema = agent.get_tools_schema(_make_state(
            executed_tools=[
                {"name": "file_identify", "args": {"path": "firmware.bin"}, "success": True},
                {"name": "binwalk_scan", "args": {"path": "firmware.bin"}, "success": True},
                {"name": "firmware_extract_summary", "args": {"path": "firmware.bin"}, "success": True},
                {"name": "firmware_web_surface_map", "args": {"path": "firmware.bin"}, "success": True},
            ],
            metadata={"target": "firmware.bin", "provenance": "artifact:firmware.bin"},
        ))
        tool_names = {item["function"]["name"] for item in schema}
        self.assertNotIn("file_identify", tool_names)
        self.assertNotIn("binwalk_scan", tool_names)
        self.assertNotIn("firmware_extract_summary", tool_names)
        self.assertNotIn("firmware_web_surface_map", tool_names)
        self.assertNotIn("firmware_read_path", tool_names)
        self.assertIn("firmware_search", tool_names)

    def test_discovery_agent_hides_readelf_for_firmware_image_targets(self):
        agent = self.AgentClass(
            llm=MagicMock(), tools=self.registry,
            memory=MagicMock(), compressor=MagicMock(), config=MagicMock(),
        )
        schema = agent.get_tools_schema(_make_state(
            metadata={
                "target": r"E:\MYAGENTS\firmware\DIR816_A1_FW101CNB04.img",
                "provenance": r"artifact:E:\MYAGENTS\firmware\DIR816_A1_FW101CNB04.img",
            },
        ))
        tool_names = {item["function"]["name"] for item in schema}
        self.assertNotIn("readelf_headers", tool_names)
        self.assertNotIn("python_exec", tool_names)
        self.assertNotIn("file_read", tool_names)
        self.assertNotIn("nmap_scan", tool_names)
        self.assertNotIn("curl_request", tool_names)
        self.assertIn("firmware_runtime_manifest", tool_names)
        self.assertIn("firmware_service_inventory", tool_names)
        self.assertIn("firmware_emulation_prepare", tool_names)
        self.assertNotIn("firmware_emulation_probe", tool_names)
        self.assertNotIn("firmware_read_path", tool_names)

    def test_discovery_agent_enables_probe_only_after_successful_usermode_launch(self):
        agent = self.AgentClass(
            llm=MagicMock(), tools=self.registry,
            memory=MagicMock(), compressor=MagicMock(), config=MagicMock(),
        )
        target = r"E:\MYAGENTS\firmware\DIR816_A1_FW101CNB04.img"
        schema = agent.get_tools_schema(_make_state(
            executed_tools=[
                {
                    "name": "firmware_runtime_manifest",
                    "args": {"path": target},
                    "success": True,
                },
                {
                    "name": "firmware_service_inventory",
                    "args": {"path": target},
                    "success": True,
                },
                {
                    "name": "firmware_emulation_launch_user",
                    "args": {"path": target},
                    "success": True,
                },
            ],
            metadata={
                "target": target,
                "provenance": f"artifact:{target}",
            },
        ))
        tool_names = {item["function"]["name"] for item in schema}
        self.assertIn("firmware_emulation_probe", tool_names)

    def test_discovery_agent_reenables_firmware_read_path_after_emulation_triage_tools_run(self):
        agent = self.AgentClass(
            llm=MagicMock(), tools=self.registry,
            memory=MagicMock(), compressor=MagicMock(), config=MagicMock(),
        )
        schema = agent.get_tools_schema(_make_state(
            executed_tools=[
                {
                    "name": "firmware_runtime_manifest",
                    "args": {"path": r"E:\MYAGENTS\firmware\DIR816_A1_FW101CNB04.img"},
                    "success": True,
                },
                {
                    "name": "firmware_service_inventory",
                    "args": {"path": r"E:\MYAGENTS\firmware\DIR816_A1_FW101CNB04.img"},
                    "success": True,
                },
                {
                    "name": "firmware_emulation_prepare",
                    "args": {"path": r"E:\MYAGENTS\firmware\DIR816_A1_FW101CNB04.img"},
                    "success": False,
                },
            ],
            metadata={
                "target": r"E:\MYAGENTS\firmware\DIR816_A1_FW101CNB04.img",
                "provenance": r"artifact:E:\MYAGENTS\firmware\DIR816_A1_FW101CNB04.img",
            },
        ))
        tool_names = {item["function"]["name"] for item in schema}
        self.assertIn("firmware_read_path", tool_names)

    def test_discovery_agent_hides_completed_firmware_triage_tools_after_initial_pass(self):
        agent = self.AgentClass(
            llm=MagicMock(), tools=self.registry,
            memory=MagicMock(), compressor=MagicMock(), config=MagicMock(),
        )
        target = r"E:\MYAGENTS\firmware\DIR816_A1_FW101CNB04.img"
        schema = agent.get_tools_schema(_make_state(
            executed_tools=[
                {
                    "name": "firmware_runtime_manifest",
                    "args": {"path": target},
                    "success": True,
                },
                {
                    "name": "firmware_service_inventory",
                    "args": {"path": target},
                    "success": True,
                },
                {
                    "name": "firmware_emulation_prepare",
                    "args": {"path": target},
                    "success": False,
                },
                {
                    "name": "firmware_emulation_launch_system",
                    "args": {"path": target},
                    "success": False,
                },
            ],
            metadata={
                "target": target,
                "provenance": f"artifact:{target}",
            },
        ))
        tool_names = {item["function"]["name"] for item in schema}
        self.assertNotIn("firmware_runtime_manifest", tool_names)
        self.assertNotIn("firmware_service_inventory", tool_names)
        self.assertNotIn("firmware_emulation_prepare", tool_names)
        self.assertNotIn("firmware_emulation_launch_system", tool_names)
        self.assertIn("firmware_emulation_launch_user", tool_names)
        self.assertIn("firmware_read_path", tool_names)

    def test_discovery_agent_hides_attempted_emulation_tools_across_path_separator_variants(self):
        agent = self.AgentClass(
            llm=MagicMock(), tools=self.registry,
            memory=MagicMock(), compressor=MagicMock(), config=MagicMock(),
        )
        target = r"E:\MYAGENTS\firmware\DIR816_A1_FW101CNB04.img"
        schema = agent.get_tools_schema(_make_state(
            executed_tools=[
                {
                    "name": "firmware_emulation_launch_system",
                    "args": {"path": "E:/MYAGENTS/firmware/DIR816_A1_FW101CNB04.img"},
                    "success": False,
                },
            ],
            metadata={
                "target": target,
                "provenance": f"artifact:{target}",
            },
        ))
        tool_names = {item["function"]["name"] for item in schema}
        self.assertNotIn("firmware_emulation_launch_system", tool_names)

    def test_discovery_agent_hides_firmware_read_path_after_emulation_and_rich_readbacks(self):
        agent = self.AgentClass(
            llm=MagicMock(), tools=self.registry,
            memory=MagicMock(), compressor=MagicMock(), config=MagicMock(),
        )
        target = r"E:\MYAGENTS\firmware\DIR816_A1_FW101CNB04.img"
        successful_reads = [
            {
                "name": "firmware_read_path",
                "args": {"path": target, "inner_path": path},
                "success": True,
            }
            for path in [
                "/etc_ro/rcS",
                "/etc_ro/web/d_telnet.asp",
                "/bin/goahead",
                "/etc_ro/web/cgi-bin/upload.cgi",
                "/etc_ro/web/cgi-bin/upload_settings.cgi",
                "/sbin/chpasswd.sh",
                "/sbin/internet.sh",
                "/etc_ro/web/d_saveconf.asp",
            ]
        ]
        schema = agent.get_tools_schema(_make_state(
            executed_tools=[
                {
                    "name": "firmware_runtime_manifest",
                    "args": {"path": target},
                    "success": True,
                },
                {
                    "name": "firmware_service_inventory",
                    "args": {"path": target},
                    "success": True,
                },
                {
                    "name": "firmware_emulation_prepare",
                    "args": {"path": target},
                    "success": False,
                },
                {
                    "name": "firmware_emulation_launch_system",
                    "args": {"path": target},
                    "success": False,
                },
                *successful_reads,
            ],
            metadata={
                "target": target,
                "provenance": f"artifact:{target}",
            },
        ))
        tool_names = {item["function"]["name"] for item in schema}
        self.assertNotIn("firmware_read_path", tool_names)

    def test_discovery_agent_hides_firmware_read_path_after_prep_and_rich_seeded_readbacks(self):
        agent = self.AgentClass(
            llm=MagicMock(), tools=self.registry,
            memory=MagicMock(), compressor=MagicMock(), config=MagicMock(),
        )
        target = r"E:\MYAGENTS\firmware\DIR816_A1_FW101CNB04.img"
        successful_reads = [
            {
                "name": "firmware_read_path",
                "args": {"path": target, "inner_path": path},
                "success": True,
            }
            for path in [
                "/etc_ro/rcS",
                "/etc_ro/web/d_telnet.asp",
                "/bin/goahead",
                "/etc_ro/web/cgi-bin/upload.cgi",
                "/etc_ro/web/cgi-bin/upload_settings.cgi",
                "/sbin/chpasswd.sh",
                "/sbin/internet.sh",
                "/etc_ro/web/d_saveconf.asp",
            ]
        ]
        schema = agent.get_tools_schema(_make_state(
            executed_tools=[
                {
                    "name": "firmware_runtime_manifest",
                    "args": {"path": target},
                    "success": True,
                },
                {
                    "name": "firmware_service_inventory",
                    "args": {"path": target},
                    "success": True,
                },
                {
                    "name": "firmware_emulation_prepare",
                    "args": {"path": target},
                    "success": False,
                },
                *successful_reads,
            ],
            metadata={
                "target": target,
                "provenance": f"artifact:{target}",
            },
        ))
        tool_names = {item["function"]["name"] for item in schema}
        self.assertNotIn("firmware_read_path", tool_names)

    def test_discovery_agent_hides_firmware_search_after_seeded_artifact_searches_exist(self):
        agent = self.AgentClass(
            llm=MagicMock(), tools=self.registry,
            memory=MagicMock(), compressor=MagicMock(), config=MagicMock(),
        )
        schema = agent.get_tools_schema(_make_state(
            executed_tools=[
                {
                    "name": "firmware_search",
                    "args": {"path": r"E:\MYAGENTS\firmware\DIR816_A1_FW101CNB04.img", "pattern": "showSystemCommandASP"},
                    "success": True,
                    "seeded": True,
                },
            ],
            metadata={
                "target": r"E:\MYAGENTS\firmware\DIR816_A1_FW101CNB04.img",
                "provenance": r"artifact:E:\MYAGENTS\firmware\DIR816_A1_FW101CNB04.img",
            },
        ))
        tool_names = {item["function"]["name"] for item in schema}
        self.assertNotIn("firmware_search", tool_names)
        self.assertNotIn("firmware_read_path", tool_names)

    def test_discovery_agent_does_not_expose_shell_exec(self):
        agent = self.AgentClass(
            llm=MagicMock(), tools=self.registry,
            memory=MagicMock(), compressor=MagicMock(), config=MagicMock(),
        )
        schema = agent.get_tools_schema()
        tool_names = {item["function"]["name"] for item in schema}
        self.assertNotIn("shell_exec", tool_names)

    def test_graph_compiles(self):
        agent = self.AgentClass(
            llm=MagicMock(), tools=MagicMock(),
            memory=MagicMock(), compressor=MagicMock(), config=MagicMock(),
        )
        graph = agent.build_graph()
        self.assertIsNotNone(graph)
        self.assertTrue(hasattr(graph, "invoke"))

    def test_prompt_includes_recent_tool_history(self):
        agent = self.AgentClass(
            llm=MagicMock(), tools=self.registry,
            memory=MagicMock(), compressor=MagicMock(), config=MagicMock(),
        )
        prompt = agent.get_system_prompt(_make_state(
            executed_tools=[
                {
                    "name": "firmware_extract_summary",
                    "args": {"path": "firmware.bin"},
                    "success": True,
                    "result_summary": "SQUASHFS_FOUND offset=0x10",
                },
            ],
        ))
        self.assertIn("Recent Tool History", prompt)
        self.assertIn("firmware_extract_summary", prompt)

    def test_prompt_includes_current_tool_evidence(self):
        agent = self.AgentClass(
            llm=MagicMock(), tools=self.registry,
            memory=MagicMock(), compressor=MagicMock(), config=MagicMock(),
        )
        prompt = agent.get_system_prompt(_make_state(
            compressed_outputs={
                "firmware_extract_summary": "SQUASHFS_FOUND offset=0x10\nINTERESTING_PATH: /bin/goahead",
                "firmware_read_path:/etc_ro/rcS": "TEXT: telnetd -l /bin/login",
            },
        ))
        self.assertIn("Current Tool Evidence", prompt)
        self.assertIn("SQUASHFS_FOUND", prompt)
        self.assertIn("/etc_ro/rcS", prompt)


class TestExploitAgent(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        from vulnagent.agents.exploit_agent import ExploitAgent
        cls.AgentClass = ExploitAgent

    def setUp(self):
        self.registry = _make_vuln_registry()

    def test_initialization(self):
        agent = self.AgentClass(
            llm=MagicMock(), tools=MagicMock(),
            memory=MagicMock(), compressor=MagicMock(), config=MagicMock(),
        )
        self.assertIsNotNone(agent)
        from vulnagent.core.agent import BaseAgent
        self.assertIsInstance(agent, BaseAgent)

    def test_system_prompt_contains_exploit_keywords(self):
        agent = self.AgentClass(
            llm=MagicMock(), tools=MagicMock(),
            memory=MagicMock(), compressor=MagicMock(), config=MagicMock(),
        )
        prompt = agent.get_system_prompt(_make_state())
        self.assertGreater(len(prompt), 0)
        self.assertTrue("exploit" in prompt.lower() or "vulnerability" in prompt.lower())

    def test_graph_compiles(self):
        agent = self.AgentClass(
            llm=MagicMock(), tools=MagicMock(),
            memory=MagicMock(), compressor=MagicMock(), config=MagicMock(),
        )
        graph = agent.build_graph()
        self.assertIsNotNone(graph)
        self.assertTrue(hasattr(graph, "invoke"))

    def test_verify_node_does_not_inject_ctf_failure_marker(self):
        agent = self.AgentClass(
            llm=MagicMock(), tools=MagicMock(),
            memory=MagicMock(), compressor=MagicMock(), config=MagicMock(),
        )
        result = agent._verify_node(_make_state(
            current_agent="exploit",
            final_result=None,
            metadata={"execution_mode": "operator-directed"},
        ))
        self.assertEqual(result["final_result"], "")

    def test_exploit_agent_does_not_expose_shell_exec(self):
        agent = self.AgentClass(
            llm=MagicMock(), tools=self.registry,
            memory=MagicMock(), compressor=MagicMock(), config=MagicMock(),
        )
        schema = agent.get_tools_schema()
        tool_names = {item["function"]["name"] for item in schema}
        self.assertNotIn("shell_exec", tool_names)

    def test_exploit_agent_hides_searchsploit_when_binary_missing(self):
        agent = self.AgentClass(
            llm=MagicMock(), tools=self.registry,
            memory=MagicMock(), compressor=MagicMock(), config=MagicMock(),
        )
        with patch("vulnagent.agents.exploit_agent.shutil.which", return_value=None):
            schema = agent.get_tools_schema()
        tool_names = {item["function"]["name"] for item in schema}
        self.assertNotIn("searchsploit", tool_names)

    def test_exploit_agent_includes_firmware_file_readback_tools(self):
        agent = self.AgentClass(
            llm=MagicMock(), tools=self.registry,
            memory=MagicMock(), compressor=MagicMock(), config=MagicMock(),
        )
        schema = agent.get_tools_schema()
        tool_names = {item["function"]["name"] for item in schema}
        self.assertIn("firmware_extract_summary", tool_names)
        self.assertIn("firmware_emulation_launch_user", tool_names)
        self.assertIn("firmware_emulation_probe", tool_names)
        self.assertIn("firmware_emulation_launch_system", tool_names)
        self.assertIn("firmware_read_path", tool_names)
        self.assertIn("firmware_search", tool_names)

    def test_exploit_agent_hides_completed_broad_artifact_tools_from_schema(self):
        agent = self.AgentClass(
            llm=MagicMock(), tools=self.registry,
            memory=MagicMock(), compressor=MagicMock(), config=MagicMock(),
        )
        schema = agent.get_tools_schema(_make_state(
            executed_tools=[
                {"name": "firmware_extract_summary", "args": {"path": "firmware.bin"}, "success": True},
                {"name": "firmware_web_surface_map", "args": {"path": "firmware.bin"}, "success": True},
            ],
            metadata={"target": "firmware.bin", "provenance": "artifact:firmware.bin"},
        ))
        tool_names = {item["function"]["name"] for item in schema}
        self.assertNotIn("firmware_extract_summary", tool_names)
        self.assertNotIn("firmware_web_surface_map", tool_names)
        self.assertIn("firmware_read_path", tool_names)
        self.assertIn("firmware_search", tool_names)

    def test_exploit_agent_hides_host_side_helpers_for_firmware_image_targets(self):
        agent = self.AgentClass(
            llm=MagicMock(), tools=self.registry,
            memory=MagicMock(), compressor=MagicMock(), config=MagicMock(),
        )
        schema = agent.get_tools_schema(_make_state(
            metadata={
                "target": r"E:\MYAGENTS\firmware\DIR816_A1_FW101CNB04.img",
                "provenance": r"artifact:E:\MYAGENTS\firmware\DIR816_A1_FW101CNB04.img",
            },
        ))
        tool_names = {item["function"]["name"] for item in schema}
        self.assertNotIn("readelf_headers", tool_names)
        self.assertNotIn("python_exec", tool_names)
        self.assertNotIn("file_read", tool_names)
        self.assertNotIn("curl_request", tool_names)
        self.assertNotIn("netcat_connect", tool_names)
        self.assertNotIn("firmware_emulation_probe", tool_names)
        self.assertIn("firmware_read_path", tool_names)

    def test_exploit_agent_enables_probe_only_after_successful_usermode_launch(self):
        agent = self.AgentClass(
            llm=MagicMock(), tools=self.registry,
            memory=MagicMock(), compressor=MagicMock(), config=MagicMock(),
        )
        target = r"E:\MYAGENTS\firmware\DIR816_A1_FW101CNB04.img"
        schema = agent.get_tools_schema(_make_state(
            executed_tools=[
                {
                    "name": "firmware_emulation_launch_user",
                    "args": {"path": target},
                    "success": True,
                },
            ],
            metadata={
                "target": target,
                "provenance": f"artifact:{target}",
            },
        ))
        tool_names = {item["function"]["name"] for item in schema}
        self.assertIn("firmware_emulation_probe", tool_names)

    def test_exploit_agent_exposes_network_validation_tools_after_successful_firmware_probe(self):
        agent = self.AgentClass(
            llm=MagicMock(), tools=self.registry,
            memory=MagicMock(), compressor=MagicMock(), config=MagicMock(),
        )
        target = r"E:\MYAGENTS\firmware\DIR816_A1_FW101CNB04.img"
        with patch("vulnagent.agents.exploit_agent.shutil.which", side_effect=lambda name: f"C:/bin/{name}"):
            schema = agent.get_tools_schema(_make_state(
                executed_tools=[
                    {
                        "name": "firmware_emulation_launch_user",
                        "args": {"path": target},
                        "success": True,
                    },
                    {
                        "name": "firmware_emulation_probe",
                        "args": {"port": 8080, "service_type": "http"},
                        "success": True,
                        "result_summary": "REACHABLE: true",
                    },
                ],
                metadata={
                    "target": target,
                    "provenance": f"artifact:{target}",
                },
            ))
        tool_names = {item["function"]["name"] for item in schema}
        self.assertIn("curl_request", tool_names)
        self.assertIn("netcat_connect", tool_names)

    def test_exploit_agent_hides_firmware_search_after_seeded_artifact_searches_exist(self):
        agent = self.AgentClass(
            llm=MagicMock(), tools=self.registry,
            memory=MagicMock(), compressor=MagicMock(), config=MagicMock(),
        )
        schema = agent.get_tools_schema(_make_state(
            executed_tools=[
                {
                    "name": "firmware_search",
                    "args": {"path": r"E:\MYAGENTS\firmware\DIR816_A1_FW101CNB04.img", "pattern": "showSystemCommandASP"},
                    "success": True,
                    "seeded": True,
                },
            ],
            metadata={
                "target": r"E:\MYAGENTS\firmware\DIR816_A1_FW101CNB04.img",
                "provenance": r"artifact:E:\MYAGENTS\firmware\DIR816_A1_FW101CNB04.img",
            },
        ))
        tool_names = {item["function"]["name"] for item in schema}
        self.assertNotIn("firmware_search", tool_names)
        self.assertIn("firmware_read_path", tool_names)

    def test_exploit_prompt_includes_current_tool_evidence(self):
        agent = self.AgentClass(
            llm=MagicMock(), tools=self.registry,
            memory=MagicMock(), compressor=MagicMock(), config=MagicMock(),
        )
        prompt = agent.get_system_prompt(_make_state(
            compressed_outputs={
                "firmware_web_surface_map": "TEXT_ROUTE: /etc_ro/web/d_upload.asp -> /cgi-bin/upload.cgi",
                "firmware_read_path:/etc_ro/web/cgi-bin/upload.cgi": "tempnam\nsystem\nimport_5g",
            },
        ))
        self.assertIn("Current Tool Evidence", prompt)
        self.assertIn("/cgi-bin/upload.cgi", prompt)
        self.assertIn("import_5g", prompt)

    def test_repeated_broad_tool_calls_are_blocked(self):
        agent = self.AgentClass(
            llm=MagicMock(), tools=self.registry,
            memory=MagicMock(), compressor=MagicMock(), config=MagicMock(),
        )
        tool_def = self.registry.get("firmware_extract_summary")
        self.assertIsNotNone(tool_def)
        assert tool_def is not None

        state = _make_state(
            executed_tools=[
                {
                    "name": "firmware_extract_summary",
                    "args": {"path": "firmware.bin"},
                    "success": True,
                    "output_key": "firmware_extract_summary",
                },
            ],
            metadata={},
        )
        blocked = agent._tool_policy_block_reason(tool_def, {
            **state,
            "_pending_tool_args_override": {
                "firmware_extract_summary": {"path": "firmware.bin"},
            },
        })
        self.assertIn("Blocked repeated tool call", blocked)

    def test_repeated_tool_calls_are_blocked_when_args_arrive_as_json(self):
        agent = self.AgentClass(
            llm=MagicMock(), tools=self.registry,
            memory=MagicMock(), compressor=MagicMock(), config=MagicMock(),
        )
        tool_def = self.registry.get("firmware_search")
        self.assertIsNotNone(tool_def)
        assert tool_def is not None

        state = _make_state(
            executed_tools=[
                {
                    "name": "firmware_search",
                    "args": {"path": "firmware.bin", "pattern": "system(", "mode": "strings"},
                    "success": True,
                    "output_key": "firmware_search:system(",
                },
            ],
            metadata={},
        )
        blocked = agent._tool_policy_block_reason(tool_def, {
            **state,
            "_pending_tool_args_override": {
                "firmware_search": json.dumps({
                    "path": "firmware.bin",
                    "pattern": "system(",
                    "mode": "strings",
                }),
            },
        })
        self.assertIn("Blocked repeated tool call", blocked)

    def test_repeated_firmware_search_is_blocked_when_only_optional_args_differ(self):
        agent = self.AgentClass(
            llm=MagicMock(), tools=self.registry,
            memory=MagicMock(), compressor=MagicMock(), config=MagicMock(),
        )
        tool_def = self.registry.get("firmware_search")
        self.assertIsNotNone(tool_def)
        assert tool_def is not None

        state = _make_state(
            executed_tools=[
                {
                    "name": "firmware_search",
                    "args": {
                        "path": "firmware.bin",
                        "pattern": "form2Telnet.cgi",
                        "mode": "auto",
                        "max_results": 12,
                        "max_bytes": 131072,
                    },
                    "success": True,
                    "output_key": "firmware_search:form2Telnet.cgi",
                },
            ],
            metadata={"target": "firmware.bin", "provenance": "artifact:firmware.bin"},
        )
        blocked = agent._tool_policy_block_reason(tool_def, {
            **state,
            "_pending_tool_args_override": {
                "firmware_search": {
                    "path": "firmware.bin",
                    "pattern": "form2Telnet.cgi",
                },
            },
        })
        self.assertIn("Blocked repeated tool call", blocked)

    def test_repeated_firmware_read_path_is_blocked_when_mode_differs(self):
        agent = self.AgentClass(
            llm=MagicMock(), tools=self.registry,
            memory=MagicMock(), compressor=MagicMock(), config=MagicMock(),
        )
        tool_def = self.registry.get("firmware_read_path")
        self.assertIsNotNone(tool_def)
        assert tool_def is not None

        state = _make_state(
            executed_tools=[
                {
                    "name": "firmware_read_path",
                    "args": {
                        "path": "firmware.bin",
                        "inner_path": "/etc_ro/web/d_telnet.asp",
                        "mode": "text",
                        "max_bytes": 8192,
                    },
                    "success": True,
                    "output_key": "firmware_read_path:/etc_ro/web/d_telnet.asp",
                },
            ],
            metadata={"target": "firmware.bin", "provenance": "artifact:firmware.bin"},
        )
        blocked = agent._tool_policy_block_reason(tool_def, {
            **state,
            "_pending_tool_args_override": {
                "firmware_read_path": {
                    "path": "firmware.bin",
                    "inner_path": "/etc_ro/web/d_telnet.asp",
                    "mode": "auto",
                },
            },
        })
        self.assertIn("Blocked repeated tool call", blocked)

    def test_repeated_failed_firmware_emulation_launch_system_is_blocked(self):
        agent = self.AgentClass(
            llm=MagicMock(), tools=self.registry,
            memory=MagicMock(), compressor=MagicMock(), config=MagicMock(),
        )
        tool_def = self.registry.get("firmware_emulation_launch_system")
        self.assertIsNotNone(tool_def)
        assert tool_def is not None

        state = _make_state(
            executed_tools=[
                {
                    "name": "firmware_emulation_launch_system",
                    "args": {"path": r"E:\MYAGENTS\firmware\DIR816_A1_FW101CNB04.img"},
                    "success": False,
                    "output_key": "firmware_emulation_launch_system",
                },
            ],
            metadata={
                "target": r"E:\MYAGENTS\firmware\DIR816_A1_FW101CNB04.img",
                "provenance": r"artifact:E:\MYAGENTS\firmware\DIR816_A1_FW101CNB04.img",
            },
        )
        blocked = agent._tool_policy_block_reason(tool_def, {
            **state,
            "_pending_tool_args_override": {
                "firmware_emulation_launch_system": {
                    "path": "E:/MYAGENTS/firmware/DIR816_A1_FW101CNB04.img",
                },
            },
        })
        self.assertIn("Blocked repeated tool call", blocked)

    def test_tools_node_stores_clean_tool_stdout_instead_of_repr(self):
        compressor = MagicMock()
        compressor.compress.side_effect = lambda text, context=None: text
        agent = self.AgentClass(
            llm=MagicMock(), tools=self.registry,
            memory=MagicMock(), compressor=compressor, config=MagicMock(),
        )
        tool = self.registry.get("firmware_search")
        self.assertIsNotNone(tool)
        assert tool is not None
        tool.executor = lambda _params: SimpleNamespace(
            stdout="SEARCH_PATTERN: x\nMATCH: /bin/goahead [strings] :: x",
            stderr="",
            return_code=0,
        )

        result = agent._tools_node(_make_state(
            messages=[
                AIMessage(
                    content="",
                    tool_calls=[
                        {
                            "id": "call-1",
                            "name": "firmware_search",
                            "args": {"path": "firmware.bin", "pattern": "x"},
                        },
                    ],
                ),
            ],
            metadata={},
        ))
        self.assertIn("firmware_search:x", result["tool_outputs"])
        self.assertTrue(result["tool_outputs"]["firmware_search:x"].startswith("SEARCH_PATTERN: x"))
        self.assertNotIn("ToolResult(", result["tool_outputs"]["firmware_search:x"])

    def test_blocked_tool_call_is_recorded_as_unsuccessful(self):
        compressor = MagicMock()
        compressor.compress.side_effect = lambda text, context=None: text
        agent = self.AgentClass(
            llm=MagicMock(), tools=self.registry,
            memory=MagicMock(), compressor=compressor, config=MagicMock(),
        )
        result = agent._tools_node(_make_state(
            messages=[
                AIMessage(
                    content="",
                    tool_calls=[
                        {
                            "id": "call-1",
                            "name": "firmware_extract_summary",
                            "args": {"path": "firmware.bin"},
                        },
                    ],
                ),
            ],
            executed_tools=[
                {
                    "name": "firmware_extract_summary",
                    "args": {"path": "firmware.bin"},
                    "success": True,
                    "output_key": "firmware_extract_summary",
                },
            ],
            metadata={"target": "firmware.bin", "provenance": "artifact:firmware.bin"},
        ))
        self.assertFalse(result["executed_tools"][-1]["success"])

    def test_rewrite_tool_args_reanchors_firmware_tool_paths_to_target(self):
        agent = self.AgentClass(
            llm=MagicMock(), tools=self.registry,
            memory=MagicMock(), compressor=MagicMock(), config=MagicMock(),
        )
        rewritten = agent._rewrite_tool_args(
            "firmware_extract_summary",
            {"path": "/mnt/data/firmware.bin"},
            _make_state(metadata={
                "target": r"E:\MYAGENTS\firmware\DIR816_A1_FW101CNB04.img",
                "provenance": r"artifact:E:\MYAGENTS\firmware\DIR816_A1_FW101CNB04.img",
            }),
        )
        self.assertEqual(
            rewritten["path"],
            r"E:\MYAGENTS\firmware\DIR816_A1_FW101CNB04.img",
        )

    def test_rewrite_tool_args_reanchors_firmware_web_surface_map_paths_to_target(self):
        agent = self.AgentClass(
            llm=MagicMock(), tools=self.registry,
            memory=MagicMock(), compressor=MagicMock(), config=MagicMock(),
        )
        rewritten = agent._rewrite_tool_args(
            "firmware_web_surface_map",
            {"path": "/mnt/data/firmware.bin"},
            _make_state(metadata={
                "target": r"E:\MYAGENTS\firmware\DIR816_A1_FW101CNB04.img",
                "provenance": r"artifact:E:\MYAGENTS\firmware\DIR816_A1_FW101CNB04.img",
            }),
        )
        self.assertEqual(
            rewritten["path"],
            r"E:\MYAGENTS\firmware\DIR816_A1_FW101CNB04.img",
        )

    def test_python_exec_host_probe_is_blocked_for_artifact_runs(self):
        agent = self.AgentClass(
            llm=MagicMock(), tools=self.registry,
            memory=MagicMock(), compressor=MagicMock(), config=MagicMock(),
        )
        tool_def = self.registry.get("python_exec")
        self.assertIsNotNone(tool_def)
        assert tool_def is not None

        blocked = agent._tool_policy_block_reason(tool_def, {
            **_make_state(metadata={
                "target": r"E:\MYAGENTS\firmware\DIR816_A1_FW101CNB04.img",
                "provenance": r"artifact:E:\MYAGENTS\firmware\DIR816_A1_FW101CNB04.img",
            }),
            "_pending_tool_args_override": {
                "python_exec": {
                    "code": "import os; print(os.path.exists('/mnt/data')); print(os.listdir('/mnt'))",
                },
            },
        })
        self.assertIn("Blocked python_exec host filesystem probe", blocked)

    def test_low_signal_firmware_search_patterns_are_blocked_for_artifact_runs(self):
        agent = self.AgentClass(
            llm=MagicMock(), tools=self.registry,
            memory=MagicMock(), compressor=MagicMock(), config=MagicMock(),
        )
        tool_def = self.registry.get("firmware_search")
        self.assertIsNotNone(tool_def)
        assert tool_def is not None

        blocked = agent._tool_policy_block_reason(tool_def, {
            **_make_state(metadata={
                "target": r"E:\MYAGENTS\firmware\DIR816_A1_FW101CNB04.img",
                "provenance": r"artifact:E:\MYAGENTS\firmware\DIR816_A1_FW101CNB04.img",
            }),
            "_pending_tool_args_override": {
                "firmware_search": {
                    "path": r"E:\MYAGENTS\firmware\DIR816_A1_FW101CNB04.img",
                    "pattern": "goform/",
                    "mode": "auto",
                },
            },
        })
        self.assertIn("Blocked low-signal firmware_search pattern", blocked)

    def test_cgi_bin_with_trailing_slash_is_blocked_for_artifact_runs(self):
        agent = self.AgentClass(
            llm=MagicMock(), tools=self.registry,
            memory=MagicMock(), compressor=MagicMock(), config=MagicMock(),
        )
        tool_def = self.registry.get("firmware_search")
        self.assertIsNotNone(tool_def)
        assert tool_def is not None

        blocked = agent._tool_policy_block_reason(tool_def, {
            **_make_state(metadata={
                "target": r"E:\MYAGENTS\firmware\DIR816_A1_FW101CNB04.img",
                "provenance": r"artifact:E:\MYAGENTS\firmware\DIR816_A1_FW101CNB04.img",
            }),
            "_pending_tool_args_override": {
                "firmware_search": {
                    "path": r"E:\MYAGENTS\firmware\DIR816_A1_FW101CNB04.img",
                    "pattern": "cgi-bin/",
                    "mode": "auto",
                },
            },
        })
        self.assertIn("Blocked low-signal firmware_search pattern", blocked)

    def test_generic_shell_readback_is_blocked_for_artifact_runs(self):
        agent = self.AgentClass(
            llm=MagicMock(), tools=self.registry,
            memory=MagicMock(), compressor=MagicMock(), config=MagicMock(),
        )
        tool_def = self.registry.get("firmware_read_path")
        self.assertIsNotNone(tool_def)
        assert tool_def is not None

        blocked = agent._tool_policy_block_reason(tool_def, {
            **_make_state(metadata={
                "target": r"E:\MYAGENTS\firmware\DIR816_A1_FW101CNB04.img",
                "provenance": r"artifact:E:\MYAGENTS\firmware\DIR816_A1_FW101CNB04.img",
            }),
            "_pending_tool_args_override": {
                "firmware_read_path": {
                    "path": r"E:\MYAGENTS\firmware\DIR816_A1_FW101CNB04.img",
                    "inner_path": "/bin/sh",
                    "mode": "strings",
                },
            },
        })
        self.assertIn("Blocked low-signal firmware_read_path target", blocked)

    def test_route_after_reasoning_verifies_at_iteration_limit_without_tool_calls(self):
        config = MagicMock()
        config.get.side_effect = lambda key, default=None: 3 if key == "max_iterations" else default
        agent = self.AgentClass(
            llm=MagicMock(), tools=self.registry,
            memory=MagicMock(), compressor=MagicMock(), config=config,
        )
        route = agent._route_after_reasoning(_make_state(
            iteration_count=3,
            messages=[AIMessage(content="enough evidence collected")],
        ))
        self.assertEqual(route, "verify")

    def test_route_after_reasoning_verifies_after_blocked_artifact_read_streak(self):
        config = MagicMock()
        config.get.side_effect = lambda key, default=None: 5 if key == "max_iterations" else default
        agent = self.AgentClass(
            llm=MagicMock(), tools=self.registry,
            memory=MagicMock(), compressor=MagicMock(), config=config,
        )
        route = agent._route_after_reasoning(_make_state(
            messages=[
                AIMessage(
                    content="",
                    tool_calls=[
                        {
                            "id": "call-1",
                            "name": "firmware_runtime_manifest",
                            "args": {"path": "firmware.bin"},
                        },
                    ],
                ),
            ],
            executed_tools=[
                {
                    "name": "firmware_emulation_launch_system",
                    "args": {"path": "firmware.bin"},
                    "success": True,
                    "result_summary": "PACKAGE_PATH: E:/Temp/vulnagent/runs/demo/emulation/launch-system.txt",
                },
                {
                    "name": "firmware_read_path",
                    "args": {"path": "firmware.bin", "inner_path": "/etc_ro/web/cgi-bin/upload.cgi"},
                    "success": False,
                    "result_summary": "Blocked repeated tool call: firmware_read_path with the same arguments already succeeded.",
                },
                {
                    "name": "firmware_read_path",
                    "args": {"path": "firmware.bin", "inner_path": "/etc_ro/web/cgi-bin/upload_settings.cgi"},
                    "success": False,
                    "result_summary": "Blocked repeated tool call: firmware_read_path with the same arguments already succeeded.",
                },
                {
                    "name": "firmware_read_path",
                    "args": {"path": "firmware.bin", "inner_path": "/etc_ro/web/d_upload.asp"},
                    "success": False,
                    "result_summary": "Blocked repeated tool call: firmware_read_path with the same arguments already succeeded.",
                },
            ],
            metadata={"target": "firmware.bin", "provenance": "artifact:firmware.bin"},
        ))
        self.assertEqual(route, "verify")

    def test_route_after_reasoning_continues_when_tools_remain_available(self):
        config = MagicMock()
        config.get.side_effect = lambda key, default=None: 5 if key == "max_iterations" else default
        agent = self.AgentClass(
            llm=MagicMock(), tools=self.registry,
            memory=MagicMock(), compressor=MagicMock(), config=config,
        )
        route = agent._route_after_reasoning(_make_state(
            messages=[AIMessage(content="Need to validate the strongest telnet lead before concluding.")],
            compaction={
                "compaction_count": 0,
                "last_compaction_at_tokens": 0,
                "micro_compact_threshold": 0.6,
                "mid_compact_threshold": 0.8,
                "deep_compact_threshold": 0.95,
                "no_tool_call_streak": 1,
                "total_iterations": 1,
                "deep_compaction_count": 0,
            },
            metadata={"target": "firmware.bin", "provenance": "artifact:firmware.bin"},
        ))
        self.assertEqual(route, "continue_reasoning")

    def test_reasoning_node_empty_firmware_response_falls_back_to_probe_tool_call(self):
        llm = SimpleNamespace(invoke=MagicMock())
        llm.invoke.side_effect = [
            SimpleNamespace(tool_calls=[], content="", usage=SimpleNamespace(total_tokens=0, prompt_tokens=0, completion_tokens=0), model="test", reasoning_content=""),
            SimpleNamespace(tool_calls=[], content="", usage=SimpleNamespace(total_tokens=0, prompt_tokens=0, completion_tokens=0), model="test", reasoning_content=""),
            SimpleNamespace(tool_calls=[], content="", usage=SimpleNamespace(total_tokens=0, prompt_tokens=0, completion_tokens=0), model="test", reasoning_content=""),
        ]
        config = MagicMock()
        config.get.side_effect = lambda key, default=None: default
        agent = self.AgentClass(
            llm=llm, tools=self.registry,
            memory=MagicMock(), compressor=MagicMock(), config=config,
        )

        result = agent._reasoning_node(_make_state(
            metadata={
                "target": r"E:\MYAGENTS\firmware\DIR816_A1_FW101CNB04.img",
                "provenance": r"artifact:E:\MYAGENTS\firmware\DIR816_A1_FW101CNB04.img",
            },
            executed_tools=[
                {
                    "name": "firmware_runtime_manifest",
                    "args": {"path": r"E:\MYAGENTS\firmware\DIR816_A1_FW101CNB04.img"},
                    "success": True,
                },
                {
                    "name": "firmware_service_inventory",
                    "args": {"path": r"E:\MYAGENTS\firmware\DIR816_A1_FW101CNB04.img"},
                    "success": True,
                },
                {
                    "name": "firmware_emulation_launch_user",
                    "args": {"path": r"E:\MYAGENTS\firmware\DIR816_A1_FW101CNB04.img"},
                    "success": True,
                    "result_summary": "PROBE_PORT: 8080 PROBE_SERVICE_TYPE: http",
                },
            ],
            tool_outputs={
                "firmware_emulation_launch_user": "PROBE_PORT: 8080\nPROBE_SERVICE_TYPE: http\nPROBE_SCHEME: http",
            },
            compressed_outputs={
                "firmware_emulation_launch_user": "PROBE_PORT: 8080\nPROBE_SERVICE_TYPE: http\nPROBE_SCHEME: http",
            },
        ))

        tool_calls = result["messages"][0].tool_calls
        self.assertEqual(tool_calls[0]["name"], "firmware_emulation_probe")
        self.assertEqual(tool_calls[0]["args"]["port"], 8080)
        self.assertEqual(tool_calls[0]["args"]["service_type"], "http")

    def test_reasoning_node_empty_firmware_response_falls_back_to_targeted_read_path(self):
        llm = SimpleNamespace(invoke=MagicMock())
        llm.invoke.side_effect = [
            SimpleNamespace(tool_calls=[], content="", usage=SimpleNamespace(total_tokens=0, prompt_tokens=0, completion_tokens=0), model="test", reasoning_content=""),
            SimpleNamespace(tool_calls=[], content="", usage=SimpleNamespace(total_tokens=0, prompt_tokens=0, completion_tokens=0), model="test", reasoning_content=""),
            SimpleNamespace(tool_calls=[], content="", usage=SimpleNamespace(total_tokens=0, prompt_tokens=0, completion_tokens=0), model="test", reasoning_content=""),
        ]
        config = MagicMock()
        config.get.side_effect = lambda key, default=None: default
        agent = self.AgentClass(
            llm=llm, tools=self.registry,
            memory=MagicMock(), compressor=MagicMock(), config=config,
        )

        result = agent._reasoning_node(_make_state(
            metadata={
                "target": r"E:\MYAGENTS\firmware\DIR816_A1_FW101CNB04.img",
                "provenance": r"artifact:E:\MYAGENTS\firmware\DIR816_A1_FW101CNB04.img",
            },
            executed_tools=[
                {
                    "name": "firmware_runtime_manifest",
                    "args": {"path": r"E:\MYAGENTS\firmware\DIR816_A1_FW101CNB04.img"},
                    "success": True,
                },
                {
                    "name": "firmware_service_inventory",
                    "args": {"path": r"E:\MYAGENTS\firmware\DIR816_A1_FW101CNB04.img"},
                    "success": True,
                },
            ],
            tool_outputs={
                "firmware_extract_summary": "INTERESTING_PATH: /etc_ro/web/cgi-bin/upload.cgi\nINTERESTING_PATH: /bin/goahead",
            },
            compressed_outputs={
                "firmware_extract_summary": "INTERESTING_PATH: /etc_ro/web/cgi-bin/upload.cgi\nINTERESTING_PATH: /bin/goahead",
            },
        ))

        tool_calls = result["messages"][0].tool_calls
        self.assertEqual(tool_calls[0]["name"], "firmware_read_path")
        self.assertEqual(tool_calls[0]["args"]["inner_path"], "/etc_ro/web/cgi-bin/upload.cgi")
        self.assertEqual(tool_calls[0]["args"]["path"], r"E:\MYAGENTS\firmware\DIR816_A1_FW101CNB04.img")

    def test_reasoning_node_empty_firmware_response_falls_back_to_service_inventory_probe_when_reads_exhausted(self):
        llm = SimpleNamespace(invoke=MagicMock())
        llm.invoke.side_effect = [
            SimpleNamespace(tool_calls=[], content="", usage=SimpleNamespace(total_tokens=0, prompt_tokens=0, completion_tokens=0), model="test", reasoning_content=""),
            SimpleNamespace(tool_calls=[], content="", usage=SimpleNamespace(total_tokens=0, prompt_tokens=0, completion_tokens=0), model="test", reasoning_content=""),
            SimpleNamespace(tool_calls=[], content="", usage=SimpleNamespace(total_tokens=0, prompt_tokens=0, completion_tokens=0), model="test", reasoning_content=""),
        ]
        config = MagicMock()
        config.get.side_effect = lambda key, default=None: default
        agent = self.AgentClass(
            llm=llm, tools=self.registry,
            memory=MagicMock(), compressor=MagicMock(), config=config,
        )
        target = r"E:\MYAGENTS\firmware\DIR816_A1_FW101CNB04.img"
        successful_reads = [
            {
                "name": "firmware_read_path",
                "args": {"path": target, "inner_path": path},
                "success": True,
            }
            for path in [
                "/etc_ro/rcS",
                "/etc_ro/web/d_telnet.asp",
                "/bin/goahead",
                "/etc_ro/web/cgi-bin/upload.cgi",
                "/etc_ro/web/cgi-bin/upload_settings.cgi",
                "/sbin/chpasswd.sh",
                "/sbin/internet.sh",
                "/etc_ro/web/d_saveconf.asp",
            ]
        ]

        result = agent._reasoning_node(_make_state(
            metadata={
                "target": target,
                "provenance": f"artifact:{target}",
            },
            executed_tools=[
                {
                    "name": "firmware_runtime_manifest",
                    "args": {"path": target},
                    "success": True,
                },
                {
                    "name": "firmware_service_inventory",
                    "args": {"path": target},
                    "success": True,
                },
                {
                    "name": "firmware_emulation_launch_user",
                    "args": {"path": target},
                    "success": True,
                },
                *successful_reads,
            ],
            tool_outputs={
                "firmware_service_inventory": (
                    "SERVICE: http :: goahead :: /bin/goahead :: goahead\n"
                    "SERVICE_PROBE: goahead :: http :: http://127.0.0.1:80/\n"
                    "SERVICE: telnet :: busybox :: /bin/busybox :: busybox telnetd -F -p 2323\n"
                    "SERVICE_PROBE: busybox :: telnet :: telnet://127.0.0.1:2323\n"
                ),
            },
            compressed_outputs={
                "firmware_service_inventory": (
                    "SERVICE: http :: goahead :: /bin/goahead :: goahead\n"
                    "SERVICE_PROBE: goahead :: http :: http://127.0.0.1:80/\n"
                    "SERVICE: telnet :: busybox :: /bin/busybox :: busybox telnetd -F -p 2323\n"
                    "SERVICE_PROBE: busybox :: telnet :: telnet://127.0.0.1:2323\n"
                ),
            },
        ))

        tool_calls = result["messages"][0].tool_calls
        self.assertEqual(tool_calls[0]["name"], "firmware_emulation_probe")
        self.assertEqual(tool_calls[0]["args"]["port"], 80)
        self.assertEqual(tool_calls[0]["args"]["service_type"], "http")

    def test_reasoning_node_empty_firmware_response_skips_repeated_probe_and_uses_next_service_hint(self):
        llm = SimpleNamespace(invoke=MagicMock())
        llm.invoke.side_effect = [
            SimpleNamespace(tool_calls=[], content="", usage=SimpleNamespace(total_tokens=0, prompt_tokens=0, completion_tokens=0), model="test", reasoning_content=""),
            SimpleNamespace(tool_calls=[], content="", usage=SimpleNamespace(total_tokens=0, prompt_tokens=0, completion_tokens=0), model="test", reasoning_content=""),
            SimpleNamespace(tool_calls=[], content="", usage=SimpleNamespace(total_tokens=0, prompt_tokens=0, completion_tokens=0), model="test", reasoning_content=""),
        ]
        config = MagicMock()
        config.get.side_effect = lambda key, default=None: default
        agent = self.AgentClass(
            llm=llm, tools=self.registry,
            memory=MagicMock(), compressor=MagicMock(), config=config,
        )
        target = r"E:\MYAGENTS\firmware\DIR816_A1_FW101CNB04.img"

        result = agent._reasoning_node(_make_state(
            metadata={
                "target": target,
                "provenance": f"artifact:{target}",
            },
            executed_tools=[
                {
                    "name": "firmware_runtime_manifest",
                    "args": {"path": target},
                    "success": True,
                },
                {
                    "name": "firmware_service_inventory",
                    "args": {"path": target},
                    "success": True,
                },
                {
                    "name": "firmware_emulation_launch_user",
                    "args": {"path": target},
                    "success": True,
                },
                {
                    "name": "firmware_emulation_probe",
                    "args": {"port": 8080, "service_type": "http"},
                    "success": False,
                    "result_summary": "REACHABLE: FALSE",
                },
            ],
            tool_outputs={
                "firmware_emulation_launch_user": "PROBE_PORT: 8080\nPROBE_SERVICE_TYPE: http\nPROBE_SCHEME: http",
                "firmware_service_inventory": (
                    "SERVICE_PROBE: goahead :: http :: http://127.0.0.1:80/\n"
                    "SERVICE_PROBE: busybox :: telnet :: telnet://127.0.0.1:2323\n"
                ),
            },
            compressed_outputs={
                "firmware_emulation_launch_user": "PROBE_PORT: 8080\nPROBE_SERVICE_TYPE: http\nPROBE_SCHEME: http",
                "firmware_service_inventory": (
                    "SERVICE_PROBE: goahead :: http :: http://127.0.0.1:80/\n"
                    "SERVICE_PROBE: busybox :: telnet :: telnet://127.0.0.1:2323\n"
                ),
                "firmware_read_path:/etc_ro/web/d_telnet.asp": "No readable content returned for /etc_ro/web/d_telnet.asp (mode=text).",
                "firmware_read_path:/etc_ro/web/dir_login.asp": "No readable content returned for /etc_ro/web/dir_login.asp (mode=text).",
                "firmware_read_path:/etc_ro/web/d_saveconf.asp": "No readable content returned for /etc_ro/web/d_saveconf.asp (mode=text).",
                "firmware_read_path:/etc_ro/web/d_upload.asp": "No readable content returned for /etc_ro/web/d_upload.asp (mode=text).",
                "firmware_read_path:/etc_ro/web/cgi-bin/upload.cgi": "No readable content returned for /etc_ro/web/cgi-bin/upload.cgi (mode=text).",
                "firmware_read_path:/etc_ro/web/cgi-bin/upload_settings.cgi": "No readable content returned for /etc_ro/web/cgi-bin/upload_settings.cgi (mode=text).",
                "firmware_read_path:/etc_ro/web/cgi-bin/upload_bootloader.cgi": "No readable content returned for /etc_ro/web/cgi-bin/upload_bootloader.cgi (mode=text).",
                "firmware_read_path:/etc_ro/web/cgi-bin/upload_torrent.cgi": "No readable content returned for /etc_ro/web/cgi-bin/upload_torrent.cgi (mode=text).",
                "firmware_read_path:/etc_ro/web/cgi-bin/ExportSettings.sh": "No readable content returned for /etc_ro/web/cgi-bin/ExportSettings.sh (mode=text).",
                "firmware_read_path:/sbin/chpasswd.sh": "No readable content returned for /sbin/chpasswd.sh (mode=text).",
                "firmware_read_path:/sbin/internet.sh": "No readable content returned for /sbin/internet.sh (mode=text).",
                "firmware_read_path:/bin/goahead": "No readable content returned for /bin/goahead (mode=strings).",
            },
        ))

        tool_calls = result["messages"][0].tool_calls
        self.assertEqual(tool_calls[0]["name"], "firmware_emulation_probe")
        self.assertEqual(tool_calls[0]["args"]["port"], 80)
        self.assertEqual(tool_calls[0]["args"]["service_type"], "http")

class TestReportAgent(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        from vulnagent.agents.report_agent import ReportAgent
        cls.AgentClass = ReportAgent

    def test_initialization(self):
        agent = self.AgentClass(
            llm=MagicMock(), tools=MagicMock(),
            memory=MagicMock(), compressor=MagicMock(), config=MagicMock(),
        )
        self.assertIsNotNone(agent)
        from vulnagent.core.agent import BaseAgent
        self.assertIsInstance(agent, BaseAgent)

    def test_no_tools_schema(self):
        agent = self.AgentClass(
            llm=MagicMock(), tools=MagicMock(),
            memory=MagicMock(), compressor=MagicMock(), config=MagicMock(),
        )
        schema = agent.get_tools_schema()
        self.assertEqual(schema, [])

    def test_single_pass_graph_no_tool_loop(self):
        agent = self.AgentClass(
            llm=MagicMock(), tools=MagicMock(),
            memory=MagicMock(), compressor=MagicMock(), config=MagicMock(),
        )
        graph = agent.build_graph()
        self.assertIsNotNone(graph)
        self.assertTrue(hasattr(graph, "invoke"))

    def test_system_prompt_includes_findings(self):
        agent = self.AgentClass(
            llm=MagicMock(), tools=MagicMock(),
            memory=MagicMock(), compressor=MagicMock(), config=MagicMock(),
        )
        state = _make_state(metadata={
            "sub_agents_findings": [
                {"vuln": "SQL Injection", "severity": "High"},
            ]
        })
        prompt = agent.get_system_prompt(state)
        self.assertIn("SQL Injection", prompt)
        self.assertIn("High", prompt)
        self.assertIn("Findings", prompt)

    def test_system_prompt_includes_anchored_summary(self):
        agent = self.AgentClass(
            llm=MagicMock(), tools=MagicMock(),
            memory=MagicMock(), compressor=MagicMock(), config=MagicMock(),
        )
        state = _make_state(
            metadata={"sub_agents_findings": []},
            anchored_summary={"scope": "target.com", "tools": "nmap, gobuster"},
        )
        prompt = agent.get_system_prompt(state)
        self.assertIn("target.com", prompt)
        self.assertIn("Context", prompt)

    def test_system_prompt_empty_state(self):
        agent = self.AgentClass(
            llm=MagicMock(), tools=MagicMock(),
            memory=MagicMock(), compressor=MagicMock(), config=MagicMock(),
        )
        prompt = agent.get_system_prompt(_make_state())
        self.assertGreater(len(prompt), 0)
        self.assertTrue("Executive Summary" in prompt or "report" in prompt.lower())


if __name__ == "__main__":
    unittest.main()
