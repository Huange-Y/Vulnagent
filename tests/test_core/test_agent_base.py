"""Tests for BaseAgent — graph building, routing logic, state management."""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

import unittest
from unittest.mock import MagicMock
from langchain_core.messages import SystemMessage, HumanMessage, AIMessage, ToolMessage

from common.core.agent import BaseAgent
from common.core.state import AgentState, TokenBudgetState, CompactionState


class _TestAgent(BaseAgent):
    """Minimal concrete agent for testing BaseAgent."""

    def get_system_prompt(self, state: AgentState) -> str:
        return "Test system prompt: iter {iteration}/{max_iterations}".format(
            iteration=state.get("iteration_count", 0),
            max_iterations=5,
        )

    def get_tools_schema(self) -> list[dict]:
        return [
            {
                "type": "function",
                "function": {
                    "name": "test_tool",
                    "description": "A test tool",
                    "parameters": {
                        "type": "object",
                        "properties": {"arg": {"type": "string"}},
                        "required": ["arg"],
                    },
                },
            }
        ]


def _make_state(**overrides) -> AgentState:
    budget = TokenBudgetState(
        total=100000, used=0,
        micro_threshold=0.6, mid_threshold=0.8, deep_threshold=0.95,
    )
    compaction = CompactionState(
        compaction_count=0, last_compaction_at_tokens=0,
        micro_compact_threshold=0.6, mid_compact_threshold=0.8,
        deep_compact_threshold=0.95,
    )
    state: AgentState = {
        "messages": [HumanMessage(content="Test task")],
        "task_description": "Test task",
        "attachment_paths": [],
        "tool_outputs": {},
        "compressed_outputs": {},
        "memory_blocks": {},
        "memory_context": {},
        "current_agent": "test",
        "iteration_count": 0,
        "token_budget": budget,
        "phase": "execution",
        "final_result": None,
        "compaction": compaction,
        "anchored_summary": {},
        "metadata": {},
    }
    state.update(overrides)
    return state


class TestBaseAgentGraph(unittest.TestCase):

    def setUp(self):
        mock_llm = MagicMock()
        mock_tools = MagicMock()
        mock_tools.get_openai_schema.return_value = []
        mock_memory = MagicMock()
        mock_compressor = MagicMock()
        self.agent = _TestAgent(
            llm=mock_llm, tools=mock_tools,
            memory=mock_memory, compressor=mock_compressor,
            config=MagicMock(),
        )

    def test_build_graph_returns_state_graph(self):
        graph = self.agent.build_graph()
        self.assertIsNotNone(graph)

    def test_graph_compiles(self):
        graph = self.agent.build_graph()
        self.assertIsNotNone(graph)

    def test_get_system_prompt(self):
        state = _make_state()
        prompt = self.agent.get_system_prompt(state)
        self.assertIn("Test system prompt", prompt)
        self.assertIn("iter 0/5", prompt)

    def test_get_tools_schema(self):
        schema = self.agent.get_tools_schema()
        self.assertEqual(len(schema), 1)
        self.assertEqual(schema[0]["function"]["name"], "test_tool")

    def test_reasoning_error_does_not_force_verification(self):
        self.agent.router = None
        self.agent.llm.invoke.side_effect = TimeoutError("Request timed out.")
        self.agent.config.get = MagicMock(return_value="")
        result = self.agent._reasoning_node(_make_state())
        self.assertNotIn("phase", result)
        self.assertIn("LLM ERROR", result["messages"][0].content)

    def test_preprocess_state_hook_default_is_identity(self):
        state = _make_state()
        result = self.agent.preprocess_state(state)
        self.assertIs(result, state)

    def test_postprocess_result_hook_default_is_identity(self):
        state = _make_state()
        result = self.agent.postprocess_result(state)
        self.assertIs(result, state)


class TestBaseAgentRouting(unittest.TestCase):

    def setUp(self):
        mock_llm = MagicMock()
        mock_tools = MagicMock()
        mock_tools.get_openai_schema.return_value = []
        mock_memory = MagicMock()
        mock_compressor = MagicMock()
        self.agent = _TestAgent(
            llm=mock_llm, tools=mock_tools,
            memory=mock_memory, compressor=mock_compressor,
            config=MagicMock(),
        )

    def test_route_with_tool_calls(self):
        state = _make_state(messages=[
            HumanMessage(content="task"),
            AIMessage(content="I'll use a tool", tool_calls=[
                {"id": "1", "name": "test_tool", "args": {"arg": "x"}},
            ]),
        ])
        route = self.agent._route_after_reasoning(state)
        self.assertEqual(route, "tools")

    def test_route_with_tool_calls_even_at_max_iterations(self):
        state = _make_state(
            iteration_count=5,
            messages=[
                HumanMessage(content="task"),
                AIMessage(content="I'll use a tool", tool_calls=[
                    {"id": "1", "name": "test_tool", "args": {"arg": "x"}},
                ]),
            ],
        )
        self.agent.config.get = MagicMock(side_effect=lambda key, default=None: {
            "max_iterations": 5,
            "hard_stop_deep_compacts": 12,
        }.get(key, default))
        route = self.agent._route_after_reasoning(state)
        self.assertEqual(route, "tools")

    def test_route_verify_when_phase_is_verification(self):
        state = _make_state(phase="verification")
        route = self.agent._route_after_reasoning(state)
        self.assertEqual(route, "verify")

    def test_route_verify_when_final_result_exists(self):
        state = _make_state(final_result="flag{test}")
        route = self.agent._route_after_reasoning(state)
        self.assertEqual(route, "verify")

    def test_route_verify_at_max_iterations(self):
        state = _make_state(iteration_count=5)
        self.agent.config.get = MagicMock(return_value=5)
        route = self.agent._route_after_reasoning(state)
        self.assertEqual(route, "deep_compact")

    def test_route_hard_stop_counts_only_deep_compactions(self):
        state = _make_state(iteration_count=5)
        state["compaction"]["compaction_count"] = 12
        state["compaction"]["deep_compaction_count"] = 0
        self.agent.config.get = MagicMock(side_effect=lambda key, default=None: {
            "max_iterations": 5,
            "hard_stop_deep_compacts": 12,
        }.get(key, default))
        route = self.agent._route_after_reasoning(state)
        self.assertEqual(route, "deep_compact")

    def test_route_hard_stops_after_deep_compaction_limit(self):
        state = _make_state(iteration_count=5)
        state["compaction"]["deep_compaction_count"] = 12
        self.agent.config.get = MagicMock(side_effect=lambda key, default=None: {
            "max_iterations": 5,
            "hard_stop_deep_compacts": 12,
        }.get(key, default))
        route = self.agent._route_after_reasoning(state)
        self.assertEqual(route, "verify")

    def test_route_end_when_no_further_action(self):
        state = _make_state(messages=[
            HumanMessage(content="task"),
            AIMessage(content="I'm done, no tools needed"),
        ])
        self.agent.config.get = MagicMock(return_value=5)
        route = self.agent._route_after_reasoning(state)
        self.assertIn(route, ("END", "__end__"))

    def test_route_micro_compact_when_budget_hits_l1_threshold(self):
        state = _make_state()
        state["token_budget"]["used"] = 65000
        state["token_budget"]["total"] = 100000
        route = self.agent._route_after_reasoning(state)
        self.assertEqual(route, "micro_compact")


class TestCompactionDecision(unittest.TestCase):

    def setUp(self):
        mock_llm = MagicMock()
        mock_tools = MagicMock()
        mock_tools.get_openai_schema.return_value = []
        mock_memory = MagicMock()
        mock_compressor = MagicMock()
        self.agent = _TestAgent(
            llm=mock_llm, tools=mock_tools,
            memory=mock_memory, compressor=mock_compressor,
            config=MagicMock(),
        )

    def test_no_compaction_when_budget_low(self):
        state = _make_state()
        state["token_budget"]["used"] = 10000
        state["token_budget"]["total"] = 100000
        result = self.agent._should_compact(state)
        self.assertEqual(result, "none")

    def test_micro_compact_at_60_percent(self):
        state = _make_state()
        state["token_budget"]["used"] = 65000
        state["token_budget"]["total"] = 100000
        result = self.agent._should_compact(state)
        self.assertEqual(result, "micro_compact")

    def test_mid_compact_at_80_percent(self):
        state = _make_state()
        state["token_budget"]["used"] = 85000
        state["token_budget"]["total"] = 100000
        result = self.agent._should_compact(state)
        self.assertEqual(result, "mid_compact")

    def test_deep_compact_at_95_percent(self):
        state = _make_state()
        state["token_budget"]["used"] = 97000
        state["token_budget"]["total"] = 100000
        result = self.agent._should_compact(state)
        self.assertEqual(result, "deep_compact")

    def test_no_compaction_when_total_is_zero(self):
        state = _make_state()
        state["token_budget"]["total"] = 0
        result = self.agent._should_compact(state)
        self.assertEqual(result, "none")
    def test_deep_compact_resets_iteration_count(self):
        state = _make_state(
            iteration_count=9,
            messages=[SystemMessage(content="system"), HumanMessage(content="task")],
        )
        result = self.agent._deep_compact_node(state)
        self.assertEqual(result["iteration_count"], 0)
        self.assertEqual(result["compaction"]["deep_compaction_count"], 1)

    def test_deep_compact_replaces_message_history(self):
        state = _make_state(
            messages=[SystemMessage(content="system"), HumanMessage(content="old task")],
            anchored_summary={"findings": "selected target"},
        )
        result = self.agent._deep_compact_node(state)
        self.assertEqual(result["messages"][0].id, "__remove_all__")

    def test_micro_compact_replaces_message_history(self):
        self.agent.compressor.compress.return_value = "old summary"
        state = _make_state(
            messages=[
                SystemMessage(content="system"),
                HumanMessage(content="old 1"),
                AIMessage(content="old 2"),
                HumanMessage(content="old 3"),
                AIMessage(content="old 4"),
                HumanMessage(content="recent 1"),
                AIMessage(content="recent 2"),
            ],
        )
        result = self.agent._compress_node(state)
        self.assertEqual(result["messages"][0].id, "__remove_all__")

    def test_micro_compact_drops_tool_call_without_output(self):
        self.agent.compressor.compress.return_value = "old summary"
        state = _make_state(
            messages=[
                SystemMessage(content="system"),
                HumanMessage(content="old 1"),
                HumanMessage(content="old 2"),
                HumanMessage(content="old 3"),
                HumanMessage(content="old 4"),
                AIMessage(content="missing tool output", tool_calls=[{"id": "call_1", "name": "test_tool", "args": {}}]),
                HumanMessage(content="recent"),
            ],
        )
        result = self.agent._compress_node(state)
        retained_messages = result["messages"][1:]
        self.assertFalse(any(getattr(message, "tool_calls", None) for message in retained_messages))

    def test_safe_recent_messages_preserves_tool_call_pair_order(self):
        messages = [
            AIMessage(content="used tool", tool_calls=[{"id": "call_1", "name": "test_tool", "args": {}}]),
            ToolMessage(content="tool output", tool_call_id="call_1"),
            AIMessage(content="next step"),
        ]
        result = self.agent._safe_recent_messages(messages, 3)
        self.assertEqual([type(message).__name__ for message in result], ["AIMessage", "ToolMessage", "AIMessage"])

    def test_safe_recent_messages_drops_orphan_tool_message(self):
        messages = [
            HumanMessage(content="filler"),
            ToolMessage(content="orphan output", tool_call_id="call_1"),
            AIMessage(content="next step"),
        ]
        result = self.agent._safe_recent_messages(messages, 3)
        self.assertFalse(any(isinstance(message, ToolMessage) for message in result))

    def test_mid_compact_replaces_message_history(self):
        self.agent.mid_compressor = MagicMock()
        self.agent.mid_compressor.compress_messages.return_value = {"findings": "selected target"}
        state = _make_state(
            messages=[
                SystemMessage(content="system"),
                HumanMessage(content="old task"),
                AIMessage(content="used tool", tool_calls=[{"id": "call_1", "name": "test_tool", "args": {"arg": "x"}}]),
                ToolMessage(content="tool output", tool_call_id="call_1"),
                AIMessage(content="next step"),
            ],
        )
        result = self.agent._mid_compact_node(state)
        self.assertEqual(result["messages"][0].id, "__remove_all__")
        retained_messages = result["messages"][1:]
        self.assertTrue(any(isinstance(message, ToolMessage) for message in retained_messages))
        tool_call_messages = [message for message in retained_messages if getattr(message, "tool_calls", None)]
        self.assertEqual(len(tool_call_messages), 1)

    def test_mid_compact_drops_orphan_tool_messages(self):
        self.agent.mid_compressor = MagicMock()
        self.agent.mid_compressor.compress_messages.return_value = {"findings": "selected target"}
        state = _make_state(
            messages=[
                SystemMessage(content="system"),
                AIMessage(content="call outside retained window", tool_calls=[{"id": "call_1", "name": "test_tool", "args": {}}]),
                *[HumanMessage(content=f"filler {index}") for index in range(10)],
                ToolMessage(content="orphan output", tool_call_id="call_1"),
                AIMessage(content="next step"),
            ],
        )
        result = self.agent._mid_compact_node(state)
        retained_messages = result["messages"][1:]
        self.assertFalse(any(isinstance(message, ToolMessage) for message in retained_messages))


class TestMessagesToDicts(unittest.TestCase):

    def setUp(self):
        mock_llm = MagicMock()
        mock_tools = MagicMock()
        mock_tools.get_openai_schema.return_value = []
        self.agent = _TestAgent(
            llm=mock_llm, tools=mock_tools,
            memory=MagicMock(), compressor=MagicMock(),
            config=MagicMock(),
        )

    def test_converts_system_message(self):
        msg = SystemMessage(content="System prompt")
        result = self.agent._messages_to_dicts([msg])
        self.assertEqual(result[0]["role"], "system")
        self.assertEqual(result[0]["content"], "System prompt")

    def test_converts_human_message(self):
        msg = HumanMessage(content="User query")
        result = self.agent._messages_to_dicts([msg])
        self.assertEqual(result[0]["role"], "user")
        self.assertEqual(result[0]["content"], "User query")

    def test_converts_ai_message(self):
        msg = AIMessage(content="AI response")
        result = self.agent._messages_to_dicts([msg])
        self.assertEqual(result[0]["role"], "assistant")
        self.assertEqual(result[0]["content"], "AI response")

    def test_converts_ai_message_with_tool_calls(self):
        msg = AIMessage(content="Calling tool", tool_calls=[
            {"id": "1", "name": "t", "args": {}},
        ])
        result = self.agent._messages_to_dicts([msg])
        self.assertEqual(result[0]["role"], "assistant")
        self.assertIn("tool_calls", result[0])

    def test_preprocess_state_injects_task_as_human_message(self):
        state = _make_state(messages=[] , task_description="open the login page")
        result = self.agent.preprocess_state(state)
        self.assertEqual(len(result["messages"]), 1)
        self.assertEqual(type(result["messages"][0]).__name__, "HumanMessage")
        self.assertEqual(result["messages"][0].content, "open the login page")

    def test_preprocess_state_keeps_existing_messages(self):
        state = _make_state(
            task_description="ignored",
            messages=[HumanMessage(content="existing")],
        )
        result = self.agent.preprocess_state(state)
        self.assertEqual(result["messages"][0].content, "existing")


if __name__ == "__main__":
    unittest.main()
