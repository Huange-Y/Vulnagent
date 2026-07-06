"""Tests for AgentState, TokenBudgetState, and CompactionState schemas."""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

import unittest
from common.core.state import AgentState, TokenBudgetState, CompactionState, MemoryBlock
from langchain_core.messages import HumanMessage


class TestTokenBudgetState(unittest.TestCase):

    def test_create_budget(self):
        budget = TokenBudgetState(
            total=100000, used=0,
            micro_threshold=0.6, mid_threshold=0.8, deep_threshold=0.95,
        )
        self.assertEqual(budget["total"], 100000)
        self.assertEqual(budget["used"], 0)

    def test_budget_usage_ratio(self):
        budget = TokenBudgetState(
            total=100000, used=75000,
            micro_threshold=0.6, mid_threshold=0.8, deep_threshold=0.95,
        )
        ratio = budget["used"] / budget["total"]
        self.assertEqual(ratio, 0.75)

    def test_budget_exhausted(self):
        budget = TokenBudgetState(
            total=100000, used=100000,
            micro_threshold=0.6, mid_threshold=0.8, deep_threshold=0.95,
        )
        self.assertGreaterEqual(budget["used"], budget["total"])


class TestCompactionState(unittest.TestCase):

    def test_create_compaction(self):
        comp = CompactionState(compaction_count=0, last_compaction_at_tokens=0)
        self.assertEqual(comp["compaction_count"], 0)

    def test_compaction_count_increment(self):
        comp = CompactionState(compaction_count=0)
        comp["compaction_count"] += 1
        self.assertEqual(comp["compaction_count"], 1)

    def test_full_compaction_state(self):
        comp = CompactionState(
            compaction_count=3, last_compaction_at_tokens=80000,
            micro_compact_threshold=0.6, mid_compact_threshold=0.8,
            deep_compact_threshold=0.95,
        )
        self.assertEqual(comp["compaction_count"], 3)
        self.assertEqual(comp["deep_compact_threshold"], 0.95)


class TestMemoryBlock(unittest.TestCase):

    def test_create_memory_block(self):
        block = MemoryBlock(
            block_id="mb1", label="web_finding",
            content="SQL injection in login", token_limit=500, priority=7,
        )
        self.assertEqual(block["block_id"], "mb1")
        self.assertEqual(block["content"], "SQL injection in login")
        self.assertEqual(block["priority"], 7)

    def test_memory_block_partial(self):
        block = MemoryBlock(block_id="mb2", label="recon_result", content="Port 80 open")
        self.assertEqual(block["block_id"], "mb2")
        # total=False allows missing keys
        self.assertNotIn("token_limit", block)


class TestAgentState(unittest.TestCase):

    def test_create_minimal_state(self):
        budget = TokenBudgetState(total=100000, used=0, micro_threshold=0.6, mid_threshold=0.8, deep_threshold=0.95)
        comp = CompactionState(compaction_count=0, last_compaction_at_tokens=0, micro_compact_threshold=0.6, mid_compact_threshold=0.8, deep_compact_threshold=0.95)

        state: AgentState = {
            "messages": [HumanMessage(content="task")],
            "task_description": "Find flag",
            "attachment_paths": [],
            "tool_outputs": {},
            "compressed_outputs": {},
            "memory_blocks": {},
            "memory_context": {},
            "current_agent": "web",
            "iteration_count": 0,
            "token_budget": budget,
            "phase": "execution",
            "final_result": None,
            "compaction": comp,
            "anchored_summary": {},
            "metadata": {},
        }

        self.assertEqual(state["task_description"], "Find flag")
        self.assertEqual(state["current_agent"], "web")
        self.assertEqual(len(state["messages"]), 1)

    def test_state_with_tool_outputs(self):
        budget = TokenBudgetState(total=100000, used=0, micro_threshold=0.6, mid_threshold=0.8, deep_threshold=0.95)
        comp = CompactionState(compaction_count=0, last_compaction_at_tokens=0)

        state: AgentState = {
            "messages": [], "task_description": "",
            "attachment_paths": [],
            "tool_outputs": {"nmap_scan": "Port 80 open\nPort 443 open"},
            "compressed_outputs": {"nmap_scan": "Ports: 80, 443"},
            "memory_blocks": {}, "memory_context": {},
            "current_agent": "", "iteration_count": 0,
            "token_budget": budget, "phase": "execution",
            "final_result": None, "compaction": comp,
            "anchored_summary": {}, "metadata": {},
        }

        self.assertEqual(len(state["tool_outputs"]), 1)
        self.assertIn("Port 80 open", state["tool_outputs"]["nmap_scan"])
        self.assertEqual(state["compressed_outputs"]["nmap_scan"], "Ports: 80, 443")

    def test_state_phases(self):
        valid_phases = ["routing", "execution", "compacting", "verification", "done"]
        budget = TokenBudgetState(total=100000, used=0, micro_threshold=0.6, mid_threshold=0.8, deep_threshold=0.95)
        comp = CompactionState(compaction_count=0, last_compaction_at_tokens=0)

        for phase in valid_phases:
            state: AgentState = {
                "messages": [], "task_description": "",
                "attachment_paths": [],
                "tool_outputs": {}, "compressed_outputs": {},
                "memory_blocks": {}, "memory_context": {},
                "current_agent": "", "iteration_count": 0,
                "token_budget": budget, "phase": phase,
                "final_result": None, "compaction": comp,
                "anchored_summary": {}, "metadata": {},
            }
            self.assertEqual(state["phase"], phase)


if __name__ == "__main__":
    unittest.main()
