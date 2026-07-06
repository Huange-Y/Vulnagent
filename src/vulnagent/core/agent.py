"""BaseAgent — the abstract class every specialized agent inherits from.

Defines the standard graph structure: retrieve → reason → [tools|compact|verify|end]
"""

from __future__ import annotations

import json
import re
import uuid
from abc import ABC, abstractmethod
from typing import Any, AsyncIterator, Callable, Sequence

from langgraph.graph import StateGraph, END, START
from langgraph.graph.message import REMOVE_ALL_MESSAGES
from langgraph.checkpoint.memory import MemorySaver
from langgraph.types import Command
from langchain_core.messages import RemoveMessage

from vulnagent.core.state import AgentState
from vulnagent.events.types import AgentEvent, EventType
from vulnagent.llm.client import LLMClient
from vulnagent.utils.config import ConfigLoader
from vulnagent.utils.logging import StructuredLogger


class BaseAgent(ABC):
    """Abstract base for all specialized agents (WebAgent, CryptoAgent, etc.).

    Subclasses need only implement:
        get_system_prompt() — domain-specific system prompt
        get_tools_schema()  — which tools this agent can use

    The standard graph (build_graph) provides:
        retrieve_memory → agent_reasoning → tools → compress → [loop|verify|end]

    Override build_graph() to customize the graph structure.
    """

    def __init__(
        self,
        llm: Any = None,  # LLMClient or ModelRouter (ModelRouter preferred)
        tools: Any = None,  # ToolRegistry
        memory: Any = None,  # HierarchicalMemory
        compressor: Any = None,  # SecurityCompressor / MicroCompressor
        config: ConfigLoader | None = None,
        logger: StructuredLogger | None = None,
        # Phase 1 additions — all optional for graceful degradation
        kg: Any = None,  # KnowledgeGraph
        mid_compressor: Any = None,  # MidCompressor
        flashbulb: Any = None,  # FlashbulbMemory
        salience_detector: Any = None,  # SalienceDetector
        # Phase 2: observability
        event_emitter: Any = None,  # EventEmitter
        # Sandbox container for isolated tool execution
        sandbox: Any = None,
    ) -> None:
        # Support both old LLMClient and new ModelRouter
        self.llm = llm  # Direct client (backward compat)
        self.router = llm if hasattr(llm, "reason") else None  # ModelRouter
        self.tools = tools
        self.memory = memory
        self.compressor = compressor
        self.config = config or ConfigLoader({})
        self.logger = logger or StructuredLogger(self.__class__.__name__)

        # Phase 1: optional advanced components
        self.kg = kg
        self.mid_compressor = mid_compressor
        self.flashbulb = flashbulb
        self.salience_detector = salience_detector

        # Phase 2: event bus
        self.event_emitter = event_emitter

        # Sandbox container for isolated tool execution
        self.sandbox = sandbox

    # ── Subclass contract ──────────────────────────────────────────

    @abstractmethod
    def get_system_prompt(self, state: AgentState) -> str:
        """Return the system prompt for this agent given the current state."""
        ...

    @abstractmethod
    def get_tools_schema(self, state: AgentState | None = None) -> list[dict[str, Any]]:
        """Return OpenAI-compatible tool definitions for this agent."""
        ...

    # ── Hook methods (optional overrides) ─────────────────────────

    def preprocess_state(self, state: AgentState) -> AgentState:
        """Hook to modify state before the agent loop starts."""
        messages = list(state.get("messages", []))
        if messages:
            return state

        task_description = state.get("task_description", "")
        if not task_description:
            return state

        from langchain_core.messages import HumanMessage

        return {
            **state,
            "messages": [HumanMessage(content=task_description)],
        }

    def postprocess_result(self, state: AgentState) -> AgentState:
        """Hook to modify state after the agent loop finishes."""
        return state

    # ── Graph construction ────────────────────────────────────────

    # All nodes that can be interrupted
    ALL_INTERRUPTIBLE_NODES = [
        "retrieve_memory", "agent_reasoning", "execute_tools",
        "compress_output", "mid_compact", "deep_compact", "verify",
    ]

    # Default interrupt points for interactive mode
    DEFAULT_INTERRUPT_POINTS = ["agent_reasoning", "execute_tools"]

    def build_graph(
        self,
        interrupt_points: list[str] | None = None,
        interactive: bool = False,
    ) -> Any:
        """Build the standard agent StateGraph.

        Graph structure:
            START → retrieve_memory → agent_reasoning
                → [tools → compress → agent_reasoning | verify | compact | END]

        Args:
            interrupt_points: List of node names to interrupt BEFORE execution.
                None or empty = no interrupts (fully autonomous).
                Use ALL_INTERRUPTIBLE_NODES for maximum control.
            interactive: Shortcut for interrupt_points=DEFAULT_INTERRUPT_POINTS.
                Kept for backward compatibility.

        Returns a compiled graph ready for invoke() or stream().
        """
        builder = StateGraph(AgentState)

        # Nodes
        builder.add_node("retrieve_memory", self._retrieve_memory_node)
        builder.add_node("agent_reasoning", self._reasoning_node)
        builder.add_node("execute_tools", self._tools_node)
        builder.add_node("compress_output", self._compress_node)
        builder.add_node("mid_compact", self._mid_compact_node)
        builder.add_node("deep_compact", self._deep_compact_node)
        builder.add_node("verify", self._verify_node)

        # Edges
        builder.add_edge(START, "retrieve_memory")
        builder.add_edge("retrieve_memory", "agent_reasoning")

        builder.add_conditional_edges(
            "agent_reasoning",
            self._route_after_reasoning,
            {
                "tools": "execute_tools",
                "continue_reasoning": "agent_reasoning",
                "verify": "verify",
                "micro_compact": "compress_output",
                "compact": "mid_compact",
                "deep_compact": "deep_compact",
                END: END,
            },
        )

        builder.add_edge("execute_tools", "compress_output")
        builder.add_edge("compress_output", "agent_reasoning")
        builder.add_edge("mid_compact", "agent_reasoning")
        # Deep compact: save memories → clear context → reload memories
        builder.add_edge("deep_compact", "retrieve_memory")
        builder.add_edge("verify", END)

        # Resolve interrupt points
        if interactive:
            points = list(self.DEFAULT_INTERRUPT_POINTS)
        elif interrupt_points:
            points = [p for p in interrupt_points if p in self.ALL_INTERRUPTIBLE_NODES]
        else:
            points = []

        if points:
            return builder.compile(
                checkpointer=MemorySaver(),
                interrupt_before=points,
            )
        return builder.compile()

    def _replace_messages(self, messages: list[Any]) -> list[Any]:
        return [RemoveMessage(id=REMOVE_ALL_MESSAGES), *messages]

    @staticmethod
    def _safe_recent_messages(messages: list[Any], limit: int) -> list[Any]:
        recent_msgs = messages[-limit:]
        pending_tool_messages: dict[str, Any] = {}
        safe_recent: list[Any] = []
        for message in reversed(recent_msgs):
            type_name = type(message).__name__
            if type_name == "ToolMessage":
                tool_call_id = getattr(message, "tool_call_id", "")
                if tool_call_id:
                    pending_tool_messages[tool_call_id] = message
                continue
            tool_calls = getattr(message, "tool_calls", None) or []
            message_call_ids = [
                call.get("id") for call in tool_calls
                if isinstance(call, dict) and call.get("id")
            ]
            if tool_calls:
                if not all(call_id in pending_tool_messages for call_id in message_call_ids):
                    continue
                paired_tool_messages = [pending_tool_messages.pop(call_id) for call_id in message_call_ids]
                safe_recent[:0] = [message, *paired_tool_messages]
                continue
            safe_recent.insert(0, message)
        return safe_recent

    # ── Routing logic ──────────────────────────────────────────────

    def _route_after_reasoning(self, state: AgentState) -> str:
        """Decide where to go after the reasoning node."""
        messages = state.get("messages", [])

        # 1. Explicit verification or final result → done (only stop on success)
        if state.get("phase") == "verification" or state.get("final_result"):
            self.logger.info(f"Route: verify (phase={state.get('phase')}, final={state.get('final_result')})")
            return "verify"

        # 2. Check iteration limits BEFORE allowing more tool calls
        #    Use total_iterations (never reset) for hard stop
        max_iter = self.config.get("max_iterations", 5)
        try:
            max_iter = int(max_iter)
        except (TypeError, ValueError):
            max_iter = 5
        hard_stop_threshold = self.config.get("hard_stop_deep_compacts", 3)
        try:
            hard_stop_threshold = int(hard_stop_threshold)
        except (TypeError, ValueError):
            hard_stop_threshold = 3

        compaction = state.get("compaction", {}) or {}
        deep_compacts = compaction.get("deep_compaction_count", 0)
        total_iterations = compaction.get("total_iterations", 0)

        # Hard stop: too many deep compacts OR too many total iterations
        max_total_iterations = max_iter * (hard_stop_threshold + 1)
        if deep_compacts >= hard_stop_threshold or total_iterations >= max_total_iterations:
            self.logger.info(f"Route: verify (hard stop, {deep_compacts} deep compacts, {total_iterations} total iterations)")
            return "verify"

        blocked_streak_reason = self._artifact_blocked_tool_streak_reason(state)
        if blocked_streak_reason:
            self.logger.info(f"Route: verify ({blocked_streak_reason})")
            return "verify"

        # 3. LLM requested tool calls → execute them
        if messages:
            last_msg = messages[-1]
            if hasattr(last_msg, "tool_calls") and last_msg.tool_calls:
                return "tools"

        no_tool_call_streak = int(compaction.get("no_tool_call_streak", 0) or 0)
        if no_tool_call_streak > 0 and self._is_firmware_container_target(state) and messages:
            last_content = str(getattr(messages[-1], "content", "") or "")
            if "[LLM ERROR]" in last_content:
                tool_schema = self.get_tools_schema(state)
                if not self._fallback_tool_call_for_empty_response(state, tool_schema):
                    self.logger.info(
                        "Route: verify (firmware empty-response fallback exhausted, no safe autonomous follow-up remains)"
                    )
                    return "verify"
        if no_tool_call_streak > 0 and self.get_tools_schema(state):
            self.logger.info(
                f"Route: continue_reasoning (no tool calls yet, streak={no_tool_call_streak}, iter={state.get('iteration_count', 0)})"
            )
            return "continue_reasoning"

        # 4. Max iterations in current phase → deep compact
        if state.get("iteration_count", 0) >= max_iter:
            self.logger.info(f"Route: verify (iteration limit reached, iter={state.get('iteration_count')}, deep_compacts={deep_compacts})")
            return "verify"

        # 3. Deep compaction (L3): save memories, clear context, reload
        if self._should_compact(state) == "deep_compact":
            return "deep_compact"

        # 4. Mid compaction (L2): anchored summarization
        if self._should_compact(state) == "mid_compact":
            return "compact"

        # 5. Micro compaction (L1): smart truncation of message history
        if self._should_compact(state) == "micro_compact":
            return "micro_compact"

        return END

    def _should_compact(self, state: AgentState) -> str:
        """Return compaction level needed: "micro_compact" | "mid_compact" | "deep_compact" | "none"."""
        budget = state.get("token_budget", {})
        used = budget.get("used", 0)
        total = budget.get("total", 100000)
        if total <= 0:
            return "none"

        ratio = used / total
        thresholds = state.get("compaction", {})

        deep = thresholds.get("deep_compact_threshold", 0.95)
        if ratio >= deep:
            return "deep_compact"

        mid = thresholds.get("mid_compact_threshold", 0.80)
        if ratio >= mid:
            return "mid_compact"

        micro = thresholds.get("micro_compact_threshold", 0.60)
        if ratio >= micro:
            return "micro_compact"

        return "none"

    # ── Graph node implementations ─────────────────────────────────

    def _retrieve_memory_node(self, state: AgentState) -> dict[str, Any]:
        """Retrieve relevant memories for the current task via ReflectiveRetriever.

        Two-pass retrieval: keyword search → sufficiency check → reflective pass if needed.
        Gracefully degrades if memory system is not configured.
        """
        agent_name = state.get("current_agent", self.__class__.__name__)
        self._emit(AgentEvent.node_enter(agent_name, "retrieve_memory"))
        self._emit(AgentEvent.memory_retrieve_started(agent_name))

        if self.memory is None:
            self.logger.log_memory_op("retrieve", count=0,
                                     note="no memory system configured")
            self._emit(AgentEvent.memory_retrieve_completed(agent_name, 0))
            self._emit(AgentEvent.node_exit(agent_name, "retrieve_memory"))
            return {"memory_context": {}}

        from vulnagent.memory.retrieval import ReflectiveRetriever

        retriever = ReflectiveRetriever(
            memory=self.memory,
            kg=self.kg,
            llm_client=self.llm if not self.router else None,
        )

        memory_context = retriever.retrieve(state)

        # Filter long-term knowledge memories — higher threshold for reused knowledge
        # Only load if salience > 0.5 (flashbulb) or return was explicitly requested
        if "long_term" in memory_context:
            lt_entries = memory_context["long_term"]
            memory_context["long_term"] = [
                e for e in lt_entries
                if e.get("emotional_salience", 0) > 0.5
            ][:3]  # max 3 long-term knowledge entries per retrieval

        total_entries = sum(len(v) for v in memory_context.values())
        self.logger.log_memory_op("retrieve", count=total_entries)
        self._emit(AgentEvent.memory_retrieve_completed(
            agent_name, total_entries,
            layers=[k for k, v in memory_context.items() if v],
        ))
        self._emit(AgentEvent.node_exit(agent_name, "retrieve_memory"))

        return {"memory_context": memory_context}

    def _reasoning_node(self, state: AgentState) -> dict[str, Any]:
        """Call the LLM with system prompt, memory context, and compressed tool outputs."""
        agent_name = state.get("current_agent", self.__class__.__name__)
        iteration = state.get("iteration_count", 0)
        budget = state.get("token_budget", {})
        self._emit(AgentEvent.node_enter(agent_name, "agent_reasoning"))
        self._emit(AgentEvent.reasoning_started(agent_name, iteration=iteration))

        system_prompt = self.get_system_prompt(state)

        messages = list(state.get("messages", []))

        # Inject anchored summary as compacted context if available
        anchored = state.get("anchored_summary", {})
        if anchored and any(v.strip() for v in anchored.values() if v):
            from langchain_core.messages import SystemMessage
            compacted_block = self._format_anchored_context(anchored)
            # Insert after system prompt, before conversation
            if messages and hasattr(messages[0], "content"):
                messages.insert(1, SystemMessage(content=compacted_block))
            else:
                messages.insert(0, SystemMessage(content=compacted_block))

        # Ensure system prompt is the first message
        need_system = not messages
        if messages:
            first = messages[0]
            if not (hasattr(first, "content") and "SYSTEM" in str(type(first).__name__).upper()):
                need_system = True
        if need_system:
            from langchain_core.messages import SystemMessage
            messages = [SystemMessage(content=system_prompt)] + messages

        tool_schema = self.get_tools_schema(state)

        # Retry logic for empty responses (proxy may not support tool_choice properly)
        max_retries = 3
        response = None

        for attempt in range(max_retries):
            try:
                # Use ModelRouter if available (provider-agnostic, purpose-aware)
                if self.router:
                    # Use "auto" instead of "required" - some proxies don't support "required"
                    tool_choice = "auto" if tool_schema else None
                    response = self.router.reason(
                        messages=self._messages_to_dicts(messages),
                        tools=tool_schema if tool_schema else None,
                        tool_choice=tool_choice,
                    )
                else:
                    # Fallback: direct LLMClient (backward compat)
                    response = self.llm.invoke(
                        messages=self._messages_to_dicts(messages),
                        model=self.config.get("model", ""),
                        tools=tool_schema if tool_schema else None,
                        max_tokens=self.config.get("max_tokens", 4096),
                    )

                # Check if response is valid (has content or tool calls)
                if response and (response.tool_calls or response.content):
                    break

                # Empty response - retry with stronger prompt
                if attempt < max_retries - 1:
                    self.logger.info(f"Empty LLM response, retrying ({attempt + 1}/{max_retries})")
                    from langchain_core.messages import HumanMessage
                    tool_names = [t.get("function", {}).get("name", "") for t in (tool_schema or [])]
                    retry_msg = HumanMessage(content=f"[SYSTEM] Your previous response was empty. You MUST call one of these tools NOW: {', '.join(tool_names[:5])}. Call browser_page_state to see the current page.")
                    messages.append(retry_msg)

            except Exception as e:
                if attempt == max_retries - 1:
                    self.logger.error(f"LLM call failed after {max_retries} attempts: {e}")
                    self._emit(AgentEvent.agent_error(agent_name, str(e), node="agent_reasoning"))
                    return self._empty_response_fallback_result(
                        state,
                        tool_schema,
                        error_text=str(e),
                    )
                self.logger.warning(f"LLM call failed (attempt {attempt + 1}): {e}")
                continue

        if not response or (not response.tool_calls and not response.content):
            self.logger.error("LLM returned empty response after all retries")
            self._emit(AgentEvent.agent_error(agent_name, "Empty LLM response", node="agent_reasoning"))
            fallback_budget = dict(state.get("token_budget", {}))
            if response:
                fallback_budget["used"] = fallback_budget.get("used", 0) + response.usage.total_tokens
            return self._empty_response_fallback_result(
                state,
                tool_schema,
                error_text="Empty response",
                budget=fallback_budget,
            )

        # Update token budget
        budget = dict(state.get("token_budget", {}))
        budget["used"] = budget.get("used", 0) + response.usage.total_tokens

        # Build assistant message with optional tool calls
        from langchain_core.messages import AIMessage, ToolMessage, HumanMessage
        new_msgs: list[Any] = []
        if response.tool_calls:
            # LLM chain library internal format (stored in state.messages)
            tool_call_dicts = [
                {
                    "id": tc.id,
                    "name": tc.name,
                    "args": tc.arguments,
                }
                for tc in response.tool_calls
            ]
            for tc in response.tool_calls:
                self._emit(AgentEvent.reasoning_tool_call(
                    agent_name, tc.name, tc.arguments,
                ))
            # Preserve reasoning_content for DeepSeek thinking mode
            ai_msg = AIMessage(
                content=response.content,
                tool_calls=tool_call_dicts,
            )
            if response.reasoning_content:
                ai_msg.additional_kwargs = ai_msg.additional_kwargs or {}
                ai_msg.additional_kwargs["reasoning_content"] = response.reasoning_content
            new_msgs.append(ai_msg)

            # Reset no-tool-call streak on successful tool call
            compaction = dict(state.get("compaction", {}))
            compaction["no_tool_call_streak"] = 0
        elif response.content:
            # LLM returned text but no tool calls - add NYU-style "Please proceed" nudge
            ai_msg = AIMessage(content=response.content)
            if response.reasoning_content:
                ai_msg.additional_kwargs = ai_msg.additional_kwargs or {}
                ai_msg.additional_kwargs["reasoning_content"] = response.reasoning_content
            new_msgs.append(ai_msg)

            # Track consecutive no-tool-call iterations
            compaction = dict(state.get("compaction", {}))
            no_tool_streak = compaction.get("no_tool_call_streak", 0) + 1
            compaction["no_tool_call_streak"] = no_tool_streak

            # Add a specific nudge message based on context (NYU CTF pattern)
            if tool_schema:
                tool_names = [t.get("function", {}).get("name", "") for t in tool_schema]

                # Determine the best nudge based on what tools are available
                if "browser_page_state" in tool_names:
                    suggested_action = "Call browser_page_state to see the current page, then attack with payloads."
                elif "browser_extract" in tool_names:
                    suggested_action = "Call browser_extract to see page content."
                else:
                    suggested_action = f"Call one of: {', '.join(tool_names[:3])}"

                # Escalating urgency based on streak
                if no_tool_streak >= 3:
                    nudge = f"[SYSTEM URGENT] You have failed to call a tool {no_tool_streak} times. You MUST call a tool NOW or you will be terminated. {suggested_action}"
                elif no_tool_streak >= 2:
                    nudge = f"[SYSTEM WARNING] Please proceed to the next step using your best judgment. {suggested_action}"
                else:
                    nudge = f"[SYSTEM] You must call a tool to proceed. {suggested_action}"

                new_msgs.append(HumanMessage(content=nudge))

        iter_count = state.get("iteration_count", 0) + 1

        # Track total iterations across deep compacts
        compaction = dict(state.get("compaction", {}))
        compaction["total_iterations"] = compaction.get("total_iterations", 0) + 1

        self.logger.log_llm_call(
            model=response.model,
            tokens_in=response.usage.prompt_tokens,
            tokens_out=response.usage.completion_tokens,
        )

        # Flashbulb detection on LLM response content
        if self.salience_detector and self.flashbulb and response.content:
            try:
                scores = self.salience_detector.analyze(
                    response.content[:4000],
                    context={
                        "tool_name": "llm_reasoning",
                        "category": state.get("current_agent", ""),
                    },
                )
                if scores.composite >= 0.6:
                    fb_id = self.flashbulb.process_event(
                        f"[LLM] {response.content[:2000]}",
                        context={
                            "category": state.get("current_agent", ""),
                            "task_id": state.get("task_description", "")[:100],
                        },
                    )
                    if fb_id:
                        self._emit(AgentEvent.flashbulb_detected(
                            agent_name, scores.composite,
                            narrative=f"LLM discovery (salience={scores.composite:.2f})",
                            memory_id=fb_id,
                        ))
            except Exception as e:
                self.logger.warning(f"Flashbulb detection failed: {e}")

        self._emit(AgentEvent.reasoning_completed(
            agent_name, response.content or "",
            tokens_used=budget["used"], tokens_total=budget.get("total", 100000),
        ))
        self._emit(AgentEvent.token_budget(
            agent_name, budget["used"], budget.get("total", 100000),
        ))
        self._emit(AgentEvent.node_exit(agent_name, "agent_reasoning"))

        return {
            "messages": new_msgs,
            "token_budget": budget,
            "iteration_count": iter_count,
            "compaction": compaction,
        }

    def _tools_node(self, state: AgentState) -> dict[str, Any]:
        """Execute tool calls from the last AI message.

        Parses tool_calls, executes each via ToolRegistry, applies MicroCompressor
        to raw outputs, and stores results in tool_outputs/compressed_outputs.

        Also triggers flashbulb salience detection if configured.
        """
        agent_name = state.get("current_agent", self.__class__.__name__)
        self._emit(AgentEvent.node_enter(agent_name, "execute_tools"))

        messages = state.get("messages", [])
        if not messages:
            self._emit(AgentEvent.node_exit(agent_name, "execute_tools"))
            return {}

        last_msg = messages[-1]
        tool_calls = getattr(last_msg, "tool_calls", None)
        if not tool_calls:
            self._emit(AgentEvent.node_exit(agent_name, "execute_tools"))
            return {}

        from langchain_core.messages import ToolMessage
        import time

        tool_outputs = dict(state.get("tool_outputs", {}))
        compressed_outputs = dict(state.get("compressed_outputs", {}))
        executed_tools = list(state.get("executed_tools", []))  # Track tool history
        tool_messages: list[Any] = []

        for tc in tool_calls:
            tool_name = tc.get("name", "") if isinstance(tc, dict) else tc.name
            tool_args = tc.get("args", {}) if isinstance(tc, dict) else tc.arguments
            tool_args = self._coerce_tool_args(tool_args)
            tool_call_id = tc.get("id", "") if isinstance(tc, dict) else tc.id
            tool_args = self._rewrite_tool_args(tool_name, tool_args, state)

            self.logger.info(f"Executing tool: {tool_name}")
            self._emit(AgentEvent.tool_called(agent_name, tool_name, tool_args))

            try:
                # Execute via ToolRegistry
                if self.tools and tool_name in self.tools:
                    tool_def = self.tools.get(tool_name)
                    policy_state = {
                        **state,
                        "tool_outputs": tool_outputs,
                        "compressed_outputs": compressed_outputs,
                        "executed_tools": executed_tools,
                        "_pending_tool_args_override": {tool_name: tool_args},
                    }
                    block_reason = self._tool_policy_block_reason(tool_def, policy_state)
                    if block_reason:
                        raw_text = block_reason
                    else:
                        raw_result = tool_def.executor(tool_args)
                        raw_text = self._normalize_tool_result_text(raw_result)
                else:
                    raw_text = f"Tool '{tool_name}' not found in registry"

                # Apply L1 MicroCompressor
                compressed_text = raw_text
                if self.compressor:
                    try:
                        compressed_text = self.compressor.compress(
                            raw_text,
                            context={"tool_name": tool_name, "max_tokens": 2000},
                        )
                    except Exception:
                        compressed_text = raw_text[:8000]  # fallback truncation

                output_key = self._tool_output_key(tool_outputs, tool_name, tool_args)
                tool_outputs[output_key] = raw_text[:16000]
                compressed_outputs[output_key] = compressed_text

                # Track executed tool in history (survives compaction - HackSynth pattern)
                args_summary = str(tool_args)[:100] if tool_args else ""
                result_summary = compressed_text[:150] if compressed_text else ""
                executed_tools.append({
                    "name": tool_name,
                    "output_key": output_key,
                    "args": tool_args,
                    "args_summary": args_summary,
                    "result_summary": result_summary,
                    "timestamp": time.time(),
                    "success": self._tool_call_succeeded(raw_text),
                })

                self._emit(AgentEvent.tool_result(
                    agent_name, tool_name, compressed_text[:150],
                    raw_chars=len(raw_text), compressed_chars=len(compressed_text),
                ))

                # Flashbulb salience detection
                if self.salience_detector and self.flashbulb:
                    try:
                        scores = self.salience_detector.analyze(
                            raw_text[:4000],
                            context={
                                "tool_name": tool_name,
                                "risk_level": getattr(
                                    self.tools.get(tool_name) if self.tools else None,
                                    "risk_level", "moderate",
                                ),
                            },
                        )
                        if scores.composite >= 0.6:
                            fb_id = self.flashbulb.process_event(
                                f"[{tool_name}] {raw_text[:4000]}",
                                context={"tool_name": tool_name, "category": state.get("current_agent", "")},
                            )
                            if fb_id:
                                self._emit(AgentEvent.flashbulb_detected(
                                    agent_name, scores.composite,
                                    narrative=f"{tool_name} high salience",
                                    memory_id=fb_id,
                                ))
                    except Exception as e:
                        self.logger.warning(f"Flashbulb detection failed for tool {tool_name}: {e}")

                tool_messages.append(ToolMessage(
                    content=compressed_text[:4000],
                    tool_call_id=tool_call_id,
                    name=tool_name,
                ))

                raw_preview = raw_text.strip().replace("\n", " ")[:500]
                if raw_preview and (
                    len(raw_text) <= 500
                    or raw_preview.lower().startswith("blocked ")
                    or " error:" in raw_preview.lower()[:160]
                ):
                    self.logger.info(f"Tool {tool_name} output preview: {raw_preview}")
                self.logger.info(f"Tool {tool_name} done, output: {len(raw_text)} chars → {len(compressed_text)} chars")

            except Exception as e:
                error_text = f"Tool execution error: {e}"
                self.logger.error(f"Tool {tool_name} failed: {e}")
                self._emit(AgentEvent.tool_error(agent_name, tool_name, str(e)))
                output_key = self._tool_output_key(tool_outputs, tool_name, tool_args)
                tool_outputs[output_key] = error_text
                compressed_outputs[output_key] = error_text
                tool_messages.append(ToolMessage(
                    content=error_text,
                    tool_call_id=tool_call_id,
                    name=tool_name,
                ))

        self._emit(AgentEvent.node_exit(agent_name, "execute_tools"))

        # Add a simple user message after tool responses to nudge the model to continue
        # Some proxies/models need this to properly continue after tool calls
        # Use a very simple message to avoid being flagged as prompt injection
        from langchain_core.messages import HumanMessage
        if tool_messages:
            tool_messages.append(HumanMessage(content="OK"))

        return {
            "tool_outputs": tool_outputs,
            "compressed_outputs": compressed_outputs,
            "messages": tool_messages,
            "executed_tools": executed_tools,  # Survives compaction
        }

    def _rewrite_tool_args(self, tool_name: str, tool_args: Any, state: AgentState) -> Any:
        tool_args = self._coerce_tool_args(tool_args)
        if not isinstance(tool_args, dict):
            return tool_args

        metadata = state.get("metadata", {}) or {}
        target = str(metadata.get("target", "")).strip()
        provenance = str(metadata.get("provenance", "")).strip()
        if not target or "://" in target:
            return tool_args
        if tool_name not in {
            "file_identify",
            "binwalk_scan",
            "firmware_extract_summary",
            "firmware_read_path",
            "firmware_search",
            "firmware_web_surface_map",
        }:
            return tool_args

        candidate_path = str(tool_args.get("path", "")).strip()
        if not candidate_path:
            return {**tool_args, "path": target}
        if self._should_reanchor_artifact_path(candidate_path, target, provenance):
            rewritten = dict(tool_args)
            rewritten["path"] = target
            return rewritten
        return tool_args

    def _tool_policy_block_reason(self, tool_def: Any, state: AgentState) -> str:
        metadata = state.get("metadata", {}) or {}
        pending = dict(state.get("_pending_tool_args_override", {}) or {})
        tool_args = pending.get(getattr(tool_def, "name", ""), {})
        risk_level = getattr(tool_def, "risk_level", "safe")
        requires_network = bool(getattr(tool_def, "requires_network", False))

        repeat_reason = self._repeated_tool_call_reason(getattr(tool_def, "name", ""), tool_args, state)
        if repeat_reason:
            return repeat_reason
        search_noise_reason = self._firmware_search_noise_reason(getattr(tool_def, "name", ""), tool_args, state)
        if search_noise_reason:
            return search_noise_reason
        read_noise_reason = self._firmware_read_noise_reason(getattr(tool_def, "name", ""), tool_args, state)
        if read_noise_reason:
            return read_noise_reason
        python_reason = self._python_exec_host_probe_reason(getattr(tool_def, "name", ""), tool_args, state)
        if python_reason:
            return python_reason
        if risk_level == "dangerous" and not metadata.get("allow_dangerous_tools", False):
            return f"Blocked dangerous tool: {tool_def.name}"
        if requires_network and metadata.get("allow_network_tools") is False:
            return f"Blocked network tool: {tool_def.name}"
        return ""

    def _repeated_tool_call_reason(self, tool_name: str, tool_args: Any, state: AgentState) -> str:
        if tool_name not in {
            "file_identify",
            "readelf_headers",
            "strings_extract",
            "binwalk_scan",
            "firmware_extract_summary",
            "firmware_emulation_probe",
            "firmware_read_path",
            "firmware_search",
            "firmware_emulation_prepare",
            "firmware_emulation_launch_user",
            "firmware_emulation_launch_system",
        }:
            return ""
        if tool_name in {
            "firmware_emulation_prepare",
            "firmware_emulation_launch_user",
            "firmware_emulation_launch_system",
            "firmware_emulation_probe",
        }:
            if not self._tool_call_already_attempted(tool_name, tool_args, state):
                return ""
            return (
                f"Blocked repeated tool call: {tool_name} with the same arguments already ran. "
                "Reuse the cached emulation evidence and pivot to a different validation step."
            )
        if not self._tool_call_already_succeeded(tool_name, tool_args, state):
            return ""
        if tool_name in {"file_identify", "readelf_headers", "strings_extract", "binwalk_scan", "firmware_extract_summary"}:
            return (
                f"Blocked repeated tool call: {tool_name} with the same arguments already succeeded. "
                "Reuse the cached output and move to firmware_read_path or firmware_search for a narrower follow-up."
            )
        if tool_name == "firmware_read_path":
            return (
                "Blocked repeated tool call: firmware_read_path with the same arguments already succeeded. "
                "Inspect the cached readback, pick a different inner_path, or use firmware_search for related references."
            )
        if tool_name == "firmware_search":
            return (
                "Blocked repeated tool call: firmware_search with the same arguments already succeeded. "
                "Use the cached matches and choose a new pattern or a concrete file read next."
            )
        return f"Blocked repeated tool call: {tool_name}"

    @staticmethod
    def _tool_call_already_succeeded(tool_name: str, tool_args: Any, state: AgentState) -> bool:
        normalized_pending = BaseAgent._tool_call_identity(tool_name, tool_args)
        for entry in list(state.get("executed_tools", [])):
            if not isinstance(entry, dict):
                continue
            if str(entry.get("name", "")).strip() != tool_name:
                continue
            if not bool(entry.get("success", False)):
                continue
            if BaseAgent._tool_call_identity(tool_name, entry.get("args")) == normalized_pending:
                return True
        return False

    @staticmethod
    def _tool_call_already_attempted(tool_name: str, tool_args: Any, state: AgentState) -> bool:
        normalized_pending = BaseAgent._tool_call_identity(tool_name, tool_args)
        for entry in list(state.get("executed_tools", [])):
            if not isinstance(entry, dict):
                continue
            if str(entry.get("name", "")).strip() != tool_name:
                continue
            if BaseAgent._tool_call_identity(tool_name, entry.get("args")) == normalized_pending:
                return True
        return False

    @staticmethod
    def _tool_call_identity(tool_name: str, tool_args: Any) -> Any:
        normalized = BaseAgent._coerce_tool_args(tool_args)
        if not isinstance(normalized, dict):
            return (tool_name, normalized)

        path = BaseAgent._normalized_artifact_path(str(normalized.get("path", "")).strip())
        inner_path = str(normalized.get("inner_path", "")).strip()
        pattern = str(normalized.get("pattern", "")).strip()

        if tool_name in {
            "file_identify",
            "readelf_headers",
            "strings_extract",
            "binwalk_scan",
            "firmware_extract_summary",
            "firmware_web_surface_map",
            "file_read",
            "firmware_runtime_manifest",
            "firmware_service_inventory",
            "firmware_emulation_prepare",
            "firmware_emulation_launch_user",
            "firmware_emulation_launch_system",
        }:
            return (tool_name, path)
        if tool_name == "firmware_emulation_probe":
            return (
                tool_name,
                str(normalized.get("service_type", "")).strip().lower(),
                str(normalized.get("port", "")).strip(),
            )
        if tool_name == "firmware_search":
            return (tool_name, path, pattern)
        if tool_name == "firmware_read_path":
            return (tool_name, path, inner_path)
        return (tool_name, BaseAgent._normalize_tool_args(normalized))

    @staticmethod
    def _normalize_tool_args(tool_args: Any) -> Any:
        tool_args = BaseAgent._coerce_tool_args(tool_args)
        if not isinstance(tool_args, dict):
            return tool_args
        return {
            str(key): tool_args[key]
            for key in sorted(tool_args.keys(), key=str)
        }

    @staticmethod
    def _normalized_artifact_path(path: str) -> str:
        return str(path or "").strip().replace("/", "\\").lower()

    @staticmethod
    def _hide_completed_targeted_tools(
        tool_names: list[str],
        state: AgentState | None,
        candidate_names: set[str],
    ) -> list[str]:
        if not state or not candidate_names:
            return list(tool_names)

        metadata = state.get("metadata", {}) or {}
        target = str(metadata.get("target", "")).strip()
        if not target or "://" in target:
            return list(tool_names)

        completed: set[str] = set()
        for entry in list(state.get("executed_tools", [])):
            if not isinstance(entry, dict):
                continue
            if not bool(entry.get("success", False)):
                continue
            name = str(entry.get("name", "")).strip()
            if name not in candidate_names:
                continue
            args = BaseAgent._coerce_tool_args(entry.get("args"))
            if not isinstance(args, dict):
                continue
            if BaseAgent._artifact_paths_match(str(args.get("path", "")).strip(), target):
                completed.add(name)

        return [name for name in tool_names if name not in completed]

    @staticmethod
    def _has_successful_artifact_search(state: AgentState | None) -> bool:
        if not state:
            return False
        metadata = state.get("metadata", {}) or {}
        target = str(metadata.get("target", "")).strip()
        provenance = str(metadata.get("provenance", "")).strip()
        if not target or "://" in target or not provenance.startswith("artifact:"):
            return False
        for entry in list(state.get("executed_tools", [])):
            if not isinstance(entry, dict):
                continue
            if str(entry.get("name", "")).strip() != "firmware_search":
                continue
            if not bool(entry.get("success", False)):
                continue
            args = BaseAgent._coerce_tool_args(entry.get("args"))
            if isinstance(args, dict) and BaseAgent._artifact_paths_match(str(args.get("path", "")).strip(), target):
                return True
        return False

    @staticmethod
    def _target_tool_matches(
        state: AgentState | None,
        candidate_names: set[str],
        *,
        require_success: bool,
    ) -> set[str]:
        if not state or not candidate_names:
            return set()
        metadata = state.get("metadata", {}) or {}
        target = str(metadata.get("target", "")).strip()
        provenance = str(metadata.get("provenance", "")).strip()
        if not target or "://" in target or not provenance.startswith("artifact:"):
            return set()

        matched: set[str] = set()
        for entry in list(state.get("executed_tools", [])):
            if not isinstance(entry, dict):
                continue
            name = str(entry.get("name", "")).strip()
            if name not in candidate_names:
                continue
            if require_success and not bool(entry.get("success", False)):
                continue
            args = BaseAgent._coerce_tool_args(entry.get("args"))
            if isinstance(args, dict) and BaseAgent._artifact_paths_match(str(args.get("path", "")).strip(), target):
                matched.add(name)
        return matched

    @staticmethod
    def _artifact_paths_match(candidate_path: str, target: str) -> bool:
        left = BaseAgent._normalized_artifact_path(candidate_path)
        right = BaseAgent._normalized_artifact_path(target)
        if not left or not right:
            return False
        return left == right

    @staticmethod
    def _should_reanchor_artifact_path(candidate_path: str, target: str, provenance: str) -> bool:
        normalized = candidate_path.replace("/", "\\").lower()
        target_normalized = target.replace("/", "\\").lower()
        if normalized == target_normalized:
            return False
        if normalized.startswith("\\mnt\\") or normalized in {"\\mnt", "\\mnt\\data"}:
            return True
        if provenance.startswith("artifact:"):
            try:
                from pathlib import Path

                return not Path(candidate_path).exists()
            except Exception:
                return True
        return False

    @staticmethod
    def _python_exec_host_probe_reason(tool_name: str, tool_args: Any, state: AgentState) -> str:
        if tool_name != "python_exec":
            return ""
        tool_args = BaseAgent._coerce_tool_args(tool_args)
        if not isinstance(tool_args, dict):
            return ""

        metadata = state.get("metadata", {}) or {}
        target = str(metadata.get("target", "")).strip()
        provenance = str(metadata.get("provenance", "")).strip()
        if not target or "://" in target or not provenance.startswith("artifact:"):
            return ""

        code = str(tool_args.get("code", "")).strip()
        lowered = code.lower()
        suspicious = (
            "/mnt/data",
            "\\mnt\\data",
            "os.listdir(",
            "os.walk(",
            "os.path.exists(",
            "glob.glob(",
            "path('/mnt",
            "path(\"/mnt",
        )
        if any(marker in lowered for marker in suspicious):
            target_lower = target.lower()
            target_escaped_lower = target.replace("\\", "\\\\").lower()
            if target_lower not in lowered and target_escaped_lower not in lowered:
                # Count streak of blocked python_exec calls — break loop after 3
                streak = sum(
                    1 for t in state.get("executed_tools", [])
                    if isinstance(t, dict) and t.get("name") == "python_exec"
                    and not t.get("success")
                )
                if streak >= 2:
                    return (
                        "STOP using python_exec. After 2 blocked attempts, switch to "
                        "firmware_read_path, firmware_search, or firmware_extract_summary. "
                        "python_exec is for firmware artifact analysis only."
                    )
                return (
                    "Blocked python_exec host filesystem probe during artifact analysis. "
                    "Use firmware_extract_summary, firmware_read_path, or firmware_search "
                    "against the provided artifact path instead."
                )
        return ""

    @staticmethod
    def _artifact_blocked_tool_streak_reason(state: AgentState | None) -> str:
        if not BaseAgent._is_firmware_container_target(state):
            return ""

        metadata = state.get("metadata", {}) or {}
        target = str(metadata.get("target", "")).strip()
        executed_tools = [
            entry
            for entry in list(state.get("executed_tools", []))
            if isinstance(entry, dict)
        ]
        if len(executed_tools) < 3:
            return ""

        recent = executed_tools[-3:]
        prior = executed_tools[:-3]
        has_prior_signal = False
        for entry in prior:
            args = BaseAgent._coerce_tool_args(entry.get("args"))
            if not isinstance(args, dict):
                continue
            if str(args.get("path", "")).strip() != target:
                continue
            if not bool(entry.get("success", False)):
                continue
            if str(entry.get("name", "")).strip() in {
                "firmware_runtime_manifest",
                "firmware_service_inventory",
                "firmware_emulation_prepare",
                "firmware_emulation_launch_user",
                "firmware_emulation_launch_system",
                "firmware_search",
                "firmware_read_path",
            }:
                has_prior_signal = True
                break
        if not has_prior_signal:
            return ""

        for entry in recent:
            if bool(entry.get("success", False)):
                return ""
            if str(entry.get("name", "")).strip() != "firmware_read_path":
                return ""
            args = BaseAgent._coerce_tool_args(entry.get("args"))
            if not isinstance(args, dict):
                return ""
            if str(args.get("path", "")).strip() != target:
                return ""
            summary = " ".join(str(entry.get("result_summary", "")).split()).lower()
            if not summary.startswith("blocked repeated tool call: firmware_read_path"):
                return ""

        return "artifact repeated-read streak exhausted"

    @staticmethod
    def _firmware_search_noise_reason(tool_name: str, tool_args: Any, state: AgentState) -> str:
        if tool_name != "firmware_search":
            return ""
        tool_args = BaseAgent._coerce_tool_args(tool_args)
        if not isinstance(tool_args, dict):
            return ""

        metadata = state.get("metadata", {}) or {}
        target = str(metadata.get("target", "")).strip()
        provenance = str(metadata.get("provenance", "")).strip()
        if not target or "://" in target or not provenance.startswith("artifact:"):
            return ""

        pattern = str(tool_args.get("pattern", "")).strip().lower()
        if pattern in {
            "goform", "goform/", "/goform/",
            "cgi-bin", "cgi-bin/", "/cgi-bin/",
            "system command", "popen", "system(", "strcpy",
        }:
            search_count = sum(
                1 for t in (state.get("executed_tools") or [])
                if isinstance(t, dict) and t.get("name") == "firmware_search"
                and t.get("success") is True
            )
            if search_count >= 2:
                return (
                    "Blocked low-signal firmware_search pattern after 2 searches. "
                    "Use the results from previous searches to pick a specific handler, "
                    "script, or symbol: form2Telnet.cgi, formLogin, "
                    "showSystemCommandASP, doSystem, upload.cgi.c, chpasswd.sh."
                )
        return ""

    @staticmethod
    def _firmware_read_noise_reason(tool_name: str, tool_args: Any, state: AgentState) -> str:
        if tool_name != "firmware_read_path":
            return ""
        tool_args = BaseAgent._coerce_tool_args(tool_args)
        if not isinstance(tool_args, dict):
            return ""

        metadata = state.get("metadata", {}) or {}
        target = str(metadata.get("target", "")).strip()
        provenance = str(metadata.get("provenance", "")).strip()
        if not target or "://" in target or not provenance.startswith("artifact:"):
            return ""

        inner_path = str(tool_args.get("inner_path", "")).strip().lower()
        if inner_path in {"/bin/sh", "/bin/ash", "/bin/bash"}:
            return (
                "Blocked low-signal firmware_read_path target during artifact analysis. "
                "Read a concrete management script, web asset, or handler binary such as "
                "/etc_ro/rcS, /etc_ro/web/d_telnet.asp, /etc_ro/web/cgi-bin/upload_settings.cgi, "
                "/sbin/internet.sh, or /bin/goahead."
            )
        return ""

    @staticmethod
    def _coerce_tool_args(tool_args: Any) -> Any:
        if isinstance(tool_args, str):
            stripped = tool_args.strip()
            if stripped.startswith("{") or stripped.startswith("["):
                try:
                    return json.loads(stripped)
                except Exception:
                    return tool_args
        return tool_args

    @staticmethod
    def _is_firmware_container_target(state: AgentState | None) -> bool:
        if not state:
            return False
        metadata = state.get("metadata", {}) or {}
        target = str(metadata.get("target", "")).strip().lower()
        provenance = str(metadata.get("provenance", "")).strip().lower()
        if not target or "://" in target or not provenance.startswith("artifact:"):
            return False
        return target.endswith((
            ".img",
            ".bin",
            ".fw",
            ".rom",
            ".trx",
            ".chk",
            ".dlf",
            ".uimage",
            ".ubi",
        ))

    def _empty_response_fallback_result(
        self,
        state: AgentState,
        tool_schema: list[dict[str, Any]],
        *,
        error_text: str,
        budget: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        from langchain_core.messages import AIMessage, SystemMessage

        compaction = dict(state.get("compaction", {}))
        fallback_call = self._fallback_tool_call_for_empty_response(state, tool_schema)
        if fallback_call:
            compaction["no_tool_call_streak"] = 0
            compaction["total_iterations"] = compaction.get("total_iterations", 0) + 1
            return {
                "messages": [
                    AIMessage(
                        content="[SYSTEM] Empty LLM response. Continuing with the next best validation action.",
                        tool_calls=[fallback_call],
                    )
                ],
                "iteration_count": state.get("iteration_count", 0) + 1,
                "compaction": compaction,
                "token_budget": dict(budget or state.get("token_budget", {})),
            }

        no_tool_streak = int(compaction.get("no_tool_call_streak", 0) or 0) + 1
        compaction["no_tool_call_streak"] = no_tool_streak
        compaction["total_iterations"] = compaction.get("total_iterations", 0) + 1
        return {
            "messages": [
                SystemMessage(
                    content=self._empty_response_guidance_message(
                        state,
                        tool_schema,
                        error_text=error_text,
                        no_tool_streak=no_tool_streak,
                    )
                )
            ],
            "iteration_count": state.get("iteration_count", 0) + 1,
            "compaction": compaction,
            "token_budget": dict(budget or state.get("token_budget", {})),
        }

    def _empty_response_guidance_message(
        self,
        state: AgentState,
        tool_schema: list[dict[str, Any]],
        *,
        error_text: str,
        no_tool_streak: int,
    ) -> str:
        tool_names = [t.get("function", {}).get("name", "") for t in (tool_schema or [])]
        prefix = f"[LLM ERROR] {error_text}." if error_text else "[LLM ERROR] Empty response."
        if "browser_page_state" in tool_names:
            return f"{prefix} Call browser_page_state to inspect the current page and continue attacking."
        if self._is_firmware_container_target(state):
            if no_tool_streak >= 3:
                return (
                    f"{prefix} The model is stalling during firmware validation. "
                    "Use the strongest remaining artifact or emulation tool now and continue narrowing the lead."
                )
            return (
                f"{prefix} Continue firmware validation with the strongest remaining artifact or emulation tool."
            )
        if tool_names:
            return f"{prefix} Continue by calling one of: {', '.join(tool_names[:4])}."
        return f"{prefix} Continue the current analysis flow."

    def _fallback_tool_call_for_empty_response(
        self,
        state: AgentState,
        tool_schema: list[dict[str, Any]],
    ) -> dict[str, Any] | None:
        if not self._is_firmware_container_target(state):
            return None

        available = {
            str(item.get("function", {}).get("name", "")).strip()
            for item in (tool_schema or [])
            if isinstance(item, dict)
        }
        metadata = state.get("metadata", {}) or {}
        target = str(metadata.get("target", "")).strip()
        if not target:
            return None

        if "firmware_emulation_probe" in available:
            for probe_hint in self._fallback_probe_hints(state):
                probe_call = self._build_safe_fallback_tool_call(
                    "firmware_emulation_probe",
                    {
                        "port": probe_hint["port"],
                        "service_type": probe_hint["service_type"],
                    },
                    state,
                )
                if probe_call:
                    return probe_call

        current_agent = str(state.get("current_agent", "")).strip().lower()

        if "firmware_read_path" in available:
            for inner_path in self._fallback_firmware_read_paths(state):
                read_call = self._build_safe_fallback_tool_call(
                    "firmware_read_path",
                    {
                        "path": target,
                        "inner_path": inner_path,
                        "mode": self._preferred_firmware_read_mode(inner_path),
                        "max_bytes": self._preferred_firmware_read_max_bytes(inner_path),
                    },
                    state,
                )
                if read_call:
                    return read_call

        if current_agent == "exploit":
            return None

        if "firmware_search" in available:
            for pattern in self._fallback_firmware_search_patterns(state):
                search_call = self._build_safe_fallback_tool_call(
                    "firmware_search",
                    {
                        "path": target,
                        "pattern": pattern,
                        "mode": "auto",
                        "max_results": 12,
                        "max_bytes": 131072,
                    },
                    state,
                )
                if search_call:
                    return search_call

        if "firmware_emulation_launch_system" in available:
            return self._build_safe_fallback_tool_call(
                "firmware_emulation_launch_system",
                {"path": target},
                state,
            )
        return None

    def _build_safe_fallback_tool_call(
        self,
        tool_name: str,
        tool_args: dict[str, Any],
        state: AgentState,
    ) -> dict[str, Any] | None:
        if not self.tools or tool_name not in self.tools:
            return None
        tool_def = self.tools.get(tool_name)
        if tool_def is None:
            return None
        block_reason = self._tool_policy_block_reason(tool_def, {
            **state,
            "_pending_tool_args_override": {tool_name: tool_args},
        })
        if block_reason:
            return None
        return {
            "id": f"empty-fallback-{uuid.uuid4().hex[:12]}",
            "name": tool_name,
            "args": tool_args,
        }

    @staticmethod
    def _fallback_probe_hint(state: AgentState) -> dict[str, Any] | None:
        hints = BaseAgent._fallback_probe_hints(state)
        return hints[0] if hints else None

    @staticmethod
    def _fallback_probe_hints(state: AgentState) -> list[dict[str, Any]]:
        text = BaseAgent._artifact_tool_text_blob(state)
        hints: list[dict[str, Any]] = []

        def add_hint(port: int, service_type: str) -> None:
            normalized_type = str(service_type or "http").strip().lower()
            if normalized_type not in {"http", "https", "telnet", "ssh"}:
                normalized_type = "http"
            candidate = {"port": int(port), "service_type": normalized_type}
            if candidate not in hints:
                hints.append(candidate)

        port_match = re.search(r"PROBE_PORT:\s+(\d+)", text, re.IGNORECASE)
        if port_match:
            try:
                port = int(port_match.group(1))
            except ValueError:
                port = 0
            service_match = re.search(r"PROBE_SERVICE_TYPE:\s+([^\r\n]+)", text, re.IGNORECASE)
            service_type = str(service_match.group(1)).strip().lower() if service_match else "http"
            if port > 0:
                add_hint(port, service_type)

        for service_probe_match in re.finditer(
            r"SERVICE_PROBE:\s+[^\r\n]*::\s*(http|https|telnet|ssh)\s*::\s*[A-Za-z]+://[^\s:/]+:(\d+)",
            text,
            re.IGNORECASE,
        ):
            service_type = str(service_probe_match.group(1)).strip().lower()
            try:
                port = int(service_probe_match.group(2))
            except ValueError:
                continue
            add_hint(port, service_type)

        return hints

    @staticmethod
    def _artifact_tool_text_blob(state: AgentState) -> str:
        parts: list[str] = []
        for mapping in (state.get("tool_outputs", {}), state.get("compressed_outputs", {})):
            if not isinstance(mapping, dict):
                continue
            for key, value in mapping.items():
                text = str(value or "").strip()
                if text:
                    parts.append(f"[{key}]\n{text}")
        for entry in list(state.get("executed_tools", [])):
            if not isinstance(entry, dict):
                continue
            summary = str(entry.get("result_summary", "")).strip()
            if summary:
                parts.append(summary)
        return "\n".join(parts)

    def _fallback_firmware_read_paths(self, state: AgentState) -> list[str]:
        from vulnagent.core.assessment import collect_artifact_observations

        candidate_paths: list[str] = []

        def add_path(inner_path: str) -> None:
            normalized = str(inner_path or "").strip()
            if not normalized.startswith("/"):
                return
            if normalized not in candidate_paths:
                candidate_paths.append(normalized)

        tool_outputs = dict(state.get("tool_outputs", {}) or {})
        observations = collect_artifact_observations({
            str(key): str(value)
            for key, value in tool_outputs.items()
            if str(value or "").strip()
        })
        for target in observations.get("priority_targets", []):
            if not isinstance(target, dict):
                continue
            for inner_path in target.get("paths", []):
                add_path(str(inner_path))

        for match in re.finditer(r"INTERESTING_PATH:\s+([^\r\n]+)", self._artifact_tool_text_blob(state), re.IGNORECASE):
            add_path(match.group(1))

        if candidate_paths:
            return candidate_paths[:20]

        for inner_path in [
            "/etc_ro/web/d_telnet.asp",
            "/etc_ro/web/dir_login.asp",
            "/etc_ro/web/d_saveconf.asp",
            "/etc_ro/web/d_upload.asp",
            "/etc_ro/web/cgi-bin/upload.cgi",
            "/etc_ro/web/cgi-bin/upload_settings.cgi",
            "/etc_ro/web/cgi-bin/upload_bootloader.cgi",
            "/etc_ro/web/cgi-bin/upload_torrent.cgi",
            "/etc_ro/web/cgi-bin/ExportSettings.sh",
            "/sbin/chpasswd.sh",
            "/sbin/internet.sh",
            "/bin/goahead",
        ]:
            add_path(inner_path)

        return candidate_paths[:20]

    def _fallback_firmware_search_patterns(self, state: AgentState) -> list[str]:
        joined = self._artifact_tool_text_blob(state).lower()
        patterns: list[str] = []
        for candidate in [
            "form2Telnet.cgi",
            "goform/formLogin",
            "showSystemCommandASP",
            "doSystem",
            "doSystembk",
            "upload.cgi.c",
            "import_5g",
            "chpasswd.sh",
            "config.img",
            "telnetEnabled",
            "upload_settings.cgi",
            "ExportSettings.sh",
            "websAspDefine",
            "ejSetGlobalFunctionDirect",
            "websGetRequestPath",
        ]:
            if candidate.lower() in joined and candidate not in patterns:
                patterns.append(candidate)
        return patterns[:12]

    @staticmethod
    def _preferred_firmware_read_mode(inner_path: str) -> str:
        normalized = str(inner_path or "").strip().lower()
        if normalized.endswith((".asp", ".cgi", ".sh", ".txt", ".cfg", ".conf", ".html", ".htm")):
            return "text"
        if normalized in {"/bin/goahead", "/bin/busybox", "/usr/sbin/httpd"}:
            return "strings"
        return "auto"

    @staticmethod
    def _preferred_firmware_read_max_bytes(inner_path: str) -> int:
        normalized = str(inner_path or "").strip().lower()
        if normalized in {"/bin/goahead", "/bin/busybox", "/usr/sbin/httpd"}:
            return 16384
        if normalized.endswith((".cgi", ".sh", ".asp", ".html", ".htm")):
            return 12288
        return 8192

    def _compress_node(self, state: AgentState) -> dict[str, Any]:
        """L1 Micro-compact: Smart Truncation on message history.

        Keeps system prompt + last N reasoning turns, truncates middle.
        Preserves security signals (CVE, flag, port, vulnerability references).
        """
        agent_name = state.get("current_agent", self.__class__.__name__)
        self._emit(AgentEvent.node_enter(agent_name, "compress_output"))

        messages = list(state.get("messages", []))
        orig_count = len(messages)
        compaction = dict(state.get("compaction", {}))

        if len(messages) <= 6:
            return {"compaction": compaction}

        # Keep system message + last 4 messages (2 turns)
        system_msgs = [m for m in messages if "System" in type(m).__name__]
        non_system = [m for m in messages if "System" not in type(m).__name__]

        if len(non_system) <= 4:
            return {"compaction": compaction}

        # Apply SmartTruncator to middle messages
        if self.compressor and hasattr(self.compressor, "compress"):
            mid_content = "\n".join(
                getattr(m, "content", "") or ""
                for m in non_system[:-4]
            )
            if mid_content:
                compressed_mid = self.compressor.compress(
                    mid_content,
                    context={"tool_name": "conversation", "max_tokens": 1500},
                )
                from langchain_core.messages import SystemMessage
                compact_msg = SystemMessage(
                    content=f"[COMPRESSED HISTORY]\n{compressed_mid}"
                )
                safe_recent = self._safe_recent_messages(non_system, 4)
                new_messages = system_msgs + [compact_msg] + safe_recent
                messages = new_messages

        compaction["compaction_count"] = compaction.get("compaction_count", 0) + 1
        compaction["micro_compaction_count"] = compaction.get("micro_compaction_count", 0) + 1
        compaction["last_compaction_at_tokens"] = state.get("token_budget", {}).get("used", 0)

        # Recalculate token budget after compaction
        budget = dict(state.get("token_budget", {}))
        estimated = sum(len(getattr(m, "content", "") or "") // 4 + 10 for m in messages)
        budget["used"] = max(
            int(budget.get("total", 100000) * 0.3),
            min(budget.get("used", 0), estimated + 500)
        )

        self.logger.info(f"L1 micro-compact: {len(non_system)} msgs → {len(messages)} msgs, budget: {budget['used']}")
        self._emit(AgentEvent.compress_micro(agent_name, orig_count, len(messages)))
        self._emit(AgentEvent.node_exit(agent_name, "compress_output"))

        return {
            "messages": self._replace_messages(messages),
            "compaction": compaction,
            "token_budget": budget,
        }

    def _mid_compact_node(self, state: AgentState) -> dict[str, Any]:
        """L2 Anchored Summarization: compress conversation into structured sections.

        Uses MidCompressor to incrementally merge conversation history into
        anchored sections (scope, files, tools, decisions, findings, open, next).
        Truncates the messages list after compression.
        """
        agent_name = state.get("current_agent", self.__class__.__name__)
        self._emit(AgentEvent.node_enter(agent_name, "mid_compact"))

        compaction = dict(state.get("compaction", {}))
        anchored = dict(state.get("anchored_summary", {}))

        messages = list(state.get("messages", []))
        orig_count = len(messages)

        if self.mid_compressor and hasattr(self.mid_compressor, "compress_messages"):
            try:
                anchored = self.mid_compressor.compress_messages(messages, anchored)
            except Exception as e:
                self.logger.error(f"Mid-compact failed: {e}")

        # Keep system + anchored summary + last N messages while preserving tool-call pairs.
        keep_msgs: list[Any] = []
        for m in messages:
            if "System" in type(m).__name__:
                keep_msgs.append(m)

        non_sys = [m for m in messages if "System" not in type(m).__name__]
        keep_msgs.extend(self._safe_recent_messages(non_sys, 10))

        from langchain_core.messages import SystemMessage
        context_block = self._format_anchored_context(anchored) if anchored else ""
        if context_block:
            keep_msgs.insert(1, SystemMessage(content=context_block))

        compaction["compaction_count"] = compaction.get("compaction_count", 0) + 1
        compaction["mid_compaction_count"] = compaction.get("mid_compaction_count", 0) + 1
        budget = dict(state.get("token_budget", {}))
        estimated_new_tokens = sum(
            len(getattr(m, "content", "") or "") // 4 + 10
            for m in keep_msgs
        )
        # Set used to a conservative estimate, never below 40% to allow future compactions
        budget["used"] = max(
            int(budget.get("total", 100000) * 0.4),
            min(budget.get("used", 0), estimated_new_tokens + 1000)
        )

        sections_populated = sum(1 for v in anchored.values() if v.strip())
        self.logger.info(
            f"L2 mid-compact: {orig_count} msgs → {len(keep_msgs)} msgs, "
            f"budget recalculated: {budget['used']}/{budget.get('total', 100000)}, "
            f"anchor sections populated: {sections_populated}"
        )
        self._emit(AgentEvent.compress_mid(
            agent_name, orig_count, len(keep_msgs), sections_populated=sections_populated,
        ))
        self._emit(AgentEvent.node_exit(agent_name, "mid_compact"))

        return {
            "messages": self._replace_messages(keep_msgs),
            "compaction": compaction,
            "token_budget": budget,
            "anchored_summary": anchored,
            "phase": "execution",
        }

    def _verify_node(self, state: AgentState) -> dict[str, Any]:
        """Verify results — vulnerability confirmation for vuln, flag extraction for CTF.

        When provenance indicates an artifact or live target (vuln mode), uses
        VulnVerifier to check for PoC evidence, reachable endpoints, and confirmed
        findings. Falls back to FlagExtractor for CTF mode.
        """
        agent_name = state.get("current_agent", self.__class__.__name__)
        self._emit(AgentEvent.node_enter(agent_name, "verify"))

        metadata = state.get("metadata", {}) or {}
        provenance = str(metadata.get("provenance", "")).strip()
        target = str(metadata.get("target", "")).strip()
        is_vuln_context = bool(
            provenance.startswith("artifact:") or provenance.startswith("live:")
        )

        final: str = ""
        phase: str = "done"
        confirmed_flag = False
        flag_candidates: list[str] = []
        flag_confidence: float = 0.0
        vuln_confirmation: Any = None

        if is_vuln_context and target:
            # ── Vuln mode: vulnerability confirmation ──
            from vulnagent.verification.flag_checker import VulnVerifier

            verifier = VulnVerifier()
            vuln_confirmation = verifier.confirm_from_state(state)

            if vuln_confirmation.confirmed:
                self.logger.log_verify(
                    "success",
                    flag=vuln_confirmation.summary(),
                )
                final = state.get("final_result") or vuln_confirmation.summary()
                confirmed_flag = True
            else:
                self.logger.log_verify("failure", flag=None)
                final = state.get("final_result") or ""
                if not final:
                    confirmed_findings = list(metadata.get("confirmed_findings", []))
                    validated_leads = list(metadata.get("validated_leads", []))
                    candidate_findings = list(metadata.get("candidate_findings", []))
                    if confirmed_findings or validated_leads:
                        final = (
                            f"Assessment complete. "
                            f"{len(confirmed_findings)} confirmed, "
                            f"{len(validated_leads)} validated, "
                            f"{len(candidate_findings)} candidate findings."
                        )
                    else:
                        final = "No vulnerabilities confirmed in this run."

            self._emit(AgentEvent.verify_completed(
                agent_name, vuln_confirmation.confirmed,
                flag=vuln_confirmation.summary(),
                confidence=vuln_confirmation.confidence,
            ))
        else:
            # ── CTF mode: flag extraction ──
            from vulnagent.verification.flag_checker import FlagExtractor

            extractor = FlagExtractor()
            flag_result = extractor.extract_from_state(state)

            execution_mode = metadata.get("execution_mode", "")

            if flag_result.found and flag_result.flag:
                self.logger.log_verify("success", flag=flag_result.flag)
                final = flag_result.flag
                confirmed_flag = True
            else:
                self.logger.log_verify("failure", flag=None)
                final = state.get("final_result") or ""
                if not final and execution_mode != "operator-directed":
                    final = "No flag found"

            flag_candidates = flag_result.candidates
            flag_confidence = flag_result.confidence

            self._emit(AgentEvent.verify_completed(
                agent_name, flag_result.found, flag=flag_result.flag or "",
                confidence=flag_result.confidence,
            ))

        # Update KG with findings from anchored summary
        anchored = state.get("anchored_summary", {})
        findings_text = anchored.get("findings", "")
        if self.kg and findings_text:
            try:
                self._update_kg_from_findings(findings_text, state)
            except Exception as e:
                self.logger.debug(f"KG update failed: {e}")  # KG update is non-critical

        self._emit(AgentEvent.node_exit(agent_name, "verify"))
        return {
            "final_result": final,
            "phase": phase,
            "flag_candidates": flag_candidates,
            "flag_confidence": flag_confidence,
        }

    def _deep_compact_node(self, state: AgentState) -> dict[str, Any]:
        """L3 Deep Compression: save session as memories, clear context, reload.

        This is the "chain" mechanism — when context grows too large:
        1. Compress the current session into MemoryEntry objects
        2. Save to HierarchicalMemory for future retrieval
        3. Update Knowledge Graph with discovered entities
        4. Clear messages (keep system prompt + anchored summary)
        5. Reset token budget
        6. Next step: retrieve_memory loads relevant context from persistent storage
        """
        agent_name = state.get("current_agent", self.__class__.__name__)
        self._emit(AgentEvent.node_enter(agent_name, "deep_compact"))
        self._emit(AgentEvent.compress_mid(agent_name, 0, 0, sections_populated=0))

        from vulnagent.context.compressor import DeepCompressor
        from langchain_core.messages import SystemMessage

        compaction = dict(state.get("compaction", {}))
        anchored = dict(state.get("anchored_summary", {}))
        messages = list(state.get("messages", []))

        # ── Save knowledge-type memories only (not session-specific details) ──
        # Knowledge memories: technique patterns, vulnerability types — reusable across sessions
        # Session details (specific URLs, specific tool outputs) saved only at final consolidation
        import time as _time
        from vulnagent.memory.hierarchical import MemoryEntry

        anchored = dict(state.get("anchored_summary", {}))
        findings = anchored.get("findings", "")
        decisions = anchored.get("decisions", "")
        tools_summary = anchored.get("tools", "")

        entries_saved = 0
        if self.memory:
            task_id = state.get("task_description", "unknown")[:100]

            # 1. Save technique/vulnerability knowledge (long_term, low weight)
            knowledge_text = f"FINDINGS: {findings}\nDECISIONS: {decisions}"
            if knowledge_text.strip() and len(knowledge_text) > 20:
                # Extract key patterns from findings
                import re
                techniques: list[str] = []
                for kw in ["SQL injection", "XSS", "CSRF", "LFI", "RFI", "command injection",
                           "buffer overflow", "format string", "SSTI", "deserialization",
                           "path traversal", "file inclusion", "SSRF", "XXE"]:
                    if kw.lower() in findings.lower():
                        techniques.append(kw)

                knowledge_tags = ["knowledge", "technique"] + techniques
                knowledge_entry = MemoryEntry(
                    content=knowledge_text[:3000],
                    layer="long_term",
                    timestamp=_time.time(),
                    ttl=None,  # permanent
                    weight=0.5,  # low weight — only retrieved when highly relevant
                    emotional_salience=0.3,
                    narrative=f"Techniques found: {', '.join(techniques) if techniques else 'patterns'}",
                    tags=knowledge_tags,
                    source_task_id=task_id,
                )
                self.memory.add_long_term(knowledge_entry)
                entries_saved += 1

            # 2. Save tools/approach summary (mid_term, moderate weight, with TTL)
            if tools_summary.strip() and len(tools_summary) > 20:
                tools_entry = MemoryEntry(
                    content=f"TOOLS: {tools_summary[:2000]}\nFINDINGS: {findings[:1000]}",
                    layer="mid_term",
                    timestamp=_time.time(),
                    ttl=86400 * 3,  # 3 days — session context expires
                    weight=0.8,
                    emotional_salience=0.2,
                    narrative="Tool execution summary",
                    tags=["session_summary", "tools", state.get("current_agent", "")],
                    source_task_id=task_id,
                )
                self.memory.add_mid_term(tools_entry)
                entries_saved += 1

            # 3. Update KG from findings (entity-level knowledge)
            if self.kg and findings:
                try:
                    self._update_kg_from_findings(findings, state)
                except Exception:
                    pass

        # ── Clear messages, keep system prompt + anchored summary ──
        system_msgs = [m for m in messages if "System" in type(m).__name__]
        keep_msgs: list[Any] = list(system_msgs)

        context_block = self._format_anchored_context(anchored) if anchored else ""
        if context_block:
            keep_msgs.append(SystemMessage(content=context_block))

        # Add a summary of what was saved
        keep_msgs.append(SystemMessage(
            content=f"[CONTEXT RESET] Saved {entries_saved} knowledge memories. "
                    f"Session context cleared. Reloading relevant knowledge..."
        ))

        # ── Reset token budget ──
        budget = dict(state.get("token_budget", {}))
        budget["used"] = sum(len(getattr(m, "content", "") or "") // 4 + 10 for m in keep_msgs) + 100

        compaction["compaction_count"] = compaction.get("compaction_count", 0) + 1
        compaction["deep_compaction_count"] = compaction.get("deep_compaction_count", 0) + 1
        # Preserve total iterations across deep compacts for hard stop
        compaction["total_iterations"] = compaction.get("total_iterations", 0) + state.get("iteration_count", 0)

        self.logger.info(
            f"L3 deep-compact: {len(messages)} msgs → {len(keep_msgs)} msgs, "
            f"saved {entries_saved} knowledge memories, budget reset to {budget['used']}, "
            f"total_iterations={compaction['total_iterations']}"
        )

        self._emit(AgentEvent.node_exit(agent_name, "deep_compact"))
        return {
            "messages": self._replace_messages(keep_msgs),
            "compaction": compaction,
            "token_budget": budget,
            "anchored_summary": anchored,
            "phase": "execution",
            "memory_context": {},  # clear — will be reloaded by retrieve_memory
            "iteration_count": 0,  # reset phase iteration, but total_iterations preserved in compaction
        }

    # ── Public API ─────────────────────────────────────────────────

    def invoke(self, state: AgentState) -> AgentState:
        """Run the agent synchronously on the given state."""
        graph = self.build_graph()
        prepared_state = self.preprocess_state(state)
        result = graph.invoke(prepared_state)
        return self.postprocess_result(result)

    def invoke_interactive(
        self,
        state: AgentState,
        on_interrupt: Callable[[AgentState, str, dict[str, Any]], str | None] | None = None,
        interrupt_points: list[str] | None = None,
    ) -> AgentState:
        """Run the agent with interactive intervention at configurable nodes.

        Supports multi-node interrupts, tool approval, and checkpoint rollback.

        Args:
            state: Initial AgentState.
            on_interrupt: Called at each pause with (current_state, node_name, context).
                context includes: 'iteration', 'interrupt_node', 'tool_name',
                'tool_args', 'risk_level', 'tokens_used', 'tokens_total'.
                Return a string to inject as guidance or special commands:
                  - "" → continue
                  - None → quit
                  - "/approve" → approve tool execution
                  - "/reject" → skip this tool
                  - "/rollback N" → rollback (handled by caller via graph.get_state)
                  - anything else → inject as HumanMessage
            interrupt_points: Nodes to pause before. None = DEFAULT_INTERRUPT_POINTS.

        Returns:
            The final AgentState after the graph completes or user quits.
        """
        points = interrupt_points if interrupt_points is not None else list(self.DEFAULT_INTERRUPT_POINTS)
        graph = self.build_graph(interrupt_points=points)
        thread_id = str(uuid.uuid4())
        config = {"configurable": {"thread_id": thread_id}}

        prepared_state = self.preprocess_state(state)
        result = graph.invoke(prepared_state, config)

        while True:
            state_info = graph.get_state(config)
            if not state_info.next:
                break

            # Determine which node we're paused before
            next_nodes = list(state_info.next) if state_info.next else []
            interrupt_node = next_nodes[0] if next_nodes else "unknown"

            iteration = result.get("iteration_count", 0) if result else 0
            budget = result.get("token_budget", {}) if result else {}

            # Build context for the callback
            context: dict[str, Any] = {
                "iteration": iteration,
                "interrupt_node": interrupt_node,
                "tokens_used": budget.get("used", 0),
                "tokens_total": budget.get("total", 100000),
            }

            # For tool execution node, extract tool details
            if interrupt_node == "execute_tools":
                msgs = result.get("messages", []) if result else []
                if msgs:
                    last_msg = msgs[-1]
                    tool_calls = getattr(last_msg, "tool_calls", None)
                    if tool_calls:
                        first_tc = tool_calls[0]
                        context["tool_name"] = first_tc.get("name", "") if isinstance(first_tc, dict) else getattr(first_tc, "name", "")
                        context["tool_args"] = first_tc.get("args", {}) if isinstance(first_tc, dict) else getattr(first_tc, "arguments", {})
                        # Check risk level
                        if self.tools and context["tool_name"] in self.tools:
                            tool_def = self.tools.get(context["tool_name"])
                            context["risk_level"] = getattr(tool_def, "risk_level", "moderate")

            user_input = ""
            if on_interrupt:
                user_input = on_interrupt(result, interrupt_node, context)
                if user_input is None:
                    return self.postprocess_result(result)

            # Handle approval flow for tools
            if interrupt_node == "execute_tools":
                if user_input == "/reject":
                    # Skip this tool call — inject error message
                    from langchain_core.messages import ToolMessage, AIMessage
                    tc = (result.get("messages", [])[-1].tool_calls if result.get("messages") else None)
                    if tc:
                        tc_dict = tc[0] if isinstance(tc, list) else tc
                        tc_id = tc_dict.get("id", "") if isinstance(tc_dict, dict) else getattr(tc_dict, "id", "")
                        tool_name = context.get("tool_name", "unknown")
                        graph.update_state(config, {
                            "messages": [ToolMessage(
                                content=f"Tool '{tool_name}' rejected by user",
                                tool_call_id=tc_id, name=tool_name,
                            )],
                        })
                        result = graph.invoke(Command(resume="continue"), config)
                        continue
                elif user_input == "/approve" or user_input == "":
                    pass  # proceed normally

            if user_input and user_input.strip() and user_input not in ("/approve", "/reject"):
                from langchain_core.messages import HumanMessage
                graph.update_state(config, {
                    "messages": [HumanMessage(content=user_input.strip())],
                })

            result = graph.invoke(Command(resume="continue"), config)

        return self.postprocess_result(result)

    async def stream(self, state: AgentState) -> AsyncIterator[dict[str, Any]]:
        """Run the agent with streaming output."""
        graph = self.build_graph()
        async for chunk in graph.astream(state):
            yield chunk

    # ── Event helpers ──────────────────────────────────────────────

    def _emit(self, event: AgentEvent) -> None:
        """Emit an event through the event bus if configured."""
        if self.event_emitter:
            self.event_emitter.emit(event)

    async def stream_events(
        self, state: AgentState, event_types: list[EventType] | None = None
    ) -> AsyncIterator[AgentEvent]:
        """Run the agent and stream lifecycle events.

        Usage:
            async for event in agent.stream_events(state):
                print(f"[{event.type.value}] {event.message}")
        """
        from vulnagent.events.emitter import EventEmitter

        # Use the agent's emitter or create a temporary one
        emitter = self.event_emitter or EventEmitter()
        original_emitter = self.event_emitter
        self.event_emitter = emitter

        try:
            # Run in a thread since graph.invoke is sync
            import asyncio
            loop = asyncio.get_event_loop()

            def _run() -> None:
                try:
                    self.invoke(state)
                except Exception as e:
                    emitter.emit(AgentEvent.agent_error(
                        self.__class__.__name__, str(e),
                    ))

            task = loop.run_in_executor(None, _run)

            async for event in emitter.stream(event_types):
                yield event

            await task
        finally:
            self.event_emitter = original_emitter

    # ── Helpers ────────────────────────────────────────────────────

    @staticmethod
    def _messages_to_dicts(messages: Sequence[Any]) -> list[dict[str, Any]]:
        """Convert LLM chain library message objects to provider-neutral dicts.

        Normalizes tool_calls to OpenAI standard format:
            {id, type: "function", function: {name, arguments}}

        Automatically strips orphaned tool_calls (without matching tool responses).
        """
        import json as _json

        # Build sets of valid tool_call_ids and valid tool messages
        # After compaction, some tool_calls or tool responses may be orphaned
        valid_tool_call_ids: set[str] = set()  # IDs that have BOTH a call and response
        pending_tool_calls: set[str] = set()
        for msg in messages:
            msg_type = type(msg).__name__
            if "AI" in msg_type or "Assistant" in msg_type:
                pending_tool_calls.clear()
                if hasattr(msg, "tool_calls") and msg.tool_calls:
                    for tc in msg.tool_calls:
                        tc_id = tc.get("id", "") if isinstance(tc, dict) else getattr(tc, "id", "")
                        if tc_id:
                            pending_tool_calls.add(tc_id)
            elif "Tool" in msg_type:
                tc_id = getattr(msg, "tool_call_id", "") if hasattr(msg, "tool_call_id") else ""
                if tc_id and tc_id in pending_tool_calls:
                    valid_tool_call_ids.add(tc_id)
            elif "Human" in msg_type or "System" in msg_type:
                pending_tool_calls.clear()

        result: list[dict[str, Any]] = []
        for msg in messages:
            msg_type = type(msg).__name__
            role = "assistant"
            if "System" in msg_type:
                role = "system"
            elif "Human" in msg_type:
                role = "user"
            elif "Tool" in msg_type:
                role = "tool"

            content = ""
            if hasattr(msg, "content"):
                content = msg.content or ""

            entry: dict[str, Any] = {"role": role, "content": content}

            if hasattr(msg, "tool_calls") and msg.tool_calls:
                normalized_tcs = []
                for tc in msg.tool_calls:
                    if isinstance(tc, dict):
                        tc_id = tc.get("id", "")
                    else:
                        tc_id = getattr(tc, "id", "")
                    # Skip orphaned tool calls — those without matching tool responses
                    if tc_id and valid_tool_call_ids and tc_id not in valid_tool_call_ids:
                        continue
                    if isinstance(tc, dict):
                        tc_name = tc.get("name", "") or tc.get("function", {}).get("name", "")
                        tc_args = tc.get("args", {}) or tc.get("function", {}).get("arguments", "{}")
                        if not isinstance(tc_args, str):
                            tc_args = _json.dumps(tc_args, ensure_ascii=False)
                        normalized_tcs.append({
                            "id": tc_id,
                            "type": "function",
                            "function": {"name": tc_name, "arguments": tc_args},
                        })
                    else:
                        tc_name = getattr(tc, "name", "")
                        tc_args = getattr(tc, "arguments", {}) or getattr(tc, "args", {})
                        if not isinstance(tc_args, str):
                            tc_args = _json.dumps(tc_args, ensure_ascii=False)
                        normalized_tcs.append({
                            "id": tc_id,
                            "type": "function",
                            "function": {"name": tc_name, "arguments": tc_args},
                        })
                if normalized_tcs:
                    entry["tool_calls"] = normalized_tcs

            if hasattr(msg, "tool_call_id"):
                entry["tool_call_id"] = msg.tool_call_id
                # DeepSeek compatibility: name is required for tool messages
                if hasattr(msg, "name") and msg.name:
                    entry["name"] = msg.name

            # Preserve reasoning_content for DeepSeek thinking mode
            extra_kwargs = getattr(msg, "additional_kwargs", None) or {}
            reasoning = extra_kwargs.get("reasoning_content", "")
            if reasoning:
                entry["reasoning_content"] = reasoning

            # Skip orphaned ToolMessages (no matching tool_calls → API error)
            if role == "tool":
                tc_id = entry.get("tool_call_id", "")
                if tc_id and valid_tool_call_ids and tc_id not in valid_tool_call_ids:
                    continue  # skip this orphaned tool message

            result.append(entry)
        return result

    @staticmethod
    def _format_anchored_context(anchored: dict[str, str]) -> str:
        """Render anchored summary sections as a compact context block."""
        sections = [
            "scope", "files", "tools", "decisions", "findings", "open", "next"
        ]
        parts: list[str] = ["[COMPACTED CONTEXT]"]
        for section in sections:
            content = anchored.get(section, "").strip()
            if content and content != "[EMPTY]":
                parts.append(f"[{section.upper()}] {content}")
            else:
                parts.append(f"[{section.upper()}] [EMPTY]")
        return "\n".join(parts)

    @staticmethod
    def _tool_output_key(existing: dict[str, str], tool_name: str, tool_args: Any) -> str:
        """Preserve repeated tool calls by deriving a stable unique key."""
        base_key = tool_name
        tool_args = BaseAgent._coerce_tool_args(tool_args)
        if isinstance(tool_args, dict):
            inner_path = str(tool_args.get("inner_path", "")).strip()
            if inner_path:
                base_key = f"{tool_name}:{inner_path}"
            elif tool_name == "firmware_search":
                pattern = str(tool_args.get("pattern", "")).strip()
                if pattern:
                    base_key = f"{tool_name}:{pattern}"
            elif tool_name in {"file_read"}:
                path = str(tool_args.get("path", "")).strip()
                if path:
                    base_key = f"{tool_name}:{path}"
        if base_key not in existing:
            return base_key
        index = 2
        while f"{base_key}#{index}" in existing:
            index += 1
        return f"{base_key}#{index}"

    @staticmethod
    def _normalize_tool_result_text(raw_result: Any) -> str:
        if raw_result is None:
            return ""
        stdout = getattr(raw_result, "stdout", None)
        stderr = getattr(raw_result, "stderr", None)
        return_code = getattr(raw_result, "return_code", None)
        if stdout is not None:
            text = str(stdout)
            if stderr:
                text = f"{text}\n[stderr]\n{stderr}"
            if return_code not in (None, 0):
                text = f"{text}\n[return_code]\n{return_code}"
            return text.strip()
        return str(raw_result)

    @staticmethod
    def _tool_call_succeeded(raw_text: str) -> bool:
        lowered = str(raw_text or "").lower().strip()
        if not lowered:
            return False
        if lowered.startswith("blocked "):
            return False
        if lowered.startswith("tool execution error:"):
            return False
        if "\n[return_code]\n" in lowered and not lowered.endswith("\n0"):
            return False
        return "error" not in lowered[:100]

    def _update_kg_from_findings(self, findings_text: str, state: AgentState) -> None:
        """Extract entities (services, CVEs, techniques) from findings and update KG.

        Also scans tool_outputs for additional entity sources.
        """
        if not self.kg:
            return

        import re
        from vulnagent.memory.kgraph import Entity

        # Combine all available text sources
        all_text = findings_text
        for output in state.get("compressed_outputs", {}).values():
            all_text += "\n" + str(output)[:4000]

        category = state.get("current_agent", "unknown")
        target_id = f"target:{category}"
        self.kg.add_entity(Entity(target_id, "target", {
            "task": state.get("task_description", "")[:200],
        }))

        # ── Extract CVEs ──
        cves_found: list[str] = []
        for cve in re.findall(r"CVE-\d{4}-\d{4,}", all_text, re.IGNORECASE):
            cve_upper = cve.upper()
            if cve_upper not in cves_found:
                cves_found.append(cve_upper)
                self.kg.add_entity(Entity(cve_upper, "vulnerability", {
                    "source": "tool_output",
                }))
                self.kg.add_relation(target_id, "has_vulnerability", cve_upper)

        # ── Extract services with versions ──
        service_patterns = [
            (r"(?:Server:\s*)?(apache)[/\s](\d+\.\d+(?:\.\d+)?)", "apache"),
            (r"(?:Server:\s*)?(nginx)[/\s](\d+\.\d+(?:\.\d+)?)", "nginx"),
            (r"(?:OpenSSH[_\s])?(\d+\.\d+[a-z]?\d*)", "openssh"),
            (r"(?:mysql)[/\s](\d+\.\d+(?:\.\d+)?)", "mysql"),
            (r"(?:PHP)[/\s](\d+\.\d+(?:\.\d+)?)", "php"),
            (r"(?:openssl)[/\s](\d+\.\d+(?:\.\d+)?[a-z]?)", "openssl"),
            (r"(\d+)/(tcp|udp)\s+open\s+(\w+)", None),  # nmap port format
        ]

        services_found: list[str] = []
        for line in all_text.split("\n"):
            for pattern, svc_name in service_patterns:
                match = re.search(pattern, line, re.IGNORECASE)
                if match:
                    if svc_name:
                        version = match.group(2) if len(match.groups()) >= 2 else match.group(1)
                        svc_id = f"service:{svc_name}/{version}"
                    else:
                        # nmap format: port/proto open service_name
                        port, proto, svc = match.groups()
                        svc_id = f"service:{svc}/{port}/{proto}"

                    if svc_id not in services_found:
                        services_found.append(svc_id)
                        self.kg.add_entity(Entity(svc_id, "service", {
                            "raw_line": line.strip()[:200],
                        }))
                        self.kg.add_relation(target_id, "exposes", svc_id)

        # ── Extract technique mentions ──
        technique_keywords = {
            "SQL injection": "technique:sql_injection",
            "command injection": "technique:command_injection",
            "XSS": "technique:xss",
            "LFI": "technique:lfi",
            "RFI": "technique:rfi",
            "CSRF": "technique:csrf",
            "buffer overflow": "technique:buffer_overflow",
            "format string": "technique:format_string",
            "directory traversal": "technique:directory_traversal",
            "privilege escalation": "technique:privilege_escalation",
            "deserialization": "technique:deserialization",
            "race condition": "technique:race_condition",
        }

        for technique_name, technique_id in technique_keywords.items():
            if technique_name.lower() in all_text.lower():
                self.kg.add_entity(Entity(technique_id, "technique", {
                    "name": technique_name,
                }))
                # Link techniques to services and CVEs
                for svc_id in services_found:
                    self.kg.add_relation(technique_id, "targets", svc_id)
                for cve_id in cves_found:
                    self.kg.add_relation(cve_id, "exploitable_by", technique_id)

        # ── Extract flag/payload entities ──
        for flag_match in re.finditer(r"flag\{([^}]+)\}", all_text, re.IGNORECASE):
            flag_content = flag_match.group(1)
            payload_id = f"payload:flag_{flag_content[:30]}"
            self.kg.add_entity(Entity(payload_id, "payload", {
                "full_flag": flag_match.group(0),
                "category": category,
            }))
            for svc_id in services_found:
                self.kg.add_relation(svc_id, "yields", payload_id)
