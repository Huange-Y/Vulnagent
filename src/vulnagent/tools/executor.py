"""Tool executor — safe subprocess execution with timeout and output capture."""

from __future__ import annotations

import shlex
import os
import subprocess
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Sequence

from vulnagent.core.state import AgentState


@dataclass
class ToolResult:
    """Result of a single tool execution."""

    tool_name: str
    command: str | Sequence[str]
    return_code: int
    stdout: str
    stderr: str
    duration_ms: float
    timed_out: bool = False


class ToolExecutor:
    """Execute shell commands with timeout, stdin, and env isolation.

    Safety:
    - Always uses shell=False to prevent command injection
    - Configurable timeout per execution (default 300s)
    - Optional working directory isolation

    Usage:
        executor = ToolExecutor(timeout_seconds=300)
        result = executor.execute("nmap -sV target -p 1-1000")
        print(result.stdout)
    """

    def __init__(
        self,
        timeout_seconds: int = 300,
        work_dir: str | None = None,
        constraint_engine: Any = None,
    ) -> None:
        self.timeout_seconds = timeout_seconds
        self.work_dir = work_dir
        self._constraint_engine = constraint_engine

    def execute(
        self,
        command: str | Sequence[str],
        stdin: str | None = None,
        env: dict[str, str] | None = None,
        timeout: int | None = None,
    ) -> ToolResult:
        """Execute a shell command and capture its output.

        Args:
            command: The full command string (will be split into args).
            stdin: Optional string to pipe to stdin.
            env: Optional environment variables to set.
            timeout: Override the default timeout.

        Returns:
            ToolResult with stdout, stderr, return_code, and timing.
        """
        timeout = timeout or self.timeout_seconds
        args = list(command) if not isinstance(command, str) else _split_command(command)
        tool_name = args[0] if args else "unknown"

        # ── Constraint engine: L1 command gate ──
        # From article: dangerous commands blocked at execution layer, not prompt layer
        if self._constraint_engine is not None:
            cmd_str = command if isinstance(command, str) else " ".join(command)
            enforcement = self._constraint_engine.check_command(cmd_str)
            if not enforcement.allowed:
                return ToolResult(
                    tool_name=tool_name,
                    command=command,
                    return_code=-1,
                    stdout="",
                    stderr=f"[CONSTRAINT ENGINE BLOCKED] {enforcement.reason}",
                    duration_ms=0.0,
                    timed_out=False,
                )

        start = time.perf_counter()
        timed_out = False

        try:
            proc = subprocess.run(
                args,
                shell=False,
                capture_output=True,
                text=True,
                input=stdin,
                env=env,
                cwd=self.work_dir,
                timeout=timeout,
            )
            duration_ms = (time.perf_counter() - start) * 1000

            return ToolResult(
                tool_name=tool_name,
                command=command,
                return_code=proc.returncode,
                stdout=proc.stdout or "",
                stderr=proc.stderr or "",
                duration_ms=duration_ms,
                timed_out=False,
            )
        except FileNotFoundError as e:
            duration_ms = (time.perf_counter() - start) * 1000
            return ToolResult(
                tool_name=tool_name,
                command=command,
                return_code=-1,
                stdout="",
                stderr=str(e),
                duration_ms=duration_ms,
                timed_out=False,
            )
        except subprocess.TimeoutExpired:
            duration_ms = (time.perf_counter() - start) * 1000
            timed_out = True
            return ToolResult(
                tool_name=tool_name,
                command=command,
                return_code=-1,
                stdout="",
                stderr=f"Command timed out after {timeout}s",
                duration_ms=duration_ms,
                timed_out=True,
            )

    async def execute_async(
        self,
        command: str | Sequence[str],
        stdin: str | None = None,
        env: dict[str, str] | None = None,
        timeout: int | None = None,
    ) -> ToolResult:
        """Async wrapper around execute()."""
        import asyncio

        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(
            None, lambda: self.execute(command, stdin, env, timeout)
        )


def create_tool_node(
    registry: Any,  # ToolRegistry
    compressor: Any,  # SecurityCompressor
) -> Callable[[AgentState], dict[str, Any]]:
    """Create a graph framework node that executes tool calls from the last message.

    This is the bridge between LLM reasoning and security tool execution.
    The node:
    1. Reads tool_calls from the last message in the state
    2. Looks up each tool in the registry
    3. Executes the tool via ToolExecutor
    4. Compresses the output via MicroCompressor
    5. Stores raw + compressed results in state

    Usage:
        builder.add_node("execute_tools", create_tool_node(registry, compressor))
    """

    def tool_node(state: AgentState) -> dict[str, Any]:
        messages = list(state.get("messages", []))
        if not messages:
            return {}

        last_msg = messages[-1]
        tool_calls = getattr(last_msg, "tool_calls", None)
        if not tool_calls:
            return {}

        executor = ToolExecutor()
        new_tool_outputs = dict(state.get("tool_outputs", {}))
        new_compressed = dict(state.get("compressed_outputs", {}))

        from langchain_core.messages import ToolMessage

        tool_messages: list[ToolMessage] = []

        for tc in tool_calls:
            # Support both dict and object tool calls
            if isinstance(tc, dict):
                tool_name = tc.get("name", "")
                tool_id = tc.get("id", "")
                args = tc.get("args", tc.get("arguments", {}))
            else:
                tool_name = getattr(tc, "name", "")
                tool_id = getattr(tc, "id", "")
                args = getattr(tc, "args", getattr(tc, "arguments", {}))

            if not tool_name:
                continue

            tool_def = registry.get(tool_name) if registry else None
            if tool_def is None:
                tool_messages.append(
                    ToolMessage(
                        content=f"Unknown tool: {tool_name}",
                        tool_call_id=tool_id,
                    )
                )
                continue

            try:
                result = tool_def.executor(args)
            except Exception as e:
                result = ToolResult(
                    tool_name=tool_name,
                    command=str(args),
                    return_code=-1,
                    stdout="",
                    stderr=str(e),
                    duration_ms=0,
                )

            new_tool_outputs[tool_name] = result.stdout

            # L1 Micro-compression
            if compressor:
                try:
                    compressed = compressor.compress(
                        result.stdout,
                        {"tool_name": tool_name, "max_tokens": 2000},
                    )
                except Exception:
                    compressed = result.stdout[:8000]  # fallback: raw truncation
            else:
                compressed = result.stdout[:8000]

            new_compressed[tool_name] = compressed

            content = (
                f"[{tool_name}]\n{compressed}\n"
                f"[return_code={result.return_code}, "
                f"duration={result.duration_ms:.0f}ms"
                f"{', TIMED OUT' if result.timed_out else ''}]"
            )
            tool_messages.append(
                ToolMessage(content=content, tool_call_id=tool_id)
            )

        return {
            "tool_outputs": {**new_tool_outputs},
            "compressed_outputs": {**new_compressed},
            "messages": tool_messages,
        }

    return tool_node


def _split_command(command: str) -> list[str]:
    if os.name != "nt":
        return shlex.split(command)

    try:
        import ctypes
        from ctypes import wintypes

        argc = ctypes.c_int()
        shell32 = ctypes.windll.shell32
        shell32.CommandLineToArgvW.restype = ctypes.POINTER(wintypes.LPWSTR)
        argv = shell32.CommandLineToArgvW(command, ctypes.byref(argc))
        if not argv:
            return shlex.split(command, posix=False)
        try:
            return [argv[i] for i in range(argc.value)]
        finally:
            ctypes.windll.kernel32.LocalFree(argv)
    except Exception:
        return shlex.split(command, posix=False)
