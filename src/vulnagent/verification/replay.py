"""L4: External PoC replayer — causal verification.

From article: "外部验证层自动重放 PoC"

Execution routing (priority order):
  1. Sandbox container (Docker) — full isolation
  2. ToolExecutor — constraint-gated subprocess
  3. Direct subprocess — bare-metal fallback (--no-sandbox mode)
"""

from __future__ import annotations

import shlex
import subprocess
from dataclasses import dataclass
from typing import Any


@dataclass
class ReplayResult:
    success: bool
    command: str = ""
    stdout: str = ""
    stderr: str = ""
    return_code: int = -1
    expected_output: str = ""
    output_matched: bool = False
    error: str = ""

    def as_dict(self) -> dict[str, object]:
        return {
            "success": self.success,
            "command": self.command,
            "return_code": self.return_code,
            "output_matched": self.output_matched,
            "stdout_preview": self.stdout[:500],
            "stderr_preview": self.stderr[:500],
            "error": self.error,
        }


class PoCReplayer:
    """Replay a PoC command and verify output.

    Routes execution through sandbox when available, falling back to
    direct subprocess only when no sandbox/executor is configured.
    From article: L4 is the final "现象→漏洞" step.
    """

    def __init__(
        self,
        timeout_seconds: int = 60,
        sandbox: Any = None,
        executor: Any = None,
    ) -> None:
        self._timeout = timeout_seconds
        self._sandbox = sandbox
        self._executor = executor

    def replay(self, poc: object) -> ReplayResult:
        if hasattr(poc, "executable_command"):
            cmd = getattr(poc, "executable_command", "")
            expected = getattr(poc, "expected_output", "")
        elif isinstance(poc, dict):
            cmd = str(poc.get("executable_command", ""))
            expected = str(poc.get("expected_output", ""))
        else:
            return ReplayResult(success=False, error="Invalid PoC type")

        if not cmd:
            return ReplayResult(success=False, error="No executable command in PoC")

        if self._is_dangerous(cmd):
            return ReplayResult(success=False, command=cmd, error="Blocked by replay safety filter")

        try:
            if self._sandbox is not None:
                return self._replay_via_sandbox(cmd, expected)
            if self._executor is not None:
                return self._replay_via_executor(cmd, expected)
            return self._replay_direct(cmd, expected)
        except subprocess.TimeoutExpired:
            return ReplayResult(success=False, command=cmd, error=f"Timed out after {self._timeout}s")
        except Exception as exc:
            return ReplayResult(success=False, command=cmd, error=str(exc))

    def _replay_via_sandbox(self, cmd: str, expected: str) -> ReplayResult:
        """Execute PoC inside the Docker sandbox container."""
        result = self._sandbox.execute(cmd, timeout=self._timeout)
        stdout = result.stdout or ""
        stderr = result.stderr or ""
        return_code = result.return_code
        output_matched = _check_expected(expected, stdout)
        success = return_code == 0 or output_matched
        return ReplayResult(
            success=success, command=cmd, stdout=stdout, stderr=stderr,
            return_code=return_code, expected_output=expected,
            output_matched=output_matched,
        )

    def _replay_via_executor(self, cmd: str, expected: str) -> ReplayResult:
        """Execute PoC via ToolExecutor with constraint engine gating."""
        argv = shlex.split(cmd)
        exec_result = self._executor.execute(argv, timeout=self._timeout)
        stdout = exec_result.stdout or ""
        stderr = exec_result.stderr or ""
        return_code = exec_result.return_code
        output_matched = _check_expected(expected, stdout)
        success = return_code == 0 or output_matched
        return ReplayResult(
            success=success, command=cmd, stdout=stdout, stderr=stderr,
            return_code=return_code, expected_output=expected,
            output_matched=output_matched,
        )

    def _replay_direct(self, cmd: str, expected: str) -> ReplayResult:
        """Fallback: execute directly via subprocess (no shell=True)."""
        argv = shlex.split(cmd)
        proc = subprocess.run(
            argv, capture_output=True, text=True, timeout=self._timeout,
        )
        stdout = proc.stdout or ""
        stderr = proc.stderr or ""
        return_code = proc.returncode
        output_matched = _check_expected(expected, stdout)
        success = return_code == 0 or output_matched
        return ReplayResult(
            success=success, command=cmd, stdout=stdout, stderr=stderr,
            return_code=return_code, expected_output=expected,
            output_matched=output_matched,
        )

    @staticmethod
    def _is_dangerous(cmd: str) -> bool:
        danger = [
            "rm -rf /", "mkfs.", "dd if=/dev/", "> /dev/sd",
            ":(){ :|:& };:", "chmod 777 /", "iptables -F",
        ]
        return any(dw.lower() in cmd.lower() for dw in danger)


def _check_expected(expected: str, stdout: str) -> bool:
    if not expected:
        return False
    return expected.lower() in stdout.lower()
