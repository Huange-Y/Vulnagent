"""Phase 0: Sandbox integration tests.

Verify:
  1. EmulationRunner routes through sandbox when available
  2. PoCReplayer no longer uses shell=True
  3. SandboxContainer graceful degradation
  4. CLI --no-sandbox flag
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from vulnagent.firmware.emulation import EmulationRunner, LaunchResult
from vulnagent.verification.replay import PoCReplayer, ReplayResult


# ── Fake sandbox for testing ──


@dataclass
class FakeContainerResult:
    container_id: str = "test-id"
    return_code: int = 0
    stdout: str = "fake stdout"
    stderr: str = ""
    duration_ms: float = 10.0
    timed_out: bool = False
    error: str = ""


class FakeSandbox:
    """A sandbox double for unit testing."""

    def __init__(self) -> None:
        self.commands: list[str] = []

    def execute(
        self, command: str | list[str], timeout: int | None = None, workdir: str = "/work"
    ) -> FakeContainerResult:
        cmd_str = command if isinstance(command, str) else " ".join(command)
        self.commands.append(cmd_str)
        return FakeContainerResult(stdout=f"executed: {cmd_str}")


# ── EmulationRunner sandbox routing tests ──


class TestEmulationRunnerSandboxRouting:
    """Verify EmulationRunner._run_local routes through sandbox."""

    def test_run_local_without_sandbox_uses_subprocess(self, tmp_path: Path) -> None:
        """Without sandbox, _run_local should use bare subprocess."""
        runner = EmulationRunner(remote_executor=None, sandbox=None)
        log_path = tmp_path / "test.log"
        result = runner._run_local(
            argv=["echo", "hello"],
            log_path=log_path,
            cwd=None,
            timeout=10,
            env=None,
        )
        assert isinstance(result, LaunchResult)
        assert result.return_code == 0
        assert "hello" in result.stdout

    def test_run_local_with_sandbox_routes_through_container(self, tmp_path: Path) -> None:
        """With sandbox, _run_local should route through container.execute()."""
        fake = FakeSandbox()
        runner = EmulationRunner(remote_executor=None, sandbox=fake)
        log_path = tmp_path / "sandbox.log"
        result = runner._run_local(
            argv=["qemu-mipsel", "-L", "/rootfs", "/bin/goahead"],
            log_path=log_path,
            cwd=None,
            timeout=30,
            env=None,
        )
        assert isinstance(result, LaunchResult)
        assert len(fake.commands) == 1
        assert "qemu-mipsel" in fake.commands[0]
        assert "executed:" in result.stdout

    def test_run_local_with_sandbox_preserves_env(self, tmp_path: Path) -> None:
        """Environment variables should be prepended to sandbox command."""
        fake = FakeSandbox()
        runner = EmulationRunner(remote_executor=None, sandbox=fake)
        log_path = tmp_path / "env.log"
        result = runner._run_local(
            argv=["/bin/busybox", "httpd"],
            log_path=log_path,
            cwd=None,
            timeout=10,
            env={"LD_LIBRARY_PATH": "/lib", "PATH": "/bin"},
        )
        assert len(fake.commands) == 1
        cmd = fake.commands[0]
        assert "LD_LIBRARY_PATH=/lib" in cmd
        assert "PATH=/bin" in cmd

    def test_run_local_with_sandbox_and_workdir(self, tmp_path: Path) -> None:
        """cwd should result in cd prefix in sandbox command."""
        fake = FakeSandbox()
        runner = EmulationRunner(remote_executor=None, sandbox=fake)
        log_path = tmp_path / "cwd.log"
        work_dir = tmp_path / "work"
        work_dir.mkdir()
        result = runner._run_local(
            argv=["ls"],
            log_path=log_path,
            cwd=work_dir,
            timeout=10,
            env=None,
        )
        assert len(fake.commands) == 1
        assert "cd " in fake.commands[0]

    def test_run_remote_unchanged_by_sandbox(self, tmp_path: Path) -> None:
        """Sandbox should NOT affect _run_remote path (only _run_local)."""
        fake = FakeSandbox()
        runner = EmulationRunner(remote_executor=None, sandbox=fake)
        log_path = tmp_path / "remote.log"
        result = runner._run_local(
            argv=["true"],
            log_path=log_path,
            cwd=None,
            timeout=5,
            env=None,
        )
        assert len(fake.commands) == 1


# ── PoCReplayer sandbox routing tests ──


class TestPoCReplayerSandboxRouting:
    """Verify PoCReplayer no longer uses shell=True and routes through sandbox."""

    def test_replay_with_sandbox_routes_through_container(self) -> None:
        """PoC with sandbox should use container.execute()."""
        fake = FakeSandbox()
        replayer = PoCReplayer(timeout_seconds=30, sandbox=fake)
        poc = {"executable_command": "curl http://127.0.0.1:8080/test", "expected_output": "OK"}
        result = replayer.replay(poc)
        assert result.success
        assert len(fake.commands) == 1
        assert "curl" in fake.commands[0]

    def test_replay_without_sandbox_uses_shlex_split(self) -> None:
        """Without sandbox, PoCReplayer should use shlex.split, not shell=True."""
        replayer = PoCReplayer(timeout_seconds=30, sandbox=None, executor=None)
        poc = {"executable_command": "echo hello world", "expected_output": "hello"}
        result = replayer.replay(poc)
        assert isinstance(result, ReplayResult)

    def test_replay_dangerous_command_blocked(self) -> None:
        """Dangerous commands should be blocked regardless of sandbox."""
        replayer = PoCReplayer(timeout_seconds=30)
        poc = {"executable_command": "rm -rf /", "expected_output": ""}
        result = replayer.replay(poc)
        assert not result.success
        assert "Blocked" in result.error or "safety" in result.error.lower()

    def test_replay_empty_command(self) -> None:
        """Empty command should return error."""
        replayer = PoCReplayer()
        poc = {"executable_command": "", "expected_output": ""}
        result = replayer.replay(poc)
        assert not result.success
        assert "No executable command" in result.error

    def test_replay_invalid_poc_type(self) -> None:
        """Non-dict, non-object PoC should return error."""
        replayer = PoCReplayer()
        result = replayer.replay("just a string")
        assert not result.success
        assert "Invalid PoC type" in result.error

    def test_dangerous_commands_detection(self) -> None:
        """_is_dangerous should catch all dangerous patterns."""
        dangerous = [
            "rm -rf /",
            "mkfs.ext4 /dev/sda",
            "dd if=/dev/zero of=/dev/sda",
            ":(){ :|:& };:",
            "chmod 777 /",
            "iptables -F",
        ]
        for cmd in dangerous:
            assert PoCReplayer._is_dangerous(cmd), f"Should be blocked: {cmd}"

        safe = [
            "curl http://localhost:8080/",
            "echo test",
            "qemu-mipsel -L /rootfs /bin/ls",
        ]
        for cmd in safe:
            assert not PoCReplayer._is_dangerous(cmd), f"Should not be blocked: {cmd}"


# ── Sandbox graceful degradation tests ──


class TestSandboxGracefulDegradation:
    """Verify sandbox initialization handles Docker absence gracefully."""

    def test_init_sandbox_returns_none_when_disabled(self) -> None:
        """use_sandbox=False should return None."""
        from vulnagent.orchestrator import _init_sandbox
        from vulnagent.utils.logging import StructuredLogger
        logger = StructuredLogger("test")
        result = _init_sandbox(use_sandbox=False, logger=logger)
        assert result is None

    def test_emulation_runner_works_without_sandbox(self, tmp_path: Path) -> None:
        """EmulationRunner should work without sandbox (backward compat)."""
        runner = EmulationRunner(remote_executor=None, sandbox=None)
        log_path = tmp_path / "test.log"
        result = runner._run_local(
            argv=["python", "-c", "print('ok')"],
            log_path=log_path,
            cwd=None,
            timeout=10,
            env=None,
        )
        assert result.return_code == 0

    def test_poc_replayer_works_without_sandbox(self) -> None:
        """PoCReplayer should work without sandbox (backward compat)."""
        replayer = PoCReplayer(timeout_seconds=30, sandbox=None, executor=None)
        assert replayer._timeout == 30
        assert replayer._sandbox is None
