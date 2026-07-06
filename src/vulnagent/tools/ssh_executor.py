"""SSH remote executor for running commands on a Linux server.

Enables Pwn/Rev agents to execute binary analysis tools (gdb, pwntools, checksec)
on a remote Linux environment when running from Windows.
"""

from __future__ import annotations

import os
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from vulnagent.tools.executor import ToolResult


@dataclass
class RemoteConfig:
    """SSH connection configuration."""
    enabled: bool = False
    host: str = ""
    port: int = 22
    username: str = ""
    key_path: str = ""
    password: str = ""
    work_dir: str = "/tmp/ctf"
    tool_paths: dict[str, str] | None = None

    @classmethod
    def from_settings(cls, settings: dict[str, Any]) -> "RemoteConfig":
        """Create config from settings dict."""
        remote = settings.get("remote", {})
        if not remote:
            return cls()

        password = ""
        password_env = remote.get("password_env", "")
        if password_env:
            password = os.environ.get(password_env, "")

        return cls(
            enabled=remote.get("enabled", False),
            host=remote.get("host", ""),
            port=remote.get("port", 22),
            username=remote.get("username", ""),
            key_path=remote.get("key_path", ""),
            password=password,
            work_dir=remote.get("work_dir", "/tmp/ctf"),
            tool_paths=remote.get("tool_paths", {}),
        )

    def is_ready(self) -> bool:
        """Check if remote config is valid and ready to use."""
        if not self.enabled:
            return False
        if not self.host or not self.username:
            return False
        if not self.key_path and not self.password:
            return False
        return True


class SSHExecutor:
    """Execute commands on a remote Linux server via SSH."""

    def __init__(self, config: RemoteConfig) -> None:
        self.config = config
        self._client = None
        self._sftp = None

    def _ensure_connection(self) -> None:
        """Establish SSH connection if not already connected."""
        if self._client is not None:
            return

        try:
            import paramiko
        except ImportError:
            raise ImportError(
                "paramiko is required for SSH remote execution. "
                "Install with: pip install paramiko"
            )

        self._client = paramiko.SSHClient()
        self._client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        connect_kwargs: dict[str, object] = {
            "hostname": self.config.host,
            "port": self.config.port,
            "username": self.config.username,
            "timeout": 5,
            "banner_timeout": 5,
            "auth_timeout": 5,
        }

        if self.config.key_path:
            key_path = os.path.expanduser(self.config.key_path)
            connect_kwargs["key_filename"] = key_path
        elif self.config.password:
            connect_kwargs["password"] = self.config.password

        try:
            self._client.connect(**connect_kwargs)
        except Exception as exc:
            raise ConnectionError(f"SSH to {self.config.host}:{self.config.port} failed: {exc}") from exc
        self._sftp = self._client.open_sftp()

        # Ensure work directory exists
        self._exec_simple(f"mkdir -p {self.config.work_dir}")

    def _exec_simple(self, command: str) -> tuple[str, str, int]:
        """Execute a simple command and return stdout, stderr, exit code."""
        stdin, stdout, stderr = self._client.exec_command(command)
        exit_code = stdout.channel.recv_exit_status()
        return stdout.read().decode(), stderr.read().decode(), exit_code

    def execute(self, command: str | list[str], timeout: int = 300) -> ToolResult:
        """Execute a command on the remote server."""
        start = time.perf_counter()

        try:
            self._ensure_connection()
        except Exception as e:
            return ToolResult(
                tool_name="ssh_exec",
                command=str(command),
                return_code=-1,
                stdout="",
                stderr=f"SSH connection failed: {e}",
                duration_ms=0,
            )

        if isinstance(command, list):
            cmd_str = " ".join(command)
        else:
            cmd_str = command

        # Resolve tool paths if configured
        if self.config.tool_paths:
            for tool, path in self.config.tool_paths.items():
                if path and cmd_str.startswith(tool):
                    cmd_str = cmd_str.replace(tool, path, 1)

        # Execute in work directory
        full_cmd = f"cd {self.config.work_dir} && {cmd_str}"

        try:
            stdin, stdout, stderr = self._client.exec_command(
                full_cmd, timeout=timeout
            )
            exit_code = stdout.channel.recv_exit_status()
            stdout_text = stdout.read().decode(errors="replace")
            stderr_text = stderr.read().decode(errors="replace")
            duration = (time.perf_counter() - start) * 1000

            return ToolResult(
                tool_name="ssh_exec",
                command=cmd_str,
                return_code=exit_code,
                stdout=stdout_text,
                stderr=stderr_text,
                duration_ms=duration,
            )
        except Exception as e:
            duration = (time.perf_counter() - start) * 1000
            return ToolResult(
                tool_name="ssh_exec",
                command=cmd_str,
                return_code=-1,
                stdout="",
                stderr=f"SSH execution failed: {e}",
                duration_ms=duration,
            )

    def upload_file(self, local_path: str, remote_name: str = "") -> str:
        """Upload a file to the remote work directory.

        Returns the remote path.
        """
        self._ensure_connection()

        local = Path(local_path)
        if not local.exists():
            raise FileNotFoundError(f"Local file not found: {local_path}")

        remote_name = remote_name or local.name
        remote_path = f"{self.config.work_dir}/{remote_name}"

        self._sftp.put(str(local), remote_path)
        # Make executable if it's a binary
        self._exec_simple(f"chmod +x {remote_path}")

        return remote_path

    def download_file(self, remote_path: str, local_path: str) -> None:
        """Download a file from the remote server."""
        self._ensure_connection()
        self._sftp.get(remote_path, local_path)

    def _get_sftp(self):
        """Get the SFTP client, ensuring connection is established first."""
        self._ensure_connection()
        return self._sftp

    def close(self) -> None:
        """Close SSH connection."""
        if self._sftp:
            self._sftp.close()
            self._sftp = None
        if self._client:
            self._client.close()
            self._client = None


# Global executor instance
_executor: SSHExecutor | None = None
_config: RemoteConfig | None = None


def get_remote_executor() -> SSHExecutor | None:
    """Get the global SSH executor if configured."""
    global _executor, _config
    if _config is None or not _config.is_ready():
        return None
    if _executor is None:
        _executor = SSHExecutor(_config)
    return _executor


def configure_remote(config: RemoteConfig) -> None:
    """Configure the global SSH executor."""
    global _executor, _config
    if _executor:
        _executor.close()
        _executor = None
    _config = config


def is_remote_available() -> bool:
    """Check if remote execution is available."""
    return _config is not None and _config.is_ready()


def remote_execute(command: str | list[str], timeout: int = 300) -> ToolResult:
    """Execute a command on the remote server if available.

    Falls back to local execution if remote is not configured.
    """
    executor = get_remote_executor()
    if executor:
        return executor.execute(command, timeout)

    # Fallback to local
    from vulnagent.tools.executor import ToolExecutor
    local_executor = ToolExecutor(timeout_seconds=timeout)
    return local_executor.execute(command)


def remote_upload(local_path: str, remote_name: str = "") -> str | None:
    """Upload a file to the remote server.

    Returns remote path, or None if remote is not available.
    """
    executor = get_remote_executor()
    if executor:
        return executor.upload_file(local_path, remote_name)
    return None
