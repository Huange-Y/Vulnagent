"""Validation backends — 4 connection modes, auto-detected at init.

SameMachine  — emu-agent as local subprocess (same host, no network needed)
SameNetwork  — direct HTTP to emu-agent on another host (same LAN)
SshTunnel    — SSH tunnel to emu-agent on remote VM (cross-network)
StaticOnly   — no backend, static analysis only

create_validation_backend() probes modes in priority order.
"""
from __future__ import annotations

import os
import platform
import socket
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol

_IS_WINDOWS = platform.system() == "Windows"


@dataclass(frozen=True)
class ServiceToVerify:
    binary_name: str; binary_path: str; launch_args: str = ""
    port: int = 0; protocol: str = "tcp"


@dataclass
class VerificationResult:
    service_name: str = ""; port: int = 0
    verified: bool = False; backend: str = ""
    evidence: str = ""; error: str = ""
    probe_data: dict[str, Any] = field(default_factory=dict)

    @property
    def status_label(self) -> str:
        return "VERIFIED" if self.verified else "STATIC_ONLY"


@dataclass
class ValidationReport:
    rootfs_id: str = ""; backend_used: str = "none"
    arch: str = "unknown"; endian: str = "unknown"
    services: list[VerificationResult] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @property
    def verified_count(self) -> int:
        return sum(1 for s in self.services if s.verified)


class FirmwareValidationBackend(Protocol):
    def is_available(self) -> bool: ...
    def upload_rootfs(self, rootfs_path: Path) -> str: ...
    def validate_services(self, rootfs_id: str, services: list[ServiceToVerify]) -> list[VerificationResult]: ...
    def cleanup(self, rootfs_id: str) -> None: ...
    def set_nvram_config(self, rootfs_id: str, config: dict[str, str]) -> None: ...


# ── SameMachine: local subprocess ─────────────────────────────────

@dataclass
class SameMachineBackend:
    """Run emu-agent as a local subprocess via uvicorn. Same host, zero network."""

    agent_port: int = 9100
    _proc: subprocess.Popen | None = None
    _client: Any = None

    def is_available(self) -> bool:
        try:
            import uvicorn  # noqa: F401
        except ImportError:
            return False
        return True

    def _start_server(self) -> bool:
        if self._proc is not None and self._proc.poll() is None:
            return True
        cmd = [
            "python" if _IS_WINDOWS else "python3",
            "-m", "uvicorn", "vulnagent.emulation_agent.server:app",
            "--host", "127.0.0.1", "--port", str(self.agent_port),
        ]
        try:
            self._proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            time.sleep(2)
            from vulnagent.emulation_agent.client import EmulationAgentClient
            self._client = EmulationAgentClient(base_url=f"http://127.0.0.1:{self.agent_port}")
            if self._client.is_reachable:
                return True
        except Exception:
            pass
        return False

    def upload_rootfs(self, p: Path) -> str:
        if self._client is None and not self._start_server():
            raise RuntimeError("local emu-agent failed to start")
        return self._client.upload_rootfs(p)

    def validate_services(self, rid, svcs):
        if self._client is None and not self._start_server():
            return []
        return self._client.validate_services(rid, svcs)

    def set_nvram_config(self, rid, cfg):
        if self._client is None and not self._start_server():
            return
        self._client.set_nvram_config(rid, cfg)

    def cleanup(self, rid):
        if self._client:
            try: self._client.delete_rootfs(rid)
            except Exception: pass


# ── SameNetwork: direct HTTP ──────────────────────────────────────

@dataclass
class SameNetworkBackend:
    """Direct HTTP to emu-agent on another host in the same LAN."""

    agent_host: str = ""; agent_port: int = 9100
    _client: Any = None

    def is_available(self) -> bool:
        if not self.agent_host:
            return False
        try:
            s = socket.socket(); s.settimeout(3)
            s.connect((self.agent_host, self.agent_port)); s.close()
        except Exception:
            return False
        from vulnagent.emulation_agent.client import EmulationAgentClient
        c = EmulationAgentClient(base_url=f"http://{self.agent_host}:{self.agent_port}")
        if c.is_reachable:
            self._client = c; return True
        return False

    def _ensure(self):
        if self._client is None:
            raise RuntimeError(f"emu-agent not reachable at {self.agent_host}:{self.agent_port}")
        return self._client

    def upload_rootfs(self, p): return self._ensure().upload_rootfs(p)
    def validate_services(self, r, s): return self._ensure().validate_services(r, s)
    def set_nvram_config(self, r, c): self._ensure().set_nvram_config(r, c)
    def cleanup(self, r):
        try: self._ensure().delete_rootfs(r)
        except Exception: pass


# ── SshTunnel: SSH forwarded port ─────────────────────────────────

@dataclass
class SshTunnelBackend:
    """SSH tunnel to emu-agent on a remote VM (cross-network)."""

    ssh_host: str = ""; ssh_port: int = 22
    ssh_user: str = ""; ssh_key: str = ""
    agent_port: int = 9100; local_forward_port: int = 9100
    _tunnel: Any = None; _client: Any = None

    def is_available(self) -> bool:
        if not self.ssh_host or not self.ssh_user:
            return False
        from vulnagent.emulation_agent.client import EmulationAgentClient, start_ssh_tunnel
        self._tunnel = start_ssh_tunnel(
            remote_host=f"{self.ssh_user}@{self.ssh_host}",
            remote_port=self.ssh_port, ssh_key=self.ssh_key,
            local_port=self.local_forward_port, remote_local_port=self.agent_port,
        )
        if self._tunnel is None:
            return False
        time.sleep(2)
        c = EmulationAgentClient(base_url=f"http://127.0.0.1:{self.local_forward_port}")
        if c.is_reachable:
            self._client = c; return True
        self._tunnel.terminate(); self._tunnel = None
        return False

    def _ensure(self):
        if self._client is None:
            raise RuntimeError("SSH tunnel not established")
        return self._client

    def upload_rootfs(self, p): return self._ensure().upload_rootfs(p)
    def validate_services(self, r, s): return self._ensure().validate_services(r, s)
    def set_nvram_config(self, r, c): self._ensure().set_nvram_config(r, c)
    def cleanup(self, r):
        try: self._ensure().delete_rootfs(r)
        except Exception: pass
        if self._tunnel: self._tunnel.terminate()


# ── StaticOnly ────────────────────────────────────────────────────

class StaticOnlyBackend:
    def is_available(self) -> bool: return True
    def upload_rootfs(self, p): return ""
    def validate_services(self, r, s): return [VerificationResult(error="static-only mode")]
    def set_nvram_config(self, r, c): pass
    def cleanup(self, r): pass


# ── Factory ───────────────────────────────────────────────────────

def create_validation_backend(
    emulation_config: dict[str, Any] | None = None,
    logger: Any = None,
) -> tuple[FirmwareValidationBackend, str]:
    """Auto-detect best backend. Priority: SameMachine → SameNetwork → SshTunnel → StaticOnly."""
    cfg = dict(emulation_config or {})
    enabled = cfg.get("enabled", True)

    def _log(msg):
        if logger: logger.info(msg)

    if not enabled:
        return StaticOnlyBackend(), "static_only (disabled)"

    # 1. Same machine
    local = SameMachineBackend(agent_port=int(cfg.get("agent_port", 9100)))
    if local.is_available():
        _log("backend: same-machine (local subprocess)")
        return local, "same_machine"

    # 2. Same network
    host = str(cfg.get("agent_host", ""))
    if host:
        net = SameNetworkBackend(agent_host=host, agent_port=int(cfg.get("agent_port", 9100)))
        if net.is_available():
            _log(f"backend: same-network ({host})")
            return net, "same_network"

    # 3. SSH tunnel
    sh = str(cfg.get("ssh_host", ""))
    if sh:
        tun = SshTunnelBackend(
            ssh_host=sh, ssh_port=int(cfg.get("ssh_port", 22)),
            ssh_user=str(cfg.get("ssh_user", "")),
            ssh_key=str(cfg.get("ssh_key", os.path.expanduser("~/.ssh/id_ed25519"))),
            agent_port=int(cfg.get("agent_port", 9100)),
        )
        if tun.is_available():
            _log(f"backend: ssh-tunnel ({cfg.get('ssh_user','')}@{sh})")
            return tun, "ssh_tunnel"

    _log("backend: static-only (no backend reachable)")
    return StaticOnlyBackend(), "static_only"
