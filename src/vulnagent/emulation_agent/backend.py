"""Validation backends — pluggable firmware verification for vulnagent.

Three backends, one Protocol:
  EmulationAgentBackend — remote Emulation Agent on Ubuntu VM (auto-discover)
  DirectHardwareBackend — real device (no rootfs upload needed)
  StaticOnlyBackend — no backend, static analysis only
"""
from __future__ import annotations

import socket
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol


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
    def status_label(self) -> str: return "VERIFIED" if self.verified else "STATIC_ONLY"


@dataclass
class ValidationReport:
    rootfs_id: str = ""; backend_used: str = "none"
    arch: str = "unknown"; endian: str = "unknown"
    services: list[VerificationResult] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    @property
    def verified_count(self) -> int: return sum(1 for s in self.services if s.verified)


class FirmwareValidationBackend(Protocol):
    def is_available(self) -> bool: ...
    def upload_rootfs(self, rootfs_path: Path) -> str: ...
    def validate_services(self, rootfs_id: str, services: list[ServiceToVerify]) -> list[VerificationResult]: ...
    def cleanup(self, rootfs_id: str) -> None: ...
    def set_nvram_config(self, rootfs_id: str, config: dict[str, str]) -> None: ...


# ── Emulation Agent ────────────────────────────────────────────────

@dataclass
class EmulationAgentBackend:
    agent_host: str = "your-vm-ip"; agent_port: int = 9100
    ssh_tunnel: bool = True
    ssh_host: str = "your-vm-host"; ssh_port: int = 22
    ssh_user: str = "your-user"; ssh_key: str = "~/.ssh/id_ed25519"
    _client: Any = None; _tunnel: Any = None; _available: bool = False

    def is_available(self) -> bool:
        if self._available: return True
        from vulnagent.emulation_agent.client import EmulationAgentClient, start_ssh_tunnel

        # 1. Try direct LAN connection to Ubuntu VM
        c = EmulationAgentClient(base_url=f"http://{self.agent_host}:{self.agent_port}")
        if c.is_reachable:
            self._client = c; self._available = True; return True

        # 2. Try SSH tunnel via forwarded port 2222
        if self.ssh_tunnel:
            self._tunnel = start_ssh_tunnel(
                remote_host=f"{self.ssh_user}@{self.ssh_host}",
                remote_port=self.ssh_port, ssh_key=self.ssh_key)
            if self._tunnel:
                time.sleep(1.5)
                c2 = EmulationAgentClient(base_url="http://127.0.0.1:9100")
                if c2.is_reachable:
                    self._client = c2; self._available = True; return True
                self._tunnel.terminate(); self._tunnel = None
        return False

    def upload_rootfs(self, path: Path) -> str:
        if not self._client: raise RuntimeError("unavailable")
        return self._client.upload_rootfs(path)

    def set_nvram_config(self, rid: str, cfg: dict[str, str]) -> None:
        if self._client:
            try: self._client.set_nvram_config(rid, cfg)
            except Exception: pass

    def validate_services(self, rid: str, svcs: list[ServiceToVerify]) -> list[VerificationResult]:
        if not self._client: raise RuntimeError("unavailable")
        from vulnagent.emulation_agent.client import ServiceSpec
        results = []
        for s in svcs:
            r = VerificationResult(service_name=s.binary_name, port=s.port, backend="emu_agent")
            try:
                start = self._client.start_service(rid, ServiceSpec(
                    binary_name=s.binary_name, binary_path=s.binary_path,
                    args=s.launch_args, port=s.port))
                if start.get("status") not in ("running","starting"):
                    r.error = f"start:{start.get('status')}"; results.append(r); continue
                p = self._client.probe(s.port, s.protocol)
                r.probe_data = p
                if p.get("reachable"):
                    r.verified = True
                    r.evidence = f"{s.protocol}:{s.port} reachable"
                    if p.get("http_status"): r.evidence += f" HTTP:{p['http_status']}"
                    if p.get("telnet_banner"): r.evidence += f" banner:{p['telnet_banner'][:20]}"
                self._client.stop_service(start.get("service_id",""))
            except Exception as e: r.error = str(e)[:120]
            results.append(r)
        return results

    def cleanup(self, rid: str) -> None:
        if self._tunnel:
            try: self._tunnel.terminate()
            except Exception: pass


# ── Direct Hardware ─────────────────────────────────────────────────

@dataclass
class DirectHardwareBackend:
    target_host: str = ""

    def is_available(self) -> bool:
        if not self.target_host: return False
        try:
            s = socket.socket(); s.settimeout(3)
            s.connect((self.target_host, 80)); s.close(); return True
        except Exception: return False

    def upload_rootfs(self, path: Path) -> str: return "direct_hardware"
    def set_nvram_config(self, rid: str, cfg: dict[str, str]) -> None: pass

    def validate_services(self, rid: str, svcs: list[ServiceToVerify]) -> list[VerificationResult]:
        results = []
        for s in svcs:
            r = VerificationResult(service_name=s.binary_name, port=s.port, backend="direct_hw")
            try:
                sk = socket.socket(); sk.settimeout(3)
                sk.connect((self.target_host, s.port)); sk.close()
                r.verified = True
                r.evidence = f"Connected to {self.target_host}:{s.port}"
            except Exception as e: r.error = str(e)
            results.append(r)
        return results

    def cleanup(self, rid: str) -> None: pass


# ── Static Only ─────────────────────────────────────────────────────

class StaticOnlyBackend:
    def is_available(self) -> bool: return True
    def upload_rootfs(self, path: Path) -> str: return "static"
    def set_nvram_config(self, rid: str, cfg: dict[str, str]) -> None: pass
    def validate_services(self, rid: str, svcs: list[ServiceToVerify]) -> list[VerificationResult]:
        return [VerificationResult(service_name=s.binary_name, port=s.port, backend="static",
            error="No network validation backend available") for s in svcs]
    def cleanup(self, rid: str) -> None: pass


# ── Factory ─────────────────────────────────────────────────────────

def create_validation_backend(
    emulation_config: dict[str, Any] | None = None,
    direct_target: str = "",
) -> tuple[FirmwareValidationBackend, str]:
    """Auto-select the best available validation backend.

    Returns (backend, mode_label) where mode_label is one of:
      "emulation_agent" / "direct_hardware" / "static_only"
    """
    # Direct hardware mode: target looks like IP or URL
    if direct_target:
        host = direct_target
        for prefix in ("http://","https://","tcp://","telnet://"):
            if host.startswith(prefix): host = host[len(prefix):]
        host = host.split("/")[0].split(":")[0]
        if _looks_like_host(host):
            be = DirectHardwareBackend(target_host=host)
            return be, f"direct_hardware@{host}"

    # Emulation Agent mode: try auto-discovery
    if emulation_config:
        be = EmulationAgentBackend(
            agent_host=emulation_config.get("agent_host","your-vm-ip"),
            agent_port=int(emulation_config.get("agent_port",9100)),
            ssh_tunnel=bool(emulation_config.get("ssh_tunnel",True)),
            ssh_host=emulation_config.get("ssh_host","localhost"),
            ssh_port=int(emulation_config.get("ssh_port",2222)),
            ssh_user=emulation_config.get("ssh_user","art"),
            ssh_key=emulation_config.get("ssh_key","~/.ssh/id_ed25519"),
        )
        if be.is_available():
            return be, f"emulation_agent@{be.agent_host}:{be.agent_port}"

    return StaticOnlyBackend(), "static_only"


def _looks_like_host(s: str) -> bool:
    import re
    return bool(re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$",s)
        or re.match(r"^[a-zA-Z0-9]([a-zA-Z0-9-]*\.)+[a-zA-Z]{2,}$",s))
