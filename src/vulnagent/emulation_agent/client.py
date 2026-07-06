"""Client for Emulation Agent — vulnagent talks to remote firmware emulation.

Connects to the Emulation Agent server (Ubuntu VM, port 9100) via SSH tunnel.
Provides: upload_rootfs, start_service, probe, exec, nvram_config.
"""
from __future__ import annotations

import json, subprocess, urllib.error, urllib.parse, urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class ServiceSpec:
    binary_name: str; binary_path: str; args: str = ""; port: int = 0


@dataclass
class EmulationStatus:
    rootfs_id: str = ""; architecture: str = "unknown"; endianness: str = "unknown"
    services: list[dict[str, Any]] = field(default_factory=list)
    ports_live: list[int] = field(default_factory=list); error: str = ""


class EmulationAgentClient:
    """HTTP client for the Emulation Agent (FastAPI on Ubuntu VM)."""

    def __init__(self, base_url: str = "http://127.0.0.1:9100") -> None:
        self._base = base_url.rstrip("/")

    @property
    def is_reachable(self) -> bool:
        try: self._get("/api/health"); return True
        except Exception: return False

    # ── RootFS ──

    def upload_rootfs(self, rootfs_path: Path) -> str:
        """Tar+upload rootfs directory. Returns rootfs_id."""
        import tempfile, tarfile
        tb = Path(tempfile.mktemp(suffix=".tar.gz"))
        try:
            with tarfile.open(tb, "w:gz") as tf: tf.add(rootfs_path, arcname=".")
            data = tb.read_bytes()
        finally: tb.unlink(missing_ok=True)
        boundary = "----EmuUpload"
        body = (f"--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"r.tar.gz\"\r\nContent-Type: application/gzip\r\n\r\n").encode()+data+f"\r\n--{boundary}--\r\n".encode()
        req = urllib.request.Request(f"{self._base}/api/upload_rootfs", data=body,
            headers={"Content-Type": f"multipart/form-data; boundary={boundary}"})
        return json.loads(urllib.request.urlopen(req, timeout=300).read()).get("rootfs_id","")

    # ── Services ──

    def start_service(self, rootfs_id: str, spec: ServiceSpec) -> dict[str, Any]:
        d = urllib.parse.urlencode({"rootfs_id":rootfs_id,"binary_path":spec.binary_path,
            "binary_name":spec.binary_name,"args":spec.args,"port":str(spec.port)}).encode()
        return json.loads(urllib.request.urlopen(
            urllib.request.Request(f"{self._base}/api/start_service",data=d),timeout=30).read())

    def stop_service(self, sid: str) -> dict[str, Any]:
        return json.loads(urllib.request.urlopen(
            urllib.request.Request(f"{self._base}/api/stop_service/{sid}",data=b"",method="POST"),timeout=10).read())

    def get_status(self) -> dict[str, Any]: return self._get("/api/status")

    # ── Probe ──

    def probe(self, port: int, protocol: str = "tcp") -> dict[str, Any]:
        d = urllib.parse.urlencode({"host":"127.0.0.1","port":str(port),"protocol":protocol}).encode()
        return json.loads(urllib.request.urlopen(
            urllib.request.Request(f"{self._base}/api/probe",data=d),timeout=10).read())

    def http_get(self, port: int, path: str = "/") -> int:
        try: return urllib.request.urlopen(f"http://127.0.0.1:{port}{path}",timeout=5).status
        except urllib.error.HTTPError as e: return e.code
        except Exception: return 0

    # ── Exec ──

    def exec_command(self, rootfs_id: str, command: str, timeout: int = 10) -> dict[str, Any]:
        d = urllib.parse.urlencode({"rootfs_id":rootfs_id,"command":command,"timeout":str(timeout)}).encode()
        return json.loads(urllib.request.urlopen(
            urllib.request.Request(f"{self._base}/api/exec",data=d),timeout=timeout+5).read())

    # ── NVRAM ──

    def set_nvram_config(self, rootfs_id: str, config: dict[str, str]) -> dict[str, Any]:
        d = urllib.parse.urlencode({"rootfs_id":rootfs_id,"config_json":json.dumps(config)}).encode()
        return json.loads(urllib.request.urlopen(
            urllib.request.Request(f"{self._base}/api/nvram_config",data=d),timeout=10).read())

    def _get(self, path: str) -> dict[str, Any]:
        return json.loads(urllib.request.urlopen(f"{self._base}{path}",timeout=5).read())


def start_ssh_tunnel(remote_host: str, remote_port: int = 22,
                     local_port: int = 9100, remote_local_port: int = 9100,
                     ssh_key: str = "") -> subprocess.Popen | None:
    """Start SSH port-forward tunnel to Emulation Agent. Returns Popen or None."""
    cmd = ["ssh","-o","StrictHostKeyChecking=no","-o","ExitOnForwardFailure=yes",
           "-N","-L",f"{local_port}:127.0.0.1:{remote_local_port}",
           "-p",str(remote_port)]
    if ssh_key: cmd.extend(["-i",ssh_key])
    cmd.append(remote_host)
    try: return subprocess.Popen(cmd,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    except Exception: return None
