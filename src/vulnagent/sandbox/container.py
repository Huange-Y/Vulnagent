"""Docker sandbox container — ported from DCRH sandbox.py + docker_ops.py."""

from __future__ import annotations

import shutil
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .config import SandboxConfig, load_sandbox_config


@dataclass
class ContainerResult:
    container_id: str = ""
    return_code: int = -1
    stdout: str = ""
    stderr: str = ""
    duration_ms: float = 0.0
    timed_out: bool = False
    error: str = ""


class SandboxContainer:
    """Docker sandbox for isolated QEMU firmware emulation.

    Port from DCRH sandbox.py + docker_ops.py.
    """

    def __init__(self, config: SandboxConfig | None = None) -> None:
        self._config = config or load_sandbox_config()
        self._container_id: str = ""
        self._docker_bin: str = self._find_docker()

    @staticmethod
    def _find_docker() -> str:
        docker = shutil.which("docker")
        if not docker:
            raise RuntimeError("Docker not found. Use --no-sandbox to run on host.")
        return docker

    def image_exists(self) -> bool:
        try:
            r = subprocess.run(
                [self._docker_bin, "image", "inspect", self._config.image_name],
                capture_output=True, text=True, timeout=30,
            )
            return r.returncode == 0
        except Exception:
            return False

    def build_image(self, dockerfile_dir: str | None = None) -> None:
        if dockerfile_dir is None:
            dockerfile_dir = str(Path(__file__).resolve().parent.parent.parent.parent)
        subprocess.run(
            [self._docker_bin, "build", "-t", self._config.image_name,
             "-f", f"{dockerfile_dir}/Dockerfile", dockerfile_dir],
            check=True, timeout=600,
        )

    def ensure_image(self) -> None:
        if not self.image_exists():
            self.build_image()

    def create(self) -> str:
        args = [
            self._docker_bin, "create", "--rm",
            f"--memory={self._config.memory_limit}",
            f"--cpus={self._config.cpu_limit}",
            f"--network={self._config.network_mode}",
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges",
        ]
        for path in self._config.mount_ro:
            args.append(f"--volume={path}:{path}:ro")
        for path in self._config.mount_rw:
            args.append(f"--volume={path}:{path}:rw")
        args.extend(["--entrypoint", "/bin/sleep", self._config.image_name, "infinity"])
        r = subprocess.run(args, capture_output=True, text=True, timeout=30)
        if r.returncode != 0:
            raise RuntimeError(f"Failed to create container: {r.stderr}")
        self._container_id = r.stdout.strip()[:12]
        return self._container_id

    def start(self) -> None:
        if not self._container_id:
            self.create()
        subprocess.run(
            [self._docker_bin, "start", self._container_id],
            capture_output=True, timeout=30,
        )

    def execute(
        self, command: str | list[str],
        timeout: int | None = None,
        workdir: str = "/work",
    ) -> ContainerResult:
        if not self._container_id:
            self.create()
            self.start()
        timeout = timeout or self._config.timeout_seconds
        cmd_str = command if isinstance(command, str) else " ".join(command)
        start = time.perf_counter()
        try:
            r = subprocess.run(
                [self._docker_bin, "exec", "-w", workdir, self._container_id,
                 "sh", "-c", cmd_str],
                capture_output=True, text=True, timeout=timeout,
            )
            duration = (time.perf_counter() - start) * 1000
            return ContainerResult(
                container_id=self._container_id,
                return_code=r.returncode,
                stdout=r.stdout or "", stderr=r.stderr or "",
                duration_ms=duration,
            )
        except subprocess.TimeoutExpired:
            return ContainerResult(
                container_id=self._container_id, return_code=-1,
                timed_out=True, duration_ms=(time.perf_counter() - start) * 1000,
                error=f"Timed out after {timeout}s",
            )
        except Exception as exc:
            return ContainerResult(container_id=self._container_id, return_code=-1, error=str(exc))

    def stop(self) -> None:
        if self._container_id:
            subprocess.run(
                [self._docker_bin, "stop", "-t", "5", self._container_id],
                capture_output=True, timeout=15,
            )
            self._container_id = ""

    def cleanup(self) -> None:
        self.stop()

    def __enter__(self) -> "SandboxContainer":
        self.ensure_image()
        self.create()
        self.start()
        return self

    def __exit__(self, *args: Any) -> None:
        self.cleanup()
