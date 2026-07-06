"""Fuzzing manager for discovered firmware services (AFL++ / Boofuzz)."""

from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class FuzzingTarget:
    binary_path: str = ""
    host: str = "127.0.0.1"
    port: int = 0
    protocol: str = "tcp"
    seed_inputs: list[str] = field(default_factory=list)


@dataclass
class FuzzingResult:
    target: FuzzingTarget = field(default_factory=FuzzingTarget)
    crashes: list[dict[str, Any]] = field(default_factory=list)
    total_execs: int = 0
    duration_s: float = 0.0
    available: bool = False
    error: str = ""


class FuzzingManager:
    """Orchestrates AFL++/Boofuzz fuzzing of firmware services."""

    def __init__(self, sandbox: Any = None, timeout: int = 300) -> None:
        self._sandbox = sandbox
        self._timeout = timeout
        self._afl_ok = shutil.which("afl-fuzz") is not None
        self._boofuzz_ok = False
        try:
            import boofuzz  # noqa: F401
            self._boofuzz_ok = True
        except ImportError:
            pass

    @property
    def afl_available(self) -> bool:
        return self._afl_ok

    @property
    def boofuzz_available(self) -> bool:
        return self._boofuzz_ok

    def can_fuzz(self, target: FuzzingTarget) -> bool:
        if target.binary_path and self._afl_ok:
            return True
        if target.host and target.port and self._boofuzz_ok:
            return True
        return False

    def prepare_afl(
        self, target: FuzzingTarget, input_dir: Path, output_dir: Path
    ) -> subprocess.Popen | None:
        if not self._afl_ok:
            return None
        input_dir.mkdir(parents=True, exist_ok=True)
        output_dir.mkdir(parents=True, exist_ok=True)
        (input_dir / "seed.bin").write_bytes(b"AAAA")
        cmd = [
            "afl-fuzz", "-i", str(input_dir), "-o", str(output_dir),
            "-t", "1000", "--", target.binary_path, "@@",
        ]
        return subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    def collect_crashes(self, output_dir: Path) -> list[dict[str, Any]]:
        d = output_dir / "crashes"
        if not d.exists():
            return []
        return [
            {"path": str(fp), "size": fp.stat().st_size}
            for fp in d.iterdir() if fp.name != "README.txt"
        ]

    def status(self) -> dict[str, bool]:
        return {"afl": self._afl_ok, "boofuzz": self._boofuzz_ok}
