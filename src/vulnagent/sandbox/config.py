"""Sandbox configuration loader."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import yaml


@dataclass
class SandboxConfig:
    image_name: str = "vulnagent-sandbox"
    memory_limit: str = "4g"
    cpu_limit: str = "2"
    network_mode: str = "bridge"
    timeout_seconds: int = 300
    mount_rw: list[str] = field(default_factory=list)
    mount_ro: list[str] = field(default_factory=list)


def load_sandbox_config(config_path: str | None = None) -> SandboxConfig:
    if config_path is None:
        config_path = str(
            Path(__file__).resolve().parent.parent.parent.parent / "config" / "sandbox.yaml"
        )
    defaults = SandboxConfig()
    if not Path(config_path).exists():
        return defaults
    try:
        with open(config_path, "r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh) or {}
    except Exception:
        return defaults
    return SandboxConfig(
        image_name=str(data.get("image_name", defaults.image_name)),
        memory_limit=str(data.get("memory_limit", defaults.memory_limit)),
        cpu_limit=str(data.get("cpu_limit", defaults.cpu_limit)),
        network_mode=str(data.get("network_mode", defaults.network_mode)),
        timeout_seconds=int(data.get("timeout_seconds", defaults.timeout_seconds)),
        mount_rw=list(data.get("mount_rw", [])),
        mount_ro=list(data.get("mount_ro", [])),
    )
