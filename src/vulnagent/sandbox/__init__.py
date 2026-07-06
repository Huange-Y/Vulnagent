"""Container sandbox — Docker-isolated execution for QEMU and tooling.

Port from DCRH: sandbox.py, docker_ops.py, agent_image.py
"""

from .container import SandboxContainer, SandboxConfig
from .config import load_sandbox_config

__all__ = ["SandboxContainer", "SandboxConfig", "load_sandbox_config"]
