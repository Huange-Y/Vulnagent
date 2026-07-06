"""Emulation Agent client — HTTP client for the QEMU emulation backend.

The emulation agent server (server.py) runs on a dedicated Ubuntu VM at
your-vm-ip:9100.  vulnagent communicates with it via EmulationAgentClient
(HTTP over SSH tunnel).

Communication path: vulnagent → backend.py → client.py → HTTP → server.py (VM)
"""

from vulnagent.emulation_agent.client import (
    EmulationAgentClient, ServiceSpec, EmulationStatus, start_ssh_tunnel,
)
from vulnagent.emulation_agent.backend import (
    FirmwareValidationBackend, EmulationAgentBackend,
    DirectHardwareBackend, StaticOnlyBackend,
    create_validation_backend, ServiceToVerify,
    VerificationResult, ValidationReport,
)

__all__ = [
    "EmulationAgentClient", "ServiceSpec", "EmulationStatus", "start_ssh_tunnel",
    "FirmwareValidationBackend", "EmulationAgentBackend",
    "DirectHardwareBackend", "StaticOnlyBackend",
    "create_validation_backend", "ServiceToVerify",
    "VerificationResult", "ValidationReport",
]
