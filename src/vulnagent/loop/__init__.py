"""Loop management system.

From article: "AI Agent 的运行本质是一个 Loop（观察→推理→行动→反馈）"

Three failure modes (directly applicable to vulnagent):
    - Direction drift: analyzing SquashFS suddenly scanning open ports
    - Rule forgetting: ignoring "verified safe" paths in long sessions
    - Pseudo-completion: "inventing" a vuln after no real progress
"""

from .manager import LoopManager, LoopState
from .detector import FailureDetector, FailureMode, FailureSignal
from .injector import ConstraintInjector, InjectionEvent

__all__ = [
    "LoopManager",
    "LoopState",
    "FailureMode",
    "FailureSignal",
    "FailureDetector",
    "ConstraintInjector",
    "InjectionEvent",
]
