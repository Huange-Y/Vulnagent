"""Constraint injector — schedules and creates injection events.

From article injection timing:
    1. Before direction switch → inject decision tree
    2. Every 20 minutes → inject garbage list
    3. Before report output → inject verification checklist
    4. Every 30 rounds → inject full rule file head+tail
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field


@dataclass
class InjectionEvent:
    trigger: str = ""
    content: str = ""
    timestamp: float = field(default_factory=time.monotonic)


class ConstraintInjector:
    """Creates and schedules constraint injection events.

    Pure scheduler — decides WHEN to inject.
    WHAT comes from ConstraintEngine (B.1).
    """

    def __init__(self) -> None:
        self._last_injection: dict[str, float] = {}
        self._injection_counts: dict[str, int] = {}

    def create_event(self, trigger: str, content: str) -> InjectionEvent:
        now = time.monotonic()
        self._last_injection[trigger] = now
        self._injection_counts[trigger] = self._injection_counts.get(trigger, 0) + 1
        return InjectionEvent(trigger=trigger, content=content, timestamp=now)

    def should_inject(
        self,
        trigger: str,
        round_count: int,
        *,
        cooldown_seconds: float = 300.0,
    ) -> bool:
        last = self._last_injection.get(trigger, 0.0)
        return (time.monotonic() - last) > cooldown_seconds

    def time_since_last(self, trigger: str) -> float:
        last = self._last_injection.get(trigger, 0.0)
        return time.monotonic() - last

    @property
    def injection_counts(self) -> dict[str, int]:
        return dict(self._injection_counts)

    def reset(self) -> None:
        self._last_injection.clear()
        self._injection_counts.clear()
