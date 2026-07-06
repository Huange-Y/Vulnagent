"""Loop lifecycle manager.

From article principles:
    - "20 分钟无进展 → 必须换方向" (external timer)
    - "超 50 轮 → 强制总结并重启"
    - "关键规则置顶 + 精简，定时注入提醒"
"""

from __future__ import annotations

import enum
import time
from dataclasses import dataclass, field
from typing import Any

from .detector import FailureDetector, FailureMode, FailureSignal
from .injector import ConstraintInjector, InjectionEvent


class LoopState(enum.Enum):
    RUNNING = "running"
    SUMMARIZING = "summarizing"
    RESTARTING = "restarting"
    TERMINATED = "terminated"


@dataclass
class LoopSnapshot:
    """Snapshot of loop state for checkpoint/resume."""

    round_count: int
    direction: str
    direction_elapsed: float
    session_elapsed: float
    failure_signals: list[str] = field(default_factory=list)
    summary: str = ""


class LoopManager:
    """Manages Loop lifecycle: detection, injection, and restart."""

    def __init__(
        self,
        constraint_engine: Any = None,
        max_rounds: int = 50,
        direction_timeout_seconds: float = 1200.0,
    ) -> None:
        self._constraint_engine = constraint_engine
        self._max_rounds = max_rounds
        self._direction_timeout = direction_timeout_seconds
        self._detector = FailureDetector()
        self._injector = ConstraintInjector()
        self._state: LoopState = LoopState.TERMINATED
        self._round_count: int = 0
        self._session_start: float = 0.0
        self._direction_start: float = 0.0
        self._current_direction: str = ""
        self._last_outputs: list[str] = []
        self._failure_history: list[FailureSignal] = []

    def start_session(self, initial_direction: str = "") -> None:
        now = time.monotonic()
        self._state = LoopState.RUNNING
        self._round_count = 0
        self._session_start = now
        self._direction_start = now
        self._current_direction = initial_direction
        self._last_outputs.clear()
        self._failure_history.clear()
        self._detector.reset()
        if self._constraint_engine:
            self._constraint_engine.start_session()

    def before_iteration(self, direction: str, recent_outputs: list[str]) -> FailureSignal:
        self._current_direction = direction
        self._last_outputs = list(recent_outputs)
        signal = self._detector.detect(
            direction=direction,
            recent_outputs=recent_outputs,
            round_count=self._round_count,
            direction_elapsed=time.monotonic() - self._direction_start,
            session_elapsed=time.monotonic() - self._session_start,
        )
        if signal.mode != FailureMode.NONE:
            self._failure_history.append(signal)
            if signal.mode == FailureMode.PSEUDO_COMPLETION and signal.confidence >= 0.6:
                self._state = LoopState.SUMMARIZING
                self._persist_snapshot()
            elif signal.mode == FailureMode.DIRECTION_DRIFT and signal.confidence >= 0.7:
                self._state = LoopState.SUMMARIZING
                self._persist_snapshot()
        return signal

    def after_iteration(self) -> None:
        self._round_count += 1
        if self._constraint_engine:
            self._constraint_engine.record_round()
        if self.should_restart():
            self._state = LoopState.RESTARTING
            self._persist_snapshot()

    def terminate(self) -> None:
        """Transition to TERMINATED state and persist final snapshot."""
        self._state = LoopState.TERMINATED
        self._persist_snapshot()

    def _persist_snapshot(self) -> None:
        """Persist current loop snapshot for checkpoint/resume (best-effort)."""
        snapshot = self.take_snapshot()
        try:
            from vulnagent.runtime.context import current_runtime_run_id
            from vulnagent.runtime.store import RuntimeStore
            from vulnagent.paths import RUNTIME_ROOT
            store = RuntimeStore(root=RUNTIME_ROOT)
            run_id = current_runtime_run_id()
            if run_id:
                store.append_event(
                    run_id=run_id,
                    event_type="loop.snapshot",
                    payload={
                        "round_count": snapshot.round_count,
                        "direction": snapshot.direction,
                        "direction_elapsed": snapshot.direction_elapsed,
                        "session_elapsed": snapshot.session_elapsed,
                        "failure_signals": snapshot.failure_signals,
                        "state": self._state.value,
                        "summary": snapshot.summary,
                    },
                )
        except Exception:
            pass

    def handle_failure(self, signal: FailureSignal) -> InjectionEvent | None:
        """Generate injection event via injector with cooldown gating."""
        if signal.mode == FailureMode.NONE:
            return None

        # Cooldown gating: don't spam the same trigger within 300s
        trigger = signal.mode.value
        if not self._injector.should_inject(trigger, self._round_count):
            return None

        if signal.mode == FailureMode.DIRECTION_DRIFT:
            return self._injector.create_event(
                trigger="direction_drift",
                content=(
                    "[LOOP MANAGER] Direction drift detected. "
                    f"Evidence: {signal.evidence}. "
                    "Re-read your task description and confirm you are on track. "
                    "If you've genuinely found a better angle, explicitly state your new direction."
                ),
            )
        elif signal.mode == FailureMode.RULE_FORGETTING:
            cheat = ""
            if self._constraint_engine:
                cheat = self._constraint_engine.get_cheat_card_text()
            return self._injector.create_event(
                trigger="rule_forgetting",
                content=(
                    f"[LOOP MANAGER] Rule reminder — session at round {self._round_count}.\n"
                    f"{cheat}\n"
                    "Re-read the constraint card above before continuing."
                ),
            )
        elif signal.mode == FailureMode.PSEUDO_COMPLETION:
            return self._injector.create_event(
                trigger="pseudo_completion",
                content=(
                    "[LOOP MANAGER] Possible pseudo-completion detected. "
                    "Have you actually found a vulnerability with an executable PoC? "
                    "If not, switch direction or dig deeper. "
                    "现象 ≠ 漏洞. No PoC = no finding. "
                    "20 分钟无进展 → 必须换方向."
                ),
            )
        return None

    def should_restart(self) -> bool:
        if self._round_count >= self._max_rounds:
            return True
        if self._constraint_engine:
            timing = self._constraint_engine.check_timing()
            return timing.should_restart_session
        return False

    def take_snapshot(self) -> LoopSnapshot:
        return LoopSnapshot(
            round_count=self._round_count,
            direction=self._current_direction,
            direction_elapsed=time.monotonic() - self._direction_start,
            session_elapsed=time.monotonic() - self._session_start,
            failure_signals=[s.mode.value for s in self._failure_history],
        )

    def record_direction_switch(self, new_direction: str) -> None:
        self._direction_start = time.monotonic()
        self._current_direction = new_direction
        self._detector.record_direction_switch(new_direction)
        if self._constraint_engine:
            self._constraint_engine.record_direction_switch(new_direction)

    @property
    def state(self) -> LoopState:
        return self._state

    @property
    def round_count(self) -> int:
        return self._round_count

    @property
    def current_direction(self) -> str:
        return self._current_direction
