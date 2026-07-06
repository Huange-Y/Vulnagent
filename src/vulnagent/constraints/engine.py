"""Hard constraint engine — external enforcement, never prompt suggestion.

From article:
    "让 AI 自我审核等于让出题人自己阅卷"
    External enforcement at the engineering layer — timeout/intercept/restart
    are executed externally, NOT relying on LLM self-awareness.

Three enforcement layers:
    L1: Command gate — block dangerous commands before subprocess execution
    L2: Finding gate — reject findings matching garbage list at output parse time
    L3: Timing gate — direction timeout / round cap enforced externally
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass
from typing import Any

from .rules import (
    CheatCard,
    DangerousCommandRule,
    DecisionTree,
    GarbageFindingList,
    build_cheat_card,
    build_dangerous_commands,
    build_decision_tree,
    build_garbage_list,
    load_constraints,
)


@dataclass
class EnforcementResult:
    """Result of a constraint check."""

    allowed: bool
    reason: str = ""
    blocked_command: str = ""


@dataclass
class FindingVerdict:
    """Verdict on whether a finding passes the garbage filter."""

    accepted: bool
    reason: str = ""
    matched_category: str = ""


@dataclass
class TimingVerdict:
    """Verdict on whether the session should continue or be forced to switch."""

    should_continue: bool
    should_switch_direction: bool = False
    should_restart_session: bool = False
    reason: str = ""


class ConstraintEngine:
    """Central constraint enforcement engine.

    Called at three points:
        pre_execution:  before any shell command → blocks dangerous commands
        post_finding:   after finding generation → filters garbage
        pre_phase:      before phase transition → injects cheat card, checks timing

    Usage:
        engine = ConstraintEngine()
        engine.start_session()

        # Pre-execution
        result = engine.check_command("rm -rf /tmp/test")
        if not result.allowed:
            raise RuntimeError(result.reason)

        # Post-finding
        verdict = engine.check_finding("版本号暴露 in lighttpd")
        if not verdict.accepted:
            logger.info(f"Finding rejected: {verdict.reason}")

        # Pre-phase
        timing = engine.check_timing()
        if timing.should_switch_direction:
            # inject cheat card + direction hint
            pass
    """

    def __init__(self, config_path: str | None = None) -> None:
        data = load_constraints(config_path)
        self._garbage_list: GarbageFindingList = build_garbage_list(data)
        self._decision_tree: DecisionTree = build_decision_tree(data)
        self._cheat_card: CheatCard = build_cheat_card(data)
        self._dangerous: list[DangerousCommandRule] = build_dangerous_commands(data)
        self._hard_rules: list[str] = [
            str(r) for r in (data.get("hard_no_report") or [])
        ]
        timing = data.get("timing", {}) or {}
        self._direction_timeout: float = float(timing.get("direction_timeout_minutes", 20)) * 60.0
        self._max_rounds: int = int(timing.get("max_rounds_per_session", 50))
        self._idle_timeout: float = float(timing.get("idle_timeout_minutes", 10)) * 60.0

        # Session state
        self._session_start: float = 0.0
        self._direction_start: float = 0.0
        self._last_activity: float = 0.0
        self._round_count: int = 0
        self._direction_switches: int = 0
        self._current_direction: str = ""
        self._current_phase: str = ""
        # Per-phase timeout overrides: phase_name → timeout_seconds
        self._phase_timeouts: dict[str, float] = {
            "brainstorm": 20 * 60,
            "discovery": 30 * 60,
            "exploit": 25 * 60,
            "verification": 15 * 60,
            "report": 5 * 60,
        }

    # ── Session management ──

    def set_phase(self, phase: str) -> None:
        """Set current pipeline phase (brainstorm/discovery/exploit/verification/report).

        Updates direction timeout if a per-phase override exists.
        """
        self._current_phase = phase
        phase_lower = phase.lower()
        if phase_lower in self._phase_timeouts:
            self._direction_timeout = self._phase_timeouts[phase_lower]
        # Reset direction timer on phase change
        self._direction_start = time.monotonic()

    def get_current_timeout(self) -> float:
        """Return the active direction timeout in seconds."""
        return self._direction_timeout

    # ── Session management ──

    def start_session(self) -> None:
        """Reset all timing state for a new session."""
        now = time.monotonic()
        self._session_start = now
        self._direction_start = now
        self._last_activity = now
        self._round_count = 0
        self._direction_switches = 0
        self._current_direction = ""

    def record_round(self) -> None:
        """Record that one agent iteration completed."""
        self._round_count += 1
        self._last_activity = time.monotonic()

    def record_direction_switch(self, new_direction: str) -> None:
        """Record a direction change."""
        self._direction_start = time.monotonic()
        self._direction_switches += 1
        self._current_direction = new_direction

    # ── L1: Command gate ──

    def check_command(self, command: str) -> EnforcementResult:
        """Check if a shell command should be blocked.

        Called BEFORE any subprocess execution in ToolExecutor.
        """
        if not command or not isinstance(command, str):
            return EnforcementResult(allowed=True)

        for rule in self._dangerous:
            if not rule.pattern:
                continue
            try:
                if re.search(rule.pattern, command):
                    return EnforcementResult(
                        allowed=False,
                        reason=f"Blocked by constraint engine: {rule.reason}",
                        blocked_command=command[:200],
                    )
            except re.error:
                continue

        return EnforcementResult(allowed=True)

    # ── L2: Finding gate ──

    def check_finding(self, title: str, description: str = "", evidence: str = "") -> FindingVerdict:
        """Check if a finding should be rejected as garbage.

        Garbage check FIRST (CORS/version leaks are garbage regardless of PoC),
        THEN PoC check (valid vuln class but no proof provided).
        """
        # L3 first: garbage hits → immediate reject
        if self._garbage_list.matches(title, description):
            return FindingVerdict(
                accepted=False,
                reason=f"Finding matches garbage list: {title[:120]}",
                matched_category="garbage_list",
            )

        # L2: must have executable PoC
        if not self._has_poc_indicators(title, description, evidence):
            return FindingVerdict(
                accepted=False,
                reason="No PoC indicators found — finding requires executable verification",
                matched_category="no_poc",
            )

        return FindingVerdict(accepted=True)

    # ── L3: Timing gate ──

    def check_timing(self) -> TimingVerdict:
        """Check session timing constraints.

        From article:
            - 20 minutes no progress → must switch direction
            - 50 rounds → force summarize + restart
            - External timer, not LLM self-check
        """
        now = time.monotonic()

        # Direction timeout
        direction_elapsed = now - self._direction_start
        if direction_elapsed > self._direction_timeout:
            return TimingVerdict(
                should_continue=True,
                should_switch_direction=True,
                reason=f"Direction timeout: {direction_elapsed:.0f}s > {self._direction_timeout:.0f}s",
            )

        # Round cap
        if self._round_count >= self._max_rounds:
            return TimingVerdict(
                should_continue=False,
                should_restart_session=True,
                reason=f"Round cap reached: {self._round_count} >= {self._max_rounds}",
            )

        # Idle timeout — session-level inactivity (was dead code, now wired)
        idle_elapsed = now - self._last_activity
        if idle_elapsed > self._idle_timeout:
            return TimingVerdict(
                should_continue=True,
                should_switch_direction=True,
                reason=f"Idle timeout: {idle_elapsed:.0f}s > {self._idle_timeout:.0f}s",
            )

        return TimingVerdict(should_continue=True)

    # ── Injection helpers ──

    def get_cheat_card_text(self) -> str:
        """Get cheat card for injection into agent context."""
        return self._cheat_card.format_for_injection()

    def get_decision_tree_text(self) -> str:
        """Get decision tree prompt snippet."""
        return self._decision_tree.format_for_prompt()

    def get_direction_hint(self, context: str) -> str:
        """Get direction suggestion based on current context."""
        return self._decision_tree.match(context)

    # ── Properties ──

    @property
    def round_count(self) -> int:
        return self._round_count

    @property
    def garbage_list(self) -> GarbageFindingList:
        return self._garbage_list

    @property
    def hard_rules(self) -> list[str]:
        return self._hard_rules

    # ── Internal ──

    @staticmethod
    def _has_poc_indicators(title: str, description: str, evidence: str) -> bool:
        """Check if the finding text contains PoC indicators.

        From article: "报告必须有 curl 或可执行命令"
        Adapted for firmware: shell command, python script, or QEMU invocation.
        """
        combined = f"{title} {description} {evidence}".lower()
        poc_markers = (
            "curl ", "wget ", "python ", "python3 ",
            "qemu-", "chroot ", "echo ", "printf ",
            "poc_script", "execute:", "command:",
            "/bin/", "#!/", ".sh", ".py",
            "proof of concept", "reproduce:", "reproduction",
        )
        return any(marker in combined for marker in poc_markers)
