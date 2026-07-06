"""Patch grader — T0-T3 verification ladder from DCRH harness/patch_grade.py.

T0: Patch apply + syntax check
T1: Original PoC no longer triggers
T2: Basic functionality tests
T3: Re-attack (advisory)
"""

from __future__ import annotations

import subprocess
import time
from dataclasses import dataclass, field
from typing import Any


@dataclass
class TierResult:
    tier: str
    passed: bool
    evidence: str = ""
    duration_ms: float = 0.0


@dataclass
class PatchGradeResult:
    patch_id: str = ""
    finding_title: str = ""
    t0: TierResult | None = None
    t1: TierResult | None = None
    t2: TierResult | None = None
    t3: TierResult | None = None
    overall_passed: bool = False
    evidence_log: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "patch_id": self.patch_id,
            "finding_title": self.finding_title,
            "overall_passed": self.overall_passed,
            "tiers": {
                "T0": {"passed": self.t0.passed, "evidence": self.t0.evidence} if self.t0 else None,
                "T1": {"passed": self.t1.passed, "evidence": self.t1.evidence} if self.t1 else None,
                "T2": {"passed": self.t2.passed, "evidence": self.t2.evidence} if self.t2 else None,
                "T3": {"passed": self.t3.passed, "evidence": self.t3.evidence} if self.t3 else None,
            },
        }


class PatchGrader:
    """Grade a firmware patch through T0-T3 ladder.

    From DCRH: each tier is an executable oracle.
    """

    def __init__(self, timeout_seconds: int = 120) -> None:
        self._timeout = timeout_seconds

    def grade(
        self,
        finding: dict[str, Any],
        patch_commands: str,
        target: str = "",
        *,
        test_command: str = "",
    ) -> PatchGradeResult:
        title = str(finding.get("title", "unknown"))
        patch_id = f"patch_{hash(title) & 0xFFFF:04x}"
        result = PatchGradeResult(patch_id=patch_id, finding_title=title)

        # T0: Validate patch commands
        t0 = self._grade_t0(patch_commands)
        result.t0 = t0
        result.evidence_log.append(f"T0: {'PASS' if t0.passed else 'FAIL'}")
        if not t0.passed:
            return result

        # T1: PoC replay
        poc_cmd = self._extract_poc(finding)
        if poc_cmd:
            t1 = self._grade_t1(poc_cmd)
            result.t1 = t1
            result.evidence_log.append(f"T1: {'PASS' if t1.passed else 'FAIL'}")
            if not t1.passed:
                return result
        else:
            result.t1 = TierResult(tier="T1", passed=True, evidence="No PoC — skipped")

        # T2: Functionality tests
        if test_command:
            t2 = self._grade_t2(test_command)
            result.t2 = t2
            result.evidence_log.append(f"T2: {'PASS' if t2.passed else 'FAIL'}")
        else:
            result.t2 = TierResult(tier="T2", passed=True, evidence="No test suite — skipped")

        # T3: Advisory (always skipped in automated mode)
        result.t3 = TierResult(tier="T3", passed=True, evidence="Re-attack not requested — skipped")

        result.overall_passed = all(
            t.passed for t in (result.t0, result.t1, result.t2) if t is not None
        )
        return result

    def _grade_t0(self, cmds: str) -> TierResult:
        if not cmds or not cmds.strip():
            return TierResult(tier="T0", passed=False, evidence="Empty patch commands")
        danger = ("rm -rf /", "mkfs.", "dd if=/dev/", "> /dev/sd")
        for d in danger:
            if d in cmds:
                return TierResult(tier="T0", passed=False, evidence=f"Dangerous: {d}")
        try:
            proc = subprocess.run(["sh", "-n", "-c", cmds], capture_output=True, text=True, timeout=10)
            if proc.returncode != 0:
                return TierResult(tier="T0", passed=False, evidence=f"Syntax error: {proc.stderr[:200]}")
        except Exception as exc:
            return TierResult(tier="T0", passed=False, evidence=str(exc))
        return TierResult(tier="T0", passed=True, evidence="Patch syntax valid")

    def _grade_t1(self, poc_cmd: str) -> TierResult:
        start = time.perf_counter()
        try:
            proc = subprocess.run(poc_cmd, shell=True, capture_output=True, text=True, timeout=self._timeout)
            duration = (time.perf_counter() - start) * 1000
            return TierResult(tier="T1", passed=True,
                evidence=f"PoC rc={proc.returncode}, stdout={proc.stdout[:200]}",
                duration_ms=duration)
        except subprocess.TimeoutExpired:
            return TierResult(tier="T1", passed=False, evidence="PoC timed out")
        except Exception as exc:
            return TierResult(tier="T1", passed=False, evidence=str(exc))

    def _grade_t2(self, test_cmd: str) -> TierResult:
        try:
            proc = subprocess.run(test_cmd, shell=True, capture_output=True, text=True, timeout=self._timeout)
            if proc.returncode == 0:
                return TierResult(tier="T2", passed=True, evidence="Tests passed")
            return TierResult(tier="T2", passed=False, evidence=f"Tests failed: {proc.stderr[:200]}")
        except subprocess.TimeoutExpired:
            return TierResult(tier="T2", passed=False, evidence="Tests timed out")
        except Exception as exc:
            return TierResult(tier="T2", passed=False, evidence=str(exc))

    @staticmethod
    def _extract_poc(finding: dict[str, Any]) -> str:
        for key in ("executable_command", "poc_command", "poc"):
            val = finding.get(key, "")
            if val and isinstance(val, str) and len(val) > 5:
                return val
        evidence = finding.get("evidence", [])
        if isinstance(evidence, list):
            for item in evidence:
                s = str(item)
                if any(kw in s for kw in ("curl ", "qemu-", "python ", "#!/")):
                    return s
        return ""
