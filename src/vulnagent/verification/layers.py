"""Four-layer verification pipeline.

From article:
    L1: AI self-check  — auxiliary noise reduction
    L2: Output parser  — structured PoC enforcement (HARD GATE)
    L3: Keyword interceptor — garbage list filter (HARD GATE)
    L4: External replay — causal verification
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .interceptor import KeywordInterceptor
from .parser import PocParser
from .replay import PoCReplayer


@dataclass
class LayerVerdict:
    passed: bool
    layer: int
    reason: str = ""
    details: dict[str, Any] = field(default_factory=dict)


@dataclass
class VerificationResult:
    finding_id: str = ""
    finding_title: str = ""
    l1_self_check: LayerVerdict | None = None
    l2_parse: LayerVerdict | None = None
    l3_intercept: LayerVerdict | None = None
    l4_replay: LayerVerdict | None = None

    @property
    def passed(self) -> bool:
        results = [v for v in (self.l1_self_check, self.l2_parse, self.l3_intercept, self.l4_replay) if v is not None]
        return all(v.passed for v in results) if results else False

    @property
    def failed_at(self) -> int:
        for v in (self.l2_parse, self.l3_intercept):
            if v is not None and not v.passed:
                return v.layer
        if self.l4_replay is not None and not self.l4_replay.passed:
            return 4
        return 0


class VerificationPipeline:
    """Four-layer verification. L1 advisory, L2/L3/L4 are hard gates."""

    def __init__(
        self,
        interceptor: KeywordInterceptor | None = None,
        replayer: PoCReplayer | None = None,
        parser: PocParser | None = None,
    ) -> None:
        self._interceptor = interceptor or KeywordInterceptor()
        self._replayer = replayer
        self._parser = parser or PocParser()

    def verify(
        self,
        finding: dict[str, Any],
        *,
        ai_self_check_passed: bool = True,
        skip_replay: bool = False,
    ) -> VerificationResult:
        title = str(finding.get("title", ""))
        finding_id = str(finding.get("id", title))
        result = VerificationResult(finding_id=finding_id, finding_title=title)

        # L1: AI self-check (advisory only)
        result.l1_self_check = LayerVerdict(
            passed=ai_self_check_passed,
            layer=1,
            reason="AI self-check passed" if ai_self_check_passed else "AI self-check failed",
        )

        # L2: Structured PoC enforcement (HARD GATE)
        poc_text = self._extract_poc_text(finding)
        parsed = self._parser.parse(poc_text)
        if parsed is None:
            result.l2_parse = LayerVerdict(
                passed=False, layer=2,
                reason="No structured PoC found — requires executable verification",
            )
            return result
        result.l2_parse = LayerVerdict(
            passed=True, layer=2,
            reason="Structured PoC extracted",
            details={"poc": parsed.as_dict()},
        )

        # L3: Garbage list filter (HARD GATE)
        intercepted = self._interceptor.check(
            title=title,
            description=str(finding.get("description", "")),
            evidence=str(finding.get("evidence", "")),
        )
        if intercepted:
            result.l3_intercept = LayerVerdict(
                passed=False, layer=3,
                reason=f"Finding matches garbage list: {intercepted}",
            )
            return result
        result.l3_intercept = LayerVerdict(passed=True, layer=3, reason="No garbage list match")

        # L4: External replay (HARD GATE, optional)
        if not skip_replay and self._replayer is not None:
            replay = self._replayer.replay(parsed)
            result.l4_replay = LayerVerdict(
                passed=replay.success, layer=4,
                reason="PoC replay succeeded" if replay.success else "PoC replay failed",
                details={"replay": replay.as_dict()},
            )

        return result

    def _extract_poc_text(self, finding: dict[str, Any]) -> str:
        parts: list[str] = []
        for key in ("poc", "poc_text", "exploit_code", "reproduction", "executable_command"):
            val = finding.get(key, "")
            if val:
                parts.append(str(val))
        evidence = finding.get("evidence", [])
        if isinstance(evidence, list):
            parts.extend(str(e) for e in evidence)
        elif isinstance(evidence, str):
            parts.append(evidence)
        return "\n".join(parts)
