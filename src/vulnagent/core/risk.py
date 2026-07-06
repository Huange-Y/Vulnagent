"""CVSS 3.1 scoring for firmware vulnerability findings — IoT/embedded adapted."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class CVSSScore:
    base_score: float = 0.0
    temporal_score: float = 0.0
    environmental_score: float = 0.0
    vector_string: str = ""
    severity: str = "none"
    breakdown: dict[str, float] = field(default_factory=dict)


class CVSSCalculator:
    """CVSS 3.1 calculator — heuristic mapping for IoT firmware vulnerabilities."""

    CWE_SEVERITY: dict[str, tuple[float, str]] = {
        "CWE-78": (9.8, "critical"), "CWE-77": (9.8, "critical"),
        "CWE-287": (9.1, "critical"), "CWE-306": (9.1, "critical"),
        "CWE-798": (9.8, "critical"),
        "CWE-120": (9.8, "critical"), "CWE-121": (9.8, "critical"),
        "CWE-122": (9.8, "critical"), "CWE-134": (7.5, "high"),
        "CWE-22": (7.5, "high"), "CWE-200": (5.3, "medium"),
        "CWE-434": (9.8, "critical"), "CWE-502": (9.8, "critical"),
        "CWE-862": (7.5, "high"), "CWE-863": (8.8, "high"),
    }

    @classmethod
    def calculate(cls, finding: dict[str, Any], *,
                  network_exposed: bool = True, auth_required: bool = False,
                  safety_impact: bool = False) -> CVSSScore:
        cwe = str(finding.get("cwe_id", "")).strip().upper()
        title = str(finding.get("title", "")).lower()
        base, severity = cls.CWE_SEVERITY.get(cwe, cls._infer(title))
        if not network_exposed:
            base = max(0.1, base - 3.0)
        if auth_required:
            base = max(0.1, base - 2.0)
        if safety_impact:
            base = min(10.0, base + 1.5)
        av = "N" if network_exposed else "A"
        ac = "L" if not auth_required else "H"
        vector = f"CVSS:3.1/AV:{av}/AC:{ac}/PR:N/UI:N/S:U"
        temporal = max(0.1, base - 0.5)
        return CVSSScore(
            base_score=round(base, 1), temporal_score=round(temporal, 1),
            environmental_score=round(base, 1),
            vector_string=vector, severity=severity if base >= 7.0 else ("medium" if base >= 4.0 else "low"),
            breakdown={"base": base, "temporal": temporal, "environmental": base},
        )

    @classmethod
    def _infer(cls, title: str) -> tuple[float, str]:
        t = title.lower()
        if any(kw in t for kw in ("command injection", "rce", "remote code", "code execution", "代码执行")): return (9.8, "critical")
        if any(kw in t for kw in ("auth bypass", "认证绕过")): return (9.1, "critical")
        if any(kw in t for kw in ("buffer overflow", "缓冲区溢出")): return (9.8, "critical")
        if any(kw in t for kw in ("hardcoded", "硬编码", "default password")): return (9.8, "critical")
        if any(kw in t for kw in ("path traversal", "目录穿越")): return (7.5, "high")
        if any(kw in t for kw in ("information", "信息泄露", "version")): return (5.3, "medium")
        return (7.5, "high")


def score_finding(finding: dict[str, Any], **kwargs: Any) -> dict[str, Any]:
    s = CVSSCalculator.calculate(finding, **kwargs)
    finding["cvss_score"] = str(s.base_score)
    finding["cvss_vector"] = s.vector_string
    finding["severity"] = s.severity
    finding["cvss_breakdown"] = s.breakdown
    return finding
