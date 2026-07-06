"""Tiered scanning — formalizes Seed→Discovery→Exploit pipeline.

Tier 1 (Surface): File ID, binwalk, strings — fast + broad, low confidence
Tier 2 (Static): Binary analysis, service inventory — medium depth
Tier 3 (Dynamic): QEMU emulation, runtime probing — high confidence
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Tier(Enum):
    SURFACE = 1
    STATIC = 2
    DYNAMIC = 3


class Confidence(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


@dataclass
class TierConfig:
    tier: Tier
    token_budget: int
    max_iterations: int
    confidence: Confidence
    enabled: bool = True
    tool_allowlist: list[str] = field(default_factory=list)


@dataclass
class TierResult:
    tier: Tier
    confidence: Confidence
    findings_count: int
    priority_targets_count: int
    tokens_used: int
    duration_s: float = 0.0
    gated: bool = False
    gate_reason: str = ""


class TierManager:
    """Manage tiered scanning with gating logic."""

    def __init__(self) -> None:
        self._configs: dict[Tier, TierConfig] = {
            Tier.SURFACE: TierConfig(
                tier=Tier.SURFACE, token_budget=20000, max_iterations=3,
                confidence=Confidence.LOW,
                tool_allowlist=["file_identify", "binwalk_scan", "strings_extract"],
            ),
            Tier.STATIC: TierConfig(
                tier=Tier.STATIC, token_budget=50000, max_iterations=5,
                confidence=Confidence.MEDIUM,
                tool_allowlist=["firmware_runtime_manifest", "firmware_service_inventory",
                                "firmware_web_surface_map", "firmware_read_path", "readelf_headers"],
            ),
            Tier.DYNAMIC: TierConfig(
                tier=Tier.DYNAMIC, token_budget=100000, max_iterations=8,
                confidence=Confidence.HIGH,
                tool_allowlist=["firmware_emulation_prepare", "firmware_emulation_launch_user",
                                "firmware_emulation_probe", "generate_poc"],
            ),
        }
        self._results: dict[Tier, TierResult] = {}

    def should_proceed(self, from_tier: Tier) -> tuple[bool, str]:
        result = self._results.get(from_tier)
        if result is None:
            return True, ""
        if from_tier == Tier.SURFACE and result.priority_targets_count == 0:
            # Allow proceed if any findings were recorded (FS markers, etc.)
            if result.findings_count > 0:
                return True, ""
            return False, "No interesting artifacts — skip static analysis"
        if from_tier == Tier.STATIC and result.priority_targets_count == 0 and result.findings_count == 0:
            return False, "No priority targets — skip dynamic analysis"
        return True, ""

    def record_result(self, result: TierResult) -> None:
        self._results[result.tier] = result

    def get_config(self, tier: Tier) -> TierConfig:
        return self._configs.get(tier, self._configs[Tier.SURFACE])

    def annotate_finding(self, finding: dict[str, Any], tier: Tier) -> dict[str, Any]:
        finding["confidence"] = self.get_config(tier).confidence.value
        finding["tier"] = tier.value
        return finding

    @property
    def results(self) -> dict[Tier, TierResult]:
        return dict(self._results)
