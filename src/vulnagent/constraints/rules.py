"""Firmware-domain constraint rules — garbage finding list, decision tree, cheat card.

Design (from article):
    - Only write boundaries, direction, standards — never methodology
    - Every line must have a clear behavior directive
    - Critical rules at top and bottom (model attention bias)
    - Garbage list cut to the bone — complexity increases false positives
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml


# ── Dataclasses ──

@dataclass(slots=True)
class GarbageFindingList:
    """Findings that MUST be rejected regardless of AI confidence.

    Mirrors the article's garbage list pattern but adapted for firmware.
    """

    info_leak: list[str] = field(default_factory=list)
    no_impact: list[str] = field(default_factory=list)
    known_safe: list[str] = field(default_factory=list)
    physical: list[str] = field(default_factory=list)
    _whitelist: set[str] = field(default_factory=set)
    _severity_weight: float = 0.5

    # Severity weights per category (higher = more likely false positive)
    _CATEGORY_WEIGHTS: dict[str, float] = field(default_factory=lambda: {
        "info_leak": 0.7, "no_impact": 0.9, "known_safe": 0.8, "physical": 0.85,
    })

    def add_whitelist(self, pattern: str) -> None:
        """Add a whitelist pattern that bypasses garbage filtering."""
        self._whitelist.add(pattern.lower().strip())

    def matches(self, title: str, description: str = "") -> bool:
        """Check if a finding matches any garbage category.

        Supports literal substrings (default) and regex patterns
        (patterns prefixed with 'regex:' for complex matching).
        Whitelisted patterns bypass all checks.
        """
        combined = f"{title} {description}".lower()

        # Whitelist check: if title/desc matches any whitelist pattern, never reject
        for wp in self._whitelist:
            if wp in combined:
                return False

        for category in (self.info_leak, self.no_impact, self.known_safe, self.physical):
            for pattern in category:
                p = pattern.strip()
                if p.startswith("regex:"):
                    try:
                        if re.search(p[6:], combined, re.IGNORECASE):
                            return True
                    except (re.error, Exception):
                        continue
                elif p.lower() in combined:
                    return True
        return False

    def summary(self) -> str:
        """One-line summary for injection into agent context."""
        items = self.info_leak[:3] + self.no_impact[:2]
        return " | ".join(items) if items else "none"


@dataclass(slots=True)
class DecisionTree:
    """Direction guide — suggests what to look for, never restricts how.

    From article: "Decision tree guides direction, does not limit specific paths."
    """

    branches: list[dict[str, str]] = field(default_factory=list)

    def match(self, context: str) -> str:
        """Return the best direction hint for a given context."""
        context_lower = context.lower()
        for branch in self.branches:
            condition = branch.get("condition", "").lower()
            if condition and condition in context_lower:
                return branch.get("direction", "")
        # Default: search for hidden assets
        for branch in self.branches:
            if "什么都没发现" in branch.get("condition", ""):
                return branch.get("direction", "")
        return ""

    def format_for_prompt(self) -> str:
        """Format as injectable prompt snippet (top 8 to save context)."""
        lines = ["## Direction Guide (decision tree)", ""]
        for branch in self.branches[:8]:
            lines.append(f"- **{branch['condition']}** → {branch['direction']}")
        return "\n".join(lines)


@dataclass(slots=True)
class CheatCard:
    """Minimal rule card injected at key points (direction switch, before report).

    From article: "Key rules at top and bottom. Every line is behavior directive."
    """

    lines: list[str] = field(default_factory=list)

    def format_for_injection(self) -> str:
        if not self.lines:
            return ""
        card = ["[CONSTRAINT CARD — Read before continuing]", ""]
        for line in self.lines:
            card.append(f"> {line}")
        card.append("")
        return "\n".join(card)


# ── Dangerous command patterns ──

@dataclass(slots=True)
class DangerousCommandRule:
    pattern: str
    reason: str


# ── Loading ──

def load_constraints(config_path: str | None = None) -> dict[str, Any]:
    """Load constraint configuration from YAML file."""
    if config_path is None:
        config_path = str(
            Path(__file__).resolve().parent.parent.parent.parent / "config" / "constraints.yaml"
        )

    if not Path(config_path).exists():
        return _default_constraints()

    try:
        with open(config_path, "r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh) or {}
    except Exception:
        return _default_constraints()

    return data


def build_garbage_list(data: dict[str, Any]) -> GarbageFindingList:
    """Build a GarbageFindingList from loaded config data."""
    gf = data.get("garbage_findings", {}) or {}
    if isinstance(gf, dict):
        return GarbageFindingList(
            info_leak=[str(s) for s in gf.get("info_leak", [])],
            no_impact=[str(s) for s in gf.get("no_impact", [])],
            known_safe=[str(s) for s in gf.get("known_safe", [])],
            physical=[str(s) for s in gf.get("physical", [])],
        )
    return GarbageFindingList()


def build_decision_tree(data: dict[str, Any]) -> DecisionTree:
    """Build a DecisionTree from loaded config data."""
    branches = data.get("decision_tree", []) or []
    if isinstance(branches, list):
        return DecisionTree(branches=branches)
    return DecisionTree()


def build_cheat_card(data: dict[str, Any]) -> CheatCard:
    """Build a CheatCard from loaded config data."""
    card_text = str(data.get("cheat_card", "") or "")
    lines = [ln.strip() for ln in card_text.splitlines() if ln.strip()]
    return CheatCard(lines=lines)


def build_dangerous_commands(data: dict[str, Any]) -> list[DangerousCommandRule]:
    """Build dangerous command list from config."""
    rules: list[DangerousCommandRule] = []
    for entry in data.get("dangerous_commands", []) or []:
        if isinstance(entry, dict):
            rules.append(DangerousCommandRule(
                pattern=str(entry.get("pattern", "")),
                reason=str(entry.get("reason", "")),
            ))
    return rules


def _default_constraints() -> dict[str, Any]:
    """Hardcoded defaults when no config file is available."""
    return {
        "garbage_findings": {
            "info_leak": ["版本号暴露", "banner信息泄露", "默认配置路径暴露"],
            "no_impact": ["无PoC的内存访问异常", "无法利用的空指针解引用"],
            "known_safe": ["busybox版本旧但无可利用CVE", "SSL/TLS证书过期"],
            "physical": ["需要物理接触的攻击", "JTAG/SWD接口暴露"],
        },
        "hard_no_report": [
            "无 PoC = 不存在",
            "现象 ≠ 漏洞，漏洞 = 已证明的影响",
        ],
        "decision_tree": [
            {"condition": "SquashFS文件系统 + Web CGI", "direction": "命令注入 / 认证绕过"},
            {"condition": "什么都没发现", "direction": "翻固件内JS/Web文件找隐藏CGI"},
        ],
        "dangerous_commands": [
            {"pattern": "rm\\s+-rf\\s+/", "reason": "危险删除操作"},
        ],
        "cheat_card": "NO POC = NO FINDING\nPHENOMENON != VULN",
        "timing": {
            "direction_timeout_minutes": 20,
            "max_rounds_per_session": 50,
            "idle_timeout_minutes": 10,
        },
    }
