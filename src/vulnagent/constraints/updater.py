"""Constraints auto-update module.

Records false positive rejections and suggests/flushes new patterns
to constraints.yaml for continuous improvement of the noise filter.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml


@dataclass
class FalsePositiveRecord:
    title: str
    category: str
    reason: str
    timestamp: float = 0.0


@dataclass
class ConstraintUpdater:
    """Accumulates false positives and flushes to constraints.yaml."""

    _pending: list[FalsePositiveRecord] = field(default_factory=list)
    _config_path: str = ""

    def __init__(self, config_path: str | None = None) -> None:
        if config_path is None:
            config_path = str(
                Path(__file__).resolve().parent.parent.parent.parent
                / "config" / "constraints.yaml"
            )
        self._config_path = config_path
        self._pending = []

    def record(self, title: str, category: str, reason: str = "") -> None:
        """Record a false positive for later flushing."""
        import time
        self._pending.append(FalsePositiveRecord(
            title=title.strip().lower(),
            category=category or self._suggest_category(title),
            reason=reason,
            timestamp=time.time(),
        ))

    def flush(self, dry_run: bool = True) -> list[str]:
        """Write pending patterns to constraints.yaml.

        Args:
            dry_run: If True, return patterns without writing.

        Returns:
            List of newly added pattern strings.
        """
        if not self._pending:
            return []

        try:
            with open(self._config_path, "r", encoding="utf-8") as fh:
                config = yaml.safe_load(fh) or {}
        except Exception:
            config = {}

        existing = set()
        for cat_data in (config.get("garbage_findings") or {}).values():
            if isinstance(cat_data, list):
                for item in cat_data:
                    existing.add(str(item).strip().lower())

        added: list[str] = []
        for record in self._pending:
            normalized = record.title.strip().lower()
            if normalized and normalized not in existing:
                added.append(record.title)
                existing.add(normalized)
                category_key = self._category_key(record.category)
                config.setdefault("garbage_findings", {}).setdefault(category_key, [])
                if record.title not in config["garbage_findings"][category_key]:
                    config["garbage_findings"][category_key].append(record.title)

        if added and not dry_run:
            try:
                with open(self._config_path, "w", encoding="utf-8") as fh:
                    yaml.safe_dump(config, fh, default_flow_style=False, allow_unicode=True, sort_keys=False)
            except Exception:
                pass

        self._pending.clear()
        return added

    @property
    def pending_count(self) -> int:
        return len(self._pending)

    @staticmethod
    def _suggest_category(title: str) -> str:
        t = title.lower()
        if any(kw in t for kw in ("version", "banner", "header", "info leak", "disclosure", "timestamp")):
            return "info_leak"
        if any(kw in t for kw in ("null", "dos", "oom", "assert", "debug", "dead code", "race")):
            return "no_impact"
        if any(kw in t for kw in ("busybox", "dropbear", "ssl", "cert", "cipher", "snmp", "upnp", "mdns")):
            return "known_safe"
        if any(kw in t for kw in ("jtag", "uart", "physical", "console", "spi", "recovery")):
            return "physical"
        if any(kw in t for kw in ("system()", "strcpy", "gets()", "sprintf", "memcpy", "function name")):
            return "binary_analysis_noise"
        return "iot_false_positives"

    @staticmethod
    def _category_key(category: str) -> str:
        mapping = {
            "info_leak": "info_leak", "no_impact": "no_impact",
            "known_safe": "known_safe", "physical": "physical",
            "iot_false_positives": "iot_false_positives",
            "binary_analysis_noise": "binary_analysis_noise",
        }
        return mapping.get(category, "iot_false_positives")
