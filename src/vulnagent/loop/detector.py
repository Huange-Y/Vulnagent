"""Loop failure detector — three failure modes from the article.

1. Direction drift: context shifts away from current focus
2. Rule forgetting: long sessions → constraints decay
3. Pseudo-completion: "inventing" a vuln after no real progress
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum


def _split_sentences(text: str) -> list[str]:
    """Split text into sentences for negation analysis."""
    return [s.strip() for s in re.split(r"[.!?\n]+", text) if s.strip()]


def _trigrams(text: str) -> list[str]:
    """Extract character trigrams for fuzzy semantic similarity."""
    clean = re.sub(r"\s+", " ", text).strip()
    return [clean[i:i+3] for i in range(len(clean) - 2)]


class FailureMode(Enum):
    DIRECTION_DRIFT = "direction_drift"
    RULE_FORGETTING = "rule_forgetting"
    PSEUDO_COMPLETION = "pseudo_completion"
    NONE = "none"


@dataclass
class FailureSignal:
    mode: FailureMode
    confidence: float = 0.0
    evidence: str = ""
    suggested_action: str = ""


class FailureDetector:
    """Detects loop failure modes from agent behavior signals.

    Uses keyword trigram similarity for semantic comparison between
    consecutive outputs, plus negation-aware drift detection.
    """

    DRIFT_CONFIDENCE_THRESHOLD = 0.6
    FORGETTING_ROUND_THRESHOLD = 25

    DRIFT_KEYWORDS: dict[str, list[str]] = {
        # Agent phase names (from orchestrator)
        "brainstorm": [
            "execute", "shell", "curl", "python_exec", "nuclei",
            "nmap_scan", "gobuster",  # brainstorming should not be running tools heavily
        ],
        "discovery": [
            "exploit", "generate_poc", "reverse_shell", "shellcode",
            "rop", "payload",  # discovery should surface assets, not build exploits
        ],
        "exploit": [
            "nmap", "gobuster", "nikto", "whatweb", "sslscan",
            "strings_extract", "binwalk_scan",  # exploit should not rescan basics
        ],
        "verification": [
            "nmap", "gobuster", "whatweb", "sslscan",  # verification should verify, not discover
        ],
        "report": [
            "nmap_scan", "gobuster_scan", "python_exec", "curl_request",
            "generate_poc",  # report should compile findings, not run more tools
        ],
        # Vulnerability direction names (from decision tree)
        "command_injection": ["http", "nmap", "port", "ssl", "cors", "header"],
        "buffer_overflow": ["http", "upload", "login", "cookie", "cors"],
        "hardcoded_credentials": ["buffer", "overflow", "stack", "heap"],
        "auth_bypass": ["buffer", "nmap", "strings", "binwalk"],
    }

    def __init__(self) -> None:
        self._direction_switch_count: int = 0
        self._last_direction: str = ""
        self._empty_rounds: int = 0
        self._recent_output_hashes: list[int] = []

    def reset(self) -> None:
        self._direction_switch_count = 0
        self._last_direction = ""
        self._empty_rounds = 0
        self._recent_output_hashes.clear()

    def record_direction_switch(self, new_direction: str) -> None:
        self._direction_switch_count += 1
        self._last_direction = new_direction

    def detect(
        self,
        direction: str,
        recent_outputs: list[str],
        round_count: int,
        direction_elapsed: float,
        session_elapsed: float,
    ) -> FailureSignal:
        drift = self._detect_direction_drift(direction, recent_outputs, round_count)
        forget = self._detect_rule_forgetting(round_count, session_elapsed)
        pseudo = self._detect_pseudo_completion(recent_outputs, round_count, direction_elapsed)
        signals = [drift, forget, pseudo]
        signals.sort(key=lambda s: s.confidence, reverse=True)
        best = signals[0]
        if best.confidence > 0.3:
            return best
        return FailureSignal(mode=FailureMode.NONE)

    def _detect_direction_drift(
        self, direction: str, recent_outputs: list[str], round_count: int,
    ) -> FailureSignal:
        if not direction or round_count < 3:
            return FailureSignal(mode=FailureMode.NONE)
        direction_key = direction.lower().replace(" ", "_").replace("/", "_")
        drift_keywords = self.DRIFT_KEYWORDS.get(direction_key, [])
        if not drift_keywords:
            return FailureSignal(mode=FailureMode.NONE)
        combined = " ".join(recent_outputs).lower() if recent_outputs else ""
        if not combined:
            return FailureSignal(mode=FailureMode.NONE)
        # Negation-aware: strip sentences with "not"/"should not"/"avoid"
        cleaned = " ".join(
            sent for sent in _split_sentences(combined)
            if not any(neg in sent for neg in (" not ", "shouldn", "avoid ", "skip ", "do not ", "don't "))
        ) or combined
        drift_hits = sum(1 for kw in drift_keywords if kw in cleaned)
        drift_ratio = drift_hits / len(drift_keywords) if drift_keywords else 0
        if drift_ratio >= 0.35:
            return FailureSignal(
                mode=FailureMode.DIRECTION_DRIFT,
                confidence=min(drift_ratio, 0.95),
                evidence=f"Output contains {drift_hits}/{len(drift_keywords)} drift keywords (negation-aware)",
                suggested_action="Re-read task description. Inject decision tree.",
            )
        return FailureSignal(mode=FailureMode.NONE)

    def _detect_rule_forgetting(
        self, round_count: int, session_elapsed: float,
    ) -> FailureSignal:
        if round_count < self.FORGETTING_ROUND_THRESHOLD:
            return FailureSignal(mode=FailureMode.NONE)
        extra = round_count - self.FORGETTING_ROUND_THRESHOLD
        confidence = min(0.3 + extra * 0.02, 0.9)
        return FailureSignal(
            mode=FailureMode.RULE_FORGETTING,
            confidence=confidence,
            evidence=f"Session at round {round_count}, elapsed {session_elapsed:.0f}s",
            suggested_action="Inject cheat card. Consider restart if >50 rounds.",
        )

    def _detect_pseudo_completion(
        self, recent_outputs: list[str], round_count: int, direction_elapsed: float,
    ) -> FailureSignal:
        if round_count < 5:
            return FailureSignal(mode=FailureMode.NONE)
        combined = " ".join(recent_outputs).lower() if recent_outputs else ""
        if not combined:
            self._empty_rounds += 1
            if self._empty_rounds >= 3:
                return FailureSignal(
                    mode=FailureMode.PSEUDO_COMPLETION,
                    confidence=0.6 + self._empty_rounds * 0.05,
                    evidence=f"{self._empty_rounds} empty rounds",
                    suggested_action="Force direction switch. Verify PoC exists.",
                )
            return FailureSignal(mode=FailureMode.NONE)
        self._empty_rounds = 0
        # Trigram fingerprint for semantic similarity (vs brittle raw hash)
        trigrams = set(_trigrams(combined[:800]))
        self._recent_output_hashes.append(hash(frozenset(trigrams)))
        if len(self._recent_output_hashes) > 10:
            self._recent_output_hashes.pop(0)
        unique = len(set(self._recent_output_hashes))
        if len(self._recent_output_hashes) >= 6 and unique <= 3:
            vuln_words = sum(1 for kw in ("vulnerability", "finding", "bug", "overflow", "injection", "bypass") if kw in combined)
            cleaned = combined
            for neg in ("no poc", "without poc", "lacks poc", "missing poc", "no proof of concept", "without proof"):
                cleaned = cleaned.replace(neg, "")
            has_poc = any(kw in cleaned for kw in ("curl ", "qemu-", "#!/", "reproduce", "exploit:", "executable_command", "poc", "proof of concept"))
            if vuln_words > 1 and not has_poc:
                return FailureSignal(
                    mode=FailureMode.PSEUDO_COMPLETION,
                    confidence=0.7,
                    evidence="Semantically similar outputs without PoC evidence",
                    suggested_action="Require concrete PoC before accepting finding.",
                )
        return FailureSignal(mode=FailureMode.NONE)
