"""Smart Truncation — security-domain keyword-based output compression.

Innovation: a three-tier security keyword system (critical/high/info) with
tool-specific presets. Unlike generic truncation, this preserves security
signals (CVE, flags, injection points) while aggressively discarding noise.

This is part of our Security-Aware Compression DSL (Innovation #1).
"""

from __future__ import annotations

from typing import Any


class SmartTruncator:
    """Intelligent truncation for security tool outputs.

    Uses keyword-based signal detection to preserve security-relevant lines
    while discarding noise (progress bars, banners, HTTP dumps, etc.).

    Usage:
        truncator = SmartTruncator()
        compressed = truncator.truncate(nmap_output, "network_scan", max_tokens=2000)
    """

    # Default security signal keywords with priority levels
    DEFAULT_KEYWORDS: dict[str, list[str]] = {
        "critical": [
            "CVE-", "flag{", "FLAG{", "CTF{",
            "[+]", "[CRITICAL]", "VULNERABLE",
            "SQL injection", "Command injection",
            "Remote Code Execution", "arbitrary file",
            "OSVDB-", "injectable", "is vulnerable",
            "exploitable", "privilege escalation",
        ],
        "high": [
            "HIGH", "open/", "XSS", "LFI", "RFI",
            "CSRF", "authentication bypass",
            "directory traversal", "path traversal",
            "information disclosure", "misconfiguration",
            "WARNING:", "ERROR:",
        ],
        "info": [
            "MEDIUM", "LOW", "INFO:", "Interesting",
            "Notice:", "Note:", "Warning:",
        ],
    }

    # Tool-specific noise patterns to strip
    NOISE_PATTERNS: dict[str, list[str]] = {
        "nmap": [
            "Not shown:", "Service detection performed",
            "Nmap done:", "Initiating ", "Completed ",
            "Stats:", "Scanning ", "Host is up",
            "Scanned at ", "Starting Nmap",
        ],
        "gobuster": [
            "Progress:", "Starting gobuster",
            "Finished", "Error: the server returns",
        ],
        "sqlmap": [
            "legal disclaimer", "Usage of sqlmap",
            "starting at", "ending at", "connected to",
            "testing connection", "do you want to",
            "fetched data logged",
        ],
        "nikto": [
            "Nikto v", "Target IP:", "Target Hostname:",
            "Target Port:", "Start Time:", "End Time:",
            "Scanning:", "Server: No web server",
            "- Nikto finished",
        ],
    }

    def __init__(
        self,
        keyword_presets: dict[str, list[str]] | None = None,
    ) -> None:
        self._keywords: dict[str, list[str]] = dict(self.DEFAULT_KEYWORDS)
        if keyword_presets:
            for level, keywords in keyword_presets.items():
                if level in self._keywords:
                    self._keywords[level].extend(keywords)
                else:
                    self._keywords[level] = list(keywords)

    def truncate(
        self,
        text: str,
        context_type: str = "generic",
        max_tokens: int = 2000,
    ) -> str:
        """Smart-truncate text, preserving security signals.

        Args:
            text: Raw text to compress
            context_type: "network_scan" | "web_scan" | "sql_injection" | "generic"
            max_tokens: Target max tokens for output

        Returns:
            Compressed text with security signals preserved.
        """
        if not text or len(text) < max_tokens * 2:
            return text

        lines = text.split("\n")
        result_lines: list[str] = []
        noise_patterns = self.NOISE_PATTERNS.get(context_type, [])

        for line in lines:
            stripped = line.strip()
            if not stripped:
                continue

            # Check noise first (explicitly discard)
            if self._is_noise(stripped, noise_patterns):
                continue

            # Check signal level
            signal_level = self._detect_signal(stripped)
            if signal_level is not None:
                result_lines.append(stripped)
                continue

            # Keep structure lines (section headers, separators)
            if self._is_structure(stripped):
                result_lines.append(stripped)

        if not result_lines:
            # Fallback: keep first and last portions
            meaningful_lines = [
                l for l in [x.strip() for x in lines if x.strip()]
                if not self._is_noise(l, noise_patterns)
            ]
            keep = max(3, len(meaningful_lines) // 4)
            result_lines = meaningful_lines[:keep] + ["[skip]"] + meaningful_lines[-keep:]

        result = "\n".join(result_lines)
        return self._cap_tokens(result, max_tokens)

    def detect_security_signals(self, text: str) -> list[str]:
        """Identify what types of security signals are present in the text.

        Returns a list of signal type strings: ["flag", "cve", "vulnerability", ...]
        """
        signals: list[str] = []
        text_lower = text.lower()

        signal_checks = {
            "flag": ["flag{", "ctf{"],
            "cve": ["cve-"],
            "vulnerability": ["vulnerability", "is vulnerable", "vulnerable"],
            "exploit": ["exploit", "exploitable"],
            "injection": ["injection", "injectable"],
            "shell": ["shell", "reverse shell", "got shell"],
            "privilege_escalation": ["privilege escalation", "root:"],
            "exposed": ["exposed", "information disclosure"],
            "misconfiguration": ["misconfiguration", "default password"],
        }

        for signal_type, keywords in signal_checks.items():
            if any(kw in text_lower for kw in keywords):
                signals.append(signal_type)

        return signals

    def register_keywords(self, level: str, keywords: list[str]) -> None:
        """Register additional keywords for a signal level."""
        if level not in self._keywords:
            self._keywords[level] = []
        for kw in keywords:
            if kw not in self._keywords[level]:
                self._keywords[level].append(kw)

    # ── Internal ───────────────────────────────────────────────────

    def _detect_signal(self, line: str) -> str | None:
        """Detect the security signal level of a line. Returns None if no signal."""
        line_lower = line.lower()
        # Check from most critical to least
        for level in ["critical", "high", "info"]:
            for kw in self._keywords.get(level, []):
                if kw.lower() in line_lower:
                    return level
        return None

    @staticmethod
    def _is_noise(line: str, noise_patterns: list[str]) -> bool:
        """Check if a line matches a noise pattern."""
        line_lower = line.lower()
        return any(np.lower() in line_lower for np in noise_patterns)

    @staticmethod
    def _is_structure(line: str) -> bool:
        """Check if a line is a structural element worth keeping."""
        return line.startswith("#") or line.startswith("=") or line.startswith("---")

    @staticmethod
    def _cap_tokens(text: str, max_tokens: int) -> str:
        """Rough token capping (~4 chars per token)."""
        max_chars = max_tokens * 4
        if len(text) <= max_chars:
            return text
        half = max_chars // 2
        return (
            text[:half]
            + f"\n\n[... truncated at {max_tokens} token cap, original: {len(text)} chars] ...\n\n"
            + text[-half:]
        )
