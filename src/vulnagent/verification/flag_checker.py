"""Flag extraction and vulnerability confirmation for CTF solving and vuln discovery."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from vulnagent.core.state import AgentState


@dataclass
class VulnConfirmation:
    """Result of vulnerability confirmation from agent state.

    Checks for PoC evidence, reachable endpoints, credential validation,
    and command-execution indicators — the vuln equivalent of FlagResult.
    """

    confirmed: bool = False
    severity: str = "unknown"
    vuln_type: str = ""
    endpoint: str = ""
    evidence_lines: list[str] = field(default_factory=list)
    confidence: float = 0.0

    def summary(self) -> str:
        if not self.confirmed:
            return "No vulnerability confirmed in this run."
        parts = [f"Vulnerability confirmed: {self.vuln_type or 'unspecified'}"]
        if self.severity and self.severity != "unknown":
            parts.append(f"Severity: {self.severity.upper()}")
        if self.endpoint:
            parts.append(f"Endpoint: {self.endpoint}")
        parts.append(f"Confidence: {self.confidence:.0%}")
        if self.evidence_lines:
            parts.append(f"Evidence: {'; '.join(self.evidence_lines[:3])}")
        return " | ".join(parts)


@dataclass
class FlagResult:
    """Result of flag extraction from agent state."""

    found: bool = False
    flag: str | None = None
    format_valid: bool = False
    extracted_from: str = ""
    confidence: float = 0.0
    candidates: list[str] = field(default_factory=list)


class FlagExtractor:
    """Extract CTF flags from agent outputs using regex patterns.

    Supports common flag formats and custom patterns.

    Usage:
        extractor = FlagExtractor()
        result = extractor.extract("Great! The flag is flag{th1s_1s_4_t3st}")
        print(result.flag)  # "flag{th1s_1s_4_t3st}"
    """

    # Standard flag patterns, ordered by specificity
    FLAG_BODY = r"[^}\s\"'<>\\]{3,200}"
    FLAG_PATTERNS: list[str] = [
        rf"(?<![A-Za-z0-9_])[A-Za-z][A-Za-z0-9_]{{0,31}}[Cc][Tt][Ff]\{{{FLAG_BODY}\}}",  # CustomCTF{flag}
        r"flag\{[^}]{3,}\}",           # flag{...} — minimum 3 chars inside
        r"FLAG\{[^}]{3,}\}",           # FLAG{...}
        r"(?<![A-Za-z0-9_])CTF\{[^}]{3,}\}",            # CTF{...}
        r"(?<![A-Za-z0-9_])ctf\{[^}]{3,}\}",            # ctf{...}
        r"picoCTF\{[^}]+\}",           # picoCTF{...}
        r"HTB\{[^}]+\}",               # HTB{...}
        r"CubeCTF\{[^}]+\}",           # CubeCTF{...}
        r"cube\{[^}]+\}",              # cube{...}
        r"GZCTF\{[^}]+\}",             # GZCTF{...}
        r"gzctf\{[^}]+\}",             # gzctf{...}
        r"DASCTF\{[^}]+\}",            # DASCTF{...}
        r"NSSCTF\{[^}]+\}",            # NSSCTF{...}
        r"ISCC\{[^}]+\}",              # ISCC{...}
        r"CISCN\{[^}]+\}",             # CISCN{...}
        r"hgame\{[^}]+\}",             # hgame{...}
        r"moectf\{[^}]+\}",            # moectf{...}
        r"(?:flag is|flag:)\s*((?:(?:[A-Za-z][A-Za-z0-9_]{0,31}[Cc][Tt][Ff])|flag|FLAG|CTF|ctf|picoCTF|HTB|CubeCTF|cube|GZCTF|DASCTF)\{[^}]{3,}\})",
        # Base64 encoded flags
        r"(?:ZmxhZ3|Q1RGe|Y3Rme)[A-Za-z0-9+/=]{10,}",  # base64 of flag{, CTF{, ctf{
    ]

    # Known false positives to skip
    SKIP_PATTERNS: list[str] = [
        r"flag\{\.\.\.\}",            # placeholder "flag{...}"
        r"flag\{\.\.\}",              # placeholder "flag{..}"
        r"flag\{\s*\}",               # empty brackets
        r"CTF\{\.\.\.\}",             # placeholder "CTF{...}"
    ]

    def __init__(self, custom_patterns: list[str] | None = None) -> None:
        if custom_patterns:
            self._patterns = custom_patterns + self.FLAG_PATTERNS
        else:
            self._patterns = list(self.FLAG_PATTERNS)

    def extract(self, text: str) -> list[str]:
        """Extract all flag candidates from text. Returns list of unique matches."""
        text = re.sub(r"\\[rnt]", " ", text)
        seen: set[str] = set()
        found: list[str] = []
        for pattern in self._patterns:
            matches = re.findall(pattern, text)
            for match in matches:
                if isinstance(match, tuple):
                    match = match[0] if match else ""
                if match and match not in seen:
                    if self._looks_structured_false_positive(match) or self._looks_placeholder_false_positive(match):
                        continue
                    skip = False
                    for skip_pat in self.SKIP_PATTERNS:
                        if re.match(skip_pat, match, re.IGNORECASE):
                            skip = True
                            break
                    if not skip:
                        found.append(match)
                        seen.add(match)
        return [candidate for candidate in found if not any(candidate != other and candidate in other for other in found)]

    @staticmethod
    def _looks_structured_false_positive(candidate: str) -> bool:
        if "{" not in candidate or "}" not in candidate:
            return False
        body = candidate.split("{", 1)[1].rsplit("}", 1)[0]
        return bool(re.search(r"[\s\"'<>\\]", body))

    @staticmethod
    def _looks_placeholder_false_positive(candidate: str) -> bool:
        if "{" not in candidate or "}" not in candidate:
            return False
        body = candidate.split("{", 1)[1].rsplit("}", 1)[0].strip()
        lowered = body.lower()
        if re.fullmatch(r"[\s.。…_-]+", body):
            return True
        if any(token in lowered for token in ("flag_inner", "your_flag", "flag_here", "hash_here")):
            return True
        return bool(re.fullmatch(r"(?:md5|sha1|sha224|sha256|sha384|sha512)\([^)]*(?:flag|inner|content|value)[^)]*\)", lowered))

    def extract_from_state(self, state: AgentState) -> FlagResult:
        """Extract flag from all relevant state fields.

        Checks (in priority order):
        1. final_result field
        2. Messages (last assistant message)
        3. Raw tool outputs
        4. Compressed tool outputs
        5. Anchored summary findings
        """
        final_candidates: list[str] = []
        message_candidates: list[str] = []
        tool_candidates: list[str] = []
        compressed_candidates: list[str] = []
        findings_candidates: list[str] = []

        # 1. final_result
        final = state.get("final_result", "")
        if final:
            final_candidates.extend(self.extract(final))

        # 2. Messages
        for msg in state.get("messages", []):
            content = getattr(msg, "content", "") or ""
            if content:
                message_candidates.extend(self.extract(str(content)))

        # 3. Raw tool outputs
        for output in state.get("tool_outputs", {}).values():
            tool_candidates.extend(self.extract(output))

        # 4. Compressed tool outputs
        for output in state.get("compressed_outputs", {}).values():
            compressed_candidates.extend(self.extract(output))

        # 5. Anchored summary findings
        anchor = state.get("anchored_summary", {})
        findings = anchor.get("findings", "")
        if findings:
            findings_candidates.extend(self.extract(findings))

        trusted_candidates = [
            *final_candidates,
            *tool_candidates,
            *compressed_candidates,
            *findings_candidates,
        ]
        trusted_set = set(trusted_candidates)
        has_tool_evidence = bool(
            state.get("executed_tools")
            or state.get("tool_outputs")
            or state.get("compressed_outputs")
        )
        if trusted_candidates:
            candidates = [
                *trusted_candidates,
                *(candidate for candidate in message_candidates if candidate in trusted_set),
            ]
        elif has_tool_evidence:
            candidates = []
        else:
            candidates = message_candidates

        # Deduplicate
        seen: set[str] = set()
        unique_candidates: list[str] = []
        for c in candidates:
            if c not in seen:
                seen.add(c)
                unique_candidates.append(c)

        # Pick the most likely flag
        best_flag = None
        best_confidence = 0.0
        best_source = ""

        for candidate in unique_candidates:
            confidence = self._flag_confidence(candidate)
            if confidence > best_confidence:
                best_confidence = confidence
                best_flag = candidate

        if best_flag:
            if best_flag in final_candidates:
                best_source = "final_result"
            elif best_flag in tool_candidates:
                best_source = "tool_outputs"
            elif best_flag in compressed_candidates:
                best_source = "compressed_outputs"
            elif best_flag in findings_candidates:
                best_source = "findings"
            elif best_flag in message_candidates:
                best_source = "messages"

        return FlagResult(
            found=best_flag is not None,
            flag=best_flag,
            format_valid=best_flag is not None and self._is_valid_format(best_flag),
            extracted_from=best_source,
            confidence=best_confidence,
            candidates=unique_candidates,
        )

    @staticmethod
    def _flag_confidence(flag: str) -> float:
        """Estimate how likely this is a real flag (0.0-1.0)."""
        score = 0.5  # base
        flag_lower = flag.lower()
        prefix = flag.split("{", 1)[0]
        prefix_lower = prefix.lower()

        # Well-known format
        if prefix_lower == "flag" and re.match(r"flag\{[^}]+\}", flag, re.IGNORECASE):
            score += 0.3
        elif prefix_lower.endswith("ctf") or prefix_lower == "cube" or prefix in {
            "HTB", "DASCTF", "NSSCTF", "ISCC", "CISCN", "hgame", "moectf"
        }:
            score += 0.4
        # Contains typical flag chars
        if re.search(r"[A-Za-z0-9_!@#$%^&*()\-+=\[\]{}|;:',.<>?/]+", flag):
            score += 0.1
        # Too short to be a flag
        if len(flag) < 6:
            score -= 0.3
        # Looks like a common word, not a flag
        if flag_lower in {"test", "flag", "ctf", "example", "admin", "password"}:
            score -= 0.3

        return min(max(score, 0.0), 1.0)

    @staticmethod
    def _is_valid_format(flag: str) -> bool:
        """Check if the flag matches a typical CTF format."""
        if not flag:
            return False
        # Must contain {} or be at least 10 chars with mixed case/numbers
        return bool(re.match(r".*\{.+\}.*", flag)) or bool(
            re.match(r"^(?=.*[a-z])(?=.*[A-Z0-9]).{10,}$", flag)
        )


class FlagValidator:
    """Optional flag validation via submission endpoint."""

    def __init__(self, expected_format: str | None = None) -> None:
        self.expected_format = expected_format

    def validate(self, flag: str) -> bool:
        """Validate a flag against expected format."""
        if not flag:
            return False
        if self.expected_format:
            return bool(re.match(self.expected_format, flag))
        return FlagExtractor._is_valid_format(flag)


class VulnVerifier:
    """Confirm vulnerability findings from agent state — the vuln counterpart of FlagExtractor.

    Scans tool outputs, metadata findings, and compressed evidence for
    PoC success, reachable endpoints, credential validation, and
    command-execution indicators.
    """

    _PROBE_CONFIRMATION_KEYS = {
        "REACHABLE: TRUE",
        "REACHABLE: true",
        "LOGIN SUCCESSFUL",
        "AUTH BYPASS CONFIRMED",
        "UPLOAD ACCEPTED",
        "COMMAND EXECUTION CONFIRMED",
    }

    _POC_CONFIRMATION_KEYS = {
        "POC_SCRIPT_PATH:",
        "POC_VULN_TYPE:",
        "POC_TITLE:",
    }

    _CREDENTIAL_EVIDENCE_KEYS = {
        "credential string:",
        "hardcoded",
        "default password",
        "default credential",
    }

    _SEVERITY_KEYWORDS: dict[str, list[str]] = {
        "critical": [
            "command injection", "rce", "root shell", "unauthenticated",
            "default credential", "remote code execution",
            "buffer overflow", "stack overflow",
        ],
        "high": [
            "auth bypass", "hardcoded credential", "information disclosure",
            "privilege escalation", "config injection",
        ],
        "medium": [
            "version string", "service marker", "path traversal",
            "insecure configuration", "missing authentication",
        ],
        "low": [
            "fingerprint", "recon", "banner", "info leak",
        ],
    }

    def __init__(self) -> None:
        pass

    def confirm_from_state(self, state: AgentState) -> VulnConfirmation:
        """Extract vulnerability confirmation from all state fields."""
        tool_text = self._join_tool_outputs(state)
        metadata = state.get("metadata", {}) or {}
        confirmed_findings = list(metadata.get("confirmed_findings", []))
        validated_leads = list(metadata.get("validated_leads", []))

        evidence_lines: list[str] = []
        confirmed = False
        endpoint = ""
        vuln_type = ""

        # 1. Check probe-level confirmation signals
        for key, value in state.get("tool_outputs", {}).items():
            text = str(value or "")
            for sig in self._PROBE_CONFIRMATION_KEYS:
                if sig in text:
                    confirmed = True
                    evidence_lines.append(f"probe_confirmation: {key} -> {sig.strip()}")
            ep_match = re.search(r"ENDPOINT:\s+([^\r\n]+)", text)
            if ep_match and not endpoint:
                endpoint = ep_match.group(1).strip()
            vt_match = re.search(r"POC_VULN_TYPE:\s+([^\r\n]+)", text)
            if vt_match and not vuln_type:
                vuln_type = vt_match.group(1).strip()

        for key, value in state.get("compressed_outputs", {}).items():
            text = str(value or "")
            for sig in self._PROBE_CONFIRMATION_KEYS:
                if sig in text:
                    confirmed = True
                    evidence_lines.append(f"compressed_confirmation: {key} -> {sig.strip()}")

        # 2. Check for PoC generation evidence
        for sig in self._POC_CONFIRMATION_KEYS:
            if sig in tool_text:
                confirmed = True
                evidence_lines.append(f"poc_generated: {sig}")

        # 3. Check confirmed/validated findings in metadata
        if confirmed_findings:
            confirmed = True
            for finding in confirmed_findings[:3]:
                title = str(finding.get("title", "")).strip()
                if title:
                    evidence_lines.append(f"confirmed_finding: {title}")
                if not vuln_type:
                    vt = str(finding.get("vuln_type", "")).strip()
                    if vt:
                        vuln_type = vt

        if validated_leads:
            confirmed = True
            for lead in validated_leads[:2]:
                title = str(lead.get("title", "")).strip()
                if title:
                    evidence_lines.append(f"validated_lead: {title}")

        # 4. Check credential evidence as secondary signal
        lowered_tool = tool_text.lower()
        for cred_key in self._CREDENTIAL_EVIDENCE_KEYS:
            if cred_key in lowered_tool:
                evidence_lines.append(f"credential_evidence: {cred_key}")
                if not confirmed:
                    confirmed = len(confirmed_findings) > 0 or len(validated_leads) > 0

        # 5. Determine severity
        severity = self._infer_severity(tool_text, confirmed_findings, validated_leads)

        # 6. Calculate confidence
        confidence = 0.0
        if confirmed:
            confidence = 0.6
            if confirmed_findings:
                confidence = 0.9
            elif evidence_lines:
                confidence = 0.7

        return VulnConfirmation(
            confirmed=confirmed,
            severity=severity,
            vuln_type=vuln_type or self._infer_vuln_type(tool_text),
            endpoint=endpoint,
            evidence_lines=evidence_lines,
            confidence=confidence,
        )

    def _join_tool_outputs(self, state: AgentState) -> str:
        parts: list[str] = []
        for mapping in (state.get("tool_outputs", {}), state.get("compressed_outputs", {})):
            for value in (mapping or {}).values():
                parts.append(str(value or ""))
        return "\n".join(parts)

    def _infer_severity(
        self,
        tool_text: str,
        confirmed_findings: list[dict[str, Any]],
        validated_leads: list[dict[str, Any]],
    ) -> str:
        combined = tool_text.lower()
        for finding in [*confirmed_findings, *validated_leads]:
            combined += " " + str(finding.get("title", "")).lower()

        for level, keywords in self._SEVERITY_KEYWORDS.items():
            for kw in keywords:
                if kw in combined:
                    return level
        return "medium"

    def _infer_vuln_type(self, tool_text: str) -> str:
        lowered = tool_text.lower()
        if "command injection" in lowered or "system(" in lowered or "dosystem" in lowered:
            return "command_injection"
        if "hardcoded credential" in lowered or "default password" in lowered or "nvram" in lowered:
            return "hardcoded_credentials"
        if "auth bypass" in lowered or "unauthenticated" in lowered:
            return "auth_bypass"
        if "buffer overflow" in lowered or "strcpy" in lowered:
            return "buffer_overflow"
        return "generic"
