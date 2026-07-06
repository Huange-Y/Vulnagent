"""Helpers for structured vulnerability assessment metadata and reporting."""

from __future__ import annotations

import re
from typing import Any

from vulnagent.prompts.remediation_prompts import (
    cwe_for_finding, cvss_score_for_finding,
)


def ensure_run_metadata(
    target: str,
    scope: str,
    provenance: str = "",
    metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    result = dict(metadata or {})
    result.setdefault("target", target)
    result.setdefault("scope", scope)
    result.setdefault("provenance", provenance or _default_provenance(target))
    result.setdefault("execution_mode", "operator-directed")
    result.setdefault("candidate_findings", [])
    result.setdefault("confirmed_findings", [])
    result.setdefault("validated_leads", [])
    result.setdefault("evidence_log", [])
    result.setdefault("priority_targets", [])
    result.setdefault("next_steps", [])
    result.setdefault("sub_agents_findings", [])
    return result


def make_finding(
    title: str,
    stage: str,
    source: str,
    severity: str = "unknown",
    status: str = "candidate",
    evidence: list[str] | None = None,
    component_path: str = "",
    *,
    poc_path: str = "",
    cvss_score: str = "",
    cvss_vector: str = "",
    cwe_id: str = "",
    remediation: list[str] | None = None,
    impact: str = "",
) -> dict[str, Any]:
    result: dict[str, Any] = {
        "title": title,
        "stage": stage,
        "source": source,
        "severity": severity,
        "status": status,
        "evidence": list(evidence or []),
        "component_path": component_path,
    }
    if poc_path:
        result["poc_path"] = poc_path
    if cvss_score:
        result["cvss_score"] = cvss_score
    if cvss_vector:
        result["cvss_vector"] = cvss_vector
    if cwe_id:
        result["cwe_id"] = cwe_id
    if remediation:
        result["remediation"] = list(remediation)
    if impact:
        result["impact"] = impact
    return result


def make_priority_target(
    title: str,
    *,
    priority: str,
    validation_focus: str,
    evidence: list[str] | None = None,
    paths: list[str] | None = None,
    status: str = "queued",
) -> dict[str, Any]:
    return {
        "title": title,
        "priority": priority,
        "validation_focus": validation_focus,
        "evidence": list(evidence or []),
        "paths": list(paths or []),
        "status": status,
    }


def build_report_sections(
    target: str,
    scope: str,
    provenance: str,
    confirmed_findings: list[dict[str, Any]] | None = None,
    validated_leads: list[dict[str, Any]] | None = None,
    candidate_findings: list[dict[str, Any]] | None = None,
    evidence: list[str] | None = None,
    priority_targets: list[dict[str, Any]] | None = None,
    next_steps: list[str] | None = None,
    *,
    poc_entries: list[str] | None = None,
    remediation_blocks: str = "",
) -> str:
    confirmed_findings = list(confirmed_findings or [])
    validated_leads = list(validated_leads or [])
    candidate_findings = list(candidate_findings or [])
    evidence = list(evidence or [])
    priority_targets = list(priority_targets or [])
    next_steps = list(next_steps or [])
    poc_entries = list(poc_entries or [])
    confirmed_lines = _bullet_lines(_format_finding_titles(confirmed_findings)) or "- None confirmed"
    validated_lines = _bullet_lines([item.get("title", "") for item in validated_leads]) or "- None"
    candidate_lines = _bullet_lines([item.get("title", "") for item in candidate_findings]) or "- None"
    evidence_lines = _bullet_lines(evidence) or "- None recorded"
    target_lines = _format_priority_targets(priority_targets) or "- None prioritized"
    poc_lines = "\n".join(poc_entries) if poc_entries else "- No PoC scripts generated."
    remediation_lines = remediation_blocks if remediation_blocks else "- No remediation advice generated."
    next_lines = _bullet_lines(
        _build_validation_closure_lines(
            confirmed_findings=confirmed_findings,
            validated_leads=validated_leads,
            candidate_findings=candidate_findings,
            evidence=evidence,
            next_steps=next_steps,
        )
    ) or "- Validation closed with no additional residual notes."
    return (
        "## Executive Summary\n"
        f"Target: {target}\n\n"
        "## Scope\n"
        f"{scope or '(not provided)'}\n\n"
        "## Provenance\n"
        f"{provenance or _default_provenance(target)}\n\n"
        "## Confirmed Findings\n"
        f"{confirmed_lines}\n\n"
        "## Validated Leads\n"
        f"{validated_lines}\n\n"
        "## Unconfirmed Leads\n"
        f"{candidate_lines}\n\n"
        "## Supporting Evidence\n"
        f"{evidence_lines}\n\n"
        "## Priority Targets\n"
        f"{target_lines}\n\n"
        "## Proof of Concept\n"
        f"{poc_lines}\n\n"
        "## Remediation\n"
        f"{remediation_lines}\n\n"
        "## Validation Closure\n"
        f"{next_lines}"
    )


def _default_provenance(target: str) -> str:
    if "://" in target:
        return f"live:{target}"
    return f"artifact:{target}"


def _bullet_lines(items: list[str]) -> str:
    return "\n".join(f"- {item}" for item in items if item)


def _format_finding_titles(findings: list[dict[str, Any]]) -> list[str]:
    """Format finding titles with CVSS/CWE annotations for the report."""
    lines: list[str] = []
    for item in findings:
        if not isinstance(item, dict):
            continue
        title = str(item.get("title", "")).strip()
        if not title:
            continue
        parts = [title]
        cwe = str(item.get("cwe_id", "")).strip()
        cvss = str(item.get("cvss_score", "")).strip()
        cvss_vector = str(item.get("cvss_vector", "")).strip()
        severity = str(item.get("severity", "")).strip()
        annotations: list[str] = []
        if cwe:
            annotations.append(cwe)
        if cvss:
            annotations.append(f"CVSS {cvss}")
        if cvss_vector:
            annotations.append(cvss_vector)
        if severity and severity != "unknown":
            annotations.append(severity.upper())
        if annotations:
            parts.append(f"({' | '.join(annotations)})")
        poc = str(item.get("poc_path", "")).strip()
        if poc:
            parts.append(f"\n    PoC: {poc}")
        remediation = item.get("remediation", [])
        if remediation:
            for r in remediation[:2]:
                parts.append(f"\n    Fix: {r[:120]}")
        lines.append("".join(parts))
    return lines


def _format_priority_targets(targets: list[dict[str, Any]]) -> str:
    lines: list[str] = []
    for item in targets:
        if not isinstance(item, dict):
            continue
        title = str(item.get("title", "")).strip()
        if not title:
            continue
        priority = str(item.get("priority", "")).strip() or "unknown"
        focus = str(item.get("validation_focus", "")).strip()
        body = f"[{priority}] {title}"
        if focus:
            body += f" - {focus}"
        lines.append(f"- {body}")
    return "\n".join(lines)


def _build_validation_closure_lines(
    *,
    confirmed_findings: list[dict[str, Any]],
    validated_leads: list[dict[str, Any]],
    candidate_findings: list[dict[str, Any]],
    evidence: list[str],
    next_steps: list[str],
) -> list[str]:
    lines: list[str] = []
    titles = [str(item.get("title", "")).strip() for item in validated_leads if str(item.get("title", "")).strip()]
    if confirmed_findings:
        lines.append("This run produced at least one directly validated finding.")
    if titles:
        for title in titles:
            lines.append(f"Validation boundary recorded: {title}.")
    lowered_evidence = [str(item).strip().lower() for item in evidence if str(item).strip()]
    if any(item.startswith("validated endpoint:") for item in lowered_evidence):
        lines.append("An emulated service endpoint was reached and used during validation.")
    elif any(item.startswith("system-mode package:") for item in lowered_evidence):
        lines.append("The run reached system-mode emulation packaging, but a stable reachable validation service was not established in the current environment.")
    if not confirmed_findings and candidate_findings:
        lines.append("High-risk leads remain unconfirmed after the static and emulation-backed validation available in this run.")
    if not lines and next_steps:
        lines.append("This run completed without a confirmed exploit path; residual review items remain evidence-backed but unconfirmed.")
    return list(dict.fromkeys(line for line in lines if line.strip()))


def format_recent_tool_history(executed_tools: list[dict[str, Any]], limit: int = 8) -> str:
    lines: list[str] = []
    for entry in reversed(list(executed_tools or [])):
        if len(lines) >= limit:
            break
        if not isinstance(entry, dict):
            continue
        name = str(entry.get("name", "")).strip()
        if not name:
            continue
        args_text = _format_tool_args(entry.get("args"))
        status = "ok" if entry.get("success", True) else "failed"
        summary = " ".join(str(entry.get("result_summary", "")).split())[:140]
        line = f"- {name}"
        if args_text:
            line += f"({args_text})"
        line += f" [{status}]"
        if summary:
            line += f" -> {summary}"
        lines.append(line)
    return "\n".join(lines) or "- none"


def format_current_tool_evidence(compressed_outputs: dict[str, Any], limit: int = 8) -> str:
    if not isinstance(compressed_outputs, dict):
        return "- none"

    items: list[tuple[str, str]] = []
    for key, value in compressed_outputs.items():
        name = str(key or "").strip()
        text = str(value or "").strip()
        if not name or not text:
            continue
        items.append((name, text))

    def sort_key(item: tuple[str, str]) -> tuple[int, str]:
        name = item[0]
        if name == "firmware_extract_summary":
            return (0, name)
        if name == "firmware_web_surface_map":
            return (1, name)
        if name.startswith("firmware_read_path:"):
            return (2, name)
        if name.startswith("firmware_search:"):
            return (3, name)
        if name in {"file_identify", "binwalk_scan", "strings_extract"}:
            return (4, name)
        return (5, name)

    lines: list[str] = []
    for name, text in sorted(items, key=sort_key):
        if len(lines) >= limit:
            break
        preview = _format_tool_evidence_preview(name, text)
        if preview:
            lines.append(f"- {name}: {preview}")
    return "\n".join(lines) or "- none"


def _format_tool_args(args: Any) -> str:
    if not isinstance(args, dict):
        return ""
    preferred_keys = ("path", "inner_path", "pattern", "target", "url", "mode")
    parts: list[str] = []
    for key in preferred_keys:
        value = str(args.get(key, "")).strip()
        if value:
            parts.append(f"{key}={value}")
    return ", ".join(parts[:4])


def _format_tool_evidence_preview(name: str, text: str, max_chars: int = 220) -> str:
    preview_lines: list[str] = []
    for raw_line in str(text or "").splitlines():
        line = " ".join(raw_line.split()).strip()
        if not line:
            continue
        if name == "firmware_web_surface_map":
            if not line.startswith(("TEXT_ROUTE:", "BINARY_ROUTE:", "ROUTE_CORRELATION:", "BINARY_MARKER:")):
                continue
        elif name.startswith("firmware_search:"):
            if not line.startswith(("MATCH:", "MATCH_COUNT:", "NO_MATCHES")):
                continue
        preview_lines.append(line)
        if len(preview_lines) >= 3:
            break

    if not preview_lines:
        preview_lines = [
            " ".join(line.split()).strip()
            for line in str(text or "").splitlines()
            if str(line).strip()
        ][:3]

    preview = " | ".join(preview_lines)
    return preview[:max_chars]


def extract_latest_ai_text(messages: list[Any]) -> str:
    """Recover the latest assistant conclusion even if a follow-up nudge was appended."""
    for message in reversed(messages):
        type_name = type(message).__name__
        if "AI" not in type_name and "Assistant" not in type_name:
            continue
        content = str(getattr(message, "content", "") or "").strip()
        if content:
            return content
    return ""


def is_substantive_ai_text(text: str) -> bool:
    normalized = " ".join((text or "").strip().split())
    if not normalized:
        return False
    if len(normalized) < 12:
        return False
    lowered = normalized.lower().strip(".! ")
    if lowered in {
        "ok",
        "okay",
        "great",
        "great work",
        "sounds good",
        "done",
        "understood",
        "got it",
    }:
        return False
    word_count = len([part for part in re.split(r"\s+", normalized) if part])
    return word_count >= 3 or len(normalized) >= 24


def normalize_ai_summary_text(text: str) -> str:
    lines = [line.strip() for line in str(text or "").splitlines()]
    while lines and _is_trivial_ai_line(lines[0]) and len(lines) > 1:
        lines.pop(0)
    normalized = "\n".join(line for line in lines if line).strip()
    if _is_continuation_offer_text(normalized):
        return ""
    for prefix in ("Good - ", "Good: ", "OK - ", "Ok - ", "Okay - "):
        if normalized.startswith(prefix):
            normalized = normalized[len(prefix) :].strip()
            break
    return normalized


def is_actionable_validation_text(text: str) -> bool:
    normalized = " ".join(normalize_ai_summary_text(text).split())
    if not is_substantive_ai_text(normalized):
        return False
    lowered = normalized.lower()
    if "promising" in lowered or "worth deeper review" in lowered:
        return False
    if _is_continuation_offer_text(normalized):
        return False
    patterns = [
        r"\b(?:auth|login|credential|password|telnet|upload|goahead|command|cgi|shell|bypass|execution|rce|xss|sqli|csrf|lfi|overflow|unauthenticated|authenticated|hardcoded|default credentials?)\b",
        r"\bCVE-\d{4}-\d{4,}\b",
    ]
    return any(re.search(pattern, normalized, re.IGNORECASE) for pattern in patterns)


def _is_trivial_ai_line(text: str) -> bool:
    lowered = " ".join((text or "").strip().split()).lower().strip(".! ")
    return lowered in {
        "ok",
        "okay",
        "great",
        "great work",
        "sounds good",
        "done",
        "understood",
        "got it",
        "summary confirmed",
    }


def _is_continuation_offer_text(text: str) -> bool:
    lowered = " ".join((text or "").strip().split()).lower()
    return (
        "if you want" in lowered
        and ("i can continue" in lowered or "i can proceed" in lowered)
    ) or (
        "if you want" in lowered
        and ("continue the firmware assessment" in lowered or "continue with the firmware assessment" in lowered)
    ) or (
        "if you want me to proceed" in lowered
        and "pick new paths/files to inspect" in lowered
    ) or (
        "next useful targets" in lowered
        and "if you want" in lowered
    ) or (
        "if you want" in lowered
        and "continue enumerating" in lowered
    ) or (
        "i'm ready to continue" in lowered
        or "i am ready to continue" in lowered
    ) or (
        "what would you like me to do next" in lowered
    ) or (
        "just tell me what area you want next" in lowered
    )


def collect_artifact_observations(tool_outputs: dict[str, str]) -> dict[str, list[Any]]:
    """Turn low-level artifact tool output into stable candidate findings and evidence."""
    joined = "\n".join(
        f"[{key}]\n{value}"
        for key, value in tool_outputs.items()
        if value
    )
    lowered = joined.lower()

    findings: list[dict[str, Any]] = []
    confirmed_findings: list[dict[str, Any]] = []
    validated_leads: list[dict[str, Any]] = []
    evidence: list[str] = []
    priority_targets: list[dict[str, Any]] = []
    next_steps: list[str] = []
    seen_titles: set[str] = set()
    seen_confirmed_titles: set[str] = set()
    seen_validated_titles: set[str] = set()
    seen_targets: set[str] = set()

    def add_finding(
        title: str,
        *,
        severity: str,
        evidence_lines: list[str] | None = None,
    ) -> None:
        if title in seen_titles:
            return
        findings.append(
            make_finding(
                title=title,
                stage="discovery",
                source="artifact",
                severity=severity,
                evidence=evidence_lines or [],
            )
        )
        seen_titles.add(title)

    def add_confirmed_finding(
        title: str,
        *,
        severity: str,
        evidence_lines: list[str] | None = None,
    ) -> None:
        if title in seen_confirmed_titles:
            return
        confirmed_findings.append(
            make_finding(
                title=title,
                stage="validation",
                source="artifact",
                severity=severity,
                status="confirmed",
                evidence=evidence_lines or [],
            )
        )
        seen_confirmed_titles.add(title)

    def add_validated_lead(
        title: str,
        *,
        severity: str,
        evidence_lines: list[str] | None = None,
    ) -> None:
        if title in seen_validated_titles:
            return
        validated_leads.append(
            make_finding(
                title=title,
                stage="validation",
                source="artifact",
                severity=severity,
                status="validated",
                evidence=evidence_lines or [],
            )
        )
        seen_validated_titles.add(title)

    def add_evidence(line: str) -> None:
        line = line.strip()
        if line and line not in evidence:
            evidence.append(line)

    def add_priority_target(
        title: str,
        *,
        priority: str,
        validation_focus: str,
        evidence_lines: list[str] | None = None,
        paths: list[str] | None = None,
    ) -> None:
        if title in seen_targets:
            return
        priority_targets.append(
            make_priority_target(
                title,
                priority=priority,
                validation_focus=validation_focus,
                evidence=evidence_lines or [],
                paths=paths or [],
            )
        )
        seen_targets.add(title)

    if "squashfs" in lowered:
        title = "Embedded SquashFS filesystem detected"
        add_finding(title, severity="medium", evidence_lines=["SquashFS marker present in artifact scan output."])
        add_evidence("filesystem marker: SquashFS")
        next_steps.append("Extract the SquashFS root filesystem and review init scripts, web assets, and credentials.")

    if "uimage header" in lowered:
        add_finding(
            "Embedded uImage firmware container detected",
            severity="medium",
            evidence_lines=["uImage header present in artifact scan output."],
        )
        add_evidence("container marker: uImage")

    jffs2_count = lowered.count("jffs2 filesystem marker")
    if jffs2_count >= 2:
        add_finding(
            "Embedded JFFS2 marker cluster detected",
            severity="medium",
            evidence_lines=[f"JFFS2 marker count observed: {jffs2_count}"],
        )
        add_evidence(f"filesystem marker: JFFS2 x{jffs2_count}")
    elif jffs2_count == 1:
        add_finding(
            "Embedded JFFS2 filesystem marker detected",
            severity="low",
            evidence_lines=["JFFS2 marker present in artifact scan output."],
        )
        add_evidence("filesystem marker: JFFS2")

    if "gzip compressed data" in lowered:
        add_finding(
            "Embedded gzip-compressed payload detected",
            severity="low",
            evidence_lines=["gzip marker present in artifact scan output."],
        )
        add_evidence("compression marker: gzip")

    if "xz compressed data" in lowered:
        add_finding(
            "Embedded XZ-compressed payload detected",
            severity="low",
            evidence_lines=["XZ marker present in artifact scan output."],
        )
        add_evidence("compression marker: XZ")

    for pattern, label, severity in (
        (r"BusyBox v?(\d+(?:\.\d+){1,3}[A-Za-z0-9._-]*)", "BusyBox", "medium"),
        (r"lighttpd/(\d+(?:\.\d+){1,3}[A-Za-z0-9._-]*)", "lighttpd", "medium"),
        (r"dropbear(?:multi)?[ /-]?(\d+(?:\.\d+){1,3}[A-Za-z0-9._-]*)", "dropbear", "medium"),
    ):
        for match in re.finditer(pattern, joined, re.IGNORECASE):
            version = match.group(1)
            add_finding(
                f"{label} version string present: {version}",
                severity=severity,
                evidence_lines=[match.group(0)],
            )
            add_evidence(f"version string: {match.group(0)}")

    credential_match = re.search(
        r"\b(admin|root|user|guest):([A-Za-z0-9_!@#$%^&*().-]{3,})\b",
        joined,
    )
    if credential_match:
        pair = credential_match.group(0)
        add_finding(
            "Default or hardcoded credential indicator present",
            severity="high",
            evidence_lines=[pair],
        )
        add_evidence(f"credential string: {pair}")
        next_steps.append("Review extracted passwd/shadow files and web login handlers for hardcoded or default credentials.")
        add_priority_target(
            "Review default credential path and login handlers",
            priority="high",
            validation_focus="Confirm whether the credential indicator is active in login handlers, configuration exports, or shipped defaults.",
            evidence_lines=[pair],
            paths=["/etc_ro/web/dir_login.asp", "/etc/passwd", "/etc/shadow"],
        )

    if "/etc/shadow" in joined or "/etc/passwd" in joined:
        add_finding(
            "Credential store path references present in artifact strings",
            severity="medium",
            evidence_lines=[
                line
                for line in ("/etc/passwd", "/etc/shadow")
                if line in joined
            ],
        )
        if "/etc/passwd" in joined:
            add_evidence("path reference: /etc/passwd")
        if "/etc/shadow" in joined:
            add_evidence("path reference: /etc/shadow")

    service_markers = {
        "GoAhead-Webs": "Embedded GoAhead web administration marker present",
        "miniupnpd": "Embedded UPnP service marker present",
        "dropbearmulti": "Embedded Dropbear SSH service marker present",
    }
    for marker, title in service_markers.items():
        if marker.lower() in lowered:
            add_finding(title, severity="medium", evidence_lines=[marker])
            add_evidence(f"service marker: {marker}")

    if "/bin/goahead" in joined or "goahead" in lowered:
        add_finding(
            "Embedded GoAhead web administration binary present",
            severity="medium",
            evidence_lines=["GoAhead binary or service markers identified in artifact content."],
        )
        if "/bin/goahead" in joined:
            add_evidence("path reference: /bin/goahead")
        elif "goahead" in lowered:
            add_evidence("service marker: goahead")

    rcS_telnet_seen = (
        ("text_hit: /etc_ro/rcs ::" in lowered and "telnetd" in lowered)
        or ("[firmware_read_path:/etc_ro/rcs]" in lowered and "telnetd" in lowered)
    )
    if rcS_telnet_seen:
        add_finding(
            "Boot script starts telnetd during initialization",
            severity="high",
            evidence_lines=["/etc_ro/rcS contains a telnetd invocation."],
        )
        add_evidence("boot script marker: /etc_ro/rcS -> telnetd")
        next_steps.append("Confirm whether telnetd is enabled by default in emulation or on the running device.")
        add_priority_target(
            "Validate telnet enablement and management path",
            priority="high",
            validation_focus="Determine whether telnet starts unconditionally, what toggles it, and whether the web UI can enable it without strong auth checks.",
            evidence_lines=["/etc_ro/rcS :: telnetd", "form2Telnet.cgi"],
            paths=["/etc_ro/rcS", "/etc_ro/web/d_telnet.asp", "/bin/goahead"],
        )

    telnet_factory_enabled = (
        "telnetenabled=1" in lowered
        and "telnetenabled=0" in lowered
        and "form2telnet.cgi" in lowered
        and rcS_telnet_seen
    )
    if telnet_factory_enabled:
        add_finding(
            "Factory configuration enables telnet management before login hardening",
            severity="high",
            evidence_lines=[
                "telnetEnabled=1",
                "telnetEnabled=0",
                "/goform/form2Telnet.cgi",
                "/etc_ro/rcS :: telnetd",
            ],
        )
        add_evidence("config marker: telnetEnabled=1")
        add_priority_target(
            "Confirm factory telnet exposure path",
            priority="critical",
            validation_focus="Determine whether factory-reset or imported settings can re-enable telnet while rcS still launches telnetd during boot.",
            evidence_lines=["telnetEnabled=1", "form2Telnet.cgi", "telnetd"],
            paths=[
                "/etc_ro/rcS",
                "/etc_ro/web/d_telnet.asp",
                "/etc_ro/Wireless/RT2860AP/RT2860_factory_vlan",
                "/etc_ro/Wireless/RT2860AP/RT2860_default_vlan",
            ],
        )

    if "text_hit: /etc_ro/inittab ::" in lowered and "ttys1::respawn:/bin/sh" in lowered:
        add_finding(
            "Serial console shell respawn configuration present",
            severity="medium",
            evidence_lines=["/etc_ro/inittab respawns /bin/sh on ttyS1."],
        )
        add_evidence("console marker: ttyS1::respawn:/bin/sh")

    upload_markers = [
        "/etc_ro/web/cgi-bin/upload.cgi",
        "upload_settings.cgi",
        "upload_torrent.cgi",
        "upload_bootloader.cgi",
    ]
    if any(marker.lower() in lowered for marker in upload_markers):
        add_finding(
            "Firmware web upload handlers present",
            severity="medium",
            evidence_lines=[marker for marker in upload_markers if marker.lower() in lowered],
        )
        for marker in upload_markers:
            if marker.lower() in lowered:
                add_evidence(f"upload surface: {marker}")
        next_steps.append("Review upload handlers for authentication, path handling, and command execution paths.")
        add_priority_target(
            "Review firmware upload attack surface",
            priority="high",
            validation_focus="Trace authentication, file validation, storage paths, and any post-upload execution or import logic for firmware/config upload handlers.",
            evidence_lines=[marker for marker in upload_markers if marker.lower() in lowered],
            paths=[
                "/etc_ro/web/cgi-bin/upload.cgi",
                "/etc_ro/web/cgi-bin/upload_settings.cgi",
                "/etc_ro/web/cgi-bin/upload_torrent.cgi",
                "/etc_ro/web/cgi-bin/upload_bootloader.cgi",
                "/bin/goahead",
            ],
        )

    upload_exec_signals = [
        "/var/webupload",
        "/var/tmpcgi",
        "upload.cgi.c",
        "tempnam",
        "import_5g",
    ]
    if any(signal.lower() in lowered for signal in upload_exec_signals) and "system" in lowered:
        matched_upload_signals = [signal for signal in upload_exec_signals if signal.lower() in lowered]
        add_finding(
            "Upload handler binaries expose system/import execution markers",
            severity="high",
            evidence_lines=["system", *matched_upload_signals],
        )
        for signal in matched_upload_signals:
            add_evidence(f"upload binary marker: {signal}")
        add_priority_target(
            "Trace upload handler execution and import workflow",
            priority="critical",
            validation_focus="Confirm how upload handlers stage files, invoke import logic, and whether attacker-controlled content can reach command execution or unsafe configuration import paths.",
            evidence_lines=["system", *matched_upload_signals],
            paths=[
                "/etc_ro/web/cgi-bin/upload.cgi",
                "/etc_ro/web/cgi-bin/upload_bootloader.cgi",
                "/etc_ro/web/cgi-bin/upload_settings.cgi",
                "/etc_ro/web/cgi-bin/upload_torrent.cgi",
            ],
        )

    if "form2telnet.cgi" in lowered or "/etc_ro/web/d_telnet.asp" in joined:
        add_finding(
            "Telnet management web surface present",
            severity="medium",
            evidence_lines=[marker for marker in ("form2Telnet.cgi", "/etc_ro/web/d_telnet.asp") if marker.lower() in lowered],
        )
        if "form2telnet.cgi" in lowered:
            add_evidence("telnet UI marker: form2Telnet.cgi")
        if "/etc_ro/web/d_telnet.asp" in joined:
            add_evidence("path reference: /etc_ro/web/d_telnet.asp")

    route_lines = re.findall(r"(?:TEXT_ROUTE|BINARY_ROUTE|ROUTE_CORRELATION):\s+([^\n]+)", joined, re.IGNORECASE)
    if route_lines:
        add_finding(
            "Firmware web route relationships extracted",
            severity="medium",
            evidence_lines=route_lines[:6],
        )
        for line in route_lines[:10]:
            add_evidence(f"route map: {line}")

    if "goform/formlogin" in lowered or "/etc_ro/web/dir_login.asp" in joined:
        add_priority_target(
            "Trace login flow and credential sources",
            priority="high",
            validation_focus="Map the login form, credential lookup, and post-auth redirect flow to see whether defaults, hidden accounts, or bypasses are plausible.",
            evidence_lines=[marker for marker in ("goform/formLogin", "/etc_ro/web/dir_login.asp") if marker.lower() in lowered],
            paths=["/etc_ro/web/dir_login.asp", "/bin/goahead"],
        )

    if 'echo "$1:$2" > /tmp/tmpchpw' in joined and "chpasswd < /tmp/tmpchpw" in joined:
        add_finding(
            "Password change helper pipes user-controlled credentials into chpasswd",
            severity="medium",
            evidence_lines=['echo "$1:$2" > /tmp/tmpchpw', "chpasswd < /tmp/tmpchpw"],
        )
        add_evidence("credential update helper: /sbin/chpasswd.sh")
        add_priority_target(
            "Review password update and credential management path",
            priority="medium",
            validation_focus="Determine which routes or binaries call chpasswd.sh and whether user-controlled values can alter credentials without robust authorization checks.",
            evidence_lines=["/tmp/tmpchpw", "chpasswd"],
            paths=["/sbin/chpasswd.sh", "/usr/sbin/chpasswd", "/bin/goahead", "/sbin/internet.sh"],
        )

    if (
        "login=`nvram_get 2860 login`" in lowered
        and "pass=`nvram_get 2860 password`" in lowered
        and 'echo "$login::0:0:adminstrator:/:/bin/sh" > /etc/passwd' in lowered
        and "chpasswd.sh $login $pass" in lowered
    ):
        add_finding(
            "Boot script materializes an administrator shell account from NVRAM credentials",
            severity="high",
            evidence_lines=[
                "login=`nvram_get 2860 Login`",
                "pass=`nvram_get 2860 Password`",
                'echo "$login::0:0:Adminstrator:/:/bin/sh" > /etc/passwd',
                "chpasswd.sh $login $pass",
            ],
        )
        add_evidence("nvram credential marker: /sbin/internet.sh -> /etc/passwd")
        add_priority_target(
            "Trace NVRAM-backed admin credential generation",
            priority="critical",
            validation_focus="Determine whether web configuration, imports, or recovery flows can set Login/Password values that become a shell-capable account at boot.",
            evidence_lines=[
                "nvram_get 2860 Login",
                "nvram_get 2860 Password",
                "/etc/passwd",
                "chpasswd.sh $login $pass",
            ],
            paths=["/sbin/internet.sh", "/sbin/chpasswd.sh", "/etc/passwd", "/etc_ro/web/dir_login.asp"],
        )

    if 'filename="config.img"' in lowered and "ralink_init show 2860" in lowered:
        add_finding(
            "Configuration export script exposes raw settings dump behavior",
            severity="medium",
            evidence_lines=['filename="config.img"', "ralink_init show 2860"],
        )
        add_evidence("config export marker: config.img")
        add_priority_target(
            "Review configuration export and secret exposure",
            priority="medium",
            validation_focus="Determine whether configuration export is authenticated and whether exported settings expose credentials, keys, or tokens that enable follow-on compromise.",
            evidence_lines=["config.img", "ralink_init show 2860"],
            paths=["/etc_ro/web/cgi-bin/ExportSettings.sh", "/etc_ro/web/cgi-bin/upload_settings.cgi"],
        )

    if "/etc_ro/web/cgi-bin/reboot.sh" in joined and "reboot &" in lowered:
        add_finding(
            "Web reboot handler script present",
            severity="low",
            evidence_lines=["/etc_ro/web/cgi-bin/reboot.sh", "reboot &"],
        )
        add_evidence("reboot handler marker: /etc_ro/web/cgi-bin/reboot.sh")

    system_command_markers = [
        "showSystemCommandASP",
        "SystemCommand",
        "repeatLastSystemCommand",
        "doSystem",
        "doSystembk",
    ]
    matched_command_markers = [marker for marker in system_command_markers if marker.lower() in lowered]
    if matched_command_markers:
        add_finding(
            "GoAhead system-command management surface markers present",
            severity="high",
            evidence_lines=matched_command_markers,
        )
        for marker in matched_command_markers:
            add_evidence(f"goahead command marker: {marker}")
        next_steps.append("Trace the GoAhead system-command handlers to confirm whether authenticated command execution is reachable.")
        add_priority_target(
            "Map GoAhead command handlers and auth gates",
            priority="critical",
            validation_focus="Identify which ASP/CGI routes reach the GoAhead system-command functions and whether they inherit authentication or request filtering.",
            evidence_lines=matched_command_markers,
            paths=["/bin/goahead", "/etc_ro/web/dir_login.asp", "/etc_ro/web/d_telnet.asp"],
        )
        if "route_correlation: /cgi-bin/upload.cgi" in lowered:
            add_priority_target(
                "Correlate upload routes with GoAhead bindings",
                priority="high",
                validation_focus="Use the route map to determine which web pages and binaries reference upload handlers, then trace the auth and execution path end to end.",
                evidence_lines=["ROUTE_CORRELATION: /cgi-bin/upload.cgi"],
                paths=["/bin/goahead", "/etc_ro/web/d_upload.asp", "/etc_ro/web/cgi-bin/upload.cgi"],
            )

    if "[firmware_emulation_launch_system]" in lowered or "package_path:" in lowered:
        package_match = re.search(r"PACKAGE_PATH:\s+([^\r\n]+)", joined, re.IGNORECASE)
        qemu_match = re.search(r"QEMU_BINARY:\s+([^\r\n]+)", joined, re.IGNORECASE)
        attempted_kernel_match = re.search(r"ATTEMPT_\d+_COMMAND:\s+.*?\s-kernel\s+([^\r\n]+)", joined, re.IGNORECASE)
        kernel_match = attempted_kernel_match or re.search(r"KERNEL_CANDIDATE:\s+([^\r\n]+)", joined, re.IGNORECASE)
        stderr_lines = re.findall(r"ATTEMPT_\d+_STDERR:\s+([^\r\n]+)", joined, re.IGNORECASE)

        emulation_evidence: list[str] = []
        if package_match:
            emulation_evidence.append(package_match.group(1).strip())
        if qemu_match:
            emulation_evidence.append(qemu_match.group(1).strip())
        if kernel_match:
            emulation_evidence.append(kernel_match.group(1).strip())
        emulation_evidence.extend(line.strip() for line in stderr_lines[:3] if line.strip())

        add_finding(
            "System-mode firmware emulation package prepared",
            severity="medium",
            evidence_lines=emulation_evidence,
        )
        if package_match:
            add_evidence(f"system-mode package: {package_match.group(1).strip()}")
        if qemu_match:
            add_evidence(f"system-mode qemu: {qemu_match.group(1).strip()}")
        if kernel_match:
            add_evidence(f"system-mode kernel candidate: {kernel_match.group(1).strip()}")
        for line in stderr_lines[:3]:
            normalized = line.strip()
            if normalized:
                add_evidence(f"system-mode stderr: {normalized}")
        next_steps.append(
            "System-mode emulation packaging completed, but kernel and machine assumptions still blocked a stable validation endpoint in this run."
        )
        add_priority_target(
            "Validate system-mode kernel candidate selection",
            priority="high",
            validation_focus="Determine which carved kernel artifact is loadable by QEMU and whether machine or endianness assumptions need adjustment.",
            evidence_lines=emulation_evidence[:4],
            paths=[
                path
                for path in (
                    package_match.group(1).strip() if package_match else "",
                    kernel_match.group(1).strip() if kernel_match else "",
                )
                if path
            ],
        )

    if any("version string:" in item for item in evidence):
        next_steps.append("Validate whether the exposed component versions are outdated in the vendor context.")

    probe_endpoint_match = re.search(r"PROBE_ENDPOINT:\s+([^\r\n]+)", joined, re.IGNORECASE)
    endpoint_match = re.search(r"ENDPOINT:\s+([^\r\n]+)", joined, re.IGNORECASE)
    validation_endpoint = ""
    if endpoint_match:
        validation_endpoint = endpoint_match.group(1).strip()
    elif probe_endpoint_match:
        validation_endpoint = probe_endpoint_match.group(1).strip()

    probe_summary_match = re.search(r"SUMMARY:\s+([^\r\n]+)", joined, re.IGNORECASE)
    probe_details_match = re.search(r"DETAILS:\s+([^\r\n]+)", joined, re.IGNORECASE)
    backend_match = re.search(r"EXECUTION_BACKEND:\s+([^\r\n]+)", joined, re.IGNORECASE)
    backend_name = backend_match.group(1).strip() if backend_match else ""

    if "reachable: true" in lowered and validation_endpoint:
        evidence_lines = [
            item
            for item in [
                validation_endpoint,
                probe_summary_match.group(1).strip() if probe_summary_match else "",
                probe_details_match.group(1).strip() if probe_details_match else "",
                backend_name,
            ]
            if item
        ]
        add_confirmed_finding(
            "Emulated firmware service reachable for validation",
            severity="high",
            evidence_lines=evidence_lines,
        )
        add_evidence(f"validated endpoint: {validation_endpoint}")
        if probe_summary_match:
            add_evidence(f"probe summary: {probe_summary_match.group(1).strip()}")
        if backend_name:
            add_evidence(f"execution backend: {backend_name}")
        next_steps.append(
            "A reachable emulated endpoint was obtained and used for protocol-aware validation in this run."
        )
    elif ("package_path:" in lowered or "qemu_binary:" in lowered) and "reachable: true" not in lowered:
        evidence_lines = [
            item
            for item in [
                validation_endpoint,
                probe_summary_match.group(1).strip() if probe_summary_match else "",
                probe_details_match.group(1).strip() if probe_details_match else "",
                backend_name,
            ]
            if item
        ]
        add_validated_lead(
            "Firmware emulation validation requires a stronger runtime environment",
            severity="medium",
            evidence_lines=evidence_lines,
        )
        add_evidence(f"validation gap endpoint: {validation_endpoint}")
        if backend_name:
            add_evidence(f"execution backend: {backend_name}")
        next_steps.append(
            "Active exploit verification could not complete because the current runtime environment did not expose a stable reachable service."
        )

    _enrich_findings_metadata(findings)
    _enrich_findings_metadata(confirmed_findings)
    _enrich_findings_metadata(validated_leads)

    return {
        "findings": findings,
        "confirmed_findings": confirmed_findings,
        "validated_leads": validated_leads,
        "evidence": evidence,
        "priority_targets": priority_targets,
        "next_steps": list(dict.fromkeys(next_steps)),
    }


def merge_report_text(
    report_text: str,
    *,
    target: str,
    scope: str,
    provenance: str,
    confirmed_findings: list[dict[str, Any]],
    validated_leads: list[dict[str, Any]] | None = None,
    candidate_findings: list[dict[str, Any]] | None = None,
    evidence: list[str] | None = None,
    priority_targets: list[dict[str, Any]] | None = None,
    next_steps: list[str] | None = None,
    poc_entries: list[str] | None = None,
    remediation_blocks: str = "",
) -> str:
    """Merge free-form report text with canonical structured sections."""
    text = (report_text or "").strip()
    validated_leads = list(validated_leads or [])
    candidate_findings = list(candidate_findings or [])
    evidence = list(evidence or [])
    priority_targets = list(priority_targets or [])
    next_steps = list(next_steps or [])
    poc_entries = list(poc_entries or [])
    fallback = build_report_sections(
        target=target,
        scope=scope,
        provenance=provenance,
        confirmed_findings=confirmed_findings,
        validated_leads=validated_leads,
        candidate_findings=candidate_findings,
        evidence=evidence,
        priority_targets=priority_targets,
        next_steps=next_steps,
        poc_entries=poc_entries,
        remediation_blocks=remediation_blocks,
    )
    if not text:
        return fallback

    summary_body = _extract_markdown_section_body(text, "## Executive Summary")
    if not summary_body:
        summary_body = _strip_managed_markdown_sections(text).strip()
    if not summary_body:
        summary_body = f"Target: {target}\nNo free-form executive summary was preserved from the report agent output."

    # Use greedy extraction: LLM may put sub-headers right after Remediation
    llm_poc = _extract_markdown_section_body_greedy(text, "## Proof of Concept")
    llm_remediation = _extract_markdown_section_body_greedy(text, "## Remediation")

    structured_poc = "\n".join(poc_entries) if poc_entries else ""
    structured_remediation = remediation_blocks if remediation_blocks else ""

    poc_body = structured_poc or llm_poc or "- No PoC scripts generated."
    remediation_body = structured_remediation or llm_remediation or "- No remediation advice generated."

    sections = [
        ("## Executive Summary", summary_body),
        ("## Scope", f"{scope or '(not provided)'}"),
        ("## Provenance", provenance or _default_provenance(target)),
        (
            "## Confirmed Findings",
            _bullet_lines(_format_finding_titles(confirmed_findings)) or "- None confirmed",
        ),
        (
            "## Validated Leads",
            _bullet_lines([item.get("title", "") for item in validated_leads]) or "- None",
        ),
        (
            "## Unconfirmed Leads",
            _bullet_lines([item.get("title", "") for item in candidate_findings]) or "- None",
        ),
        ("## Supporting Evidence", _bullet_lines(evidence) or "- None recorded"),
        ("## Priority Targets", _format_priority_targets(priority_targets) or "- None prioritized"),
        ("## Proof of Concept", poc_body),
        ("## Remediation", remediation_body),
        (
            "## Validation Closure",
            _bullet_lines(
                _build_validation_closure_lines(
                    confirmed_findings=confirmed_findings,
                    validated_leads=validated_leads,
                    candidate_findings=candidate_findings,
                    evidence=evidence,
                    next_steps=next_steps,
                )
            ) or "- Validation closed with no additional residual notes.",
        ),
    ]
    return "\n\n".join(f"{header}\n{body}".strip() for header, body in sections)


def _extract_markdown_section_body_greedy(text: str, header: str) -> str:
    """Extract section body greedily — skip immediate sub-headers (###) after the header.

    Unlike _extract_markdown_section_body, this does not stop at the next ## header.
    It captures all content from the header to the end of text, handling the case
    where the LLM emits sub-headings right after the section header.
    """
    escaped = re.escape(header)
    pattern = rf"(?s)^{escaped}\s*\n(.*)$"
    match = re.search(pattern, text.strip())
    if not match:
        return ""
    body = str(match.group(1)).strip()
    if not body:
        return ""
    # If the body starts with ## (sub-headers from LLM), we still keep it
    # But trim off anything after the last known reporting header
    # Trim at "## Validation Closure" or end of text
    closure_match = re.search(r"(?m)^##\s+Validation\s+Closure", body)
    if closure_match:
        body = body[:closure_match.start()].strip()
    return body


def _extract_markdown_section_body(text: str, header: str) -> str:
    pattern = rf"(?ms)^{re.escape(header)}\s*\n(.*?)(?=^##\s+\S|\Z)"
    match = re.search(pattern, text.strip())
    if not match:
        return ""
    return str(match.group(1)).strip()


def _strip_managed_markdown_sections(text: str) -> str:
    managed_headers = (
        "## Executive Summary",
        "## Scope",
        "## Provenance",
        "## Confirmed Findings",
        "## Validated Leads",
        "## Unconfirmed Leads",
        "## Supporting Evidence",
        "## Priority Targets",
        "## Proof of Concept",
        "## Remediation",
        "## Validation Closure",
    )
    stripped = text.strip()
    for header in managed_headers:
        stripped = re.sub(
            rf"(?ms)^{re.escape(header)}\s*\n.*?(?=^##\s+\S|\Z)",
            "",
            stripped,
        ).strip()
    return stripped


def _enrich_findings_metadata(findings_list: list[dict[str, Any]]) -> None:
    """Add CWE/CVSS metadata to each finding dict in-place using remediation templates."""
    for finding in findings_list:
        if not isinstance(finding, dict):
            continue
        title = str(finding.get("title", "")).strip()
        evidence = list(finding.get("evidence", []))
        if not title:
            continue
        try:
            finding.setdefault("cwe_id", cwe_for_finding(finding))
            finding.setdefault("cvss_score", cvss_score_for_finding(finding))
        except Exception:
            pass


def collect_xml_tagged_findings(messages: list[Any]) -> list[dict[str, Any]]:
    """Parse XML-tagged findings from agent messages.

    Scans the final assistant message for <finding>...</finding> blocks
    (DCRH-style structured output) and converts them into finding dicts
    compatible with make_finding().

    Handles multiple findings in one message (separated by blank lines
    or consecutive <finding> blocks).
    """
    from vulnagent.utils.xml_tags import find_tagged_message, extract_finding_from_text

    text = find_tagged_message(messages, "finding")
    if not text or "<finding>" not in text:
        return []

    # Split on <finding> boundaries to handle multiple findings
    parts = re.split(r"(?=<finding>)", text)
    findings: list[dict[str, Any]] = []
    seen: set[str] = set()

    for part in parts:
        if "<finding>" not in part:
            continue
        parsed = extract_finding_from_text(part)
        title = parsed.get("finding", "").strip()
        if not title or title in seen:
            continue
        seen.add(title)

        evidence_text = parsed.get("evidence", "").strip()
        evidence_lines = [evidence_text] if evidence_text else []

        finding_entry = make_finding(
            title=title,
            stage="discovery" if "exploit" not in text.lower() else "validation",
            source="xml_tagged",
            severity=parsed.get("severity", "medium").strip() or "medium",
            status="candidate",
            evidence=evidence_lines,
            component_path=parsed.get("component_path", ""),
        )

        # Enrich with vuln type -> CWE mapping
        vuln_type = parsed.get("vuln_type", "").strip().lower()
        if vuln_type:
            finding_entry["vuln_type"] = vuln_type
            finding_entry.setdefault("cwe_id", _vuln_type_to_cwe(vuln_type))

        # Dup check is preservation-only -- the agent already self-policed
        dup_check = parsed.get("dup_check", "").strip()
        if dup_check:
            finding_entry["dup_check"] = dup_check

        # Reachability
        reachability = parsed.get("reachability", "").strip()
        if reachability:
            finding_entry["reachability"] = reachability

        findings.append(finding_entry)

    _enrich_findings_metadata(findings)
    return findings


def collect_xml_tagged_verdict(messages: list[Any]) -> dict[str, Any] | None:
    """Parse a 5-criterion grader verdict from agent messages.

    Returns None if no <overall> tag found.
    """
    from vulnagent.utils.xml_tags import find_tagged_message, extract_verdict_from_text

    text = find_tagged_message(messages, "overall")
    if not text or "<overall>" not in text:
        return None
    return extract_verdict_from_text(text)


def collect_report_grading(messages: list[Any]) -> dict[str, Any] | None:
    """Parse a report self-grading from agent messages.

    Returns None if no <rubric_score> tag found.
    """
    from vulnagent.utils.xml_tags import find_tagged_message, extract_report_grading_from_text

    text = find_tagged_message(messages, "rubric_score")
    if not text or "<rubric_score>" not in text:
        return None
    return extract_report_grading_from_text(text)


_VULN_TYPE_CWE_MAP: dict[str, str] = {
    "command_injection": "CWE-78",
    "hardcoded_credentials": "CWE-798",
    "auth_bypass": "CWE-306",
    "config_import": "CWE-502",
    "buffer_overflow": "CWE-120",
    "generic": "CWE-0",
}


def _vuln_type_to_cwe(vuln_type: str) -> str:
    return _VULN_TYPE_CWE_MAP.get(vuln_type.strip().lower(), "CWE-0")
