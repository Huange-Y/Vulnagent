"""CVE dedup + false-positive filter for vulnagent findings.

Pass 1 — False-positive filter: remove busybox symlinks, C libraries,
          standard daemons, kernel modules, confd/PAM/pppd plugins.
Pass 2 — Known-CVE cross-reference against vendor CVE knowledge base.

Integrates into orchestrator pipeline after verification, before report.
"""

from __future__ import annotations

import re
import time as _time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


# ═══════════════════════════════════════════════════════════════
# False-positive patterns
# ═══════════════════════════════════════════════════════════════

_BUSYBOX_SYMLINKS: set[str] = {
    "dd", "cp", "df", "ln", "ls", "mv", "ps", "rm", "sh", "vi", "ash",
    "cat", "pwd", "sed", "tar", "date", "echo", "grep", "gzip", "kill",
    "lock", "nice", "ping", "sync", "true", "zcat", "netstat", "gunzip",
    "hostname", "mktemp", "netmsg", "dnsdomainname", "chgrp", "chmod",
    "chown", "dmesg", "egrep", "false", "fgrep", "fsync", "login",
    "mkdir", "mknod", "mount", "pidof", "ping6", "rmdir", "sleep",
    "touch", "uname", "umount", "usleep", "awk", "basename", "bunzip2",
    "bzcat", "clear", "cmp", "crontab", "cut", "dirname", "du", "env",
    "expr", "find", "free", "head", "hexdump", "hostid", "id", "killall",
    "less", "logger", "lspci", "lsusb", "md5sum", "mesg", "mkfifo",
    "nc", "nohup", "nslookup", "passwd", "pgrep", "pkill", "printf",
    "readlink", "renice", "reset", "seq", "sort", "strings", "tail",
    "taskset", "tee", "telnet", "test", "tftp", "time", "top", "tr",
    "traceroute", "traceroute6", "uniq", "unzip", "uptime", "wc",
    "wget", "which", "xargs", "yes", "[", "[[",
}

_LIBRARY_FPS: set[str] = {
    "libc-2.19.so", "libc.so.6", "libpthread-2.19.so", "libpthread.so.0",
    "libpython2.7.so.1.0", "libstdc++.so.6", "libstdc++.so.6.0.19",
    "libglib-2.0.so.0.4101.0", "libgio-2.0.so", "libgio-2.0.so.0",
    "libgio-2.0.so.0.4101.0", "libxml2.so", "libxml2.so.2", "libxml2.so.2.9.2",
    "liblua.so.5.1.5", "libcrypto.so.1.0.0", "libdb-4.7.so",
    "libexpat.so.1.5.2", "libsmartcols.so.1", "libsmartcols.so.1.1.0",
    "libwrap.so.0.7.6", "libzebra.so.0", "libzebra.so.0.0.0",
    "libblkid.so.1.1.0", "libbsd.so.0.3.0", "libbsd.so.0", "libbsd.so",
    "libperl.so", "libqmi-glib.so.1.1.0", "libusb-1.0.so.0.1.0",
    "libusb-1.0.so.0", "libusb-1.0.so", "libfstools.so", "libboardinfo.so",
    "liboperdata_api.so", "liblicenseclient.so", "libshared.so",
    "libmiscu.so", "libconfd.so", "libunittest.so",
    "pyexpat.so", "_bsddb.so", "_socket.so", "POSIX.so", "Socket.so",
    "pam_authorize.so", "pam_krb5.so", "pam_ldap.so", "pam_localdb.so",
    "pam_pwhistory.so", "pam_radius_auth.so", "pam_rhosts.so",
    "pam_exec.so", "pam_mkhomedir.so", "pam_unix.so",
    "libstrongswan-eap-radius.so", "libstrongswan.so.0.0.0",
    "libstrongswan.so.0", "libcharon.so.0.0.0",
    "authorize.so", "radius.so",
    "crypt-hash", "mmap_schema", "confd_aaa_bridge", "confdexec", "heart",
    "yang_parser_nif.so", "child_setup",
    "libdcplugin_example_ldns_opendns_deviceid.so",
    "sudo_noexec.so", "sudoers.so",
}

_SYSTEM_TOOL_FPS: set[str] = {
    "busybox", "crond", "syslog-ng", "dropbear", "dropbearkey", "dbclient",
    "scp", "ssh", "ntpd", "rdate", "telnetd", "dnsmasq", "pppd", "pptpd",
    "racoon", "tcpdump", "init", "procd", "mdev", "hotplug2", "jffs2reset",
    "mtd", "ldconfig", "ifconfig", "route", "brctl", "vconfig", "slattach",
    "nameif", "switch_root", "pivot_root", "poweroff", "reboot", "halt",
    "hwclock", "mke2fs", "mkfs.ext2", "mkswap", "fdisk", "start-stop-daemon",
    "udhcpc", "devmem", "arp", "sysctl", "blkid", "chroot", "watchquagga",
    "hping3", "kadmin.local", "sendmail", "mcproxy", "lldpd", "vtysh",
    "comgt", "strace", "objcopy", "strip", "sadf", "sar", "sqlite3",
    "visudo", "sudo", "uwsgi", "nginx", "haserl",
    "boardutil", "ktutil", "qmicli", "uqmi", "decomp_server",
    "ip6tables-uci", "iptables-uci",
    # Additional OpenWrt system tools
    "netifd", "opkg", "ubus", "ubusd", "askfirst", "jshn",
    "mutt", "smidump", "snmpd",  # standard utilities
}

_CONFD_FPS: set[str] = {
    "confd", "confd.smp", "confd_cmd", "confd_load", "maapi",
}

_SAFE_WRAPPERS: set[str] = {
    "ucicfg", "ucicfg_license", "ucicfg_network", "ucicfg_security",
    "ucicfg_system", "ucicfg_aaa", "ucicfg_hook", "ucicfg_init",
}


def is_false_positive(finding: dict[str, Any]) -> tuple[bool, str]:
    """Return (is_fp, reason) for a single finding."""
    component = str(finding.get("component_path", "")).replace("\\", "/")
    binary_path = str(finding.get("binary_path", "")).replace("\\", "/")
    title = str(finding.get("title", ""))

    name = Path(component).name or Path(binary_path).name
    name_lower = name.lower()

    if any(name_lower.endswith(ext) for ext in (".ko",)):
        return True, "kernel_module"
    if name_lower in _BUSYBOX_SYMLINKS:
        return True, "busybox_symlink"
    if name_lower in _LIBRARY_FPS:
        return True, "system_library"
    if name_lower in _SYSTEM_TOOL_FPS:
        return True, "system_tool"
    if name_lower in _CONFD_FPS:
        return True, "confd_infrastructure"
    if name_lower in _SAFE_WRAPPERS:
        return True, "safe_wrapper"

    # Pattern-based filters
    if "/lib/" in component and (".so" in name_lower or ".so." in name_lower):
        return True, "shared_library_path"
    if "/confd/" in component or "/erts/" in component:
        return True, "confd_internal"
    if "/perl5/" in component or "/python2." in component:
        return True, "scripting_extension"
    if "/pppd/" in component:
        return True, "pppd_plugin"
    if "/security/" in component and name_lower.startswith("pam_"):
        return True, "pam_module"
    if "/ipsec/plugins/" in component:
        return True, "ipsec_plugin"
    if "/sudo/" in component and name_lower.endswith(".so"):
        return True, "sudo_plugin"
    if "/dnscrypt-proxy/" in component:
        return True, "dnscrypt_plugin"

    return False, ""


# ═══════════════════════════════════════════════════════════════
# Known-CVE knowledge base
# ═══════════════════════════════════════════════════════════════

@dataclass
class KnownCve:
    cve_id: str
    cvss_score: float
    severity: str
    summary: str
    affected_binaries: list[str] = field(default_factory=list)
    fixed_in: str = ""


_CISCO_RV_CVES: list[KnownCve] = [
    KnownCve("CVE-2022-20707", 10.0, "CRITICAL",
             "Command injection in upload.cgi /upload handler. "
             "destination multipart field → popen(). pwn2own 2021.",
             ["upload.cgi"], "1.0.03.26"),
    KnownCve("CVE-2022-20705", 10.0, "CRITICAL",
             "Session ID traversal auth bypass. sessionid=../../www/index.html.",
             [], "1.0.03.26"),
    KnownCve("CVE-2022-20712", 10.0, "CRITICAL",
             "Upload module RCE in /form-file-upload. uwsgi 127.0.0.1:9003.",
             [], "1.0.03.26"),
    KnownCve("CVE-2022-20827", 9.0, "CRITICAL",
             "Web filter DB update cmd injection in wfapp. XML filename→popen().",
             ["wfapp"], "1.0.03.28"),
    KnownCve("CVE-2022-20841", 9.0, "CRITICAL",
             "Open PnP command injection.", [], "1.0.03.28"),
    KnownCve("CVE-2022-20842", 9.0, "CRITICAL",
             "Web management unauthenticated RCE+DoS.", [], "1.0.03.28"),
    KnownCve("CVE-2021-1609", 9.8, "CRITICAL",
             "Web management unauthenticated RCE.", [], "1.0.03.22"),
    KnownCve("CVE-2021-1610", 7.2, "HIGH",
             "Web management authenticated cmd injection.", [], "1.0.03.22"),
    KnownCve("CVE-2021-1472", 9.8, "CRITICAL",
             "Auth bypass in jsonrpc.cgi.", ["jsonrpc.cgi"], "1.0.03.21"),
    KnownCve("CVE-2021-1473", 9.8, "CRITICAL",
             "RCE in web management (chain with CVE-2021-1472).",
             ["jsonrpc.cgi"], "1.0.03.21"),
    KnownCve("CVE-2020-3451", 7.3, "HIGH",
             "Unauthenticated cmd injection (restricted user).", [], "1.0.03.20"),
    KnownCve("CVE-2020-3453", 7.3, "HIGH",
             "Unauthenticated RCE boundary check.", [], "1.0.03.20"),
    KnownCve("CVE-2024-20470", 7.2, "HIGH",
             "Authenticated RCE post-EOL UNPATCHED. Requires admin creds.",
             ["upload.cgi"], ""),
    KnownCve("CVE-2024-20416", 6.5, "MEDIUM",
             "Upload module authenticated RCE post-EOL UNPATCHED. CWE-130.",
             ["upload.cgi"], ""),
    KnownCve("CVE-2024-20393", 8.8, "HIGH",
             "Info disclosure → guest-to-admin privesc post-EOL.", [], ""),
    KnownCve("CVE-2024-20381", 8.8, "HIGH",
             "Authenticated RCE post-EOL.", [], ""),
    KnownCve("CVE-2025-32433", 10.0, "CRITICAL",
             "Erlang/OTP SSH RCE. Affects ConfD. Not Cisco-specific.",
             ["confd", "confd.smp"], ""),
]

_VENDOR_KB: dict[str, list[KnownCve]] = {"cisco": _CISCO_RV_CVES}


# ═══════════════════════════════════════════════════════════════
# Dedup engine
# ═══════════════════════════════════════════════════════════════

@dataclass
class DedupVerdict:
    finding: dict[str, Any]
    is_false_positive: bool = False
    fp_reason: str = ""
    matched_cves: list[KnownCve] = field(default_factory=list)
    verdict: str = "potential_0day"
    verdict_detail: str = ""


@dataclass
class DedupReport:
    total_findings: int = 0
    false_positives: list[DedupVerdict] = field(default_factory=list)
    known_cve_findings: list[DedupVerdict] = field(default_factory=list)
    potential_0day: list[DedupVerdict] = field(default_factory=list)
    vendor: str = ""
    product: str = ""
    duration_s: float = 0.0

    def summary_text(self) -> str:
        lines = [
            "CVE Dedup Report",
            "================",
            f"Total: {self.total_findings}  FalsePositives: {len(self.false_positives)}",
            f"Known CVEs: {len(self.known_cve_findings)}  Potential 0day: {len(self.potential_0day)}",
            "",
        ]
        if self.potential_0day:
            lines.append("--- POTENTIAL 0DAY ---")
            for v in self.potential_0day:
                t = str(v.finding.get("title", ""))[:120]
                cp = str(v.finding.get("component_path", ""))
                lines.append(f"  [{v.finding.get('severity', '?')}] {t}")
                lines.append(f"       component: {cp}")
            lines.append("")
        if self.known_cve_findings:
            lines.append("--- KNOWN CVEs ---")
            for v in self.known_cve_findings[:10]:
                t = str(v.finding.get("title", ""))[:100]
                ids = ", ".join(c.cve_id for c in v.matched_cves)
                lines.append(f"  {t} → {ids}")
        return "\n".join(lines)


def _match_cves(finding: dict[str, Any], cves: list[KnownCve]) -> list[KnownCve]:
    component = str(finding.get("component_path", ""))
    title = str(finding.get("title", ""))
    binary_path = str(finding.get("binary_path", ""))
    evidence = " ".join(str(e) for e in finding.get("evidence", []))
    text = f"{component} {binary_path} {title} {evidence}".lower()

    matches: list[KnownCve] = []
    for cve in cves:
        for ab in cve.affected_binaries:
            if ab.lower() in text:
                matches.append(cve)
                break
        else:
            kws = re.findall(r"[a-z_/.-]+", cve.summary.lower())
            if sum(1 for kw in kws if len(kw) > 4 and kw in text) >= 3:
                matches.append(cve)
    return matches


def dedup_findings(
    findings: list[dict[str, Any]],
    vendor: str = "",
    product: str = "",
) -> DedupReport:
    start = _time.perf_counter()
    cves = _VENDOR_KB.get((vendor or "").strip().lower(), [])

    report = DedupReport(
        total_findings=len(findings), vendor=vendor, product=product,
    )

    for f in findings:
        if not isinstance(f, dict):
            continue

        is_fp, reason = is_false_positive(f)
        if is_fp:
            report.false_positives.append(DedupVerdict(
                finding=f, is_false_positive=True, fp_reason=reason,
                verdict="false_positive", verdict_detail=f"Filtered: {reason}",
            ))
            continue

        matched = _match_cves(f, cves)
        if matched:
            top = matched[0]
            fix = f" (fixed {top.fixed_in})" if top.fixed_in else " (UNPATCHED/EOL)"
            report.known_cve_findings.append(DedupVerdict(
                finding=f, matched_cves=matched, verdict="known_cve",
                verdict_detail=f"Matches {', '.join(c.cve_id for c in matched)}{fix}",
            ))
        else:
            report.potential_0day.append(DedupVerdict(
                finding=f, verdict="potential_0day",
                verdict_detail="No known CVE — potential 0day",
            ))

    report.duration_s = _time.perf_counter() - start
    return report


def annotate_metadata(metadata: dict[str, Any], vendor: str = "",
                      product: str = "") -> dict[str, Any]:
    """Run dedup on metadata findings and annotate in-place.

    Adds ``dedup_verdict``, ``dedup_detail``, ``matched_cves`` to each
    finding, and a top-level ``_dedup_report`` summary dict.
    """
    all_findings = (
        list(metadata.get("candidate_findings", []))
        + list(metadata.get("validated_leads", []))
        + list(metadata.get("confirmed_findings", []))
    )
    if not all_findings:
        metadata["_dedup_report"] = {"total": 0}
        return metadata

    report = dedup_findings(all_findings, vendor=vendor, product=product)

    vmap: dict[str, DedupVerdict] = {}
    for v in (report.false_positives + report.known_cve_findings
              + report.potential_0day):
        cp = str(v.finding.get("component_path", ""))
        if cp:
            vmap[cp] = v

    for key in ("candidate_findings", "validated_leads", "confirmed_findings"):
        for f in metadata.get(key, []):
            if not isinstance(f, dict):
                continue
            cp = str(f.get("component_path", ""))
            v = vmap.get(cp)
            if v is None:
                # Try matching by title substring
                title = str(f.get("title", ""))
                for vcp, vv in vmap.items():
                    if vcp in title or title[:20] in vcp:
                        v = vv
                        break
            if v is not None:
                f["dedup_verdict"] = v.verdict
                f["dedup_detail"] = v.verdict_detail
                if v.matched_cves:
                    f["matched_cves"] = [c.cve_id for c in v.matched_cves]

    fp_reasons: dict[str, int] = {}
    for v in report.false_positives:
        fp_reasons[v.fp_reason] = fp_reasons.get(v.fp_reason, 0) + 1

    metadata["_dedup_report"] = {
        "total": report.total_findings,
        "false_positives": len(report.false_positives),
        "known_cve": len(report.known_cve_findings),
        "potential_0day": len(report.potential_0day),
        "fp_breakdown": fp_reasons,
        "top_0day": [
            {"title": str(v.finding.get("title", ""))[:150],
             "component": str(v.finding.get("component_path", "")),
             "severity": str(v.finding.get("severity", ""))}
            for v in report.potential_0day[:10]
        ],
    }
    return metadata
