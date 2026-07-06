"""Nikto output parser — extracts vulnerability findings."""

from __future__ import annotations

import re
from typing import Any


def parse_nikto_output(raw: str) -> dict[str, Any]:
    """Parse nikto scan output into structured vulnerability data.

    Returns:
        {
            "vulnerabilities": [
                {
                    "id": "OSVDB-3092",
                    "severity": "high",
                    "description": "/admin/ is available...",
                    "url": "http://target/admin/",
                    "method": "GET",
                }
            ],
            "server_info": {
                "ip": "10.10.10.5",
                "hostname": "target.example.com",
                "port": 80,
                "server": "Apache/2.4.29",
            }
        }
    """
    result: dict[str, Any] = {
        "vulnerabilities": [],
        "server_info": {},
    }

    # Vulnerability lines: + OSVDB-XXXX: description
    vuln_re = re.compile(
        r"\+\s+(OSVDB-\d+)?\s*:?\s*(.+)",
        re.IGNORECASE,
    )
    # URL extraction
    url_re = re.compile(r"(https?://\S+)")

    # Server info extraction
    target_re = re.compile(r"-+\s*:\s*(.+)")
    server_re = re.compile(r"Server:\s*(.+)", re.IGNORECASE)
    ip_re = re.compile(r"Target IP:\s*(\S+)", re.IGNORECASE)
    port_re = re.compile(r"Target Port:\s*(\d+)", re.IGNORECASE)

    for line in raw.split("\n"):
        stripped = line.strip()
        if not stripped:
            continue

        # Server info
        if "Target IP:" in stripped:
            result["server_info"]["ip"] = ip_re.search(stripped).group(1) if ip_re.search(stripped) else ""
        if "Target Port:" in stripped:
            result["server_info"]["port"] = int(port_re.search(stripped).group(1)) if port_re.search(stripped) else 0
        if "Target Hostname:" in stripped:
            result["server_info"]["hostname"] = stripped.split(":", 1)[-1].strip()
        server_match = server_re.search(stripped)
        if server_match:
            result["server_info"]["server"] = server_match.group(1)

        # Vulnerability findings (lines starting with +)
        vuln_match = vuln_re.match(stripped)
        if vuln_match:
            vuln_id = vuln_match.group(1) or ""
            description = vuln_match.group(2).strip()
            url = ""
            url_match = url_re.search(description)
            if url_match:
                url = url_match.group(1)

            severity = _guess_severity(description, vuln_id)
            result["vulnerabilities"].append({
                "id": vuln_id,
                "severity": severity,
                "description": description,
                "url": url,
            })

    return result


def _guess_severity(description: str, vuln_id: str) -> str:
    """Guess severity based on keywords and OSVDB ID."""
    desc_lower = description.lower()
    critical_keywords = ["remote code execution", "rce", "command injection",
                         "sql injection", "authentication bypass", "arbitrary file upload"]
    high_keywords = ["xss", "cross-site scripting", "directory traversal",
                     "path traversal", "information disclosure", "sensitive"]
    for kw in critical_keywords:
        if kw in desc_lower:
            return "critical"
    for kw in high_keywords:
        if kw in desc_lower:
            return "high"
    return "medium"
