"""Nmap output parser — extracts structured host/port/service data."""

from __future__ import annotations

import re
from typing import Any


def parse_nmap_output(raw: str) -> dict[str, Any]:
    """Parse nmap -sV/-sC output into structured data.

    Returns:
        {
            "hosts": [
                {
                    "ip": "10.10.10.5",
                    "hostname": "target.example.com",
                    "status": "up",
                    "ports": [
                        {
                            "port": 80,
                            "protocol": "tcp",
                            "state": "open",
                            "service": "http",
                            "version": "Apache httpd 2.4.29",
                        }
                    ],
                    "os": "Linux 3.x|4.x",
                }
            ]
        }
    """
    hosts: list[dict[str, Any]] = []
    current_host: dict[str, Any] | None = None

    host_start = re.compile(r"Nmap scan report for (.+)")
    host_ip = re.compile(r"Nmap scan report for .*\(?(\d+\.\d+\.\d+\.\d+)\)?")
    port_line = re.compile(
        r"(\d+)/(tcp|udp)\s+(\S+)\s+(\S+)(?:\s+(.+))?"
    )
    os_line = re.compile(r"Aggressive OS guesses:\s+(.+)")
    hostname_line = re.compile(r"Other addresses for .*: (.+)")
    mac_line = re.compile(r"MAC Address:\s+(\S+)\s+\((.+)\)")

    for line in raw.split("\n"):
        stripped = line.strip()
        if not stripped:
            continue

        # New host
        host_match = host_start.match(stripped)
        if host_match:
            if current_host and current_host.get("ports"):
                hosts.append(current_host)
            ip_match = host_ip.search(stripped)
            current_host = {
                "ip": ip_match.group(1) if ip_match else host_match.group(1),
                "hostname": host_match.group(1),
                "status": "up",
                "ports": [],
                "os": "",
            }
            continue

        if current_host is None:
            continue

        # Port line
        port_match = port_line.match(stripped)
        if port_match:
            port_num = int(port_match.group(1))
            protocol = port_match.group(2)
            state = port_match.group(3)
            service = port_match.group(4)
            version = port_match.group(5).strip() if port_match.group(5) else ""

            current_host["ports"].append({
                "port": port_num,
                "protocol": protocol,
                "state": state,
                "service": service,
                "version": version,
            })
            continue

        # OS detection
        os_match = os_line.search(stripped)
        if os_match:
            current_host["os"] = os_match.group(1)
            continue

        # MAC address
        mac_match = mac_line.search(stripped)
        if mac_match:
            current_host["mac"] = mac_match.group(1)
            current_host["vendor"] = mac_match.group(2)
            continue

        # Host status
        if "Host is up" in stripped:
            current_host["status"] = "up"

    if current_host and current_host.get("ports"):
        hosts.append(current_host)

    return {"hosts": hosts}


def extract_open_ports(raw: str) -> list[int]:
    """Quick extraction: just the open port numbers."""
    ports: list[int] = []
    port_re = re.compile(r"(\d+)/tcp\s+open")
    for match in port_re.finditer(raw):
        ports.append(int(match.group(1)))
    return sorted(set(ports))
