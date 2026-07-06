"""Gobuster output parser — extracts discovered paths and status codes."""

from __future__ import annotations

import re
from typing import Any


def parse_gobuster_output(raw: str) -> dict[str, Any]:
    """Parse gobuster output into structured data.

    Returns:
        {
            "found_paths": [
                {"path": "/admin", "status": 200, "size": 1234},
                {"path": "/api", "status": 301, "size": 0},
            ]
        }
    """
    found: list[dict[str, Any]] = []

    # Gobuster format: /path (Status: 200) [Size: 1234]
    # or: /path                (Status: 200) [Size: 1234]
    line_re = re.compile(
        r"(\S+)\s+\(Status:\s*(\d+)\)\s*\[Size:\s*(\d+)\]"
    )

    for line in raw.split("\n"):
        match = line_re.search(line)
        if match:
            path = match.group(1)
            status = int(match.group(2))
            size = int(match.group(3))
            found.append({"path": path, "status": status, "size": size})

    return {"found_paths": found}


def extract_non_404_paths(raw: str) -> list[str]:
    """Quick extraction: paths that didn't return 404."""
    paths: list[str] = []
    line_re = re.compile(r"(\S+)\s+\(Status:\s*(\d+)\)")
    for match in line_re.finditer(raw):
        status = int(match.group(2))
        if status != 404:
            paths.append(f"{match.group(1)} ({status})")
    return paths
