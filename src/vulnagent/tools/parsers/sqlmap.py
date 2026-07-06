"""SQLMap output parser — extracts injection points and DB information."""

from __future__ import annotations

import re
from typing import Any


def parse_sqlmap_output(raw: str) -> dict[str, Any]:
    """Parse sqlmap output into structured vulnerability data.

    Returns:
        {
            "vulnerable": True,
            "injection_points": [
                {"parameter": "id", "type": "UNION query", "payload": "' UNION SELECT..."},
            ],
            "databases": ["information_schema", "challenge_db"],
            "tables": {"challenge_db": ["users", "flags"]},
            "payloads": ["id=1' OR '1'='1"],
        }
    """
    result: dict[str, Any] = {
        "vulnerable": False,
        "injection_points": [],
        "databases": [],
        "tables": {},
        "payloads": [],
    }

    # Detect vulnerability
    if re.search(r"parameter .* is vulnerable", raw, re.IGNORECASE):
        result["vulnerable"] = True

    # Extract injection points
    param_re = re.compile(
        r"Parameter:\s*(\S+).*?Type:\s*([\w\s]+?)(?:\s|$)",
        re.IGNORECASE,
    )
    for match in param_re.finditer(raw):
        param = match.group(1)
        inj_type = match.group(2).strip()
        if inj_type:
            result["injection_points"].append({
                "parameter": param,
                "type": inj_type,
            })

    # Extract payloads
    payload_re = re.compile(r"Payload:\s*(.+?)$", re.IGNORECASE | re.MULTILINE)
    for match in payload_re.finditer(raw):
        payload = match.group(1).strip()
        if payload and payload not in result["payloads"]:
            result["payloads"].append(payload)

    # Extract databases
    db_re = re.compile(r"\[\*\]\s+(\w+)", re.IGNORECASE)
    # More specific: look for database enumeration section
    db_section = re.findall(r"available databases.*?\[(.*?)\]", raw, re.DOTALL | re.IGNORECASE)
    if db_section:
        for db_name in re.findall(r"\[\*\]\s+(\S+)", db_section[0]):
            if db_name not in result["databases"]:
                result["databases"].append(db_name)

    # Extract table info
    table_block = re.findall(
        r"Database:\s*(\S+).*?\[(\d+) tables\].*?\n(.*?)(?:\n\n|\Z)",
        raw, re.DOTALL | re.IGNORECASE,
    )
    for db, count, tables_text in table_block:
        table_names = re.findall(r"\|\s+(\S+)\s+\|", tables_text)
        if table_names:
            result["tables"][db] = table_names

    return result


def is_sql_injectable(raw: str) -> bool:
    """Quick check: does the sqlmap output indicate a vulnerability?"""
    return bool(re.search(r"is vulnerable|injectable", raw, re.IGNORECASE))
