"""Vulnerability discovery tool registrations."""

from vulnagent.tools.vuln_tools import (
    register_vuln_tools,
    register_all_vuln_tools,
)

__all__ = ["register_vuln_tools", "register_all_vuln_tools"]
