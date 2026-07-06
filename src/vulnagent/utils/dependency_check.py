"""Startup dependency checker for external tools.

Checks availability of external tools and provides clear feedback
about what's available and what's missing.
"""

from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass
from typing import Callable


@dataclass
class ToolStatus:
    name: str
    available: bool
    version: str = ""
    fallback: str = ""
    category: str = "general"


def check_command(cmd: str, version_flag: str = "--version") -> tuple[bool, str]:
    """Check if a command is available and get its version."""
    path = shutil.which(cmd)
    if not path:
        return False, ""
    try:
        result = subprocess.run(
            [cmd, version_flag],
            capture_output=True,
            text=True,
            timeout=5,
        )
        version = result.stdout.strip() or result.stderr.strip()
        version = version.split("\n")[0][:80]
        return True, version
    except Exception:
        return True, "(version unknown)"


def check_python_package(package: str) -> tuple[bool, str]:
    """Check if a Python package is importable."""
    try:
        mod = __import__(package)
        version = getattr(mod, "__version__", "")
        return True, version
    except ImportError:
        return False, ""


TOOL_DEFINITIONS: list[dict] = [
    # Web/Recon tools
    {"name": "nmap", "category": "recon", "fallback": "python-nmap package"},
    {"name": "gobuster", "category": "recon", "fallback": "manual directory enumeration"},
    {"name": "nikto", "category": "recon", "fallback": "manual vulnerability scanning"},
    {"name": "sqlmap", "category": "web", "fallback": "manual SQL injection testing"},
    {"name": "curl", "category": "web", "fallback": "Python requests"},
    # Artifact tools
    {"name": "file", "category": "artifact", "fallback": "Python mimetypes"},
    {"name": "readelf", "category": "artifact", "fallback": "objdump -f"},
    {"name": "strings", "category": "artifact", "fallback": "Python strings fallback"},
    {"name": "binwalk", "category": "artifact", "fallback": "manual hex triage"},
    {"name": "unsquashfs", "category": "artifact", "fallback": "Python squashfs fallback"},
    {"name": "7z", "category": "artifact", "fallback": "skip archive-assisted extraction"},
    # Binary/Pwn tools
    {"name": "objdump", "category": "binary", "fallback": "Python pwntools"},
    {"name": "checksec", "category": "binary", "fallback": "Python checksec fallback"},
    {"name": "gdb", "category": "binary", "fallback": "manual debugging"},
    {"name": "radare2", "category": "binary", "version_flag": "-v", "fallback": "objdump"},
    # Crypto tools
    {"name": "openssl", "category": "crypto", "fallback": "Python cryptography"},
    {"name": "hashcat", "category": "crypto", "fallback": "Python hashlib"},
    {"name": "john", "category": "crypto", "fallback": "Python passlib"},
    # Emulation tools
    {"name": "qemu-mips-static", "category": "emulation", "fallback": "skip MIPS user-mode launch"},
    {"name": "qemu-mipsel-static", "category": "emulation", "fallback": "skip MIPSEL user-mode launch"},
    {"name": "qemu-arm-static", "category": "emulation", "fallback": "skip ARM user-mode launch"},
    {"name": "qemu-aarch64-static", "category": "emulation", "fallback": "skip AArch64 user-mode launch"},
    {"name": "qemu-system-mips", "category": "emulation", "fallback": "write boot package only"},
    {"name": "qemu-system-arm", "category": "emulation", "fallback": "write boot package only"},
]

PYTHON_PACKAGES: list[dict] = [
    {"name": "playwright", "category": "browser", "install": "pip install playwright && playwright install chromium"},
    {"name": "pwntools", "package": "pwn", "category": "binary", "install": "pip install pwntools"},
    {"name": "requests", "category": "web", "install": "pip install requests"},
    {"name": "cryptography", "category": "crypto", "install": "pip install cryptography"},
]


def check_all_dependencies(verbose: bool = False) -> dict[str, list[ToolStatus]]:
    """Check all external tool dependencies.

    Returns:
        Dict mapping category to list of ToolStatus
    """
    results: dict[str, list[ToolStatus]] = {}

    for tool in TOOL_DEFINITIONS:
        name = tool["name"]
        category = tool.get("category", "general")
        version_flag = tool.get("version_flag", "--version")
        fallback = tool.get("fallback", "")

        available, version = check_command(name, version_flag)
        status = ToolStatus(
            name=name,
            available=available,
            version=version,
            fallback=fallback,
            category=category,
        )

        if category not in results:
            results[category] = []
        results[category].append(status)

    for pkg in PYTHON_PACKAGES:
        name = pkg["name"]
        package = pkg.get("package", name)
        category = pkg.get("category", "python")
        install = pkg.get("install", f"pip install {name}")

        available, version = check_python_package(package)
        status = ToolStatus(
            name=f"python:{name}",
            available=available,
            version=version,
            fallback=install,
            category=category,
        )

        if category not in results:
            results[category] = []
        results[category].append(status)

    return results


def print_dependency_report(results: dict[str, list[ToolStatus]] | None = None) -> None:
    """Print a formatted dependency report."""
    if results is None:
        results = check_all_dependencies()

    print("=== Dependency Check ===\n")

    total_available = 0
    total_missing = 0

    for category, tools in sorted(results.items()):
        available = [t for t in tools if t.available]
        missing = [t for t in tools if not t.available]

        total_available += len(available)
        total_missing += len(missing)

        print(f"[{category.upper()}]")
        for t in available:
            ver = f" ({t.version})" if t.version else ""
            print(f"  OK  {t.name}{ver}")
        for t in missing:
            fb = f" -> fallback: {t.fallback}" if t.fallback else ""
            print(f"  --  {t.name}{fb}")
        print()

    print(f"Summary: {total_available} available, {total_missing} missing")

    if total_missing > 0:
        print("\nNote: Missing tools will use Python fallbacks where available.")
        print("For full functionality, install missing tools or run on Linux.")


def get_available_tools(category: str | None = None) -> list[str]:
    """Get list of available tool names, optionally filtered by category."""
    results = check_all_dependencies()
    available = []

    for cat, tools in results.items():
        if category and cat != category:
            continue
        for t in tools:
            if t.available:
                available.append(t.name)

    return available


def is_tool_available(name: str) -> bool:
    """Check if a specific tool is available."""
    if name.startswith("python:"):
        package = name[7:]
        available, _ = check_python_package(package)
        return available

    available, _ = check_command(name)
    return available
