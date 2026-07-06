"""Cross-platform utilities — handles differences between Windows and Linux.

All tool execution goes through these helpers so the rest of the code
doesn't need to care about the platform.
"""

from __future__ import annotations

import os
import platform
import shutil
import subprocess
from pathlib import Path

from vulnagent.paths import PROJECT_ROOT


def is_windows() -> bool:
    return platform.system() == "Windows"


def is_linux() -> bool:
    return platform.system() == "Linux"


# ── Python executable ────────────────────────────────────────────────

def get_python() -> str:
    """Get the python executable name for the current platform."""
    if is_windows():
        return "python"
    # On Linux, prefer python3, fall back to python
    if shutil.which("python3"):
        return "python3"
    return "python"


# ── Tool availability ────────────────────────────────────────────────

_WINDOWS_TOOL_CANDIDATES: dict[str, tuple[tuple[str, ...], ...]] = {
    "nmap": (
        ("ProgramFiles(x86)", "Nmap", "nmap.exe"),
        ("ProgramFiles", "Nmap", "nmap.exe"),
    ),
    "ncat": (
        ("ProgramFiles(x86)", "Nmap", "ncat.exe"),
        ("ProgramFiles", "Nmap", "ncat.exe"),
    ),
    "nc": (
        ("ProgramFiles(x86)", "Nmap", "ncat.exe"),
        ("ProgramFiles", "Nmap", "ncat.exe"),
    ),
    "sqlmap": (
        ("LOCALAPPDATA", "sqlmap", "sqlmap.py"),
        ("ProgramFiles", "sqlmap", "sqlmap.py"),
    ),
    "gobuster": (
        ("ProgramFiles", "gobuster", "gobuster.exe"),
        ("LOCALAPPDATA", "gobuster", "gobuster.exe"),
    ),
    "nikto": (
        ("LOCALAPPDATA", "nikto", "program", "nikto.pl"),
        ("ProgramFiles", "nikto", "program", "nikto.pl"),
    ),
    "openssl": (
        ("ProgramFiles", "OpenSSL", "bin", "openssl.exe"),
        ("ProgramFiles", "Git", "mingw64", "bin", "openssl.exe"),
        ("ProgramFiles", "Git", "usr", "bin", "openssl.exe"),
    ),
    "strings": (
        ("ProgramFiles(x86)", "SysinternalsSuite", "strings.exe"),
        ("ProgramFiles", "SysinternalsSuite", "strings.exe"),
        ("ProgramFiles", "Git", "usr", "bin", "strings.exe"),
    ),
    "objdump": (
        ("ProgramFiles", "Git", "mingw64", "bin", "objdump.exe"),
        ("ProgramFiles", "Git", "usr", "bin", "objdump.exe"),
    ),
    "checksec": (
        ("ProgramFiles", "checksec", "checksec.exe"),
        ("LOCALAPPDATA", "checksec", "checksec.exe"),
    ),
}


def _windows_tool_candidates(name: str) -> list[Path]:
    candidates: list[Path] = []
    for env_var, *parts in _WINDOWS_TOOL_CANDIDATES.get(name.lower(), ()):
        base = os.environ.get(env_var, "")
        if base:
            candidates.append(Path(base).joinpath(*parts))
    return candidates


def find_tool(name: str) -> str | None:
    """Find a tool on PATH. Returns the full path or None.

    On Windows, also tries environment-derived install locations.
    """
    direct = shutil.which(name)
    if direct:
        return direct

    if is_windows():
        for ext in ("", ".exe", ".bat", ".cmd"):
            path = shutil.which(name + ext)
            if path:
                return path

        for candidate in _windows_tool_candidates(name):
            if candidate.exists():
                return str(candidate)

        return None
    return None


def check_tool(name: str) -> bool:
    """Check if a tool is available."""
    return find_tool(name) is not None


# ── Command construction ─────────────────────────────────────────────

def build_command(tool: str, args: str, use_shell: bool = False) -> str | list[str]:
    """Build a platform-appropriate command.

    On Windows with shell=False: returns a list for subprocess
    On Windows with shell=True or Linux: returns a string
    """
    if is_windows() and not use_shell:
        # Split into list for subprocess (avoids shell injection)
        return [tool] + args.split()
    return f"{tool} {args}"


def shell_execute(command: str, timeout: int = 300) -> tuple[int, str, str]:
    """Execute a shell command safely, cross-platform.

    Returns (return_code, stdout, stderr).
    """
    try:
        proc = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return proc.returncode, proc.stdout, proc.stderr
    except subprocess.TimeoutExpired:
        return -1, "", f"Command timed out after {timeout}s"
    except Exception as e:
        return -1, "", str(e)


# ── Common tool paths ────────────────────────────────────────────────

def get_default_wordlist() -> str:
    """Get a reasonable default wordlist path for the platform."""
    # Linux paths
    candidates = [
        "/usr/share/wordlists/dirb/common.txt",
        "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
        "/usr/share/seclists/Discovery/Web-Content/common.txt",
        "/usr/share/wordlists/seclists/Discovery/Web-Content/common.txt",
        # Windows / Kali-in-WSL paths
        "/usr/share/wordlists/dirb/common.txt",
    ]
    for path in candidates:
        if os.path.exists(path):
            return path
    # Try to use a bundled wordlist if none found
    local = PROJECT_ROOT / "data" / "common.txt"
    if local.exists():
        return str(local)
    # Last resort: return the most common path (will fail if not present)
    return "/usr/share/wordlists/dirb/common.txt"


def get_null_device() -> str:
    """Get the null device path for the current platform."""
    return "NUL" if is_windows() else "/dev/null"


def get_temp_dir() -> str:
    """Get a temporary directory."""
    import tempfile
    return tempfile.gettempdir()


# ── Echo/pipe helper ─────────────────────────────────────────────────

def pipe_string_through(pipe_input: str, command: str, timeout: int = 30) -> tuple[int, str, str]:
    """Pipe a string as stdin to a command. Cross-platform."""
    try:
        proc = subprocess.run(
            command,
            shell=True,
            input=pipe_input,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return proc.returncode, proc.stdout, proc.stderr
    except subprocess.TimeoutExpired:
        return -1, "", f"Command timed out after {timeout}s"
    except Exception as e:
        return -1, "", str(e)


# ── Tool info ────────────────────────────────────────────────────────

def list_available_tools(tool_names: list[str]) -> dict[str, bool]:
    """Check which tools from a list are available."""
    return {name: check_tool(name) for name in tool_names}
