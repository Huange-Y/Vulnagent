"""Python-native fallback implementations for tools not available on Windows.

These are used automatically when the native binary is not found.
"""

from __future__ import annotations

from pathlib import Path


def python_strings(filepath: str, min_length: int = 4) -> str:
    """Extract printable ASCII strings from a binary file (pure Python)."""
    try:
        with open(filepath, "rb") as f:
            data = f.read()
    except Exception as e:
        return f"Error reading file: {e}"

    result: list[str] = []
    current: list[str] = []
    for byte in data:
        if 32 <= byte < 127:
            current.append(chr(byte))
        else:
            if len(current) >= min_length:
                result.append("".join(current))
            current = []
    if len(current) >= min_length:
        result.append("".join(current))

    if not result:
        return "(no printable strings found)"

    # Group by likely type
    interesting: list[str] = []
    other: list[str] = []

    interest_keywords = [
        "flag", "CTF", "password", "secret", "key", "token",
        "http", ".com", ".org", "admin", "root", "login",
        "/bin/", "ELF", "PE", "MZ", ".text", ".data",
        "GCC", "GLIBC", "libc", "system", "exec",
    ]
    for s in result:
        if any(kw.lower() in s.lower() for kw in interest_keywords):
            interesting.append(s)
        else:
            other.append(s)

    lines: list[str] = []
    if interesting:
        lines.append(f"=== Interesting Strings ({len(interesting)}) ===")
        lines.extend(interesting[:50])
    if other:
        lines.append(f"\n=== Other Strings ({len(other)}) ===")
        lines.extend(other[:100])
    if len(result) > 150:
        lines.append(f"\n... ({len(result)} total, showing first 150)")

    return "\n".join(lines)


def python_checksec(filepath: str) -> str:
    """Check basic security properties of a PE/ELF binary (pure Python)."""
    try:
        with open(filepath, "rb") as f:
            header = f.read(1024)
    except Exception as e:
        return f"Error reading file: {e}"

    result: list[str] = [f"File: {filepath}"]
    result.append(f"Size: {Path(filepath).stat().st_size} bytes")

    # Detect PE (Windows) or ELF (Linux)
    if header[:2] == b"MZ":
        result.append("Type: PE (Windows executable)")
        result.extend(_check_pe(header))
    elif header[:4] == b"\x7fELF":
        result.append("Type: ELF (Linux executable)")
        result.extend(_check_elf(header))
    else:
        # Generic check
        result.append("Type: Unknown (raw binary or script)")
        # Check for common patterns
        if b"#!/" in header[:100]:
            interp = header[:100].split(b"\n")[0].decode("utf-8", errors="replace")
            result.append(f"Script interpreter: {interp}")

    return "\n".join(result)


def _check_pe(header: bytes) -> list[str]:
    """Basic PE security checks."""
    result: list[str] = []

    # PE signature
    pe_offset = int.from_bytes(header[0x3C:0x3C + 4], "little")
    result.append(f"PE offset: 0x{pe_offset:x}")

    # Check for common flags
    # ASLR (DYNAMIC_BASE) — rough heuristic
    result.append("ASLR (DYNAMIC_BASE): check with full PE parsing")
    result.append("DEP (NX_COMPAT): check with full PE parsing")
    result.append("Note: Full PE analysis requires pefile library (pip install pefile)")

    return result


def _check_elf(header: bytes) -> list[str]:
    """Basic ELF security checks."""
    result: list[str] = []

    # Class
    elf_class = header[4]
    result.append(f"Class: {'64-bit' if elf_class == 2 else '32-bit'}")

    # Check for common security features
    # This is a simplified check; full analysis needs pyelftools
    result.append("Stack Canary: check with pyelftools")
    result.append("PIE: check with pyelftools")
    result.append("RELRO: check with pyelftools")
    result.append("Note: Full ELF analysis requires pyelftools (pip install pyelftools)")

    return result


def python_objdump(filepath: str) -> str:
    """Basic disassembly info for a binary (pure Python — very limited).

    Full disassembly requires objdump/capstone. This provides
    file identification and hex dump of entry points.
    """
    try:
        with open(filepath, "rb") as f:
            data = f.read()
    except Exception as e:
        return f"Error reading file: {e}"

    result: list[str] = [f"File: {filepath}"]
    result.append(f"Size: {len(data)} bytes")

    if data[:2] == b"MZ":
        result.append("Type: PE (Windows executable)")
        pe_offset = int.from_bytes(data[0x3C:0x3C + 4], "little")
        result.append(f"PE header at offset: 0x{pe_offset:x}")
        result.append("Full disassembly requires objdump or capstone engine")
        result.append("Install: apt install binutils (Linux) or pip install capstone")
    elif data[:4] == b"\x7fELF":
        result.append("Type: ELF (Linux executable)")
        entry = int.from_bytes(data[24:32] if data[4] == 2 else data[24:28], "little")
        result.append(f"Entry point: 0x{entry:x}")
        result.append("Full disassembly requires objdump or capstone engine")
    else:
        result.append("Type: Unknown")
        # Show hex dump of first 256 bytes
        result.append("\nHex dump (first 256 bytes):")
        for i in range(0, min(256, len(data)), 16):
            chunk = data[i:i + 16]
            hex_str = " ".join(f"{b:02x}" for b in chunk)
            ascii_str = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
            result.append(f"  {i:08x}  {hex_str:<48s}  |{ascii_str}|")

    return "\n".join(result)


def python_http_scan(target_url: str) -> str:
    """Basic HTTP scan without nikto (pure Python, using urllib)."""
    import urllib.request
    import urllib.error

    result: list[str] = [f"=== HTTP Scan: {target_url} ===\n"]

    # Ensure URL has scheme
    if not target_url.startswith("http"):
        target_url = "http://" + target_url

    # Basic HTTP GET
    try:
        req = urllib.request.Request(target_url, headers={"User-Agent": "MYAGENTS/1.0"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            result.append(f"Status: {resp.status} {resp.reason}")
            result.append(f"Server: {resp.headers.get('Server', 'unknown')}")
            result.append(f"Content-Type: {resp.headers.get('Content-Type', 'unknown')}")
            result.append(f"Content-Length: {resp.headers.get('Content-Length', 'unknown')}")
            result.append("")
            result.append("Response Headers:")
            for key, value in resp.headers.items():
                result.append(f"  {key}: {value}")
            # Read some body
            body = resp.read(4096).decode("utf-8", errors="replace")
            result.append(f"\nBody preview (first 4096 bytes):\n{body}")
    except urllib.error.HTTPError as e:
        result.append(f"HTTP Error: {e.code} {e.reason}")
    except Exception as e:
        result.append(f"Error: {e}")

    return "\n".join(result)


def python_dirbust(target_url: str, wordlist: str = "") -> str:
    """Basic directory busting without gobuster (pure Python).

    Uses a small built-in wordlist combined with user-provided list.
    """
    import urllib.request
    import urllib.error

    # Built-in mini wordlist for common web paths
    default_words = [
        "admin", "login", "wp-admin", "backup", "config", "robots.txt",
        ".git", ".env", "api", "test", "dev", "upload", "shell",
        "phpinfo.php", "info.php", "status", "debug", "console",
        ".htaccess", ".htpasswd", "sitemap.xml", "crossdomain.xml",
        "phpmyadmin", "db", "sql", "backup.zip", "backup.tar.gz",
        "wp-content", "wp-includes", "administrator", "manager",
    ]

    # Try to read user wordlist
    custom_words: list[str] = []
    if wordlist:
        try:
            with open(wordlist, encoding="utf-8", errors="ignore") as f:
                custom_words = [l.strip() for l in f if l.strip() and not l.startswith("#")]
        except Exception:
            pass

    all_words = custom_words[:500] if custom_words else default_words

    # Ensure URL has scheme and trailing slash
    if not target_url.startswith("http"):
        target_url = "http://" + target_url
    if not target_url.endswith("/"):
        target_url += "/"

    result: list[str] = [f"=== Directory Bust: {target_url} ({len(all_words)} paths) ===\n"]

    found: list[str] = []
    for word in all_words:
        url = target_url + word
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "MYAGENTS/1.0"})
            with urllib.request.urlopen(req, timeout=5) as resp:
                if resp.status != 404:
                    found.append(f"  [{resp.status}] {url}")
        except urllib.error.HTTPError as e:
            if e.code != 404:
                found.append(f"  [{e.code}] {url}")
        except Exception:
            pass  # timeout or connection error — skip

    if found:
        result.append(f"Found {len(found)} paths:\n" + "\n".join(found[:50]))
    else:
        result.append("No paths found with built-in wordlist.")
        result.append("Install gobuster for more comprehensive scanning.")

    return "\n".join(result)
