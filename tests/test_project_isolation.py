from pathlib import Path
import re


def _python_files():
    root = Path(__file__).resolve().parents[1] / "src" / "vulnagent"
    return [path for path in root.rglob("*.py") if path.is_file()]


def test_vulnagent_runtime_has_no_legacy_common_imports():
    offenders = []
    needles = ("import common", "from common import", "from common.")
    for path in _python_files():
        text = path.read_text(encoding="utf-8")
        if any(needle in text for needle in needles):
            offenders.append(path.as_posix())
    assert offenders == []


def test_vulnagent_runtime_has_no_legacy_package_imports():
    offenders = []
    needles = (
        "import ctfagents",
        "from ctfagents import",
        "ctfagents.",
        "import vulnagents",
        "from vulnagents import",
        "vulnagents.",
        "import ctfagent",
        "from ctfagent import",
        "ctfagent.",
    )
    for path in _python_files():
        text = path.read_text(encoding="utf-8")
        if any(needle in text for needle in needles):
            offenders.append(path.as_posix())
    assert offenders == []


def test_vulnagent_runtime_has_no_absolute_windows_paths():
    offenders = []
    drive_path_pattern = re.compile(r"(?<![A-Za-z0-9_])[A-Za-z]:(?:\\|\|/)")
    for path in _python_files():
        text = path.read_text(encoding="utf-8")
        if drive_path_pattern.search(text):
            offenders.append(path.as_posix())
    assert offenders == []
