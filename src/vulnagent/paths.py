from __future__ import annotations

import os
from pathlib import Path
import tempfile


PACKAGE_ROOT = Path(__file__).resolve().parent
PROJECT_ROOT = PACKAGE_ROOT.parent.parent
RUNTIME_BASE = PROJECT_ROOT / "runtime"
RUNTIME_ROOT = RUNTIME_BASE / "vulnagent"
CONFIG_ROOT = PROJECT_ROOT / "config"
STATE_ROOT = RUNTIME_ROOT / "state"
CACHE_ROOT = RUNTIME_ROOT / "cache"
LOG_ROOT = RUNTIME_ROOT / "logs"


def default_run_root() -> Path:
    configured = os.environ.get("VULNAGENT_RUN_ROOT", "").strip()
    if configured:
        return Path(configured).expanduser()
    return Path(tempfile.gettempdir()) / "vulnagent"


def ensure_runtime_dirs() -> None:
    for path in (RUNTIME_BASE, RUNTIME_ROOT, STATE_ROOT, CACHE_ROOT, LOG_ROOT):
        path.mkdir(parents=True, exist_ok=True)
