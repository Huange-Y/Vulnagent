from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass(slots=True)
class RunRecord:
    run_id: str
    asset_id: str
    asset_name: str
    asset_kind: str
    source_path: str
    entry_target: str
    scope: str
    status: str
    run_root: Path
