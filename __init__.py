"""Workspace-level package shim for running vulnagent from the repo root.

This makes ``python -m vulnagent.cli`` resolve to this checkout's
``vulnagent/src/vulnagent`` package even when the current working directory
is ``e:/MYAGENTS`` instead of ``e:/MYAGENTS/vulnagent``.
"""

from __future__ import annotations

from pathlib import Path

_SRC_PACKAGE = Path(__file__).resolve().parent / "src" / "vulnagent"

__path__ = [str(_SRC_PACKAGE)]
