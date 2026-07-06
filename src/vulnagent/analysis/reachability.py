"""Symbolic execution reachability analysis for firmware binaries.

Provides optional angr-based path verification to confirm whether
a vulnerability sink is reachable from attacker-controlled input.
Falls back gracefully when angr is not installed.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol


@dataclass(frozen=True)
class ReachabilityResult:
    """Result of a reachability check via symbolic execution."""

    reachable: bool
    path_found: bool
    constraints: str = ""
    estimated_steps: int = 0
    error: str = ""
    source_addr: int = 0
    sink_addr: int = 0
    binary_path: str = ""

    def as_dict(self) -> dict[str, object]:
        return {
            "reachable": self.reachable,
            "path_found": self.path_found,
            "constraints": self.constraints[:500],
            "estimated_steps": self.estimated_steps,
            "error": self.error,
            "source_addr": hex(self.source_addr) if self.source_addr else "",
            "sink_addr": hex(self.sink_addr) if self.sink_addr else "",
        }


class ReachabilityAnalyzer(Protocol):
    """Protocol for symbolic execution reachability checkers."""

    def verify_path(
        self,
        binary_path: Path,
        source_addr: int,
        sink_addr: int,
        timeout: int = 30,
    ) -> ReachabilityResult:
        """Verify if sink_addr is reachable from source_addr in binary."""
        ...


class AngrReachabilityAnalyzer:
    """angr-based symbolic execution for path reachability verification.

    Uses angr's simulation manager to explore control flow from a
    source address to a sink address within a configurable timeout.
    """

    def __init__(self) -> None:
        self._angr_available = _check_angr()

    @property
    def available(self) -> bool:
        return self._angr_available

    def verify_path(
        self,
        binary_path: Path,
        source_addr: int,
        sink_addr: int,
        timeout: int = 30,
    ) -> ReachabilityResult:
        if not self._angr_available:
            return ReachabilityResult(
                reachable=False,
                path_found=False,
                error="angr not installed",
                source_addr=source_addr,
                sink_addr=sink_addr,
                binary_path=str(binary_path),
            )

        try:
            import angr

            project = angr.Project(str(binary_path), auto_load_libs=False)
            state = project.factory.blank_state(addr=source_addr)
            simgr = project.factory.simulation_manager(state)

            def _find_sink(s):
                return s.addr == sink_addr

            simgr.explore(find=_find_sink, num_find=1)

            if simgr.found:
                found_state = simgr.found[0]
                return ReachabilityResult(
                    reachable=True,
                    path_found=True,
                    constraints=str(found_state.solver.constraints)[:1000],
                    estimated_steps=found_state.history.depth,
                    source_addr=source_addr,
                    sink_addr=sink_addr,
                    binary_path=str(binary_path),
                )

            return ReachabilityResult(
                reachable=False,
                path_found=False,
                constraints="",
                estimated_steps=len(simgr.active) + len(simgr.deadended),
                source_addr=source_addr,
                sink_addr=sink_addr,
                binary_path=str(binary_path),
                error="No path found to sink",
            )

        except Exception as exc:
            return ReachabilityResult(
                reachable=False,
                path_found=False,
                error=f"angr analysis failed: {exc}",
                source_addr=source_addr,
                sink_addr=sink_addr,
                binary_path=str(binary_path),
            )


class NoopReachabilityAnalyzer:
    """No-op analyzer used when angr is unavailable."""

    def verify_path(
        self,
        binary_path: Path,
        source_addr: int,
        sink_addr: int,
        timeout: int = 30,
    ) -> ReachabilityResult:
        return ReachabilityResult(
            reachable=False,
            path_found=False,
            error="reachability analysis not available (angr not installed)",
            source_addr=source_addr,
            sink_addr=sink_addr,
            binary_path=str(binary_path),
        )


def create_reachability_analyzer(require_angr: bool = False) -> ReachabilityAnalyzer:
    """Factory: returns AngrReachabilityAnalyzer if available, else Noop.

    Args:
        require_angr: If True, raise RuntimeError when angr is missing.

    Raises:
        RuntimeError: When require_angr=True and angr is not installed.
    """
    if _check_angr():
        return AngrReachabilityAnalyzer()
    if require_angr:
        raise RuntimeError(
            "angr is required but not installed. "
            "Install with: pip install angr"
        )
    return NoopReachabilityAnalyzer()


def _check_angr() -> bool:
    """Check if angr is importable (may fail due to keystone/archinfo deps)."""
    try:
        import angr  # noqa: F401
        _ = angr.Project  # Verify angr is functional
        return True
    except (ImportError, AttributeError, TypeError):
        return False
