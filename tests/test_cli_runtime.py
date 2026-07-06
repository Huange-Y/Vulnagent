from __future__ import annotations

import os
import subprocess
import sys
from importlib import import_module
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def _run_cli(
    *args: str,
    env: dict[str, str] | None = None,
    cwd: Path | None = None,
) -> subprocess.CompletedProcess[str]:
    merged_env = os.environ.copy()
    merged_env["PYTHONIOENCODING"] = "utf-8"
    if env:
        merged_env.update(env)
    return subprocess.run(
        [sys.executable, "-m", "vulnagent.cli", *args],
        cwd=cwd or ROOT,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        env=merged_env,
    )


def test_module_help_runs_from_project_root() -> None:
    result = _run_cli("--help")
    assert result.returncode == 0, result.stderr
    assert "Vuln Agent" in result.stdout
    assert "--status" in result.stdout
    assert "--check-deps" in result.stdout
    assert "--routing-model" in result.stdout
    assert "--api-key" in result.stdout
    assert "LLM chain libraryPendingDeprecationWarning" not in result.stderr


def test_module_help_runs_from_workspace_root() -> None:
    result = _run_cli("--help", cwd=ROOT.parent)
    assert result.returncode == 0, result.stderr
    assert "Vuln Agent" in result.stdout


def test_status_runs_without_target() -> None:
    result = _run_cli("--status")
    assert result.returncode == 0, result.stderr
    assert "Provider Configuration" in result.stdout
    assert "Purpose Mapping" in result.stdout
    assert "Config Paths" in result.stdout
    assert "project_root" in result.stdout
    assert "run_root" in result.stdout
    assert "execution_backend" in result.stdout
    assert "LLM chain libraryPendingDeprecationWarning" not in result.stderr


def test_check_deps_reports_emulation_readiness() -> None:
    result = _run_cli("--check-deps")
    assert result.returncode == 0, result.stderr
    assert "EMULATION" in result.stdout


def test_module_help_lists_web_serve_mode() -> None:
    result = _run_cli("--help")
    assert result.returncode == 0, result.stderr
    assert "--serve" in result.stdout
    assert "--host" in result.stdout
    assert "--port" in result.stdout


def test_cli_can_import_server_app_from_project_root() -> None:
    from vulnagent import cli

    workspace_root = str(ROOT.parent.resolve())
    original_path = list(sys.path)
    removed_modules = {
        name: module
        for name, module in list(sys.modules.items())
        if name == "server" or name.startswith("server.")
    }
    for name in removed_modules:
        sys.modules.pop(name, None)
    sys.path[:] = [
        entry
        for entry in sys.path
        if str(Path(entry).resolve()) != workspace_root
    ]
    try:
        cli._ensure_workspace_root_on_path()
        module = import_module("server.app")
        assert hasattr(module, "create_app")
    finally:
        sys.path[:] = original_path
        sys.modules.update(removed_modules)


def test_cli_reports_missing_artifact_for_targeted_run() -> None:
    result = _run_cli("--target", "firmware.bin")
    assert result.returncode == 1
    assert "Target artifact not found" in result.stderr or "Target artifact not found" in result.stdout
