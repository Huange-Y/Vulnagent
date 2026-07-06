from importlib import import_module
from pathlib import Path
import sys
import types


def test_vulnagent_project_layout_exists():
    root = Path(__file__).resolve().parents[1]
    assert (root / "pyproject.toml").exists()
    assert (root / "src" / "vulnagent" / "__init__.py").exists()
    assert (root / "config" / "settings.example.yaml").exists()


def test_vulnagent_runtime_dirs_are_gitignored():
    root = Path(__file__).resolve().parents[1]
    gitignore = (root / ".gitignore").read_text(encoding="utf-8")
    assert ".vulnagent/" in gitignore
    assert "runtime/" in gitignore
    assert "config/settings.local.yaml" in gitignore


def test_vulnagent_cli_entrypoint_imports_from_src_tree():
    root = Path(__file__).resolve().parents[1]
    src_root = root / "src"
    expected_cli_path = (src_root / "vulnagent" / "cli.py").resolve()
    fake_package = types.ModuleType("vulnagent")
    fake_package.__path__ = []
    fake_cli = types.ModuleType("vulnagent.cli")
    fake_cli.main = None
    original_package = sys.modules.get("vulnagent")
    original_cli = sys.modules.get("vulnagent.cli")
    sys.modules["vulnagent"] = fake_package
    sys.modules["vulnagent.cli"] = fake_cli
    sys.path.insert(0, str(src_root))
    try:
        sys.modules.pop("vulnagent.cli", None)
        sys.modules.pop("vulnagent", None)
        cli_module = import_module("vulnagent.cli")
        assert Path(cli_module.__file__).resolve() == expected_cli_path
        assert callable(cli_module.main)
    finally:
        sys.path.pop(0)
        if original_package is None:
            sys.modules.pop("vulnagent", None)
        else:
            sys.modules["vulnagent"] = original_package
        if original_cli is None:
            sys.modules.pop("vulnagent.cli", None)
        else:
            sys.modules["vulnagent.cli"] = original_cli


def test_vulnagent_readme_mentions_status_and_target_modes():
    root = Path(__file__).resolve().parents[1]
    readme = (root / "README.md").read_text(encoding="utf-8")
    assert "python -m vulnagent.cli --status" in readme
    assert "--target" in readme
