from __future__ import annotations

from pathlib import Path

import argparse
import yaml

from vulnagent import cli
from vulnagent.paths import PROJECT_ROOT
from vulnagent.utils.settings import SettingsManager


ROOT = Path(__file__).resolve().parents[1]


def test_settings_manager_finds_vulnagent_project_root() -> None:
    manager = SettingsManager(project_root=ROOT)
    assert manager._project_root == PROJECT_ROOT
    assert manager._project_root.name == "vulnagent"


def test_settings_manager_uses_vulnagent_user_dir() -> None:
    manager = SettingsManager(project_root=ROOT)
    assert manager._user_dir.name == ".vulnagent"


def test_settings_example_documents_runtime_and_provider_keys() -> None:
    data = yaml.safe_load((ROOT / "config" / "settings.example.yaml").read_text(encoding="utf-8"))
    assert "runtime" in data
    assert "providers" in data
    assert "purposes" in data


def test_settings_manager_defaults_run_root_outside_repo(tmp_path: Path) -> None:
    project = tmp_path / "vulnagent"
    (project / "src" / "vulnagent").mkdir(parents=True)
    (project / "pyproject.toml").write_text("[project]\nname='vulnagent'\n", encoding="utf-8")

    manager = SettingsManager(project_root=project).load()
    run_root = str(manager.get("runtime.run_root", ""))

    assert run_root
    assert ".vulnagent" not in run_root
    assert "vulnagent" in run_root.lower()


def test_settings_manager_defaults_firmware_execution_backend_local(tmp_path: Path) -> None:
    project = tmp_path / "vulnagent"
    (project / "src" / "vulnagent").mkdir(parents=True)
    (project / "pyproject.toml").write_text("[project]\nname='vulnagent'\n", encoding="utf-8")

    manager = SettingsManager(project_root=project).load()

    assert manager.get("runtime.execution_backend") == "local"
    assert manager.get("remote.host") == ""
    assert manager.get("remote.port") == 22


def test_registry_configuration_prefers_available_provider(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv("DEEPSEEK_API_KEY", "test-deepseek-key")
    monkeypatch.setenv("OPENAI_API_KEY", "")
    monkeypatch.setenv("OPENROUTER_API_KEY", "")

    project = tmp_path / "vulnagent"
    (project / "src" / "vulnagent").mkdir(parents=True)
    (project / "pyproject.toml").write_text("[project]\nname='vulnagent'\n", encoding="utf-8")

    settings = SettingsManager(project_root=project).load()
    args = argparse.Namespace(
        api_key="",
        provider="",
        model="",
        routing_model="",
    )

    registry = cli._configure_registry(settings, args)
    reasoning = registry.get_purpose("reasoning")

    assert reasoning.provider == "deepseek"
    assert reasoning.model in {"deepseek-chat", "deepseek-reasoner"}


def test_settings_manager_loads_legacy_workspace_config(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    project = workspace / "vulnagent"
    (project / "src" / "vulnagent").mkdir(parents=True)
    (project / "pyproject.toml").write_text("[project]\nname='vulnagent'\n", encoding="utf-8")

    legacy_config = workspace / ".myagents" / "settings.yaml"
    legacy_config.parent.mkdir(parents=True)
    legacy_config.write_text(
        """
providers:
  local:
    base_url: http://127.0.0.1:8317/v1
    api_key: sk-test
    models:
      - gpt-5.4
purposes:
  reasoning:
    provider: local
    model: gpt-5.4
""".strip(),
        encoding="utf-8",
    )

    manager = SettingsManager(project_root=project).load()

    assert manager.get("providers.local.base_url") == "http://127.0.0.1:8317/v1"
    assert manager.get("purposes.reasoning.provider") == "local"
    assert manager.find_config_file() == legacy_config


def test_settings_manager_loads_api_key_from_workspace_env_file(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.delenv("CLIPROXY_API_KEY", raising=False)

    workspace = tmp_path / "workspace"
    project = workspace / "vulnagent"
    (project / "src" / "vulnagent").mkdir(parents=True)
    (project / "pyproject.toml").write_text("[project]\nname='vulnagent'\n", encoding="utf-8")

    legacy_config = workspace / ".myagents" / "settings.yaml"
    legacy_config.parent.mkdir(parents=True)
    legacy_config.write_text(
        """
providers:
  local:
    base_url: http://127.0.0.1:8317/v1
    api_key_env: CLIPROXY_API_KEY
    models:
      - gpt-5.4
purposes:
  reasoning:
    provider: local
    model: gpt-5.4
""".strip(),
        encoding="utf-8",
    )
    (workspace / "apikeys.txt").write_text("CLIPROXY_API_KEY=sk-test\n", encoding="utf-8")

    manager = SettingsManager(project_root=project).load()
    provider = manager.get_provider_for("local")
    registry = manager.create_model_registry()

    assert provider["api_key"] == "sk-test"
    assert registry.get_provider("local").resolve_api_key() == "sk-test"


def test_settings_manager_applies_project_local_override_after_project_config(tmp_path: Path) -> None:
    project = tmp_path / "vulnagent"
    (project / "src" / "vulnagent").mkdir(parents=True)
    (project / "pyproject.toml").write_text("[project]\nname='vulnagent'\n", encoding="utf-8")
    config_dir = project / "config"
    config_dir.mkdir(parents=True)
    (config_dir / "settings.yaml").write_text(
        """
purposes:
  reasoning:
    provider: local
    model: gpt-5.4
""".strip(),
        encoding="utf-8",
    )
    (config_dir / "settings.local.yaml").write_text(
        """
purposes:
  reasoning:
    model: gpt-5.5
""".strip(),
        encoding="utf-8",
    )

    manager = SettingsManager(project_root=project).load()

    assert manager.get("purposes.reasoning.provider") == "local"
    assert manager.get("purposes.reasoning.model") == "gpt-5.5"
