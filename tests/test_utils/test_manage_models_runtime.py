from __future__ import annotations

import manage_models


def test_load_runtime_env_reads_workspace_apikeys_file(monkeypatch, tmp_path) -> None:
    monkeypatch.delenv("CLIPROXY_API_KEY", raising=False)
    monkeypatch.setattr(manage_models, "_PROJECT_ROOT", tmp_path)

    (tmp_path / ".myagents").mkdir()
    (tmp_path / ".myagents" / "settings.yaml").write_text(
        """
providers:
  local:
    api_key_env: CLIPROXY_API_KEY
""".strip(),
        encoding="utf-8",
    )
    (tmp_path / "apikeys.txt").write_text("CLIPROXY_API_KEY=sk-test\n", encoding="utf-8")

    runtime_env = manage_models._load_runtime_env()

    assert runtime_env["CLIPROXY_API_KEY"] == "sk-test"


def test_load_runtime_env_preserves_process_env_precedence(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("CLIPROXY_API_KEY", "sk-process")
    monkeypatch.setattr(manage_models, "_PROJECT_ROOT", tmp_path)

    (tmp_path / ".myagents").mkdir()
    (tmp_path / ".myagents" / "settings.yaml").write_text(
        """
providers:
  local:
    api_key_env: CLIPROXY_API_KEY
""".strip(),
        encoding="utf-8",
    )
    (tmp_path / "apikeys.txt").write_text("CLIPROXY_API_KEY=sk-file\n", encoding="utf-8")

    runtime_env = manage_models._load_runtime_env()

    assert runtime_env["CLIPROXY_API_KEY"] == "sk-process"
