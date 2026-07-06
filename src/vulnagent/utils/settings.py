"""Hierarchical settings manager for vulnagent."""

from __future__ import annotations

import os
from pathlib import Path
import tempfile
from typing import Any

from vulnagent.paths import CONFIG_ROOT, PROJECT_ROOT, RUNTIME_ROOT, default_run_root


class SettingsManager:
    """Load settings from built-in defaults, disk, env, and runtime overrides."""

    LEGACY_WORKSPACE_DIR = ".myagents"
    ENV_FILE_NAMES = (".env", ".env.local", "apikeys.txt")

    BUILTIN_DEFAULTS: dict[str, Any] = {
        "runtime": {
            "run_root": str(default_run_root()),
            "execution_backend": "local",
        },
        "remote": {
            "enabled": False,
            "host": "",
            "port": 22,
            "username": "",
            "key_path": "",
            "password_env": "",
            "work_dir": "/tmp/vulnagent",
            "tool_paths": {},
        },
        "providers": {
            "openai": {
                "base_url": "https://api.openai.com/v1",
                "api_key_env": "OPENAI_API_KEY",
                "models": ["gpt-4o", "gpt-4o-mini"],
            },
            "deepseek": {
                "base_url": "https://api.deepseek.com/v1",
                "api_key_env": "DEEPSEEK_API_KEY",
                "models": ["deepseek-chat", "deepseek-reasoner"],
            },
            "openrouter": {
                "base_url": "https://openrouter.ai/api/v1",
                "api_key_env": "OPENROUTER_API_KEY",
                "models": [
                    "openai/gpt-4o",
                    "openai/gpt-4o-mini",
                ],
            },
        },
        "purposes": {
            "reasoning": {
                "provider": "openai",
                "model": "gpt-4o",
            },
            "routing": {
                "provider": "openai",
                "model": "gpt-4o-mini",
            },
            "critique": {
                "provider": "openai",
                "model": "gpt-4o-mini",
            },
            "compress": {
                "provider": "openai",
                "model": "gpt-4o-mini",
            },
            "default": {
                "provider": "openai",
                "model": "gpt-4o",
            },
        },
        "provider": {
            "primary": "openai",
        },
        "model": {
            "reasoning": "gpt-4o",
            "routing": "gpt-4o-mini",
            "critique": "gpt-4o-mini",
            "compress": "gpt-4o-mini",
            "default": "gpt-4o",
        },
        "agent": {
            "max_iterations": 5,
            "token_limit": 100000,
            "temperature": 0.0,
            "tool_timeout": 300,
        },
        "research": {
            "mode": "operator-directed",
            "default_scope": "",
            "default_provenance": "",
        },
        "compaction": {
            "micro_threshold": 0.60,
            "mid_threshold": 0.80,
            "deep_threshold": 0.95,
        },
        "memory": {
            "backend": "sqlite",
            "db_path": ":memory:",
            "max_short_term": 10,
            "max_mid_term": 50,
            "max_long_term": 200,
        },
        "flashbulb": {
            "threshold": 0.6,
        },
        "debug": {
            "verbose": False,
            "log_file": "",
        },
    }

    def __init__(self, project_root: str | Path = PROJECT_ROOT) -> None:
        given = Path(project_root).resolve()
        self._project_root = self._find_project_root(given)
        self._config_dir = self._project_root / CONFIG_ROOT.name
        self._user_dir = Path.home() / ".vulnagent"
        self._merged: dict[str, Any] = {}
        self._runtime_overrides: dict[str, Any] = {}
        self._file_env_values: dict[str, str] = {}
        self._loaded = False

    @property
    def project_root(self) -> Path:
        return self._project_root

    @property
    def project_config_file(self) -> Path:
        return self._config_dir / "settings.yaml"

    @property
    def project_local_config_file(self) -> Path:
        return self._config_dir / "settings.local.yaml"

    @property
    def user_config_file(self) -> Path:
        return self._user_dir / "settings.yaml"

    @property
    def legacy_workspace_config_file(self) -> Path | None:
        current = self._project_root
        while current != current.parent:
            candidate = current / self.LEGACY_WORKSPACE_DIR / "settings.yaml"
            if candidate.exists():
                return candidate
            current = current.parent
        return None

    @staticmethod
    def _find_project_root(start: Path) -> Path:
        current = start
        while current != current.parent:
            if (current / CONFIG_ROOT.name / "settings.yaml").exists():
                return current
            if (current / RUNTIME_ROOT.name).is_dir():
                return current
            if (current / "pyproject.toml").exists() and (current / "src" / "vulnagent").exists():
                return current
            current = current.parent
        return PROJECT_ROOT if PROJECT_ROOT.exists() else start

    def load(self) -> "SettingsManager":
        self._load_env_files_into_environment()
        self._merged = self._deep_merge({}, self.BUILTIN_DEFAULTS)

        if self.user_config_file.exists():
            user_data = self._load_yaml(self.user_config_file)
            self._merged = self._deep_merge(self._merged, user_data)

        legacy_config_file = self.legacy_workspace_config_file
        if legacy_config_file is not None:
            legacy_data = self._load_yaml(legacy_config_file)
            self._merged = self._deep_merge(self._merged, legacy_data)

        if self.project_config_file.exists():
            project_data = self._load_yaml(self.project_config_file)
            self._merged = self._deep_merge(self._merged, project_data)

        if self.project_local_config_file.exists():
            local_project_data = self._load_yaml(self.project_local_config_file)
            self._merged = self._deep_merge(self._merged, local_project_data)

        env_data = self._load_env_vars()
        self._merged = self._deep_merge(self._merged, env_data)

        self._loaded = True
        return self

    def reload(self) -> "SettingsManager":
        self._loaded = False
        return self.load()

    def get(self, key: str, default: Any = None) -> Any:
        if not self._loaded:
            self.load()

        if key in self._runtime_overrides:
            return self._runtime_overrides[key]

        return self._dot_get(self._merged, key, default)

    def set(self, key: str, value: Any) -> "SettingsManager":
        self._runtime_overrides[key] = value
        return self

    def all(self) -> dict[str, Any]:
        if not self._loaded:
            self.load()

        result = self._deep_merge({}, self._merged)
        for key, value in self._runtime_overrides.items():
            self._dot_set(result, key, value)
        return result

    def find_config_file(self) -> Path | None:
        current = self._project_root
        while current != current.parent:
            config_file = current / CONFIG_ROOT.name / "settings.yaml"
            if config_file.exists():
                return config_file
            local_config_file = current / CONFIG_ROOT.name / "settings.local.yaml"
            if local_config_file.exists():
                return local_config_file
            current = current.parent
        return self.legacy_workspace_config_file

    def get_model_for(self, purpose: str) -> str:
        purpose_cfg = self.get(f"purposes.{purpose}", {})
        if isinstance(purpose_cfg, dict) and purpose_cfg.get("model"):
            return str(purpose_cfg["model"])
        return self.get(f"model.{purpose}", self.get("model.default", "gpt-4o"))

    def get_provider_for(self, provider: str) -> dict[str, Any]:
        provider_cfg = self.get(f"providers.{provider}", {})
        if isinstance(provider_cfg, dict) and provider_cfg:
            api_key = provider_cfg.get("api_key", "")
            api_key_env = provider_cfg.get("api_key_env", "")
            if not api_key and api_key_env:
                api_key = os.environ.get(str(api_key_env), "")
            return {
                "api_key": api_key,
                "api_key_env": api_key_env,
                "base_url": provider_cfg.get("base_url", ""),
                "models": provider_cfg.get("models", []),
            }

        return {
            "api_key": self.get(f"provider.{provider}.api_key", ""),
            "base_url": self.get(f"provider.{provider}.base_url", ""),
        }

    def is_verbose(self) -> bool:
        return bool(self.get("debug.verbose", False))

    def dump_config(self) -> dict[str, Any]:
        return {
            "effective": self.all(),
            "loaded_from": {
                "user": str(self.user_config_file),
                "legacy": str(self.legacy_workspace_config_file) if self.legacy_workspace_config_file else "",
                "project": str(self.project_config_file),
                "project_local": str(self.project_local_config_file),
            },
        }

    @staticmethod
    def _load_yaml(path: Path) -> dict[str, Any]:
        try:
            import yaml

            with open(path, encoding="utf-8") as handle:
                data = yaml.safe_load(handle)
                return data if isinstance(data, dict) else {}
        except Exception:
            return {}

    @staticmethod
    def _load_env_vars() -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in os.environ.items():
            if not key.startswith("MYAGENTS_"):
                continue
            config_key = key[len("MYAGENTS_") :].lower()
            if value:
                SettingsManager._dot_set(result, config_key, value)
        return result

    def _load_env_files_into_environment(self) -> None:
        for key, previous_value in self._file_env_values.items():
            if os.environ.get(key) == previous_value:
                os.environ.pop(key, None)

        protected_keys = set(os.environ)
        loaded_values: dict[str, str] = {}

        for env_file in self._discover_env_files():
            for key, value in self._parse_env_file(env_file).items():
                if key in protected_keys:
                    continue
                os.environ[key] = value
                loaded_values[key] = value

        self._file_env_values = loaded_values

    def _discover_env_files(self) -> list[Path]:
        search_roots: list[Path] = []
        current = self._project_root
        while True:
            search_roots.append(current)
            if current == current.parent:
                break
            current = current.parent

        env_files: list[Path] = []
        for root in reversed(search_roots):
            for name in self.ENV_FILE_NAMES:
                candidate = root / name
                if candidate.exists():
                    env_files.append(candidate)
        return env_files

    @staticmethod
    def _parse_env_file(path: Path) -> dict[str, str]:
        parsed: dict[str, str] = {}
        try:
            for raw_line in path.read_text(encoding="utf-8").splitlines():
                line = raw_line.strip()
                if not line or line.startswith("#"):
                    continue
                if line.startswith("export "):
                    line = line[len("export ") :].strip()
                if "=" not in line:
                    continue
                key, value = line.split("=", 1)
                key = key.strip()
                if not key:
                    continue
                value = value.strip()
                if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
                    value = value[1:-1]
                parsed[key] = value
        except OSError:
            return {}
        return parsed

    @staticmethod
    def _dot_get(data: dict[str, Any], key: str, default: Any = None) -> Any:
        keys = key.split(".")
        current: Any = data
        for item in keys:
            if isinstance(current, dict):
                if item in current:
                    current = current[item]
                else:
                    return default
            else:
                return default
        return current

    @staticmethod
    def _dot_set(data: dict[str, Any], key: str, value: Any) -> None:
        keys = key.split(".")
        current = data
        for item in keys[:-1]:
            if item not in current or not isinstance(current[item], dict):
                current[item] = {}
            current = current[item]
        current[keys[-1]] = value

    def create_model_registry(self) -> "ModelRegistry":
        from vulnagent.llm.model_registry import ModelRegistry

        registry = ModelRegistry()
        registry.load_from_settings(self.all())
        return registry

    @staticmethod
    def _deep_merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
        result = dict(base)
        for key, value in override.items():
            if key in result and isinstance(result[key], dict) and isinstance(value, dict):
                result[key] = SettingsManager._deep_merge(result[key], value)
            else:
                result[key] = value
        return result
