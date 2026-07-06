"""Configuration loader supporting YAML files and environment variables."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import yaml


class ConfigLoader:
    """Loads configuration from YAML files with environment variable overrides.

    Usage:
        config = ConfigLoader.from_yaml("config.yaml")
        config = ConfigLoader.from_env()
        config = ConfigLoader({"key": "value"})
        value = config.get("nested.key", default="fallback")
    """

    def __init__(self, data: dict[str, Any] | None = None) -> None:
        self._data = data or {}

    @classmethod
    def from_yaml(cls, path: str | Path) -> "ConfigLoader":
        with open(path, encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
        return cls(data)

    @classmethod
    def from_env(cls, prefix: str = "MYAGENTS_") -> "ConfigLoader":
        data: dict[str, Any] = {}
        for key, value in os.environ.items():
            if key.startswith(prefix):
                config_key = key[len(prefix):].lower()
                data[config_key] = value
        return cls(data)

    def get(self, key: str, default: Any = None) -> Any:
        """Get a config value by dot-separated key. Returns default if not found."""
        keys = key.split(".")
        current: Any = self._data
        for k in keys:
            if isinstance(current, dict) and k in current:
                current = current[k]
            else:
                return default
        return current

    def set(self, key: str, value: Any) -> None:
        """Set a config value by dot-separated key."""
        keys = key.split(".")
        current = self._data
        for k in keys[:-1]:
            if k not in current:
                current[k] = {}
            current = current[k]
        current[keys[-1]] = value

    def to_dict(self) -> dict[str, Any]:
        return dict(self._data)

    def __getitem__(self, key: str) -> Any:
        result = self.get(key)
        if result is None:
            raise KeyError(key)
        return result

    def __contains__(self, key: str) -> bool:
        return self.get(key) is not None
