"""Tests for SettingsManager."""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

import tempfile
import unittest
from pathlib import Path
from common.utils.settings import SettingsManager


class TestSettingsManager(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.settings = SettingsManager(project_root=Path(self.temp_dir.name))

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_load_returns_self(self):
        result = self.settings.load()
        self.assertIs(result, self.settings)

    def test_builtin_defaults(self):
        self.settings.load()
        self.assertEqual(self.settings.get("model.reasoning"), "gpt-4o")
        self.assertEqual(self.settings.get("model.routing"), "gpt-4o-mini")
        self.assertEqual(self.settings.get("agent.max_iterations"), 5)
        self.assertEqual(self.settings.get("agent.token_limit"), 100000)

    def test_get_with_default(self):
        self.settings.load()
        self.assertEqual(self.settings.get("nonexistent.key", "fallback"), "fallback")
        self.assertIsNone(self.settings.get("nonexistent.key"))

    def test_set_runtime_override(self):
        self.settings.load()
        self.settings.set("model.reasoning", "gpt-4o")
        self.assertEqual(self.settings.get("model.reasoning"), "gpt-4o")

    def test_runtime_override_priority(self):
        self.settings.load()
        original = self.settings.get("model.reasoning")
        self.settings.set("model.reasoning", "gpt-5.5-override")
        self.assertEqual(self.settings.get("model.reasoning"), "gpt-5.5-override")
        self.assertNotEqual(self.settings.get("model.reasoning"), original)

    def test_get_model_for(self):
        self.settings.load()
        model = self.settings.get_model_for("reasoning")
        self.assertEqual(model, "gpt-4o")

    def test_is_verbose(self):
        self.settings.load()
        self.assertFalse(self.settings.is_verbose())
        self.settings.set("debug.verbose", True)
        self.assertTrue(self.settings.is_verbose())

    def test_dump_config(self):
        self.settings.load()
        config = self.settings.dump_config()
        self.assertIn("effective", config)
        self.assertIn("loaded_from", config)

    def test_all_returns_full_dict(self):
        self.settings.load()
        all_settings = self.settings.all()
        self.assertIn("model", all_settings)
        self.assertIn("agent", all_settings)
        self.assertIn("memory", all_settings)

    def test_create_model_registry(self):
        self.settings.load()
        registry = self.settings.create_model_registry()
        self.assertIsNotNone(registry)
        from common.llm.model_registry import ModelRegistry
        self.assertIsInstance(registry, ModelRegistry)

    def test_dot_get_nested(self):
        data = {"a": {"b": {"c": 42}}}
        self.assertEqual(SettingsManager._dot_get(data, "a.b.c"), 42)
        self.assertEqual(SettingsManager._dot_get(data, "a.x", "default"), "default")

    def test_dot_set_nested(self):
        data = {}
        SettingsManager._dot_set(data, "a.b.c", 99)
        self.assertEqual(data["a"]["b"]["c"], 99)

    def test_deep_merge(self):
        base = {"a": 1, "b": {"x": 1}}
        override = {"b": {"y": 2}, "c": 3}
        result = SettingsManager._deep_merge(base, override)
        self.assertEqual(result["a"], 1)
        self.assertEqual(result["b"]["x"], 1)
        self.assertEqual(result["b"]["y"], 2)
        self.assertEqual(result["c"], 3)


if __name__ == "__main__":
    unittest.main()
