"""Tests for ModelRegistry and ModelRouter."""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

import unittest
from unittest.mock import MagicMock, patch

from common.llm.client import LLMResponse, TokenUsage
from common.llm.model_registry import ModelRegistry, ProviderConfig, PurposeConfig


class TestProviderConfig(unittest.TestCase):

    def test_with_direct_key(self):
        cfg = ProviderConfig(name="test", base_url="http://localhost:8080/v1", api_key="sk-123")
        self.assertEqual(cfg.resolve_api_key(), "sk-123")

    def test_with_env_var(self):
        cfg = ProviderConfig(name="test", base_url="http://localhost:8080/v1", api_key_env="TEST_API_KEY")
        with patch.dict(os.environ, {"TEST_API_KEY": "env-key-value"}):
            self.assertEqual(cfg.resolve_api_key(), "env-key-value")

    def test_without_key(self):
        cfg = ProviderConfig(name="test", base_url="http://localhost:8080/v1")
        self.assertEqual(cfg.resolve_api_key(), "")

    def test_direct_key_priority_over_env(self):
        cfg = ProviderConfig(name="test", base_url="http://localhost:8080/v1",
                             api_key="direct", api_key_env="TEST_KEY")
        with patch.dict(os.environ, {"TEST_KEY": "from-env"}):
            self.assertEqual(cfg.resolve_api_key(), "direct")


class TestModelRegistry(unittest.TestCase):

    def setUp(self):
        self.registry = ModelRegistry()

    def test_add_provider(self):
        self.registry.add_provider(ProviderConfig(
            name="test_prov", base_url="http://localhost:11434/v1",
            api_key="sk-test", models=["model-a", "model-b"],
        ))
        self.assertIn("test_prov", self.registry.list_providers())

    def test_set_purpose(self):
        self.registry.add_provider(ProviderConfig(
            name="test_prov", base_url="http://localhost:11434/v1",
            api_key="sk-test", models=["model-a"],
        ))
        self.registry.set_purpose("reasoning", provider="test_prov", model="model-a")
        purpose = self.registry.get_purpose("reasoning")
        self.assertEqual(purpose.provider, "test_prov")
        self.assertEqual(purpose.model, "model-a")

    def test_default_purposes_exist(self):
        for purpose in ["reasoning", "routing", "critique", "compress", "default"]:
            cfg = self.registry.get_purpose(purpose)
            self.assertNotEqual(cfg.provider, "")
            self.assertNotEqual(cfg.model, "")

    def test_is_ready_false_when_no_key(self):
        self.registry.add_provider(ProviderConfig(
            name="test", base_url="http://localhost:8080/v1",
        ))
        self.assertFalse(self.registry.is_ready())

    def test_is_ready_true_when_has_key(self):
        self.registry.add_provider(ProviderConfig(
            name="test", base_url="http://localhost:8080/v1", api_key="sk-test",
        ))
        self.assertTrue(self.registry.is_ready())

    def test_list_available_providers(self):
        self.registry.add_provider(ProviderConfig(
            name="with_key", base_url="http://a:8080/v1", api_key="sk-1",
        ))
        self.registry.add_provider(ProviderConfig(
            name="no_key", base_url="http://b:8080/v1",
        ))
        available = self.registry.list_available_providers()
        with_key = [p for p in available if p["name"] == "with_key"]
        no_key = [p for p in available if p["name"] == "no_key"]
        self.assertTrue(with_key[0]["available"])
        self.assertFalse(no_key[0]["available"])

    def test_load_from_settings(self):
        settings = {
            "providers": {
                "test_p": {
                    "base_url": "http://localhost:8080/v1",
                    "api_key": "sk-abc",
                    "models": ["m1", "m2"],
                },
            },
            "purposes": {
                "reasoning": {"provider": "test_p", "model": "m1"},
            },
        }
        self.registry.load_from_settings(settings)
        self.assertIn("test_p", self.registry.list_providers())
        purpose = self.registry.get_purpose("reasoning")
        self.assertEqual(purpose.provider, "test_p")
        self.assertEqual(purpose.model, "m1")

    def test_dump_config(self):
        self.registry.add_provider(ProviderConfig(
            name="p1", base_url="http://localhost:8080/v1", api_key="key1",
        ))
        config = self.registry.dump_config()
        self.assertIn("providers", config)
        self.assertIn("purposes", config)
        self.assertTrue(config["providers"]["p1"]["has_key"])


class TestModelRouter(unittest.TestCase):

    def test_router_creation(self):
        from common.llm.model_router import ModelRouter
        registry = ModelRegistry()
        registry.add_provider(ProviderConfig(
            name="test", base_url="http://localhost:8080/v1", api_key="sk-test",
            models=["test-model"],
        ))
        registry.set_purpose("reasoning", provider="test", model="test-model")
        router = ModelRouter(registry)
        self.assertIs(router.registry, registry)
        self.assertEqual(router.stats, {})

    def test_router_stats_tracking_initial(self):
        from common.llm.model_router import ModelRouter
        registry = ModelRegistry()
        registry.add_provider(ProviderConfig(
            name="test", base_url="http://localhost:8080/v1", api_key="sk-test",
            models=["test-model"],
        ))
        router = ModelRouter(registry)
        self.assertIsInstance(router.stats, dict)

    def test_cost_mapping_has_known_models(self):
        from common.llm.model_router import ModelRouter
        registry = ModelRegistry()
        router = ModelRouter(registry)
        self.assertIn("gpt-4o", router._COST_PER_M_INPUT)
        self.assertIn("deepseek-chat", router._COST_PER_M_INPUT)
        self.assertIn("gpt-4o", router._COST_PER_M_INPUT)

    def test_usage_report_empty(self):
        from common.llm.model_router import ModelRouter
        registry = ModelRegistry()
        router = ModelRouter(registry)
        report = router.usage_report()
        self.assertIn("=== Model Usage Report ===", report)
        self.assertIn("TOTAL", report)

    def test_falls_back_when_primary_invoke_fails(self):
        from common.llm.model_router import ModelRouter

        registry = ModelRegistry()
        registry.add_provider(ProviderConfig(
            name="primary", base_url="http://primary/v1", api_key="sk-primary",
            models=["bad-model"],
        ))
        registry.add_provider(ProviderConfig(
            name="fallback", base_url="http://fallback/v1", api_key="sk-fallback",
            models=["good-model"],
        ))
        registry.set_purpose(
            "reasoning",
            provider="primary",
            model="bad-model",
            fallback_provider="fallback",
            fallback_model="good-model",
        )

        primary_client = MagicMock()
        primary_client.invoke.side_effect = RuntimeError("unknown provider for model")
        fallback_client = MagicMock()
        fallback_client.invoke.return_value = LLMResponse(
            content="OK",
            usage=TokenUsage(prompt_tokens=1, completion_tokens=2, total_tokens=3),
            model="good-model",
        )
        registry._clients["primary"] = primary_client
        registry._clients["fallback"] = fallback_client

        router = ModelRouter(registry)
        response = router.reason([{"role": "user", "content": "ping"}])

        self.assertEqual(response.content, "OK")
        primary_client.invoke.assert_called_once()
        fallback_client.invoke.assert_called_once()
        self.assertEqual(
            fallback_client.invoke.call_args.kwargs["model"],
            "good-model",
        )


if __name__ == "__main__":
    unittest.main()
