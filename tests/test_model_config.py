import os
import importlib
import unittest
from unittest.mock import patch, MagicMock

import config
from agent import FortiGateAgent
from core.llm_provider import GeminiLLMProvider, ModelConfig, ModelRegistry
from core.schemas import AgentRole
from fortigate_client import FortiGateClient


class TestModelConfigDefaults(unittest.TestCase):
    """Tests that default model configuration uses flagship Gemini 4 models and thinking_level."""

    def test_default_models_and_thinking_levels(self):
        with patch.dict(os.environ, {}, clear=False):
            for k in (
                "GEMINI_MODEL",
                "ORCHESTRATOR_MODEL",
                "SPECIALIST_MODEL",
                "GEMINI_THINKING_LEVEL",
                "ORCHESTRATOR_THINKING_LEVEL",
                "SPECIALIST_THINKING_LEVEL",
            ):
                os.environ.pop(k, None)
            importlib.reload(config)
            self.assertEqual(config.Config.GEMINI_MODEL, "gemini-4-neon")
            self.assertEqual(config.Config.ORCHESTRATOR_MODEL, "gemini-4-carbon")
            self.assertEqual(config.Config.SPECIALIST_MODEL, "gemini-4-neon")
            self.assertEqual(config.Config.GEMINI_THINKING_LEVEL, "MEDIUM")
            self.assertEqual(config.Config.ORCHESTRATOR_THINKING_LEVEL, "HIGH")

            reg = ModelRegistry()
            orch_cfg = reg.get_model_config(AgentRole.ORCHESTRATOR)
            net_cfg = reg.get_model_config(AgentRole.NETWORK)
            self.assertEqual(orch_cfg.thinking_level, "HIGH")
            self.assertIsNone(orch_cfg.temperature)
            self.assertEqual(net_cfg.thinking_level, "MEDIUM")
            self.assertIsNone(net_cfg.temperature)

    def test_gemini_4_omits_temperature_and_sets_thinking_config(self):
        client = FortiGateClient(host="10.0.0.1", token="tok", mock=True)
        with patch("agent.genai.Client"):
            ag = FortiGateAgent(fg_client=client, api_key="dummy")
            ag.model = "gemini-4-carbon"
            ag.thinking_level = "HIGH"
            gen_cfg = ag._build_generate_config()
            self.assertIsNone(gen_cfg.temperature)
            self.assertIsNotNone(gen_cfg.thinking_config)
            self.assertEqual(str(gen_cfg.thinking_config.thinking_level.value), "HIGH")

            # Legacy model fallback keeps temperature=0.2 and omits thinking_config
            ag.model = "gemini-2.5-pro"
            legacy_cfg = ag._build_generate_config()
            self.assertEqual(legacy_cfg.temperature, 0.2)
            self.assertIsNone(legacy_cfg.thinking_config)


if __name__ == "__main__":
    unittest.main()
