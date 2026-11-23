import os
import importlib
import unittest
from unittest.mock import patch

import config


class TestModelConfigDefaults(unittest.TestCase):
    """Tests that default model configuration uses flagship Gemini 4 models."""

    def test_default_models_are_gemini_4_flagships(self):
        env_overrides = {}
        with patch.dict(os.environ, env_overrides, clear=False):
            os.environ.pop("GEMINI_MODEL", None)
            os.environ.pop("ORCHESTRATOR_MODEL", None)
            os.environ.pop("SPECIALIST_MODEL", None)
            importlib.reload(config)
            self.assertEqual(config.Config.GEMINI_MODEL, "gemini-4-neon")
            self.assertEqual(config.Config.ORCHESTRATOR_MODEL, "gemini-4-carbon")
            self.assertEqual(config.Config.SPECIALIST_MODEL, "gemini-4-neon")


if __name__ == "__main__":
    unittest.main()
