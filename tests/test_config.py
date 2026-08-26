import os
import tempfile
import unittest
from unittest.mock import patch

from lima.config import Settings, load_dotenv


class DotenvTests(unittest.TestCase):
    def test_loads_valid_assignments_and_quoted_values(self):
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", delete=False) as handle:
            handle.write("# comment\n")
            handle.write("export LIMA_LLM_PROVIDER=deepseek\n")
            handle.write('LIMA_DEEPSEEK_API_KEY="test-key"\n')
            handle.write("invalid line\n")
            path = handle.name
        try:
            with patch.dict(os.environ, {}, clear=True):
                load_dotenv([path])
                self.assertEqual("deepseek", os.environ["LIMA_LLM_PROVIDER"])
                self.assertEqual("test-key", os.environ["LIMA_DEEPSEEK_API_KEY"])
        finally:
            os.unlink(path)

    def test_process_environment_has_priority(self):
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", delete=False) as handle:
            handle.write("LIMA_LLM_PROVIDER=deepseek\n")
            path = handle.name
        try:
            with patch.dict(os.environ, {"LIMA_LLM_PROVIDER": "custom"}, clear=True):
                load_dotenv([path])
                self.assertEqual("custom", os.environ["LIMA_LLM_PROVIDER"])
        finally:
            os.unlink(path)

    def test_legacy_prefix_is_promoted_without_overriding_lima(self):
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", delete=False) as handle:
            handle.write("EVOAGENT_LLM_PROVIDER=deepseek\n")
            handle.write("EVOAGENT_DEEPSEEK_API_KEY=legacy-key\n")
            path = handle.name
        try:
            with patch.dict(os.environ, {"LIMA_LLM_PROVIDER": "local"}, clear=True):
                load_dotenv([path])
                self.assertEqual("local", os.environ["LIMA_LLM_PROVIDER"])
                self.assertEqual("legacy-key", os.environ["LIMA_DEEPSEEK_API_KEY"])
                self.assertEqual("local", Settings.from_env().llm_provider)
        finally:
            os.unlink(path)

    def test_repository_semantic_triage_budget_is_loaded_and_validated(self):
        environment = {
            "LIMA_REPOSITORY_SCAN_LLM_MODE": "auto",
            "LIMA_REPOSITORY_SCAN_LLM_TIMEOUT_SECONDS": "30",
            "LIMA_REPOSITORY_SCAN_LLM_MAX_CANDIDATES": "4",
            "LIMA_REPOSITORY_SCAN_LLM_MAX_CONTEXT_CHARS": "12000",
            "LIMA_REPOSITORY_SCAN_LLM_MAX_COMPLETION_TOKENS": "900",
        }
        with patch.dict(os.environ, environment, clear=True):
            settings = Settings.from_env()

        settings.validate_evolution()
        self.assertEqual("auto", settings.repository_scan_llm_mode)
        self.assertEqual(30, settings.repository_scan_llm_timeout_seconds)
        self.assertEqual(4, settings.repository_scan_llm_max_candidates)
        self.assertEqual(12000, settings.repository_scan_llm_max_context_chars)
        self.assertEqual(900, settings.repository_scan_llm_max_completion_tokens)

    def test_legacy_real_api_configuration_remains_resolvable(self):
        legacy = {
            "EVOAGENT_LLM_PROVIDER": "deepseek",
            "EVOAGENT_DEEPSEEK_API_KEY": "legacy-real-key",
        }
        with patch.dict(os.environ, legacy, clear=True):
            load_dotenv([])
            resolved = Settings.from_env().resolved_llm()
            self.assertEqual("deepseek", resolved["provider"])
            self.assertEqual("legacy-real-key", resolved["api_key"])
