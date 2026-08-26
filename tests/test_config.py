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

    def test_cxx_memory_settings_are_parsed_and_validated(self):
        values = {
            "LIMA_CXX_MEMORY_MODE": "required",
            "LIMA_CXX_ANALYZER_URL": "http://cxx-analyzer:8090",
            "LIMA_CXX_ANALYSIS_TIMEOUT_SECONDS": "41",
            "LIMA_CXX_MAX_RESPONSE_BYTES": "4096",
        }
        with patch.dict(os.environ, values, clear=True):
            settings = Settings.from_env()
            settings.validate_evolution()

        self.assertEqual("required", settings.cxx_memory_mode)
        self.assertEqual("http://cxx-analyzer:8090", settings.cxx_analyzer_url)
        self.assertEqual(41, settings.cxx_analysis_timeout_seconds)
        self.assertEqual(4096, settings.cxx_max_response_bytes)

    def test_cxx_memory_mode_rejects_unknown_value(self):
        with patch.dict(os.environ, {"LIMA_CXX_MEMORY_MODE": "maybe"}, clear=True):
            with self.assertRaisesRegex(ValueError, "LIMA_CXX_MEMORY_MODE"):
                Settings.from_env().validate_evolution()

    def test_cxx_analyzer_url_rejects_unsafe_or_invalid_components(self):
        invalid_urls = (
            "ftp://cxx-analyzer:8090",
            "http://user@cxx-analyzer:8090",
            "http://cxx-analyzer:8090?layer=source",
            "http://cxx-analyzer:8090#source",
            "http://cxx-analyzer:not-a-port",
        )
        for url in invalid_urls:
            with self.subTest(url=url), patch.dict(
                os.environ, {"LIMA_CXX_ANALYZER_URL": url}, clear=True
            ):
                with self.assertRaisesRegex(ValueError, "LIMA_CXX_ANALYZER_URL"):
                    Settings.from_env().validate_evolution()
