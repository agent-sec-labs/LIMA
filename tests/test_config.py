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

    def test_cxx_agent_settings_parse_mode_model_and_total_budgets(self):
        with patch.dict(
            os.environ,
            {
                "LIMA_CXX_AGENT_MODE": "required",
                "LIMA_CXX_AGENT_MODEL": "gpt-test",
                "LIMA_CXX_AGENT_MAX_CANDIDATES": "50",
                "LIMA_CXX_AGENT_MAX_CALLS": "20",
                "LIMA_CXX_AGENT_MAX_CONTEXT_FILES": "6",
                "LIMA_CXX_AGENT_MAX_CONTEXT_LINES": "600",
                "LIMA_CXX_AGENT_MAX_OUTPUT_BYTES": "524288",
                "LIMA_CXX_AGENT_TIMEOUT_SECONDS": "300",
                "LIMA_CXX_AGENT_PARALLELISM": "2",
                "LIMA_CXX_AGENT_DIALOGUE_ROUNDS": "1",
            },
            clear=True,
        ):
            settings = Settings.from_env()
        self.assertEqual("required", settings.cxx_agent_mode)
        self.assertEqual("gpt-test", settings.cxx_agent_model)
        self.assertEqual(50, settings.cxx_agent_max_candidates)
        self.assertEqual(20, settings.cxx_agent_max_calls)
        self.assertEqual(6, settings.cxx_agent_max_context_files)
        self.assertEqual(600, settings.cxx_agent_max_context_lines)
        self.assertEqual(524288, settings.cxx_agent_max_output_bytes)
        self.assertEqual(300, settings.cxx_agent_timeout_seconds)
        self.assertEqual(2, settings.cxx_agent_parallelism)
        self.assertEqual(1, settings.cxx_agent_dialogue_rounds)

    def test_cxx_agent_defaults_and_strict_mode(self):
        with patch.dict(os.environ, {}, clear=True):
            settings = Settings.from_env()
        self.assertEqual("off", settings.cxx_agent_mode)
        self.assertEqual("", settings.cxx_agent_model)
        self.assertEqual(100, settings.cxx_agent_max_candidates)
        self.assertEqual(40, settings.cxx_agent_max_calls)
        self.assertEqual(12, settings.cxx_agent_max_context_files)
        self.assertEqual(1200, settings.cxx_agent_max_context_lines)
        self.assertEqual(1048576, settings.cxx_agent_max_output_bytes)
        self.assertEqual(600, settings.cxx_agent_timeout_seconds)
        self.assertEqual(3, settings.cxx_agent_parallelism)
        self.assertEqual(2, settings.cxx_agent_dialogue_rounds)
        for mode in ("maybe", "on"):
            with patch.dict(
                os.environ, {"LIMA_CXX_AGENT_MODE": mode}, clear=True
            ):
                with self.subTest(mode=mode), self.assertRaisesRegex(
                    ValueError, "LIMA_CXX_AGENT_MODE"
                ):
                    Settings.from_env().validate_evolution()
        with patch.dict(
            os.environ,
            {"LIMA_CXX_AGENT_MODE": "required"},
            clear=True,
        ):
            with self.assertRaisesRegex(ValueError, "LIMA_CXX_AGENT_MODEL"):
                Settings.from_env().validate_evolution()
        for name in (
            "LIMA_CXX_AGENT_MAX_CANDIDATES",
            "LIMA_CXX_AGENT_MAX_CALLS",
            "LIMA_CXX_AGENT_MAX_CONTEXT_FILES",
            "LIMA_CXX_AGENT_MAX_CONTEXT_LINES",
            "LIMA_CXX_AGENT_MAX_OUTPUT_BYTES",
            "LIMA_CXX_AGENT_TIMEOUT_SECONDS",
            "LIMA_CXX_AGENT_PARALLELISM",
            "LIMA_CXX_AGENT_DIALOGUE_ROUNDS",
        ):
            with patch.dict(os.environ, {name: "0"}, clear=True):
                with self.subTest(name=name), self.assertRaisesRegex(
                    ValueError, name
                ):
                    Settings.from_env().validate_evolution()

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
