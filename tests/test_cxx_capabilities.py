"""Executable-capability contracts for the C/C++ analyzer health boundary."""

from __future__ import annotations

import importlib
import unittest
from types import SimpleNamespace
from unittest import mock

from cxx_analyzer import server
from cxx_analyzer.config import AnalyzerSettings
from lima.cxx_memory import CxxAnalyzerProtocolError, CxxMemoryAnalyzerClient


def analyzer_settings(**changes: object) -> AnalyzerSettings:
    values: dict[str, object] = {
        "auto_cmake": True,
        "build_steps": (),
        "test_steps": (),
        "max_memory_mb": 1024,
        "max_processes": 32,
        "max_output_bytes": 8192,
        "step_timeout_seconds": 10,
        "total_timeout_seconds": 30,
        "repository_scan_max_files": 100,
        "repository_scan_max_file_bytes": 4096,
        "repository_scan_max_total_bytes": 16384,
    }
    values.update(changes)
    return AnalyzerSettings(**values)  # type: ignore[arg-type]


def health_with(
    tools: dict[str, object] | None = None,
    *,
    auto_cmake: bool = True,
    build_steps: tuple[tuple[str, ...], ...] = (),
    test_steps: tuple[tuple[str, ...], ...] = (),
    landlock_abi: int = 4,
    process_isolation: bool = True,
) -> dict[str, object]:
    """Probe one health payload from the exact executability inputs."""

    paths = {
        "semgrep": "/usr/bin/semgrep",
        "cmake": "/usr/bin/cmake",
        "clang-14": "/usr/bin/clang-14",
        "clang++-14": "/usr/bin/clang++-14",
    }
    paths.update(
        {name: (value if value else None) for name, value in (tools or {}).items()}
    )
    settings = analyzer_settings(
        auto_cmake=auto_cmake, build_steps=build_steps, test_steps=test_steps
    )
    with (
        mock.patch.object(server.shutil, "which", side_effect=paths.get),
        mock.patch.object(server.sandbox, "landlock_abi", return_value=landlock_abi),
        mock.patch.object(
            server.sandbox, "process_isolation_available", return_value=process_isolation
        ),
    ):
        return server.health_payload(settings)


_HEALTH_FIELDS = {
    "schema_version",
    "source_available",
    "build_available",
    "test_configured",
    "clang_c_available",
    "clang_cxx_available",
    "cmake_available",
    "landlock_available",
    "process_isolation_available",
}


class SidecarHealthCapabilityTests(unittest.TestCase):
    def test_auto_cmake_without_cmake_disables_build(self):
        health = health_with(tools={"clang-14": True, "clang++-14": True, "cmake": False})
        self.assertFalse(health["build_available"])

    def test_missing_either_clang_driver_disables_build(self):
        for missing in ("clang-14", "clang++-14"):
            with self.subTest(missing=missing):
                health = health_with(tools={missing: None})
                self.assertFalse(health["build_available"])

    def test_explicit_build_steps_do_not_require_cmake(self):
        health = health_with(tools={"cmake": None}, build_steps=(("make", "all"),))
        self.assertTrue(health["build_available"])

    def test_sandbox_unavailability_disables_source_and_build(self):
        for landlock_abi, process_isolation in ((2, True), (4, False)):
            with self.subTest(
                landlock_abi=landlock_abi, process_isolation=process_isolation
            ):
                health = health_with(
                    tools={}, landlock_abi=landlock_abi,
                    process_isolation=process_isolation,
                )
                self.assertFalse(health["source_available"])
                self.assertFalse(health["build_available"])
                self.assertTrue(health["landlock_available"] is (landlock_abi >= 3))
                self.assertEqual(process_isolation, health["process_isolation_available"])

    def test_source_requires_semgrep_independent_of_build(self):
        health = health_with(tools={"semgrep": None})
        self.assertFalse(health["source_available"])
        self.assertTrue(health["build_available"])

    def test_test_steps_are_reported_as_configuration_only(self):
        self.assertFalse(health_with(tools={})["test_configured"])
        self.assertTrue(
            health_with(tools={}, test_steps=(("ctest",),))["test_configured"]
        )

    def test_health_exposes_only_the_exact_versioned_field_set(self):
        health = health_with(tools={})
        self.assertEqual(_HEALTH_FIELDS, set(health))
        self.assertEqual(1, health["schema_version"])
        for field in _HEALTH_FIELDS - {"schema_version"}:
            self.assertIs(bool, type(health[field]), field)


class ClientHealthContractTests(unittest.TestCase):
    @staticmethod
    def _client(payload: object) -> CxxMemoryAnalyzerClient:
        import io
        import json

        class Response(io.BytesIO):
            def __init__(self, body: object):
                if isinstance(body, (bytes, bytearray)):
                    super().__init__(bytes(body))
                else:
                    super().__init__(json.dumps(body).encode("utf-8"))

            def __enter__(self):
                return self

            def __exit__(self, *args: object) -> bool:
                return False

        return CxxMemoryAnalyzerClient(
            "http://analyzer", 30, 1_000_000, mock.Mock(return_value=Response(payload))
        )

    def test_client_accepts_the_executable_capability_shape(self):
        health = self._client(
            {
                "schema_version": 1,
                "source_available": True,
                "build_available": True,
                "test_configured": False,
                "clang_c_available": True,
                "clang_cxx_available": True,
                "cmake_available": True,
                "landlock_available": True,
                "process_isolation_available": True,
            }
        ).health()
        self.assertTrue(health.source_available)
        self.assertTrue(health.build_available)
        self.assertFalse(health.test_configured)

    def test_client_rejects_legacy_or_fuzzed_health_shapes(self):
        legacy = {
            "schema_version": 1,
            "tools": {"semgrep": True, "cmake": True, "clang": True},
            "configuration": {"source": True, "build": True, "test": False},
        }
        with self.assertRaises(CxxAnalyzerProtocolError):
            self._client(legacy).health()

        base = {
            "schema_version": 1,
            "source_available": True,
            "build_available": True,
            "test_configured": False,
            "clang_c_available": True,
            "clang_cxx_available": True,
            "cmake_available": True,
            "landlock_available": True,
            "process_isolation_available": True,
        }
        for name, mutate in (
            ("extra field", lambda value: value.update({"unexpected": True})),
            ("missing field", lambda value: value.pop("cmake_available")),
            ("non-boolean", lambda value: value.update({"cmake_available": "yes"})),
            ("wrong version", lambda value: value.update({"schema_version": 2})),
        ):
            with self.subTest(name=name):
                import copy

                payload = copy.deepcopy(base)
                mutate(payload)
                with self.assertRaises(CxxAnalyzerProtocolError):
                    self._client(payload).health()


class ServiceCapabilityTests(unittest.TestCase):
    @staticmethod
    def _health(
        *,
        source_available: bool = True,
        build_available: bool = False,
        test_configured: bool = False,
    ):
        from lima.cxx_memory import CxxAnalyzerHealth

        return CxxAnalyzerHealth(
            schema_version=1,
            source_available=source_available,
            build_available=build_available,
            test_configured=test_configured,
            clang_c_available=True,
            clang_cxx_available=True,
            cmake_available=True,
            landlock_available=True,
            process_isolation_available=True,
        )

    @staticmethod
    def _service(health: object) -> SimpleNamespace:
        service_module = importlib.import_module("lima.service")
        service = object.__new__(service_module.ReviewService)
        service.repository_import = SimpleNamespace(capabilities=lambda: {})
        service.settings = SimpleNamespace(
            repository_scan_sources="local-import",
            repository_scan_llm_mode="off",
            repository_scan_llm_max_candidates=6,
            repository_scan_llm_max_context_chars=36_000,
            repository_scan_llm_max_completion_tokens=3_000,
            repository_scan_sast_mode="off",
            repair_test_command=(),
            cxx_memory_mode="auto",
            cxx_analyzer_url="http://analyzer",
            repository_scan_max_files=100,
            repository_scan_max_file_bytes=4096,
            repository_scan_max_total_bytes=16384,
        )
        service.llm_config = None
        service.repository_semantic_triage = None
        service.repository_scanner = SimpleNamespace(
            python_dataflow=SimpleNamespace(max_call_depth=4),
            cxx_memory_adapter=SimpleNamespace(health=lambda: health),
        )
        return service

    def test_layer_availability_comes_from_probed_executability(self):
        cxx = self._service(
            self._health(source_available=True, build_available=False, test_configured=True)
        ).repository_scan_capabilities()["cxx_memory"]
        self.assertEqual("available", cxx["health_status"])
        self.assertTrue(cxx["source_layer_available"])
        self.assertFalse(cxx["build_layer_available"])
        self.assertFalse(cxx["sanitizer_layer_available"])

    def test_sanitizer_needs_build_and_test_configuration(self):
        cxx = self._service(
            self._health(source_available=True, build_available=True, test_configured=True)
        ).repository_scan_capabilities()["cxx_memory"]
        self.assertTrue(cxx["sanitizer_layer_available"])
        self.assertTrue(cxx["capabilities"]["test_configured"])

    def test_capabilities_are_absent_when_health_is_unreachable(self):
        def unavailable() -> object:
            raise importlib.import_module("lima.cxx_memory").CxxAnalyzerUnavailable(
                "offline"
            )

        service = self._service(None)
        service.repository_scanner.cxx_memory_adapter = SimpleNamespace(
            health=unavailable
        )
        cxx = service.repository_scan_capabilities()["cxx_memory"]
        self.assertEqual("unavailable", cxx["health_status"])
        self.assertIsNone(cxx["capabilities"])
        self.assertFalse(cxx["source_layer_available"])


if __name__ == "__main__":
    unittest.main()
