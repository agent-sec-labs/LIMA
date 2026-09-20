"""Contract tests for the versioned ``/v1/repro`` Sidecar protocol.

Platform plan Task 1: the reproduction workbench is a dedicated versioned
endpoint (never a ``requested_layers`` value).  The Sidecar compiles the
requested snapshot sources plus an untrusted PoC driver under ASan inside
the existing sandbox and returns a structured, bounded execution record.
The strict main-process client validates the closed response schema, both
echo identities and the experiment audit block.  The ``/v1/analyze``,
``/v1/uaf-facts`` and ``/health`` contracts must remain byte-for-byte
unchanged.
"""

import io
import json
import tempfile
import unittest
import urllib.error
from dataclasses import FrozenInstanceError
from pathlib import Path
from unittest.mock import Mock, patch

import cxx_analyzer.repro as repro
import cxx_analyzer.server as analyzer_server
from cxx_analyzer.config import AnalyzerSettings
from lima.cxx_memory import (
    CxxAnalyzerProtocolError,
    CxxAnalyzerUnavailable,
    CxxMemoryAnalyzerClient,
    ReproResponse,
)

REQUEST_ID = "00000000-0000-0000-0000-000000000003"
REPOSITORY_KEY = "team/project"
SNAPSHOT_SHA256 = "c" * 64
SOURCE_FILES = ("src/vuln.cpp",)
DRIVER_CODE = "#include <cstdio>\nint main() { return 0; }\n"
MAX_DRIVER_BYTES = 256 * 1024


def analyzer_settings() -> AnalyzerSettings:
    return AnalyzerSettings(
        auto_cmake=False,
        build_steps=(),
        test_steps=(),
        max_memory_mb=1024,
        max_processes=32,
        max_output_bytes=8192,
        step_timeout_seconds=17,
        total_timeout_seconds=90,
        repository_scan_max_files=100,
        repository_scan_max_file_bytes=4096,
        repository_scan_max_total_bytes=16384,
    )


def repro_request(**changes):
    payload = {
        "schema_version": 1,
        "request_id": REQUEST_ID,
        "repository_key": REPOSITORY_KEY,
        "snapshot_sha256": SNAPSHOT_SHA256,
        "source_files": list(SOURCE_FILES),
        "driver_code": DRIVER_CODE,
    }
    payload.update(changes)
    return payload


def repro_request_body(**changes):
    return json.dumps(repro_request(**changes)).encode("utf-8")


def asan_report_payload():
    return {
        "error_type": "heap-use-after-free",
        "access": "READ",
        "access_size": 4,
        "faulting_frame": {
            "function": "main",
            "file": "build/repro_driver_ab12cd34.cpp",
            "line": 6,
            "column": 30,
        },
        "freed_by_frame": {
            "function": "main",
            "file": "build/repro_driver_ab12cd34.cpp",
            "line": 5,
            "column": 5,
        },
        "allocated_by_frame": None,
        "raw_report_sha256": "b" * 64,
    }


def run_execution(**changes):
    fields = {
        "stage": "run",
        "ok": False,
        "exit_code": 1,
        "asan_report": asan_report_payload(),
        "diagnostics": (),
        "artifacts": {
            "driver_path": "build/repro_driver_ab12cd34.cpp",
            "binary_path": "build/repro_bin_ab12cd34",
            "driver_sha256": "d" * 64,
            "binary_sha256": "e" * 64,
        },
        "elapsed_seconds": 0.25,
    }
    fields.update(changes)
    return repro.ReproExecution(**fields)


def prepared_snapshot_mock(files=SOURCE_FILES):
    snapshot = Mock()
    snapshot.files = tuple(files)
    snapshot.verify_inventory = Mock()
    prepared = Mock()
    prepared.__enter__ = Mock(return_value=snapshot)
    prepared.__exit__ = Mock(return_value=False)
    prepared.cleanup = Mock()
    return prepared


class ServerContractTests(unittest.TestCase):
    def test_unknown_request_field_rejected(self):
        with self.assertRaises(analyzer_server.RequestError) as caught:
            analyzer_server.repro_request(repro_request(extra=True), analyzer_settings())
        self.assertEqual("invalid_request", caught.exception.code)
        self.assertEqual(400, caught.exception.status)

        missing = repro_request()
        missing.pop("driver_code")
        with self.assertRaises(analyzer_server.RequestError) as caught:
            analyzer_server.repro_request(missing, analyzer_settings())
        self.assertEqual("invalid_request", caught.exception.code)

        status, response = analyzer_server.dispatch_request(
            "POST",
            "/v1/repro",
            "application/json",
            json.dumps(repro_request(command=["echo", "secret"])).encode("utf-8"),
            analyzer_settings(),
         )
        self.assertEqual(400, status)
        self.assertEqual({"error", "request_id"}, set(response))
        self.assertEqual("invalid_request", response["error"])
        self.assertNotIn("secret", json.dumps(response))

    def test_wrong_schema_version_rejected(self):
        for version in (0, 2, "1", True, None, 1.0):
            with self.subTest(version=version):
                with self.assertRaises(analyzer_server.RequestError) as caught:
                    analyzer_server.repro_request(
                        repro_request(schema_version=version), analyzer_settings()
                     )
                self.assertEqual("unsupported_schema", caught.exception.code)
                self.assertEqual(400, caught.exception.status)

    def test_driver_code_size_capped(self):
        oversized = "int main() { return 0; }\n" + "x" * (MAX_DRIVER_BYTES + 16)
        with self.assertRaises(analyzer_server.RequestError) as caught:
            analyzer_server.repro_request(
                repro_request(driver_code=oversized), analyzer_settings()
             )
        self.assertEqual("invalid_request", caught.exception.code)

        for driver in ("", "\x00int main() {}\n", 42, None):
            with self.subTest(driver_code=repr(driver)[:20]):
                with self.assertRaises(analyzer_server.RequestError) as caught:
                    analyzer_server.repro_request(
                        repro_request(driver_code=driver), analyzer_settings()
                     )
                self.assertEqual("invalid_request", caught.exception.code)

        # At the boundary the request passes the closed-set validation and
        # fails later on the unknown snapshot (not invalid_request).
        boundary_driver = "int main() { return 0; }\n" + "x" * (
            MAX_DRIVER_BYTES - len("int main() { return 0; }\n")
        )
        self.assertEqual(MAX_DRIVER_BYTES, len(boundary_driver.encode("utf-8")))
        with self.assertRaises(analyzer_server.RequestError) as caught:
            analyzer_server.repro_request(
                repro_request(driver_code=boundary_driver), analyzer_settings()
             )
        self.assertEqual("snapshot_rejected", caught.exception.code)

    def test_oversized_request_rejected(self):
        status, response = analyzer_server.dispatch_request(
            "POST",
            "/v1/repro",
            "application/json",
            b"x" * (analyzer_server.REPRO_MAX_REQUEST_BYTES + 1),
            analyzer_settings(),
         )
        self.assertEqual(413, status)
        self.assertEqual("request_too_large", response["error"])

        # A driver-only request above the legacy 64 KiB cap but below the
        # repro cap reaches the handler (fails on the unknown snapshot only).
        large_driver = "x" * (analyzer_server.MAX_REQUEST_BYTES + 1)
        payload = repro_request(driver_code=large_driver)
        self.assertLess(len(json.dumps(payload).encode("utf-8")),
                        analyzer_server.REPRO_MAX_REQUEST_BYTES)
        status, response = analyzer_server.dispatch_request(
            "POST", "/v1/repro", "application/json",
            json.dumps(payload).encode("utf-8"), analyzer_settings(),
         )
        self.assertEqual(400, status)
        self.assertEqual("snapshot_rejected", response["error"])

    def test_source_files_closed_set_rejected(self):
        cases = (
            ("escape", ["../escape.cpp"]),
            ("absolute", ["/etc/passwd.cpp"]),
            ("traversal", ["src/./traversal.cpp"]),
            ("backslash", ["src\\vuln.cpp"]),
            ("empty-entry", ["src/ok.cpp", ""]),
            ("null", ["src/\x00null.cpp"]),
            ("empty-list", []),
            ("duplicates", ["src/a.cpp", "src/a.cpp"]),
            ("non-string", ["src/a.cpp", 3]),
            ("non-list", "src/a.cpp"),
            ("over-budget", [f"src/f{index}.cpp" for index in range(17)]),
        )
        for label, sources in cases:
            with self.subTest(source_files=label):
                with self.assertRaises(analyzer_server.RequestError) as caught:
                    analyzer_server.repro_request(
                        repro_request(source_files=sources), analyzer_settings()
                     )
                self.assertEqual("invalid_request", caught.exception.code)

    def test_snapshot_missing_source_file_rejected(self):
        from cxx_analyzer.snapshot import prepare_snapshot as real_prepare
        from lima.workspace import RepositoryWorkspace

        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            import_root = base / "imports"
            repository = import_root / "team" / "project"
            work_root = base / "snapshots"
            repository.mkdir(parents=True)
            work_root.mkdir()
            (repository / "src").mkdir()
            (repository / "src" / "vuln.cpp").write_text(
                "int main() { return 0; }\n", encoding="utf-8"
            )
            fingerprint = RepositoryWorkspace(repository).inventory().fingerprint()
            with patch(
                "cxx_analyzer.server.prepare_snapshot", side_effect=real_prepare
            ), patch("cxx_analyzer.repro.run_step") as step:
                status, response = analyzer_server.dispatch_request(
                    "POST",
                    "/v1/repro",
                    "application/json",
                    repro_request_body(
                        snapshot_sha256=fingerprint,
                        source_files=["src/absent.cpp"],
                    ),
                    analyzer_settings(),
                 )
        self.assertEqual(400, status)
        self.assertEqual("snapshot_rejected", response["error"])
        step.assert_not_called()

    @patch("cxx_analyzer.server.run_repro", return_value=run_execution())
    def test_response_carries_run_identity_and_hashes(self, run_mock):
        with patch(
            "cxx_analyzer.server.prepare_snapshot",
            return_value=prepared_snapshot_mock(),
        ):
            status, response = analyzer_server.dispatch_request(
                "POST",
                "/v1/repro",
                "application/json",
                repro_request_body(),
                analyzer_settings(),
             )
        self.assertEqual(200, status)
        self.assertEqual(
            {
                "schema_version",
                "request_id",
                "snapshot_sha256",
                "stage",
                "ok",
                "exit_code",
                "asan_report",
                "diagnostics",
                "experiment",
            },
            set(response),
         )
        self.assertEqual(1, response["schema_version"])
        self.assertEqual(REQUEST_ID, response["request_id"])
        self.assertEqual(SNAPSHOT_SHA256, response["snapshot_sha256"])
        self.assertEqual("run", response["stage"])
        self.assertIs(False, response["ok"])
        self.assertEqual(1, response["exit_code"])
        self.assertEqual(asan_report_payload(), response["asan_report"])
        self.assertEqual([], response["diagnostics"])
        self.assertEqual(
            {
                "driver_sha256": "d" * 64,
                "binary_sha256": "e" * 64,
                "elapsed_seconds": 0.25,
            },
            response["experiment"],
         )
        run_mock.assert_called_once()

    @patch(
        "cxx_analyzer.server.run_repro",
        return_value=run_execution(
            stage="compile",
            ok=False,
            exit_code=1,
            asan_report=None,
            diagnostics=("main.cpp:1:1: error: expected ';' after expression",),
            artifacts={
                "driver_path": "build/repro_driver_ab12cd34.cpp",
                "binary_path": "build/repro_bin_ab12cd34",
                "driver_sha256": "d" * 64,
                "binary_sha256": "",
            },
        ),
    )
    def test_compile_failure_response_has_no_report_and_empty_binary_hash(
        self, _run_mock
    ):
        with patch(
            "cxx_analyzer.server.prepare_snapshot",
            return_value=prepared_snapshot_mock(),
        ):
            status, response = analyzer_server.dispatch_request(
                "POST",
                "/v1/repro",
                "application/json",
                repro_request_body(),
                analyzer_settings(),
             )
        self.assertEqual(200, status)
        self.assertEqual("compile", response["stage"])
        self.assertIs(False, response["ok"])
        self.assertIsNone(response["asan_report"])
        self.assertEqual("", response["experiment"]["binary_sha256"])

    def test_existing_endpoints_and_shared_boundary_unchanged(self):
        # Frozen legacy closed sets: the repro endpoint added a path, never a
        # field or a layer on the old requests.
        self.assertEqual(
            frozenset({"request_id", "repository_key", "snapshot_sha256", "requested_layers"}),
            analyzer_server._REQUEST_FIELDS,
         )
        self.assertEqual(
            frozenset({"source-only", "build-backed", "sanitizer-confirmed"}),
            analyzer_server._SUPPORTED_LAYERS,
         )

        status, response = analyzer_server.dispatch_request(
            "GET", "/health", "", b"", analyzer_settings()
         )
        self.assertEqual(200, status)
        self.assertIn("schema_version", response)

        status, response = analyzer_server.dispatch_request(
            "GET", "/v1/repro", "", b"", analyzer_settings()
         )
        self.assertEqual(405, status)
        self.assertEqual("method_not_allowed", response["error"])

        status, response = analyzer_server.dispatch_request(
            "POST", "/v1/repro", "text/plain", repro_request_body(), analyzer_settings()
         )
        self.assertEqual(415, status)
        self.assertEqual("unsupported_media_type", response["error"])

        status, response = analyzer_server.dispatch_request(
            "POST", "/nope", "application/json", repro_request_body(), analyzer_settings()
         )
        self.assertEqual(404, status)
        self.assertEqual("not_found", response["error"])

        # The legacy cap still guards the analyze endpoint exactly.
        status, response = analyzer_server.dispatch_request(
            "POST",
            "/v1/analyze",
            "application/json",
            b"x" * (analyzer_server.MAX_REQUEST_BYTES + 1),
            analyzer_settings(),
         )
        self.assertEqual(413, status)
        self.assertEqual("request_too_large", response["error"])


class FakeResponse:
    def __init__(self, body):
        self.body = body
        self._stream = io.BytesIO(body)

    def read(self, size=-1):
        return self._stream.read(size)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        return False


class RecordingOpener:
    def __init__(self, payload=None, *, body=None, error=None):
        self.body = body if body is not None else json.dumps(payload).encode("utf-8")
        self.error = error
        self.request = None
        self.timeout = None

    def __call__(self, request, timeout):
        self.request = request
        self.timeout = timeout
        if self.error is not None:
            raise self.error
        return FakeResponse(self.body)


def repro_client(opener) -> CxxMemoryAnalyzerClient:
    return CxxMemoryAnalyzerClient(
        "http://cxx-analyzer:8090",
        timeout_seconds=30,
        max_response_bytes=1024 * 1024,
        opener=opener,
    )


def valid_repro_response_payload():
    return {
        "schema_version": 1,
        "request_id": REQUEST_ID,
        "snapshot_sha256": SNAPSHOT_SHA256,
        "stage": "run",
        "ok": False,
        "exit_code": 1,
        "asan_report": asan_report_payload(),
        "diagnostics": [],
        "experiment": {
            "driver_sha256": "d" * 64,
            "binary_sha256": "e" * 64,
            "elapsed_seconds": 0.25,
        },
    }


class ClientContractTests(unittest.TestCase):
    @patch("lima.cxx_memory.uuid.uuid4", return_value=REQUEST_ID)
    def test_repro_compile_run_validates_response_schema(self, _uuid4):
        opener = RecordingOpener(valid_repro_response_payload())
        client = repro_client(opener)

        result = client.repro_compile_run(
            REPOSITORY_KEY, SNAPSHOT_SHA256, SOURCE_FILES, DRIVER_CODE
        )

        self.assertEqual("http://cxx-analyzer:8090/v1/repro", opener.request.full_url)
        self.assertEqual("POST", opener.request.get_method())
        self.assertEqual("application/json", opener.request.get_header("Content-type"))
        self.assertEqual(30, opener.timeout)
        self.assertEqual(
            {
                "schema_version": 1,
                "request_id": REQUEST_ID,
                "repository_key": REPOSITORY_KEY,
                "snapshot_sha256": SNAPSHOT_SHA256,
                "source_files": list(SOURCE_FILES),
                "driver_code": DRIVER_CODE,
            },
            json.loads(opener.request.data.decode("utf-8")),
         )
        self.assertIsInstance(result, ReproResponse)
        self.assertEqual(REQUEST_ID, result.request_id)
        self.assertEqual(SNAPSHOT_SHA256, result.snapshot_sha256)
        self.assertEqual("run", result.stage)
        self.assertIs(False, result.ok)
        self.assertEqual(1, result.exit_code)
        self.assertEqual(asan_report_payload(), result.asan_report)
        self.assertEqual((), result.diagnostics)
        self.assertEqual("d" * 64, result.driver_sha256)
        self.assertEqual("e" * 64, result.binary_sha256)
        self.assertEqual(0.25, result.elapsed_seconds)
        with self.assertRaises(FrozenInstanceError):
            result.stage = "compile"

    @patch("lima.cxx_memory.uuid.uuid4", return_value=REQUEST_ID)
    def test_repro_compile_run_per_call_timeout_reaches_opener(self, _uuid4):
        # Round-3 acceptance contract: the deadline-bounded per-call wire
        # timeout overrides the client-level default on the real transport.
        opener = RecordingOpener(valid_repro_response_payload())
        client = repro_client(opener)

        client.repro_compile_run(
            REPOSITORY_KEY, SNAPSHOT_SHA256, SOURCE_FILES, DRIVER_CODE,
            timeout=7,
        )

        self.assertEqual(7, opener.timeout)

    @patch("lima.cxx_memory.uuid.uuid4", return_value=REQUEST_ID)
    def test_clean_run_response_accepted(self, _uuid4):
        payload = valid_repro_response_payload()
        payload.update({"stage": "run", "ok": True, "exit_code": 0, "asan_report": None})
        client = repro_client(RecordingOpener(payload))

        result = client.repro_compile_run(
            REPOSITORY_KEY, SNAPSHOT_SHA256, SOURCE_FILES, DRIVER_CODE
        )

        self.assertIs(True, result.ok)
        self.assertEqual(0, result.exit_code)
        self.assertIsNone(result.asan_report)

    @patch("lima.cxx_memory.uuid.uuid4", return_value=REQUEST_ID)
    def test_compile_stage_response_accepted(self, _uuid4):
        payload = valid_repro_response_payload()
        payload.update(
            {
                "stage": "compile",
                "ok": False,
                "exit_code": 1,
                "asan_report": None,
                "diagnostics": ["driver.cpp:2:5: error: use of undeclared identifier"],
                "experiment": {
                    "driver_sha256": "d" * 64,
                    "binary_sha256": "",
                    "elapsed_seconds": 0.1,
                },
            }
        )
        client = repro_client(RecordingOpener(payload))

        result = client.repro_compile_run(
            REPOSITORY_KEY, SNAPSHOT_SHA256, SOURCE_FILES, DRIVER_CODE
        )

        self.assertEqual("compile", result.stage)
        self.assertEqual(
            ("driver.cpp:2:5: error: use of undeclared identifier",), result.diagnostics
        )
        self.assertEqual("", result.binary_sha256)

    @patch("lima.cxx_memory.uuid.uuid4", return_value=REQUEST_ID)
    def test_malformed_asan_report_rejected(self, _uuid4):
        def extra_field(payload):
            payload["asan_report"]["symbolized"] = True

        def missing_digest(payload):
            payload["asan_report"].pop("raw_report_sha256")

        def bad_digest(payload):
            payload["asan_report"]["raw_report_sha256"] = "z" * 64

        def empty_error_type(payload):
            payload["asan_report"]["error_type"] = ""

        def unknown_access(payload):
            payload["asan_report"]["access"] = "Poke"

        def size_without_access(payload):
            payload["asan_report"]["access"] = None

        def mismatched_access_pair(payload):
            payload["asan_report"]["access"] = None
            payload["asan_report"]["access_size"] = 4

        def bad_access_size(payload):
            payload["asan_report"]["access_size"] = 0

        def frame_extra_field(payload):
            payload["asan_report"]["faulting_frame"]["module"] = "libc"

        def frame_bad_line(payload):
            payload["asan_report"]["faulting_frame"]["line"] = 0

        def frame_missing_file(payload):
            payload["asan_report"]["faulting_frame"].pop("file")

        def report_is_string(payload):
            payload["asan_report"] = "AddressSanitizer: heap-use-after-free"

        cases = (
            ("extra field", extra_field),
            ("missing digest", missing_digest),
            ("bad digest", bad_digest),
            ("empty error type", empty_error_type),
            ("unknown access", unknown_access),
            ("size without access", size_without_access),
            ("mismatched access pair", mismatched_access_pair),
            ("bad access size", bad_access_size),
            ("frame extra field", frame_extra_field),
            ("frame bad line", frame_bad_line),
            ("frame missing file", frame_missing_file),
            ("report is string", report_is_string),
        )
        for label, mutate in cases:
            with self.subTest(mutation=label):
                payload = valid_repro_response_payload()
                mutate(payload)
                client = repro_client(RecordingOpener(payload))
                with self.assertRaises(CxxAnalyzerProtocolError):
                    client.repro_compile_run(
                        REPOSITORY_KEY, SNAPSHOT_SHA256, SOURCE_FILES, DRIVER_CODE
                    )

    @patch("lima.cxx_memory.uuid.uuid4", return_value=REQUEST_ID)
    def test_unknown_response_field_or_schema_rejected(self, _uuid4):
        def top_level_extra(payload):
            payload["tool_runs"] = []

        def wrong_schema(payload):
            payload["schema_version"] = 2

        def wrong_request_id(payload):
            payload["request_id"] = "00000000-0000-0000-0000-000000000004"

        def wrong_snapshot(payload):
            payload["snapshot_sha256"] = "d" * 64

        def unknown_stage(payload):
            payload["stage"] = "link"

        def compile_stage_with_report(payload):
            payload["stage"] = "compile"

        def compile_stage_claiming_ok(payload):
            payload["stage"] = "compile"
            payload["asan_report"] = None
            payload["ok"] = True

        def clean_run_claiming_report(payload):
            payload["ok"] = True

        def clean_run_claiming_ok(payload):
            payload["asan_report"] = None
            payload["ok"] = True

        def bad_exit_code(payload):
            payload["exit_code"] = "1"

        def experiment_extra_field(payload):
            payload["experiment"]["cache_hit"] = True

        def experiment_bad_elapsed(payload):
            payload["experiment"]["elapsed_seconds"] = -1

        def experiment_bad_driver_hash(payload):
            payload["experiment"]["driver_sha256"] = "d"

        def oversized_diagnostic(payload):
            payload["diagnostics"] = ["x" * 4096]

        cases = (
            ("top-level extra field", top_level_extra),
            ("wrong schema", wrong_schema),
            ("wrong request id", wrong_request_id),
            ("wrong snapshot", wrong_snapshot),
            ("unknown stage", unknown_stage),
            ("compile stage with report", compile_stage_with_report),
            ("compile stage claiming ok", compile_stage_claiming_ok),
            ("failed run claiming report-free ok", clean_run_claiming_report),
            ("clean run claiming ok without zero exit", clean_run_claiming_ok),
            ("bad exit code", bad_exit_code),
            ("experiment extra field", experiment_extra_field),
            ("experiment bad elapsed", experiment_bad_elapsed),
            ("experiment bad driver hash", experiment_bad_driver_hash),
            ("oversized diagnostic", oversized_diagnostic),
        )
        for label, mutate in cases:
            with self.subTest(mutation=label):
                payload = valid_repro_response_payload()
                mutate(payload)
                client = repro_client(RecordingOpener(payload))
                with self.assertRaises(CxxAnalyzerProtocolError):
                    client.repro_compile_run(
                        REPOSITORY_KEY, SNAPSHOT_SHA256, SOURCE_FILES, DRIVER_CODE
                    )

    def test_transport_error_maps_to_unavailable(self):
        opener = RecordingOpener(error=urllib.error.URLError("connection refused"))
        client = repro_client(opener)
        with self.assertRaises(CxxAnalyzerUnavailable):
            client.repro_compile_run(
                REPOSITORY_KEY, SNAPSHOT_SHA256, SOURCE_FILES, DRIVER_CODE
            )
        self.assertIsNotNone(opener.request)

        opener = RecordingOpener(error=TimeoutError("timed out"))
        client = repro_client(opener)
        with self.assertRaises(CxxAnalyzerUnavailable):
            client.repro_compile_run(
                REPOSITORY_KEY, SNAPSHOT_SHA256, SOURCE_FILES, DRIVER_CODE
            )

    def test_client_input_contract_enforced_before_network(self):
        bad_inputs = (
            ((REPOSITORY_KEY, SNAPSHOT_SHA256, (), DRIVER_CODE), "no sources"),
            ((REPOSITORY_KEY, SNAPSHOT_SHA256, ("../escape.cpp",), DRIVER_CODE), "escape"),
            (
                (REPOSITORY_KEY, SNAPSHOT_SHA256,
                 tuple(f"src/{index}.cpp" for index in range(17)), DRIVER_CODE),
                "over budget",
            ),
            (
                (REPOSITORY_KEY, SNAPSHOT_SHA256, ("src/a.cpp", "src/a.cpp"), DRIVER_CODE),
                "duplicates",
            ),
            ((REPOSITORY_KEY, SNAPSHOT_SHA256, ("src\\a.cpp",), DRIVER_CODE), "backslash"),
            ((REPOSITORY_KEY, "A" * 64, SOURCE_FILES, DRIVER_CODE), "bad digest"),
            ((REPOSITORY_KEY, SNAPSHOT_SHA256, SOURCE_FILES, ""), "empty driver"),
            (
                (REPOSITORY_KEY, SNAPSHOT_SHA256, SOURCE_FILES,
                 "x" * (MAX_DRIVER_BYTES + 1)),
                "oversized driver",
            ),
            ((REPOSITORY_KEY, SNAPSHOT_SHA256, SOURCE_FILES, "int\x00main() {}"), "nul driver"),
        )
        for arguments, label in bad_inputs:
            with self.subTest(input=label):
                opener = RecordingOpener(valid_repro_response_payload())
                fresh = repro_client(opener)
                with self.assertRaises(CxxAnalyzerProtocolError):
                    fresh.repro_compile_run(*arguments)
                self.assertIsNone(opener.request, f"network reached for {label}")


if __name__ == "__main__":
    unittest.main()
