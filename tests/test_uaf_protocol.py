"""Contract tests for the versioned ``/v1/uaf-facts`` Sidecar protocol.

UAF v2 plan Task 2: the facts channel is a dedicated versioned endpoint
(never a ``requested_layers`` value), served by a strict skeleton that
returns a legal ``extraction: unavailable`` empty bundle per translation
unit, and consumed by a strict main-process client that re-derives the
bundle hash independently.  Old ``/v1/analyze`` and ``/health`` contracts
must remain byte-for-byte unchanged.
"""

import hashlib
import io
import json
import unittest
import urllib.error
from dataclasses import FrozenInstanceError
from unittest.mock import patch

import cxx_analyzer.server as analyzer_server
from cxx_analyzer.config import AnalyzerSettings
from lima.cxx_memory import (
    CxxAnalyzerProtocolError,
    CxxAnalyzerUnavailable,
    CxxMemoryAnalyzerClient,
    UafFactsResponse,
)

REQUEST_ID = "00000000-0000-0000-0000-000000000001"
REPOSITORY_KEY = "team/project"
SNAPSHOT_SHA256 = "a" * 64
TRANSLATION_UNITS = ("src/a.cpp", "src/b.cpp")


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


def uaf_request(**changes):
    payload = {
        "schema_version": 1,
        "request_id": REQUEST_ID,
        "repository_key": REPOSITORY_KEY,
        "snapshot_sha256": SNAPSHOT_SHA256,
        "translation_units": list(TRANSLATION_UNITS),
        "build_context": {"mode": "snapshot-compdb"},
    }
    payload.update(changes)
    return payload


def uaf_request_body(**changes):
    return json.dumps(uaf_request(**changes)).encode("utf-8")


def bundle_sha256(translation_units):
    """The frozen bundle digest both protocol sides must agree on."""
    material = json.dumps(
        {"translation_units": translation_units},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    return hashlib.sha256(material).hexdigest()


def skeleton_unit_entry(translation_unit):
    return {
        "translation_unit": translation_unit,
        "extraction": "unavailable",
        "build_context": {
            "status": "unavailable",
            "source_kind": "",
            "context_hash": "",
            "diagnostics": [],
        },
        "coverage": {
            "ast_complete": False,
            "cfg_complete": False,
            "semantic_gaps": ["extraction-not-implemented"],
        },
        "facts": [],
    }


def valid_uaf_response_payload():
    entries = [skeleton_unit_entry(unit) for unit in TRANSLATION_UNITS]
    return {
        "schema_version": 1,
        "request_id": REQUEST_ID,
        "repository_key": REPOSITORY_KEY,
        "snapshot_sha256": SNAPSHOT_SHA256,
        "tool_runs": [{"run_id": "run-uaf-1", "tool": "uaf-facts", "status": "unavailable"}],
        "translation_units": entries,
        "bundle_sha256": bundle_sha256(entries),
        "diagnostics": [],
    }


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


def uaf_client(opener) -> CxxMemoryAnalyzerClient:
    return CxxMemoryAnalyzerClient(
        "http://cxx-analyzer:8090",
        timeout_seconds=8,
        max_response_bytes=64 * 1024,
        opener=opener,
    )


def request_uaf_facts(client, units=TRANSLATION_UNITS, mode="snapshot-compdb"):
    return client.analyze_uaf_facts(
        REPOSITORY_KEY, SNAPSHOT_SHA256, units, mode
    )


class ServerContractTests(unittest.TestCase):
    def test_unknown_request_field_rejected(self):
        with self.assertRaises(analyzer_server.RequestError) as caught:
            analyzer_server.uaf_facts_request(uaf_request(extra=True), analyzer_settings())
        self.assertEqual("invalid_request", caught.exception.code)
        self.assertEqual(400, caught.exception.status)

        missing = uaf_request()
        missing.pop("build_context")
        with self.assertRaises(analyzer_server.RequestError) as caught:
            analyzer_server.uaf_facts_request(missing, analyzer_settings())
        self.assertEqual("invalid_request", caught.exception.code)

        status, response = analyzer_server.dispatch_request(
            "POST",
            "/v1/uaf-facts",
            "application/json",
            uaf_request_body(command=["echo", "secret"]),
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
                    analyzer_server.uaf_facts_request(
                        uaf_request(schema_version=version), analyzer_settings()
                     )
                self.assertEqual(400, caught.exception.status)

    def test_oversized_request_rejected(self):
        status, response = analyzer_server.dispatch_request(
            "POST",
            "/v1/uaf-facts",
            "application/json",
            b"x" * (analyzer_server.MAX_REQUEST_BYTES + 1),
            analyzer_settings(),
         )
        self.assertEqual(413, status)
        self.assertEqual("request_too_large", response["error"])

    def test_response_carries_bundle_hash_and_tool_run(self):
        status, response = analyzer_server.dispatch_request(
            "POST", "/v1/uaf-facts", "application/json", uaf_request_body(), analyzer_settings()
         )
        self.assertEqual(200, status)
        self.assertEqual(
            {
                "schema_version",
                "request_id",
                "repository_key",
                "snapshot_sha256",
                "tool_runs",
                "translation_units",
                "bundle_sha256",
                "diagnostics",
            },
            set(response),
         )
        self.assertEqual(1, response["schema_version"])
        self.assertEqual(REQUEST_ID, response["request_id"])
        self.assertEqual(REPOSITORY_KEY, response["repository_key"])
        self.assertEqual(SNAPSHOT_SHA256, response["snapshot_sha256"])
        self.assertEqual([], response["diagnostics"])

        self.assertEqual(1, len(response["tool_runs"]))
        tool_run = response["tool_runs"][0]
        self.assertEqual({"run_id", "tool", "status"}, set(tool_run))
        self.assertEqual("uaf-facts", tool_run["tool"])
        self.assertEqual("unavailable", tool_run["status"])
        self.assertTrue(tool_run["run_id"])

        self.assertEqual(len(TRANSLATION_UNITS), len(response["translation_units"]))
        served = response["translation_units"]
        for entry, requested in zip(served, TRANSLATION_UNITS, strict=True):
            self.assertEqual(
                {"translation_unit", "extraction", "build_context", "coverage", "facts"},
                set(entry),
             )
            self.assertEqual(requested, entry["translation_unit"])
            self.assertEqual("unavailable", entry["extraction"])
            self.assertEqual(
                {"status", "source_kind", "context_hash", "diagnostics"},
                set(entry["build_context"]),
             )
            self.assertEqual("unavailable", entry["build_context"]["status"])
            self.assertEqual(
                {"ast_complete", "cfg_complete", "semantic_gaps"}, set(entry["coverage"])
             )
            self.assertIs(False, entry["coverage"]["ast_complete"])
            self.assertIs(False, entry["coverage"]["cfg_complete"])
            self.assertEqual(["extraction-not-implemented"], entry["coverage"]["semantic_gaps"])
            self.assertEqual([], entry["facts"])

        # The bundle digest is the frozen canonical serialization of exactly
        # the served translation units, re-derived with the same algorithm.
        self.assertEqual(bundle_sha256(response["translation_units"]), response["bundle_sha256"])
        digest = response["bundle_sha256"]
        self.assertTrue(all(character in "0123456789abcdef" for character in digest))

        # Deterministic bundles: identical requests hash identically even
        # though each run carries a fresh run_id.
        again = analyzer_server.uaf_facts_request(uaf_request(), analyzer_settings())
        self.assertEqual(response["bundle_sha256"], again["bundle_sha256"])
        self.assertNotEqual(response["tool_runs"][0]["run_id"], again["tool_runs"][0]["run_id"])

    def test_translation_unit_path_escape_rejected(self):
        escapes = (
            "../escape.cpp",
            "/etc/passwd.cpp",
            "src/../../escape.cpp",
            "src/./traversal.cpp",
            "src\\backslash.cpp",
            "",
            "src/\x00null.cpp",
         )
        for unit in escapes:
            with self.subTest(translation_unit=unit):
                with self.assertRaises(analyzer_server.RequestError) as caught:
                    analyzer_server.uaf_facts_request(
                        uaf_request(translation_units=["src/ok.cpp", unit]),
                        analyzer_settings(),
                     )
                self.assertEqual("invalid_request", caught.exception.code)

    def test_too_many_translation_units_rejected(self):
        cases = (
            ("over budget", [f"src/file{index}.cpp" for index in range(17)]),
            ("empty", []),
            ("duplicate", ["src/a.cpp", "src/a.cpp"]),
            ("non-string", ["src/a.cpp", 3]),
            ("non-list", "src/a.cpp"),
         )
        for label, units in cases:
            with self.subTest(label=label):
                with self.assertRaises(analyzer_server.RequestError) as caught:
                    analyzer_server.uaf_facts_request(
                        uaf_request(translation_units=units), analyzer_settings()
                     )
                self.assertEqual("invalid_request", caught.exception.code)

        boundary = [f"src/file{index}.cpp" for index in range(16)]
        result = analyzer_server.uaf_facts_request(
            uaf_request(translation_units=boundary), analyzer_settings()
         )
        self.assertEqual(16, len(result["translation_units"]))

    def test_existing_analyze_layers_unchanged(self):
        # Frozen legacy closed sets: the new endpoint added a path, never a
        # layer or a field on the old request.
        self.assertEqual(
            frozenset({"request_id", "repository_key", "snapshot_sha256", "requested_layers"}),
            analyzer_server._REQUEST_FIELDS,
         )
        self.assertEqual(
            frozenset({"source-only", "build-backed", "sanitizer-confirmed"}),
            analyzer_server._SUPPORTED_LAYERS,
         )

        old_payload = {
            "request_id": REQUEST_ID,
            "repository_key": REPOSITORY_KEY,
            "snapshot_sha256": SNAPSHOT_SHA256,
            "requested_layers": ["unknown-layer"],
        }
        with self.assertRaises(analyzer_server.RequestError) as caught:
            analyzer_server.analyze_request(old_payload, analyzer_settings())
        self.assertEqual("invalid_request", caught.exception.code)

        with self.assertRaises(analyzer_server.RequestError) as caught:
            analyzer_server.analyze_request(
                {**old_payload, "requested_layers": ["source-only"], "schema_version": 1},
                analyzer_settings(),
             )
        self.assertEqual("invalid_request", caught.exception.code)

        status, response = analyzer_server.dispatch_request(
            "GET", "/v1/analyze", "", b"", analyzer_settings()
         )
        self.assertEqual(405, status)
        self.assertEqual("method_not_allowed", response["error"])

        status, response = analyzer_server.dispatch_request(
            "POST", "/nope", "application/json", b"{}", analyzer_settings()
         )
        self.assertEqual(404, status)
        self.assertEqual("not_found", response["error"])

        # The new endpoint rides the same shared HTTP boundary errors.
        status, response = analyzer_server.dispatch_request(
            "GET", "/v1/uaf-facts", "", b"", analyzer_settings()
         )
        self.assertEqual(405, status)
        self.assertEqual("method_not_allowed", response["error"])
        status, response = analyzer_server.dispatch_request(
            "POST", "/v1/uaf-facts", "text/plain", uaf_request_body(), analyzer_settings()
         )
        self.assertEqual(415, status)
        self.assertEqual("unsupported_media_type", response["error"])


class ClientContractTests(unittest.TestCase):
    @patch("lima.cxx_memory.uuid.uuid4", return_value=REQUEST_ID)
    def test_analyze_uaf_facts_validates_response_schema(self, _uuid4):
        opener = RecordingOpener(valid_uaf_response_payload())
        client = uaf_client(opener)

        result = request_uaf_facts(client)

        self.assertEqual("http://cxx-analyzer:8090/v1/uaf-facts", opener.request.full_url)
        self.assertEqual("POST", opener.request.get_method())
        self.assertEqual("application/json", opener.request.get_header("Content-type"))
        self.assertEqual(8, opener.timeout)
        self.assertEqual(
            {
                "schema_version": 1,
                "request_id": REQUEST_ID,
                "repository_key": REPOSITORY_KEY,
                "snapshot_sha256": SNAPSHOT_SHA256,
                "translation_units": list(TRANSLATION_UNITS),
                "build_context": {"mode": "snapshot-compdb"},
            },
            json.loads(opener.request.data.decode("utf-8")),
         )
        self.assertIsInstance(result, UafFactsResponse)
        self.assertEqual(REQUEST_ID, result.request_id)
        self.assertEqual(REPOSITORY_KEY, result.repository_key)
        self.assertEqual(SNAPSHOT_SHA256, result.snapshot_sha256)
        self.assertEqual(
            ({"run_id": "run-uaf-1", "tool": "uaf-facts", "status": "unavailable"},),
            result.tool_runs,
         )
        self.assertEqual(
            tuple(skeleton_unit_entry(unit) for unit in TRANSLATION_UNITS),
            result.translation_units,
         )
        self.assertEqual(bundle_sha256(result.translation_units), result.bundle_sha256)
        self.assertEqual((), result.diagnostics)
        with self.assertRaises(FrozenInstanceError):
            result.request_id = "tampered"

        # Client-side input contract is enforced before any network call.
        bad_inputs = (
            (("team/project", SNAPSHOT_SHA256, ("src/a.cpp",), "cmake"), "unknown mode"),
            (("team/project", SNAPSHOT_SHA256, (), "heuristic"), "no units"),
            (
                (
                    "team/project",
                    SNAPSHOT_SHA256,
                    tuple(f"src/{i}.cpp" for i in range(17)),
                    "heuristic",
                ),
                "over budget",
            ),
            (("team/project", SNAPSHOT_SHA256, ("../escape.cpp",), "heuristic"), "escape"),
            (
                ("team/project", SNAPSHOT_SHA256,
                 ("src/a.cpp", "src/a.cpp"), "heuristic"),
                "duplicate",
            ),
            (("team/project", "A" * 64, ("src/a.cpp",), "heuristic"), "bad digest"),
        )
        for arguments, label in bad_inputs:
            with self.subTest(input=label):
                fresh = uaf_client(RecordingOpener(valid_uaf_response_payload()))
                with self.assertRaises(Exception) as caught:
                    fresh.analyze_uaf_facts(*arguments)
                self.assertNotIsInstance(caught.exception, urllib.error.URLError)

    @patch("lima.cxx_memory.uuid.uuid4", return_value=REQUEST_ID)
    def test_bundle_hash_mismatch_raises_protocol_error(self, _uuid4):
        mutations = (
            ("digest rewritten", lambda payload: payload.update({"bundle_sha256": "b" * 64})),
            (
                "bundle tampered",
                lambda payload: payload["translation_units"][0]["coverage"].update(
                    {"ast_complete": True}
                ),
            ),
            (
                "unit appended without digest",
                lambda payload: payload["translation_units"].append(
                    skeleton_unit_entry("src/c.cpp")
                ),
            ),
         )
        for label, mutate in mutations:
            with self.subTest(mutation=label):
                payload = valid_uaf_response_payload()
                mutate(payload)
                client = uaf_client(RecordingOpener(payload))
                with self.assertRaises(CxxAnalyzerProtocolError):
                    request_uaf_facts(client)

    @patch("lima.cxx_memory.uuid.uuid4", return_value=REQUEST_ID)
    def test_unknown_response_field_raises_protocol_error(self, _uuid4):
        def top_level_extra(payload):
            payload["extra"] = True

        def unit_extra_field(payload):
            payload["translation_units"][0]["path"] = "src/a.cpp"

        def tool_run_extra_field(payload):
            payload["tool_runs"][0]["command"] = "secret"

        def unknown_extraction(payload):
            payload["translation_units"][0]["extraction"] = "completed"

        def unknown_tool(payload):
            payload["tool_runs"][0]["tool"] = "clang"

        def unknown_run_status(payload):
            payload["tool_runs"][0]["status"] = "failed"

        def unknown_build_context_status(payload):
            payload["translation_units"][0]["build_context"]["status"] = "complete"

        def unknown_coverage_field(payload):
            payload["translation_units"][0]["coverage"]["percent"] = 0.5

        def unavailable_with_facts(payload):
            payload["translation_units"][0]["facts"] = [
                {"fact_id": "fabricated", "kind": "allocation"}
            ]

        def unavailable_with_ast(payload):
            payload["translation_units"][0]["coverage"]["ast_complete"] = True

        cases = (
            ("top-level extra field", top_level_extra),
            ("unit extra field", unit_extra_field),
            ("tool run extra field", tool_run_extra_field),
            ("unknown extraction", unknown_extraction),
            ("unknown tool", unknown_tool),
            ("unknown run status", unknown_run_status),
            ("unknown build context status", unknown_build_context_status),
            ("unknown coverage field", unknown_coverage_field),
            ("unavailable extraction carries facts", unavailable_with_facts),
            ("unavailable extraction claims ast", unavailable_with_ast),
         )
        for label, mutate in cases:
            with self.subTest(mutation=label):
                payload = valid_uaf_response_payload()
                mutate(payload)
                payload["bundle_sha256"] = bundle_sha256(payload["translation_units"])
                client = uaf_client(RecordingOpener(payload))
                with self.assertRaises(CxxAnalyzerProtocolError):
                    request_uaf_facts(client)

    @patch("lima.cxx_memory.uuid.uuid4", return_value=REQUEST_ID)
    def test_echo_mismatch_raises_protocol_error(self, _uuid4):
        def wrong_request_id(payload):
            payload["request_id"] = "00000000-0000-0000-0000-000000000002"

        def wrong_repository_key(payload):
            payload["repository_key"] = "other/project"

        def wrong_snapshot(payload):
            payload["snapshot_sha256"] = "b" * 64

        def reordered_units(payload):
            payload["translation_units"] = [
                skeleton_unit_entry(unit) for unit in ("src/b.cpp", "src/a.cpp")
            ]

        def missing_unit(payload):
            payload["translation_units"] = [skeleton_unit_entry("src/a.cpp")]

        def extra_unit(payload):
            payload["translation_units"] = [
                skeleton_unit_entry(unit)
                for unit in ("src/a.cpp", "src/b.cpp", "src/c.cpp")
            ]

        def renamed_unit(payload):
            payload["translation_units"] = [
                skeleton_unit_entry(unit) for unit in ("src/other.cpp", "src/b.cpp")
            ]

        cases = (
            ("wrong request id", wrong_request_id),
            ("wrong repository key", wrong_repository_key),
            ("wrong snapshot digest", wrong_snapshot),
            ("reordered units", reordered_units),
            ("missing unit", missing_unit),
            ("extra unit", extra_unit),
            ("renamed unit", renamed_unit),
         )
        for label, mutate in cases:
            with self.subTest(mutation=label):
                payload = valid_uaf_response_payload()
                mutate(payload)
                payload["bundle_sha256"] = bundle_sha256(payload["translation_units"])
                client = uaf_client(RecordingOpener(payload))
                with self.assertRaises(CxxAnalyzerProtocolError):
                    request_uaf_facts(client)

    def test_transport_error_maps_to_unavailable(self):
        opener = RecordingOpener(error=urllib.error.URLError("connection refused"))
        client = uaf_client(opener)
        with self.assertRaises(CxxAnalyzerUnavailable):
            request_uaf_facts(client)
        self.assertIsNotNone(opener.request)

        opener = RecordingOpener(error=TimeoutError("timed out"))
        client = uaf_client(opener)
        with self.assertRaises(CxxAnalyzerUnavailable):
            request_uaf_facts(client)


if __name__ == "__main__":
    unittest.main()
