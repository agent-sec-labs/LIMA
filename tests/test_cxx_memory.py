import copy
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from lima.cxx_memory import (
    REQUESTED_LAYERS,
    CxxAnalysisResult,
    CxxAnalyzerProtocolError,
    CxxAnalyzerUnavailable,
    CxxMemoryAnalyzerClient,
    map_asan_error,
)
from lima.fixer import SafeFixer
from lima.models import Finding, Severity
from lima.repository_scanner import VERIFICATION_RANK, RepositoryScanner
from lima.workspace import RepositoryWorkspace

REQUEST_ID = "00000000-0000-0000-0000-000000000001"
SNAPSHOT_SHA256 = "a" * 64


def valid_response_payload():
    return {
        "schema_version": 1,
        "request_id": REQUEST_ID,
        "status": "completed",
        "snapshot_sha256": SNAPSHOT_SHA256,
        "tool_runs": [],
        "findings": [{
            "rule_id": "cxx.double-free",
            "severity": "high",
            "title": "Potential double free",
            "explanation": "free called twice",
            "path": "src/free.c",
            "line": 12,
            "evidence": "free(p)",
            "fix": "",
            "test": "Reproduce under AddressSanitizer",
            "confidence": 0.72,
            "cwe": "CWE-415",
            "tool": "semgrep",
            "evidence_kind": "line",
            "verification_state": "candidate",
            "language": "c",
            "symbol": "release",
            "analysis_mode": "source-only",
        }],
        "coverage": {},
        "diagnostics": [],
    }


class FakeResponse:
    def __init__(self, body):
        self.body = body
        self.headers = {"Content-Length": str(len(body))}
        self._stream = io.BytesIO(body)

    def read(self, size=-1):
        return self._stream.read(size)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        return False


class RecordingOpener:
    def __init__(self, payload=None, *, body=None):
        self.body = body if body is not None else json.dumps(payload).encode("utf-8")
        self.request = None
        self.timeout = None

    def __call__(self, request, timeout):
        self.request = request
        self.timeout = timeout
        return FakeResponse(self.body)


class RecordingConversionClient(CxxMemoryAnalyzerClient):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.converted_findings = []

    def _convert_finding(self, item):
        self.converted_findings.append(item)
        return super()._convert_finding(item)


class FakeCxxAdapter:
    def __init__(self, result=None, error=None):
        self.calls = []
        self.result = result
        self.error = error

    def analyze(self, repository_key, snapshot_sha256, requested_layers):
        self.calls.append((repository_key, snapshot_sha256, requested_layers))
        if self.error:
            raise self.error
        return self.result


def cxx_result(*findings, status="completed"):
    return CxxAnalysisResult(
        status=status,
        tool_runs=[{"tool": "semgrep", "status": "completed"}],
        findings=list(findings),
        coverage={"source_files": 1},
        diagnostics=["bounded diagnostic"],
    )


def cxx_finding(tool, analysis_mode, *, symbol="release"):
    states = {
        "source-only": "candidate",
        "build-backed": "build-verified",
        "sanitizer-confirmed": "confirmed",
    }
    return Finding(
        rule_id="cxx.double-free", severity=Severity.HIGH,
        title="Potential double free", explanation="free called twice",
        path="src/free.c", line=12, evidence="free(p)", fix="",
        test="Reproduce under AddressSanitizer", confidence=0.72,
        cwe="CWE-415", source=tool, evidence_kind="line",
        verification_state=states[analysis_mode], language="c",
        symbol=symbol, analysis_mode=analysis_mode, automatic_repair=False,
    )


class CxxFindingModelTests(unittest.TestCase):
    def test_new_evidence_fields_have_backward_compatible_defaults(self):
        finding = Finding(
            rule_id="SEC-EVAL", severity=Severity.HIGH, title="eval",
            explanation="unsafe", path="app.py", line=1, evidence="eval(x)",
            fix="remove eval", test="exercise input",
        )

        self.assertEqual("", finding.language)
        self.assertEqual("", finding.symbol)
        self.assertEqual("", finding.analysis_mode)
        self.assertIsNone(finding.automatic_repair)
        self.assertEqual("", finding.evidence_records[0].language)

    def test_fallback_evidence_preserves_finding_metadata(self):
        finding = Finding(
            rule_id="CXX-OOB-WRITE", severity=Severity.HIGH, title="overflow",
            explanation="unsafe write", path="src/buffer.cpp", line=12,
            evidence="buffer[index] = value", fix="bound the index",
            test="exercise the boundary", language="c++", symbol="write_buffer",
            analysis_mode="build-backed",
        )

        evidence = finding.evidence_records[0]
        self.assertEqual("c++", evidence.language)
        self.assertEqual("write_buffer", evidence.symbol)
        self.assertEqual("build-backed", evidence.analysis_mode)

    def test_explicitly_disabled_finding_is_rejected_before_rule_matching(self):
        eligibility = SafeFixer.repair_eligibility({
            "rule_id": "SEC-SQL-CONCAT", "cwe": "CWE-89",
            "verification_state": "dataflow-verified", "automatic_repair": False,
        })

        self.assertEqual(
            {"eligible": False, "reason": "automatic-repair-disabled"},
            eligibility,
        )


class CxxRepositoryScannerTests(unittest.TestCase):
    @staticmethod
    def _scanner(adapter, mode="auto"):
        return RepositoryScanner(
            sast_mode="off", dataflow_enabled=False,
            cxx_memory_mode=mode, cxx_memory_adapter=adapter,
        )

    def test_sidecar_invocation_requires_cxx_source_or_header(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "app.py").write_text("safe = True\n", encoding="utf-8")
            (root / "CMakeLists.txt").write_text("project(sample)\n", encoding="utf-8")
            adapter = FakeCxxAdapter(cxx_result())

            result = self._scanner(adapter).scan(
                RepositoryWorkspace(root), repository_key="team/project"
            )

            self.assertEqual([], adapter.calls)
            self.assertEqual("not-applicable", result.report.collaboration["cxx_memory"]["status"])

    def test_sidecar_receives_repository_key_snapshot_and_requested_layers(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "main.cpp").write_text("int main() { return 0; }\n", encoding="utf-8")
            adapter = FakeCxxAdapter(cxx_result())

            result = self._scanner(adapter).scan(
                RepositoryWorkspace(root), repository_key="team/project"
            )

            self.assertEqual([
                ("team/project", result.inventory.fingerprint(), REQUESTED_LAYERS)
            ], adapter.calls)
            self.assertEqual("completed", result.report.collaboration["cxx_memory"]["status"])

    def test_off_mode_never_invokes_sidecar(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "main.cpp").write_text("int main() { return 0; }\n", encoding="utf-8")
            adapter = FakeCxxAdapter(cxx_result())

            result = self._scanner(adapter, mode="off").scan(
                RepositoryWorkspace(root), repository_key="team/project"
            )

            self.assertEqual([], adapter.calls)
            self.assertEqual("disabled", result.report.collaboration["cxx_memory"]["status"])

    def test_cxx_findings_fuse_by_cwe_path_symbol_and_line(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "main.cpp").write_text("int main() { return 0; }\n", encoding="utf-8")
            adapter = FakeCxxAdapter(cxx_result(
                cxx_finding("semgrep", "source-only"),
                cxx_finding("clang", "build-backed"),
                cxx_finding("asan", "sanitizer-confirmed"),
            ))

            result = self._scanner(adapter).scan(
                RepositoryWorkspace(root), repository_key="team/project"
            )

            self.assertEqual(1, len(result.report.findings))
            finding = result.report.findings[0]
            self.assertEqual("asan+clang+semgrep", finding.source)
            self.assertEqual(
                {"asan", "clang", "semgrep"},
                {item.source for item in finding.evidence_records},
            )
            self.assertEqual("sanitizer-confirmed", finding.analysis_mode)
            self.assertEqual("confirmed", finding.verification_state)
            self.assertFalse(finding.automatic_repair)

    def test_cxx_findings_with_different_symbols_remain_independent(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "main.cpp").write_text("int main() { return 0; }\n", encoding="utf-8")
            adapter = FakeCxxAdapter(cxx_result(
                cxx_finding("semgrep", "source-only", symbol="release_left"),
                cxx_finding("clang", "build-backed", symbol="release_right"),
            ))

            result = self._scanner(adapter).scan(
                RepositoryWorkspace(root), repository_key="team/project"
            )

            self.assertEqual(
                {"release_left", "release_right"},
                {item.symbol for item in result.report.findings},
            )

    def test_build_verified_ranks_with_dataflow_verified(self):
        self.assertEqual(
            VERIFICATION_RANK["dataflow-verified"],
            VERIFICATION_RANK["build-verified"],
        )

    def test_source_only_fusion_never_promotes_candidate(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "main.cpp").write_text("int main() { return 0; }\n", encoding="utf-8")
            adapter = FakeCxxAdapter(cxx_result(
                cxx_finding("semgrep", "source-only"),
                cxx_finding("semgrep", "source-only"),
            ))

            result = self._scanner(adapter).scan(
                RepositoryWorkspace(root), repository_key="team/project"
            )

            self.assertEqual(1, len(result.report.findings))
            self.assertEqual("source-only", result.report.findings[0].analysis_mode)
            self.assertEqual("candidate", result.report.findings[0].verification_state)

    def test_auto_unavailable_preserves_other_results(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "main.cpp").write_text("int main() { return 0; }\n", encoding="utf-8")
            (root / "app.py").write_text("eval(data)\n", encoding="utf-8")
            adapter = FakeCxxAdapter(error=CxxAnalyzerUnavailable("offline"))

            result = self._scanner(adapter).scan(
                RepositoryWorkspace(root), repository_key="team/project"
            )

            self.assertEqual("unavailable", result.report.collaboration["cxx_memory"]["status"])
            self.assertIn("SEC-EVAL", {item.rule_id for item in result.report.findings})

    def test_required_unavailable_fails_scan(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "main.cpp").write_text("int main() { return 0; }\n", encoding="utf-8")
            adapter = FakeCxxAdapter(error=CxxAnalyzerUnavailable("offline"))

            with self.assertRaisesRegex(RuntimeError, "required C/C\\+\\+ memory analyzer"):
                self._scanner(adapter, mode="required").scan(
                    RepositoryWorkspace(root), repository_key="team/project"
                )

    def test_build_failed_is_an_analysis_result_in_all_modes(self):
        for mode in ("auto", "required"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                (root / "main.cpp").write_text("int main() { return 0; }\n", encoding="utf-8")
                source_finding = cxx_finding("semgrep", "source-only")
                adapter = FakeCxxAdapter(cxx_result(source_finding, status="build_failed"))

                result = self._scanner(adapter, mode=mode).scan(
                    RepositoryWorkspace(root), repository_key="team/project"
                )

                self.assertEqual(
                    "build_failed",
                    result.report.collaboration["cxx_memory"]["status"],
                )
                self.assertEqual("candidate", result.report.findings[0].verification_state)

    def test_protocol_error_is_rejected_in_auto_and_fatal_when_required(self):
        for mode in ("auto", "required"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                (root / "main.cpp").write_text("int main() { return 0; }\n", encoding="utf-8")
                adapter = FakeCxxAdapter(error=CxxAnalyzerProtocolError("bad response"))

                if mode == "required":
                    with self.assertRaisesRegex(RuntimeError, "invalid response"):
                        self._scanner(adapter, mode=mode).scan(
                            RepositoryWorkspace(root), repository_key="team/project"
                        )
                else:
                    result = self._scanner(adapter, mode=mode).scan(
                        RepositoryWorkspace(root), repository_key="team/project"
                    )
                    self.assertEqual(
                        "invalid-response",
                        result.report.collaboration["cxx_memory"]["status"],
                    )
                    self.assertEqual([], result.report.findings)


class CxxMemoryClientTests(unittest.TestCase):
    @patch("lima.cxx_memory.uuid.uuid4", return_value=REQUEST_ID)
    def test_valid_response_is_converted_to_findings(self, _uuid4):
        opener = RecordingOpener(valid_response_payload())
        client = CxxMemoryAnalyzerClient(
            "http://cxx-analyzer:8090", timeout_seconds=8,
            max_response_bytes=4096, opener=opener,
        )

        result = client.analyze(
            "team/project", SNAPSHOT_SHA256,
            ("source-only", "build-backed"),
        )

        self.assertEqual("http://cxx-analyzer:8090/v1/analyze", opener.request.full_url)
        self.assertEqual("POST", opener.request.get_method())
        self.assertEqual("application/json", opener.request.get_header("Content-type"))
        self.assertEqual(8, opener.timeout)
        self.assertEqual(
            {
                "request_id": REQUEST_ID,
                "repository_key": "team/project",
                "snapshot_sha256": SNAPSHOT_SHA256,
                "requested_layers": ["source-only", "build-backed"],
            },
            json.loads(opener.request.data.decode("utf-8")),
        )
        self.assertEqual("completed", result.status)
        self.assertEqual([], result.tool_runs)
        self.assertEqual({}, result.coverage)
        self.assertEqual([], result.diagnostics)
        self.assertEqual(1, len(result.findings))
        finding = result.findings[0]
        self.assertEqual(
            Finding(
                rule_id="cxx.double-free", severity=Severity.HIGH,
                title="Potential double free", explanation="free called twice",
                path="src/free.c", line=12, evidence="free(p)", fix="",
                test="Reproduce under AddressSanitizer", confidence=0.72,
                cwe="CWE-415", source="semgrep", evidence_kind="line",
                verification_state="candidate", language="c",
                symbol="release", analysis_mode="source-only",
                automatic_repair=False,
            ),
            finding,
        )
        evidence = finding.evidence_records[0]
        self.assertEqual("semgrep", evidence.source)
        self.assertEqual("cxx.double-free", evidence.rule_id)
        self.assertEqual("src/free.c", evidence.path)
        self.assertEqual(12, evidence.line)
        self.assertEqual("free(p)", evidence.snippet)
        self.assertEqual("c", evidence.language)
        self.assertEqual("release", evidence.symbol)
        self.assertEqual("source-only", evidence.analysis_mode)

    @patch("lima.cxx_memory.uuid.uuid4", return_value=REQUEST_ID)
    def test_tool_cannot_claim_another_evidence_level(self, _uuid4):
        invalid_bindings = [
            ("semgrep", "sanitizer-confirmed", "confirmed"),
            ("clang", "source-only", "candidate"),
            ("asan", "build-backed", "build-verified"),
            ("unknown-tool", "source-only", "candidate"),
        ]

        for tool, analysis_mode, verification_state in invalid_bindings:
            with self.subTest(tool=tool, analysis_mode=analysis_mode):
                payload = valid_response_payload()
                payload["findings"][0].update({
                    "tool": tool,
                    "analysis_mode": analysis_mode,
                    "verification_state": verification_state,
                })
                client = RecordingConversionClient(
                    "http://cxx-analyzer:8090", timeout_seconds=8,
                    max_response_bytes=4096,
                    opener=RecordingOpener(payload),
                )

                with self.assertRaises(CxxAnalyzerProtocolError):
                    client.analyze(
                        "team/project", SNAPSHOT_SHA256,
                        ("source-only", "build-backed"),
                    )

                self.assertEqual([], client.converted_findings)

    @patch("lima.cxx_memory.uuid.uuid4", return_value=REQUEST_ID)
    def test_invalid_requested_layers_are_rejected_before_network(self, _uuid4):
        invalid_layers = [
            ("unknown", ("source-only", "run-command")),
            ("duplicate", ("source-only", "source-only")),
            ("empty", ()),
            ("non-string", ("source-only", 7)),
        ]

        for name, requested_layers in invalid_layers:
            with self.subTest(name=name):
                opener = RecordingOpener(valid_response_payload())
                client = CxxMemoryAnalyzerClient(
                    "http://cxx-analyzer:8090", timeout_seconds=8,
                    max_response_bytes=4096, opener=opener,
                )

                with self.assertRaises(CxxAnalyzerProtocolError):
                    client.analyze(
                        "team/project", SNAPSHOT_SHA256,
                        requested_layers,
                    )

                self.assertIsNone(opener.request)

    @patch("lima.cxx_memory.uuid.uuid4", return_value=REQUEST_ID)
    def test_invalid_response_rejects_the_entire_payload(self, _uuid4):
        invalid_payloads = []

        def changed(name, mutate):
            payload = copy.deepcopy(valid_response_payload())
            mutate(payload)
            invalid_payloads.append((name, json.dumps(payload).encode("utf-8"), 4096))

        changed("unknown top-level field", lambda value: value.update({"extra": True}))
        changed("schema version", lambda value: value.update({"schema_version": 2}))
        changed("request id", lambda value: value.update({"request_id": "wrong"}))
        changed(
            "snapshot digest",
            lambda value: value.update({"snapshot_sha256": "b" * 64}),
        )
        changed("unknown CWE", lambda value: value["findings"][0].update({"cwe": "CWE-119"}))
        changed("absolute path", lambda value: value["findings"][0].update({"path": "/etc/passwd"}))
        changed("parent path", lambda value: value["findings"][0].update({"path": "../escape.c"}))
        changed("zero line", lambda value: value["findings"][0].update({"line": 0}))
        changed(
            "unknown severity",
            lambda value: value["findings"][0].update({"severity": "urgent"}),
        )
        changed(
            "unknown analysis mode",
            lambda value: value["findings"][0].update({"analysis_mode": "fuzzed"}),
        )
        changed(
            "mode and state mismatch",
            lambda value: value["findings"][0].update({"verification_state": "confirmed"}),
        )

        valid_body = json.dumps(valid_response_payload()).encode("utf-8")
        invalid_payloads.extend([
            ("oversized body", valid_body, len(valid_body) - 1),
            (
                "duplicate JSON key",
                valid_body.replace(
                    b'"status": "completed"',
                    b'"status": "completed", "status": "completed"',
                    1,
                ),
                4096,
            ),
            ("non UTF-8", b"\xff", 4096),
            ("non JSON", b"not-json", 4096),
        ])

        for name, body, max_response_bytes in invalid_payloads:
            with self.subTest(name=name):
                client = RecordingConversionClient(
                    "http://cxx-analyzer:8090", timeout_seconds=8,
                    max_response_bytes=max_response_bytes,
                    opener=RecordingOpener(body=body),
                )

                with self.assertRaises(CxxAnalyzerProtocolError):
                    client.analyze(
                        "team/project", SNAPSHOT_SHA256,
                        ("source-only", "build-backed"),
                    )

                self.assertEqual([], client.converted_findings)

    def test_asan_error_mapping_is_conservative(self):
        cases = [
            ("heap-buffer-overflow", "WRITE", "CWE-787"),
            ("stack-buffer-overflow", "READ", "CWE-125"),
            ("global-buffer-overflow", "WRITE", "CWE-787"),
            ("heap-use-after-free", "READ", "CWE-416"),
            ("attempting double-free", "FREE", "CWE-415"),
        ]

        for error_type, access, expected in cases:
            with self.subTest(error_type=error_type, access=access):
                self.assertEqual(expected, map_asan_error(error_type, access))

        self.assertIsNone(map_asan_error("heap-buffer-overflow", "FREE"))
        self.assertIsNone(map_asan_error("unknown-sanitizer-error", "WRITE"))

    def test_uaf_mapping_rejects_unrecognized_access_tokens(self):
        self.assertIsNone(map_asan_error("heap-use-after-free", "FREE"))
        self.assertIsNone(map_asan_error("heap-use-after-free", "BOGUS"))


if __name__ == "__main__":
    unittest.main()
