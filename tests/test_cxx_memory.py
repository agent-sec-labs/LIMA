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
from lima.report import to_markdown
from lima.repository_scanner import VERIFICATION_RANK, RepositoryScanner
from lima.workspace import (
    RepositoryWorkspace,
    WorkspaceFile,
    WorkspaceInventory,
)

REQUEST_ID = "00000000-0000-0000-0000-000000000001"
CLIENT_INVENTORY = WorkspaceInventory(
    root="/repositories/team/project",
    files=[
        WorkspaceFile("src/free.c", 1, "c" * 64, 12),
        WorkspaceFile("config.json", 1, "d" * 64, 1),
    ],
)
SNAPSHOT_SHA256 = CLIENT_INVENTORY.fingerprint()


def valid_tool_run(tool="semgrep", status="completed"):
    return {
        "tool": tool,
        "status": status,
        "returncode": 0 if status == "completed" else None if status == "timed-out" else 1,
        "output_sha256": "b" * 64,
        "output_truncated": False,
        "digests_complete": True,
    }


def valid_response_payload():
    return {
        "schema_version": 1,
        "request_id": REQUEST_ID,
        "status": "completed",
        "snapshot_sha256": SNAPSHOT_SHA256,
        "tool_runs": [],
        "findings": [
            {
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
            }
        ],
        "coverage": {"source_files": 1, "snapshot_files": 2},
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

    def analyze(self, repository_key, snapshot_sha256, requested_layers, *, inventory):
        self.calls.append((repository_key, snapshot_sha256, requested_layers, inventory))
        if self.error:
            raise self.error
        return self.result


def cxx_result(*findings):
    return CxxAnalysisResult(
        status="completed",
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
        rule_id="cxx.double-free",
        severity=Severity.HIGH,
        title="Potential double free",
        explanation="free called twice",
        path="src/free.c",
        line=12,
        evidence="free(p)",
        fix="",
        test="Reproduce under AddressSanitizer",
        confidence=0.72,
        cwe="CWE-415",
        source=tool,
        evidence_kind="line",
        verification_state=states[analysis_mode],
        language="c",
        symbol=symbol,
        analysis_mode=analysis_mode,
        automatic_repair=False,
    )


class CxxFindingModelTests(unittest.TestCase):
    def test_new_evidence_fields_have_backward_compatible_defaults(self):
        finding = Finding(
            rule_id="SEC-EVAL",
            severity=Severity.HIGH,
            title="eval",
            explanation="unsafe",
            path="app.py",
            line=1,
            evidence="eval(x)",
            fix="remove eval",
            test="exercise input",
        )

        self.assertEqual("", finding.language)
        self.assertEqual("", finding.symbol)
        self.assertEqual("", finding.analysis_mode)
        self.assertIsNone(finding.automatic_repair)
        self.assertEqual("", finding.evidence_records[0].language)

    def test_fallback_evidence_preserves_finding_metadata(self):
        finding = Finding(
            rule_id="CXX-OOB-WRITE",
            severity=Severity.HIGH,
            title="overflow",
            explanation="unsafe write",
            path="src/buffer.cpp",
            line=12,
            evidence="buffer[index] = value",
            fix="bound the index",
            test="exercise the boundary",
            language="c++",
            symbol="write_buffer",
            analysis_mode="build-backed",
        )

        evidence = finding.evidence_records[0]
        self.assertEqual("c++", evidence.language)
        self.assertEqual("write_buffer", evidence.symbol)
        self.assertEqual("build-backed", evidence.analysis_mode)

    def test_explicitly_disabled_finding_is_rejected_before_rule_matching(self):
        eligibility = SafeFixer.repair_eligibility(
            {
                "rule_id": "SEC-SQL-CONCAT",
                "cwe": "CWE-89",
                "verification_state": "dataflow-verified",
                "automatic_repair": False,
            }
        )

        self.assertEqual(
            {"eligible": False, "reason": "automatic-repair-disabled"},
            eligibility,
        )


class CxxRepositoryScannerTests(unittest.TestCase):
    @staticmethod
    def _scanner(adapter, mode="auto"):
        return RepositoryScanner(
            sast_mode="off",
            dataflow_enabled=False,
            cxx_memory_mode=mode,
            cxx_memory_adapter=adapter,
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

            self.assertEqual(
                [
                    (
                        "team/project",
                        result.inventory.fingerprint(),
                        REQUESTED_LAYERS,
                        result.inventory,
                    )
                ],
                adapter.calls,
            )
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
            adapter = FakeCxxAdapter(
                cxx_result(
                    cxx_finding("semgrep", "source-only"),
                    cxx_finding("clang", "build-backed"),
                    cxx_finding("asan", "sanitizer-confirmed"),
                )
            )

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
            adapter = FakeCxxAdapter(
                cxx_result(
                    cxx_finding("semgrep", "source-only", symbol="release_left"),
                    cxx_finding("clang", "build-backed", symbol="release_right"),
                )
            )

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
            adapter = FakeCxxAdapter(
                cxx_result(
                    cxx_finding("semgrep", "source-only"),
                    cxx_finding("semgrep", "source-only"),
                )
            )

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

    @patch("lima.cxx_memory.uuid.uuid4", return_value=REQUEST_ID)
    def test_build_failed_layer_metadata_is_preserved_in_all_modes(self, _uuid4):
        for mode in ("auto", "required"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                (root / "main.cpp").write_text("int main() { return 0; }\n", encoding="utf-8")
                workspace = RepositoryWorkspace(root)
                payload = valid_response_payload()
                payload["snapshot_sha256"] = workspace.inventory().fingerprint()
                payload["findings"][0].update(
                    {"path": "main.cpp", "line": 1, "language": "c++"}
                )
                payload["tool_runs"] = [
                    valid_tool_run(),
                    valid_tool_run("build-step", "build_failed"),
                ]
                payload["tool_runs"][1]["returncode"] = 1
                payload["coverage"] = {"source_files": 1, "snapshot_files": 1}
                payload["diagnostics"] = ["build_failed"]
                adapter = CxxMemoryAnalyzerClient(
                    "http://cxx-analyzer:8090",
                    timeout_seconds=8,
                    max_response_bytes=4096,
                    opener=RecordingOpener(payload),
                )

                result = self._scanner(adapter, mode=mode).scan(
                    workspace, repository_key="team/project"
                )

                metadata = result.report.collaboration["cxx_memory"]
                self.assertEqual(
                    "completed",
                    metadata["status"],
                )
                self.assertEqual(payload["tool_runs"], metadata["tool_runs"])
                self.assertEqual(payload["coverage"], metadata["coverage"])
                self.assertEqual(payload["diagnostics"], metadata["diagnostics"])
                self.assertEqual(1, len(result.report.findings))
                self.assertEqual("source-only", result.report.findings[0].analysis_mode)
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
            "http://cxx-analyzer:8090",
            timeout_seconds=8,
            max_response_bytes=4096,
            opener=opener,
        )

        result = client.analyze(
            "team/project",
            SNAPSHOT_SHA256,
            ("source-only", "build-backed"),
            inventory=CLIENT_INVENTORY,
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
        self.assertEqual({"source_files": 1, "snapshot_files": 2}, result.coverage)
        self.assertEqual([], result.diagnostics)
        self.assertEqual(1, len(result.findings))
        finding = result.findings[0]
        self.assertEqual(
            Finding(
                rule_id="cxx.double-free",
                severity=Severity.HIGH,
                title="Potential double free",
                explanation="free called twice",
                path="src/free.c",
                line=12,
                evidence="free(p)",
                fix="",
                test="Reproduce under AddressSanitizer",
                confidence=0.72,
                cwe="CWE-415",
                source="semgrep",
                evidence_kind="line",
                verification_state="candidate",
                language="c",
                symbol="release",
                analysis_mode="source-only",
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
    def test_non_finding_response_fields_are_strictly_validated(self, _uuid4):
        mutations = {
            "tool run extra field": lambda payload: payload.update(
                tool_runs=[{**valid_tool_run(), "command": "secret"}]
            ),
            "unknown tool": lambda payload: payload.update(tool_runs=[valid_tool_run("unknown")]),
            "unknown status": lambda payload: payload.update(
                tool_runs=[valid_tool_run(status="unknown")]
            ),
            "boolean returncode": lambda payload: payload.update(
                tool_runs=[{**valid_tool_run(), "returncode": True}]
            ),
            "invalid output digest": lambda payload: payload.update(
                tool_runs=[{**valid_tool_run(), "output_sha256": "short"}]
            ),
            "coverage extra field": lambda payload: payload.update(
                coverage={"source_files": 1, "snapshot_files": 2, "percent": 0.5}
            ),
            "coverage boolean": lambda payload: payload.update(
                coverage={"source_files": True, "snapshot_files": 2}
            ),
            "coverage inconsistent": lambda payload: payload.update(
                coverage={"source_files": 3, "snapshot_files": 2}
            ),
            "object diagnostic": lambda payload: payload.update(
                diagnostics=[{"message": "not-v1"}]
            ),
            "oversized diagnostic": lambda payload: payload.update(diagnostics=["x" * 2049]),
        }
        for label, mutate in mutations.items():
            with self.subTest(label=label):
                payload = valid_response_payload()
                mutate(payload)
                client = RecordingConversionClient(
                    "http://cxx-analyzer:8090",
                    timeout_seconds=8,
                    max_response_bytes=8192,
                    opener=RecordingOpener(payload),
                )

                with self.assertRaises(CxxAnalyzerProtocolError):
                    client.analyze(
                        "team/project",
                        SNAPSHOT_SHA256,
                        ("source-only",),
                        inventory=CLIENT_INVENTORY,
                    )

                self.assertEqual([], client.converted_findings)

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
                payload["findings"][0].update(
                    {
                        "tool": tool,
                        "analysis_mode": analysis_mode,
                        "verification_state": verification_state,
                    }
                )
                client = RecordingConversionClient(
                    "http://cxx-analyzer:8090",
                    timeout_seconds=8,
                    max_response_bytes=4096,
                    opener=RecordingOpener(payload),
                )

                with self.assertRaises(CxxAnalyzerProtocolError):
                    client.analyze(
                        "team/project",
                        SNAPSHOT_SHA256,
                        ("source-only", "build-backed"),
                        inventory=CLIENT_INVENTORY,
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
                    "http://cxx-analyzer:8090",
                    timeout_seconds=8,
                    max_response_bytes=4096,
                    opener=opener,
                )

                with self.assertRaises(CxxAnalyzerProtocolError):
                    client.analyze(
                        "team/project",
                        SNAPSHOT_SHA256,
                        requested_layers,
                        inventory=CLIENT_INVENTORY,
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
        changed("top-level status", lambda value: value.update({"status": "build_failed"}))
        changed("request id", lambda value: value.update({"request_id": "wrong"}))
        changed(
            "snapshot digest",
            lambda value: value.update({"snapshot_sha256": "b" * 64}),
        )
        changed("non-object finding", lambda value: value.update({"findings": [None]}))
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
        invalid_payloads.extend(
            [
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
            ]
        )

        for name, body, max_response_bytes in invalid_payloads:
            with self.subTest(name=name):
                client = RecordingConversionClient(
                    "http://cxx-analyzer:8090",
                    timeout_seconds=8,
                    max_response_bytes=max_response_bytes,
                    opener=RecordingOpener(body=body),
                )

                with self.assertRaises(CxxAnalyzerProtocolError):
                    client.analyze(
                        "team/project",
                        SNAPSHOT_SHA256,
                        ("source-only", "build-backed"),
                        inventory=CLIENT_INVENTORY,
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


class CxxReportTests(unittest.TestCase):
    def test_markdown_explains_source_only_evidence_and_degraded_layers(self):
        finding = cxx_finding("semgrep", "source-only")
        report = {
            "repository": "team/project",
            "summary": "C/C++ memory analysis completed with limitations.",
            "risk": "high",
            "reviewer": "local-rules",
            "findings": [finding.to_dict()],
            "collaboration": {
                "cxx_memory": {
                    "status": "completed",
                    "tool_runs": [{"tool": "semgrep", "status": "completed"}],
                    "diagnostics": [
                        {
                            "layer": "build-backed",
                            "status": "build_failed",
                            "message": (
                                "CMake configuration failed at C:\\container\\build --token=secret"
                            ),
                        },
                        {
                            "layer": "sanitizer-confirmed",
                            "status": "sanitizer_not_configured",
                            "message": "see http://cxx-analyzer:8090/?api_key=secret",
                        },
                    ],
                },
            },
        }

        markdown = to_markdown(report)

        for text in (
            "Language: `c`",
            "Symbol: `release`",
            "CWE-415",
            "src/free.c:12",
            "纯源码候选",
            "candidate",
            "semgrep",
            "free(p)",
            "纯源码分析，尚未经过目标项目构建验证",
            "不支持自动修复",
            "BUILD_FAILED",
            "构建支持的静态验证未完成",
            "SANITIZER_NOT_CONFIGURED",
            "Sanitizer 动态确认未配置",
        ):
            self.assertIn(text, markdown)
        self.assertNotIn("C:\\container\\build", markdown)
        self.assertNotIn("http://cxx-analyzer:8090", markdown)
        self.assertNotIn("secret", markdown)

    def test_markdown_uses_safe_fallbacks_and_bounds_cxx_diagnostics(self):
        finding = cxx_finding("semgrep", "source-only").to_dict()
        finding["analysis_mode"] = "future-engine"
        finding["verification_state"] = "future-state"
        report = {
            "repository": "team/project",
            "summary": "limited analysis",
            "risk": "medium",
            "findings": [finding],
            "collaboration": {
                "cxx_memory": {
                    "status": "completed",
                    "diagnostics": [f"diagnostic-{index}" for index in range(20)],
                },
            },
        }

        markdown = to_markdown(report)

        self.assertIn("未知分析模式（需人工复核）", markdown)
        self.assertIn("未知验证状态（需人工复核）", markdown)
        self.assertLessEqual(markdown.count("`DIAGNOSTIC_"), 8)

    def test_non_cxx_markdown_keeps_existing_report_shape(self):
        report = {
            "repository": "team/project",
            "summary": "Python finding",
            "risk": "medium",
            "findings": [
                {
                    "severity": "medium",
                    "title": "Unsafe eval",
                    "path": "app.py",
                    "line": 9,
                    "rule_id": "SEC-EVAL",
                    "cwe": "CWE-95",
                    "verification_state": "candidate",
                    "explanation": "unsafe",
                    "evidence": "eval(value)",
                    "fix": "remove eval",
                    "test": "exercise input",
                    "source": "local-rule",
                }
            ],
        }

        markdown = to_markdown(report)

        self.assertIn("**Suggested fix:** remove eval", markdown)
        self.assertNotIn("纯源码分析，尚未经过目标项目构建验证", markdown)
        self.assertNotIn("不支持自动修复", markdown)

    def test_markdown_reserves_source_only_warning_for_source_only_findings(self):
        finding = cxx_finding("clang", "build-backed").to_dict()
        report = {
            "repository": "team/project",
            "summary": "build evidence",
            "risk": "medium",
            "findings": [finding],
        }

        markdown = to_markdown(report)

        self.assertIn("构建支持的静态验证", markdown)
        self.assertNotIn("纯源码分析，尚未经过目标项目构建验证", markdown)

    def test_markdown_marks_legacy_cxx_findings_as_not_auto_repairable(self):
        finding = cxx_finding("semgrep", "source-only").to_dict()
        finding.pop("automatic_repair")
        report = {
            "repository": "team/project",
            "summary": "legacy C/C++ finding",
            "risk": "high",
            "findings": [finding],
        }

        markdown = to_markdown(report)

        self.assertIn("不支持自动修复", markdown)

    def test_markdown_never_allows_automatic_repair_for_cxx_findings(self):
        finding = cxx_finding("semgrep", "source-only").to_dict()
        finding["automatic_repair"] = True
        markdown = to_markdown(
            {
                "repository": "team/project",
                "summary": "malformed C/C++ finding",
                "risk": "high",
                "findings": [finding],
            }
        )

        self.assertIn("不支持自动修复", markdown)

    def test_markdown_redacts_sensitive_cxx_fields_without_hiding_relative_evidence(self):
        finding = cxx_finding("https://internal.example/?token=secret", "source-only").to_dict()
        finding.update(
            {
                "path": '"C:\\Program Files\\private source\\buffer.c"',
                "evidence": (
                    'src/buffer.c reads "/container/private source/input.c" '
                    '--token secret --password "secret pass"'
                ),
                "evidence_records": [
                    {
                        "source": "clang --api_key=secret",
                        "path": "'/opt/private path/trace.c'",
                        "line": 12,
                        "snippet": "--secret secret --password='secret pass' relative/trace.c",
                    }
                ],
            }
        )

        markdown = to_markdown(
            {
                "repository": "team/project",
                "summary": "redaction",
                "risk": "high",
                "findings": [finding],
            }
        )

        for leaked in (
            "internal.example",
            "secret",
            "C:\\Program Files",
            "/container/private",
            "/opt/private",
            "private source",
            "secret pass",
        ):
            self.assertNotIn(leaked, markdown)
        self.assertIn("src/buffer.c", markdown)
        self.assertIn("relative/trace.c", markdown)

    def test_markdown_filters_malformed_evidence_records_and_falls_back_when_none_are_mappings(
        self,
    ):
        finding = cxx_finding("semgrep", "source-only").to_dict()
        finding["evidence"] = "top-level fallback evidence"
        finding["evidence_records"] = [
            None,
            3,
            {"source": "partial"},
            {
                "source": "clang",
                "path": "src/free.c",
                "line": 12,
                "snippet": "valid trace",
            },
        ]
        markdown = to_markdown(
            {
                "repository": "team/project",
                "summary": "mixed evidence",
                "risk": "high",
                "findings": [finding],
            }
        )
        self.assertIn("valid trace", markdown)
        self.assertIn("`partial` · `:0`", markdown)

        finding["evidence_records"] = [None, 3]
        fallback_markdown = to_markdown(
            {
                "repository": "team/project",
                "summary": "fallback evidence",
                "risk": "high",
                "findings": [finding],
            }
        )
        evidence_trace = fallback_markdown.split("**工具证据 / trace**", 1)[1]
        self.assertIn("top-level fallback evidence", evidence_trace)

    def test_markdown_redactor_hides_key_forms_and_preserves_relative_paths(self):
        finding = cxx_finding("semgrep", "source-only").to_dict()
        finding["evidence"] = (
            "src/x.c ./src/x.c ../src/x.c /work/tmp/x C:\\secret\\x "
            '--key secret key=secret --key "quoted secret" monkey=ordinary'
        )
        markdown = to_markdown(
            {
                "repository": "team/project",
                "summary": "redaction",
                "risk": "high",
                "findings": [finding],
            }
        )

        for leaked in ("/work/tmp/x", "C:\\secret\\x", "secret", "quoted secret"):
            self.assertNotIn(leaked, markdown)
        for relative_path in ("src/x.c", "./src/x.c", "../src/x.c"):
            self.assertIn(relative_path, markdown)
        self.assertIn("monkey=ordinary", markdown)

    def test_markdown_falls_back_for_nonsequence_or_nonmapping_evidence_records(self):
        finding = cxx_finding("semgrep", "source-only").to_dict()
        finding["evidence"] = "top-level fallback evidence"
        for records in (7, "not-a-record-list", [[], None, 3, {}]):
            with self.subTest(records=repr(records)):
                finding["evidence_records"] = records
                markdown = to_markdown(
                    {
                        "repository": "team/project",
                        "summary": "fallback",
                        "risk": "high",
                        "findings": [finding],
                    }
                )
                evidence_trace = markdown.split("**工具证据 / trace**", 1)[1]
                self.assertIn("top-level fallback evidence", evidence_trace)


if __name__ == "__main__":
    unittest.main()
