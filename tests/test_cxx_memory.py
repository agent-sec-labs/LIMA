import copy
import io
import json
import unittest
from unittest.mock import patch

from lima.cxx_memory import (
    CxxAnalyzerProtocolError,
    CxxMemoryAnalyzerClient,
    map_asan_error,
)
from lima.fixer import SafeFixer
from lima.models import Finding, Severity

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


if __name__ == "__main__":
    unittest.main()
