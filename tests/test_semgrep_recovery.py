import json
import shutil
import sys
import tempfile
import unittest
from contextlib import nullcontext
from pathlib import Path
from unittest.mock import patch

from cxx_analyzer.config import AnalyzerSettings
from cxx_analyzer.execution import ToolExecution, _validate_argv
from cxx_analyzer.semgrep_targets import load_targets
from cxx_analyzer.snapshot import prepare_snapshot
from cxx_analyzer.source_scan import run_source_scan
from lima.workspace import RepositoryWorkspace


def execution(document):
    return ToolExecution(
        status="completed",
        returncode=0,
        stdout=json.dumps(document),
        stderr="",
        stdout_sha256="a" * 64,
        stderr_sha256="b" * 64,
        output_sha256="c" * 64,
        output_truncated=False,
        digests_complete=True,
        diagnostic="",
    )


class SemgrepRecoveryTests(unittest.TestCase):
    @staticmethod
    def finding(line=1):
        return {
            "check_id": "cxx.source.oob-write.constant-index",
            "path": "good.cpp",
            "start": {"line": line},
            "extra": {"lines": "requires login", "metadata": {"cwe": "CWE-787", "candidate": True}},
        }

    def run_scan(self, responses=None, extra_files=0, bad_source=None):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            root = base / "imports" / "demo"
            root.mkdir(parents=True)
            (root / "bad.cpp").write_text(
                bad_source
                or (
                    "void bad() { for (const auto& [key, value] : values) "
                    "{ consume(key, value); } }\n"
                ),
                encoding="utf8",
            )
            (root / "good.cpp").write_text(
                "void good() { int a[2]={0}; a[2]=1; }\n", encoding="utf8"
            )
            for index in range(extra_files):
                (root / f"extra{index}.cpp").write_text("int value;\n", encoding="utf8")
            work = base / "work"
            work.mkdir()
            fingerprint = RepositoryWorkspace(root).inventory().fingerprint()
            with prepare_snapshot(base / "imports", "demo", fingerprint, work) as snapshot:
                response_iter = iter(responses) if responses is not None else None

                def checked_run(argv, *_args, **_kwargs):
                    _validate_argv(argv)
                    return next(response_iter)

                context = (
                    patch("cxx_analyzer.source_scan.run_step", side_effect=checked_run)
                    if responses is not None
                    else nullcontext()
                )
                with context as tool:
                    result = run_source_scan(snapshot, AnalyzerSettings.from_env())
                    calls = tool.call_args_list if tool is not None else []
            return result, calls

    def test_accepts_only_a_clean_second_scan_excluding_known_error_paths(self):
        error = {"type": "Other syntax error", "message": "single name expected", "path": "bad.cpp"}
        finding = {
            "check_id": "cxx.source.oob-write.constant-index",
            "path": "good.cpp",
            "start": {"line": 1},
            "extra": {"lines": "a[2]=1;", "metadata": {"cwe": "CWE-787", "candidate": True}},
        }
        result, calls = self.run_scan(
            [
                execution({"errors": [error] * 178, "results": []}),
                execution({"errors": [], "results": [finding]}),
            ]
        )
        self.assertEqual(2, len(calls))
        self.assertEqual(["failed", "completed"], [x["status"] for x in result.tool_runs])
        self.assertEqual(["good.cpp"], [x.path for x in result.findings])
        self.assertIn("semgrep-excluded-source-files:1", result.diagnostics)
        self.assertIn("semgrep-accepted-source-files:1", result.diagnostics)
        self.assertNotIn("bad.cpp", calls[1].args[0])
        self.assertIn("good.cpp", calls[1].args[0])
        self.assertIn("--max-target-bytes", calls[1].args[0])
        self.assertIn("--experimental", calls[1].args[0])
        self.assertIn("--jobs", calls[0].args[0])
        self.assertEqual("2", calls[0].args[0][calls[0].args[0].index("--jobs") + 1])
        self.assertIn("--metrics=off", calls[1].args[0])
        self.assertIn("--disable-version-check", calls[1].args[0])
        self.assertEqual((result.tool_runs[1]["run_id"],), result.findings[0].producer_run_ids)

    def test_untrusted_or_non_source_errors_never_trigger_recovery(self):
        for error in [
            {"type": "Rule parse error", "message": "bad config", "path": "bad.cpp"},
            {"type": "Timeout", "message": "slow", "path": "../outside.cpp"},
            {"type": "Other syntax error", "message": "invalid"},
        ]:
            with self.subTest(error=error):
                result, calls = self.run_scan([execution({"errors": [error], "results": []})])
                self.assertEqual(1, len(calls))
                self.assertEqual((), result.findings)
                self.assertEqual("failed", result.tool_runs[0]["status"])

    def test_second_scan_with_errors_cannot_emit_findings(self):
        error = {"type": "Timeout", "message": "slow", "path": "bad.cpp"}
        result, calls = self.run_scan(
            [
                execution({"errors": [error], "results": []}),
                execution(
                    {
                        "errors": [
                            {"type": "Timeout", "message": "still slow", "path": "good.cpp"}
                        ],
                        "results": [],
                    }
                ),
            ]
        )
        self.assertEqual(2, len(calls))
        self.assertEqual((), result.findings)
        self.assertTrue(all(x["status"] == "failed" for x in result.tool_runs))
        self.assertIn("semgrep-recovery-failed", result.diagnostics)
        self.assertIn("semgrep-recovery-tool-status:completed", result.diagnostics)
        self.assertIn("semgrep-recovery-attempted-source-files:1", result.diagnostics)

    def test_partial_parsing_locations_are_validated_before_exclusion(self):
        error = {"type": ["PartialParsing", [{"path": "bad.cpp"}]], "message": "partial source"}
        result, calls = self.run_scan(
            [
                execution({"errors": [error], "results": []}),
                execution({"errors": [], "results": []}),
            ]
        )
        self.assertEqual(2, len(calls))
        self.assertIn("semgrep-excluded-source-files:1", result.diagnostics)

    def test_syntax_errors_with_snapshot_paths_allow_one_clean_recovery(self):
        error = {"type": "Syntax error", "message": "unsupported syntax", "path": "bad.cpp"}
        result, calls = self.run_scan(
            [
                execution({"errors": [error], "results": []}),
                execution({"errors": [], "results": []}),
            ]
        )
        self.assertEqual(2, len(calls))
        self.assertIn("semgrep-excluded-source-files:1", result.diagnostics)
        self.assertEqual(["failed", "completed"], [run["status"] for run in result.tool_runs])

    def test_large_recovery_respects_the_execution_argument_limit(self):
        error = {"type": "Syntax error", "message": "unsupported syntax", "path": "bad.cpp"}
        result, calls = self.run_scan(
            [
                execution({"errors": [error], "results": []}),
                execution({"errors": [], "results": []}),
            ],
            extra_files=150,
        )
        self.assertEqual(2, len(calls))
        self.assertIn("semgrep-accepted-source-files:151", result.diagnostics)

    def test_manifest_loader_accepts_only_bounded_regular_relative_source_files(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            (root / "good.cpp").write_text("int value;", encoding="utf8")
            manifest = root / "targets.json"
            for value in [
                ["good.cpp"],
                ["../outside.cpp"],
                ["/outside.cpp"],
                ["bad.py"],
                ["good.cpp", 7],
                ["./good.cpp"],
                ["missing.cpp"],
                ["good.cpp"] * 20_001,
            ]:
                manifest.write_text(json.dumps(value), encoding="utf8")
                with (
                    self.subTest(value=str(value)[:60]),
                    patch("cxx_analyzer.semgrep_targets.Path.cwd", return_value=root),
                ):
                    if value == ["good.cpp"]:
                        self.assertEqual(value, load_targets(manifest))
                    else:
                        with self.assertRaises((ValueError, OSError)):
                            load_targets(manifest)

    def test_redacted_tool_evidence_is_replaced_by_verified_snapshot_source(self):
        error = {"type": "Syntax error", "message": "unsupported syntax", "path": "bad.cpp"}
        result, _ = self.run_scan(
            [
                execution({"errors": [error], "results": []}),
                execution({"errors": [], "results": [self.finding()]}),
            ]
        )
        self.assertEqual("void good() { int a[2]={0}; a[2]=1; }", result.findings[0].evidence)

    def test_tool_line_outside_snapshot_file_is_rejected(self):
        result, _ = self.run_scan([execution({"errors": [], "results": [self.finding(999)]})])
        self.assertEqual((), result.findings)
        self.assertIn("Semgrep JSON was rejected", result.diagnostics)

    @unittest.skipUnless(
        sys.platform == "linux" and shutil.which("semgrep"), "requires Linux Sidecar Semgrep"
    )
    def test_live_engine_recovers_usable_source_without_accepting_error_results(self):
        with patch.dict("os.environ", {"LIMA_CXX_STEP_TIMEOUT_SECONDS": "15"}):
            result, _ = self.run_scan(extra_files=500, bad_source="void bad() { if (@@@) { } }\n")
        self.assertTrue(
            any(item.path == "good.cpp" for item in result.findings), result.diagnostics
        )
        self.assertTrue(all(item.path != "bad.cpp" for item in result.findings))
        self.assertTrue(all(item.evidence != "requires login" for item in result.findings))
        self.assertEqual("void good() { int a[2]={0}; a[2]=1; }", result.findings[0].evidence)
        self.assertEqual(["failed", "completed"], [run["status"] for run in result.tool_runs])
        self.assertIn("semgrep-excluded-source-files:1", result.diagnostics)
        self.assertIn("semgrep-accepted-source-files:501", result.diagnostics)
