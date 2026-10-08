"""Aggregate ASan output must retain evidence and incomplete-run diagnostics."""

import unittest
from unittest.mock import patch

from cxx_analyzer.build_scan import BuildContext
from cxx_analyzer.deadline import AnalysisDeadline
from cxx_analyzer.sanitizer_scan import parse_asan_log, run_sanitizer_scan
from tests import test_cxx_analyzer as original_cases


class MixedSanitizerOutputTests(unittest.TestCase):
    def test_valid_report_does_not_hide_a_separate_crash(self):
        temporary, snapshot = original_cases.SanitizerScanTests()._snapshot()
        self.addCleanup(temporary.cleanup)
        root = snapshot.root.as_posix()
        report = (
            "==12==ERROR: AddressSanitizer: heap-use-after-free on address 0x1\n"
            "READ of size 4 at 0x1 thread T0\n"
            f"#0 0x1 in report_memory {root}/src/memory.c:9\n"
            "SUMMARY: AddressSanitizer: heap-use-after-free\n"
        )
        for crash in (
            "1/8 Test #1: case_0 ...***Exception: SegFault 0.08 sec\n",
            "AddressSanitizer:DEADLYSIGNAL\n",
            "Segmentation fault (core dumped)\n",
        ):
            for text in (crash + report, report + crash):
                with self.subTest(crash=crash, before=text.startswith(crash)):
                    findings, diagnostics = parse_asan_log(text, snapshot)
                    self.assertEqual(["CWE-416"], [item.cwe for item in findings])
                    self.assertEqual(["needs-human-review"], diagnostics)
                    execution = original_cases.SanitizerScanTests._execution(stderr=text)
                    with patch("cxx_analyzer.sanitizer_scan.run_step", return_value=execution):
                        result = run_sanitizer_scan(
                            snapshot,
                            original_cases.SanitizerScanTests._settings(test_steps=(("ctest",),)),
                            BuildContext(
                                snapshot.root,
                                snapshot.files,
                                sanitizer_enabled=True,
                                deadline=AnalysisDeadline.start(90),
                            ),
                        )
                    self.assertEqual(("needs-human-review",), result.diagnostics)
                    self.assertEqual(1, len(result.findings))
                    self.assertEqual("failed", result.tool_runs[0]["status"])
                    self.assertEqual(
                        (result.tool_runs[0]["run_id"],), result.findings[0].producer_run_ids
                    )


if __name__ == "__main__":
    unittest.main()
