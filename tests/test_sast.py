import json
import tempfile
import unittest
from pathlib import Path

from lima.models import Finding, Severity
from lima.repository_scanner import RepositoryScanner
from lima.sast import BanditAdapter, SastRunResult
from lima.workspace import RepositoryWorkspace


class StubBandit:
    name = "bandit"

    def __init__(self, result):
        self.result = result

    def available(self):
        return self.result.status == "completed"

    def scan(self, _workspace, _inventory):
        return self.result


class SastAdapterTests(unittest.TestCase):
    def test_bandit_report_is_normalized_and_outside_paths_are_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            target = root / "app.py"
            target.write_text("eval(user_input)\n", encoding="utf-8")
            payload = {
                "results": [
                    {
                        "filename": str(target),
                        "test_id": "B307",
                        "issue_severity": "MEDIUM",
                        "issue_confidence": "HIGH",
                        "issue_text": "Use of possibly insecure function",
                        "issue_cwe": {"id": 78},
                        "line_number": 1,
                        "code": "1 eval(user_input)",
                        "more_info": "https://bandit.readthedocs.io/",
                    },
                    {
                        "filename": str(root.parent / "outside.py"),
                        "test_id": "B999",
                        "issue_severity": "HIGH",
                        "line_number": 1,
                    },
                ]
            }

            findings = BanditAdapter.parse_report(json.dumps(payload), root)

            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0].rule_id, "BANDIT-B307")
            self.assertEqual(findings[0].cwe, "CWE-95")
            self.assertEqual(findings[0].source, "bandit")
            self.assertEqual(findings[0].path, "app.py")

    def test_ast_and_sast_evidence_are_fused_by_location_and_cwe(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "app.py").write_text("eval(user_input)\n", encoding="utf-8")
            bandit_finding = Finding(
                rule_id="BANDIT-B307",
                severity=Severity.MEDIUM,
                title="Bandit eval",
                explanation="Bandit detected eval",
                path="app.py",
                line=1,
                evidence="eval(user_input)",
                fix="avoid eval",
                test="test malicious input",
                confidence=0.9,
                cwe="CWE-95",
                source="bandit",
                evidence_kind="sast",
            )
            adapter = StubBandit(SastRunResult("bandit", "completed", [bandit_finding]))

            result = RepositoryScanner(sast_adapters=[adapter]).scan(
                RepositoryWorkspace(root)
            )

            self.assertEqual(len(result.report.findings), 1)
            finding = result.report.findings[0]
            self.assertEqual(finding.rule_id, "SEC-EVAL")
            self.assertEqual(finding.source, "bandit+python-ast")
            self.assertEqual(finding.evidence_kind, "corroborated")
            self.assertEqual(finding.verification_state, "corroborated")
            self.assertEqual(len(finding.evidence_records), 2)
            self.assertEqual(
                {item.source for item in finding.evidence_records},
                {"python-ast", "bandit"},
            )
            self.assertEqual(finding.confidence, 0.99)
            self.assertEqual(result.report.collaboration["corroborated_findings"], 1)

    def test_required_sast_fails_closed_when_engine_is_unavailable(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "app.py").write_text("safe = True\n", encoding="utf-8")
            adapter = StubBandit(
                SastRunResult("bandit", "unavailable", diagnostic="not installed")
            )

            with self.assertRaisesRegex(RuntimeError, "required SAST engine bandit"):
                RepositoryScanner(
                    sast_mode="required", sast_adapters=[adapter]
                ).scan(RepositoryWorkspace(root))


if __name__ == "__main__":
    unittest.main()
