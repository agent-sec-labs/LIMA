import unittest

from lima.fixer import SafeFixer
from lima.models import Finding, Severity


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

    def test_explicitly_disabled_finding_is_rejected_before_rule_matching(self):
        eligibility = SafeFixer.repair_eligibility({
            "rule_id": "SEC-SQL-CONCAT", "cwe": "CWE-89",
            "verification_state": "dataflow-verified", "automatic_repair": False,
        })

        self.assertEqual(
            {"eligible": False, "reason": "automatic-repair-disabled"},
            eligibility,
        )


if __name__ == "__main__":
    unittest.main()
