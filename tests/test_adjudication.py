import unittest

from lima.adjudication import (
    POLICY_NAME,
    adjudicate_findings,
    finalize_adjudication,
)
from lima.models import Finding, Severity
from lima.report import to_markdown


def finding(state: str = "candidate") -> Finding:
    return Finding(
        rule_id="PY-CMD-001",
        severity=Severity.HIGH,
        title="Untrusted input reaches a shell",
        explanation="A request value is passed to a shell command.",
        path="app.py",
        line=12,
        evidence="subprocess.run(command, shell=True)",
        fix="Use a fixed argv list without a shell.",
        test="Assert shell metacharacters are treated as plain input.",
        confidence=0.9,
        cwe="CWE-78",
        source="python-dataflow",
        evidence_kind="source-to-sink",
        verification_state=state,
    )


class AdjudicationTests(unittest.TestCase):
    def test_verified_repository_risk_is_an_alert(self):
        item = finding("dataflow-verified")

        result = adjudicate_findings([item])

        self.assertEqual(POLICY_NAME, result["policy"])
        self.assertEqual("alert", result["overall_disposition"])
        self.assertEqual(1, result["counts"]["alert"])
        self.assertEqual(item.fingerprint, result["decisions"][0]["fingerprint"])
        self.assertEqual(
            "source-to-sink-risk-evidence", result["decisions"][0]["reason"]
        )
        self.assertFalse(result["auto_clear"])

    def test_unverified_repository_risk_requires_review(self):
        result = adjudicate_findings([finding("candidate")])

        self.assertEqual("needs_review", result["overall_disposition"])
        self.assertEqual(1, result["counts"]["needs_review"])
        self.assertEqual(
            "unverified-finding-requires-human-review",
            result["decisions"][0]["reason"],
        )

    def test_multi_agent_final_finding_is_an_alert_without_relabeling_evidence(self):
        item = finding("candidate")

        result = adjudicate_findings([item], multi_agent_verified=True)

        self.assertEqual("alert", result["overall_disposition"])
        self.assertEqual("candidate", item.verification_state)
        self.assertEqual(
            "multi-agent-verification-approved-risk",
            result["decisions"][0]["reason"],
        )

    def test_empty_report_does_not_claim_automatic_safety(self):
        result = adjudicate_findings([])

        self.assertEqual("needs_review", result["overall_disposition"])
        self.assertEqual("no-positive-safety-evidence", result["overall_reason"])
        self.assertFalse(result["auto_clear"])

    def test_only_all_clear_safety_decisions_enable_automatic_clear(self):
        result = finalize_adjudication([
            {
                "path": "safe.py",
                "symbol": "run",
                "disposition": "clear",
                "reason": "mitigation-invariant-and-llm-agree",
                "invariant_statuses": ["mitigation"],
                "llm_is_vulnerable": False,
            },
        ])

        self.assertEqual("clear", result["overall_disposition"])
        self.assertTrue(result["auto_clear"])
        self.assertEqual(
            {"alert": 0, "needs_review": 0, "clear": 1}, result["counts"]
        )

    def test_unsubstantiated_clear_request_is_downgraded_to_review(self):
        result = finalize_adjudication([{
            "path": "unknown.py",
            "symbol": "run",
            "disposition": "clear",
            "reason": "caller-claimed-safe",
        }])

        self.assertEqual("needs_review", result["overall_disposition"])
        self.assertFalse(result["auto_clear"])
        self.assertEqual("clear", result["decisions"][0]["requested_disposition"])
        self.assertEqual(
            "clear-rejected-without-agreeing-safety-evidence",
            result["decisions"][0]["reason"],
        )

    def test_markdown_explains_disposition_and_no_finding_boundary(self):
        adjudication = adjudicate_findings([])
        markdown = to_markdown({
            "repository": "org/repo",
            "pull_request": None,
            "risk": "low",
            "reviewer": "repository-hybrid",
            "summary": "No threshold finding.",
            "findings": [],
            "adjudication": adjudication,
        })

        self.assertIn("## Evidence disposition", markdown)
        self.assertIn("Human review required", markdown)
        self.assertIn("not proof that the reviewed code is secure", markdown)


if __name__ == "__main__":
    unittest.main()
