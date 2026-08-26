import unittest

from lima.adjudication import adjudicate_findings
from lima.models import Finding, Severity
from lima.repository_triage import (
    RepositorySemanticTriage,
    RepositorySemanticTriageError,
)
from lima.report import to_markdown
from lima.semantic_retrieval import (
    RetrievalRun,
    SecurityInvariant,
    SemanticCandidate,
)


def candidate(status: str) -> SemanticCandidate:
    return SemanticCandidate(
        path="app.py",
        qualname="run",
        start_line=10,
        end_line=12,
        category="command",
        score=80,
        signals=("dynamic-shell-sink",),
        code="def run(command):\n    return subprocess.run(command, shell=True)\n",
        invariants=(SecurityInvariant(
            identifier="command-shell-data-boundary",
            category="command",
            status=status,
            summary=(
                "Dynamic command data reaches a shell."
                if status == "risk"
                else "Shell expansion is rejected before execution."
            ),
        ),),
    )


class StubRetriever:
    def __init__(self, candidates):
        self.candidates = tuple(candidates)

    def retrieve_run(self, _root):
        return RetrievalRun(
            candidates=self.candidates,
            inventory_paths=frozenset({"app.py"}),
            diagnostics={
                "inventory": {"files": 1, "bytes": 80, "truncated": False},
                "parsed_files": 1,
                "parse_errors": 0,
                "functions_seen": 1,
                "selected_candidates": len(self.candidates),
            },
        )

    @staticmethod
    def evidence_packet(candidates, max_candidates=6):
        return candidates[:max_candidates]


class StubClient:
    provider = "test-provider"
    model = "test-model"

    def __init__(self, vulnerable: bool, contract_valid: bool = True):
        self.vulnerable = vulnerable
        self.contract_valid = contract_valid

    def triage_candidate_batch(self, candidates):
        verdicts = []
        for item in candidates:
            verdicts.append({
                "path": item.path,
                "symbol": item.qualname,
                "is_vulnerable": self.vulnerable,
                "cwe": "CWE-78" if self.vulnerable else "NONE",
                "root_cause": "Untrusted command data reaches shell expansion.",
                "trust_boundary": "function argument",
                "source_evidence": "command parameter",
                "sink_evidence": "subprocess.run shell=True",
                "mitigation_evidence": "operator guard" if not self.vulnerable else "",
                "confidence": 0.91,
                "locally_template_repairable": False,
            })
        return {
            "status": "completed",
            "contract_valid": self.contract_valid,
            "contract_errors": [] if self.contract_valid else ["invalid-test-contract"],
            "provider": self.provider,
            "model": self.model,
            "verdicts": verdicts,
            "usage": {"prompt_tokens": 100, "completion_tokens": 40, "total_tokens": 140},
            "latency_ms": 25.0,
            "prompt_sha256": "a" * 64,
            "context_chars": 120,
        }


class BrokenClient:
    provider = "broken-provider"
    model = "broken-model"

    def __init__(self):
        self.calls = 0

    def triage_candidate_batch(self, _candidates):
        self.calls += 1
        raise RuntimeError("secret-token-must-not-be-persisted")


class RepositorySemanticTriageTests(unittest.TestCase):
    def test_agreeing_mitigation_and_clean_verdict_can_clear_empty_baseline(self):
        triage = RepositorySemanticTriage(
            StubClient(False), retriever=StubRetriever([candidate("mitigation")])
        )

        result = triage.run("unused", adjudicate_findings([]))

        self.assertEqual("clear", result.adjudication["overall_disposition"])
        self.assertTrue(result.adjudication["auto_clear"])
        self.assertEqual("completed", result.diagnostics["status"])
        self.assertEqual(140, result.diagnostics["usage"]["total_tokens"])
        self.assertEqual((), result.findings)

    def test_risk_and_model_agreement_creates_human_readable_finding(self):
        triage = RepositorySemanticTriage(
            StubClient(True), retriever=StubRetriever([candidate("risk")])
        )

        result = triage.run("unused", adjudicate_findings([]))

        self.assertEqual("alert", result.adjudication["overall_disposition"])
        self.assertEqual(1, len(result.findings))
        self.assertEqual("HYBRID-CWE-78", result.findings[0].rule_id)
        self.assertEqual("corroborated", result.findings[0].verification_state)
        self.assertEqual(
            result.findings[0].fingerprint,
            result.adjudication["decisions"][0]["fingerprint"],
        )

    def test_semantic_alert_reuses_matching_scanner_finding(self):
        existing = Finding(
            "FLOW-COMMAND", Severity.HIGH, "Command injection", "Flow confirmed.",
            "app.py", 11, "shell=True", "Use argv.", "Add a regression test.",
            cwe="CWE-78", verification_state="dataflow-verified",
        )
        triage = RepositorySemanticTriage(
            StubClient(True), retriever=StubRetriever([candidate("risk")])
        )

        result = triage.run(
            "unused", adjudicate_findings([existing]), [existing]
        )

        self.assertEqual((), result.findings)
        self.assertEqual(1, result.adjudication["counts"]["alert"])
        self.assertEqual(
            existing.fingerprint, result.adjudication["decisions"][0]["fingerprint"]
        )

    def test_auto_mode_provider_failure_is_redacted_and_needs_review(self):
        client = BrokenClient()
        triage = RepositorySemanticTriage(
            client, retriever=StubRetriever([candidate("risk")])
        )

        result = triage.run("unused", adjudicate_findings([]))

        self.assertEqual("needs_review", result.adjudication["overall_disposition"])
        self.assertEqual("failed-closed", result.diagnostics["status"])
        self.assertEqual(1, result.diagnostics["retrieval"]["evidence_candidates"])
        self.assertEqual(1, client.calls)
        self.assertNotIn("secret-token", str(result.diagnostics))
        self.assertFalse(result.diagnostics["secret_persisted"])

    def test_required_mode_provider_failure_stops_the_scan(self):
        client = BrokenClient()
        triage = RepositorySemanticTriage(
            client, mode="required",
            retriever=StubRetriever([candidate("risk")]),
        )

        with self.assertRaisesRegex(
            RepositorySemanticTriageError, "failed closed"
        ):
            triage.run("unused", adjudicate_findings([]))
        self.assertEqual(1, client.calls)

    def test_required_mode_rejects_invalid_output_contract(self):
        triage = RepositorySemanticTriage(
            StubClient(False, contract_valid=False), mode="required",
            retriever=StubRetriever([candidate("mitigation")]),
        )

        with self.assertRaisesRegex(
            RepositorySemanticTriageError, "invalid contract"
        ):
            triage.run("unused", adjudicate_findings([]))

    def test_markdown_exposes_semantic_status_without_a_raw_payload(self):
        markdown = to_markdown({
            "repository": "org/repo",
            "pull_request": None,
            "risk": "low",
            "summary": "Bounded repository scan.",
            "reviewer": "repository-hybrid",
            "findings": [],
            "collaboration": {
                "semantic_triage": {
                    "mode": "auto",
                    "status": "completed",
                    "provider": "test-provider",
                    "model": "test-model",
                    "usage": {"total_tokens": 140},
                    "latency_ms": 25,
                    "secret_persisted": False,
                    "retrieval": {"evidence_candidates": 1},
                },
            },
            "adjudication": adjudicate_findings([]),
        })

        self.assertIn("## Production semantic triage", markdown)
        self.assertIn("test-provider", markdown)
        self.assertIn("secret persisted: `False`", markdown)


if __name__ == "__main__":
    unittest.main()
