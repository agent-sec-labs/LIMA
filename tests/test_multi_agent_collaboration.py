import os
import tempfile
import unittest

from lima.agents import MultiAgentCoordinator
from lima.diff_parser import parse_unified_diff
from lima.models import Finding, Severity
from lima.reviewer import ReliabilityRuleReviewer, SecurityRuleReviewer
from lima.store import TaskStore


DIFF = "--- a/app.py\n+++ b/app.py\n@@ -1 +1,2 @@\n-old\n+eval(data)\n+print(data)\n"


class MultiAgentCollaborationTests(unittest.TestCase):
    def setUp(self):
        handle, self.path = tempfile.mkstemp(suffix=".db")
        os.close(handle)
        self.store = TaskStore(self.path)

    def tearDown(self):
        os.unlink(self.path)

    def test_security_and_reliability_are_independent_specialists(self):
        parsed = parse_unified_diff(DIFF)

        security = SecurityRuleReviewer().review(DIFF, parsed)
        reliability = ReliabilityRuleReviewer().review(DIFF, parsed)

        self.assertEqual({"SEC-EVAL"}, {item.rule_id for item in security})
        self.assertEqual({"REL-DEBUG-PRINT"}, {item.rule_id for item in reliability})
        self.assertNotEqual(type(SecurityRuleReviewer()), type(ReliabilityRuleReviewer()))

    def test_critic_challenge_is_returned_for_revision_then_verified(self):
        class RevisingSpecialist:
            name = "revising-specialist"
            domains = ("correctness",)

            def __init__(self):
                self.calls = 0

            def review(self, diff, parsed):
                return self.review_assignment(diff, parsed, {}, [], [])

            def review_assignment(self, _diff, parsed, _assignment, feedback, _inbox):
                self.calls += 1
                line = parsed.added_lines[0]
                evidence = line.content if feedback else "evidence not present in the diff"
                return [Finding(
                    "LLM-CORRECTNESS", Severity.MEDIUM, "Unsafe dynamic execution",
                    "Untrusted input reaches a dynamic execution operation on the changed line.",
                    line.path, line.line, evidence,
                    "Replace dynamic execution with an explicit parser and allow-listed dispatch.",
                    "Add a regression test proving untrusted expressions are treated as data.",
                    0.8,
                )]

        specialist = RevisingSpecialist()
        self.store.create("task", "org/repo", 1, {})
        coordinator = MultiAgentCoordinator(
            [specialist], store=self.store, collaboration_rounds=2
        )

        findings = coordinator.review_with_context(
            "task", DIFF, parse_unified_diff(DIFF)
        )
        task = self.store.get("task")
        kinds = {item["kind"] for item in task["collaboration"]}
        summary = coordinator.collaboration_summary("task")

        self.assertEqual(1, len(findings))
        self.assertGreaterEqual(specialist.calls, 2)
        self.assertTrue({
            "assignment", "peer_challenge", "revision_request", "revision_response",
            "reflection_guidance", "evidence_report", "verification_decision",
            "arbitration_decision",
        }.issubset(kinds))
        self.assertEqual(2, summary["dialogue_rounds"])
        self.assertEqual(1, summary["approved_findings"])

    def test_failed_agent_is_retried_then_replanned_to_substitute(self):
        class BrokenSpecialist:
            name = "broken-lima"
            domains = ("reliability",)

            def review(self, _diff, _parsed):
                raise RuntimeError("provider unavailable")

        self.store.create("task", "org/repo", 1, {})
        coordinator = MultiAgentCoordinator(
            [BrokenSpecialist()], store=self.store, agent_retries=1,
            fallback_agent=ReliabilityRuleReviewer(),
        )

        findings = coordinator.review_with_context(
            "task", DIFF, parse_unified_diff(DIFF)
        )
        summary = coordinator.collaboration_summary("task")
        kinds = [item["kind"] for item in self.store.get("task")["collaboration"]]

        self.assertEqual({"REL-DEBUG-PRINT"}, {item.rule_id for item in findings})
        self.assertEqual(1, summary["retries"])
        self.assertEqual(1, summary["handoffs"])
        self.assertIn("assignment_handoff", kinds)
        self.assertEqual("broken-lima", summary["agents"][0]["substituted_for"])

    def test_arbiter_rejects_finding_that_fails_fix_safety_gate(self):
        class UnsafeFixSpecialist:
            name = "unsafe-fix-specialist"
            domains = ("correctness",)

            def review(self, _diff, parsed):
                line = parsed.added_lines[0]
                return [Finding(
                    "LLM-UNSAFE-FIX", Severity.MEDIUM, "Dynamic execution risk",
                    "The changed line dynamically executes input without a trust boundary.",
                    line.path, line.line, line.content,
                    "Disable validation and keep the dynamic execution behavior unchanged.",
                    "Add a focused regression test for malicious expression input.", 0.9,
                )]

        coordinator = MultiAgentCoordinator([UnsafeFixSpecialist()])

        findings = coordinator.review(DIFF, parse_unified_diff(DIFF))

        self.assertEqual([], findings)


if __name__ == "__main__":
    unittest.main()
