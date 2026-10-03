"""Repository investigation chain behavior tests (2026-10-03 mainline).

All tests run offline with a scripted model client: the production
AgentLoop/ToolRegistry, snapshot tools, privacy scrubbing, validation,
scheduling and report merge are the real implementation; only the chat
transport is replaced.  The real-model acceptance runs are separate
evidence (see docs/LIMA_Agent_Investigation_Report_2026-10-03.md).
"""

import json
import pathlib
import sys
import tempfile
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from lima.adjudication import finalize_adjudication
from lima.models import Finding, ReviewReport, Severity
from lima.repository_investigation import (
    FindingInvestigator,
    InvestigationBudget,
    InvestigationLLMClient,
    InvestigationSnapshot,
    build_investigation_targets,
    build_module_targets,
    merge_investigation_into_report,
)

SAMPLE = {
    "svc/__init__.py": "",
    "svc/eval_like.py": (
        "class Metrics:\n"
        "    def eval(self):\n"
        "        return {'ok': True}\n"
        "\n"
        "\n"
        "def report():\n"
        "    m = Metrics()\n"
        "    return m.eval()\n"
        "\n"
        "\n"
        "def run(user):\n"
        "    return eval(user)\n"
    ),
    "svc/secrets.py": (
        "API_TOKEN = \"sk-live-9f2c7b1e4d6a8c0f3b5d7e9a45c8\"\n"
        "SERVICE_PASSWORD_ENV = \"SERVICE_PASSWORD\"\n"
        "OTHER_TOKEN_BOX = \"token-box-label\"\n"
    ),
    "svc/unclear.py": (
        "from toolkit import evaluate\n"
        "\n"
        "\n"
        "def run(payload):\n"
        "    return evaluate(payload)\n"
    ),
}

REVIEWER_ID = "investigation-tests"


class ScriptedClient(InvestigationLLMClient):
    """Offline stand-in for the chat transport with a response script."""

    def __init__(self, script, budget_max=100):
        super().__init__(
            base_url="http://offline", api_key="offline-key",
            model="offline-model", provider="offline",
            budget=InvestigationBudget(max_requests=budget_max),
        )
        self.script = list(script)
        self.sent_user_messages: list[str] = []

    def complete_json(self, *, system: str, user: str):
        self.budget = self.budget.reserve()
        self.sent_user_messages.append(user)
        if not self.script:
            raise RuntimeError("script exhausted (offline client)")
        action = self.script.pop(0)
        if isinstance(action, Exception):
            raise action
        return action


def make_snapshot(root: pathlib.Path) -> InvestigationSnapshot:
    return InvestigationSnapshot(root)


def write_sample(root: pathlib.Path) -> None:
    for rel, text in SAMPLE.items():
        path = root / pathlib.PurePosixPath(rel)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")


def finding(path, line, rule="SEC-HARDCODED-SECRET", cwe="CWE-798",
            evidence="literal") -> Finding:
    return Finding(
        rule_id=rule, severity=Severity.HIGH, title="candidate",
        explanation="test candidate", path=path, line=line, evidence=evidence,
        fix="", test="", confidence=0.9, cwe=cwe, source="python-ast",
        evidence_kind="ast-assignment", verification_state="syntax-verified",
    )


def tool_action(tool, **arguments):
    return {"action": "tool", "tool": tool, "arguments": arguments,
            "reason": "missing evidence"}


def final(results, new_targets=None):
    return {
        "action": "final", "results": results,
        "new_targets": new_targets or [],
    }


def result(fp, path, line, verdict, refs=None, reasoning="model reasoning",
           basis=None, confidence=0.9):
    return {
        "fingerprint": fp, "path": path, "line": line, "verdict": verdict,
        "reasoning": reasoning, "evidence_refs": refs or [],
        "evidence_basis": basis or {
            "syntax_hit": True, "model_reasoning": True,
            "dynamic_observation": False,
        },
        "confidence": confidence,
    }


class InvestigationTestCase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self._tmp.name) / "repo"
        self.root.mkdir()
        write_sample(self.root)
        self.snapshot = make_snapshot(self.root)
        self.addCleanup(self._tmp.cleanup)

    def findings(self):
        return [
            finding("svc/eval_like.py", 9, rule="SEC-EVAL", cwe="CWE-95",
                    evidence="m.eval()"),
            finding("svc/eval_like.py", 13, rule="SEC-EVAL", cwe="CWE-95",
                    evidence="eval(user)"),
            finding("svc/secrets.py", 1, evidence="sk-live..."),
            finding("svc/secrets.py", 2, evidence="SERVICE_PASSWORD"),
            finding("svc/secrets.py", 3, evidence="token-box-label"),
            finding("svc/unclear.py", 4, rule="SEC-EVAL", cwe="CWE-95",
                    evidence="evaluate(payload)"),
        ]

    def investigator(self, script, *, batch_size=6, budget=100):
        client = ScriptedClient(script, budget_max=budget)
        return FindingInvestigator(
            client, batch_size=batch_size, max_steps=5, timeout_seconds=30,
        )


class TestScheduling(InvestigationTestCase):
    def test_every_finding_routed_with_pagination(self):
        findings = self.findings()
        targets = build_investigation_targets(findings, self.snapshot)
        # Rule grouping: the three SEC-EVAL candidates form the first
        # batch, the three SEC-HARDCODED-SECRET candidates the second.
        eval_targets = [t for t in targets if t.rule_id == "SEC-EVAL"]
        secret_targets = [t for t in targets if t.rule_id != "SEC-EVAL"]
        script = [
            final([
                result(t.fingerprint, t.path, t.line, "insufficient")
                for t in eval_targets
            ]),
            final([
                result(t.fingerprint, t.path, t.line, "insufficient")
                for t in secret_targets
            ]),
        ]
        investigator = self.investigator(script, batch_size=3)
        outcome = investigator.investigate(targets, self.snapshot)
        # Six targets, batch size three: two batches, everything covered.
        self.assertEqual(len(outcome.results), len(targets))
        self.assertEqual(
            set(outcome.results), {t.fingerprint for t in targets}
        )
        self.assertEqual(len(outcome.traces), 2)
        self.assertTrue(all(
            s["status"] == "completed" for s in outcome.statuses.values()
        ))

    def test_same_file_same_rule_independent(self):
        findings = self.findings()
        targets = build_investigation_targets(findings, self.snapshot)
        by_line = {t.line: t for t in targets if t.path == "svc/secrets.py"}
        self.assertEqual(len(by_line), 3)  # same file, same rule, 3 lines
        script = [
            tool_action("read_source", path="svc/secrets.py",
                        start_line=1, end_line=3),
            final([
                result(t.fingerprint, t.path, t.line, "refuted",
                       refs=["read_source:svc/secrets.py"])
                for t in targets
            ]),
        ]
        outcome = self.investigator(script).investigate(targets, self.snapshot)
        for _line, target in by_line.items():
            record = outcome.results[target.fingerprint]
            self.assertEqual(record["verdict"], "refuted")
            self.assertIn(":svc/secrets.py", record["evidence_refs"][0])


class TestVerdictValidation(InvestigationTestCase):
    def test_refuted_without_observed_evidence_is_insufficient(self):
        findings = [finding("svc/secrets.py", 1)]
        targets = build_investigation_targets(findings, self.snapshot)
        target = targets[0]
        script = [final([
            result(target.fingerprint, target.path, target.line, "refuted",
                   refs=["read_source:svc/secrets.py"]),
        ])]
        outcome = self.investigator(script).investigate(targets, self.snapshot)
        record = outcome.results[target.fingerprint]
        # The model never actually read the file: no tool call happened.
        self.assertEqual(record["verdict"], "insufficient")
        self.assertIn("bare clean", record["reasoning"])

    def test_refuted_with_real_tool_observation_passes(self):
        findings = [finding("svc/secrets.py", 2)]
        targets = build_investigation_targets(findings, self.snapshot)
        target = targets[0]
        script = [
            tool_action("read_source", path="svc/secrets.py",
                        start_line=1, end_line=3),
            final([result(
                target.fingerprint, target.path, target.line, "refuted",
                refs=["read_source:svc/secrets.py:1-3"],
            )]),
        ]
        outcome = self.investigator(script).investigate(targets, self.snapshot)
        self.assertEqual(
            outcome.results[target.fingerprint]["verdict"], "refuted"
        )

    def test_off_contract_verdict_and_identity_echo_mismatch(self):
        findings = [finding("svc/secrets.py", 1), finding("svc/unclear.py", 4)]
        targets = build_investigation_targets(findings, self.snapshot)
        secret, unclear = targets
        script = [final([
            result(secret.fingerprint, secret.path, secret.line, "clean"),
            result(unclear.fingerprint, "svc/other-file.py",
                   unclear.line, "refuted",
                   refs=["read_source:svc/secrets.py"]),
        ])]
        outcome = self.investigator(script).investigate(targets, self.snapshot)
        self.assertEqual(
            outcome.results[secret.fingerprint]["verdict"], "insufficient"
        )
        record = outcome.results[unclear.fingerprint]
        self.assertEqual(record["verdict"], "insufficient")
        self.assertIn("different path", record["reasoning"])

    def test_invented_fingerprint_ignored_and_missing_requeued(self):
        findings = [finding("svc/secrets.py", 1), finding("svc/unclear.py", 4)]
        targets = build_investigation_targets(findings, self.snapshot)
        secret, unclear = targets
        invented = "ffffffffffffffffffff"
        script = [
            final([
                result(secret.fingerprint, secret.path, secret.line,
                       "supported",
                       refs=["read_source:svc/secrets.py"]),
                result(invented, "svc/secrets.py", 1, "refuted"),
            ]),
            # Retry batch contains only the skipped candidate.
            final([
                result(unclear.fingerprint, unclear.path, unclear.line,
                       "insufficient"),
            ]),
        ]
        outcome = self.investigator(script).investigate(targets, self.snapshot)
        self.assertEqual(
            outcome.results[secret.fingerprint]["verdict"], "supported"
        )
        self.assertEqual(
            outcome.results[unclear.fingerprint]["verdict"], "insufficient"
        )
        self.assertNotIn(invented, outcome.results)

    def test_transport_failure_isolates_batch_and_keeps_status(self):
        findings = self.findings()
        targets = build_investigation_targets(findings, self.snapshot)
        script = [RuntimeError("provider down")]
        outcome = self.investigator(script, batch_size=3).investigate(
            targets, self.snapshot
        )
        self.assertFalse(outcome.results)
        self.assertTrue(all(
            s["status"] == "failed" for s in outcome.statuses.values()
        ))
        self.assertEqual(len(outcome.failures), 2)  # two batches failed

    def test_budget_exhaustion_marks_unprocessed(self):
        findings = self.findings()
        targets = build_investigation_targets(findings, self.snapshot)
        script = [final([
            result(t.fingerprint, t.path, t.line, "supported",
                   refs=["read_source:svc/secrets.py"])
            for t in targets[:3]
        ])]
        investigator = self.investigator(script, batch_size=3, budget=1)
        outcome = investigator.investigate(targets, self.snapshot)
        # The first batch completed inside the budget; every later target
        # is an explicit unprocessed entry, never silently dropped.
        self.assertEqual(len(outcome.results), 3)
        unprocessed = {
            fp: status for fp, status in outcome.statuses.items()
            if status["status"] == "unprocessed"
        }
        self.assertEqual(len(unprocessed), len(targets) - 3)
        self.assertTrue(all(
            s["reason"] == "request-budget-exhausted"
            for s in unprocessed.values()
        ))


class TestToolsAndPrivacy(InvestigationTestCase):
    def test_model_triggered_dynamic_contrast(self):
        findings = [finding("svc/eval_like.py", 9, rule="SEC-EVAL",
                            cwe="CWE-95", evidence="m.eval()")]
        targets = build_investigation_targets(findings, self.snapshot)
        target = targets[0]
        script = [
            tool_action("dynamic_contrast", sample_id="method-eval-vs-builtin"),
            final([result(
                target.fingerprint, target.path, target.line, "refuted",
                refs=["read_source:svc/eval_like.py"],
                basis={"syntax_hit": True, "model_reasoning": True,
                       "dynamic_observation": True},
            )]),
        ]
        outcome = self.investigator(script).investigate(targets, self.snapshot)
        self.assertEqual(outcome.dynamic_observations, 1)
        dyn = [
            step for trace in outcome.traces for step in trace["steps"]
            if step["tool"] == "dynamic_contrast"
        ]
        self.assertEqual(len(dyn), 1)
        self.assertIn("object-method eval", dyn[0]["result"])

    def test_secret_never_reaches_prompt_or_trace(self):
        findings = [finding("svc/secrets.py", 1)]
        targets = build_investigation_targets(findings, self.snapshot)
        target = targets[0]
        secret = SAMPLE["svc/secrets.py"].splitlines()[0].split('"')[1]
        script = [
            tool_action("read_source", path="svc/secrets.py",
                        start_line=1, end_line=3),
            final([result(
                target.fingerprint, target.path, target.line, "refuted",
                refs=["read_source:svc/secrets.py:1-3"],
            )]),
        ]
        investigator = self.investigator(script)
        outcome = investigator.investigate(targets, self.snapshot)
        client = investigator.client
        # The full literal appears in no model-facing prompt...
        for message in client.sent_user_messages:
            self.assertNotIn(secret, message)
        # ...and in no persisted trace or verdict.
        for trace in outcome.traces:
            self.assertNotIn(secret, json.dumps(trace))
        self.assertNotIn(
            secret, json.dumps(outcome.results[target.fingerprint])
        )
        # The masked shape stays visible for reasoning.
        self.assertIn("masked", json.dumps(outcome.traces))

    def test_unknown_path_and_sample_fail_closed_as_tool_errors(self):
        findings = [finding("svc/secrets.py", 1)]
        targets = build_investigation_targets(findings, self.snapshot)
        target = targets[0]
        script = [
            tool_action("read_source", path="../../etc/passwd",
                        start_line=1, end_line=2),
            tool_action("dynamic_contrast", sample_id="rm -rf /"),
            final([result(
                target.fingerprint, target.path, target.line, "insufficient",
            )]),
        ]
        outcome = self.investigator(script).investigate(targets, self.snapshot)
        observations = [
            step for trace in outcome.traces for step in trace["steps"]
        ]
        # Two recorded tool errors (illegal path, illegal sample id) plus
        # the recorded final = three trace entries.
        self.assertEqual(len(observations), 3)
        self.assertIn("not part of the fixed snapshot",
                      observations[0]["error"])
        self.assertIn("unknown dynamic contrast", observations[1]["error"])


class TestModuleEntry(InvestigationTestCase):
    def test_module_target_with_zero_findings_discovers_risk(self):
        targets = build_module_targets(self.snapshot, ["svc/unclear.py"])
        self.assertEqual(len(targets), 1)
        script = [
            tool_action("read_source", path="svc/unclear.py",
                        start_line=1, end_line=5),
            final([], new_targets=[{
                "path": "svc/unclear.py", "line": 4, "symbol": "run",
                "why": "evaluate imported from an unresolved module and "
                       "invoked on caller data",
                "evidence_refs": ["read_source:svc/unclear.py:1-5"],
            }]),
        ]
        outcome = self.investigator(script).investigate(targets, self.snapshot)
        self.assertEqual(len(outcome.new_targets), 1)
        report = ReviewReport(
            repository="repo", pull_request=None, summary="s", risk="low",
        )
        merge_investigation_into_report(report, outcome, [])
        discovered = [
            f for f in report.findings if f.rule_id == "AGENT-DISCOVERY"
        ]
        self.assertEqual(len(discovered), 1)
        self.assertEqual(discovered[0].path, "svc/unclear.py")
        self.assertEqual(discovered[0].line, 4)
        # A model new-target claiming an unread path is not materialized.
        script2 = [final([], new_targets=[{
            "path": "not/in/snapshot.py", "line": 1, "why": "claim",
            "evidence_refs": [],
        }])]
        outcome2 = self.investigator(script2).investigate(
            build_module_targets(self.snapshot, ["svc/unclear.py"]),
            self.snapshot,
        )
        report2 = ReviewReport(
            repository="repo", pull_request=None, summary="s", risk="low",
        )
        merge_investigation_into_report(report2, outcome2, [])
        self.assertEqual(report2.findings, [])


class TestReportMerge(InvestigationTestCase):
    def test_merge_three_verdicts_user_faces(self):
        findings = self.findings()[:4]
        targets = build_investigation_targets(findings, self.snapshot)
        verdicts = {}
        for index, target in enumerate(targets):
            verdict = ("supported", "refuted", "insufficient", "refuted")[index]
            verdicts[target.fingerprint] = result(
                target.fingerprint, target.path, target.line, verdict,
                refs=["read_source:svc/secrets.py:1-3"],
            )
        outcome = self.investigator([
            tool_action("read_source", path="svc/secrets.py",
                        start_line=1, end_line=3),
            final(list(verdicts.values())),
        ]).investigate(targets, self.snapshot)
        report = ReviewReport(
            repository="repo", pull_request=None, summary="old", risk="high",
            findings=list(findings),
        )
        merge_investigation_into_report(report, outcome, findings)
        decisions = {
            d["fingerprint"]: d for d in report.adjudication["decisions"]
        }
        supported_fp = targets[0].fingerprint
        refuted_fps = {targets[1].fingerprint, targets[3].fingerprint}
        insufficient_fp = targets[2].fingerprint
        # Supported risk stays an active alert with explicit reasons.
        self.assertEqual(decisions[supported_fp]["disposition"], "alert")
        self.assertEqual(
            decisions[supported_fp]["reason"], "model-supported-risk-evidence"
        )
        # Evidence-backed refutations leave the active alert set but stay
        # in history with their recorded refutation.
        for fp in refuted_fps:
            self.assertEqual(decisions[fp]["disposition"], "needs_review")
            self.assertEqual(
                decisions[fp]["effective_state"],
                "excluded-from-active-alerts",
            )
            self.assertEqual(
                decisions[fp]["investigation_verdict"], "refuted"
            )
        self.assertEqual(
            decisions[insufficient_fp]["reason"],
            "investigation-insufficient-evidence",
        )
        # Transition table row 4 (alert + insufficient): the insufficient
        # verdict keeps the pre-investigation active alert; the merged
        # status must speak the contract vocabulary ("insufficient"), and
        # the candidate must not leave the active alert set.
        self.assertEqual(decisions[insufficient_fp]["disposition"], "alert")
        self.assertEqual(
            decisions[insufficient_fp]["investigation_status"], "insufficient"
        )
        self.assertNotEqual(
            decisions[insufficient_fp].get("effective_state"),
            "excluded-from-active-alerts",
        )
        # Original findings remain in history untouched.
        self.assertEqual(len(report.findings), len(findings))
        summary_faces = report.adjudication["investigation_summary"]
        self.assertEqual(summary_faces["supported"], 1)
        self.assertEqual(summary_faces["refuted"], 2)
        self.assertEqual(summary_faces["insufficient"], 1)
        # Supported + insufficient-kept are both active alerts now.
        self.assertEqual(summary_faces["active_alerts"], 2)
        self.assertEqual(report.adjudication["counts"]["alert"], 2)
        self.assertEqual(report.adjudication["counts"]["needs_review"], 2)
        self.assertEqual(report.adjudication["overall_disposition"], "alert")
        self.assertIn("refuted with scope-limited evidence", report.summary)
        self.assertIn("2 refuted", report.summary)
        # The user-facing collaboration block is conclusion-first.
        block = report.collaboration["investigation"]
        self.assertEqual(block["verdict_counts"]["refuted"], 2)
        self.assertFalse(block["secret_persisted"])

    def test_merge_failure_keeps_alerts(self):
        findings = self.findings()[:2]
        targets = build_investigation_targets(findings, self.snapshot)
        outcome = self.investigator(
            [RuntimeError("provider down")]
        ).investigate(targets, self.snapshot)
        report = ReviewReport(
            repository="repo", pull_request=None, summary="old", risk="high",
            findings=list(findings),
        )
        merge_investigation_into_report(report, outcome, findings)
        # Transition table row 5 (alert + failed): a failed investigation
        # never downgrades or clears the pre-investigation active alert
        # (these findings have no prior adjudication decision, so the
        # frozen fallback applies: findings that entered investigation are
        # active-alert candidates).  The failure state and its specific
        # reason stay recorded on the decision.
        for decision in report.adjudication["decisions"]:
            self.assertEqual(decision["disposition"], "alert")
            self.assertNotEqual(
                decision.get("effective_state"), "excluded-from-active-alerts"
            )
            self.assertEqual(decision["investigation_status"], "failed")
            self.assertEqual(decision["reason"], "investigation-failed")
            self.assertEqual(
                decision.get("investigation_failure_reason"),
                "batch-error:RuntimeError",
            )
        self.assertEqual(report.adjudication["overall_disposition"], "alert")
        self.assertEqual(
            report.adjudication["investigation_summary"]["active_alerts"], 2
        )
        # The failure detail lives in the failures list, sanitized.
        self.assertEqual(len(outcome.failures), 1)
        self.assertEqual(outcome.failures[0]["failure"], "RuntimeError")


class TestMergeTransitionTable(InvestigationTestCase):
    """Frozen A2 merge contract: one test per transition-table row.

    Frozen pre-investigation disposition source: the decisions already in
    ``report.adjudication`` at merge time, looked up by fingerprint; a
    finding with no prior decision falls back to the active-alert
    candidate (findings that entered investigation are active alerts by
    construction).  Frozen implementation-state mapping: timeout ->
    failed with a timeout-specific reason, budget exhaustion ->
    unprocessed with a budget-specific reason; no new ambiguous states.
    """

    def prior_adjudication(self, pairs):
        decisions = [
            {
                "fingerprint": item.fingerprint,
                "path": item.path,
                "line": item.line,
                "rule_id": item.rule_id,
                "disposition": disposition,
                "reason": "semantic-triage-pre-state",
            }
            for item, disposition in pairs
        ]
        return finalize_adjudication(decisions)

    def merge_with(self, findings, script, *, prior=None, budget=100,
                   batch_size=6):
        targets = build_investigation_targets(findings, self.snapshot)
        outcome = self.investigator(
            script, batch_size=batch_size, budget=budget
        ).investigate(targets, self.snapshot)
        report = ReviewReport(
            repository="repo", pull_request=None, summary="old", risk="high",
            findings=list(findings),
        )
        if prior is not None:
            report.adjudication = prior
        merge_investigation_into_report(report, outcome, findings)
        decisions = {
            d["fingerprint"]: d for d in report.adjudication["decisions"]
        }
        return report, decisions

    def observed_refuted_script(self, target, verdict):
        return [
            tool_action("read_source", path="svc/secrets.py",
                        start_line=1, end_line=3),
            final([result(
                target.fingerprint, target.path, target.line, verdict,
                refs=["read_source:svc/secrets.py:1-3"],
            )]),
        ]

    def test_row1_prior_alert_supported_keeps_active_alert(self):
        secret = self.findings()[2]
        script = self.observed_refuted_script(secret, "supported")
        report, decisions = self.merge_with([secret], script)
        decision = decisions[secret.fingerprint]
        self.assertEqual(decision["disposition"], "alert")
        self.assertEqual(decision["investigation_verdict"], "supported")
        self.assertEqual(decision["reason"], "model-supported-risk-evidence")
        # Row 1 evidence level: valid evidence refs and basis recorded.
        self.assertTrue(decision["investigation_evidence_refs"])
        self.assertTrue(decision["investigation_evidence_basis"])
        self.assertNotEqual(
            decision.get("effective_state"), "excluded-from-active-alerts"
        )
        self.assertEqual(
            report.adjudication["investigation_summary"]["active_alerts"], 1
        )

    def test_row2_prior_alert_refuted_with_observed_refs_excluded(self):
        secret = self.findings()[2]
        script = self.observed_refuted_script(secret, "refuted")
        report, decisions = self.merge_with([secret], script)
        decision = decisions[secret.fingerprint]
        self.assertEqual(decision["disposition"], "needs_review")
        self.assertEqual(decision["investigation_verdict"], "refuted")
        self.assertEqual(
            decision["effective_state"], "excluded-from-active-alerts"
        )
        # Refutation scope and evidence stay recorded; the original
        # finding stays in history.
        self.assertTrue(decision["investigation_evidence_refs"])
        self.assertEqual(len(report.findings), 1)
        self.assertEqual(
            report.adjudication["investigation_summary"]["active_alerts"], 0
        )

    def test_row3_refuted_without_observed_refs_keeps_alert(self):
        secret = self.findings()[2]
        # No tool call happens, so the cited ref was never actually
        # observed: the validation layer downgrades the refutation to
        # insufficient (existing behavior kept); the merge must keep the
        # active alert and record that the refutation was rejected.
        script = [final([result(
            secret.fingerprint, secret.path, secret.line, "refuted",
            refs=["read_source:svc/secrets.py"],
        )])]
        report, decisions = self.merge_with([secret], script)
        decision = decisions[secret.fingerprint]
        self.assertEqual(decision["disposition"], "alert")
        self.assertEqual(decision["investigation_verdict"], "insufficient")
        self.assertEqual(decision["investigation_status"], "insufficient")
        self.assertEqual(
            decision["reason"], "refutation-rejected-no-observed-evidence"
        )
        self.assertIn("bare clean", decision["investigation_reasoning"])
        self.assertNotEqual(
            decision.get("effective_state"), "excluded-from-active-alerts"
        )
        self.assertEqual(
            report.adjudication["investigation_summary"]["active_alerts"], 1
        )

    def test_row4_insufficient_verdict_keeps_alert(self):
        secret = self.findings()[2]
        script = [final([result(
            secret.fingerprint, secret.path, secret.line, "insufficient",
            reasoning="no observation supporting either direction",
        )])]
        report, decisions = self.merge_with([secret], script)
        decision = decisions[secret.fingerprint]
        self.assertEqual(decision["disposition"], "alert")
        self.assertEqual(decision["investigation_verdict"], "insufficient")
        self.assertEqual(decision["investigation_status"], "insufficient")
        self.assertEqual(
            decision["reason"], "investigation-insufficient-evidence"
        )
        self.assertIn(
            "no observation", decision["investigation_reasoning"]
        )
        self.assertNotEqual(
            decision.get("effective_state"), "excluded-from-active-alerts"
        )
        self.assertEqual(
            report.adjudication["investigation_summary"]["active_alerts"], 1
        )

    def test_row5_timeout_maps_to_failed_with_reason(self):
        secret = self.findings()[2]
        report, decisions = self.merge_with(
            [secret], [TimeoutError("model timeout")]
        )
        decision = decisions[secret.fingerprint]
        self.assertEqual(decision["disposition"], "alert")
        self.assertEqual(decision["investigation_status"], "failed")
        self.assertEqual(decision["reason"], "investigation-failed")
        # Frozen implementation-state mapping: timeout -> failed with the
        # timeout-specific reason preserved verbatim.
        self.assertEqual(
            decision.get("investigation_failure_reason"),
            "batch-error:TimeoutError",
        )
        self.assertEqual(
            report.adjudication["investigation_summary"]["active_alerts"], 1
        )

    def test_row5_budget_exhausted_maps_to_unprocessed_with_reason(self):
        secret = self.findings()[2]
        report, decisions = self.merge_with([secret], [], budget=0)
        decision = decisions[secret.fingerprint]
        self.assertEqual(decision["disposition"], "alert")
        self.assertEqual(decision["investigation_status"], "unprocessed")
        self.assertEqual(decision["reason"], "investigation-unprocessed")
        self.assertEqual(
            decision.get("investigation_failure_reason"),
            "request-budget-exhausted",
        )
        self.assertEqual(
            report.adjudication["investigation_summary"]["active_alerts"], 1
        )

    def test_row6_prior_needs_review_failure_stays_non_active(self):
        first, second = self.findings()[:2]
        prior = self.prior_adjudication([(first, "needs_review")])
        report, decisions = self.merge_with(
            [first, second], [RuntimeError("provider down")], prior=prior,
        )
        kept = decisions[first.fingerprint]
        # Row 6: a non-active pre-investigation disposition is kept on
        # failure -- neither escalated to alert nor excluded.
        self.assertEqual(kept["disposition"], "needs_review")
        self.assertNotEqual(
            kept.get("effective_state"), "excluded-from-active-alerts"
        )
        self.assertEqual(kept["investigation_status"], "failed")
        self.assertEqual(
            kept.get("investigation_failure_reason"),
            "batch-error:RuntimeError",
        )
        # Frozen pre-investigation source rule: only the first finding has
        # a prior decision; the second falls back to the active-alert
        # candidate (row 5 applies to it).
        fallback = decisions[second.fingerprint]
        self.assertEqual(fallback["disposition"], "alert")
        self.assertEqual(fallback["investigation_status"], "failed")
        self.assertEqual(
            report.adjudication["investigation_summary"]["active_alerts"], 1
        )

    def test_row7_prior_needs_review_supported_promotes_to_alert(self):
        secret = self.findings()[2]
        prior = self.prior_adjudication([(secret, "needs_review")])
        script = self.observed_refuted_script(secret, "supported")
        report, decisions = self.merge_with([secret], script, prior=prior)
        decision = decisions[secret.fingerprint]
        self.assertEqual(decision["disposition"], "alert")
        self.assertEqual(decision["investigation_verdict"], "supported")
        self.assertEqual(decision["reason"], "model-supported-risk-evidence")
        self.assertNotEqual(
            decision.get("effective_state"), "excluded-from-active-alerts"
        )
        self.assertEqual(
            report.adjudication["investigation_summary"]["active_alerts"], 1
        )

    def test_row8_prior_needs_review_refuted_with_refs_excluded(self):
        secret = self.findings()[2]
        prior = self.prior_adjudication([(secret, "needs_review")])
        script = self.observed_refuted_script(secret, "refuted")
        report, decisions = self.merge_with([secret], script, prior=prior)
        decision = decisions[secret.fingerprint]
        self.assertEqual(decision["disposition"], "needs_review")
        self.assertEqual(
            decision["effective_state"], "excluded-from-active-alerts"
        )
        self.assertTrue(decision["investigation_evidence_refs"])
        self.assertEqual(
            report.adjudication["investigation_summary"]["active_alerts"], 0
        )

    def test_all_failed_active_candidates_stay_alert_overall(self):
        findings = self.findings()[:3]
        report, decisions = self.merge_with(
            findings, [RuntimeError("provider down")], batch_size=3,
        )
        # Derived surface: counts, overall disposition and active_alerts
        # are derived from the preserved dispositions -- a fully failed
        # prior-alert set must present as an alert run, never as
        # needs_review.
        self.assertEqual(
            [d["disposition"] for d in decisions.values()], ["alert"] * 3
        )
        self.assertEqual(report.adjudication["counts"]["alert"], 3)
        self.assertEqual(report.adjudication["counts"]["needs_review"], 0)
        self.assertEqual(report.adjudication["overall_disposition"], "alert")
        self.assertEqual(
            report.adjudication["investigation_summary"]["active_alerts"], 3
        )


class TestServiceWiring(unittest.TestCase):
    def setUp(self):
        import os
        import tempfile

        # Read-only container roots: point every writable path at a temp
        # directory so service construction works under `--read-only`.
        self._svc_tmp = tempfile.mkdtemp(suffix="-inv-svc")
        os.environ["LIMA_DB_PATH"] = str(
            pathlib.Path(self._svc_tmp) / "state.db"
        )
        os.environ["LIMA_REPOSITORY_CACHE_ROOT"] = str(
            pathlib.Path(self._svc_tmp) / "cache"
        )
        self.addCleanup(self._cleanup_tmp)

    def _cleanup_tmp(self):
        import shutil

        shutil.rmtree(self._svc_tmp, ignore_errors=True)

    def test_builder_modes(self):
        import os

        from lima.config import Settings
        from lima.service import ReviewService

        def build(mode):
            os.environ["LIMA_REPOSITORY_INVESTIGATION_MODE"] = mode
            os.environ["LIMA_LLM_PROVIDER"] = "deepseek"
            os.environ["LIMA_DEEPSEEK_API_KEY"] = "test-key"
            settings = Settings.from_env()
            return ReviewService(settings)

        service_off = build("off")
        self.assertIsNone(service_off.repository_investigation)
        service_auto = build("auto")
        self.assertIsNotNone(service_auto.repository_investigation)
        self.assertEqual(
            service_auto.repository_investigation.batch_size,
            service_auto.settings.repository_investigation_batch_size,
        )
        service_auto.queue.close()
        service_off.queue.close()
        os.environ.pop("LIMA_REPOSITORY_INVESTIGATION_MODE", None)
        os.environ.pop("LIMA_LLM_PROVIDER", None)
        os.environ.pop("LIMA_DEEPSEEK_API_KEY", None)

    def test_scan_runs_investigation_through_service(self):
        import os
        import shutil
        import time

        from lima.config import Settings
        from lima.service import ReviewService

        root = tempfile.mkdtemp(suffix="-svc")
        self.addCleanup(lambda: shutil.rmtree(root, ignore_errors=True))
        repo_root = pathlib.Path(root) / "repo"
        write_sample(repo_root)

        os.environ["LIMA_REPOSITORY_INVESTIGATION_MODE"] = "auto"
        os.environ["LIMA_LLM_PROVIDER"] = "deepseek"
        os.environ["LIMA_DEEPSEEK_API_KEY"] = "test-key"
        os.environ["LIMA_REPOSITORY_SCAN_SAST_MODE"] = "off"
        os.environ["LIMA_REPOSITORY_SCAN_LLM_MODE"] = "off"
        os.environ["LIMA_REPOSITORY_SCAN_SOURCES"] = "local-import"
        os.environ["LIMA_REPOSITORY_IMPORT_ROOT"] = root
        settings = Settings.from_env()
        service = ReviewService(settings)
        self.addCleanup(service.queue.close)

        # Import the sample as a local repository and stub the investigator
        # with a deterministic outcome (software-level wiring; the real
        # model acceptance run is separate evidence).
        import lima.repository_import as import_mod

        original = import_mod.RepositoryImportPolicy.resolve
        import_mod.RepositoryImportPolicy.resolve = (
            lambda self, key: repo_root
        )
        try:
            findings = [finding("svc/secrets.py", 2)]
            snapshot = make_snapshot(repo_root)
            targets = build_investigation_targets(findings, snapshot)

            class StubInvestigator:
                def __init__(self, outcome):
                    self.outcome = outcome

                def investigate(self, batch, snap):
                    return self.outcome

            class StubOutcome:
                def __init__(self, results):
                    self.results = results
                    self.statuses = {
                        fp: {"status": "completed", "reason": "model-verdict"}
                        for fp in results
                    }
                    self.new_targets = []
                    self.traces = []
                    self.failures = []
                    self.dynamic_observations = 0
                    self.usage = {
                        "requests": 1, "usage_totals": {},
                        "provider": "stub", "model": "stub",
                        "secret_persisted": False,
                    }

            stub_results = {
                targets[0].fingerprint: {
                    "fingerprint": targets[0].fingerprint,
                    "verdict": "refuted",
                    "reasoning": "env var name reference",
                    "evidence_refs": ["read_source:svc/secrets.py:1-3"],
                    "evidence_basis": {}, "confidence": 0.9,
                }
            }
            # Rebuild the scanner findings via a real scan first: the
            # service scan happens inside the queue worker; stub instead on
            # the finding level through the investigation merge path.
            created = service.enqueue_repository_scan(
                "repo", "default", investigate_paths=["svc/unclear"],
            )
            # Replace the investigator before the worker picks the task up.
            service.repository_investigation = StubInvestigator(
                StubOutcome(stub_results)
            )
            deadline = time.time() + 60
            task = {}
            while time.time() < deadline:
                task = service.store.get(created["task_id"], "default") or {}
                if task.get("state") in {"SUCCESS", "FAILED"}:
                    break
                time.sleep(0.05)
        finally:
            import_mod.RepositoryImportPolicy.resolve = original
            for key in (
                "LIMA_REPOSITORY_INVESTIGATION_MODE",
                "LIMA_REPOSITORY_SCAN_SAST_MODE",
                "LIMA_REPOSITORY_SCAN_LLM_MODE",
                "LIMA_REPOSITORY_SCAN_SOURCES",
                "LIMA_REPOSITORY_IMPORT_ROOT",
                "LIMA_LLM_PROVIDER",
                "LIMA_DEEPSEEK_API_KEY",
            ):
                os.environ.pop(key, None)
        self.assertEqual(task.get("state"), "SUCCESS", task.get("failure"))
        report = task.get("report") or {}
        investigation = (
            report.get("collaboration", {}).get("investigation") or {}
        )
        self.assertIn(investigation.get("status"), {"completed", "no-results"})


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
