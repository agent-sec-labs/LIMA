"""Report-consistency acceptance tests for merge_investigation_into_report.

Supplemental frozen acceptance face for PACKET-265B-REPORT-CONSISTENCY
(task PR265-MERGE-CONSISTENCY-2026-10-04, matrix rows 1-13 plus the
derived-faces checks).  Every defect-regression case drives the REAL
``FindingInvestigator`` chain (production AgentLoop/ToolRegistry/snapshot
tools/validation/scheduling) with a scripted offline client and then the
REAL ``merge_investigation_into_report``; nothing here hand-crafts an
"already accepted" field or monkeypatches the merge.

The sample below is deliberately independent of the frozen test sample
(``svc/*``) and of the B-1 probes (``payroll/dispatch.py``,
``ingest/receive.py``): new packages, new symbols, new source shapes.

Behavior Oracle only (Packet C1-C10 observable faces); no assertion copies
private implementation details of the merge function.
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
    "ledger/__init__.py": "",
    "ledger/posting.py": (
        "from settlement_gateway import submit_batch\n"
        "\n"
        "\n"
        "def post(entries):\n"
        "    return submit_batch(entries)\n"
    ),
    "vault/__init__.py": "",
    "vault/keystore.py": (
        "BILLING_TOKEN = \"sk-live-77e2c4a1f0b3d5e6a7c8\"\n"
        "VAULT_PASSWORD_ENV = \"VAULT_PASSWORD\"\n"
        "CONFIG_LABEL = \"config-label-only\"\n"
    ),
    "vault/unresolved.py": (
        "from scoring_engine import score\n"
        "\n"
        "\n"
        "def grade(record):\n"
        "    return score(record)\n"
    ),
}

LEDGER = "ledger/posting.py"
VAULT_UNRESOLVED = "vault/unresolved.py"
KEYSTORE = "vault/keystore.py"
LEDGER_FP = "module-scope:" + LEDGER
VAULT_UNRESOLVED_FP = "module-scope:" + VAULT_UNRESOLVED


class ScriptedClient(InvestigationLLMClient):
    """Offline stand-in for the chat transport (zero real model calls)."""

    def __init__(self, script, budget_max=100):
        super().__init__(
            base_url="http://offline", api_key="offline-key",
            model="offline-model", provider="scripted-offline",
            budget=InvestigationBudget(max_requests=budget_max),
        )
        self.script = list(script)

    def complete_json(self, *, system: str, user: str):
        self.budget = self.budget.reserve()
        if not self.script:
            raise RuntimeError("script exhausted (offline client)")
        action = self.script.pop(0)
        if isinstance(action, Exception):
            raise action
        return action


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


def module_result(module_path,
                  reasoning="gateway binding unresolved within the snapshot"):
    return result("module-scope:" + module_path, module_path, 0,
                  "insufficient", reasoning=reasoning)


def new_target(path, line, symbol, why, refs):
    return {"path": path, "line": line, "symbol": symbol, "why": why,
            "evidence_refs": refs}


def finding(path, line, rule="SEC-PICKLE", cwe="CWE-502",
            evidence="deserialization of untrusted payload") -> Finding:
    return Finding(
        rule_id=rule, severity=Severity.HIGH, title="candidate",
        explanation="consistency test candidate", path=path, line=line,
        evidence=evidence, fix="", test="", confidence=0.9, cwe=cwe,
        source="python-ast", evidence_kind="ast-call",
        verification_state="syntax-verified",
    )


def prior_decision(item, disposition, **extra):
    decision = {
        "fingerprint": item.fingerprint, "path": item.path,
        "line": item.line, "rule_id": item.rule_id,
        "disposition": disposition, "reason": "semantic-triage-pre-state",
    }
    decision.update(extra)
    return decision


class ReportConsistencyTestCase(unittest.TestCase):
    """Shared arrange helpers: fresh sample, real investigator, real merge."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self._tmp.name) / "repo"
        self.root.mkdir()
        for rel, text in SAMPLE.items():
            path = self.root / pathlib.PurePosixPath(rel)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text, encoding="utf-8")
        self.snapshot = InvestigationSnapshot(self.root)
        self.addCleanup(self._tmp.cleanup)

    def investigator(self, script, *, batch_size=6, budget=100):
        client = ScriptedClient(script, budget_max=budget)
        return FindingInvestigator(
            client, batch_size=batch_size, max_steps=5, timeout_seconds=30,
        )

    def merge_report(self, outcome, findings, *, risk="low", prior=None):
        report = ReviewReport(
            repository="consistency", pull_request=None, summary="old",
            risk=risk, findings=list(findings),
        )
        if prior is not None:
            report.adjudication = prior
        merge_investigation_into_report(report, outcome, findings)
        return report

    def decisions_of(self, report):
        return {
            d["fingerprint"]: d
            for d in report.adjudication["decisions"]
        }

    def discovered(self, report):
        return [f for f in report.findings if f.rule_id == "AGENT-DISCOVERY"]

    # -- scenario runners ------------------------------------------------

    def run_candidate_discovery(self, module_path=LEDGER, line=5,
                                symbol="post"):
        """Zero static findings + real read_source + one legal new target."""
        why = (
            "submit_batch is imported from an unresolved gateway module "
            "and invoked on caller-controlled entries"
        )
        targets = build_module_targets(self.snapshot, [module_path])
        script = [
            tool_action("read_source", path=module_path,
                        start_line=1, end_line=6),
            final(
                [module_result(module_path)],
                new_targets=[new_target(
                    module_path, line, symbol, why,
                    [f"read_source:{module_path}:1-6"],
                )],
            ),
        ]
        outcome = self.investigator(script).investigate(targets, self.snapshot)
        report = self.merge_report(outcome, [])
        return report, outcome

    def run_module_variant(self, variant, module_path=LEDGER):
        """Timeout / budget-exhausted / insufficient / missing final result."""
        targets = build_module_targets(self.snapshot, [module_path])
        budget = 100
        if variant == "timeout":
            script = [TimeoutError("model timeout")]
        elif variant == "budget":
            script, budget = [], 0
        elif variant == "insufficient":
            script = [final([module_result(module_path)])]
        elif variant == "missing":
            script = [final([]), final([])]
        else:  # pragma: no cover - programming error in the table
            raise AssertionError(f"unknown variant {variant!r}")
        outcome = self.investigator(
            script, budget=budget
        ).investigate(targets, self.snapshot)
        report = self.merge_report(outcome, [])
        return report, outcome


class TestDiscoveredCandidates(ReportConsistencyTestCase):
    """Matrix row 1 / AC-01: zero static + read_source + legal new target."""

    def test_observed_new_target_gets_unique_traceable_decision(self):
        report, _ = self.run_candidate_discovery()
        discovered = self.discovered(report)
        self.assertEqual(len(discovered), 1)
        self.assertEqual(discovered[0].verification_state, "candidate")
        decisions = self.decisions_of(report)
        # C1: exactly one decision per accepted candidate (module decision
        # for the scheduled scope + the candidate decision).
        self.assertEqual(len(decisions), 2)
        candidate_fp = discovered[0].fingerprint
        self.assertIn(candidate_fp, decisions)
        decision = decisions[candidate_fp]
        self.assertEqual(decision["disposition"], "needs_review")
        self.assertEqual(
            decision["reason"], "unverified-finding-requires-human-review"
        )
        self.assertEqual(decision["rule_id"], "AGENT-DISCOVERY")
        self.assertEqual(decision["cwe"], "")
        self.assertEqual(decision["path"], discovered[0].path)
        self.assertEqual(decision["line"], discovered[0].line)
        self.assertEqual(decision["verification_state"], "candidate")

    def test_high_candidate_reflected_in_risk_and_not_clear(self):
        report, _ = self.run_candidate_discovery()
        discovered = self.discovered(report)
        self.assertEqual(len(discovered), 1)
        self.assertEqual(discovered[0].severity, Severity.HIGH)
        # C2: an unexcluded HIGH candidate forces risk=high.
        self.assertEqual(report.risk, "high")
        # C4: unknowns can never derive an overall clear.
        self.assertEqual(
            report.adjudication["overall_disposition"], "needs_review"
        )
        self.assertNotEqual(report.adjudication["overall_disposition"], "clear")

    def test_candidate_defaults_needs_review_no_fabricated_supported(self):
        report, _ = self.run_candidate_discovery()
        decisions = self.decisions_of(report)
        self.assertEqual(len(decisions), 2)
        for decision in decisions.values():
            self.assertEqual(decision["disposition"], "needs_review")
            self.assertNotIn("investigation_verdict", decision)
        block = report.collaboration["investigation"]
        self.assertEqual(block["verdict_counts"]["supported"], 0)
        self.assertEqual(block["verdict_counts"]["refuted"], 0)
        faces = report.adjudication["investigation_summary"]
        self.assertEqual(faces["supported"], 0)
        self.assertEqual(faces["new_targets"], 1)

    def test_candidate_decision_preserves_observation_refs_and_state(self):
        report, _ = self.run_candidate_discovery()
        discovered = self.discovered(report)
        decisions = self.decisions_of(report)
        self.assertEqual(len(decisions), 2)
        decision = decisions[discovered[0].fingerprint]
        self.assertEqual(
            decision["investigation_evidence_refs"],
            [f"read_source:{LEDGER}:1-6"],
        )
        self.assertTrue(decision["investigation_evidence_refs"])
        self.assertEqual(decision["verification_state"], "candidate")
        self.assertEqual(decision["path"], LEDGER)
        self.assertEqual(decision["line"], 5)


class TestModuleUnknownFaces(ReportConsistencyTestCase):
    """Matrix rows 2-4 / AC-02..04: module failure/unknown visibility."""

    def test_timeout_variant_presents_unknown_and_preserves_reason(self):
        report, _ = self.run_module_variant("timeout")
        decisions = self.decisions_of(report)
        self.assertEqual(len(decisions), 1)
        decision = decisions[LEDGER_FP]
        self.assertEqual(decision["fingerprint"], LEDGER_FP)
        self.assertEqual(decision["path"], LEDGER)
        self.assertEqual(decision["line"], 0)
        self.assertEqual(decision["rule_id"], "")
        self.assertEqual(decision["cwe"], "")
        self.assertEqual(decision["disposition"], "needs_review")
        self.assertEqual(decision["investigation_status"], "failed")
        self.assertEqual(decision["reason"], "investigation-failed")
        self.assertEqual(
            decision.get("investigation_failure_reason"),
            "batch-error:TimeoutError",
        )
        self.assertNotEqual(decision["disposition"], "alert")
        self.assertNotEqual(decision["disposition"], "clear")
        self.assertNotEqual(
            decision.get("effective_state"), "excluded-from-active-alerts"
        )
        self.assertEqual(
            report.adjudication["overall_disposition"], "needs_review"
        )

    def test_module_failure_never_claims_completed_review(self):
        report, outcome = self.run_module_variant("timeout")
        decisions = self.decisions_of(report)
        self.assertEqual(len(decisions), 1)
        decision = decisions[LEDGER_FP]
        # C7: a failed module is an execution failure, never a completed
        # model review and never a model verdict.
        self.assertEqual(decision["investigation_status"], "failed")
        self.assertNotIn("investigation_verdict", decision)
        block = report.collaboration["investigation"]
        self.assertEqual(
            block["statuses"][LEDGER_FP],
            {"status": "failed", "reason": "batch-error:TimeoutError"},
        )
        self.assertEqual(block["verdict_counts"],
                         {"supported": 0, "refuted": 0, "insufficient": 0})
        self.assertIn(LEDGER_FP, outcome.statuses)

    def test_budget_exhausted_variant_presents_unknown(self):
        report, _ = self.run_module_variant("budget")
        decisions = self.decisions_of(report)
        self.assertEqual(len(decisions), 1)
        decision = decisions[LEDGER_FP]
        self.assertEqual(decision["disposition"], "needs_review")
        self.assertEqual(decision["investigation_status"], "unprocessed")
        self.assertEqual(decision["reason"], "investigation-unprocessed")
        self.assertEqual(
            decision.get("investigation_failure_reason"),
            "request-budget-exhausted",
        )
        self.assertNotIn("investigation_verdict", decision)
        self.assertEqual(
            report.adjudication["overall_disposition"], "needs_review"
        )
        self.assertNotEqual(report.adjudication["overall_disposition"], "clear")

    def test_insufficient_and_missing_result_variants_visible(self):
        variants = {
            "insufficient": "gateway binding unresolved within the snapshot",
            "missing": "model final did not include this fingerprint",
        }
        for variant, expected_reasoning in variants.items():
            with self.subTest(variant=variant):
                report, _ = self.run_module_variant(variant)
                decisions = self.decisions_of(report)
                self.assertEqual(len(decisions), 1)
                decision = decisions[LEDGER_FP]
                self.assertEqual(decision["disposition"], "needs_review")
                self.assertEqual(
                    decision["investigation_status"], "insufficient"
                )
                self.assertEqual(
                    decision["reason"],
                    "investigation-insufficient-evidence",
                )
                # C3: the product's own recorded reasoning survives verbatim.
                self.assertEqual(
                    decision.get("investigation_reasoning"),
                    expected_reasoning,
                )
                self.assertEqual(
                    report.adjudication["overall_disposition"],
                    "needs_review",
                )

    def test_module_results_visible_in_collaboration(self):
        static = finding(KEYSTORE, 1)
        targets = build_module_targets(self.snapshot, [LEDGER])
        targets += build_investigation_targets([static], self.snapshot)
        script = [final([
            module_result(LEDGER),
            result(static.fingerprint, KEYSTORE, 1, "insufficient",
                   reasoning="no decisive evidence either way"),
        ])]
        outcome = self.investigator(script).investigate(targets, self.snapshot)
        report = self.merge_report(outcome, [static])
        block = report.collaboration["investigation"]
        # C3: results carry EVERY completed target (static + module).
        self.assertEqual(
            {r["fingerprint"] for r in block["results"]},
            {LEDGER_FP, static.fingerprint},
        )
        decisions = self.decisions_of(report)
        self.assertEqual(set(decisions), {LEDGER_FP, static.fingerprint})
        self.assertEqual(
            report.adjudication["overall_disposition"], "needs_review"
        )


class TestEmptyAndRejectedPopulations(ReportConsistencyTestCase):
    """Matrix rows 5-6 / AC-05..06: empty sets and rejected claims."""

    def test_all_empty_preserves_no_positive_safety_evidence_guard(self):
        outcome = self.investigator([]).investigate([], self.snapshot)
        report = self.merge_report(outcome, [])
        adjudication = report.adjudication
        # C4: the shared empty-set guard is the derivation path again.
        self.assertEqual(adjudication["overall_disposition"], "needs_review")
        self.assertEqual(
            adjudication["overall_reason"], "no-positive-safety-evidence"
        )
        self.assertEqual(adjudication["decisions"], [])
        self.assertEqual(report.findings, [])
        self.assertEqual(report.risk, "low")
        self.assertEqual(adjudication["counts"],
                         {"alert": 0, "needs_review": 0, "clear": 0})

    def test_unread_or_outside_snapshot_claim_rejected_visible_not_clear(self):
        targets = build_module_targets(self.snapshot, [LEDGER])
        script = [final(
            [module_result(LEDGER)],
            new_targets=[new_target(
                "not/in/snapshot.py", 1, "ghost",
                "claim about code that was never read", [],
            )],
        )]
        outcome = self.investigator(script).investigate(targets, self.snapshot)
        report = self.merge_report(outcome, [])
        # Rejection face: no fabricated finding for an unread path.
        self.assertEqual(self.discovered(report), [])
        self.assertEqual(report.findings, [])
        claims = [
            t for t in outcome.new_targets
            if not str(t.get("binding", "")).startswith("observed")
        ]
        self.assertEqual(len(claims), 1)
        self.assertEqual(
            claims[0]["binding"],
            "unverified-model-claim-no-observed-path",
        )
        block = report.collaboration["investigation"]
        self.assertEqual(block["new_targets"], outcome.new_targets)
        # The scheduled module scope is still an explicit unknown.
        decisions = self.decisions_of(report)
        self.assertEqual(set(decisions), {LEDGER_FP})
        self.assertEqual(
            report.adjudication["overall_disposition"], "needs_review"
        )
        self.assertNotEqual(report.adjudication["overall_disposition"], "clear")

    def test_no_fabricated_findings_for_failures(self):
        report, _ = self.run_module_variant("timeout")
        # A failed module investigation never fabricates a vulnerability
        # Finding; the unknown is carried by a traceable module decision.
        self.assertEqual(report.findings, [])
        self.assertEqual(self.discovered(report), [])
        decisions = self.decisions_of(report)
        self.assertEqual(set(decisions), {LEDGER_FP})
        self.assertEqual(decisions[LEDGER_FP]["disposition"], "needs_review")


class TestPreservedStates(ReportConsistencyTestCase):
    """Matrix rows 7-9 / AC-07..09: compatibility rows, GREEN at baseline."""

    def test_bare_clean_refutation_rejected_alert_kept(self):
        static = finding(KEYSTORE, 1)
        targets = build_investigation_targets([static], self.snapshot)
        script = [final([result(
            static.fingerprint, KEYSTORE, 1, "refuted",
            refs=[f"read_source:{KEYSTORE}"],
        )])]
        outcome = self.investigator(script).investigate(targets, self.snapshot)
        report = self.merge_report(outcome, [static])
        decision = self.decisions_of(report)[static.fingerprint]
        self.assertEqual(decision["disposition"], "alert")
        self.assertEqual(decision["investigation_verdict"], "insufficient")
        self.assertEqual(decision["investigation_status"], "insufficient")
        self.assertEqual(
            decision["reason"], "refutation-rejected-no-observed-evidence"
        )
        self.assertNotEqual(
            decision.get("effective_state"), "excluded-from-active-alerts"
        )
        faces = report.adjudication["investigation_summary"]
        self.assertEqual(faces["active_alerts"], 1)
        self.assertEqual(report.adjudication["counts"]["alert"], 1)
        self.assertEqual(report.adjudication["overall_disposition"], "alert")

    def test_prior_alert_kept_on_failure_with_consistent_counts(self):
        static = finding(KEYSTORE, 1)
        targets = build_investigation_targets([static], self.snapshot)
        variants = {
            "failed": ([RuntimeError("provider down")], 100),
            "unprocessed": ([], 0),
            "insufficient": ([final([result(
                static.fingerprint, KEYSTORE, 1, "insufficient",
                reasoning="no observation supporting either direction",
            )])], 100),
        }
        for variant, (script, budget) in variants.items():
            with self.subTest(variant=variant):
                outcome = self.investigator(
                    script, budget=budget
                ).investigate(targets, self.snapshot)
                report = self.merge_report(outcome, [static])
                decision = self.decisions_of(report)[static.fingerprint]
                self.assertEqual(decision["disposition"], "alert")
                if variant in {"failed", "unprocessed"}:
                    self.assertIn(
                        decision["investigation_status"], {"failed",
                                                           "unprocessed"}
                    )
                    self.assertIn(
                        decision.get("investigation_failure_reason"),
                        {"batch-error:RuntimeError",
                         "request-budget-exhausted"},
                    )
                counts = report.adjudication["counts"]
                self.assertEqual(counts["alert"], 1)
                self.assertEqual(counts["needs_review"], 0)
                faces = report.adjudication["investigation_summary"]
                self.assertEqual(faces["active_alerts"], 1)
                self.assertEqual(
                    report.adjudication["overall_disposition"], "alert"
                )

    def test_prior_needs_review_kept_not_escalated(self):
        static = finding(KEYSTORE, 2)
        prior = finalize_adjudication(
            [prior_decision(static, "needs_review")]
        )
        targets = build_investigation_targets([static], self.snapshot)
        variants = {
            "failed": ([RuntimeError("provider down")], 100),
            "unprocessed": ([], 0),
            "insufficient": ([final([result(
                static.fingerprint, KEYSTORE, 2, "insufficient",
                reasoning="evidence window too narrow",
            )])], 100),
        }
        for variant, (script, budget) in variants.items():
            with self.subTest(variant=variant):
                outcome = self.investigator(
                    script, budget=budget
                ).investigate(targets, self.snapshot)
                report = self.merge_report(outcome, [static], prior=prior)
                decision = self.decisions_of(report)[static.fingerprint]
                self.assertEqual(decision["disposition"], "needs_review")
                self.assertNotEqual(decision["disposition"], "alert")
                self.assertNotEqual(decision["disposition"], "clear")
                self.assertNotEqual(
                    decision.get("effective_state"),
                    "excluded-from-active-alerts",
                )
                counts = report.adjudication["counts"]
                self.assertEqual(counts["needs_review"], 1)
                self.assertEqual(counts["alert"], 0)
                self.assertEqual(
                    report.adjudication["overall_disposition"], "needs_review"
                )


class TestMixedAggregation(ReportConsistencyTestCase):
    """Matrix rows 10-11 / AC-10..11: mixed populations stay consistent."""

    def test_supported_plus_candidate_plus_failed_module_consistent(self):
        static = finding(KEYSTORE, 1)
        targets = build_module_targets(
            self.snapshot, [LEDGER, VAULT_UNRESOLVED]
        )
        targets += build_investigation_targets([static], self.snapshot)
        why = (
            "score is imported from an unresolved engine module and "
            "invoked on caller-controlled records"
        )
        script = [
            TimeoutError("model timeout"),
            tool_action("read_source", path=VAULT_UNRESOLVED,
                        start_line=1, end_line=6),
            final(
                [module_result(VAULT_UNRESOLVED,
                               reasoning="scoring binding unresolved")],
                new_targets=[new_target(
                    VAULT_UNRESOLVED, 5, "grade", why,
                    [f"read_source:{VAULT_UNRESOLVED}:1-6"],
                )],
            ),
            tool_action("read_source", path=KEYSTORE,
                        start_line=1, end_line=4),
            final([result(
                static.fingerprint, KEYSTORE, 1, "supported",
                refs=[f"read_source:{KEYSTORE}:1-4"],
            )]),
        ]
        outcome = self.investigator(script, batch_size=1).investigate(
            targets, self.snapshot
        )
        report = self.merge_report(outcome, [static])
        decisions = self.decisions_of(report)
        discovered = self.discovered(report)
        self.assertEqual(len(discovered), 1)
        expected_ids = {
            static.fingerprint, LEDGER_FP, VAULT_UNRESOLVED_FP,
            discovered[0].fingerprint,
        }
        self.assertEqual(set(decisions), expected_ids)
        # Supported stays an active alert whatever else happened.
        self.assertEqual(decisions[static.fingerprint]["disposition"], "alert")
        self.assertEqual(
            decisions[static.fingerprint]["investigation_verdict"],
            "supported",
        )
        # The failed module keeps its verbatim failure reason.
        self.assertEqual(
            decisions[LEDGER_FP].get("investigation_failure_reason"),
            "batch-error:TimeoutError",
        )
        # The candidate defaults to needs_review, never fabricated supported.
        candidate = decisions[discovered[0].fingerprint]
        self.assertEqual(candidate["disposition"], "needs_review")
        self.assertNotIn("investigation_verdict", candidate)
        counts = report.adjudication["counts"]
        self.assertEqual(counts, {"alert": 1, "needs_review": 3, "clear": 0})
        faces = report.adjudication["investigation_summary"]
        self.assertEqual(faces["supported"], 1)
        self.assertEqual(faces["active_alerts"], 1)
        self.assertEqual(faces["new_targets"], 1)
        self.assertEqual(report.adjudication["overall_disposition"], "alert")
        self.assertEqual(report.risk, "high")
        self.assertIn("pending", report.summary.lower())

    def test_refuted_history_high_not_recounted_while_pending_candidate_raises_risk(self):
        history = finding(KEYSTORE, 1)
        # Scenario 1: the history HIGH is refuted with observed evidence and
        # excluded; nothing else carries risk, so incoming risk is kept.
        targets = build_investigation_targets([history], self.snapshot)
        script = [
            tool_action("read_source", path=KEYSTORE,
                        start_line=1, end_line=4),
            final([result(
                history.fingerprint, KEYSTORE, 1, "refuted",
                refs=[f"read_source:{KEYSTORE}:1-4"],
            )]),
        ]
        outcome = self.investigator(script).investigate(targets, self.snapshot)
        report = self.merge_report(outcome, [history])
        decision = self.decisions_of(report)[history.fingerprint]
        self.assertEqual(decision["investigation_verdict"], "refuted")
        self.assertEqual(
            decision.get("effective_state"), "excluded-from-active-alerts"
        )
        self.assertEqual(report.risk, "low")
        self.assertEqual(
            report.collaboration["investigation"]["verdict_counts"]["refuted"],
            1,
        )
        # Scenario 2: same refuted history plus a pending HIGH candidate --
        # the excluded HIGH must not be recounted, the pending one must
        # raise the risk and stay visible.
        module_targets = build_module_targets(self.snapshot, [LEDGER])
        why = (
            "submit_batch is imported from an unresolved gateway module "
            "and invoked on caller-controlled entries"
        )
        script2 = [
            tool_action("read_source", path=LEDGER,
                        start_line=1, end_line=6),
            final(
                [module_result(LEDGER)],
                new_targets=[new_target(
                    LEDGER, 5, "post", why,
                    [f"read_source:{LEDGER}:1-6"],
                )],
            ),
            tool_action("read_source", path=KEYSTORE,
                        start_line=1, end_line=4),
            final([result(
                history.fingerprint, KEYSTORE, 1, "refuted",
                refs=[f"read_source:{KEYSTORE}:1-4"],
            )]),
        ]
        targets2 = module_targets + build_investigation_targets(
            [history], self.snapshot
        )
        outcome2 = self.investigator(script2, batch_size=1).investigate(
            targets2, self.snapshot
        )
        report2 = self.merge_report(outcome2, [history])
        decisions2 = self.decisions_of(report2)
        discovered2 = self.discovered(report2)
        self.assertEqual(len(discovered2), 1)
        self.assertEqual(len(decisions2), 3)
        history2 = decisions2[history.fingerprint]
        self.assertEqual(history2["investigation_verdict"], "refuted")
        self.assertEqual(
            history2.get("effective_state"), "excluded-from-active-alerts"
        )
        self.assertEqual(report2.risk, "high")
        counts2 = report2.adjudication["counts"]
        self.assertEqual(counts2, {"alert": 0, "needs_review": 3, "clear": 0})


class TestIdentityAndRepeatMerge(ReportConsistencyTestCase):
    """Matrix rows 12-13 / AC-12..13: coverage, identity and idempotence."""

    def test_module_batch_smaller_than_targets_full_coverage_or_explicit_unprocessed(self):
        with self.subTest(population="static-full-coverage"):
            findings = [finding(KEYSTORE, line) for line in (1, 2, 3)]
            targets = build_investigation_targets(findings, self.snapshot)
            script = [
                final([result(
                    f.fingerprint, KEYSTORE, f.line, "insufficient",
                    reasoning="no decisive evidence either way",
                ) for f in findings[:2]]),
                final([result(
                    findings[2].fingerprint, KEYSTORE, findings[2].line,
                    "insufficient",
                    reasoning="no decisive evidence either way",
                )]),
            ]
            outcome = self.investigator(
                script, batch_size=2
            ).investigate(targets, self.snapshot)
            report = self.merge_report(outcome, findings)
            decisions = self.decisions_of(report)
            self.assertEqual(set(decisions),
                             {f.fingerprint for f in findings})
            self.assertEqual(
                report.adjudication["counts"]["alert"], 3
            )
        with self.subTest(population="modules-explicit-unprocessed"):
            targets = build_module_targets(
                self.snapshot, [LEDGER, VAULT_UNRESOLVED]
            )
            script = [final([module_result(LEDGER)])]
            outcome = self.investigator(
                script, batch_size=1, budget=1
            ).investigate(targets, self.snapshot)
            report = self.merge_report(outcome, [])
            decisions = self.decisions_of(report)
            self.assertEqual(set(decisions), {LEDGER_FP, VAULT_UNRESOLVED_FP})
            unprocessed = decisions[VAULT_UNRESOLVED_FP]
            self.assertEqual(
                unprocessed["investigation_status"], "unprocessed"
            )
            self.assertEqual(
                unprocessed.get("investigation_failure_reason"),
                "request-budget-exhausted",
            )
            self.assertEqual(
                decisions[LEDGER_FP]["investigation_status"], "insufficient"
            )
            self.assertEqual(
                report.adjudication["overall_disposition"], "needs_review"
            )

    def test_duplicate_new_targets_collapse_to_single_identity(self):
        targets = build_module_targets(self.snapshot, [LEDGER])
        claim = new_target(
            LEDGER, 5, "post",
            "submit_batch invoked on caller-controlled entries",
            [f"read_source:{LEDGER}:1-6"],
        )
        script = [
            tool_action("read_source", path=LEDGER,
                        start_line=1, end_line=6),
            final([module_result(LEDGER)], new_targets=[claim, dict(claim)]),
        ]
        outcome = self.investigator(script).investigate(targets, self.snapshot)
        report = self.merge_report(outcome, [])
        discovered = self.discovered(report)
        self.assertEqual(len(discovered), 1)
        fingerprints = [f.fingerprint for f in discovered]
        self.assertEqual(len(set(fingerprints)), len(fingerprints))
        decisions = self.decisions_of(report)
        self.assertIn(discovered[0].fingerprint, decisions)
        self.assertEqual(len(decisions), 2)

    def test_remerge_same_outcome_idempotent(self):
        # run_candidate_discovery already performed the first merge.
        report, outcome = self.run_candidate_discovery()
        first_faces = (
            len(self.discovered(report)),
            frozenset(self.decisions_of(report)),
            dict(report.adjudication["counts"]),
            report.adjudication["overall_disposition"],
            report.risk,
            report.summary,
        )
        merge_investigation_into_report(report, outcome, [])
        self.assertEqual(len(self.discovered(report)), first_faces[0])
        self.assertEqual(frozenset(self.decisions_of(report)), first_faces[1])
        self.assertEqual(report.adjudication["counts"], first_faces[2])
        self.assertEqual(
            report.adjudication["overall_disposition"], first_faces[3]
        )
        self.assertEqual(report.risk, first_faces[4])
        self.assertEqual(report.summary, first_faces[5])

    def test_new_targets_order_change_stable_set_and_counts(self):
        claims = {
            LEDGER: new_target(
                LEDGER, 5, "post",
                "submit_batch invoked on caller-controlled entries",
                [f"read_source:{LEDGER}:1-6"],
            ),
            VAULT_UNRESOLVED: new_target(
                VAULT_UNRESOLVED, 5, "grade",
                "score invoked on caller-controlled records",
                [f"read_source:{VAULT_UNRESOLVED}:1-6"],
            ),
        }

        def run(order):
            targets = build_module_targets(
                self.snapshot, [LEDGER, VAULT_UNRESOLVED]
            )
            script = [
                tool_action("read_source", path=LEDGER,
                            start_line=1, end_line=6),
                tool_action("read_source", path=VAULT_UNRESOLVED,
                            start_line=1, end_line=6),
                final(
                    [module_result(LEDGER),
                     module_result(VAULT_UNRESOLVED)],
                    new_targets=order,
                ),
            ]
            outcome = self.investigator(script).investigate(
                targets, self.snapshot
            )
            return self.merge_report(outcome, [])

        report_a = run([claims[LEDGER], claims[VAULT_UNRESOLVED]])
        report_b = run([claims[VAULT_UNRESOLVED], claims[LEDGER]])
        decisions_a = self.decisions_of(report_a)
        self.assertEqual(len(decisions_a), 4)
        self.assertEqual(frozenset(decisions_a),
                         frozenset(self.decisions_of(report_b)))
        self.assertEqual(report_a.adjudication["counts"],
                         report_b.adjudication["counts"])
        self.assertEqual(
            report_a.adjudication["overall_disposition"],
            report_b.adjudication["overall_disposition"],
        )
        self.assertEqual(report_a.risk, report_b.risk)
        self.assertEqual(
            [f.fingerprint for f in report_a.findings].count(
                self.discovered(report_a)[0].fingerprint
            ),
            1,
        )

    def test_remerge_does_not_dilute_stronger_conclusion(self):
        static = finding(KEYSTORE, 1)
        targets = build_module_targets(self.snapshot, [LEDGER])
        targets += build_investigation_targets([static], self.snapshot)
        why = (
            "submit_batch is imported from an unresolved gateway module "
            "and invoked on caller-controlled entries"
        )
        script = [
            tool_action("read_source", path=LEDGER,
                        start_line=1, end_line=6),
            final(
                [module_result(LEDGER)],
                new_targets=[new_target(
                    LEDGER, 5, "post", why,
                    [f"read_source:{LEDGER}:1-6"],
                )],
            ),
            tool_action("read_source", path=KEYSTORE,
                        start_line=1, end_line=4),
            final([result(
                static.fingerprint, KEYSTORE, 1, "supported",
                refs=[f"read_source:{KEYSTORE}:1-4"],
            )]),
        ]
        outcome = self.investigator(script, batch_size=1).investigate(
            targets, self.snapshot
        )
        report = self.merge_report(outcome, [static], risk="medium")
        merge_investigation_into_report(report, outcome, [static])
        decisions = self.decisions_of(report)
        self.assertEqual(len(decisions), 3)
        # The stronger conclusion survives the remerge undiluted.
        supported = decisions[static.fingerprint]
        self.assertEqual(supported["disposition"], "alert")
        self.assertEqual(supported["investigation_verdict"], "supported")
        counts = report.adjudication["counts"]
        self.assertEqual(counts, {"alert": 1, "needs_review": 2, "clear": 0})
        self.assertEqual(len(self.discovered(report)), 1)
        self.assertEqual(report.adjudication["overall_disposition"], "alert")


class TestDerivedFacesAgreement(ReportConsistencyTestCase):
    """Derived faces: counts / active_alerts / summary / serialization /
    execution_counts (Packet C5-C8, C10)."""

    def run_candidate_and_failed_module(self):
        """One pending HIGH candidate plus one failed module scope."""
        targets = build_module_targets(
            self.snapshot, [LEDGER, VAULT_UNRESOLVED]
        )
        why = (
            "score is imported from an unresolved engine module and "
            "invoked on caller-controlled records"
        )
        script = [
            TimeoutError("model timeout"),
            tool_action("read_source", path=VAULT_UNRESOLVED,
                        start_line=1, end_line=6),
            final(
                [module_result(VAULT_UNRESOLVED,
                               reasoning="scoring binding unresolved")],
                new_targets=[new_target(
                    VAULT_UNRESOLVED, 5, "grade", why,
                    [f"read_source:{VAULT_UNRESOLVED}:1-6"],
                )],
            ),
        ]
        outcome = self.investigator(script, batch_size=1).investigate(
            targets, self.snapshot
        )
        report = self.merge_report(outcome, [])
        return report, outcome

    def test_counts_conserved_with_unique_decisions_including_legitimate_clear(self):
        static = finding(KEYSTORE, 2)
        prior = finalize_adjudication([prior_decision(
            static, "clear",
            reason="mitigation-invariant-and-llm-agree",
            invariant_statuses=["mitigation"],
            llm_is_vulnerable=False,
        )])
        targets = build_investigation_targets([static], self.snapshot)
        script = [final([result(
            static.fingerprint, KEYSTORE, 2, "insufficient",
            reasoning="mitigation invariant unchanged; nothing contradicted",
        )])]
        outcome = self.investigator(script).investigate(targets, self.snapshot)
        report = self.merge_report(outcome, [static], prior=prior)
        decisions = self.decisions_of(report)
        self.assertEqual(len(decisions), 1)
        counts = report.adjudication["counts"]
        # C5: a legitimate prior clear kept by an insufficient verdict must
        # still count as clear -- no "total minus alerts" arithmetic.
        self.assertEqual(counts, {"alert": 0, "needs_review": 0, "clear": 1})
        self.assertEqual(sum(counts.values()), len(decisions))
        self.assertEqual(decisions[static.fingerprint]["disposition"], "clear")
        self.assertEqual(
            report.adjudication["overall_disposition"], "clear"
        )
        self.assertEqual(
            report.adjudication["overall_reason"],
            "all-items-have-agreeing-safety-evidence",
        )
        block = report.collaboration["investigation"]
        self.assertEqual(block["verdict_counts"]["insufficient"], 1)
        self.assertEqual(
            report.adjudication["investigation_summary"]["insufficient"], 1
        )

    def test_active_alerts_matches_effective_disposition(self):
        first = finding(KEYSTORE, 1)
        second = finding(KEYSTORE, 2)
        targets = build_investigation_targets([first, second], self.snapshot)
        script = [
            tool_action("read_source", path=KEYSTORE,
                        start_line=1, end_line=4),
            final([
                result(first.fingerprint, KEYSTORE, 1, "supported",
                       refs=[f"read_source:{KEYSTORE}:1-4"]),
                result(second.fingerprint, KEYSTORE, 2, "insufficient",
                       reasoning="no decisive evidence either way"),
            ]),
        ]
        outcome = self.investigator(script).investigate(targets, self.snapshot)
        with self.subTest(population="with-alerts"):
            report = self.merge_report(outcome, [first, second])
            decisions = self.decisions_of(report)
            alerts = sum(
                1 for d in decisions.values() if d["disposition"] == "alert"
            )
            faces = report.adjudication["investigation_summary"]
            self.assertEqual(faces["active_alerts"], alerts)
            self.assertEqual(report.adjudication["counts"]["alert"], alerts)
            self.assertEqual(
                faces["active_alerts"] > 0,
                report.adjudication["overall_disposition"] == "alert",
            )
        with self.subTest(population="without-alerts"):
            report2, _ = self.run_module_variant("timeout")
            faces2 = report2.adjudication["investigation_summary"]
            self.assertEqual(faces2["active_alerts"], 0)
            self.assertEqual(report2.adjudication["counts"]["alert"], 0)
            self.assertEqual(
                faces2["active_alerts"] > 0,
                report2.adjudication["overall_disposition"] == "alert",
            )

    def test_summary_matches_data_and_no_clear_claim_when_not_clear(self):
        report, outcome = self.run_candidate_and_failed_module()
        candidate_count = len(
            [t for t in outcome.new_targets
             if str(t.get("binding", "")).startswith("observed")]
        )
        module_unknown = len(
            [fp for fp, status in outcome.statuses.items()
             if status.get("status") != "completed"]
        )
        self.assertEqual(candidate_count, 1)
        self.assertEqual(module_unknown, 1)
        lowered = report.summary.lower()
        # C8 frozen markers: pending candidates must read as pending.
        self.assertIn("pending", lowered)
        self.assertIn(str(candidate_count), report.summary)
        # Module unknowns must be named as unknown-ish.
        self.assertTrue(
            any(marker in lowered for marker in
                ("unknown", "unresolved", "failed", "unprocessed"))
        )
        self.assertIn(str(module_unknown), report.summary)
        # Data not clear -> the text must not claim an all-clear.
        for phrase in ("no issues", "all clear", "no security issues"):
            self.assertNotIn(phrase, lowered)
        self.assertNotEqual(
            report.adjudication["overall_disposition"], "clear"
        )

    def test_serialized_json_matches_in_memory_faces(self):
        report, _ = self.run_candidate_and_failed_module()
        document = report.to_dict()
        self.assertEqual(document["adjudication"], report.adjudication)
        self.assertEqual(document["collaboration"], report.collaboration)
        self.assertEqual(document["summary"], report.summary)
        self.assertEqual(document["risk"], report.risk)
        round_trip = json.loads(json.dumps(document, ensure_ascii=False))
        self.assertEqual(round_trip["adjudication"], report.adjudication)
        self.assertEqual(round_trip["collaboration"], report.collaboration)
        self.assertEqual(round_trip["summary"], report.summary)
        self.assertEqual(round_trip["risk"], report.risk)

    def test_execution_counts_separate_from_verdicts(self):
        static = finding(KEYSTORE, 1)
        targets = build_module_targets(self.snapshot, [LEDGER])
        targets += build_investigation_targets([static], self.snapshot)
        script = [
            TimeoutError("model timeout"),
            tool_action("read_source", path=KEYSTORE,
                        start_line=1, end_line=4),
            final([result(
                static.fingerprint, KEYSTORE, 1, "insufficient",
                reasoning="no decisive evidence either way",
            )]),
        ]
        outcome = self.investigator(script, batch_size=1).investigate(
            targets, self.snapshot
        )
        report = self.merge_report(outcome, [static])
        block = report.collaboration["investigation"]
        # C7: execution state is a separate, explicit dimension.
        self.assertIn("execution_counts", block)
        self.assertEqual(
            block["execution_counts"],
            {"completed": 1, "failed": 1, "unprocessed": 0},
        )
        self.assertEqual(
            set(block["execution_counts"]),
            {"completed", "failed", "unprocessed"},
        )
        # Verdict vocabulary stays verdict-only and static-only.
        self.assertEqual(
            block["verdict_counts"],
            {"supported": 0, "refuted": 0, "insufficient": 1},
        )
        self.assertNotIn("failed", block["verdict_counts"])
        faces = report.adjudication["investigation_summary"]
        self.assertEqual(
            faces["insufficient"], block["verdict_counts"]["insufficient"]
        )


class TestVerdictCountsCompatibility(ReportConsistencyTestCase):
    """C7 compatibility: verdict_counts keeps its static-population meaning."""

    def test_verdict_counts_meaning_unchanged_for_static_population(self):
        findings = [finding(KEYSTORE, line) for line in (1, 2, 3)]
        targets = build_investigation_targets(findings, self.snapshot)
        script = [
            tool_action("read_source", path=KEYSTORE,
                        start_line=1, end_line=4),
            final([
                result(findings[0].fingerprint, KEYSTORE, 1, "supported",
                       refs=[f"read_source:{KEYSTORE}:1-4"]),
                result(findings[1].fingerprint, KEYSTORE, 2, "refuted",
                       refs=[f"read_source:{KEYSTORE}:1-4"]),
                result(findings[2].fingerprint, KEYSTORE, 3, "insufficient",
                       reasoning="no decisive evidence either way"),
            ]),
        ]
        outcome = self.investigator(script).investigate(targets, self.snapshot)
        report = self.merge_report(outcome, findings)
        block = report.collaboration["investigation"]
        self.assertEqual(
            block["verdict_counts"],
            {"supported": 1, "refuted": 1, "insufficient": 1},
        )
        faces = report.adjudication["investigation_summary"]
        self.assertEqual(faces["supported"], 1)
        self.assertEqual(faces["refuted"], 1)
        self.assertEqual(faces["insufficient"], 1)
        self.assertEqual(faces["active_alerts"], 2)
        self.assertEqual(report.adjudication["counts"]["alert"], 2)
        self.assertEqual(report.adjudication["overall_disposition"], "alert")

    def test_verdict_counts_excludes_module_and_candidate_populations(self):
        static = finding(KEYSTORE, 1)
        targets = build_module_targets(
            self.snapshot, [LEDGER, VAULT_UNRESOLVED]
        )
        targets += build_investigation_targets([static], self.snapshot)
        why = (
            "submit_batch is imported from an unresolved gateway module "
            "and invoked on caller-controlled entries"
        )
        script = [
            tool_action("read_source", path=LEDGER,
                        start_line=1, end_line=6),
            final(
                [module_result(LEDGER)],
                new_targets=[new_target(
                    LEDGER, 5, "post", why,
                    [f"read_source:{LEDGER}:1-6"],
                )],
            ),
            final([module_result(
                VAULT_UNRESOLVED,
                reasoning="scoring binding unresolved within the snapshot",
            )]),
            final([result(
                static.fingerprint, KEYSTORE, 1, "insufficient",
                reasoning="no decisive evidence either way",
            )]),
        ]
        outcome = self.investigator(script, batch_size=1).investigate(
            targets, self.snapshot
        )
        report = self.merge_report(outcome, [static])
        decisions = self.decisions_of(report)
        discovered = self.discovered(report)
        self.assertEqual(len(discovered), 1)
        # Module and candidate populations exist as decisions...
        self.assertEqual(
            set(decisions),
            {static.fingerprint, LEDGER_FP, VAULT_UNRESOLVED_FP,
             discovered[0].fingerprint},
        )
        self.assertEqual(
            decisions[VAULT_UNRESOLVED_FP]["investigation_status"],
            "insufficient",
        )
        # ...but never enter verdict_counts (static basis, C7).
        block = report.collaboration["investigation"]
        self.assertEqual(
            block["verdict_counts"],
            {"supported": 0, "refuted": 0, "insufficient": 1},
        )
        faces = report.adjudication["investigation_summary"]
        self.assertEqual(
            faces["insufficient"], block["verdict_counts"]["insufficient"]
        )


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
