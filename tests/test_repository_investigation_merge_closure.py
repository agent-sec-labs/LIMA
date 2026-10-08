"""Closure acceptance tests for merge_investigation_into_report (PR265 cycle I).

Frozen acceptance face for PACKET-265C-CLOSURE-ADDENDUM v0.1 (task
PR265-STAGE-A-CLOSURE-2026-10-05, matrix rows 1-9 plus the derived
fingerprint-formula check; clauses CA-1..CA-8 over the inherited C1-C10
face).  Two defects are pinned here:

* R-01 -- a repeated identical legal claim (same path/line/evidence_refs,
  hence the same fingerprint) materializes more than one decision and
  inflates the derived counts/new-target faces.
* R-02 -- the production alias call shape (``findings=report.findings``)
  miscounts the static population on the first merge and drifts the whole
  report face on a re-merge of the same outcome.

Raw-list rule (addendum section 5): every uniqueness verdict starts from
the RAW ``adjudication["decisions"]`` list (``len(raw) ==
len({fingerprints})`` and per-fingerprint ``Counter`` == 1) BEFORE any
dict/set conversion.  The legacy dict-by-fingerprint helper shape is
never used as a uniqueness proof here; it is only ever used, in raw
order, as a field lookup for already-uniquely-identified decisions.

Transport honesty: zero real model calls.  Unit cases subclass
``InvestigationLLMClient`` with a scripted ``complete_json``; the single
service-chain case (approved single-file organization,
COORD-RULING-C1-ADDENDUM_v1 section 4) patches
``lima.reviewer.post_chat_completion_full`` BEFORE ``ReviewService``
construction, so the production client binds the fake as its transport.
``merge_investigation_into_report``, ``FindingInvestigator``,
``ReviewService``, the queue worker and the store are the real F3
implementations throughout; nothing is monkeypatched at the merge layer.

Sample independence: ``foundry/*`` and ``press/*`` (unit) and
``lumber/sawmill.py`` (service chain) are fresh for this closure round --
distinct from every earlier round's samples (``svc/*``,
``payroll/dispatch.py``, ``ingest/receive.py``, ``orchard|tannery|depot``,
``greenhouse/``, ``harbor/gateway.py`` and the frozen-test samples
``ledger|vault|fleet``) and from the cycle-I reproduction samples
(``observatory/``, ``kiln/``).
"""

import hashlib
import json
import os
import pathlib
import re
import shutil
import sys
import tempfile
import time
import unittest
from collections import Counter
from unittest import mock

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

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

UNIT_SAMPLE = {
    "foundry/__init__.py": "",
    "foundry/casting.py": (
        "from alloy.supply import pour_mold\n"
        "\n"
        "\n"
        "class Ladle:\n"
        "    def mold_spin(self, batch):\n"
        "        return pour_mold(batch)\n"
        "\n"
        "\n"
        "def pour(stock):\n"
        "    return pour_mold(stock)\n"
    ),
    "foundry/core.py": (
        "import alloy.supply as supply\n"
        "\n"
        "\n"
        "def preheat(mold):\n"
        "    return supply.preheat(mold)\n"
    ),
    "foundry/flux.py": (
        "FLUX_TOKEN = \"sk-live-9f31c7a2b5e4d8c6f0a1\"\n"
        "FLUX_PASSWORD_ENV = \"FLUX_PASSWORD\"\n"
    ),
    "press/__init__.py": "",
    "press/rolling.py": (
        "import gauge.feed as feed\n"
        "\n"
        "\n"
        "def feed_sheet(sheet):\n"
        "    return feed(sheet)\n"
    ),
}

SERVICE_SAMPLE = {
    "lumber/__init__.py": "",
    "lumber/sawmill.py": (
        "from conveyor.timber import feed_board\n"
        "\n"
        "\n"
        "def rip(board):\n"
        "    return feed_board(board)\n"
    ),
}

CASTING = "foundry/casting.py"
CASTING_CLAIM_LINE = 6
CASTING_WHY = (
    "pour_mold is imported from an unresolved alloy module and invoked on "
    "caller-controlled batches"
)
CORE = "foundry/core.py"
FLUX = "foundry/flux.py"
FLUX_HISTORY_EVIDENCE = "hardcoded token literal assigned at module scope"
FLUX_PRIOR_EVIDENCE = "credential routed through environment indirection"
ROLLING = "press/rolling.py"
ROLLING_CLAIM_LINE = 5
ROLLING_WHY = (
    "feed is imported from an unresolved gauge module and invoked on "
    "caller-controlled sheets"
)
SAWMILL = "lumber/sawmill.py"
SAWMILL_CLAIM_LINE = 5
SAWMILL_WHY = (
    "feed_board is imported from an unresolved conveyor module and invoked "
    "on caller-controlled boards"
)

MODULE_REASONING = {
    CASTING: "alloy supply binding unresolved within the snapshot",
    CORE: "alloy preheat binding unresolved within the snapshot",
    ROLLING: "gauge feed binding unresolved within the snapshot",
    SAWMILL: "conveyor timber binding unresolved within the snapshot",
}

STATIC_COUNT_RE = re.compile(r"Investigation reviewed (\d+) static candidates")
PENDING_COUNT_RE = re.compile(r"(\d+) pending agent-discovered target")

ENV_KEYS = (
    "LIMA_DB_PATH",
    "LIMA_REPOSITORY_CACHE_ROOT",
    "LIMA_REPOSITORY_INVESTIGATION_MODE",
    "LIMA_LLM_PROVIDER",
    "LIMA_DEEPSEEK_API_KEY",
    "LIMA_REPOSITORY_SCAN_SAST_MODE",
    "LIMA_REPOSITORY_SCAN_LLM_MODE",
    "LIMA_REPOSITORY_SCAN_SOURCES",
    "LIMA_REPOSITORY_IMPORT_ROOT",
)

ENV_VALUES = {
    "LIMA_REPOSITORY_INVESTIGATION_MODE": "auto",
    "LIMA_LLM_PROVIDER": "deepseek",
    "LIMA_DEEPSEEK_API_KEY": "test-key",
    "LIMA_REPOSITORY_SCAN_SAST_MODE": "off",
    "LIMA_REPOSITORY_SCAN_LLM_MODE": "off",
    "LIMA_REPOSITORY_SCAN_SOURCES": "local-import",
}


def tool_action(tool, **arguments):
    return {"action": "tool", "tool": tool, "arguments": arguments,
            "reason": "missing evidence"}


def final_action(results, new_targets=None):
    return {
        "action": "final", "results": results,
        "new_targets": new_targets or [],
    }


def result(fp, path, line, verdict, refs=None, reasoning="model reasoning"):
    return {
        "fingerprint": fp, "path": path, "line": line, "verdict": verdict,
        "reasoning": reasoning, "evidence_refs": refs or [],
        "evidence_basis": {
            "syntax_hit": True, "model_reasoning": True,
            "dynamic_observation": False,
        },
        "confidence": 0.9,
    }


def module_result(module_path):
    return result("module-scope:" + module_path, module_path, 0,
                  "insufficient", reasoning=MODULE_REASONING[module_path])


def new_target(path, line, symbol, why, refs):
    return {"path": path, "line": line, "symbol": symbol, "why": why,
            "evidence_refs": refs}


def casting_claim():
    return new_target(CASTING, CASTING_CLAIM_LINE, "mold_spin", CASTING_WHY,
                      [f"read_source:{CASTING}:1-{CASTING_CLAIM_LINE}"])


def rolling_claim():
    return new_target(ROLLING, ROLLING_CLAIM_LINE, "feed_sheet", ROLLING_WHY,
                      [f"read_source:{ROLLING}:1-{ROLLING_CLAIM_LINE}"])


def static_finding(path, line, evidence):
    return Finding(
        rule_id="SEC-TAINT-SINK", severity=Severity.HIGH,
        title="closure static candidate",
        explanation="closure mixed-population static finding",
        path=path, line=line, evidence=evidence, fix="", test="",
        confidence=0.9, cwe="CWE-89", source="python-ast",
        evidence_kind="ast-assign", verification_state="syntax-verified",
    )


def claim_fingerprint(path, line, refs):
    """The frozen candidate identity formula (CA-3, current formula)."""
    evidence = " | ".join(refs)[:2000]
    material = f"AGENT-DISCOVERY\0{path}\0{line}\0{evidence}"
    return hashlib.sha256(material.encode("utf-8")).hexdigest()[:24]


class ScriptedClient(InvestigationLLMClient):
    """Offline stand-in for the chat client (zero real model calls)."""

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


class ScriptedTransport:
    """Offline stand-in for the shared chat-completions transport.

    No network I/O ever happens: real external model calls are zero by
    construction while the production client/loop/tools keep running.
    """

    def __init__(self, script):
        self.script = list(script)
        self.calls = []

    def __call__(self, provider, base_url, api_key, payload, timeout,
                 extra_headers=None, max_bytes=None):
        self.calls.append({
            "provider": provider, "model": payload.get("model"),
            "messages": len(payload.get("messages") or []),
        })
        if not self.script:
            raise RuntimeError("script exhausted (offline transport)")
        action = self.script.pop(0)
        if isinstance(action, Exception):
            raise action
        return {
            "content": json.dumps(action),
            "usage": {"prompt_tokens": 10, "completion_tokens": 10,
                      "total_tokens": 20},
            "finish_reason": "stop",
        }


def service_duplicate_claim_script():
    """Module review that reads real source then reports one legal target
    twice -- the production duplicate-claim shape for the service chain."""
    claim = new_target(SAWMILL, SAWMILL_CLAIM_LINE, "rip", SAWMILL_WHY,
                       [f"read_source:{SAWMILL}:1-{SAWMILL_CLAIM_LINE}"])
    return [
        tool_action("read_source", path=SAWMILL, start_line=1,
                    end_line=SAWMILL_CLAIM_LINE),
        final_action(
            [module_result(SAWMILL)],
            new_targets=[dict(claim), dict(claim)],
        ),
    ]


class MergeClosureTestCase(unittest.TestCase):
    """Shared arrange: fresh sample, real investigator, real merge.

    Both merge call shapes are first-class here (addendum CA-6): the fixed
    static-list shape and the production alias shape
    ``findings=report.findings`` (the list the merge itself appends to).
    """

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = pathlib.Path(self._tmp.name) / "repo"
        for rel, text in UNIT_SAMPLE.items():
            path = self.root / pathlib.PurePosixPath(rel)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text, encoding="utf-8")
        self.snapshot = InvestigationSnapshot(self.root)

    def investigator(self, script, *, batch_size=6, budget=100):
        return FindingInvestigator(
            ScriptedClient(script, budget_max=budget),
            batch_size=batch_size, max_steps=5, timeout_seconds=30,
        )

    def fresh_report(self, findings=()):
        return ReviewReport(
            repository="closure", pull_request=None, summary="before",
            risk="low", findings=list(findings),
        )

    def merge_fixed(self, outcome):
        """Fixed-list shape: the static population is a private empty list."""
        report = self.fresh_report()
        merge_investigation_into_report(report, outcome, [])
        return report

    def merge_alias(self, outcome, findings=()):
        """Production shape: the argument IS the report's own findings list."""
        report = self.fresh_report(findings)
        merge_investigation_into_report(report, outcome, report.findings)
        return report

    # -- raw-list face (addendum section 5: raw checks come first) --------

    def raw_decisions(self, report):
        return list(report.adjudication["decisions"])

    def raw_fingerprint_counts(self, report):
        return Counter(
            d["fingerprint"] for d in self.raw_decisions(report)
        )

    def assert_raw_list_unique(self, report):
        raw = self.raw_decisions(report)
        self.assertEqual(len(raw), len({d["fingerprint"] for d in raw}))
        self.assertTrue(all(
            count == 1 for count in self.raw_fingerprint_counts(report).values()
        ))

    def decision_of(self, report, fingerprint):
        """Field lookup in raw order only -- never a uniqueness proof."""
        for decision in self.raw_decisions(report):
            if decision["fingerprint"] == fingerprint:
                return decision
        return None

    def discovered(self, report):
        return [f for f in report.findings if f.rule_id == "AGENT-DISCOVERY"]

    def shape_faces(self, report):
        """Comparable closure face (the CA-5/CA-6 checklist projection)."""
        adjudication = report.adjudication
        block = report.collaboration["investigation"]
        static_match = STATIC_COUNT_RE.search(report.summary or "")
        pending_match = PENDING_COUNT_RE.search(report.summary or "")
        return {
            "identity_set": frozenset(
                d["fingerprint"] for d in self.raw_decisions(report)
            ),
            "counts": dict(adjudication["counts"]),
            "overall": adjudication["overall_disposition"],
            "overall_reason": adjudication["overall_reason"],
            "new_targets": adjudication["investigation_summary"]["new_targets"],
            "verdict_counts": dict(block["verdict_counts"]),
            "summary_static": (
                int(static_match.group(1)) if static_match else None
            ),
            "summary_pending": pending_match is not None,
            "risk": report.risk,
            "findings_fps": frozenset(
                f.fingerprint for f in report.findings
            ),
        }

    # -- scenario runners (real investigator chain, offline transport) ----

    def run_module_investigation(self, module_paths, script, *, batch_size=6):
        targets = build_module_targets(self.snapshot, list(module_paths))
        return self.investigator(
            script, batch_size=batch_size
        ).investigate(targets, self.snapshot)

    def run_duplicate_claim_outcome(self, *, claim_count=2):
        """One module batch whose final carries identical legal claims."""
        script = [
            tool_action("read_source", path=CASTING, start_line=1,
                        end_line=CASTING_CLAIM_LINE),
            final_action(
                [module_result(CASTING)],
                new_targets=[casting_claim() for _ in range(claim_count)],
            ),
        ]
        return self.run_module_investigation([CASTING], script)

    def run_repeated_claims_across_batches_outcome(self):
        """batch_size=1: two module batches, each declaring the SAME claim."""
        claim = casting_claim()
        script = [
            tool_action("read_source", path=CASTING, start_line=1,
                        end_line=CASTING_CLAIM_LINE),
            final_action(
                [module_result(CASTING)], new_targets=[dict(claim)],
            ),
            tool_action("read_source", path=CORE, start_line=1, end_line=5),
            tool_action("read_source", path=CASTING, start_line=1,
                        end_line=CASTING_CLAIM_LINE),
            final_action(
                [module_result(CORE)], new_targets=[dict(claim)],
            ),
        ]
        return self.run_module_investigation(
            [CASTING, CORE], script, batch_size=1
        )

    def run_supported_candidate_and_module_outcome(self, variant):
        """One supported static finding, one new candidate and one module
        scope whose outcome is a real failure or a real insufficient."""
        static = static_finding(FLUX, 1, FLUX_HISTORY_EVIDENCE)
        module_script = (
            [TimeoutError("model timeout")] if variant == "failed" else [
                tool_action("read_source", path=CASTING, start_line=1,
                            end_line=CASTING_CLAIM_LINE),
                final_action([module_result(CASTING)]),
            ]
        )
        static_script = [
            tool_action("read_source", path=FLUX, start_line=1, end_line=2),
            tool_action("read_source", path=CASTING, start_line=1,
                        end_line=CASTING_CLAIM_LINE),
            final_action(
                [result(static.fingerprint, FLUX, 1, "supported",
                        refs=[f"read_source:{FLUX}:1-2"])],
                new_targets=[casting_claim()],
            ),
        ]
        targets = build_module_targets(self.snapshot, [CASTING])
        targets += build_investigation_targets([static], self.snapshot)
        outcome = self.investigator(
            module_script + static_script, batch_size=1
        ).investigate(targets, self.snapshot)
        return outcome, static

    def run_refuted_and_insufficient_priors_outcome(self):
        """A refuted-with-observed-evidence history plus an insufficient
        prior, no new targets (matrix row 8 compatibility shape)."""
        history = static_finding(FLUX, 1, FLUX_HISTORY_EVIDENCE)
        prior = static_finding(FLUX, 2, FLUX_PRIOR_EVIDENCE)
        script = [
            tool_action("read_source", path=FLUX, start_line=1, end_line=2),
            final_action([result(
                history.fingerprint, FLUX, 1, "refuted",
                refs=[f"read_source:{FLUX}:1-2"],
            )]),
            tool_action("read_source", path=FLUX, start_line=1, end_line=2),
            final_action([result(
                prior.fingerprint, FLUX, 2, "insufficient",
                reasoning="no decisive evidence either way",
            )]),
        ]
        targets = build_investigation_targets([history, prior], self.snapshot)
        outcome = self.investigator(
            script, batch_size=1
        ).investigate(targets, self.snapshot)
        return outcome, history, prior


class TestRawDecisionUniqueness(MergeClosureTestCase):
    """Matrix rows 1-3 / CA-1..CA-3: raw-list identity of merged decisions."""

    def test_duplicate_claims_single_final_raw_list_unique(self):
        outcome = self.run_duplicate_claim_outcome(claim_count=2)
        report = self.merge_fixed(outcome)
        discovered = self.discovered(report)
        self.assertEqual(len(discovered), 1)
        # CA-1: the RAW-list check is the FIRST uniqueness verdict (the
        # dict-by-fingerprint container can hide duplicates).
        raw = self.raw_decisions(report)
        self.assertEqual(len(raw), len({d["fingerprint"] for d in raw}))
        counts = self.raw_fingerprint_counts(report)
        self.assertEqual(counts[discovered[0].fingerprint], 1)
        self.assertEqual(counts["module-scope:" + CASTING], 1)
        # Two legal identities exist: the scheduled module scope and the
        # once-materialized candidate.
        self.assertEqual(len(raw), 2)

    def test_raw_per_finding_decision_count_exactly_one(self):
        outcome = self.run_duplicate_claim_outcome(claim_count=2)
        report = self.merge_fixed(outcome)
        counts = self.raw_fingerprint_counts(report)
        self.assertEqual(counts["module-scope:" + CASTING], 1)
        # CA-2: exactly one raw decision per actual finding.
        for finding in report.findings:
            self.assertEqual(counts[finding.fingerprint], 1)
        self.assertEqual(len(self.raw_decisions(report)),
                         len(report.findings) + 1)

    def test_same_location_different_evidence_distinct_identities_not_merged(self):
        claim_a = casting_claim()
        claim_b = new_target(
            CASTING, CASTING_CLAIM_LINE, "mold_spin", CASTING_WHY,
            [f"read_source:{CASTING}:1-{CASTING_CLAIM_LINE}",
             f"search_code:{CASTING}"],
        )
        script = [
            tool_action("read_source", path=CASTING, start_line=1,
                        end_line=CASTING_CLAIM_LINE),
            final_action(
                [module_result(CASTING)],
                new_targets=[claim_a, claim_b],
            ),
        ]
        outcome = self.run_module_investigation([CASTING], script)
        report = self.merge_fixed(outcome)
        discovered = self.discovered(report)
        # CA-3 (compatibility row): different evidence_refs are different
        # legal identities -- never force-merged for a tidier count.
        self.assertEqual(len(discovered), 2)
        fingerprints = [f.fingerprint for f in discovered]
        self.assertEqual(len(set(fingerprints)), 2)
        counts = self.raw_fingerprint_counts(report)
        for fingerprint in fingerprints:
            self.assertEqual(counts[fingerprint], 1)
        self.assertEqual(len(self.raw_decisions(report)), 3)

    def test_repeated_claims_across_batches_single_materialization(self):
        outcome = self.run_repeated_claims_across_batches_outcome()
        self.assertEqual(len(outcome.new_targets), 2)
        report = self.merge_fixed(outcome)
        discovered = self.discovered(report)
        self.assertEqual(len(discovered), 1)
        raw = self.raw_decisions(report)
        # CA-1 (matrix row 2): claims repeated in DIFFERENT batches of the
        # same outcome still materialize and adjudicate exactly once.
        self.assertEqual(len(raw), len({d["fingerprint"] for d in raw}))
        counts = self.raw_fingerprint_counts(report)
        self.assertEqual(counts[discovered[0].fingerprint], 1)
        self.assertEqual(counts["module-scope:" + CASTING], 1)
        self.assertEqual(counts["module-scope:" + CORE], 1)
        # Coverage and the execution dimension stay complete.
        block = report.collaboration["investigation"]
        self.assertEqual(block["execution_counts"],
                         {"completed": 2, "failed": 0, "unprocessed": 0})
        self.assertEqual(
            report.adjudication["investigation_summary"]["new_targets"], 1
        )


class TestProductionAliasPopulation(MergeClosureTestCase):
    """Matrix rows 4-6 / CA-4..CA-6: the production alias call shape."""

    def test_alias_first_merge_zero_static_summary_and_counts(self):
        outcome = self.run_duplicate_claim_outcome(claim_count=1)
        report = self.merge_alias(outcome)
        # CA-4: the static population is fixed at merge entry (zero here);
        # the "static candidates" digit counts only that population.
        static_match = STATIC_COUNT_RE.search(report.summary or "")
        self.assertIsNotNone(static_match, report.summary)
        self.assertEqual(int(static_match.group(1)), 0)
        pending_match = PENDING_COUNT_RE.search(report.summary or "")
        self.assertIsNotNone(pending_match, report.summary)
        self.assertEqual(int(pending_match.group(1)), 1)
        block = report.collaboration["investigation"]
        self.assertEqual(block["verdict_counts"],
                         {"supported": 0, "refuted": 0, "insufficient": 0})
        self.assertEqual(block["execution_counts"],
                         {"completed": 1, "failed": 0, "unprocessed": 0})
        # The module unknown stays a separate module face, never static.
        module_decision = self.decision_of(report, "module-scope:" + CASTING)
        self.assertEqual(module_decision["investigation_status"], "insufficient")
        self.assertIn("module scope(s) with unknown", report.summary)
        self.assertEqual(report.adjudication["counts"]["needs_review"], 2)
        self.assertEqual(
            report.adjudication["investigation_summary"]["new_targets"], 1
        )
        self.assert_raw_list_unique(report)
        self.assertEqual(
            report.adjudication["overall_disposition"], "needs_review"
        )

    def test_alias_remerge_candidate_refs_state_pending_preserved(self):
        outcome = self.run_duplicate_claim_outcome(claim_count=1)
        report = self.merge_alias(outcome)
        first = self.shape_faces(report)
        candidate_fp = self.discovered(report)[0].fingerprint
        first_candidate = self.decision_of(report, candidate_fp)
        self.assertEqual(
            first_candidate["reason"],
            "unverified-finding-requires-human-review",
        )
        merge_investigation_into_report(report, outcome, report.findings)
        second = self.shape_faces(report)
        candidate = self.decision_of(report, candidate_fp)
        # CA-5: the already-materialized candidate is never re-classified
        # as an unscheduled static finding on a production-shaped re-merge.
        self.assertEqual(
            candidate["reason"], "unverified-finding-requires-human-review"
        )
        self.assertNotEqual(candidate["reason"], "investigation-not-scheduled")
        self.assertNotIn("investigation_status", candidate)
        self.assertTrue(candidate.get("investigation_evidence_refs"))
        self.assertEqual(candidate["verification_state"], "candidate")
        self.assertEqual(second["identity_set"], first["identity_set"])
        self.assertEqual(second["verdict_counts"], first["verdict_counts"])
        self.assertEqual(second["new_targets"], first["new_targets"])
        self.assertEqual(second["summary_static"], first["summary_static"])
        self.assertTrue(second["summary_pending"])
        self.assertEqual(second["counts"], first["counts"])
        self.assertEqual(second["overall"], first["overall"])
        self.assertEqual(second["overall_reason"], first["overall_reason"])
        self.assertEqual(second["risk"], first["risk"])
        self.assertEqual(second["findings_fps"], first["findings_fps"])

    def test_alias_vs_fixed_list_equivalence_and_order_stability(self):
        claims = {"foundry": casting_claim(), "press": rolling_claim()}
        expected_fps = frozenset(
            claim_fingerprint(claim["path"], claim["line"],
                              claim["evidence_refs"])
            for claim in claims.values()
        )
        module_fps = frozenset(
            "module-scope:" + path for path in (CASTING, ROLLING)
        )

        def outcome_for(order):
            script = [
                tool_action("read_source", path=CASTING, start_line=1,
                            end_line=CASTING_CLAIM_LINE),
                tool_action("read_source", path=ROLLING, start_line=1,
                            end_line=ROLLING_CLAIM_LINE),
                final_action(
                    [module_result(CASTING), module_result(ROLLING)],
                    new_targets=order,
                ),
            ]
            return self.run_module_investigation([CASTING, ROLLING], script)

        fixed_faces = {}
        for order_name, order in (
            ("forward", [claims["foundry"], claims["press"]]),
            ("reverse", [claims["press"], claims["foundry"]]),
        ):
            outcome = outcome_for(order)
            faces = {}
            for shape in ("fixed", "alias"):
                if shape == "fixed":
                    report = self.merge_fixed(outcome)
                    first = self.shape_faces(report)
                    merge_investigation_into_report(report, outcome, [])
                else:
                    report = self.merge_alias(outcome)
                    first = self.shape_faces(report)
                    merge_investigation_into_report(
                        report, outcome, report.findings
                    )
                second = self.shape_faces(report)
                with self.subTest(order=order_name, shape=shape):
                    # CA-6: BOTH shapes are exercised first-merge AND
                    # re-merge; each must stay self-consistent.
                    self.assertEqual(second, first)
                faces[shape] = second
            with self.subTest(order=order_name, check="shape-equivalence"):
                # The two shapes are two spellings of one merge input; the
                # fixed-list control may not stand in for the alias shape.
                self.assertEqual(faces["alias"], faces["fixed"])
            with self.subTest(order=order_name, check="per-sample-identities"):
                self.assertEqual(
                    faces["fixed"]["identity_set"] - module_fps, expected_fps
                )
                self.assertEqual(faces["fixed"]["new_targets"], 2)
            fixed_faces[order_name] = faces["fixed"]
        with self.subTest(check="order-stability"):
            # Claim order never changes the identity set/counts/overall/risk.
            self.assertEqual(fixed_faces["forward"], fixed_faces["reverse"])


class TestMixedPopulationAliasConservation(MergeClosureTestCase):
    """Matrix rows 7-8 / CA-7: strong conclusions survive; priors do not
    drift (row 8 is the A2/C9 compatibility row)."""

    def test_supported_static_alias_remerge_strong_conclusion_kept(self):
        for variant in ("failed", "insufficient"):
            with self.subTest(variant=variant):
                outcome, static = (
                    self.run_supported_candidate_and_module_outcome(variant)
                )
                report = self.merge_alias(outcome, [static])
                first = self.shape_faces(report)
                first_strong = self.decision_of(report, static.fingerprint)
                self.assertEqual(first_strong["disposition"], "alert")
                self.assertEqual(
                    first_strong["investigation_verdict"], "supported"
                )
                self.assertEqual(
                    first_strong["investigation_evidence_refs"],
                    [f"read_source:{FLUX}:1-2"],
                )
                merge_investigation_into_report(
                    report, outcome, report.findings
                )
                second = self.shape_faces(report)
                strong = self.decision_of(report, static.fingerprint)
                # The stronger conclusion survives the production re-merge
                # with its evidence intact (C9/A2 protection list).
                self.assertEqual(strong["disposition"], "alert")
                self.assertEqual(strong["investigation_verdict"], "supported")
                self.assertEqual(strong["investigation_evidence_refs"],
                                 [f"read_source:{FLUX}:1-2"])
                # Three-population conservation (CA-7): verdict_counts keeps
                # its static basis, candidates stay pending, counts conserve.
                self.assertEqual(second["verdict_counts"],
                                 first["verdict_counts"])
                self.assertEqual(second["new_targets"], first["new_targets"])
                self.assertTrue(second["summary_pending"])
                self.assertEqual(second["counts"], first["counts"])
                self.assert_raw_list_unique(report)
                self.assertEqual(
                    report.adjudication["overall_disposition"], "alert"
                )
                module_decision = self.decision_of(
                    report, "module-scope:" + CASTING
                )
                if variant == "failed":
                    self.assertEqual(
                        module_decision["investigation_status"], "failed"
                    )
                    self.assertEqual(
                        module_decision.get("investigation_failure_reason"),
                        "batch-error:TimeoutError",
                    )
                else:
                    self.assertEqual(
                        module_decision["investigation_status"], "insufficient"
                    )

    def test_refuted_history_and_insufficient_priors_alias_remerge_no_drift(self):
        outcome, history, prior = (
            self.run_refuted_and_insufficient_priors_outcome()
        )
        report = self.merge_alias(outcome, [history, prior])
        first = self.shape_faces(report)
        merge_investigation_into_report(report, outcome, report.findings)
        second = self.shape_faces(report)
        self.assertEqual(second, first)
        # The refuted history is not re-opened: scope, refs and the
        # exclusion survive verbatim (A2/C9 protection list).
        refuted_decision = self.decision_of(report, history.fingerprint)
        self.assertEqual(refuted_decision["disposition"], "needs_review")
        self.assertEqual(refuted_decision["investigation_verdict"], "refuted")
        self.assertEqual(refuted_decision.get("effective_state"),
                         "excluded-from-active-alerts")
        self.assertEqual(refuted_decision["investigation_evidence_refs"],
                         [f"read_source:{FLUX}:1-2"])
        self.assertEqual(refuted_decision["path"], FLUX)
        self.assertEqual(refuted_decision["line"], 1)
        # The insufficient prior does not drift across the re-merge.
        prior_decision = self.decision_of(report, prior.fingerprint)
        self.assertEqual(prior_decision["disposition"], "alert")
        self.assertEqual(prior_decision["investigation_status"],
                         "insufficient")
        self.assertEqual(first["verdict_counts"],
                         {"supported": 0, "refuted": 1, "insufficient": 1})
        self.assertEqual(first["counts"],
                         {"alert": 1, "needs_review": 1, "clear": 0})
        self.assertEqual(report.risk, "high")
        self.assert_raw_list_unique(report)


class TestServiceStoreClosure(unittest.TestCase):
    """Matrix row 9 / CA-8: the real service chain's persisted JSON face.

    Real ``ReviewService`` -> queue worker -> ``FindingInvestigator`` ->
    ``merge_investigation_into_report`` (production alias shape, called by
    the service itself) -> store -> ``task["report"]`` JSON; transport-level
    fake only (patched before service construction).
    """

    def setUp(self):
        tmp = tempfile.mkdtemp(suffix="-pr265c1-svc")
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        self.outer_root = pathlib.Path(tmp)
        self.repo_root = self.outer_root / "repo"
        for rel, text in SERVICE_SAMPLE.items():
            path = self.repo_root / pathlib.PurePosixPath(rel)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text, encoding="utf-8")
        self._saved_env = {key: os.environ.get(key) for key in ENV_KEYS}
        values = dict(ENV_VALUES)
        values["LIMA_DB_PATH"] = str(self.outer_root / "state.db")
        values["LIMA_REPOSITORY_CACHE_ROOT"] = str(self.outer_root / "cache")
        values["LIMA_REPOSITORY_IMPORT_ROOT"] = str(self.outer_root)
        for key, value in values.items():
            os.environ[key] = value
        self.addCleanup(self._restore_env)

    def _restore_env(self):
        for key, value in self._saved_env.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value

    def test_service_duplicate_claims_json_raw_unique_zero_static(self):
        from lima.config import Settings
        from lima.service import ReviewService

        transport = ScriptedTransport(service_duplicate_claim_script())
        with mock.patch(
            "lima.reviewer.post_chat_completion_full", new=transport,
        ):
            service = ReviewService(Settings.from_env())
            try:
                import lima.repository_import as import_mod

                original_resolve = import_mod.RepositoryImportPolicy.resolve
                import_mod.RepositoryImportPolicy.resolve = (
                    lambda policy, key: self.repo_root
                )
                try:
                    created = service.enqueue_repository_scan(
                        "repo", "default", investigate_paths=[SAWMILL],
                    )
                    deadline = time.time() + 60
                    task = {}
                    while time.time() < deadline:
                        task = service.store.get(
                            created["task_id"], "default"
                        ) or {}
                        if task.get("state") in {"SUCCESS", "FAILED"}:
                            break
                        time.sleep(0.05)
                finally:
                    import_mod.RepositoryImportPolicy.resolve = original_resolve
            finally:
                service.queue.close()
        self.assertEqual(task.get("state"), "SUCCESS", task.get("error"))
        document = task["report"]
        adjudication = document["adjudication"]
        # CA-8: the RAW persisted decision list is checked FIRST.
        raw = list(adjudication["decisions"])
        self.assertEqual(len(raw), len({d["fingerprint"] for d in raw}))
        raw_counts = Counter(d["fingerprint"] for d in raw)
        discovered = [
            f for f in document["findings"]
            if f["rule_id"] == "AGENT-DISCOVERY"
        ]
        self.assertEqual(len(discovered), 1)
        self.assertEqual(raw_counts[discovered[0]["fingerprint"]], 1)
        self.assertEqual(raw_counts["module-scope:" + SAWMILL], 1)
        # Zero static population: the persisted summary digit counts only
        # that population, and the pending candidate stays pending.
        static_match = STATIC_COUNT_RE.search(document.get("summary") or "")
        self.assertIsNotNone(static_match, document.get("summary"))
        self.assertEqual(int(static_match.group(1)), 0)
        pending_match = PENDING_COUNT_RE.search(document.get("summary") or "")
        self.assertIsNotNone(pending_match, document.get("summary"))
        self.assertEqual(int(pending_match.group(1)), 1)
        self.assertEqual(adjudication["counts"]["needs_review"], 2)
        self.assertEqual(
            adjudication["investigation_summary"]["new_targets"], 1
        )
        self.assertEqual(adjudication["overall_disposition"], "needs_review")
        self.assertEqual(document["risk"], "high")
        # The real chain really ran over the offline transport (fake as
        # labelled; real external model calls are zero by construction).
        self.assertGreaterEqual(len(transport.calls), 2)


class TestIdentityAndNoWhitelist(MergeClosureTestCase):
    """Derived formula row / CA-3: the frozen candidate identity formula."""

    def test_candidate_fingerprint_formula_stable_across_samples(self):
        cases = {
            "foundry": (CASTING, CASTING_CLAIM_LINE, casting_claim()),
            "press": (ROLLING, ROLLING_CLAIM_LINE, rolling_claim()),
        }
        fingerprints = {}
        for sample, (module_path, claim_line, claim) in cases.items():
            with self.subTest(sample=sample):
                script = [
                    tool_action("read_source", path=module_path,
                                start_line=1, end_line=claim_line),
                    final_action(
                        [module_result(module_path)],
                        new_targets=[dict(claim)],
                    ),
                ]
                outcome = self.run_module_investigation([module_path], script)
                report = self.merge_fixed(outcome)
                discovered = self.discovered(report)
                self.assertEqual(len(discovered), 1)
                # CA-3: the identity is the frozen Finding formula over
                # rule/path/line/evidence -- unchanged by the closure.
                self.assertEqual(
                    discovered[0].fingerprint,
                    claim_fingerprint(claim["path"], claim["line"],
                                      claim["evidence_refs"]),
                )
                self.assertEqual(discovered[0].path, module_path)
                self.assertEqual(discovered[0].line, claim_line)
                fingerprints[sample] = discovered[0].fingerprint
        # No repository/path/symbol whitelist: the same formula maps
        # different samples to different identities.
        self.assertNotEqual(fingerprints["foundry"], fingerprints["press"])


class TestDerivedConservation(MergeClosureTestCase):
    """Row-1 derived faces / CA-2: conservation by unique identity."""

    def test_counts_summary_new_targets_conserved_by_unique_identity(self):
        outcome = self.run_duplicate_claim_outcome(claim_count=2)
        report = self.merge_fixed(outcome)
        adjudication = report.adjudication
        # CA-2/C5: counts are the real count of unique merged decisions --
        # a duplicated declaration is not a second unit of review.
        self.assertEqual(adjudication["counts"],
                         {"alert": 0, "needs_review": 2, "clear": 0})
        faces = adjudication["investigation_summary"]
        self.assertEqual(faces["new_targets"], 1)
        self.assertEqual(faces["active_alerts"],
                         adjudication["counts"]["alert"])
        # C8: the summary digit agrees with the unique-identity face.
        pending_match = PENDING_COUNT_RE.search(report.summary or "")
        self.assertIsNotNone(pending_match, report.summary)
        self.assertEqual(int(pending_match.group(1)), 1)
        self.assertEqual(adjudication["overall_disposition"], "needs_review")
        self.assertEqual(report.risk, "high")


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
