"""UAF v2 instrument tests (retained from the retired v2 orchestrator suite).

Plan Task 4 (agent-vuln-platform design section 10): the v2 orchestration is
retired -- the scanner runs the single agent chain in
``lima.agent_orchestrator`` -- while the deterministic components stay
available as **instruments** for agent consultation.  Red lines pinned here:

- ``_expectation_for`` pins the bundle expectation (identity chain, closed
  multi-TU context allowlists) without crashing on legitimate inputs;
- ``instrument_facts`` drives the strict analyzer client and certifies the
  bundle, and refuses clients without the facts capability;
- ``instrument_proof`` returns the frozen P1-P7 verdicts (PASS on complete
  evidence, UNKNOWN under incomplete CFG, REFUTED on the rebind
  counterexample);
- ``instrument_broker`` binds tool findings per producer and answers
  support/no-evidence without ever inventing a contradiction;
- the pure ``arbiter_state`` keeps its frozen priority rules, including the
  strong-evidence conflict -> ``needs-human-review`` rule.

Zero network: the Sidecar is a fake ``analyze_uaf_facts`` client returning
canned ``UafFactsResponse`` wire bundles.
"""

import unittest
from dataclasses import replace

from lima.cxx_memory import (
    CxxAnalysisResult,
    UafFactsResponse,
    uaf_facts_bundle_sha256,
)
from lima.models import EvidenceRecord, Finding, Severity
from lima.uaf_candidates import generate_candidates
from lima.uaf_models import CandidateIdentity
from lima.uaf_orchestrator import (
    UAF_FINDING_STATES,
    _expectation_for,
    arbiter_state,
    instrument_broker,
    instrument_facts,
    instrument_proof,
)

REPO_KEY = "team/project"
SNAPSHOT = "a" * 64
CONTEXT = "c" * 64
CONTEXT_B = "d" * 64
RUN_ID = "run-uaf-1"
UNIT = "src/a.cpp"
UNIT_B = "src/b.cpp"
USR = "C::leak"


def _fid(number: int) -> str:
    return format(number, "064x")


ALLOC = _fid(1)
RELEASE = _fid(2)
USE = _fid(3)
REBIND = _fid(4)
RELEASE2 = _fid(5)


# ------------------------------------------------------------------ wire


def _wire_fact(
    kind,
    fact_id,
    line,
    *,
    unit=UNIT,
    api=None,
    pointer=None,
    source_pointer=None,
    related=None,
):
    fact = {
        "fact_id": fact_id,
        "kind": kind,
        "translation_unit": unit,
        "canonical_path": unit,
        "function_usr": USR,
        "source_range": [line, line],
        "cfg_block": 0,
    }
    if kind == "allocation":
        fact["allocation_api"] = api or "new"
        fact["pointer_id"] = pointer or "p"
    elif kind == "release":
        fact["release_api"] = api or "delete"
        fact["pointer_id"] = pointer or "p"
        fact["related_fact_ids"] = list(related or ())
    elif kind == "dereference":
        fact["pointer_id"] = pointer or "p"
    elif kind == "rebind":
        fact["pointer_id"] = pointer or "p"
        fact["source_pointer_id"] = source_pointer or "n"
        fact["related_fact_ids"] = list(related or ())
    return fact


def _straight_facts():
    return [
        _wire_fact("allocation", ALLOC, 10),
        _wire_fact("release", RELEASE, 20, related=(ALLOC,)),
        _wire_fact("dereference", USE, 30),
    ]


def _rebind_facts():
    return _straight_facts() + [
        _wire_fact("rebind", REBIND, 25, pointer="p", source_pointer="n",
                   related=(ALLOC,)),
    ]


def _unit_entry(facts, *, unit=UNIT, build=None, cfg_complete=True, gaps=()):
    if build is None:
        build = {
            "status": "resolved",
            "source_kind": "repository-compdb",
            "context_hash": CONTEXT,
            "diagnostics": [],
        }
    return {
        "translation_unit": unit,
        "extraction": "completed",
        "build_context": build,
        "coverage": {
            "ast_complete": True,
            "cfg_complete": cfg_complete,
            "semantic_gaps": list(gaps),
        },
        "facts": list(facts),
    }


def _resolved_unit(facts=None):
    return _unit_entry(_straight_facts() if facts is None else facts)


def _payload(*units, snapshot=SNAPSHOT, run_id=RUN_ID):
    tool_run = {"run_id": run_id, "tool": "uaf-facts", "status": "completed"}
    return {
        "schema_version": 1,
        "request_id": "req-1",
        "repository_key": REPO_KEY,
        "snapshot_sha256": snapshot,
        "tool_runs": [tool_run],
        "translation_units": list(units),
        "bundle_sha256": uaf_facts_bundle_sha256(list(units)),
        "diagnostics": [],
    }


class FakeUafAnalyzer:
    """Offline ``CxxMemoryAnalyzerClient`` stand-in (facts + tool layers)."""

    def __init__(self, payload=None, tool_result=None):
        self.payload = payload
        self.tool_result = tool_result
        self.unit_calls = []

    def analyze(
        self, repository_key, snapshot_sha256, requested_layers, inventory=None,
    ):
        return self.tool_result or CxxAnalysisResult(
            "completed", [], [], {"files": 0}, [],
        )

    def analyze_uaf_facts(
        self, repository_key, snapshot_sha256, translation_units,
        build_context_mode,
    ):
        self.unit_calls.append((tuple(translation_units), build_context_mode))
        payload = dict(self.payload or _payload())
        payload["repository_key"] = repository_key
        payload["snapshot_sha256"] = snapshot_sha256
        payload["bundle_sha256"] = uaf_facts_bundle_sha256(
            payload["translation_units"]
        )
        return UafFactsResponse(
            request_id=payload["request_id"],
            repository_key=payload["repository_key"],
            snapshot_sha256=payload["snapshot_sha256"],
            tool_runs=tuple(payload["tool_runs"]),
            translation_units=tuple(payload["translation_units"]),
            bundle_sha256=payload["bundle_sha256"],
            diagnostics=tuple(payload["diagnostics"]),
        )


# ------------------------------------------------------------- tool results


def _asan_tool_analysis():
    """Canned Sidecar result with one ASan record bound to the use site."""

    finding = Finding(
        rule_id="asan.uaf", severity=Severity.HIGH,
        title="heap-use-after-free", explanation="read of freed pointer",
        path=UNIT, line=30, evidence="p->value read after free(p)",
        fix="", test="reproduce under ASan", cwe="CWE-416", source="asan",
        symbol="leak",
        evidence_records=[EvidenceRecord(
            source="asan", kind="runtime", path=UNIT, line=30,
            snippet="READ of size 4 ... freed by ... allocated by ...",
            rule_id="asan.uaf", cwe="CWE-416", symbol="leak",
            tool_run_id="asan-run-1",
        )],
    )
    return CxxAnalysisResult(
        status="completed",
        tool_runs=[{
            "run_id": "asan-run-1", "tool": "asan-test", "status": "completed",
        }],
        findings=[finding],
        coverage={"files": 1},
        diagnostics=[],
    )


# --------------------------------------------------------- local helpers


def _rmtree(root):
    import shutil

    shutil.rmtree(root, ignore_errors=True)


def _certified(facts=None, *, cfg_complete=True):
    """One certified bundle served by the offline facts client."""

    analyzer = FakeUafAnalyzer(
        _payload(_unit_entry(
            _straight_facts() if facts is None else facts,
            cfg_complete=cfg_complete,
        ))
    )
    bundle = instrument_facts(
        analyzer,
        repository_key=REPO_KEY,
        snapshot_hash=SNAPSHOT,
        translation_units=(UNIT,),
    )
    return analyzer, bundle


# ================================================================= tests


class ExpectationPinningTests(unittest.TestCase):
    """``_expectation_for`` pins identity without crashing legitimately."""

    @staticmethod
    def _response(payload):
        return UafFactsResponse(
            request_id=payload["request_id"],
            repository_key=payload["repository_key"],
            snapshot_sha256=payload["snapshot_sha256"],
            tool_runs=tuple(payload["tool_runs"]),
            translation_units=tuple(payload["translation_units"]),
            bundle_sha256=payload["bundle_sha256"],
            diagnostics=(),
        )

    @staticmethod
    def _unavailable_unit(unit):
        return {
            "translation_unit": unit,
            "extraction": "unavailable",
            "build_context": {
                "status": "unavailable", "source_kind": "",
                "context_hash": "", "diagnostics": [],
            },
            "coverage": {
                "ast_complete": False, "cfg_complete": False,
                "semantic_gaps": ["context-not-resolved"],
            },
            "facts": [],
        }

    def test_multiple_resolved_tus_with_distinct_contexts_do_not_crash(self):
        unit_b_facts = [
            _wire_fact("allocation", _fid(11), 10, unit=UNIT_B, pointer="q"),
            _wire_fact(
                "release", _fid(12), 20, unit=UNIT_B, pointer="q",
                related=(_fid(11),),
            ),
            _wire_fact("dereference", _fid(13), 30, unit=UNIT_B, pointer="q"),
        ]
        payload = _payload(
            _unit_entry(_straight_facts()),
            _unit_entry(
                unit_b_facts,
                unit=UNIT_B,
                build={
                    "status": "resolved",
                    "source_kind": "repository-compdb",
                    "context_hash": CONTEXT_B,
                    "diagnostics": [],
                },
            ),
        )
        expectation = _expectation_for(
            self._response(payload), SNAPSHOT, "snapshot-compdb",
            (UNIT, UNIT_B),
        )
        self.assertEqual("", expectation.build_context_hash)
        self.assertEqual(
            frozenset({CONTEXT, CONTEXT_B}),
            expectation.allowed_context_hashes,
        )

    def test_expectation_for_pins_single_and_no_completed_decisions(self):
        # One completed unit keeps the single-anchor behavior: the anchor is
        # the observed hash and the allowlist contains exactly that hash.
        single = _expectation_for(
            self._response(_payload(_resolved_unit())),
            SNAPSHOT, "snapshot-compdb", (UNIT,),
        )
        self.assertEqual(CONTEXT, single.build_context_hash)
        self.assertEqual(frozenset({CONTEXT}), single.allowed_context_hashes)

        # No completed unit keeps the review-identity digest: a deterministic
        # 64-hex anchor with an empty allowlist (no completed hash exists).
        empty = _expectation_for(
            self._response(_payload(self._unavailable_unit(UNIT))),
            SNAPSHOT, "snapshot-compdb", (UNIT,),
        )
        self.assertRegex(empty.build_context_hash, r"^[0-9a-f]{64}$")
        self.assertEqual(frozenset(), empty.allowed_context_hashes)


class InstrumentFactsTests(unittest.TestCase):
    """The facts instrument certifies the wire bundle, fail-closed."""

    def test_instrument_facts_drives_the_strict_client_and_certifies(self):
        analyzer = FakeUafAnalyzer(_payload(_resolved_unit()))
        bundle = instrument_facts(
            analyzer,
            repository_key=REPO_KEY,
            snapshot_hash=SNAPSHOT,
            translation_units=(UNIT,),
        )
        self.assertEqual([((UNIT,), "snapshot-compdb")], analyzer.unit_calls)
        self.assertEqual(1, len(bundle.per_unit))
        self.assertEqual(3, len(bundle.facts))
        self.assertEqual(UNIT, bundle.per_unit[0].translation_unit)

    def test_instrument_facts_requires_a_facts_capable_client(self):
        with self.assertRaises(ValueError):
            instrument_facts(
                object(),
                repository_key=REPO_KEY,
                snapshot_hash=SNAPSHOT,
                translation_units=(UNIT,),
            )

    def test_instrument_facts_bounds_the_unit_request(self):
        analyzer = FakeUafAnalyzer(_payload(_resolved_unit()))
        with self.assertRaises(ValueError):
            instrument_facts(
                analyzer,
                repository_key=REPO_KEY,
                snapshot_hash=SNAPSHOT,
                translation_units=(),
            )


class InstrumentProofTests(unittest.TestCase):
    """The proof instrument returns the frozen P1-P7 verdicts."""

    def test_complete_evidence_proves_pass(self):
        _, bundle = _certified()
        candidate = generate_candidates(bundle)[0]
        proof = instrument_proof(candidate, bundle)
        self.assertEqual("PASS", proof.verdict)
        self.assertTrue(all(
            item.verdict == "satisfied" for item in proof.obligations
        ))

    def test_incomplete_cfg_keeps_the_proof_unknown(self):
        _, bundle = _certified(cfg_complete=False)
        candidate = generate_candidates(bundle)[0]
        proof = instrument_proof(candidate, bundle)
        self.assertEqual("UNKNOWN", proof.verdict)

    def test_rebind_counterexample_refutes(self):
        _, bundle = _certified(_rebind_facts())
        candidate = generate_candidates(bundle)[0]
        proof = instrument_proof(candidate, bundle)
        self.assertEqual("REFUTED", proof.verdict)
        self.assertTrue(any(
            item.verdict == "refuted" and item.obligation.value == "P6"
            for item in proof.obligations
        ))

    def test_candidate_outside_the_bundle_is_refused(self):
        _, bundle = _certified()
        candidate = generate_candidates(bundle)[0]
        stray = replace(candidate, allocation_fact_id=_fid(0x98))
        with self.assertRaises(ValueError):
            instrument_proof(stray, bundle)


class InstrumentBrokerTests(unittest.TestCase):
    """The broker instrument binds tool findings per producer."""

    def _candidate_identity_and_proof(self, *, cfg_complete=True):
        _, bundle = _certified(cfg_complete=cfg_complete)
        candidate = generate_candidates(bundle)[0]
        identity = CandidateIdentity(SNAPSHOT, candidate.candidate_id)
        return bundle, candidate, identity, instrument_proof(candidate, bundle)

    def test_binds_asan_runtime_evidence_as_support(self):
        _, candidate, identity, proof = self._candidate_identity_and_proof(
            cfg_complete=False,
        )
        diagnostics: list[str] = []
        verdicts, evidence = instrument_broker(
            identity, candidate, _asan_tool_analysis(), proof, diagnostics,
        )
        self.assertEqual([], diagnostics)
        self.assertEqual(1, len(verdicts))
        self.assertEqual("support", verdicts[0].verdict)
        self.assertEqual("asan", verdicts[0].producer)
        self.assertEqual(1, len(evidence))
        self.assertEqual("asan", evidence[0].source)

    def test_without_tool_analysis_there_is_no_evidence(self):
        _, candidate, identity, proof = self._candidate_identity_and_proof()
        diagnostics: list[str] = []
        verdicts, evidence = instrument_broker(
            identity, candidate, None, proof, diagnostics,
        )
        self.assertEqual((), verdicts)
        self.assertEqual((), evidence)
        self.assertEqual([], diagnostics)


class ArbiterPriorityTests(unittest.TestCase):
    """Arbiter rule 1: strong conflicting evidence forces human review."""

    def _broker_support(self, level, producer="semgrep"):
        from lima.contracts.evidence import EvidencePolarity
        from lima.uaf_broker import BrokerVerdict

        return BrokerVerdict(
            identity=CandidateIdentity(SNAPSHOT, _fid(9)),
            producer=producer,
            verdict="support",
            evidence_level=level,
            evidence_polarity=EvidencePolarity.SUPPORTS,
        )

    def _broker_contradict(self, level, producer="clang"):
        from lima.contracts.evidence import EvidencePolarity
        from lima.uaf_broker import BrokerVerdict

        return BrokerVerdict(
            identity=CandidateIdentity(SNAPSHOT, _fid(9)),
            producer=producer,
            verdict="contradict",
            evidence_level=level,
            evidence_polarity=EvidencePolarity.REFUTES,
        )

    def _arbiter_proof(self, verdict):
        from lima.uaf_models import (
            ObligationVerdict,
            ProofObligation,
            ProofResult,
        )

        obligations = tuple(
            ObligationVerdict(
                obligation=obligation,
                verdict=(
                    "refuted" if verdict == "REFUTED" and obligation.value == "P6"
                    else "satisfied" if verdict == "PASS" else "unknown"
                ),
                fact_ids=(ALLOC,),
                reason="fixture obligation",
            )
            for obligation in ProofObligation
        )
        return ProofResult(verdict=verdict, obligations=obligations)

    def test_arbiter_priority_conflict_forces_needs_human_review(self):
        # PASS proof + valid D2 REFUTES tool evidence -> needs-human-review.
        state = arbiter_state(
            self._arbiter_proof("PASS"),
            (self._broker_contradict(level="D2"),),
            None,
        )
        self.assertEqual("needs-human-review", state)

        # REFUTED proof + valid D2 SUPPORTS tool evidence -> ditto.
        state = arbiter_state(
            self._arbiter_proof("REFUTED"),
            (self._broker_support(level="D2"),),
            None,
        )
        self.assertEqual("needs-human-review", state)

        # Without the conflict the same inputs decide deterministically:
        self.assertEqual(
            "fact-verified",
            arbiter_state(self._arbiter_proof("PASS"), (), None),
        )
        self.assertEqual(
            "rejected",
            arbiter_state(self._arbiter_proof("REFUTED"), (), None),
        )
        self.assertEqual(
            "tool-corroborated",
            arbiter_state(
                self._arbiter_proof("UNKNOWN"),
                (self._broker_support(level="D2"),),
                None,
            ),
        )

    def test_rejected_state_is_never_a_finding_state(self):
        self.assertNotIn("rejected", UAF_FINDING_STATES)
        self.assertNotIn("abstain", UAF_FINDING_STATES)


if __name__ == "__main__":
    unittest.main()
