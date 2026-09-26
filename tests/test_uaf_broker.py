"""Plan Task 9: three-state Evidence Broker for UAF v2 candidates.

Freezes design section 11 (``docs/superpowers/specs/2026-09-10-cxx-uaf-v2.md``):

- The verdict domain is exactly ``support | contradict | no-evidence`` and a
  verdict is serialized separately from ``EvidenceLevel``/``EvidencePolarity``
  (four independent keys, no mixed level+polarity field).
- ``contradict`` needs all five strict conditions (exact identity by caller
  contract, completed producer run, valid provenance, an explicit REFUTES
  record, and a refuted proof obligation); every missing condition degrades
  the REFUTES record to ``no-evidence`` with a ``provenance-incomplete`` gap.
- The seven design 11.2 situations that are never a contradiction stay
  ``no-evidence``; an empty tool result is never safety.
"""

import json
import unittest

from lima.contracts.evidence import (
    EvidenceLevel,
    EvidencePolarity,
    EvidenceRecord,
    EvidenceSubjectKind,
)
from lima.uaf_broker import (
    BROKER_IS_NOT_CONTRADICTION,
    BROKER_VERDICTS,
    BrokerVerdict,
    broker_verdict,
)
from lima.uaf_models import (
    PROOF_OBLIGATIONS,
    CandidateIdentity,
    ObligationVerdict,
    ProofObligation,
    ProofResult,
)

_A = "a" * 64


def _identity(snapshot_hash="2" * 64, candidate_id="1" * 64):
    return CandidateIdentity(snapshot_hash=snapshot_hash, candidate_id=candidate_id)


def _record(
    *,
    evidence_id="evidence-0001",
    level=EvidenceLevel.D1,
    polarity=EvidencePolarity.SUPPORTS,
    run_id="run-1",
    extensions=None,
):
    if extensions is None:
        extensions = {"tool_run_id": run_id} if run_id else {}
    return EvidenceRecord(
        evidence_id=evidence_id,
        subject_kind=EvidenceSubjectKind.VULNERABILITY_HYPOTHESIS,
        subject_id="cand-0001",
        level=level,
        polarity=polarity,
        analysis_family="runtime-sanitizer",
        producer="asan",
        independence_key="asan:src/session.cpp:22",
        summary="Tool evidence about the UAF candidate witness.",
        source_artifact_ids=("tool-run-0001",),
        reason_codes=("ASAN_USE_AFTER_FREE",),
        extensions=extensions,
    )


def _proof(*, refuted=(), verdict=None):
    obligations = tuple(
        ObligationVerdict(
            obligation=obligation,
            verdict="refuted" if obligation in refuted else "satisfied",
            fact_ids=(_A,),
            reason="fixture obligation",
        )
        for obligation in PROOF_OBLIGATIONS
    )
    resolved = verdict or ("REFUTED" if refuted else "PASS")
    return ProofResult(verdict=resolved, obligations=obligations)


class VerdictDomainTests(unittest.TestCase):
    """The closed vocabularies of design section 11."""

    def test_broker_verdicts_are_exactly_three_states(self):
        self.assertEqual(
            frozenset({"support", "contradict", "no-evidence"}), BROKER_VERDICTS
        )

    def test_not_contradiction_list_covers_design_11_2(self):
        # One entry per design 11.2 bullet, in design order.
        expected = (
            "semgrep-no-report",  # Semgrep 没有报告
            "clang-no-report",  # Clang Static Analyzer 没有报告
            "asan-witness-not-covered",  # ASan 运行但没有覆盖 witness path
            "producer-run-not-completed",  # 工具未运行、超时或失败
            "different-cwe-same-location",  # 同一位置报告了另一个 CWE
            "fuzzy-position-match",  # symbol/line/path 只能模糊匹配
            "missing-tool-run-identity",  # finding 缺少有效 tool-run identity
        )
        self.assertEqual(7, len(BROKER_IS_NOT_CONTRADICTION))
        for code in expected:
            with self.subTest(code=code):
                self.assertIn(code, BROKER_IS_NOT_CONTRADICTION)


class NoEvidenceTests(unittest.TestCase):
    """Empty results and broken provenance are never safety."""

    def test_empty_records_no_evidence_without_gap(self):
        verdict = broker_verdict(_identity(), "semgrep", (), frozenset(), _proof())
        self.assertEqual("no-evidence", verdict.verdict)
        self.assertEqual("", verdict.gap)
        self.assertIsNone(verdict.evidence_level)
        self.assertIsNone(verdict.evidence_polarity)

    def test_records_with_unresolvable_run_are_no_evidence_with_gap(self):
        records = (_record(run_id="run-9"),)
        verdict = broker_verdict(
            _identity(), "semgrep", records, frozenset({"run-1"}), _proof()
        )
        self.assertEqual("no-evidence", verdict.verdict)
        self.assertEqual("provenance-incomplete", verdict.gap)
        self.assertIsNone(verdict.evidence_level)
        self.assertIsNone(verdict.evidence_polarity)

    def test_record_without_tool_run_identity_is_no_evidence(self):
        records = (_record(extensions={}),)
        verdict = broker_verdict(
            _identity(), "semgrep", records, frozenset({"run-1"}), _proof()
        )
        self.assertEqual("no-evidence", verdict.verdict)
        self.assertEqual("provenance-incomplete", verdict.gap)


class SupportTests(unittest.TestCase):
    """Valid same-identity support survives at its own evidence level."""

    def test_valid_support_keeps_record_level(self):
        records = (_record(level=EvidenceLevel.D1),)
        verdict = broker_verdict(
            _identity(), "semgrep", records, frozenset({"run-1"}), _proof()
        )
        self.assertEqual("support", verdict.verdict)
        self.assertEqual(EvidenceLevel.D1, verdict.evidence_level)
        self.assertEqual(EvidencePolarity.SUPPORTS, verdict.evidence_polarity)
        self.assertEqual("", verdict.gap)

    def test_support_is_never_promoted_by_producer_name(self):
        # A D1 record behind a clang producer stays D1: no automatic D2.
        records = (_record(level=EvidenceLevel.D1),)
        verdict = broker_verdict(
            _identity(), "clang", records, frozenset({"run-1"}), _proof()
        )
        self.assertEqual(EvidenceLevel.D1, verdict.evidence_level)

    def test_unresolvable_refutes_with_valid_support_yields_support(self):
        records = (
            _record(
                evidence_id="evidence-refutes",
                level=EvidenceLevel.D2,
                polarity=EvidencePolarity.REFUTES,
                run_id="run-missing",
            ),
            _record(),
        )
        verdict = broker_verdict(
            _identity(), "semgrep", records, frozenset({"run-1"}), _proof()
        )
        self.assertEqual("support", verdict.verdict)
        self.assertEqual(EvidencePolarity.SUPPORTS, verdict.evidence_polarity)
        self.assertEqual("", verdict.gap)


class ContradictTests(unittest.TestCase):
    """contradict requires all five design 11.2 conditions at once."""

    def test_valid_contradiction(self):
        records = (
            _record(
                evidence_id="evidence-refutes",
                level=EvidenceLevel.D2,
                polarity=EvidencePolarity.REFUTES,
            ),
        )
        verdict = broker_verdict(
            _identity(),
            "asan",
            records,
            frozenset({"run-1"}),
            _proof(refuted=(ProofObligation.P4,)),
        )
        self.assertEqual("contradict", verdict.verdict)
        self.assertEqual(EvidenceLevel.D2, verdict.evidence_level)
        self.assertEqual(EvidencePolarity.REFUTES, verdict.evidence_polarity)
        self.assertEqual("", verdict.gap)

    def test_contradiction_conditions_missing_one_by_one(self):
        refutes = _record(
            evidence_id="evidence-refutes",
            level=EvidenceLevel.D2,
            polarity=EvidencePolarity.REFUTES,
        )
        cases = (
            # (label, records, completed_run_ids, proof)
            (
                "completed-run-missing",
                (refutes,),
                frozenset({"run-other"}),
                _proof(refuted=(ProofObligation.P4,)),
            ),
            (
                "provenance-missing",
                (_record(
                    evidence_id="evidence-refutes",
                    level=EvidenceLevel.D2,
                    polarity=EvidencePolarity.REFUTES,
                    extensions={},
                ),),
                frozenset({"run-1"}),
                _proof(refuted=(ProofObligation.P4,)),
            ),
            (
                "refuted-obligation-missing",
                (refutes,),
                frozenset({"run-1"}),
                _proof(refuted=()),
            ),
            (
                "proof-result-absent",
                (refutes,),
                frozenset({"run-1"}),
                None,
            ),
            (
                "refutes-record-missing",
                (_record(),),
                frozenset({"run-1"}),
                _proof(refuted=(ProofObligation.P4,)),
            ),
        )
        for label, records, runs, proof in cases:
            with self.subTest(label=label):
                verdict = broker_verdict(_identity(), "asan", records, runs, proof)
                self.assertNotEqual("contradict", verdict.verdict)
                if label == "refutes-record-missing":
                    # Valid support never becomes a contradiction.
                    self.assertEqual("support", verdict.verdict)
                else:
                    self.assertEqual("no-evidence", verdict.verdict)
                    self.assertEqual("provenance-incomplete", verdict.gap)
                    self.assertIsNone(verdict.evidence_level)
                    self.assertIsNone(verdict.evidence_polarity)


class SerializationTests(unittest.TestCase):
    """Verdict, level and polarity travel as independent flat keys."""

    def test_to_dict_keys_are_flat_and_independent(self):
        verdict = broker_verdict(
            _identity(),
            "asan",
            (
                _record(
                    evidence_id="evidence-refutes",
                    level=EvidenceLevel.D2,
                    polarity=EvidencePolarity.REFUTES,
                ),
            ),
            frozenset({"run-1"}),
            _proof(refuted=(ProofObligation.P4,)),
        )
        data = verdict.to_dict()
        self.assertEqual(
            {
                "snapshot_hash",
                "candidate_id",
                "producer",
                "verdict",
                "evidence_level",
                "evidence_polarity",
                "gap",
            },
            frozenset(data),
        )
        self.assertEqual("contradict", data["verdict"])
        self.assertEqual("D2", data["evidence_level"])
        self.assertEqual("refutes", data["evidence_polarity"])
        self.assertEqual("", data["gap"])
        # The three fields never merge into one wire value.
        encoded = json.dumps(data)
        self.assertIn('"verdict": "contradict"', encoded)
        self.assertIn('"evidence_level": "D2"', encoded)
        self.assertIn('"evidence_polarity": "refutes"', encoded)

    def test_no_evidence_serializes_null_level_and_polarity(self):
        verdict = broker_verdict(_identity(), "semgrep", (), frozenset(), _proof())
        data = verdict.to_dict()
        self.assertIsNone(data["evidence_level"])
        self.assertIsNone(data["evidence_polarity"])
        self.assertEqual("no-evidence", data["verdict"])
        json.dumps(data)


class BrokerVerdictValidationTests(unittest.TestCase):
    """The frozen verdict record refuses incoherent combinations."""

    def test_verdict_outside_domain_rejected(self):
        with self.assertRaises(ValueError):
            BrokerVerdict(
                identity=_identity(),
                producer="asan",
                verdict="safe",
                evidence_level=None,
                evidence_polarity=None,
            )

    def test_support_with_refutes_polarity_rejected(self):
        with self.assertRaises(ValueError):
            BrokerVerdict(
                identity=_identity(),
                producer="asan",
                verdict="support",
                evidence_level=EvidenceLevel.D2,
                evidence_polarity=EvidencePolarity.REFUTES,
            )

    def test_contradict_with_supports_polarity_rejected(self):
        with self.assertRaises(ValueError):
            BrokerVerdict(
                identity=_identity(),
                producer="asan",
                verdict="contradict",
                evidence_level=EvidenceLevel.D2,
                evidence_polarity=EvidencePolarity.SUPPORTS,
            )

    def test_no_evidence_with_level_rejected(self):
        with self.assertRaises(ValueError):
            BrokerVerdict(
                identity=_identity(),
                producer="asan",
                verdict="no-evidence",
                evidence_level=EvidenceLevel.D2,
                evidence_polarity=None,
            )

    def test_support_without_level_rejected(self):
        with self.assertRaises(ValueError):
            BrokerVerdict(
                identity=_identity(),
                producer="asan",
                verdict="support",
                evidence_level=None,
                evidence_polarity=EvidencePolarity.SUPPORTS,
            )

    def test_non_identity_rejected(self):
        with self.assertRaises(ValueError):
            BrokerVerdict(
                identity="cand-0001",
                producer="asan",
                verdict="no-evidence",
                evidence_level=None,
                evidence_polarity=None,
            )


class BrokerInputValidationTests(unittest.TestCase):
    """broker_verdict is fail-closed about its own inputs."""

    def test_non_identity_rejected(self):
        with self.assertRaises(ValueError):
            broker_verdict("identity", "asan", (), frozenset(), _proof())

    def test_empty_producer_rejected(self):
        with self.assertRaises(ValueError):
            broker_verdict(_identity(), "", (), frozenset(), _proof())

    def test_non_evidence_record_rejected(self):
        with self.assertRaises(ValueError):
            broker_verdict(
                _identity(), "asan", ("junk",), frozenset({"run-1"}), _proof()
            )

    def test_completed_run_ids_must_be_a_set(self):
        # A plain set works (FactBundleExpectation precedent); sequences
        # and strings do not.
        broker_verdict(_identity(), "asan", (), {"run-1"}, _proof())
        with self.assertRaises(ValueError):
            broker_verdict(_identity(), "asan", (), ["run-1"], _proof())
        with self.assertRaises(ValueError):
            broker_verdict(_identity(), "asan", (), "run-1", _proof())

    def test_wrong_proof_result_type_rejected(self):
        with self.assertRaises(ValueError):
            broker_verdict(_identity(), "asan", (), frozenset(), "proof")


class CrossSnapshotIdentityTests(unittest.TestCase):
    """Identity is the full (snapshot_hash, candidate_id) pair, always."""

    def test_same_candidate_id_different_snapshot_identities_differ(self):
        identity_a = _identity(snapshot_hash="2" * 64, candidate_id="1" * 64)
        identity_b = _identity(snapshot_hash="3" * 64, candidate_id="1" * 64)
        self.assertNotEqual(identity_a, identity_b)
        self.assertNotEqual(identity_a.as_key(), identity_b.as_key())

    def test_verdicts_are_parameterized_by_their_own_identity(self):
        records = (_record(),)
        runs = frozenset({"run-1"})
        identity_a = _identity(snapshot_hash="2" * 64)
        identity_b = _identity(snapshot_hash="3" * 64)
        verdict_a = broker_verdict(identity_a, "semgrep", records, runs, _proof())
        verdict_b = broker_verdict(identity_b, "semgrep", records, runs, _proof())
        # Same evidence behaves the same for both identities...
        self.assertEqual(verdict_a.verdict, verdict_b.verdict)
        self.assertEqual(verdict_a.evidence_level, verdict_b.evidence_level)
        # ...but each verdict carries exactly its own identity, never the
        # bare candidate_id, so cross-snapshot results cannot collapse.
        self.assertEqual(identity_a, verdict_a.identity)
        self.assertEqual(identity_b, verdict_b.identity)
        self.assertNotEqual(verdict_a, verdict_b)
        self.assertNotEqual(
            verdict_a.to_dict()["snapshot_hash"],
            verdict_b.to_dict()["snapshot_hash"],
        )
        self.assertEqual(
            verdict_a.to_dict()["candidate_id"],
            verdict_b.to_dict()["candidate_id"],
        )

    def test_identity_without_evidence_stays_no_evidence(self):
        ran_snapshot = _identity(snapshot_hash="2" * 64)
        fresh_snapshot = _identity(snapshot_hash="3" * 64)
        proven = broker_verdict(
            ran_snapshot, "semgrep", (_record(),), frozenset({"run-1"}), _proof()
        )
        self.assertEqual("support", proven.verdict)
        # The same candidate_id on a snapshot whose producer never ran is
        # no-evidence: the bare candidate_id is never a run identity.
        fresh = broker_verdict(fresh_snapshot, "semgrep", (), frozenset(), _proof())
        self.assertEqual("no-evidence", fresh.verdict)
        self.assertEqual(fresh_snapshot, fresh.identity)


if __name__ == "__main__":
    unittest.main()
