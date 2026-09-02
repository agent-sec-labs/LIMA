"""Deterministic vulnerability evidence package domain tests (IP-0005 packet sections 10-14, 17)."""

import unittest
from pathlib import Path

from lima.contracts.codec import (
    canonical_decode,
    canonical_encode,
    compute_content_digest,
)
from lima.contracts.common import SchemaVersion
from lima.contracts.errors import ContractError, ContractErrorCode
from lima.contracts.evidence import SourceLocation
from lima.contracts.vep import (
    AepReference,
    ClaimKind,
    OracleReference,
    ReproductionOutcome,
    ReproductionRun,
    VerificationVerdict,
    VulnerabilityEvidencePackage,
    decode_vep_payload,
    encode_vep_payload,
)

VERSION_4_0 = SchemaVersion(4, 0)
VERSION_4_2 = SchemaVersion(4, 2)
FIXTURE = (
    Path(__file__).resolve().parent
    / "fixtures"
    / "vulnerability_evidence_package_v4_golden.json"
)
GOLDEN_PAYLOAD_DIGEST = (
    "cd76622b48d11c0300e63d7489701479c75dc2f4b06cc6c4e88af1f453061d01"
)
AEP_GOLDEN_DIGEST = (
    "f0a985432ebd11dc4b85897653cf443dc2c0b0312e453424648ebc2d164705d0"
)
FORBIDDEN_BYPASS_KEYS = frozenset(
    {"confidence", "severity", "risk_score", "is_vulnerable", "safe", "clear"}
)


def _location():
    return {
        "path": "src/example.py",
        "start_line": 10,
        "end_line": 10,
        "start_column": 5,
        "end_column": 18,
        "symbol": "run_command",
    }


def _evidence(eid, level, polarity="supports", deps=(), sources=("run-0001",)):
    return {
        "evidence_id": eid,
        "subject_kind": "vulnerability_hypothesis",
        "subject_id": "hypothesis-0001",
        "level": level,
        "polarity": polarity,
        "analysis_family": "dynamic-validation",
        "producer": "lima-mining",
        "independence_key": f"mining:{eid}",
        "summary": f"Summary for {eid}.",
        "source_artifact_ids": sorted(sources),
        "reason_codes": ["RUNTIME_REPRODUCED"],
        "location": None,
        "depends_on_evidence_ids": list(deps),
    }


def _run(rid="run-0001", outcome="reproduced"):
    return {"run_artifact_id": rid, "outcome": outcome, "detail": f"Run {rid} detail."}


def _payload(**overrides):
    payload = {
        "verification_verdict": "verified",
        "claim_kind": "runtime_exploitability",
        "hypothesis_id": "hypothesis-0001",
        "source_aep": {
            "artifact_id": "aep-0001",
            "content_digest": AEP_GOLDEN_DIGEST,
            "schema_version": "4.0",
        },
        "source_aep_revision": 1,
        "oracle": {"oracle_artifact_id": "oracle-0001", "content_digest": "7" * 64},
        "evidence": [
            _evidence(
                "evidence-impact-0001",
                "D4",
                deps=["evidence-run-0001"],
                sources=("oracle-0001", "run-0001"),
            ),
            _evidence("evidence-run-0001", "D3"),
        ],
        "reproduction_runs": [_run()],
        "target_location": _location(),
        "path_locations": [_location()],
        "trigger_conditions": ["attacker controls the CLI argument"],
        "cwe_ids": ["CWE-78"],
        "impact": "Arbitrary command execution.",
        "refutation_scope": None,
    }
    payload.update(overrides)
    return payload


def _inconclusive_payload(**overrides):
    payload = _payload(
        verification_verdict="inconclusive",
        evidence=[],
        reproduction_runs=[_run(outcome="blocked")],
        impact=None,
    )
    payload.update(overrides)
    return payload


def _aep_ref():
    return AepReference(
        artifact_id="aep-0001",
        content_digest=AEP_GOLDEN_DIGEST,
        schema_version=VERSION_4_0,
    )


def _oracle_ref():
    return OracleReference(oracle_artifact_id="oracle-0001", content_digest="7" * 64)


def _target_location():
    return SourceLocation(
        path="src/example.py",
        start_line=10,
        end_line=10,
        start_column=5,
        end_column=18,
        symbol="run_command",
    )


class VepContractTestCase(unittest.TestCase):
    def assert_rejected(self, invoke, code, field_path=None):
        with self.assertRaises(ContractError) as ctx:
            invoke()
        self.assertIs(ctx.exception.code, code)
        if field_path is not None:
            self.assertEqual(ctx.exception.field_path, field_path)
        return ctx.exception


class VepEnumTests(VepContractTestCase):
    def test_wire_values_are_exact(self):
        self.assertEqual(
            sorted(member.value for member in ClaimKind),
            ["runtime_exploitability", "static_property"],
        )
        self.assertEqual(len(ClaimKind), 2)
        self.assertEqual(
            sorted(member.value for member in VerificationVerdict),
            ["candidate", "inconclusive", "refuted_scope", "verified"],
        )
        self.assertEqual(len(VerificationVerdict), 4)
        self.assertEqual(
            sorted(member.value for member in ReproductionOutcome),
            [
                "blocked",
                "inconclusive",
                "not_reproduced",
                "policy_denied",
                "reproduced",
                "tool_error",
            ],
        )
        self.assertEqual(len(ReproductionOutcome), 6)
        for value in ("safe", "clear", "not_vulnerable", "verified"):
            self.assertNotIn(value, {member.value for member in ReproductionOutcome})


class AepReferenceTests(VepContractTestCase):
    def test_round_trip_has_exact_wire_shape(self):
        reference = _aep_ref()
        wire = {
            "artifact_id": "aep-0001",
            "content_digest": AEP_GOLDEN_DIGEST,
            "schema_version": "4.0",
        }
        self.assertEqual(reference.to_dict(), wire)
        decoded = AepReference.from_dict(wire, schema_version=VERSION_4_0)
        self.assertEqual(decoded, reference)
        self.assertEqual(decoded.to_dict(), wire)

    def test_rejects_missing_invalid_and_mismatched_fields(self):
        missing = {"artifact_id": "aep-0001", "content_digest": AEP_GOLDEN_DIGEST,
                   "schema_version": "4.0"}
        del missing["artifact_id"]
        self.assert_rejected(
            lambda: AepReference.from_dict(missing, schema_version=VERSION_4_0),
            ContractErrorCode.REQUIRED_FIELD_MISSING,
            "$.artifact_id",
        )
        bad_digest = {"artifact_id": "aep-0001", "content_digest": "NOTHEX",
                      "schema_version": "4.0"}
        self.assert_rejected(
            lambda: AepReference.from_dict(bad_digest, schema_version=VERSION_4_0),
            ContractErrorCode.INVALID_FIELD_VALUE,
            "$.content_digest",
        )
        unknown_major = {"artifact_id": "aep-0001", "content_digest": AEP_GOLDEN_DIGEST,
                         "schema_version": "5.0"}
        self.assert_rejected(
            lambda: AepReference.from_dict(unknown_major, schema_version=VERSION_4_0),
            ContractErrorCode.SCHEMA_UNKNOWN_MAJOR,
        )


class OracleReferenceTests(VepContractTestCase):
    def test_round_trip_has_exact_wire_shape(self):
        reference = _oracle_ref()
        wire = {"oracle_artifact_id": "oracle-0001", "content_digest": "7" * 64}
        self.assertEqual(reference.to_dict(), wire)
        decoded = OracleReference.from_dict(wire, schema_version=VERSION_4_0)
        self.assertEqual(decoded, reference)
        self.assertEqual(decoded.to_dict(), wire)

    def test_rejects_missing_and_invalid_fields(self):
        missing = {"oracle_artifact_id": "oracle-0001", "content_digest": "7" * 64}
        del missing["oracle_artifact_id"]
        self.assert_rejected(
            lambda: OracleReference.from_dict(missing, schema_version=VERSION_4_0),
            ContractErrorCode.REQUIRED_FIELD_MISSING,
            "$.oracle_artifact_id",
        )
        uppercase = {"oracle_artifact_id": "oracle-0001", "content_digest": "7" * 63 + "A"}
        self.assert_rejected(
            lambda: OracleReference.from_dict(uppercase, schema_version=VERSION_4_0),
            ContractErrorCode.INVALID_FIELD_VALUE,
            "$.content_digest",
        )


class ReproductionRunTests(VepContractTestCase):
    def test_round_trip_has_exact_wire_shape(self):
        entry = ReproductionRun(
            run_artifact_id="run-0001",
            outcome=ReproductionOutcome.REPRODUCED,
            detail="Run run-0001 detail.",
        )
        wire = {
            "run_artifact_id": "run-0001",
            "outcome": "reproduced",
            "detail": "Run run-0001 detail.",
        }
        self.assertEqual(entry.to_dict(), wire)
        decoded = ReproductionRun.from_dict(wire, schema_version=VERSION_4_0)
        self.assertEqual(decoded, entry)
        self.assertEqual(decoded.to_dict(), wire)

    def test_rejects_invalid_outcome_detail_and_missing_fields(self):
        unknown = _run(outcome="crashed")
        self.assert_rejected(
            lambda: ReproductionRun.from_dict(unknown, schema_version=VERSION_4_0),
            ContractErrorCode.UNKNOWN_ENUM_VALUE,
            "$.outcome",
        )
        empty_detail = _run()
        empty_detail["detail"] = ""
        self.assert_rejected(
            lambda: ReproductionRun.from_dict(empty_detail, schema_version=VERSION_4_0),
            ContractErrorCode.INVALID_FIELD_VALUE,
            "$.detail",
        )
        missing = _run()
        del missing["run_artifact_id"]
        self.assert_rejected(
            lambda: ReproductionRun.from_dict(missing, schema_version=VERSION_4_0),
            ContractErrorCode.REQUIRED_FIELD_MISSING,
            "$.run_artifact_id",
        )


class VulnerabilityEvidencePackageTests(VepContractTestCase):
    def test_minimal_inconclusive_package_round_trip_is_valid(self):
        payload = _inconclusive_payload()
        package = decode_vep_payload(payload, schema_version=VERSION_4_0)
        self.assertEqual(package.to_dict(), payload)
        self.assertEqual(encode_vep_payload(package), payload)
        rebuilt = VulnerabilityEvidencePackage(
            schema_version=VERSION_4_0,
            verification_verdict=VerificationVerdict.INCONCLUSIVE,
            claim_kind=ClaimKind.RUNTIME_EXPLOITABILITY,
            hypothesis_id="hypothesis-0001",
            source_aep=_aep_ref(),
            source_aep_revision=1,
            oracle=_oracle_ref(),
            evidence=(),
            target_location=_target_location(),
            impact=None,
            refutation_scope=None,
        )
        self.assertEqual(rebuilt.to_dict(), payload)

    def test_golden_package_round_trip_and_digest(self):
        raw = FIXTURE.read_bytes()
        self.assertEqual(len(raw), 2091)
        payload = canonical_decode(raw)
        package = decode_vep_payload(payload, schema_version=VERSION_4_0)
        self.assertEqual(package.to_dict(), payload)
        self.assertEqual(compute_content_digest(payload), GOLDEN_PAYLOAD_DIGEST)
        self.assertEqual(canonical_encode(encode_vep_payload(package)), raw)
        self.assertEqual(package.source_aep.content_digest, AEP_GOLDEN_DIGEST)

    def test_rejects_wrong_container_and_missing_required_fields(self):
        self.assert_rejected(
            lambda: decode_vep_payload(["not", "an", "object"], schema_version=VERSION_4_0),
            ContractErrorCode.INVALID_FIELD_TYPE,
            "$",
        )
        for missing in (
            "verification_verdict",
            "claim_kind",
            "hypothesis_id",
            "source_aep",
            "source_aep_revision",
            "oracle",
            "evidence",
            "reproduction_runs",
            "target_location",
            "path_locations",
            "trigger_conditions",
            "cwe_ids",
            "impact",
            "refutation_scope",
        ):
            data = _payload()
            del data[missing]
            self.assert_rejected(
                lambda d=data: decode_vep_payload(d, schema_version=VERSION_4_0),
                ContractErrorCode.REQUIRED_FIELD_MISSING,
                f"$.{missing}",
            )

    def test_rejects_unknown_enum_and_wrong_field_type(self):
        self.assert_rejected(
            lambda: decode_vep_payload(
                _payload(verification_verdict="safe"), schema_version=VERSION_4_0
            ),
            ContractErrorCode.UNKNOWN_ENUM_VALUE,
            "$.verification_verdict",
        )
        self.assert_rejected(
            lambda: decode_vep_payload(
                _payload(claim_kind=1), schema_version=VERSION_4_0
            ),
            ContractErrorCode.INVALID_FIELD_TYPE,
            "$.claim_kind",
        )
        self.assert_rejected(
            lambda: decode_vep_payload(
                _payload(source_aep_revision="1"), schema_version=VERSION_4_0
            ),
            ContractErrorCode.INVALID_FIELD_TYPE,
            "$.source_aep_revision",
        )
        self.assert_rejected(
            lambda: decode_vep_payload(
                _payload(source_aep=[]), schema_version=VERSION_4_0
            ),
            ContractErrorCode.INVALID_FIELD_TYPE,
            "$.source_aep",
        )
        self.assert_rejected(
            lambda: decode_vep_payload(
                _payload(impact=5), schema_version=VERSION_4_0
            ),
            ContractErrorCode.INVALID_FIELD_TYPE,
            "$.impact",
        )

    def test_rejects_static_evidence_levels(self):
        for level in ("D0", "D1", "D2"):
            error = self.assert_rejected(
                lambda lvl=level: decode_vep_payload(
                    _payload(evidence=[_evidence("evidence-run-0001", lvl)]),
                    schema_version=VERSION_4_0,
                ),
                ContractErrorCode.INVALID_FIELD_VALUE,
            )
            self.assertTrue(
                error.field_path.startswith("$.evidence[0].level"), error.field_path
            )

    def test_evidence_subject_must_match_hypothesis(self):
        wrong_kind = _evidence("evidence-run-0001", "D3")
        wrong_kind["subject_kind"] = "signal"
        self.assert_rejected(
            lambda: decode_vep_payload(
                _payload(evidence=[wrong_kind]), schema_version=VERSION_4_0
            ),
            ContractErrorCode.INVALID_FIELD_VALUE,
            "$.evidence[0].subject_kind",
        )
        wrong_subject = _evidence("evidence-run-0001", "D3")
        wrong_subject["subject_id"] = "signal-0001"
        self.assert_rejected(
            lambda: decode_vep_payload(
                _payload(evidence=[wrong_subject]), schema_version=VERSION_4_0
            ),
            ContractErrorCode.INVALID_FIELD_VALUE,
            "$.evidence[0].subject_id",
        )

    def test_verified_runtime_requires_d3_and_d4_supports_impact_and_reproduced_run(self):
        d4_only = [_evidence("evidence-impact-0001", "D4", sources=("oracle-0001",))]
        self.assert_rejected(
            lambda: decode_vep_payload(_payload(evidence=d4_only), schema_version=VERSION_4_0),
            ContractErrorCode.INVALID_FIELD_VALUE,
            "$.verification_verdict",
        )
        d3_only = [_evidence("evidence-run-0001", "D3")]
        self.assert_rejected(
            lambda: decode_vep_payload(_payload(evidence=d3_only), schema_version=VERSION_4_0),
            ContractErrorCode.INVALID_FIELD_VALUE,
            "$.verification_verdict",
        )
        self.assert_rejected(
            lambda: decode_vep_payload(_payload(impact=None), schema_version=VERSION_4_0),
            ContractErrorCode.INVALID_FIELD_VALUE,
            "$.impact",
        )
        blocked_run = [_run(outcome="blocked")]
        self.assert_rejected(
            lambda: decode_vep_payload(
                _payload(reproduction_runs=blocked_run), schema_version=VERSION_4_0
            ),
            ContractErrorCode.INVALID_FIELD_VALUE,
            "$.reproduction_runs",
        )
        package = decode_vep_payload(_payload(), schema_version=VERSION_4_0)
        self.assertIs(package.verification_verdict, VerificationVerdict.VERIFIED)

    def test_verified_static_property_requires_only_d4(self):
        static = _payload(
            claim_kind="static_property",
            evidence=[_evidence("evidence-impact-0001", "D4", sources=("oracle-0001",))],
        )
        package = decode_vep_payload(static, schema_version=VERSION_4_0)
        self.assertIs(package.claim_kind, ClaimKind.STATIC_PROPERTY)
        self.assertIs(package.verification_verdict, VerificationVerdict.VERIFIED)
        static_d3 = _payload(
            claim_kind="static_property",
            evidence=[_evidence("evidence-run-0001", "D3")],
        )
        self.assert_rejected(
            lambda: decode_vep_payload(static_d3, schema_version=VERSION_4_0),
            ContractErrorCode.INVALID_FIELD_VALUE,
            "$.verification_verdict",
        )

    def test_refuted_scope_requires_refuting_evidence_and_scope_text(self):
        refuted = _payload(
            verification_verdict="refuted_scope",
            evidence=[_evidence("evidence-ref-0001", "D3", polarity="refutes")],
            impact=None,
            refutation_scope="Refuted for the declared CLI-only scope.",
        )
        package = decode_vep_payload(refuted, schema_version=VERSION_4_0)
        self.assertIs(package.verification_verdict, VerificationVerdict.REFUTED_SCOPE)
        no_refuting = _payload(
            verification_verdict="refuted_scope", refutation_scope="scope"
        )
        self.assert_rejected(
            lambda: decode_vep_payload(no_refuting, schema_version=VERSION_4_0),
            ContractErrorCode.INVALID_FIELD_VALUE,
            "$.verification_verdict",
        )
        no_scope_text = _payload(
            verification_verdict="refuted_scope",
            evidence=[_evidence("evidence-ref-0001", "D3", polarity="refutes")],
            impact=None,
        )
        self.assert_rejected(
            lambda: decode_vep_payload(no_scope_text, schema_version=VERSION_4_0),
            ContractErrorCode.INVALID_FIELD_VALUE,
            "$.refutation_scope",
        )

    def test_supports_and_refutes_conflict_requires_inconclusive(self):
        conflict = [
            _evidence(
                "evidence-impact-0001",
                "D4",
                deps=["evidence-run-0001"],
                sources=("oracle-0001", "run-0001"),
            ),
            _evidence("evidence-ref-0001", "D3", polarity="refutes"),
            _evidence("evidence-run-0001", "D3"),
        ]
        self.assert_rejected(
            lambda: decode_vep_payload(
                _payload(verification_verdict="candidate", evidence=conflict),
                schema_version=VERSION_4_0,
            ),
            ContractErrorCode.INVALID_FIELD_VALUE,
            "$.verification_verdict",
        )
        self.assert_rejected(
            lambda: decode_vep_payload(_payload(evidence=conflict), schema_version=VERSION_4_0),
            ContractErrorCode.INVALID_FIELD_VALUE,
            "$.verification_verdict",
        )
        package = decode_vep_payload(
            _payload(verification_verdict="inconclusive", evidence=conflict, impact=None),
            schema_version=VERSION_4_0,
        )
        self.assertIs(package.verification_verdict, VerificationVerdict.INCONCLUSIVE)
        d4_without_d3 = [_evidence("evidence-impact-0001", "D4", sources=("oracle-0001",))]
        self.assert_rejected(
            lambda: decode_vep_payload(
                _payload(verification_verdict="candidate", evidence=d4_without_d3),
                schema_version=VERSION_4_0,
            ),
            ContractErrorCode.INVALID_FIELD_VALUE,
            "$.verification_verdict",
        )

    def test_insufficient_evidence_forces_inconclusive_or_candidate(self):
        self.assert_rejected(
            lambda: decode_vep_payload(
                _payload(verification_verdict="candidate", evidence=[]),
                schema_version=VERSION_4_0,
            ),
            ContractErrorCode.INVALID_FIELD_VALUE,
            "$.verification_verdict",
        )
        package = decode_vep_payload(_inconclusive_payload(), schema_version=VERSION_4_0)
        self.assertIs(package.verification_verdict, VerificationVerdict.INCONCLUSIVE)
        candidate = _payload(
            verification_verdict="candidate",
            evidence=[_evidence("evidence-run-0001", "D3")],
            impact=None,
        )
        package = decode_vep_payload(candidate, schema_version=VERSION_4_0)
        self.assertIs(package.verification_verdict, VerificationVerdict.CANDIDATE)

    def test_oracle_reference_is_always_required(self):
        missing_oracle = _inconclusive_payload()
        del missing_oracle["oracle"]
        self.assert_rejected(
            lambda: decode_vep_payload(missing_oracle, schema_version=VERSION_4_0),
            ContractErrorCode.REQUIRED_FIELD_MISSING,
            "$.oracle",
        )

    def test_blocked_tool_error_and_policy_denied_never_yield_verdicts(self):
        failing_runs = [
            _run(rid="run-0001", outcome="blocked"),
            _run(rid="run-0002", outcome="tool_error"),
        ]
        for verdict in ("candidate", "refuted_scope", "verified"):
            self.assert_rejected(
                lambda v=verdict: decode_vep_payload(
                    _payload(
                        verification_verdict=v,
                        evidence=[],
                        reproduction_runs=failing_runs,
                        impact=None,
                        refutation_scope="scope" if v == "refuted_scope" else None,
                    ),
                    schema_version=VERSION_4_0,
                ),
                ContractErrorCode.INVALID_FIELD_VALUE,
                "$.verification_verdict",
            )
        package = decode_vep_payload(
            _payload(
                verification_verdict="inconclusive",
                evidence=[],
                reproduction_runs=failing_runs,
                impact=None,
            ),
            schema_version=VERSION_4_0,
        )
        self.assertIs(package.reproduction_runs[0].outcome, ReproductionOutcome.BLOCKED)
        self.assertIs(package.reproduction_runs[1].outcome, ReproductionOutcome.TOOL_ERROR)

    def test_rejects_unsorted_duplicate_and_oversize_arrays(self):
        unsorted_evidence = [
            _evidence("evidence-run-0001", "D3"),
            _evidence("evidence-impact-0001", "D4", sources=("oracle-0001",)),
        ]
        self.assert_rejected(
            lambda: decode_vep_payload(
                _payload(evidence=unsorted_evidence), schema_version=VERSION_4_0
            ),
            ContractErrorCode.INVALID_FIELD_VALUE,
        )
        duplicate_runs = [_run(rid="run-0001"), _run(rid="run-0001")]
        self.assert_rejected(
            lambda: decode_vep_payload(
                _payload(reproduction_runs=duplicate_runs), schema_version=VERSION_4_0
            ),
            ContractErrorCode.INVALID_FIELD_VALUE,
        )
        oversize_evidence = [
            _evidence(f"evidence-e{index:04d}", "D3") for index in range(257)
        ]
        self.assert_rejected(
            lambda: decode_vep_payload(
                _payload(evidence=oversize_evidence), schema_version=VERSION_4_0
            ),
            ContractErrorCode.MAX_ARRAY_LENGTH_EXCEEDED,
        )
        oversize_runs = [_run(rid=f"run-{index:04d}") for index in range(65)]
        self.assert_rejected(
            lambda: decode_vep_payload(
                _payload(reproduction_runs=oversize_runs), schema_version=VERSION_4_0
            ),
            ContractErrorCode.MAX_ARRAY_LENGTH_EXCEEDED,
        )
        self.assert_rejected(
            lambda: decode_vep_payload(
                _payload(cwe_ids=["CWE-89", "CWE-78"]), schema_version=VERSION_4_0
            ),
            ContractErrorCode.INVALID_FIELD_VALUE,
        )

    def test_evidence_dependency_dag_enforced(self):
        dangling = [_evidence("evidence-a-0001", "D3", deps=["evidence-missing"])]
        self.assert_rejected(
            lambda: decode_vep_payload(
                _payload(evidence=dangling), schema_version=VERSION_4_0
            ),
            ContractErrorCode.INVALID_FIELD_VALUE,
        )
        self_dep = [_evidence("evidence-a-0001", "D3", deps=["evidence-a-0001"])]
        self.assert_rejected(
            lambda: decode_vep_payload(
                _payload(evidence=self_dep), schema_version=VERSION_4_0
            ),
            ContractErrorCode.INVALID_FIELD_VALUE,
        )
        cycle = [
            _evidence("evidence-a-0001", "D3", deps=["evidence-b-0001"]),
            _evidence("evidence-b-0001", "D3", deps=["evidence-a-0001"]),
        ]
        self.assert_rejected(
            lambda: decode_vep_payload(
                _payload(verification_verdict="candidate", evidence=cycle, impact=None),
                schema_version=VERSION_4_0,
            ),
            ContractErrorCode.INVALID_FIELD_VALUE,
        )
        inverted = [
            _evidence("evidence-a-0001", "D3", deps=["evidence-b-0001"]),
            _evidence("evidence-b-0001", "D4", sources=("oracle-0001",)),
        ]
        self.assert_rejected(
            lambda: decode_vep_payload(
                _payload(evidence=inverted), schema_version=VERSION_4_0
            ),
            ContractErrorCode.INVALID_FIELD_VALUE,
        )
        package = decode_vep_payload(_payload(), schema_version=VERSION_4_0)
        self.assertEqual(
            package.evidence[0].depends_on_evidence_ids, ("evidence-run-0001",)
        )

    def test_future_minor_round_trips_unknown_fields_at_every_level(self):
        payload = _inconclusive_payload()
        payload["future_top"] = 1
        payload["source_aep"]["future_aep"] = 2
        payload["oracle"]["future_oracle"] = 3
        payload["reproduction_runs"] = [
            dict(_run(outcome="blocked"), future_run=4)
        ]
        package = decode_vep_payload(payload, schema_version=VERSION_4_2)
        wire = package.to_dict()
        self.assertEqual(wire["future_top"], 1)
        self.assertEqual(wire["source_aep"]["future_aep"], 2)
        self.assertEqual(wire["oracle"]["future_oracle"], 3)
        self.assertEqual(wire["reproduction_runs"][0]["future_run"], 4)
        again = decode_vep_payload(wire, schema_version=VERSION_4_2)
        self.assertEqual(again.to_dict(), wire)

    def test_current_minor_rejects_unknown_fields_at_every_level(self):
        def inject_top(data):
            data["future_top"] = 1

        def inject_aep(data):
            data["source_aep"]["future_aep"] = 2

        def inject_oracle(data):
            data["oracle"]["future_oracle"] = 3

        def inject_run(data):
            data["reproduction_runs"] = [dict(_run(outcome="blocked"), future_run=4)]

        for inject in (inject_top, inject_aep, inject_oracle, inject_run):
            payload = _inconclusive_payload()
            inject(payload)
            self.assert_rejected(
                lambda p=payload: decode_vep_payload(p, schema_version=VERSION_4_0),
                ContractErrorCode.UNKNOWN_FIELD,
            )

    def test_defensive_copy_prevents_post_construction_mutation(self):
        evidence = [
            _evidence(
                "evidence-impact-0001",
                "D4",
                deps=["evidence-run-0001"],
                sources=("oracle-0001", "run-0001"),
            )
        ]
        runs = [ReproductionRun(
            run_artifact_id="run-0001",
            outcome=ReproductionOutcome.REPRODUCED,
            detail="Run run-0001 detail.",
        )]
        extensions = {"future_key": "v"}
        package = VulnerabilityEvidencePackage(
            schema_version=VERSION_4_2,
            verification_verdict=VerificationVerdict.VERIFIED,
            claim_kind=ClaimKind.RUNTIME_EXPLOITABILITY,
            hypothesis_id="hypothesis-0001",
            source_aep=_aep_ref(),
            source_aep_revision=1,
            oracle=_oracle_ref(),
            evidence=evidence
            + [_evidence("evidence-run-0001", "D3")],
            target_location=_target_location(),
            impact="Arbitrary command execution.",
            refutation_scope=None,
            path_locations=[_target_location()],
            reproduction_runs=runs,
            trigger_conditions=["attacker controls the CLI argument"],
            cwe_ids=["CWE-78"],
            extensions=extensions,
        )
        evidence.append(_evidence("evidence-zzz-0001", "D3"))
        runs.append(ReproductionRun(
            run_artifact_id="run-0002",
            outcome=ReproductionOutcome.BLOCKED,
            detail="extra",
        ))
        extensions["future_key2"] = "v2"
        self.assertEqual(len(package.evidence), 2)
        self.assertEqual(len(package.reproduction_runs), 1)
        self.assertEqual(package.extensions, {"future_key": "v"})
        wire = package.to_dict()
        wire["injected"] = True
        self.assertNotIn("injected", package.to_dict())

    def test_payload_has_no_confidence_severity_or_verdict_bypass_fields(self):
        def scan(node):
            if isinstance(node, dict):
                for key, value in node.items():
                    self.assertNotIn(key, FORBIDDEN_BYPASS_KEYS)
                    scan(value)
            elif isinstance(node, list):
                for item in node:
                    scan(item)

        scan(canonical_decode(FIXTURE.read_bytes()))
        scan(_payload())
        scan(_inconclusive_payload())
        self.assertEqual(
            FORBIDDEN_BYPASS_KEYS,
            frozenset(
                {"confidence", "severity", "risk_score", "is_vulnerable", "safe", "clear"}
            ),
        )


if __name__ == "__main__":
    unittest.main()
