"""Deterministic repair verification report domain tests (IP-0006 packet sections 10-14, 17)."""

import unittest
from pathlib import Path

from lima.contracts.codec import (
    canonical_decode,
    canonical_encode,
    compute_content_digest,
)
from lima.contracts.common import SchemaVersion
from lima.contracts.errors import ContractError, ContractErrorCode
from lima.contracts.rvr import (
    CandidateVerdict,
    CandidateVerification,
    GateKind,
    GateOutcome,
    GateResult,
    RepairVerificationReport,
    VepReference,
    decode_rvr_payload,
    encode_rvr_payload,
)

VERSION_4_0 = SchemaVersion(4, 0)
VERSION_4_2 = SchemaVersion(4, 2)
FIXTURE = (
    Path(__file__).resolve().parent
    / "fixtures"
    / "repair_verification_report_v4_golden.json"
)
GOLDEN_PAYLOAD_DIGEST = (
    "a9a35d358308a2957b9182d2ca5e503903d8c7282c6c43bb09d1680313cb2cac"
)
VEP_GOLDEN_DIGEST = (
    "cd76622b48d11c0300e63d7489701479c75dc2f4b06cc6c4e88af1f453061d01"
)
FORBIDDEN_BYPASS_KEYS = frozenset(
    {"confidence", "severity", "risk_score", "is_fixed", "vulnerability_resolved",
     "safe", "clear"}
)


def _gate_wire(gate="functional_preservation", outcome="pass",
               producer="lima-repair-verifier-2", evidence=("diff-0001",),
               detail="Gate detail."):
    return {
        "gate": gate,
        "outcome": outcome,
        "producer": producer,
        "evidence_artifact_ids": sorted(evidence),
        "detail": detail,
    }


def _candidate_wire(cid="candidate-0001", patch_id="patch-0001", patch_digest="1" * 64,
                    files=("src/example.py",), gates=None, verdict="verified_patch",
                    generator="lima-repair-generator", strategy="Strategy."):
    return {
        "candidate_id": cid,
        "patch": {"patch_artifact_id": patch_id, "content_digest": patch_digest},
        "strategy": strategy,
        "changed_files": sorted(files),
        "generator": generator,
        "gates": gates
        if gates is not None
        else [
            _gate_wire("functional_preservation", "pass"),
            _gate_wire("security_preservation", "pass",
                       producer="lima-repair-verifier-1",
                       evidence=("sec-oracle-0001",)),
        ],
        "verdict": verdict,
    }


def _report_wire(candidates=None):
    return {
        "source_vep": {
            "artifact_id": "vep-0001",
            "content_digest": VEP_GOLDEN_DIGEST,
            "schema_version": "4.0",
        },
        "candidates": candidates if candidates is not None else [_candidate_wire()],
    }


def _vep_ref():
    return VepReference(
        artifact_id="vep-0001",
        content_digest=VEP_GOLDEN_DIGEST,
        schema_version=VERSION_4_0,
    )


def _gate(gate=GateKind.FUNCTIONAL_PRESERVATION, outcome=GateOutcome.PASS,
          producer="lima-repair-verifier-2", evidence=("diff-0001",),
          detail="Gate detail."):
    return GateResult(
        gate=gate,
        outcome=outcome,
        producer=producer,
        evidence_artifact_ids=tuple(sorted(evidence)),
        detail=detail,
    )


def _candidate(cid="candidate-0001", patch_id="patch-0001", patch_digest="1" * 64,
               files=("src/example.py",), gates=None,
               verdict=CandidateVerdict.VERIFIED_PATCH,
               generator="lima-repair-generator", strategy="Strategy."):
    return CandidateVerification(
        candidate_id=cid,
        patch=_patch_ref(patch_id, patch_digest),
        strategy=strategy,
        changed_files=tuple(sorted(files)),
        generator=generator,
        gates=gates
        if gates is not None
        else (
            _gate(),
            _gate(gate=GateKind.SECURITY_PRESERVATION, producer="lima-repair-verifier-1",
                  evidence=("sec-oracle-0001",)),
        ),
        verdict=verdict,
    )


def _patch_ref(patch_id="patch-0001", patch_digest="1" * 64):
    from lima.contracts.rvr import PatchReference

    return PatchReference(
        patch_artifact_id=patch_id,
        content_digest=patch_digest,
    )


class RvrContractTestCase(unittest.TestCase):
    def assert_rejected(self, invoke, code, field_path=None):
        with self.assertRaises(ContractError) as ctx:
            invoke()
        self.assertIs(ctx.exception.code, code)
        if field_path is not None:
            self.assertEqual(ctx.exception.field_path, field_path)
        return ctx.exception


class RvrEnumTests(RvrContractTestCase):
    def test_wire_values_are_exact(self):
        self.assertEqual(
            sorted(member.value for member in GateKind),
            ["functional_preservation", "security_preservation"],
        )
        self.assertEqual(len(GateKind), 2)
        self.assertEqual(
            sorted(member.value for member in GateOutcome),
            ["blocked", "failed", "inconclusive", "pass", "policy_denied",
             "tool_error"],
        )
        self.assertEqual(len(GateOutcome), 6)
        self.assertEqual(
            sorted(member.value for member in CandidateVerdict),
            ["inconclusive", "rejected", "verified_patch"],
        )
        self.assertEqual(len(CandidateVerdict), 3)
        for value in ("safe", "clear", "not_vulnerable", "vulnerability_resolved"):
            self.assertNotIn(
                value, {member.value for member in CandidateVerdict}
            )


class VepReferenceTests(RvrContractTestCase):
    def test_round_trip_has_exact_wire_shape(self):
        reference = _vep_ref()
        wire = {
            "artifact_id": "vep-0001",
            "content_digest": VEP_GOLDEN_DIGEST,
            "schema_version": "4.0",
        }
        self.assertEqual(reference.to_dict(), wire)
        decoded = VepReference.from_dict(wire, schema_version=VERSION_4_0)
        self.assertEqual(decoded, reference)
        self.assertEqual(decoded.to_dict(), wire)

    def test_rejects_missing_invalid_and_mismatched_fields(self):
        missing = {"artifact_id": "vep-0001", "content_digest": VEP_GOLDEN_DIGEST,
                   "schema_version": "4.0"}
        del missing["artifact_id"]
        self.assert_rejected(
            lambda: VepReference.from_dict(missing, schema_version=VERSION_4_0),
            ContractErrorCode.REQUIRED_FIELD_MISSING,
            "$.artifact_id",
        )
        bad_digest = {"artifact_id": "vep-0001", "content_digest": "NOTHEX",
                      "schema_version": "4.0"}
        self.assert_rejected(
            lambda: VepReference.from_dict(bad_digest, schema_version=VERSION_4_0),
            ContractErrorCode.INVALID_FIELD_VALUE,
            "$.content_digest",
        )
        unknown_major = {"artifact_id": "vep-0001", "content_digest": VEP_GOLDEN_DIGEST,
                         "schema_version": "5.0"}
        self.assert_rejected(
            lambda: VepReference.from_dict(unknown_major, schema_version=VERSION_4_0),
            ContractErrorCode.SCHEMA_UNKNOWN_MAJOR,
        )


class GateResultTests(RvrContractTestCase):
    def test_round_trip_has_exact_wire_shape(self):
        result = _gate(evidence=("diff-0001", "test-run-0001"))
        wire = {
            "gate": "functional_preservation",
            "outcome": "pass",
            "producer": "lima-repair-verifier-2",
            "evidence_artifact_ids": ["diff-0001", "test-run-0001"],
            "detail": "Gate detail.",
        }
        self.assertEqual(result.to_dict(), wire)
        decoded = GateResult.from_dict(wire, schema_version=VERSION_4_0)
        self.assertEqual(decoded, result)
        self.assertEqual(decoded.to_dict(), wire)

    def test_rejects_unknown_gate_outcome_and_missing_fields(self):
        unknown = _gate_wire(outcome="crashed")
        self.assert_rejected(
            lambda: GateResult.from_dict(unknown, schema_version=VERSION_4_0),
            ContractErrorCode.UNKNOWN_ENUM_VALUE,
            "$.outcome",
        )
        unknown_gate = _gate_wire(gate="lint")
        self.assert_rejected(
            lambda: GateResult.from_dict(unknown_gate, schema_version=VERSION_4_0),
            ContractErrorCode.UNKNOWN_ENUM_VALUE,
            "$.gate",
        )
        missing = _gate_wire()
        del missing["producer"]
        self.assert_rejected(
            lambda: GateResult.from_dict(missing, schema_version=VERSION_4_0),
            ContractErrorCode.REQUIRED_FIELD_MISSING,
            "$.producer",
        )

    def test_rejects_empty_evidence_provenance(self):
        no_evidence = _gate_wire(evidence=())
        self.assert_rejected(
            lambda: GateResult.from_dict(no_evidence, schema_version=VERSION_4_0),
            ContractErrorCode.INVALID_FIELD_VALUE,
            "$.evidence_artifact_ids",
        )
        unsorted_evidence = dict(
            _gate_wire(), evidence_artifact_ids=["test-run-0001", "diff-0001"]
        )
        self.assert_rejected(
            lambda: GateResult.from_dict(unsorted_evidence, schema_version=VERSION_4_0),
            ContractErrorCode.INVALID_FIELD_VALUE,
        )

    def test_rejects_oversize_detail(self):
        oversize = _gate_wire(detail="x" * 4097)
        self.assert_rejected(
            lambda: GateResult.from_dict(oversize, schema_version=VERSION_4_0),
            ContractErrorCode.MAX_STRING_LENGTH_EXCEEDED,
            "$.detail",
        )


class CandidateVerificationTests(RvrContractTestCase):
    def test_round_trip_has_exact_wire_shape(self):
        candidate = _candidate()
        wire = _candidate_wire()
        self.assertEqual(candidate.to_dict(), wire)
        decoded = CandidateVerification.from_dict(wire, schema_version=VERSION_4_0)
        self.assertEqual(decoded, candidate)
        self.assertEqual(decoded.to_dict(), wire)

    def test_rejects_invalid_changed_files_paths(self):
        for bad_files in (("src/",), ("/abs",), ("../up",), ("src\\x",)):
            payload = _report_wire(candidates=[_candidate_wire(files=bad_files)])
            self.assert_rejected(
                lambda p=payload: decode_rvr_payload(p, schema_version=VERSION_4_0),
                ContractErrorCode.INVALID_FIELD_VALUE,
            )
        unsorted = _report_wire(
            candidates=[
                dict(
                    _candidate_wire(),
                    changed_files=["src/example.py", "src/cli.py"],
                )
            ]
        )
        self.assert_rejected(
            lambda: decode_rvr_payload(unsorted, schema_version=VERSION_4_0),
            ContractErrorCode.INVALID_FIELD_VALUE,
        )
        oversize = _report_wire(
            candidates=[
                _candidate_wire(files=tuple(f"src/f{i:04d}.py" for i in range(1025)))
            ]
        )
        self.assert_rejected(
            lambda: decode_rvr_payload(oversize, schema_version=VERSION_4_0),
            ContractErrorCode.MAX_ARRAY_LENGTH_EXCEEDED,
        )

    def test_mandatory_gates_present_exactly_once(self):
        missing_gate = _report_wire(
            candidates=[_candidate_wire(gates=[_gate_wire("functional_preservation", "pass")])]
        )
        self.assert_rejected(
            lambda: decode_rvr_payload(missing_gate, schema_version=VERSION_4_0),
            ContractErrorCode.INVALID_FIELD_VALUE,
            "$.candidates[0].gates",
        )
        duplicated = _report_wire(
            candidates=[
                _candidate_wire(gates=[
                    _gate_wire("functional_preservation", "pass"),
                    _gate_wire("functional_preservation", "pass"),
                ])
            ]
        )
        self.assert_rejected(
            lambda: decode_rvr_payload(duplicated, schema_version=VERSION_4_0),
            ContractErrorCode.INVALID_FIELD_VALUE,
            "$.candidates[0].gates",
        )

    def test_verdict_matrix_all_pass_implies_verified_patch_only(self):
        wrong = _report_wire(
            candidates=[_candidate_wire(verdict="rejected")]
        )
        self.assert_rejected(
            lambda: decode_rvr_payload(wrong, schema_version=VERSION_4_0),
            ContractErrorCode.INVALID_FIELD_VALUE,
            "$.candidates[0].verdict",
        )
        wrong_inconclusive = _report_wire(
            candidates=[_candidate_wire(verdict="inconclusive")]
        )
        self.assert_rejected(
            lambda: decode_rvr_payload(wrong_inconclusive, schema_version=VERSION_4_0),
            ContractErrorCode.INVALID_FIELD_VALUE,
            "$.candidates[0].verdict",
        )
        package = decode_rvr_payload(_report_wire(), schema_version=VERSION_4_0)
        self.assertIs(package.candidates[0].verdict, CandidateVerdict.VERIFIED_PATCH)

    def test_any_failed_gate_implies_rejected_only(self):
        failed = [
            _gate_wire("functional_preservation", "pass"),
            _gate_wire("security_preservation", "failed",
                       producer="lima-repair-verifier-3",
                       evidence=("sec-oracle-0002",), detail="PoC still triggers."),
        ]
        for verdict in ("verified_patch", "inconclusive"):
            payload = _report_wire(
                candidates=[_candidate_wire(verdict=verdict, gates=failed)]
            )
            self.assert_rejected(
                lambda p=payload: decode_rvr_payload(p, schema_version=VERSION_4_0),
                ContractErrorCode.INVALID_FIELD_VALUE,
                "$.candidates[0].verdict",
            )
        payload = _report_wire(
            candidates=[_candidate_wire(verdict="rejected", gates=failed)]
        )
        package = decode_rvr_payload(payload, schema_version=VERSION_4_0)
        self.assertIs(package.candidates[0].verdict, CandidateVerdict.REJECTED)

    def test_blocked_tool_error_policy_denied_and_inconclusive_imply_inconclusive_only(self):
        for outcome in ("blocked", "tool_error", "policy_denied", "inconclusive"):
            gates = [
                _gate_wire("functional_preservation", "pass"),
                _gate_wire("security_preservation", outcome,
                           evidence=("sec-oracle-0001",), detail="Incomplete."),
            ]
            for verdict in ("verified_patch", "rejected"):
                payload = _report_wire(
                    candidates=[_candidate_wire(verdict=verdict, gates=gates)]
                )
                self.assert_rejected(
                    lambda p=payload: decode_rvr_payload(p, schema_version=VERSION_4_0),
                    ContractErrorCode.INVALID_FIELD_VALUE,
                    "$.candidates[0].verdict",
                )
            payload = _report_wire(
                candidates=[_candidate_wire(verdict="inconclusive", gates=gates)]
            )
            package = decode_rvr_payload(payload, schema_version=VERSION_4_0)
            self.assertIs(package.candidates[0].verdict, CandidateVerdict.INCONCLUSIVE)

    def test_generator_may_not_verify_own_candidate(self):
        self_verified = [
            _gate_wire("functional_preservation", "pass",
                       producer="lima-repair-generator"),
            _gate_wire("security_preservation", "pass",
                       producer="lima-repair-verifier-1",
                       evidence=("sec-oracle-0001",)),
        ]
        payload = _report_wire(candidates=[_candidate_wire(gates=self_verified)])
        error = self.assert_rejected(
            lambda: decode_rvr_payload(payload, schema_version=VERSION_4_0),
            ContractErrorCode.INVALID_FIELD_VALUE,
        )
        self.assertTrue(
            error.field_path.startswith("$.candidates[0].gates["), error.field_path
        )

    def test_strategy_and_generator_validation(self):
        payload = _report_wire(candidates=[_candidate_wire(strategy="x" * 513)])
        self.assert_rejected(
            lambda: decode_rvr_payload(payload, schema_version=VERSION_4_0),
            ContractErrorCode.MAX_STRING_LENGTH_EXCEEDED,
        )
        payload = _report_wire(candidates=[_candidate_wire(generator="bad id!")])
        self.assert_rejected(
            lambda: decode_rvr_payload(payload, schema_version=VERSION_4_0),
            ContractErrorCode.INVALID_FIELD_VALUE,
        )
        payload = _report_wire(candidates=[_candidate_wire(generator="lima-repair-gen")])
        package = decode_rvr_payload(payload, schema_version=VERSION_4_0)
        self.assertEqual(package.candidates[0].generator, "lima-repair-gen")


class RepairVerificationReportTests(RvrContractTestCase):
    def test_minimal_empty_report_round_trip_is_valid(self):
        payload = _report_wire(candidates=[])
        report = decode_rvr_payload(payload, schema_version=VERSION_4_0)
        self.assertEqual(report.to_dict(), payload)
        self.assertEqual(encode_rvr_payload(report), payload)
        rebuilt = RepairVerificationReport(
            schema_version=VERSION_4_0,
            source_vep=_vep_ref(),
            candidates=(),
        )
        self.assertEqual(rebuilt.to_dict(), payload)

    def test_golden_report_round_trip_and_digest(self):
        raw = FIXTURE.read_bytes()
        self.assertEqual(len(raw), 1709)
        payload = canonical_decode(raw)
        report = decode_rvr_payload(payload, schema_version=VERSION_4_0)
        self.assertEqual(report.to_dict(), payload)
        self.assertEqual(compute_content_digest(payload), GOLDEN_PAYLOAD_DIGEST)
        self.assertEqual(canonical_encode(encode_rvr_payload(report)), raw)
        self.assertEqual(report.source_vep.content_digest, VEP_GOLDEN_DIGEST)
        self.assertEqual(len(report.candidates), 2)
        self.assertIs(report.candidates[0].verdict, CandidateVerdict.VERIFIED_PATCH)
        self.assertIs(report.candidates[1].verdict, CandidateVerdict.REJECTED)

    def test_rejects_wrong_container_and_missing_required_fields(self):
        self.assert_rejected(
            lambda: decode_rvr_payload(["not", "an", "object"], schema_version=VERSION_4_0),
            ContractErrorCode.INVALID_FIELD_TYPE,
            "$",
        )
        for missing in ("source_vep", "candidates"):
            data = _report_wire()
            del data[missing]
            self.assert_rejected(
                lambda d=data: decode_rvr_payload(d, schema_version=VERSION_4_0),
                ContractErrorCode.REQUIRED_FIELD_MISSING,
                f"$.{missing}",
            )

    def test_rejects_unknown_enum_and_wrong_field_type(self):
        self.assert_rejected(
            lambda: decode_rvr_payload(
                _report_wire(candidates=[_candidate_wire(verdict="safe")]),
                schema_version=VERSION_4_0,
            ),
            ContractErrorCode.UNKNOWN_ENUM_VALUE,
            "$.candidates[0].verdict",
        )
        self.assert_rejected(
            lambda: decode_rvr_payload(
                dict(_report_wire(), source_vep=[]), schema_version=VERSION_4_0
            ),
            ContractErrorCode.INVALID_FIELD_TYPE,
            "$.source_vep",
        )
        self.assert_rejected(
            lambda: decode_rvr_payload(
                dict(_report_wire(), candidates="nope"), schema_version=VERSION_4_0
            ),
            ContractErrorCode.INVALID_FIELD_TYPE,
            "$.candidates",
        )

    def test_rejects_unsorted_duplicate_and_oversize_candidates(self):
        two = [_candidate_wire(), _candidate_wire(cid="candidate-0002", patch_id="patch-0002",
                                                   patch_digest="2" * 64, verdict="rejected",
                                                   gates=[
                                                       _gate_wire(
                                                           "functional_preservation", "pass"
                                                       ),
                                                       _gate_wire("security_preservation", "failed",
                                                                  producer="lima-repair-verifier-3",
                                                                  evidence=("sec-oracle-0002",),
                                                                  detail="x."),
                                                   ])]
        unsorted = _report_wire(candidates=list(reversed(two)))
        self.assert_rejected(
            lambda: decode_rvr_payload(unsorted, schema_version=VERSION_4_0),
            ContractErrorCode.INVALID_FIELD_VALUE,
        )
        duplicate = _report_wire(candidates=[_candidate_wire(), _candidate_wire(
            cid="candidate-0001", patch_id="patch-0002", patch_digest="2" * 64)])
        self.assert_rejected(
            lambda: decode_rvr_payload(duplicate, schema_version=VERSION_4_0),
            ContractErrorCode.INVALID_FIELD_VALUE,
        )
        oversize = _report_wire(
            candidates=[
                _candidate_wire(cid=f"candidate-{i:04d}", patch_id=f"patch-{i:04d}",
                                patch_digest=f"{i % 10}" * 64)
                for i in range(65)
            ]
        )
        self.assert_rejected(
            lambda: decode_rvr_payload(oversize, schema_version=VERSION_4_0),
            ContractErrorCode.MAX_ARRAY_LENGTH_EXCEEDED,
        )

    def test_patch_digests_unique_across_candidates(self):
        payload = _report_wire(candidates=[
            _candidate_wire(),
            _candidate_wire(cid="candidate-0002", verdict="rejected", gates=[
                _gate_wire("functional_preservation", "pass"),
                _gate_wire("security_preservation", "failed",
                           producer="lima-repair-verifier-3",
                           evidence=("sec-oracle-0002",), detail="x."),
            ]),
        ])
        error = self.assert_rejected(
            lambda: decode_rvr_payload(payload, schema_version=VERSION_4_0),
            ContractErrorCode.INVALID_FIELD_VALUE,
        )
        self.assertTrue(
            error.field_path.startswith("$.candidates[1].patch"), error.field_path
        )

    def test_candidate_failure_does_not_modify_vulnerability_status(self):
        payload = _report_wire(candidates=[
            _candidate_wire(cid="candidate-0001", verdict="rejected", gates=[
                _gate_wire("functional_preservation", "failed", detail="Tests failed."),
                _gate_wire("security_preservation", "pass",
                           producer="lima-repair-verifier-1",
                           evidence=("sec-oracle-0001",)),
            ]),
            _candidate_wire(cid="candidate-0002", patch_id="patch-0002",
                            patch_digest="2" * 64, verdict="rejected", gates=[
                _gate_wire("functional_preservation", "pass"),
                _gate_wire("security_preservation", "failed",
                           producer="lima-repair-verifier-3",
                           evidence=("sec-oracle-0002",), detail="x."),
            ]),
        ])
        report = decode_rvr_payload(payload, schema_version=VERSION_4_0)
        self.assertTrue(
            all(c.verdict is CandidateVerdict.REJECTED for c in report.candidates)
        )
        empty = decode_rvr_payload(_report_wire(candidates=[]), schema_version=VERSION_4_0)
        self.assertEqual(empty.candidates, ())

    def test_future_minor_round_trips_unknown_fields_at_every_level(self):
        payload = _report_wire(candidates=[])
        payload["future_top"] = 1
        payload["source_vep"]["future_vep"] = 2
        payload["candidates"] = [
            dict(_candidate_wire(), future_candidate=3,
                 patch=dict(_candidate_wire()["patch"], future_patch=4),
                 gates=[
                     dict(_gate_wire("functional_preservation", "pass"), future_gate=5),
                     dict(_gate_wire("security_preservation", "pass",
                                     producer="lima-repair-verifier-1",
                                     evidence=("sec-oracle-0001",)), future_gate=6),
                 ])
        ]
        report = decode_rvr_payload(payload, schema_version=VERSION_4_2)
        wire = report.to_dict()
        self.assertEqual(wire["future_top"], 1)
        self.assertEqual(wire["source_vep"]["future_vep"], 2)
        self.assertEqual(wire["candidates"][0]["future_candidate"], 3)
        self.assertEqual(wire["candidates"][0]["patch"]["future_patch"], 4)
        self.assertEqual(wire["candidates"][0]["gates"][0]["future_gate"], 5)
        self.assertEqual(wire["candidates"][0]["gates"][1]["future_gate"], 6)
        again = decode_rvr_payload(wire, schema_version=VERSION_4_2)
        self.assertEqual(again.to_dict(), wire)

    def test_current_minor_rejects_unknown_fields_at_every_level(self):
        def inject_top(data):
            data["future_top"] = 1

        def inject_vep(data):
            data["source_vep"]["future_vep"] = 2

        def inject_candidate(data):
            data["candidates"] = [dict(_candidate_wire(), future_candidate=3)]

        def inject_patch(data):
            data["candidates"] = [
                dict(_candidate_wire(),
                     patch=dict(_candidate_wire()["patch"], future_patch=4))
            ]

        def inject_gate(data):
            data["candidates"] = [
                dict(_candidate_wire(),
                     gates=[dict(g, future_gate=5) for g in _candidate_wire()["gates"]])
            ]

        for inject in (inject_top, inject_vep, inject_candidate, inject_patch, inject_gate):
            payload = _report_wire()
            inject(payload)
            self.assert_rejected(
                lambda p=payload: decode_rvr_payload(p, schema_version=VERSION_4_0),
                ContractErrorCode.UNKNOWN_FIELD,
            )

    def test_defensive_copy_prevents_post_construction_mutation(self):
        candidates = [_candidate()]
        gates = [
            _gate(),
            _gate(gate=GateKind.SECURITY_PRESERVATION, outcome=GateOutcome.FAILED,
                  producer="lima-repair-verifier-1", evidence=("sec-oracle-0002",)),
        ]
        extensions = {"future_key": "v"}
        report = RepairVerificationReport(
            schema_version=VERSION_4_2,
            source_vep=_vep_ref(),
            candidates=candidates
            + [_candidate(cid="candidate-0002", patch_id="patch-0002",
                          patch_digest="2" * 64, gates=gates,
                          verdict=CandidateVerdict.REJECTED)],
            extensions=extensions,
        )
        candidates.append(_candidate(cid="candidate-9999"))
        gates.append(_gate(gate=GateKind.SECURITY_PRESERVATION))
        extensions["future_key2"] = "v2"
        self.assertEqual(len(report.candidates), 2)
        self.assertEqual(len(report.candidates[1].gates), 2)
        self.assertEqual(report.extensions, {"future_key": "v"})
        wire = report.to_dict()
        wire["injected"] = True
        self.assertNotIn("injected", report.to_dict())

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
        scan(_report_wire())
        scan(_report_wire(candidates=[]))
        self.assertEqual(
            FORBIDDEN_BYPASS_KEYS,
            frozenset(
                {"confidence", "severity", "risk_score", "is_fixed",
                 "vulnerability_resolved", "safe", "clear"}
            ),
        )


if __name__ == "__main__":
    unittest.main()
