"""Deterministic audit evidence package domain tests (IP-0004 packet sections 10-14, 17)."""

import copy
import unittest
from pathlib import Path

from lima.contracts.aep import (
    AuditBudget,
    AuditCoverage,
    AuditCoverageGap,
    AuditDepth,
    AuditEvidencePackage,
    AuditOutcome,
    AuditPackageStatus,
    decode_aep_payload,
    encode_aep_payload,
)
from lima.contracts.codec import (
    canonical_decode,
    canonical_encode,
    compute_content_digest,
)
from lima.contracts.common import SchemaVersion
from lima.contracts.errors import ContractError, ContractErrorCode
from lima.contracts.evidence import (
    EvidenceDomainBundle,
    decode_evidence_payload,
)

VERSION_4_0 = SchemaVersion(4, 0)
VERSION_4_2 = SchemaVersion(4, 2)
FIXTURE = (
    Path(__file__).resolve().parent / "fixtures" / "audit_evidence_package_v4_golden.json"
)
EVIDENCE_FIXTURE = (
    Path(__file__).resolve().parent / "fixtures" / "evidence_domain_bundle_v4_golden.json"
)
GOLDEN_PAYLOAD_DIGEST = (
    "f0a985432ebd11dc4b85897653cf443dc2c0b0312e453424648ebc2d164705d0"
)
FORBIDDEN_VERDICT_KEYS = frozenset(
    {"verified", "safe", "clear", "is_vulnerable", "confidence", "severity", "trust_score"}
)


def _empty_bundle():
    return {"signals": [], "security_issues": [], "vulnerability_hypotheses": [], "evidence": []}


def _supported_bundle():
    return canonical_decode(EVIDENCE_FIXTURE.read_bytes())


def _proposed_bundle():
    bundle = copy.deepcopy(_supported_bundle())
    bundle["evidence"][0]["level"] = "D1"
    bundle["vulnerability_hypotheses"][0]["status"] = "proposed"
    return bundle


def _two_supported_bundle():
    bundle = copy.deepcopy(_supported_bundle())
    bundle["vulnerability_hypotheses"].append(
        {
            "capability_requirements": ["python"],
            "claim": "A second CLI input path reaches the same process execution sink.",
            "critical_path": [],
            "cwe_ids": ["CWE-78"],
            "evidence_ids": ["evidence-hypothesis-0002"],
            "hypothesis_id": "hypothesis-0002",
            "input_constraints": [],
            "issue_id": "issue-0001",
            "reason_codes": ["STATIC_DATAFLOW_REACHES_PROCESS_SINK"],
            "required_proof_kind": "runtime_behavior",
            "security_invariant": (
                "Process arguments must not be interpreted by a command shell."
            ),
            "source_locations": [],
            "status": "statically_supported",
            "target_location": copy.deepcopy(
                bundle["vulnerability_hypotheses"][0]["target_location"]
            ),
            "trigger_conditions": [],
        }
    )
    second = copy.deepcopy(bundle["evidence"][0])
    second["evidence_id"] = "evidence-hypothesis-0002"
    second["subject_id"] = "hypothesis-0002"
    second["independence_key"] = "python-dataflow:cli-to-process-2"
    second["summary"] = "A second deterministic source-to-sink path reaches process execution."
    bundle["evidence"].insert(1, second)
    return bundle


def _package_dict(**overrides):
    payload = {
        "package_status": "sealed",
        "revision": 1,
        "audit_depth": "deep",
        "audit_outcome": "completed",
        "evidence_domain": _supported_bundle(),
        "repository_profile_artifact_ids": ["profile-0001"],
        "mining_eligible_hypothesis_ids": ["hypothesis-0001"],
        "coverage": {"in_scope_file_count": 42, "analyzed_file_count": 40},
        "coverage_gaps": [],
        "budget": {"tool_runs": 3, "model_calls": 1, "model_tokens": 12000, "wall_clock_ms": 45000},
    }
    payload.update(overrides)
    return payload


def _no_actionable_package_dict(**overrides):
    payload = _package_dict(
        package_status="draft",
        audit_depth="initial",
        audit_outcome="no_actionable_hypothesis",
        evidence_domain=_empty_bundle(),
        mining_eligible_hypothesis_ids=[],
        coverage={"in_scope_file_count": 0, "analyzed_file_count": 0},
        budget={"tool_runs": 0, "model_calls": 0, "model_tokens": 0, "wall_clock_ms": 0},
    )
    payload.update(overrides)
    return payload


def _coverage(in_scope=42, analyzed=40):
    return AuditCoverage(in_scope_file_count=in_scope, analyzed_file_count=analyzed)


def _budget(tool_runs=3, model_calls=1, model_tokens=12000, wall_clock_ms=45000):
    return AuditBudget(
        tool_runs=tool_runs,
        model_calls=model_calls,
        model_tokens=model_tokens,
        wall_clock_ms=wall_clock_ms,
    )


def _gap(gap_code="TIER0_FILE_BUDGET_EXCEEDED", detail="Two vendored files were skipped."):
    return AuditCoverageGap(gap_code=gap_code, detail=detail)


class AepContractTestCase(unittest.TestCase):
    def assert_rejected(self, invoke, code, field_path=None):
        with self.assertRaises(ContractError) as ctx:
            invoke()
        self.assertIs(ctx.exception.code, code)
        if field_path is not None:
            self.assertEqual(ctx.exception.field_path, field_path)
        return ctx.exception


class AepEnumTests(AepContractTestCase):
    def test_wire_values_are_exact(self):
        self.assertEqual(
            sorted(member.value for member in AuditPackageStatus), ["draft", "sealed"]
        )
        self.assertEqual(len(AuditPackageStatus), 2)
        self.assertEqual(sorted(member.value for member in AuditDepth), ["deep", "initial"])
        self.assertEqual(len(AuditDepth), 2)
        self.assertEqual(
            sorted(member.value for member in AuditOutcome),
            [
                "completed",
                "incomplete",
                "no_actionable_hypothesis",
                "no_supported_attack_surface",
            ],
        )
        self.assertEqual(len(AuditOutcome), 4)
        for value in ("verified", "safe", "clear", "vulnerable"):
            self.assertNotIn(value, {member.value for member in AuditOutcome})


class AuditCoverageTests(AepContractTestCase):
    def test_round_trip_has_exact_wire_shape(self):
        coverage = _coverage(in_scope=7, analyzed=5)
        wire = {"in_scope_file_count": 7, "analyzed_file_count": 5}
        self.assertEqual(coverage.to_dict(), wire)
        decoded = AuditCoverage.from_dict(wire, schema_version=VERSION_4_0)
        self.assertEqual(decoded, coverage)
        self.assertEqual(decoded.to_dict(), wire)

    def test_rejects_bool_negative_missing_and_impossible_counts(self):
        self.assert_rejected(
            lambda: AuditCoverage.from_dict(
                {"in_scope_file_count": 10, "analyzed_file_count": 11},
                schema_version=VERSION_4_0,
            ),
            ContractErrorCode.INVALID_FIELD_VALUE,
            "$.analyzed_file_count",
        )
        self.assert_rejected(
            lambda: AuditCoverage.from_dict(
                {"in_scope_file_count": True, "analyzed_file_count": 0},
                schema_version=VERSION_4_0,
            ),
            ContractErrorCode.INVALID_FIELD_TYPE,
            "$.in_scope_file_count",
        )
        self.assert_rejected(
            lambda: AuditCoverage.from_dict(
                {"in_scope_file_count": -1, "analyzed_file_count": 0},
                schema_version=VERSION_4_0,
            ),
            ContractErrorCode.INVALID_FIELD_VALUE,
            "$.in_scope_file_count",
        )
        missing = {"in_scope_file_count": 1, "analyzed_file_count": 1}
        del missing["analyzed_file_count"]
        self.assert_rejected(
            lambda: AuditCoverage.from_dict(missing, schema_version=VERSION_4_0),
            ContractErrorCode.REQUIRED_FIELD_MISSING,
            "$.analyzed_file_count",
        )


class AuditBudgetTests(AepContractTestCase):
    def test_round_trip_has_exact_wire_shape(self):
        budget = _budget(tool_runs=2, model_calls=0, model_tokens=0, wall_clock_ms=1500)
        wire = {
            "tool_runs": 2,
            "model_calls": 0,
            "model_tokens": 0,
            "wall_clock_ms": 1500,
        }
        self.assertEqual(budget.to_dict(), wire)
        decoded = AuditBudget.from_dict(wire, schema_version=VERSION_4_0)
        self.assertEqual(decoded, budget)
        self.assertEqual(decoded.to_dict(), wire)

    def test_rejects_bool_negative_and_missing_values(self):
        wire = _budget().to_dict()
        wire["tool_runs"] = -1
        self.assert_rejected(
            lambda: AuditBudget.from_dict(wire, schema_version=VERSION_4_0),
            ContractErrorCode.INVALID_FIELD_VALUE,
            "$.tool_runs",
        )
        wire = _budget().to_dict()
        wire["model_tokens"] = True
        self.assert_rejected(
            lambda: AuditBudget.from_dict(wire, schema_version=VERSION_4_0),
            ContractErrorCode.INVALID_FIELD_TYPE,
            "$.model_tokens",
        )
        wire = _budget().to_dict()
        del wire["wall_clock_ms"]
        self.assert_rejected(
            lambda: AuditBudget.from_dict(wire, schema_version=VERSION_4_0),
            ContractErrorCode.REQUIRED_FIELD_MISSING,
            "$.wall_clock_ms",
        )


class AuditCoverageGapTests(AepContractTestCase):
    def test_round_trip_has_exact_wire_shape(self):
        gap = _gap()
        wire = {
            "gap_code": "TIER0_FILE_BUDGET_EXCEEDED",
            "detail": "Two vendored files were skipped.",
        }
        self.assertEqual(gap.to_dict(), wire)
        decoded = AuditCoverageGap.from_dict(wire, schema_version=VERSION_4_0)
        self.assertEqual(decoded, gap)
        self.assertEqual(decoded.to_dict(), wire)

    def test_rejects_invalid_code_detail_and_oversize(self):
        self.assert_rejected(
            lambda: _gap(gap_code="tier0"),
            ContractErrorCode.INVALID_FIELD_VALUE,
            "$.gap_code",
        )
        self.assert_rejected(
            lambda: _gap(detail=""),
            ContractErrorCode.INVALID_FIELD_VALUE,
            "$.detail",
        )
        self.assert_rejected(
            lambda: _gap(detail="line\nbreak"),
            ContractErrorCode.INVALID_FIELD_VALUE,
            "$.detail",
        )
        self.assert_rejected(
            lambda: _gap(detail="x" * 4097),
            ContractErrorCode.MAX_STRING_LENGTH_EXCEEDED,
            "$.detail",
        )

    def test_rejects_unsorted_and_duplicate_gaps(self):
        unsorted_gaps = _no_actionable_package_dict(
            audit_outcome="incomplete",
            coverage_gaps=[
                {"gap_code": "B_GAP", "detail": "second"},
                {"gap_code": "A_GAP", "detail": "first"},
            ],
        )
        self.assert_rejected(
            lambda: decode_aep_payload(unsorted_gaps, schema_version=VERSION_4_0),
            ContractErrorCode.INVALID_FIELD_VALUE,
        )
        duplicate_gaps = _no_actionable_package_dict(
            audit_outcome="incomplete",
            coverage_gaps=[
                {"gap_code": "A_GAP", "detail": "same"},
                {"gap_code": "A_GAP", "detail": "same"},
            ],
        )
        self.assert_rejected(
            lambda: decode_aep_payload(duplicate_gaps, schema_version=VERSION_4_0),
            ContractErrorCode.INVALID_FIELD_VALUE,
        )


class AuditEvidencePackageTests(AepContractTestCase):
    def test_minimal_no_actionable_package_round_trip_is_valid(self):
        payload = _no_actionable_package_dict()
        package = decode_aep_payload(payload, schema_version=VERSION_4_0)
        self.assertEqual(package.to_dict(), payload)
        self.assertEqual(encode_aep_payload(package), payload)
        rebuilt = AuditEvidencePackage(
            schema_version=VERSION_4_0,
            package_status=AuditPackageStatus.DRAFT,
            revision=1,
            audit_depth=AuditDepth.INITIAL,
            audit_outcome=AuditOutcome.NO_ACTIONABLE_HYPOTHESIS,
            evidence=EvidenceDomainBundle(schema_version=VERSION_4_0),
            coverage=_coverage(in_scope=0, analyzed=0),
            budget=_budget(tool_runs=0, model_calls=0, model_tokens=0, wall_clock_ms=0),
            repository_profile_artifact_ids=("profile-0001",),
        )
        self.assertEqual(rebuilt.to_dict(), payload)

    def test_minimal_completed_package_round_trip_is_valid(self):
        payload = _package_dict()
        package = decode_aep_payload(payload, schema_version=VERSION_4_0)
        self.assertEqual(package.to_dict(), payload)
        self.assertIs(package.package_status, AuditPackageStatus.SEALED)
        self.assertIs(package.audit_depth, AuditDepth.DEEP)
        self.assertIs(package.audit_outcome, AuditOutcome.COMPLETED)
        self.assertEqual(
            package.evidence,
            decode_evidence_payload(_supported_bundle(), schema_version=VERSION_4_0),
        )

    def test_golden_package_round_trip_and_digest(self):
        raw = FIXTURE.read_bytes()
        self.assertEqual(len(raw), 4235)
        payload = canonical_decode(raw)
        package = decode_aep_payload(payload, schema_version=VERSION_4_0)
        self.assertEqual(package.to_dict(), payload)
        self.assertEqual(compute_content_digest(payload), GOLDEN_PAYLOAD_DIGEST)
        self.assertEqual(canonical_encode(encode_aep_payload(package)), raw)

    def test_rejects_wrong_container_and_missing_required_fields(self):
        self.assert_rejected(
            lambda: decode_aep_payload(["not", "an", "object"], schema_version=VERSION_4_0),
            ContractErrorCode.INVALID_FIELD_TYPE,
            "$",
        )
        for missing in (
            "package_status",
            "revision",
            "audit_depth",
            "audit_outcome",
            "evidence_domain",
            "repository_profile_artifact_ids",
            "mining_eligible_hypothesis_ids",
            "coverage",
            "coverage_gaps",
            "budget",
        ):
            data = _package_dict()
            del data[missing]
            self.assert_rejected(
                lambda d=data: decode_aep_payload(d, schema_version=VERSION_4_0),
                ContractErrorCode.REQUIRED_FIELD_MISSING,
                f"$.{missing}",
            )

    def test_rejects_unknown_enum_and_wrong_field_type(self):
        self.assert_rejected(
            lambda: decode_aep_payload(
                _package_dict(package_status="frozen"), schema_version=VERSION_4_0
            ),
            ContractErrorCode.UNKNOWN_ENUM_VALUE,
            "$.package_status",
        )
        self.assert_rejected(
            lambda: decode_aep_payload(
                _package_dict(audit_depth=3), schema_version=VERSION_4_0
            ),
            ContractErrorCode.INVALID_FIELD_TYPE,
            "$.audit_depth",
        )
        self.assert_rejected(
            lambda: decode_aep_payload(
                _package_dict(revision="1"), schema_version=VERSION_4_0
            ),
            ContractErrorCode.INVALID_FIELD_TYPE,
            "$.revision",
        )
        self.assert_rejected(
            lambda: decode_aep_payload(
                _package_dict(evidence_domain=[]), schema_version=VERSION_4_0
            ),
            ContractErrorCode.INVALID_FIELD_TYPE,
            "$.evidence_domain",
        )

    def test_rejects_revision_below_one_bool_and_out_of_range(self):
        self.assert_rejected(
            lambda: decode_aep_payload(
                _package_dict(revision=0), schema_version=VERSION_4_0
            ),
            ContractErrorCode.INVALID_FIELD_VALUE,
            "$.revision",
        )
        self.assert_rejected(
            lambda: decode_aep_payload(
                _package_dict(revision=True), schema_version=VERSION_4_0
            ),
            ContractErrorCode.INVALID_FIELD_TYPE,
            "$.revision",
        )
        self.assert_rejected(
            lambda: decode_aep_payload(
                _package_dict(revision=2**63), schema_version=VERSION_4_0
            ),
            ContractErrorCode.INVALID_FIELD_VALUE,
            "$.revision",
        )

    def test_embedded_evidence_bundle_is_validated(self):
        d3_bundle = copy.deepcopy(_supported_bundle())
        d3_bundle["evidence"][0]["level"] = "D3"
        error = self.assert_rejected(
            lambda: decode_aep_payload(
                _package_dict(evidence_domain=d3_bundle), schema_version=VERSION_4_0
            ),
            ContractErrorCode.INVALID_FIELD_VALUE,
        )
        self.assertTrue(
            error.field_path.startswith("$.evidence_domain.evidence[0].level"),
            error.field_path,
        )
        dangling = copy.deepcopy(_supported_bundle())
        dangling["evidence"][0]["subject_id"] = "hypothesis-9999"
        self.assert_rejected(
            lambda: decode_aep_payload(
                _package_dict(evidence_domain=dangling), schema_version=VERSION_4_0
            ),
            ContractErrorCode.INVALID_FIELD_VALUE,
        )

    def test_rejects_missing_and_non_statically_supported_eligible_hypotheses(self):
        self.assert_rejected(
            lambda: decode_aep_payload(
                _package_dict(mining_eligible_hypothesis_ids=["hypothesis-9999"]),
                schema_version=VERSION_4_0,
            ),
            ContractErrorCode.INVALID_FIELD_VALUE,
        )
        self.assert_rejected(
            lambda: decode_aep_payload(
                _package_dict(
                    evidence_domain=_proposed_bundle(),
                    audit_outcome="no_actionable_hypothesis",
                    mining_eligible_hypothesis_ids=["hypothesis-0001"],
                ),
                schema_version=VERSION_4_0,
            ),
            ContractErrorCode.INVALID_FIELD_VALUE,
        )

    def test_eligible_set_must_equal_full_statically_supported_set(self):
        hidden = _package_dict(
            evidence_domain=_two_supported_bundle(),
            mining_eligible_hypothesis_ids=["hypothesis-0001"],
        )
        self.assert_rejected(
            lambda: decode_aep_payload(hidden, schema_version=VERSION_4_0),
            ContractErrorCode.INVALID_FIELD_VALUE,
        )
        inflated = _package_dict(
            evidence_domain=_two_supported_bundle(),
            mining_eligible_hypothesis_ids=[
                "hypothesis-0001",
                "hypothesis-0002",
                "hypothesis-9999",
            ],
        )
        self.assert_rejected(
            lambda: decode_aep_payload(inflated, schema_version=VERSION_4_0),
            ContractErrorCode.INVALID_FIELD_VALUE,
        )
        exact = _package_dict(
            evidence_domain=_two_supported_bundle(),
            mining_eligible_hypothesis_ids=["hypothesis-0001", "hypothesis-0002"],
        )
        package = decode_aep_payload(exact, schema_version=VERSION_4_0)
        self.assertEqual(
            package.mining_eligible_hypothesis_ids, ("hypothesis-0001", "hypothesis-0002")
        )

    def test_audit_outcome_mapping_enforced(self):
        self.assert_rejected(
            lambda: decode_aep_payload(
                _no_actionable_package_dict(audit_outcome="completed"),
                schema_version=VERSION_4_0,
            ),
            ContractErrorCode.INVALID_FIELD_VALUE,
            "$.audit_outcome",
        )
        self.assert_rejected(
            lambda: decode_aep_payload(
                _package_dict(audit_outcome="no_actionable_hypothesis"),
                schema_version=VERSION_4_0,
            ),
            ContractErrorCode.INVALID_FIELD_VALUE,
            "$.audit_outcome",
        )
        self.assert_rejected(
            lambda: decode_aep_payload(
                _package_dict(audit_outcome="no_supported_attack_surface"),
                schema_version=VERSION_4_0,
            ),
            ContractErrorCode.INVALID_FIELD_VALUE,
            "$.audit_outcome",
        )
        incomplete = decode_aep_payload(
            _no_actionable_package_dict(
                audit_outcome="incomplete",
                coverage_gaps=[{"gap_code": "BUDGET_EXHAUSTED", "detail": "Budget spent."}],
            ),
            schema_version=VERSION_4_0,
        )
        self.assertIs(incomplete.audit_outcome, AuditOutcome.INCOMPLETE)
        self.assertEqual(len(incomplete.coverage_gaps), 1)

    def test_incomplete_outcome_requires_coverage_gaps(self):
        self.assert_rejected(
            lambda: decode_aep_payload(
                _no_actionable_package_dict(audit_outcome="incomplete"),
                schema_version=VERSION_4_0,
            ),
            ContractErrorCode.INVALID_FIELD_VALUE,
            "$.coverage_gaps",
        )

    def test_empty_bundle_is_not_a_safety_verdict(self):
        package = decode_aep_payload(
            _no_actionable_package_dict(audit_outcome="no_supported_attack_surface"),
            schema_version=VERSION_4_0,
        )
        self.assertIs(package.audit_outcome, AuditOutcome.NO_SUPPORTED_ATTACK_SURFACE)
        self.assertEqual(package.mining_eligible_hypothesis_ids, ())
        self.assertEqual(package.evidence.signals, ())

    def test_rejects_unsorted_duplicate_and_oversize_arrays(self):
        self.assert_rejected(
            lambda: decode_aep_payload(
                _package_dict(repository_profile_artifact_ids=[]), schema_version=VERSION_4_0
            ),
            ContractErrorCode.INVALID_FIELD_VALUE,
        )
        self.assert_rejected(
            lambda: decode_aep_payload(
                _package_dict(
                    repository_profile_artifact_ids=["profile-0002", "profile-0001"]
                ),
                schema_version=VERSION_4_0,
            ),
            ContractErrorCode.INVALID_FIELD_VALUE,
        )
        self.assert_rejected(
            lambda: decode_aep_payload(
                _package_dict(
                    mining_eligible_hypothesis_ids=["hypothesis-0001", "hypothesis-0001"]
                ),
                schema_version=VERSION_4_0,
            ),
            ContractErrorCode.INVALID_FIELD_VALUE,
        )
        oversize_profiles = _package_dict(
            repository_profile_artifact_ids=[
                f"profile-{index:04d}" for index in range(17)
            ]
        )
        self.assert_rejected(
            lambda: decode_aep_payload(oversize_profiles, schema_version=VERSION_4_0),
            ContractErrorCode.MAX_ARRAY_LENGTH_EXCEEDED,
        )
        oversize_gaps = _no_actionable_package_dict(
            audit_outcome="incomplete",
            coverage_gaps=[
                {"gap_code": f"G{index:04d}", "detail": "gap"} for index in range(257)
            ],
        )
        self.assert_rejected(
            lambda: decode_aep_payload(oversize_gaps, schema_version=VERSION_4_0),
            ContractErrorCode.MAX_ARRAY_LENGTH_EXCEEDED,
        )

    def test_future_minor_round_trips_unknown_fields_at_every_level(self):
        payload = _no_actionable_package_dict()
        payload["future_top"] = 1
        payload["coverage"]["future_cov"] = 2
        payload["budget"]["future_budget"] = 3
        payload["coverage_gaps"] = [
            {"gap_code": "A_GAP", "detail": "d", "future_gap": 4}
        ]
        payload["evidence_domain"] = dict(_empty_bundle(), future_bundle=5)
        package = decode_aep_payload(payload, schema_version=VERSION_4_2)
        wire = package.to_dict()
        self.assertEqual(wire["future_top"], 1)
        self.assertEqual(wire["coverage"]["future_cov"], 2)
        self.assertEqual(wire["budget"]["future_budget"], 3)
        self.assertEqual(wire["coverage_gaps"][0]["future_gap"], 4)
        self.assertEqual(wire["evidence_domain"]["future_bundle"], 5)
        again = decode_aep_payload(wire, schema_version=VERSION_4_2)
        self.assertEqual(again.to_dict(), wire)

    def test_current_minor_rejects_unknown_fields_at_every_level(self):
        def inject_top(data):
            data["future_top"] = 1

        def inject_coverage(data):
            data["coverage"]["future_cov"] = 2

        def inject_budget(data):
            data["budget"]["future_budget"] = 3

        def inject_gap(data):
            data["coverage_gaps"] = [{"gap_code": "A_GAP", "detail": "d", "future_gap": 4}]

        def inject_bundle(data):
            data["evidence_domain"] = dict(_empty_bundle(), future_bundle=5)

        for inject in (inject_top, inject_coverage, inject_budget, inject_gap, inject_bundle):
            payload = _no_actionable_package_dict()
            inject(payload)
            self.assert_rejected(
                lambda p=payload: decode_aep_payload(p, schema_version=VERSION_4_0),
                ContractErrorCode.UNKNOWN_FIELD,
            )

    def test_defensive_copy_prevents_post_construction_mutation(self):
        profile_refs = ["profile-0001"]
        gaps = [_gap()]
        extensions = {"future_key": "v"}
        package = AuditEvidencePackage(
            schema_version=VERSION_4_2,
            package_status=AuditPackageStatus.SEALED,
            revision=1,
            audit_depth=AuditDepth.DEEP,
            audit_outcome=AuditOutcome.COMPLETED,
            evidence=decode_evidence_payload(_supported_bundle(), schema_version=VERSION_4_0),
            coverage=_coverage(),
            budget=_budget(),
            repository_profile_artifact_ids=profile_refs,
            mining_eligible_hypothesis_ids=("hypothesis-0001",),
            coverage_gaps=gaps,
            extensions=extensions,
        )
        profile_refs.append("profile-9999")
        gaps.append(_gap(gap_code="OTHER"))
        extensions["future_key2"] = "v2"
        self.assertEqual(package.repository_profile_artifact_ids, ("profile-0001",))
        self.assertEqual(len(package.coverage_gaps), 1)
        self.assertEqual(package.extensions, {"future_key": "v"})
        wire = package.to_dict()
        wire["injected"] = True
        self.assertNotIn("injected", package.to_dict())

    def test_payload_has_no_verified_safe_clear_confidence_or_severity_fields(self):
        def scan(node):
            if isinstance(node, dict):
                for key, value in node.items():
                    self.assertNotIn(key, FORBIDDEN_VERDICT_KEYS)
                    scan(value)
            elif isinstance(node, list):
                for item in node:
                    scan(item)

        scan(canonical_decode(FIXTURE.read_bytes()))
        scan(_package_dict())
        scan(_no_actionable_package_dict())
        self.assertEqual(
            FORBIDDEN_VERDICT_KEYS,
            frozenset(
                {"verified", "safe", "clear", "is_vulnerable", "confidence", "severity",
                 "trust_score"}
            ),
        )


if __name__ == "__main__":
    unittest.main()
