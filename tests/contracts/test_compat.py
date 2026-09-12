"""Frozen acceptance tests for the legacy adapter forward mapping (IP-0013 PR4).

Packet reference: ``docs/LIMA_Implementation_Packet_IP-0013_PR4_Legacy_Adapter.md``
sections 7/8/D2/D3/D4/D7 at main ``3e04a045``. Category counts: forward
mapping semantics >= 12, forward negatives >= 8, backward mapping >= 6.
"""

import hashlib
import re
import unittest

from lima.contracts.common import SchemaVersion
from lima.contracts.compat import (
    LEGACY_REASON_CODE,
    LEGACY_SENTINEL,
    LEGACY_SOURCE_ARTIFACT_ID,
    UNMAPPED_FROZEN_FIELDS,
    UNMAPPED_LEGACY_FINDING_FIELDS,
    domain_to_finding,
    finding_to_domain_bundle,
)
from lima.contracts.errors import ContractError, ContractErrorCode
from lima.contracts.evidence import (
    EvidenceLevel,
    EvidencePolarity,
    EvidenceSubjectKind,
)
from lima.models import EvidenceRecord, Finding

_DIGEST_PATTERN = re.compile(r"[0-9a-f]{64}")
_IDENTIFIER_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}")


def _minimal_finding() -> Finding:
    return Finding(
        rule_id="PY001",
        severity="medium",
        title="Use of eval on untrusted input",
        explanation="User-controlled CLI input reaches eval.",
        path="src/app.py",
        line=10,
        evidence="eval(user_input) evaluates untrusted CLI input",
        fix="Replace eval with ast.literal_eval.",
        test="test_app_eval_rejected",
    )


def _full_finding() -> Finding:
    return Finding(
        rule_id="B602",
        severity="high",
        title="Shell injection in subprocess call",
        explanation="Untrusted argument reaches subprocess with shell=True.",
        path="src/runner.py",
        line=42,
        evidence="subprocess.run(cmd, shell=True) with cmd from request body",
        fix="Pass a list and shell=False.",
        test="test_runner_shell_false",
        confidence=0.9,
        cwe="CWE-78",
        source="bandit",
        evidence_kind="line",
        verification_state="confirmed",
        evidence_records=[
            EvidenceRecord(
                source="bandit",
                kind="line",
                path="src/runner.py",
                line=42,
                snippet="subprocess.run(cmd, shell=True)",
            ),
            EvidenceRecord(
                source="semgrep",
                kind="line",
                path="src/api/handler.py",
                line=17,
                snippet="cmd = request.json['cmd']",
            ),
        ],
    )


def _material_digest(finding: Finding) -> str:
    material = f"{finding.rule_id}\0{finding.path}\0{finding.line}\0{finding.evidence}"
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


class CompatForwardMappingTests(unittest.TestCase):
    """P->F mapping semantics (Packet D2; category lower bound 12)."""

    def test_identity_digest_derivation_matches_legacy_material(self):
        finding = _full_finding()
        bundle = finding_to_domain_bundle(finding)
        expected = _material_digest(finding)
        self.assertEqual(bundle.signals[0].fingerprint, expected)
        self.assertEqual(bundle.security_issues[0].identity_digest, expected)
        self.assertIsNotNone(_DIGEST_PATTERN.fullmatch(expected))

    def test_derived_ids_follow_frozen_scheme(self):
        finding = _full_finding()
        bundle = finding_to_domain_bundle(finding)
        prefix = _material_digest(finding)[:12]
        signal = bundle.signals[0]
        issue = bundle.security_issues[0]
        self.assertEqual(signal.signal_id, f"sig-{prefix}")
        self.assertEqual(issue.issue_id, f"issue-{prefix}")
        expected_ids = [f"ev-{prefix}-000"] + [
            f"ev-{prefix}-{index:03d}" for index in range(1, 3)
        ]
        self.assertEqual(
            [record.evidence_id for record in bundle.evidence], expected_ids
        )
        for identifier in (
            [signal.signal_id, issue.issue_id] + expected_ids
        ):
            self.assertIsNotNone(_IDENTIFIER_PATTERN.fullmatch(identifier))

    def test_bundle_structure_is_one_signal_one_issue_one_plus_n_evidence(self):
        bundle = finding_to_domain_bundle(_full_finding())
        self.assertEqual(len(bundle.signals), 1)
        self.assertEqual(len(bundle.security_issues), 1)
        self.assertEqual(len(bundle.vulnerability_hypotheses), 0)
        self.assertEqual(len(bundle.evidence), 3)
        minimal = finding_to_domain_bundle(_minimal_finding())
        self.assertEqual(len(minimal.evidence), 2)

    def test_evidence_subject_binding_ev000_signal_rest_issue(self):
        finding = _full_finding()
        bundle = finding_to_domain_bundle(finding)
        signal_id = bundle.signals[0].signal_id
        issue_id = bundle.security_issues[0].issue_id
        self.assertEqual(bundle.evidence[0].subject_kind, EvidenceSubjectKind.SIGNAL)
        self.assertEqual(bundle.evidence[0].subject_id, signal_id)
        for record in bundle.evidence[1:]:
            self.assertEqual(
                record.subject_kind, EvidenceSubjectKind.SECURITY_ISSUE
            )
            self.assertEqual(record.subject_id, issue_id)

    def test_sentinel_literals_on_issue_and_constants(self):
        bundle = finding_to_domain_bundle(_full_finding())
        issue = bundle.security_issues[0]
        self.assertEqual(LEGACY_SENTINEL, "legacy-finding")
        self.assertEqual(LEGACY_SOURCE_ARTIFACT_ID, "legacy-finding")
        self.assertEqual(LEGACY_REASON_CODE, "LEGACY_MIGRATED")
        self.assertEqual(issue.root_cause_class, LEGACY_SENTINEL)
        self.assertEqual(issue.sink_identity, LEGACY_SENTINEL)
        self.assertEqual(issue.trust_boundary, LEGACY_SENTINEL)

    def test_all_reason_codes_carry_legacy_reason_sentinel(self):
        bundle = finding_to_domain_bundle(_full_finding())
        self.assertEqual(bundle.signals[0].reason_codes, (LEGACY_REASON_CODE,))
        self.assertEqual(
            bundle.security_issues[0].reason_codes, (LEGACY_REASON_CODE,)
        )
        for record in bundle.evidence:
            self.assertEqual(record.reason_codes, (LEGACY_REASON_CODE,))

    def test_all_records_carry_legacy_source_artifact_id(self):
        bundle = finding_to_domain_bundle(_full_finding())
        for record in bundle.evidence:
            self.assertEqual(
                record.source_artifact_ids, (LEGACY_SOURCE_ARTIFACT_ID,)
            )

    def test_unmapped_legacy_finding_fields_frozen_set(self):
        self.assertEqual(
            UNMAPPED_LEGACY_FINDING_FIELDS,
            frozenset(
                {
                    "severity",
                    "title",
                    "explanation",
                    "fix",
                    "test",
                    "confidence",
                    "verification_state",
                }
            ),
        )

    def test_cwe_empty_string_maps_to_empty_tuple(self):
        bundle = finding_to_domain_bundle(_minimal_finding())
        self.assertEqual(bundle.security_issues[0].cwe_ids, ())

    def test_cwe_valid_maps_to_single_element_tuple(self):
        bundle = finding_to_domain_bundle(_full_finding())
        self.assertEqual(bundle.security_issues[0].cwe_ids, ("CWE-78",))

    def test_records_degrade_to_d0_supports(self):
        bundle = finding_to_domain_bundle(_full_finding())
        for record in bundle.evidence:
            self.assertEqual(record.level, EvidenceLevel.D0)
            self.assertEqual(record.polarity, EvidencePolarity.SUPPORTS)

    def test_locations_pass_through_path_and_line(self):
        finding = _full_finding()
        bundle = finding_to_domain_bundle(finding)
        signal = bundle.signals[0]
        issue = bundle.security_issues[0]
        for location in (signal.location, issue.primary_location):
            self.assertEqual(location.path, finding.path)
            self.assertEqual(location.start_line, finding.line)
            self.assertEqual(location.end_line, finding.line)
        self.assertEqual(bundle.evidence[1].location.path, finding.path)
        self.assertEqual(bundle.evidence[1].location.start_line, finding.line)
        self.assertEqual(
            bundle.evidence[2].location.path, "src/api/handler.py"
        )
        self.assertEqual(bundle.evidence[2].location.start_line, 17)

    def test_record_summaries_pass_through_evidence_and_snippets(self):
        finding = _full_finding()
        bundle = finding_to_domain_bundle(finding)
        self.assertEqual(bundle.evidence[0].summary, finding.evidence)
        self.assertEqual(
            bundle.evidence[1].summary, finding.evidence_records[0].snippet
        )
        self.assertEqual(
            bundle.evidence[2].summary, finding.evidence_records[1].snippet
        )

    def test_independence_keys_derived_and_unique(self):
        finding = _full_finding()
        bundle = finding_to_domain_bundle(finding)
        keys = [record.independence_key for record in bundle.evidence]
        self.assertEqual(keys, ["B602:000", "B602:001", "B602:002"])
        self.assertEqual(len(set(keys)), len(keys))

    def test_signal_and_issue_reference_wiring(self):
        finding = _full_finding()
        bundle = finding_to_domain_bundle(finding)
        signal = bundle.signals[0]
        issue = bundle.security_issues[0]
        self.assertEqual(signal.evidence_ids, (bundle.evidence[0].evidence_id,))
        self.assertEqual(issue.signal_ids, (signal.signal_id,))
        self.assertEqual(
            issue.evidence_ids,
            (
                bundle.evidence[1].evidence_id,
                bundle.evidence[2].evidence_id,
            ),
        )

    def test_analysis_family_producer_and_evidence_kind_pass_through(self):
        finding = _full_finding()
        bundle = finding_to_domain_bundle(finding)
        signal = bundle.signals[0]
        self.assertEqual(signal.analysis_family, finding.source)
        self.assertEqual(signal.evidence_kind, finding.evidence_kind)
        for record in bundle.evidence:
            self.assertEqual(record.analysis_family, finding.source)
            self.assertEqual(record.producer, finding.source)

    def test_bundle_schema_version_is_current_minor(self):
        bundle = finding_to_domain_bundle(_full_finding())
        self.assertEqual(bundle.schema_version, SchemaVersion(4, 0))


class CompatForwardNegativeTests(unittest.TestCase):
    """P->F negatives: unmappable legacy values (Packet D4; lower bound 8)."""

    def _assert_contract_error(self, finding: Finding, code: ContractErrorCode,
                               field_path: str) -> None:
        with self.assertRaises(ContractError) as caught:
            finding_to_domain_bundle(finding)
        self.assertEqual(caught.exception.code, code)
        self.assertEqual(caught.exception.field_path, field_path)

    def test_rule_id_vocabulary_violation_rejected(self):
        finding = _full_finding()
        finding.rule_id = "bad rule!"
        self._assert_contract_error(
            finding, ContractErrorCode.INVALID_FIELD_VALUE, "$.rule_id"
        )

    def test_absolute_path_rejected(self):
        finding = _full_finding()
        finding.path = "/abs/path.py"
        self._assert_contract_error(
            finding, ContractErrorCode.INVALID_FIELD_VALUE, "$.path"
        )

    def test_drive_prefix_path_rejected(self):
        finding = _full_finding()
        finding.path = "C:" + "\\" + "src" + "\\" + "runner.py"
        self._assert_contract_error(
            finding, ContractErrorCode.INVALID_FIELD_VALUE, "$.path"
        )

    def test_parent_segment_path_rejected(self):
        finding = _full_finding()
        finding.path = "src/../runner.py"
        self._assert_contract_error(
            finding, ContractErrorCode.INVALID_FIELD_VALUE, "$.path"
        )

    def test_line_zero_rejected(self):
        finding = _full_finding()
        finding.line = 0
        self._assert_contract_error(
            finding, ContractErrorCode.INVALID_FIELD_VALUE, "$.line"
        )

    def test_line_above_int32_rejected(self):
        finding = _full_finding()
        finding.line = 2147483648
        self._assert_contract_error(
            finding, ContractErrorCode.INVALID_FIELD_VALUE, "$.line"
        )

    def test_empty_record_snippet_rejected(self):
        finding = _full_finding()
        finding.evidence_records[0].snippet = ""
        self._assert_contract_error(
            finding,
            ContractErrorCode.INVALID_FIELD_VALUE,
            "$.evidence_records[0].snippet",
        )

    def test_oversized_record_snippet_rejected(self):
        finding = _full_finding()
        finding.evidence_records[0].snippet = "a" * 4097
        self._assert_contract_error(
            finding,
            ContractErrorCode.MAX_STRING_LENGTH_EXCEEDED,
            "$.evidence_records[0].snippet",
        )

    def test_control_character_snippet_rejected(self):
        finding = _full_finding()
        finding.evidence_records[0].snippet = "eval\x00payload"
        self._assert_contract_error(
            finding,
            ContractErrorCode.INVALID_FIELD_VALUE,
            "$.evidence_records[0].snippet",
        )

    def test_invalid_cwe_rejected_not_silently_dropped(self):
        finding = _full_finding()
        finding.cwe = "CWE-0"
        self._assert_contract_error(
            finding, ContractErrorCode.INVALID_FIELD_VALUE, "$.cwe"
        )

    def test_invalid_source_rejected(self):
        finding = _full_finding()
        finding.source = "bad source!"
        self._assert_contract_error(
            finding, ContractErrorCode.INVALID_FIELD_VALUE, "$.source"
        )

    def test_oversized_top_level_evidence_rejected(self):
        finding = _full_finding()
        finding.evidence = "a" * 4097
        self._assert_contract_error(
            finding,
            ContractErrorCode.MAX_STRING_LENGTH_EXCEEDED,
            "$.evidence",
        )


class CompatBackwardMappingTests(unittest.TestCase):
    """F->P mapping (Packet D3; category lower bound 6)."""

    def test_roundtrip_fingerprint_identity(self):
        for finding in (_minimal_finding(), _full_finding()):
            with self.subTest(rule_id=finding.rule_id):
                back = domain_to_finding(finding_to_domain_bundle(finding))
                self.assertEqual(back.fingerprint, finding.fingerprint)

    def test_backward_field_mapping_frozen_rules(self):
        finding = _full_finding()
        bundle = finding_to_domain_bundle(finding)
        back = domain_to_finding(bundle)
        issue = bundle.security_issues[0]
        self.assertEqual(back.rule_id, finding.rule_id)
        self.assertEqual(back.path, finding.path)
        self.assertEqual(back.line, finding.line)
        self.assertEqual(back.cwe, "CWE-78")
        self.assertEqual(back.evidence_kind, finding.evidence_kind)
        self.assertEqual(back.fingerprint, issue.identity_digest[:24])
        self.assertEqual(back.title, f"migrated:{issue.issue_id}")
        self.assertEqual(back.explanation, "LEGACY_MIGRATED")
        self.assertEqual(back.fix, "unmapped:fix")
        self.assertEqual(back.test, "unmapped:test")
        self.assertEqual(back.source, "legacy-adapter")
        self.assertEqual(back.severity.value, "low")
        self.assertEqual(
            back.evidence, finding.evidence_records[0].snippet
        )

    def test_backward_empty_cwe_maps_to_empty_string(self):
        back = domain_to_finding(finding_to_domain_bundle(_minimal_finding()))
        self.assertEqual(back.cwe, "")

    def test_backward_multi_cwe_is_lossy_minimum(self):
        finding = _full_finding()
        bundle = finding_to_domain_bundle(finding)
        payload = bundle.to_dict()
        payload["security_issues"][0]["cwe_ids"] = ["CWE-78", "CWE-89"]
        rebuilt = type(bundle).from_dict(
            payload, schema_version=SchemaVersion(4, 0)
        )
        back = domain_to_finding(rebuilt)
        self.assertEqual(back.cwe, "CWE-78")

    def test_backward_explanation_joins_reason_codes(self):
        finding = _full_finding()
        bundle = finding_to_domain_bundle(finding)
        payload = bundle.to_dict()
        payload["security_issues"][0]["reason_codes"] = [
            "LEGACY_MIGRATED",
            "RULE_MATCHED",
        ]
        rebuilt = type(bundle).from_dict(
            payload, schema_version=SchemaVersion(4, 0)
        )
        back = domain_to_finding(rebuilt)
        self.assertEqual(back.explanation, "LEGACY_MIGRATED; RULE_MATCHED")

    def test_unmapped_frozen_fields_frozen_set(self):
        self.assertEqual(
            UNMAPPED_FROZEN_FIELDS,
            frozenset(
                {
                    "confidence",
                    "verification_state",
                    "fingerprint",
                    "level",
                    "polarity",
                    "producer",
                    "independence_key",
                    "source_artifact_ids",
                    "dependency_graph",
                }
            ),
        )
        self.assertIn("confidence", UNMAPPED_FROZEN_FIELDS)
        self.assertIn("verification_state", UNMAPPED_FROZEN_FIELDS)

    def test_issue_index_out_of_range_rejected(self):
        bundle = finding_to_domain_bundle(_full_finding())
        for index in (1, -1, 99):
            with self.subTest(index=index):
                with self.assertRaises(ContractError) as caught:
                    domain_to_finding(bundle, issue_index=index)
                self.assertEqual(
                    caught.exception.code, ContractErrorCode.INVALID_FIELD_VALUE
                )
                self.assertEqual(
                    caught.exception.field_path,
                    f"$.security_issues[{index}]",
                )

    def test_structural_missing_items_rejected(self):
        finding = _full_finding()
        payload = finding_to_domain_bundle(finding).to_dict()
        dangling = dict(payload)
        dangling["security_issues"] = [
            dict(
                payload["security_issues"][0],
                signal_ids=["sig-does-not-exist"],
            )
        ]
        no_evidence = dict(payload)
        no_evidence["security_issues"] = [
            dict(payload["security_issues"][0], evidence_ids=[])
        ]
        for case, mutated in (
            ("dangling_signal", dangling),
            ("empty_issue_evidence", no_evidence),
        ):
            with self.subTest(case=case):
                with self.assertRaises(ContractError) as caught:
                    type(finding_to_domain_bundle(finding)).from_dict(
                        mutated, schema_version=SchemaVersion(4, 0)
                    )
                self.assertEqual(
                    caught.exception.code, ContractErrorCode.INVALID_FIELD_VALUE
                )


if __name__ == "__main__":
    unittest.main()
