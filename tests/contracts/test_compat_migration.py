"""Frozen acceptance tests for V5-FR-05 migration wiring and goldens (IP-0013 PR4).

Packet reference: ``docs/LIMA_Implementation_Packet_IP-0013_PR4_Legacy_Adapter.md``
sections D5/D7 at main ``3e04a045``. Category counts: V5-FR-05 behaviour >= 6,
golden + round-trip >= 5, AC-03/FR-06 >= 3.
"""

import json
import unittest
from pathlib import Path

from lima.contracts.codec import (
    canonical_encode,
    compute_content_digest,
)
from lima.contracts.common import SchemaVersion
from lima.contracts.compat import (
    domain_to_finding,
    finding_to_domain_bundle,
    review_report_to_workflow_summary,
)
from lima.contracts.errors import ContractError, ContractErrorCode
from lima.contracts.evidence import EvidenceDomainBundle
from lima.contracts.summary import (
    ArtifactLink,
    ExecutionStatus,
    SummaryReferenceKind,
    SummarySourceKind,
    WorkflowSummary,
)
from lima.models import Finding, ReviewReport, Severity

FIXTURES = Path(__file__).resolve().parent / "fixtures"


def _pin_bytes(value: object) -> bytes:
    """Byte-pinning encoding for fixtures carrying legacy float fields."""
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def _load(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))

_MINIMAL_DICT = {
    "rule_id": "PY001",
    "severity": "medium",
    "title": "Use of eval on untrusted input",
    "explanation": "User-controlled CLI input reaches eval.",
    "path": "src/app.py",
    "line": 10,
    "evidence": "eval(user_input) evaluates untrusted CLI input",
    "fix": "Replace eval with ast.literal_eval.",
    "test": "test_app_eval_rejected",
    "confidence": 0.8,
    "cwe": "",
    "source": "local-rule",
    "evidence_kind": "line",
    "verification_state": "candidate",
    "evidence_records": [],
}

_FULL_RECORDS = [
    {
        "source": "bandit",
        "kind": "line",
        "path": "src/runner.py",
        "line": 42,
        "snippet": "subprocess.run(cmd, shell=True)",
    },
    {
        "source": "semgrep",
        "kind": "line",
        "path": "src/api/handler.py",
        "line": 17,
        "snippet": "cmd = request.json['cmd']",
    },
]

_FULL_DICT = {
    "rule_id": "B602",
    "severity": "high",
    "title": "Shell injection in subprocess call",
    "explanation": "Untrusted argument reaches subprocess with shell=True.",
    "path": "src/runner.py",
    "line": 42,
    "evidence": "subprocess.run(cmd, shell=True) with cmd from request body",
    "fix": "Pass a list and shell=False.",
    "test": "test_runner_shell_false",
    "confidence": 0.9,
    "cwe": "CWE-78",
    "source": "bandit",
    "evidence_kind": "line",
    "verification_state": "confirmed",
    "evidence_records": _FULL_RECORDS,
}


def _minimal_finding() -> Finding:
    return Finding(**_MINIMAL_DICT)


def _full_finding() -> Finding:
    return Finding(**_FULL_DICT)


def _from_payload(payload: dict) -> Finding:
    fields = dict(payload)
    fields["severity"] = Severity(fields["severity"])
    return Finding(**fields)


def _report() -> ReviewReport:
    return ReviewReport(
        repository="lima-demo",
        pull_request=7,
        summary="legacy audit report",
        risk="high",
        findings=[_minimal_finding(), _full_finding()],
    )


def _typed_workflow_link() -> ArtifactLink:
    return ArtifactLink(
        kind=SummaryReferenceKind.WORKFLOW,
        artifact_id="workflow-0001",
        content_digest="a" * 64,
        schema_version=SchemaVersion(4, 0),
    )


class CompatMigrationSummaryTests(unittest.TestCase):
    """V5-FR-05 behaviour (Packet D5; category lower bound 6)."""

    def test_summary_shape_is_legacy_audit_succeeded(self):
        summary = review_report_to_workflow_summary(_report())
        self.assertEqual(summary.source, SummarySourceKind.LEGACY_AUDIT)
        self.assertEqual(summary.execution_status, ExecutionStatus.SUCCEEDED)
        self.assertEqual(summary.schema_version, SchemaVersion(4, 0))
        self.assertIsNone(summary.workflow)
        self.assertIsNone(summary.security_outcome)
        self.assertIsNone(summary.run_manifest)
        self.assertEqual(summary.stage_attempts, ())
        self.assertEqual(summary.evidence, ())
        self.assertEqual(summary.extensions, {})

    def test_legacy_artifact_ids_sorted_and_deduplicated(self):
        summary = review_report_to_workflow_summary(_report())
        fingerprints = sorted(
            {finding.fingerprint for finding in _report().findings}
        )
        self.assertEqual(list(summary.legacy_artifact_ids), fingerprints)

    def test_duplicate_fingerprints_fold_explicitly(self):
        duplicate = Finding(**_MINIMAL_DICT)
        report = ReviewReport(
            repository="lima-demo",
            pull_request=None,
            summary="s",
            risk="low",
            findings=[_minimal_finding(), duplicate],
        )
        summary = review_report_to_workflow_summary(report)
        self.assertEqual(
            list(summary.legacy_artifact_ids), [duplicate.fingerprint]
        )

    def test_empty_findings_report_rejected(self):
        report = ReviewReport(
            repository="lima-demo",
            pull_request=None,
            summary="s",
            risk="low",
            findings=[],
        )
        with self.assertRaises(ContractError) as caught:
            review_report_to_workflow_summary(report)
        self.assertEqual(caught.exception.code, ContractErrorCode.INVALID_FIELD_VALUE)
        self.assertEqual(caught.exception.field_path, "$.findings")

    def test_legacy_audit_with_typed_link_rejected_at_summary_contract(self):
        with self.assertRaises(ContractError) as caught:
            WorkflowSummary(
                schema_version=SchemaVersion(4, 0),
                source=SummarySourceKind.LEGACY_AUDIT,
                execution_status=ExecutionStatus.SUCCEEDED,
                legacy_artifact_ids=("1acc784801e73861ba30086a",),
                workflow=_typed_workflow_link(),
            )
        self.assertEqual(caught.exception.code, ContractErrorCode.INVALID_FIELD_VALUE)
        self.assertEqual(caught.exception.field_path, "$.workflow")

    def test_legacy_audit_without_legacy_ids_rejected(self):
        with self.assertRaises(ContractError) as caught:
            WorkflowSummary(
                schema_version=SchemaVersion(4, 0),
                source=SummarySourceKind.LEGACY_AUDIT,
                execution_status=ExecutionStatus.SUCCEEDED,
            )
        self.assertEqual(caught.exception.code, ContractErrorCode.INVALID_FIELD_VALUE)
        self.assertEqual(caught.exception.field_path, "$.legacy_artifact_ids")

    def test_adapter_output_always_legacy_audit_for_any_report(self):
        for findings in (
            [_minimal_finding()],
            [_full_finding()],
            [_minimal_finding(), _full_finding(), Finding(**_FULL_DICT)],
        ):
            report = ReviewReport(
                repository="r",
                pull_request=None,
                summary="s",
                risk="low",
                findings=findings,
            )
            with self.subTest(count=len(findings)):
                summary = review_report_to_workflow_summary(report)
                self.assertEqual(summary.source, SummarySourceKind.LEGACY_AUDIT)
                self.assertEqual(
                    summary.execution_status, ExecutionStatus.SUCCEEDED
                )


class CompatGoldenRoundTripTests(unittest.TestCase):
    """Golden fixtures and round-trip identity (Packet D5/D7; lower bound 5)."""

    def _golden_bytes(self, name: str) -> bytes:
        return (FIXTURES / name).read_bytes()

    def test_legacy_finding_fixtures_are_canonical_and_loadable(self):
        for name, payload_dict in (
            ("legacy_finding_minimal.json", _MINIMAL_DICT),
            ("legacy_finding_full.json", _FULL_DICT),
        ):
            with self.subTest(name=name):
                raw = self._golden_bytes(name)
                decoded = _load(name)
                self.assertEqual(_pin_bytes(decoded), raw)
                finding = _from_payload(decoded)
                self.assertEqual(finding.to_dict(), decoded)
                self.assertEqual(
                    finding.fingerprint,
                    Finding(**payload_dict).fingerprint,
                )

    def test_domain_v4_golden_matches_forward_conversion(self):
        raw = self._golden_bytes("legacy_finding_domain_v4_golden.json")
        decoded = _load("legacy_finding_domain_v4_golden.json")
        bundle = finding_to_domain_bundle(_full_finding())
        self.assertEqual(canonical_encode(decoded), raw)
        self.assertEqual(decoded, bundle.to_dict())
        rebuilt = EvidenceDomainBundle.from_dict(
            decoded, schema_version=SchemaVersion(4, 0)
        )
        self.assertEqual(rebuilt, bundle)

    def test_domain_golden_payload_digest_recomputed_by_codec(self):
        raw = self._golden_bytes("legacy_finding_domain_v4_golden.json")
        golden_payload = _load("legacy_finding_domain_v4_golden.json")
        bundle = finding_to_domain_bundle(_full_finding())
        expected = compute_content_digest(golden_payload)
        self.assertEqual(compute_content_digest(bundle.to_dict()), expected)
        self.assertEqual(canonical_encode(golden_payload), raw)
        self.assertEqual(len(expected), 64)

    def test_roundtrip_v4_golden_matches_backward_conversion(self):
        raw = self._golden_bytes("legacy_finding_roundtrip_v4_golden.json")
        decoded = _load("legacy_finding_roundtrip_v4_golden.json")
        bundle = finding_to_domain_bundle(_full_finding())
        back = domain_to_finding(bundle)
        self.assertEqual(_pin_bytes(decoded), raw)
        self.assertEqual(decoded, back.to_dict())

    def test_workflow_summary_v4_golden_matches_conversion(self):
        raw = self._golden_bytes("legacy_report_workflow_summary_v4_golden.json")
        decoded = _load("legacy_report_workflow_summary_v4_golden.json")
        summary = review_report_to_workflow_summary(_report())
        self.assertEqual(canonical_encode(decoded), raw)
        self.assertEqual(decoded, summary.to_dict())

    def test_golden_regeneration_from_legacy_fixtures_is_identical(self):
        minimal = _from_payload(_load("legacy_finding_minimal.json"))
        full = _from_payload(_load("legacy_finding_full.json"))
        report = ReviewReport(
            repository="lima-demo",
            pull_request=7,
            summary="legacy audit report",
            risk="high",
            findings=[minimal, full],
        )
        self.assertEqual(
            _pin_bytes(finding_to_domain_bundle(full).to_dict()),
            self._golden_bytes("legacy_finding_domain_v4_golden.json"),
        )
        self.assertEqual(
            _pin_bytes(
                domain_to_finding(finding_to_domain_bundle(full)).to_dict()
            ),
            self._golden_bytes("legacy_finding_roundtrip_v4_golden.json"),
        )
        self.assertEqual(
            _pin_bytes(review_report_to_workflow_summary(report).to_dict()),
            self._golden_bytes("legacy_report_workflow_summary_v4_golden.json"),
        )

    def test_roundtrip_fingerprint_identity_both_samples(self):
        for finding in (_minimal_finding(), _full_finding()):
            with self.subTest(rule_id=finding.rule_id):
                back = domain_to_finding(finding_to_domain_bundle(finding))
                self.assertEqual(back.fingerprint, finding.fingerprint)


class CompatFutureMinorTests(unittest.TestCase):
    """AC-03 legacy consumer face and FR-06 version gate (lower bound 3)."""

    def _bundle_payload_with_unknown_issue_field(self) -> dict:
        payload = finding_to_domain_bundle(_full_finding()).to_dict()
        mutated = dict(payload)
        mutated["security_issues"] = [
            dict(payload["security_issues"][0], future_note="reserved-4.1")
        ]
        return mutated

    def test_future_minor_unknown_fields_survive_decode_encode(self):
        payload = self._bundle_payload_with_unknown_issue_field()
        bundle = EvidenceDomainBundle.from_dict(
            payload, schema_version=SchemaVersion(4, 1)
        )
        self.assertEqual(
            bundle.security_issues[0].extensions, {"future_note": "reserved-4.1"}
        )
        self.assertEqual(bundle.to_dict(), payload)

    def test_domain_to_finding_reads_known_fields_on_future_minor_bundle(self):
        payload = self._bundle_payload_with_unknown_issue_field()
        bundle = EvidenceDomainBundle.from_dict(
            payload, schema_version=SchemaVersion(4, 1)
        )
        back = domain_to_finding(bundle)
        self.assertEqual(back.rule_id, "B602")
        self.assertEqual(back.path, "src/runner.py")
        self.assertEqual(back.line, 42)
        self.assertEqual(back.cwe, "CWE-78")
        self.assertEqual(
            back.fingerprint, bundle.security_issues[0].identity_digest[:24]
        )

    def test_current_minor_unknown_fields_rejected(self):
        payload = self._bundle_payload_with_unknown_issue_field()
        with self.assertRaises(ContractError) as caught:
            EvidenceDomainBundle.from_dict(
                payload, schema_version=SchemaVersion(4, 0)
            )
        self.assertEqual(caught.exception.code, ContractErrorCode.UNKNOWN_FIELD)


if __name__ == "__main__":
    unittest.main()
