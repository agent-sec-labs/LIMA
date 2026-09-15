"""PlatformFinding -> VulnerabilityEvidencePackage converter tests (T1).

The converter is the agent-platform boundary onto the main-branch contract
chain: platform findings must enter the audit chain only as strictly
validated VEPs.  Every test here builds the VEP through the real contract
constructors (fail-closed): an inadmissible verdict/claim combination, an
unsortable id, or a sub-admissible evidence level must surface as an
exception, never a coerced package.

Mapping pinned here (task T1 design decisions):

- ``runtime-confirmed`` -> ``runtime_exploitability`` + ``verified``: the
  frozen V4 matrix admits ``verified`` only with D4+D3 SUPPORTS evidence,
  at least one ``reproduced`` run and non-empty impact; the converter
  layers a D4 platform-confirmation record (grounded in the real ASan run)
  onto the D3 sanitizer record, mirroring the golden-path VEP shape.
- ``fact-verified`` / ``tool-corroborated`` / ``semantic-supported`` /
  ``needs-human-review`` -> the probable bucket.  The frozen matrix cannot
  express a candidate without D3+ dynamic evidence, and the platform never
  mints D3 for these states, so the fail-closed wire form is
  ``static_property`` + ``inconclusive``.
- ``rejected`` -> ``runtime_exploitability`` + ``refuted_scope`` with a
  synthesized D3 REFUTES record grounded in the proof refutation and the
  bounded ``rejected_reason`` as refutation scope.
- Static (D2) evidence records stay platform-side: VEP admits D3/D4 only.
"""

import json
import unittest

from lima.contracts.common import SchemaVersion
from lima.contracts.evidence import EvidenceLevel, EvidencePolarity
from lima.contracts.vep import (
    ClaimKind,
    ReproductionOutcome,
    VerificationVerdict,
    decode_vep_payload,
    encode_vep_payload,
)
from lima.models import EvidenceRecord

try:  # module under test (RED until implemented)
    from lima.platform_contracts import finding_to_vep
except ImportError:  # pragma: no cover - RED phase
    finding_to_vep = None


SNAPSHOT = "a" * 64
REPOSITORY = "repos/demo"

_HIT_ENTRY = {
    "round": 1,
    "driver_sha256": "abcdef0123456789",
    "stage": "run",
    "ok": True,
    "exit_code": -11,
    "error_type": "heap-buffer-overflow",
    "faulting_line": 42,
    "hit": True,
}

_ASAN_RECORD = EvidenceRecord(
    source="asan",
    kind="runtime",
    path="src/example.c",
    line=42,
    snippet="ERROR: AddressSanitizer: heap-buffer-overflow on address",
    rule_id="asan.repro",
    cwe="CWE-787",
    symbol="parse_input",
    tool_run_id="repro-" + "0" * 24,
)


def _finding(**overrides):
    base = {
        "target_id": "lead-0001",
        "path": "src/example.c",
        "line": 42,
        "symbol": "parse_input",
        "cwe": "CWE-787",
        "state": "runtime-confirmed",
        "hypothesis_reason": "Attacker-controlled length reaches memcpy unbounded.",
        "poc_driver_code": "int main(void) { return 0; }",
        "experiment_log": (_HIT_ENTRY,),
        "identity": None,
        "evidence_records": (_ASAN_RECORD,),
    }
    base.update(overrides)
    return None if finding_to_vep is None else _plain_finding(base)


def _plain_finding(base):
    from lima.agent_orchestrator import PlatformFinding

    return PlatformFinding(**base)


@unittest.skipIf(finding_to_vep is None, "platform_contracts not implemented (RED)")
class FindingToVepTests(unittest.TestCase):
    def test_finding_to_vep_maps_all_fields(self):
        finding = _finding()
        vep = finding_to_vep(finding, snapshot_sha256=SNAPSHOT, repository=REPOSITORY)
        self.assertEqual(vep.schema_version, SchemaVersion(4, 0))
        self.assertIs(vep.claim_kind, ClaimKind.RUNTIME_EXPLOITABILITY)
        self.assertIs(vep.verification_verdict, VerificationVerdict.VERIFIED)
        self.assertEqual(vep.cwe_ids, ("CWE-787",))
        self.assertEqual(vep.target_location.path, "src/example.c")
        self.assertEqual(vep.target_location.start_line, 42)
        self.assertEqual(vep.target_location.end_line, 42)
        self.assertEqual(vep.target_location.symbol, "parse_input")
        self.assertTrue(vep.hypothesis_id.startswith("hyp-"))
        self.assertEqual(vep.source_aep_revision, 1)
        self.assertIsNotNone(vep.impact)
        self.assertNotEqual(vep.impact, "")
        self.assertEqual(
            vep.trigger_conditions,
            ("Attacker-controlled length reaches memcpy unbounded.",),
        )
        self.assertEqual(
            len([record for record in vep.evidence if record.level is EvidenceLevel.D4]),
            1,
        )
        # Deterministic: same inputs -> identical package.
        again = finding_to_vep(finding, snapshot_sha256=SNAPSHOT, repository=REPOSITORY)
        self.assertEqual(vep, again)
        self.assertEqual(vep.hypothesis_id, again.hypothesis_id)

    def test_finding_to_vep_semantic_supported_maps_to_probable(self):
        finding = _finding(
            state="semantic-supported",
            experiment_log=(),
            evidence_records=(),
        )
        vep = finding_to_vep(finding, snapshot_sha256=SNAPSHOT, repository=REPOSITORY)
        # Probable bucket, fail-closed wire form: the frozen V4 matrix has no
        # candidate without D3+ evidence and semantic support stays D1.
        self.assertIs(vep.claim_kind, ClaimKind.STATIC_PROPERTY)
        self.assertIs(vep.verification_verdict, VerificationVerdict.INCONCLUSIVE)
        self.assertEqual(vep.evidence, ())
        self.assertIsNone(vep.impact)

    def test_finding_to_vep_rejected_maps_to_disputed(self):
        finding = _finding(
            state="rejected",
            rejected_reason="taint-sink: obligation refuted by analysis",
            experiment_log=(),
            evidence_records=(),
        )
        vep = finding_to_vep(finding, snapshot_sha256=SNAPSHOT, repository=REPOSITORY)
        self.assertIs(vep.claim_kind, ClaimKind.RUNTIME_EXPLOITABILITY)
        self.assertIs(vep.verification_verdict, VerificationVerdict.REFUTED_SCOPE)
        self.assertEqual(vep.refutation_scope, "taint-sink: obligation refuted by analysis")
        refutes = [
            record
            for record in vep.evidence
            if record.polarity is EvidencePolarity.REFUTES
        ]
        self.assertEqual(len(refutes), 1)
        for record in refutes:
            self.assertEqual(record.subject_id, vep.hypothesis_id)

    def test_finding_to_vep_experiment_log_becomes_reproduction_runs(self):
        entries = (
            _HIT_ENTRY,
            {
                "round": 2,
                "driver_sha256": "1111111111111111",
                "stage": "run",
                "ok": True,
                "exit_code": 0,
                "error_type": None,
                "faulting_line": None,
                "hit": False,
            },
            {
                "round": 3,
                "driver_sha256": "2222222222222222",
                "stage": "build",
                "ok": False,
                "exit_code": 1,
                "error_type": None,
                "faulting_line": None,
                "hit": False,
            },
        )
        finding = _finding(experiment_log=entries)
        vep = finding_to_vep(finding, snapshot_sha256=SNAPSHOT, repository=REPOSITORY)
        self.assertEqual(len(vep.reproduction_runs), 3)
        outcomes = {run.outcome for run in vep.reproduction_runs}
        self.assertIn(ReproductionOutcome.REPRODUCED, outcomes)
        self.assertIn(ReproductionOutcome.NOT_REPRODUCED, outcomes)
        self.assertIn(ReproductionOutcome.TOOL_ERROR, outcomes)
        run_ids = [run.run_artifact_id for run in vep.reproduction_runs]
        self.assertEqual(run_ids, sorted(set(run_ids)))
        for run in vep.reproduction_runs:
            self.assertNotEqual(run.detail, "")

    def test_finding_to_vep_evidence_records_preserved(self):
        static_record = EvidenceRecord(
            source="cppcheck",
            kind="static",
            path="src/example.c",
            line=40,
            snippet="Buffer overrun detected",
            rule_id="cppcheck.bufferOverflow",
            cwe="CWE-787",
            tool_run_id="run-static-0001",
        )
        finding = _finding(evidence_records=(_ASAN_RECORD, static_record))
        vep = finding_to_vep(finding, snapshot_sha256=SNAPSHOT, repository=REPOSITORY)
        d3 = [
            record
            for record in vep.evidence
            if record.level is EvidenceLevel.D3
            and record.polarity is EvidencePolarity.SUPPORTS
        ]
        self.assertEqual(len(d3), 1)
        record = d3[0]
        self.assertEqual(record.producer, "asan")
        self.assertEqual(record.subject_id, vep.hypothesis_id)
        self.assertIn("AddressSanitizer", record.summary)
        # Static D2 records are not VEP-admissible and stay platform-side:
        # only the lifted D3 record plus the D4 confirmation layer remain.
        self.assertEqual(len(vep.evidence), 2)

    def test_finding_to_vep_rejects_invalid_cwe(self):
        for bad in ("CWE-0", "nonsense", "", "cwe-", "CWE-12345678", None):
            with self.subTest(cwe=bad):
                finding = _finding(cwe=bad)
                with self.assertRaises(ValueError):
                    finding_to_vep(finding, snapshot_sha256=SNAPSHOT, repository=REPOSITORY)

    def test_finding_to_vep_rejects_unknown_state(self):
        finding = _finding(state="abstain")
        with self.assertRaises(ValueError):
            finding_to_vep(finding, snapshot_sha256=SNAPSHOT, repository=REPOSITORY)

    def test_vep_roundtrip_via_codec(self):
        finding = _finding()
        vep = finding_to_vep(finding, snapshot_sha256=SNAPSHOT, repository=REPOSITORY)
        payload = vep.to_dict()
        decoded = decode_vep_payload(payload, schema_version=SchemaVersion(4, 0))
        self.assertEqual(encode_vep_payload(decoded), payload)
        self.assertEqual(decoded, vep)
        # Canonical JSON round trip stays stable for downstream digesting.
        self.assertEqual(json.loads(json.dumps(payload)), payload)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
