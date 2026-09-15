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

import hashlib
import json
import unittest

from lima.agent_orchestrator import PlatformReviewOutcome, PlatformReviewStats
from lima.agent_patch import PatchFlowOutcome, PatchProposal, PatchVerification
from lima.contracts.aep import (
    AuditBudget,
    AuditCoverageGap,
    AuditDepth,
    AuditOutcome,
    AuditPackageStatus,
    decode_aep_payload,
    encode_aep_payload,
)
from lima.contracts.codec import compute_content_digest
from lima.contracts.common import SchemaVersion
from lima.contracts.evidence import EvidenceLevel, EvidencePolarity, HypothesisStatus
from lima.contracts.rvr import (
    CandidateVerdict,
    GateKind,
    GateOutcome,
    decode_rvr_payload,
    encode_rvr_payload,
)
from lima.contracts.summary import (
    ExecutionStatus,
    SummaryReferenceKind,
    SummarySourceKind,
    decode_workflow_summary_payload,
    encode_workflow_summary_payload,
)
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

try:  # T2 converters (RED until implemented)
    from lima.platform_contracts import (
        platform_review_to_aep,
        platform_review_to_workflow_summary,
    )
except ImportError:  # pragma: no cover - RED phase
    platform_review_to_aep = None
    platform_review_to_workflow_summary = None

try:  # T3 converter (RED until implemented)
    from lima.platform_contracts import patch_outcome_to_rvr
except ImportError:  # pragma: no cover - RED phase
    patch_outcome_to_rvr = None


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


_STATIC_RECORD = EvidenceRecord(
    source="cppcheck",
    kind="static",
    path="src/example.c",
    line=40,
    snippet="Buffer overrun detected",
    rule_id="cppcheck.bufferOverflow",
    cwe="CWE-787",
    tool_run_id="run-static-0001",
)


def _outcome(**overrides):
    """One platform review outcome carrying the T1 runtime-confirmed finding."""

    finding = _plain_finding(
        {
            "target_id": "lead-0001",
            "path": "src/example.c",
            "line": 42,
            "symbol": "parse_input",
            "cwe": "CWE-787",
            "state": "tool-corroborated",
            "hypothesis_reason": "Attacker-controlled length reaches memcpy unbounded.",
            "poc_driver_code": "int main(void) { return 0; }",
            "experiment_log": (),
            "identity": None,
            "evidence_records": (_STATIC_RECORD,),
        }
    )
    base = {
        "findings": (finding,),
        "targets": (finding,),
        "stats": PlatformReviewStats(2, 1, 1, 2, 3, 2, 1),
        "diagnostics": (),
        "leads_considered": 2,
        "translation_units": ("src/example.c", "src/other.c", "vendored/big.c"),
    }
    base.update(overrides)
    return PlatformReviewOutcome(**base)


class PlatformReviewContractsTests(unittest.TestCase):
    """PlatformReviewOutcome -> AEP / WorkflowSummary converters (T2)."""

    # ------------------------------------------------------------ AEP mapping

    def test_aep_maps_coverage_and_budget(self):
        aep = platform_review_to_aep(
            _outcome(), snapshot_sha256=SNAPSHOT, repository=REPOSITORY
        )
        self.assertEqual(aep.schema_version, SchemaVersion(4, 0))
        self.assertIs(aep.package_status, AuditPackageStatus.SEALED)
        self.assertIs(aep.audit_depth, AuditDepth.INITIAL)
        self.assertIs(aep.audit_outcome, AuditOutcome.COMPLETED)
        self.assertEqual(aep.revision, 1)
        # stats numbers survive verbatim: experiment_count -> tool_runs and
        # the three LLM roles sum into model_calls; unmetered axes stay 0.
        self.assertEqual(
            aep.budget,
            AuditBudget(tool_runs=2, model_calls=6, model_tokens=0, wall_clock_ms=0),
        )
        # analyzed = distinct audited target paths; in scope adds the
        # translation units the fact instrument covered (vendored/big.c).
        self.assertEqual(aep.coverage.analyzed_file_count, 1)
        self.assertEqual(aep.coverage.in_scope_file_count, 3)
        self.assertTrue(
            aep.repository_profile_artifact_ids[0].startswith("profile-platform-")
        )
        # tool-corroborated finding: D2 SUPPORTS -> statically supported ->
        # mining eligible and the completed outcome is mandatory.
        self.assertEqual(len(aep.mining_eligible_hypothesis_ids), 1)
        statuses = {
            hypothesis.status
            for hypothesis in aep.evidence.vulnerability_hypotheses
        }
        self.assertEqual(statuses, {HypothesisStatus.STATICALLY_SUPPORTED})

    def test_aep_maps_coverage_gaps_from_diagnostics(self):
        outcome = _outcome(
            diagnostics=(
                "coverage gap: unit vendored/big.c skipped: over per-file budget",
                "scout: degraded provider output",
            )
        )
        aep = platform_review_to_aep(
            outcome, snapshot_sha256=SNAPSHOT, repository=REPOSITORY
        )
        self.assertEqual(
            aep.coverage_gaps,
            (
                AuditCoverageGap(
                    gap_code="COVERAGE_GAP",
                    detail="unit vendored/big.c skipped: over per-file budget",
                ),
            ),
        )
        # Non coverage-gap diagnostics never become gaps.
        plain = platform_review_to_aep(
            _outcome(diagnostics=("scout: degraded provider output",)),
            snapshot_sha256=SNAPSHOT,
            repository=REPOSITORY,
        )
        self.assertEqual(plain.coverage_gaps, ())

    def test_aep_without_supported_hypotheses_is_no_actionable(self):
        outcome = _outcome(
            findings=(),
            targets=(),
            stats=PlatformReviewStats(0, 0, 0, 0, 0, 0, 1),
            leads_considered=0,
            translation_units=("src/example.c",),
        )
        aep = platform_review_to_aep(
            outcome, snapshot_sha256=SNAPSHOT, repository=REPOSITORY
        )
        self.assertIs(aep.audit_outcome, AuditOutcome.NO_ACTIONABLE_HYPOTHESIS)
        self.assertEqual(aep.mining_eligible_hypothesis_ids, ())
        self.assertEqual(aep.evidence.vulnerability_hypotheses, ())
        self.assertEqual(aep.coverage.in_scope_file_count, 1)
        self.assertEqual(aep.coverage.analyzed_file_count, 0)

    # ------------------------------------------------- WorkflowSummary mapping

    def test_workflow_summary_completed(self):
        summary = platform_review_to_workflow_summary(
            _outcome(), snapshot_sha256=SNAPSHOT, repository=REPOSITORY
        )
        self.assertEqual(summary.schema_version, SchemaVersion(4, 0))
        self.assertIs(summary.source, SummarySourceKind.CHAIN)
        self.assertIs(summary.execution_status, ExecutionStatus.SUCCEEDED)
        self.assertIsNotNone(summary.workflow)
        self.assertIs(summary.workflow.kind, SummaryReferenceKind.WORKFLOW)
        self.assertIsNotNone(summary.security_outcome)
        self.assertIs(
            summary.security_outcome.kind, SummaryReferenceKind.SECURITY_OUTCOME
        )
        self.assertIsNone(summary.run_manifest)
        # Chain-source summaries must never carry legacy ids.
        self.assertEqual(summary.legacy_artifact_ids, ())
        # Deterministic: same inputs -> identical summary.
        again = platform_review_to_workflow_summary(
            _outcome(), snapshot_sha256=SNAPSHOT, repository=REPOSITORY
        )
        self.assertEqual(summary, again)

    def test_workflow_summary_maps_execution_status(self):
        cancelled = platform_review_to_workflow_summary(
            _outcome(
                findings=(),
                targets=(),
                stats=PlatformReviewStats(0, 0, 0, 0, 0, 0, 0),
                diagnostics=("cancelled before the platform review started",),
            ),
            snapshot_sha256=SNAPSHOT,
            repository=REPOSITORY,
        )
        self.assertIs(cancelled.execution_status, ExecutionStatus.CANCELLED)
        for diagnostic in (
            "deadline-exceeded before the platform review started",
            "scout-unavailable: provider offline",
        ):
            with self.subTest(diagnostic=diagnostic):
                summary = platform_review_to_workflow_summary(
                    _outcome(
                        findings=(),
                        targets=(),
                        stats=PlatformReviewStats(0, 0, 0, 0, 0, 0, 0),
                        diagnostics=(diagnostic,),
                    ),
                    snapshot_sha256=SNAPSHOT,
                    repository=REPOSITORY,
                )
                self.assertIs(summary.execution_status, ExecutionStatus.FAILED)
        # Degradation is not an execution failure: the wire vocabulary has no
        # degraded value and the run finished its audit loop.
        degraded = platform_review_to_workflow_summary(
            _outcome(diagnostics=("scout: degraded provider output",)),
            snapshot_sha256=SNAPSHOT,
            repository=REPOSITORY,
        )
        self.assertIs(degraded.execution_status, ExecutionStatus.SUCCEEDED)

    def test_workflow_summary_evidence_links_to_veps(self):
        findings = (
            _plain_finding(
                {
                    "target_id": "lead-0001",
                    "path": "src/example.c",
                    "line": 42,
                    "symbol": "parse_input",
                    "cwe": "CWE-787",
                    "state": "runtime-confirmed",
                    "hypothesis_reason": "Attacker-controlled length reaches memcpy.",
                    "poc_driver_code": "int main(void) { return 0; }",
                    "experiment_log": (_HIT_ENTRY,),
                    "identity": None,
                    "evidence_records": (_ASAN_RECORD,),
                }
            ),
            _plain_finding(
                {
                    "target_id": "lead-0002",
                    "path": "src/example.c",
                    "line": 43,
                    "symbol": "parse_input",
                    "cwe": "CWE-787",
                    "state": "tool-corroborated",
                    "hypothesis_reason": "Second reachable memcpy.",
                    "poc_driver_code": "int main(void) { return 0; }",
                    "experiment_log": (),
                    "identity": None,
                    "evidence_records": (_STATIC_RECORD,),
                }
            ),
        )
        summary = platform_review_to_workflow_summary(
            _outcome(findings=findings, targets=findings, stats=PlatformReviewStats(
                2, 2, 2, 1, 3, 2, 1,
            )),
            snapshot_sha256=SNAPSHOT,
            repository=REPOSITORY,
        )
        veps = [
            finding_to_vep(finding, snapshot_sha256=SNAPSHOT, repository=REPOSITORY)
            for finding in findings
        ]
        digests = {
            vep.hypothesis_id: compute_content_digest(vep.to_dict()) for vep in veps
        }
        # One evidence link per finding, addressed at the real VEP identity.
        self.assertEqual(len(summary.evidence), len(veps))
        self.assertEqual(
            [link.artifact_id for link in summary.evidence],
            sorted(digests),
        )
        for link in summary.evidence:
            self.assertIs(
                link.kind, SummaryReferenceKind.VULNERABILITY_EVIDENCE_PACKAGE
            )
            self.assertEqual(link.schema_version, SchemaVersion(4, 0))
            self.assertEqual(link.content_digest, digests[link.artifact_id])
        # One stage-attempt link per platform role, sorted by artifact id.
        self.assertEqual(len(summary.stage_attempts), 3)
        for link in summary.stage_attempts:
            self.assertIs(link.kind, SummaryReferenceKind.STAGE_ATTEMPT)
        self.assertEqual(
            [link.artifact_id for link in summary.stage_attempts],
            sorted(link.artifact_id for link in summary.stage_attempts),
        )

    def test_workflow_summary_rejects_empty_outcome(self):
        empty = _outcome(
            findings=(),
            targets=(),
            stats=PlatformReviewStats(0, 0, 0, 0, 0, 0, 0),
            leads_considered=0,
            diagnostics=(),
        )
        with self.assertRaises(ValueError):
            platform_review_to_workflow_summary(
                empty, snapshot_sha256=SNAPSHOT, repository=REPOSITORY
            )

    # ---------------------------------------------------------------- codec

    def test_roundtrip_via_codec(self):
        aep = platform_review_to_aep(
            _outcome(
                diagnostics=("coverage gap: unit vendored/big.c skipped",)
            ),
            snapshot_sha256=SNAPSHOT,
            repository=REPOSITORY,
        )
        payload = encode_aep_payload(aep)
        decoded = decode_aep_payload(payload, schema_version=SchemaVersion(4, 0))
        self.assertEqual(decoded, aep)
        self.assertEqual(encode_aep_payload(decoded), payload)

        summary = platform_review_to_workflow_summary(
            _outcome(), snapshot_sha256=SNAPSHOT, repository=REPOSITORY
        )
        summary_payload = encode_workflow_summary_payload(summary)
        summary_decoded = decode_workflow_summary_payload(
            summary_payload, schema_version=SchemaVersion(4, 0)
        )
        self.assertEqual(summary_decoded, summary)
        self.assertEqual(
            encode_workflow_summary_payload(summary_decoded), summary_payload
        )


# --- task T3: PatchFlowOutcome -> RVR + golden path chain -------------------

_PATCHED_CONTENT = (
    "void parse_input(const char *data, unsigned n) {\n"
    "    if (n <= 256u) {\n"
    "        memcpy(buffer, data, n);\n"
    "    }\n"
    "}\n"
)
_PATCH_RATIONALE = (
    "Bounds-check the attacker-controlled length against the buffer size "
    "before the memcpy; everything else is preserved verbatim."
)


def _patch_outcome(**overrides):
    """One verified patch flow outcome for the T1 runtime-confirmed finding."""

    proposal = PatchProposal(
        target_path="src/example.c",
        patched_content=_PATCHED_CONTENT,
        rationale=_PATCH_RATIONALE,
    )
    verification = PatchVerification(
        compiles=True,
        poc_still_triggers=False,
        asan_type_after=None,
        verified=True,
        diagnostics=(),
    )
    base = {
        "proposal": proposal,
        "verification": verification,
        "rounds_used": 1,
        "verified": True,
        "diagnostics": (),
    }
    base.update(overrides)
    return PatchFlowOutcome(**base)


@unittest.skipIf(
    patch_outcome_to_rvr is None, "patch_outcome_to_rvr not implemented (RED)"
)
class PatchOutcomeToRvrTests(unittest.TestCase):
    """PatchFlowOutcome -> RepairVerificationReport converter (T3)."""

    def test_patch_outcome_to_rvr_verified(self):
        finding = _finding()
        rvr = patch_outcome_to_rvr(
            _patch_outcome(),
            finding=finding,
            snapshot_sha256=SNAPSHOT,
            repository=REPOSITORY,
        )
        vep = finding_to_vep(finding, snapshot_sha256=SNAPSHOT, repository=REPOSITORY)
        self.assertEqual(rvr.schema_version, SchemaVersion(4, 0))
        self.assertEqual(rvr.source_vep.artifact_id, vep.hypothesis_id)
        self.assertEqual(
            rvr.source_vep.content_digest, compute_content_digest(vep.to_dict())
        )
        self.assertEqual(len(rvr.candidates), 1)
        candidate = rvr.candidates[0]
        self.assertIs(candidate.verdict, CandidateVerdict.VERIFIED_PATCH)
        self.assertTrue(candidate.candidate_id.startswith("cand-"))
        self.assertEqual(candidate.changed_files, ("src/example.c",))
        self.assertEqual(
            candidate.patch.content_digest,
            hashlib.sha256(_PATCHED_CONTENT.encode("utf-8")).hexdigest(),
        )
        self.assertTrue(candidate.patch.patch_artifact_id.startswith("patch-"))
        self.assertEqual(candidate.strategy, _PATCH_RATIONALE)
        self.assertEqual(
            [gate.gate for gate in candidate.gates],
            [GateKind.FUNCTIONAL_PRESERVATION, GateKind.SECURITY_PRESERVATION],
        )
        self.assertIs(candidate.gates[0].outcome, GateOutcome.PASS)
        self.assertIs(candidate.gates[1].outcome, GateOutcome.PASS)
        # The generator (patch engineer model) never verifies its own patch.
        for gate in candidate.gates:
            self.assertNotEqual(gate.producer, candidate.generator)
        # Deterministic: same inputs -> identical report.
        again = patch_outcome_to_rvr(
            _patch_outcome(),
            finding=finding,
            snapshot_sha256=SNAPSHOT,
            repository=REPOSITORY,
        )
        self.assertEqual(rvr, again)

    def test_patch_outcome_to_rvr_rejected(self):
        poc_still = patch_outcome_to_rvr(
            _patch_outcome(
                rounds_used=2,
                verified=False,
                verification=PatchVerification(
                    compiles=True,
                    poc_still_triggers=True,
                    asan_type_after="heap-buffer-overflow",
                    verified=False,
                    diagnostics=("poc-still-triggers",),
                ),
            ),
            finding=_finding(),
            snapshot_sha256=SNAPSHOT,
            repository=REPOSITORY,
        )
        candidate = poc_still.candidates[0]
        self.assertIs(candidate.verdict, CandidateVerdict.REJECTED)
        self.assertIs(candidate.gates[0].outcome, GateOutcome.PASS)
        self.assertIs(candidate.gates[1].outcome, GateOutcome.FAILED)
        self.assertIn("poc-still-triggers", candidate.gates[1].detail)
        self.assertIn("heap-buffer-overflow", candidate.gates[1].detail)
        # Compile failure is the other honest rejection path.
        no_compile = patch_outcome_to_rvr(
            _patch_outcome(
                rounds_used=2,
                verified=False,
                verification=PatchVerification(
                    compiles=False,
                    poc_still_triggers=None,
                    asan_type_after=None,
                    verified=False,
                    diagnostics=("patch-does-not-compile",),
                ),
            ),
            finding=_finding(),
            snapshot_sha256=SNAPSHOT,
            repository=REPOSITORY,
        )
        candidate = no_compile.candidates[0]
        self.assertIs(candidate.verdict, CandidateVerdict.REJECTED)
        self.assertIs(candidate.gates[0].outcome, GateOutcome.FAILED)
        self.assertIs(candidate.gates[1].outcome, GateOutcome.INCONCLUSIVE)
        self.assertIn("patch-does-not-compile", candidate.gates[0].detail)

    def test_patch_outcome_to_rvr_noop_diagnostic_preserved(self):
        rvr = patch_outcome_to_rvr(
            _patch_outcome(
                verified=False,
                verification=PatchVerification(
                    compiles=None,
                    poc_still_triggers=None,
                    asan_type_after=None,
                    verified=False,
                    diagnostics=("patch-is-noop",),
                ),
            ),
            finding=_finding(),
            snapshot_sha256=SNAPSHOT,
            repository=REPOSITORY,
        )
        candidate = rvr.candidates[0]
        # The noop shortcut never compiled and never ran the PoC: nothing was
        # judged, so both gates stay inconclusive and the verdict follows.
        self.assertIs(candidate.verdict, CandidateVerdict.INCONCLUSIVE)
        for gate in candidate.gates:
            self.assertIs(gate.outcome, GateOutcome.INCONCLUSIVE)
            self.assertIn("patch-is-noop", gate.detail)

    def test_patch_outcome_to_rvr_rejects_unrepresentable_outcomes(self):
        generation_failed = PatchFlowOutcome(
            proposal=None,
            verification=None,
            rounds_used=1,
            verified=False,
            diagnostics=("patch-generation-failed",),
        )
        with self.assertRaises(ValueError):
            patch_outcome_to_rvr(
                generation_failed,
                finding=_finding(),
                snapshot_sha256=SNAPSHOT,
                repository=REPOSITORY,
            )
        # An unverified outcome whose gates would both pass is contradictory
        # and must never surface as verified_patch (fail-closed).
        with self.assertRaises(ValueError):
            patch_outcome_to_rvr(
                _patch_outcome(verified=False, diagnostics=("critic-overruled",)),
                finding=_finding(),
                snapshot_sha256=SNAPSHOT,
                repository=REPOSITORY,
            )

    def test_rvr_roundtrip_via_codec(self):
        rvr = patch_outcome_to_rvr(
            _patch_outcome(),
            finding=_finding(),
            snapshot_sha256=SNAPSHOT,
            repository=REPOSITORY,
        )
        payload = rvr.to_dict()
        decoded = decode_rvr_payload(payload, schema_version=SchemaVersion(4, 0))
        self.assertEqual(decoded, rvr)
        self.assertEqual(encode_rvr_payload(decoded), payload)
        self.assertEqual(
            compute_content_digest(payload),
            compute_content_digest(encode_rvr_payload(decoded)),
        )
        # Canonical JSON round trip stays stable for downstream digesting.
        self.assertEqual(json.loads(json.dumps(payload)), payload)


@unittest.skipIf(
    patch_outcome_to_rvr is None, "patch_outcome_to_rvr not implemented (RED)"
)
class PlatformGoldenPathTests(unittest.TestCase):
    """End-to-end platform run -> AEP -> VEP -> RVR -> WorkflowSummary (T3)."""

    def test_golden_path_chain_digest_consistency(self):
        finding = _finding()
        outcome = _outcome(findings=(finding,), targets=(finding,))
        patch_outcome = _patch_outcome()

        vep = finding_to_vep(finding, snapshot_sha256=SNAPSHOT, repository=REPOSITORY)
        aep = platform_review_to_aep(
            outcome, snapshot_sha256=SNAPSHOT, repository=REPOSITORY
        )
        rvr = patch_outcome_to_rvr(
            patch_outcome,
            finding=finding,
            snapshot_sha256=SNAPSHOT,
            repository=REPOSITORY,
        )
        summary = platform_review_to_workflow_summary(
            outcome, snapshot_sha256=SNAPSHOT, repository=REPOSITORY
        )
        digests = {
            "vulnerability_evidence_package": compute_content_digest(vep.to_dict()),
            "audit_evidence_package": compute_content_digest(aep.to_dict()),
            "repair_verification_report": compute_content_digest(rvr.to_dict()),
            "workflow_summary": compute_content_digest(summary.to_dict()),
        }

        # Hop RVR -> VEP: the identity triple pins the real VEP payload digest.
        self.assertEqual(rvr.source_vep.artifact_id, vep.hypothesis_id)
        self.assertEqual(
            rvr.source_vep.content_digest,
            digests["vulnerability_evidence_package"],
        )
        # Hop WorkflowSummary -> VEP: one evidence link at the VEP digest.
        links = {link.artifact_id: link for link in summary.evidence}
        self.assertEqual(sorted(links), [vep.hypothesis_id])
        link = links[vep.hypothesis_id]
        self.assertIs(link.kind, SummaryReferenceKind.VULNERABILITY_EVIDENCE_PACKAGE)
        self.assertEqual(link.schema_version, SchemaVersion(4, 0))
        self.assertEqual(
            link.content_digest, digests["vulnerability_evidence_package"]
        )
        # Every artifact decodes through the frozen contract decoder, re-encodes
        # identically, and recomputes to the same codec digest.
        for name, payload, decode, encode in (
            (
                "audit_evidence_package",
                aep.to_dict(),
                decode_aep_payload,
                encode_aep_payload,
            ),
            (
                "vulnerability_evidence_package",
                vep.to_dict(),
                decode_vep_payload,
                encode_vep_payload,
            ),
            (
                "repair_verification_report",
                rvr.to_dict(),
                decode_rvr_payload,
                encode_rvr_payload,
            ),
            (
                "workflow_summary",
                summary.to_dict(),
                decode_workflow_summary_payload,
                encode_workflow_summary_payload,
            ),
        ):
            with self.subTest(artifact=name):
                decoded = decode(payload, schema_version=SchemaVersion(4, 0))
                self.assertEqual(encode(decoded), payload)
                self.assertEqual(
                    compute_content_digest(encode(decoded)), digests[name]
                )
        # The RVR gates carry the real patch verification facts.
        candidate = rvr.candidates[0]
        self.assertIs(candidate.verdict, CandidateVerdict.VERIFIED_PATCH)
        self.assertIs(candidate.gates[0].outcome, GateOutcome.PASS)
        self.assertIs(candidate.gates[1].outcome, GateOutcome.PASS)
        self.assertEqual(
            candidate.patch.content_digest,
            hashlib.sha256(_PATCHED_CONTENT.encode("utf-8")).hexdigest(),
        )
        # Deterministic end to end: rerunning the whole chain is stable.
        again_vep = finding_to_vep(
            finding, snapshot_sha256=SNAPSHOT, repository=REPOSITORY
        )
        again_aep = platform_review_to_aep(
            outcome, snapshot_sha256=SNAPSHOT, repository=REPOSITORY
        )
        again_rvr = patch_outcome_to_rvr(
            _patch_outcome(),
            finding=finding,
            snapshot_sha256=SNAPSHOT,
            repository=REPOSITORY,
        )
        again_summary = platform_review_to_workflow_summary(
            outcome, snapshot_sha256=SNAPSHOT, repository=REPOSITORY
        )
        self.assertEqual(
            compute_content_digest(again_vep.to_dict()),
            digests["vulnerability_evidence_package"],
        )
        self.assertEqual(
            compute_content_digest(again_aep.to_dict()),
            digests["audit_evidence_package"],
        )
        self.assertEqual(
            compute_content_digest(again_rvr.to_dict()),
            digests["repair_verification_report"],
        )
        self.assertEqual(
            compute_content_digest(again_summary.to_dict()),
            digests["workflow_summary"],
        )


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
