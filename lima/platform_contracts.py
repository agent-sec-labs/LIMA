"""PlatformFinding -> VulnerabilityEvidencePackage conversion (agent platform T1).

The agent platform (:mod:`lima.agent_orchestrator`) renders audited targets
as :class:`~lima.agent_orchestrator.PlatformFinding`; the main-branch
contract chain consumes :class:`~lima.contracts.vep.VulnerabilityEvidencePackage`.
This module is the one-way boundary between the two: it maps a platform
finding onto the V4 VEP vocabulary and lets the frozen VEP validation
reject anything it cannot express honestly.  Nothing here mutates the
contracts; every produced package is validated by the real
``VulnerabilityEvidencePackage`` constructor (fail-closed).

State mapping (task T1, adapted to the frozen V4 vocabulary):

========================================  ==========================  ==========================
``PlatformFinding.state``                 ``claim_kind``              ``verification_verdict``
========================================  ==========================  ==========================
``runtime-confirmed``                     ``runtime_exploitability``  ``verified``
``fact-verified`` / ``tool-corroborated`` ``static_property``         ``inconclusive`` (*)
``semantic-supported`` /
``needs-human-review``
``rejected``                              ``runtime_exploitability``  ``refuted_scope``
anything else (incl. ``abstain``)         rejected (``ValueError``)
========================================  ==========================  ==========================

(*) The task's "probable-vulnerability" bucket.  The frozen V4 verdict
matrix admits ``candidate`` only with D3+ SUPPORTS evidence, and the
platform never mints D3 for these states (semantic support is D1, static
tools are D2), so the fail-closed wire form is ``inconclusive``.  If a
future platform state carries D3 SUPPORTS evidence, the bucket upgrades to
``runtime_exploitability`` + ``candidate``.

Evidence policy:

- ``models.EvidenceRecord`` entries with ``source == "asan"`` lift to D3
  SUPPORTS records (the producer-documented level assignment of
  :func:`lima.uaf_orchestrator.contract_evidence_record`); static tool
  records are D2 and stay platform-side because the VEP admits D3/D4 only.
- ``runtime-confirmed`` layers a D4 platform-confirmation record onto the
  D3 run record (golden-path VEP shape: D3 = reproduced run, D4 =
  confirmation layer) and requires the reproduced run plus non-empty
  impact, as the matrix demands.
- ``rejected`` synthesizes a D3 REFUTES record grounded in the proof
  refutation, with the bounded ``rejected_reason`` as refutation scope.

``source_aep``/``oracle`` references are deterministic stand-ins derived
from the finding identity unless the caller supplies real references
(task T2 re-stamps them once the platform AEP exists); they are payload-
level pins only and gain real lineage binding when VEPs travel in
envelopes.
"""

import hashlib
import json
import re
import secrets
import unicodedata
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Final

from lima.agent_orchestrator import (
    PlatformFinding,
    PlatformReviewOutcome,
    platform_rule_id,
)
from lima.agent_patch import PatchFlowOutcome
from lima.contracts.aep import (
    AuditBudget,
    AuditCoverage,
    AuditCoverageGap,
    AuditDepth,
    AuditEvidencePackage,
    AuditOutcome,
    AuditPackageStatus,
)
from lima.contracts.codec import compute_content_digest
from lima.contracts.common import SchemaVersion
from lima.contracts.evidence import (
    EvidenceDomainBundle,
    EvidenceLevel,
    EvidencePolarity,
    EvidenceRecord,
    EvidenceSubjectKind,
    HypothesisStatus,
    RequiredProofKind,
    SecurityIssue,
    Signal,
    SourceLocation,
    VulnerabilityHypothesis,
)
from lima.contracts.rvr import (
    CandidateVerdict,
    CandidateVerification,
    GateKind,
    GateOutcome,
    GateResult,
    PatchReference,
    RepairVerificationReport,
    VepReference,
)
from lima.contracts.summary import (
    ArtifactLink,
    ExecutionStatus,
    SummaryReferenceKind,
    SummarySourceKind,
    WorkflowSummary,
)
from lima.contracts.vep import (
    AepReference,
    ClaimKind,
    OracleReference,
    ReproductionOutcome,
    ReproductionRun,
    VerificationVerdict,
    VulnerabilityEvidencePackage,
)
from lima.evidence_privacy.models import (
    ArtifactClassification,
    EvidencePayload,
    SinkContext,
)
from lima.evidence_privacy.policy import DEFAULT_POLICY
from lima.evidence_privacy.port import sanitize_for_sink

__all__ = [
    "PlatformSealBundle",
    "finding_to_vep",
    "patch_outcome_to_rvr",
    "platform_review_to_aep",
    "platform_review_to_workflow_summary",
    "privacy_text",
    "seal_platform_review",
]

SCHEMA_VERSION: Final = SchemaVersion(4, 0)
_PLATFORM_PRODUCER: Final = "lima-agent-platform"
_CWE_PATTERN: Final = re.compile(r"CWE-[1-9][0-9]{0,5}")
_MAX_TEXT_BYTES: Final = 4096

_CONFIRMED_STATE: Final = "runtime-confirmed"
_PROBABLE_STATES: Final = frozenset(
    {
        "fact-verified",
        "tool-corroborated",
        "semantic-supported",
        "needs-human-review",
    }
)
_DISPUTED_STATE: Final = "rejected"

# --- task T2: platform review -> AEP / WorkflowSummary ---------------------

_IDENTIFIER_SAFE: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}")
_CANCELLED_PRESTART: Final = "cancelled before the platform review started"
_FAILED_PRESTART_PREFIXES: Final = (
    "deadline-exceeded before the platform review started",
    "scout-unavailable:",
)
_COVERAGE_GAP_PREFIX: Final = "coverage gap: "
_COVERAGE_GAP_CODE: Final = "COVERAGE_GAP"
_AEP_MAX_DETAIL_BYTES: Final = 4096
_STAGE_ROLES: Final = ("scout", "specialist", "critic")


def _canonical_json(material: Mapping[str, Any]) -> str:
    return json.dumps(material, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _short_digest(material: str) -> str:
    return hashlib.sha256(material.encode("utf-8")).hexdigest()[:24]


# --- review round 3: #94 privacy redaction for report-bound free text -------

# One random tenant key per process run, mirroring the one-run pattern of
# scripts/audit_sensitive_artifacts.py (#94): fingerprints are comparable
# within the run and meaningless outside it.
_PRIVACY_TENANT_KEY: Final = secrets.token_bytes(32)
_PRIVACY_REDACTED: Final = "[privacy-redacted]"


def privacy_text(value: str) -> str:
    """Mask secret-shaped material in free text (#94 detection reuse).

    Review round 4: the report-embedded preview has no tenant-key
    infrastructure, so it deliberately emits **no fingerprints** -- any
    string the #94 classifier flags (sensitive or restricted, or carrying
    redactable spans) is replaced by one fixed opaque mask. The #94 tenant
    fingerprint contract (cross-tenant non-linkability, same-tenant
    cross-task dedup, NFR-N05-01/AC-N05-02) therefore does not apply to
    this path: the mask is constant, carries no correlation signal, and
    this preview path provides no dedup semantics. Classification itself
    is key-independent, so the detection tenant key stays random and
    never leaves this function; any sanitizer failure fails closed to the
    same mask -- never the original text. Clean internal text passes
    through unchanged.
    """

    try:
        sanitized = sanitize_for_sink(
            EvidencePayload(payload_kind="text", value=value),
            SinkContext(
                sink_kind="storage",
                purpose="platform-report-preview",
                tenant_id="platform-preview",
                tenant_key=_PRIVACY_TENANT_KEY,
            ),
            DEFAULT_POLICY,
        )
    except Exception:  # noqa: BLE001 - fail closed, never persist raw text
        return _PRIVACY_REDACTED
    manifest = sanitized.manifest
    if (
        manifest.classification is not ArtifactClassification.INTERNAL
        or manifest.entries
    ):
        return _PRIVACY_REDACTED
    return value


def _sanitize_text(value: object, *, cap: int) -> str:
    """Bound one piece of platform free text for a bounded-text field.

    Control characters (ASan logs carry newlines) collapse to spaces so the
    contract's bounded-text validation passes; output is deterministic.
    Free text additionally passes the #94 privacy redaction
    (:func:`privacy_text`) so credential-shaped material never enters the
    report-bound payloads.
    """

    if not isinstance(value, str):
        raise ValueError(f"expected str text, got {type(value).__name__}")
    cleaned = "".join(
        " " if unicodedata.category(char) == "Cc" else char for char in value
    )
    cleaned = " ".join(cleaned.split())
    cleaned = privacy_text(cleaned)
    if len(cleaned.encode("utf-8")) > cap:
        cleaned = cleaned[:cap]
    return cleaned.strip()


def _normalized_cwe(raw: object) -> str:
    if not isinstance(raw, str):
        raise ValueError(f"invalid cwe: {raw!r}")
    text = raw.strip().upper()
    if text and not text.startswith("CWE-"):
        text = "CWE-" + text
    if _CWE_PATTERN.fullmatch(text) is None:
        raise ValueError(f"invalid cwe: {raw!r}")
    return text


def _normalized_path(raw: object) -> str:
    if not isinstance(raw, str):
        raise ValueError(f"invalid path: {raw!r}")
    text = raw.replace("\\", "/").strip()
    while text.startswith("./"):
        text = text[2:]
    return text


def _hypothesis_id(finding: PlatformFinding, *, snapshot_sha256: str, repository: str) -> str:
    material = _canonical_json(
        {
            "repository": repository,
            "snapshot_sha256": snapshot_sha256,
            "target_id": finding.target_id,
        }
    )
    return "hyp-" + _short_digest(material)


def _run_outcome(entry: Mapping[str, Any]) -> ReproductionOutcome:
    if entry.get("hit"):
        return ReproductionOutcome.REPRODUCED
    if not entry.get("ok", False):
        return ReproductionOutcome.TOOL_ERROR
    return ReproductionOutcome.NOT_REPRODUCED


def _run_artifact_id(
    entry: Mapping[str, Any],
    *,
    snapshot_sha256: str,
    bound_run_id: str | None,
) -> str:
    if bound_run_id is not None:
        return bound_run_id
    material = (
        f"{snapshot_sha256}:{entry.get('driver_sha256', '')}:{entry.get('round', 0)}"
    )
    return "repro-" + _short_digest(material)


def _reproduction_runs(
    finding: PlatformFinding,
    *,
    snapshot_sha256: str,
    asan_run_id: str | None,
) -> tuple[ReproductionRun, ...]:
    runs: dict[str, ReproductionRun] = {}
    bound_used = False
    for entry in finding.experiment_log:
        if not isinstance(entry, Mapping):
            raise ValueError("experiment_log entries must be mappings")
        run_id = _run_artifact_id(
            entry,
            snapshot_sha256=snapshot_sha256,
            bound_run_id=asan_run_id if entry.get("hit") and not bound_used else None,
        )
        if entry.get("hit") and asan_run_id is not None:
            bound_used = True
        runs.setdefault(
            run_id,
            ReproductionRun(
                run_artifact_id=run_id,
                outcome=_run_outcome(entry),
                detail=_canonical_json(dict(entry))[:_MAX_TEXT_BYTES],
            ),
        )
    return tuple(sorted(runs.values(), key=lambda run: run.run_artifact_id))


def _lift_evidence_record(record: Any, subject_id: str) -> EvidenceRecord | None:
    """Lift one ``models.EvidenceRecord`` to the contract domain, or None.

    Only runtime (ASan) records are VEP-admissible (D3); static tool
    records are D2 and stay platform-side.
    """

    if record.source != "asan":
        return None
    material = _canonical_json(
        {
            "line": record.line,
            "path": record.path,
            "snippet": record.snippet,
            "source": record.source,
            "subject_id": subject_id,
            "tool_run_id": record.tool_run_id,
        }
    )
    summary = _sanitize_text(record.snippet, cap=_MAX_TEXT_BYTES)
    if not summary:
        summary = _sanitize_text(
            f"{record.source} evidence at {record.path}:{record.line}", cap=512
        )
    return EvidenceRecord(
        evidence_id="ev" + _short_digest(material),
        subject_kind=EvidenceSubjectKind.VULNERABILITY_HYPOTHESIS,
        subject_id=subject_id,
        level=EvidenceLevel.D3,
        polarity=EvidencePolarity.SUPPORTS,
        analysis_family="runtime-sanitizer",
        producer=record.source,
        independence_key=_sanitize_text(
            f"{record.source}:{record.path}:{record.line}", cap=512
        ),
        summary=summary,
        source_artifact_ids=(record.tool_run_id,) if record.tool_run_id else (),
        reason_codes=("RUNTIME_REPRODUCED",),
    )


def _adjudication_record(
    *,
    subject_id: str,
    layer: str,
    level: EvidenceLevel,
    polarity: EvidencePolarity,
    summary: str,
    reason_code: str,
    source_artifact_ids: tuple[str, ...],
    depends_on: tuple[str, ...] = (),
) -> EvidenceRecord:
    material = _canonical_json(
        {
            "layer": layer,
            "subject_id": subject_id,
            "summary": summary,
        }
    )
    return EvidenceRecord(
        evidence_id="ev" + _short_digest(material),
        subject_kind=EvidenceSubjectKind.VULNERABILITY_HYPOTHESIS,
        subject_id=subject_id,
        level=level,
        polarity=polarity,
        analysis_family="platform-adjudication",
        producer=_PLATFORM_PRODUCER,
        independence_key=_sanitize_text(f"{layer}:{subject_id}", cap=512),
        summary=_sanitize_text(summary, cap=_MAX_TEXT_BYTES),
        source_artifact_ids=source_artifact_ids,
        reason_codes=(reason_code,),
        depends_on_evidence_ids=depends_on,
    )


def _dedupe_sorted(records: list[EvidenceRecord]) -> tuple[EvidenceRecord, ...]:
    unique: dict[str, EvidenceRecord] = {}
    for record in records:
        unique.setdefault(record.evidence_id, record)
    return tuple(sorted(unique.values(), key=lambda record: record.evidence_id))


def finding_to_vep(
    finding: PlatformFinding,
    *,
    snapshot_sha256: str,
    repository: str,
    source_aep: AepReference | None = None,
    oracle: OracleReference | None = None,
) -> VulnerabilityEvidencePackage:
    """Convert one platform finding into a strictly validated V4 VEP.

    Raises ``ValueError`` for findings that express no claim the VEP
    vocabulary can carry honestly (``abstain``, unknown states, malformed
    fields) and lets ``ContractError`` surface whenever the constructed
    package fails the frozen VEP validation.
    """

    if not isinstance(snapshot_sha256, str) or not snapshot_sha256:
        raise ValueError("snapshot_sha256 must be a non-empty string")
    if not isinstance(repository, str) or not repository:
        raise ValueError("repository must be a non-empty string")

    cwe = _normalized_cwe(finding.cwe)
    state = finding.state
    if (
        state != _CONFIRMED_STATE
        and state not in _PROBABLE_STATES
        and state != _DISPUTED_STATE
    ):
        raise ValueError(f"finding state {state!r} expresses no VEP claim")

    path = _normalized_path(finding.path)
    hypothesis_id = _hypothesis_id(
        finding, snapshot_sha256=snapshot_sha256, repository=repository
    )
    target_location = SourceLocation(
        path=path,
        start_line=finding.line,
        end_line=finding.line,
        symbol=_sanitize_text(finding.symbol, cap=512) or None,
    )

    lifted = [
        lifted_record
        for candidate in finding.evidence_records
        if (lifted_record := _lift_evidence_record(candidate, hypothesis_id))
        is not None
    ]
    asan_run_ids = [
        candidate.tool_run_id
        for candidate in finding.evidence_records
        if candidate.source == "asan" and candidate.tool_run_id
    ]
    asan_run_id = asan_run_ids[0] if asan_run_ids else None
    runs = _reproduction_runs(
        finding, snapshot_sha256=snapshot_sha256, asan_run_id=asan_run_id
    )

    impact: str | None = None
    refutation_scope: str | None = None
    if state == _CONFIRMED_STATE:
        if not lifted:
            raise ValueError("runtime-confirmed finding carries no D3 runtime evidence")
        reproduced = [
            run.run_artifact_id
            for run in runs
            if run.outcome is ReproductionOutcome.REPRODUCED
        ]
        if not reproduced:
            raise ValueError("runtime-confirmed finding carries no reproduced run")
        reproduced_id = min(reproduced)
        d3_ids = sorted(record.evidence_id for record in lifted)
        lifted.append(
            _adjudication_record(
                subject_id=hypothesis_id,
                layer="platform-confirmation",
                level=EvidenceLevel.D4,
                polarity=EvidencePolarity.SUPPORTS,
                summary=(
                    f"Platform adjudication runtime-confirmed {cwe} at "
                    f"{path}:{finding.line}; reproduced by {reproduced_id}."
                ),
                reason_code="RUNTIME_CONFIRMED",
                source_artifact_ids=(reproduced_id,),
                depends_on=(d3_ids[0],),
            )
        )
        impact = _sanitize_text(
            f"{cwe} at {path}:{finding.line} "
            f"({target_location.symbol or 'unknown symbol'}): runtime-confirmed, "
            f"reproduced by {reproduced_id}",
            cap=1024,
        )
        claim_kind = ClaimKind.RUNTIME_EXPLOITABILITY
        verdict = VerificationVerdict.VERIFIED
    elif state == _DISPUTED_STATE:
        scope = _sanitize_text(finding.rejected_reason, cap=1024)
        if not scope:
            raise ValueError("rejected finding carries no refutation scope")
        refutation_scope = scope
        lifted.append(
            _adjudication_record(
                subject_id=hypothesis_id,
                layer="proof-refutation",
                level=EvidenceLevel.D3,
                polarity=EvidencePolarity.REFUTES,
                summary=scope,
                reason_code="PROOF_OBLIGATION_REFUTED",
                source_artifact_ids=(
                    "proof-" + _short_digest(f"{snapshot_sha256}:{finding.target_id}"),
                ),
            )
        )
        claim_kind = ClaimKind.RUNTIME_EXPLOITABILITY
        verdict = VerificationVerdict.REFUTED_SCOPE
    else:
        # Probable bucket: candidate is expressible only with D3+ SUPPORTS.
        if any(
            record.level is EvidenceLevel.D3
            and record.polarity is EvidencePolarity.SUPPORTS
            for record in lifted
        ):
            claim_kind = ClaimKind.RUNTIME_EXPLOITABILITY
            verdict = VerificationVerdict.CANDIDATE
        else:
            claim_kind = ClaimKind.STATIC_PROPERTY
            verdict = VerificationVerdict.INCONCLUSIVE

    trigger = _sanitize_text(finding.hypothesis_reason, cap=512)

    identity_material = _canonical_json(
        {
            "cwe": cwe,
            "kind": "lima.platform.finding",
            "line": finding.line,
            "path": path,
            "repository": repository,
            "snapshot_sha256": snapshot_sha256,
            "target_id": finding.target_id,
        }
    )
    resolved_aep = source_aep or AepReference(
        artifact_id="aep-platform-" + _short_digest(identity_material),
        content_digest=hashlib.sha256(identity_material.encode("utf-8")).hexdigest(),
        schema_version=SCHEMA_VERSION,
    )
    oracle_material = _canonical_json(
        {
            "driver_sha256": hashlib.sha256(
                finding.poc_driver_code.encode("utf-8")
            ).hexdigest(),
            "kind": "lima.platform.oracle",
            "repository": repository,
            "snapshot_sha256": snapshot_sha256,
            "target_id": finding.target_id,
        }
    )
    resolved_oracle = oracle or OracleReference(
        oracle_artifact_id="oracle-platform-" + _short_digest(oracle_material),
        content_digest=hashlib.sha256(oracle_material.encode("utf-8")).hexdigest(),
    )

    return VulnerabilityEvidencePackage(
        schema_version=SCHEMA_VERSION,
        verification_verdict=verdict,
        claim_kind=claim_kind,
        hypothesis_id=hypothesis_id,
        source_aep=resolved_aep,
        source_aep_revision=1,
        oracle=resolved_oracle,
        evidence=_dedupe_sorted(lifted),
        target_location=target_location,
        impact=impact,
        refutation_scope=refutation_scope,
        reproduction_runs=runs,
        trigger_conditions=(trigger,) if trigger else (),
        cwe_ids=(cwe,),
    )


def _identifier_safe(value: object, fallback: str) -> str:
    """Keep ``value`` when it already is a contract identifier, else fall back."""

    if isinstance(value, str) and _IDENTIFIER_SAFE.fullmatch(value) is not None:
        return value
    return fallback


def _audit_subject_record(
    *,
    evidence_id: str,
    subject_kind: EvidenceSubjectKind,
    subject_id: str,
    summary: str,
    reason_code: str,
    artifact_id: str,
) -> EvidenceRecord:
    """One D0 platform bookkeeping record bound to a signal or issue subject."""

    return EvidenceRecord(
        evidence_id=evidence_id,
        subject_kind=subject_kind,
        subject_id=subject_id,
        level=EvidenceLevel.D0,
        polarity=EvidencePolarity.SUPPORTS,
        analysis_family="platform-adjudication",
        producer=_PLATFORM_PRODUCER,
        independence_key=_sanitize_text(
            f"{subject_kind.value}:{subject_id}", cap=512
        ),
        summary=_sanitize_text(summary, cap=_MAX_TEXT_BYTES),
        source_artifact_ids=(artifact_id,),
        reason_codes=(reason_code,),
    )


def _aep_finding_objects(
    finding: PlatformFinding,
    *,
    snapshot_sha256: str,
    repository: str,
) -> tuple[Signal, SecurityIssue, VulnerabilityHypothesis, list[EvidenceRecord]]:
    """Project one platform finding onto the audit (D0-D2) evidence graph.

    State -> static hypothesis status (the bundle derives statuses from D2
    records bound to the hypothesis, so the mapping below is exactly the
    admissible one):

    ================================  ==============================  =============================
    ``PlatformFinding.state``         bound records                   hypothesis status
    ================================  ==============================  =============================
    ``fact-verified`` /
    ``tool-corroborated``             D2 SUPPORTS per static record   ``statically_supported``
    ``semantic-supported`` /
    ``needs-human-review`` /
    ``runtime-confirmed``             D1 SUPPORTS platform record     ``proposed``
    ================================  ==============================  =============================

    Runtime (ASan, D3) records stay out of the audit bundle (D0-D2 only);
    they travel in the VEP produced by :func:`finding_to_vep`.  Every graph
    object also gets one D0 bookkeeping record because the bundle requires
    non-empty evidence binding per subject.
    """

    cwe = _normalized_cwe(finding.cwe)
    path = _normalized_path(finding.path)
    hypothesis_id = _hypothesis_id(
        finding, snapshot_sha256=snapshot_sha256, repository=repository
    )
    identity_material = _canonical_json(
        {
            "cwe": cwe,
            "kind": "lima.platform.audit-object",
            "line": finding.line,
            "path": path,
            "repository": repository,
            "snapshot_sha256": snapshot_sha256,
            "target_id": finding.target_id,
        }
    )
    digest = hashlib.sha256(identity_material.encode("utf-8")).hexdigest()
    short = _short_digest(identity_material)
    issue_id = "issue-" + short
    signal_id = "signal-" + short
    location = SourceLocation(
        path=path,
        start_line=finding.line,
        end_line=finding.line,
        symbol=_sanitize_text(finding.symbol, cap=512) or None,
    )

    records: list[EvidenceRecord] = []
    d2_supported = False
    for candidate in finding.evidence_records:
        if candidate.source == "asan":
            continue  # D3 runtime evidence is VEP-domain, not audit-bundle.
        material = _canonical_json(
            {
                "layer": "aep-static",
                "line": candidate.line,
                "path": candidate.path,
                "snippet": candidate.snippet,
                "source": candidate.source,
                "subject_id": hypothesis_id,
                "tool_run_id": candidate.tool_run_id,
            }
        )
        summary = _sanitize_text(candidate.snippet, cap=_MAX_TEXT_BYTES)
        if not summary:
            summary = _sanitize_text(
                f"{candidate.source} static evidence at "
                f"{candidate.path}:{candidate.line}",
                cap=512,
            )
        artifact_id = (
            candidate.tool_run_id
            if candidate.tool_run_id
            else "tool-" + _short_digest(material)
        )
        records.append(
            EvidenceRecord(
                evidence_id="ev" + _short_digest(material),
                subject_kind=EvidenceSubjectKind.VULNERABILITY_HYPOTHESIS,
                subject_id=hypothesis_id,
                level=EvidenceLevel.D2,
                polarity=EvidencePolarity.SUPPORTS,
                analysis_family="static-tool-analysis",
                producer=_identifier_safe(candidate.source, "static-tool"),
                independence_key=_sanitize_text(
                    f"{candidate.source}:{candidate.path}:{candidate.line}",
                    cap=512,
                ),
                summary=summary,
                source_artifact_ids=(artifact_id,),
                reason_codes=("STATIC_TOOL_SUPPORT",),
            )
        )
        d2_supported = True

    if not records:
        records.append(
            _adjudication_record(
                subject_id=hypothesis_id,
                layer="hypothesis-raised",
                level=EvidenceLevel.D1,
                polarity=EvidencePolarity.SUPPORTS,
                summary=(
                    f"Platform raised {cwe} hypothesis for {finding.target_id} "
                    f"at {path}:{finding.line} without D2 static corroboration."
                ),
                reason_code="HYPOTHESIS_RAISED",
                source_artifact_ids=("target-" + short,),
            )
        )

    signal_record_id = "ev" + _short_digest(
        _canonical_json({"layer": "aep-signal", "subject_id": signal_id})
    )
    issue_record_id = "ev" + _short_digest(
        _canonical_json({"layer": "aep-issue", "subject_id": issue_id})
    )
    records.append(
        _audit_subject_record(
            evidence_id=signal_record_id,
            subject_kind=EvidenceSubjectKind.SIGNAL,
            subject_id=signal_id,
            summary=(
                f"Scout selected {finding.target_id} at {path}:{finding.line} "
                f"({cwe})."
            ),
            reason_code="PLATFORM_TARGET_SELECTED",
            artifact_id="target-" + short,
        )
    )
    records.append(
        _audit_subject_record(
            evidence_id=issue_record_id,
            subject_kind=EvidenceSubjectKind.SECURITY_ISSUE,
            subject_id=issue_id,
            summary=f"Investigation unit opened for {finding.target_id}.",
            reason_code="PLATFORM_ISSUE_OPENED",
            artifact_id="target-" + short,
        )
    )

    signal = Signal(
        signal_id=signal_id,
        fingerprint=digest,
        rule_id=platform_rule_id(cwe),
        analysis_family="platform-adjudication",
        evidence_kind="scout-target",
        location=location,
        evidence_ids=(signal_record_id,),
        reason_codes=("PLATFORM_TARGET_SELECTED",),
        cwe_ids=(cwe,),
    )
    issue = SecurityIssue(
        issue_id=issue_id,
        identity_digest=digest,
        root_cause_class="platform-target",
        sink_identity="sink-" + short,
        trust_boundary="unassessed",
        primary_location=location,
        signal_ids=(signal_id,),
        evidence_ids=(issue_record_id,),
        reason_codes=("PLATFORM_ISSUE_OPENED",),
        cwe_ids=(cwe,),
    )
    trigger = _sanitize_text(finding.hypothesis_reason, cap=512)
    claim = _sanitize_text(
        f"{cwe} hypothesis at {path}:{finding.line}: "
        f"{finding.hypothesis_reason}",
        cap=_MAX_TEXT_BYTES,
    ) or _sanitize_text(
        f"{cwe} hypothesis at {path}:{finding.line}.", cap=512
    )
    hypothesis = VulnerabilityHypothesis(
        hypothesis_id=hypothesis_id,
        issue_id=issue_id,
        status=(
            HypothesisStatus.STATICALLY_SUPPORTED
            if d2_supported
            else HypothesisStatus.PROPOSED
        ),
        claim=claim,
        security_invariant=_sanitize_text(
            f"No attacker-controlled {cwe} violation at {path}:{finding.line}.",
            cap=512,
        ),
        required_proof_kind=RequiredProofKind.RUNTIME_BEHAVIOR,
        capability_requirements=("local-execution",),
        target_location=location,
        source_locations=(),
        critical_path=(),
        trigger_conditions=(trigger,) if trigger else (),
        input_constraints=(),
        evidence_ids=tuple(
            sorted(
                record.evidence_id
                for record in records
                if record.subject_id == hypothesis_id
                and record.subject_kind
                is EvidenceSubjectKind.VULNERABILITY_HYPOTHESIS
            )
        ),
        reason_codes=("PLATFORM_HYPOTHESIS_RAISED",),
        cwe_ids=(cwe,),
    )
    return signal, issue, hypothesis, records


def platform_review_to_aep(
    outcome: PlatformReviewOutcome,
    *,
    snapshot_sha256: str,
    repository: str,
) -> AuditEvidencePackage:
    """Fold one platform review into the audit evidence package (task T2).

    This emits the D0-D2 ``AuditEvidencePackage`` that the VEPs produced by
    :func:`finding_to_vep` pin through ``source_aep``.  Mapping:

    ===================================  =====================================
    platform review fact                 AEP field
    ===================================  =====================================
    ``outcome.findings`` (per finding)   one Signal + SecurityIssue +
                                         VulnerabilityHypothesis + D0-D2
                                         records in ``evidence``
    static tool records (non-ASan)       D2 SUPPORTS bound to the hypothesis
    ASan runtime records                 excluded (audit bundle admits
                                         D0-D2 only; runtime proof lives
                                         in the VEP)
    ``stats.experiment_count``           ``budget.tool_runs``
    scout + specialist + critic calls    ``budget.model_calls``
    (unmetered)                          ``budget.model_tokens`` /
                                         ``budget.wall_clock_ms`` = 0
    distinct ``targets[].path``          ``coverage.analyzed_file_count``
    analyzed paths + ``translation_units union`` ``coverage.in_scope_file_count``
    diagnostics ``"coverage gap: X"``    ``coverage_gaps`` (code
                                         ``COVERAGE_GAP``, detail ``X``)
    STATICALLY_SUPPORTED hypotheses      ``mining_eligible_hypothesis_ids``
    eligible / hypotheses / none         ``audit_outcome`` completed /
                                         no_supported_attack_surface /
                                         no_actionable_hypothesis
    ===================================  =====================================

    Deviations forced by the frozen contract vocabulary: ``AuditBudget``
    carries no byte/line meters or upper bounds (facts, not quota
    decisions), and ``AuditOutcome.INCOMPLETE`` is unused because it
    demands coverage gaps the platform diagnostics cannot guarantee.  The
    repository-profile id is a deterministic stand-in (the platform has no
    profile artifact yet).  The package is validated by the real
    ``AuditEvidencePackage`` constructor; failures propagate (fail-closed).
    """

    if not isinstance(outcome, PlatformReviewOutcome):
        raise ValueError("outcome must be a PlatformReviewOutcome")
    if not isinstance(snapshot_sha256, str) or not snapshot_sha256:
        raise ValueError("snapshot_sha256 must be a non-empty string")
    if not isinstance(repository, str) or not repository:
        raise ValueError("repository must be a non-empty string")

    signals: dict[str, Signal] = {}
    issues: dict[str, SecurityIssue] = {}
    hypotheses: dict[str, VulnerabilityHypothesis] = {}
    records: list[EvidenceRecord] = []
    for finding in outcome.findings:
        signal, issue, hypothesis, finding_records = _aep_finding_objects(
            finding, snapshot_sha256=snapshot_sha256, repository=repository
        )
        signals[signal.signal_id] = signal
        issues[issue.issue_id] = issue
        hypotheses[hypothesis.hypothesis_id] = hypothesis
        records.extend(finding_records)

    eligible = tuple(
        sorted(
            hypothesis_id
            for hypothesis_id, hypothesis in hypotheses.items()
            if hypothesis.status is HypothesisStatus.STATICALLY_SUPPORTED
        )
    )
    if eligible:
        audit_outcome = AuditOutcome.COMPLETED
    elif not hypotheses:
        audit_outcome = AuditOutcome.NO_ACTIONABLE_HYPOTHESIS
    else:
        audit_outcome = AuditOutcome.NO_SUPPORTED_ATTACK_SURFACE

    analyzed = {_normalized_path(target.path) for target in outcome.targets}
    in_scope = analyzed | {
        _normalized_path(unit) for unit in outcome.translation_units
    }
    coverage = AuditCoverage(
        in_scope_file_count=len(in_scope),
        analyzed_file_count=len(analyzed),
    )
    budget = AuditBudget(
        tool_runs=outcome.stats.experiment_count,
        model_calls=(
            outcome.stats.scout_calls
            + outcome.stats.specialist_calls
            + outcome.stats.critic_calls
        ),
        model_tokens=0,
        wall_clock_ms=0,
    )

    gaps: list[AuditCoverageGap] = []
    seen_details: set[str] = set()
    for diagnostic in outcome.diagnostics:
        if not diagnostic.startswith(_COVERAGE_GAP_PREFIX):
            continue
        detail = _sanitize_text(
            diagnostic[len(_COVERAGE_GAP_PREFIX):], cap=_AEP_MAX_DETAIL_BYTES
        )
        if not detail or detail in seen_details:
            continue
        seen_details.add(detail)
        gaps.append(AuditCoverageGap(gap_code=_COVERAGE_GAP_CODE, detail=detail))
    gaps.sort(key=lambda gap: (gap.gap_code, gap.detail.encode("utf-8")))

    profile_material = _canonical_json(
        {"repository": repository, "snapshot_sha256": snapshot_sha256}
    )
    return AuditEvidencePackage(
        schema_version=SCHEMA_VERSION,
        package_status=AuditPackageStatus.SEALED,
        revision=1,
        audit_depth=AuditDepth.INITIAL,
        audit_outcome=audit_outcome,
        evidence=EvidenceDomainBundle(
            schema_version=SCHEMA_VERSION,
            signals=tuple(sorted(signals.values(), key=lambda s: s.signal_id)),
            security_issues=tuple(
                sorted(issues.values(), key=lambda issue: issue.issue_id)
            ),
            vulnerability_hypotheses=tuple(
                sorted(
                    hypotheses.values(), key=lambda hypothesis: hypothesis.hypothesis_id
                )
            ),
            evidence=_dedupe_sorted(records),
        ),
        coverage=coverage,
        budget=budget,
        repository_profile_artifact_ids=(
            "profile-platform-" + _short_digest(profile_material),
        ),
        mining_eligible_hypothesis_ids=eligible,
        coverage_gaps=tuple(gaps),
    )


def _review_material(
    outcome: PlatformReviewOutcome,
    *,
    snapshot_sha256: str,
    repository: str,
    kind: str,
    extra: Mapping[str, Any] | None = None,
) -> str:
    """Canonical digest material for one deterministic stand-in reference."""

    material: dict[str, Any] = {
        "diagnostics": list(outcome.diagnostics),
        "kind": kind,
        "repository": repository,
        "snapshot_sha256": snapshot_sha256,
        "stats": {
            "critic_calls": outcome.stats.critic_calls,
            "experiment_count": outcome.stats.experiment_count,
            "finding_count": outcome.stats.finding_count,
            "lead_count": outcome.stats.lead_count,
            "scout_calls": outcome.stats.scout_calls,
            "specialist_calls": outcome.stats.specialist_calls,
            "target_count": outcome.stats.target_count,
        },
        "targets": [target.target_id for target in outcome.targets],
    }
    if extra is not None:
        material.update(extra)
    return _canonical_json(material)


def _stand_in_link(
    kind: SummaryReferenceKind,
    id_prefix: str,
    material: str,
) -> ArtifactLink:
    """Deterministic stand-in link (T1 pattern: pinned when real artifacts land)."""

    return ArtifactLink(
        kind=kind,
        artifact_id=id_prefix + _short_digest(material),
        content_digest=hashlib.sha256(material.encode("utf-8")).hexdigest(),
        schema_version=SCHEMA_VERSION,
    )


def platform_review_to_workflow_summary(
    outcome: PlatformReviewOutcome,
    *,
    snapshot_sha256: str,
    repository: str,
    source_aep: AepReference | None = None,
    veps: Sequence[VulnerabilityEvidencePackage] | None = None,
) -> WorkflowSummary:
    """Summarize one platform review as a V4 chain workflow summary (T2).

    Mapping:

    ===================================  =====================================
    platform review fact                 WorkflowSummary field
    ===================================  =====================================
    (fixed)                              ``source`` = chain
    ``cancelled ... review started`` /
    deadline / scout-unavailable
    pre-start diagnostics                ``execution_status`` cancelled / failed
    anything else (incl. degraded
    best-effort diagnostics)             ``execution_status`` succeeded
    per finding -> :func:`finding_to_vep`  one ``evidence`` ArtifactLink whose
                                         artifact_id is the VEP hypothesis_id
                                         and whose content_digest is the real
                                         canonical VEP payload digest
    scout / specialist / critic roles    three ``stage_attempts`` links with
                                         the role call counters folded into
                                         the deterministic digest
    ===================================  =====================================

    Vocabulary deviations forced by the frozen contract: there is no
    ``AGENT`` source kind, so the chain kind is used (the platform emits
    typed frozen artifacts); ``ExecutionStatus`` has no degraded value and
    degradation is a quality fact, not an execution failure; chain-source
    summaries must not carry ``legacy_artifact_ids``, so finding
    fingerprints ride inside the workflow/security-outcome digest material
    instead.  ``workflow``/``security_outcome`` are deterministic stand-in
    links (same policy as T1's ``source_aep``/``oracle`` stand-ins) until
    the platform mints those artifacts; VEP evidence links are real
    content-addressed references.  ``source_aep`` (optional) is passed
    through to every :func:`finding_to_vep` call so sealed summaries pin
    the real AEP reference instead of the finding-identity stand-in;
    ``veps`` (optional) supplies already-sealed VEPs (one per finding) so
    the summary's evidence links address exactly the sealed payloads
    instead of rebuilding converters with different references.
    Required-mode hard failures raise ``RuntimeError`` inside the
    orchestrator before any outcome exists, so they cannot be summarized
    here.  Findings the VEP constructor rejects (``abstain``, unknown
    states, malformed fields) are rejected here too (fail-closed); more
    than 64 findings exceed the frozen evidence cap.
    """

    if not isinstance(outcome, PlatformReviewOutcome):
        raise ValueError("outcome must be a PlatformReviewOutcome")
    if not isinstance(snapshot_sha256, str) or not snapshot_sha256:
        raise ValueError("snapshot_sha256 must be a non-empty string")
    if not isinstance(repository, str) or not repository:
        raise ValueError("repository must be a non-empty string")
    if (
        not outcome.targets
        and not outcome.findings
        and outcome.leads_considered == 0
        and outcome.stats.scout_calls == 0
        and not outcome.diagnostics
    ):
        raise ValueError(
            "platform review outcome carries no audit facts to summarize"
        )

    if _CANCELLED_PRESTART in outcome.diagnostics:
        execution_status = ExecutionStatus.CANCELLED
    elif any(
        diagnostic.startswith(prefix)
        for diagnostic in outcome.diagnostics
        for prefix in _FAILED_PRESTART_PREFIXES
    ):
        execution_status = ExecutionStatus.FAILED
    else:
        execution_status = ExecutionStatus.SUCCEEDED

    sealed_veps: list[VulnerabilityEvidencePackage] | None = None
    if veps is not None:
        sealed_veps = list(veps)
        if len(sealed_veps) != len(outcome.findings):
            raise ValueError(
                "sealed veps must correspond one-to-one with outcome findings"
            )
    evidence: list[ArtifactLink] = []
    evidence_digests: list[str] = []
    for index, finding in enumerate(outcome.findings):
        vep = (
            sealed_veps[index]
            if sealed_veps is not None
            else finding_to_vep(
                finding,
                snapshot_sha256=snapshot_sha256,
                repository=repository,
                source_aep=source_aep,
            )
        )
        digest = compute_content_digest(vep.to_dict())
        evidence_digests.append(digest)
        evidence.append(
            ArtifactLink(
                kind=SummaryReferenceKind.VULNERABILITY_EVIDENCE_PACKAGE,
                artifact_id=vep.hypothesis_id,
                content_digest=digest,
                schema_version=SCHEMA_VERSION,
            )
        )
    evidence.sort(key=lambda link: link.artifact_id)

    workflow_link = _stand_in_link(
        SummaryReferenceKind.WORKFLOW,
        "wf-platform-",
        _review_material(
            outcome,
            snapshot_sha256=snapshot_sha256,
            repository=repository,
            kind="lima.workflow",
        ),
    )
    security_link = _stand_in_link(
        SummaryReferenceKind.SECURITY_OUTCOME,
        "sec-platform-",
        _review_material(
            outcome,
            snapshot_sha256=snapshot_sha256,
            repository=repository,
            kind="lima.security-outcome",
            extra={"evidence_digests": evidence_digests},
        ),
    )
    role_calls = {
        "scout": outcome.stats.scout_calls,
        "specialist": outcome.stats.specialist_calls,
        "critic": outcome.stats.critic_calls,
    }
    stage_attempts = [
        _stand_in_link(
            SummaryReferenceKind.STAGE_ATTEMPT,
            "attempt-" + role + "-",
            _review_material(
                outcome,
                snapshot_sha256=snapshot_sha256,
                repository=repository,
                kind="lima.stage-attempt",
                extra={"calls": role_calls[role], "role": role},
            ),
        )
        for role in _STAGE_ROLES
    ]
    stage_attempts.sort(key=lambda link: link.artifact_id)

    return WorkflowSummary(
        schema_version=SCHEMA_VERSION,
        source=SummarySourceKind.CHAIN,
        execution_status=execution_status,
        workflow=workflow_link,
        security_outcome=security_link,
        run_manifest=None,
        stage_attempts=tuple(stage_attempts),
        evidence=tuple(evidence),
        legacy_artifact_ids=(),
    )


# --- production seal: real AEP/oracle references for every sealed VEP -------

@dataclass(frozen=True)
class PlatformSealBundle:
    """One sealed V4 artifact chain for a platform review.

    ``aep_artifact_id``/``aep_content_digest`` content-address the AEP
    payload that every VEP pins through ``source_aep``.
    """

    aep: AuditEvidencePackage
    aep_artifact_id: str
    aep_content_digest: str
    veps: tuple[VulnerabilityEvidencePackage, ...]
    workflow_summary: WorkflowSummary


def seal_platform_review(
    outcome: PlatformReviewOutcome,
    *,
    snapshot_sha256: str,
    repository: str,
) -> PlatformSealBundle:
    """Seal one platform review into a V4 chain with real references.

    This is the production wiring the T1 stand-in policy pointed at: the
    AEP minted by :func:`platform_review_to_aep` is content-addressed
    (artifact id derived from the payload digest) and every VEP pins it
    through ``source_aep``; the oracle reference digests the actual PoC
    driver bytes carried by the finding.  Conversions are fail-closed: a
    finding the frozen VEP vocabulary cannot carry (or more than 64
    findings) propagates the ``ValueError`` to the caller instead of
    being silently dropped.

    Consumption caveat: the scanner embeds these payloads inside the
    task report as a preview projection -- no independent artifact store
    backs these references yet, and the workflow/security-outcome and
    repository-profile links remain stand-ins.
    """

    aep = platform_review_to_aep(
        outcome, snapshot_sha256=snapshot_sha256, repository=repository
    )
    aep_digest = compute_content_digest(aep.to_dict())
    aep_reference = AepReference(
        artifact_id="aep-platform-" + _short_digest(aep_digest),
        content_digest=aep_digest,
        schema_version=SCHEMA_VERSION,
    )
    veps: list[VulnerabilityEvidencePackage] = []
    for finding in outcome.findings:
        driver_digest = hashlib.sha256(
            finding.poc_driver_code.encode("utf-8")
        ).hexdigest()
        veps.append(
            finding_to_vep(
                finding,
                snapshot_sha256=snapshot_sha256,
                repository=repository,
                source_aep=aep_reference,
                oracle=OracleReference(
                    oracle_artifact_id="oracle-" + _short_digest(driver_digest),
                    content_digest=driver_digest,
                ),
            )
        )
    summary = platform_review_to_workflow_summary(
        outcome,
        snapshot_sha256=snapshot_sha256,
        repository=repository,
        source_aep=aep_reference,
        veps=tuple(veps),
    )
    return PlatformSealBundle(
        aep=aep,
        aep_artifact_id=aep_reference.artifact_id,
        aep_content_digest=aep_digest,
        veps=tuple(veps),
        workflow_summary=summary,
    )


# --- task T3: PatchFlowOutcome -> RepairVerificationReport ------------------

_PATCH_GENERATOR_ID: Final = "lima-agent-patch-engineer"
_VERIFY_PRODUCER_ID: Final = "lima-agent-platform"


def _gate_outcome_for(value: bool | None) -> GateOutcome:
    """Map one ``PatchVerification`` boolean fact onto a gate outcome.

    ``None`` means the fact was never established (compile skipped by the
    noop shortcut, PoC unjudgeable after a compile failure, instrument noise
    or an inconclusive run), so the honest six-state wire form is
    ``inconclusive`` -- never a guessed pass/fail.
    """

    if value is True:
        return GateOutcome.PASS
    if value is False:
        return GateOutcome.FAILED
    return GateOutcome.INCONCLUSIVE


def _security_gate_outcome(poc_still_triggers: bool | None) -> GateOutcome:
    """Inverted polarity of the PoC oracle: ``False`` is the passing fact.

    The PoC *no longer* triggering (``False``) means the patch preserved the
    security property -> pass; still triggering -> failed; unjudged ->
    inconclusive.
    """

    if poc_still_triggers is True:
        return GateOutcome.FAILED
    if poc_still_triggers is False:
        return GateOutcome.PASS
    return GateOutcome.INCONCLUSIVE


def _gate_detail(headline: str, diagnostics: tuple[str, ...]) -> str:
    """One bounded, deterministic gate detail line with its diagnostics."""

    detail = headline
    if diagnostics:
        detail += "; diagnostics: " + ", ".join(diagnostics)
    return _sanitize_text(detail, cap=_MAX_TEXT_BYTES)


def patch_outcome_to_rvr(
    patch_outcome: PatchFlowOutcome,
    *,
    finding: PlatformFinding,
    snapshot_sha256: str,
    repository: str,
) -> RepairVerificationReport:
    """Convert one patch flow outcome into a strictly validated V4 RVR (T3).

    Mapping:

    ==================================  ===================================
    platform patch fact                 RVR field
    ==================================  ===================================
    :func:`finding_to_vep`\ (``finding``) ``source_vep`` triple pinned at
                                        the real canonical VEP payload
                                        digest (hypothesis id as artifact id)
    ``proposal.patched_content``        ``patch.content_digest`` (sha256 of
                                        the complete replacement file) plus
                                        a deterministic ``patch-`` artifact id
    ``proposal.target_path``            ``changed_files`` (single entry)
    ``proposal.rationale``              ``strategy`` (bounded; fixed
                                        fallback when sanitization empties it)
    ``verification.compiles``           functional_preservation gate:
                                        True/False/None -> pass/failed/
                                        inconclusive
    ``verification.poc_still_triggers`` security_preservation gate:
                                        False/True/None -> pass/failed/
                                        inconclusive (the PoC no longer
                                        triggering is the passing fact)
    derived from both gates             ``verdict`` (frozen matrix: any
                                        failed gate -> rejected; both pass
                                        -> verified_patch; else inconclusive)
    ``asan_type_after`` + diagnostics   security gate ``detail``
    ``rounds_used``                     not expressible at 4.0 (the frozen
                                        RVR admits no extensions) -- dropped
    ``proposal=None`` (generation
    failed) or ``verification=None``    rejected (``ValueError``)
    ==================================  ===================================

    Honesty boundaries: the generator (the platform patch engineer model)
    never produces gate evidence -- both gates are owned by the platform's
    isolated-copy build and PoC regression run, so the frozen
    generator-may-not-verify-own-candidate ban holds structurally.  The
    ``patch_outcome.verified`` flag must agree with the gate-derived verdict
    in both directions (a contradictory outcome is ``ValueError``, never a
    coerced verified_patch).  Gate evidence ids are deterministic stand-ins
    (T1 stand-in policy): the isolated-copy run artifacts are payload-level
    pins until the platform mints them.  Failures of the real ``RVR`` /
    ``CandidateVerification`` constructors propagate unchanged (fail-closed).
    """

    if not isinstance(patch_outcome, PatchFlowOutcome):
        raise ValueError("patch_outcome must be a PatchFlowOutcome")
    if not isinstance(finding, PlatformFinding):
        raise ValueError("finding must be a PlatformFinding")
    if not isinstance(snapshot_sha256, str) or not snapshot_sha256:
        raise ValueError("snapshot_sha256 must be a non-empty string")
    if not isinstance(repository, str) or not repository:
        raise ValueError("repository must be a non-empty string")
    proposal = patch_outcome.proposal
    verification = patch_outcome.verification
    if proposal is None or verification is None:
        raise ValueError(
            "patch outcome carries no proposal/verification pair to verify "
            f"(diagnostics: {', '.join(patch_outcome.diagnostics) or 'none'})"
        )

    vep = finding_to_vep(
        finding, snapshot_sha256=snapshot_sha256, repository=repository
    )
    patch_digest = hashlib.sha256(
        proposal.patched_content.encode("utf-8")
    ).hexdigest()
    target_path = _normalized_path(proposal.target_path)
    identity_material = _canonical_json(
        {
            "hypothesis_id": vep.hypothesis_id,
            "patch_sha256": patch_digest,
            "target_path": target_path,
        }
    )
    short = _short_digest(identity_material)
    gate_material = _canonical_json(
        {
            "candidate_id": "cand-" + short,
            "patch_artifact_id": "patch-" + short,
            "repository": repository,
            "snapshot_sha256": snapshot_sha256,
        }
    )
    gates = (
        GateResult(
            gate=GateKind.FUNCTIONAL_PRESERVATION,
            outcome=_gate_outcome_for(verification.compiles),
            producer=_VERIFY_PRODUCER_ID,
            evidence_artifact_ids=("build-" + _short_digest(gate_material),),
            detail=_gate_detail(
                f"Isolated-copy compile of {target_path}: "
                f"compiles={verification.compiles}",
                verification.diagnostics,
            ),
        ),
        GateResult(
            gate=GateKind.SECURITY_PRESERVATION,
            outcome=_security_gate_outcome(verification.poc_still_triggers),
            producer=_VERIFY_PRODUCER_ID,
            evidence_artifact_ids=("pocpost-" + _short_digest(gate_material),),
            detail=_gate_detail(
                "PoC regression on the patched isolated copy: "
                f"poc_still_triggers={verification.poc_still_triggers}"
                + (
                    f"; observed post-patch sanitizer type "
                    f"{verification.asan_type_after}"
                    if verification.asan_type_after is not None
                    else ""
                ),
                verification.diagnostics,
            ),
        ),
    )
    outcomes = [gate.outcome for gate in gates]
    if any(outcome is GateOutcome.FAILED for outcome in outcomes):
        verdict = CandidateVerdict.REJECTED
    elif all(outcome is GateOutcome.PASS for outcome in outcomes):
        verdict = CandidateVerdict.VERIFIED_PATCH
    else:
        verdict = CandidateVerdict.INCONCLUSIVE
    if patch_outcome.verified is not (verdict is CandidateVerdict.VERIFIED_PATCH):
        raise ValueError("patch outcome verified flag contradicts the gates")

    candidate = CandidateVerification(
        candidate_id="cand-" + short,
        patch=PatchReference(
            patch_artifact_id="patch-" + short, content_digest=patch_digest
        ),
        strategy=(
            _sanitize_text(proposal.rationale, cap=512)
            or "platform-proposed complete-file patch"
        ),
        changed_files=(target_path,),
        generator=_PATCH_GENERATOR_ID,
        gates=gates,
        verdict=verdict,
    )
    return RepairVerificationReport(
        schema_version=SCHEMA_VERSION,
        source_vep=VepReference(
            artifact_id=vep.hypothesis_id,
            content_digest=compute_content_digest(vep.to_dict()),
            schema_version=SCHEMA_VERSION,
        ),
        candidates=(candidate,),
    )
