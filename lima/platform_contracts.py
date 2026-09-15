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
import unicodedata
from collections.abc import Mapping
from typing import Any, Final

from lima.agent_orchestrator import PlatformFinding, PlatformReviewOutcome
from lima.contracts.common import SchemaVersion
from lima.contracts.evidence import (
    EvidenceLevel,
    EvidencePolarity,
    EvidenceRecord,
    EvidenceSubjectKind,
    SourceLocation,
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

__all__ = [
    "finding_to_vep",
    "platform_review_to_aep",
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


def _canonical_json(material: Mapping[str, Any]) -> str:
    return json.dumps(material, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _short_digest(material: str) -> str:
    return hashlib.sha256(material.encode("utf-8")).hexdigest()[:24]


def _sanitize_text(value: object, *, cap: int) -> str:
    """Bound one piece of platform free text for a bounded-text field.

    Control characters (ASan logs carry newlines) collapse to spaces so the
    contract's bounded-text validation passes; output is deterministic.
    """

    if not isinstance(value, str):
        raise ValueError(f"expected str text, got {type(value).__name__}")
    cleaned = "".join(
        " " if unicodedata.category(char) == "Cc" else char for char in value
    )
    cleaned = " ".join(cleaned.split())
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


def platform_review_to_aep(
    outcome: PlatformReviewOutcome,
    *,
    snapshot_sha256: str,
    repository: str,
) -> None:
    """Fold one platform review into the audit evidence package (task T2).

    Placeholder only: T2 will emit the D0-D2 ``AuditEvidencePackage`` that
    the VEPs produced by :func:`finding_to_vep` pin through
    ``source_aep``.
    """

    raise NotImplementedError("platform_review_to_aep lands with task T2")
