"""Legacy adapter between ``lima.models`` and the frozen contracts (IP-0013 PR4).

Bidirectional payload-layer adapter: legacy ``Finding``/``ReviewReport`` to
frozen ``EvidenceDomainBundle``/``WorkflowSummary`` and back. Never constructs
``ArtifactEnvelope`` and never performs lineage existence checks — envelope
binding is the existing encode/decode face, not adapter business (Packet
IP-0013 section 7, decision D1).

Mapping discipline (Packet decisions D2/D3/D4/D5, frozen single solutions):

- Identity is derived from the exact legacy fingerprint material
  ``M = "%s\\0%s\\0%s\\0%s" % (rule_id, path, line, evidence)`` (models.py
  ``Finding.__post_init__``); the adapter keeps the *full* sha256 hex digest
  as ``Signal.fingerprint`` / ``SecurityIssue.identity_digest`` and truncates
  back to 24 hex on the reverse trip (round-trip identity).
- Every legacy value is either pass-through (re-validated against the frozen
  vocabulary/limits), transform, explicitly degraded (D0/SUPPORTS/sentinels),
  or explicitly unsupported (declared in the ``UNMAPPED_*`` frozensets).
  Nothing is silently dropped and no severity/polarity/refutation is forged.
- ``review_report_to_workflow_summary`` can only produce
  ``source=legacy_audit`` summaries; the frozen summary contract rejects any
  legacy_audit summary carrying typed links, so a legacy audit result is
  structurally unable to masquerade as full-chain success (V5-FR-05).
- Violations raise the existing ``ContractError`` codes only (no new codes,
  no new messages); ``field_path`` follows the Packet D4 table.
"""

import hashlib
import re
import unicodedata
from typing import Final

from lima.contracts.common import SchemaVersion
from lima.contracts.errors import ContractError, ContractErrorCode
from lima.contracts.evidence import (
    EvidenceDomainBundle,
    EvidenceLevel,
    EvidencePolarity,
    EvidenceRecord,
    EvidenceSubjectKind,
    SecurityIssue,
    Signal,
    SourceLocation,
)
from lima.contracts.summary import (
    ExecutionStatus,
    SummarySourceKind,
    WorkflowSummary,
)
from lima.models import Finding, ReviewReport, Severity

__all__ = [
    "LEGACY_REASON_CODE",
    "LEGACY_SENTINEL",
    "LEGACY_SOURCE_ARTIFACT_ID",
    "UNMAPPED_FROZEN_FIELDS",
    "UNMAPPED_LEGACY_FINDING_FIELDS",
    "domain_to_finding",
    "finding_to_domain_bundle",
    "review_report_to_workflow_summary",
]

LEGACY_REASON_CODE: Final[str] = "LEGACY_MIGRATED"
LEGACY_SOURCE_ARTIFACT_ID: Final[str] = "legacy-finding"
LEGACY_SENTINEL: Final[str] = "legacy-finding"

UNMAPPED_LEGACY_FINDING_FIELDS: Final[frozenset[str]] = frozenset(
    {
        "severity",
        "title",
        "explanation",
        "fix",
        "test",
        "confidence",
        "verification_state",
    }
)
UNMAPPED_FROZEN_FIELDS: Final[frozenset[str]] = frozenset(
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
)

_RULE_ID_PATTERN: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:+/-]{0,255}")
_IDENTIFIER_PATTERN: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}")
_CWE_PATTERN: Final = re.compile(r"CWE-[1-9][0-9]{0,5}")
_DRIVE_PREFIX_PATTERN: Final = re.compile(r"[A-Za-z]:")
_MAX_PATH_BYTES: Final[int] = 1024
_MAX_TEXT_BYTES: Final[int] = 4096
_MAX_LINE_VALUE: Final[int] = 2147483647

_VERSION_4_0: Final = SchemaVersion(4, 0)


def _fail(code: ContractErrorCode, field_path: str) -> None:
    raise ContractError(code, field_path)


def _rule_id(value: str, field_path: str) -> str:
    normalized = unicodedata.normalize("NFC", value)
    if _RULE_ID_PATTERN.fullmatch(normalized) is None:
        _fail(ContractErrorCode.INVALID_FIELD_VALUE, field_path)
    return normalized


def _identifier(value: str, field_path: str) -> str:
    normalized = unicodedata.normalize("NFC", value)
    if _IDENTIFIER_PATTERN.fullmatch(normalized) is None:
        _fail(ContractErrorCode.INVALID_FIELD_VALUE, field_path)
    return normalized


def _bounded_text(value: str, field_path: str) -> str:
    normalized = unicodedata.normalize("NFC", value)
    if not normalized:
        _fail(ContractErrorCode.INVALID_FIELD_VALUE, field_path)
    if any(unicodedata.category(char) == "Cc" for char in normalized):
        _fail(ContractErrorCode.INVALID_FIELD_VALUE, field_path)
    if normalized != normalized.strip():
        _fail(ContractErrorCode.INVALID_FIELD_VALUE, field_path)
    if len(normalized.encode("utf-8")) > _MAX_TEXT_BYTES:
        _fail(ContractErrorCode.MAX_STRING_LENGTH_EXCEEDED, field_path)
    return normalized


def _path(value: str, field_path: str) -> str:
    normalized = unicodedata.normalize("NFC", value)
    if not normalized:
        _fail(ContractErrorCode.INVALID_FIELD_VALUE, field_path)
    if len(normalized.encode("utf-8")) > _MAX_PATH_BYTES:
        _fail(ContractErrorCode.MAX_STRING_LENGTH_EXCEEDED, field_path)
    if any(unicodedata.category(char) == "Cc" for char in normalized):
        _fail(ContractErrorCode.INVALID_FIELD_VALUE, field_path)
    if normalized.startswith("/") or "\\" in normalized:
        _fail(ContractErrorCode.INVALID_FIELD_VALUE, field_path)
    if _DRIVE_PREFIX_PATTERN.match(normalized) is not None:
        _fail(ContractErrorCode.INVALID_FIELD_VALUE, field_path)
    for segment in normalized.split("/"):
        if segment in ("", ".", ".."):
            _fail(ContractErrorCode.INVALID_FIELD_VALUE, field_path)
    return normalized


def _line(value: int, field_path: str) -> int:
    if not 1 <= value <= _MAX_LINE_VALUE:
        _fail(ContractErrorCode.INVALID_FIELD_VALUE, field_path)
    return value


def _cwe(value: str) -> tuple[str, ...]:
    if not value:
        return ()
    if _CWE_PATTERN.fullmatch(value) is None:
        _fail(ContractErrorCode.INVALID_FIELD_VALUE, "$.cwe")
    return (value,)


def _location(path: str, line: int) -> SourceLocation:
    return SourceLocation(path=path, start_line=line, end_line=line)


def finding_to_domain_bundle(finding: Finding) -> EvidenceDomainBundle:
    """Convert one legacy ``Finding`` into a frozen evidence domain bundle."""
    rule_id = _rule_id(finding.rule_id, "$.rule_id")
    path = _path(finding.path, "$.path")
    line = _line(finding.line, "$.line")
    evidence = _bounded_text(finding.evidence, "$.evidence")
    evidence_kind = _identifier(finding.evidence_kind, "$.evidence_kind")
    source = _identifier(finding.source, "$.source")
    cwe_ids = _cwe(finding.cwe)

    # Identity: the exact legacy fingerprint material, hashed in full
    # (models.py Finding.__post_init__ keeps only the first 24 hex; the
    # frozen Signal.fingerprint requires the complete 64-hex digest).
    material = "%s\0%s\0%s\0%s" % (  # noqa: UP031 -- byte-identical legacy material
        rule_id,
        path,
        line,
        evidence,
    )
    digest = hashlib.sha256(material.encode("utf-8")).hexdigest()
    prefix = digest[:12]
    signal_id = f"sig-{prefix}"
    issue_id = f"issue-{prefix}"

    records: list[EvidenceRecord] = [
        EvidenceRecord(
            evidence_id=f"ev-{prefix}-000",
            subject_kind=EvidenceSubjectKind.SIGNAL,
            subject_id=signal_id,
            level=EvidenceLevel.D0,
            polarity=EvidencePolarity.SUPPORTS,
            analysis_family=source,
            producer=source,
            independence_key=f"{rule_id}:000",
            summary=evidence,
            source_artifact_ids=(LEGACY_SOURCE_ARTIFACT_ID,),
            reason_codes=(LEGACY_REASON_CODE,),
            location=_location(path, line),
        )
    ]
    for index, record in enumerate(finding.evidence_records, start=1):
        record_path = _path(record.path, f"$.evidence_records[{index - 1}].path")
        record_line = _line(record.line, f"$.evidence_records[{index - 1}].line")
        snippet = _bounded_text(
            record.snippet, f"$.evidence_records[{index - 1}].snippet"
        )
        records.append(
            EvidenceRecord(
                evidence_id=f"ev-{prefix}-{index:03d}",
                subject_kind=EvidenceSubjectKind.SECURITY_ISSUE,
                subject_id=issue_id,
                level=EvidenceLevel.D0,
                polarity=EvidencePolarity.SUPPORTS,
                analysis_family=source,
                producer=source,
                independence_key=f"{rule_id}:{index:03d}",
                summary=snippet,
                source_artifact_ids=(LEGACY_SOURCE_ARTIFACT_ID,),
                reason_codes=(LEGACY_REASON_CODE,),
                location=_location(record_path, record_line),
            )
        )

    signal = Signal(
        signal_id=signal_id,
        fingerprint=digest,
        rule_id=rule_id,
        analysis_family=source,
        evidence_kind=evidence_kind,
        location=_location(path, line),
        evidence_ids=(records[0].evidence_id,),
        reason_codes=(LEGACY_REASON_CODE,),
    )
    issue = SecurityIssue(
        issue_id=issue_id,
        identity_digest=digest,
        root_cause_class=LEGACY_SENTINEL,
        sink_identity=LEGACY_SENTINEL,
        trust_boundary=LEGACY_SENTINEL,
        primary_location=_location(path, line),
        signal_ids=(signal_id,),
        evidence_ids=tuple(record.evidence_id for record in records[1:]),
        reason_codes=(LEGACY_REASON_CODE,),
        cwe_ids=cwe_ids,
    )
    return EvidenceDomainBundle(
        schema_version=_VERSION_4_0,
        signals=(signal,),
        security_issues=(issue,),
        evidence=tuple(records),
    )


def domain_to_finding(
    bundle: EvidenceDomainBundle, *, issue_index: int = 0
) -> Finding:
    """Convert one frozen bundle (one issue) back into a legacy ``Finding``."""
    issues = bundle.security_issues
    if not 0 <= issue_index < len(issues):
        _fail(
            ContractErrorCode.INVALID_FIELD_VALUE, f"$.security_issues[{issue_index}]"
        )
    issue = issues[issue_index]
    if not issue.signal_ids:
        _fail(
            ContractErrorCode.INVALID_FIELD_VALUE,
            f"$.security_issues[{issue_index}].signal_ids",
        )
    signals = {signal.signal_id: signal for signal in bundle.signals}
    signal = signals.get(issue.signal_ids[0])
    if signal is None:
        _fail(
            ContractErrorCode.INVALID_FIELD_VALUE,
            f"$.security_issues[{issue_index}].signal_ids[0]",
        )
    bound = [
        record
        for record in bundle.evidence
        if record.subject_kind is EvidenceSubjectKind.SECURITY_ISSUE
        and record.subject_id == issue.issue_id
    ]
    if not bound:
        _fail(
            ContractErrorCode.INVALID_FIELD_VALUE,
            f"$.security_issues[{issue_index}].evidence_ids",
        )
    return Finding(
        rule_id=signal.rule_id,
        severity=Severity.LOW,
        title=f"migrated:{issue.issue_id}",
        explanation="; ".join(issue.reason_codes),
        path=issue.primary_location.path,
        line=issue.primary_location.start_line,
        evidence=bound[0].summary,
        fix="unmapped:fix",
        test="unmapped:test",
        cwe=min(issue.cwe_ids) if issue.cwe_ids else "",
        source="legacy-adapter",
        evidence_kind=signal.evidence_kind,
        fingerprint=issue.identity_digest[:24],
    )


def review_report_to_workflow_summary(report: ReviewReport) -> WorkflowSummary:
    """Convert a legacy ``ReviewReport`` into a legacy_audit workflow summary."""
    if not report.findings:
        _fail(ContractErrorCode.INVALID_FIELD_VALUE, "$.findings")
    legacy_artifact_ids = sorted(
        {finding.fingerprint for finding in report.findings}
    )
    return WorkflowSummary(
        schema_version=_VERSION_4_0,
        source=SummarySourceKind.LEGACY_AUDIT,
        execution_status=ExecutionStatus.SUCCEEDED,
        legacy_artifact_ids=tuple(legacy_artifact_ids),
    )
