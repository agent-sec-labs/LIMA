import hashlib
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class TaskState(str, Enum):
    PENDING = "PENDING"
    PLANNING = "PLANNING"
    EXECUTING = "EXECUTING"
    REVIEWING = "REVIEWING"
    SUCCESS = "SUCCESS"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass
class ChangedLine:
    path: str
    line: int
    content: str


@dataclass
class EvidenceRecord:
    source: str
    kind: str
    path: str
    line: int
    snippet: str
    rule_id: str = ""
    cwe: str = ""
    confidence: float = 0.0
    language: str = ""
    symbol: str = ""
    analysis_mode: str = ""


@dataclass
class Finding:
    rule_id: str
    severity: Severity
    title: str
    explanation: str
    path: str
    line: int
    evidence: str
    fix: str
    test: str
    confidence: float = 0.8
    cwe: str = ""
    source: str = "local-rule"
    evidence_kind: str = "line"
    fingerprint: str = ""
    verification_state: str = "candidate"
    evidence_records: List[EvidenceRecord] = field(default_factory=list)
    language: str = ""
    symbol: str = ""
    analysis_mode: str = ""
    automatic_repair: Optional[bool] = None

    def __post_init__(self) -> None:
        self.cwe = self.cwe.upper().strip()
        self.source = self.source.strip() or "unknown"
        self.evidence_kind = self.evidence_kind.strip() or "line"
        self.verification_state = self.verification_state.strip() or "candidate"
        if not self.fingerprint:
            material = "%s\0%s\0%s\0%s" % (
                self.rule_id, self.path, self.line, self.evidence
            )
            self.fingerprint = hashlib.sha256(material.encode("utf-8")).hexdigest()[:24]
        self.evidence_records = [
            item if isinstance(item, EvidenceRecord) else EvidenceRecord(**item)
            for item in self.evidence_records
        ]
        if not self.evidence_records:
            self.evidence_records.append(EvidenceRecord(
                source=self.source,
                kind=self.evidence_kind,
                path=self.path,
                line=self.line,
                snippet=self.evidence,
                rule_id=self.rule_id,
                cwe=self.cwe,
                confidence=self.confidence,
            ))

    def to_dict(self) -> Dict[str, Any]:
        value = asdict(self)
        value["severity"] = self.severity.value
        return value


@dataclass
class ReviewReport:
    repository: str
    pull_request: Optional[int]
    summary: str
    risk: str
    findings: List[Finding] = field(default_factory=list)
    files_reviewed: List[str] = field(default_factory=list)
    reviewer: str = "local-rules"
    collaboration: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "repository": self.repository,
            "pull_request": self.pull_request,
            "summary": self.summary,
            "risk": self.risk,
            "findings": [item.to_dict() for item in self.findings],
            "files_reviewed": self.files_reviewed,
            "reviewer": self.reviewer,
            "collaboration": self.collaboration,
        }


@dataclass
class TraceEvent:
    step: int
    state: TaskState
    message: str
    created_at: str

    def to_dict(self) -> Dict[str, Any]:
        value = asdict(self)
        value["state"] = self.state.value
        return value
