"""Public API of the LIMA evidence privacy core (IP-0015 Feature Slice S1-Core)."""

from __future__ import annotations

from lima.evidence_privacy.classifier import classify_payload
from lima.evidence_privacy.errors import PrivacyError, PrivacyErrorCode
from lima.evidence_privacy.fingerprint import compute_fingerprint
from lima.evidence_privacy.models import (
    ClassificationManifest,
    EvidencePayload,
    FingerprintRecord,
    PrivacyLimits,
    SanitizedPayload,
    SinkContext,
    TenantPolicy,
)
from lima.evidence_privacy.policy import SINK_KINDS
from lima.evidence_privacy.port import sanitize_for_sink

__all__ = [
    "ClassificationManifest",
    "EvidencePayload",
    "FingerprintRecord",
    "PrivacyError",
    "PrivacyErrorCode",
    "PrivacyLimits",
    "SINK_KINDS",
    "SanitizedPayload",
    "SinkContext",
    "TenantPolicy",
    "classify_payload",
    "compute_fingerprint",
    "sanitize_for_sink",
]
