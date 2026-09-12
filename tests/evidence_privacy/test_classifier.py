# IP-0015 Evidence Privacy Core - frozen acceptance tests (P&V owned).
# Packet: docs/LIMA_Implementation_Packet_IP-0015_Evidence_Privacy_Core.md v1.0
"""Classification core tests (Packet section 8.7; FR-N05-01, AC/T-N05-03 core)."""

from __future__ import annotations

from lima.evidence_privacy import (
    EvidencePayload,
    TenantPolicy,
    classify_payload,
)

from lima.contracts.common import ArtifactClassification

POLICY = TenantPolicy(policy_version="v1")


def _manifest(value):
    return classify_payload(EvidencePayload(payload_kind="structured_json", value=value), POLICY)


def test_enum_comes_from_contracts():
    # FR-N05-01: no parallel enum; classification values come from #58 DI-001.
    assert ArtifactClassification.PUBLIC.value == "public"
    assert ArtifactClassification.RESTRICTED.value == "restricted"
    m = _manifest({"note": "hello world"})
    assert isinstance(m.classification, ArtifactClassification)


def test_plain_internal_payload_defaults_internal():
    # Packet 8.7: no sensitive key / PEM / URL credential -> INTERNAL default.
    m = _manifest({"note": "just a normal sentence"})
    assert m.classification == ArtifactClassification.INTERNAL
    assert m.entries == ()


def test_sensitive_key_pattern_matches_case_insensitive():
    # FR-N05-01 / Packet 8.7: secret/token/key/password/credential/private_key
    # key-name match (case-insensitive) -> SENSITIVE.
    for key in ("api_token", "DB_PASSWORD", "secretValue", "private_key", "Credential"):
        m = _manifest({key: "abcdefghijklmnop"})
        assert m.classification == ArtifactClassification.SENSITIVE, key
        assert len(m.entries) == 1
        assert m.entries[0].value_kind == "string"


def test_url_credential_classified_restricted():
    # FR-N05-01 / Appendix A: scheme://user:pass@ text -> RESTRICTED.
    m = _manifest({"endpoint": "https://user:supersecretpw@example.com/p"})
    assert m.classification == ArtifactClassification.RESTRICTED
    assert m.entries[0].length > 0


def test_pem_private_key_classified_restricted():
    # FR-N05-01 / Appendix A: PEM header -> RESTRICTED.
    pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIB...\n-----END RSA PRIVATE KEY-----\n"
    m = _manifest({"body": pem})
    assert m.classification == ArtifactClassification.RESTRICTED


def test_overall_classification_is_max_of_entries():
    # Packet 8.7: envelope classification = highest entry level
    # (public < internal < sensitive < restricted, #58 enum order).
    m = _manifest({"note": "ok", "api_secret": "abcdefghijklmnop"})
    assert m.classification == ArtifactClassification.SENSITIVE
    m2 = _manifest({"api_secret": "abcdefghijklmnop", "body": "https://u:pw1234@h/x"})
    assert m2.classification == ArtifactClassification.RESTRICTED


def test_enum_ordering_follows_contracts():
    # Packet 8.7: ordering is the #58 enum definition order.
    order = [e.name for e in ArtifactClassification]
    assert order.index("PUBLIC") < order.index("INTERNAL")
    assert order.index("INTERNAL") < order.index("SENSITIVE")
    assert order.index("SENSITIVE") < order.index("RESTRICTED")


def test_text_payload_whole_value_fingerprinted():
    # Appendix A: unstructured text handled conservatively (whole-value).
    m = classify_payload(
        EvidencePayload(payload_kind="text", value="line with secret inside"), POLICY
    )
    assert m.classification in (
        ArtifactClassification.SENSITIVE,
        ArtifactClassification.RESTRICTED,
    )
    assert len(m.entries) >= 1


def test_bytes_payload_classified_sensitive():
    # Appendix A: binary secret blob -> SENSITIVE entry with bytes kind.
    m = classify_payload(
        EvidencePayload(payload_kind="bytes", value=b"\x00\x11binaryblob"), POLICY
    )
    assert m.classification == ArtifactClassification.SENSITIVE
    assert m.entries[0].value_kind == "bytes"
    assert m.entries[0].length == len(b"\x00\x11binaryblob")


def test_manifest_carries_policy_version_and_digest():
    # NFR-N05-04: manifest always carries policy_version and 64-hex digest.
    m = _manifest({"api_key": "abcdefghijklmnop"})
    assert m.policy_version == "v1"
    assert len(m.policy_digest) == 64
    assert all(c in "0123456789abcdef" for c in m.policy_digest)
    assert m.created_at  # UTC ISO-8601 NFC string present
