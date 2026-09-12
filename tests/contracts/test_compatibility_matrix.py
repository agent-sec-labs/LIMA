"""Compatibility-matrix and ADR consistency tests (IP-0010 packet section 18.2).

Every test method first loads the matrix artifact (or the ADR), so the module is RED
(FileNotFoundError) until the IP-0010 deliverables exist.
"""

import hashlib
import json
import unittest
from pathlib import Path

from lima.contracts.common import SchemaVersion, decode_envelope
from lima.contracts.errors import ContractError, ContractErrorCode
from tests.contracts.test_schema_export import (
    ADR_PATH,
    DECODE,
    FROZEN_ARTIFACT_DIGESTS,
    GOLDENS,
    SCHEMA_DIR,
    load_goldens,
)

MATRIX_PATH = SCHEMA_DIR / "version_compatibility_matrix.json"
V4 = SchemaVersion(4, 0)
V42 = SchemaVersion(4, 2)


def load_matrix():
    return json.loads(MATRIX_PATH.read_text(encoding="utf-8"))


def matrix_schema_names(matrix):
    return [row["schema_name"] for row in matrix["schemas"]]


def matrix_payload_names(matrix):
    return [n for n in matrix_schema_names(matrix) if n != "lima.artifact-envelope"]


def first_payload(name):
    return load_goldens(name)[0]


class CompatibilityMatrixTests(unittest.TestCase):
    def test_matrix_lists_all_thirteen_schemas(self):
        matrix = load_matrix()
        self.assertEqual(matrix["wire_major"], 4)
        self.assertEqual(matrix["current_minor"], "4.0")
        names = matrix_schema_names(matrix)
        self.assertEqual(len(names), 13)
        self.assertEqual(sorted(names), sorted(n for n in GOLDENS))
        for row in matrix["schemas"]:
            self.assertEqual(row["wire_version"], "4.0")
            self.assertTrue((SCHEMA_DIR / f"{row['schema_name']}.json").exists())

    def test_matrix_digest_is_frozen(self):
        data = MATRIX_PATH.read_bytes()
        size, digest = FROZEN_ARTIFACT_DIGESTS["version_compatibility_matrix.json"]
        self.assertEqual(len(data), size)
        self.assertEqual(hashlib.sha256(data).hexdigest(), digest)
        behavior_ids = [b["id"] for b in load_matrix()["global_behaviors"]]
        self.assertEqual(
            sorted(behavior_ids),
            sorted(["unknown_major", "future_minor_extension_roundtrip",
                    "current_minor_unknown_field", "required_missing", "unknown_enum"]),
        )

    def test_unknown_major_rejected_for_all_schemas(self):
        matrix = load_matrix()
        with self.assertRaises(ContractError) as ctx:
            SchemaVersion.parse("5.0")
        self.assertIs(ctx.exception.code, ContractErrorCode.SCHEMA_UNKNOWN_MAJOR)
        for name in matrix_schema_names(matrix):
            with self.assertRaises(ContractError) as ctx:
                SchemaVersion.parse("5.0")
            self.assertIs(ctx.exception.code, ContractErrorCode.SCHEMA_UNKNOWN_MAJOR,
                          name)

    def test_unknown_field_rejected_at_current_minor_for_all_schemas(self):
        matrix = load_matrix()
        for name in matrix_payload_names(matrix):
            payload = first_payload(name)
            payload["future_top"] = 1
            with self.assertRaises(ContractError) as ctx:
                DECODE[name](payload)
            self.assertIs(ctx.exception.code, ContractErrorCode.UNKNOWN_FIELD, name)

    def test_required_missing_rejected_for_all_schemas(self):
        matrix = load_matrix()
        for name in matrix_payload_names(matrix):
            payload = first_payload(name)
            first_required = sorted(payload.keys())[0]
            stripped = {k: v for k, v in payload.items() if k != first_required}
            with self.assertRaises(ContractError) as ctx:
                DECODE[name](stripped)
            self.assertIs(ctx.exception.code, ContractErrorCode.REQUIRED_FIELD_MISSING,
                          name)

    def test_future_minor_roundtrips_for_all_schemas(self):
        matrix = load_matrix()
        for name in matrix_payload_names(matrix):
            payload = first_payload(name)
            payload["future_top"] = {"note": name}
            decoded = DECODE[name](payload, V42)
            encoded = decoded.to_dict()
            self.assertEqual(encoded["future_top"], {"note": name}, name)
        envelope = json.loads((Path(__file__).resolve().parent / "fixtures"
                              / "artifact_envelope_v4_golden.json").read_text(
                                  encoding="utf-8"))
        envelope["schema_version"] = "4.2"
        envelope["future_env_top"] = 1
        decoded_env = decode_envelope(
            json.dumps(envelope).encode("utf-8"))
        self.assertEqual(decoded_env.extensions.get("future_env_top"), 1)

    def test_unknown_enum_rejected_for_representative_schemas(self):
        matrix = load_matrix()
        representatives = {
            "lima.workflow": ("status", "zombie"),
            "lima.stage-attempt": ("status", "paused"),
            "lima.security-outcome": ("kind", "mostly_harmless"),
            "lima.plan": ("workflow_mode", "chaos"),
            "lima.audit-evidence-package": ("audit_outcome", "excellent"),
            "lima.workflow-summary": ("source", "hybrid"),
            "lima.failure-report": ("failure_kind", "act_of_god"),
        }
        names = set(matrix_schema_names(matrix))
        self.assertTrue(set(representatives) <= names)
        for name, (field, bad) in representatives.items():
            payload = first_payload(name)
            payload[field] = bad
            with self.assertRaises(ContractError) as ctx:
                DECODE[name](payload)
            self.assertIs(ctx.exception.code, ContractErrorCode.UNKNOWN_ENUM_VALUE,
                          f"{name}.{field}")

    def test_adr_records_frozen_version_policies(self):
        data = ADR_PATH.read_bytes()
        self.assertEqual(hashlib.sha256(data).hexdigest(),
                         "d96ccca7b10b02d058b35d417ed126dcd84c6a03a6f037f16da670bde16c47d4")
        text = data.decode("utf-8")
        for phrase in ("SCHEMA_UNKNOWN_MAJOR", "additionalProperties",
                       "extensions", "major bump", "schemas/v4",
                       "REQUIRED_FIELD_MISSING", "UNKNOWN_ENUM_VALUE"):
            self.assertIn(phrase, text)
        self.assertIn("不新增决策", text)


if __name__ == "__main__":
    unittest.main()
