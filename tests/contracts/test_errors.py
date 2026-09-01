"""Stable error contract tests: error codes, message catalog, and resource limits."""

import dataclasses
import json
import unittest

from lima.contracts.codec import DEFAULT_LIMITS, ContractLimits

from lima.contracts.errors import ContractError, ContractErrorCode

EXPECTED_MESSAGES = {
    "INVALID_LIMIT": "Contract resource limit is invalid.",
    "INVALID_UTF8": "Input is not valid UTF-8.",
    "INVALID_JSON": "Input is not valid JSON.",
    "TOP_LEVEL_NOT_OBJECT": "Envelope input must be a JSON object.",
    "DUPLICATE_FIELD": "JSON object contains a duplicate field.",
    "DUPLICATE_SEMANTIC_FIELD": "JSON object contains fields that normalize to the same name.",
    "UNSUPPORTED_VALUE_TYPE": "Value type is not supported by canonical JSON v4.0.",
    "INTEGER_OUT_OF_RANGE": "Integer is outside the signed 64-bit range.",
    "REQUIRED_FIELD_MISSING": "A required contract field is missing.",
    "UNKNOWN_FIELD": "Contract contains an unknown field for this schema version.",
    "INVALID_FIELD_TYPE": "Contract field has an invalid type.",
    "INVALID_FIELD_VALUE": "Contract field has an invalid value.",
    "UNKNOWN_ENUM_VALUE": "Contract field contains an unknown enum value.",
    "SCHEMA_VERSION_INVALID": "Schema version is invalid.",
    "SCHEMA_UNKNOWN_MAJOR": "Schema major version is not supported.",
    "RESOURCE_LIMIT_EXCEEDED": "Contract input exceeds the byte limit.",
    "MAX_DEPTH_EXCEEDED": "Contract input exceeds the nesting depth limit.",
    "MAX_ARRAY_LENGTH_EXCEEDED": "Contract array exceeds the item limit.",
    "MAX_OBJECT_FIELDS_EXCEEDED": "Contract object exceeds the field limit.",
    "MAX_STRING_LENGTH_EXCEEDED": "Contract string exceeds the UTF-8 byte limit.",
    "INLINE_OR_BLOB_REQUIRED": "Envelope requires inline payload or a blob reference.",
    "INLINE_AND_BLOB_CONFLICT": (
        "Envelope cannot contain both inline payload and a blob reference."
    ),
    "DIGEST_MISMATCH": "Declared content digest does not match authoritative content.",
    "LINEAGE_DUPLICATE": "Envelope lineage contains a duplicate reference.",
    "LINEAGE_CONFLICT": "Envelope lineage contains conflicting identities for one artifact.",
    "LINEAGE_SELF_REFERENCE": "Envelope cannot reference itself.",
    "LINEAGE_TENANT_MISMATCH": "Envelope reference belongs to a different tenant.",
    "LINEAGE_SNAPSHOT_MISMATCH": (
        "Envelope reference belongs to a different repository snapshot."
    ),
    "COVERAGE_GAP_DUPLICATE": "Envelope contains a duplicate coverage gap.",
}


class ContractErrorTests(unittest.TestCase):
    def test_every_error_code_has_stable_message(self):
        self.assertEqual(
            set(EXPECTED_MESSAGES), {code.value for code in ContractErrorCode}
        )
        for code in ContractErrorCode:
            error = ContractError(code)
            self.assertEqual(str(error), EXPECTED_MESSAGES[code.value])
            self.assertIs(error.code, code)

    def test_to_dict_has_exact_public_shape(self):
        error = ContractError(ContractErrorCode.INVALID_JSON, "$.payload.entries[0]")
        payload = error.to_dict()
        self.assertEqual(set(payload), {"code", "field_path", "message"})
        self.assertEqual(payload["code"], "INVALID_JSON")
        self.assertEqual(payload["field_path"], "$.payload.entries[0]")
        self.assertEqual(payload["message"], EXPECTED_MESSAGES["INVALID_JSON"])
        for value in payload.values():
            self.assertIsInstance(value, str)
        self.assertEqual(error.field_path, "$.payload.entries[0]")

    def test_error_does_not_render_raw_value(self):
        sentinel = "raw-input-sentinel-9f31c2"
        for code in ContractErrorCode:
            error = ContractError(code, "$.payload.api_key")
            rendered = json.dumps(error.to_dict())
            self.assertNotIn(sentinel, rendered)
            self.assertNotIn(sentinel, str(error))
            self.assertEqual(str(error), EXPECTED_MESSAGES[code.value])
        with self.assertRaises(TypeError):
            ContractError(ContractErrorCode.INVALID_FIELD_VALUE, "$.x", sentinel)


class ContractLimitsTests(unittest.TestCase):
    def test_defaults_are_frozen(self):
        limits = ContractLimits()
        self.assertEqual(limits.max_input_bytes, 1_048_576)
        self.assertEqual(limits.max_depth, 32)
        self.assertEqual(limits.max_array_items, 10_000)
        self.assertEqual(limits.max_object_fields, 1_000)
        self.assertEqual(limits.max_string_bytes, 262_144)
        self.assertEqual(DEFAULT_LIMITS, ContractLimits())
        with self.assertRaises(dataclasses.FrozenInstanceError):
            limits.max_depth = 64

    def test_rejects_bool_zero_negative_and_non_integer_limits(self):
        invalid_values = [True, False, 0, -1, "32", 3.5, None]
        for value in invalid_values:
            for field in (
                "max_input_bytes",
                "max_depth",
                "max_array_items",
                "max_object_fields",
                "max_string_bytes",
            ):
                with self.subTest(field=field, value=repr(value)):
                    with self.assertRaises(ContractError) as ctx:
                        ContractLimits(**{field: value})
                    self.assertIs(ctx.exception.code, ContractErrorCode.INVALID_LIMIT)


if __name__ == "__main__":
    unittest.main()
