"""Stable error contract for the LIMA artifact contract foundation.

Every failure path in ``lima.contracts`` raises :class:`ContractError` with a
frozen :class:`ContractErrorCode` and a catalog-owned stable English message.
Messages never embed raw input values; structural position is carried only by
``field_path``.
"""

import enum

__all__ = ["ContractError", "ContractErrorCode"]


class ContractErrorCode(str, enum.Enum):  # noqa: UP042 -- signature frozen by IP-0001 §7
    """Frozen wire values for every deterministic contract failure."""

    INVALID_LIMIT = "INVALID_LIMIT"
    INVALID_UTF8 = "INVALID_UTF8"
    INVALID_JSON = "INVALID_JSON"
    TOP_LEVEL_NOT_OBJECT = "TOP_LEVEL_NOT_OBJECT"
    DUPLICATE_FIELD = "DUPLICATE_FIELD"
    DUPLICATE_SEMANTIC_FIELD = "DUPLICATE_SEMANTIC_FIELD"
    UNSUPPORTED_VALUE_TYPE = "UNSUPPORTED_VALUE_TYPE"
    INTEGER_OUT_OF_RANGE = "INTEGER_OUT_OF_RANGE"
    REQUIRED_FIELD_MISSING = "REQUIRED_FIELD_MISSING"
    UNKNOWN_FIELD = "UNKNOWN_FIELD"
    INVALID_FIELD_TYPE = "INVALID_FIELD_TYPE"
    INVALID_FIELD_VALUE = "INVALID_FIELD_VALUE"
    UNKNOWN_ENUM_VALUE = "UNKNOWN_ENUM_VALUE"
    SCHEMA_VERSION_INVALID = "SCHEMA_VERSION_INVALID"
    SCHEMA_UNKNOWN_MAJOR = "SCHEMA_UNKNOWN_MAJOR"
    RESOURCE_LIMIT_EXCEEDED = "RESOURCE_LIMIT_EXCEEDED"
    MAX_DEPTH_EXCEEDED = "MAX_DEPTH_EXCEEDED"
    MAX_ARRAY_LENGTH_EXCEEDED = "MAX_ARRAY_LENGTH_EXCEEDED"
    MAX_OBJECT_FIELDS_EXCEEDED = "MAX_OBJECT_FIELDS_EXCEEDED"
    MAX_STRING_LENGTH_EXCEEDED = "MAX_STRING_LENGTH_EXCEEDED"
    INLINE_OR_BLOB_REQUIRED = "INLINE_OR_BLOB_REQUIRED"
    INLINE_AND_BLOB_CONFLICT = "INLINE_AND_BLOB_CONFLICT"
    DIGEST_MISMATCH = "DIGEST_MISMATCH"
    LINEAGE_DUPLICATE = "LINEAGE_DUPLICATE"
    LINEAGE_CONFLICT = "LINEAGE_CONFLICT"
    LINEAGE_SELF_REFERENCE = "LINEAGE_SELF_REFERENCE"
    LINEAGE_TENANT_MISMATCH = "LINEAGE_TENANT_MISMATCH"
    LINEAGE_SNAPSHOT_MISMATCH = "LINEAGE_SNAPSHOT_MISMATCH"
    COVERAGE_GAP_DUPLICATE = "COVERAGE_GAP_DUPLICATE"


_STABLE_MESSAGES: dict[ContractErrorCode, str] = {
    ContractErrorCode.INVALID_LIMIT: "Contract resource limit is invalid.",
    ContractErrorCode.INVALID_UTF8: "Input is not valid UTF-8.",
    ContractErrorCode.INVALID_JSON: "Input is not valid JSON.",
    ContractErrorCode.TOP_LEVEL_NOT_OBJECT: "Envelope input must be a JSON object.",
    ContractErrorCode.DUPLICATE_FIELD: "JSON object contains a duplicate field.",
    ContractErrorCode.DUPLICATE_SEMANTIC_FIELD: (
        "JSON object contains fields that normalize to the same name."
    ),
    ContractErrorCode.UNSUPPORTED_VALUE_TYPE: (
        "Value type is not supported by canonical JSON v4.0."
    ),
    ContractErrorCode.INTEGER_OUT_OF_RANGE: "Integer is outside the signed 64-bit range.",
    ContractErrorCode.REQUIRED_FIELD_MISSING: "A required contract field is missing.",
    ContractErrorCode.UNKNOWN_FIELD: "Contract contains an unknown field for this schema version.",
    ContractErrorCode.INVALID_FIELD_TYPE: "Contract field has an invalid type.",
    ContractErrorCode.INVALID_FIELD_VALUE: "Contract field has an invalid value.",
    ContractErrorCode.UNKNOWN_ENUM_VALUE: "Contract field contains an unknown enum value.",
    ContractErrorCode.SCHEMA_VERSION_INVALID: "Schema version is invalid.",
    ContractErrorCode.SCHEMA_UNKNOWN_MAJOR: "Schema major version is not supported.",
    ContractErrorCode.RESOURCE_LIMIT_EXCEEDED: "Contract input exceeds the byte limit.",
    ContractErrorCode.MAX_DEPTH_EXCEEDED: "Contract input exceeds the nesting depth limit.",
    ContractErrorCode.MAX_ARRAY_LENGTH_EXCEEDED: "Contract array exceeds the item limit.",
    ContractErrorCode.MAX_OBJECT_FIELDS_EXCEEDED: "Contract object exceeds the field limit.",
    ContractErrorCode.MAX_STRING_LENGTH_EXCEEDED: (
        "Contract string exceeds the UTF-8 byte limit."
    ),
    ContractErrorCode.INLINE_OR_BLOB_REQUIRED: (
        "Envelope requires inline payload or a blob reference."
    ),
    ContractErrorCode.INLINE_AND_BLOB_CONFLICT: (
        "Envelope cannot contain both inline payload and a blob reference."
    ),
    ContractErrorCode.DIGEST_MISMATCH: (
        "Declared content digest does not match authoritative content."
    ),
    ContractErrorCode.LINEAGE_DUPLICATE: "Envelope lineage contains a duplicate reference.",
    ContractErrorCode.LINEAGE_CONFLICT: (
        "Envelope lineage contains conflicting identities for one artifact."
    ),
    ContractErrorCode.LINEAGE_SELF_REFERENCE: "Envelope cannot reference itself.",
    ContractErrorCode.LINEAGE_TENANT_MISMATCH: (
        "Envelope reference belongs to a different tenant."
    ),
    ContractErrorCode.LINEAGE_SNAPSHOT_MISMATCH: (
        "Envelope reference belongs to a different repository snapshot."
    ),
    ContractErrorCode.COVERAGE_GAP_DUPLICATE: "Envelope contains a duplicate coverage gap.",
}


class ContractError(ValueError):
    """Deterministic contract violation with a stable code and message.

    The exception renders exactly the catalog message; raw payloads, secrets,
    and field values are never embedded. Use ``field_path`` for structure-only
    position reporting such as ``$.lineage[0].tenant_id``.
    """

    code: ContractErrorCode
    field_path: str

    def __init__(self, code: ContractErrorCode, field_path: str = "") -> None:
        if not isinstance(code, ContractErrorCode):
            raise TypeError("code must be a ContractErrorCode member")
        if not isinstance(field_path, str):
            raise TypeError("field_path must be a str")
        self.code = code
        self.field_path = field_path
        super().__init__(_STABLE_MESSAGES[code])

    def to_dict(self) -> dict[str, str]:
        """Return the frozen public error payload."""
        return {
            "code": self.code.value,
            "field_path": self.field_path,
            "message": _STABLE_MESSAGES[self.code],
        }
