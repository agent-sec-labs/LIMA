"""Canonical JSON v4.0 codec tests: stability, negative inputs, and resource limits."""

import enum
import hashlib
import unittest

from lima.contracts.codec import (
    DEFAULT_LIMITS,
    ContractLimits,
    canonical_decode,
    canonical_encode,
    compute_content_digest,
)
from lima.contracts.errors import ContractError, ContractErrorCode

FROZEN_PAYLOAD = {"coverage": {"files": 3}, "kind": "contract-foundation"}
FROZEN_PAYLOAD_DIGEST = "567791dedb5a4052163ab8fcc5e7abc3ff71008fa1ec690c8fa739dfe14822d7"


class CanonicalCodecTests(unittest.TestCase):
    def _round_trip(self, data, *, limits=DEFAULT_LIMITS):
        return canonical_encode(canonical_decode(data, limits=limits), limits=limits)

    def _assert_rejected(self, invoke, code):
        with self.assertRaises(ContractError) as ctx:
            invoke()
        self.assertIs(ctx.exception.code, code)

    def test_key_order_and_json_whitespace_are_stable(self):
        baseline = self._round_trip(b'{"b": 1, "a": 2}')
        self.assertEqual(baseline, b'{"a":2,"b":1}')
        self.assertEqual(self._round_trip(b'{"a":2,"b":1}'), baseline)
        self.assertEqual(self._round_trip(b'{ "a" : 2 , "b" : 1 }'), baseline)
        self.assertEqual(self._round_trip(b'{"a" : 2,\t"b"\n: 1}'), baseline)
        self.assertEqual(canonical_decode(b'{"a": 2, "b": 1}'), {"a": 2, "b": 1})

    def test_lf_crlf_and_indentation_decode_to_same_bytes(self):
        lf = b'{"a": {"b": 1}, "c": [1, 2]}'
        crlf = b'{"a": {"b": 1},\r\n "c": [1, 2]}'
        indented = b'{\n  "c": [\n    1,\n    2\n  ],\n  "a": {\n    "b": 1\n  }\n}'
        expected = b'{"a":{"b":1},"c":[1,2]}'
        self.assertEqual(self._round_trip(lf), expected)
        self.assertEqual(self._round_trip(crlf), expected)
        self.assertEqual(self._round_trip(indented), expected)

    def test_unicode_nfc_is_stable_for_keys_and_values(self):
        composed_key = b'{"caf\xc3\xa9": "ol\xc3\xa9"}'
        decomposed_key = '{"cafe\u0301": "ole\u0301"}'.encode("utf-8")
        self.assertEqual(self._round_trip(composed_key), b'{"caf\xc3\xa9":"ol\xc3\xa9"}')
        self.assertEqual(self._round_trip(decomposed_key), b'{"caf\xc3\xa9":"ol\xc3\xa9"}')
        decoded = canonical_decode(decomposed_key)
        self.assertEqual(list(decoded), ["café"])
        self.assertEqual(decoded["café"], "olé")
        self.assertEqual(
            compute_content_digest(canonical_decode(composed_key)),
            compute_content_digest(canonical_decode(decomposed_key)),
        )

    def test_rejects_unpaired_unicode_surrogate(self):
        self._assert_rejected(
            lambda: canonical_decode(b'"\\ud800"'), ContractErrorCode.INVALID_UTF8
        )
        self._assert_rejected(
            lambda: canonical_decode(b'{"\\udfff": 1}'), ContractErrorCode.INVALID_UTF8
        )
        self._assert_rejected(
            lambda: canonical_encode("\ud800"), ContractErrorCode.INVALID_UTF8
        )
        self._assert_rejected(
            lambda: canonical_encode({"bad": "\udfff"}), ContractErrorCode.INVALID_UTF8
        )

    def test_rejects_raw_duplicate_field(self):
        self._assert_rejected(
            lambda: canonical_decode(b'{"a": 1, "a": 2}'), ContractErrorCode.DUPLICATE_FIELD
        )
        self._assert_rejected(
            lambda: canonical_decode(b'{"x": {"a": 1, "a": 2}}'),
            ContractErrorCode.DUPLICATE_FIELD,
        )

    def test_rejects_unicode_semantic_duplicate_field(self):
        document = '{"e\u0301": 1, "\u00e9": 2}'.encode("utf-8")
        self._assert_rejected(
            lambda: canonical_decode(document), ContractErrorCode.DUPLICATE_SEMANTIC_FIELD
        )

    def test_rejects_finite_float_nan_and_infinity(self):
        for raw in (b"1.5", b"-0.25", b"1e5", b"NaN", b"Infinity", b"-Infinity", b'{"x": 2.0}'):
            with self.subTest(raw=raw):
                self._assert_rejected(
                    lambda raw=raw: canonical_decode(raw),
                    ContractErrorCode.UNSUPPORTED_VALUE_TYPE,
                )
        for value in (1.5, float("nan"), float("inf"), float("-inf")):
            with self.subTest(value=value):
                self._assert_rejected(
                    lambda value=value: canonical_encode(value),
                    ContractErrorCode.UNSUPPORTED_VALUE_TYPE,
                )
                self._assert_rejected(
                    lambda value=value: canonical_encode({"x": value}),
                    ContractErrorCode.UNSUPPORTED_VALUE_TYPE,
                )

    def test_rejects_non_string_key_and_unsupported_python_type(self):
        self._assert_rejected(
            lambda: canonical_encode({1: "x"}), ContractErrorCode.UNSUPPORTED_VALUE_TYPE
        )
        self._assert_rejected(
            lambda: canonical_encode({None: "x"}), ContractErrorCode.UNSUPPORTED_VALUE_TYPE
        )

        class Custom:
            pass

        class Shade(enum.Enum):
            RED = "red"

        for value in (
            (1, 2),
            {1, 2},
            b"bytes",
            bytearray(b"bytes"),
            Custom(),
            Shade.RED,
            object(),
        ):
            with self.subTest(value=repr(value)):
                self._assert_rejected(
                    lambda value=value: canonical_encode(value),
                    ContractErrorCode.UNSUPPORTED_VALUE_TYPE,
                )

    def test_rejects_integer_outside_signed_64_bit(self):
        self._assert_rejected(
            lambda: canonical_decode(b"9223372036854775808"),
            ContractErrorCode.INTEGER_OUT_OF_RANGE,
        )
        self._assert_rejected(
            lambda: canonical_decode(b"-9223372036854775809"),
            ContractErrorCode.INTEGER_OUT_OF_RANGE,
        )
        self._assert_rejected(
            lambda: canonical_decode(b"1" + b"0" * 500),
            ContractErrorCode.INTEGER_OUT_OF_RANGE,
        )
        self._assert_rejected(
            lambda: canonical_encode(9223372036854775808),
            ContractErrorCode.INTEGER_OUT_OF_RANGE,
        )
        self._assert_rejected(
            lambda: canonical_encode(-9223372036854775809),
            ContractErrorCode.INTEGER_OUT_OF_RANGE,
        )
        self.assertEqual(canonical_decode(b"9223372036854775807"), 9223372036854775807)
        self.assertEqual(canonical_decode(b"-9223372036854775808"), -9223372036854775808)
        self.assertEqual(canonical_encode(9223372036854775807), b"9223372036854775807")
        self.assertEqual(canonical_encode(-9223372036854775808), b"-9223372036854775808")

    def test_enforces_input_and_output_byte_limits(self):
        tight = ContractLimits(max_input_bytes=8)
        self._assert_rejected(
            lambda: canonical_decode(b'{"a": 12}', limits=tight),
            ContractErrorCode.RESOURCE_LIMIT_EXCEEDED,
        )
        self.assertEqual(self._round_trip(b'{"a":12}', limits=tight), b'{"a":12}')
        self._assert_rejected(
            lambda: canonical_encode({"aa": 1234}, limits=tight),
            ContractErrorCode.RESOURCE_LIMIT_EXCEEDED,
        )
        self._assert_rejected(
            lambda: compute_content_digest(b"123456789", limits=tight),
            ContractErrorCode.RESOURCE_LIMIT_EXCEEDED,
        )
        self.assertEqual(
            compute_content_digest(b"12345678", limits=tight),
            hashlib.sha256(b"12345678").hexdigest(),
        )

    def test_enforces_depth_limit_at_exact_boundary(self):
        shallow = ContractLimits(max_depth=2)
        self.assertEqual(self._round_trip(b"[[1]]", limits=shallow), b"[[1]]")
        self.assertEqual(self._round_trip(b"1", limits=shallow), b"1")
        self.assertEqual(self._round_trip(b'{"a":{"b":1}}', limits=shallow), b'{"a":{"b":1}}')
        self._assert_rejected(
            lambda: canonical_decode(b"[[[1]]]", limits=shallow),
            ContractErrorCode.MAX_DEPTH_EXCEEDED,
        )
        self._assert_rejected(
            lambda: canonical_encode([[[1]]], limits=shallow),
            ContractErrorCode.MAX_DEPTH_EXCEEDED,
        )
        unit = ContractLimits(max_depth=1)
        self.assertEqual(self._round_trip(b"[1]", limits=unit), b"[1]")
        self._assert_rejected(
            lambda: canonical_encode([[1]], limits=unit), ContractErrorCode.MAX_DEPTH_EXCEEDED
        )

    def test_enforces_array_object_and_string_limits(self):
        arrays = ContractLimits(max_array_items=2)
        self.assertEqual(self._round_trip(b"[1,2]", limits=arrays), b"[1,2]")
        self._assert_rejected(
            lambda: canonical_decode(b"[1,2,3]", limits=arrays),
            ContractErrorCode.MAX_ARRAY_LENGTH_EXCEEDED,
        )
        self._assert_rejected(
            lambda: canonical_encode([1, 2, 3], limits=arrays),
            ContractErrorCode.MAX_ARRAY_LENGTH_EXCEEDED,
        )
        self._assert_rejected(
            lambda: canonical_encode([[1, 2, 3]], limits=arrays),
            ContractErrorCode.MAX_ARRAY_LENGTH_EXCEEDED,
        )

        objects = ContractLimits(max_object_fields=2)
        self.assertEqual(self._round_trip(b'{"a":1,"b":2}', limits=objects), b'{"a":1,"b":2}')
        self._assert_rejected(
            lambda: canonical_decode(b'{"a":1,"b":2,"c":3}', limits=objects),
            ContractErrorCode.MAX_OBJECT_FIELDS_EXCEEDED,
        )
        self._assert_rejected(
            lambda: canonical_encode({"a": 1, "b": 2, "c": 3}, limits=objects),
            ContractErrorCode.MAX_OBJECT_FIELDS_EXCEEDED,
        )

        strings = ContractLimits(max_string_bytes=2)
        self.assertEqual(self._round_trip('"é"'.encode(), limits=strings), '"é"'.encode())
        self._assert_rejected(
            lambda: canonical_encode("éé", limits=strings),
            ContractErrorCode.MAX_STRING_LENGTH_EXCEEDED,
        )
        self._assert_rejected(
            lambda: canonical_encode({"éé": 1}, limits=strings),
            ContractErrorCode.MAX_STRING_LENGTH_EXCEEDED,
        )
        self._assert_rejected(
            lambda: canonical_decode('"éé"'.encode(), limits=strings),
            ContractErrorCode.MAX_STRING_LENGTH_EXCEEDED,
        )
        self.assertEqual(
            self._round_trip('"e\u0301"'.encode(), limits=strings), '"é"'.encode()
        )

    def test_rejects_invalid_utf8_bom_and_trailing_json(self):
        self._assert_rejected(
            lambda: canonical_decode(b'{"a": "\xff"}'), ContractErrorCode.INVALID_UTF8
        )
        self._assert_rejected(
            lambda: canonical_decode(b"\x80"), ContractErrorCode.INVALID_UTF8
        )
        self._assert_rejected(
            lambda: canonical_decode(b'\xef\xbb\xbf{"a": 1}'), ContractErrorCode.INVALID_JSON
        )
        self._assert_rejected(
            lambda: canonical_decode(b'{"a": 1} trailing'), ContractErrorCode.INVALID_JSON
        )
        self._assert_rejected(
            lambda: canonical_decode(b'{"a": 1}{"b": 2}'), ContractErrorCode.INVALID_JSON
        )
        self._assert_rejected(
            lambda: canonical_decode(b'{"a": 1,}'), ContractErrorCode.INVALID_JSON
        )
        self.assertEqual(self._round_trip(b'{"a": 1} \r\n\t'), b'{"a":1}')

    def test_digest_matches_frozen_payload_vector(self):
        self.assertEqual(compute_content_digest(FROZEN_PAYLOAD), FROZEN_PAYLOAD_DIGEST)
        canonical = canonical_encode(FROZEN_PAYLOAD)
        self.assertEqual(hashlib.sha256(canonical).hexdigest(), FROZEN_PAYLOAD_DIGEST)
        self.assertEqual(
            compute_content_digest(canonical_decode(canonical)), FROZEN_PAYLOAD_DIGEST
        )
        reordered = b'{"kind": "contract-foundation", "coverage": {"files": 3}}'
        self.assertEqual(
            compute_content_digest(canonical_decode(reordered)), FROZEN_PAYLOAD_DIGEST
        )
        self.assertEqual(canonical, b'{"coverage":{"files":3},"kind":"contract-foundation"}')

    def test_bytes_digest_uses_raw_bytes(self):
        self.assertEqual(compute_content_digest(b"abc"), hashlib.sha256(b"abc").hexdigest())
        raw = b'{ "a" : 1 }'
        self.assertEqual(compute_content_digest(raw), hashlib.sha256(raw).hexdigest())
        self.assertNotEqual(compute_content_digest(raw), compute_content_digest({"a": 1}))
        self.assertEqual(
            compute_content_digest("abc"), hashlib.sha256(b'"abc"').hexdigest()
        )
        self.assertEqual(compute_content_digest(None), hashlib.sha256(b"null").hexdigest())
        self.assertEqual(
            compute_content_digest(b'"abc"'), compute_content_digest("abc")
        )
        self._assert_rejected(
            lambda: compute_content_digest(bytearray(b"abc")),
            ContractErrorCode.UNSUPPORTED_VALUE_TYPE,
        )


if __name__ == "__main__":
    unittest.main()
