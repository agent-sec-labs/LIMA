"""Shared primitive tests (retirement Task 2 trim).

Only the parsing and field-validation helpers that remain in
``lima.cxx_agent_models`` are covered; the candidate/decision/consensus
contract tests rode the retired seven-role chain.
"""

import unittest

from lima.cxx_agent_models import (
    MAX_PATH_BYTES,
    MAX_TEXT_BYTES,
    _bounded_text,
    _hex_digest,
    _safe_relative_path,
    parse_untrusted_json,
)


class UntrustedJsonBoundaryTests(unittest.TestCase):
    def test_valid_document_parses(self):
        self.assertEqual({"a": [1, 2]}, parse_untrusted_json('{"a": [1, 2]}'))

    def test_duplicate_keys_are_rejected(self):
        with self.assertRaises(ValueError):
            parse_untrusted_json('{"a": 1, "a": 2}')

    def test_non_finite_numbers_are_rejected(self):
        for literal in ("NaN", "Infinity", "-Infinity"):
            with self.subTest(literal=literal), self.assertRaises(ValueError):
                parse_untrusted_json(f'{{"a": {literal}}}')

    def test_non_utf8_bytes_are_rejected(self):
        with self.assertRaises(ValueError):
            parse_untrusted_json(b'{"a": "' + bytes([0xff]) + b'"}')

    def test_non_text_input_is_rejected(self):
        with self.assertRaises(ValueError):
            parse_untrusted_json(123)

    def test_broken_json_is_rejected(self):
        for raw in ("{", "[]]", '"unterminated'):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                parse_untrusted_json(raw)


class BoundedTextTests(unittest.TestCase):
    def test_accepts_non_empty_text_within_the_cap(self):
        self.assertEqual("hello", _bounded_text("hello", "field"))

    def test_rejects_empty_and_non_string(self):
        for bad in ("", None, 42):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    _bounded_text(bad, "field")

    def test_rejects_over_limit_values(self):
        with self.assertRaises(ValueError):
            _bounded_text("x" * (MAX_TEXT_BYTES + 1), "field")


class SafeRelativePathTests(unittest.TestCase):
    def test_accepts_relative_posix_paths(self):
        self.assertEqual("src/a.c", _safe_relative_path("src/a.c", "path"))

    def test_rejects_absolute_backslash_traversal(self):
        for bad in ("/etc/x", "a\\b", "../x", ".", ".."):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    _safe_relative_path(bad, "path")

    def test_rejects_over_limit_paths(self):
        with self.assertRaises(ValueError):
            _safe_relative_path("a" * (MAX_PATH_BYTES + 1), "path")


class HexDigestTests(unittest.TestCase):
    def test_accepts_lowercase_sha256(self):
        digest = "a" * 64
        self.assertEqual(digest, _hex_digest(digest, "digest"))

    def test_rejects_wrong_length_uppercase_and_non_string(self):
        for bad in ("a" * 63, "A" * 64, None, 42):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    _hex_digest(bad, "digest")


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
