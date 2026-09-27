"""Path validation for changed-file inputs (retirement Task 2 trim)."""

import unittest

from lima.cxx_retrieval import _validate_changed_path


class ValidateChangedPathTests(unittest.TestCase):
    def test_accepts_plain_relative_posix_paths(self) -> None:
        _validate_changed_path("src/main.c")
        _validate_changed_path("deeply/nested/Header.hpp")
        _validate_changed_path("a")

    def test_rejects_empty_and_non_string(self) -> None:
        for bad in ("", None, 42, ("a",)):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    _validate_changed_path(bad)

    def test_rejects_backslash_paths(self) -> None:
        with self.assertRaises(ValueError):
            _validate_changed_path("src\\main.c")

    def test_rejects_drive_and_absolute_paths(self) -> None:
        for bad in ("C:/tmp/x.c", "/etc/passwd"):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    _validate_changed_path(bad)

    def test_rejects_traversal(self) -> None:
        for bad in ("../escape.c", "a/../../b", ".."):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    _validate_changed_path(bad)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
