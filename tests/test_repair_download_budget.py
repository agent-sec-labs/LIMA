"""Offline response-budget tests for repair source and archive downloads."""

import base64
import io
import json
import os
import tempfile
import unittest
from unittest.mock import patch

from lima.fixer import SafeFixer
from lima.github import GitHubClient, ResponseTooLarge
from lima.verifier import RepairVerifier


class _Response:
    def __init__(self, chunks, content_length=None):
        self._body = io.BytesIO(b"".join(chunks))
        self.headers = {}
        if content_length is not None:
            self.headers["Content-Length"] = str(content_length)
        self.read_sizes = []

    def read(self, size=-1):
        self.read_sizes.append(size)
        return self._body.read(size)

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False


class RepairDownloadBudgetTests(unittest.TestCase):
    def test_misleading_content_length_cannot_bypass_actual_budget(self):
        response = _Response([b"abcdef"], content_length=1)
        with patch("urllib.request.urlopen", return_value=response):
            with self.assertRaises(ResponseTooLarge):
                with GitHubClient("").download_archive_file("org/repo", "main", max_bytes=5):
                    self.fail("oversized body was accepted")
        self.assertTrue(all(0 < size <= 6 for size in response.read_sizes))

    def test_verification_exception_still_removes_archive(self):
        with patch("urllib.request.urlopen", return_value=_Response([b"data"])):
            with self.assertRaisesRegex(ValueError, "verification failed"):
                with GitHubClient("").download_archive_file("org/repo", "main") as archive:
                    raise ValueError("verification failed")
        self.assertFalse(archive.exists())

    def test_oversized_sources_cannot_enter_ast_or_patch_planning(self):
        source = "x" * (512 * 1024 + 1)
        with patch("lima.verifier.ast.parse", side_effect=AssertionError("AST entered")):
            self.assertFalse(RepairVerifier().verify_contents({"app.py": source})["passed"])

        class Client:
            def get_pull_request(self, *args):
                return {"head": {"sha": "a" * 40, "repo": {"full_name": "org/repo"}}}

            def get_file(self, *args):
                return {"decoded_content": source}

        fixer = SafeFixer()
        with patch.object(fixer, "apply", side_effect=AssertionError("planning entered")):
            result = fixer.create_fix_commits(
                Client(),
                "org/repo",
                7,
                {
                    "findings": [
                        {
                            "path": "app.py",
                            "line": 3,
                            "cwe": "CWE-89",
                            "rule_id": "FLOW-SQL",
                            "verification_state": "dataflow-verified",
                        }
                    ]
                },
                expected_source_sha="a" * 40,
            )
        self.assertEqual("repair-input-too-large", result["failure_code"])

    def test_get_file_bounds_contents_json_and_decoded_source(self):
        content = base64.b64encode(b"x" * 17).decode("ascii")
        body = json.dumps({"content": content}).encode("utf-8")
        with patch("urllib.request.urlopen", return_value=_Response([body])):
            result = GitHubClient("").get_file("owner/repo", "x.py", "main")
        self.assertEqual("x" * 17, result["decoded_content"])

        oversized_source = base64.b64encode(b"x" * (512 * 1024 + 1)).decode("ascii")
        body = json.dumps({"content": oversized_source}).encode("utf-8")
        with patch("urllib.request.urlopen", return_value=_Response([body])):
            with self.assertRaisesRegex(ResponseTooLarge, "decoded source limit"):
                GitHubClient("").get_file("owner/repo", "x.py", "main")

        with patch("urllib.request.urlopen", return_value=_Response([b"x" * 1_000_001])):
            with self.assertRaises(ResponseTooLarge):
                GitHubClient("").get_file("owner/repo", "x.py", "main")

    def test_download_archive_file_streams_within_budget_and_cleans_up(self):
        response = _Response([b"abc", b"def"], content_length=None)
        with patch("urllib.request.urlopen", return_value=response):
            with GitHubClient("").download_archive_file(
                "owner/repo", "main", max_bytes=6
            ) as archive:
                self.assertEqual(b"abcdef", archive.read_bytes())
                self.assertTrue(archive.exists())
            self.assertFalse(archive.exists())
        self.assertTrue(all(size <= 64 * 1024 for size in response.read_sizes))

    def test_download_archive_file_rejects_actual_oversize_without_content_length(self):
        response = _Response([b"abcd", b"ef"], content_length=None)
        with patch("urllib.request.urlopen", return_value=response):
            with self.assertRaisesRegex(ResponseTooLarge, "archive limit"):
                with GitHubClient("").download_archive_file("owner/repo", "main", max_bytes=5):
                    self.fail("oversized archive must not yield a path")

    def test_download_archive_file_removes_tempfile_when_write_fails(self):
        response = _Response([b"abc"], content_length=3)
        descriptor, name = tempfile.mkstemp(suffix=".zip")
        os.close(descriptor)

        class _WriteFailure:
            def __init__(self, path):
                self.name = path

            def write(self, _chunk):
                raise OSError("disk full")

            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

        with (
            patch("urllib.request.urlopen", return_value=response),
            patch("lima.github.tempfile.NamedTemporaryFile", return_value=_WriteFailure(name)),
        ):
            with self.assertRaisesRegex(OSError, "disk full"):
                with GitHubClient("").download_archive_file("owner/repo", "main", max_bytes=3):
                    self.fail("a write failure must not yield a path")
        self.assertFalse(os.path.exists(name))


if __name__ == "__main__":
    unittest.main()
