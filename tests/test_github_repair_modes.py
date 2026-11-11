"""Offline safety tests for repair-commit file-mode preservation."""

import io
import json
import unittest
from unittest.mock import patch

from lima.github import GitHubClient, ResponseTooLarge

REPOSITORY = "owner/repo"
PARENT_SHA = "a" * 40
ROOT_TREE_SHA = "b" * 40
SOURCE_TREE_SHA = "c" * 40
NEW_TREE_SHA = "d" * 40
COMMIT_SHA = "e" * 40


class RecordingGitHubClient(GitHubClient):
    def __init__(self, responses):
        super().__init__("token")
        self.responses = responses
        self.calls = []

    def _json(self, method, url, payload=None, **_kwargs):
        self.calls.append((method, url, payload))
        if method == "POST":
            if url.endswith("/git/trees"):
                return {"sha": NEW_TREE_SHA}
            if url.endswith("/git/commits"):
                return {"sha": COMMIT_SHA}
            if url.endswith("/git/refs"):
                return {}
            raise AssertionError(f"unexpected POST {url}")
        try:
            return self.responses[url]
        except KeyError as exc:
            raise AssertionError(f"unexpected GET {url}") from exc


def commit_url():
    return f"https://api.github.com/repos/{REPOSITORY}/git/commits/{PARENT_SHA}"


def tree_url(sha):
    return f"https://api.github.com/repos/{REPOSITORY}/git/trees/{sha}"


def parent():
    return {"tree": {"sha": ROOT_TREE_SHA}}


class AtomicCommitModeTests(unittest.TestCase):
    def test_oversized_tree_response_never_starts_writes(self):
        methods = []

        def opener(request, **kwargs):
            methods.append(request.method)
            if "/git/commits/" in request.full_url:
                return io.BytesIO(json.dumps(parent()).encode())
            return io.BytesIO(b" " * 2_000_000)

        with patch("urllib.request.urlopen", side_effect=opener):
            with self.assertRaises(ResponseTooLarge):
                GitHubClient("").create_atomic_commit(
                    REPOSITORY,
                    "repair/1",
                    PARENT_SHA,
                    {"target": "new"},
                    "repair",
                )
        self.assertEqual(["GET", "GET"], methods)

    def test_later_special_file_prevents_writes_for_all_files(self):
        client = RecordingGitHubClient(
            {
                commit_url(): parent(),
                tree_url(ROOT_TREE_SHA): {
                    "truncated": False,
                    "tree": [
                        {"path": "a", "mode": "100644", "type": "blob", "sha": "1" * 40},
                        {"path": "z", "mode": "120000", "type": "blob", "sha": "2" * 40},
                    ],
                },
            }
        )
        with self.assertRaises(ValueError):
            client.create_atomic_commit(
                REPOSITORY,
                "repair/1",
                PARENT_SHA,
                {"a": "new", "z": "new"},
                "repair",
            )
        self.assertFalse(any(method == "POST" for method, _url, _payload in client.calls))

    def test_preserves_regular_and_executable_modes_in_nested_directories(self):
        client = RecordingGitHubClient(
            {
                commit_url(): parent(),
                tree_url(ROOT_TREE_SHA): {
                    "truncated": False,
                    "tree": [
                        {"path": "run", "mode": "100755", "type": "blob", "sha": "1" * 40},
                        {"path": "src", "mode": "040000", "type": "tree", "sha": SOURCE_TREE_SHA},
                    ],
                },
                tree_url(SOURCE_TREE_SHA): {
                    "truncated": False,
                    "tree": [
                        {"path": "main.py", "mode": "100644", "type": "blob", "sha": "2" * 40},
                    ],
                },
            }
        )

        client.create_atomic_commit(
            REPOSITORY,
            "repair/1",
            PARENT_SHA,
            {"src/main.py": "new source", "run": "#!/bin/sh\n"},
            "repair",
        )

        tree_post = next(
            payload
            for method, url, payload in client.calls
            if method == "POST" and url.endswith("/git/trees")
        )
        self.assertEqual(
            [
                {"path": "run", "mode": "100755", "type": "blob", "content": "#!/bin/sh\n"},
                {"path": "src/main.py", "mode": "100644", "type": "blob", "content": "new source"},
            ],
            tree_post["tree"],
        )
        first_post = next(index for index, call in enumerate(client.calls) if call[0] == "POST")
        self.assertTrue(all(call[0] == "GET" for call in client.calls[:first_post]))

    def test_rejects_missing_special_truncated_or_unusable_metadata_before_post(self):
        cases = {
            "missing": {"truncated": False, "tree": []},
            "symlink": {
                "truncated": False,
                "tree": [
                    {"path": "target", "mode": "120000", "type": "blob", "sha": "1" * 40},
                ],
            },
            "gitlink": {
                "truncated": False,
                "tree": [
                    {"path": "target", "mode": "160000", "type": "commit", "sha": "1" * 40},
                ],
            },
            "truncated": {"truncated": True, "tree": []},
            "unusable": {
                "truncated": False,
                "tree": [
                    {"path": "target", "mode": "100644", "type": "blob"},
                ],
            },
        }
        for name, root_tree in cases.items():
            with self.subTest(name=name):
                client = RecordingGitHubClient(
                    {
                        commit_url(): parent(),
                        tree_url(ROOT_TREE_SHA): root_tree,
                    }
                )
                with self.assertRaises(ValueError):
                    client.create_atomic_commit(
                        REPOSITORY,
                        "repair/1",
                        PARENT_SHA,
                        {"target": "new"},
                        "repair",
                    )
                self.assertFalse(any(method == "POST" for method, _url, _payload in client.calls))

    def test_rejects_invalid_repository_parent_or_path_before_post(self):
        client = RecordingGitHubClient({})
        invalid_requests = [
            ("owner/repo?x=1", PARENT_SHA, {"target": "new"}),
            (REPOSITORY, "not-a-commit", {"target": "new"}),
            (REPOSITORY, PARENT_SHA, {"../target": "new"}),
        ]
        for repository, parent_sha, files in invalid_requests:
            with self.subTest(repository=repository, parent_sha=parent_sha, files=files):
                with self.assertRaises(ValueError):
                    client.create_atomic_commit(repository, "repair/1", parent_sha, files, "repair")
        self.assertEqual([], client.calls)
