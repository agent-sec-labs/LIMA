"""Durable publication recovery over real orchestration and fake HTTP state."""

import base64
import hashlib
import tempfile
import threading
import unittest
import urllib.error
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import patch
from urllib.parse import unquote, urlsplit

from lima import github
from lima.store import TaskStore
from tests.test_repair_publication_gates import SHA, PublicationGateFixer, ReadyVerifier, finding


def git_blob(content):
    data = content.encode()
    return hashlib.sha1(
        b"blob " + str(len(data)).encode() + b"\0" + data, usedforsecurity=False
    ).hexdigest()


class FakeGitHub(github.GitHubClient):
    def __init__(self, fail=None):
        super().__init__("")
        self.fail = fail
        self.lock = threading.RLock()
        self.calls = []
        self.root = "b" * 40
        self.trees = {
            self.root: [
                {
                    "path": "app.py",
                    "mode": "100644",
                    "type": "blob",
                    "sha": git_blob("print('debug')\n"),
                }
            ]
        }
        self.commits = {SHA: {"sha": SHA, "tree": {"sha": self.root}, "parents": []}}
        self.refs = {}
        self.pulls = []

    @contextmanager
    def download_archive_file(self, *args):
        yield b"archive"  # Prepared verifier only; no repository test execution.

    def fault(self, stage):
        if self.fail == stage:
            self.fail = None
            raise RuntimeError("simulated acknowledgement loss: " + stage)

    def _json(self, method, url, payload=None, **kwargs):
        with self.lock:
            self.calls.append((method, url, payload))
            path = unquote(urlsplit(url).path).removeprefix("/repos/org/repo/")
            if method == "GET":
                if path == "pulls/7":
                    return {
                        "head": {"sha": SHA, "repo": {"full_name": "org/repo"}},
                        "base": {"ref": "main"},
                    }
                if path.startswith("contents/"):
                    return {"content": base64.b64encode(b"print('debug')\n").decode()}
                if path.startswith("git/commits/"):
                    return self.commits[path.split("/")[-1]]
                if path.startswith("git/trees/"):
                    return {"truncated": False, "tree": self.trees[path.split("/")[-1]]}
                if path.startswith("git/ref/heads/"):
                    branch = path.removeprefix("git/ref/heads/")
                    if branch not in self.refs:
                        raise github.GitHubHTTPError(404, "not found")
                    return {"object": {"sha": self.refs[branch], "type": "commit"}}
                if path.startswith("compare/"):
                    child = path.split("...")[-1]
                    entries = self.trees[self.commits[child]["tree"]["sha"]]
                    return {
                        "total_commits": 1,
                        "files": [
                            {"filename": row["path"], "status": "modified", "sha": row["sha"]}
                            for row in entries
                        ],
                    }
                if path == "pulls":
                    return list(self.pulls)
            if method == "POST":
                if path == "git/trees":
                    sha = hashlib.sha1(repr(payload).encode(), usedforsecurity=False).hexdigest()
                    self.trees[sha] = [
                        {
                            "path": row["path"],
                            "mode": row["mode"],
                            "type": "blob",
                            "sha": git_blob(row["content"]),
                        }
                        for row in payload["tree"]
                    ]
                    self.fault("tree")
                    return {"sha": sha}
                if path == "git/commits":
                    sha = hashlib.sha1(repr(payload).encode(), usedforsecurity=False).hexdigest()
                    self.commits[sha] = {
                        "sha": sha,
                        "tree": {"sha": payload["tree"]},
                        "parents": [{"sha": p} for p in payload["parents"]],
                        "message": payload["message"],
                    }
                    self.fault("commit")
                    return {"sha": sha}
                if path == "git/refs":
                    branch = payload["ref"].removeprefix("refs/heads/")
                    if branch in self.refs:
                        raise github.GitHubHTTPError(422, "ref exists")
                    self.refs[branch] = payload["sha"]
                    self.fault("branch")
                    return {"object": {"sha": payload["sha"]}}
                if path == "pulls":
                    if self.pulls:
                        raise github.GitHubHTTPError(422, "PR exists")
                    result = {
                        "number": 99,
                        "html_url": "https://github.com/org/repo/pull/99",
                        "body": payload["body"],
                        "draft": True,
                        "head": {
                            "ref": payload["head"],
                            "sha": self.refs[payload["head"]],
                            "repo": {"full_name": "org/repo"},
                        },
                        "base": {"ref": payload["base"]},
                    }
                    self.pulls.append(result)
                    self.fault("draft")
                    return result
            raise AssertionError((method, url, payload))


class PublicationRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = str(Path(self.directory.name) / "tasks.db")
        self.store = TaskStore(self.path)

    def publish(self, remote, store=None):
        return PublicationGateFixer(ReadyVerifier()).create_fix_commits(
            remote,
            "org/repo",
            7,
            {"findings": [finding()]},
            expected_source_sha=SHA,
            publication_store=store or self.store,
            publication_scope="tenant/task-7",
        )

    def test_ack_loss_at_each_remote_stage_resumes_same_operation(self):
        for stage in ("tree", "commit", "branch", "draft"):
            with self.subTest(stage=stage):
                remote = FakeGitHub(stage)
                store = TaskStore(str(Path(self.directory.name) / (stage + ".db")))
                result = self.publish(remote, store)
                for _ in range(2):
                    if result.get("draft_pull_request"):
                        break
                    result = self.publish(remote, TaskStore(store.path))
                self.assertTrue(result.get("draft_pull_request"), result)
                self.assertEqual(1, len(remote.refs))
                self.assertEqual(1, len(remote.pulls))

    def test_completed_retry_reconciles_without_any_post(self):
        remote = FakeGitHub()
        first = self.publish(remote)
        before = sum(method == "POST" for method, _, _ in remote.calls)
        again = self.publish(remote, TaskStore(self.path))
        self.assertEqual(first["branch"], again["branch"])
        self.assertEqual(before, sum(method == "POST" for method, _, _ in remote.calls))

    def test_reconciliation_does_not_depend_on_large_textual_diffs(self):
        class LargeCompare(FakeGitHub):
            def _json(self, method, url, payload=None, **kwargs):
                if "/compare/" in url:
                    raise github.ResponseTooLarge("textual diff exceeds metadata budget")
                return super()._json(method, url, payload, **kwargs)

        self.assertTrue(self.publish(LargeCompare()).get("draft_pull_request"))

    def test_unplanned_branch_tree_changes_are_rejected(self):
        remote = FakeGitHub()
        result = self.publish(remote)
        current = remote.commits[remote.refs[result["branch"]]]
        remote.trees["e" * 40] = remote.trees[current["tree"]["sha"]] + [
            {"path": "extra.py", "sha": "b" * 40, "mode": "100644", "type": "blob"},
        ]
        remote.commits["f" * 40] = {**current, "sha": "f" * 40, "tree": {"sha": "e" * 40}}
        remote.refs[result["branch"]] = "f" * 40
        failed = self.publish(remote)
        self.assertEqual("repair-publication-conflict", failed["failure_code"])

    def test_remote_branch_changes_are_not_accepted(self):
        remote = FakeGitHub()
        first = self.publish(remote)
        self.assertTrue(first["branch"])
        sha = remote.refs[first["branch"]]
        remote.commits[sha]["message"] = "foreign content"
        before = sum(method == "POST" for method, _, _ in remote.calls)
        result = self.publish(remote)
        self.assertFalse(result.get("branch"))
        self.assertEqual(before, sum(method == "POST" for method, _, _ in remote.calls))

    def test_parallel_retries_produce_one_branch_and_one_draft(self):
        from concurrent.futures import ThreadPoolExecutor

        remote = FakeGitHub()
        with ThreadPoolExecutor(max_workers=4) as executor:
            results = list(executor.map(lambda _: self.publish(remote), range(4)))
        self.assertEqual(1, len(remote.refs))
        self.assertEqual(1, len(remote.pulls))
        self.assertTrue(all(result.get("draft_pull_request") for result in results), results)

    def test_missing_store_is_closed_before_any_post(self):
        remote = FakeGitHub()
        result = PublicationGateFixer(ReadyVerifier()).create_fix_commits(
            remote,
            "org/repo",
            7,
            {"findings": [finding()]},
            expected_source_sha=SHA,
        )
        self.assertFalse(result.get("branch"))
        self.assertFalse(any(method == "POST" for method, _, _ in remote.calls))

    def test_db_completion_failure_recovers_remote_pr_without_new_writes(self):
        remote = FakeGitHub()
        with patch.object(
            self.store, "complete_repair_publication", side_effect=RuntimeError("DB offline")
        ):
            failed = self.publish(remote)
        self.assertEqual("repair-publication-pending", failed["failure_code"])
        self.assertEqual(1, len(remote.pulls))
        before = sum(method == "POST" for method, _, _ in remote.calls)
        recovered = self.publish(remote, TaskStore(self.path))
        self.assertTrue(recovered.get("draft_pull_request"))
        self.assertEqual(before, sum(method == "POST" for method, _, _ in remote.calls))

    def test_completed_deleted_branch_is_not_recreated(self):
        remote = FakeGitHub()
        self.assertTrue(self.publish(remote).get("draft_pull_request"))
        remote.refs.clear()
        before = sum(method == "POST" for method, _, _ in remote.calls)
        result = self.publish(remote)
        self.assertEqual("repair-publication-conflict", result["failure_code"])
        self.assertEqual(before, sum(method == "POST" for method, _, _ in remote.calls))

    def test_write_transport_does_not_blindly_retry_unknown_outcome(self):
        calls = []

        def fail(request, **kwargs):
            calls.append(request.method)
            raise urllib.error.URLError("response lost")

        with patch("urllib.request.urlopen", side_effect=fail):
            with self.assertRaises(RuntimeError):
                github.GitHubClient("", max_attempts=4).create_draft_pull_request(
                    "org/repo",
                    "title",
                    "branch",
                    "main",
                    "body",
                )
        self.assertEqual(["POST"], calls)
