"""Contract tests for the SHA-pinned PR source provider (Task 11).

Every test is offline: GitHub traffic goes through fake clients or a patched
``urllib.request.urlopen``, and local workspaces through fake sources. The
tests lock the evidence boundary: 40-hex SHA-only refs, POSIX-relative paths,
whole-file admission under byte/file budgets, all-or-nothing degradation to
diff-only, fixed-vocabulary reasons, and diff parsing that keeps only
new-side added line numbers.
"""

import base64
import hashlib
import json
import unittest
from unittest import mock

from lima.github import GitHubClient, ResponseTooLarge
from lima.github_source import (
    MODE_DIFF_ONLY,
    MODE_GITHUB,
    MODE_LOCAL,
    REASON_DIFF_ONLY,
    REASON_GITHUB_UNAVAILABLE,
    REASON_LOCAL_MISS,
    GitHubSnapshot,
    GitHubSourceProvider,
    SnapshotFile,
    SourceFetchBudget,
    snapshot_from_diff,
)

REPO = "owner/repo"
SHA = "a" * 40
_CREDENTIAL = "unit-test-credential"


def sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def github_b64(text: str) -> str:
    """Encode like the GitHub Contents API: base64 wrapped at 60 columns."""
    encoded = base64.b64encode(text.encode("utf-8")).decode("ascii")
    return "\n".join(
        encoded[start : start + 60] for start in range(0, len(encoded), 60)
    )


def file_payload(text: str) -> dict:
    content = text.encode("utf-8")
    return {"type": "file", "size": len(content), "content": github_b64(text)}


MULTI_FILE_DIFF = """\
diff --git a/src/a.cpp b/src/a.cpp
index 1111111..2222222 100644
--- a/src/a.cpp
+++ b/src/a.cpp
@@ -1,4 +1,5 @@ void f() {
 keep one
-remove me
+added two
 keep three
+added four
 keep five
diff --git a/src/new.cpp b/src/new.cpp
new file mode 100644
index 0000000..3333333
--- /dev/null
+++ b/src/new.cpp
@@ -0,0 +1,3 @@
+first
+second
+third
diff --git a/src/gone.cpp b/src/gone.cpp
deleted file mode 100644
index 4444444..0000000
--- a/src/gone.cpp
+++ /dev/null
@@ -1,2 +0,0 @@
-old one
-old two
"""

MULTI_HUNK_DIFF = """\
diff --git a/src/m.cpp b/src/m.cpp
index aaaaaaa..bbbbbbb 100644
--- a/src/m.cpp
+++ b/src/m.cpp
@@ -1,2 +1,4 @@
 alpha
+beta one
 gamma
+beta two
@@ -10,2 +12,2 @@
 delta
+epsilon
"""

MIXED_DIFF = """\
diff --git a/src/n.cpp b/src/n.cpp
index 1111111..2222222 100644
--- a/src/n.cpp
+++ b/src/n.cpp
@@ -1,1 +1,2 @@
+y
\\ No newline at end of file
 x
diff --git a/data/blob.bin b/data/blob.bin
index 3333333..4444444 100644
Binary files a/data/blob.bin and b/data/blob.bin differ
diff --git a/../evil.cpp b/../evil.cpp
index 5555555..6666666 100644
--- a/../evil.cpp
+++ b/../evil.cpp
@@ -1,1 +1,1 @@
-bad
+still bad
"""

BROKEN_HUNK_DIFF = """\
diff --git a/src/y.cpp b/src/y.cpp
index 3333333..4444444 100644
--- a/src/y.cpp
+++ b/src/y.cpp
@@ -1,1 +1,2 @@
+fine
 old
diff --git a/src/x.cpp b/src/x.cpp
index 1111111..2222222 100644
--- a/src/x.cpp
+++ b/src/x.cpp
@@ -1,3 +1,3 @@
+only one
diff --git a/ignored.cpp b/ignored.cpp
"""


class FakeGitHubClient:
    """Offline stand-in mirroring ``GitHubClient.get_file_at_commit``."""

    def __init__(self, payloads=None, fail_on=None):
        self.payloads = payloads or {}
        self.fail_on = fail_on or {}
        self.calls = []

    def get_file_at_commit(self, repository, path, commit_sha, max_response_bytes=None):
        self.calls.append((repository, path, commit_sha, max_response_bytes))
        if path in self.fail_on:
            raise self.fail_on[path]
        payload = self.payloads.get(path)
        if payload is None:
            raise RuntimeError("GitHub API GET returned HTTP 404: not found")
        return payload


class FakeLocalSource:
    """Offline ``LocalCommitSource`` matching only exact (repo, sha) pairs."""

    def __init__(self, trees=None):
        self.trees = trees or {}
        self.calls = []

    def snapshot(self, repository, commit_sha):
        self.calls.append((repository, commit_sha))
        return self.trees.get((repository, commit_sha))


class SourceFetchBudgetTests(unittest.TestCase):
    def test_defaults_are_positive(self):
        budget = SourceFetchBudget()
        self.assertEqual(budget.max_files, 12)
        self.assertEqual(budget.max_total_bytes, 1_048_576)

    def test_rejects_non_positive_bool_and_non_int(self):
        for bad in (0, -1, True, False, 1.5, "12", None):
            with self.assertRaises(ValueError):
                SourceFetchBudget(max_files=bad)
            with self.assertRaises(ValueError):
                SourceFetchBudget(max_total_bytes=bad)


class SnapshotFileTests(unittest.TestCase):
    def test_from_content_derives_hash_and_size(self):
        content = "int main(){}\n"
        entry = SnapshotFile.from_content("src/a.cpp", content)
        self.assertEqual(entry.path, "src/a.cpp")
        self.assertEqual(entry.sha256, sha256_hex(content))
        self.assertEqual(entry.size_bytes, len(content.encode("utf-8")))

    def test_rejects_mismatched_hash_or_size(self):
        with self.assertRaises(ValueError):
            SnapshotFile("src/a.cpp", "0" * 64, "text", 4)
        with self.assertRaises(ValueError):
            SnapshotFile("src/a.cpp", sha256_hex("text"), "text", 5)


class GitHubSnapshotValidationTests(unittest.TestCase):
    def _local_snapshot(self, **overrides):
        fields = {
            "repository": REPO,
            "commit": SHA,
            "mode": MODE_LOCAL,
            "files": (SnapshotFile.from_content("a.cpp", "x"),),
        }
        fields.update(overrides)
        return GitHubSnapshot(**fields)

    def test_rejects_unknown_mode(self):
        with self.assertRaises(ValueError):
            self._local_snapshot(mode="svn")

    def test_diff_only_must_not_carry_files(self):
        with self.assertRaises(ValueError):
            self._local_snapshot(
                mode=MODE_DIFF_ONLY,
                files=(SnapshotFile.from_content("a.cpp", "x"),),
                unavailable_reason=REASON_DIFF_ONLY,
            )

    def test_content_modes_must_not_carry_changed_lines(self):
        with self.assertRaises(ValueError):
            self._local_snapshot(changed_lines=(("a.cpp", (1,)),))

    def test_reason_vocabulary_is_fixed_and_canonical(self):
        allowed = (
            REASON_DIFF_ONLY,
            REASON_GITHUB_UNAVAILABLE,
            REASON_LOCAL_MISS + "+" + REASON_GITHUB_UNAVAILABLE,
        )
        for reason in allowed:
            GitHubSnapshot(REPO, SHA, MODE_DIFF_ONLY, unavailable_reason=reason)
        for bad in (
            "boom at https://x",
            REASON_GITHUB_UNAVAILABLE + "+" + REASON_LOCAL_MISS,
            REASON_LOCAL_MISS + "+" + REASON_LOCAL_MISS,
        ):
            with self.assertRaises(ValueError):
                GitHubSnapshot(REPO, SHA, MODE_DIFF_ONLY, unavailable_reason=bad)

    def test_content_modes_require_empty_reason(self):
        with self.assertRaises(ValueError):
            self._local_snapshot(unavailable_reason=REASON_GITHUB_UNAVAILABLE)

    def test_diff_only_requires_reason(self):
        with self.assertRaises(ValueError):
            self._local_snapshot(mode=MODE_DIFF_ONLY, files=())


class FetchValidationTests(unittest.TestCase):
    def setUp(self):
        self.client = FakeGitHubClient()
        self.provider = GitHubSourceProvider(self.client)
        self.budget = SourceFetchBudget()

    def test_rejects_branch_names(self):
        for branch in ("main", "release/v2", "HEAD"):
            with self.assertRaises(ValueError):
                self.provider.fetch(REPO, branch, ["a.cpp"], self.budget)

    def test_rejects_short_and_long_sha(self):
        for bad in ("abc1234", "a" * 39, "a" * 41):
            with self.assertRaises(ValueError):
                self.provider.fetch(REPO, bad, ["a.cpp"], self.budget)

    def test_rejects_uppercase_sha(self):
        with self.assertRaises(ValueError):
            self.provider.fetch(REPO, "A" * 40, ["a.cpp"], self.budget)

    def test_rejects_non_string_sha(self):
        for bad in (None, 123):
            with self.assertRaises(ValueError):
                self.provider.fetch(REPO, bad, ["a.cpp"], self.budget)

    def test_rejects_bad_repositories(self):
        for repo in ("", "owner", "owner/sub/repo", "https://github.com/o/r",
                     "/repo", "owner/", "own er/repo"):
            with self.assertRaises(ValueError):
                self.provider.fetch(repo, SHA, ["a.cpp"], self.budget)

    def test_rejects_escaping_paths(self):
        for path in ("../x.cpp", "/etc/x.cpp", "a\\b.cpp", "C:x.cpp", "",
                     "..", "src/../../evil.cpp"):
            with self.assertRaises(ValueError):
                self.provider.fetch(REPO, SHA, [path], self.budget)

    def test_rejects_non_string_paths(self):
        for bad in ([None], [5]):
            with self.assertRaises(ValueError):
                self.provider.fetch(REPO, SHA, bad, self.budget)

    def test_validation_precedes_any_client_call(self):
        failing = FakeGitHubClient(
            fail_on={"a.cpp": RuntimeError("GitHub API returned HTTP 404")}
        )
        provider = GitHubSourceProvider(failing)
        with self.assertRaises(ValueError):
            provider.fetch(REPO, "not-a-sha", ["a.cpp"], self.budget)
        self.assertEqual(failing.calls, [])

    def test_overlong_paths_are_rejected_at_the_boundary(self):
        # Contents-API envelopes echo the full path; reject >512 characters
        # before any call so the bounded response read can never overflow.
        overlong = "src/" + "x" * 512 + ".cpp"
        with self.assertRaises(ValueError):
            self.provider.fetch(REPO, SHA, [overlong], self.budget)
        self.assertEqual(self.client.calls, [])
        # Exactly at the cap is still legal input: validation passes and the
        # fetch only fails (degrades) at the fake GitHub 404.
        result = self.provider.fetch(REPO, SHA, ["a" * 512], self.budget)
        self.assertEqual(result.mode, MODE_DIFF_ONLY)


class FetchOrderingTests(unittest.TestCase):
    def test_paths_are_deduplicated_and_sorted(self):
        payloads = {
            "src/b.cpp": file_payload("int b;\n"),
            "src/a.cpp": file_payload("int a;\n"),
        }
        client = FakeGitHubClient(payloads=payloads)
        GitHubSourceProvider(client).fetch(
            REPO, SHA, ["src/b.cpp", "src/a.cpp", "src/b.cpp"], SourceFetchBudget()
        )
        self.assertEqual(
            [call[1] for call in client.calls], ["src/a.cpp", "src/b.cpp"]
        )


class LocalFirstTests(unittest.TestCase):
    def test_local_hit_avoids_github_entirely(self):
        local = FakeLocalSource({(REPO, SHA): {"src/a.cpp": "int x;\n"}})
        client = FakeGitHubClient(payloads={"src/a.cpp": file_payload("other")})
        provider = GitHubSourceProvider(client, local_source=local)
        snapshot = provider.fetch(REPO, SHA, ["src/a.cpp"], SourceFetchBudget())
        self.assertEqual(snapshot.mode, MODE_LOCAL)
        self.assertEqual(snapshot.files[0].path, "src/a.cpp")
        self.assertEqual(snapshot.files[0].sha256, sha256_hex("int x;\n"))
        self.assertEqual(snapshot.files[0].size_bytes, len(b"int x;\n"))
        self.assertEqual(snapshot.unavailable_reason, "")
        self.assertEqual(local.calls, [(REPO, SHA)])
        self.assertEqual(client.calls, [])

    def test_local_miss_falls_through_to_github(self):
        local = FakeLocalSource()
        client = FakeGitHubClient(payloads={"src/a.cpp": file_payload("int a;\n")})
        provider = GitHubSourceProvider(client, local_source=local)
        snapshot = provider.fetch(REPO, SHA, ["src/a.cpp"], SourceFetchBudget())
        self.assertEqual(snapshot.mode, MODE_GITHUB)
        self.assertEqual(len(snapshot.files), 1)
        self.assertEqual(local.calls, [(REPO, SHA)])
        self.assertEqual(len(client.calls), 1)

    def test_local_hit_with_absent_path_counts_skipped(self):
        local = FakeLocalSource({(REPO, SHA): {"src/a.cpp": "int x;\n"}})
        provider = GitHubSourceProvider(FakeGitHubClient(), local_source=local)
        snapshot = provider.fetch(
            REPO, SHA, ["src/a.cpp", "src/missing.cpp"], SourceFetchBudget()
        )
        self.assertEqual(snapshot.mode, MODE_LOCAL)
        self.assertEqual(len(snapshot.files), 1)
        self.assertEqual(snapshot.skipped_files, 1)

    def test_local_byte_budget_skips_whole_files(self):
        tree = {"src/a.cpp": "a" * 10, "src/b.cpp": "b" * 10}
        local = FakeLocalSource({(REPO, SHA): tree})
        provider = GitHubSourceProvider(FakeGitHubClient(), local_source=local)
        snapshot = provider.fetch(
            REPO, SHA, ["src/a.cpp", "src/b.cpp"],
            SourceFetchBudget(max_total_bytes=15),
        )
        self.assertEqual(len(snapshot.files), 1)
        self.assertEqual(snapshot.files[0].content, "a" * 10)
        self.assertEqual(snapshot.skipped_files, 1)
        self.assertEqual(snapshot.skipped_bytes, 10)

    def test_local_file_cap_counts_skipped_bytes(self):
        tree = {"src/a.cpp": "a" * 10, "src/b.cpp": "b" * 10}
        local = FakeLocalSource({(REPO, SHA): tree})
        provider = GitHubSourceProvider(FakeGitHubClient(), local_source=local)
        snapshot = provider.fetch(
            REPO, SHA, ["src/a.cpp", "src/b.cpp"], SourceFetchBudget(max_files=1)
        )
        self.assertEqual(len(snapshot.files), 1)
        self.assertEqual(snapshot.skipped_files, 1)
        self.assertEqual(snapshot.skipped_bytes, 10)


class GitHubPinnedFetchTests(unittest.TestCase):
    def test_provider_pins_full_sha_and_read_bound(self):
        budget = SourceFetchBudget()
        client = FakeGitHubClient(payloads={"src/a.cpp": file_payload("int a;\n")})
        GitHubSourceProvider(client).fetch(REPO, SHA, ["src/a.cpp"], budget)
        repository, path, commit_sha, bound = client.calls[0]
        self.assertEqual((repository, path, commit_sha), (REPO, "src/a.cpp", SHA))
        # The read bound must be generous (base64 + JSON envelope) yet finite.
        self.assertEqual(bound, 2 * budget.max_total_bytes + 8192)

    def test_returns_exact_content_hash_and_size(self):
        content = "int main() { return 0; }\n"
        client = FakeGitHubClient(payloads={"src/a.cpp": file_payload(content)})
        snapshot = GitHubSourceProvider(client).fetch(
            REPO, SHA, ["src/a.cpp"], SourceFetchBudget()
        )
        self.assertEqual(snapshot.mode, MODE_GITHUB)
        self.assertEqual(snapshot.repository, REPO)
        self.assertEqual(snapshot.commit, SHA)
        self.assertEqual(snapshot.unavailable_reason, "")
        self.assertEqual(snapshot.skipped_files, 0)
        entry = snapshot.files[0]
        self.assertEqual(entry.path, "src/a.cpp")
        self.assertEqual(entry.content, content)
        self.assertEqual(entry.sha256, sha256_hex(content))
        self.assertEqual(entry.size_bytes, len(content.encode("utf-8")))

    def test_non_file_types_are_skipped_never_followed(self):
        payloads = {
            "src/link.cpp": {"type": "symlink", "size": 12,
                             "content": github_b64("../secrets.cpp")},
            "src/mod.cpp": {"type": "submodule"},
            "src/dir": {"type": "dir"},
        }
        client = FakeGitHubClient(payloads=payloads)
        snapshot = GitHubSourceProvider(client).fetch(
            REPO, SHA, sorted(payloads), SourceFetchBudget()
        )
        self.assertEqual(snapshot.mode, MODE_GITHUB)
        self.assertEqual(snapshot.files, ())
        self.assertEqual(snapshot.skipped_files, 3)

    def test_single_file_over_budget_is_skipped_whole(self):
        client = FakeGitHubClient(payloads={"src/big.cpp": file_payload("x" * 100)})
        snapshot = GitHubSourceProvider(client).fetch(
            REPO, SHA, ["src/big.cpp"], SourceFetchBudget(max_total_bytes=50)
        )
        self.assertEqual(snapshot.files, ())
        self.assertEqual(snapshot.skipped_files, 1)
        self.assertEqual(snapshot.skipped_bytes, 100)
        self.assertEqual(snapshot.mode, MODE_GITHUB)

    def test_lying_declared_size_still_skips_by_measured_bytes(self):
        big = "z" * 300
        payload = {"type": "file", "size": 5, "content": github_b64(big)}
        client = FakeGitHubClient(payloads={"src/big.cpp": payload})
        snapshot = GitHubSourceProvider(client).fetch(
            REPO, SHA, ["src/big.cpp"], SourceFetchBudget(max_total_bytes=100)
        )
        self.assertEqual(snapshot.files, ())
        self.assertEqual(snapshot.skipped_files, 1)
        self.assertEqual(snapshot.skipped_bytes, 300)

    def test_byte_budget_exhaustion_skips_rest(self):
        payloads = {
            "src/a.cpp": file_payload("a" * 60),
            "src/b.cpp": file_payload("b" * 60),
        }
        client = FakeGitHubClient(payloads=payloads)
        snapshot = GitHubSourceProvider(client).fetch(
            REPO, SHA, ["src/a.cpp", "src/b.cpp"],
            SourceFetchBudget(max_total_bytes=100),
        )
        self.assertEqual(len(snapshot.files), 1)
        self.assertEqual(snapshot.files[0].path, "src/a.cpp")
        self.assertEqual(snapshot.skipped_files, 1)
        self.assertEqual(snapshot.skipped_bytes, 60)

    def test_file_cap_skips_without_extra_client_calls(self):
        payloads = {
            "src/a.cpp": file_payload("a" * 10),
            "src/b.cpp": file_payload("b" * 10),
        }
        client = FakeGitHubClient(payloads=payloads)
        snapshot = GitHubSourceProvider(client).fetch(
            REPO, SHA, ["src/a.cpp", "src/b.cpp"], SourceFetchBudget(max_files=1)
        )
        self.assertEqual(len(snapshot.files), 1)
        self.assertEqual(snapshot.skipped_files, 1)
        self.assertEqual(len(client.calls), 1)

    def test_response_too_large_skips_file_without_degrading(self):
        client = FakeGitHubClient(
            payloads={"src/a.cpp": file_payload("int a;\n")},
            fail_on={"src/big.cpp": ResponseTooLarge("response exceeded limit")},
        )
        snapshot = GitHubSourceProvider(client).fetch(
            REPO, SHA, ["src/a.cpp", "src/big.cpp"], SourceFetchBudget()
        )
        self.assertEqual(snapshot.mode, MODE_GITHUB)
        self.assertEqual(len(snapshot.files), 1)
        self.assertEqual(snapshot.skipped_files, 1)

    def test_fetch_is_deterministic(self):
        payloads = {
            "src/a.cpp": file_payload("int a;\n"),
            "src/b.cpp": file_payload("int b;\n"),
        }
        provider = GitHubSourceProvider(FakeGitHubClient(payloads=payloads))
        paths = ["src/a.cpp", "src/b.cpp"]
        self.assertEqual(
            provider.fetch(REPO, SHA, paths, SourceFetchBudget()),
            provider.fetch(REPO, SHA, paths, SourceFetchBudget()),
        )


class DegradationTests(unittest.TestCase):
    def test_404_degrades_to_diff_only(self):
        client = FakeGitHubClient(
            fail_on={"src/a.cpp": RuntimeError(
                "GitHub API GET returned HTTP 404: Not Found")}
        )
        snapshot = GitHubSourceProvider(client).fetch(
            REPO, SHA, ["src/a.cpp"], SourceFetchBudget()
        )
        self.assertEqual(snapshot.mode, MODE_DIFF_ONLY)
        self.assertEqual(snapshot.files, ())
        self.assertEqual(snapshot.changed_lines, ())
        self.assertEqual(snapshot.unavailable_reason, REASON_GITHUB_UNAVAILABLE)

    def test_rate_limit_degrades_to_diff_only(self):
        client = FakeGitHubClient(
            fail_on={"src/a.cpp": RuntimeError(
                "GitHub API GET returned HTTP 403: rate limit exceeded")}
        )
        snapshot = GitHubSourceProvider(client).fetch(
            REPO, SHA, ["src/a.cpp"], SourceFetchBudget()
        )
        self.assertEqual(snapshot.mode, MODE_DIFF_ONLY)
        self.assertEqual(snapshot.unavailable_reason, REASON_GITHUB_UNAVAILABLE)

    def test_local_miss_and_github_failure_combine_reason(self):
        client = FakeGitHubClient(
            fail_on={"src/a.cpp": RuntimeError("GitHub API returned HTTP 404")}
        )
        provider = GitHubSourceProvider(client, local_source=FakeLocalSource())
        snapshot = provider.fetch(REPO, SHA, ["src/a.cpp"], SourceFetchBudget())
        self.assertEqual(snapshot.mode, MODE_DIFF_ONLY)
        self.assertEqual(
            snapshot.unavailable_reason,
            REASON_LOCAL_MISS + "+" + REASON_GITHUB_UNAVAILABLE,
        )

    def test_mid_fetch_failure_discards_partial_files(self):
        client = FakeGitHubClient(
            payloads={"src/a.cpp": file_payload("int a;\n")},
            fail_on={"src/b.cpp": RuntimeError(
                "GitHub API GET returned HTTP 404: Not Found")},
        )
        snapshot = GitHubSourceProvider(client).fetch(
            REPO, SHA, ["src/a.cpp", "src/b.cpp"], SourceFetchBudget()
        )
        self.assertEqual(snapshot.mode, MODE_DIFF_ONLY)
        self.assertEqual(snapshot.files, ())
        self.assertEqual(snapshot.skipped_files, 0)

    def test_reason_never_contains_error_details(self):
        error = RuntimeError(
            "GitHub API GET https://api.github.com/repos/owner/repo "
            "returned HTTP 403: SUPER-SECRET-RESPONSE-BODY"
        )
        client = FakeGitHubClient(fail_on={"src/a.cpp": error})
        snapshot = GitHubSourceProvider(client).fetch(
            REPO, SHA, ["src/a.cpp"], SourceFetchBudget()
        )
        self.assertEqual(snapshot.unavailable_reason, "github-unavailable")
        self.assertNotIn("SUPER-SECRET-RESPONSE-BODY", repr(snapshot))
        self.assertNotIn("api.github.com", repr(snapshot))

    def test_value_errors_are_not_swallowed_by_degradation(self):
        client = FakeGitHubClient(
            fail_on={"a.cpp": RuntimeError("GitHub API returned HTTP 404")}
        )
        provider = GitHubSourceProvider(client)
        with self.assertRaises(ValueError):
            provider.fetch(REPO, "not-a-sha", ["a.cpp"], SourceFetchBudget())


class DiffOnlySnapshotTests(unittest.TestCase):
    def setUp(self):
        self.budget = SourceFetchBudget()

    def test_multi_file_multi_hunk_added_lines(self):
        snapshot = snapshot_from_diff(REPO, SHA, MULTI_FILE_DIFF, self.budget)
        self.assertEqual(snapshot.mode, MODE_DIFF_ONLY)
        self.assertEqual(snapshot.repository, REPO)
        self.assertEqual(snapshot.commit, SHA)
        self.assertEqual(snapshot.files, ())
        self.assertEqual(snapshot.unavailable_reason, REASON_DIFF_ONLY)
        self.assertEqual(
            snapshot.changed_lines,
            (("src/a.cpp", (2, 4)), ("src/new.cpp", (1, 2, 3))),
        )
        self.assertNotIn("src/gone.cpp", dict(snapshot.changed_lines))

    def test_multi_hunk_same_file_lines_are_merged_and_sorted(self):
        snapshot = snapshot_from_diff(REPO, SHA, MULTI_HUNK_DIFF, self.budget)
        self.assertEqual(snapshot.changed_lines, (("src/m.cpp", (2, 4, 13)),))

    def test_binary_escape_and_no_newline_are_handled_without_guessing(self):
        snapshot = snapshot_from_diff(REPO, SHA, MIXED_DIFF, self.budget)
        self.assertEqual(snapshot.changed_lines, (("src/n.cpp", (1,)),))
        self.assertEqual(snapshot.skipped_files, 2)

    def test_broken_hunk_drops_only_that_file(self):
        snapshot = snapshot_from_diff(REPO, SHA, BROKEN_HUNK_DIFF, self.budget)
        self.assertEqual(snapshot.changed_lines, (("src/y.cpp", (1,)),))
        self.assertEqual(snapshot.skipped_files, 1)

    def test_garbled_hunk_header_is_skipped_not_guessed(self):
        garbled = (
            "diff --git a/src/z.cpp b/src/z.cpp\n"
            "--- a/src/z.cpp\n"
            "+++ b/src/z.cpp\n"
            "@@ garbage @@\n"
            "+nope\n"
        )
        snapshot = snapshot_from_diff(REPO, SHA, garbled, self.budget)
        self.assertEqual(snapshot.changed_lines, ())
        self.assertEqual(snapshot.skipped_files, 1)

    def test_context_and_removed_lines_are_never_retained(self):
        snapshot = snapshot_from_diff(REPO, SHA, MULTI_FILE_DIFF, self.budget)
        self.assertEqual(snapshot.files, ())
        self.assertNotIn("remove me", repr(snapshot))
        self.assertNotIn("keep one", repr(snapshot))

    def test_empty_diff_yields_empty_snapshot(self):
        snapshot = snapshot_from_diff(REPO, SHA, "", self.budget)
        self.assertEqual(snapshot.mode, MODE_DIFF_ONLY)
        self.assertEqual(snapshot.changed_lines, ())
        self.assertEqual(snapshot.skipped_files, 0)

    def test_diff_parsing_is_deterministic(self):
        self.assertEqual(
            snapshot_from_diff(REPO, SHA, MULTI_FILE_DIFF, self.budget),
            snapshot_from_diff(REPO, SHA, MULTI_FILE_DIFF, self.budget),
        )

    def test_inputs_are_validated(self):
        with self.assertRaises(ValueError):
            snapshot_from_diff(REPO, "main", MULTI_FILE_DIFF, self.budget)
        with self.assertRaises(ValueError):
            snapshot_from_diff("bad repo", SHA, MULTI_FILE_DIFF, self.budget)
        with self.assertRaises(ValueError):
            snapshot_from_diff(REPO, SHA, 123, self.budget)
        with self.assertRaises(ValueError):
            snapshot_from_diff(REPO, SHA, MULTI_FILE_DIFF, "budget")


class _CannedResponse:
    def __init__(self, body: bytes) -> None:
        self._body = body

    def read(self, size=-1):
        if size is None or size < 0:
            return self._body
        return self._body[:size]

    def __enter__(self):
        return self

    def __exit__(self, *exc_info):
        return False


class _RecordingURLOpen:
    """Callable replacing ``urllib.request.urlopen`` with a canned body."""

    def __init__(self, body: bytes) -> None:
        self._body = body
        self.requests = []

    def __call__(self, request, timeout=None):
        self.requests.append(request)
        return _CannedResponse(self._body)


class GitHubClientBoundedRequestTests(unittest.TestCase):
    """Exercises the real ``lima.github`` additions with zero network."""

    def test_response_too_large_is_a_runtime_error(self):
        self.assertTrue(issubclass(ResponseTooLarge, RuntimeError))

    def test_get_file_at_commit_builds_pinned_url(self):
        body = json.dumps(file_payload("int x;\n")).encode("utf-8")
        capture = _RecordingURLOpen(body)
        with mock.patch("urllib.request.urlopen", capture):
            client = GitHubClient(_CREDENTIAL)
            result = client.get_file_at_commit(
                REPO, "src/a.cpp", SHA, max_response_bytes=100_000
            )
        self.assertEqual(result["size"], len(b"int x;\n"))
        request = capture.requests[0]
        self.assertEqual(
            request.full_url,
            f"https://api.github.com/repos/{REPO}/contents/src/a.cpp?ref={SHA}",
        )
        self.assertEqual(request.get_header("Authorization"), f"Bearer {_CREDENTIAL}")

    def test_get_file_at_commit_rejects_non_sha_refs(self):
        client = GitHubClient(_CREDENTIAL)
        for bad in ("main", "a" * 39, "a" * 41, "A" * 40, None, 12345):
            with self.assertRaises(ValueError):
                client.get_file_at_commit(REPO, "src/a.cpp", bad)

    def test_bounded_request_raises_before_decoding_oversized_body(self):
        body = json.dumps(file_payload("y" * 500)).encode("utf-8")
        capture = _RecordingURLOpen(body)
        with mock.patch("urllib.request.urlopen", capture):
            client = GitHubClient(_CREDENTIAL)
            with self.assertRaises(ResponseTooLarge):
                client.get_file_at_commit(
                    REPO, "src/a.cpp", SHA, max_response_bytes=64
                )
        self.assertEqual(len(capture.requests), 1)

    def test_bounded_request_parses_body_within_limit(self):
        body = json.dumps(file_payload("int x;\n")).encode("utf-8")
        capture = _RecordingURLOpen(body)
        with mock.patch("urllib.request.urlopen", capture):
            client = GitHubClient(_CREDENTIAL)
            result = client.get_file_at_commit(
                REPO, "src/a.cpp", SHA, max_response_bytes=len(body)
            )
        self.assertEqual(result["type"], "file")

    def test_unbounded_request_keeps_previous_behavior(self):
        body = json.dumps(file_payload("int x;\n")).encode("utf-8")
        capture = _RecordingURLOpen(body)
        with mock.patch("urllib.request.urlopen", capture):
            client = GitHubClient(_CREDENTIAL)
            result = client.get_file_at_commit(REPO, "src/a.cpp", SHA)
        self.assertEqual(result["type"], "file")

    def test_max_bytes_must_be_positive_when_provided(self):
        capture = _RecordingURLOpen(b"{}")
        with mock.patch("urllib.request.urlopen", capture):
            client = GitHubClient(_CREDENTIAL)
            for bad in (0, -1, True, 1.5):
                with self.assertRaises(ValueError):
                    client._request("GET", "https://api.github.com/x", max_bytes=bad)
        self.assertEqual(capture.requests, [])


if __name__ == "__main__":
    unittest.main()
