import unittest
from unittest.mock import Mock

from lima.github import GitHubClient

HEAD = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"
BASE = "f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1"


class PinnedCompareDiffTests(unittest.TestCase):
    def setUp(self):
        self.client = GitHubClient("token")
        self.client._request = Mock(return_value=b"diff --git a/a.py b/a.py\n")

    def test_fetches_raw_diff_from_commit_compare_endpoint(self):
        diff = self.client.fetch_diff_at_commits(
            "example-org/example_repo", BASE, HEAD, max_bytes=512
        )

        self.assertEqual("diff --git a/a.py b/a.py\n", diff)
        self.client._request.assert_called_once_with(
            "GET",
            f"https://api.github.com/repos/example-org/example_repo/compare/{BASE}...{HEAD}",
            accept="application/vnd.github.v3.diff",
            raw=True,
            max_bytes=512,
        )

    def test_rejects_non_pinned_refs_without_transport(self):
        with self.assertRaises(ValueError):
            self.client.fetch_diff_at_commits("org/repo", "main", HEAD, max_bytes=512)
        with self.assertRaises(ValueError):
            self.client.fetch_diff_at_commits("org/repo", BASE, HEAD.upper(), max_bytes=512)
        self.client._request.assert_not_called()

    def test_rejects_unsafe_repository_without_transport(self):
        for repository in ("org/repo/extra", "org/repo?x=1", "org@evil/repo", "org/"):
            with self.subTest(repository=repository):
                with self.assertRaises(ValueError):
                    self.client.fetch_diff_at_commits(repository, BASE, HEAD, max_bytes=512)
        self.client._request.assert_not_called()


if __name__ == "__main__":
    unittest.main()
