import socket
import unittest
from dataclasses import FrozenInstanceError
from unittest import mock

from lima.repository_source import (
    RepositorySource,
    normalize_github_repository,
    normalize_local_repository_key,
    parse_repository_source,
)


class GitHubRepositorySourceTests(unittest.TestCase):
    def test_normalizes_https_urls_and_git_suffix_deterministically(self):
        expected = "owner/project"

        for value in (
            "https://github.com/owner/project",
            "https://github.com/owner/project.git",
            "https://github.com/Owner/Project/",
            "OWNER/PROJECT.git",
        ):
            with self.subTest(value=value):
                self.assertEqual(expected, normalize_github_repository(value))

    def test_builds_immutable_github_source(self):
        source = RepositorySource.github(
            "https://github.com/Owner/Project.git", requested_ref="feature/audit"
        )

        self.assertEqual("github", source.type)
        self.assertEqual("github", source.provider)
        self.assertEqual("owner/project", source.canonical_name)
        self.assertEqual("feature/audit", source.requested_ref)
        self.assertEqual("", source.repository_key)
        with self.assertRaises(FrozenInstanceError):
            source.canonical_name = "other/project"

    def test_parses_task_input_and_serializes_canonical_contract(self):
        source = parse_repository_source(
            {
                "type": "github",
                "url": "https://github.com/Owner/Project.git",
                "ref": "main",
            }
        )

        self.assertEqual(
            {
                "type": "github",
                "provider": "github",
                "canonical_name": "owner/project",
                "requested_ref": "main",
                "repository_key": "",
            },
            source.to_dict(),
        )
        self.assertEqual(source, RepositorySource.from_dict(source.to_dict()))

    def test_rejects_unsupported_transports_hosts_and_path_shapes(self):
        invalid_values = (
            "file:///tmp/repository",
            "ssh://git@github.com/owner/project",
            "git://github.com/owner/project",
            "http://github.com/owner/project",
            "https://evil.example/repository",
            "http://127.0.0.1/owner/project",
            "https://github.com.evil.example/owner/project",
            "https://github.com:443/owner/project",
            "https://user@github.com/owner/project",
            "https://github.com/owner",
            "https://github.com/owner/project/issues",
            "https://github.com/owner/project?tab=readme",
            "https://github.com/owner/project#readme",
            "https://git\nhub.com/owner/project",
            "https://github.com/owner/pro\tject",
            "https://github.com//owner/project",
            "https://github.com/owner/%2e%2e",
            "git@github.com:owner/project.git",
            "../repository",
            "/repository",
            "owner/project/",
            "owner//project",
            "owner/project/extra",
            "",
        )

        for value in invalid_values:
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    normalize_github_repository(value)

    def test_rejects_conflicting_or_cross_source_fields(self):
        invalid_sources = (
            {
                "type": "github",
                "url": "https://github.com/owner/project",
                "provider": "local",
            },
            {
                "type": "github",
                "url": "https://github.com/owner/project",
                "repository_key": "owner/project",
            },
            {
                "type": "github",
                "url": "https://github.com/owner/project",
                "canonical_name": "owner/other",
            },
            {
                "type": "github",
                "url": "https://github.com/owner/project",
                "token": "secret",
            },
            {"type": "gitlab", "url": "https://gitlab.com/owner/project"},
        )

        for value in invalid_sources:
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    RepositorySource.from_dict(value)

    def test_normalization_performs_no_network_access(self):
        with mock.patch.object(
            socket, "create_connection", side_effect=AssertionError("network access")
        ):
            source = RepositorySource.github("https://github.com/owner/project")

        self.assertEqual("owner/project", source.canonical_name)

    def test_accepts_branch_tag_and_commit_ref_shapes(self):
        for requested_ref in (
            "main",
            "feature/audit",
            "refs/tags/v1.2.3",
            "0123456789abcdef0123456789abcdef01234567",
        ):
            with self.subTest(requested_ref=requested_ref):
                source = RepositorySource.github("owner/project", requested_ref)
                self.assertEqual(requested_ref, source.requested_ref)

    def test_rejects_invalid_or_ambiguous_git_ref_shapes(self):
        for requested_ref in (
            "feature branch",
            "../main",
            "/main",
            "main/",
            "feature//audit",
            ".hidden/main",
            "refs/heads/main.lock",
            "main@{1}",
            "main~1",
            "main^",
            "main:\\other",
            "main\nother",
            "@",
        ):
            with self.subTest(requested_ref=requested_ref):
                with self.assertRaises(ValueError):
                    RepositorySource.github("owner/project", requested_ref)


class LocalImportRepositorySourceTests(unittest.TestCase):
    def test_normalizes_local_import_without_resolving_a_host_path(self):
        source = RepositorySource.local_import("  team/project-1  ")

        self.assertEqual("local-import", source.type)
        self.assertEqual("local", source.provider)
        self.assertEqual("", source.canonical_name)
        self.assertEqual("", source.requested_ref)
        self.assertEqual("team/project-1", source.repository_key)
        self.assertEqual("team/project-1", normalize_local_repository_key("team/project-1"))

    def test_local_import_serialization_remains_distinct_from_github(self):
        source = RepositorySource.from_dict(
            {"type": "local-import", "repository_key": "team/project"}
        )

        self.assertEqual(
            {
                "type": "local-import",
                "provider": "local",
                "canonical_name": "",
                "requested_ref": "",
                "repository_key": "team/project",
            },
            source.to_dict(),
        )
        self.assertNotEqual(
            source,
            RepositorySource.github("https://github.com/team/project"),
        )
        self.assertIs(source, parse_repository_source(source))

    def test_rejects_path_like_and_remote_local_import_keys(self):
        for value in (
            "../repository",
            "/repository",
            "C:/repository",
            "team\\repository",
            "file:///repository",
            "ssh://github.com/owner/project",
            "https://github.com/owner/project",
            ".hidden/repository",
            "",
        ):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    RepositorySource.local_import(value)

    def test_rejects_github_fields_on_local_import(self):
        for value in (
            {
                "type": "local-import",
                "repository_key": "team/project",
                "url": "https://github.com/team/project",
            },
            {"type": "local-import", "repository_key": "team/project", "ref": "main"},
            {"type": "local-import", "repository_key": "team/project", "provider": "github"},
        ):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    RepositorySource.from_dict(value)


if __name__ == "__main__":
    unittest.main()
