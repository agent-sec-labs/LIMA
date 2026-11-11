"""Publication gates for deterministic repair commits."""

from __future__ import annotations

import unittest
import tempfile
from pathlib import Path
from lima.store import TaskStore

from lima.fixer import SafeFixer

SHA = "a" * 40
NEW_SHA = "b" * 40


class RecordingClient:
    def __init__(self, heads: list[str] | None = None) -> None:
        self.heads = list(heads or [SHA])
        self.file_refs: list[str] = []
        self.archive_refs: list[str] = []
        self.commit_parents: list[str] = []
        self.commit_messages: list[str] = []
        self.draft_titles: list[str] = []
        self.draft_bodies: list[str] = []

    def get_pull_request(self, _repository, _pull_request):
        head = self.heads.pop(0) if self.heads else SHA
        return {
            "head": {"sha": head, "repo": {"full_name": "org/repo"}},
            "base": {"ref": "main"},
        }

    def get_file(self, _repository, _path, ref):
        self.file_refs.append(ref)
        return {"decoded_content": "print('debug')\n", "sha": "blob"}

    def download_archive(self, _repository, ref):
        self.archive_refs.append(ref)
        return b"archive"

    def create_atomic_commit(self, _repository, _branch, parent, _files, message):
        self.commit_parents.append(parent)
        self.commit_messages.append(message)
        return {"sha": "c" * 40}

    def create_draft_pull_request(self, _repository, title, _branch, _base, body):
        self.draft_titles.append(title)
        self.draft_bodies.append(body)
        return {"number": 1, "html_url": "https://example.test/pr/1"}

    def ensure_repair_commit(self, repository, branch, parent, files, message, **kwargs):
        return self.create_atomic_commit(repository, branch, parent, files, message)

    def ensure_repair_pull(self, repository, title, branch, base, body, sha, operation_id, **kwargs):
        return self.create_draft_pull_request(repository, title, branch, base, body)


class ReadyVerifier:
    test_command = "sandbox-tests"

    @staticmethod
    def _checks():
        return [
            {"name": "compile:app.py", "passed": True},
            {"name": "security-oracle:CWE-78:app.py:1", "passed": True},
            {"name": "differential-rescan:CWE-78:app.py", "passed": True},
            {"name": "repository-tests", "passed": True},
        ]

    def verify_contents(self, _files, _repairs):
        return {"passed": True, "checks": self._checks()[:2]}

    def verify_archive(self, _archive, _files, _repairs):
        return {
            "passed": True,
            "checks": self._checks(),
            "sandbox": {
                "configured": True,
                "executed": True,
                "stop_confirmed": True,
                "passed": True,
                "image_id": "sha256:" + "d" * 64,
            },
        }


class PublicationGateFixer(SafeFixer):
    """Avoid coupling publication tests to repair AST transformation details."""

    def apply(self, content, _findings, path):
        return {
            "content": content.replace("debug", "safe"),
            "rules": ["SEC-SUBPROCESS-SHELL"],
            "blocked": [],
            "repairs": [{
                "path": path,
                "line": 1,
                "cwe": "CWE-78",
                "original_ast": "original",
                "expected_ast": "expected",
                "strategy": "argv-no-shell",
            }],
            "patch_metrics": {"changed_lines": 1, "strategies": ["argv-no-shell"]},
        }


def finding(rule_id: str = "SEC-SUBPROCESS-SHELL") -> dict:
    return {
        "path": "app.py", "line": 1, "rule_id": rule_id,
        "verification_state": "dataflow-verified", "cwe": "CWE-78",
    }


class RepairPublicationGateTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.store = TaskStore(str(Path(directory.name) / "publication.db"))

    def test_missing_or_invalid_expected_sha_never_reads_or_writes(self):
        for expected in (None, "not-a-sha"):
            with self.subTest(expected=expected):
                client = RecordingClient()
                result = PublicationGateFixer(ReadyVerifier()).create_fix_commits(
                    client, "org/repo", 7, {"findings": [finding()]},
                    expected_source_sha=expected,
                )
                self.assertEqual(result["failure_code"], "repair-source-stale")
                self.assertEqual(client.file_refs, [])
                self.assertEqual(client.commit_parents, [])
                self.assertEqual(client.draft_bodies, [])

    def test_initial_stale_head_never_reads_or_writes(self):
        client = RecordingClient([NEW_SHA])
        result = PublicationGateFixer(ReadyVerifier()).create_fix_commits(
            client, "org/repo", 7, {"findings": [finding()]},
            expected_source_sha=SHA,
        )
        self.assertEqual(result["failure_code"], "repair-source-stale")
        self.assertEqual(client.file_refs, [])
        self.assertEqual(client.archive_refs, [])
        self.assertEqual(client.commit_parents, [])

    def test_midflight_stale_head_never_writes(self):
        client = RecordingClient([SHA, NEW_SHA])
        result = PublicationGateFixer(ReadyVerifier()).create_fix_commits(
            client, "org/repo", 7, {"findings": [finding()]},
            expected_source_sha=SHA,
        )
        self.assertEqual(result["failure_code"], "repair-source-stale")
        self.assertEqual(client.file_refs, [SHA])
        self.assertEqual(client.archive_refs, [SHA])
        self.assertEqual(client.commit_parents, [])
        self.assertEqual(client.draft_bodies, [])

    def test_legacy_repair_without_manifest_cannot_publish(self):
        class LegacyFixer(PublicationGateFixer):
            def apply(self, content, _findings, _path):
                return {
                    "content": content.replace("debug", "safe"), "rules": ["REL-DEBUG-PRINT"],
                    "blocked": [], "repairs": [], "patch_metrics": {},
                }

        for rule in ("REL-DEBUG-PRINT", "SEC-HARDCODED-SECRET"):
            with self.subTest(rule=rule):
                client = RecordingClient()
                result = LegacyFixer(ReadyVerifier()).create_fix_commits(
                    client, "org/repo", 7, {"findings": [finding(rule)]},
                    expected_source_sha=SHA,
                )
                self.assertEqual(result["failure_code"], "repair-manifest-missing")
                self.assertEqual(client.archive_refs, [])
                self.assertEqual(client.commit_parents, [])

    def test_missing_test_command_cannot_publish(self):
        verifier = ReadyVerifier()
        verifier.test_command = ""
        client = RecordingClient()
        result = PublicationGateFixer(verifier).create_fix_commits(
            client, "org/repo", 7, {"findings": [finding()]}, expected_source_sha=SHA,
        )
        self.assertEqual(result["failure_code"], "repository-tests-not-configured")
        self.assertEqual(client.archive_refs, [])
        self.assertEqual(client.commit_parents, [])

    def test_failed_gate_cannot_publish(self):
        class FailedVerifier(ReadyVerifier):
            def verify_archive(self, archive, files, repairs):
                result = super().verify_archive(archive, files, repairs)
                result["checks"][-1]["passed"] = False
                result["passed"] = False
                return result

        client = RecordingClient()
        result = PublicationGateFixer(FailedVerifier()).create_fix_commits(
            client, "org/repo", 7, {"findings": [finding()]}, expected_source_sha=SHA,
        )
        self.assertFalse(result["verification"]["passed"])
        self.assertEqual(client.commit_parents, [])
        self.assertEqual(client.draft_bodies, [])

    def test_every_check_must_explicitly_pass(self):
        class FalseCheckVerifier(ReadyVerifier):
            def verify_archive(self, archive, files, repairs):
                result = super().verify_archive(archive, files, repairs)
                result["checks"][-1]["passed"] = False
                # A buggy verifier may still report its aggregate as true.
                result["passed"] = True
                return result

        client = RecordingClient()
        result = PublicationGateFixer(FalseCheckVerifier()).create_fix_commits(
            client, "org/repo", 7, {"findings": [finding()]}, expected_source_sha=SHA,
        )
        self.assertEqual(result["failure_code"], "repair-verification-failed")
        self.assertEqual(client.commit_parents, [])

    def test_contradictory_duplicate_check_cannot_be_hidden_by_a_passing_duplicate(self):
        class DuplicateVerifier(ReadyVerifier):
            def verify_archive(self, archive, files, repairs):
                result = super().verify_archive(archive, files, repairs)
                result["checks"].append({
                    "name": "repository-tests", "passed": False,
                })
                return result

        client = RecordingClient()
        result = PublicationGateFixer(DuplicateVerifier()).create_fix_commits(
            client, "org/repo", 7, {"findings": [finding()]}, expected_source_sha=SHA,
        )
        self.assertEqual(result["failure_code"], "repair-verification-failed")
        self.assertEqual(client.commit_parents, [])

    def test_missing_sandbox_image_cannot_publish(self):
        class NoImageVerifier(ReadyVerifier):
            def verify_archive(self, archive, files, repairs):
                result = super().verify_archive(archive, files, repairs)
                del result["sandbox"]["image_id"]
                return result

        client = RecordingClient()
        result = PublicationGateFixer(NoImageVerifier()).create_fix_commits(
            client, "org/repo", 7, {"findings": [finding()]}, expected_source_sha=SHA,
        )
        self.assertEqual(result["failure_code"], "repair-verification-failed")
        self.assertEqual(client.commit_parents, [])

    def test_false_sandbox_metadata_cannot_publish(self):
        for field in ("configured", "executed", "stop_confirmed", "passed"):
            with self.subTest(field=field):
                class FalseMetadataVerifier(ReadyVerifier):
                    def __init__(self, metadata_field: str) -> None:
                        self.metadata_field = metadata_field

                    def verify_archive(self, archive, files, repairs):
                        result = super().verify_archive(archive, files, repairs)
                        result["sandbox"][self.metadata_field] = False
                        return result

                client = RecordingClient()
                result = PublicationGateFixer(
                    FalseMetadataVerifier(field)
                ).create_fix_commits(
                    client, "org/repo", 7, {"findings": [finding()]},
                    expected_source_sha=SHA,
                )
                self.assertEqual(result["failure_code"], "repair-verification-failed")
                self.assertEqual(client.commit_parents, [])

    def test_success_uses_fixed_sha_and_truthful_checks(self):
        client = RecordingClient([SHA, SHA])
        result = PublicationGateFixer(ReadyVerifier()).create_fix_commits(
            client, "org/repo", 7, {"findings": [finding()]}, expected_source_sha=SHA,
            publication_store=self.store, publication_scope="tenant/task",
        )
        self.assertEqual(result["source_sha"], SHA)
        self.assertEqual(client.file_refs, [SHA])
        self.assertEqual(client.archive_refs, [SHA])
        self.assertEqual(client.commit_parents, [SHA])
        body = client.draft_bodies[0]
        self.assertIn(SHA, client.commit_messages[0])
        self.assertIn(SHA, client.draft_titles[0])
        self.assertIn(SHA, body)
        self.assertIn("compile:app.py: passed", body)
        self.assertIn("repository-tests: passed", body)
        self.assertNotIn("configured regression tests passed", body)

    def test_verification_body_escapes_control_characters_in_check_names(self):
        body = SafeFixer._verification_body({
            "source_sha": SHA,
            "checks": [{
                "name": "compile:app.py\n- repository-tests",
                "passed": True,
            }],
            "sandbox": {
                "executed": True,
                "stop_confirmed": True,
                "passed": True,
            },
        })
        self.assertIn("compile:app.py\\u000a- repository-tests: passed", body)
        self.assertNotIn("compile:app.py\n- repository-tests: passed", body)

