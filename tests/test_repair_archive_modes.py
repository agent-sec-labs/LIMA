"""Repair verification must not silently change Git file types or modes."""

import io
import json
import stat
import tempfile
import unittest
import zipfile
from pathlib import Path

from lima.container_execution import ContainerRunResult
from lima.fixer import SafeFixer
from lima.repair_sandbox import DockerRepairTestSandbox
from lima.verifier import RepairVerifier

SOURCE = "import sqlite3; cursor=sqlite3.connect(':memory:').cursor()\nvalue=input()\ncursor.execute('SELECT * FROM t WHERE id = ' + value)\n"
FINDING = {
    "path": "app.py",
    "line": 3,
    "cwe": "CWE-89",
    "rule_id": "FLOW-SQL",
    "verification_state": "dataflow-verified",
}


def archive(entries):
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w") as bundle:
        for path, mode, content in entries:
            info = zipfile.ZipInfo("repo/" + path)
            info.create_system = 3
            info.external_attr = mode << 16
            bundle.writestr(info, content)
    return stream.getvalue()


class NoTestVerifier(RepairVerifier):
    def verify_worktree(self, *args, **kwargs):
        raise AssertionError("unsafe archive reached repository tests")


class RepairArchiveModeTests(unittest.TestCase):
    def test_links_and_special_types_fail_before_extracting_any_file(self):
        for mode in (
            stat.S_IFLNK | 0o777,
            stat.S_IFIFO | 0o644,
            stat.S_IFCHR | 0o644,
            stat.S_IFSOCK | 0o644,
            stat.S_IFDIR | 0o755,
        ):
            # The first member is valid: a later bad header must still stop all writes.
            data = archive(
                [("app.py", stat.S_IFREG | 0o644, SOURCE), ("config", mode, "payload.txt")]
            )
            with self.subTest(mode=oct(mode)), tempfile.TemporaryDirectory() as root:
                with self.assertRaises(ValueError):
                    RepairVerifier._safe_extract(data, root)
                self.assertEqual([], list(Path(root).iterdir()))

    def test_internal_external_and_dangling_links_do_not_start_tests_or_publish(self):
        planned = SafeFixer().apply(SOURCE, [FINDING], "app.py")
        for destination in ("payload.txt", "../outside", "/outside", "missing.txt"):
            data = archive(
                [
                    ("app.py", stat.S_IFREG | 0o644, SOURCE),
                    ("config", stat.S_IFLNK | 0o777, destination),
                ]
            )
            with self.subTest(destination=destination):
                result = NoTestVerifier("configured").verify_archive(
                    data,
                    {"app.py": planned["content"]},
                    planned["repairs"],
                )
                self.assertFalse(result["passed"])
                self.assertIsNone(result["sandbox"])
                self.assertEqual("repair-archive-link-unsupported", result["checks"][0]["detail"])

                class Client:
                    def __init__(self, archive_bytes):
                        self.archive_bytes = archive_bytes

                    def get_pull_request(self, *args):
                        return {"head": {"sha": "a" * 40, "repo": {"full_name": "org/repo"}}}

                    def get_file(self, *args):
                        return {"decoded_content": SOURCE}

                    def download_archive(self, *args):
                        return self.archive_bytes

                    def create_atomic_commit(self, *args):
                        raise AssertionError("unsafe archive reached remote writes")

                response = SafeFixer(NoTestVerifier("configured")).create_fix_commits(
                    Client(data),
                    "org/repo",
                    7,
                    {"findings": [FINDING]},
                    expected_source_sha="a" * 40,
                )
                self.assertIsNone(response["branch"])
                self.assertEqual("repair-verification-failed", response["failure_code"])

    def test_git_modes_reach_container_metadata_even_on_windows(self):
        observed = {}

        def runner(argv, **kwargs):
            for value in argv:
                if "target=/lima-modes.json,readonly" in value:
                    source = next(
                        part[7:] for part in value.split(",") if part.startswith("source=")
                    )
                    observed.update(json.loads(Path(source).read_text()))
            return ContainerRunResult(0, False, False, 0.01)

        planned = SafeFixer().apply(SOURCE, [FINDING], "app.py")
        data = archive(
            [
                ("app.py", stat.S_IFREG | 0o755, SOURCE),
                ("ordinary.txt", stat.S_IFREG | 0o644, "data"),
            ]
        )
        result = RepairVerifier(
            "python test.py", sandbox_image="sha256:" + "a" * 64, sandbox_runner=runner
        ).verify_archive(
            data,
            {"app.py": planned["content"]},
            planned["repairs"],
        )
        self.assertTrue(result["passed"])
        self.assertEqual({"app.py": "100755", "ordinary.txt": "100644"}, observed)

    def test_zip_without_unix_type_metadata_is_a_regular_file(self):
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, "w") as bundle:
            bundle.writestr("repo/readme.txt", "hello")
        with tempfile.TemporaryDirectory() as root:
            RepairVerifier._safe_extract(stream.getvalue(), root)
            self.assertEqual("hello", Path(root, "repo/readme.txt").read_text())

    def test_invalid_or_incomplete_modes_never_start_container(self):
        with tempfile.TemporaryDirectory() as root:
            Path(root, "app.py").write_text("pass\n")
            for modes in (
                {"app.py": "120000"},
                {},
                {"../outside": "100755"},
                {"app.py": "100644", "extra.py": "100755"},
            ):
                with self.subTest(modes=modes):

                    def runner(*args, **kwargs):
                        self.fail("invalid mode metadata reached the runner")

                    result = DockerRepairTestSandbox(
                        "sha256:" + "a" * 64,
                        runner=runner,
                    ).run(root, "python test.py", 10, file_modes=modes)
                    self.assertFalse(result["passed"])
                    self.assertFalse(result["executed"])
