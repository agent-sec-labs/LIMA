"""Regression tests for matching analyzed bytes to the reported workspace snapshot."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from lima.repository_scanner import RepositoryScanner
from lima.sast import SastRunResult
from lima.workspace import RepositoryWorkspace

VULNERABLE = "import subprocess\nvalue=input()\nsubprocess.run('echo ' + value, shell=True)\n"
SAFE = "import subprocess\nvalue=input()\nsubprocess.run(['echo', value], shell=False)\n"


class WorkspaceSnapshotConsistencyTests(unittest.TestCase):
    def test_iter_text_rejects_same_size_content_change(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target = root / "app.py"
            target.write_text("value = 'old'\n", encoding="utf-8")
            workspace = RepositoryWorkspace(root)
            inventory = workspace.inventory()

            target.write_text("value = 'new'\n", encoding="utf-8")

            with self.assertRaisesRegex(ValueError, "snapshot drift"):
                list(workspace.iter_text(inventory))

    def test_iter_text_preserves_crlf_and_accepts_unchanged_file(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target = root / "app.py"
            target.write_bytes(b"first = 1\r\nsecond = 2\r\n")
            workspace = RepositoryWorkspace(root)

            inventory = workspace.inventory()

            self.assertEqual(
                [("app.py", "first = 1\r\nsecond = 2\r\n")],
                list(workspace.iter_text(inventory)),
            )

    def test_read_text_rejects_file_that_grows_after_stat(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target = root / "app.py"
            target.write_text("small\n", encoding="utf-8")
            workspace = RepositoryWorkspace(root, max_file_bytes=10)
            original_open = Path.open

            def grow_before_open(path: Path, *args: object, **kwargs: object):
                if path == target:
                    with original_open(target, "wb") as writer:
                        writer.write(b"x" * 11)
                return original_open(path, *args, **kwargs)

            with patch.object(Path, "open", new=grow_before_open):
                with self.assertRaisesRegex(ValueError, "per-file size limit"):
                    workspace.read_text("app.py")

    def test_scanner_rejects_mutation_after_inventory(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target = root / "app.py"
            target.write_bytes(VULNERABLE.encode("utf-8"))

            def mutate_after_inventory(_stage: str, message: str, **_detail: object) -> None:
                if message == "工作区盘点完成":
                    target.write_bytes(SAFE.encode("utf-8"))

            scanner = RepositoryScanner(
                sast_mode="off", cxx_agent_mode="off", cxx_memory_mode="off"
            )
            with self.assertRaisesRegex(ValueError, "snapshot drift"):
                scanner.scan(RepositoryWorkspace(root), progress_callback=mutate_after_inventory)

    def test_sast_reads_materialized_snapshot_after_source_mutates(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target = root / "app.py"
            target.write_bytes(VULNERABLE.encode("utf-8"))

            class MutatingSastAdapter:
                name = "mutating-test"

                def available(self) -> bool:
                    return True

                def scan(self, workspace: RepositoryWorkspace, _inventory: object) -> SastRunResult:
                    target.write_bytes(SAFE.encode("utf-8"))
                    self.read_text_content = workspace.read_text("app.py")
                    self.absolute_file_content = workspace.absolute_file("app.py").read_text(
                        encoding="utf-8"
                    )
                    return SastRunResult(self.name, "completed")

            adapter = MutatingSastAdapter()
            result = RepositoryScanner(
                sast_mode="required",
                sast_adapters=[adapter],
                cxx_agent_mode="off",
                cxx_memory_mode="off",
            ).scan(RepositoryWorkspace(root))

            self.assertEqual(VULNERABLE, adapter.read_text_content)
            self.assertEqual(VULNERABLE, adapter.absolute_file_content)
            self.assertEqual(str(root.resolve()), result.report.repository)
            self.assertTrue(any(item.cwe == "CWE-78" for item in result.report.findings))


if __name__ == "__main__":
    unittest.main()
