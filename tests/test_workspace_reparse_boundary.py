"""Windows reparse-point defenses without requiring junction privileges."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest import mock

from lima.workspace import RepositoryWorkspace


class WorkspaceReparseBoundaryTests(unittest.TestCase):
    def test_inventory_skips_mocked_reparse_directory(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            junction = root / "junction"
            junction.mkdir()
            junction.joinpath("outside.py").write_text("secret = 1\n", encoding="utf-8")
            root.joinpath("inside.py").write_text("safe = 1\n", encoding="utf-8")
            with mock.patch(
                "lima.workspace._is_link_or_reparse_point",
                side_effect=lambda path: Path(path).name == "junction",
            ):
                inventory = RepositoryWorkspace(root).inventory()
            self.assertEqual([item.path for item in inventory.files], ["inside.py"])
            self.assertEqual(inventory.skipped["reparse-point"], 1)

    def test_read_rejects_mocked_reparse_file_before_resolution(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target = root / "reparse.py"
            target.write_text("secret = 1\n", encoding="utf-8")
            workspace = RepositoryWorkspace(root)
            with mock.patch(
                "lima.workspace._is_link_or_reparse_point",
                side_effect=lambda path: Path(path).name == "reparse.py",
            ):
                with self.assertRaisesRegex(ValueError, "regular file"):
                    workspace.read_text("reparse.py")

    def test_read_rejects_mocked_reparse_parent_before_resolution(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            linked_directory = root / "junction"
            linked_directory.mkdir()
            linked_directory.joinpath("inside.py").write_text(
                "secret = 1\n", encoding="utf-8"
            )
            workspace = RepositoryWorkspace(root)
            with mock.patch(
                "lima.workspace._is_link_or_reparse_point",
                side_effect=lambda path: Path(path).name == "junction",
            ):
                with self.assertRaisesRegex(ValueError, "regular file"):
                    workspace.read_text("junction/inside.py")
