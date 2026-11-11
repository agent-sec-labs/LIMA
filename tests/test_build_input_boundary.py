"""Security boundary tests for the build snapshot hand-off."""

import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from lima.build_executor import BuildExecutor, IsolatedStepOutcome
from lima.build_inputs import (
    BuildInputError,
    collect_build_inputs,
    compute_build_input_digest,
    copy_build_inputs,
)
from lima.build_recipe import BuildRecipe


class Limits:
    max_input_files = 20
    max_input_file_bytes = 1024
    max_input_total_bytes = 2048


class BuildInputBoundaryTest(unittest.TestCase):
    def test_copy_rejects_snapshot_root_replaced_by_reparse_point(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = self._tree(Path(tmp) / "snapshot")
            manifest = collect_build_inputs(root, Limits())
            with mock.patch(
                "lima.build_inputs._is_link_or_junction",
                side_effect=lambda path: Path(path) == root,
            ):
                with self.assertRaisesRegex(BuildInputError, "build-input-link"):
                    copy_build_inputs(manifest, root, Path(tmp) / "copy")

    def _tree(self, root: Path) -> Path:
        root.mkdir()
        (root / "CMakeLists.txt").write_text("project(boundary)", encoding="utf8")
        (root / "asset.dat").write_bytes(b"asset")
        (root / ".env").write_text("SECRET=never-copy", encoding="utf8")
        return root

    def test_env_is_excluded_and_regular_resources_are_preserved(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = self._tree(Path(tmp) / "snapshot")
            (root / ".git").write_text("gitdir: C:/host/.git/worktrees/x", encoding="utf8")
            manifest = collect_build_inputs(root, Limits())
            self.assertEqual([m.path for m in manifest.members], ["CMakeLists.txt", "asset.dat"])
            self.assertNotIn(".git", [m.path for m in manifest.members])
            destination = Path(tmp) / "copy"
            copy_build_inputs(manifest, root, destination)
            self.assertTrue((destination / "CMakeLists.txt").is_file())
            self.assertEqual((destination / "asset.dat").read_bytes(), b"asset")
            self.assertFalse((destination / ".env").exists())

    def test_digest_tracks_included_files_not_env(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = self._tree(Path(tmp) / "snapshot")
            original = compute_build_input_digest(root, Limits())
            (root / ".env").write_text("SECRET=changed", encoding="utf8")
            self.assertEqual(compute_build_input_digest(root, Limits()), original)
            (root / "asset.dat").write_bytes(b"changed")
            self.assertNotEqual(compute_build_input_digest(root, Limits()), original)

    def test_walk_error_is_rejected_not_silently_ignored(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = self._tree(Path(tmp) / "snapshot")
            real_walk = os.walk

            def denied(*args, **kwargs):
                onerror = kwargs.get("onerror")
                if onerror is not None:
                    onerror(PermissionError("denied"))
                return iter(())

            with mock.patch("lima.build_inputs.os.walk", denied):
                with self.assertRaisesRegex(BuildInputError, "build-input-unreadable"):
                    collect_build_inputs(root, Limits())
            self.assertIsNotNone(real_walk)

    def test_file_growth_during_hash_is_rejected_by_actual_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = self._tree(Path(tmp) / "snapshot")
            target = root / "asset.dat"
            target.write_bytes(b"x" * 1000)
            limits = Limits()
            limits.max_input_file_bytes = 1000
            # The file grows after stat but before its second stream chunk.
            original_open = Path.open

            class Growing:
                def __init__(self, handle): self.handle, self.calls = handle, 0
                def __enter__(self): return self
                def __exit__(self, *args): self.handle.close()
                def read(self, size=-1):
                    self.calls += 1
                    data = self.handle.read(size)
                    if self.calls == 1:
                        with original_open(target, "wb") as writer:
                            writer.write(b"x" * 2000)
                    return data

            def opened(path, *args, **kwargs):
                handle = original_open(path, *args, **kwargs)
                mode = args[0] if args else kwargs.get("mode", "r")
                return Growing(handle) if Path(path) == target and mode == "rb" else handle

            with mock.patch.object(Path, "open", opened):
                with self.assertRaisesRegex(BuildInputError, "build-input-file-too-large"):
                    collect_build_inputs(root, limits)

    def test_cancelled_input_never_opens_session_and_cleans_temp(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = self._tree(Path(tmp) / "snapshot")
            factory = _Factory()
            work = Path(tmp) / "work"
            with mock.patch(
                "lima.build_executor.tempfile.mkdtemp", return_value=str(work)
            ):
                result = BuildExecutor(session_factory=factory).execute(
                    _recipe(), root, Path(tmp) / "attempt", cancel=lambda: True
                )
            self.assertEqual(result.failure_code, "cancelled")
            self.assertFalse(result.repository_code_executed)
            self.assertEqual(factory.opens, 0)
            self.assertFalse(work.exists())

    def test_failed_sandbox_step_has_execution_receipt(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = self._tree(Path(tmp) / "snapshot")
            factory = _Factory(returncode=7)
            result = BuildExecutor(session_factory=factory).execute(
                _recipe(), root, Path(tmp) / "attempt"
            )
            self.assertFalse(result.ok)
            self.assertEqual(result.failure_code, "configure-step-failed")
            self.assertTrue(result.repository_code_executed)

    @unittest.skipUnless(os.name == "nt", "junctions are Windows-specific")
    def test_junction_is_rejected_before_or_during_copy(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            root = self._tree(base / "snapshot")
            outside = base / "outside"
            outside.mkdir()
            (outside / "marker.cpp").write_text("outside", encoding="utf8")
            junction = root / "linked"
            try:
                os.system(f'mklink /J "{junction}" "{outside}" >nul')  # noqa: S605
                if not junction.exists():
                    self.skipTest("junction creation unavailable")
                with self.assertRaisesRegex(BuildInputError, "build-input-link"):
                    collect_build_inputs(root, Limits())
            finally:
                if junction.exists():
                    os.rmdir(junction)

    @unittest.skipUnless(os.name == "nt", "junctions are Windows-specific")
    def test_directory_replaced_by_junction_after_manifest_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            root = self._tree(base / "snapshot")
            nested = root / "nested"
            nested.mkdir()
            (nested / "same.dat").write_bytes(b"same")
            manifest = collect_build_inputs(root, Limits())
            outside = base / "outside"
            outside.mkdir()
            (outside / "same.dat").write_bytes(b"same")
            (nested / "same.dat").unlink()
            nested.rmdir()
            try:
                os.system(f'mklink /J "{nested}" "{outside}" >nul')  # noqa: S605
                if not nested.exists():
                    self.skipTest("junction creation unavailable")
                with self.assertRaisesRegex(BuildInputError, "build-input-link"):
                    copy_build_inputs(manifest, root, base / "copy")
            finally:
                if nested.exists():
                    os.rmdir(nested)


def _recipe() -> BuildRecipe:
    return BuildRecipe(
        schema_version=1,
        name="input-boundary",
        image="fixture:latest",
        repository="Fixture/Repo",
        source_mount="/src",
        configure=(("cmake", "-S", ".", "-B", "build"),),
        compdb_path="build/compile_commands.json",
        generated_globs=(),
        include_roots=(),
    )


class _Session:
    image_digest = None
    def __init__(self, returncode: int): self.returncode = returncode
    def run_step(self, _argv, *, step_id, timeout_seconds):
        return IsolatedStepOutcome(
            returncode=self.returncode, stdout="", stderr="", elapsed_seconds=0.01
        )
    def close(self): pass


class _Factory:
    def __init__(self, returncode: int = 0): self.opens, self.returncode = 0, returncode
    def open(self, **_kwargs):
        self.opens += 1
        return _Session(self.returncode)

