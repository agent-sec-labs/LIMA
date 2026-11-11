import os
import subprocess
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from lima.container_execution import ContainerRunResult
from lima.repair_sandbox import DockerRepairTestSandbox
from lima.verifier import RepairVerifier


class RepairTestSandboxTest(unittest.TestCase):
    def test_private_source_is_readable_in_staging_without_changing_original_modes(self):
        observed = {}

        def runner(argv, **kwargs):
            mount = next(value for value in argv if "target=/input,readonly" in value)
            stage = Path(next(part[7:] for part in mount.split(",") if part.startswith("source=")))
            observed["contents"] = (stage / "test.py").read_text()
            observed["root_mode"] = stage.stat().st_mode & 0o777
            return ContainerRunResult(0, False, False, 0.01)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "private"
            root.mkdir(mode=0o700)
            target = root / "test.py"
            target.write_text("assert True\n")
            target.chmod(0o600)
            root_before, file_before = root.stat().st_mode, target.stat().st_mode
            result = RepairVerifier(
                "python3 test.py", sandbox_image="sha256:" + "a" * 64,
                sandbox_runner=runner,
            ).verify_worktree(str(root), True)
            self.assertEqual(root.stat().st_mode, root_before)
            self.assertEqual(target.stat().st_mode, file_before)
        self.assertTrue(result["passed"])
        self.assertEqual(observed["contents"], "assert True\n")
        if os.name != "nt":
            self.assertEqual(observed["root_mode"], 0o755)

    @unittest.skipUnless(os.name == "nt", "Windows junction boundary")
    def test_windows_junction_never_enters_staging(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            root, outside = base / "root", base / "outside"
            root.mkdir()
            outside.mkdir()
            (outside / "marker.py").write_text("BENIGN_OUTSIDE_MARKER=1\n")
            junction = root / "linked"
            made = subprocess.run(  # noqa: S603, S607 - fixed task-owned junction creation
                ["cmd", "/c", "mklink", "/J", str(junction), str(outside)],  # noqa: S607
                capture_output=True, check=False,
            )
            self.assertEqual(made.returncode, 0)
            try:
                result = RepairVerifier(
                    "python3 test.py", sandbox_image="sha256:" + "a" * 64,
                    sandbox_runner=lambda *_args, **_kwargs: self.fail("unsafe input"),
                ).verify_worktree(str(root), True)
                self.assertFalse(result["passed"])
                self.assertFalse(result["sandbox"]["executed"])
            finally:
                if junction.exists() and junction.resolve() == outside.resolve():
                    os.rmdir(junction)

    def test_expired_staging_never_starts_runner(self):
        with tempfile.TemporaryDirectory() as temporary:
            sandbox = DockerRepairTestSandbox(
                "sha256:" + "a" * 64,
                runner=lambda *_args, **_kwargs: self.fail("expired sandbox entered runner"),
            )

            def stage(source, destination, deadline):
                destination.mkdir()
                time.sleep(0.02)

            with mock.patch.object(sandbox, "_stage_input", side_effect=stage):
                result = sandbox.run(temporary, "python3 test.py", 0.005)
            self.assertFalse(result["passed"])
            self.assertFalse(result["executed"])
            self.assertEqual(result["reason"], "repair-sandbox-timeout")

    def test_late_success_receipt_cannot_overrun_shared_deadline(self):
        def runner(*_args, **_kwargs):
            time.sleep(0.03)
            return ContainerRunResult(0, False, False, 0.03)

        with tempfile.TemporaryDirectory() as temporary:
            result = DockerRepairTestSandbox(
                "sha256:" + "a" * 64, runner=runner,
            ).run(temporary, "python3 test.py", 0.01)
            self.assertFalse(result["passed"])

    def test_unconfigured_image_never_runs_host_sentinel(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sentinel = root / "host-ran"
            result = RepairVerifier(
                test_command=f"python3 -c \"open('{sentinel}', 'w').write('x')\""
            ).verify_worktree(str(root), require_tests=True)
            self.assertFalse(result["passed"])
            self.assertFalse(result["sandbox"]["executed"])
            self.assertFalse(sentinel.exists())
            self.assertEqual(
                result["checks"][0]["detail"], "repair-sandbox-image-unconfigured",
            )

    def test_runner_receives_hardened_networkless_readonly_argv(self) -> None:
        captured = {}
        def runner(argv, **kwargs):
            captured["argv"] = argv
            Path(kwargs["stdout_path"]).write_text("ok")
            Path(kwargs["stderr_path"]).write_text("")
            return ContainerRunResult(0, False, False, 0.1)
        with tempfile.TemporaryDirectory() as tmp:
            result = RepairVerifier(
                "pytest -q", sandbox_image="sha256:" + "a" * 64, sandbox_runner=runner
            ).verify_worktree(tmp, True)
        self.assertTrue(result["passed"])
        argv = captured["argv"]
        for token in (
            "--network", "none", "--read-only", "--cap-drop", "ALL", "--user",
            "65534:65534", "--pull", "never", "--tmpfs",
        ):
            self.assertIn(token, argv)
        self.assertIn("readonly", " ".join(argv))
        self.assertEqual(argv[argv.index("--workdir") + 1], "/work")
        self.assertIn("/work:rw,noexec,nosuid,mode=1777,size=1g", argv)

    def test_unconfirmed_cleanup_cannot_pass(self) -> None:
        def runner(argv, **kwargs):
            return ContainerRunResult(0, True, False, 0.1, stop_confirmed=False)
        with tempfile.TemporaryDirectory() as tmp:
            result = RepairVerifier(
                "pytest", sandbox_image="sha256:" + "a" * 64, sandbox_runner=runner
            ).verify_worktree(tmp, True)
        self.assertFalse(result["passed"])
        self.assertTrue(result["sandbox"]["executed"])
        self.assertFalse(result["sandbox"]["stop_confirmed"])

    def test_staging_rejects_links_and_preserves_original_mode(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "root"
            root.mkdir(mode=0o700)
            original = root / "run.py"
            original.write_text("print('ok')")
            original.chmod(0o700)
            try:
                (root / "linked").symlink_to(original)
            except OSError:
                self.skipTest("symlink creation unavailable")
            result = RepairVerifier(
                "python3 run.py", sandbox_image="sha256:" + "a" * 64,
                sandbox_runner=lambda *_args, **_kwargs: None,
            ).verify_worktree(str(root), True)
            self.assertFalse(result["passed"])
            self.assertEqual(result["sandbox"]["reason"], "repair-sandbox-input-link")
            self.assertEqual(original.stat().st_mode & 0o777, 0o700)
