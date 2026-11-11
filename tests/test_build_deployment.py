"""Deployment preflight tests for the host-executed Build Agent."""

from __future__ import annotations

import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from lima.build_deployment import build_environment_failure


class BuildDeploymentTest(unittest.TestCase):
    def test_missing_docker_cli_is_reported_before_artifact_checks(self) -> None:
        with mock.patch("lima.build_deployment.shutil.which", return_value=None):
            self.assertEqual(
                build_environment_failure(Path("unused-artifacts")),
                "docker-cli-unavailable",
            )

    def test_unreachable_docker_daemon_is_reported(self) -> None:
        with tempfile.TemporaryDirectory() as temporary, mock.patch(
            "lima.build_deployment.shutil.which", return_value="docker"
        ), mock.patch(
            "lima.build_deployment.subprocess.run",
            side_effect=subprocess.TimeoutExpired(["docker", "info"], 5),
        ):
            self.assertEqual(
                build_environment_failure(Path(temporary) / "artifacts"),
                "docker-daemon-unavailable",
            )

    def test_nonzero_docker_info_is_reported_without_exposing_output(self) -> None:
        with tempfile.TemporaryDirectory() as temporary, mock.patch(
            "lima.build_deployment.shutil.which", return_value="docker"
        ), mock.patch(
            "lima.build_deployment.subprocess.run",
            return_value=subprocess.CompletedProcess(["docker", "info"], 1),
        ):
            self.assertEqual(
                build_environment_failure(Path(temporary) / "artifacts"),
                "docker-daemon-unavailable",
            )

    def test_unwritable_artifacts_root_is_reported_after_docker_preflight(self) -> None:
        with tempfile.TemporaryDirectory() as temporary, mock.patch(
            "lima.build_deployment.shutil.which", return_value="docker"
        ), mock.patch(
            "lima.build_deployment.subprocess.run",
            return_value=subprocess.CompletedProcess(["docker", "info"], 0),
        ), mock.patch("lima.build_deployment.tempfile.mkstemp", side_effect=OSError("read-only")):
            self.assertEqual(
                build_environment_failure(Path(temporary) / "artifacts"),
                "build-artifacts-unwritable",
            )

    def test_usable_daemon_and_artifacts_root_pass(self) -> None:
        with tempfile.TemporaryDirectory() as temporary, mock.patch(
            "lima.build_deployment.shutil.which", return_value="docker"
        ), mock.patch(
            "lima.build_deployment.subprocess.run",
            return_value=subprocess.CompletedProcess(["docker", "info"], 0),
        ) as run:
            root = Path(temporary) / "artifacts"
            self.assertIsNone(build_environment_failure(root))
            self.assertTrue(root.is_dir())
        self.assertEqual(run.call_args.kwargs["timeout"], 5)
        self.assertIs(run.call_args.kwargs["stdout"], subprocess.DEVNULL)
        self.assertIs(run.call_args.kwargs["stderr"], subprocess.DEVNULL)

