"""Fail-closed Docker sandbox for repository repair tests."""
from __future__ import annotations

import dataclasses
import json
import math
import os
import re
import shlex
import stat
import subprocess
import tempfile
import time
import uuid
from collections.abc import Callable
from pathlib import Path
from typing import Any

from lima.build_inputs import _is_link_or_junction
from lima.container_execution import (
    ContainerExecutionError,
    ContainerLimits,
    ContainerRunResult,
    docker_run_argv,
    run_isolated_worker,
)

_BOOTSTRAP = """import json, os, shutil, sys
shutil.copytree('/input', '/work/repository', symlinks=False)
with open('/lima-modes.json') as handle:
    modes = json.load(handle)
for path, mode in modes.items():
    os.chmod(os.path.join('/work/repository', path), int(mode, 8) & 0o777)
os.chdir('/work/repository')
os.execvp(sys.argv[1], sys.argv[1:])
"""
_IMAGE_ID = re.compile(r"sha256:[0-9a-f]{64}\Z")
_MAX_INPUT_BYTES = 200 * 1024 * 1024
_MAX_INPUT_FILES = 20_000


@dataclasses.dataclass(frozen=True, slots=True)
class RepairSandboxLimits:
    memory: str = "2g"
    cpus: str = "2"
    pids_limit: int = 256
    output_bytes: int = 1024 * 1024


class DockerRepairTestSandbox:
    def __init__(self, image: str, *, runner: Callable[..., Any] | None = None,
                 limits: RepairSandboxLimits | None = None) -> None:
        self.image = image.strip() if isinstance(image, str) else ""
        self.runner = runner
        self.limits = limits or RepairSandboxLimits()

    def _image_id(self, timeout_seconds: float = 10.0) -> str | None:
        if (
            not self.image or self.image.startswith("-")
            or any(character.isspace() for character in self.image)
            or timeout_seconds <= 0
        ):
            return None
        try:
            inspected = subprocess.run(  # noqa: S603 - fixed local docker argv
                ["docker", "image", "inspect", "--format", "{{.Id}}", self.image],  # noqa: S607
                capture_output=True, text=True, check=False, timeout=min(10, timeout_seconds),
            )
        except (OSError, subprocess.SubprocessError):
            return None
        value = inspected.stdout.strip()
        return value if inspected.returncode == 0 and _IMAGE_ID.fullmatch(value) else None

    def _stage_input(self, source: Path, destination: Path, deadline: float,
                     *, file_modes: dict[str, str] | None = None) -> dict[str, str]:
        if file_modes is not None and not isinstance(file_modes, dict):
            raise ValueError("repair-sandbox-input-invalid")
        if _is_link_or_junction(source) or not source.is_dir():
            raise ValueError("repair-sandbox-input-invalid")
        source = source.resolve(strict=True)
        destination.mkdir(mode=0o755)
        total = 0
        count = 0
        modes = {}
        def fail(error: OSError) -> None:
            raise ValueError("repair-sandbox-input-unreadable") from error
        for current, directories, files in os.walk(
            source, topdown=True, followlinks=False, onerror=fail
        ):
            base = Path(current)
            if time.monotonic() >= deadline:
                raise ValueError("repair-sandbox-timeout")
            relative = base.relative_to(source)
            target_base = destination / relative
            target_base.mkdir(mode=0o755, exist_ok=True)
            os.chmod(target_base, 0o755)  # noqa: S103 - sandbox-readable staging
            for name in sorted(directories):
                if _is_link_or_junction(base / name):
                    raise ValueError("repair-sandbox-input-link")
            for name in sorted(files):
                original = base / name
                if _is_link_or_junction(original):
                    raise ValueError("repair-sandbox-input-link")
                try:
                    original.resolve(strict=True).relative_to(source)
                except (OSError, ValueError) as exc:
                    raise ValueError("repair-sandbox-input-unreadable") from exc
                info = original.stat()
                if not stat.S_ISREG(info.st_mode):
                    raise ValueError("repair-sandbox-input-invalid")
                count += 1
                if count > _MAX_INPUT_FILES:
                    raise ValueError("repair-sandbox-input-too-large")
                if info.st_size > _MAX_INPUT_BYTES:
                    raise ValueError("repair-sandbox-input-too-large")
                target = target_base / name
                copied = 0
                with original.open("rb") as reader, target.open("xb") as writer:
                    while chunk := reader.read(1024 * 1024):
                        if time.monotonic() >= deadline:
                            raise ValueError("repair-sandbox-timeout")
                        copied += len(chunk)
                        total += len(chunk)
                        if copied > _MAX_INPUT_BYTES or total > _MAX_INPUT_BYTES:
                            raise ValueError("repair-sandbox-input-too-large")
                        writer.write(chunk)
                if copied != info.st_size or original.stat().st_size != info.st_size:
                    raise ValueError("repair-sandbox-input-mutated")
                relative_file = original.relative_to(source).as_posix()
                mode = (file_modes.get(relative_file) if file_modes is not None else
                        "100755" if info.st_mode & stat.S_IXUSR else "100644")
                if mode not in {"100644", "100755"}:
                    raise ValueError("repair-sandbox-input-invalid")
                modes[relative_file] = mode
                os.chmod(target, int(mode, 8) & 0o777)
        if file_modes is not None and set(modes) != set(file_modes):
            raise ValueError("repair-sandbox-input-invalid")
        return modes

    def run(self, root: str | Path, command: str, timeout_seconds: float,
            *, file_modes: dict[str, str] | None = None) -> dict[str, Any]:
        base = {"configured": bool(self.image), "executed": False,
                "stop_confirmed": False, "passed": False, "reason": ""}
        if not self.image:
            return base | {"reason": "repair-sandbox-image-unconfigured", "image_id": None,
                           "limits": dataclasses.asdict(self.limits)}
        if not math.isfinite(timeout_seconds) or timeout_seconds <= 0:
            return base | {"reason": "repair-sandbox-timeout", "image_id": None,
                           "limits": dataclasses.asdict(self.limits)}
        deadline = time.monotonic() + timeout_seconds
        image_id = (
            self._image_id(max(0.0, deadline - time.monotonic()))
            if self.runner is None else self.image
        )
        if image_id and not _IMAGE_ID.fullmatch(image_id):
            image_id = None
        if not image_id:
            return base | {"reason": "repair-sandbox-image-unavailable", "image_id": None,
                           "limits": dataclasses.asdict(self.limits)}
        try:
            argv = shlex.split(command, posix=True)
        except ValueError:
            return base | {"reason": "repair-test-command-invalid", "image_id": image_id,
                           "limits": dataclasses.asdict(self.limits)}
        if not argv:
            return base | {"reason": "repair-test-command-empty", "image_id": image_id,
                           "limits": dataclasses.asdict(self.limits)}
        source = Path(root)
        if not source.is_dir() or source.is_symlink():
            return base | {"reason": "repair-worktree-missing", "image_id": image_id,
                           "limits": dataclasses.asdict(self.limits)}
        name = "lima-repair-test-" + uuid.uuid4().hex[:16]
        with tempfile.TemporaryDirectory(prefix="lima-repair-sandbox-") as temp:
            stage = Path(temp) / "input"
            try:
                modes = (self._stage_input(source, stage, deadline) if file_modes is None else
                         self._stage_input(source, stage, deadline, file_modes=file_modes)) or {}
            except (OSError, ValueError) as exc:
                reason = str(exc)
                allowed = {
                    "repair-sandbox-input-invalid", "repair-sandbox-input-link",
                    "repair-sandbox-input-too-large", "repair-sandbox-input-mutated",
                    "repair-sandbox-timeout",
                }
                if reason not in allowed:
                    reason = "repair-sandbox-input-unreadable"
                return base | {"reason": reason, "image_id": image_id,
                               "limits": dataclasses.asdict(self.limits)}
            metadata = Path(temp) / "modes.json"
            metadata.write_text(json.dumps(modes, ensure_ascii=True), encoding="utf-8")
            os.chmod(metadata, 0o644)  # noqa: S103 - non-root container must read its mode receipt
            mounts = [f"type=bind,source={stage.resolve().as_posix()},target=/input,readonly",
                      f"type=bind,source={metadata.resolve().as_posix()},target=/lima-modes.json,readonly"]
            docker = docker_run_argv(
                image=image_id, name=name, mounts=mounts, workdir="/work",
                argv=("-c", _BOOTSTRAP, *argv),
                limits=ContainerLimits(memory=self.limits.memory, cpus=self.limits.cpus,
                                       pids_limit=self.limits.pids_limit, network=False),
            )
            image_at = docker.index(image_id)
            docker[image_at:image_at] = [
                "--pull", "never", "--entrypoint", "python3", "--read-only",
                "--env", "HOME=/tmp", "--env", "TMPDIR=/tmp",
                "--user", "65534:65534", "--tmpfs", "/work:rw,noexec,nosuid,mode=1777,size=1g",
                "--tmpfs", "/tmp:rw,noexec,nosuid,mode=1777,size=256m",  # noqa: S108
            ]
            paths = {key: Path(temp) / value for key, value in {
                "stdout": "stdout.log", "stderr": "stderr.log", "stop": "stop.log"}.items()}
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return base | {"reason": "repair-sandbox-timeout", "image_id": image_id,
                               "limits": dataclasses.asdict(self.limits)}
            try:
                if self.runner is not None:
                    result = self.runner(
                        docker, name=name, timeout_seconds=remaining,
                        stdout_path=paths["stdout"], stderr_path=paths["stderr"],
                        stop_log_path=paths["stop"], capture_limit_bytes=self.limits.output_bytes,
                    )
                else:
                    result = run_isolated_worker(
                        docker, name=name,
                        timeout_seconds=remaining,
                        cancel=lambda: False,
                        stdout_path=paths["stdout"], stderr_path=paths["stderr"],
                        stop_log_path=paths["stop"], capture_limit_bytes=self.limits.output_bytes)
            except ContainerExecutionError:
                return base | {"reason": "repair-sandbox-invocation-failed", "image_id": image_id,
                               "limits": dataclasses.asdict(self.limits)}
            if not isinstance(result, ContainerRunResult):
                return base | {"reason": "repair-sandbox-runner-invalid", "image_id": image_id,
                               "limits": dataclasses.asdict(self.limits)}
            passed = (
                result.returncode == 0 and not result.timed_out and not result.cancelled
                and time.monotonic() < deadline
            )
            detail_out = _tail(paths["stdout"])
            detail_err = _tail(paths["stderr"])
            for host_path, replacement in (
                (str(source), "<repository>"), (str(Path(temp)), "<sandbox-log>"),
                (str(source).replace("\\", "/"), "<repository>"),
                (str(Path(temp)).replace("\\", "/"), "<sandbox-log>"),
            ):
                detail_out = detail_out.replace(host_path, replacement)
                detail_err = detail_err.replace(host_path, replacement)
            stop_confirmed = result.stop_confirmed is True
            return base | {"executed": True, "stop_confirmed": stop_confirmed,
                           "passed": passed and stop_confirmed,
                           "reason": (
                               "ok" if passed and stop_confirmed else "repair-tests-failed"
                           ),
                           "image_id": image_id, "limits": dataclasses.asdict(self.limits),
                           "stdout": detail_out, "stderr": detail_err,
                           "stdout_truncated": bool(result.stdout_truncated),
                           "stderr_truncated": bool(result.stderr_truncated)}


def _tail(path: Path) -> str:
    return path.read_text(encoding="utf8", errors="replace")[-8000:] if path.exists() else ""
