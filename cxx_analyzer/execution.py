"""Shell-free, bounded process execution for verified analyzer snapshots."""

from __future__ import annotations

import hashlib
import os
import stat
import subprocess
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

from .config import MAX_ARGUMENT_BYTES, MAX_ARGUMENTS_PER_STEP

CLEAN_ENVIRONMENT = {
    "PATH": "/usr/local/bin:/usr/bin:/bin",
    "HOME": "/tmp/analyzer-home",  # noqa: S108 - fixed container-only path
    "LANG": "C.UTF-8",
    "LC_ALL": "C.UTF-8",
    "TMPDIR": "/work/tmp",
}


@dataclass(frozen=True)
class ToolExecution:
    """Bounded subprocess result with digests over each complete raw stream."""

    status: str
    returncode: int | None
    stdout: str
    stderr: str
    stdout_sha256: str
    stderr_sha256: str
    output_sha256: str
    output_truncated: bool


def _raw_bytes(value: bytes | str | None) -> bytes:
    if value is None:
        return b""
    if isinstance(value, bytes):
        return value
    return value.encode("utf-8", errors="replace")


def _bounded_text(value: bytes, budget: int) -> str:
    if budget <= 0:
        return ""
    text = value[:budget].decode("utf-8", errors="replace")
    while len(text.encode("utf-8")) > budget:
        text = text[:-1]
    return text


def _validate_argv(argv: Sequence[str]) -> list[str]:
    if isinstance(argv, str | bytes) or not isinstance(argv, Sequence):
        raise ValueError("tool command must be an argv sequence")
    if not argv or len(argv) > MAX_ARGUMENTS_PER_STEP:
        raise ValueError("tool argv must contain a bounded non-empty argument list")
    result: list[str] = []
    for argument in argv:
        if not isinstance(argument, str):
            raise ValueError("tool argv values must be strings")
        if "\0" in argument:
            raise ValueError("tool argv values must not contain NUL")
        if len(argument.encode("utf-8")) > MAX_ARGUMENT_BYTES:
            raise ValueError("tool argv value exceeds the byte limit")
        result.append(argument)
    if not result[0]:
        raise ValueError("tool executable must not be empty")
    return result


def _validated_cwd(cwd: str | os.PathLike[str]) -> Path:
    try:
        raw = Path(cwd).expanduser()
        metadata = raw.lstat()
        resolved = raw.resolve(strict=True)
    except OSError as exc:
        raise ValueError("tool cwd must be an available directory") from exc
    attributes = getattr(metadata, "st_file_attributes", 0)
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    if (
        stat.S_ISLNK(metadata.st_mode)
        or bool(attributes & reparse_flag)
        or not stat.S_ISDIR(metadata.st_mode)
    ):
        raise ValueError("tool cwd must be a real directory")
    return resolved


def run_step(
    argv: Sequence[str],
    cwd: str | os.PathLike[str],
    timeout_seconds: int,
    max_output_bytes: int,
    env: Mapping[str, str] | None,
) -> ToolExecution:
    """Run one fixed argv step with no shell, inherited input, or inherited secrets."""

    arguments = _validate_argv(argv)
    working_directory = _validated_cwd(cwd)
    if not isinstance(timeout_seconds, int) or timeout_seconds < 1:
        raise ValueError("tool timeout must be a positive integer")
    if not isinstance(max_output_bytes, int) or max_output_bytes < 1:
        raise ValueError("tool output limit must be a positive integer")
    if env is not None and not isinstance(env, Mapping):
        raise ValueError("tool environment must be a mapping")

    # The argument is intentionally not merged. Tool-specific environments must be
    # admitted explicitly here in a future reviewed allowlist change.
    clean_environment = dict(CLEAN_ENVIRONMENT)
    try:
        completed = subprocess.run(  # noqa: S603 - bounded argv, never a shell
            arguments,
            cwd=working_directory,
            env=clean_environment,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            timeout=timeout_seconds,
            shell=False,
            check=False,
        )
        stdout = _raw_bytes(completed.stdout)
        stderr = _raw_bytes(completed.stderr)
        returncode: int | None = completed.returncode
        status = "completed" if completed.returncode == 0 else "failed"
    except subprocess.TimeoutExpired as exc:
        stdout = _raw_bytes(exc.output)
        stderr = _raw_bytes(exc.stderr)
        returncode = None
        status = "timed-out"

    stdout_budget = min(len(stdout), max_output_bytes)
    stderr_budget = max_output_bytes - stdout_budget
    bounded_stdout = _bounded_text(stdout, stdout_budget)
    bounded_stderr = _bounded_text(stderr, stderr_budget)
    return ToolExecution(
        status=status,
        returncode=returncode,
        stdout=bounded_stdout,
        stderr=bounded_stderr,
        stdout_sha256=hashlib.sha256(stdout).hexdigest(),
        stderr_sha256=hashlib.sha256(stderr).hexdigest(),
        output_sha256=hashlib.sha256(stdout + b"\0" + stderr).hexdigest(),
        output_truncated=len(stdout) + len(stderr) > max_output_bytes,
    )
