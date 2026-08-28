"""Fail-closed Linux Landlock launcher for repository-provided tool processes."""

from __future__ import annotations

import ctypes
import errno
import os
import platform
import stat
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Final

MIN_LANDLOCK_ABI: Final = 3

LANDLOCK_CREATE_RULESET_VERSION: Final = 1
LANDLOCK_RULE_PATH_BENEATH: Final = 1
PR_SET_NO_NEW_PRIVS: Final = 38

ACCESS_EXECUTE: Final = 1 << 0
ACCESS_WRITE_FILE: Final = 1 << 1
ACCESS_READ_FILE: Final = 1 << 2
ACCESS_READ_DIR: Final = 1 << 3
ACCESS_REMOVE_DIR: Final = 1 << 4
ACCESS_REMOVE_FILE: Final = 1 << 5
ACCESS_MAKE_CHAR: Final = 1 << 6
ACCESS_MAKE_DIR: Final = 1 << 7
ACCESS_MAKE_REG: Final = 1 << 8
ACCESS_MAKE_SOCK: Final = 1 << 9
ACCESS_MAKE_FIFO: Final = 1 << 10
ACCESS_MAKE_BLOCK: Final = 1 << 11
ACCESS_MAKE_SYM: Final = 1 << 12
ACCESS_REFER: Final = 1 << 13
ACCESS_TRUNCATE: Final = 1 << 14

READ_ONLY = ACCESS_EXECUTE | ACCESS_READ_FILE | ACCESS_READ_DIR
READ_FILE_ONLY = ACCESS_READ_FILE
READ_WRITE_FILE = ACCESS_READ_FILE | ACCESS_WRITE_FILE
READ_WRITE_TREE = (
    READ_ONLY
    | ACCESS_WRITE_FILE
    | ACCESS_REMOVE_DIR
    | ACCESS_REMOVE_FILE
    | ACCESS_MAKE_CHAR
    | ACCESS_MAKE_DIR
    | ACCESS_MAKE_REG
    | ACCESS_MAKE_SOCK
    | ACCESS_MAKE_FIFO
    | ACCESS_MAKE_BLOCK
    | ACCESS_MAKE_SYM
    | ACCESS_REFER
    | ACCESS_TRUNCATE
)
HANDLED_ACCESS = READ_WRITE_TREE

_RUNTIME_TREES = ("/usr", "/usr/local", "/bin", "/lib", "/lib64")
_WRITABLE_TREES = (
    "/tmp/analyzer-home",  # noqa: S108 - fixed container-only path
    "/work/tmp",
)
_ETC_FILES = (
    "/etc/ld.so.cache",
    "/etc/nsswitch.conf",
    "/etc/passwd",
    "/etc/group",
    "/etc/localtime",
)
_READABLE_TREES = ("/proc",)
_READ_WRITE_FILES = ("/dev/null",)
_SYSCALLS = {
    "x86_64": (444, 445, 446),
    "amd64": (444, 445, 446),
    "aarch64": (444, 445, 446),
    "arm64": (444, 445, 446),
    "riscv64": (444, 445, 446),
}


class _RulesetAttr(ctypes.Structure):
    _fields_ = [("handled_access_fs", ctypes.c_uint64)]


class _PathBeneathAttr(ctypes.Structure):
    _fields_ = [
        ("allowed_access", ctypes.c_uint64),
        ("parent_fd", ctypes.c_int32),
    ]


@dataclass(frozen=True)
class SandboxRule:
    path: Path
    access: int


@dataclass(frozen=True)
class SandboxPolicy:
    rules: tuple[SandboxRule, ...]


def _syscall_numbers() -> tuple[int, int, int] | None:
    if sys.platform != "linux":
        return None
    return _SYSCALLS.get(platform.machine().lower())


def _libc() -> ctypes.CDLL:
    return ctypes.CDLL(None, use_errno=True)


def _syscall(number: int, *arguments: object) -> int:
    result = int(_libc().syscall(number, *arguments))
    if result == -1:
        error_number = ctypes.get_errno()
        raise OSError(error_number, os.strerror(error_number))
    return result


def landlock_abi() -> int:
    """Return the supported Landlock ABI, or zero when unavailable."""

    numbers = _syscall_numbers()
    if numbers is None:
        return 0
    try:
        return _syscall(numbers[0], None, 0, LANDLOCK_CREATE_RULESET_VERSION)
    except OSError as exc:
        if exc.errno in {errno.ENOSYS, errno.EOPNOTSUPP, errno.EINVAL}:
            return 0
        raise


def _existing_rule(path: str | os.PathLike[str], access: int) -> SandboxRule | None:
    try:
        resolved = Path(path).resolve(strict=True)
        metadata = resolved.lstat()
    except OSError:
        return None
    if stat.S_ISLNK(metadata.st_mode):
        return None
    if not (stat.S_ISDIR(metadata.st_mode) or stat.S_ISREG(metadata.st_mode)):
        return None
    return SandboxRule(resolved, access)


def build_policy(snapshot_root: str | os.PathLike[str]) -> SandboxPolicy:
    """Build the fixed filesystem allowlist; the import mount is never admitted."""

    snapshot_rule = _existing_rule(snapshot_root, READ_WRITE_TREE)
    if snapshot_rule is None or not snapshot_rule.path.is_dir():
        raise ValueError("sandbox snapshot root must be a real directory")
    candidates: list[SandboxRule] = [snapshot_rule]
    for path in _RUNTIME_TREES:
        rule = _existing_rule(path, READ_ONLY)
        if rule is not None:
            candidates.append(rule)
    for path in _WRITABLE_TREES:
        rule = _existing_rule(path, READ_WRITE_TREE)
        if rule is not None:
            candidates.append(rule)
    for path in _ETC_FILES:
        rule = _existing_rule(path, READ_FILE_ONLY)
        if rule is not None:
            candidates.append(rule)
    for path in _READABLE_TREES:
        rule = _existing_rule(path, ACCESS_READ_FILE | ACCESS_READ_DIR)
        if rule is not None:
            candidates.append(rule)
    for path in _READ_WRITE_FILES:
        rule = _existing_rule(path, READ_WRITE_FILE)
        if rule is not None:
            candidates.append(rule)

    unique: list[SandboxRule] = []
    seen: set[tuple[Path, int]] = set()
    for rule in candidates:
        identity = (rule.path, rule.access)
        if identity not in seen:
            seen.add(identity)
            unique.append(rule)
    return SandboxPolicy(tuple(unique))


def build_launcher_argv(
    argv: list[str], snapshot_root: str | os.PathLike[str], status_fd: int
) -> list[str]:
    """Construct the internal launcher argv without accepting shell syntax."""

    return [
        sys.executable,
        str(Path(__file__).resolve()),
        "--status-fd",
        str(status_fd),
        "--snapshot-root",
        os.fspath(snapshot_root),
        "--",
        *argv,
    ]


def apply_landlock(policy: SandboxPolicy) -> None:
    """Apply no-new-privileges and the complete path-beneath ruleset."""

    numbers = _syscall_numbers()
    if numbers is None or landlock_abi() < MIN_LANDLOCK_ABI:
        raise OSError(errno.EOPNOTSUPP, "required Landlock ABI is unavailable")
    ruleset_attr = _RulesetAttr(HANDLED_ACCESS)
    ruleset_fd = _syscall(
        numbers[0], ctypes.byref(ruleset_attr), ctypes.sizeof(ruleset_attr), 0
    )
    try:
        for rule in policy.rules:
            path_fd = os.open(
                rule.path,
                os.O_RDONLY
                | getattr(os, "O_PATH", 0)
                | getattr(os, "O_CLOEXEC", 0),
            )
            try:
                path_attr = _PathBeneathAttr(rule.access, path_fd)
                _syscall(
                    numbers[1],
                    ruleset_fd,
                    LANDLOCK_RULE_PATH_BENEATH,
                    ctypes.byref(path_attr),
                    0,
                )
            finally:
                os.close(path_fd)
        libc = _libc()
        if libc.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0:
            error_number = ctypes.get_errno()
            raise OSError(error_number, os.strerror(error_number))
        _syscall(numbers[2], ruleset_fd, 0)
    finally:
        os.close(ruleset_fd)


def _parse_launcher_args(arguments: list[str]) -> tuple[int, Path, list[str]]:
    if len(arguments) < 6 or arguments[0] != "--status-fd":
        raise ValueError("invalid sandbox launcher arguments")
    status_fd = int(arguments[1])
    if arguments[2] != "--snapshot-root" or "--" not in arguments[4:]:
        raise ValueError("invalid sandbox launcher arguments")
    separator = arguments.index("--", 4)
    command = arguments[separator + 1 :]
    if separator != 4 or not command:
        raise ValueError("invalid sandbox launcher arguments")
    return status_fd, Path(arguments[3]), command


def _main(arguments: list[str]) -> int:
    status_fd = -1
    try:
        status_fd, snapshot_root, command = _parse_launcher_args(arguments)
        os.set_inheritable(status_fd, False)
        os.write(status_fd, b"R")
        apply_landlock(build_policy(snapshot_root))
        os.execvpe(command[0], command, dict(os.environ))  # noqa: S606
    except BaseException:  # noqa: BLE001 - child must fail closed without a traceback
        if status_fd >= 0:
            try:
                os.write(status_fd, b"F")
            except OSError:
                pass
        return 125
    return 125


if __name__ == "__main__":
    raise SystemExit(_main(sys.argv[1:]))
