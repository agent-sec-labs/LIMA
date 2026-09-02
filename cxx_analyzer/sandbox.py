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
PR_SET_CHILD_SUBREAPER: Final = 36
PR_SET_SECCOMP: Final = 22
SECCOMP_MODE_FILTER: Final = 2
SECCOMP_RET_KILL_PROCESS: Final = 0x80000000
SECCOMP_RET_ALLOW: Final = 0x7FFF0000
SECCOMP_RET_ERRNO: Final = 0x00050000
BPF_LD_W_ABS: Final = 0x20
BPF_JMP_JEQ_K: Final = 0x15
BPF_RET_K: Final = 0x06
# seccomp_data argument words start after nr, arch and the instruction pointer.
SECCOMP_ARG_OFFSET: Final = 16

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
_SECCOMP_ARCH = {
    "x86_64": 0xC000003E,
    "amd64": 0xC000003E,
    "aarch64": 0xC00000B7,
    "arm64": 0xC00000B7,
    "riscv64": 0xC00000F3,
}
_BLOCKED_PROCESS_SYSCALLS = {
    "x86_64": frozenset(
        {
            62,  # kill
            101,  # ptrace
            109,  # setpgid
            112,  # setsid
            129,  # rt_sigqueueinfo
            200,  # tkill
            234,  # tgkill
            272,  # unshare
            297,  # rt_tgsigqueueinfo
            308,  # setns
            310,  # process_vm_readv
            311,  # process_vm_writev
            312,  # kcmp
            424,  # pidfd_send_signal
            435,  # clone3
            438,  # pidfd_getfd
            440,  # process_madvise
        }
    ),
    "aarch64": frozenset(
        {
            97,  # unshare
            117,  # ptrace
            129,  # kill
            130,  # tkill
            131,  # tgkill
            138,  # rt_sigqueueinfo
            154,  # setpgid
            157,  # setsid
            240,  # rt_tgsigqueueinfo
            268,  # setns
            270,  # process_vm_readv
            271,  # process_vm_writev
            272,  # kcmp
            424,  # pidfd_send_signal
            435,  # clone3 (asm-generic numbering, like riscv64)
            438,  # pidfd_getfd
            440,  # process_madvise
        }
    ),
    "riscv64": frozenset(
        {
            97, 117, 129, 130, 131, 138, 154, 157, 240, 268, 270, 271,
            272, 424, 435, 438, 440,
        }
    ),
}
# Same-UID process control syscalls that stay usable for the caller itself:
# prlimit64 is allowed only while the target pid argument is zero (self).
_ARG_GUARDED_SYSCALLS = {
    "x86_64": {302: 0},
    "aarch64": {261: 0},
    "riscv64": {261: 0},
}
# clone3 reports ENOSYS instead of EPERM so glibc >= 2.34 falls back to
# plain clone for pthread_create instead of failing thread creation.
_BLOCKED_SYSCALL_ERRNOS = {
    435: errno.ENOSYS,  # clone3 on every supported architecture
}


class _RulesetAttr(ctypes.Structure):
    _fields_ = [("handled_access_fs", ctypes.c_uint64)]


class _PathBeneathAttr(ctypes.Structure):
    _fields_ = [
        ("allowed_access", ctypes.c_uint64),
        ("parent_fd", ctypes.c_int32),
    ]


class _SockFilter(ctypes.Structure):
    _fields_ = [
        ("code", ctypes.c_ushort),
        ("jt", ctypes.c_ubyte),
        ("jf", ctypes.c_ubyte),
        ("k", ctypes.c_uint32),
    ]


class _SockFprog(ctypes.Structure):
    _fields_ = [
        ("length", ctypes.c_ushort),
        ("filter", ctypes.POINTER(_SockFilter)),
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


def process_isolation_available() -> bool:
    """Return whether this architecture has the audited seccomp denylist."""

    machine = platform.machine().lower()
    if machine == "amd64":
        machine = "x86_64"
    elif machine == "arm64":
        machine = "aarch64"
    return (
        sys.platform == "linux"
        and machine in _SECCOMP_ARCH
        and machine in _BLOCKED_PROCESS_SYSCALLS
    )


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


def build_policy(
    snapshot_root: str | os.PathLike[str],
    writable_roots: tuple[str | os.PathLike[str], ...] = (),
) -> SandboxPolicy:
    """Build the fixed filesystem allowlist; the import mount is never admitted."""

    snapshot_rule = _existing_rule(snapshot_root, READ_ONLY)
    if snapshot_rule is None or not snapshot_rule.path.is_dir():
        raise ValueError("sandbox snapshot root must be a real directory")
    candidates: list[SandboxRule] = [snapshot_rule]
    for path in _RUNTIME_TREES:
        rule = _existing_rule(path, READ_ONLY)
        if rule is not None:
            candidates.append(rule)
    snapshot_path = snapshot_rule.path
    for path in writable_roots:
        rule = _existing_rule(path, READ_WRITE_TREE)
        if rule is None or not rule.path.is_dir():
            raise ValueError("sandbox writable root must be a real directory")
        if rule.path == snapshot_path:
            raise ValueError("verified source root must never be writable")
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
    argv: list[str],
    snapshot_root: str | os.PathLike[str],
    status_fd: int,
    writable_roots: tuple[str | os.PathLike[str], ...] = (),
) -> list[str]:
    """Construct the internal launcher argv without accepting shell syntax."""

    result = [
        sys.executable,
        str(Path(__file__).resolve()),
        "--status-fd",
        str(status_fd),
        "--snapshot-root",
        os.fspath(snapshot_root),
    ]
    for root in writable_roots:
        result.extend(("--writable-root", os.fspath(root)))
    result.extend(("--", *argv))
    return result


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


def install_subreaper() -> bool:
    """Adopt orphaned tool descendants so the boundary can reap them."""

    if sys.platform != "linux":
        return False
    if _libc().prctl(PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) != 0:
        error_number = ctypes.get_errno()
        raise OSError(error_number, os.strerror(error_number))
    return True


def apply_process_isolation() -> None:
    """Deny process-group escape and same-UID peer process control."""

    machine = platform.machine().lower()
    if machine == "amd64":
        machine = "x86_64"
    elif machine == "arm64":
        machine = "aarch64"
    audit_arch = _SECCOMP_ARCH.get(machine)
    blocked = _BLOCKED_PROCESS_SYSCALLS.get(machine)
    guarded = _ARG_GUARDED_SYSCALLS.get(machine)
    if (
        sys.platform != "linux"
        or audit_arch is None
        or blocked is None
        or guarded is None
    ):
        raise OSError(errno.EOPNOTSUPP, "required process isolation is unavailable")

    instructions: list[_SockFilter] = [
        _SockFilter(BPF_LD_W_ABS, 0, 0, 4),
        _SockFilter(BPF_JMP_JEQ_K, 1, 0, audit_arch),
        _SockFilter(BPF_RET_K, 0, 0, SECCOMP_RET_KILL_PROCESS),
        _SockFilter(BPF_LD_W_ABS, 0, 0, 0),
    ]
    for syscall_number in sorted(blocked):
        error_number = _BLOCKED_SYSCALL_ERRNOS.get(syscall_number, errno.EPERM)
        instructions.extend(
            (
                _SockFilter(BPF_JMP_JEQ_K, 0, 1, syscall_number),
                _SockFilter(BPF_RET_K, 0, 0, SECCOMP_RET_ERRNO | error_number),
            )
        )
    for syscall_number, argument_index in sorted(guarded.items()):
        # Allow the syscall only when the target pid word is exactly zero.
        low_offset = SECCOMP_ARG_OFFSET + 8 * argument_index
        match = len(instructions)
        instructions.append(_SockFilter(BPF_JMP_JEQ_K, 0, 0, syscall_number))
        guard_start = len(instructions)
        instructions.extend(
            (
                _SockFilter(BPF_LD_W_ABS, 0, 0, low_offset),
                _SockFilter(BPF_JMP_JEQ_K, 0, 2, 0),
                _SockFilter(BPF_LD_W_ABS, 0, 0, low_offset + 4),
                _SockFilter(BPF_JMP_JEQ_K, 1, 0, 0),
                _SockFilter(BPF_RET_K, 0, 0, SECCOMP_RET_ERRNO | errno.EPERM),
                _SockFilter(BPF_RET_K, 0, 0, SECCOMP_RET_ALLOW),
            )
        )
        guard_end = len(instructions)
        instructions[match] = _SockFilter(
            BPF_JMP_JEQ_K,
            guard_start - (match + 1),
            guard_end - (match + 1),
            syscall_number,
        )
    instructions.append(_SockFilter(BPF_RET_K, 0, 0, SECCOMP_RET_ALLOW))
    program_array = (_SockFilter * len(instructions))(*instructions)
    program = _SockFprog(len(instructions), program_array)
    libc = _libc()
    if libc.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0:
        error_number = ctypes.get_errno()
        raise OSError(error_number, os.strerror(error_number))
    if libc.prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, ctypes.byref(program)) != 0:
        error_number = ctypes.get_errno()
        raise OSError(error_number, os.strerror(error_number))


def _parse_launcher_args(
    arguments: list[str],
) -> tuple[int, Path, tuple[Path, ...], list[str]]:
    if len(arguments) < 6 or arguments[0] != "--status-fd":
        raise ValueError("invalid sandbox launcher arguments")
    status_fd = int(arguments[1])
    if arguments[2] != "--snapshot-root" or "--" not in arguments[4:]:
        raise ValueError("invalid sandbox launcher arguments")
    separator = arguments.index("--", 4)
    writable_arguments = arguments[4:separator]
    if len(writable_arguments) % 2 or any(
        writable_arguments[index] != "--writable-root"
        for index in range(0, len(writable_arguments), 2)
    ):
        raise ValueError("invalid sandbox launcher arguments")
    writable_roots = tuple(
        Path(writable_arguments[index])
        for index in range(1, len(writable_arguments), 2)
    )
    command = arguments[separator + 1 :]
    if not command:
        raise ValueError("invalid sandbox launcher arguments")
    return status_fd, Path(arguments[3]), writable_roots, command


def _main(arguments: list[str]) -> int:
    status_fd = -1
    try:
        status_fd, snapshot_root, writable_roots, command = _parse_launcher_args(arguments)
        os.set_inheritable(status_fd, False)
        apply_landlock(build_policy(snapshot_root, writable_roots))
        apply_process_isolation()
        os.write(status_fd, b"R")
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
