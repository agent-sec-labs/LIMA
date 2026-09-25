"""Read-only sensitive-artifact audit CLI for one local directory (IP-0020 v1.7).

Scans the ``*.json`` / ``*.txt`` files directly inside a caller-supplied
target directory and emits a single value-free JSON audit report: artifact
indices, member-ordinal positions, fingerprints, value kinds, lengths, and
policy evidence. Audited content is never printed, logged, or written
anywhere; file names never appear in any output surface -- artifacts are
identified by their lexicographic index ``a<n>`` (Packet §17.D1'.2).

Read-only contract (Packet §8.3): input files are only ever read; nothing
inside the target directory is created, modified, or deleted. The sole
permitted write is the explicit ``--output`` report file, which must resolve
outside the scanned directory. Files that fail strict UTF-8 decoding or JSON
parsing, plus symlinks, special files, and over-budget reads, are skipped
identifiably: one ``{"artifact": "a<n>", "error": <category>}`` stderr line
and one ``incomplete_reasons`` entry each; such runs end with status
``"incomplete"`` and exit code 3 (a normal completed-with-gaps exit, not an
error). Exit codes: 0 complete, 1 report-write failure, 2 parameter or
platform errors, 3 completed with gaps.

Safe-scan mechanics (Packet §17.B2'/F5', R10-R17): the script first probes
the platform for ``dir_fd``-bound ``os.open`` plus ``O_NOFOLLOW`` and
``O_NONBLOCK`` support and refuses to run (exit 2, no report) where they are
absent -- Windows users need a WSL/POSIX environment. The target directory
handle is acquired by a per-component openat chain anchored at ``/`` (or
``.`` for relative paths); every component is resolved relative to the
parent handle with ``O_DIRECTORY | O_NOFOLLOW``, so intermediate directory
symlinks and in-flight path substitution are rejected
(``target-invalid:<category>``). Each selected file is then read through the
frozen five-step sequence: one ``os.open`` with ``O_NOFOLLOW | O_NONBLOCK``
relative to the directory handle, one ``fstat`` behind a type gate
(``S_ISREG``) and an identity gate (``st_dev``/``st_ino`` match against the
no-follow entry stat), a bounded ``read(limit + 1)`` on that same handle, and
a single close path. Enumeration is single-pass over ``os.scandir(dir_fd)``
with a bounded lexicographic top-K selection over supported suffixes only;
directory budgets (files, bytes, findings) stop processing with exactly one
truncation summary each.

Offline fingerprint domain (Packet §17.D3', per-run random key): every run
generates a fresh 32-byte random tenant key via ``secrets.token_bytes``.
Fingerprints are usable for de-duplication and consistency checks within one
run only; they are not comparable across runs, provide no confidentiality,
guess-resistance, or tamper-evidence, and cannot be correlated with online
tenant fingerprints. Cross-run comparison requires a separately approved
protected-key design.

Dependencies: standard library plus ``lima.evidence_privacy.audit``; no
subprocess execution, no network, no shell.
"""

from __future__ import annotations

import argparse
import errno
import heapq
import json
import os
import secrets
import stat
import sys
from collections.abc import Sequence
from pathlib import Path, PurePath
from typing import Final

_REPO_ROOT: Final[Path] = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from lima.evidence_privacy.audit import (  # noqa: E402
    AuditFinding,
    TenantAuditContext,
    audit_report_to_json,
    audit_structured,
    audit_text,
    build_audit_report,
)
from lima.evidence_privacy.errors import PrivacyError  # noqa: E402
from lima.evidence_privacy.models import PrivacyLimits  # noqa: E402
from lima.evidence_privacy.policy import DEFAULT_POLICY  # noqa: E402

# D3' §17.D3': per-run random fingerprint domain; the label self-documents it.
_OFFLINE_TENANT_ID: Final[str] = "offline-audit"
_TENANT_CONTEXT_VALUE: Final[str] = "offline-audit/random-per-run"
_OFFLINE_TENANT_KEY_BYTES: Final[int] = 32

# R9/R14 §17.F5'-R9/R14: only supported suffixes enter the selection set.
_ARTIFACT_SUFFIXES: Final[frozenset[str]] = frozenset({".json", ".txt"})

# R2/R8/R15 §17.F5': script-layer scan budgets (library signature untouched).
max_files_per_scan: Final[int] = 10_000
max_total_bytes_per_scan: Final[int] = PrivacyLimits().max_payload_bytes * 100
max_report_findings: Final[int] = 10_000

# R13 §17.F5'-R13: the startup chain binds the pristine ``os.open`` once at
# import time so the security-critical component walk cannot be diverted by
# runtime attribute replacement; the per-artifact read path keeps using the
# live ``os.open`` attribute (single per-file open, test-observable).
_CHAIN_OPEN: Final = os.open

_TARGET_INVALID_PREFIX: Final[str] = "target-invalid:"
_SYMLINK_FINAL_MESSAGE: Final[str] = (
    "target-dir must not be a symlink path (target-invalid:symlink-component)"
)


class _TargetInvalid(Exception):
    """Startup-chain rejection; the single-line message names only the category."""

    def __init__(self, category: str, *, final_component: bool = False) -> None:
        if category == "symlink-component" and final_component:
            message = _SYMLINK_FINAL_MESSAGE
        else:
            message = f"{_TARGET_INVALID_PREFIX}{category}"
        super().__init__(message)
        self.category = category


def _warn(artifact: str, category: str) -> None:
    """One-line stderr warning carrying the artifact index and category only."""
    print(json.dumps({"artifact": artifact, "error": category}), file=sys.stderr)


def _finding_view(finding: AuditFinding) -> dict[str, object]:
    """Value-free JSON-shaped view of one finding (carries the fingerprint key)."""
    location = finding.location
    return {
        "fingerprint": finding.fingerprint,
        "length": finding.length,
        "value_kind": finding.value_kind,
        "location": {
            "source_path": location.source_path,
            "field_path": location.field_path,
            "span": (
                [location.span[0], location.span[1]]
                if location.span is not None
                else None
            ),
        },
    }


def _platform_supported() -> bool:
    """R10 §17.B2'-R10: dir_fd-bound opens plus both flags must exist (probe first).

    The membership test uses the import-time bound ``os.open`` (``_CHAIN_OPEN``)
    rather than the live attribute: ``os.supports_dir_fd`` is a set of function
    objects, so a replaced ``os.open`` attribute would otherwise be reported as
    lacking ``dir_fd`` support even on capable platforms.
    """
    return (
        _CHAIN_OPEN in os.supports_dir_fd
        and hasattr(os, "O_NOFOLLOW")
        and hasattr(os, "O_NONBLOCK")
    )


def _classify_chain_error(
    exc: OSError, component: str, parent_fd: int, *, final_component: bool
) -> _TargetInvalid:
    """R13/R17 §17.F5'-R13.3: errno classification, fail-closed on every branch.

    ``ENOTDIR`` runs exactly one diagnostic
    ``os.stat(component, dir_fd=parent_fd, follow_symlinks=False)``: a symlink
    classifies as ``symlink-component`` (some platforms return ``ENOTDIR``
    instead of ``ELOOP`` for directory symlinks under combined flags), a
    non-link non-directory as ``not-a-directory``, a failing diagnostic as
    ``io-error``. No branch retries the component open, follows the link, or
    reads any content.
    """
    if exc.errno == errno.ELOOP:
        return _TargetInvalid("symlink-component", final_component=final_component)
    if exc.errno == errno.ENOTDIR:
        try:
            diagnostic = os.stat(component, dir_fd=parent_fd, follow_symlinks=False)
        except OSError:
            return _TargetInvalid("io-error", final_component=final_component)
        if stat.S_ISLNK(diagnostic.st_mode):
            return _TargetInvalid("symlink-component", final_component=final_component)
        return _TargetInvalid("not-a-directory", final_component=final_component)
    if exc.errno in (errno.EACCES, errno.EPERM):
        return _TargetInvalid("permission-denied", final_component=final_component)
    if exc.errno == errno.ENOENT:
        return _TargetInvalid("not-found", final_component=final_component)
    return _TargetInvalid("io-error", final_component=final_component)


def _acquire_target_dir_fd(target_arg: str) -> int:
    """R13 §17.F5'-R13: per-component openat chain from an anchor fd.

    Absolute paths anchor at ``/``, relative paths at ``.`` (both anchors are
    structurally not symlinks); every component is then resolved relative to
    the parent handle with ``O_DIRECTORY | O_NOFOLLOW``, keeping at most two
    chain handles live. No ``resolve()`` and no by-path directory open is
    performed anywhere in the startup sequence.
    """
    parts = PurePath(target_arg).parts
    anchor = "/" if parts and parts[0] == "/" else "."
    try:
        parent_fd = _CHAIN_OPEN(anchor, os.O_RDONLY | os.O_DIRECTORY)
    except OSError:
        raise _TargetInvalid("io-error") from None
    last_index = len(parts) - 1
    try:
        for position, component in enumerate(parts):
            if component in ("/", ""):
                continue
            try:
                next_fd = _CHAIN_OPEN(
                    component,
                    os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                    dir_fd=parent_fd,
                )
            except OSError as exc:
                raise _classify_chain_error(
                    exc, component, parent_fd, final_component=position == last_index
                ) from None
            os.close(parent_fd)
            parent_fd = next_fd
    except BaseException:
        os.close(parent_fd)
        raise
    return parent_fd


class _ReverseName(str):
    """Ordering-inverted name so a min-heap of these keeps the largest evictable."""

    def __lt__(self, other: object) -> bool:
        return str.__gt__(self, other)

    def __le__(self, other: object) -> bool:
        return str.__ge__(self, other)


def _collect_selection(dir_fd: int) -> tuple[list[str], int]:
    """R9/R14: single-pass dirent enumeration with a bounded lexicographic top-K.

    The name-collection pass reads directory entries only -- zero ``stat``
    calls, zero file opens. Unsupported suffixes are silently out of scope
    (no quota, no index, no warning, no incomplete reason); supported-suffix
    names feed a capacity-``max_files_per_scan`` structure that keeps the
    lexicographically smallest subset. Returns the ascending selection and
    the supported-suffix entry count for the file-budget decision.
    """
    kept: list[_ReverseName] = []
    supported_count = 0
    with os.scandir(dir_fd) as entries:
        for entry in entries:
            name = entry.name
            if not name.endswith(tuple(sorted(_ARTIFACT_SUFFIXES))):
                continue
            supported_count += 1
            if len(kept) < max_files_per_scan:
                heapq.heappush(kept, _ReverseName(name))
            elif name < kept[0]:
                heapq.heapreplace(kept, _ReverseName(name))
    return sorted(str(item) for item in kept), supported_count


def _is_symlink(entry_stat: os.stat_result) -> bool:
    """B2' §17.B2': entry-level link check (S_IFLNK of the no-follow stat)."""
    return stat.S_ISLNK(entry_stat.st_mode)


def _read_artifacts(
    dir_fd: int,
    names: Sequence[str],
    *,
    context: TenantAuditContext | None = None,
) -> dict[str, object]:
    """R10/R11 seam: the frozen five-step read over one selection slice.

    ``names`` must already be in ``a<n>`` order (the caller's lexicographic
    selection); position ``i`` in the slice is artifact ``a{i}``. Each
    artifact goes through: the no-follow entry stat (symlink skip), exactly
    one ``os.open(name, O_RDONLY | O_NOFOLLOW | O_NONBLOCK, dir_fd=dir_fd)``,
    exactly one ``fstat`` behind the ``S_ISREG`` type gate and the
    ``(st_dev, st_ino)`` identity gate, one bounded ``read(limit + 1)`` on
    that same handle, and the single ``with``-block close path. The byte and
    findings budgets stop processing with exactly one truncation summary
    each. Returns a value-free result mapping (``artifact_count``,
    ``findings_by_artifact``, serialized ``findings``, ``incomplete_reasons``).
    """
    if context is None:
        context = TenantAuditContext(
            tenant_id=_OFFLINE_TENANT_ID,
            tenant_key=secrets.token_bytes(_OFFLINE_TENANT_KEY_BYTES),
        )
    read_limit = PrivacyLimits().max_payload_bytes
    reasons: list[str] = []
    findings_by_artifact: dict[str, tuple[AuditFinding, ...]] = {}
    finding_views: list[dict[str, object]] = []
    total_findings = 0
    total_bytes = 0
    findings_stop: str | None = None
    bytes_stop: str | None = None
    for index, name in enumerate(names):
        artifact = f"a{index}"
        # Step 0: no-follow entry stat for the symlink skip and gate-B identity.
        try:
            entry_stat = os.stat(name, dir_fd=dir_fd, follow_symlinks=False)
        except OSError:
            _warn(artifact, "io-error")
            reasons.append(f"{artifact}:io-error")
            findings_by_artifact[artifact] = ()
            if total_bytes > max_total_bytes_per_scan:
                bytes_stop = artifact
                break
            continue
        if _is_symlink(entry_stat):
            _warn(artifact, "symlink-skipped")
            reasons.append(f"{artifact}:symlink-skipped")
            findings_by_artifact[artifact] = ()
            continue
        # Step 1: the single per-artifact open. O_NONBLOCK makes FIFO and
        # device opens return immediately instead of blocking before fstat.
        try:
            fd = os.open(
                name,
                os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                dir_fd=dir_fd,
            )
        except OSError:
            _warn(artifact, "io-error")
            reasons.append(f"{artifact}:io-error")
            findings_by_artifact[artifact] = ()
            if total_bytes > max_total_bytes_per_scan:
                bytes_stop = artifact
                break
            continue
        # Step 2: one fstat, two gates (R11 type gate, R3 identity gate).
        try:
            fd_stat = os.fstat(fd)
        except OSError:
            os.close(fd)
            _warn(artifact, "io-error")
            reasons.append(f"{artifact}:io-error")
            findings_by_artifact[artifact] = ()
            continue
        if not stat.S_ISREG(fd_stat.st_mode):
            os.close(fd)
            _warn(artifact, "special-file")
            reasons.append(f"{artifact}:special-file")
            findings_by_artifact[artifact] = ()
            continue
        if fd_stat.st_ino == 0 or (fd_stat.st_dev, fd_stat.st_ino) != (
            entry_stat.st_dev,
            entry_stat.st_ino,
        ):
            os.close(fd)
            _warn(artifact, "symlink-risk")
            reasons.append(f"{artifact}:symlink-risk")
            findings_by_artifact[artifact] = ()
            continue
        # Steps 3+4: bounded read on the same handle; the with block is the
        # sole close path. The handle-read length is the budget evidence.
        with os.fdopen(fd, "rb") as handle:
            data = handle.read(read_limit + 1)
        total_bytes += len(data)
        if len(data) > read_limit:
            _warn(artifact, "resource-limit")
            reasons.append(f"{artifact}:resource-limit")
            findings_by_artifact[artifact] = ()
            if total_bytes > max_total_bytes_per_scan:
                bytes_stop = artifact
                break
            continue
        try:
            if name.endswith(".json"):
                value = json.loads(data.decode("utf-8"))
                batch = audit_structured(artifact, value, DEFAULT_POLICY, context=context)
            else:
                text = data.decode("utf-8")
                batch = audit_text(artifact, text, DEFAULT_POLICY, context=context)
        except UnicodeDecodeError:
            _warn(artifact, "undecodable-text")
            reasons.append(f"{artifact}:undecodable-text")
            findings_by_artifact[artifact] = ()
            if total_bytes > max_total_bytes_per_scan:
                bytes_stop = artifact
                break
            continue
        except ValueError:
            _warn(artifact, "unparseable-json")
            reasons.append(f"{artifact}:unparseable-json")
            findings_by_artifact[artifact] = ()
            if total_bytes > max_total_bytes_per_scan:
                bytes_stop = artifact
                break
            continue
        except PrivacyError:
            # A typed library budget rejection for one file (F5' §17.F5'):
            # file-level identifiability, never a silent skip.
            _warn(artifact, "resource-limit")
            reasons.append(f"{artifact}:resource-limit")
            findings_by_artifact[artifact] = ()
            if total_bytes > max_total_bytes_per_scan:
                bytes_stop = artifact
                break
            continue
        # R15 §17.F5'-R15: report-level findings cap. A partial take keeps the
        # first ``remaining`` findings of this batch and records the last
        # fully processed artifact; an exact fit records this artifact.
        remaining = max_report_findings - total_findings
        if len(batch) > remaining:
            kept_batch = batch[:remaining]
            findings_by_artifact[artifact] = kept_batch
            total_findings += len(kept_batch)
            finding_views.extend(_finding_view(item) for item in kept_batch)
            findings_stop = f"a{index - 1}"
            break
        findings_by_artifact[artifact] = batch
        total_findings += len(batch)
        finding_views.extend(_finding_view(item) for item in batch)
        if total_findings >= max_report_findings:
            findings_stop = artifact
            break
        if total_bytes > max_total_bytes_per_scan:
            bytes_stop = artifact
            break
    if findings_stop is not None:
        summary = f"scan:findings-budget:truncated-at={findings_stop}"
        reasons.append(summary)
        print(summary, file=sys.stderr)
    if bytes_stop is not None:
        summary = f"scan:byte-budget:truncated-at={bytes_stop}"
        reasons.append(summary)
        print(summary, file=sys.stderr)
    return {
        "artifact_count": len(names),
        "findings_by_artifact": findings_by_artifact,
        "findings": finding_views,
        "incomplete_reasons": tuple(reasons),
    }


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="audit_sensitive_artifacts.py",
        description=(
            "Read-only sensitive-artifact audit: scan one directory and print "
            "(or write via --output) a value-free JSON report."
        ),
    )
    parser.add_argument(
        "target_dir",
        metavar="target-dir",
        help="existing local directory to scan (never modified)",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help="explicit report path; must resolve outside the target directory",
    )
    parser.add_argument(
        "--pretty",
        action="store_true",
        help="indent the JSON report instead of the canonical single line",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """CLI entry: 0 complete, 1 report-write failure, 2 parameter/platform, 3 gaps."""
    parser = _build_parser()
    args = parser.parse_args(argv)
    # R10 §17.B2'-R10: the capability probe runs before any scan work; where
    # safe-scan primitives are absent the script refuses to run (exit 2, no
    # report output, single stderr line).
    if not _platform_supported():
        print("error: platform-unsupported-safe-scan", file=sys.stderr)
        return 2
    output_resolved: Path | None = None
    if args.output is not None:
        target_resolved = Path(args.target_dir).resolve()
        output_resolved = Path(args.output).resolve()
        if (
            output_resolved == target_resolved
            or target_resolved in output_resolved.parents
        ):
            print(
                "error: --output path must resolve outside the scanned target "
                f"directory: {output_resolved}",
                file=sys.stderr,
            )
            return 2
    # R13: the component chain yields the directory handle or a single-line
    # target-invalid rejection (caller-supplied paths may be echoed).
    try:
        dir_fd = _acquire_target_dir_fd(args.target_dir)
    except _TargetInvalid as rejection:
        print(f"error: {rejection}", file=sys.stderr)
        return 2
    try:
        names, supported_count = _collect_selection(dir_fd)
        context = TenantAuditContext(
            tenant_id=_OFFLINE_TENANT_ID,
            tenant_key=secrets.token_bytes(_OFFLINE_TENANT_KEY_BYTES),
        )
        scan = _read_artifacts(dir_fd, names, context=context)
    finally:
        os.close(dir_fd)
    reasons = list(scan["incomplete_reasons"])
    # R8/R9 §17.F5'-R2.2': more supported-suffix entries than the selection
    # capacity -> exactly one fixed-shape file-budget summary after the scan.
    if supported_count > max_files_per_scan:
        summary = f"scan:file-budget:truncated-at=a{max_files_per_scan - 1}"
        reasons.append(summary)
        print(summary, file=sys.stderr)
    report = build_audit_report(
        context, scan["findings_by_artifact"], DEFAULT_POLICY
    )
    payload = json.loads(audit_report_to_json(report))
    payload["tenant_context"] = _TENANT_CONTEXT_VALUE
    payload["incomplete_reasons"] = reasons
    payload["status"] = "incomplete" if reasons else "complete"
    if args.pretty:
        serialized = json.dumps(payload, ensure_ascii=False, sort_keys=True, indent=2)
    else:
        serialized = json.dumps(
            payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")
        )
    if output_resolved is None:
        print(serialized)
        return 3 if reasons else 0
    try:
        output_resolved.write_text(serialized + "\n", encoding="utf-8")
    except OSError as write_error:
        print(
            f"error: cannot write report file: {write_error.strerror}",
            file=sys.stderr,
        )
        return 1
    return 3 if reasons else 0


if __name__ == "__main__":
    sys.exit(main())
