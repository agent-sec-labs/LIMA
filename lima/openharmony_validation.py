"""OpenHarmony dual-revision validation pilot.

This module owns the frozen case contract (``openharmony-validation-v1``):
one closed-schema manifest pinning the vulnerable/fixed commit pair of a
public OpenHarmony CWE-416 advisory, plus the loader that refuses every
deviation (unknown fields, unsafe paths, non-pinned provenance).  Later
tasks extend the module with checkout preflight, the paired run and the
evidence bundle writer.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Final

SCHEMA_VERSION: Final = "openharmony-validation-v1"
CASE_CWE: Final = "CWE-416"
CASE_BUILD_CONTEXT_MODE: Final = "snapshot-compdb"

OVERLAY_ROOT: Final = "_overlay/"
OVERLAY_ROLES: Final = frozenset({"dependency-header"})

CASE_FIELDS: Final = frozenset({
    "schema_version", "case_id", "repository", "component", "cve_id", "cwe",
    "vulnerable", "fixed", "translation_units", "target_paths",
    "build_context_mode", "advisory_urls", "patch_paths", "remediation",
    "license", "dependency_overlay",
})
REVISION_FIELDS: Final = frozenset({"repository_key", "commit", "version"})
OVERLAY_FIELDS: Final = frozenset({
    "path", "sha256", "role", "upstream_repo", "upstream_commit", "license",
    "note",
})
OPTIONAL_FIELDS: Final = frozenset({"dependency_overlay"})

_MAX_CASE_FILE_BYTES: Final = 256 * 1024
_MAX_TEXT_BYTES: Final = 8 * 1024
_MAX_REMEDIATION_BYTES: Final = 32 * 1024
_MAX_LIST_ITEMS: Final = 16

_SHA40_RE: Final = re.compile(r"[0-9a-f]{40}\Z")
_SHA256_RE: Final = re.compile(r"[0-9a-f]{64}\Z")
_CVE_ID_RE: Final = re.compile(r"CVE-\d{4}-\d{4,}\Z")
_HTTPS_RE: Final = re.compile(r"https://[^\s\"']+\Z")
_REPO_KEY_RE: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z")
_DRIVE_RE: Final = re.compile(r"^[A-Za-z]:")
_C_EXTENSIONS: Final = frozenset({".c", ".cc", ".cpp", ".cxx"})


@dataclass(frozen=True)
class OpenHarmonyRevision:
    """One pinned snapshot: the import-root key and its exact commit."""

    repository_key: str
    commit: str
    version: str


@dataclass(frozen=True)
class DependencyOverlayEntry:
    """One digest-pinned out-of-repo dependency header staged under _overlay/."""

    path: str
    sha256: str
    role: str
    upstream_repo: str
    upstream_commit: str
    license: str
    note: str


@dataclass(frozen=True)
class OpenHarmonyCase:
    """The decoded, deviation-free pilot manifest."""

    schema_version: str
    case_id: str
    repository: str
    component: str
    cve_id: str
    cwe: str
    vulnerable: OpenHarmonyRevision
    fixed: OpenHarmonyRevision
    translation_units: tuple[str, ...]
    target_paths: tuple[str, ...]
    build_context_mode: str
    advisory_urls: tuple[str, ...]
    patch_paths: tuple[str, ...]
    remediation: str
    license: str
    dependency_overlay: tuple[DependencyOverlayEntry, ...] = ()


def _fail(message: str) -> None:
    raise ValueError(f"OpenHarmony case manifest: {message}")


def _bounded_text(value: object, field: str, limit: int) -> str:
    if not isinstance(value, str) or not value:
        _fail(f"{field} must be non-empty text")
    if len(value.encode("utf-8")) > limit:
        _fail(f"{field} exceeds {limit} UTF-8 bytes")
    return value


def _https_url(value: object, field: str) -> str:
    text = _bounded_text(value, field, _MAX_TEXT_BYTES)
    if not _HTTPS_RE.match(text):
        _fail(f"{field} must be an HTTPS URL")
    return text


def _safe_relative_path(value: object, field: str) -> str:
    text = _bounded_text(value, field, _MAX_TEXT_BYTES)
    if "\\" in text or text.startswith("/") or _DRIVE_RE.match(text):
        _fail(f"{field} must be a relative POSIX path: {text!r}")
    if any(segment in ("", ".", "..") for segment in text.split("/")):
        _fail(f"{field} must not contain empty, . or .. segments: {text!r}")
    return text


def _bounded_list(value: object, field: str) -> list:
    if not isinstance(value, list) or not value:
        _fail(f"{field} must be a non-empty list")
    if len(value) > _MAX_LIST_ITEMS:
        _fail(f"{field} exceeds {_MAX_LIST_ITEMS} entries")
    return value


def _sha40(value: object, field: str) -> str:
    if not isinstance(value, str) or not _SHA40_RE.match(value):
        _fail(f"{field} must be a 40-character lowercase hex commit")
    return value


def _no_duplicate_keys(pairs: list[tuple[str, object]]) -> dict:
    seen: set[str] = set()
    for key, _value in pairs:
        if key in seen:
            raise ValueError(f"duplicate JSON key {key!r}")
        seen.add(key)
    return dict(pairs)


def _reject_constant(name: str) -> object:
    raise ValueError(f"JSON constant {name} is not allowed")


def _load_manifest_json(path: Path) -> object:
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise ValueError(f"cannot read case manifest {path.name}: {exc}") from exc
    if not raw or len(raw) > _MAX_CASE_FILE_BYTES:
        _fail(f"manifest must be 1..{_MAX_CASE_FILE_BYTES} bytes")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError(f"case manifest must be UTF-8: {exc}") from exc
    try:
        return json.loads(
            text,
            object_pairs_hook=_no_duplicate_keys,
            parse_constant=_reject_constant,
        )
    except ValueError as exc:
        raise ValueError(f"invalid case manifest JSON: {exc}") from exc


def _decode_cve_id(value: object) -> str:
    text = _bounded_text(value, "cve_id", _MAX_TEXT_BYTES)
    if not _CVE_ID_RE.match(text):
        _fail("cve_id must match CVE-YYYY-NNNN+")
    return text


def _decode_revision(value: object, field: str) -> OpenHarmonyRevision:
    if not isinstance(value, dict) or set(value) != REVISION_FIELDS:
        _fail(f"{field} must hold exactly {sorted(REVISION_FIELDS)}")
    key = value["repository_key"]
    if not isinstance(key, str) or not _REPO_KEY_RE.match(key):
        _fail(f"{field}.repository_key must be a safe single-segment key")
    return OpenHarmonyRevision(
        repository_key=key,
        commit=_sha40(value["commit"], f"{field}.commit"),
        version=_bounded_text(value["version"], f"{field}.version",
                              _MAX_TEXT_BYTES),
    )


def _decode_overlay_entry(value: object) -> DependencyOverlayEntry:
    if not isinstance(value, dict) or set(value) != OVERLAY_FIELDS:
        _fail(f"dependency_overlay entry must hold exactly "
              f"{sorted(OVERLAY_FIELDS)}")
    path = _safe_relative_path(value["path"], "dependency_overlay.path")
    if not path.startswith(OVERLAY_ROOT) or path == OVERLAY_ROOT:
        _fail(f"dependency_overlay.path must live under {OVERLAY_ROOT}")
    role = value["role"]
    if role not in OVERLAY_ROLES:
        _fail(f"dependency_overlay.role must be one of {sorted(OVERLAY_ROLES)}")
    sha = value["sha256"]
    if not isinstance(sha, str) or not _SHA256_RE.match(sha):
        _fail("dependency_overlay.sha256 must be 64 lowercase hex characters")
    note = value["note"]
    if not isinstance(note, str) or len(note.encode("utf-8")) > _MAX_TEXT_BYTES:
        _fail("dependency_overlay.note must be bounded text")
    return DependencyOverlayEntry(
        path=path,
        sha256=sha,
        role=role,
        upstream_repo=_https_url(
            value["upstream_repo"], "dependency_overlay.upstream_repo"),
        upstream_commit=_sha40(
            value["upstream_commit"], "dependency_overlay.upstream_commit"),
        license=_bounded_text(
            value["license"], "dependency_overlay.license", _MAX_TEXT_BYTES),
        note=note,
    )


def load_openharmony_case(path: str | Path) -> OpenHarmonyCase:
    """Decode and validate one closed-schema pilot manifest."""
    payload = _load_manifest_json(Path(path))
    if not isinstance(payload, dict):
        _fail("top level must be a JSON object")
    unknown = set(payload) - CASE_FIELDS
    if unknown:
        _fail(f"unknown fields {sorted(unknown)}")
    missing = CASE_FIELDS - OPTIONAL_FIELDS - set(payload)
    if missing:
        _fail(f"missing fields {sorted(missing)}")
    if payload["schema_version"] != SCHEMA_VERSION:
        _fail(f"schema_version must be {SCHEMA_VERSION}")
    if payload["cwe"] != CASE_CWE:
        _fail(f"cwe must be exactly {CASE_CWE}")
    if payload["build_context_mode"] != CASE_BUILD_CONTEXT_MODE:
        _fail(f"build_context_mode must be {CASE_BUILD_CONTEXT_MODE}")

    vulnerable = _decode_revision(payload["vulnerable"], "vulnerable")
    fixed = _decode_revision(payload["fixed"], "fixed")
    if vulnerable.repository_key == fixed.repository_key:
        _fail("vulnerable and fixed must use different repository keys")

    units: list[str] = []
    for unit in _bounded_list(payload["translation_units"],
                              "translation_units"):
        text = _safe_relative_path(unit, "translation_units")
        if Path(text).suffix not in _C_EXTENSIONS:
            _fail(f"translation unit must be C/C++: {text!r}")
        units.append(text)
    targets = [
        _safe_relative_path(item, "target_paths")
        for item in _bounded_list(payload["target_paths"], "target_paths")
    ]
    patches = [
        _safe_relative_path(item, "patch_paths")
        for item in _bounded_list(payload["patch_paths"], "patch_paths")
    ]
    advisories = [
        _https_url(item, "advisory_urls")
        for item in _bounded_list(payload["advisory_urls"], "advisory_urls")
    ]

    overlay_payload = payload.get("dependency_overlay")
    overlay: tuple[DependencyOverlayEntry, ...] = ()
    if overlay_payload is not None:
        entries = [
            _decode_overlay_entry(entry)
            for entry in _bounded_list(overlay_payload,
                                       "dependency_overlay")
        ]
        if len({entry.path for entry in entries}) != len(entries):
            _fail("dependency_overlay paths must be unique")
        overlay = tuple(sorted(entries, key=lambda entry: entry.path))

    return OpenHarmonyCase(
        schema_version=payload["schema_version"],
        case_id=_bounded_text(payload["case_id"], "case_id", _MAX_TEXT_BYTES),
        repository=_https_url(payload["repository"], "repository"),
        component=_bounded_text(payload["component"], "component",
                                _MAX_TEXT_BYTES),
        cve_id=_decode_cve_id(payload["cve_id"]),
        cwe=payload["cwe"],
        vulnerable=vulnerable,
        fixed=fixed,
        translation_units=tuple(sorted(set(units))),
        target_paths=tuple(sorted(set(targets))),
        build_context_mode=payload["build_context_mode"],
        advisory_urls=tuple(sorted(set(advisories))),
        patch_paths=tuple(sorted(set(patches))),
        remediation=_bounded_text(payload["remediation"], "remediation",
                                  _MAX_REMEDIATION_BYTES),
        license=_bounded_text(payload["license"], "license", _MAX_TEXT_BYTES),
        dependency_overlay=overlay,
    )
