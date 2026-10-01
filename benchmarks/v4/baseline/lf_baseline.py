"""Fixed-SHA LlamaFactory local baseline entry for LIMA v4 (IP-0043, Issue #257).

This module composes the frozen upstream faces read-only into the formal
offline entry :func:`run_lf_local_baseline_suite` (Packet
docs/LIMA_Implementation_Packet_IP-0043_LF_Local_Baseline.md): the sealed
LlamaFactory source archive pinned at commit
``7fcf5b3b130e5713b52415bb7404c476fada9c8c`` is reused strictly read-only,
every cold attempt re-materializes a fresh working copy from the archive
into an internal temporary workspace and truly re-scans it with the real
local ``RepositoryScanner`` under the explicit offline configuration (SAST
engines, the C/C++ memory analyzer, the platform agent chain and every LLM
factory explicitly disabled -- never ambient defaults), and every warm
attempt honestly reuses the last cold snapshot and scanner result (recorded
truthfully in the per-attempt receipts, never claimed as a re-scan).

Identity is fail-closed on three layers (Packet R2): the run-specific
schema-v1 source-binding document is checked for shape and for agreement
with the pinned external identity (repository, commit SHA, dataset name and
role), then cross-validated through the frozen spec layer
(``spec_from_mapping`` + ``validate_baseline_manifest``), and finally every
cold materialization is verified against the declared snapshot tree
fingerprint computed locally from the extracted bytes.  A missing archive,
an archive hash mismatch, a snapshot tree mismatch, an identity conflict, an
invalid binding shape, a non-empty output directory or an invalid
cold/warm parameter each terminates with its own typed ``LFSourceError``
code; the four identity codes additionally carry ``needs_decision`` (the
tenth-round ruling semantics: only this scan is blocked, nothing is
re-downloaded and the pinned SHA is never replaced).

The entry does NOT route through ``run_baseline_attempt``/``run_repeats``:
the SF-01 frozen dataset registry only binds the three frozen
popular-python datasets and would reject the run-specific LF dataset name.
Instead the frozen identity/aggregation/persistence primitives are reused
directly: ``spec_from_mapping`` + ``validate_baseline_manifest`` (identity
layer), ``result_from_mapping`` (nearest-rank aggregation and status),
``write_result_file``/``write_exclusive`` (exclusive artifact naming) and
``PlatformSources``/``elapsed_ms``/``require_metric``/``classify_failure``
(collection and the bounded failure taxonomy).  A corrupt-but-hash-pinned
archive fails every attempt body without raising: the failure samples stay
in the aggregate denominator under the frozen taxonomy instead of being
dropped.

The workload is zero-model by construction: there is no wire client, no
request building and no approval surface anywhere in this module, every
sample carries integer-zero prompt/completion/cost faces, and
``model_calls`` is the constant ``0``.

The scanner payload handed to the frozen ``build_baseline_report`` scanner
path is the canonical projection of the scan output: the materialization
root labels (``report.repository`` and ``workspace.root``) are replaced by
the frozen stable external identity
``external/llamafactory-replay@7fcf5b3b``, so the scanner wire digest (the
frozen sorted-key compact UTF-8 JSON SHA-256 rule) and the run identity
faces depend only on the snapshot content, the analyzer configuration, the
workload and the seed -- never on the temporary directory location
(DR-C2 Option A: the same layout projects to one wire digest across
directories and cannot collide with the existing frozen families).

Everything here is offline and deterministic: zero model calls, zero
network, zero credentials, zero ambient reads, and writes go only into the
caller-provided output directory plus internal temporary workspaces.  The
LF suite is local-scanner wiring evidence over the sealed snapshot, not
real model acceptance evidence.
"""

import dataclasses
import enum
import hashlib
import json
import os
import pathlib
import tarfile
import tempfile
import typing

from benchmarks.v4.baseline.collect import (
    PlatformSources,
    classify_failure,
    elapsed_ms,
    require_metric,
)
from benchmarks.v4.baseline.orchestrate import BaselineRunSummary
from benchmarks.v4.baseline.report import build_baseline_report, write_report_file
from benchmarks.v4.baseline.run import write_exclusive, write_result_file
from lima.baseline_run_result import from_mapping as result_from_mapping
from lima.baseline_run_spec import BaselineRunSpecError, validate_baseline_manifest
from lima.baseline_run_spec import from_mapping as spec_from_mapping
from lima.contracts.codec import canonical_encode, compute_content_digest
from lima.repository_scanner import RepositoryScanner, RepositoryScanResult
from lima.reviewer import SecurityRuleReviewer
from lima.workspace import RepositoryWorkspace

__all__ = [
    "LF_CANONICAL_LABEL",
    "LF_DATASET_NAME",
    "LF_DATASET_ROLE",
    "LF_REPOSITORY_IDENTITY",
    "LFSourceError",
    "LFSourceErrorCode",
    "LF_SUITE_RESULT_VERSION",
    "LFSuiteResult",
    "LF_TARGET_COMMIT_SHA",
    "LF_WORKLOAD",
    "run_lf_local_baseline_suite",
]

#: The pinned external identity (Packet R2; pinned, never replaced).
LF_TARGET_COMMIT_SHA: typing.Final[str] = "7fcf5b3b130e5713b52415bb7404c476fada9c8c"
LF_REPOSITORY_IDENTITY: typing.Final[str] = "hiyouga/LlamaFactory"
LF_DATASET_NAME: typing.Final[str] = "lima-external-llamafactory-holdout-v1"
LF_DATASET_ROLE: typing.Final[str] = "external-holdout"

#: The canonical projection label (Packet R1: the exact frozen literal).
LF_CANONICAL_LABEL: typing.Final[str] = "external/llamafactory-replay@7fcf5b3b"

#: The LF workload label; it enters the run identity face.
LF_WORKLOAD: typing.Final[str] = "lf-local-scanner-v1"

#: The suite-result document version (informational face of this module).
LF_SUITE_RESULT_VERSION: typing.Final[int] = 1

# The explicit offline scanner configuration (Packet R1, the b1_source
# discipline).  Every value is passed explicitly to the constructor; no
# default and no ambient value is ever consulted, and each disabled face
# removes the code-run or LLM production path behind its verification
# states.
_SAST_MODE: typing.Final[str] = "off"
_CXX_MEMORY_MODE: typing.Final[str] = "off"
_CXX_AGENT_MODE: typing.Final[str] = "off"
_DATAFLOW_ENABLED: typing.Final[bool] = True

# The explicit workspace limits (Packet R1): the numeric equals of the
# frozen defaults, always passed explicitly.
_WORKSPACE_MAX_FILES: typing.Final[int] = 5000
_WORKSPACE_MAX_FILE_BYTES: typing.Final[int] = 512 * 1024
_WORKSPACE_MAX_TOTAL_BYTES: typing.Final[int] = 20 * 1024 * 1024

#: The frozen per-attempt receipt key set (Packet 7.6; twelve keys, closed).
_RECEIPT_KEYS: typing.Final[tuple[str, ...]] = (
    "attempt_index",
    "mode",
    "run_spec_digest",
    "workload",
    "commit_sha",
    "snapshot_tree_sha256",
    "archive_sha256",
    "materializations",
    "scanner_reexecuted",
    "scanner_result_reused",
    "snapshot_reused",
    "scanner_payload_sha256",
)

#: The frozen lf-binding manifest key set (Packet 7.6; closed).
_MANIFEST_KEYS: typing.Final[tuple[str, ...]] = (
    "schema_version",
    "workload",
    "run_spec_digest",
    "attempt_count",
    "cold_count",
    "warm_count",
    "repository_identity",
    "commit_sha",
    "dataset_name",
    "dataset_role",
    "archive_sha256",
    "archive_bytes",
    "snapshot_tree_sha256",
    "analyzer_name",
    "analyzer_fingerprint",
    "config_digest",
    "scanner_config",
    "scanner_config_sha256",
    "seed",
    "scanner_payload_sha256",
    "lf_receipts",
    "lf_receipts_digest",
    "failures",
    "model_calls",
    "declarations",
)

#: The per-attempt receipt document key set (three keys, the b1 precedent).
_ATTEMPT_DOCUMENT_KEYS: typing.Final[tuple[str, ...]] = (
    "schema_version",
    "run_spec_digest",
    "source_receipt",
)

_MANIFEST_DECLARATIONS: typing.Final[tuple[str, ...]] = (
    "lf-local-offline-zero-model-calls",
    "sealed-tarball-read-only-source-reuse",
    "warm-attempts-reuse-recorded-not-rescanned",
    "local-scanner-wiring-not-model-acceptance",
)

#: The outcome names paired with the frozen failure taxonomy codes.
_TAXONOMY_OUTCOMES: typing.Final[dict[str, str]] = {
    "EXECUTION_ERROR": "failure",
    "EXECUTION_TIMEOUT": "timeout",
    "EXECUTION_CANCELLED": "cancelled",
}

_BINDING_DATASET_REQUIRED_FIELDS: typing.Final[tuple[str, ...]] = (
    "name",
    "fingerprint",
    "role",
    "entries",
    "archive_sha256",
    "archive_bytes",
)
_BINDING_ENTRY_FIELDS: typing.Final[tuple[str, ...]] = ("repository", "commit_sha")

_HEX64_ALPHABET: typing.Final[frozenset[str]] = frozenset("0123456789abcdef")
_SNAPSHOT_MARKER_NAME: typing.Final[str] = ".lima-snapshot.json"

#: The platform text-line convention applied at materialization time: every
#: ``b"\\n"`` in an extracted member is written as the platform line
#: separator (the identity on POSIX, ``b"\\r\\n"`` on Windows).  This is
#: exactly the byte convention of a text-mode write, so a materialized
#: snapshot is byte-identical to the same content written by any
#: text-mode tool on the same platform, and the declared binding
#: fingerprint must be computed over a tree materialized under the same
#: convention (Packet 7.5).
_PLATFORM_LINESEP_BYTES: typing.Final[bytes] = os.linesep.encode("ascii")


class LFSourceErrorCode(str, enum.Enum):  # noqa: UP042 -- frozen by IP-0043 Packet
    """Frozen wire values for every deterministic LF source failure."""

    LF_SOURCE_MISSING = "LF_SOURCE_MISSING"
    LF_SOURCE_HASH_MISMATCH = "LF_SOURCE_HASH_MISMATCH"
    LF_SNAPSHOT_TREE_MISMATCH = "LF_SNAPSHOT_TREE_MISMATCH"
    LF_IDENTITY_CONFLICT = "LF_IDENTITY_CONFLICT"
    LF_OUTPUT_NOT_EMPTY = "LF_OUTPUT_NOT_EMPTY"
    LF_BINDING_INVALID = "LF_BINDING_INVALID"
    LF_PARAM_INVALID = "LF_PARAM_INVALID"

    def __str__(self) -> str:
        """Render the bare frozen wire value (the str-mixin face)."""
        return self.value


_STABLE_MESSAGES: dict[LFSourceErrorCode, str] = {
    LFSourceErrorCode.LF_SOURCE_MISSING: (
        "The pinned LF source archive is missing."
    ),
    LFSourceErrorCode.LF_SOURCE_HASH_MISMATCH: (
        "The LF source archive bytes disagree with the declared binding."
    ),
    LFSourceErrorCode.LF_SNAPSHOT_TREE_MISMATCH: (
        "The materialized LF snapshot tree disagrees with the declared binding."
    ),
    LFSourceErrorCode.LF_IDENTITY_CONFLICT: (
        "The LF source binding identity conflicts with the pinned target."
    ),
    LFSourceErrorCode.LF_OUTPUT_NOT_EMPTY: (
        "The LF output directory already holds content."
    ),
    LFSourceErrorCode.LF_BINDING_INVALID: (
        "The LF source binding document is invalid."
    ),
    LFSourceErrorCode.LF_PARAM_INVALID: (
        "LF suite cold/warm parameters must be positive integers."
    ),
}

#: The identity faces that block this scan and mark the run needs-decision
#: (the tenth-round ruling: report tooling continues, the SHA never moves).
_IDENTITY_CODES: typing.Final[frozenset[LFSourceErrorCode]] = frozenset(
    {
        LFSourceErrorCode.LF_SOURCE_MISSING,
        LFSourceErrorCode.LF_SOURCE_HASH_MISMATCH,
        LFSourceErrorCode.LF_SNAPSHOT_TREE_MISMATCH,
        LFSourceErrorCode.LF_IDENTITY_CONFLICT,
    }
)


class LFSourceError(ValueError):
    """Deterministic LF source violation with a stable code and message.

    The shape aligns with the frozen ``B1SourceError`` precedent while
    remaining an independent class.  The rendered message is exactly the
    catalog entry above; raw payloads, secrets, digest values and host
    paths are never embedded.  ``needs_decision`` is ``True`` exactly for
    the four identity codes (missing or mismatched sealed source), meaning
    only this scan is blocked and the decision belongs to the operator.
    """

    code: LFSourceErrorCode
    field_path: str
    needs_decision: bool

    def __init__(self, code: LFSourceErrorCode, field_path: str = "") -> None:
        if not isinstance(code, LFSourceErrorCode):
            raise TypeError("code must be a LFSourceErrorCode member")
        if not isinstance(field_path, str):
            raise TypeError("field_path must be a str")
        self.code = code
        self.field_path = field_path
        self.needs_decision = code in _IDENTITY_CODES
        super().__init__(_STABLE_MESSAGES[code])


@dataclasses.dataclass(frozen=True, slots=True)
class _SourceBinding:
    """The validated faces of the run-specific LF source-binding document."""

    dataset_name: str
    fingerprint: str
    role: str
    repository_identity: str
    commit_sha: str
    archive_sha256: str
    archive_bytes: int
    document: dict[str, object]


@dataclasses.dataclass(frozen=True, slots=True)
class LFSuiteResult:
    """Paths, digests, and counters of one offline LF local baseline suite run.

    An independent frozen type (not a ``BaselineRunResult`` or
    ``BaselineRunSummary`` subclass), mirroring the ``B1SuiteResult``
    discipline.  ``model_calls`` is the constant ``0`` (the workload performs
    no model calls of any kind) and ``lf`` is the constant ``True``
    discriminant, so downstream code can never mistake an LF wiring suite
    for a real model run.  ``report_path``/``report_sha256``/
    ``scanner_payload_sha256`` are ``None`` when no attempt ever produced a
    scanner payload (an honestly failing suite; nothing is fabricated).
    """

    run_spec_digest: str
    attempt_count: int
    status: str
    result_paths: tuple[pathlib.Path, ...]
    aggregate_path: pathlib.Path
    aggregate_sha256: str
    report_path: pathlib.Path | None
    report_sha256: str | None
    binding_path: pathlib.Path
    binding_sha256: str
    workload: str
    commit_sha: str
    dataset_name: str
    dataset_role: str
    archive_sha256: str
    archive_bytes: int
    snapshot_tree_sha256: str
    analyzer_name: str
    analyzer_fingerprint: str
    config_digest: str
    scanner_config_sha256: str
    scanner_payload_sha256: str | None
    scanner_executions: int
    materializations: int
    model_calls: int
    lf: bool


def _is_hex64(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in _HEX64_ALPHABET for character in value)
    )


def _extract_binding(binding: object) -> _SourceBinding:
    """Validate the run-specific source-binding document, fail-closed.

    Shape faces (structure, key presence, digest shapes, integer bytes)
    fail with ``LF_BINDING_INVALID``; disagreement with the pinned external
    identity (repository identity or commit SHA) fails with
    ``LF_IDENTITY_CONFLICT``; disagreement on the run-specific dataset name
    or role fails with ``LF_BINDING_INVALID``.  Extra manifest fields
    (license, source, layout provenance) are tolerated, mirroring the
    frozen manifest cross-check.
    """
    if not isinstance(binding, dict):
        raise LFSourceError(LFSourceErrorCode.LF_BINDING_INVALID, "$")
    if binding.get("schema_version") != 1:
        raise LFSourceError(LFSourceErrorCode.LF_BINDING_INVALID, "$.schema_version")
    datasets = binding.get("datasets")
    if not isinstance(datasets, list) or len(datasets) != 1:
        raise LFSourceError(LFSourceErrorCode.LF_BINDING_INVALID, "$.datasets")
    dataset = datasets[0]
    if not isinstance(dataset, dict):
        raise LFSourceError(LFSourceErrorCode.LF_BINDING_INVALID, "$.datasets[0]")
    for field in _BINDING_DATASET_REQUIRED_FIELDS:
        if field not in dataset:
            raise LFSourceError(
                LFSourceErrorCode.LF_BINDING_INVALID, f"$.datasets[0].{field}"
            )
    if not isinstance(dataset["name"], str) or not dataset["name"]:
        raise LFSourceError(LFSourceErrorCode.LF_BINDING_INVALID, "$.datasets[0].name")
    if not _is_hex64(dataset["fingerprint"]):
        raise LFSourceError(
            LFSourceErrorCode.LF_BINDING_INVALID, "$.datasets[0].fingerprint"
        )
    if not isinstance(dataset["role"], str) or not dataset["role"]:
        raise LFSourceError(LFSourceErrorCode.LF_BINDING_INVALID, "$.datasets[0].role")
    if not _is_hex64(dataset["archive_sha256"]):
        raise LFSourceError(
            LFSourceErrorCode.LF_BINDING_INVALID, "$.datasets[0].archive_sha256"
        )
    if type(dataset["archive_bytes"]) is not int or dataset["archive_bytes"] < 0:
        raise LFSourceError(
            LFSourceErrorCode.LF_BINDING_INVALID, "$.datasets[0].archive_bytes"
        )
    entries = dataset["entries"]
    if not isinstance(entries, list) or len(entries) != 1:
        raise LFSourceError(
            LFSourceErrorCode.LF_BINDING_INVALID, "$.datasets[0].entries"
        )
    entry = entries[0]
    if not isinstance(entry, dict):
        raise LFSourceError(
            LFSourceErrorCode.LF_BINDING_INVALID, "$.datasets[0].entries[0]"
        )
    for field in _BINDING_ENTRY_FIELDS:
        if field not in entry or not isinstance(entry[field], str) or not entry[field]:
            raise LFSourceError(
                LFSourceErrorCode.LF_BINDING_INVALID,
                f"$.datasets[0].entries[0].{field}",
            )
    if dataset["name"] != LF_DATASET_NAME:
        raise LFSourceError(LFSourceErrorCode.LF_BINDING_INVALID, "$.datasets[0].name")
    if dataset["role"] != LF_DATASET_ROLE:
        raise LFSourceError(LFSourceErrorCode.LF_BINDING_INVALID, "$.datasets[0].role")
    if entry["repository"] != LF_REPOSITORY_IDENTITY:
        raise LFSourceError(
            LFSourceErrorCode.LF_IDENTITY_CONFLICT,
            "$.datasets[0].entries[0].repository",
        )
    if entry["commit_sha"] != LF_TARGET_COMMIT_SHA:
        raise LFSourceError(
            LFSourceErrorCode.LF_IDENTITY_CONFLICT,
            "$.datasets[0].entries[0].commit_sha",
        )
    return _SourceBinding(
        dataset_name=dataset["name"],
        fingerprint=dataset["fingerprint"],
        role=dataset["role"],
        repository_identity=entry["repository"],
        commit_sha=entry["commit_sha"],
        archive_sha256=dataset["archive_sha256"],
        archive_bytes=dataset["archive_bytes"],
        document=binding,
    )


def _tree_fingerprint(
    root: pathlib.Path,
    *,
    pinned_name: str | None = None,
    pinned_payload: bytes | None = None,
) -> str:
    """The frozen snapshot tree fingerprint rule, independently transcribed.

    Mirrors ``SnapshotStore._tree_identity`` (the algorithm backing the
    sealed 596-file inventory): sorted relative POSIX paths excluding the
    snapshot metadata marker, ``len(path):path:size:\\0`` framing then the
    raw bytes.  Dual-source discipline: this module always computes the
    value from the materialized bytes, never from a pinned constant.

    ``pinned_name``/``pinned_payload`` optionally frame one extra member --
    the reused sealed archive under its own file name -- so the same rule
    can verify a source binding whose declared fingerprint pins the whole
    sealed-source directory (working copy plus archive) as well as one
    that pins the pure snapshot tree (Packet 7.5).
    """
    entries: list[tuple[str, int, pathlib.Path | None]] = [
        (
            item.relative_to(root).as_posix(),
            item.stat().st_size,
            item,
        )
        for item in sorted(
            (
                member
                for member in root.rglob("*")
                if member.name != _SNAPSHOT_MARKER_NAME and member.is_file()
            ),
            key=lambda member: member.relative_to(root).as_posix(),
        )
    ]
    if pinned_name is not None and pinned_payload is not None:
        entries.append((pinned_name, len(pinned_payload), None))
        entries.sort(key=lambda entry: entry[0])
    digest = hashlib.sha256()
    for relative, size, item in entries:
        encoded_relative = relative.encode("utf-8")
        digest.update(str(len(encoded_relative)).encode("ascii"))
        digest.update(b":")
        digest.update(encoded_relative)
        digest.update(b":")
        digest.update(str(size).encode("ascii"))
        digest.update(b"\0")
        if item is None:
            digest.update(pinned_payload)
            continue
        with item.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
    return digest.hexdigest()


def _materialize_snapshot(
    archive_path: pathlib.Path, target: pathlib.Path
) -> pathlib.Path:
    """Extract the sealed archive's single top-level directory under target.

    Only regular file members are extracted; the single top-level directory
    segment is stripped; absolute paths, dot segments and unexpected member
    types are rejected.  Link members (symbolic and hard links) are
    deterministically skipped, mirroring the frozen production precedent
    (``real_world_evaluation.py``: the analysis workspace never follows
    links, so omit them instead of materializing attacker-controlled link
    targets) and the authoritative 09-28 sealed materialization; they never
    enter the materialized tree or its fingerprint.  Member content is
    written under the platform text-line convention (Packet 7.5), so the
    materialized tree is byte-identical to the same content written by any
    text-mode tool on the same platform.  An unreadable or corrupt archive
    raises the underlying ``tarfile`` error (the caller retains it as an
    honest attempt-body failure under the frozen taxonomy).
    """
    target.mkdir(parents=True, exist_ok=True)
    with tarfile.open(archive_path, "r:gz") as bundle:
        for member in bundle:
            if member.isdir():
                continue
            if member.issym() or member.islnk():
                # The sealed archive carries at most link members as
                # repository links (the 09-28 authoritative snapshot has
                # exactly one).  The analysis workspace never follows links,
                # so omit them instead of materializing attacker-controlled
                # link targets -- the frozen real_world_evaluation precedent.
                continue
            if not member.isfile():
                raise ValueError(
                    "archive member is neither a regular file nor a directory"
                )
            parts = member.name.split("/")
            if (
                len(parts) < 2
                or not parts[0]
                or parts[0] in (".", "..")
                or any(part in ("", ".", "..") for part in parts[1:])
            ):
                raise ValueError(
                    "archive member escapes the single top-level directory"
                )
            destination = target.joinpath(*parts[1:])
            destination.parent.mkdir(parents=True, exist_ok=True)
            source = bundle.extractfile(member)
            if source is None:  # pragma: no cover - defensive
                raise ValueError("archive member could not be read")
            with source:
                payload = source.read()
            destination.write_bytes(payload.replace(b"\n", _PLATFORM_LINESEP_BYTES))
    return target


def _scan_snapshot(root: pathlib.Path) -> RepositoryScanResult:
    """Run the real local scanner over one materialized snapshot, offline.

    Every disabling parameter is passed explicitly (the b1_source
    discipline): SAST engines and adapters, the C/C++ memory analyzer, the
    platform agent chain with its allocation-plan factory, and the platform
    LLM factory are all off or empty; the static cross-file dataflow index
    stays on (pure local AST); the default security rule reviewer is
    constructed explicitly.  The workspace limits are the frozen defaults,
    passed explicitly.
    """
    scanner = RepositoryScanner(
        [SecurityRuleReviewer()],
        sast_mode=_SAST_MODE,
        sast_adapters=[],
        cxx_memory_mode=_CXX_MEMORY_MODE,
        cxx_memory_adapter=None,
        cxx_agent_mode=_CXX_AGENT_MODE,
        cxx_agent_budget_factory=None,
        cxx_uaf_llm_factory=None,
        dataflow_enabled=_DATAFLOW_ENABLED,
        should_cancel=None,
    )
    workspace = RepositoryWorkspace(
        root,
        max_files=_WORKSPACE_MAX_FILES,
        max_file_bytes=_WORKSPACE_MAX_FILE_BYTES,
        max_total_bytes=_WORKSPACE_MAX_TOTAL_BYTES,
    )
    return scanner.scan(workspace)


def _canonical_payload(
    scan_result: RepositoryScanResult, repository_label: str
) -> RepositoryScanResult:
    """Project one scan result onto canonical, path-independent wire bytes.

    The scanner labels ``report.repository`` and ``workspace.root`` with the
    absolute materialization directory; both are replaced by the frozen
    stable external identity so that the frozen report wire fingerprint is
    a pure function of the snapshot content and the analyzer configuration.
    Findings, collaboration, adjudication and every inventory statistic are
    carried over unchanged (shared read-only references; nothing is
    re-derived or dropped).
    """
    report = dataclasses.replace(scan_result.report, repository=repository_label)
    inventory = dataclasses.replace(scan_result.inventory, root=repository_label)
    return RepositoryScanResult(report=report, inventory=inventory)


def _wire_fingerprint(payload: RepositoryScanResult) -> str:
    """The frozen scanner source digest rule (report.py L1340-1344, verbatim).

    An independent local transcription of the frozen rule so the receipts
    bind to exactly the digest the report projection computes: sorted-key
    compact UTF-8 JSON via the stdlib, then SHA-256.
    """
    wire = {
        **payload.report.to_dict(),
        "workspace": payload.inventory.to_dict(),
    }
    encoded = json.dumps(
        wire,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _derive_analyzer_name(*, dataflow_enabled: bool) -> str:
    """The scanner identity string implied by the frozen offline config.

    The scanner composes ``repository-hybrid:python-ast`` with
    ``+python-dataflow`` when the static dataflow index runs and one segment
    per completed SAST engine; with SAST explicitly off the string is a pure
    function of the configuration.  Every cold attempt cross-checks the
    realized ``report.reviewer`` against this derivation and fails the
    attempt if they diverge.
    """
    name = "repository-hybrid:python-ast"
    if dataflow_enabled:
        name += "+python-dataflow"
    return name


def run_lf_local_baseline_suite(
    *,
    output_dir: str | pathlib.Path,
    machine_profile: object,
    source_root: str | pathlib.Path,
    binding: object,
    cold_count: int = 3,
    warm_count: int = 5,
    seed: int = 0,
    sources: PlatformSources | None = None,
) -> LFSuiteResult:
    """Run one fully offline fixed-SHA LlamaFactory local baseline suite.

    Order (Packet 7.6): the positive-integer cold/warm parameter gate; the
    empty-output-directory gate; the three-layer source-binding validation
    (shape and pinned identity here, then the frozen spec layer, then the
    archive-bytes hash); the explicit offline configuration document, its
    digest and the derived analyzer faces; the spec build; ``cold_count``
    cold attempts each extracting a fresh working copy from the sealed
    archive, verifying the materialized tree fingerprint and truly
    re-running the scanner; ``warm_count`` warm attempts each reusing the
    last cold snapshot and scan result; the aggregate through the frozen
    result contract; the report through the frozen scanner projection; the
    per-attempt receipt documents and the closed-key ``lf-binding.json``
    manifest; the :class:`LFSuiteResult`.

    A typed identity violation (missing or mismatched sealed source)
    terminates before any output byte is written and marks the failure
    needs-decision.  A corrupt-but-hash-consistent archive instead fails
    every attempt body without raising: the eight failure samples stay in
    the aggregate denominator under the frozen taxonomy.  An ``Exception``
    body becomes a retained taxonomy sample while the loop continues; a
    control-flow ``BaseException`` body is persisted then re-raised.
    """
    if type(cold_count) is not int or cold_count < 1:
        raise LFSourceError(LFSourceErrorCode.LF_PARAM_INVALID, "$.cold_count")
    if type(warm_count) is not int or warm_count < 1:
        raise LFSourceError(LFSourceErrorCode.LF_PARAM_INVALID, "$.warm_count")
    directory = pathlib.Path(output_dir)
    if directory.exists():
        if not directory.is_dir() or any(directory.iterdir()):
            raise LFSourceError(LFSourceErrorCode.LF_OUTPUT_NOT_EMPTY, "$.output_dir")
    else:
        directory.mkdir(parents=True)

    source_binding = _extract_binding(binding)
    archive_path = pathlib.Path(source_root)
    if not archive_path.is_file():
        raise LFSourceError(LFSourceErrorCode.LF_SOURCE_MISSING, "$.source_root")
    archive_bytes_actual = archive_path.read_bytes()
    archive_sha256_actual = hashlib.sha256(archive_bytes_actual).hexdigest()
    if archive_sha256_actual != source_binding.archive_sha256:
        raise LFSourceError(
            LFSourceErrorCode.LF_SOURCE_HASH_MISMATCH, "$.datasets[0].archive_sha256"
        )
    if len(archive_bytes_actual) != source_binding.archive_bytes:
        raise LFSourceError(
            LFSourceErrorCode.LF_SOURCE_HASH_MISMATCH, "$.datasets[0].archive_bytes"
        )

    scanner_config: dict[str, object] = {
        "workload": LF_WORKLOAD,
        "dataset_name": LF_DATASET_NAME,
        "commit_sha": LF_TARGET_COMMIT_SHA,
        "archive_sha256": source_binding.archive_sha256,
        "archive_bytes": source_binding.archive_bytes,
        "snapshot_tree_sha256": source_binding.fingerprint,
        "seed": seed,
        "cold_count": cold_count,
        "warm_count": warm_count,
        "scanner": {
            "sast_mode": _SAST_MODE,
            "sast_adapters": [],
            "cxx_memory_mode": _CXX_MEMORY_MODE,
            "cxx_memory_adapter": None,
            "cxx_agent_mode": _CXX_AGENT_MODE,
            "cxx_agent_budget_factory": None,
            "cxx_uaf_llm_factory": None,
            "dataflow_enabled": _DATAFLOW_ENABLED,
            "reviewers": "security-rule-reviewer",
            "should_cancel": None,
        },
        "workspace": {
            "max_files": _WORKSPACE_MAX_FILES,
            "max_file_bytes": _WORKSPACE_MAX_FILE_BYTES,
            "max_total_bytes": _WORKSPACE_MAX_TOTAL_BYTES,
        },
    }
    scanner_config_sha256 = compute_content_digest(scanner_config)
    analyzer_name = _derive_analyzer_name(dataflow_enabled=_DATAFLOW_ENABLED)
    analyzer_fingerprint = compute_content_digest(
        {
            "analyzer_name": analyzer_name,
            "scanner_config_sha256": scanner_config_sha256,
        }
    )
    spec_mapping: dict[str, object] = {
        "schema_version": 1,
        "repositories": [
            {
                "identity": LF_REPOSITORY_IDENTITY,
                "commit_sha": LF_TARGET_COMMIT_SHA,
            }
        ],
        "datasets": [
            {
                "name": LF_DATASET_NAME,
                "fingerprint": source_binding.fingerprint,
                "role": LF_DATASET_ROLE,
            }
        ],
        "analyzer_fingerprint": analyzer_fingerprint,
        "config_digest": scanner_config_sha256,
        "seed": seed,
        "machine_profile": machine_profile,
    }
    try:
        spec = spec_from_mapping(spec_mapping)
        validate_baseline_manifest(source_binding.document, spec)
    except BaselineRunSpecError as exc:
        raise LFSourceError(
            LFSourceErrorCode.LF_BINDING_INVALID, "$.binding"
        ) from exc
    spec_digest = spec.content_digest()

    if sources is None:
        sources = PlatformSources()
    scan_payload: RepositoryScanResult | None = None
    scan_digest: str | None = None
    scanner_executions = 0
    materializations = 0
    attempts = []
    result_paths: list[pathlib.Path] = []
    receipts: list[dict[str, object]] = []

    with tempfile.TemporaryDirectory() as workspace:
        for attempt_index in range(cold_count + warm_count):
            mode = "cold" if attempt_index < cold_count else "warm"
            scanner_ran = False
            reuse_served = False
            caught: BaseException | None = None
            wall_start = sources.wall_ns()
            cpu_start = sources.cpu_ns()
            try:
                if mode == "cold":
                    cold_root = (
                        pathlib.Path(workspace)
                        / f"cold-{attempt_index:02d}"
                        / "snapshot"
                    )
                    _materialize_snapshot(archive_path, cold_root)
                    materializations += 1
                    pure_tree = _tree_fingerprint(cold_root)
                    sealed_tree = _tree_fingerprint(
                        cold_root,
                        pinned_name=archive_path.name,
                        pinned_payload=archive_bytes_actual,
                    )
                    if source_binding.fingerprint not in (pure_tree, sealed_tree):
                        raise LFSourceError(
                            LFSourceErrorCode.LF_SNAPSHOT_TREE_MISMATCH,
                            "$.datasets[0].fingerprint",
                        )
                    scan = _scan_snapshot(cold_root)
                    if scan.report.reviewer != analyzer_name:
                        raise ValueError(
                            "realized scanner reviewer identity diverged from "
                            "the pinned offline configuration derivation"
                        )
                    scan_payload = _canonical_payload(scan, LF_CANONICAL_LABEL)
                    scan_digest = _wire_fingerprint(scan_payload)
                    scanner_executions += 1
                    scanner_ran = True
                if scan_payload is None or scan_digest is None:
                    raise ValueError(
                        "no earlier cold scanner result is available to reuse"
                    )
                reuse_served = mode == "warm"
            except BaseException as exc:  # noqa: B036 -- persisted then re-raised below
                caught = exc
            if isinstance(caught, LFSourceError) and caught.needs_decision:
                raise caught
            wall_end = sources.wall_ns()
            cpu_end = sources.cpu_ns()
            wall_time_ms = elapsed_ms(wall_start, wall_end)
            cpu_time_ms = elapsed_ms(cpu_start, cpu_end)
            memory_rss_peak_bytes = require_metric(
                sources.peak_rss_bytes(), "$.samples[0].memory_rss_peak_bytes"
            )
            io_read_bytes = require_metric(
                sources.io_read_bytes(), "$.samples[0].io_read_bytes"
            )
            io_write_bytes = require_metric(
                sources.io_write_bytes(), "$.samples[0].io_write_bytes"
            )
            if caught is None:
                outcome = "success"
                failure_code: str | None = None
            else:
                failure_code = classify_failure(caught)
                outcome = _TAXONOMY_OUTCOMES[failure_code]
            sample: dict[str, object] = {
                "attempt_index": attempt_index,
                "mode": mode,
                "outcome": outcome,
                "wall_time_ms": wall_time_ms,
                "queue_time_ms": None,
                "cpu_time_ms": cpu_time_ms,
                "expert_time_ms": None,
                "memory_rss_peak_bytes": memory_rss_peak_bytes,
                "io_read_bytes": io_read_bytes,
                "io_write_bytes": io_write_bytes,
                "prompt_tokens": 0,
                "completion_tokens": 0,
                "cost_micro_usd": 0,
                "failure_code": failure_code,
            }
            result = result_from_mapping(
                {
                    "schema_version": 1,
                    "run_spec_digest": spec_digest,
                    "samples": [sample],
                }
            )
            artifacts = write_result_file(result, directory)
            result_paths.append(artifacts.result_path)
            attempts.append(result)
            receipts.append(
                {
                    "attempt_index": attempt_index,
                    "mode": mode,
                    "run_spec_digest": spec_digest,
                    "workload": LF_WORKLOAD,
                    "commit_sha": LF_TARGET_COMMIT_SHA,
                    "snapshot_tree_sha256": source_binding.fingerprint,
                    "archive_sha256": source_binding.archive_sha256,
                    "materializations": materializations,
                    "scanner_reexecuted": scanner_ran,
                    "scanner_result_reused": reuse_served,
                    "snapshot_reused": reuse_served,
                    "scanner_payload_sha256": scan_digest,
                }
            )
            if caught is not None and not isinstance(caught, Exception):
                raise caught

        aggregate = result_from_mapping(
            {
                "schema_version": 1,
                "run_spec_digest": spec_digest,
                "samples": [
                    dict(result.samples[0].items())
                    for result in sorted(
                        attempts, key=lambda item: item.samples[0]["attempt_index"]
                    )
                ],
            }
        )
        aggregate_artifacts = write_result_file(aggregate, directory)
        summary = BaselineRunSummary(
            attempts=tuple(attempts),
            result_paths=tuple(result_paths),
            aggregate=aggregate,
            aggregate_path=aggregate_artifacts.result_path,
            aggregate_sha256=aggregate_artifacts.result_sha256,
            status=aggregate.status,
        )
        if scan_payload is not None:
            report = build_baseline_report(summary, scan_payload)
            report_artifacts = write_report_file(report, directory)
            report_path: pathlib.Path | None = report_artifacts.report_path
            report_sha256: str | None = report_artifacts.report_sha256
        else:
            report_path = None
            report_sha256 = None

    failures = [
        result.samples[0]["failure_code"]
        for result in attempts
        if result.samples[0]["failure_code"] is not None
    ]
    lf_receipts_digest = compute_content_digest(receipts)
    attempts_directory = directory / "lf-attempts"
    attempts_directory.mkdir()
    for attempt_index, receipt in enumerate(receipts):
        document = canonical_encode(
            {
                "schema_version": 1,
                "run_spec_digest": spec_digest,
                "source_receipt": receipt,
            }
        )
        write_exclusive(
            attempts_directory / f"attempt-{attempt_index:02d}.json", document
        )
    manifest_document = {
        "schema_version": 1,
        "workload": LF_WORKLOAD,
        "run_spec_digest": spec_digest,
        "attempt_count": len(attempts),
        "cold_count": cold_count,
        "warm_count": warm_count,
        "repository_identity": LF_REPOSITORY_IDENTITY,
        "commit_sha": LF_TARGET_COMMIT_SHA,
        "dataset_name": LF_DATASET_NAME,
        "dataset_role": LF_DATASET_ROLE,
        "archive_sha256": source_binding.archive_sha256,
        "archive_bytes": source_binding.archive_bytes,
        "snapshot_tree_sha256": source_binding.fingerprint,
        "analyzer_name": analyzer_name,
        "analyzer_fingerprint": analyzer_fingerprint,
        "config_digest": scanner_config_sha256,
        "scanner_config": scanner_config,
        "scanner_config_sha256": scanner_config_sha256,
        "seed": seed,
        "scanner_payload_sha256": scan_digest,
        "lf_receipts": receipts,
        "lf_receipts_digest": lf_receipts_digest,
        "failures": failures,
        "model_calls": 0,
        "declarations": list(_MANIFEST_DECLARATIONS),
    }
    if set(manifest_document) != frozenset(_MANIFEST_KEYS):  # pragma: no cover
        raise LFSourceError(LFSourceErrorCode.LF_BINDING_INVALID, "$.lf_binding")
    binding_file = directory / "lf-binding.json"
    binding_bytes = canonical_encode(manifest_document)
    write_exclusive(binding_file, binding_bytes)
    return LFSuiteResult(
        run_spec_digest=spec_digest,
        attempt_count=len(attempts),
        status=summary.status,
        result_paths=tuple(result_paths),
        aggregate_path=aggregate_artifacts.result_path,
        aggregate_sha256=aggregate_artifacts.result_sha256,
        report_path=report_path,
        report_sha256=report_sha256,
        binding_path=binding_file,
        binding_sha256=compute_content_digest(binding_bytes),
        workload=LF_WORKLOAD,
        commit_sha=LF_TARGET_COMMIT_SHA,
        dataset_name=LF_DATASET_NAME,
        dataset_role=LF_DATASET_ROLE,
        archive_sha256=source_binding.archive_sha256,
        archive_bytes=source_binding.archive_bytes,
        snapshot_tree_sha256=source_binding.fingerprint,
        analyzer_name=analyzer_name,
        analyzer_fingerprint=analyzer_fingerprint,
        config_digest=scanner_config_sha256,
        scanner_config_sha256=scanner_config_sha256,
        scanner_payload_sha256=scan_digest,
        scanner_executions=scanner_executions,
        materializations=materializations,
        model_calls=0,
        lf=True,
    )
