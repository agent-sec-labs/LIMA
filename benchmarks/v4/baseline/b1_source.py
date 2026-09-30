"""B1 machine-source wiring entry for LIMA v4 baselines (IP-0040, Issue #249).

This module composes the frozen upstream faces read-only into the formal
offline B1 entry :func:`run_b1_source_baseline_suite` (Packet
docs/LIMA_Implementation_Packet_IP-0040_B1_Source_Wiring.md sections 7.4-7.7):
a frozen synthetic fixture is materialized into an internal temporary
workspace (never the output directory), scanned by the real local
``RepositoryScanner`` under the explicit offline configuration (SAST engines,
the C/C++ memory analyzer, the platform agent chain and every LLM factory
explicitly disabled -- never ambient defaults), and the resulting
``RepositoryScanResult`` is projected through the frozen
``build_baseline_report`` scanner path (no bundle and no domain block:
signals/security issues stay ``legacy_projection`` while the hypothesis, VEP,
RVR, stage and model-resource faces stay ``null`` + ``unavailable``).
Attempts run as an own cold+warm loop over the frozen
``run_baseline_attempt`` primitive (the 3 cold + 5 warm shape is asymmetric,
so the frozen symmetric ``run_repeats`` is not reused), the aggregate flows
through the frozen ``result_from_mapping`` and ``write_result_file``, and
every attempt documents its ``source_receipt`` sixteen-key block; the
closed-key ``b1-manifest.json`` aggregates the receipts under
``source_receipts_digest``.  :func:`verify_b1_evidence` re-reads the evidence
directory and cross-checks every receipt, manifest, attempt-document and
report binding, failing closed with the frozen four-code typed error family.

The scanner payload handed to the report is the canonical projection of the
scan output: the materialization-root path labels (``report.repository`` and
``workspace.root``, which the scanner derives from the absolute temporary
directory) are replaced by the fixture key, so the canonical source bytes --
and therefore the scanner wire digest and the run identity faces -- depend
only on the snapshot content, the analyzer configuration, the workload and
the seed, never on the temporary directory location (Packet 7.6.4/7.7).  The
wire fingerprint rule itself is the frozen report rule verbatim: the
sorted-key compact UTF-8 JSON SHA-256 of ``{**report.to_dict(), "workspace":
inventory.to_dict()}``.

Everything here is offline and deterministic: zero model calls (an injected
transport only verifies future wiring and its call count is never a real
call), zero network, zero credentials, zero env-var reads, and writes go
only into the caller-provided output directory plus internal temporary
workspaces.  The B1 report is synthetic-fixture wiring evidence, not real
acceptance evidence, and never compares against pilot workloads.
"""

import dataclasses
import enum
import hashlib
import json
import pathlib
import tempfile
import typing

from benchmarks.v4.baseline.fixtures import (
    compute_tree_fingerprint,
    load_registry,
    materialize_fixture,
    verify_fixture,
)
from benchmarks.v4.baseline.orchestrate import (
    BaselineOrchestrationError,
    BaselineOrchestrationErrorCode,
    BaselineRunSummary,
)
from benchmarks.v4.baseline.report import build_baseline_report, write_report_file
from benchmarks.v4.baseline.run import (
    run_baseline_attempt,
    write_exclusive,
    write_result_file,
)
from lima.baseline_run_result import from_mapping as result_from_mapping
from lima.baseline_run_spec import from_mapping as spec_from_mapping
from lima.contracts.codec import canonical_encode, compute_content_digest
from lima.repository_scanner import RepositoryScanner, RepositoryScanResult
from lima.reviewer import SecurityRuleReviewer
from lima.workspace import RepositoryWorkspace

__all__ = [
    "B1SourceError",
    "B1SourceErrorCode",
    "B1SuiteResult",
    "B1_WORKLOAD",
    "CANDIDATE_FILE_CAP",
    "run_b1_source_baseline_suite",
    "verify_b1_evidence",
]

#: The B1 workload label (Packet 7.4): it enters the run identity face.
B1_WORKLOAD: typing.Final[str] = "b1-offline-scanner-v1"

#: The frozen request-construction parameter for the candidate file
#: selection carried by every transport request document.  It bounds the
#: request construction only -- never the scanned findings, which are always
#: reported at full scope.
CANDIDATE_FILE_CAP: typing.Final[int] = 12

_DEFAULT_MANIFEST_PATH = (
    pathlib.Path(__file__).resolve().parents[3]
    / "evaluation_data"
    / "v4"
    / "baseline_manifest.json"
)

# The explicit offline scanner configuration (Packet 7.5).  Every value is
# passed explicitly to the constructor; no default and no env-var value
# is ever consulted, and each disabled face removes the code-execution or
# LLM production path behind its verification states.
_SAST_MODE: typing.Final[str] = "off"
_CXX_MEMORY_MODE: typing.Final[str] = "off"
_CXX_AGENT_MODE: typing.Final[str] = "off"
_DATAFLOW_ENABLED: typing.Final[bool] = True

# The explicit workspace limits (Packet 7.5): the numeric equals of the
# frozen defaults, always passed explicitly.
_WORKSPACE_MAX_FILES: typing.Final[int] = 5000
_WORKSPACE_MAX_FILE_BYTES: typing.Final[int] = 512 * 1024
_WORKSPACE_MAX_TOTAL_BYTES: typing.Final[int] = 20 * 1024 * 1024

#: The frozen source_receipt key set (Packet 7.6.3; sixteen keys).
_RECEIPT_KEYS: typing.Final[tuple[str, ...]] = (
    "snapshot_tree_sha256",
    "fixture_key",
    "fixture_manifest_sha256",
    "analyzer_name",
    "analyzer_fingerprint",
    "scanner_config_sha256",
    "seed",
    "workload",
    "run_spec_digest",
    "attempt_index",
    "mode",
    "scanner_payload_sha256",
    "scanner_reexecuted",
    "scanner_result_reused",
    "snapshot_reused",
    "request_body_rebuilt",
)
_RECEIPT_KEY_SET: typing.Final[frozenset[str]] = frozenset(_RECEIPT_KEYS)

#: The frozen b1-manifest key set (Packet 7.6.3; closed).
_MANIFEST_KEYS: typing.Final[tuple[str, ...]] = (
    "schema_version",
    "workload",
    "run_spec_digest",
    "attempt_count",
    "cold_count",
    "warm_count",
    "fixture_key",
    "fixture_manifest_sha256",
    "snapshot_tree_sha256",
    "analyzer_name",
    "analyzer_fingerprint",
    "scanner_config",
    "scanner_config_sha256",
    "seed",
    "scanner_payload_sha256",
    "source_receipts",
    "source_receipts_digest",
    "failures",
    "transport_calls",
    "model_calls",
    "declarations",
)
_MANIFEST_KEY_SET: typing.Final[frozenset[str]] = frozenset(_MANIFEST_KEYS)

_ATTEMPT_DOCUMENT_KEYS: typing.Final[tuple[str, ...]] = (
    "schema_version",
    "run_spec_digest",
    "source_receipt",
)
_ATTEMPT_DOCUMENT_KEY_SET: typing.Final[frozenset[str]] = frozenset(
    _ATTEMPT_DOCUMENT_KEYS
)

_MANIFEST_DECLARATIONS: typing.Final[tuple[str, ...]] = (
    "b1-offline-zero-model-calls",
    "synthetic-fixture-wiring-not-real-acceptance",
)

_HEX64_ALPHABET: typing.Final[frozenset[str]] = frozenset("0123456789abcdef")


class B1SourceErrorCode(str, enum.Enum):  # noqa: UP042 -- frozen by IP-0040 7.6.3
    """Frozen wire values for every deterministic B1 evidence failure."""

    B1_OUTPUT_NOT_EMPTY = "B1_OUTPUT_NOT_EMPTY"
    SOURCE_RECEIPT_INVALID = "SOURCE_RECEIPT_INVALID"
    SOURCE_BINDING_MISMATCH = "SOURCE_BINDING_MISMATCH"
    SCANNER_DIGEST_MISMATCH = "SCANNER_DIGEST_MISMATCH"

    def __str__(self) -> str:
        """Render the bare frozen wire value (the str-mixin face)."""
        return self.value


_STABLE_MESSAGES: dict[B1SourceErrorCode, str] = {
    B1SourceErrorCode.B1_OUTPUT_NOT_EMPTY: (
        "The B1 evidence output directory already holds content."
    ),
    B1SourceErrorCode.SOURCE_RECEIPT_INVALID: (
        "A B1 source receipt or evidence document is invalid."
    ),
    B1SourceErrorCode.SOURCE_BINDING_MISMATCH: (
        "A B1 evidence binding does not match its aggregate."
    ),
    B1SourceErrorCode.SCANNER_DIGEST_MISMATCH: (
        "A scanner payload digest does not match its report source."
    ),
}


class B1SourceError(ValueError):
    """Deterministic B1 evidence violation with a stable code and message.

    The shape aligns with the frozen collection/report/orchestration error
    precedents while remaining an independent class.  The rendered message is
    exactly the catalog entry above; raw payloads, secrets, digest values and
    host paths are never embedded.  Use ``field_path`` for structure-only
    position reporting such as ``$.source_receipts[0]``.
    """

    code: B1SourceErrorCode
    field_path: str

    def __init__(self, code: B1SourceErrorCode, field_path: str = "") -> None:
        if not isinstance(code, B1SourceErrorCode):
            raise TypeError("code must be a B1SourceErrorCode member")
        if not isinstance(field_path, str):
            raise TypeError("field_path must be a str")
        self.code = code
        self.field_path = field_path
        super().__init__(_STABLE_MESSAGES[code])


@dataclasses.dataclass(frozen=True, slots=True)
class B1SuiteResult:
    """Paths, digests, and counters of one offline B1 source-wiring suite run.

    An independent frozen type (not a ``BaselineRunResult`` or
    ``BaselineRunSummary`` subclass), mirroring the ``OfflineSuiteResult``
    discipline.  ``model_calls`` is the constant ``0`` (the workload performs
    no model calls of any kind) and ``b1`` is the constant ``True``
    discriminant, so downstream code can never mistake a B1 wiring suite for
    a real run.
    """

    run_spec_digest: str
    attempt_count: int
    status: str
    result_paths: tuple[pathlib.Path, ...]
    aggregate_path: pathlib.Path
    aggregate_sha256: str
    report_path: pathlib.Path
    report_sha256: str
    manifest_path: pathlib.Path
    manifest_sha256: str
    source_receipts_digest: str
    fixture_key: str
    snapshot_tree_sha256: str
    scanner_config_sha256: str
    scanner_payload_sha256: str
    workload: str
    scanner_executions: int
    transport_calls: int
    model_calls: int
    b1: bool


def _is_hex64(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in _HEX64_ALPHABET for character in value)
    )


def _load_manifest(manifest_path: str | pathlib.Path | None) -> object:
    """Parse the baseline manifest (frozen default when ``None``), fail closed.

    Mirrors the frozen offline-suite loader: an unreadable file, a non-UTF-8
    byte stream, or invalid JSON raises the frozen orchestration error
    ``MANIFEST_UNREADABLE`` under ``$.manifest_path``.
    """
    path = _DEFAULT_MANIFEST_PATH if manifest_path is None else pathlib.Path(manifest_path)
    try:
        payload = path.read_bytes()
        parsed = json.loads(payload.decode("utf-8"))
    except (OSError, UnicodeDecodeError, ValueError) as exc:
        raise BaselineOrchestrationError(
            BaselineOrchestrationErrorCode.MANIFEST_UNREADABLE, "$.manifest_path"
        ) from exc
    return parsed


def _registry_fingerprint(registry: dict, fixture_key: str) -> str:
    """The frozen registry entry fingerprint of one synthetic fixture key."""
    for entry in registry["fixtures"]:
        if entry.get("key") == fixture_key:
            fingerprint = entry.get("fingerprint")
            if not _is_hex64(fingerprint):
                raise B1SourceError(
                    B1SourceErrorCode.SOURCE_RECEIPT_INVALID,
                    "$.fixture_manifest_sha256",
                )
            return fingerprint
    raise B1SourceError(
        B1SourceErrorCode.SOURCE_RECEIPT_INVALID, "$.fixture_manifest_sha256"
    )


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


def _scan_snapshot(root: pathlib.Path) -> RepositoryScanResult:
    """Run the real local scanner over one materialized snapshot, offline.

    Every disabling parameter is passed explicitly (Packet 7.5): SAST engines
    and adapters, the C/C++ memory analyzer, the platform agent chain and its
    budget factory, and the platform LLM factory are all off or empty; the
    static cross-file dataflow index stays on (pure local AST); the default
    security rule reviewer is constructed explicitly.  The workspace limits
    are the frozen defaults, passed explicitly.
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
    absolute materialization directory; both are replaced by the fixture key
    so that the frozen report wire fingerprint -- the sorted-key compact
    UTF-8 JSON SHA-256 of ``{**report.to_dict(), "workspace":
    inventory.to_dict()}`` -- is a pure function of the snapshot content and
    the analyzer configuration.  Findings, collaboration, adjudication and
    every inventory statistic are carried over unchanged (shared read-only
    references; nothing is re-derived or dropped).
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


def _build_spec_mapping(
    manifest: dict,
    *,
    analyzer_fingerprint: str,
    config_digest: str,
    seed: int,
    machine_profile: object,
) -> dict[str, object]:
    """Assemble the frozen seven-field spec mapping from the manifest faces.

    The repositories and datasets come from the loaded frozen manifest; the
    three identity faces (analyzer fingerprint, config digest, seed) are the
    deterministically derived B1 values; the machine profile is the caller's
    declared mapping, passed through verbatim.
    """
    repositories = [
        {"identity": entry["repository"], "commit_sha": entry["commit_sha"]}
        for dataset in manifest["datasets"]
        for entry in dataset["entries"]
    ]
    datasets = [
        {
            "name": dataset["name"],
            "fingerprint": dataset["fingerprint"],
            "role": dataset["role"],
        }
        for dataset in manifest["datasets"]
    ]
    return {
        "schema_version": 1,
        "repositories": repositories,
        "datasets": datasets,
        "analyzer_fingerprint": analyzer_fingerprint,
        "config_digest": config_digest,
        "seed": seed,
        "machine_profile": machine_profile,
    }


def run_b1_source_baseline_suite(
    *,
    output_dir: str | pathlib.Path,
    machine_profile: object,
    fixture_key: str = "archetype/minimal-python-repository",
    seed: int = 0,
    cold_count: int = 3,
    warm_count: int = 5,
    workload: str = B1_WORKLOAD,
    transport: typing.Callable[[dict], dict] | None = None,
    manifest_path: str | pathlib.Path | None = None,
    sources: object = None,
) -> B1SuiteResult:
    """Run one fully offline B1 source-wiring suite (frozen order 1-11).

    Order (Packet 7.6.1): the empty-output-directory gate; the manifest
    load; fixture registry validation, materialization into an internal
    temporary workspace and the snapshot tree fingerprint cross-check; the
    explicit offline configuration document and its digest; the spec build
    with deterministically derived identity faces; ``cold_count`` cold
    attempts each re-materializing the snapshot and re-running the scanner;
    ``warm_count`` warm attempts each reusing the last cold snapshot and scan
    result; the aggregate through the frozen result contract; the report
    through the frozen scanner projection (no bundle, no domain block); the
    per-attempt receipt documents and the closed-key b1-manifest; the
    :class:`B1SuiteResult`.  Every attempt goes through the frozen
    ``run_baseline_attempt`` (an ``Exception`` body becomes a retained
    taxonomy sample while the loop continues; a ``BaseException`` body is
    persisted then re-raised, leaving no aggregate and no receipts).

    The model layer is entirely absent or injected: ``transport`` is called
    at most once per attempt with a canonical request document (workload,
    fixture key, snapshot binding, a candidate file selection bounded by
    :data:`CANDIDATE_FILE_CAP`, attempt index, mode) purely to verify future
    wiring; no measured report field is ever derived from its response, and
    ``model_calls`` stays the constant ``0`` regardless of the transport
    call count.
    """
    if type(cold_count) is not int or cold_count < 1:
        raise TypeError("cold_count must be a positive integer")
    if type(warm_count) is not int or warm_count < 1:
        raise TypeError("warm_count must be a positive integer")
    if type(seed) is not int:
        raise TypeError("seed must be an integer")
    if not isinstance(workload, str) or not workload:
        raise TypeError("workload must be a non-empty string")
    if not isinstance(fixture_key, str) or not fixture_key:
        raise TypeError("fixture_key must be a non-empty string")
    directory = pathlib.Path(output_dir)
    if directory.exists():
        if not directory.is_dir() or any(directory.iterdir()):
            raise B1SourceError(B1SourceErrorCode.B1_OUTPUT_NOT_EMPTY, "$.output_dir")
    else:
        directory.mkdir(parents=True)
    manifest = _load_manifest(manifest_path)
    registry = load_registry()
    fixture_manifest_sha256 = _registry_fingerprint(registry, fixture_key)

    with tempfile.TemporaryDirectory() as workspace:
        probe_root = materialize_fixture(
            fixture_key, pathlib.Path(workspace) / "probe" / "fixture"
        ).root
        verify_fixture(fixture_key, probe_root)
        snapshot_tree_sha256 = _registry_fingerprint(registry, fixture_key)
        if compute_tree_fingerprint(probe_root) != snapshot_tree_sha256:
            raise B1SourceError(
                B1SourceErrorCode.SOURCE_RECEIPT_INVALID, "$.snapshot_tree_sha256"
            )
        scanner_config: dict[str, object] = {
            "workload": workload,
            "fixture_key": fixture_key,
            "snapshot_tree_sha256": snapshot_tree_sha256,
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
        spec_mapping = _build_spec_mapping(
            manifest,
            analyzer_fingerprint=analyzer_fingerprint,
            config_digest=scanner_config_sha256,
            seed=seed,
            machine_profile=machine_profile,
        )
        spec_digest = spec_from_mapping(spec_mapping).content_digest()

        scan_state: dict[str, object] = {"payload": None, "digest": None}
        scanner_executions = 0
        transport_calls = 0
        attempts = []
        result_paths: list[pathlib.Path] = []
        receipts: list[dict[str, object]] = []

        for attempt_index in range(cold_count + warm_count):
            mode = "cold" if attempt_index < cold_count else "warm"
            before = {child.name for child in directory.iterdir()}

            def attempt_body(
                attempt_index: int = attempt_index, mode: str = mode
            ) -> object:
                nonlocal scanner_executions, transport_calls
                if mode == "cold":
                    root = materialize_fixture(
                        fixture_key,
                        pathlib.Path(workspace) / f"cold-{attempt_index:02d}" / "fixture",
                    ).root
                    verify_fixture(fixture_key, root)
                    scan = _scan_snapshot(root)
                    if scan.report.reviewer != analyzer_name:
                        raise ValueError(
                            "realized scanner reviewer identity diverged from "
                            "the frozen offline configuration derivation"
                        )
                    payload = _canonical_payload(scan, fixture_key)
                    scan_state["payload"] = payload
                    scan_state["digest"] = _wire_fingerprint(payload)
                    scanner_executions += 1
                payload = scan_state["payload"]
                if payload is None:
                    raise ValueError("no scanner result is available to consume")
                candidates = sorted(
                    item.path for item in payload.inventory.files
                )[:CANDIDATE_FILE_CAP]
                if transport is not None:
                    transport(
                        {
                            "workload": workload,
                            "fixture_key": fixture_key,
                            "snapshot_tree_sha256": snapshot_tree_sha256,
                            "candidates": candidates,
                            "attempt_index": attempt_index,
                            "mode": mode,
                        }
                    )
                    transport_calls += 1
                return payload

            result = run_baseline_attempt(
                spec_mapping,
                manifest,
                attempt_body,
                directory,
                attempt_index=attempt_index,
                mode=mode,
                sources=sources,
            )
            added = sorted(
                {child.name for child in directory.iterdir()} - before,
                key=lambda name: int(name.rsplit("-", 1)[1].split(".")[0]),
            )
            result_paths.extend(directory / name for name in added)
            attempts.append(result)
            receipts.append(
                {
                    "snapshot_tree_sha256": snapshot_tree_sha256,
                    "fixture_key": fixture_key,
                    "fixture_manifest_sha256": fixture_manifest_sha256,
                    "analyzer_name": analyzer_name,
                    "analyzer_fingerprint": analyzer_fingerprint,
                    "scanner_config_sha256": scanner_config_sha256,
                    "seed": seed,
                    "workload": workload,
                    "run_spec_digest": spec_digest,
                    "attempt_index": attempt_index,
                    "mode": mode,
                    "scanner_payload_sha256": scan_state["digest"],
                    "scanner_reexecuted": mode == "cold",
                    "scanner_result_reused": mode == "warm",
                    "snapshot_reused": mode == "warm",
                    "request_body_rebuilt": mode == "cold",
                }
            )

        report_payload = scan_state["payload"]
        wire_digest = scan_state["digest"]
        if report_payload is None or wire_digest is None:
            raise B1SourceError(
                B1SourceErrorCode.SOURCE_RECEIPT_INVALID, "$.scanner_payload_sha256"
            )
        aggregate = result_from_mapping(
            {
                "schema_version": 1,
                "run_spec_digest": spec_digest,
                "samples": [
                    dict(result.samples[0].items())
                    for result in sorted(
                        attempts, key=lambda result: result.samples[0]["attempt_index"]
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
        report = build_baseline_report(summary, report_payload)
        report_artifacts = write_report_file(report, directory)
        failures = [
            result.samples[0]["failure_code"]
            for result in attempts
            if result.samples[0]["failure_code"] is not None
        ]
        source_receipts_digest = compute_content_digest(receipts)
        attempts_directory = directory / "b1-attempts"
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
            "workload": workload,
            "run_spec_digest": spec_digest,
            "attempt_count": len(attempts),
            "cold_count": cold_count,
            "warm_count": warm_count,
            "fixture_key": fixture_key,
            "fixture_manifest_sha256": fixture_manifest_sha256,
            "snapshot_tree_sha256": snapshot_tree_sha256,
            "analyzer_name": analyzer_name,
            "analyzer_fingerprint": analyzer_fingerprint,
            "scanner_config": scanner_config,
            "scanner_config_sha256": scanner_config_sha256,
            "seed": seed,
            "scanner_payload_sha256": wire_digest,
            "source_receipts": receipts,
            "source_receipts_digest": source_receipts_digest,
            "failures": failures,
            "transport_calls": transport_calls,
            "model_calls": 0,
            "declarations": list(_MANIFEST_DECLARATIONS),
        }
        manifest_file = directory / "b1-manifest.json"
        manifest_bytes = canonical_encode(manifest_document)
        write_exclusive(manifest_file, manifest_bytes)
        return B1SuiteResult(
            run_spec_digest=spec_digest,
            attempt_count=len(attempts),
            status=summary.status,
            result_paths=tuple(result_paths),
            aggregate_path=aggregate_artifacts.result_path,
            aggregate_sha256=aggregate_artifacts.result_sha256,
            report_path=report_artifacts.report_path,
            report_sha256=report_artifacts.report_sha256,
            manifest_path=manifest_file,
            manifest_sha256=compute_content_digest(manifest_bytes),
            source_receipts_digest=source_receipts_digest,
            fixture_key=fixture_key,
            snapshot_tree_sha256=snapshot_tree_sha256,
            scanner_config_sha256=scanner_config_sha256,
            scanner_payload_sha256=wire_digest,
            workload=workload,
            scanner_executions=scanner_executions,
            transport_calls=transport_calls,
            model_calls=0,
            b1=True,
        )


def _read_json_file(path: pathlib.Path, field_path: str) -> object:
    try:
        return json.loads(path.read_bytes().decode("utf-8"))
    except (OSError, UnicodeDecodeError, ValueError) as exc:
        raise B1SourceError(
            B1SourceErrorCode.SOURCE_RECEIPT_INVALID, field_path
        ) from exc


def _validate_receipt(receipt: object, index: int) -> None:
    prefix = f"$.source_receipts[{index}]"
    if not isinstance(receipt, dict) or set(receipt) != _RECEIPT_KEY_SET:
        raise B1SourceError(B1SourceErrorCode.SOURCE_RECEIPT_INVALID, prefix)
    for field in ("snapshot_tree_sha256", "scanner_payload_sha256"):
        if not _is_hex64(receipt[field]):
            raise B1SourceError(
                B1SourceErrorCode.SOURCE_RECEIPT_INVALID, f"{prefix}.{field}"
            )
    for field in ("fixture_manifest_sha256", "analyzer_fingerprint"):
        if not _is_hex64(receipt[field]):
            raise B1SourceError(
                B1SourceErrorCode.SOURCE_RECEIPT_INVALID, f"{prefix}.{field}"
            )
    if not _is_hex64(receipt["scanner_config_sha256"]) or not _is_hex64(
        receipt["run_spec_digest"]
    ):
        raise B1SourceError(
            B1SourceErrorCode.SOURCE_RECEIPT_INVALID, f"{prefix}.scanner_config_sha256"
        )
    if type(receipt["seed"]) is not int or type(receipt["attempt_index"]) is not int:
        raise B1SourceError(
            B1SourceErrorCode.SOURCE_RECEIPT_INVALID, f"{prefix}.seed"
        )
    if receipt["mode"] not in ("cold", "warm"):
        raise B1SourceError(B1SourceErrorCode.SOURCE_RECEIPT_INVALID, f"{prefix}.mode")
    for field in (
        "scanner_reexecuted",
        "scanner_result_reused",
        "snapshot_reused",
        "request_body_rebuilt",
    ):
        if type(receipt[field]) is not bool:
            raise B1SourceError(
                B1SourceErrorCode.SOURCE_RECEIPT_INVALID, f"{prefix}.{field}"
            )
    for field in ("fixture_key", "analyzer_name", "workload"):
        if not isinstance(receipt[field], str) or not receipt[field]:
            raise B1SourceError(
                B1SourceErrorCode.SOURCE_RECEIPT_INVALID, f"{prefix}.{field}"
            )


def verify_b1_evidence(output_dir: str | pathlib.Path) -> dict[str, object]:
    """Re-read one B1 evidence directory and cross-check every binding.

    Checks (Packet 7.6.3/7.6.5, all fail-closed with the typed family, never
    a downgrade to unavailable): the b1-manifest parses and carries exactly
    the closed key set; every receipt in the aggregate list carries exactly
    the sixteen-key set with well-formed digests, modes and reuse booleans;
    the manifest ``source_receipts_digest`` equals the recomputed digest of
    its receipt list; every ``b1-attempts/attempt-*.json`` document carries
    exactly its three-key shape, the suite digest, and a receipt byte-equal
    to its manifest slot; every receipt's ``scanner_payload_sha256`` equals
    the report's single scanner source digest; and the receipt, manifest and
    report ``run_spec_digest`` faces agree.  On success a summary mapping
    with the verified identity faces is returned.
    """
    directory = pathlib.Path(output_dir)
    manifest = _read_json_file(directory / "b1-manifest.json", "$.b1_manifest")
    if not isinstance(manifest, dict) or set(manifest) != _MANIFEST_KEY_SET:
        raise B1SourceError(B1SourceErrorCode.SOURCE_RECEIPT_INVALID, "$.b1_manifest")
    receipts = manifest["source_receipts"]
    if not isinstance(receipts, list) or not receipts:
        raise B1SourceError(
            B1SourceErrorCode.SOURCE_RECEIPT_INVALID, "$.source_receipts"
        )
    for index, receipt in enumerate(receipts):
        _validate_receipt(receipt, index)
    if manifest["source_receipts_digest"] != compute_content_digest(receipts):
        raise B1SourceError(
            B1SourceErrorCode.SOURCE_BINDING_MISMATCH, "$.source_receipts_digest"
        )
    run_spec_digest = manifest["run_spec_digest"]
    if not _is_hex64(run_spec_digest):
        raise B1SourceError(
            B1SourceErrorCode.SOURCE_RECEIPT_INVALID, "$.run_spec_digest"
        )
    attempts_directory = directory / "b1-attempts"
    try:
        document_paths = sorted(attempts_directory.glob("attempt-*.json"))
    except OSError as exc:
        raise B1SourceError(
            B1SourceErrorCode.SOURCE_RECEIPT_INVALID, "$.b1_attempts"
        ) from exc
    if len(document_paths) != len(receipts):
        raise B1SourceError(
            B1SourceErrorCode.SOURCE_BINDING_MISMATCH, "$.b1_attempts"
        )
    for index, (path, receipt) in enumerate(
        zip(document_paths, receipts, strict=True)
    ):
        prefix = f"$.b1_attempts[{index}]"
        document = _read_json_file(path, prefix)
        if not isinstance(document, dict) or set(document) != (
            _ATTEMPT_DOCUMENT_KEY_SET
        ):
            raise B1SourceError(B1SourceErrorCode.SOURCE_RECEIPT_INVALID, prefix)
        if document["schema_version"] != 1 or document["run_spec_digest"] != (
            run_spec_digest
        ):
            raise B1SourceError(B1SourceErrorCode.SOURCE_BINDING_MISMATCH, prefix)
        if document["source_receipt"] != receipt:
            raise B1SourceError(
                B1SourceErrorCode.SOURCE_BINDING_MISMATCH, f"{prefix}.source_receipt"
            )
    report = _read_json_file(
        directory / f"{run_spec_digest[:16]}-report-1.json", "$.report"
    )
    if not isinstance(report, dict):
        raise B1SourceError(B1SourceErrorCode.SOURCE_RECEIPT_INVALID, "$.report")
    if report.get("run_spec_digest") != run_spec_digest:
        raise B1SourceError(
            B1SourceErrorCode.SOURCE_BINDING_MISMATCH, "$.report.run_spec_digest"
        )
    scanner_digest: str | None = None
    report_sources = report.get("sources")
    if isinstance(report_sources, list):
        for source in report_sources:
            if isinstance(source, dict) and source.get("kind") == "scanner":
                scanner_digest = source.get("payload_sha256")
    if not _is_hex64(scanner_digest):
        raise B1SourceError(
            B1SourceErrorCode.SOURCE_RECEIPT_INVALID, "$.report.sources"
        )
    for index, receipt in enumerate(receipts):
        if receipt["scanner_payload_sha256"] != scanner_digest:
            raise B1SourceError(
                B1SourceErrorCode.SCANNER_DIGEST_MISMATCH,
                f"$.source_receipts[{index}].scanner_payload_sha256",
            )
        if receipt["run_spec_digest"] != run_spec_digest:
            raise B1SourceError(
                B1SourceErrorCode.SOURCE_BINDING_MISMATCH,
                f"$.source_receipts[{index}].run_spec_digest",
            )
    if manifest["scanner_payload_sha256"] != scanner_digest:
        raise B1SourceError(
            B1SourceErrorCode.SCANNER_DIGEST_MISMATCH, "$.scanner_payload_sha256"
        )
    return {
        "run_spec_digest": run_spec_digest,
        "scanner_payload_sha256": scanner_digest,
        "source_receipts_digest": manifest["source_receipts_digest"],
        "attempt_count": manifest["attempt_count"],
        "workload": manifest["workload"],
    }
