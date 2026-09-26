"""SF-01 role gate, collection runner, and result writer for LIMA v4 baselines (IP-0027).

This module consumes the frozen contracts read-only: specs are built by
``lima.baseline_run_spec.from_mapping`` and cross-checked by
``validate_baseline_manifest``, results are assembled by
``lima.baseline_run_result.from_mapping`` and persisted byte-identically
through ``BaselineRunResult.canonical_bytes``.  On top of that it adds the
consumer side of SF-IP-0026-20260925-01: an explicit dataset-to-role binding
gate against a frozen third-party registry, because the frozen cross-check
compares fingerprints by name but never compares spec-side and manifest-side
dataset roles.

The runner never starts the execution body before every gate passes, and the
writer never overwrites history: result files are named deterministically
from the run spec digest prefix plus a monotonic sequence number and are
created exclusively, so a repeated execution of the same spec always adds a
new file and failed runs are retained with a bounded failure taxonomy code.
"""

import dataclasses
import pathlib
import types
import typing

from benchmarks.v4.baseline.collect import (
    BaselineCollectionError,
    BaselineCollectionErrorCode,
    PlatformSources,
    classify_failure,
    elapsed_ms,
    require_metric,
)
from lima.baseline_run_result import BaselineRunResult
from lima.baseline_run_result import from_mapping as result_from_mapping
from lima.baseline_run_spec import BaselineRunSpec, validate_baseline_manifest
from lima.baseline_run_spec import from_mapping as spec_from_mapping

__all__ = [
    "FROZEN_DATASET_BINDINGS",
    "ResultFileArtifacts",
    "validate_role_bindings",
    "write_exclusive",
    "write_result_file",
    "run_baseline_attempt",
]

_BINDING_FIELDS = ("name", "fingerprint", "role")

_TAXONOMY_OUTCOMES: dict[str, str] = {
    "EXECUTION_ERROR": "failure",
    "EXECUTION_TIMEOUT": "timeout",
    "EXECUTION_CANCELLED": "cancelled",
}

# Third-party truth transcribed verbatim from
# evaluation_data/v4/baseline_manifest.json (IP-0026, baseline 2f4b8bb):
# dataset name -> (role, fingerprint) double-pinned bindings.  The registry
# fingerprint pin catches self-consistent recomputations where a spec and a
# manifest are mutated together and therefore agree with each other.
FROZEN_DATASET_BINDINGS = types.MappingProxyType(
    {
        "lima-popular-python-calibration-v1": (
            "calibration",
            "049d69b25731e51f75a800c5c406ab2d8faef1257d7dacfb275f9734b407b986",
        ),
        "lima-popular-python-external-holdout-v2": (
            "external-holdout",
            "23d4ef1da097e6af3d1099546d3cb6167b8964ecdc23f546ad5a835f342b284a",
        ),
        "lima-real-world-pilot-v1": (
            "development",
            "7d88728caca8bc3387802b7bdaa09b59e5ffe1fede21a71c3d314bd63eb0c106",
        ),
    }
)


def _check_dataset_against_registry(
    name: object, role: object, fingerprint: object, index: int
) -> None:
    """Compare one dataset triple against the frozen registry, in order."""
    prefix = f"$.datasets[{index}]"
    if not isinstance(name, str) or name not in FROZEN_DATASET_BINDINGS:
        raise BaselineCollectionError(
            BaselineCollectionErrorCode.UNKNOWN_FROZEN_DATASET, f"{prefix}.name"
        )
    frozen_role, frozen_fingerprint = FROZEN_DATASET_BINDINGS[name]
    if role != frozen_role:
        raise BaselineCollectionError(
            BaselineCollectionErrorCode.ROLE_BINDING_MISMATCH, f"{prefix}.role"
        )
    if fingerprint != frozen_fingerprint:
        raise BaselineCollectionError(
            BaselineCollectionErrorCode.FROZEN_FINGERPRINT_MISMATCH,
            f"{prefix}.fingerprint",
        )


def validate_role_bindings(spec: BaselineRunSpec, manifest: object) -> None:
    """Explicit dataset-to-role binding gate against the frozen registry (SF-01).

    The shape gate rejects a non-spec ``spec``, a non-dict ``manifest``, a
    non-list ``manifest["datasets"]``, and any manifest dataset element that
    is not a dict or lacks ``name``/``fingerprint``/``role``.  The spec side
    is then checked first and the manifest side second, each dataset against
    the frozen registry truth by name, role, and fingerprint.  Any violation
    fails closed with a typed error before any execution body may start;
    this function performs no I/O of its own and returns ``None`` on pass.
    """
    if not isinstance(spec, BaselineRunSpec):
        raise BaselineCollectionError(
            BaselineCollectionErrorCode.INVALID_FIELD_TYPE, "$"
        )
    if not isinstance(manifest, dict):
        raise BaselineCollectionError(
            BaselineCollectionErrorCode.INVALID_FIELD_TYPE, "$"
        )
    manifest_datasets = manifest.get("datasets")
    if not isinstance(manifest_datasets, list):
        raise BaselineCollectionError(
            BaselineCollectionErrorCode.INVALID_FIELD_TYPE, "$.datasets"
        )
    for index, dataset in enumerate(manifest_datasets):
        prefix = f"$.datasets[{index}]"
        if not isinstance(dataset, dict):
            raise BaselineCollectionError(
                BaselineCollectionErrorCode.INVALID_FIELD_TYPE, prefix
            )
        for field in _BINDING_FIELDS:
            if field not in dataset:
                raise BaselineCollectionError(
                    BaselineCollectionErrorCode.INVALID_FIELD_TYPE, f"{prefix}.{field}"
                )
    for index, dataset in enumerate(spec.datasets):
        _check_dataset_against_registry(
            dataset["name"], dataset["role"], dataset["fingerprint"], index
        )
    for index, dataset in enumerate(manifest_datasets):
        _check_dataset_against_registry(
            dataset["name"], dataset["role"], dataset["fingerprint"], index
        )


@dataclasses.dataclass(frozen=True, slots=True)
class ResultFileArtifacts:
    """Paths and SHA-256 digests of one persisted result (and sidecar) file."""

    result_path: pathlib.Path
    sidecar_path: pathlib.Path | None
    result_sha256: str
    sidecar_sha256: str | None


def write_exclusive(path: pathlib.Path, payload: bytes) -> None:
    """Create ``path`` exclusively with ``payload``; never overwrite.

    An already existing path fails closed with a typed error and its bytes
    are left untouched.  The typed error carries the structure-only
    ``$.output_path`` field path; host paths are never embedded.
    """
    try:
        with open(path, "xb") as handle:
            handle.write(payload)
    except FileExistsError as exc:
        raise BaselineCollectionError(
            BaselineCollectionErrorCode.OUTPUT_PATH_ALREADY_EXISTS, "$.output_path"
        ) from exc


def write_result_file(
    result: BaselineRunResult,
    output_dir: str | pathlib.Path,
    *,
    expert_session: object = None,
) -> ResultFileArtifacts:
    """Persist one result file (and optional expert-timing sidecar) exclusively.

    The output directory must already exist and be a directory; this slice
    defines no default directory; the typed directory error carries the
    structure-only ``$.output_dir`` field path.  The result file name is
    deterministic and wall-clock-free: ``{run_spec_digest[:16]}-run-{n}.json``
    with ``n`` the smallest positive integer not yet taken under that prefix
    by either the result file name or the matching ``.expert-timing.json``
    sidecar name (both names are probed against the directory state alone),
    so re-running the same spec always adds a new file instead of
    overwriting history.
    The result payload is exactly ``result.canonical_bytes()``; when an
    expert session is provided, a sidecar with the same stem and the
    ``.expert-timing.json`` suffix carries ``expert_session.sidecar_bytes``.
    """
    directory = pathlib.Path(output_dir)
    if not directory.is_dir():
        raise BaselineCollectionError(
            BaselineCollectionErrorCode.OUTPUT_DIRECTORY_UNAVAILABLE, "$.output_dir"
        )
    prefix = result.run_spec_digest[:16]
    sequence = 1
    while (
        (directory / f"{prefix}-run-{sequence}.json").exists()
        or (directory / f"{prefix}-run-{sequence}.expert-timing.json").exists()
    ):
        sequence += 1
    result_path = directory / f"{prefix}-run-{sequence}.json"
    write_exclusive(result_path, result.canonical_bytes())
    if expert_session is None:
        return ResultFileArtifacts(
            result_path=result_path,
            sidecar_path=None,
            result_sha256=result.content_digest(),
            sidecar_sha256=None,
        )
    sidecar_path = result_path.with_name(
        result_path.stem + ".expert-timing.json"
    )
    write_exclusive(
        sidecar_path, expert_session.sidecar_bytes(result.run_spec_digest)
    )
    return ResultFileArtifacts(
        result_path=result_path,
        sidecar_path=sidecar_path,
        result_sha256=result.content_digest(),
        sidecar_sha256=expert_session.sidecar_digest(result.run_spec_digest),
    )


def run_baseline_attempt(
    spec_mapping: object,
    manifest: object,
    execute: typing.Callable[[], object],
    output_dir: str | pathlib.Path,
    *,
    attempt_index: int = 0,
    mode: str = "cold",
    enqueued_ns: int | None = None,
    sources: PlatformSources | None = None,
    prompt_tokens: int | None = None,
    completion_tokens: int | None = None,
    cost_micro_usd: int | None = None,
    expert_session: object = None,
) -> BaselineRunResult:
    """Run exactly one guarded collection attempt and persist its result file.

    Gate order (frozen; any failure means zero execute calls and zero files
    written): metric parameter types, output directory availability, the
    frozen spec layer (moving refs, abbreviated SHAs, fingerprint shapes),
    the frozen manifest cross-check, and the role binding gate; the typed
    directory error carries the structure-only ``$.output_dir`` field path.
    Only after every gate passes is ``execute()`` invoked.

    Timing and platform metrics come from ``sources`` (defaults read the
    real platform); every recorded value is an int or None.  A failing
    execution body still produces and retains a result file with a bounded
    taxonomy failure code.  ``Exception`` bodies return the failure result;
    control-flow ``BaseException`` bodies (cancellation, interrupt, exit)
    are classified, persisted, and then re-raised unchanged.  A non-monotonic
    clock reading aborts without writing any file.
    """
    require_metric(prompt_tokens, "$.samples[0].prompt_tokens")
    require_metric(completion_tokens, "$.samples[0].completion_tokens")
    require_metric(cost_micro_usd, "$.samples[0].cost_micro_usd")
    directory = pathlib.Path(output_dir)
    if not directory.is_dir():
        raise BaselineCollectionError(
            BaselineCollectionErrorCode.OUTPUT_DIRECTORY_UNAVAILABLE, "$.output_dir"
        )
    spec = spec_from_mapping(spec_mapping)
    validate_baseline_manifest(manifest, spec)
    validate_role_bindings(spec, manifest)

    if sources is None:
        sources = PlatformSources()
    wall_start = sources.wall_ns()
    cpu_start = sources.cpu_ns()
    caught: BaseException | None = None
    try:
        execute()
    except BaseException as exception:  # noqa: B036 -- re-raised below after persisting
        caught = exception
    if caught is None:
        outcome = "success"
        failure_code: str | None = None
    else:
        failure_code = classify_failure(caught)
        outcome = _TAXONOMY_OUTCOMES[failure_code]
    wall_end = sources.wall_ns()
    cpu_end = sources.cpu_ns()

    wall_time_ms = elapsed_ms(wall_start, wall_end)
    cpu_time_ms = elapsed_ms(cpu_start, cpu_end)
    queue_time_ms = (
        elapsed_ms(enqueued_ns, wall_start) if enqueued_ns is not None else None
    )
    memory_rss_peak_bytes = require_metric(
        sources.peak_rss_bytes(), "$.samples[0].memory_rss_peak_bytes"
    )
    io_read_bytes = require_metric(
        sources.io_read_bytes(), "$.samples[0].io_read_bytes"
    )
    io_write_bytes = require_metric(
        sources.io_write_bytes(), "$.samples[0].io_write_bytes"
    )
    expert_time_ms = (
        expert_session.active_time_ms() if expert_session is not None else None
    )
    sample: dict[str, object] = {
        "attempt_index": attempt_index,
        "mode": mode,
        "outcome": outcome,
        "wall_time_ms": wall_time_ms,
        "queue_time_ms": queue_time_ms,
        "cpu_time_ms": cpu_time_ms,
        "expert_time_ms": expert_time_ms,
        "memory_rss_peak_bytes": memory_rss_peak_bytes,
        "io_read_bytes": io_read_bytes,
        "io_write_bytes": io_write_bytes,
        "prompt_tokens": prompt_tokens,
        "completion_tokens": completion_tokens,
        "cost_micro_usd": cost_micro_usd,
        "failure_code": failure_code,
    }
    result = result_from_mapping(
        {
            "schema_version": 1,
            "run_spec_digest": spec.content_digest(),
            "samples": [sample],
        }
    )
    write_result_file(result, directory, expert_session=expert_session)
    if caught is not None and not isinstance(caught, Exception):
        raise caught
    return result
