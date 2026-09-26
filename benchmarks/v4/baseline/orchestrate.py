"""Shared CLI orchestration for LIMA v4 baseline runs (IP-0028).

This module owns the baseline-mode CLI face wired into the three
evaluation scripts: :func:`add_baseline_arguments` adds the three shared
arguments, :func:`run_baseline_from_args` is the CLI adapter that runs the
full pre-execution gate stack exactly once before any attempt starts, and
:func:`run_repeats` executes N cold attempts followed by N warm attempts
through the frozen ``run_baseline_attempt`` and assembles the multi-sample
aggregate exclusively through the frozen
``lima.baseline_run_result.from_mapping`` before persisting it with the
existing ``write_result_file`` under the same digest prefix.

The module is offline and stdlib-only: deterministic, secretless, no
network, and no host configuration lookup.  Token counts, cost, and
expert-timing measurement are honestly absent (``None``); no expert
sidecar is written through this layer.
"""

import argparse
import dataclasses
import enum
import json
import pathlib
import typing

from benchmarks.v4.baseline.collect import (
    BaselineCollectionError,
    BaselineCollectionErrorCode,
)
from benchmarks.v4.baseline.run import (
    run_baseline_attempt,
    validate_role_bindings,
    write_result_file,
)
from lima.baseline_run_result import BaselineRunResult
from lima.baseline_run_result import from_mapping as result_from_mapping
from lima.baseline_run_spec import load_baseline_run_spec, validate_baseline_manifest

__all__ = [
    "add_baseline_arguments",
    "BaselineOrchestrationError",
    "BaselineOrchestrationErrorCode",
    "BaselineRunSummary",
    "run_baseline_from_args",
    "run_repeats",
]

_DEFAULT_MANIFEST_PATH = (
    pathlib.Path(__file__).resolve().parents[3]
    / "evaluation_data"
    / "v4"
    / "baseline_manifest.json"
)


class BaselineOrchestrationErrorCode(str, enum.Enum):  # noqa: UP042 -- signature frozen by IP-0028
    """Frozen wire values for every deterministic CLI orchestration failure."""

    BASELINE_OUTPUT_REQUIRED = "BASELINE_OUTPUT_REQUIRED"
    INVALID_REPEAT_COUNT = "INVALID_REPEAT_COUNT"
    MANIFEST_UNREADABLE = "MANIFEST_UNREADABLE"


_STABLE_MESSAGES: dict[BaselineOrchestrationErrorCode, str] = {
    BaselineOrchestrationErrorCode.BASELINE_OUTPUT_REQUIRED: (
        "A baseline run requires the --baseline-output directory."
    ),
    BaselineOrchestrationErrorCode.INVALID_REPEAT_COUNT: (
        "The baseline repeat count must be a positive integer."
    ),
    BaselineOrchestrationErrorCode.MANIFEST_UNREADABLE: (
        "The baseline manifest file could not be read."
    ),
}


class BaselineOrchestrationError(ValueError):
    """Deterministic CLI orchestration violation with a stable code and message.

    The shape aligns with the frozen collection/spec/result error
    precedents while remaining an independent class that neither subclasses
    nor reuses them.  The rendered message is exactly the catalog entry
    above; raw payloads, secrets, and field values are never embedded.  Use
    ``field_path`` for structure-only position reporting such as
    ``$.baseline_output``.
    """

    code: BaselineOrchestrationErrorCode
    field_path: str

    def __init__(self, code: BaselineOrchestrationErrorCode, field_path: str = "") -> None:
        if not isinstance(code, BaselineOrchestrationErrorCode):
            raise TypeError("code must be a BaselineOrchestrationErrorCode member")
        if not isinstance(field_path, str):
            raise TypeError("field_path must be a str")
        self.code = code
        self.field_path = field_path
        super().__init__(_STABLE_MESSAGES[code])


def _positive_int(value: str) -> int:
    """argparse ``type`` guard: the repeat count must be a positive integer.

    A non-integer or non-positive value raises ``argparse.ArgumentTypeError``
    so ``parse_args`` fails with ``SystemExit(2)`` before any execution.
    """

    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise argparse.ArgumentTypeError("must be a positive integer") from exc
    if parsed < 1:
        raise argparse.ArgumentTypeError("must be a positive integer")
    return parsed


def add_baseline_arguments(parser: argparse.ArgumentParser) -> None:
    """Add the three baseline-mode arguments shared by the evaluation scripts.

    ``--run-spec`` switches the script into baseline mode; in that mode the
    legacy report parameters (``--output`` / ``--output-dir``) are inert and
    ``--baseline-output`` is the only output channel.  Real repository or
    model runs are manual-only and require a budget cap whose numeric
    limits are still to be fixed by a later slice.
    """

    parser.add_argument(
        "--run-spec",
        default=None,
        help="Path to a baseline run spec JSON; switches the script to baseline mode.",
    )
    parser.add_argument(
        "--baseline-output",
        default=None,
        help="Existing directory for baseline result files (required with --run-spec).",
    )
    parser.add_argument(
        "--repeat",
        type=_positive_int,
        default=5,
        help="Executions per mode (N cold then N warm); default 5.",
    )


@dataclasses.dataclass(frozen=True, slots=True)
class BaselineRunSummary:
    """Paths, artifacts, and aggregate of one orchestrated baseline run."""

    attempts: tuple[BaselineRunResult, ...]
    result_paths: tuple[pathlib.Path, ...]
    aggregate: BaselineRunResult
    aggregate_path: pathlib.Path
    aggregate_sha256: str
    status: str


def _load_manifest(manifest_path: str | pathlib.Path | None) -> object:
    """Read and parse the baseline manifest, failing closed with a typed error.

    ``manifest_path=None`` resolves to the frozen default manifest path
    next to the repository root; the lookup is deterministic and offline.
    A missing or unreadable file, a non-UTF-8 byte stream, or invalid JSON
    raises :class:`BaselineOrchestrationError` with ``MANIFEST_UNREADABLE``.
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


def run_baseline_from_args(
    args: argparse.Namespace,
    *,
    execute: typing.Callable[[], object],
    sources: object = None,
    manifest_path: str | pathlib.Path | None = None,
) -> BaselineRunSummary:
    """Adapt parsed CLI arguments to one fully gated orchestrated baseline run.

    Operation order (frozen; any failure below means zero execute calls and
    zero files written): the argument-combination gate, the repeat-count
    gate, the frozen spec load (typed errors pass through unchanged), the
    manifest load, the one-shot gate stack (the frozen manifest cross-check
    and then the SF-01 role binding gate), the output-directory gate, and
    finally the delegation to :func:`run_repeats`.
    """

    if args.run_spec is not None and args.baseline_output is None:
        raise BaselineOrchestrationError(
            BaselineOrchestrationErrorCode.BASELINE_OUTPUT_REQUIRED, "$.baseline_output"
        )
    if type(args.repeat) is not int or args.repeat < 1:
        raise BaselineOrchestrationError(
            BaselineOrchestrationErrorCode.INVALID_REPEAT_COUNT, "$.repeat"
        )
    spec = load_baseline_run_spec(args.run_spec)
    manifest = _load_manifest(manifest_path)
    validate_baseline_manifest(manifest, spec)
    validate_role_bindings(spec, manifest)
    if not pathlib.Path(args.baseline_output).is_dir():
        raise BaselineCollectionError(
            BaselineCollectionErrorCode.OUTPUT_DIRECTORY_UNAVAILABLE, "$.output_dir"
        )
    return run_repeats(
        spec.to_canonical_value(),
        manifest,
        execute,
        args.baseline_output,
        repeat=args.repeat,
        sources=sources,
    )


def run_repeats(
    spec_mapping: object,
    manifest: object,
    execute: typing.Callable[[], object],
    output_dir: str | pathlib.Path,
    *,
    repeat: int = 5,
    sources: object = None,
) -> BaselineRunSummary:
    """Execute N cold then N warm attempts and persist one aggregate result.

    Attempt indices are assigned globally: cold attempts take
    ``0..repeat-1`` and warm attempts ``repeat..2*repeat-1``.  Every attempt
    goes through the frozen ``run_baseline_attempt`` (which re-runs the full
    gate stack idempotently, writes one exclusive per-attempt result file,
    turns ``Exception`` bodies into retained taxonomy samples while the
    orchestration continues, and re-raises control-flow ``BaseException``
    bodies after persisting that attempt, in which case no aggregate is
    written and no summary is built).  The aggregate carries all samples
    (failures included, sorted by attempt index), is assembled only through
    the frozen ``from_mapping``, and is persisted through the existing
    ``write_result_file`` under the same digest prefix with the next free
    sequence number.  An absent output directory is not gated here; the
    first attempt fails closed with the frozen typed directory error.
    """

    if type(repeat) is not int or repeat < 1:
        raise BaselineOrchestrationError(
            BaselineOrchestrationErrorCode.INVALID_REPEAT_COUNT, "$.repeat"
        )
    directory = pathlib.Path(output_dir)
    before = {path.name for path in directory.iterdir()} if directory.is_dir() else set()
    attempts: list[BaselineRunResult] = []
    for index in range(repeat):
        attempts.append(
            run_baseline_attempt(
                spec_mapping,
                manifest,
                execute,
                output_dir,
                attempt_index=index,
                mode="cold",
                sources=sources,
            )
        )
    for index in range(repeat):
        attempts.append(
            run_baseline_attempt(
                spec_mapping,
                manifest,
                execute,
                output_dir,
                attempt_index=repeat + index,
                mode="warm",
                sources=sources,
            )
        )
    aggregate = result_from_mapping(
        {
            "schema_version": 1,
            "run_spec_digest": attempts[0].run_spec_digest,
            "samples": [
                dict(result.samples[0].items())
                for result in sorted(
                    attempts, key=lambda result: result.samples[0]["attempt_index"]
                )
            ],
        }
    )
    artifacts = write_result_file(aggregate, output_dir)
    after = {path.name for path in directory.iterdir()}
    new_names = after - before - {artifacts.result_path.name}
    result_paths = tuple(
        sorted(
            (directory / name for name in new_names),
            key=lambda path: int(path.stem.rsplit("-", 1)[1]),
        )
    )
    return BaselineRunSummary(
        attempts=tuple(attempts),
        result_paths=result_paths,
        aggregate=aggregate,
        aggregate_path=artifacts.result_path,
        aggregate_sha256=artifacts.result_sha256,
        status=aggregate.status,
    )
