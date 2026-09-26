"""Collection primitives for LIMA v4 baseline runs (IP-0027).

This module owns the package-wide typed error family
(:class:`BaselineCollectionError` with the closed
:class:`BaselineCollectionErrorCode` set), the bounded execution failure
taxonomy, the monotonic clock guard, the int-or-None metric type gate, and
the injectable platform metric sources.  Every metric value is an ``int`` or
``None``: floating point values are rejected outright because the frozen
canonical codec refuses them, and unavailable platform metrics are reported
as ``None`` rather than fabricated (for example peak RSS and I/O counters on
platforms without the ``resource`` module or without ``/proc/self/io``).

The module is a pure offline stdlib-only library: deterministic, secretless,
no network, no environment reads, and no host probing beyond the documented
platform sources.
"""

import dataclasses
import enum
import pathlib
import time
import typing

try:  # POSIX-only module; guarded so other platforms degrade to None.
    import resource
except ImportError:  # pragma: no cover - platform dependent
    resource = None

__all__ = [
    "BaselineCollectionError",
    "BaselineCollectionErrorCode",
    "FAILURE_TAXONOMY_CODES",
    "classify_failure",
    "elapsed_ms",
    "require_metric",
    "read_peak_rss_bytes",
    "read_io_bytes",
    "default_io_read_bytes",
    "default_io_write_bytes",
    "PlatformSources",
]

_NS_PER_MS = 1_000_000
_PROC_SELF_IO_PATH = pathlib.Path("/proc/self/io")


class BaselineCollectionErrorCode(str, enum.Enum):  # noqa: UP042 -- frozen by IP-0027 7.0
    """Frozen wire values for every deterministic baseline-collection failure."""

    INVALID_FIELD_TYPE = "INVALID_FIELD_TYPE"
    UNKNOWN_FROZEN_DATASET = "UNKNOWN_FROZEN_DATASET"
    ROLE_BINDING_MISMATCH = "ROLE_BINDING_MISMATCH"
    FROZEN_FINGERPRINT_MISMATCH = "FROZEN_FINGERPRINT_MISMATCH"
    CLOCK_NOT_MONOTONIC = "CLOCK_NOT_MONOTONIC"
    INVALID_METRIC_TYPE = "INVALID_METRIC_TYPE"
    INVALID_REVIEWER_ID = "INVALID_REVIEWER_ID"
    EVENT_SEQUENCE_INVALID = "EVENT_SEQUENCE_INVALID"
    OUTPUT_DIRECTORY_UNAVAILABLE = "OUTPUT_DIRECTORY_UNAVAILABLE"
    OUTPUT_PATH_ALREADY_EXISTS = "OUTPUT_PATH_ALREADY_EXISTS"


_STABLE_MESSAGES: dict[BaselineCollectionErrorCode, str] = {
    BaselineCollectionErrorCode.INVALID_FIELD_TYPE: (
        "Baseline collection field has an invalid type."
    ),
    BaselineCollectionErrorCode.UNKNOWN_FROZEN_DATASET: (
        "Dataset name is not part of the frozen baseline dataset registry."
    ),
    BaselineCollectionErrorCode.ROLE_BINDING_MISMATCH: (
        "Dataset role differs from the frozen baseline dataset registry."
    ),
    BaselineCollectionErrorCode.FROZEN_FINGERPRINT_MISMATCH: (
        "Dataset fingerprint differs from the frozen baseline dataset registry."
    ),
    BaselineCollectionErrorCode.CLOCK_NOT_MONOTONIC: (
        "Monotonic clock readings moved backwards."
    ),
    BaselineCollectionErrorCode.INVALID_METRIC_TYPE: (
        "Baseline collection metric values must be int or None."
    ),
    BaselineCollectionErrorCode.INVALID_REVIEWER_ID: (
        "Expert reviewer id must be a non-empty string."
    ),
    BaselineCollectionErrorCode.EVENT_SEQUENCE_INVALID: (
        "Expert timing event is invalid for the current session state."
    ),
    BaselineCollectionErrorCode.OUTPUT_DIRECTORY_UNAVAILABLE: (
        "The requested output directory is unavailable."
    ),
    BaselineCollectionErrorCode.OUTPUT_PATH_ALREADY_EXISTS: (
        "The requested output path already exists and is never overwritten."
    ),
}


class BaselineCollectionError(ValueError):
    """Deterministic baseline-collection violation with a stable code and message.

    The shape aligns with the frozen ``BaselineRunSpecError`` /
    ``BaselineRunResultError`` precedent while remaining an independent
    class.  The rendered message is exactly the catalog entry above; raw
    payloads, secrets, and field values are never embedded.  Use
    ``field_path`` for structure-only position reporting such as
    ``$.datasets[0].role``.
    """

    code: BaselineCollectionErrorCode
    field_path: str

    def __init__(self, code: BaselineCollectionErrorCode, field_path: str = "") -> None:
        if not isinstance(code, BaselineCollectionErrorCode):
            raise TypeError("code must be a BaselineCollectionErrorCode member")
        if not isinstance(field_path, str):
            raise TypeError("field_path must be a str")
        self.code = code
        self.field_path = field_path
        super().__init__(_STABLE_MESSAGES[code])


FAILURE_TAXONOMY_CODES = frozenset(
    {"EXECUTION_ERROR", "EXECUTION_TIMEOUT", "EXECUTION_CANCELLED"}
)


def classify_failure(exception: BaseException) -> str:
    """Classify one execution-body exception into the bounded failure taxonomy.

    ``TimeoutError`` (including subclasses) maps to ``EXECUTION_TIMEOUT``;
    ``KeyboardInterrupt`` and cancellation errors map to
    ``EXECUTION_CANCELLED``; everything else maps to ``EXECUTION_ERROR``.
    Cancellation is detected structurally (an exception class named
    ``CancelledError`` in the method resolution order) so that the asyncio
    control-flow exception is recognized without importing asyncio here.
    """
    if isinstance(exception, TimeoutError):
        return "EXECUTION_TIMEOUT"
    if isinstance(exception, KeyboardInterrupt):
        return "EXECUTION_CANCELLED"
    if any(base.__name__ == "CancelledError" for base in type(exception).__mro__):
        return "EXECUTION_CANCELLED"
    return "EXECUTION_ERROR"


def elapsed_ms(start_ns: int, end_ns: int) -> int:
    """Elapsed whole milliseconds between two monotonic nanosecond reads.

    Reads must be exact ``int`` values (``bool`` and ``float`` are rejected)
    and the end read must not precede the start read; equal reads are legal
    and yield zero.  Any violation fails closed with a typed error instead
    of producing an untrustworthy duration.
    """
    if type(start_ns) is not int or type(end_ns) is not int:
        raise BaselineCollectionError(
            BaselineCollectionErrorCode.INVALID_METRIC_TYPE, "$.time_ns"
        )
    if end_ns < start_ns:
        raise BaselineCollectionError(
            BaselineCollectionErrorCode.CLOCK_NOT_MONOTONIC, "$.time_ns"
        )
    return (end_ns - start_ns) // _NS_PER_MS


def require_metric(value: object, field_path: str) -> int | None:
    """Pass ``None`` through, or require an exact ``int`` metric value.

    ``bool`` and ``float`` are rejected because the frozen canonical codec
    refuses floats and boolean metrics are meaningless; negative values are
    not rejected here (the frozen result contract owns that domain check).
    """
    if value is None:
        return None
    if type(value) is not int:
        raise BaselineCollectionError(
            BaselineCollectionErrorCode.INVALID_METRIC_TYPE, field_path
        )
    return value


def _linux_procfs_available() -> bool:
    """Whether the Linux procfs backing the I/O counters is present."""
    try:
        return _PROC_SELF_IO_PATH.is_file()
    except OSError:  # pragma: no cover - defensive, e.g. invalid path state
        return False


def read_peak_rss_bytes() -> int | None:
    """Peak resident set size of this process in bytes, or ``None``.

    POSIX platforms report ``resource.getrusage(RUSAGE_SELF).ru_maxrss``
    scaled by the platform convention: Linux reports KiB (detected through
    the procfs presence that also backs :func:`read_io_bytes`) while macOS
    already reports bytes.  Platforms without the ``resource`` module
    (Windows) honestly report ``None`` instead of fabricating a value.
    """
    if resource is None:
        return None
    raw = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    if type(raw) is not int or raw < 0:
        return None
    if _linux_procfs_available():
        return raw * 1024
    return raw


def read_io_bytes() -> tuple[int | None, int | None]:
    """Return ``(read_bytes, write_bytes)`` from Linux ``/proc/self/io``.

    Any platform without the file, or any read or parse failure, yields
    ``(None, None)``; values are never fabricated.
    """
    try:
        text = _PROC_SELF_IO_PATH.read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        return (None, None)
    counters: dict[str, int] = {}
    for line in text.splitlines():
        key, separator, value = line.partition(":")
        if not separator:
            continue
        name = key.strip()
        if name not in ("read_bytes", "write_bytes"):
            continue
        digits = value.strip()
        if not digits.isdigit():
            continue
        counters[name] = int(digits)
    return (counters.get("read_bytes"), counters.get("write_bytes"))


def default_io_read_bytes() -> int | None:
    """Component wrapper of :func:`read_io_bytes` for the read counter."""
    return read_io_bytes()[0]


def default_io_write_bytes() -> int | None:
    """Component wrapper of :func:`read_io_bytes` for the write counter."""
    return read_io_bytes()[1]


@dataclasses.dataclass(frozen=True, slots=True)
class PlatformSources:
    """Injectable platform metric sources (stdlib-only, int-or-None).

    Tests inject deterministic fake callables; the defaults read the real
    platform clocks and counters.  Source return values still pass the
    :func:`require_metric` type gate in the runner, so a source yielding a
    float or bool fails closed exactly like a raw parameter would.
    """

    wall_ns: typing.Callable[[], int] = time.perf_counter_ns
    cpu_ns: typing.Callable[[], int] = time.process_time_ns
    peak_rss_bytes: typing.Callable[[], int | None] = read_peak_rss_bytes
    io_read_bytes: typing.Callable[[], int | None] = default_io_read_bytes
    io_write_bytes: typing.Callable[[], int | None] = default_io_write_bytes
