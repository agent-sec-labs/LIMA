"""Frozen result contract for LIMA v4 baseline runs (IP-0025).

A :class:`BaselineRunResult` freezes the observed sample set of one baseline
run: every attempt with its mode, open-vocabulary outcome, ten nullable
integer metrics, and a bounded stable failure code.  Successful samples must
record a wall time and failure codes must pair with non-success outcomes;
every schema, type, value-domain, or cross-field violation fails closed with
a typed error before any aggregation happens.

Percentiles are nearest-rank p50/p95 computed with pure integer arithmetic
over the successful samples' wall times, independently per mode.  The status
follows an all-or-nothing policy: at least 3 cold and 5 warm successes yield
``sufficient_sample`` with four integer percentiles, anything less yields
``insufficient_sample`` with four null percentiles (never partial).

Canonical JSON and the SHA-256 digest are delegated entirely to
``lima.contracts.codec``; identical semantic input -- including any sample
permutation -- always produces byte-identical canonical bytes and an identical
digest, recomputed fresh on every call.

The module is a pure offline library: deterministic, secretless, no network,
and no environment reads.  Constructed results are deeply immutable: every
mutation attempt against the result, its sample collection, or a sample entry
fails closed, and mutating the input mapping or a canonical copy can never
change the frozen content.
"""

import dataclasses
import enum
import re
from typing import NoReturn

from lima.contracts.codec import JSONValue, canonical_encode, compute_content_digest

__all__ = [
    "BaselineRunResult",
    "BaselineRunResultError",
    "BaselineRunResultErrorCode",
    "from_mapping",
]

_SCHEMA_VERSION = 1
_INT64_MAX = 2**63 - 1

_TOP_LEVEL_FIELDS = ("schema_version", "run_spec_digest", "samples")
_MODES = ("cold", "warm")

_METRIC_FIELDS = (
    "wall_time_ms",
    "queue_time_ms",
    "cpu_time_ms",
    "expert_time_ms",
    "memory_rss_peak_bytes",
    "io_read_bytes",
    "io_write_bytes",
    "prompt_tokens",
    "completion_tokens",
    "cost_micro_usd",
)

_SAMPLE_FIELDS = ("attempt_index", "mode", "outcome") + _METRIC_FIELDS + ("failure_code",)

_RUN_SPEC_DIGEST_PATTERN = re.compile(r"[0-9a-f]{64}")
_OUTCOME_PATTERN = re.compile(r"[a-z][a-z0-9_]{0,63}")
_FAILURE_CODE_PATTERN = re.compile(r"[A-Z][A-Z0-9_]{0,63}")

_COLD_MIN_SUCCESSES = 3
_WARM_MIN_SUCCESSES = 5
_STATUS_SUFFICIENT = "sufficient_sample"
_STATUS_INSUFFICIENT = "insufficient_sample"


class BaselineRunResultErrorCode(str, enum.Enum):  # noqa: UP042 -- signature frozen by IP-0025
    """Frozen wire values for every deterministic baseline-result failure."""

    SCHEMA_VERSION_INVALID = "SCHEMA_VERSION_INVALID"
    REQUIRED_FIELD_MISSING = "REQUIRED_FIELD_MISSING"
    UNKNOWN_FIELD = "UNKNOWN_FIELD"
    INVALID_FIELD_TYPE = "INVALID_FIELD_TYPE"
    INVALID_FIELD_VALUE = "INVALID_FIELD_VALUE"
    INVALID_DIGEST = "INVALID_DIGEST"
    DUPLICATE_ATTEMPT_INDEX = "DUPLICATE_ATTEMPT_INDEX"
    SUCCESS_WALL_TIME_REQUIRED = "SUCCESS_WALL_TIME_REQUIRED"
    FAILURE_CODE_CONFLICT = "FAILURE_CODE_CONFLICT"


_STABLE_MESSAGES: dict[BaselineRunResultErrorCode, str] = {
    BaselineRunResultErrorCode.SCHEMA_VERSION_INVALID: (
        "Baseline run result schema version is invalid."
    ),
    BaselineRunResultErrorCode.REQUIRED_FIELD_MISSING: (
        "A required baseline run result field is missing."
    ),
    BaselineRunResultErrorCode.UNKNOWN_FIELD: (
        "Baseline run result contains an unknown field for this schema version."
    ),
    BaselineRunResultErrorCode.INVALID_FIELD_TYPE: (
        "Baseline run result field has an invalid type."
    ),
    BaselineRunResultErrorCode.INVALID_FIELD_VALUE: (
        "Baseline run result field has an invalid value."
    ),
    BaselineRunResultErrorCode.INVALID_DIGEST: (
        "Run spec digest is not a lowercase 64-character hex digest."
    ),
    BaselineRunResultErrorCode.DUPLICATE_ATTEMPT_INDEX: (
        "Attempt indices must be unique across all samples."
    ),
    BaselineRunResultErrorCode.SUCCESS_WALL_TIME_REQUIRED: (
        "Successful samples must record a wall time."
    ),
    BaselineRunResultErrorCode.FAILURE_CODE_CONFLICT: (
        "Failure code must be present if and only if the outcome is not a success."
    ),
}


class BaselineRunResultError(ValueError):
    """Deterministic baseline-result violation with a stable code and message.

    The shape aligns with the contract error family while remaining an
    independent class.  The rendered message is exactly the catalog entry
    above; raw payloads, secrets, and field values are never embedded.  Use
    ``field_path`` for structure-only position reporting such as
    ``$.samples[0].mode``.
    """

    code: BaselineRunResultErrorCode
    field_path: str

    def __init__(self, code: BaselineRunResultErrorCode, field_path: str = "") -> None:
        if not isinstance(code, BaselineRunResultErrorCode):
            raise TypeError("code must be a BaselineRunResultErrorCode member")
        if not isinstance(field_path, str):
            raise TypeError("field_path must be a str")
        self.code = code
        self.field_path = field_path
        super().__init__(_STABLE_MESSAGES[code])


def _fail(code: BaselineRunResultErrorCode, field_path: str) -> NoReturn:
    raise BaselineRunResultError(code, field_path)


class _FrozenMapping:
    """A read-only, JSON-compatible view over one validated sample mapping.

    Content is stored as an immutable tuple of key-value pairs, so no mutable
    builtin container (``dict``/``list``/``set``/``bytearray``) is reachable
    through any attribute.  Reads (subscript, ``len``, iteration, membership,
    ``get``/``keys``/``values``/``items``) behave like a plain ``dict`` whose
    values are already-validated immutable scalars, resolved by a linear scan
    over at most fourteen frozen fields.  Every mutating operation and every
    attribute assignment fails closed with ``TypeError``.  Equality holds for
    another frozen view with equal items or an equal plain ``dict``.
    """

    __slots__ = ("_items",)

    def __init__(self, items: dict[str, int | str | None]) -> None:
        object.__setattr__(self, "_items", tuple(items.items()))

    def _as_dict(self) -> dict[str, int | str | None]:
        return dict(self._items)

    def __setattr__(self, name: str, value: object) -> None:
        raise TypeError("baseline run result samples are deeply immutable")

    def __delattr__(self, name: str) -> None:
        raise TypeError("baseline run result samples are deeply immutable")

    def __getitem__(self, key: str) -> int | str | None:
        for item_key, item_value in self._items:
            if item_key == key:
                return item_value
        raise KeyError(key)

    def __iter__(self):
        return iter(self._as_dict())

    def __len__(self) -> int:
        return len(self._items)

    def __contains__(self, key: object) -> bool:
        return any(item_key == key for item_key, _ in self._items)

    def keys(self) -> tuple[str, ...]:
        return tuple(item_key for item_key, _ in self._items)

    def values(self) -> tuple[int | str | None, ...]:
        return tuple(item_value for _, item_value in self._items)

    def items(self) -> tuple[tuple[str, int | str | None], ...]:
        return self._items

    def get(self, key: str, default: object = None) -> object:
        for item_key, item_value in self._items:
            if item_key == key:
                return item_value
        return default

    def __setitem__(self, key: str, value: object) -> None:
        raise TypeError("baseline run result samples are deeply immutable")

    def __delitem__(self, key: str) -> None:
        raise TypeError("baseline run result samples are deeply immutable")

    def update(self, *args: object, **kwargs: object) -> None:
        raise TypeError("baseline run result samples are deeply immutable")

    def pop(self, *args: object, **kwargs: object) -> object:
        raise TypeError("baseline run result samples are deeply immutable")

    def popitem(self) -> tuple[str, object]:
        raise TypeError("baseline run result samples are deeply immutable")

    def setdefault(self, *args: object, **kwargs: object) -> object:
        raise TypeError("baseline run result samples are deeply immutable")

    def clear(self) -> None:
        raise TypeError("baseline run result samples are deeply immutable")

    def __eq__(self, other: object) -> bool:
        if isinstance(other, _FrozenMapping):
            return self._as_dict() == other._as_dict()
        if isinstance(other, dict):
            return self._as_dict() == other
        return NotImplemented

    def __repr__(self) -> str:
        return repr(self._as_dict())


class _FrozenSequence:
    """A read-only, JSON-compatible view over the validated sample list.

    Reads (subscript, ``len``, iteration, membership, ``index``/``count``)
    behave like a plain ``tuple`` of frozen sample mappings.  Every mutating
    operation and every attribute assignment fails closed with ``TypeError``.
    Equality holds for another frozen view with equal items or an equal plain
    ``list``/``tuple``.
    """

    __slots__ = ("_items",)

    def __init__(self, items: list[_FrozenMapping]) -> None:
        object.__setattr__(self, "_items", tuple(items))

    def __setattr__(self, name: str, value: object) -> None:
        raise TypeError("baseline run result samples are deeply immutable")

    def __delattr__(self, name: str) -> None:
        raise TypeError("baseline run result samples are deeply immutable")

    def __getitem__(self, index: int | slice) -> object:
        return self._items[index]

    def __iter__(self):
        return iter(self._items)

    def __len__(self) -> int:
        return len(self._items)

    def __contains__(self, item: object) -> bool:
        return item in self._items

    def index(self, value: object, *args: int) -> int:
        return self._items.index(value, *args)

    def count(self, value: object) -> int:
        return self._items.count(value)

    def __setitem__(self, index: int, value: object) -> None:
        raise TypeError("baseline run result samples are deeply immutable")

    def __delitem__(self, index: int) -> None:
        raise TypeError("baseline run result samples are deeply immutable")

    def append(self, item: object) -> None:
        raise TypeError("baseline run result samples are deeply immutable")

    def insert(self, index: int, item: object) -> None:
        raise TypeError("baseline run result samples are deeply immutable")

    def extend(self, items: object) -> None:
        raise TypeError("baseline run result samples are deeply immutable")

    def pop(self, *args: int, **kwargs: int) -> object:
        raise TypeError("baseline run result samples are deeply immutable")

    def clear(self) -> None:
        raise TypeError("baseline run result samples are deeply immutable")

    def remove(self, item: object) -> None:
        raise TypeError("baseline run result samples are deeply immutable")

    def sort(self, *args: object, **kwargs: object) -> None:
        raise TypeError("baseline run result samples are deeply immutable")

    def reverse(self) -> None:
        raise TypeError("baseline run result samples are deeply immutable")

    def __eq__(self, other: object) -> bool:
        if isinstance(other, _FrozenSequence):
            return self._items == other._items
        if isinstance(other, (list, tuple)):
            return list(self._items) == list(other)
        return NotImplemented

    def __repr__(self) -> str:
        return repr(list(self._items))


def _require_fields(container: dict[object, object], fields: tuple[str, ...], prefix: str) -> None:
    for field in fields:
        if field not in container:
            _fail(BaselineRunResultErrorCode.REQUIRED_FIELD_MISSING, f"{prefix}.{field}")


def _reject_unknown_fields(
    container: dict[object, object], fields: tuple[str, ...], prefix: str
) -> None:
    allowed = frozenset(fields)
    for key in container:
        if key in allowed:
            continue
        if isinstance(key, str):
            _fail(BaselineRunResultErrorCode.UNKNOWN_FIELD, f"{prefix}.{key}")
        _fail(BaselineRunResultErrorCode.UNKNOWN_FIELD, prefix)


def _validate_schema_version(value: object) -> int:
    if type(value) is not int:
        _fail(BaselineRunResultErrorCode.INVALID_FIELD_TYPE, "$.schema_version")
    if value != _SCHEMA_VERSION:
        _fail(BaselineRunResultErrorCode.SCHEMA_VERSION_INVALID, "$.schema_version")
    return value


def _validate_run_spec_digest(value: object) -> str:
    if not isinstance(value, str):
        _fail(BaselineRunResultErrorCode.INVALID_FIELD_TYPE, "$.run_spec_digest")
    if _RUN_SPEC_DIGEST_PATTERN.fullmatch(value) is None:
        _fail(BaselineRunResultErrorCode.INVALID_DIGEST, "$.run_spec_digest")
    return value


def _validate_attempt_index(value: object, field_path: str) -> int:
    if type(value) is not int:
        _fail(BaselineRunResultErrorCode.INVALID_FIELD_TYPE, field_path)
    if not 0 <= value <= _INT64_MAX:
        _fail(BaselineRunResultErrorCode.INVALID_FIELD_VALUE, field_path)
    return value


def _validate_mode(value: object, field_path: str) -> str:
    if not isinstance(value, str):
        _fail(BaselineRunResultErrorCode.INVALID_FIELD_TYPE, field_path)
    if value not in _MODES:
        _fail(BaselineRunResultErrorCode.INVALID_FIELD_VALUE, field_path)
    return value


def _validate_outcome(value: object, field_path: str) -> str:
    if not isinstance(value, str):
        _fail(BaselineRunResultErrorCode.INVALID_FIELD_TYPE, field_path)
    if _OUTCOME_PATTERN.fullmatch(value) is None:
        _fail(BaselineRunResultErrorCode.INVALID_FIELD_VALUE, field_path)
    return value


def _validate_metric(value: object, field_path: str) -> int | None:
    if value is None:
        return None
    if type(value) is not int:
        _fail(BaselineRunResultErrorCode.INVALID_FIELD_TYPE, field_path)
    if not 0 <= value <= _INT64_MAX:
        _fail(BaselineRunResultErrorCode.INVALID_FIELD_VALUE, field_path)
    return value


def _validate_failure_code(value: object, field_path: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        _fail(BaselineRunResultErrorCode.INVALID_FIELD_TYPE, field_path)
    if _FAILURE_CODE_PATTERN.fullmatch(value) is None:
        _fail(BaselineRunResultErrorCode.INVALID_FIELD_VALUE, field_path)
    return value


def _validate_cross_fields(
    outcome: str, wall_time_ms: int | None, failure_code: str | None, prefix: str
) -> None:
    """Enforce the frozen in-sample order: wall time first, pairing second."""

    if outcome == "success" and wall_time_ms is None:
        _fail(BaselineRunResultErrorCode.SUCCESS_WALL_TIME_REQUIRED, f"{prefix}.wall_time_ms")
    if outcome == "success":
        if failure_code is not None:
            _fail(BaselineRunResultErrorCode.FAILURE_CODE_CONFLICT, f"{prefix}.failure_code")
    elif failure_code is None:
        _fail(BaselineRunResultErrorCode.FAILURE_CODE_CONFLICT, f"{prefix}.failure_code")


def _validate_samples(value: object) -> _FrozenSequence:
    if not isinstance(value, list):
        _fail(BaselineRunResultErrorCode.INVALID_FIELD_TYPE, "$.samples")
    entries: list[_FrozenMapping] = []
    seen_indices: set[int] = set()
    for index, element in enumerate(value):
        prefix = f"$.samples[{index}]"
        if not isinstance(element, dict):
            _fail(BaselineRunResultErrorCode.INVALID_FIELD_TYPE, prefix)
        _require_fields(element, _SAMPLE_FIELDS, prefix)
        _reject_unknown_fields(element, _SAMPLE_FIELDS, prefix)
        attempt_index = _validate_attempt_index(
            element["attempt_index"], f"{prefix}.attempt_index"
        )
        if attempt_index in seen_indices:
            _fail(BaselineRunResultErrorCode.DUPLICATE_ATTEMPT_INDEX, f"{prefix}.attempt_index")
        seen_indices.add(attempt_index)
        mode = _validate_mode(element["mode"], f"{prefix}.mode")
        outcome = _validate_outcome(element["outcome"], f"{prefix}.outcome")
        metrics = {
            field: _validate_metric(element[field], f"{prefix}.{field}")
            for field in _METRIC_FIELDS
        }
        failure_code = _validate_failure_code(
            element["failure_code"], f"{prefix}.failure_code"
        )
        _validate_cross_fields(outcome, metrics["wall_time_ms"], failure_code, prefix)
        entry: dict[str, int | str | None] = {
            "attempt_index": attempt_index,
            "mode": mode,
            "outcome": outcome,
        }
        entry.update(metrics)
        entry["failure_code"] = failure_code
        entries.append(_FrozenMapping(entry))
    entries.sort(key=lambda entry: entry["attempt_index"])
    return _FrozenSequence(entries)


def _success_wall_times(samples: _FrozenSequence, mode: str) -> list[int]:
    """Sorted successful wall times for one mode (validated non-null ints)."""

    walls = [
        sample["wall_time_ms"]
        for sample in samples
        if sample["mode"] == mode and sample["outcome"] == "success"
    ]
    walls.sort()
    return walls


def _nearest_rank(sorted_values: list[int], r: int) -> int:
    """Nearest-rank percentile with pure integer arithmetic (1-based ranks)."""

    rank = (r * len(sorted_values) + 99) // 100
    return sorted_values[rank - 1]


@dataclasses.dataclass(frozen=True)
class BaselineRunResult:
    """The frozen, replayable observed result of one baseline run.

    Instances are constructed through :func:`from_mapping` so that every
    field carries the validated schema-v1 shape.  ``status`` and the four
    percentiles are always computed by this module (never carried in) via
    the all-or-nothing policy.  The nested sample containers are deeply
    immutable read-only views: JSON-compatible reads (subscript, ``len``,
    iteration, membership, equality) are supported, while every mutation
    attempt fails closed and never changes the canonical bytes or digest,
    which are always recomputed from the frozen content.
    """

    schema_version: int
    run_spec_digest: str
    samples: _FrozenSequence
    status: str
    cold_p50_wall_time_ms: int | None
    cold_p95_wall_time_ms: int | None
    warm_p50_wall_time_ms: int | None
    warm_p95_wall_time_ms: int | None

    def to_canonical_value(self) -> dict[str, JSONValue]:
        """Return a fresh, mutable, plain JSON subset copy of every field.

        The returned tree is a newly built ``dict``/``list`` structure that
        shares no mutable state with the result; mutating it can never affect
        the result, its canonical bytes, or its digest.
        """

        return {
            "schema_version": self.schema_version,
            "run_spec_digest": self.run_spec_digest,
            "samples": [dict(sample.items()) for sample in self.samples],
            "status": self.status,
            "cold_p50_wall_time_ms": self.cold_p50_wall_time_ms,
            "cold_p95_wall_time_ms": self.cold_p95_wall_time_ms,
            "warm_p50_wall_time_ms": self.warm_p50_wall_time_ms,
            "warm_p95_wall_time_ms": self.warm_p95_wall_time_ms,
        }

    def canonical_bytes(self) -> bytes:
        """Return the byte-identical canonical JSON via ``lima.contracts.codec``."""

        return canonical_encode(self.to_canonical_value())

    def content_digest(self) -> str:
        """Return the lowercase hex SHA-256 of :meth:`canonical_bytes`."""

        return compute_content_digest(self.canonical_bytes())


def from_mapping(mapping: object) -> BaselineRunResult:
    """Strictly validate and freeze a baseline run result mapping (schema v1).

    Required-field presence, unknown-key rejection, exact types, value
    domains, attempt-index uniqueness, and the success-wall-time /
    failure-code pairing rules are all enforced; any violation raises
    :class:`BaselineRunResultError`.  The status and the four nearest-rank
    percentiles are computed here and never read from the input.
    """

    if not isinstance(mapping, dict):
        _fail(BaselineRunResultErrorCode.INVALID_FIELD_TYPE, "$")
    _require_fields(mapping, _TOP_LEVEL_FIELDS, "$")
    _reject_unknown_fields(mapping, _TOP_LEVEL_FIELDS, "$")
    samples = _validate_samples(mapping["samples"])
    cold_walls = _success_wall_times(samples, "cold")
    warm_walls = _success_wall_times(samples, "warm")
    if len(cold_walls) < _COLD_MIN_SUCCESSES or len(warm_walls) < _WARM_MIN_SUCCESSES:
        status = _STATUS_INSUFFICIENT
        cold_p50: int | None = None
        cold_p95: int | None = None
        warm_p50: int | None = None
        warm_p95: int | None = None
    else:
        status = _STATUS_SUFFICIENT
        cold_p50 = _nearest_rank(cold_walls, 50)
        cold_p95 = _nearest_rank(cold_walls, 95)
        warm_p50 = _nearest_rank(warm_walls, 50)
        warm_p95 = _nearest_rank(warm_walls, 95)
    return BaselineRunResult(
        schema_version=_validate_schema_version(mapping["schema_version"]),
        run_spec_digest=_validate_run_spec_digest(mapping["run_spec_digest"]),
        samples=samples,
        status=status,
        cold_p50_wall_time_ms=cold_p50,
        cold_p95_wall_time_ms=cold_p95,
        warm_p50_wall_time_ms=warm_p50,
        warm_p95_wall_time_ms=warm_p95,
    )
