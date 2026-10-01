"""Gated B1 real-entry suite for LIMA v4 baselines (IP-0041, Issue #251).

This module is the reviewed B1 real public entry of the 2026-10-01
eighth-ruling authorization: :func:`run_b1_real_baseline_suite` composes the
frozen upstream faces read-only (Packet
docs/LIMA_Implementation_Packet_IP-0041_B1_Real_Entry.md sections 7.2, 7.5
and 7.6) instead of re-implementing any gated primitive.  The entry is the
twelfth catalog key's dedicated face -- the artifact key
``real-pilot/signal-storm`` is pinned internally and never exposed as a
parameter -- and the one-time pilot shape (one cold plus four warm attempts)
is an authorization face the entry enforces before anything runs, never a
tunable it carries.

The frozen data flow (Packet 7.1): the pre-phase loads and enforces the
approval artifact through the frozen real-run loader (identity pins, the
date pin family, the seven-dimension budget, and the one-time {1,4,5}
attempt shape -- a drift is the typed ``B1_REAL_INPUT_INVALID`` refusal with
zero POSTs); the transport is wrapped by an independent POST-only counter
(an injected transport stays the injected face, the product default stays
the single-urlopen default); the frozen order 1-9 real chain then runs
through ``run_real_baseline_suite(artifact_key="real-pilot/signal-storm")``
with every gate, canary item, first-failure rule, deadline, settlement and
cancellation discipline reused verbatim -- the scanner itself executes
exactly once inside the cold attempt-0 reserve/deadline window over the
same materialized snapshot the request body was built from (the real_run
hook of Packet 7.4 E3), and the four warm attempts reuse the snapshot, the
scan result and the request body.

The post-phase verifies and binds: it re-reads the evidence set, recomputes
the persisted snapshot tree digest, independently re-scans the persisted
snapshot with the frozen offline scanner program (read-only, zero model
calls) and cross-checks the scanner wire digest against the report's
scanner source, checks the projection faces (the report counts equal the
independent direct scan, never a summation across the five samples, and the
real POST count equals the ledger call count), then writes the independent
companion artifacts -- ``b1-real-attempts/b1-real-attempt-{i:02d}.json``
with the closed twenty-three-key receipt set plus the closed-key
``b1-real-manifest.json`` -- which bind the approval bytes, the actual
request-body digest, every RunResult, every attempt document, the ledger
and the suite identity by canonical SHA-256 digests.  Any mismatch is the
typed fail-closed refusal of the frozen five-code family and no companion
is written.  :func:`verify_b1_real_evidence` re-reads one output root and
recomputes every binding the same way.  The honesty face is frozen: the
companion and the result carry ``real_post_count`` -- the independently
counted actual POST face -- and never a ``model_calls`` key or any
offline-proof marker (the scanner component's zero model calls is a
component-level declaration only).

Everything here is offline and secretless: zero network roots, zero
environment reads, zero credentials beyond the explicit ``api_key``
parameter handed straight to the frozen chain (never logged, never
persisted, never embedded in an error), and the entry source carries no
numeric budget constant -- every seven-dimension value loads from the
approval artifact through the frozen loader.
"""

import dataclasses
import enum
import hashlib
import json
import pathlib
import typing

from benchmarks.v4.baseline import b1_source, real_run
from benchmarks.v4.baseline.budget import LedgerSnapshot
from benchmarks.v4.baseline.fixtures import compute_tree_fingerprint, load_registry
from lima.contracts.codec import canonical_encode, compute_content_digest

__all__ = [
    "B1RealError",
    "B1RealErrorCode",
    "B1RealSuiteResult",
    "run_b1_real_baseline_suite",
    "verify_b1_real_evidence",
]

#: The pinned artifact key (Packet 7.2.1): the entry is the twelfth
#: catalog key's dedicated face and never exposes the key as a parameter.
_ARTIFACT_KEY: typing.Final[str] = "real-pilot/signal-storm"

#: The twelfth descriptor's binding pins (Packet 7.3; literal mirrors of the
#: catalog values the entry enforces against -- the catalog stays the sole
#: derivation source for the provenance fields).
_FIXTURE_KEY: typing.Final[str] = "archetype/signal-storm"
_APPROVAL_TYPE_PIN: typing.Final[str] = "PR3D-B1-REAL-ENTRY-ONE-SHOT"
_RUN_NAME_PIN: typing.Final[str] = "pr3d-b1-real-signal-storm-2026-10-01"
_WORKLOAD: typing.Final[str] = "b1-real-signal-storm-v1"
_SCANNER_CONFIG_REF: typing.Final[str] = "b1-source-offline-scan-v1"
_SOURCE_CONTRACT: typing.Final[str] = "b1-real-source-binding"
_SOURCE_CONTRACT_VERSION: typing.Final[int] = 1

#: The one-time pilot authorization shape (Packet 7.1 (0a) / 7.6.4): the
#: entry pins the shape before anything runs; it is an authorization face,
#: never a tunable, and never a numeric budget constant.
_COLD_COUNT: typing.Final[int] = 1
_WARM_COUNT: typing.Final[int] = 4
_ATTEMPT_COUNT: typing.Final[int] = 5
_SEED: typing.Final[int] = 0
_CANARY_FIRST_ATTEMPT: typing.Final[int] = 0

#: The frozen offline scanner configuration mirrors (b1_source Packet 7.5,
#: transcribed so the config document and its digest are independently
#: recomputable): every disabling value explicit, never an ambient default.
_SAST_MODE: typing.Final[str] = "off"
_CXX_MEMORY_MODE: typing.Final[str] = "off"
_CXX_AGENT_MODE: typing.Final[str] = "off"
_DATAFLOW_ENABLED: typing.Final[bool] = True
_REVIEWERS: typing.Final[str] = "security-rule-reviewer"
_WORKSPACE_MAX_FILES: typing.Final[int] = 5000
_WORKSPACE_MAX_FILE_BYTES: typing.Final[int] = 512 * 1024
_WORKSPACE_MAX_TOTAL_BYTES: typing.Final[int] = 20 * 1024 * 1024

#: The companion source_receipt key set (Packet 7.5.3; twenty-three keys:
#: the b1_source sixteen with their semantics preserved plus the seven
#: real-binding additions, order frozen).
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
    "approval_sha256",
    "request_body_sha256",
    "run_result_name",
    "run_result_sha256",
    "attempt_document_name",
    "suite_run_name",
    "ledger_sha256",
)
_RECEIPT_KEY_SET: typing.Final[frozenset[str]] = frozenset(_RECEIPT_KEYS)

#: The companion manifest key set (Packet 7.5.4; closed).  No ``model_calls``
#: key and no offline-proof declaration ever join this face.
_MANIFEST_KEYS: typing.Final[tuple[str, ...]] = (
    "schema_version",
    "workload",
    "run_name",
    "artifact_key",
    "approval_sha256",
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
    "source_contract",
    "source_contract_version",
    "scanner_payload_sha256",
    "scanner_executions",
    "scanner_phase",
    "source_receipts",
    "source_receipts_digest",
    "failures",
    "real_post_count",
    "ledger_calls",
    "companion_bytes_total",
    "transport_face",
    "declarations",
)
_MANIFEST_KEY_SET: typing.Final[frozenset[str]] = frozenset(_MANIFEST_KEYS)

#: The estimate-registration face (Packet 7.6.3): the scanner wall belongs
#: to the attempt-0 wall reservation -- an explicit registration, never a
#: fabricated scanner-specific wall number.
_SCANNER_PHASE: typing.Final[dict[str, object]] = {
    "executions": _COLD_COUNT,
    "reuses": _WARM_COUNT,
    "window": "attempt-0-guarded",
    "wall_registration": "inside-attempt0-wall-reservation",
}

#: The closed declaration set (Packet 7.5.4): the scanner component's zero
#: model calls is a component-level declaration only -- the suite-level
#: honesty face is ``real_post_count``.
_DECLARATIONS: typing.Final[tuple[str, ...]] = (
    "b1-real-suite-actual-post-count-recorded",
    "signal-storm-local-materialization-zero-download",
    "one-time-pilot-shape-one-cold-four-warm",
    "not-nine-category-sample",
    "scanner-component-zero-model-calls",
)

_TRANSPORT_FACE_INJECTED: typing.Final[str] = "injected"
_TRANSPORT_FACE_DEFAULT: typing.Final[str] = "default-urllib"

#: The frozen report projection faces (report.py mirrors): the skip reasons
#: that affect coverage and the two finding-state partitions.
_COVERAGE_AFFECTING_SKIPS: typing.Final[frozenset[str]] = frozenset(
    {
        "symlink",
        "unreadable",
        "file-size-limit",
        "file-limit",
        "total-size-limit",
        "binary",
        "non-utf8",
    }
)
_DETERMINISTIC_STATES: typing.Final[frozenset[str]] = frozenset(
    {"corroborated", "dataflow-verified", "confirmed"}
)
_INCONCLUSIVE_STATES: typing.Final[frozenset[str]] = frozenset(
    {"candidate", "syntax-verified"}
)
_CONFIRMED_STATE: typing.Final[str] = "confirmed"

_HEX64_ALPHABET: typing.Final[frozenset[str]] = frozenset("0123456789abcdef")


class B1RealErrorCode(str, enum.Enum):  # noqa: UP042 -- frozen by IP-0041 7.2.3
    """Frozen wire values for every deterministic B1 real-entry failure."""

    B1_REAL_INPUT_INVALID = "B1_REAL_INPUT_INVALID"
    B1_REAL_RECEIPT_INVALID = "B1_REAL_RECEIPT_INVALID"
    B1_REAL_BINDING_MISMATCH = "B1_REAL_BINDING_MISMATCH"
    B1_REAL_SCANNER_DIGEST_MISMATCH = "B1_REAL_SCANNER_DIGEST_MISMATCH"
    B1_REAL_PROJECTION_MISMATCH = "B1_REAL_PROJECTION_MISMATCH"

    def __str__(self) -> str:
        """Render the bare frozen wire value (the str-mixin face)."""
        return self.value


_STABLE_MESSAGES: dict[B1RealErrorCode, str] = {
    B1RealErrorCode.B1_REAL_INPUT_INVALID: (
        "The B1 real entry refused an input outside the frozen authorization."
    ),
    B1RealErrorCode.B1_REAL_RECEIPT_INVALID: (
        "A B1 real companion receipt or evidence document is invalid."
    ),
    B1RealErrorCode.B1_REAL_BINDING_MISMATCH: (
        "A B1 real evidence binding does not match its cross-checked face."
    ),
    B1RealErrorCode.B1_REAL_SCANNER_DIGEST_MISMATCH: (
        "A B1 real scanner payload digest does not match its chain."
    ),
    B1RealErrorCode.B1_REAL_PROJECTION_MISMATCH: (
        "A B1 real report projection does not match the independent scan."
    ),
}


class B1RealError(ValueError):
    """Deterministic B1 real-entry violation with a stable code and message.

    The shape aligns with the frozen real-run and B1 source error
    precedents while remaining an independent class.  The rendered message
    is exactly the catalog entry above; raw payloads, secrets, digest
    values and host paths are never embedded.  Use ``field_path`` for
    structure-only position reporting such as ``$.attempt_policy``.  The
    frozen upstream families (real_run's eleven codes, b1_source's four)
    are never modified and their refusals pass through unchanged wherever
    the frozen chain is the authority.
    """

    code: B1RealErrorCode
    field_path: str

    def __init__(self, code: B1RealErrorCode, field_path: str = "") -> None:
        if not isinstance(code, B1RealErrorCode):
            raise TypeError("code must be a B1RealErrorCode member")
        if not isinstance(field_path, str):
            raise TypeError("field_path must be a str")
        self.code = code
        self.field_path = field_path
        super().__init__(_STABLE_MESSAGES[code])


@dataclasses.dataclass(frozen=True, slots=True)
class B1RealSuiteResult:
    """Paths, digests, counters and binding faces of one B1 real suite run.

    The first sixteen fields mirror :class:`real_run.RealSuiteResult`
    verbatim (``real_run`` is the constant ``True`` discriminant of the
    driven frozen chain); the remaining fields are the B1 discriminant and
    binding faces: ``b1_real`` is the constant ``True`` discriminant,
    ``real_post_count`` is the independently counted actual POST face
    (never a constant and never a model-calls stand-in), and the scanner /
    companion faces carry the twelfth-key binding the companion artifacts
    persist.
    """

    run_name: str
    approval_digest: str
    run_spec_digest: str
    attempt_count: int
    status: str
    result_paths: tuple[pathlib.Path, ...]
    aggregate_path: pathlib.Path
    aggregate_sha256: str
    report_path: pathlib.Path
    report_sha256: str
    ledger_snapshot: LedgerSnapshot
    model: str | None
    system_fingerprint_baseline: str | None
    canary_status: str
    evidence_paths: dict[str, pathlib.Path]
    real_run: bool
    b1_real: bool
    artifact_key: str
    fixture_key: str
    workload: str
    snapshot_tree_sha256: str
    scanner_config_sha256: str
    scanner_payload_sha256: str
    scanner_executions: int
    real_post_count: int
    companion_manifest_path: pathlib.Path
    companion_manifest_sha256: str
    source_receipts_digest: str
    source_contract: str
    source_contract_version: int


def _is_hex64(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in _HEX64_ALPHABET for character in value)
    )


def _read_json(path: pathlib.Path, field_path: str) -> object:
    """Read and parse one evidence json file, fail closed with the family."""
    try:
        return json.loads(path.read_bytes().decode("utf-8"))
    except (OSError, UnicodeDecodeError, ValueError) as exc:
        raise B1RealError(B1RealErrorCode.B1_REAL_RECEIPT_INVALID, field_path) from exc


def _write_exclusive(path: pathlib.Path, payload: bytes) -> pathlib.Path:
    """Create ``path`` exclusively with ``payload``; never overwrite."""
    with open(path, "xb") as handle:
        handle.write(payload)
    return path


def _scanner_config_document() -> dict[str, object]:
    """The B1 real scanner config document (Packet 7.3 shape, PC3 mirror).

    The key set and values mirror the frozen b1_source config-document
    shape verbatim (the workload, the fixture binding, the registry tree
    fingerprint, the pinned seed, the one-time {1,4} shape, the explicit
    offline scanner disables, and the explicit workspace limits), so the
    canonical digest of this document equals the twelfth descriptor's
    ``scanner_config_sha256`` pin -- the entry checks that equality and
    refuses any drift before anything runs.
    """
    return {
        "workload": _WORKLOAD,
        "fixture_key": _FIXTURE_KEY,
        "snapshot_tree_sha256": b1_source._registry_fingerprint(
            load_registry(), _FIXTURE_KEY
        ),
        "seed": _SEED,
        "cold_count": _COLD_COUNT,
        "warm_count": _WARM_COUNT,
        "scanner": {
            "sast_mode": _SAST_MODE,
            "sast_adapters": [],
            "cxx_memory_mode": _CXX_MEMORY_MODE,
            "cxx_memory_adapter": None,
            "cxx_agent_mode": _CXX_AGENT_MODE,
            "cxx_agent_budget_factory": None,
            "cxx_uaf_llm_factory": None,
            "dataflow_enabled": _DATAFLOW_ENABLED,
            "reviewers": _REVIEWERS,
            "should_cancel": None,
        },
        "workspace": {
            "max_files": _WORKSPACE_MAX_FILES,
            "max_file_bytes": _WORKSPACE_MAX_FILE_BYTES,
            "max_total_bytes": _WORKSPACE_MAX_TOTAL_BYTES,
        },
    }


def _read_approval_document(approval_path: str | pathlib.Path) -> dict | None:
    """Leniently pre-parse the approval document; ``None`` on any failure.

    Mirrors the frozen fence parse (bytes, UTF-8, first fenced json block)
    without enforcing anything: the frozen loader stays the sole authority
    for every malformed-artifact rejection, so a document this helper
    cannot read simply skips the entry's identity pre-check and flows into
    the loader's own typed refusal.
    """
    try:
        raw = pathlib.Path(approval_path).read_bytes()
        text = raw.decode("utf-8")
        match = real_run._JSON_FENCE_PATTERN.search(text)
        if match is None:
            return None
        document = json.loads(match.group(1))
    except (OSError, UnicodeDecodeError, ValueError):
        return None
    return document if isinstance(document, dict) else None


def _scan_faces(scan_result: object) -> dict[str, object]:
    """The direct-scanner-output projection faces (PC3 recomputation)."""
    report = scan_result.report
    findings = report.findings
    states = [finding.verification_state for finding in findings]
    skipped = report.collaboration["skipped"]
    reasons: dict[str, int] = {
        reason: count
        for reason, count in sorted(skipped.items())
        if reason in _COVERAGE_AFFECTING_SKIPS and count > 0
    }
    return {
        "raw_candidates": len(findings),
        "deterministic_alerts": sum(
            1 for state in states if state in _DETERMINISTIC_STATES
        ),
        "confirmed": sum(1 for state in states if state == _CONFIRMED_STATE),
        "inconclusive": sum(
            1 for state in states if state in _INCONCLUSIVE_STATES
        ),
        "scanned_files": report.collaboration["scanned_files"],
        "coverage_gap": sum(reasons.values()),
        "coverage_gap_reasons": reasons,
    }


def _projection_matches(report_document: object, faces: dict[str, object]) -> bool:
    """Whether the report's projection equals the independent scan faces.

    The frozen no-summation rule rides the same comparison: the chain
    counts must equal one single scan's faces (never the five-sample sum)
    and the partition invariant ``raw == deterministic + inconclusive``
    must hold.
    """
    if not isinstance(report_document, dict):
        return False
    chain = report_document.get("compression_chain")
    counts = report_document.get("counts")
    if not isinstance(chain, dict) or not isinstance(counts, dict):
        return False
    for face in (
        "raw_candidates",
        "deterministic_alerts",
        "confirmed",
        "inconclusive",
    ):
        if chain.get(face) != faces[face]:
            return False
    if (
        chain["raw_candidates"]
        != chain["deterministic_alerts"] + chain["inconclusive"]
    ):
        return False
    scanned = counts.get("scanned_files")
    gap = counts.get("coverage_gap")
    if not isinstance(scanned, dict) or scanned.get("value") != faces["scanned_files"]:
        return False
    if not isinstance(gap, dict) or gap.get("value") != faces["coverage_gap"]:
        return False
    return report_document.get("coverage_gap_reasons") == faces["coverage_gap_reasons"]


def _validate_receipt(receipt: object, index: int) -> None:
    """Validate one companion receipt's closed key set and field types."""
    prefix = f"$.source_receipts[{index}]"
    if not isinstance(receipt, dict) or set(receipt) != _RECEIPT_KEY_SET:
        raise B1RealError(B1RealErrorCode.B1_REAL_RECEIPT_INVALID, prefix)
    for field in (
        "snapshot_tree_sha256",
        "fixture_manifest_sha256",
        "analyzer_fingerprint",
        "scanner_config_sha256",
        "scanner_payload_sha256",
        "run_spec_digest",
        "approval_sha256",
        "request_body_sha256",
        "run_result_sha256",
        "ledger_sha256",
    ):
        if not _is_hex64(receipt[field]):
            raise B1RealError(
                B1RealErrorCode.B1_REAL_RECEIPT_INVALID, f"{prefix}.{field}"
            )
    for field in ("seed", "attempt_index"):
        if type(receipt[field]) is not int:
            raise B1RealError(
                B1RealErrorCode.B1_REAL_RECEIPT_INVALID, f"{prefix}.{field}"
            )
    if receipt["mode"] not in ("cold", "warm"):
        raise B1RealError(B1RealErrorCode.B1_REAL_RECEIPT_INVALID, f"{prefix}.mode")
    for field in (
        "scanner_reexecuted",
        "scanner_result_reused",
        "snapshot_reused",
        "request_body_rebuilt",
    ):
        if type(receipt[field]) is not bool:
            raise B1RealError(
                B1RealErrorCode.B1_REAL_RECEIPT_INVALID, f"{prefix}.{field}"
            )
    for field in (
        "fixture_key",
        "analyzer_name",
        "workload",
        "run_result_name",
        "attempt_document_name",
        "suite_run_name",
    ):
        if not isinstance(receipt[field], str) or not receipt[field]:
            raise B1RealError(
                B1RealErrorCode.B1_REAL_RECEIPT_INVALID, f"{prefix}.{field}"
            )


class _CountingTransport:
    """The independent POST-only counting wrapper (Packet 7.1 (0b)).

    Wraps any four-argument transport and counts only the payload-carrying
    (POST) calls -- the synthetic materialization path never performs a
    GET -- while delegating every call verbatim: zero behavioral
    difference, an audit face only.  The count feeds ``real_post_count``
    and never touches any ledger or budget dimension.
    """

    __slots__ = ("_inner", "post_count")

    def __init__(self, inner: typing.Callable) -> None:
        self._inner = inner
        self.post_count = 0

    def __call__(
        self, url: str, payload: bytes | None, headers: dict[str, str], timeout: int
    ) -> object:
        if payload is not None:
            self.post_count += 1
        return self._inner(url, payload, headers, timeout)


def run_b1_real_baseline_suite(
    approval_path: str | pathlib.Path,
    api_key: str,
    *,
    output_root: str | pathlib.Path,
    spec_mapping: object,
    transport: typing.Callable | None = None,
    timeout_seconds: int = 120,
    manifest_path: str | pathlib.Path | None = None,
    sources: object = None,
) -> "B1RealSuiteResult":
    """Run one gated B1 real baseline suite (Packet 7.1 / 7.2, frozen flow).

    The pre-phase enforces the twelfth-key authorization (the pinned
    approval identity, the frozen loader's pin family, the one-time
    {1,4,5} attempt shape, and the binding block's equality with the
    twelfth descriptor) and wraps the transport with the independent
    POST-only counter; the frozen order 1-9 real chain then runs under
    ``artifact_key="real-pilot/signal-storm"`` with every frozen gate
    reused verbatim; the post-phase cross-verifies the evidence, the
    persisted snapshot and the report projection against an independent
    re-scan, then writes the companion artifacts and returns the
    :class:`B1RealSuiteResult`.  Every upstream refusal (the frozen
    loader, the budget gate, the typed real-run family, and control-flow
    cancellation) passes through unchanged; the entry's own refusals are
    the typed five-code family and leave no companion behind.
    """
    # -- (0a) the pre-phase enforcement --------------------------------
    document = _read_approval_document(approval_path)
    if document is not None:
        # The twelfth-bound identity: an approval carrying any other
        # identity is not a twelfth-key approval and is refused here, zero
        # POSTs, before the frozen loader's own pin family runs.
        if document.get("approval_type") != _APPROVAL_TYPE_PIN:
            raise B1RealError(
                B1RealErrorCode.B1_REAL_INPUT_INVALID, "$.approval_type"
            )
        if document.get("run_name") != _RUN_NAME_PIN:
            raise B1RealError(B1RealErrorCode.B1_REAL_INPUT_INVALID, "$.run_name")
    approval = real_run._load_and_validate_approval(approval_path, _ARTIFACT_KEY)
    policy = approval.document["attempt_policy"]
    if (
        policy["cold"] != _COLD_COUNT
        or policy["warm"] != _WARM_COUNT
        or policy["max_attempts"] != _ATTEMPT_COUNT
        or policy["canary_required"] is not True
        or policy["canary_first_attempt"] != _CANARY_FIRST_ATTEMPT
    ):
        raise B1RealError(B1RealErrorCode.B1_REAL_INPUT_INVALID, "$.attempt_policy")
    descriptor = real_run.REAL_RUN_ARTIFACT_FAMILY[_ARTIFACT_KEY]
    scanner_config = _scanner_config_document()
    if compute_content_digest(scanner_config) != descriptor["scanner_config_sha256"]:
        raise B1RealError(
            B1RealErrorCode.B1_REAL_INPUT_INVALID, "$.scanner_config_sha256"
        )
    expected_binding = {
        "workload": descriptor["workload"],
        "scanner_config_ref": descriptor["scanner_config_ref"],
        "scanner_config_sha256": descriptor["scanner_config_sha256"],
        "source_contract": descriptor["source_contract"],
        "source_contract_version": descriptor["source_contract_version"],
    }
    if approval.b1_source_binding != expected_binding:
        raise B1RealError(
            B1RealErrorCode.B1_REAL_INPUT_INVALID, "$.b1_source_binding"
        )
    # -- (0b) the independent POST-only counter -------------------------
    counting = _CountingTransport(
        transport if transport is not None else real_run._urllib_transport
    )
    # -- the frozen order 1-9 real chain --------------------------------
    result = real_run.run_real_baseline_suite(
        approval_path,
        api_key,
        output_root=output_root,
        spec_mapping=spec_mapping,
        transport=counting,
        timeout_seconds=timeout_seconds,
        manifest_path=manifest_path,
        sources=sources,
        artifact_key=_ARTIFACT_KEY,
    )
    # -- (10) the post-phase verification (fail closed, no companion) ----
    root = pathlib.Path(output_root)
    report_document = _read_json(result.report_path, "$.report")
    report_sources = (
        report_document.get("sources") if isinstance(report_document, dict) else None
    )
    if (
        not isinstance(report_sources, list)
        or len(report_sources) != 1
        or not isinstance(report_sources[0], dict)
        or report_sources[0].get("kind") != "scanner"
    ):
        # The scanner never completed inside the attempt-0 window (a
        # scan-phase failure, a pre-scan refusal, or a deadline miss): the
        # suite is unbound, the frozen chain already kept the first cause,
        # and no companion may bind it.
        raise B1RealError(B1RealErrorCode.B1_REAL_BINDING_MISMATCH, "$.report.sources")
    snapshot_dir = root / "_materialized" / "snapshot"
    try:
        persisted_tree = compute_tree_fingerprint(snapshot_dir)
    except OSError as exc:
        raise B1RealError(
            B1RealErrorCode.B1_REAL_BINDING_MISMATCH, "$.snapshot_tree_sha256"
        ) from exc
    fixture_manifest_sha256 = b1_source._registry_fingerprint(
        load_registry(), _FIXTURE_KEY
    )
    attempt_documents = [
        _read_json(
            root / "attempts" / f"attempt-{index:02d}.json", f"$.attempts[{index}]"
        )
        for index in range(result.attempt_count)
    ]
    cold_reset = attempt_documents[0].get("cold_reset")
    if (
        not isinstance(cold_reset, dict)
        or cold_reset.get("performed") is not False
        or cold_reset.get("materialization_count") != 1
        or cold_reset.get("snapshot_tree_sha256") != persisted_tree
        or not _is_hex64(cold_reset.get("request_body_sha256"))
    ):
        raise B1RealError(
            B1RealErrorCode.B1_REAL_BINDING_MISMATCH, "$.attempts[0].cold_reset"
        )
    request_body_sha256 = cold_reset["request_body_sha256"]
    # The independent re-scan of the persisted snapshot (read-only, zero
    # model calls) crosses the scanner digest chain.
    scan = b1_source._scan_snapshot(snapshot_dir)
    wire_digest = b1_source._wire_fingerprint(scan)
    if report_sources[0].get("payload_sha256") != wire_digest:
        raise B1RealError(
            B1RealErrorCode.B1_REAL_SCANNER_DIGEST_MISMATCH,
            "$.report.sources[0].payload_sha256",
        )
    if not _projection_matches(report_document, _scan_faces(scan)):
        raise B1RealError(
            B1RealErrorCode.B1_REAL_PROJECTION_MISMATCH, "$.report.counts"
        )
    real_post_count = counting.post_count
    ledger_calls = result.ledger_snapshot.batch["calls"]
    if real_post_count != ledger_calls:
        raise B1RealError(
            B1RealErrorCode.B1_REAL_PROJECTION_MISMATCH, "$.real_post_count"
        )
    # The identity and evidence digests the receipts bind.
    approval_digest = hashlib.sha256((root / "approval.json").read_bytes()).hexdigest()
    if approval_digest != result.approval_digest:
        raise B1RealError(B1RealErrorCode.B1_REAL_BINDING_MISMATCH, "$.approval")
    ledger_sha256 = hashlib.sha256((root / "ledger.json").read_bytes()).hexdigest()
    analyzer_name = b1_source._derive_analyzer_name(dataflow_enabled=_DATAFLOW_ENABLED)
    if scan.report.reviewer != analyzer_name:
        raise B1RealError(B1RealErrorCode.B1_REAL_BINDING_MISMATCH, "$.analyzer_name")
    analyzer_fingerprint = compute_content_digest(
        {
            "analyzer_name": analyzer_name,
            "scanner_config_sha256": descriptor["scanner_config_sha256"],
        }
    )
    scanner_config_sha256 = descriptor["scanner_config_sha256"]
    if len(result.result_paths) != result.attempt_count:
        raise B1RealError(B1RealErrorCode.B1_REAL_BINDING_MISMATCH, "$.result_paths")
    receipts: list[dict[str, object]] = []
    for index, attempt_document in enumerate(attempt_documents):
        if not isinstance(attempt_document, dict):
            raise B1RealError(
                B1RealErrorCode.B1_REAL_BINDING_MISMATCH, f"$.attempts[{index}]"
            )
        if attempt_document.get("attempt_index") != index:
            raise B1RealError(
                B1RealErrorCode.B1_REAL_BINDING_MISMATCH, f"$.attempts[{index}]"
            )
        run_path = result.result_paths[index]
        receipts.append(
            {
                "snapshot_tree_sha256": persisted_tree,
                "fixture_key": _FIXTURE_KEY,
                "fixture_manifest_sha256": fixture_manifest_sha256,
                "analyzer_name": analyzer_name,
                "analyzer_fingerprint": analyzer_fingerprint,
                "scanner_config_sha256": scanner_config_sha256,
                "seed": _SEED,
                "workload": _WORKLOAD,
                "run_spec_digest": result.run_spec_digest,
                "attempt_index": index,
                "mode": attempt_document["mode"],
                "scanner_payload_sha256": wire_digest,
                "scanner_reexecuted": index == 0,
                "scanner_result_reused": index != 0,
                "snapshot_reused": index != 0,
                "request_body_rebuilt": index == 0,
                "approval_sha256": approval_digest,
                "request_body_sha256": request_body_sha256,
                "run_result_name": run_path.name,
                "run_result_sha256": hashlib.sha256(
                    run_path.read_bytes()
                ).hexdigest(),
                "attempt_document_name": f"attempts/attempt-{index:02d}.json",
                "suite_run_name": _RUN_NAME_PIN,
                "ledger_sha256": ledger_sha256,
            }
        )
    # -- (11) the companion artifacts ------------------------------------
    attempts_directory = root / "b1-real-attempts"
    attempts_directory.mkdir()
    receipts_total = 0
    for index, receipt in enumerate(receipts):
        _validate_receipt(receipt, index)
        payload = canonical_encode(receipt)
        _write_exclusive(
            attempts_directory / f"b1-real-attempt-{index:02d}.json", payload
        )
        receipts_total += len(payload)
    failures = [
        attempt_document["error_code"]
        for attempt_document in attempt_documents
        if isinstance(attempt_document, dict)
        and attempt_document.get("error_code") is not None
    ]
    source_receipts_digest = compute_content_digest(receipts)
    manifest_document: dict[str, object] = {
        "schema_version": 1,
        "workload": _WORKLOAD,
        "run_name": result.run_name,
        "artifact_key": _ARTIFACT_KEY,
        "approval_sha256": approval_digest,
        "run_spec_digest": result.run_spec_digest,
        "attempt_count": result.attempt_count,
        "cold_count": _COLD_COUNT,
        "warm_count": _WARM_COUNT,
        "fixture_key": _FIXTURE_KEY,
        "fixture_manifest_sha256": fixture_manifest_sha256,
        "snapshot_tree_sha256": persisted_tree,
        "analyzer_name": analyzer_name,
        "analyzer_fingerprint": analyzer_fingerprint,
        "scanner_config": scanner_config,
        "scanner_config_sha256": scanner_config_sha256,
        "seed": _SEED,
        "source_contract": _SOURCE_CONTRACT,
        "source_contract_version": _SOURCE_CONTRACT_VERSION,
        "scanner_payload_sha256": wire_digest,
        "scanner_executions": _COLD_COUNT,
        "scanner_phase": dict(_SCANNER_PHASE),
        "source_receipts": receipts,
        "source_receipts_digest": source_receipts_digest,
        "failures": failures,
        "real_post_count": real_post_count,
        "ledger_calls": ledger_calls,
        "companion_bytes_total": 0,
        "transport_face": (
            _TRANSPORT_FACE_INJECTED
            if transport is not None
            else _TRANSPORT_FACE_DEFAULT
        ),
        "declarations": list(_DECLARATIONS),
    }
    # The companion byte registration converges on the exact on-disk total
    # (the receipts plus the manifest's own encoded length).
    companion_bytes_total = 0
    manifest_bytes = b""
    for _ in range(4):
        manifest_document["companion_bytes_total"] = companion_bytes_total
        manifest_bytes = canonical_encode(manifest_document)
        total = receipts_total + len(manifest_bytes)
        if total == companion_bytes_total:
            break
        companion_bytes_total = total
    else:  # pragma: no cover - converges within two passes
        manifest_document["companion_bytes_total"] = companion_bytes_total
        manifest_bytes = canonical_encode(manifest_document)
    manifest_file = _write_exclusive(root / "b1-real-manifest.json", manifest_bytes)
    return B1RealSuiteResult(
        run_name=result.run_name,
        approval_digest=result.approval_digest,
        run_spec_digest=result.run_spec_digest,
        attempt_count=result.attempt_count,
        status=result.status,
        result_paths=result.result_paths,
        aggregate_path=result.aggregate_path,
        aggregate_sha256=result.aggregate_sha256,
        report_path=result.report_path,
        report_sha256=result.report_sha256,
        ledger_snapshot=result.ledger_snapshot,
        model=result.model,
        system_fingerprint_baseline=result.system_fingerprint_baseline,
        canary_status=result.canary_status,
        evidence_paths=result.evidence_paths,
        real_run=True,
        b1_real=True,
        artifact_key=_ARTIFACT_KEY,
        fixture_key=_FIXTURE_KEY,
        workload=_WORKLOAD,
        snapshot_tree_sha256=persisted_tree,
        scanner_config_sha256=scanner_config_sha256,
        scanner_payload_sha256=wire_digest,
        scanner_executions=_COLD_COUNT,
        real_post_count=real_post_count,
        companion_manifest_path=manifest_file,
        companion_manifest_sha256=compute_content_digest(manifest_bytes),
        source_receipts_digest=source_receipts_digest,
        source_contract=_SOURCE_CONTRACT,
        source_contract_version=_SOURCE_CONTRACT_VERSION,
    )


def verify_b1_real_evidence(
    output_root: str | pathlib.Path,
) -> dict[str, object]:
    """Re-read one B1 real output root and cross-check every binding.

    Checks (Packet 7.2.3 / 7.5, all fail-closed with the typed family,
    never a downgrade): the companion manifest parses and carries exactly
    its closed key set; every receipt file carries exactly the
    twenty-three-key set with well-formed digests, modes and reuse
    booleans; the persisted snapshot tree still matches the bound tree
    digest; the independent re-scan of the persisted snapshot recomputes
    the scanner wire digest that the report's scanner source and every
    receipt carry; the receipt files equal their manifest slots and the
    aggregate receipts digest; every RunResult pointer's content digest,
    every attempt-document pointer, the approval and ledger byte digests,
    the request-body digest and the analyzer identity hold; and the
    report's projection plus the real-POST and ledger call counts agree.
    On success a summary mapping with the verified identity faces is
    returned.
    """
    root = pathlib.Path(output_root)
    manifest = _read_json(root / "b1-real-manifest.json", "$.b1_real_manifest")
    if not isinstance(manifest, dict) or set(manifest) != _MANIFEST_KEY_SET:
        raise B1RealError(
            B1RealErrorCode.B1_REAL_RECEIPT_INVALID, "$.b1_real_manifest"
        )
    if manifest["schema_version"] != 1:
        raise B1RealError(
            B1RealErrorCode.B1_REAL_RECEIPT_INVALID, "$.b1_real_manifest.schema_version"
        )
    for field in (
        "approval_sha256",
        "run_spec_digest",
        "fixture_manifest_sha256",
        "snapshot_tree_sha256",
        "analyzer_fingerprint",
        "scanner_config_sha256",
        "scanner_payload_sha256",
        "source_receipts_digest",
    ):
        if not _is_hex64(manifest[field]):
            raise B1RealError(
                B1RealErrorCode.B1_REAL_RECEIPT_INVALID,
                f"$.b1_real_manifest.{field}",
            )
    for field in (
        "attempt_count",
        "cold_count",
        "warm_count",
        "seed",
        "scanner_executions",
        "real_post_count",
        "ledger_calls",
        "companion_bytes_total",
    ):
        if type(manifest[field]) is not int:
            raise B1RealError(
                B1RealErrorCode.B1_REAL_RECEIPT_INVALID,
                f"$.b1_real_manifest.{field}",
            )
    if manifest["scanner_phase"] != _SCANNER_PHASE:
        raise B1RealError(
            B1RealErrorCode.B1_REAL_RECEIPT_INVALID, "$.b1_real_manifest.scanner_phase"
        )
    if (
        not isinstance(manifest["declarations"], list)
        or set(manifest["declarations"]) != set(_DECLARATIONS)
    ):
        raise B1RealError(
            B1RealErrorCode.B1_REAL_RECEIPT_INVALID,
            "$.b1_real_manifest.declarations",
        )
    if manifest["transport_face"] not in (
        _TRANSPORT_FACE_INJECTED,
        _TRANSPORT_FACE_DEFAULT,
    ):
        raise B1RealError(
            B1RealErrorCode.B1_REAL_RECEIPT_INVALID,
            "$.b1_real_manifest.transport_face",
        )
    attempt_count = manifest["attempt_count"]
    embedded_receipts = manifest["source_receipts"]
    if not isinstance(embedded_receipts, list) or len(embedded_receipts) != (
        attempt_count
    ):
        raise B1RealError(
            B1RealErrorCode.B1_REAL_RECEIPT_INVALID, "$.b1_real_manifest.source_receipts"
        )
    file_paths = sorted((root / "b1-real-attempts").glob("b1-real-attempt-*.json"))
    if len(file_paths) != attempt_count:
        raise B1RealError(
            B1RealErrorCode.B1_REAL_BINDING_MISMATCH, "$.b1_real_attempts"
        )
    file_receipts = [
        _read_json(path, f"$.b1_real_attempts[{index}]")
        for index, path in enumerate(file_paths)
    ]
    for index, receipt in enumerate(file_receipts):
        _validate_receipt(receipt, index)
    # The persisted snapshot binding first: the receipts bind the exact
    # materialized tree, so any content change is the typed binding
    # refusal before the re-scan chain runs.
    snapshot_dir = root / "_materialized" / "snapshot"
    try:
        persisted_tree = compute_tree_fingerprint(snapshot_dir)
    except OSError as exc:
        raise B1RealError(
            B1RealErrorCode.B1_REAL_BINDING_MISMATCH, "$.snapshot_tree_sha256"
        ) from exc
    if manifest["snapshot_tree_sha256"] != persisted_tree:
        raise B1RealError(
            B1RealErrorCode.B1_REAL_BINDING_MISMATCH, "$.snapshot_tree_sha256"
        )
    for index, receipt in enumerate(file_receipts):
        if receipt["snapshot_tree_sha256"] != persisted_tree:
            raise B1RealError(
                B1RealErrorCode.B1_REAL_BINDING_MISMATCH,
                f"$.b1_real_attempts[{index}].snapshot_tree_sha256",
            )
    # The scanner digest chain: the independent re-scan recomputes the
    # wire digest the report source, the manifest and every receipt carry.
    scan = b1_source._scan_snapshot(snapshot_dir)
    wire_digest = b1_source._wire_fingerprint(scan)
    report = _read_json(
        root / f"{manifest['run_spec_digest'][:16]}-report-1.json", "$.report"
    )
    report_sources = report.get("sources") if isinstance(report, dict) else None
    if (
        not isinstance(report_sources, list)
        or len(report_sources) != 1
        or not isinstance(report_sources[0], dict)
        or report_sources[0].get("kind") != "scanner"
        or report_sources[0].get("payload_sha256") != wire_digest
    ):
        raise B1RealError(
            B1RealErrorCode.B1_REAL_SCANNER_DIGEST_MISMATCH, "$.report.sources"
        )
    for index, receipt in enumerate(file_receipts):
        if receipt["scanner_payload_sha256"] != wire_digest:
            raise B1RealError(
                B1RealErrorCode.B1_REAL_SCANNER_DIGEST_MISMATCH,
                f"$.b1_real_attempts[{index}].scanner_payload_sha256",
            )
    if manifest["scanner_payload_sha256"] != wire_digest:
        raise B1RealError(
            B1RealErrorCode.B1_REAL_SCANNER_DIGEST_MISMATCH,
            "$.b1_real_manifest.scanner_payload_sha256",
        )
    # The aggregate bindings: the receipt files equal their manifest slots
    # and the manifest's aggregate digest claim.
    for index, (file_receipt, embedded) in enumerate(
        zip(file_receipts, embedded_receipts, strict=True)
    ):
        if file_receipt != embedded:
            raise B1RealError(
                B1RealErrorCode.B1_REAL_BINDING_MISMATCH,
                f"$.b1_real_attempts[{index}]",
            )
    if manifest["source_receipts_digest"] != compute_content_digest(
        embedded_receipts
    ):
        raise B1RealError(
            B1RealErrorCode.B1_REAL_BINDING_MISMATCH,
            "$.b1_real_manifest.source_receipts_digest",
        )
    # The pointer bindings: RunResult content digests, attempt documents,
    # the approval and ledger bytes, the request-body digest, the analyzer
    # identity, and the cross-document run identity.
    for index, receipt in enumerate(file_receipts):
        run_result_path = root / receipt["run_result_name"]
        if not run_result_path.is_file():
            raise B1RealError(
                B1RealErrorCode.B1_REAL_BINDING_MISMATCH,
                f"$.source_receipts[{index}].run_result_name",
            )
        if hashlib.sha256(run_result_path.read_bytes()).hexdigest() != receipt[
            "run_result_sha256"
        ]:
            raise B1RealError(
                B1RealErrorCode.B1_REAL_BINDING_MISMATCH,
                f"$.source_receipts[{index}].run_result_sha256",
            )
        attempt_path = root / receipt["attempt_document_name"]
        attempt_document = _read_json(
            attempt_path, f"$.source_receipts[{index}].attempt_document_name"
        )
        if (
            not isinstance(attempt_document, dict)
            or attempt_document.get("attempt_index") != receipt["attempt_index"]
            or attempt_document.get("mode") != receipt["mode"]
        ):
            raise B1RealError(
                B1RealErrorCode.B1_REAL_BINDING_MISMATCH,
                f"$.source_receipts[{index}].attempt_document_name",
            )
        if receipt["run_spec_digest"] != manifest["run_spec_digest"]:
            raise B1RealError(
                B1RealErrorCode.B1_REAL_BINDING_MISMATCH,
                f"$.source_receipts[{index}].run_spec_digest",
            )
    attempt0 = _read_json(root / "attempts" / "attempt-00.json", "$.attempts[0]")
    cold_reset = attempt0.get("cold_reset") if isinstance(attempt0, dict) else None
    if not isinstance(cold_reset, dict):
        raise B1RealError(
            B1RealErrorCode.B1_REAL_BINDING_MISMATCH, "$.attempts[0].cold_reset"
        )
    for index, receipt in enumerate(file_receipts):
        if receipt["request_body_sha256"] != cold_reset.get("request_body_sha256"):
            raise B1RealError(
                B1RealErrorCode.B1_REAL_BINDING_MISMATCH,
                f"$.source_receipts[{index}].request_body_sha256",
            )
        if receipt["approval_sha256"] != manifest["approval_sha256"]:
            raise B1RealError(
                B1RealErrorCode.B1_REAL_BINDING_MISMATCH,
                f"$.source_receipts[{index}].approval_sha256",
            )
        if receipt["suite_run_name"] != manifest["run_name"]:
            raise B1RealError(
                B1RealErrorCode.B1_REAL_BINDING_MISMATCH,
                f"$.source_receipts[{index}].suite_run_name",
            )
    approval_digest = hashlib.sha256((root / "approval.json").read_bytes()).hexdigest()
    if approval_digest != manifest["approval_sha256"]:
        raise B1RealError(
            B1RealErrorCode.B1_REAL_BINDING_MISMATCH, "$.b1_real_manifest.approval"
        )
    ledger_sha256 = hashlib.sha256((root / "ledger.json").read_bytes()).hexdigest()
    for index, receipt in enumerate(file_receipts):
        if receipt["ledger_sha256"] != ledger_sha256:
            raise B1RealError(
                B1RealErrorCode.B1_REAL_BINDING_MISMATCH,
                f"$.source_receipts[{index}].ledger_sha256",
            )
    analyzer_name = b1_source._derive_analyzer_name(dataflow_enabled=_DATAFLOW_ENABLED)
    analyzer_fingerprint = compute_content_digest(
        {
            "analyzer_name": analyzer_name,
            "scanner_config_sha256": manifest["scanner_config_sha256"],
        }
    )
    for index, receipt in enumerate(file_receipts):
        if (
            receipt["analyzer_name"] != analyzer_name
            or receipt["analyzer_fingerprint"] != analyzer_fingerprint
            or receipt["scanner_config_sha256"]
            != manifest["scanner_config_sha256"]
        ):
            raise B1RealError(
                B1RealErrorCode.B1_REAL_BINDING_MISMATCH,
                f"$.source_receipts[{index}].analyzer_fingerprint",
            )
    if isinstance(report, dict) and report.get("run_spec_digest") != manifest[
        "run_spec_digest"
    ]:
        raise B1RealError(
            B1RealErrorCode.B1_REAL_BINDING_MISMATCH, "$.report.run_spec_digest"
        )
    # The projection faces: the report equals the independent re-scan and
    # the counted POST face equals the ledger call face.
    if not _projection_matches(report, _scan_faces(scan)):
        raise B1RealError(
            B1RealErrorCode.B1_REAL_PROJECTION_MISMATCH, "$.report.counts"
        )
    ledger_document = _read_json(root / "ledger.json", "$.ledger")
    ledger_calls = (
        ledger_document.get("batch", {}).get("calls")
        if isinstance(ledger_document, dict)
        else None
    )
    if (
        manifest["real_post_count"] != ledger_calls
        or manifest["ledger_calls"] != ledger_calls
    ):
        raise B1RealError(
            B1RealErrorCode.B1_REAL_PROJECTION_MISMATCH,
            "$.b1_real_manifest.real_post_count",
        )
    return {
        "run_spec_digest": manifest["run_spec_digest"],
        "scanner_payload_sha256": wire_digest,
        "source_receipts_digest": manifest["source_receipts_digest"],
        "attempt_count": attempt_count,
        "workload": manifest["workload"],
        "real_post_count": manifest["real_post_count"],
    }
