#!/usr/bin/env python3
"""Reproducible unlabeled paired benchmark for the UAF v2 pipeline.

Plan Task 12 (design section 16,
``docs/superpowers/specs/2026-09-10-cxx-uaf-v2-design.md``).  Every committed
case is a fixed vulnerable/fixed source pair.  The evaluation side owns the
labels: :func:`review_uaf` only ever receives the fixture workspace and a
fact bundle -- no case id, title, rationale, license or expected verdict has
a path into the pipeline.  The Sidecar half of the wire is a canned
``/v1/uaf-facts`` bundle per committed case (real Clang extraction is
already covered by the Task 4 container tests); ``--fake-llm`` scripts the
Specialist/Critic transport so CI stays offline.  Real provider traffic
happens only when the script runs without ``--fake-llm`` and a provider is
configured; without one the script refuses before any pipeline work.

Metrics (design section 16, all recomputable from the embedded records):

- Candidate Recall;
- Fact-verified Precision / Recall;
- Abstention Correctness (exact non-positive-state match);
- Vulnerable/Fixed Paired Accuracy (both sides exact);
- Coverage Gap Rate;
- LLM Calls / reply bytes / Latency;
- Proof Obligation Failure Distribution: an independent top-level P1-P7
  structure (counts and ratios, sliced by case kind, build-context source,
  language standard and project) that is never collapsed into one score.
"""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import json
import math
import os
import re
import shutil
import sys
import tempfile
import time
import unittest.mock
from collections.abc import Callable
from dataclasses import asdict
from pathlib import Path, PurePosixPath
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from lima import uaf_llm_branch  # noqa: E402
from lima.cxx_memory import UafFactsResponse, uaf_facts_bundle_sha256  # noqa: E402
from lima.uaf_orchestrator import UAF_POSITIVE_STATES, review_uaf  # noqa: E402
from lima.workspace import RepositoryWorkspace  # noqa: E402

VALIDITY_BOUNDARY = (
    "Synthetic and pinned pairs do not measure production detection capability."
)
REVISIONS = ("vulnerable", "fixed")
CASES_RELATIVE = "evaluation_data/uaf_v2_cases.json"
PAIRS_ROOT = ROOT / "tests" / "fixtures" / "uaf_v2_pairs"
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_CASE_ID = re.compile(r"^[a-z0-9][a-z0-9._-]{2,127}$")
_STANDARD = re.compile(r"^[A-Za-z0-9+#.]{1,32}$")
_CASE_KEYS = frozenset(
    {
        "id",
        "title",
        "kind",
        "origin",
        "language_standard",
        "expected",
        "vulnerable",
        "fixed",
        "selection_rationale",
        "license",
    }
)
_VERSION_KEYS = frozenset({"kind", "files"})
_EXPECTED_KEYS = frozenset({"verdict", "final_state", "candidates"})
_LICENSE_KEYS = frozenset({"spdx", "note"})
_PROOF_VERDICTS = frozenset({"PASS", "REFUTED", "UNKNOWN", "none"})
_FINAL_STATES = frozenset(
    {
        "fact-verified",
        "rejected",
        "abstain",
        "semantic-supported",
        "tool-corroborated",
        "runtime-confirmed",
        "needs-human-review",
        "none",
    }
)
# Closed code-shape vocabulary.  ``lifetime-restart-counterexample`` is
# accepted for future pairs: the Task 4 extractor does not emit supported
# lifetime-restart facts yet, so no committed case uses it (honest gap).
_CASE_KINDS = frozenset(
    {
        "direct-uaf",
        "guarded-same-block-uaf",
        "rebind-counterexample",
        "unreachable-use",
        "predicated-unknown",
        "lifetime-restart-counterexample",
        "deterministic-unknown-needs-llm",
    }
)
_SEMANTIC_CASE_KIND = "deterministic-unknown-needs-llm"
_ORIGINS = frozenset({"synthetic"})
_MAX_TITLE_BYTES = 200
_MAX_RATIONALE_BYTES = 4_096
_MAX_LICENSE_BYTES = 256
_MAX_CANDIDATES = 64
_MAX_LINE = 10_000_000
_MAX_ELAPSED_SECONDS = 3_600.0
_OBLIGATIONS = ("P1", "P2", "P3", "P4", "P5", "P6", "P7")
_OBLIGATION_VERDICTS = frozenset({"satisfied", "refuted", "unknown"})
_RECORD_KEYS = frozenset(
    {
        "case_id",
        "revision",
        "counted",
        "build_context_source",
        "translation_units",
        "coverage_gaps",
        "candidates",
        "candidate_count",
        "llm",
        "elapsed_seconds",
        "diagnostics",
    }
)
_CANDIDATE_KEYS = frozenset(
    {
        "candidate_id",
        "state",
        "proof_verdict",
        "obligations",
        "p5",
        "rejected_reason",
        "llm_invoked",
        "llm_calls",
    }
)
_LLM_KEYS = frozenset({"calls", "invoked_candidates", "reply_bytes"})
_MAX_USAGE_VALUE = 1_000_000_000
# The full deterministic v2 chain whose sources are fingerprinted into the
# report identity (order-stable, mirroring the Task 20 evaluator).
UAF_PIPELINE_COMPONENTS = (
    "cxx_memory.py",
    "uaf_models.py",
    "uaf_facts.py",
    "uaf_candidates.py",
    "uaf_proof.py",
    "uaf_llm_branch.py",
    "uaf_evidence_binder.py",
    "uaf_broker.py",
    "uaf_orchestrator.py",
)
_FAKE_CONTEXT_HASH = "e" * 64
FAKE_LLM_CONFIG = {
    "provider": "fake",
    "base_url": "https://fake-uaf-llm.invalid/v1",
    "api_key": "",
    "model": "fake-uaf-model",
    "headers": {},
}


# --------------------------------------------------------------------- schema


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def load_case_document(path: Path) -> dict[str, Any]:
    raw = Path(path).read_bytes()
    try:
        document = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=lambda value: (_ for _ in ()).throw(ValueError(value)),
        )
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise ValueError("case document is not valid JSON") from exc
    validate_case_document(document)
    return document


def _bounded_text(value: Any, label: str, maximum: int) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{label} must be non-empty text")
    if len(value.encode("utf-8")) > maximum:
        raise ValueError(f"{label} exceeds the byte limit")
    return value


def _safe_relative_path(value: Any, label: str) -> str:
    text = _bounded_text(value, label, 4_096)
    parsed = PurePosixPath(text)
    if (
        parsed.is_absolute()
        or "\\" in text
        or "\0" in text
        or any(part in {"", ".", ".."} for part in text.split("/"))
    ):
        raise ValueError(f"{label} must be a safe relative POSIX path")
    return text


def _exact_fields(
    payload: Any, expected: frozenset[str] | set[str], label: str
) -> dict[str, Any]:
    if type(payload) is not dict or set(payload) != set(expected):
        raise ValueError(f"{label} fields do not match the schema")
    return payload


def _validate_expected(expected: object, label: str) -> None:
    fields = _exact_fields(expected, _EXPECTED_KEYS, label)
    if fields["verdict"] not in _PROOF_VERDICTS:
        raise ValueError(f"{label} verdict is outside the closed domain")
    if fields["final_state"] not in _FINAL_STATES:
        raise ValueError(f"{label} final_state is outside the closed domain")
    candidates = fields["candidates"]
    if isinstance(candidates, bool) or type(candidates) is not int or not (
        0 <= candidates <= _MAX_CANDIDATES
    ):
        raise ValueError(f"{label} candidates must be a bounded non-negative integer")


def _validate_version(version: object, label: str) -> None:
    fields = _exact_fields(version, _VERSION_KEYS, label)
    if fields["kind"] != "source-pair":
        raise ValueError(f"{label} kind must be source-pair")
    files = fields["files"]
    if not isinstance(files, dict) or not files:
        raise ValueError(f"{label} must pin at least one file")
    if len(files) > 32:
        raise ValueError(f"{label} exceeds the file budget")
    for relative, digest in files.items():
        _safe_relative_path(relative, f"{label} file path")
        if not isinstance(digest, str) or not _HEX64.fullmatch(digest):
            raise ValueError(f"{label} file digest must be a lowercase SHA-256")


def _validate_case(case: object) -> None:
    fields = _exact_fields(case, _CASE_KEYS, "case")
    case_id = fields["id"]
    if not isinstance(case_id, str) or not _CASE_ID.fullmatch(case_id):
        raise ValueError("case id is invalid")
    _bounded_text(fields["title"], "case title", _MAX_TITLE_BYTES)
    if fields["kind"] not in _CASE_KINDS:
        raise ValueError("case kind is outside the closed code-shape domain")
    if fields["origin"] not in _ORIGINS:
        raise ValueError("case origin must be synthetic")
    if not isinstance(fields["language_standard"], str) or not _STANDARD.fullmatch(
        fields["language_standard"]
    ):
        raise ValueError("case language_standard is invalid")
    _validate_expected(fields["expected"]["vulnerable"], "vulnerable expected")
    _validate_expected(fields["expected"]["fixed"], "fixed expected")
    _validate_version(fields["vulnerable"], "vulnerable version")
    _validate_version(fields["fixed"], "fixed version")
    rationale = fields["selection_rationale"]
    if not isinstance(rationale, str) or len(rationale.strip()) < 40:
        raise ValueError("selection rationale is too short")
    if len(rationale.encode("utf-8")) > _MAX_RATIONALE_BYTES:
        raise ValueError("selection rationale exceeds the byte limit")
    license_info = _exact_fields(fields["license"], _LICENSE_KEYS, "license")
    _bounded_text(license_info["spdx"], "license spdx", _MAX_LICENSE_BYTES)
    _bounded_text(license_info["note"], "license note", _MAX_LICENSE_BYTES)


def validate_case_document(document: object) -> None:
    if not isinstance(document, dict) or set(document) != {"schema_version", "cases"}:
        raise ValueError("case document fields do not match schema")
    if (
        type(document["schema_version"]) is not int
        or document["schema_version"] != 1
        or not isinstance(document["cases"], list)
        or not document["cases"]
    ):
        raise ValueError("unsupported case document schema")
    identifiers: set[str] = set()
    for case in document["cases"]:
        _validate_case(case)
        if case["id"] in identifiers:
            raise ValueError("case ids must be unique")
        identifiers.add(case["id"])
    # Design section 16 hard rule: the manifest is invalid without at least
    # one deterministic proof UNKNOWN case that needs the Specialist/Critic
    # branch -- otherwise a real-model run could not claim verification.
    semantic = [
        case for case in document["cases"] if case["kind"] == _SEMANTIC_CASE_KIND
    ]
    if len(semantic) != 1:
        raise ValueError(
            "the manifest must contain exactly one "
            f"{_SEMANTIC_CASE_KIND} case (design section 16)"
        )
    expected = semantic[0]["expected"]["vulnerable"]
    if expected["verdict"] != "UNKNOWN" or expected["candidates"] < 1:
        raise ValueError("the deterministic-unknown case must expect UNKNOWN proof")


def select_cases(document: dict[str, Any], case_id: str | None) -> list[dict[str, Any]]:
    """Select already-validated committed cases for the evaluation run."""

    validate_case_document(document)
    if case_id is None:
        return list(document["cases"])
    if type(case_id) is not str or not re.fullmatch(_CASE_ID.pattern, case_id):
        raise ValueError("evaluation case id is invalid")
    matches = [case for case in document["cases"] if case["id"] == case_id]
    if len(matches) != 1:
        raise ValueError("evaluation case id is not in the committed manifest")
    return matches


# ------------------------------------------------------------------- fixtures


def file_digest(path: Path) -> str:
    """Digest one fixture file from newline-normalized content.

    Normalizing CRLF to LF keeps the pin stable across checkouts, mirroring
    the Task 20 evaluator and ``lima.real_world_evaluation``.
    """

    payload = Path(path).read_bytes().replace(b"\r\n", b"\n").replace(b"\r", b"\n")
    return hashlib.sha256(payload).hexdigest()


def verify_version_pins(case: dict[str, Any], revision: str) -> list[tuple[str, Path]]:
    """Verify the pinned files of one revision exist with pinned content.

    Returns the sorted ``(relative path, absolute path)`` list; any drift,
    missing file or unsafe path fails closed before any pipeline work.
    """

    if revision not in REVISIONS:
        raise ValueError(f"unknown revision {revision!r}")
    version = case[revision]
    files: list[tuple[str, Path]] = []
    for relative in sorted(version["files"]):
        absolute = (PAIRS_ROOT / case["id"] / revision / relative).resolve()
        root = (PAIRS_ROOT / case["id"] / revision).resolve()
        if not absolute.is_relative_to(root) or not absolute.is_file():
            raise ValueError(
                f"pinned fixture {case['id']}/{revision}/{relative} is unavailable"
            )
        if file_digest(absolute) != version["files"][relative]:
            raise ValueError(
                f"fixture content digest mismatch for {case['id']} {revision} "
                f"{relative}; the pinned pair changed on disk"
            )
        files.append((relative, absolute))
    return files


@contextlib.contextmanager
def pinned_workspace(case: dict[str, Any], revision: str):
    """Materialize one pinned revision into a temporary workspace.

    Yields ``(root, translation_units)``; the units are the sorted pinned
    paths, exactly the TU selection a scanner would pass for this snapshot.
    """

    files = verify_version_pins(case, revision)
    root = Path(tempfile.mkdtemp(prefix="uaf-v2-evaluation-"))
    try:
        for relative, source in files:
            target = root.joinpath(*PurePosixPath(relative).parts)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(source.read_bytes())
        units = tuple(relative for relative, _ in files)
        yield root, units
    finally:
        shutil.rmtree(root, ignore_errors=True)


def evaluation_repository_key(revision: str) -> str:
    """Neutral scan key: deliberately free of any case identifier."""

    return f"uaf-v2-evaluation/{revision}"


# ------------------------------------------------------- fake sidecar wires


def _fact(
    kind: str,
    number: int,
    line: int,
    *,
    unit: str,
    usr: str,
    pointer: str = "",
    api: str = "",
    source: str = "",
    related: tuple[int, ...] = (),
    block: int = 0,
) -> dict[str, Any]:
    """One wire fact with the kind's exact closed field set (Task 4 form)."""

    fact_id = format(number, "064x")
    fact: dict[str, Any] = {
        "fact_id": fact_id,
        "kind": kind,
        "translation_unit": unit,
        "canonical_path": unit,
        "function_usr": usr,
        "source_range": [line, line],
        "cfg_block": block,
    }
    if kind == "allocation":
        fact["allocation_api"] = api
        fact["pointer_id"] = pointer
    elif kind == "release":
        fact["release_api"] = api
        fact["pointer_id"] = pointer
        fact["related_fact_ids"] = [format(item, "064x") for item in related]
    elif kind in ("dereference", "member-access"):
        fact["pointer_id"] = pointer
    elif kind in ("alias-copy", "points-to"):
        fact["pointer_id"] = pointer
        fact["source_pointer_id"] = source
    elif kind == "rebind":
        fact["pointer_id"] = pointer
        fact["source_pointer_id"] = source
        fact["related_fact_ids"] = [format(item, "064x") for item in related]
    else:
        raise ValueError(f"unsupported wire fact kind {kind!r}")
    return fact


def _unit_entry(unit: str, facts: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "translation_unit": unit,
        "extraction": "completed",
        "build_context": {
            "status": "resolved",
            "source_kind": "repository-compdb",
            "context_hash": _FAKE_CONTEXT_HASH,
            "diagnostics": [],
        },
        "coverage": {"ast_complete": True, "cfg_complete": True, "semantic_gaps": []},
        "facts": facts,
    }


def _wire_direct_new_delete(unit: str, revision: str) -> list[dict[str, Any]]:
    usr = "c:@F@packet_size#"
    head = [
        _fact("allocation", 1, 8, unit=unit, usr=usr, pointer="p", api="new"),
        _fact("member-access", 2, 9, unit=unit, usr=usr, pointer="p"),
        _fact("release", 3, 10, unit=unit, usr=usr, pointer="p", api="delete",
              related=(1,)),
    ]
    if revision == "vulnerable":
        head.append(_fact("member-access", 4, 11, unit=unit, usr=usr, pointer="p"))
    return [_unit_entry(unit, head)]


def _wire_direct_malloc_free(unit: str, revision: str) -> list[dict[str, Any]]:
    usr = "c:@F@session_id#"
    head = [
        _fact("allocation", 1, 8, unit=unit, usr=usr, pointer="s", api="malloc"),
        _fact("member-access", 2, 9, unit=unit, usr=usr, pointer="s"),
        _fact("release", 3, 10, unit=unit, usr=usr, pointer="s", api="free",
              related=(1,)),
    ]
    if revision == "vulnerable":
        head.append(_fact("member-access", 4, 11, unit=unit, usr=usr, pointer="s"))
    return [_unit_entry(unit, head)]


def _wire_guarded_same_block(unit: str, revision: str) -> list[dict[str, Any]]:
    usr = "c:@F@frame_id#"
    head = [
        _fact("allocation", 1, 8, unit=unit, usr=usr, pointer="f", api="new"),
        _fact("member-access", 2, 9, unit=unit, usr=usr, pointer="f"),
        _fact("release", 3, 13, unit=unit, usr=usr, pointer="f", api="delete",
              related=(1,), block=1),
    ]
    if revision == "vulnerable":
        head.append(
            _fact("member-access", 4, 14, unit=unit, usr=usr, pointer="f", block=1)
        )
    return [_unit_entry(unit, head)]


def _wire_rebind_counterexample(unit: str, revision: str) -> list[dict[str, Any]]:
    usr = "c:@F@cursor_read#"
    if revision == "vulnerable":
        facts = [
            _fact("allocation", 1, 8, unit=unit, usr=usr, pointer="p", api="malloc"),
            _fact("member-access", 2, 9, unit=unit, usr=usr, pointer="p"),
            _fact("release", 3, 10, unit=unit, usr=usr, pointer="p", api="free",
                  related=(1,)),
            _fact("rebind", 4, 11, unit=unit, usr=usr, pointer="p", source="fresh",
                  related=(1,)),
            _fact("member-access", 5, 12, unit=unit, usr=usr, pointer="p"),
        ]
    else:
        facts = [
            _fact("allocation", 1, 8, unit=unit, usr=usr, pointer="p", api="malloc"),
            _fact("member-access", 2, 9, unit=unit, usr=usr, pointer="p"),
            _fact("release", 3, 10, unit=unit, usr=usr, pointer="p", api="free",
                  related=(1,)),
        ]
    return [_unit_entry(unit, facts)]


def _wire_unreachable_use(unit: str, revision: str) -> list[dict[str, Any]]:
    usr = "c:@F@ring_head#"
    if revision == "vulnerable":
        # Modeled serialization under test: the read linearizes into cfg
        # block 1 while the conditional release sits in block 2, so P5
        # structural reachability refutes the witness.
        facts = [
            _fact("allocation", 1, 8, unit=unit, usr=usr, pointer="ring",
                  api="malloc"),
            _fact("member-access", 2, 9, unit=unit, usr=usr, pointer="ring"),
            _fact("release", 3, 11, unit=unit, usr=usr, pointer="ring", api="free",
                  related=(1,), block=2),
            _fact("member-access", 4, 13, unit=unit, usr=usr, pointer="ring",
                  block=1),
        ]
    else:
        facts = [
            _fact("allocation", 1, 8, unit=unit, usr=usr, pointer="ring",
                  api="malloc"),
            _fact("member-access", 2, 9, unit=unit, usr=usr, pointer="ring"),
            _fact("member-access", 3, 10, unit=unit, usr=usr, pointer="ring"),
            _fact("release", 4, 12, unit=unit, usr=usr, pointer="ring", api="free",
                  related=(1,), block=1),
        ]
    return [_unit_entry(unit, facts)]


def _wire_predicated_unknown(unit: str, revision: str) -> list[dict[str, Any]]:
    usr = "c:@F@sample_pick#"
    if revision == "vulnerable":
        facts = [
            _fact("allocation", 1, 8, unit=unit, usr=usr, pointer="s", api="malloc"),
            _fact("member-access", 2, 9, unit=unit, usr=usr, pointer="s"),
            _fact("release", 3, 11, unit=unit, usr=usr, pointer="s", api="free",
                  related=(1,), block=1),
            _fact("member-access", 4, 14, unit=unit, usr=usr, pointer="s", block=3),
        ]
    else:
        facts = [
            _fact("allocation", 1, 8, unit=unit, usr=usr, pointer="s", api="malloc"),
            _fact("member-access", 2, 9, unit=unit, usr=usr, pointer="s"),
            _fact("member-access", 3, 10, unit=unit, usr=usr, pointer="s"),
            _fact("release", 4, 12, unit=unit, usr=usr, pointer="s", api="free",
                  related=(1,), block=1),
        ]
    return [_unit_entry(unit, facts)]


def _wire_semantic_unknown_alias(unit: str, revision: str) -> list[dict[str, Any]]:
    usr = "c:@F@bridge_read#"
    if revision == "vulnerable":
        # The alias-copy for q carries no source anchor (the launder hop is
        # outside the supported alias syntax) while the release attribution
        # still names the allocation: exactly the P2/P6 unknown fact form
        # that only the Specialist/Critic branch can decide.
        facts = [
            _fact("allocation", 1, 10, unit=unit, usr=usr, pointer="b",
                  api="malloc"),
            _fact("alias-copy", 2, 11, unit=unit, usr=usr, pointer="q", source=""),
            _fact("release", 3, 12, unit=unit, usr=usr, pointer="q", api="free",
                  related=(1,)),
            _fact("member-access", 4, 13, unit=unit, usr=usr, pointer="b"),
        ]
    else:
        facts = [
            _fact("allocation", 1, 10, unit=unit, usr=usr, pointer="b",
                  api="malloc"),
            _fact("alias-copy", 2, 11, unit=unit, usr=usr, pointer="q", source=""),
            _fact("member-access", 3, 12, unit=unit, usr=usr, pointer="b"),
            _fact("release", 4, 13, unit=unit, usr=usr, pointer="q", api="free",
                  related=(1,)),
        ]
    return [_unit_entry(unit, facts)]


# Canned sidecar wires per committed case id.  Adding a case to the
# manifest without adding its wire here fails the run before any scoring.
_WIRE_BUILDERS: dict[str, Callable[[str, str], list[dict[str, Any]]]] = {
    "direct-new-delete-uaf": _wire_direct_new_delete,
    "direct-malloc-free-uaf": _wire_direct_malloc_free,
    "guarded-same-block-uaf": _wire_guarded_same_block,
    "rebind-counterexample-uaf": _wire_rebind_counterexample,
    "unreachable-use-uaf": _wire_unreachable_use,
    "predicated-unknown-uaf": _wire_predicated_unknown,
    "semantic-unknown-alias-uaf": _wire_semantic_unknown_alias,
}


def build_fake_wire(case_id: str, unit: str, revision: str) -> list[dict[str, Any]]:
    """Build the canned bundle for one case over its pinned TU selection."""

    builder = _WIRE_BUILDERS.get(case_id)
    if builder is None:
        raise ValueError(f"no canned sidecar wire is committed for case {case_id!r}")
    return builder(unit, revision)


class FakeUafSidecar:
    """Offline stand-in for the strict ``/v1/uaf-facts`` client boundary.

    Serves one canned bundle and echoes the caller identity exactly like
    the real Sidecar; ``review_uaf`` cannot distinguish it from
    ``CxxMemoryAnalyzerClient`` by the response shape alone.
    """

    def __init__(self, units: list[dict[str, Any]], *, run_id: str = "run-uaf-v2-eval"):
        self.units = json.loads(json.dumps(units))
        self.run_id = run_id
        self.calls: list[tuple[tuple[str, ...], str]] = []

    def analyze_uaf_facts(
        self,
        repository_key: str,
        snapshot_sha256: str,
        translation_units: tuple[str, ...],
        build_context_mode: str,
    ) -> UafFactsResponse:
        self.calls.append((tuple(translation_units), build_context_mode))
        return UafFactsResponse(
            request_id="req-uaf-v2-evaluation",
            repository_key=repository_key,
            snapshot_sha256=snapshot_sha256,
            tool_runs=(
                {"run_id": self.run_id, "tool": "uaf-facts", "status": "completed"},
            ),
            translation_units=tuple(self.units),
            bundle_sha256=uaf_facts_bundle_sha256(self.units),
            diagnostics=(),
        )


# ------------------------------------------------------------- fake semantic


_ABSTAIN_ASSUMPTION = (
    "joint predicate satisfiability cannot be decided from the provided facts"
)
# The scripted honest model: the Specialist/Critic abstain everywhere
# except the committed deterministic-UNKNOWN case, where both roles
# support the candidate with a real fact id from the served context.
_SEMANTIC_SCRIPTS: dict[str, dict[str, Any]] = {
    "semantic-unknown-alias-uaf": {
        "assessment": "supports-uaf",
        "support_kind": "allocation",
        "assumptions": (),
        "rationale": (
            "the recorded allocation and release facts keep the candidate "
            "object bound at the post-release use"
        ),
    }
}
_DEFAULT_SCRIPT: dict[str, Any] = {
    "assessment": "abstain",
    "support_kind": "",
    "assumptions": (_ABSTAIN_ASSUMPTION,),
    "rationale": "the provided facts do not decide the candidate's lifetime",
}


def scripted_semantic_transport(
    case_id: str, counter: dict[str, int]
) -> Callable[..., str]:
    """Build the offline Specialist/Critic transport for one case."""

    script = _SEMANTIC_SCRIPTS.get(case_id, _DEFAULT_SCRIPT)

    def transport(
        provider, base_url, api_key, payload, timeout, extra_headers=None,
        max_bytes=None,
    ):
        del provider, base_url, api_key, timeout, extra_headers, max_bytes
        counter["calls"] += 1
        user = payload["messages"][1]["content"]
        candidate_id = ""
        fact_kinds: list[tuple[str, str]] = []
        for line in user.splitlines():
            if line.startswith("- candidate_id: "):
                candidate_id = line.split(": ", 1)[1]
            elif line.startswith("- ") and " kind=" in line:
                head = line[2:].split(" ", 1)
                fact_kinds.append((head[0], head[1].split(" ", 1)[0]))
        supporting: list[str] = []
        if script["assessment"] == "supports-uaf":
            anchor = next(
                (
                    fact_id
                    for fact_id, kind in fact_kinds
                    if kind == script["support_kind"]
                ),
                fact_kinds[0][0] if fact_kinds else "",
            )
            supporting = [anchor] if anchor else []
        reply = {
            "candidate_id": candidate_id,
            "supporting_fact_ids": supporting,
            "refuting_fact_ids": [],
            "unresolved_assumptions": list(script["assumptions"]),
            "semantic_assessment": script["assessment"],
            "rationale": script["rationale"],
        }
        text = json.dumps(reply)
        counter["bytes"] += len(text.encode("utf-8"))
        return text

    return transport


# ------------------------------------------------------------------- runner


def run_revision(
    case: dict[str, Any],
    revision: str,
    *,
    mode: str = "auto",
    fake_llm: bool = True,
    llm_config: dict[str, Any] | None = None,
    timeout: int = 60,
) -> dict[str, Any]:
    """Run the real review chain over one pinned revision, offline or not.

    The pipeline receives only the fixture workspace and the served fact
    bundle; every label stays on the evaluation side and is applied later
    by :func:`run_evaluation`.  With ``fake_llm`` the Specialist/Critic
    transport is the scripted honest model and no provider is needed.
    """

    if revision not in REVISIONS:
        raise ValueError(f"unknown revision {revision!r}")
    case_id = case["id"]
    if case_id not in _WIRE_BUILDERS:
        raise ValueError(f"no canned sidecar wire is committed for case {case_id!r}")
    if not fake_llm and not llm_config:
        raise ValueError("a real run needs llm_config (or use --fake-llm)")
    with pinned_workspace(case, revision) as (root, units):
        workspace = RepositoryWorkspace(root)
        snapshot = workspace.inventory().fingerprint()
        analyzer = FakeUafSidecar(build_fake_wire(case_id, units[0], revision))
        counter = {"calls": 0, "bytes": 0}
        started = time.monotonic()
        if fake_llm:
            transport = scripted_semantic_transport(case_id, counter)
            with unittest.mock.patch.object(
                uaf_llm_branch, "post_chat_completion_text", transport
            ):
                outcome = review_uaf(
                    analyzer,
                    workspace,
                    repository_key=evaluation_repository_key(revision),
                    snapshot_hash=snapshot,
                    translation_units=units,
                    mode=mode,
                    llm_config=dict(FAKE_LLM_CONFIG),
                    timeout=timeout,
                )
        else:
            outcome = review_uaf(
                analyzer,
                workspace,
                repository_key=evaluation_repository_key(revision),
                snapshot_hash=snapshot,
                translation_units=units,
                mode=mode,
                llm_config=dict(llm_config or {}),
                timeout=timeout,
            )
        elapsed = time.monotonic() - started
        return _record_from_outcome(
            case_id, revision, analyzer, outcome, counter, elapsed
        )


def _record_from_outcome(
    case_id: str,
    revision: str,
    analyzer: FakeUafSidecar,
    outcome: Any,
    counter: dict[str, int],
    elapsed: float,
) -> dict[str, Any]:
    candidates = []
    for item in outcome.candidates:
        proof = item.proof
        p5 = (
            asdict(proof.p5_detail)
            if proof is not None and proof.p5_detail is not None
            else None
        )
        candidates.append(
            {
                "candidate_id": item.identity.candidate_id,
                "state": item.state,
                "proof_verdict": proof.verdict if proof is not None else "",
                "obligations": (
                    {v.obligation.value: v.verdict for v in proof.obligations}
                    if proof is not None
                    else {}
                ),
                "p5": p5,
                "rejected_reason": item.rejected_reason,
                "llm_invoked": bool(item.llm is not None and item.llm.invoked),
                "llm_calls": item.llm.calls if item.llm is not None else 0,
            }
        )
    served_units = analyzer.units
    return {
        "case_id": case_id,
        "revision": revision,
        "counted": True,
        "build_context_source": str(
            served_units[0]["build_context"]["source_kind"]
        ) if served_units else "",
        "translation_units": [unit["translation_unit"] for unit in served_units],
        "coverage_gaps": sorted(
            {
                gap
                for unit in served_units
                for gap in unit["coverage"]["semantic_gaps"]
            }
        ),
        "candidates": candidates,
        "candidate_count": len(candidates),
        "llm": {
            "calls": int(outcome.stats.llm_calls),
            "invoked_candidates": int(outcome.stats.llm_invoked_count),
            "reply_bytes": int(counter["bytes"]),
        },
        "elapsed_seconds": float(elapsed),
        "diagnostics": [str(item) for item in outcome.diagnostics][:64],
    }


# ------------------------------------------------------------------- scoring


def _validate_record(raw: object) -> dict[str, Any]:
    record = _exact_fields(raw, _RECORD_KEYS, "pipeline record")
    if type(record["counted"]) is not bool:
        raise ValueError("record counted must be a boolean")
    _bounded_text(record["case_id"], "record case_id", 128)
    if record["revision"] not in REVISIONS:
        raise ValueError("record revision is outside the closed domain")
    candidates = record["candidates"]
    if type(candidates) is not list or len(candidates) > _MAX_CANDIDATES:
        raise ValueError("record candidates must be a bounded array")
    for candidate in candidates:
        fields = _exact_fields(candidate, _CANDIDATE_KEYS, "candidate record")
        _bounded_text(fields["candidate_id"], "candidate_id", 64)
        _bounded_text(fields["state"], "candidate state", 64)
        _bounded_text(fields["proof_verdict"], "proof verdict", 16)
        obligations = fields["obligations"]
        if type(obligations) is not dict or not set(obligations) <= set(_OBLIGATIONS):
            raise ValueError("candidate obligations must be a P1-P7 subset")
        for obligation, verdict in obligations.items():
            if verdict not in _OBLIGATION_VERDICTS:
                raise ValueError(f"obligation {obligation} has an invalid verdict")
        if fields["p5"] is not None and not isinstance(fields["p5"], dict):
            raise ValueError("candidate p5 must be an object or null")
    llm = _exact_fields(record["llm"], _LLM_KEYS, "record llm usage")
    for name, value in llm.items():
        if isinstance(value, bool) or type(value) is not int or not (
            0 <= value <= _MAX_USAGE_VALUE
        ):
            raise ValueError(f"llm usage {name} must be a bounded integer")
    elapsed = record["elapsed_seconds"]
    if (
        isinstance(elapsed, bool)
        or not isinstance(elapsed, int | float)
        or not math.isfinite(elapsed)
        or not 0 <= elapsed <= _MAX_ELAPSED_SECONDS
    ):
        raise ValueError("elapsed_seconds must be a finite bounded number")
    return record


def _observed_state(record: dict[str, Any]) -> str:
    states = [candidate["state"] for candidate in record["candidates"]]
    if not states:
        return "none"
    return states[0] if len(set(states)) == 1 else "mixed"


def _observed_verdicts(record: dict[str, Any]) -> list[str]:
    return sorted(
        {candidate["proof_verdict"] for candidate in record["candidates"]}
    )


def _safe_ratio(
    numerator: float, denominator: float, label: str, diagnostics: list[str]
) -> Any:
    if denominator == 0:
        diagnostics.append(f"{label} denominator is zero")
        return None
    return numerator / denominator


def _new_tally() -> dict[str, dict[str, int]]:
    return {
        obligation: {"satisfied": 0, "unknown": 0, "refuted": 0, "total": 0}
        for obligation in _OBLIGATIONS
    }


def _tally(tally: dict[str, dict[str, int]], candidates: list[dict[str, Any]]) -> None:
    for candidate in candidates:
        for obligation, verdict in candidate["obligations"].items():
            if obligation in tally and verdict in _OBLIGATION_VERDICTS:
                tally[obligation][verdict] += 1
                tally[obligation]["total"] += 1


def _finalize_tally(
    tally: dict[str, dict[str, int]], diagnostics: list[str]
) -> dict[str, dict[str, Any]]:
    finalized: dict[str, dict[str, Any]] = {}
    for obligation in _OBLIGATIONS:
        entry = dict(tally[obligation])
        total = entry["total"]
        entry["unknown_ratio"] = _safe_ratio(
            entry["unknown"], total, f"obligation {obligation} unknown_ratio",
            diagnostics,
        )
        entry["refuted_ratio"] = _safe_ratio(
            entry["refuted"], total, f"obligation {obligation} refuted_ratio",
            diagnostics,
        )
        finalized[obligation] = entry
    return finalized


def _obligation_distribution(
    cases: list[dict[str, Any]], records: dict[tuple[str, str], dict[str, Any]]
) -> tuple[dict[str, Any], list[str]]:
    """Build the independent top-level P1-P7 failure distribution.

    Counts and ratios of ``unknown``/``refuted`` per obligation, sliced by
    case kind, build-context source, language standard and project.  The
    structure is deliberately never collapsed into a single score (design
    section 16): the slices decide what the next phase strengthens.
    """

    diagnostics: list[str] = []
    overall = _new_tally()
    slices: dict[str, dict[str, dict[str, dict[str, int]]]] = {
        "by_case_kind": {},
        "by_build_context_source": {},
        "by_language_standard": {},
        "by_project": {},
    }
    for case in cases:
        for revision in REVISIONS:
            record = records[(case["id"], revision)]
            if not record["counted"]:
                continue
            candidates = record["candidates"]
            _tally(overall, candidates)
            for name, key in (
                ("by_case_kind", case["kind"]),
                ("by_build_context_source", record["build_context_source"]),
                ("by_language_standard", case["language_standard"]),
                ("by_project", case["origin"]),
            ):
                _tally(slices[name].setdefault(key, _new_tally()), candidates)
    finalized_slices = {
        name: {
            key: _finalize_tally(tally, diagnostics)
            for key, tally in sorted(bucket.items())
        }
        for name, bucket in slices.items()
    }
    distribution = {
        "description": (
            "P1-P7 obligation verdicts over every generated candidate; counts "
            "and ratios of unknown/refuted per obligation, sliced for the "
            "next-phase decision and never collapsed into a single score"
        ),
        "overall": _finalize_tally(overall, diagnostics),
        "slices": finalized_slices,
    }
    return distribution, diagnostics


def run_evaluation(
    cases: list[dict[str, Any]],
    records: dict[tuple[str, str], dict[str, Any]],
) -> dict[str, Any]:
    """Score the fixed pairs; labels never enter the records themselves.

    Every revision record stays visible; counted revisions feed the
    confusion matrices and rates, and any zero denominator yields JSON
    ``null`` plus a diagnostic instead of a fabricated zero.
    """

    diagnostics: list[str] = []
    confusion = {"tp": 0, "fp": 0, "fn": 0, "tn": 0}
    case_results: list[dict[str, Any]] = []
    counted_revisions = revision_count = 0
    recall_eligible = recall_hits = 0
    abstain_total = abstain_correct = 0
    pair_eligible = pair_correct = 0
    gap_revisions = 0
    calls_total = invoked_total = bytes_total = 0
    latency_total = 0.0

    for case in cases:
        revisions_result: dict[str, Any] = {}
        counted_pair = True
        correct_pair = True
        for revision in REVISIONS:
            record = _validate_record(records[(case["id"], revision)])
            revision_count += 1
            expected = case["expected"][revision]
            observed = _observed_state(record)
            states = [candidate["state"] for candidate in record["candidates"]]
            expected_fv = expected["final_state"] == "fact-verified"
            observed_fv = "fact-verified" in states
            confusion[
                "tp" if expected_fv and observed_fv
                else "fn" if expected_fv
                else "fp" if observed_fv
                else "tn"
            ] += 1
            if record["counted"]:
                counted_revisions += 1
                if revision == "vulnerable" and expected["candidates"] >= 1:
                    recall_eligible += 1
                    recall_hits += int(record["candidate_count"] >= 1)
                if expected["final_state"] not in UAF_POSITIVE_STATES:
                    abstain_total += 1
                    abstain_correct += int(observed == expected["final_state"])
                if record["coverage_gaps"]:
                    gap_revisions += 1
                latency_total += float(record["elapsed_seconds"])
                calls_total += record["llm"]["calls"]
                invoked_total += record["llm"]["invoked_candidates"]
                bytes_total += record["llm"]["reply_bytes"]
            else:
                counted_pair = False
                diagnostics.append(
                    f"pair scoring for {case['id']} skips the degraded "
                    f"{revision} revision"
                )
            state_exact = observed == expected["final_state"]
            correct_pair = correct_pair and state_exact
            revisions_result[revision] = {
                "counted": record["counted"],
                "expected_verdict": expected["verdict"],
                "expected_final_state": expected["final_state"],
                "expected_candidates": expected["candidates"],
                "observed_final_state": observed,
                "observed_verdicts": _observed_verdicts(record),
                "observed_states": states,
                "state_exact": state_exact,
                "fact_verified_hit": observed_fv,
                "candidate_count": record["candidate_count"],
                "coverage_gaps": record["coverage_gaps"],
                "llm": dict(record["llm"]),
                "elapsed_seconds": float(record["elapsed_seconds"]),
                "diagnostics": record["diagnostics"],
            }
        if counted_pair:
            pair_eligible += 1
            pair_correct += int(correct_pair)
            case_results.append(
                {
                    "case_id": case["id"],
                    "kind": case["kind"],
                    "language_standard": case["language_standard"],
                    "revisions": revisions_result,
                    "pair_correct": bool(correct_pair),
                }
            )
        else:
            case_results.append(
                {
                    "case_id": case["id"],
                    "kind": case["kind"],
                    "language_standard": case["language_standard"],
                    "revisions": revisions_result,
                    "pair_correct": None,
                }
            )

    precision = _safe_ratio(
        confusion["tp"], confusion["tp"] + confusion["fp"],
        "fact_verified_precision", diagnostics,
    )
    recall = _safe_ratio(
        confusion["tp"], confusion["tp"] + confusion["fn"],
        "fact_verified_recall", diagnostics,
    )
    distribution, distribution_diagnostics = _obligation_distribution(
        cases, records
    )
    diagnostics.extend(distribution_diagnostics)
    return {
        "schema_version": 1,
        "case_count": len(cases),
        "revision_count": revision_count,
        "counted_revision_count": counted_revisions,
        "candidate_recall": _safe_ratio(
            recall_hits, recall_eligible, "candidate_recall", diagnostics
        ),
        "fact_verified_confusion": confusion,
        "fact_verified_precision": precision,
        "fact_verified_recall": recall,
        "abstention_correctness": {
            "rate": _safe_ratio(
                abstain_correct, abstain_total, "abstention_correctness",
                diagnostics,
            ),
            "correct": abstain_correct,
            "total": abstain_total,
            "definition": (
                "exact non-positive-state match: expected abstain/rejected/none "
                "revisions where the pipeline stayed in the expected state"
            ),
        },
        "paired_accuracy": _safe_ratio(
            pair_correct, pair_eligible, "paired_accuracy", diagnostics
        ),
        "pair_eligible_count": pair_eligible,
        "coverage_gap_rate": {
            "rate": _safe_ratio(
                gap_revisions, counted_revisions, "coverage_gap_rate", diagnostics
            ),
            "revisions_with_gaps": gap_revisions,
            "revisions_counted": counted_revisions,
        },
        "llm_usage": {
            "calls_total": calls_total,
            "calls_mean": _safe_ratio(
                calls_total, revision_count, "calls_mean", diagnostics
            ),
            "invoked_candidates_total": invoked_total,
            "reply_bytes_total": bytes_total,
            "reply_bytes_mean": _safe_ratio(
                bytes_total, revision_count, "reply_bytes_mean", diagnostics
            ),
            "accounting": (
                "provider calls charged by the pipeline; reply size in bytes as "
                "the transport-level proxy (no provider token accounting)"
            ),
        },
        "latency_seconds": {
            "total": latency_total,
            "mean": _safe_ratio(
                latency_total, revision_count, "latency_mean", diagnostics
            ),
        },
        "proof_obligation_distribution": distribution,
        "cases": case_results,
        "records": [records[(case["id"], revision)] for case in cases
                    for revision in REVISIONS],
        "diagnostics": diagnostics,
    }


# ------------------------------------------------------------------ identity


def _canonical_source_bytes(payload: bytes) -> bytes:
    return payload.replace(b"\r\n", b"\n").replace(b"\r", b"\n")


def uaf_pipeline_fingerprint() -> str:
    digest = hashlib.sha256()
    package_root = ROOT / "lima"
    for name in UAF_PIPELINE_COMPONENTS:
        payload = _canonical_source_bytes((package_root / name).read_bytes())
        digest.update(name.encode("utf-8"))
        digest.update(b"\0")
        digest.update(str(len(payload)).encode("ascii"))
        digest.update(b"\0")
        digest.update(payload)
    return digest.hexdigest()


def build_identity_manifest(
    *,
    mode: str,
    fake_llm: bool,
    provider: str,
    model: str,
    raw_case_data: bytes,
) -> dict[str, Any]:
    return {
        "mode": mode,
        "llm_transport": "fake" if fake_llm else "provider",
        "provider": provider,
        "model": model,
        "uaf_pipeline_sha256": uaf_pipeline_fingerprint(),
        "case_data_sha256": hashlib.sha256(raw_case_data).hexdigest(),
    }


def add_report_metadata(
    report: dict[str, Any],
    raw_case_data: bytes,
    *,
    mode: str,
    fake_llm: bool,
    provider: str,
    model: str,
) -> dict[str, Any]:
    result = dict(report)
    result["mode"] = mode
    result["llm_transport"] = "fake" if fake_llm else "provider"
    result["identity"] = build_identity_manifest(
        mode=mode, fake_llm=fake_llm, provider=provider, model=model,
        raw_case_data=raw_case_data,
    )
    result["validity_boundaries"] = [
        VALIDITY_BOUNDARY,
        "The pipeline input is the fixture workspace plus the served fact "
        "bundle only; labels are applied outside the pipeline.",
        "The Sidecar half is a canned /v1/uaf-facts bundle per committed "
        "case; real Clang extraction is verified separately by the Task 4 "
        "container tests and the real-environment acceptance runs.",
        "A null metric means its denominator was zero, not a perfect score.",
        "The Proof Obligation Failure Distribution is an independent P1-P7 "
        "structure and is never collapsed into a single score.",
        "The reply-byte LLM proxy is not provider token accounting.",
        "Real-model, Docker/Clang/ASan runs that have not happened are "
        "reported as unverified and never substituted by this fake run.",
    ]
    return result


# ------------------------------------------------------------------ provider


class ProviderNotConfigured(RuntimeError):
    """A real (non-fake) run started without a usable provider config."""


def build_llm_config(
    args: argparse.Namespace, env: dict[str, str] | None = None
) -> tuple[dict[str, Any], str, str]:
    """Resolve the semantic-branch provider, preferring explicit arguments.

    Mirrors ``lima.config.Settings.resolved_llm()``: ``LIMA_LLM_BASE_URL``,
    ``LIMA_LLM_PROVIDER``, the model selection and the key environments.
    Fake runs bypass this entirely.
    """

    if getattr(args, "fake_llm", False):
        return dict(FAKE_LLM_CONFIG), "fake", str(FAKE_LLM_CONFIG["model"])
    environment = dict(os.environ) if env is None else env
    base_url = str(
        getattr(args, "provider_url", None)
        or environment.get("LIMA_LLM_BASE_URL", "")
        or ""
    ).rstrip("/")
    model = str(
        getattr(args, "model", None)
        or environment.get("LIMA_CXX_AGENT_MODEL", "")
        or environment.get("LIMA_LLM_MODEL", "")
        or ""
    ).strip()
    api_key = str(
        getattr(args, "provider_key", None)
        or environment.get("LIMA_LLM_API_KEY", "")
        or ""
    )
    provider = environment.get("LIMA_LLM_PROVIDER", "").strip() or "custom"
    if not base_url or not model:
        raise ProviderNotConfigured(
            "provider-not-configured: the UAF v2 evaluation needs a real "
            "provider for non-fake runs -- pass --provider-url and --model, "
            "or set LIMA_LLM_BASE_URL and LIMA_CXX_AGENT_MODEL (or "
            "LIMA_LLM_MODEL); use --fake-llm for the offline scripted run"
        )
    return (
        {
            "provider": provider,
            "base_url": base_url,
            "api_key": api_key,
            "model": model,
            "headers": {},
        },
        provider,
        model,
    )


# ------------------------------------------------------------------------ CLI


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cases", type=Path, default=ROOT / CASES_RELATIVE)
    parser.add_argument("--case-id", default=None)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument(
        "--mode", choices=("off", "auto", "required"), default="auto"
    )
    parser.add_argument(
        "--fake-llm", action="store_true",
        help="script the Specialist/Critic transport; no provider traffic",
    )
    parser.add_argument("--timeout", type=int, default=300)
    parser.add_argument("--provider-url", default=None)
    parser.add_argument("--provider-key", default=None)
    parser.add_argument("--model", default=None)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.timeout < 1:
        raise SystemExit("--timeout must be a positive integer of seconds")
    document = load_case_document(args.cases)
    cases = select_cases(document, args.case_id)
    # Provider resolution happens before any pipeline work so a missing
    # configuration can never degrade into a silent empty report.
    llm_config, provider, model = build_llm_config(args)
    raw_case_data = args.cases.read_bytes()
    records: dict[tuple[str, str], dict[str, Any]] = {}
    for case in cases:
        for revision in REVISIONS:
            records[(case["id"], revision)] = run_revision(
                case,
                revision,
                mode=args.mode,
                fake_llm=bool(args.fake_llm),
                llm_config=llm_config,
                timeout=args.timeout,
            )
    report = run_evaluation(cases, records)
    report = add_report_metadata(
        report,
        raw_case_data,
        mode=args.mode,
        fake_llm=bool(args.fake_llm),
        provider=provider,
        model=model,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    print(VALIDITY_BOUNDARY)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
