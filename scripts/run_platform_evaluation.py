#!/usr/bin/env python3
"""Reproducible unlabeled paired benchmark for the agent vulnerability platform.

Plan Task 10 (design section 11,
``docs/superpowers/specs/2026-09-12-agent-vuln-platform-design.md``).  Every
committed case is a fixed vulnerable/fixed source pair.  The evaluation side
owns the labels: :func:`run_platform_review` only ever receives the fixture
workspace, a canned fact bundle and canned triage leads -- no case id, title,
rationale, license or expected verdict has a path into the pipeline.  The
Sidecar half of the wire is a canned ``/v1/uaf-facts`` bundle per committed
case, the triage half is a canned lead table, and the reproduction half is a
scripted workbench that judges each PoC driver by its content hash (real
Clang extraction and real container ASan are covered by separate acceptance
runs).  ``--fake-llm`` scripts the Scout/Specialist/Critic transport so CI
stays offline.  Real provider traffic happens only when the script runs
without ``--fake-llm`` and a provider is configured; without one the script
refuses before any pipeline work.

Competition metric mapping (design section 11, all recomputable from the
embedded records):

- Detection Rate: vulnerable revisions with an expected positive final
  state that reached exactly that state (accuracy/completeness mapping);
- False Positive Rate: fixed/clean/non-security revisions that produced any
  Finding (the false-positive penalty mapping);
- Non-security Filter Rate: non-security cases (competition note 3) whose
  revisions produced zero Findings -- the hypothesis contract's closed
  memory-pack CWE vocabulary is the filter;
- Experiment Convergence: revisable cases (design section 11's
  hypothesis-experiment-revision sample) hitting within the round budget;
- PoC Stability: executed-hit revisions whose final PoC driver triggered the
  hypothesized bug class in ``runs_per_poc`` repeated executions;
- LLM calls / reply bytes / Latency from the platform stats.
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
from dataclasses import replace
from pathlib import Path, PurePosixPath
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from lima import (  # noqa: E402
    agent_orchestrator,
    agent_scout,
    uaf_llm_branch,
)
from lima.agent_orchestrator import run_platform_review  # noqa: E402
from lima.agent_repro_tools import ExperimentObservation  # noqa: E402
from lima.agent_scout import ScoutLead  # noqa: E402
from lima.cxx_agent_tools import CxxAgentBudget  # noqa: E402
from lima.cxx_memory import (  # noqa: E402
    UafFactsResponse,
    uaf_facts_bundle_sha256,
)
from lima.uaf_orchestrator import (  # noqa: E402
    UAF_FINDING_STATES,
    UAF_POSITIVE_STATES,
)
from lima.vuln_packs import MEMORY_PACK  # noqa: E402
from lima.workspace import RepositoryWorkspace  # noqa: E402

VALIDITY_BOUNDARY = (
    "Synthetic and pinned pairs do not measure production detection capability."
)
REVISIONS = ("vulnerable", "fixed")
CASES_RELATIVE = "evaluation_data/platform_cases/cases.json"
PAIRS_ROOT = ROOT / "tests" / "fixtures" / "platform_cases"
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_CASE_ID = re.compile(r"^[a-z0-9][a-z0-9._-]{2,127}$")
_STANDARD = re.compile(r"^[A-Za-z0-9+#.]{1,32}$")
_CASE_KEYS = frozenset(
    {
        "id",
        "title",
        "vuln_pack",
        "cwe",
        "kind",
        "requires_experiment",
        "non_security",
        "language_standard",
        "expected",
        "vulnerable",
        "fixed",
        "selection_rationale",
        "license",
        "notes",
    }
)
_VERSION_KEYS = frozenset({"kind", "files", "driver_hint"})
_EXPECTED_KEYS = frozenset({"vulnerable", "fixed"})
_REVISION_EXPECTED_KEYS = frozenset({"final_state", "findings"})
_LICENSE_KEYS = frozenset({"spdx", "note"})
_PLATFORM_STATES = frozenset(UAF_FINDING_STATES) | {"abstain", "rejected", "none"}
PLATFORM_POSITIVE_STATES = UAF_POSITIVE_STATES
_CASE_KINDS = frozenset({"direct", "revisable", "clean"})
_VULN_PACKS = frozenset({"memory"})
# The pack's own PoC driver template names plus the neutral generic hint.
_DRIVER_HINTS = frozenset({"generic"}) | frozenset(MEMORY_PACK.driver_templates)
_MAX_TITLE_BYTES = 200
_MAX_RATIONALE_BYTES = 4_096
_MAX_LICENSE_BYTES = 256
_MAX_NOTES_BYTES = 2_048
_MAX_FINDINGS = 64
_MAX_LINE = 10_000_000
_MAX_ELAPSED_SECONDS = 3_600.0
# Competition PoC-stability repetitions and the revisable round budget
# (initial experiment plus at most one Critic-guided revision).
_STABILITY_RUNS = 3
_CONVERGENCE_ROUND_BUDGET = 2
_ROUND_BOUND = 16
# The full platform detection chain whose sources are fingerprinted into
# the report identity (order-stable, mirroring the Task 12 evaluator).
PLATFORM_PIPELINE_COMPONENTS = (
    "agent_scout.py",
    "agent_orchestrator.py",
    "agent_repro_tools.py",
    "agent_scale.py",
    "uaf_llm_branch.py",
    "uaf_models.py",
    "uaf_facts.py",
    "uaf_candidates.py",
    "uaf_proof.py",
    "uaf_broker.py",
    "uaf_orchestrator.py",
    "vuln_packs/__init__.py",
    "vuln_packs/memory.py",
)
FAKE_LLM_CONFIG = {
    "provider": "fake",
    "base_url": "https://fake-platform-llm.invalid/v1",
    "api_key": "",
    "model": "fake-platform-model",
    "headers": {},
}
_REVIEW_BUDGET = CxxAgentBudget(max_calls=64, max_output_bytes=1_048_576)
FAKE_CONTEXT_HASH = "e" * 64


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


def _validate_revision_expected(expected: object, label: str) -> dict[str, Any]:
    fields = _exact_fields(expected, _REVISION_EXPECTED_KEYS, label)
    if fields["final_state"] not in _PLATFORM_STATES:
        raise ValueError(f"{label} final_state is outside the closed domain")
    findings = fields["findings"]
    if isinstance(findings, bool) or type(findings) is not int or not (
        0 <= findings <= _MAX_FINDINGS
    ):
        raise ValueError(f"{label} findings must be a bounded non-negative integer")
    return fields


def _validate_version(version: object, label: str) -> None:
    fields = _exact_fields(version, _VERSION_KEYS, label)
    if fields["kind"] != "source-pair":
        raise ValueError(f"{label} kind must be source-pair")
    if fields["driver_hint"] not in _DRIVER_HINTS:
        raise ValueError(f"{label} driver_hint is outside the closed domain")
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
    if fields["vuln_pack"] not in _VULN_PACKS:
        raise ValueError("case vuln_pack is outside the closed domain")
    allowed_cwes = set(MEMORY_PACK.cwe_ids) | {"none"}
    if fields["cwe"] not in allowed_cwes:
        raise ValueError("case cwe is outside the closed CWE vocabulary")
    if fields["kind"] not in _CASE_KINDS:
        raise ValueError("case kind is outside the closed domain")
    for name in ("requires_experiment", "non_security"):
        if type(fields[name]) is not bool:
            raise ValueError(f"case {name} must be a boolean")
    if not isinstance(fields["language_standard"], str) or not _STANDARD.fullmatch(
        fields["language_standard"]
    ):
        raise ValueError("case language_standard is invalid")
    expected = _exact_fields(fields["expected"], _EXPECTED_KEYS, "case expected")
    vuln_expected = _validate_revision_expected(
        expected["vulnerable"], "vulnerable expected"
    )
    _validate_revision_expected(expected["fixed"], "fixed expected")
    _validate_version(fields["vulnerable"], "vulnerable version")
    _validate_version(fields["fixed"], "fixed version")
    rationale = fields["selection_rationale"]
    if not isinstance(rationale, str) or len(rationale.strip()) < 40:
        raise ValueError("selection rationale is too short")
    if len(rationale.encode("utf-8")) > _MAX_RATIONALE_BYTES:
        raise ValueError("selection rationale exceeds the byte limit")
    _bounded_text(fields["notes"], "case notes", _MAX_NOTES_BYTES)
    license_info = _exact_fields(fields["license"], _LICENSE_KEYS, "license")
    _bounded_text(license_info["spdx"], "license spdx", _MAX_LICENSE_BYTES)
    _bounded_text(license_info["note"], "license note", _MAX_LICENSE_BYTES)
    # Cross rules: a positive expectation demands an executed experiment and
    # a non-clean code shape; clean cases never expect positive states.
    if vuln_expected["final_state"] in PLATFORM_POSITIVE_STATES:
        if not fields["requires_experiment"]:
            raise ValueError(
                "a positive expectation requires requires_experiment=true"
            )
        if fields["kind"] not in {"direct", "revisable"}:
            raise ValueError("a positive expectation requires a vulnerable pair")
    if fields["non_security"] and fields["kind"] != "clean":
        raise ValueError("a non-security case must be a clean-kind case")


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
    kinds: set[str] = set()
    non_security = 0
    runtime_expected = 0
    for case in document["cases"]:
        _validate_case(case)
        if case["id"] in identifiers:
            raise ValueError("case ids must be unique")
        identifiers.add(case["id"])
        kinds.add(case["kind"])
        non_security += int(case["non_security"])
        if case["expected"]["vulnerable"]["final_state"] == "runtime-confirmed":
            runtime_expected += 1
    # Coverage hard rules (design section 11): the manifest must exercise the
    # direct shapes, the revision loop, the false-positive discipline and the
    # non-security filter, and its detection-rate denominator must be live.
    missing = {"direct", "revisable", "clean"} - kinds
    if missing:
        raise ValueError(f"the manifest is missing case kinds: {sorted(missing)}")
    if non_security < 1:
        raise ValueError("the manifest must contain a non-security case")
    if runtime_expected < 1:
        raise ValueError("the manifest must expect at least one runtime hit")


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
    the Task 12 evaluator.
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
    root = Path(tempfile.mkdtemp(prefix="platform-evaluation-"))
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

    return f"platform-evaluation/{revision}"


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
            "context_hash": FAKE_CONTEXT_HASH,
            "diagnostics": [],
        },
        "coverage": {"ast_complete": True, "cfg_complete": True, "semantic_gaps": []},
        "facts": facts,
    }


def _wire_uaf_direct(unit: str, revision: str) -> list[dict[str, Any]]:
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


def _wire_null_deref(unit: str, revision: str) -> list[dict[str, Any]]:
    usr = "c:@F@session_id#"
    use_line = 12 if revision == "vulnerable" else 15
    facts = [
        _fact("allocation", 1, 10, unit=unit, usr=usr, pointer="s", api="malloc"),
        _fact("member-access", 2, use_line, unit=unit, usr=usr, pointer="s"),
    ]
    return [_unit_entry(unit, facts)]


def _wire_overflow(unit: str, revision: str) -> list[dict[str, Any]]:
    usr = "c:@F@frame_write#"
    if revision == "vulnerable":
        allocation_line, write_line, release_line = 4, 6, 8
    else:
        allocation_line, write_line, release_line = 7, 9, 11
    facts = [
        _fact("allocation", 1, allocation_line, unit=unit, usr=usr, pointer="buf",
              api="new[]"),
        _fact("member-access", 2, write_line, unit=unit, usr=usr, pointer="buf"),
        _fact("release", 3, release_line, unit=unit, usr=usr, pointer="buf",
              api="delete[]", related=(1,)),
    ]
    return [_unit_entry(unit, facts)]


def _wire_rebind_revisable(unit: str, revision: str) -> list[dict[str, Any]]:
    usr = "c:@F@cursor_read#"
    if revision == "vulnerable":
        # The conditional rebind is deliberately not certified (honest
        # coverage); the p-object lifetime stays a straight candidate.
        facts = [
            _fact("allocation", 1, 8, unit=unit, usr=usr, pointer="p",
                  api="malloc"),
            _fact("member-access", 2, 9, unit=unit, usr=usr, pointer="p"),
            _fact("release", 3, 10, unit=unit, usr=usr, pointer="p", api="free",
                  related=(1,)),
            _fact("member-access", 4, 18, unit=unit, usr=usr, pointer="p"),
        ]
    else:
        facts = [
            _fact("allocation", 1, 8, unit=unit, usr=usr, pointer="p",
                  api="malloc"),
            _fact("member-access", 2, 9, unit=unit, usr=usr, pointer="p"),
            _fact("member-access", 3, 11, unit=unit, usr=usr, pointer="p"),
            _fact("member-access", 4, 12, unit=unit, usr=usr, pointer="p"),
            _fact("member-access", 5, 14, unit=unit, usr=usr, pointer="p"),
            _fact("release", 6, 15, unit=unit, usr=usr, pointer="p", api="free",
                  related=(1,)),
        ]
    return [_unit_entry(unit, facts)]


def _wire_clean(unit: str, _revision: str) -> list[dict[str, Any]]:
    usr = "c:@F@label_len#"
    facts = [_fact("member-access", 1, 9, unit=unit, usr=usr, pointer="label")]
    return [_unit_entry(unit, facts)]


def _wire_non_security(unit: str, _revision: str) -> list[dict[str, Any]]:
    # A plain functional bug holds no memory facts at all.
    return [_unit_entry(unit, [])]


# Canned sidecar wires per committed case id.  Adding a case to the
# manifest without adding its wire here fails the run before any scoring.
_WIRE_BUILDERS: dict[str, Callable[[str, str], list[dict[str, Any]]]] = {
    "uaf-direct": _wire_uaf_direct,
    "null-deref-direct": _wire_null_deref,
    "overflow-direct": _wire_overflow,
    "rebind-revisable": _wire_rebind_revisable,
    "clean-function": _wire_clean,
    "non-security-filter": _wire_non_security,
}


def build_fake_wire(case_id: str, unit: str, revision: str) -> list[dict[str, Any]]:
    """Build the canned bundle for one case over its pinned TU selection."""

    builder = _WIRE_BUILDERS.get(case_id)
    if builder is None:
        raise ValueError(f"no canned sidecar wire is committed for case {case_id!r}")
    return builder(unit, revision)


# ---------------------------------------------------------- canned triage


def _lead(path: str, line: int, summary: str, seed: str, score: int) -> dict[str, Any]:
    return {
        "lead_id": "lead-001",
        "path": path,
        "line": line,
        "summary": summary,
        "seed": seed,
        "score": score,
    }


def _leads_null_deref(unit: str, revision: str) -> list[dict[str, Any]]:
    if revision != "vulnerable":
        return []
    return [
        _lead(
            unit, 12,
            "pointer s is dereferenced with no guard on the null path",
            "null-deref", 3,
        )
    ]


def _leads_overflow(unit: str, revision: str) -> list[dict[str, Any]]:
    if revision != "vulnerable":
        return []
    return [
        _lead(
            unit, 6,
            "loop writes up to count bytes into the four-byte allocation",
            "heap-overflow", 3,
        )
    ]


def _leads_clean(unit: str, _revision: str) -> list[dict[str, Any]]:
    return [
        _lead(
            unit, 9,
            "pointer label is dereferenced after a conditional check",
            "null-deref", 2,
        )
    ]


def _leads_non_security(unit: str, _revision: str) -> list[dict[str, Any]]:
    return [
        _lead(
            unit, 5,
            "integer arithmetic result feeds the return value unchecked",
            "generic", 1,
        )
    ]


_LEAD_BUILDERS: dict[str, Callable[[str, str], list[dict[str, Any]]]] = {
    "null-deref-direct": _leads_null_deref,
    "overflow-direct": _leads_overflow,
    "clean-function": _leads_clean,
    "non-security-filter": _leads_non_security,
}


def build_fake_leads(case_id: str, unit: str, revision: str) -> list[dict[str, Any]]:
    """The canned triage leads for one case (UAF shapes derive none)."""

    builder = _LEAD_BUILDERS.get(case_id)
    if builder is None:
        return []
    return builder(unit, revision)


def build_leads(case_id: str, unit: str, revision: str) -> tuple[ScoutLead, ...]:
    """Materialize the canned leads as ScoutLead records."""

    return tuple(
        ScoutLead(**spec)
        for spec in build_fake_leads(case_id, unit, revision)
    )


# ------------------------------------------------------- scripted workbench


_DRIVER_UAF = """struct Packet { int size; };
extern int packet_size(void);
int main() {
    return packet_size();
}
"""
_DRIVER_NULL = """struct Session { int id; };
extern int session_id(int has_session);
int main() {
    return session_id(0);
}
"""
_DRIVER_OVERFLOW = """extern int frame_write(int count);
int main() {
    return frame_write(8);
}
"""
# Deliberately wrong first driver: it exercises the safe rebind path.
_DRIVER_REBIND_WRONG = """extern int cursor_read(int take_alt);
int main() {
    return cursor_read(0);
}
"""
# The Critic's corrected driver: it reaches the post-release read.
_DRIVER_REBIND_HIT = """extern int cursor_read(int take_alt);
int main() {
    return cursor_read(1);
}
"""
_DRIVER_CLEAN = """extern int label_len(struct Label *label);
int main() {
    return label_len(0);
}
"""
_DRIVER_NON_SECURITY = """extern int ratio_percent(int part, int whole);
int main() {
    return ratio_percent(25, 200);
}
"""


def _observation(
    error_type: str | None,
    *,
    faulting_line: int | None = None,
    freed_line: int | None = None,
    allocated_line: int | None = None,
    raw_tail: str = "",
) -> ExperimentObservation:
    if error_type is None:
        return ExperimentObservation(
            ok=True, stage="run", exit_code=0, error_type=None,
            faulting_line=None, freed_line=None, allocated_line=None,
            diagnostics=(), raw_tail="",
        )
    # Protocol-possible shape: a parsed ASan report forces ok=False (the
    # binary died under the sanitizer); the faulting file is bound to the
    # audited source by the fake workbench below.
    return ExperimentObservation(
        ok=False, stage="run", exit_code=1, error_type=error_type,
        faulting_line=faulting_line, freed_line=freed_line,
        allocated_line=allocated_line, diagnostics=(), raw_tail=raw_tail,
    )


_Asan_TAIL = (
    "READ of size 4 at 0x60200000eff4 thread T0; freed by thread T0 here; "
    "previously allocated by thread T0 here"
)


def _hitting_observations() -> dict[tuple[str, str], dict[str, ExperimentObservation]]:
    """Canned ASan reports keyed by the triggering driver's content hash.

    The scripted workbench judges a driver by its content hash: the same
    driver always produces the same observation, and only a driver that
    actually reaches the hypothesized fault produces a matching report.
    """

    def keyed(driver: str, observation: ExperimentObservation):
        return {hashlib.sha256(driver.encode("utf-8")).hexdigest(): observation}

    return {
        ("uaf-direct", "vulnerable"): keyed(
            _DRIVER_UAF,
            _observation(
                "heap-use-after-free",
                faulting_line=11, freed_line=10, allocated_line=8,
                raw_tail=_Asan_TAIL,
            ),
        ),
        ("null-deref-direct", "vulnerable"): keyed(
            _DRIVER_NULL,
            _observation(
                "SEGV on unknown address 0x000000000000",
                faulting_line=12,
                raw_tail="SEGV on unknown address 0x000000000000",
            ),
        ),
        ("overflow-direct", "vulnerable"): keyed(
            _DRIVER_OVERFLOW,
            _observation(
                "heap-buffer-overflow WRITE of size 1",
                faulting_line=6, allocated_line=4,
                raw_tail="WRITE of size 1 at 0x602000000ef7 thread T0",
            ),
        ),
        ("rebind-revisable", "vulnerable"): keyed(
            _DRIVER_REBIND_HIT,
            _observation(
                "heap-use-after-free",
                faulting_line=18, freed_line=10, allocated_line=8,
                raw_tail=_Asan_TAIL,
            ),
        ),
    }


_HITTING_OBSERVATIONS = _hitting_observations()


class FakePlatformWorkbench:
    """Offline ``run_experiment`` double keyed by driver content hash.

    Mirrors the real workbench boundary: the observation depends on the
    driver (and the already-fixed snapshot), never on the caller identity,
    and a driver that misses the fault runs clean.
    """

    def __init__(self, case_id: str, revision: str):
        self.calls: list[tuple[str, str, tuple[str, ...], str]] = []
        self._hitting = _HITTING_OBSERVATIONS.get((case_id, revision), {})

    def run_experiment(
        self, repository_key: str, snapshot_hash: str, source_files, driver_code: str,
    ) -> ExperimentObservation:
        self.calls.append(
            (repository_key, snapshot_hash, tuple(source_files), driver_code)
        )
        key = hashlib.sha256(driver_code.encode("utf-8")).hexdigest()
        observation = self._hitting.get(key)
        if observation is None:
            return _observation(None)
        # A driver that reaches the fault crashes inside the audited
        # source file, mirroring the real Sidecar's target-bound ASan
        # frames; the crash never lands in the staged driver itself.
        sources = tuple(source_files)
        if observation.error_type is not None and sources:
            return replace(observation, faulting_file=sources[0])
        return observation


# ------------------------------------------------------------- fake sidecar


class FakePlatformSidecar:
    """Offline stand-in for the strict ``/v1/uaf-facts`` client boundary.

    Serves one canned bundle and echoes the caller identity exactly like
    the real Sidecar; ``run_platform_review`` cannot distinguish it from
    ``CxxMemoryAnalyzerClient`` by the response shape alone.
    """

    def __init__(self, units: list[dict[str, Any]], *, run_id: str = "run-platform-eval"):
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
            request_id="req-platform-evaluation",
            repository_key=repository_key,
            snapshot_sha256=snapshot_sha256,
            tool_runs=(
                {"run_id": self.run_id, "tool": "uaf-facts", "status": "completed"},
            ),
            translation_units=tuple(self.units),
            bundle_sha256=uaf_facts_bundle_sha256(self.units),
            diagnostics=(),
        )


# ----------------------------------------------------------- fake transports


def new_counter() -> dict[str, int]:
    return {
        "scout_calls": 0,
        "scout_bytes": 0,
        "llm_calls": 0,
        "llm_bytes": 0,
    }


def scripted_scout_transport(counter: dict[str, int]) -> Callable[..., str]:
    """The scripted Scout: escalate every reviewed lead as a target."""

    def transport(
        provider, base_url, api_key, payload, timeout,
        extra_headers=None, max_bytes=None,
    ):
        del provider, base_url, api_key, timeout, extra_headers, max_bytes
        counter["scout_calls"] += 1
        user = payload["messages"][1]["content"]
        lead_id = next(
            line.split(": ", 1)[1]
            for line in user.splitlines()
            if line.startswith("- lead_id: ")
        )
        reply = json.dumps(
            [
                {
                    "lead_id": lead_id,
                    "verdict": "target",
                    "reason": "suspicious location worth an experiment",
                    "confidence": "high",
                }
            ]
        )
        counter["scout_bytes"] += len(reply.encode("utf-8"))
        return reply

    return transport


_SPECIALIST_SCRIPTS: dict[str, dict[str, Any]] = {
    "uaf-direct": {
        "cwe": "CWE-416",
        "hypothesis": "the packet object is read after delete on the return path",
        "trigger_path": ("delete p", "return p->size"),
        "driver_code": _DRIVER_UAF,
        "experiment_design": (
            "compile the target with the driver and run it under AddressSanitizer"
        ),
        "unresolved_assumptions": (),
    },
    "null-deref-direct": {
        "cwe": "CWE-476",
        "hypothesis": "the session pointer is dereferenced without a null guard",
        "trigger_path": ("fallback stays null", "return s->id"),
        "driver_code": _DRIVER_NULL,
        "experiment_design": (
            "compile the target with the driver and run it under AddressSanitizer"
        ),
        "unresolved_assumptions": (),
    },
    "overflow-direct": {
        "cwe": "CWE-787",
        "hypothesis": "the loop writes up to count bytes into a four-byte buffer",
        "trigger_path": ("new char[4]", "buf[i]"),
        "driver_code": _DRIVER_OVERFLOW,
        "experiment_design": (
            "compile the target with the driver and run it under AddressSanitizer"
        ),
        "unresolved_assumptions": (),
    },
    "rebind-revisable": {
        "cwe": "CWE-416",
        "hypothesis": "the cursor object is read after free on the alternate path",
        "trigger_path": ("free(p)", "return p->pos"),
        "driver_code": _DRIVER_REBIND_WRONG,
        "experiment_design": (
            "compile the target with the driver and run it under AddressSanitizer"
        ),
        "unresolved_assumptions": (),
    },
    "clean-function": {
        "cwe": "CWE-476",
        "hypothesis": "the label pointer may be null at the member access",
        "trigger_path": ("if (label == 0)", "return label->len"),
        "driver_code": _DRIVER_CLEAN,
        "experiment_design": (
            "compile the target with the driver and run it under AddressSanitizer"
        ),
        "unresolved_assumptions": (),
    },
    # Competition note 3 sample: a plain functional bug.  The proposed CWE
    # sits outside the memory pack's closed vocabulary, so the hypothesis
    # contract must reject the reply (one repair, then an audited abstain).
    "non-security-filter": {
        "cwe": "CWE-703",
        "hypothesis": "ratio_percent multiplies by the wrong scale factor",
        "trigger_path": ("return part * whole / 100",),
        "driver_code": _DRIVER_NON_SECURITY,
        "experiment_design": "compare the return value against the expected ratio",
        "unresolved_assumptions": (),
    },
}

_CRITIC_SCRIPTS: dict[str, dict[str, Any]] = {
    "rebind-revisable": {
        "assessment": "revise-experiment",
        "rationale": (
            "the driver exercised the rebind path; drive the alternate path "
            "to reach the post-release read"
        ),
        "revised_driver_code": _DRIVER_REBIND_HIT,
    },
    "clean-function": {
        "assessment": "hypothesis-wrong",
        "rationale": (
            "the null guard returns before the member access, so the "
            "hypothesized fault is unreachable"
        ),
        "revised_driver_code": "",
    },
}
_DEFAULT_CRITIC: dict[str, Any] = {
    "assessment": "supports-hypothesis",
    "rationale": "no guard, rebind or lifetime restart survives the evidence",
    "revised_driver_code": "",
}


def _target_id_from(payload: dict[str, Any]) -> str:
    for line in payload["messages"][1]["content"].splitlines():
        if line.startswith("- target_id: "):
            return line.split(": ", 1)[1]
    return ""


def scripted_platform_transport(
    case_id: str, counter: dict[str, int]
) -> Callable[..., str]:
    """The scripted Specialist/Critic transport for one committed case."""

    if case_id not in _SPECIALIST_SCRIPTS:
        raise ValueError(f"no scripted semantic transport for case {case_id!r}")
    specialist = _SPECIALIST_SCRIPTS[case_id]
    critic = _CRITIC_SCRIPTS.get(case_id, _DEFAULT_CRITIC)

    def transport(
        provider, base_url, api_key, payload, timeout,
        extra_headers=None, max_bytes=None,
    ):
        del provider, base_url, api_key, timeout, extra_headers, max_bytes
        system = payload["messages"][0]["content"]
        counter["llm_calls"] += 1
        if uaf_llm_branch.SPECIALIST_ROLE in system:
            reply = json.dumps(
                {
                    "target_id": _target_id_from(payload),
                    "hypothesis": specialist["hypothesis"],
                    "trigger_path": list(specialist["trigger_path"]),
                    "cwe": specialist["cwe"],
                    "driver_code": specialist["driver_code"],
                    "experiment_design": specialist["experiment_design"],
                    "unresolved_assumptions": list(
                        specialist["unresolved_assumptions"]
                    ),
                }
            )
        elif uaf_llm_branch.CRITIC_ROLE in system:
            reply = json.dumps(
                {
                    "target_id": _target_id_from(payload),
                    "assessment": critic["assessment"],
                    "rationale": critic["rationale"],
                    "revised_driver_code": critic["revised_driver_code"],
                }
            )
        else:
            raise AssertionError("platform transport saw an unknown role")
        counter["llm_bytes"] += len(reply.encode("utf-8"))
        return reply

    return transport


# ------------------------------------------------------------------- runner


def _experiment_hit(observation: Any, cwe: str, *, target_path: str = "") -> bool:
    """Evaluation-side mirror of the platform's runtime-hit predicate.

    Delegates to the production predicate so the mirror can never drift
    from the platform contract (run-stage ASan report of the hypothesized
    class, faulting frame bound to the audited target file).
    """

    return agent_orchestrator._experiment_hit(
        observation, cwe, target_path=target_path,
    )


def _driver_digest(driver_code: str) -> str:
    if not driver_code:
        return ""
    return hashlib.sha256(driver_code.encode("utf-8")).hexdigest()


def run_revision(
    case: dict[str, Any],
    revision: str,
    *,
    mode: str = "auto",
    fake_llm: bool = True,
    llm_config: dict[str, Any] | None = None,
    timeout: int = 60,
    dialogue_rounds: int = 1,
) -> dict[str, Any]:
    """Run the real review chain over one pinned revision, offline or not.

    The pipeline receives only the fixture workspace, the served fact
    bundle and the canned triage leads; every label stays on the
    evaluation side and is applied later by :func:`run_evaluation`.  With
    ``fake_llm`` the Scout/Specialist/Critic transport is the scripted
    honest model and no provider is needed.  The canned Sidecar and the
    hash-keyed scripted workbench stay in place in both modes: real Clang
    extraction and real container ASan are separate acceptance runs.
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
        served_units = build_fake_wire(case_id, units[0], revision)
        analyzer = FakePlatformSidecar(served_units)
        leads = build_leads(case_id, units[0], revision)
        workbench = FakePlatformWorkbench(case_id, revision)
        counter = new_counter()
        started = time.monotonic()
        if fake_llm:
            scout_transport = scripted_scout_transport(counter)
            platform_transport = scripted_platform_transport(case_id, counter)
            with unittest.mock.patch.object(
                agent_scout, "post_chat_completion_text", scout_transport
            ), unittest.mock.patch.object(
                uaf_llm_branch, "post_chat_completion_text", platform_transport
            ):
                outcome = run_platform_review(
                    analyzer,
                    workspace,
                    repository_key=evaluation_repository_key(revision),
                    snapshot_hash=snapshot,
                    translation_units=units,
                    mode=mode,
                    budget=_REVIEW_BUDGET,
                    llm_config=dict(
                        llm_config if llm_config is not None else FAKE_LLM_CONFIG
                    ),
                    repro_workbench=workbench,
                    leads=leads,
                    dialogue_rounds=dialogue_rounds,
                    timeout=timeout,
                )
        else:
            outcome = run_platform_review(
                analyzer,
                workspace,
                repository_key=evaluation_repository_key(revision),
                snapshot_hash=snapshot,
                translation_units=units,
                mode=mode,
                budget=_REVIEW_BUDGET,
                llm_config=dict(llm_config or {}),
                repro_workbench=workbench,
                leads=leads,
                dialogue_rounds=dialogue_rounds,
                timeout=timeout,
            )
        elapsed = time.monotonic() - started
        record = _record_from_outcome(
            case_id, revision, len(leads), served_units, outcome, counter, elapsed
        )
        record["poc_stability"] = _poc_stability_probe(
            case_id, revision, outcome, workbench_class=FakePlatformWorkbench
        )
        return record


def _record_from_outcome(
    case_id: str,
    revision: str,
    lead_count: int,
    served_units: list[dict[str, Any]],
    outcome: Any,
    counter: dict[str, int],
    elapsed: float,
) -> dict[str, Any]:
    targets = []
    for item in outcome.targets:
        targets.append(
            {
                "target_id": item.target_id,
                "path": item.path,
                "line": item.line,
                "cwe": item.cwe,
                "state": item.state,
                "finding": item.state in UAF_FINDING_STATES,
                "proof_verdict": item.proof_verdict,
                "rejected_reason": item.rejected_reason[:2_000],
                "experiment_log": [
                    {
                        "round": entry["round"],
                        "stage": entry["stage"],
                        "hit": entry["hit"],
                        "error_type": entry["error_type"] or "",
                    }
                    for entry in item.experiment_log
                ],
                "driver_sha256": _driver_digest(item.poc_driver_code),
            }
        )
    return {
        "case_id": case_id,
        "revision": revision,
        "counted": True,
        "build_context_source": str(
            served_units[0]["build_context"]["source_kind"]
        ) if served_units else "",
        "translation_units": [
            unit["translation_unit"] for unit in served_units
        ],
        "coverage_gaps": sorted(
            {
                gap
                for unit in served_units
                for gap in unit["coverage"]["semantic_gaps"]
            }
        ),
        "leads": lead_count,
        "targets": targets,
        "finding_count": int(outcome.stats.finding_count),
        "experiment_count": int(outcome.stats.experiment_count),
        "poc_stability": None,
        "llm": {
            "scout_calls": int(outcome.stats.scout_calls),
            "specialist_calls": int(outcome.stats.specialist_calls),
            "critic_calls": int(outcome.stats.critic_calls),
            "reply_bytes": int(counter["scout_bytes"] + counter["llm_bytes"]),
        },
        "elapsed_seconds": float(elapsed),
        "diagnostics": [str(item) for item in outcome.diagnostics][:64],
    }


def _poc_stability_probe(case_id: str, revision: str, outcome: Any, *,
                         workbench_class=FakePlatformWorkbench) -> dict[str, Any] | None:
    """Re-run the winning PoC driver ``_STABILITY_RUNS`` times.

    The competition PoC-stability mapping: the driver that produced the
    executed hit must trigger the hypothesized bug class on every repeat.
    Under the scripted workbench the hash rule is deterministic, so the
    probe is stable by construction; under a real workbench it measures
    exactly what the competition asks for.
    """

    driver = ""
    cwe = ""
    target_path = ""
    for item in outcome.targets:
        if any(entry["hit"] for entry in item.experiment_log) and item.poc_driver_code:
            driver = item.poc_driver_code
            cwe = item.cwe
            target_path = item.path
            break
    if not driver:
        return None
    workbench = workbench_class(case_id, revision)
    hits = 0
    for _ in range(_STABILITY_RUNS):
        observation = workbench.run_experiment("", "", (target_path,), driver)
        hits += int(_experiment_hit(observation, cwe, target_path=target_path))
    return {"runs": _STABILITY_RUNS, "hits": hits, "stable": hits == _STABILITY_RUNS}


# ------------------------------------------------------------------- scoring


_RECORD_KEYS = frozenset(
    {
        "case_id",
        "revision",
        "counted",
        "build_context_source",
        "translation_units",
        "coverage_gaps",
        "leads",
        "targets",
        "finding_count",
        "experiment_count",
        "poc_stability",
        "llm",
        "elapsed_seconds",
        "diagnostics",
    }
)
_TARGET_KEYS = frozenset(
    {
        "target_id",
        "path",
        "line",
        "cwe",
        "state",
        "finding",
        "proof_verdict",
        "rejected_reason",
        "experiment_log",
        "driver_sha256",
    }
)
_LOG_KEYS = frozenset({"round", "stage", "hit", "error_type"})
_LLM_KEYS = frozenset(
    {"scout_calls", "specialist_calls", "critic_calls", "reply_bytes"}
)
_MAX_USAGE_VALUE = 1_000_000_000
_PROOF_VERDICTS = frozenset({"PASS", "REFUTED", "UNKNOWN", ""})


def _bounded_int(value: Any, label: str, low: int, high: int) -> int:
    if isinstance(value, bool) or type(value) is not int or not low <= value <= high:
        raise ValueError(f"{label} must be an integer in [{low}, {high}]")
    return value


def validate_record(raw: object) -> dict[str, Any]:
    """Validate one pipeline record; the shape is part of the contract."""

    record = _exact_fields(raw, _RECORD_KEYS, "pipeline record")
    if type(record["counted"]) is not bool:
        raise ValueError("record counted must be a boolean")
    _bounded_text(record["case_id"], "record case_id", 128)
    if record["revision"] not in REVISIONS:
        raise ValueError("record revision is outside the closed domain")
    _bounded_int(record["leads"], "record leads", 0, 1_000)
    _bounded_int(record["finding_count"], "record finding_count", 0, _MAX_FINDINGS)
    _bounded_int(
        record["experiment_count"], "record experiment_count", 0, 1_000
    )
    targets = record["targets"]
    if type(targets) is not list or len(targets) > 1_000:
        raise ValueError("record targets must be a bounded array")
    executed_hit = False
    for target in targets:
        fields = _exact_fields(target, _TARGET_KEYS, "target record")
        _bounded_text(fields["target_id"], "target_id", 300)
        _bounded_text(fields["path"], "target path", 4_096)
        _bounded_int(fields["line"], "target line", 1, _MAX_LINE)
        # ``cwe`` may be empty: audited abstentions carry no hypothesis.
        if not isinstance(fields["cwe"], str) or len(fields["cwe"]) > 32:
            raise ValueError("target cwe must be bounded text")
        if fields["state"] not in _PLATFORM_STATES:
            raise ValueError("target state is outside the closed domain")
        if type(fields["finding"]) is not bool:
            raise ValueError("target finding must be a boolean")
        if fields["finding"] != (fields["state"] in UAF_FINDING_STATES):
            raise ValueError("target finding must match the finding-state set")
        if fields["proof_verdict"] not in _PROOF_VERDICTS:
            raise ValueError("target proof_verdict is outside the closed domain")
        if not isinstance(fields["rejected_reason"], str):
            raise ValueError("target rejected_reason must be text")
        digest = fields["driver_sha256"]
        if not isinstance(digest, str) or (
            digest != "" and not _HEX64.fullmatch(digest)
        ):
            raise ValueError("target driver_sha256 must be empty or a hex digest")
        log = fields["experiment_log"]
        if type(log) is not list or len(log) > _ROUND_BOUND:
            raise ValueError("target experiment_log must be a bounded array")
        for entry in log:
            item = _exact_fields(entry, _LOG_KEYS, "experiment entry")
            _bounded_int(item["round"], "experiment round", 1, _ROUND_BOUND)
            _bounded_text(item["stage"], "experiment stage", 32)
            if type(item["hit"]) is not bool:
                raise ValueError("experiment hit must be a boolean")
            if not isinstance(item["error_type"], str):
                raise ValueError("experiment error_type must be text")
            executed_hit = executed_hit or item["hit"]
    stability = record["poc_stability"]
    if stability is not None:
        item = _exact_fields(stability, {"runs", "hits", "stable"}, "poc stability")
        _bounded_int(item["runs"], "stability runs", 1, _ROUND_BOUND)
        _bounded_int(item["hits"], "stability hits", 0, item["runs"])
        if type(item["stable"]) is not bool:
            raise ValueError("stability stable must be a boolean")
        if item["stable"] != (item["hits"] == item["runs"]):
            raise ValueError("stability stable must match hits == runs")
    if executed_hit and stability is None:
        raise ValueError("an executed hit requires a poc_stability probe")
    llm = _exact_fields(record["llm"], _LLM_KEYS, "record llm usage")
    for name, value in llm.items():
        _bounded_int(value, f"llm usage {name}", 0, _MAX_USAGE_VALUE)
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
    states = [target["state"] for target in record["targets"]]
    if not states:
        return "none"
    return states[0] if len(set(states)) == 1 else "mixed"


def _first_hit_round(record: dict[str, Any]) -> int | None:
    rounds = [
        entry["round"]
        for target in record["targets"]
        for entry in target["experiment_log"]
        if entry["hit"]
    ]
    return min(rounds) if rounds else None


def _safe_ratio(
    numerator: float, denominator: float, label: str, diagnostics: list[str]
) -> Any:
    if denominator == 0:
        diagnostics.append(f"{label} denominator is zero")
        return None
    return numerator / denominator


def run_evaluation(
    cases: list[dict[str, Any]],
    records: dict[tuple[str, str], dict[str, Any]],
) -> dict[str, Any]:
    """Score the fixed pairs; labels never enter the records themselves.

    Every revision record stays visible; counted revisions feed the
    competition-mapped rates, and any zero denominator yields JSON ``null``
    plus a diagnostic instead of a fabricated zero.
    """

    diagnostics: list[str] = []
    case_results: list[dict[str, Any]] = []
    revision_count = counted_revisions = 0
    detection_total = detection_hits = 0
    fp_total = fp_count = 0
    pair_total = pair_correct = 0
    stability_total = stability_stable = 0
    convergence_total = convergence_hits = 0
    nonsec_total = nonsec_filtered = 0
    scout_total = specialist_total = critic_total = bytes_total = 0
    latency_total = 0.0

    for case in cases:
        revisions_result: dict[str, Any] = {}
        counted_pair = True
        correct_pair = True
        for revision in REVISIONS:
            record = validate_record(records[(case["id"], revision)])
            revision_count += 1
            expected = case["expected"][revision]
            observed = _observed_state(record)
            positive = expected["final_state"] in PLATFORM_POSITIVE_STATES
            state_exact = observed == expected["final_state"]
            if record["counted"]:
                counted_revisions += 1
                if revision == "vulnerable" and positive:
                    detection_total += 1
                    detection_hits += int(state_exact)
                if not positive:
                    fp_total += 1
                    fp_count += int(record["finding_count"] > 0)
                latency_total += float(record["elapsed_seconds"])
                scout_total += record["llm"]["scout_calls"]
                specialist_total += record["llm"]["specialist_calls"]
                critic_total += record["llm"]["critic_calls"]
                bytes_total += record["llm"]["reply_bytes"]
            else:
                counted_pair = False
                diagnostics.append(
                    f"pair scoring for {case['id']} skips the degraded "
                    f"{revision} revision"
                )
            correct_pair = correct_pair and state_exact
            revisions_result[revision] = {
                "counted": record["counted"],
                "expected_final_state": expected["final_state"],
                "expected_findings": expected["findings"],
                "observed_final_state": observed,
                "observed_states": [
                    target["state"] for target in record["targets"]
                ],
                "state_exact": state_exact,
                "finding_count": record["finding_count"],
                "first_hit_round": _first_hit_round(record),
                "llm": dict(record["llm"]),
                "elapsed_seconds": float(record["elapsed_seconds"]),
                "diagnostics": record["diagnostics"],
            }
        if counted_pair:
            pair_total += 1
            pair_correct += int(correct_pair)
            case_results.append(
                {
                    "case_id": case["id"],
                    "kind": case["kind"],
                    "non_security": case["non_security"],
                    "revisions": revisions_result,
                    "pair_correct": bool(correct_pair),
                }
            )
        else:
            case_results.append(
                {
                    "case_id": case["id"],
                    "kind": case["kind"],
                    "non_security": case["non_security"],
                    "revisions": revisions_result,
                    "pair_correct": None,
                }
            )

    # Competition-note-3 filter and the experiment-loop metrics, sliced
    # from the same validated records.
    for case in cases:
        if case["non_security"]:
            nonsec_total += 1
            nonsec_filtered += int(
                all(
                    records[(case["id"], revision)]["finding_count"] == 0
                    for revision in REVISIONS
                )
            )
        if case["kind"] == "revisable":
            convergence_total += 1
            hit_round = _first_hit_round(records[(case["id"], "vulnerable")])
            convergence_hits += int(
                hit_round is not None
                and hit_round <= _CONVERGENCE_ROUND_BUDGET
            )
        for revision in REVISIONS:
            record = records[(case["id"], revision)]
            if _first_hit_round(record) is not None:
                stability_total += 1
                stability_entry = record["poc_stability"]
                stability_stable += int(
                    bool(stability_entry and stability_entry["stable"])
                )

    return {
        "schema_version": 1,
        "case_count": len(cases),
        "revision_count": revision_count,
        "counted_revision_count": counted_revisions,
        "detection_rate": {
            "rate": _safe_ratio(
                detection_hits, detection_total, "detection_rate", diagnostics
            ),
            "detected": detection_hits,
            "total": detection_total,
            "definition": (
                "vulnerable revisions with an expected positive final state "
                "that reached exactly that state (accuracy/completeness mapping)"
            ),
        },
        "false_positive_rate": {
            "rate": _safe_ratio(
                fp_count, fp_total, "false_positive_rate", diagnostics
            ),
            "false_positives": fp_count,
            "total": fp_total,
            "definition": (
                "non-positive expected revisions (fixed/clean/non-security "
                "sides) that produced any Finding -- the false-positive "
                "penalty mapping"
            ),
        },
        "non_security_filter_rate": {
            "rate": _safe_ratio(
                nonsec_filtered, nonsec_total, "non_security_filter_rate",
                diagnostics,
            ),
            "filtered": nonsec_filtered,
            "total": nonsec_total,
            "definition": (
                "non-security cases (competition note 3) whose revisions all "
                "produced zero Findings; the hypothesis contract's closed "
                "memory-pack CWE vocabulary is the filter"
            ),
        },
        "experiment_convergence": {
            "rate": _safe_ratio(
                convergence_hits, convergence_total, "experiment_convergence",
                diagnostics,
            ),
            "converged": convergence_hits,
            "total": convergence_total,
            "round_budget": _CONVERGENCE_ROUND_BUDGET,
            "definition": (
                "revisable cases (design section 11 revision-loop sample) "
                "whose vulnerable side recorded an executed hit within the "
                "round budget"
            ),
        },
        "poc_stability": {
            "rate": _safe_ratio(
                stability_stable, stability_total, "poc_stability", diagnostics
            ),
            "stable": stability_stable,
            "total": stability_total,
            "runs_per_poc": _STABILITY_RUNS,
            "definition": (
                "executed-hit revisions whose final PoC driver triggered the "
                "hypothesized bug class in runs_per_poc repeated executions "
                "(competition PoC-stability mapping)"
            ),
        },
        "paired_detection": {
            "rate": _safe_ratio(
                pair_correct, pair_total, "paired_detection", diagnostics
            ),
            "correct": pair_correct,
            "total": pair_total,
            "definition": (
                "pairs where both revisions finished in their expected state"
            ),
        },
        "llm_usage": {
            "scout_calls_total": scout_total,
            "specialist_calls_total": specialist_total,
            "critic_calls_total": critic_total,
            "reply_bytes_total": bytes_total,
            "reply_bytes_mean": _safe_ratio(
                bytes_total, revision_count, "reply_bytes_mean", diagnostics
            ),
            "accounting": (
                "agent wire calls charged by the pipeline; reply size in "
                "bytes as the transport-level proxy (no provider token "
                "accounting)"
            ),
        },
        "latency_seconds": {
            "total": latency_total,
            "mean": _safe_ratio(
                latency_total, revision_count, "latency_mean", diagnostics
            ),
        },
        "cases": case_results,
        "records": [
            records[(case["id"], revision)]
            for case in cases
            for revision in REVISIONS
        ],
        "diagnostics": diagnostics,
    }


# ------------------------------------------------------------------ identity


def _canonical_source_bytes(payload: bytes) -> bytes:
    return payload.replace(b"\r\n", b"\n").replace(b"\r", b"\n")


def platform_pipeline_fingerprint() -> str:
    digest = hashlib.sha256()
    package_root = ROOT / "lima"
    for name in PLATFORM_PIPELINE_COMPONENTS:
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
        "platform_pipeline_sha256": platform_pipeline_fingerprint(),
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
        "bundle and the canned triage leads only; labels are applied "
        "outside the pipeline.",
        "The Sidecar half is a canned /v1/uaf-facts bundle and the "
        "reproduction half is a hash-keyed scripted workbench per committed "
        "case; real Clang extraction and real container ASan runs are "
        "verified separately and recorded as unverified in "
        "docs/COMPETITION_VALIDATION.md until they happen.",
        "A null metric means its denominator was zero, not a perfect score.",
        "The PoC-stability probe under the scripted workbench is stable by "
        "construction; it carries information only in real workbench runs.",
        "The reply-byte LLM proxy is not provider token accounting.",
    ]
    return result


# ------------------------------------------------------------------ provider


class ProviderNotConfigured(RuntimeError):
    """A real (non-fake) run started without a usable provider config."""


def build_llm_config(
    args: argparse.Namespace, env: dict[str, str] | None = None
) -> tuple[dict[str, Any], str, str]:
    """Resolve the agent transport provider, preferring explicit arguments.

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
            "provider-not-configured: the platform evaluation needs a real "
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
        help="script the Scout/Specialist/Critic transport; no provider traffic",
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
