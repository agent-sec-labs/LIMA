#!/usr/bin/env python3
"""Reproducible unlabeled evaluation of the C/C++ LLM agent pipeline.

Every committed case is a fixed vulnerable/fixed pair. The evaluation side
owns the labels: the pipeline under test only ever receives the fixture
workspace, never the case document, expected identities, or ground truth.
Real provider traffic happens only when this script runs; the committed
tests inject a fake client and stay offline.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import re
import sys
import time
from collections.abc import Callable, Mapping
from pathlib import Path, PurePosixPath
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from lima.cxx_agent_models import (  # noqa: E402
    CXX_AGENT_VERIFICATION_STATES,
    SUPPORTED_CWES,
    VERIFIED_STATES,
)
from lima.cxx_agents import ROLE_ORDER  # noqa: E402
from lima.cxx_llm import _STEP_SCHEMA, _UNTRUSTED_DATA_RULE, CxxLLMClient  # noqa: E402
from lima.real_world_evaluation import analyzer_fingerprint  # noqa: E402
from lima.repository_scanner import RepositoryScanner  # noqa: E402
from lima.service import CXX_AGENT_PROMPT_TEMPLATE  # noqa: E402
from lima.workspace import RepositoryWorkspace  # noqa: E402

VALIDITY_BOUNDARY = (
    "Synthetic and pinned pairs do not measure production detection capability."
)
CXX_AGENT_PIPELINE_COMPONENTS = (
    "cxx_agent_models.py",
    "cxx_agent_tools.py",
    "cxx_agents.py",
    "cxx_llm.py",
    "cxx_context.py",
    "cxx_retrieval.py",
    "repository_scanner.py",
    "workspace.py",
)
REVISIONS = ("vulnerable", "fixed")
_HEX40 = re.compile(r"^[0-9a-f]{40}$")
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_CASE_ID = re.compile(r"^[a-z0-9][a-z0-9._-]{2,127}$")
_ID_PATTERN_TEXT = r"[a-z0-9][a-z0-9._-]{2,127}"
_SYNTHETIC_CASE_KEYS = frozenset(
    {"id", "title", "cwe", "origin", "affected", "versions", "selection_rationale", "license"}
)
_REPOSITORY_CASE_KEYS = frozenset(
    {
        "id",
        "title",
        "cwe",
        "origin",
        "project",
        "commits",
        "archives",
        "affected",
        "selection_rationale",
        "license",
    }
)
_VERSION_KEYS = {
    "local": frozenset({"kind", "source_dir", "content_sha256"}),
}
_ARCHIVE_KEYS = frozenset({"url", "sha256"})
_AFFECTED_KEYS = frozenset({"path", "symbol"})
_LICENSE_KEYS = frozenset({"spdx", "note"})
_ORIGINS = frozenset({"synthetic", "repository"})
_LOCAL_SOURCE_PREFIX = "tests/fixtures/"
_MAX_TITLE_BYTES = 200
_MAX_LICENSE_BYTES = 256
_MAX_FINDINGS = 10_000
_MAX_FINDING_BYTES = 4_096
_MAX_LINE = 10_000_000
_MAX_USAGE_VALUE = 1_000_000_000
_MAX_COLLABORATION_BYTES = 1_000_000
_MAX_ELAPSED_SECONDS = 86_400.0
# Closed domain of ``collaboration.cxx_agent`` statuses emitted by
# ``RepositoryScanner._run_cxx_agent_branch``.
_PIPELINE_STATUSES = frozenset(
    {"completed", "llm-unavailable", "llm-not-configured", "no-cxx-sources", "cancelled"}
)
_PIPELINE_RESULT_KEYS = frozenset(
    {
        "status",
        "collaboration",
        "agent_findings",
        "snapshot_sha256",
        "usage",
        "elapsed_seconds",
    }
)
_FINDING_KEYS = frozenset(
    {"cwe", "path", "symbol", "line", "verification_state", "automatic_repair"}
)
_USAGE_KEYS = frozenset({"calls", "context_files", "context_lines", "output_bytes"})
_DEFAULT_BASE_URLS = {
    "deepseek": "https://api.deepseek.com",
    "openrouter": "https://openrouter.ai/api/v1",
    "openrouter-free": "https://openrouter.ai/api/v1",
    "openrouter-deepseek-free": "https://openrouter.ai/api/v1",
}
_PROVIDER_KEY_ENVIRONMENTS = {
    "deepseek": "LIMA_DEEPSEEK_API_KEY",
    "openrouter": "LIMA_OPENROUTER_API_KEY",
    "openrouter-free": "LIMA_OPENROUTER_API_KEY",
    "openrouter-deepseek-free": "LIMA_OPENROUTER_API_KEY",
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


def _exact_fields(payload: Any, expected: frozenset[str] | set[str], label: str) -> dict[str, Any]:
    if type(payload) is not dict or set(payload) != set(expected):
        raise ValueError(f"{label} fields do not match the schema")
    return payload


def _validate_local_version(version: object, label: str) -> None:
    if not isinstance(version, dict):
        raise ValueError(f"{label} version must be an object")
    fields = _exact_fields(version, _VERSION_KEYS["local"], f"{label} version")
    if fields["kind"] != "local":
        raise ValueError(f"{label} version kind must be local")
    source_dir = _safe_relative_path(fields["source_dir"], f"{label} source_dir")
    if not source_dir.startswith(_LOCAL_SOURCE_PREFIX):
        raise ValueError(f"{label} source_dir must stay under {_LOCAL_SOURCE_PREFIX}")
    if not isinstance(fields["content_sha256"], str) or not _HEX64.fullmatch(
        fields["content_sha256"]
    ):
        raise ValueError(f"{label} content_sha256 must be a lowercase SHA-256 digest")


def _validate_archive_pair(project: str, commits: Mapping[str, str], archives: object) -> None:
    """Pin the future repository form: HTTPS archives bound to exact commits."""

    fields = _exact_fields(archives, set(REVISIONS), "archives")
    for revision in REVISIONS:
        archive = _exact_fields(fields[revision], _ARCHIVE_KEYS, f"{revision} archive")
        url = archive["url"]
        digest = archive["sha256"]
        if not isinstance(url, str) or not url.startswith("https://"):
            raise ValueError(f"{revision} archive URL must be HTTPS")
        if not isinstance(digest, str) or not _HEX64.fullmatch(digest):
            raise ValueError(f"{revision} archive sha256 must be a lowercase SHA-256 digest")
        expected_path = f"/{project}/tar.gz/{commits[revision]}"
        if not url.split("?", 1)[0].rstrip("/").endswith(expected_path):
            raise ValueError(f"{revision} archive URL must contain its exact commit")


def _validate_case(case: object) -> None:
    if not isinstance(case, dict) or "origin" not in case:
        raise ValueError("case fields do not match the schema")
    origin = case["origin"]
    if origin == "synthetic":
        fields = _exact_fields(case, _SYNTHETIC_CASE_KEYS, "synthetic case")
    elif origin == "repository":
        fields = _exact_fields(case, _REPOSITORY_CASE_KEYS, "repository case")
    else:
        raise ValueError("case origin must be synthetic or repository")

    case_id = fields["id"]
    if not isinstance(case_id, str) or not _CASE_ID.fullmatch(case_id):
        raise ValueError("case id is invalid")
    _bounded_text(fields["title"], "case title", _MAX_TITLE_BYTES)
    if fields["cwe"] not in SUPPORTED_CWES:
        raise ValueError("case CWE is unsupported")

    affected = _exact_fields(fields["affected"], _AFFECTED_KEYS, "affected identity")
    _safe_relative_path(affected["path"], "affected path")
    _bounded_text(affected["symbol"], "affected symbol", _MAX_FINDING_BYTES)

    commits: dict[str, str] | None = None
    if origin == "repository":
        project = fields["project"]
        if not isinstance(project, str) or not re.fullmatch(
            r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", project
        ):
            raise ValueError("project must be an owner/repository pair")
        commits = fields["commits"]
        if (
            not isinstance(commits, dict)
            or set(commits) != set(REVISIONS)
            or any(not isinstance(value, str) or not _HEX40.fullmatch(value) for value in
                   commits.values())
            or commits["vulnerable"] == commits["fixed"]
        ):
            raise ValueError("repository commits must be two distinct 40-hex SHAs")
        _validate_archive_pair(project, commits, fields["archives"])
    else:
        versions = fields["versions"]
        if not isinstance(versions, dict) or set(versions) != set(REVISIONS):
            raise ValueError("versions must contain vulnerable and fixed entries")
        for revision in REVISIONS:
            _validate_local_version(versions[revision], revision)

    rationale = fields["selection_rationale"]
    if not isinstance(rationale, str) or len(rationale.strip()) < 40:
        raise ValueError("selection rationale is too short")

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
    cwes: set[str] = set()
    for case in document["cases"]:
        _validate_case(case)
        if case["id"] in identifiers:
            raise ValueError("case ids must be unique")
        identifiers.add(case["id"])
        cwes.add(case["cwe"])
    if cwes != SUPPORTED_CWES:
        raise ValueError("case document must contain every supported CWE")


def select_evaluation_cases(
    document: dict[str, Any], case_id: str | None, max_cases: int | None
) -> list[dict[str, Any]]:
    """Select already-validated committed cases for trusted orchestration."""

    validate_case_document(document)
    if max_cases is not None and (type(max_cases) is not int or max_cases < 1):
        raise ValueError("max-cases must be a positive integer")
    if case_id is None:
        return list(document["cases"])[: max_cases or len(document["cases"])]
    if type(case_id) is not str or not re.fullmatch(_ID_PATTERN_TEXT, case_id):
        raise ValueError("evaluation case id is invalid")
    matches = [case for case in document["cases"] if case["id"] == case_id]
    if len(matches) != 1:
        raise ValueError("evaluation case id is not in the committed manifest")
    return matches


# ------------------------------------------------------------------- fixtures


def canonical_tree_digest(source_root: Path) -> str:
    """Digest a fixture tree from newline-normalized text content.

    Normalizing CRLF to LF keeps the pin stable across checkouts, mirroring
    ``lima.real_world_evaluation``. The digest covers every regular file, so
    any content drift invalidates the pinned pair.
    """

    source_root = Path(source_root)
    if not source_root.is_dir():
        raise ValueError(f"fixture source directory is unavailable: {source_root}")
    files = sorted(path for path in source_root.rglob("*") if path.is_file())
    digest = hashlib.sha256()
    for path in files:
        payload = path.read_bytes().replace(b"\r\n", b"\n").replace(b"\r", b"\n")
        relative = path.relative_to(source_root).as_posix()
        digest.update(relative.encode("utf-8"))
        digest.update(b"\0")
        digest.update(str(len(payload)).encode("ascii"))
        digest.update(b"\0")
        digest.update(payload)
        digest.update(b"\n")
    return digest.hexdigest()


def _verified_fixture_root(case: dict[str, Any], revision: str) -> Path:
    version = case["versions"][revision]
    if version.get("kind") != "local":
        raise ValueError(
            "repository archive cases are structurally validated but not runnable "
            "in this evaluation version"
        )
    source_root = (ROOT / version["source_dir"]).resolve()
    digest = canonical_tree_digest(source_root)
    if digest != version["content_sha256"]:
        raise ValueError(
            f"fixture content digest mismatch for {case['id']} {revision}; "
            "the pinned pair changed on disk"
        )
    affected_path = source_root.joinpath(*PurePosixPath(case["affected"]["path"]).parts)
    if not affected_path.is_file():
        raise ValueError(
            f"affected path {case['affected']['path']} is missing from the pinned fixture"
        )
    return source_root


# -------------------------------------------------------------------- pipeline


def _usage_from_collaboration(collaboration: Mapping[str, Any]) -> dict[str, int]:
    budget = collaboration.get("budget") or {}
    remaining = budget.get("remaining") or {}

    def used(maximum_name: str, remaining_name: str) -> int:
        maximum = int(budget.get(maximum_name, 0) or 0)
        left = int(remaining.get(remaining_name, 0) or 0)
        return max(0, maximum - left)

    return {
        "calls": used("max_calls", "calls"),
        "context_files": used("max_context_files", "files"),
        "context_lines": used("max_context_lines", "lines"),
        "output_bytes": used("max_output_bytes", "bytes_remaining"),
    }


def scan_revision(
    case: dict[str, Any],
    revision: str,
    client_factory: Callable[[], object],
    timeout_seconds: int,
) -> dict[str, Any]:
    """Run the real repository scan chain over one pinned fixture revision.

    The pipeline receives only the fixture workspace; no label, expected
    identity, or case-document byte enters this path. Scoring happens
    outside, in :func:`run_evaluation`.
    """

    del timeout_seconds  # The injected client owns transport timing.
    if case.get("origin") != "synthetic":
        raise ValueError(
            "repository archive cases are structurally validated but not runnable "
            "in this evaluation version"
        )
    source_root = _verified_fixture_root(case, revision)
    workspace = RepositoryWorkspace(source_root)
    scanner = RepositoryScanner(
        sast_mode="off",
        dataflow_enabled=False,
        cxx_memory_mode="off",
        cxx_agent_mode="auto",
        cxx_agent_client_factory=client_factory,
    )
    started = time.monotonic()
    result = scanner.scan(
        workspace, repository_key=f"cxx-agent-eval/{case['id']}/{revision}"
    )
    elapsed = time.monotonic() - started
    collaboration = result.report.collaboration.get("cxx_agent")
    if not isinstance(collaboration, dict) or "status" not in collaboration:
        raise ValueError("the scan report is missing the C/C++ agent collaboration payload")
    agent_findings = []
    for finding in result.report.findings:
        if "cxx-agent" not in str(finding.source).split("+"):
            continue
        agent_findings.append(
            {
                "cwe": finding.cwe,
                "path": PurePosixPath(finding.path).as_posix(),
                "symbol": finding.symbol,
                "line": int(finding.line),
                "verification_state": finding.verification_state,
                "automatic_repair": bool(finding.automatic_repair),
            }
        )
    return {
        "status": str(collaboration.get("status", "")),
        "collaboration": collaboration,
        "agent_findings": agent_findings,
        "snapshot_sha256": result.inventory.fingerprint(),
        "usage": _usage_from_collaboration(collaboration),
        "elapsed_seconds": elapsed,
    }


# --------------------------------------------------------------------- scoring


def _validate_pipeline_result(result: object) -> dict[str, Any]:
    raw = _exact_fields(result, _PIPELINE_RESULT_KEYS, "pipeline result")
    if raw["status"] not in _PIPELINE_STATUSES:
        raise ValueError("pipeline status is outside the closed collaboration domain")
    collaboration = raw["collaboration"]
    if not isinstance(collaboration, dict):
        raise ValueError("collaboration payload must be an object")
    if len(json.dumps(collaboration, ensure_ascii=False).encode("utf-8")) > (
        _MAX_COLLABORATION_BYTES
    ):
        raise ValueError("collaboration payload exceeds the bounded report size")
    findings = raw["agent_findings"]
    if type(findings) is not list or len(findings) > _MAX_FINDINGS:
        raise ValueError("agent findings must be a bounded array")
    for finding in findings:
        fields = _exact_fields(finding, _FINDING_KEYS, "agent finding")
        if fields["cwe"] not in SUPPORTED_CWES:
            raise ValueError("agent finding CWE is unsupported")
        _safe_relative_path(fields["path"], "agent finding path")
        _bounded_text(fields["symbol"], "agent finding symbol", _MAX_FINDING_BYTES)
        if type(fields["line"]) is not int or not 1 <= fields["line"] <= _MAX_LINE:
            raise ValueError("agent finding line is out of range")
        if fields["verification_state"] not in CXX_AGENT_VERIFICATION_STATES:
            raise ValueError("agent finding verification state is outside the closed domain")
        if fields["automatic_repair"] is not False:
            raise ValueError("C/C++ findings must keep automatic_repair false")
    if not isinstance(raw["snapshot_sha256"], str) or not _HEX64.fullmatch(
        raw["snapshot_sha256"]
    ):
        raise ValueError("snapshot_sha256 must be a lowercase SHA-256 digest")
    usage = _exact_fields(raw["usage"], _USAGE_KEYS, "usage")
    for name, value in usage.items():
        if type(value) is not int or not 0 <= value <= _MAX_USAGE_VALUE:
            raise ValueError(f"usage {name} must be a bounded non-negative integer")
    elapsed = raw["elapsed_seconds"]
    if (
        isinstance(elapsed, bool)
        or not isinstance(elapsed, int | float)
        or not 0 <= elapsed <= _MAX_ELAPSED_SECONDS
        or not math.isfinite(elapsed)
    ):
        raise ValueError("elapsed_seconds must be a finite non-negative number")
    return raw


def _safe_ratio(numerator: float, denominator: float, label: str, diagnostics: list[str]) -> Any:
    if denominator == 0:
        diagnostics.append(f"{label} denominator is zero")
        return None
    return numerator / denominator


def _matches_target(case: dict[str, Any], finding: Mapping[str, Any]) -> bool:
    return (
        finding["cwe"] == case["cwe"]
        and finding["path"] == case["affected"]["path"]
        and finding["symbol"] == case["affected"]["symbol"]
    )


def _score_revision(
    case: dict[str, Any], revision: str, raw: dict[str, Any]
) -> dict[str, Any]:
    findings = raw["agent_findings"]
    hits = [finding for finding in findings if _matches_target(case, finding)]
    verified_hits = [
        finding for finding in hits if finding["verification_state"] in VERIFIED_STATES
    ]
    state_counts: dict[str, int] = {}
    for finding in findings:
        state = finding["verification_state"]
        state_counts[state] = state_counts.get(state, 0) + 1
    return {
        "expected_vulnerable": revision == "vulnerable",
        "counted": raw["status"] == "completed",
        "status": raw["status"],
        "predicted_vulnerable": bool(hits),
        "verified_hit": bool(verified_hits),
        "target_identity": {
            "cwe": case["cwe"],
            "path": case["affected"]["path"],
            "symbol": case["affected"]["symbol"],
        },
        "target_finding_count": len(hits),
        "verified_target_finding_count": len(verified_hits),
        "agent_findings": findings,
        "verification_state_counts": state_counts,
        "verified_only": sum(
            1 for finding in findings if finding["verification_state"] in VERIFIED_STATES
        ),
        "usage": dict(raw["usage"]),
        "elapsed_seconds": float(raw["elapsed_seconds"]),
        "snapshot_sha256": raw["snapshot_sha256"],
        "collaboration": raw["collaboration"],
    }


def run_evaluation(
    cases: list[dict[str, Any]],
    revision_runner: Callable[[dict[str, Any], str], dict[str, Any]],
) -> dict[str, Any]:
    """Score fixed pairs from raw pipeline records; labels never enter the runner.

    Only revisions whose pipeline status is ``completed`` are counted in the
    confusion matrices; every other revision stays visible through its record
    and lowers ``completed_coverage``. ``cost_usd`` is always null in v1: the
    pipeline records an output-bytes proxy, never provider token accounting.
    """

    diagnostics: list[str] = []
    confusion = {"tp": 0, "fp": 0, "fn": 0, "tn": 0}
    verified_confusion = {"tp": 0, "fp": 0, "fn": 0, "tn": 0}
    case_results: list[dict[str, Any]] = []
    correct_pairs = eligible_pairs = 0
    counted_revisions = 0
    revision_count = 0
    usage_totals = {"calls": 0, "context_files": 0, "context_lines": 0, "output_bytes": 0}
    elapsed_values: list[float] = []
    state_counts: dict[str, int] = {}
    verified_only_total = 0

    for case in cases:
        pair_record: dict[str, Any] = {
            "case_id": case["id"],
            "cwe": case["cwe"],
            "title": case["title"],
            "revisions": {},
        }
        for revision in REVISIONS:
            raw = _validate_pipeline_result(revision_runner(case, revision))
            record = _score_revision(case, revision, raw)
            pair_record["revisions"][revision] = record
            revision_count += 1
            elapsed_values.append(record["elapsed_seconds"])
            for name in usage_totals:
                usage_totals[name] += record["usage"][name]
            for state, count in record["verification_state_counts"].items():
                state_counts[state] = state_counts.get(state, 0) + count
            verified_only_total += record["verified_only"]
            if not record["counted"]:
                continue
            counted_revisions += 1
            expected = record["expected_vulnerable"]
            for matrix, key in ((confusion, "predicted_vulnerable"), (verified_confusion,
                                                                       "verified_hit")):
                predicted = record[key]
                matrix[
                    "tp" if expected and predicted
                    else "fn" if expected
                    else "fp" if predicted
                    else "tn"
                ] += 1
        vulnerable = pair_record["revisions"]["vulnerable"]
        fixed = pair_record["revisions"]["fixed"]
        if vulnerable["counted"] and fixed["counted"]:
            eligible_pairs += 1
            pair_record["pair_correct"] = (
                vulnerable["predicted_vulnerable"] and not fixed["predicted_vulnerable"]
            )
            correct_pairs += int(pair_record["pair_correct"])
        else:
            pair_record["pair_correct"] = None
            diagnostics.append(
                f"pair_accuracy case {case['id']} has a degraded revision and is not scored"
            )
        case_results.append(pair_record)

    precision = _safe_ratio(confusion["tp"], confusion["tp"] + confusion["fp"],
                            "precision", diagnostics)
    recall = _safe_ratio(confusion["tp"], confusion["tp"] + confusion["fn"],
                         "recall", diagnostics)
    if precision is None or recall is None or precision + recall == 0:
        diagnostics.append("f1 denominator is zero")
        f1 = None
    else:
        f1 = 2 * precision * recall / (precision + recall)
    verified_precision = _safe_ratio(
        verified_confusion["tp"],
        verified_confusion["tp"] + verified_confusion["fp"],
        "verified_precision",
        diagnostics,
    )
    verified_recall = _safe_ratio(
        verified_confusion["tp"],
        verified_confusion["tp"] + verified_confusion["fn"],
        "verified_recall",
        diagnostics,
    )
    if verified_precision is None or verified_recall is None or (
        verified_precision + verified_recall == 0
    ):
        diagnostics.append("verified_f1 denominator is zero")
        verified_f1 = None
    else:
        verified_f1 = 2 * verified_precision * verified_recall / (
            verified_precision + verified_recall
        )
    elapsed_total = float(sum(elapsed_values))
    return {
        "schema_version": 1,
        "case_count": len(cases),
        "revision_count": revision_count,
        "completed_revision_count": counted_revisions,
        "confusion_matrix": confusion,
        "verified_confusion_matrix": verified_confusion,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "verified_precision": verified_precision,
        "verified_recall": verified_recall,
        "verified_f1": verified_f1,
        "pair_accuracy": _safe_ratio(correct_pairs, eligible_pairs,
                                     "pair_accuracy", diagnostics),
        "pair_eligible_count": eligible_pairs,
        "completed_coverage": _safe_ratio(counted_revisions, revision_count,
                                          "completed_coverage", diagnostics),
        "verification_state_counts": state_counts,
        "verified_only_total": verified_only_total,
        "usage": {
            "token_accounting": "bytes-proxy",
            "calls_total": usage_totals["calls"],
            "calls_mean": _safe_ratio(usage_totals["calls"], revision_count,
                                      "calls_mean", diagnostics),
            "context_files_total": usage_totals["context_files"],
            "context_files_mean": _safe_ratio(usage_totals["context_files"], revision_count,
                                              "context_files_mean", diagnostics),
            "context_lines_total": usage_totals["context_lines"],
            "context_lines_mean": _safe_ratio(usage_totals["context_lines"], revision_count,
                                              "context_lines_mean", diagnostics),
            "output_bytes_total": usage_totals["output_bytes"],
            "output_bytes_mean": _safe_ratio(usage_totals["output_bytes"], revision_count,
                                             "output_bytes_mean", diagnostics),
        },
        "cost_usd": None,
        "latency_seconds": {
            "total": elapsed_total,
            "mean": _safe_ratio(elapsed_total, revision_count, "latency_mean", diagnostics),
        },
        "cases": case_results,
        "diagnostics": diagnostics,
    }


# -------------------------------------------------------------------- identity


def _canonical_source_bytes(payload: bytes) -> bytes:
    return payload.replace(b"\r\n", b"\n").replace(b"\r", b"\n")


def _cxx_agent_pipeline_fingerprint() -> str:
    digest = hashlib.sha256()
    package_root = ROOT / "lima"
    for name in CXX_AGENT_PIPELINE_COMPONENTS:
        payload = _canonical_source_bytes((package_root / name).read_bytes())
        digest.update(name.encode("utf-8"))
        digest.update(b"\0")
        digest.update(str(len(payload)).encode("ascii"))
        digest.update(b"\0")
        digest.update(payload)
    return digest.hexdigest()


def build_identity_manifest(
    *, model: str, provider: str, raw_case_data: bytes
) -> dict[str, Any]:
    return {
        "model": model,
        "provider": provider,
        "prompt": {
            "template": CXX_AGENT_PROMPT_TEMPLATE,
            "roles": list(ROLE_ORDER),
            "step_schema_sha256": hashlib.sha256(_STEP_SCHEMA.encode("utf-8")).hexdigest(),
            "untrusted_data_rule_sha256": hashlib.sha256(
                _UNTRUSTED_DATA_RULE.encode("utf-8")
            ).hexdigest(),
        },
        "analyzer_fingerprint": analyzer_fingerprint(),
        "cxx_agent_pipeline_sha256": _cxx_agent_pipeline_fingerprint(),
        "case_data_sha256": hashlib.sha256(raw_case_data).hexdigest(),
    }


def add_report_metadata(
    report: dict[str, Any],
    raw_case_data: bytes,
    *,
    model: str,
    provider: str,
) -> dict[str, Any]:
    result = dict(report)
    result["identity"] = build_identity_manifest(
        model=model, provider=provider, raw_case_data=raw_case_data
    )
    result["validity_boundaries"] = [
        VALIDITY_BOUNDARY,
        "Only the pinned affected path and symbol are labelled; other findings are not scored.",
        "A null metric means its denominator was zero, not a perfect score.",
        "Degraded revisions are excluded from the confusion matrices and counted in "
        "completed_coverage instead.",
        "The evaluation document never enters the pipeline: retrieval and agent context "
        "see only the fixture workspace.",
        "cost_usd stays null because the pipeline records an output-bytes proxy, not "
        "provider token accounting.",
    ]
    return result


# ------------------------------------------------------------------- provider


def build_provider(
    args: argparse.Namespace, env: Mapping[str, str] | None = None
) -> dict[str, Any]:
    """Resolve the OpenAI-compatible provider for the real client.

    Explicit arguments win; otherwise the existing LIMA_LLM_* / provider key
    environments are reused, mirroring ``Settings.resolved_llm()``.
    """

    environment = os.environ if env is None else env
    provider = str(environment.get("LIMA_LLM_PROVIDER", "")).strip().lower()
    base_url = str(args.provider_url or environment.get("LIMA_LLM_BASE_URL", "")).rstrip("/")
    specific_key = _PROVIDER_KEY_ENVIRONMENTS.get(provider, "")
    api_key = str(
        args.provider_key
        or (environment.get(specific_key, "") if specific_key else "")
        or environment.get("LIMA_LLM_API_KEY", "")
    )
    model = str(
        args.model
        or environment.get("LIMA_CXX_AGENT_MODEL", "")
        or environment.get("LIMA_LLM_MODEL", "")
    ).strip()
    if not api_key or not model or (not base_url and provider not in _DEFAULT_BASE_URLS):
        raise ValueError(
            "the C/C++ agent evaluation needs a real provider: pass --provider-url, "
            "--provider-key and --model, or set LIMA_LLM_BASE_URL, LIMA_LLM_API_KEY "
            "(or LIMA_DEEPSEEK_API_KEY / LIMA_OPENROUTER_API_KEY with LIMA_LLM_PROVIDER) "
            "and LIMA_CXX_AGENT_MODEL or LIMA_LLM_MODEL"
        )
    return {
        "provider": provider or "custom",
        "base_url": base_url or _DEFAULT_BASE_URLS[provider],
        "api_key": api_key,
        "model": model,
        "headers": {},
    }


def build_client_factory(
    resolved: Mapping[str, Any], timeout_seconds: int
) -> Callable[[], CxxLLMClient]:
    return lambda: CxxLLMClient(dict(resolved), timeout=timeout_seconds)


# ------------------------------------------------------------------------- CLI


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cases", type=Path, required=True)
    parser.add_argument("--case-id", default=None)
    parser.add_argument("--provider-url", default=None)
    parser.add_argument("--provider-key", default=None)
    parser.add_argument("--model", default=None)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--timeout", type=int, default=600)
    parser.add_argument("--max-cases", type=int, default=None)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.timeout < 1:
        raise SystemExit("--timeout must be a positive integer of seconds")
    document = load_case_document(args.cases)
    selected_cases = select_evaluation_cases(document, args.case_id, args.max_cases)
    # The provider must resolve before any pipeline work so a missing key can
    # never turn into silent degraded metrics or accidental network retries.
    resolved = build_provider(args)
    client_factory = build_client_factory(resolved, args.timeout)
    raw_case_data = args.cases.read_bytes()
    records: dict[tuple[str, str], dict[str, Any]] = {}
    for case in selected_cases:
        for revision in REVISIONS:
            records[(case["id"], revision)] = scan_revision(
                case, revision, client_factory, args.timeout
            )
    report = run_evaluation(
        selected_cases, lambda case, revision: records[(case["id"], revision)]
    )
    report = add_report_metadata(
        report,
        raw_case_data,
        model=str(resolved["model"]),
        provider=str(resolved["provider"]),
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    print(VALIDITY_BOUNDARY)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
