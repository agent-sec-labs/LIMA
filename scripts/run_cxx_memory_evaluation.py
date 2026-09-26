#!/usr/bin/env python3
"""Reproducible evaluation of pinned C/C++ memory vulnerability pairs."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import re
import shutil
import sys
import tarfile
import tempfile
import time
import urllib.request
from collections.abc import Callable
from pathlib import Path, PurePosixPath
from typing import Any
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from lima.cxx_memory import (  # noqa: E402
    CxxAnalyzerProtocolError,
    CxxMemoryAnalyzerClient,
    validate_response_metadata,
)
from lima.workspace import RepositoryWorkspace  # noqa: E402

SUPPORTED_CWES = frozenset({"CWE-125", "CWE-415", "CWE-416", "CWE-787"})
ANALYSIS_MODES = ("source-only", "build-backed", "sanitizer-confirmed")
VALIDITY_BOUNDARY = "合成和固定样本结果不代表真实项目完整检测能力"
_HEX40 = re.compile(r"^[0-9a-f]{40}$")
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_IMAGE_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_CASE_KEYS = {
    "id",
    "project",
    "cwe",
    "vulnerable_commit",
    "fixed_commit",
    "archives",
    "advisory_url",
    "upstream_fix_url",
    "affected",
    "build_steps",
    "test_steps",
    "selection_rationale",
    "license",
}
_MAX_ARCHIVE_BYTES = 512 * 1024 * 1024
_MAX_ARCHIVE_MEMBERS = 100_000
_MAX_EXTRACTED_BYTES = 2 * 1024 * 1024 * 1024
_MAX_EVALUATION_FINDINGS = 10_000
_ANALYSIS_RESULT_KEYS = {
    "findings",
    "tool_runs",
    "coverage",
    "diagnostics",
    "elapsed_seconds",
    "timed_out",
    "source_lines",
    "snapshot_sha256",
}
_DOWNLOAD_DEADLINE_SECONDS = 300.0
_DOWNLOAD_SOCKET_TIMEOUT_SECONDS = 60.0


class _HttpsRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, file_pointer, code, message, headers, new_url):
        if not _is_https(new_url):
            raise ValueError("archive redirect hops must remain HTTPS")
        return super().redirect_request(request, file_pointer, code, message, headers, new_url)


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _is_https(value: object) -> bool:
    if not isinstance(value, str) or not value:
        return False
    parsed = urlparse(value)
    return (
        parsed.scheme == "https"
        and bool(parsed.netloc)
        and not parsed.username
        and not parsed.password
    )


def _validate_steps(label: str, value: object, *, allow_empty: bool = False) -> None:
    if not isinstance(value, list):
        raise ValueError(f"{label} must be an array of argv arrays")
    if not value and not allow_empty:
        raise ValueError(f"{label} must be a non-empty array of argv arrays")
    for step in value:
        if not isinstance(step, list) or not step:
            raise ValueError(f"{label} must contain only non-empty argv arrays")
        if any(
            not isinstance(argument, str) or not argument or "\0" in argument for argument in step
        ):
            raise ValueError(f"{label} argv values must be non-empty strings")
        shell_names = {"bash", "cmd", "cmd.exe", "powershell", "pwsh", "sh"}
        shell_switches = {"-c", "/c", "-command", "-encodedcommand"}
        for index, argument in enumerate(step):
            if Path(argument).name.lower() in shell_names and any(
                later.lower() in shell_switches for later in step[index + 1 :]
            ):
                raise ValueError(f"{label} must not invoke a shell command string")


def _validate_archive(project: str, revision: str, archive: object, label: str) -> None:
    if not isinstance(archive, dict) or set(archive) != {"url", "sha256"}:
        raise ValueError(f"{label} archive must contain only url and sha256")
    url = archive["url"]
    digest = archive["sha256"]
    if not _is_https(url) or not isinstance(digest, str) or not _HEX64.fullmatch(digest):
        raise ValueError(f"{label} archive URL and SHA-256 must be pinned HTTPS values")
    parsed = urlparse(url)
    expected_path = f"/{project}/tar.gz/{revision}"
    if parsed.netloc.lower() != "codeload.github.com" or parsed.path != expected_path:
        raise ValueError(f"{label} archive URL must contain its corresponding exact commit")
    if parsed.query or parsed.fragment:
        raise ValueError(f"{label} archive URL must not contain query or fragment data")


def _advisory_id(value: object) -> str:
    if not _is_https(value):
        raise ValueError("advisory_url must be canonical HTTPS")
    parsed = urlparse(value)
    if parsed.query or parsed.fragment:
        raise ValueError("advisory_url must not contain query or fragment data")
    if parsed.netloc == "nvd.nist.gov":
        match = re.fullmatch(r"/vuln/detail/(CVE-[0-9]{4}-[0-9]{4,})", parsed.path)
    elif parsed.netloc == "github.com":
        match = re.fullmatch(
            r"/advisories/(GHSA-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4})",
            parsed.path,
        )
    else:
        match = None
    if match is None:
        raise ValueError("advisory_url must be a canonical NVD CVE or GitHub GHSA")
    return match.group(1)


def _validate_upstream_fix(project: str, fixed: str, value: object) -> None:
    if not _is_https(value):
        raise ValueError("upstream_fix_url must be canonical HTTPS")
    parsed = urlparse(value)
    if (
        parsed.netloc != "github.com"
        or parsed.path != f"/{project}/commit/{fixed}"
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("upstream fix URL must identify the exact GitHub project and commit")


def _validate_license(project: str, fixed: str, license_info: object) -> None:
    if (
        not isinstance(license_info, dict)
        or set(license_info) != {"spdx", "url"}
        or not isinstance(license_info["spdx"], str)
        or not license_info["spdx"].strip()
        or not _is_https(license_info["url"])
    ):
        raise ValueError("license provenance is invalid")
    parsed = urlparse(license_info["url"])
    prefix = f"/{project}/{fixed}/"
    relative = parsed.path.removeprefix(prefix)
    if (
        parsed.netloc != "raw.githubusercontent.com"
        or not parsed.path.startswith(prefix)
        or not relative
        or "\\" in relative
        or any(part in {"", ".", ".."} for part in PurePosixPath(relative).parts)
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("license URL must be pinned to the fixed GitHub project commit")


def _validate_case(case: object) -> None:
    if not isinstance(case, dict) or set(case) != _CASE_KEYS:
        raise ValueError("case fields do not match schema")
    if not isinstance(case["id"], str) or not re.fullmatch(
        r"[a-z0-9][a-z0-9._-]{2,127}", case["id"]
    ):
        raise ValueError("case id is invalid")
    project = case["project"]
    if not isinstance(project, str) or not re.fullmatch(
        r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", project
    ):
        raise ValueError("project must be an owner/repository pair")
    if case["cwe"] not in SUPPORTED_CWES:
        raise ValueError("case CWE is unsupported")
    vulnerable = case["vulnerable_commit"]
    fixed = case["fixed_commit"]
    if not isinstance(vulnerable, str) or not _HEX40.fullmatch(vulnerable):
        raise ValueError("vulnerable commit must be an exact lowercase 40-hex SHA")
    if not isinstance(fixed, str) or not _HEX40.fullmatch(fixed) or fixed == vulnerable:
        raise ValueError("fixed commit must be a distinct exact lowercase 40-hex SHA")
    archives = case["archives"]
    if not isinstance(archives, dict) or set(archives) != {"vulnerable", "fixed"}:
        raise ValueError("archives must contain vulnerable and fixed entries")
    _validate_archive(project, vulnerable, archives["vulnerable"], "vulnerable")
    _validate_archive(project, fixed, archives["fixed"], "fixed")
    advisory_id = _advisory_id(case["advisory_url"])
    _validate_upstream_fix(project, fixed, case["upstream_fix_url"])
    if advisory_id.lower() not in case["id"]:
        raise ValueError("case id must contain its canonical advisory id")
    affected = case["affected"]
    if not isinstance(affected, dict) or set(affected) != {"path", "symbol"}:
        raise ValueError("affected identity must contain path and symbol")
    path = affected["path"]
    if (
        not isinstance(path, str)
        or not path
        or "\\" in path
        or PurePosixPath(path).is_absolute()
        or any(part in {"", ".", ".."} for part in PurePosixPath(path).parts)
        or not isinstance(affected["symbol"], str)
        or not affected["symbol"].strip()
    ):
        raise ValueError("affected path or symbol is unsafe")
    _validate_steps("build_steps", case["build_steps"])
    _validate_steps("test_steps", case["test_steps"], allow_empty=True)
    rationale = case["selection_rationale"]
    if (
        not isinstance(rationale, str)
        or len(rationale.strip()) < 40
        or advisory_id.lower() not in rationale.lower()
    ):
        raise ValueError("selection rationale is too short")
    _validate_license(project, fixed, case["license"])


def validate_case_document(document: object) -> None:
    if not isinstance(document, dict) or set(document) != {"schema_version", "cases"}:
        raise ValueError("case document fields do not match schema")
    if (
        type(document["schema_version"]) is not int
        or document["schema_version"] != 1
        or not isinstance(document["cases"], list)
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


def select_evaluation_cases(document: dict[str, Any], case_id: str | None) -> list[dict[str, Any]]:
    """Select one already-validated committed case for trusted orchestration."""

    validate_case_document(document)
    if case_id is None:
        return list(document["cases"])
    if type(case_id) is not str or not re.fullmatch(r"[a-z0-9][a-z0-9._-]{2,127}", case_id):
        raise ValueError("evaluation case id is invalid")
    matches = [case for case in document["cases"] if case["id"] == case_id]
    if len(matches) != 1:
        raise ValueError("evaluation case id is not in the committed manifest")
    return matches


def _safe_ratio(
    numerator: float, denominator: float, label: str, diagnostics: list[str]
) -> float | None:
    if denominator == 0:
        diagnostics.append(f"{label} denominator is zero")
        return None
    return numerator / denominator


def _matches_target(case: dict[str, Any], finding: object) -> bool:
    return (
        isinstance(finding, dict)
        and finding.get("cwe") == case["cwe"]
        and finding.get("path") == case["affected"]["path"]
        and finding.get("symbol") == case["affected"]["symbol"]
    )


def _validate_analysis_result(result: object) -> dict[str, Any]:
    if type(result) is not dict or set(result) != _ANALYSIS_RESULT_KEYS:
        raise ValueError("analyzer result fields do not match schema")
    findings = result["findings"]
    if type(findings) is not list or len(findings) > _MAX_EVALUATION_FINDINGS:
        raise ValueError("analyzer findings must be a bounded array")
    for finding in findings:
        if type(finding) is not dict or set(finding) != {
            "cwe",
            "path",
            "symbol",
            "analysis_mode",
        }:
            raise ValueError("analyzer finding fields do not match schema")
        path = finding["path"]
        symbol = finding["symbol"]
        if (
            finding["cwe"] not in SUPPORTED_CWES
            or finding["analysis_mode"] not in ANALYSIS_MODES
            or type(path) is not str
            or not path
            or len(path.encode("utf-8")) > 4096
            or "\\" in path
            or PurePosixPath(path).is_absolute()
            or any(part in {"", ".", ".."} for part in PurePosixPath(path).parts)
            or type(symbol) is not str
            or not symbol
            or len(symbol.encode("utf-8")) > 512
        ):
            raise ValueError("analyzer finding identity is invalid")
    try:
        validate_response_metadata(result["tool_runs"], result["coverage"], result["diagnostics"])
    except CxxAnalyzerProtocolError as exc:
        raise ValueError("analyzer result metadata is invalid") from exc
    if type(result["source_lines"]) is not int or not 0 <= result["source_lines"] <= 2**31 - 1:
        raise ValueError("source_lines must be a bounded non-negative integer")
    if type(result["timed_out"]) is not bool:
        raise ValueError("timed_out must be a boolean")
    elapsed = result["elapsed_seconds"]
    if (
        isinstance(elapsed, bool)
        or not isinstance(elapsed, int | float)
        or elapsed < 0
        or not math.isfinite(elapsed)
    ):
        raise ValueError("elapsed_seconds must be a finite non-negative number")
    snapshot = result["snapshot_sha256"]
    if type(snapshot) is not str or not _HEX64.fullmatch(snapshot):
        raise ValueError("snapshot_sha256 must be an exact lowercase SHA-256")
    return result


def run_evaluation(
    cases: list[dict[str, Any]],
    analyzer: Callable[[dict[str, Any], str], dict[str, Any]],
) -> dict[str, Any]:
    diagnostics: list[str] = []
    tp = fp = fn = tn = 0
    correct_pairs = 0
    false_positive_findings = 0
    fixed_source_lines = 0
    total_snapshots = 0
    timed_out = 0
    elapsed_values: list[float] = []
    layer_counts = {mode: 0 for mode in ANALYSIS_MODES}
    layer_completed = {mode: 0 for mode in ANALYSIS_MODES}
    build_attempts = build_successes = 0
    case_results: list[dict[str, Any]] = []

    for case in cases:
        pair_predictions: dict[str, bool] = {}
        pair_record = {"case_id": case["id"], "cwe": case["cwe"], "revisions": {}}
        for revision in ("vulnerable", "fixed"):
            result = _validate_analysis_result(analyzer(case, revision))
            findings = result["findings"]
            tool_runs = result["tool_runs"]
            target_findings = [finding for finding in findings if _matches_target(case, finding)]
            predicted = bool(target_findings)
            pair_predictions[revision] = predicted
            if revision == "vulnerable":
                if predicted:
                    tp += 1
                else:
                    fn += 1
            else:
                if predicted:
                    fp += 1
                    false_positive_findings += len(target_findings)
                else:
                    tn += 1
                lines = result["source_lines"]
                fixed_source_lines += lines

            revision_layer_counts = {mode: 0 for mode in ANALYSIS_MODES}
            for finding in findings:
                mode = finding["analysis_mode"]
                layer_counts[mode] += 1
                revision_layer_counts[mode] += 1
            semgrep_runs = [run for run in tool_runs if run["tool"] == "semgrep"]
            build_runs = [run for run in tool_runs if run["tool"] == "build-step"]
            clang_runs = [run for run in tool_runs if run["tool"] == "clang"]
            asan_runs = [run for run in tool_runs if run["tool"] == "asan-test"]
            build_attempted = bool(build_runs)
            build_completed = build_attempted and all(
                run["status"] == "completed" for run in build_runs
            )
            revision_layer_completed = {
                "source-only": bool(semgrep_runs)
                and all(run["status"] == "completed" for run in semgrep_runs),
                "build-backed": build_completed
                and bool(clang_runs)
                and all(run["status"] == "completed" for run in clang_runs),
                "sanitizer-confirmed": bool(asan_runs)
                and all(run["status"] == "completed" for run in asan_runs),
            }
            for mode, completed in revision_layer_completed.items():
                layer_completed[mode] += int(completed)
            if build_attempted:
                build_attempts += 1
                build_successes += int(build_completed)
            is_timeout = result["timed_out"] or any(
                run["status"] == "timed-out" for run in tool_runs
            )
            timed_out += int(is_timeout)
            elapsed = result["elapsed_seconds"]
            elapsed_values.append(float(elapsed))
            total_snapshots += 1
            pair_record["revisions"][revision] = {
                "expected_vulnerable": revision == "vulnerable",
                "predicted_vulnerable": predicted,
                "target_identity": {
                    "cwe": case["cwe"],
                    "path": case["affected"]["path"],
                    "symbol": case["affected"]["symbol"],
                },
                "target_finding_count": len(target_findings),
                "snapshot_sha256": result["snapshot_sha256"],
                "source_lines": result["source_lines"],
                "layer_finding_counts": revision_layer_counts,
                "layer_completed": revision_layer_completed,
                "build_attempted": build_attempted,
                "build_completed": build_completed,
                "timed_out": is_timeout,
                "elapsed_seconds": float(elapsed),
                "tool_runs": tool_runs,
                "coverage": result["coverage"],
                "diagnostics": result["diagnostics"],
            }
        pair_ok = pair_predictions["vulnerable"] and not pair_predictions["fixed"]
        correct_pairs += int(pair_ok)
        pair_record["pair_correct"] = pair_ok
        case_results.append(pair_record)

    precision = _safe_ratio(tp, tp + fp, "precision", diagnostics)
    recall = _safe_ratio(tp, tp + fn, "recall", diagnostics)
    if precision is None or recall is None or precision + recall == 0:
        diagnostics.append("f1 denominator is zero")
        f1 = None
    else:
        f1 = 2 * precision * recall / (precision + recall)
    pair_accuracy = _safe_ratio(correct_pairs, len(cases), "pair_accuracy", diagnostics)
    false_positive_rate = _safe_ratio(
        false_positive_findings * 1000,
        fixed_source_lines,
        "false_positives_per_kloc",
        diagnostics,
    )
    build_success_rate = _safe_ratio(
        build_successes, build_attempts, "build_success_rate", diagnostics
    )
    timeout_rate = _safe_ratio(timed_out, total_snapshots, "timeout_rate", diagnostics)
    layer_coverage = {
        mode: _safe_ratio(layer_completed[mode], total_snapshots, f"{mode} coverage", diagnostics)
        for mode in ANALYSIS_MODES
    }
    return {
        "schema_version": 1,
        "case_count": len(cases),
        "snapshot_count": total_snapshots,
        "confusion_matrix": {"tp": tp, "fp": fp, "fn": fn, "tn": tn},
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "pair_accuracy": pair_accuracy,
        "false_positives_per_kloc": false_positive_rate,
        "layer_counts": layer_counts,
        "layer_coverage": layer_coverage,
        "build_success_rate": build_success_rate,
        "timeout_rate": timeout_rate,
        "elapsed_seconds": {
            "total": sum(elapsed_values),
            "mean": _safe_ratio(
                sum(elapsed_values), len(elapsed_values), "mean elapsed", diagnostics
            ),
        },
        "cases": case_results,
        "diagnostics": diagnostics,
    }


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _validated_member_path(name: str) -> PurePosixPath:
    if not name or "\0" in name or "\\" in name or re.match(r"^[A-Za-z]:", name):
        raise ValueError("archive member path is unsafe")
    path = PurePosixPath(name)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise ValueError("archive member path is unsafe")
    return path


def extract_verified_archive(archive_path: Path, expected_sha256: str, destination: Path) -> Path:
    archive_path = Path(archive_path)
    destination = Path(destination)
    if not _HEX64.fullmatch(expected_sha256) or _sha256_file(archive_path) != expected_sha256:
        raise ValueError("archive SHA-256 mismatch")
    if destination.exists():
        raise ValueError("archive destination must not already exist")
    try:
        with tarfile.open(archive_path, mode="r:gz") as archive:
            members = archive.getmembers()
            if not members or len(members) > _MAX_ARCHIVE_MEMBERS:
                raise ValueError("archive member count is invalid")
            validated: list[tuple[tarfile.TarInfo, PurePosixPath]] = []
            total_size = 0
            names: set[str] = set()
            for member in members:
                path = _validated_member_path(
                    member.name.rstrip("/") if member.isdir() else member.name
                )
                normalized = path.as_posix()
                if normalized in names:
                    raise ValueError("archive contains duplicate member paths")
                names.add(normalized)
                if not (member.isdir() or member.isreg()):
                    raise ValueError("archive links and special files are forbidden")
                if member.size < 0:
                    raise ValueError("archive member size is invalid")
                total_size += member.size
                if total_size > _MAX_EXTRACTED_BYTES:
                    raise ValueError("archive expanded size exceeds limit")
                validated.append((member, path))
            roots = {path.parts[0] for _, path in validated}
            if len(roots) != 1:
                raise ValueError("archive must contain exactly one project root")
            destination.mkdir(parents=True, exist_ok=False)
            try:
                for member, relative in validated:
                    target = destination.joinpath(*relative.parts)
                    if member.isdir():
                        target.mkdir(parents=True, exist_ok=True)
                        continue
                    target.parent.mkdir(parents=True, exist_ok=True)
                    source = archive.extractfile(member)
                    if source is None:
                        raise ValueError("archive regular file has no payload")
                    with source, target.open("xb") as output:
                        shutil.copyfileobj(source, output, length=1024 * 1024)
            except Exception:
                shutil.rmtree(destination, ignore_errors=True)
                raise
    except (tarfile.TarError, OSError) as exc:
        if destination.exists():
            shutil.rmtree(destination, ignore_errors=True)
        raise ValueError("archive is unreadable") from exc
    return destination / next(iter(roots))


def download_verified_archive(url: str, expected_sha256: str, destination: Path) -> Path:
    if not _is_https(url):
        raise ValueError("archive download URL must be HTTPS")
    destination = Path(destination)
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists():
        if _sha256_file(destination) != expected_sha256:
            raise ValueError("cached archive SHA-256 mismatch")
        return destination
    temporary = destination.with_suffix(destination.suffix + ".part")
    if temporary.exists():
        temporary.unlink()
    request = urllib.request.Request(  # noqa: S310
        url, headers={"User-Agent": "LIMA-cxx-evaluation/1"}
    )
    opener = urllib.request.build_opener(_HttpsRedirectHandler())
    digest = hashlib.sha256()
    size = 0
    started = time.monotonic()

    def remaining_seconds() -> float:
        remaining = _DOWNLOAD_DEADLINE_SECONDS - (time.monotonic() - started)
        if remaining <= 0:
            raise TimeoutError("archive download exceeded total deadline")
        return remaining

    try:
        with (
            opener.open(  # noqa: S310
                request,
                timeout=min(_DOWNLOAD_SOCKET_TIMEOUT_SECONDS, remaining_seconds()),
            ) as response,
            temporary.open("xb") as output,
        ):
            if not _is_https(response.geturl()):
                raise ValueError("archive redirect must remain HTTPS")
            read1 = getattr(response, "read1", None)
            if not callable(read1):
                raise RuntimeError(
                    "archive response stream cannot enforce the total deadline"
                )
            while True:
                try:
                    response_socket = response.fp.raw._sock
                    set_timeout = response_socket.settimeout
                except AttributeError as exc:
                    raise RuntimeError(
                        "archive response socket cannot enforce the total deadline"
                    ) from exc
                if not callable(set_timeout):
                    raise RuntimeError(
                        "archive response socket cannot enforce the total deadline"
                    )
                set_timeout(
                    min(_DOWNLOAD_SOCKET_TIMEOUT_SECONDS, remaining_seconds())
                )
                # One bounded read per iteration, so a slow trickle on a
                # content-length response cannot keep one greedy read alive
                # past the absolute deadline. Chunked framing and header
                # parsing still rely on the per-recv socket timeout.
                block = read1(64 * 1024)
                remaining_seconds()
                if not block:
                    break
                size += len(block)
                if size > _MAX_ARCHIVE_BYTES:
                    raise ValueError("archive download exceeds size limit")
                digest.update(block)
                output.write(block)
        if digest.hexdigest() != expected_sha256:
            raise ValueError("downloaded archive SHA-256 mismatch")
        os.replace(temporary, destination)
    except Exception:
        temporary.unlink(missing_ok=True)
        raise
    return destination


def _source_line_count(workspace: RepositoryWorkspace) -> int:
    inventory = workspace.inventory()
    total = 0
    for item in inventory.files:
        if PurePosixPath(item.path).suffix.lower() in {
            ".c",
            ".cc",
            ".cpp",
            ".cxx",
            ".h",
            ".hh",
            ".hpp",
            ".hxx",
        }:
            text = workspace.read_text(item.path)
            total += len(text.splitlines())
    return total


def _sidecar_result(base_url: str, repository_key: str, source_root: Path) -> dict[str, Any]:
    workspace = RepositoryWorkspace(source_root)
    inventory = workspace.inventory()
    fingerprint = inventory.fingerprint()
    client = CxxMemoryAnalyzerClient(
        base_url, timeout_seconds=300, max_response_bytes=2 * 1024 * 1024
    )
    started = time.monotonic()
    result = client.analyze(
        repository_key,
        fingerprint,
        ("source-only", "build-backed", "sanitizer-confirmed"),
        inventory=inventory,
    )
    elapsed = time.monotonic() - started
    findings = [
        {
            "cwe": finding.cwe,
            "path": finding.path,
            "symbol": finding.symbol,
            "analysis_mode": finding.analysis_mode,
        }
        for finding in result.findings
    ]
    return {
        "findings": findings,
        "tool_runs": result.tool_runs,
        "coverage": result.coverage,
        "diagnostics": result.diagnostics,
        "elapsed_seconds": elapsed,
        "timed_out": any(run.get("status") == "timed-out" for run in result.tool_runs),
        "source_lines": _source_line_count(workspace),
        "snapshot_sha256": fingerprint,
    }


def add_report_metadata(
    report: dict[str, Any],
    raw_case_data: bytes,
    *,
    analyzer_image_digest: str | None,
    analyzer_base_image_digest: str | None = None,
) -> dict[str, Any]:
    if (
        not isinstance(analyzer_image_digest, str)
        or not _IMAGE_DIGEST.fullmatch(analyzer_image_digest)
    ):
        raise ValueError("analyzer image digest must be an exact Docker image ID")
    if analyzer_base_image_digest is not None and (
        not isinstance(analyzer_base_image_digest, str)
        or not _IMAGE_DIGEST.fullmatch(analyzer_base_image_digest)
    ):
        raise ValueError("analyzer base image digest must be an exact Docker image ID")
    result = dict(report)
    diagnostics = list(result.get("diagnostics", []))
    result["diagnostics"] = diagnostics
    result["analyzer_image_digest"] = analyzer_image_digest
    result["analyzer_base_image_digest"] = analyzer_base_image_digest or ""
    result["case_data_sha256"] = hashlib.sha256(raw_case_data).hexdigest()
    result["validity_boundaries"] = [
        VALIDITY_BOUNDARY,
        "Only the pinned affected path and symbol are labelled; other findings are not scored.",
        "A null metric means its denominator was zero, not a perfect score.",
        "Build and test argv are provenance metadata and are never sent in analyzer requests.",
        (
            "The base image digest, exact Semgrep version, package manifests, and actual "
            "image ID are auditable; Debian apt repositories are not snapshot-pinned."
        ),
    ]
    return result


def _image_digest_argument(value: str) -> str:
    if not _IMAGE_DIGEST.fullmatch(value):
        raise argparse.ArgumentTypeError(
            "must be a Docker image ID in sha256:<64 lowercase hex> form"
        )
    return value


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cases", type=Path, required=True)
    parser.add_argument("--cache-dir", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--analyzer-url", required=True)
    parser.add_argument(
        "--analyzer-image-digest",
        type=_image_digest_argument,
        required=True,
    )
    parser.add_argument(
        "--analyzer-base-image-digest",
        type=_image_digest_argument,
        default=None,
    )
    parser.add_argument("--fail-under-precision", type=float, required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if not 0.0 <= args.fail_under_precision <= 1.0:
        raise SystemExit("--fail-under-precision must be between 0 and 1")
    raw_case_data = args.cases.read_bytes()
    document = json.loads(
        raw_case_data.decode("utf-8"),
        object_pairs_hook=_reject_duplicate_keys,
        parse_constant=lambda value: (_ for _ in ()).throw(ValueError(value)),
    )
    selected_cases = select_evaluation_cases(
        document, os.environ.get("LIMA_CXX_EVALUATION_CASE_ID")
    )
    cache_dir = args.cache_dir.resolve()
    archive_dir = cache_dir / "archives"
    repositories_dir = cache_dir / "repositories"
    archive_dir.mkdir(parents=True, exist_ok=True)
    repositories_dir.mkdir(parents=True, exist_ok=True)
    analyzed: dict[tuple[str, str], dict[str, Any]] = {}
    for case in selected_cases:
        for revision in ("vulnerable", "fixed"):
            archive_info = case["archives"][revision]
            archive_path = download_verified_archive(
                archive_info["url"],
                archive_info["sha256"],
                archive_dir / f"{archive_info['sha256']}.tar.gz",
            )
            with tempfile.TemporaryDirectory(
                prefix=f"{case['id']}-{revision}-", dir=repositories_dir
            ) as temporary:
                extraction = Path(temporary) / "source"
                source_root = extract_verified_archive(
                    archive_path, archive_info["sha256"], extraction
                )
                repository_key = source_root.relative_to(repositories_dir).as_posix()
                analyzed[(case["id"], revision)] = _sidecar_result(
                    args.analyzer_url, repository_key, source_root
                )
    report = run_evaluation(selected_cases, lambda case, revision: analyzed[(case["id"], revision)])
    report = add_report_metadata(
        report,
        raw_case_data,
        analyzer_image_digest=args.analyzer_image_digest,
        analyzer_base_image_digest=args.analyzer_base_image_digest,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    print(VALIDITY_BOUNDARY)
    precision = report["precision"]
    return 0 if precision is not None and precision >= args.fail_under_precision else 2


if __name__ == "__main__":
    raise SystemExit(main())
