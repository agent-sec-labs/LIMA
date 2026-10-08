"""Verify local GitHub Actions attempt snapshots without network or repository writes.

The result covers supplied evidence only. It is never a merge authorization or
proof of remote freshness, checkout lineage, or runtime/model verification.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import stat
import sys
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

MAX_INPUT_BYTES = 8 * 1024 * 1024
MAX_TOTAL_BYTES = 32 * 1024 * 1024
MAX_PAGES = 100
MAX_JOBS = 10_000
_CONCLUSIONS = frozenset({
    "success", "failure", "neutral", "cancelled", "skipped", "timed_out",
    "action_required", "stale", "startup_failure",
})
_PENDING = frozenset({"queued", "in_progress", "waiting", "requested", "pending"})
# Tuple position is the CLI exit code; these are decision labels, not credentials.
_EXIT_DECISIONS = ("pass", "fail", "invalid", "incomplete")


class EvidenceError(ValueError):
    """A value-free diagnostic: only a fixed code and structural location."""

    def __init__(self, code: str, location: str) -> None:
        super().__init__(f"{code}: {location}")
        self.code = code
        self.location = location


@dataclass(frozen=True)
class ExpectedRun:
    repository: str
    run_id: int
    head_sha: str
    event: str
    attempt: int
    required_jobs: tuple[str, ...]


def _object(value: object, location: str) -> dict:
    if not isinstance(value, dict):
        raise EvidenceError("expected-object", location)
    return value


def _integer(value: object, location: str, minimum: int = 1) -> int:
    if type(value) is not int or value < minimum:
        raise EvidenceError("expected-integer", location)
    return value


def _name(value: object, location: str) -> str:
    if (not isinstance(value, str) or not 1 <= len(value) <= 256
            or not value.isprintable() or value.strip() != value):
        raise EvidenceError("invalid-name", location)
    return value


def _match(value: object, expected: object, location: str, *, fold: bool = False) -> None:
    if fold and isinstance(value, str) and isinstance(expected, str):
        matches = value.casefold() == expected.casefold()
    else:
        matches = type(value) is type(expected) and value == expected
    if not matches:
        raise EvidenceError("binding-mismatch", location)


def _state(obj: dict, location: str) -> str:
    if "conclusion" not in obj:
        raise EvidenceError("missing-conclusion", location)
    status, conclusion = obj.get("status"), obj.get("conclusion")
    if not isinstance(status, str) or status not in _PENDING | {"completed"}:
        raise EvidenceError("invalid-status", location)
    if status == "completed":
        if not isinstance(conclusion, str) or conclusion not in _CONCLUSIONS:
            raise EvidenceError("invalid-conclusion", location)
        return "success" if conclusion == "success" else "failed"
    if conclusion is not None:
        raise EvidenceError("status-conclusion-conflict", location)
    return "pending"


def _validate_expected(expected: ExpectedRun) -> None:
    if (not isinstance(expected.repository, str)
            or not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", expected.repository)
            or any(part in {".", ".."} for part in expected.repository.split("/"))):
        raise EvidenceError("invalid-repository", "expected.repository")
    _integer(expected.run_id, "expected.run_id")
    _integer(expected.attempt, "expected.attempt")
    if (not isinstance(expected.head_sha, str)
            or not re.fullmatch(r"[0-9a-f]{40}", expected.head_sha)):
        raise EvidenceError("invalid-sha", "expected.head_sha")
    if (not isinstance(expected.event, str)
            or not re.fullmatch(r"[a-z][a-z0-9_]{0,63}", expected.event)):
        raise EvidenceError("invalid-event", "expected.event")
    if (not isinstance(expected.required_jobs, tuple)
            or not 1 <= len(expected.required_jobs) <= MAX_JOBS):
        raise EvidenceError("invalid-required-jobs", "expected.required_jobs")
    seen = set()
    for index, name in enumerate(expected.required_jobs):
        _name(name, f"expected.required_jobs[{index}]")
        if name in seen:
            raise EvidenceError("duplicate-required-job", "expected.required_jobs")
        seen.add(name)
    if "merge-gate" not in seen:
        raise EvidenceError("merge-gate-required", "expected.required_jobs")


def verify_snapshot(run: object, job_pages: Sequence[object], expected: ExpectedRun) -> dict:
    """Bind, validate and summarize one attempt; never infer missing identifiers."""
    _validate_expected(expected)
    run = _object(run, "run")
    api_url = f"https://api.github.com/repos/{expected.repository}/actions/runs/{expected.run_id}"
    _match(run.get("id"), expected.run_id, "run.id")
    _match(run.get("run_attempt"), expected.attempt, "run.run_attempt")
    _match(run.get("head_sha"), expected.head_sha, "run.head_sha")
    _match(run.get("event"), expected.event, "run.event")
    repository = _object(run.get("repository"), "run.repository")
    _match(repository.get("full_name"), expected.repository, "run.repository.full_name", fold=True)
    _match(run.get("url"), api_url, "run.url", fold=True)
    run_state = _state(run, "run")
    if (not isinstance(job_pages, (list, tuple)) or not 1 <= len(job_pages) <= MAX_PAGES):
        raise EvidenceError("invalid-page-count", "jobs")

    total_count: int | None = None
    seen_ids, seen_names = set(), set()
    counts = {"total": 0, "success": 0, "failed": 0, "pending": 0}
    normalized_jobs = []
    for page_index, page in enumerate(job_pages):
        page_location = f"jobs[{page_index}]"
        page = _object(page, page_location)
        count = _integer(page.get("total_count"), f"{page_location}.total_count", 0)
        if count > MAX_JOBS:
            raise EvidenceError("job-budget-exceeded", page_location)
        if total_count is None:
            total_count = count
        elif count != total_count:
            raise EvidenceError("page-total-conflict", page_location)
        jobs = page.get("jobs")
        if not isinstance(jobs, list):
            raise EvidenceError("expected-array", f"{page_location}.jobs")
        if len(jobs) > MAX_JOBS - counts["total"]:
            raise EvidenceError("job-budget-exceeded", page_location)
        for index, job in enumerate(jobs):
            location = f"{page_location}.jobs[{index}]"
            job = _object(job, location)
            job_id = _integer(job.get("id"), f"{location}.id")
            name = _name(job.get("name"), f"{location}.name")
            if job_id in seen_ids or name in seen_names:
                raise EvidenceError("duplicate-job", location)
            seen_ids.add(job_id)
            seen_names.add(name)
            for key, value in (("run_id", expected.run_id), ("run_attempt", expected.attempt),
                               ("head_sha", expected.head_sha)):
                _match(job.get(key), value, f"{location}.{key}")
            _match(job.get("run_url"), api_url, f"{location}.run_url", fold=True)
            state = _state(job, location)
            counts["total"] += 1
            counts[state] += 1
            normalized_jobs.append({
                "id": job_id, "name": name, "status": job["status"],
                "conclusion": job.get("conclusion"), "head_sha": expected.head_sha,
                "run_id": expected.run_id, "attempt": expected.attempt,
                "url": f"https://github.com/{expected.repository}/actions/runs/"
                       f"{expected.run_id}/job/{job_id}",
            })
    if counts["total"] > total_count:
        raise EvidenceError("page-total-overflow", "jobs")
    missing = sorted(set(expected.required_jobs) - seen_names)
    reasons = []
    if counts["total"] != total_count:
        reasons.append("pagination-incomplete")
    if missing:
        reasons.append("required-jobs-missing")
    if counts["pending"] or run_state == "pending":
        reasons.append("execution-incomplete")
    if counts["failed"]:
        reasons.append("jobs-not-successful")
    if run_state == "failed":
        reasons.append("run-not-successful")
    gaps = {"pagination-incomplete", "required-jobs-missing", "execution-incomplete"}
    decision = "incomplete" if gaps.intersection(reasons) else "fail" if reasons else "pass"
    normalized_jobs.sort(key=lambda job: (job["name"], job["id"]))
    return {
        "schema": "lima-ci-evidence-v1", "scope": "offline-workflow-attempt-snapshot",
        "decision": decision,
        "identity": {
            "repository": expected.repository, "run_id": expected.run_id,
            "head_sha": expected.head_sha, "event": expected.event, "attempt": expected.attempt,
            "url": f"https://github.com/{expected.repository}/actions/runs/{expected.run_id}"
                   f"/attempts/{expected.attempt}",
        },
        "run": {"status": run["status"], "conclusion": run.get("conclusion")},
        "counts": counts, "declared_total": total_count, "reasons": reasons,
        "required_jobs": sorted(expected.required_jobs), "missing_required_jobs": missing,
        "failed_jobs": [job["name"] for job in normalized_jobs
                        if job["status"] == "completed" and job["conclusion"] != "success"],
        "jobs": normalized_jobs,
        "limitations": [
            "Supplied local files are not authenticated; digests bind bytes only.",
            "Remote freshness, rules, reviews and merge readiness are not evaluated.",
            "Run head SHA does not prove the actual checkout or merge/base lineage.",
            "CI success does not prove security conclusions or real-model acceptance.",
        ],
    }


def _unique_object(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise EvidenceError("duplicate-json-key", "input")
        result[key] = value
    return result


def _reject_constant(_value: str) -> None:
    raise EvidenceError("nonfinite-json", "input")


def _read_json(path: Path, label: str, remaining: int) -> tuple[object, dict, int]:
    try:
        if not stat.S_ISREG(path.stat().st_mode):
            raise EvidenceError("input-not-regular-file", label)
        with path.open("rb") as handle:
            raw = handle.read(min(MAX_INPUT_BYTES, remaining) + 1)
    except OSError as exc:
        raise EvidenceError("input-read-error", label) from exc
    if len(raw) > min(MAX_INPUT_BYTES, remaining):
        raise EvidenceError("input-budget-exceeded", label)
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_object,
                           parse_constant=_reject_constant)
    except EvidenceError as exc:
        raise EvidenceError(exc.code, label) from exc
    except (UnicodeError, ValueError, RecursionError) as exc:
        raise EvidenceError("invalid-json", label) from exc
    source = {"source": label, "sha256": hashlib.sha256(raw).hexdigest(), "bytes": len(raw)}
    return value, source, len(raw)


class _Parser(argparse.ArgumentParser):
    def error(self, _message: str) -> None:
        raise EvidenceError("usage-error", "arguments")


def main(argv: Sequence[str] | None = None) -> int:
    parser = _Parser(description=__doc__)
    parser.add_argument("--run", required=True, type=Path)
    parser.add_argument("--jobs", required=True, action="append", type=Path)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--run-id", required=True, type=int)
    parser.add_argument("--head-sha", required=True)
    parser.add_argument("--event", required=True)
    parser.add_argument("--attempt", required=True, type=int)
    parser.add_argument("--required-job", required=True, action="append")
    parser.add_argument("--output", type=Path)
    try:
        args = parser.parse_args(argv)
        expected = ExpectedRun(args.repository, args.run_id, args.head_sha, args.event,
                               args.attempt, tuple(args.required_job))
        _validate_expected(expected)
        if len(args.jobs) > MAX_PAGES:
            raise EvidenceError("invalid-page-count", "jobs")
        inputs = [args.run, *args.jobs]
        if args.output is not None and args.output.resolve() in {path.resolve() for path in inputs}:
            raise EvidenceError("output-is-input", "output")
        sources, pages = [], []
        remaining = MAX_TOTAL_BYTES
        run, source, size = _read_json(args.run, "run", remaining)
        sources.append(source)
        remaining -= size
        for index, path in enumerate(args.jobs):
            page, source, size = _read_json(path, f"jobs[{index}]", remaining)
            pages.append(page)
            sources.append(source)
            remaining -= size
        report = verify_snapshot(run, pages, expected)
        report["source_sha256"] = sources
        rendered = json.dumps(report, ensure_ascii=False, indent=2) + "\n"
        if args.output is not None:
            try:
                with args.output.open("x", encoding="utf-8", newline="\n") as handle:
                    handle.write(rendered)
            except OSError as exc:
                raise EvidenceError("output-create-error", "output") from exc
    except EvidenceError as exc:
        report = {"schema": "lima-ci-evidence-v1", "decision": "invalid",
                  "error": {"code": exc.code, "location": exc.location}}
        rendered = json.dumps(report, indent=2) + "\n"
    except (OSError, ValueError, RuntimeError) as exc:
        # Path resolution and parameter conversion errors must not echo caller values.
        report = {"schema": "lima-ci-evidence-v1", "decision": "invalid",
                  "error": {"code": "input-or-path-error", "location": "arguments"}}
        rendered = json.dumps(report, indent=2) + "\n"
        del exc
    sys.stdout.write(rendered)
    return _EXIT_DECISIONS.index(report["decision"])


if __name__ == "__main__":
    raise SystemExit(main())
