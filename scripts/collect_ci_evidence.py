"""Collect and verify one public LIMA CI attempt; GET only, without credentials.

Raw responses and report.json are saved in a new directory for offline replay.
This command does not rerun jobs or make a merge-readiness decision.
"""

from __future__ import annotations

import http.client
import json
import sys
import time
from collections.abc import Sequence
from contextlib import closing
from pathlib import Path

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scripts import verify_ci_evidence as verifier  # noqa: E402

WORKFLOW_PATH = ".github/workflows/ci.yml"
REQUEST_TIMEOUT = 15
COLLECTION_TIMEOUT = 120


def _download(url: str, remaining: int, deadline: float) -> bytes:
    # URLs are constructed below from validated repository/run/attempt integers.
    if not url.startswith("https://api.github.com/repos/"):
        raise verifier.EvidenceError("github-url-rejected", "collection")
    timeout = min(REQUEST_TIMEOUT, deadline - time.monotonic())
    if timeout <= 0:
        raise verifier.EvidenceError("collection-timeout", "collection")
    headers = {
        "Accept": "application/vnd.github+json", "User-Agent": "LIMA-ci-evidence",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    try:
        # Fixed HTTPS authority, default certificate validation, no redirect handling.
        with closing(http.client.HTTPSConnection("api.github.com", timeout=timeout)) as connection:
            connection.request("GET", url.removeprefix("https://api.github.com"), headers=headers)
            response = connection.getresponse()
            if 300 <= response.status < 400:
                raise verifier.EvidenceError("github-redirect-rejected", "collection")
            if response.status != 200:
                raise verifier.EvidenceError(f"github-http-{response.status}", "collection")
            raw = response.read(min(verifier.MAX_INPUT_BYTES, remaining) + 1)
    except verifier.EvidenceError:
        raise
    except (OSError, ValueError, http.client.HTTPException) as exc:
        raise verifier.EvidenceError("github-read-error", "collection") from exc
    if time.monotonic() > deadline:
        raise verifier.EvidenceError("collection-timeout", "collection")
    if len(raw) > min(verifier.MAX_INPUT_BYTES, remaining):
        raise verifier.EvidenceError("input-budget-exceeded", "collection")
    return raw


def collect_snapshot(expected: verifier.ExpectedRun, directory: Path) -> dict:
    """Collect bounded attempt-specific pages, then use the offline validator."""
    verifier._validate_expected(expected)
    # An existing directory is never reused, including after a partial collection.
    directory.mkdir()
    base = f"https://api.github.com/repos/{expected.repository}/actions/runs/{expected.run_id}"
    attempt_url = f"{base}/attempts/{expected.attempt}"
    deadline = time.monotonic() + COLLECTION_TIMEOUT
    remaining = verifier.MAX_TOTAL_BYTES
    sources = []

    def save(url: str, filename: str, label: str) -> object:
        nonlocal remaining
        raw = _download(url, remaining, deadline)
        path = directory / filename
        with path.open("xb") as handle:
            handle.write(raw)
        value, source, size = verifier._read_json(path, label, remaining)
        remaining -= size
        sources.append(source)
        return value

    run = save(attempt_url, "run.json", "run")
    # Reject wrong run identity/workflow before collecting any jobs.
    verifier.verify_snapshot(run, [{"total_count": 0, "jobs": []}], expected)
    verifier._match(run.get("path"), WORKFLOW_PATH, "run.path")
    pages = []
    for number in range(1, verifier.MAX_PAGES + 1):
        page = save(f"{attempt_url}/jobs?per_page=100&page={number}",
                    f"jobs-{number}.json", f"jobs[{number - 1}]")
        pages.append(page)
        report = verifier.verify_snapshot(run, pages, expected)
        if report["counts"]["total"] == report["declared_total"] or len(page["jobs"]) < 100:
            break
    report["source_sha256"] = sources
    report["collection"] = {"source": "public-github-rest", "workflow_path": WORKFLOW_PATH}
    with (directory / "report.json").open("x", encoding="utf-8", newline="\n") as handle:
        handle.write(json.dumps(report, ensure_ascii=False, indent=2) + "\n")
    return report


def main(argv: Sequence[str] | None = None) -> int:
    parser = verifier._Parser(description=__doc__)
    parser.add_argument("--repository", default="agent-sec-labs/LIMA")
    parser.add_argument("--run-id", required=True, type=int)
    parser.add_argument("--attempt", required=True, type=int)
    parser.add_argument("--head-sha", required=True)
    parser.add_argument("--event", required=True)
    parser.add_argument("--evidence-dir", required=True, type=Path)
    parser.add_argument("--required-job", action="append",
                        help="Complete required-name list; default: LIMA's aggregate merge-gate")
    try:
        args = parser.parse_args(argv)
        expected = verifier.ExpectedRun(args.repository, args.run_id, args.head_sha, args.event,
                                       args.attempt, tuple(args.required_job
                                                           or verifier.DEFAULT_REQUIRED_JOBS))
        report = collect_snapshot(expected, args.evidence_dir)
    except verifier.EvidenceError as exc:
        report = {"schema": "lima-ci-evidence-v1", "decision": "invalid",
                  "error": {"code": exc.code, "location": exc.location}}
    except (OSError, ValueError, RuntimeError):
        report = {"schema": "lima-ci-evidence-v1", "decision": "invalid",
                  "error": {"code": "collection-or-path-error", "location": "collection"}}
    sys.stdout.write(json.dumps(report, ensure_ascii=False, indent=2) + "\n")
    return verifier._EXIT_DECISIONS.index(report["decision"])


if __name__ == "__main__":
    raise SystemExit(main())
