"""Bounded #264 offline rehearsal through the real repository service chain.

Only the chat transport is scripted. Import policy, scanner, queue, investigation
tools, merge and persisted report are real. No endpoint, credential or target
repository can be supplied to this command. Scripted tool choice is not evidence
that a real model chose a tool or discovered a vulnerability.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import socket
import tempfile
import time
from pathlib import Path
from unittest.mock import patch

from lima.config import Settings
from lima.service import ReviewService
from lima.workspace import RepositoryWorkspace

MODULE_PATH = "harbor/relay.py"
DYNAMIC_PATH = "harbor/compute.py"
MODULE_SAMPLE = {
    "harbor/__init__.py": "",
    MODULE_PATH: (
        "from external_relay import deliver\n\n\n"
        "def forward(message):\n    return deliver(message)\n"
    ),
}
DYNAMIC_SAMPLE = {
    "harbor/__init__.py": "",
    DYNAMIC_PATH: "def compute(expression):\n    return eval(expression)\n",
}
CASES = ("dynamic-observation", "module-discovery", "module-timeout", "dynamic-tool-error")
SOURCE_FILES = (
    "lima/repository_investigation.py",
    "lima/repository_scanner.py",
    "lima/service.py",
    "lima/workspace.py",
    "lima/models.py",
    "lima/runtime.py",
    "lima/reviewer.py",
    "lima/python_analyzer.py",
    "lima/evidence_privacy/port.py",
    "benchmarks/v4/preflight/investigation.py",
)


def runtime_sources() -> dict[str, str]:
    root = Path(__file__).resolve().parents[3]
    return {name: hashlib.sha256((root / name).read_bytes()).hexdigest() for name in SOURCE_FILES}


def fixture_snapshot(sample: dict[str, str]) -> str:
    """Mirror the public inventory fingerprint framing for these known fixtures."""
    digest = hashlib.sha256()
    for path, source in sorted(sample.items()):
        data = source.encode("utf-8")
        digest.update(
            (path + "\0" + str(len(data)) + "\0" + hashlib.sha256(data).hexdigest() + "\n").encode(
                "utf-8"
            )
        )
    return digest.hexdigest()


class OfflineTransport:
    def __init__(self, case: str):
        self.case = case
        self.transcript: list[dict] = []

    def __call__(
        self, provider, base_url, api_key, payload, timeout, extra_headers=None, max_bytes=None
    ):
        messages = payload["messages"]
        user = messages[-1]["content"]
        call = len(self.transcript)
        entry = {"messages": messages}
        self.transcript.append(entry)
        if self.case == "module-timeout":
            entry["error"] = "TimeoutError: offline scripted timeout"
            raise TimeoutError("offline scripted timeout")
        dynamic = self.case.startswith("dynamic-")
        path = DYNAMIC_PATH if dynamic else MODULE_PATH
        if call == 0:
            action = {
                "action": "tool",
                "tool": "read_source",
                "reason": "offline fixture read",
                "arguments": {"path": path, "start_line": 1, "end_line": 6},
            }
        elif dynamic and call == 1:
            sample = (
                "method-eval-vs-builtin"
                if self.case == "dynamic-observation"
                else "unknown-offline-sample"
            )
            action = {
                "action": "tool",
                "tool": "dynamic_contrast",
                "reason": "offline scripted choice",
                "arguments": {"sample_id": sample},
            }
        else:
            if call > 2:
                raise RuntimeError("offline script exceeded its bounded steps")
            if dynamic:
                matches = re.findall(r"CANDIDATE fingerprint=(\S+)\nFILE (\S+) LINE (\d+)", user)
                if not matches:
                    raise RuntimeError("expected a real scanner fingerprint in the prompt")
            else:
                matches = [("module-scope:" + path, path, "0")]
            results = [
                {
                    "fingerprint": fingerprint,
                    "path": file_path,
                    "line": int(line),
                    "verdict": "insufficient",
                    "reasoning": (
                        "Offline rehearsal only: synthetic contrast or unresolved import "
                        "cannot prove repository safety."
                    ),
                    "evidence_refs": ["read_source:" + path],
                    "evidence_basis": {
                        "syntax_hit": dynamic,
                        "model_reasoning": True,
                        "dynamic_observation": self.case == "dynamic-observation",
                    },
                    "confidence": 0.5,
                }
                for fingerprint, file_path, line in matches
            ]
            action = {"action": "final", "results": results, "new_targets": []}
            if not dynamic:
                action["new_targets"] = [
                    {
                        "path": path,
                        "line": 5,
                        "symbol": "forward",
                        "why": (
                            "deliver is imported from an unresolved module "
                            "and receives caller-supplied messages"
                        ),
                        "evidence_refs": ["read_source:" + path + ":1-6"],
                    }
                ]
        entry["action"] = action
        return {"content": json.dumps(action), "finish_reason": "stop", "usage": {}}


def _settings(root: Path) -> Settings:
    # Explicit construction avoids inheriting provider keys or live DB/queue URLs.
    return Settings(
        host="127.0.0.1",
        port=0,
        db_path=str(root / "tasks.sqlite3"),
        max_diff_bytes=200000,
        max_steps=5,
        timeout_seconds=30,
        llm_base_url="http://offline.invalid",
        llm_api_key="offline-placeholder",
        llm_model="scripted-offline",
        github_webhook_secret="",
        github_token="",
        auto_post_review=False,
        async_workers=1,
        memory_enabled=False,
        skills_dir=str(Path(__file__).resolve().parents[3] / "skills"),
        repository_import_root=str(root / "imports"),
        repository_cache_root=str(root / "cache"),
        repository_scan_sources="local-import",
        repository_scan_sast_mode="off",
        repository_scan_llm_mode="off",
        repository_investigation_mode="auto",
        repository_investigation_max_requests=4,
        repository_investigation_max_steps=4,
        repository_investigation_timeout_seconds=15,
    )


def validate_case(record: dict) -> None:
    """Check persisted outcomes and tool-to-next-prompt feedback, not fake answers."""
    case = record["case"]
    if (
        case not in CASES
        or record["mode"] != "scripted-offline"
        or record["real_model_requests"] != 0
    ):
        raise ValueError("invalid rehearsal mode or case")
    if not record["source_unchanged"] or record["network_attempts"]:
        raise ValueError("source mutation or network attempt")
    sample = DYNAMIC_SAMPLE if case.startswith("dynamic-") else MODULE_SAMPLE
    if record["fixture"] != sample or record["snapshot_digest"] != fixture_snapshot(sample):
        raise ValueError("fixture snapshot binding mismatch")
    if (
        record["acceptance_264_real_model"] != "not-demonstrated"
        or record["repository_code_executed"]
    ):
        raise ValueError("offline evidence was promoted or target code executed")
    report = record["report"]
    block = report["collaboration"]["investigation"]
    adjudication = report["adjudication"]
    decisions = adjudication["decisions"]
    if adjudication["overall_disposition"] == "clear":
        raise ValueError("offline probe must not clear an unresolved case")
    transcript = record["transcript"]
    if (
        not transcript
        or len(transcript) > 4
        or record["scripted_transport_calls"] != len(transcript)
    ):
        raise ValueError("missing or excessive transport calls")
    if record["reserved_budget_requests"] != len(transcript):
        raise ValueError("production request budget differs from offline attempts")
    # The production usage face counts returned responses, not failed attempts.
    successful_responses = sum("action" in entry for entry in transcript)
    if block["usage"]["requests"] != successful_responses:
        raise ValueError("production response count differs from offline transport")
    if case == "module-timeout":
        if (
            report["findings"]
            or report["risk"] != "low"
            or adjudication["overall_disposition"] != "needs_review"
        ):
            raise ValueError("module failure lost its separate risk/review dimensions")
        if block["statuses"].get("module-scope:" + MODULE_PATH, {}).get("status") != "failed":
            raise ValueError("module timeout was not persisted as failed")
    elif case == "module-discovery":
        discoveries = [f for f in report["findings"] if f["rule_id"] == "AGENT-DISCOVERY"]
        if (
            len(discoveries) != 1
            or len(report["findings"]) != 1
            or len(decisions) != 2
            or report["risk"] != "high"
        ):
            raise ValueError("zero-static discovery did not propagate to report risk")
        finding = discoveries[0]
        if (
            finding["path"] != MODULE_PATH
            or finding["line"] != 5
            or finding["verification_state"] != "candidate"
        ):
            raise ValueError("discovery source binding or candidate state lost")
        decision = next(d for d in decisions if d["fingerprint"] == finding["fingerprint"])
        if decision["disposition"] != "needs_review" or not decision.get(
            "investigation_evidence_refs"
        ):
            raise ValueError("candidate review/evidence missing")
    else:
        if not report["findings"] or not all(
            d.get("investigation_verdict") == "insufficient" for d in decisions
        ):
            raise ValueError("static candidates were dropped or falsely resolved")
        feedback = transcript[-1]["messages"][-1]["content"]
        if "PREVIOUS TOOL OBSERVATIONS" not in feedback or "dynamic_contrast" not in feedback:
            raise ValueError("tool observation did not feed the next production prompt")
        marker = (
            "method-eval-vs-builtin"
            if case == "dynamic-observation"
            else "unknown dynamic contrast sample id"
        )
        if marker not in feedback or block["dynamic_observations"] != 1:
            raise ValueError("dynamic success/error observation was not retained")
        if case == "dynamic-observation":
            observation = re.search(r"dynamic_contrast -> (\{[^\n]+\})", feedback)
            value = json.loads(observation.group(1)) if observation else {}
            if (
                value.get("ok") is not True
                or value.get("returncode") != 0
                or not value.get("stdout")
            ):
                raise ValueError("canned dynamic tool did not actually complete")


def run_case(case: str) -> dict:
    if case not in CASES:
        raise ValueError("unknown offline case")
    sample = DYNAMIC_SAMPLE if case.startswith("dynamic-") else MODULE_SAMPLE
    transport = OfflineTransport(case)
    network_attempts: list[str] = []

    def deny_network(*args, **kwargs):
        network_attempts.append("blocked-connect")
        raise RuntimeError("network is disabled for offline rehearsal")

    with tempfile.TemporaryDirectory(prefix="lima-investigation-preflight-") as directory:
        root = Path(directory)
        repo = root / "imports" / "sample"
        for path, source in sample.items():
            target = repo / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(source.encode("utf-8"))
        before = RepositoryWorkspace(repo).inventory().fingerprint()
        with (
            patch("lima.reviewer.post_chat_completion_full", new=transport),
            patch.object(socket.socket, "connect", new=deny_network),
            patch.object(socket, "create_connection", new=deny_network),
        ):
            service = ReviewService(_settings(root))
            try:
                created = service.enqueue_repository_scan(
                    "sample",
                    "offline",
                    investigate_paths=None if case.startswith("dynamic-") else [MODULE_PATH],
                )
                deadline = time.monotonic() + 30
                task = {}
                while time.monotonic() < deadline:
                    task = service.store.get(created["task_id"], "offline") or {}
                    if task.get("state") in {"SUCCESS", "FAILED"}:
                        break
                    time.sleep(0.01)
                reserved = service.repository_investigation.client.budget.spent
            finally:
                service.queue.close()
        if task.get("state") != "SUCCESS":
            raise RuntimeError(
                "offline service scan failed: " + str(task.get("error", task.get("state")))
            )
        record = {
            "case": case,
            "mode": "scripted-offline",
            "real_model_requests": 0,
            "scripted_transport_calls": len(transport.transcript),
            "reserved_budget_requests": reserved,
            "network_attempts": network_attempts,
            "repository_code_executed": False,
            "snapshot_digest": before,
            "source_unchanged": before == RepositoryWorkspace(repo).inventory().fingerprint(),
            "fixture": sample,
            "transcript": transport.transcript,
            "report": task["report"],
            "acceptance_264_real_model": "not-demonstrated",
        }
        validate_case(record)
        return record


def write_bundle(directory: Path) -> dict:
    # Require a new directory: keep failed or previous runs available for review.
    directory.mkdir(parents=True, exist_ok=False)
    hashes = {}
    for case in CASES:
        record = run_case(case)
        data = (json.dumps(record, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode(
            "utf-8"
        )
        name = case + ".json"
        (directory / name).write_bytes(data)
        hashes[name] = hashlib.sha256(data).hexdigest()
    manifest = {
        "schema": "lima.offline-investigation-preflight.v1",
        "mode": "scripted-offline",
        "real_model_requests": 0,
        "acceptance_264_real_model": "not-demonstrated",
        "runtime_sources": runtime_sources(),
        "files": hashes,
    }
    (directory / "manifest.json").write_text(
        json.dumps(manifest, indent=2) + "\n", encoding="utf-8"
    )
    validate_bundle(directory)
    return manifest


def validate_bundle(directory: Path) -> dict:
    manifest = json.loads((directory / "manifest.json").read_text(encoding="utf-8"))
    expected = {case + ".json" for case in CASES}
    if (
        manifest.get("schema") != "lima.offline-investigation-preflight.v1"
        or manifest.get("mode") != "scripted-offline"
        or manifest.get("real_model_requests") != 0
        or manifest.get("acceptance_264_real_model") != "not-demonstrated"
        or manifest.get("runtime_sources") != runtime_sources()
        or set(manifest.get("files", {})) != expected
    ):
        raise ValueError("invalid offline manifest")
    for name, expected_hash in manifest["files"].items():
        data = (directory / name).read_bytes()
        if hashlib.sha256(data).hexdigest() != expected_hash:
            raise ValueError("artifact digest mismatch: " + name)
        record = json.loads(data)
        if record.get("case") + ".json" != name:
            raise ValueError("artifact case mismatch")
        validate_case(record)
    return manifest


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--output", type=Path)
    group.add_argument("--verify", type=Path)
    args = parser.parse_args(argv)
    validate_bundle(args.verify) if args.verify else write_bundle(args.output)
    print("PASS: four offline service-chain probes; real-model acceptance not demonstrated")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
