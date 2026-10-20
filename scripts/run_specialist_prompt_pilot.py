"""Fixed-target A/B pilot using real provider traffic and the real ASan workbench.

No Scout/Discovery resampling, result cache, simulated findings or label input.
Default invocation prepares/fingerprints snapshots only; --execute calls services.
Resume skips completed records only after validating the immutable run identity.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
import sys
import time
from dataclasses import asdict
from pathlib import Path, PurePosixPath
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from lima import agent_orchestrator as orchestrator  # noqa: E402
from lima.agent_repro_tools import ReproWorkbench  # noqa: E402
from lima.agent_scout import ScoutTarget  # noqa: E402
from lima.config import Settings  # noqa: E402
from lima.cxx_agent_tools import CxxAgentBudget  # noqa: E402
from lima.cxx_memory import CxxMemoryAnalyzerClient  # noqa: E402
from lima.specialist_knowledge import build_specialist_prompt  # noqa: E402
from lima.uaf_orchestrator import UAF_FINDING_STATES  # noqa: E402
from lima.workspace import RepositoryWorkspace  # noqa: E402

SOURCE_PATH = "src/target.cpp"
TARGET = ScoutTarget("pilot-target", SOURCE_PATH, 10, "Inspect the public function and its resource accesses", "high")
MAX_CALLS = 12
MAX_BYTES = 1024 * 1024
TIMEOUT = 90
DEADLINE = 300


def write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2, default=str) + "\n", encoding="utf-8")


def _pairs() -> list[dict]:
    """Evaluator-owned labels and oracle drivers never enter model context.

    Oracle drivers always ``return 0``: the discriminator is ASan crash on
    the vulnerable revision versus a clean exit on the fixed revision, never
    the target's error-return value (a ``return fn(...)`` driver turns the
    fixed side's documented ``-1`` into exit code 255 and fails the clean-run
    criterion).  The cleanup and overflow pairs additionally defeat the
    pinned ``-O1`` dead-store elimination and malloc-to-alloca promotion:
    without an observable effect the buggy access never executes and the
    oracle silently stops discriminating.
    """
    fixture = ROOT / "tests/fixtures/platform_cases"
    cases = []
    for name, filename, cwe, decl, call in (
        ("uaf-direct", "buffer.cpp", "CWE-416", "int packet_size(void);", "packet_size();"),
    ):
        cases.append(dict(id=name, partition="development", expected_cwe=cwe,
                          knowledge_history="Existing synthetic regression fixture with a return-0 oracle driver; not an independent test set.",
                          oracle_driver=f"{decl} int main(){{ {call} return 0; }}",
                          **{rev: (fixture / name / rev / "src" / filename).read_text(encoding="utf-8")
                             for rev in ("vulnerable", "fixed")}))
    cases.append(dict(
        id="null-deref-direct", partition="development", expected_cwe="CWE-476",
        knowledge_history=("Adapted from the platform regression fixture for this pilot: at the pinned -O1 "
                           "flags LLVM exploits the unconditional load through a possibly-null pointer as "
                           "undefined behaviour and removes the crash entirely, so the pointee is volatile "
                           "and the dereference is a real load. Same defect, contract and trigger; "
                           "pilot-only adaptation, not model feedback."),
        oracle_driver="int session_id(int); int main(){ session_id(0); return 0; }",
        vulnerable="""#include <cstdlib>

struct Session {
    int id;
};

int session_id(int has_session) {
    volatile Session *s = 0;
    if (has_session) {
        s = (Session *)malloc(sizeof(Session));
    }
    return s->id;
}
""",
        fixed="""#include <cstdlib>

struct Session {
    int id;
};

int session_id(int has_session) {
    volatile Session *s = 0;
    if (has_session) {
        s = (Session *)malloc(sizeof(Session));
    }
    if (s == 0) {
        return -1;
    }
    return s->id;
}
"""))
    cases.append(dict(
        id="overflow-direct", partition="development", expected_cwe="CWE-787",
        knowledge_history=("Adapted from the platform regression fixture for this pilot: the original "
                           "write-only overflow is dead-store-eliminated at the pinned -O1 flags, so the "
                           "target now reads back the last written byte. Same defect class, boundary and "
                           "public contract; pilot-only adaptation, not model feedback."),
        oracle_driver="int frame_write(int); int main(){ frame_write(5); return 0; }",
        vulnerable="""#include <new>
// Public API: count is any int; writes are returned to the caller.
int frame_write(int count) {
    char *buf = new char[4];
    for (int i = 0; i < count; ++i) {
        buf[i] = (char)i;
    }
    char last = buf[count - 1];
    delete[] buf;
    return last;
}
""",
        fixed="""#include <new>
// Public API: count is any int; unsupported counts return -1.
int frame_write(int count) {
    if (count > 4 || count < 0) {
        return -1;
    }
    char *buf = new char[4];
    for (int i = 0; i < count; ++i) {
        buf[i] = (char)i;
    }
    char last = buf[count - 1];
    delete[] buf;
    return last;
}
"""))
    cases.append(dict(
        id="cleanup-release", partition="development", expected_cwe="CWE-415",
        knowledge_history=("New synthetic development pair; no model feedback used in its construction. "
                           "The volatile sink keeps the allocation from being promoted to an alloca at "
                           "-O1, which would delete both free() calls and the defect with them."),
        oracle_driver="int process_message(int); int main(){ process_message(1); return 0; }",
        vulnerable="""#include <cstdlib>
// Public API: fail is 0 or 1; this function owns and releases its buffer.
volatile void *g_sink;
int process_message(int fail) {
    void *buffer = malloc(16);
    if (!buffer) return -1;
    g_sink = buffer;
    if (fail) free(buffer);
    free(buffer);
    return 0;
}
""",
        fixed="""#include <cstdlib>
// Public API: fail is 0 or 1; this function owns and releases its buffer.
volatile void *g_sink;
int process_message(int fail) {
    void *buffer = malloc(16);
    if (!buffer) return -1;
    g_sink = buffer;
    if (fail) { free(buffer); return -1; }
    free(buffer);
    return 0;
}
"""))
    cases.append(dict(
        id="indexed-read", partition="holdout", expected_cwe="CWE-125",
        knowledge_history="New synthetic pair held out from prompt tuning in this pilot only.",
        oracle_driver="int read_slot(unsigned); int main(){ read_slot(4); return 0; }",
        vulnerable="""#include <cstdlib>
// Public API: arbitrary unsigned indices are accepted; errors return -1.
int read_slot(unsigned index) {
    volatile int *slots = (int *)malloc(4 * sizeof(int));
    if (!slots) return -1;
    for (unsigned k = 0; k < 4; ++k) slots[k] = 7;
    int value = slots[index];
    free((void *)slots);
    return value;
}
""",
        fixed="""#include <cstdlib>
// Public API: arbitrary unsigned indices are accepted; errors return -1.
int read_slot(unsigned index) {
    if (index >= 4) return -1;
    volatile int *slots = (int *)malloc(4 * sizeof(int));
    if (!slots) return -1;
    for (unsigned k = 0; k < 4; ++k) slots[k] = 7;
    int value = slots[index];
    free((void *)slots);
    return value;
}
"""))
    cases.append(dict(
        id="narrow-size", partition="holdout", expected_cwe="CWE-787",
        knowledge_history="New synthetic size-conversion pair held out from prompt tuning in this pilot only; ASan grades the write consequence, not CWE-190.",
        oracle_driver="int fill_records(unsigned); int main(){ fill_records(65); return 0; }",
        vulnerable="""#include <cstdlib>
#include <cstdint>
// Public API: count is any unsigned input; unsupported counts return -1.
int fill_records(unsigned count) {
    if (count > 255) return -1;
    uint8_t bytes = static_cast<uint8_t>(count * 4);
    volatile unsigned char *out = (unsigned char *)malloc(bytes);
    if (!out) return -1;
    for (unsigned k = 0; k < count * 4; ++k) out[k] = 1;
    free((void *)out);
    return 0;
}
""",
        fixed="""#include <cstdlib>
#include <cstdint>
// Public API: count is any unsigned input; unsupported counts return -1.
int fill_records(unsigned count) {
    if (count > 63) return -1;
    uint8_t bytes = static_cast<uint8_t>(count * 4);
    volatile unsigned char *out = (unsigned char *)malloc(bytes);
    if (!out) return -1;
    for (unsigned k = 0; k < count * 4; ++k) out[k] = 1;
    free((void *)out);
    return 0;
}
"""))
    return cases


def _repo_dir(snapshot_root: Path, repository_key: str) -> Path:
    """Local directory for one mount-relative repository key.

    Keys carry the snapshot root's directory name as a prefix so several
    frozen generations coexist under one container mount of the parent
    directory; locally every generation stays flat inside its own root.
    """

    return snapshot_root / PurePosixPath(repository_key).name


def prepare_snapshots(snapshot_root: Path) -> dict:
    snapshot_root.mkdir(parents=True, exist_ok=True)
    manifest_path = snapshot_root / "manifest.json"
    if manifest_path.exists():
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        verify_snapshots(snapshot_root, manifest)
        return manifest
    cases = []
    for index, pair in enumerate(_pairs()):
        case = {key: value for key, value in pair.items() if key not in {"vulnerable", "fixed"}}
        for revision in ("vulnerable", "fixed"):
            # Opaque keys and identical filenames; labels stay outside snapshots.
            dir_name = "p" + hashlib.sha256(f"pilot-v1:{index}:{revision}".encode()).hexdigest()[:16]
            key = f"{snapshot_root.name}/{dir_name}"
            root = _repo_dir(snapshot_root, key)
            source = root / SOURCE_PATH
            source.parent.mkdir(parents=True, exist_ok=True)
            if source.exists():
                raise ValueError("unmanifested snapshot already exists; use a fresh root")
            source.write_bytes(pair[revision].encode("utf-8"))
            write_json(root / "compile_commands.json", [{
                "directory": ".", "file": SOURCE_PATH,
                "arguments": ["clang++", "-std=c++14", "-c", SOURCE_PATH],
            }])
            inventory = RepositoryWorkspace(root).inventory()
            case[revision] = {"repository_key": key, "snapshot_hash": inventory.fingerprint(),
                              "files": {item.path: item.sha256 for item in inventory.files}}
        cases.append(case)
    manifest = {"schema_version": 1, "cases": cases, "labels_in_model_input": False,
                "scope": "synthetic fixed-target pilot; not production vulnerability detection"}
    write_json(manifest_path, manifest)
    return manifest


def verify_snapshots(root: Path, manifest: dict) -> None:
    expected_prefix = root.name + "/"
    for case in manifest["cases"]:
        for revision in ("vulnerable", "fixed"):
            item = case[revision]
            key = item.get("repository_key")
            if (
                not isinstance(key, str)
                or len(PurePosixPath(key).parts) != 2
                or not key.startswith(expected_prefix)
            ):
                raise ValueError(
                    "snapshot manifest repository key is missing the snapshot root prefix"
                )
            path = _repo_dir(root, item["repository_key"]).resolve()
            if not path.is_relative_to(root.resolve()):
                raise ValueError("snapshot path escapes root")
            if RepositoryWorkspace(path).inventory().fingerprint() != item["snapshot_hash"]:
                raise ValueError("snapshot changed since manifest freeze")


def target_context(root: Path) -> str:
    workspace = RepositoryWorkspace(root)
    return orchestrator.build_hypothesis_context(
        target_id=TARGET.lead_id, path=TARGET.path, line=TARGET.line,
        fact_lines=(), snippet=orchestrator._bounded_snippet(workspace, TARGET.path, TARGET.line),
        driver_contract=orchestrator._driver_contract(workspace, TARGET.path),
    )


def build_schedule(manifest: dict, *, repeats: int, partition: str) -> list[tuple]:
    if type(repeats) is not int or repeats < 1 or partition not in {"all", "development", "holdout"}:
        raise ValueError("invalid schedule")
    schedule = []
    for repeat in range(repeats):
        for case in manifest["cases"]:
            if partition != "all" and case["partition"] != partition:
                continue
            for revision in ("vulnerable", "fixed"):
                profiles = ("legacy", "structured") if repeat % 2 == 0 else ("structured", "legacy")
                schedule.extend((case["id"], revision, repeat, profile) for profile in profiles)
    return schedule


def replay_discriminates(positive: list[dict], negative: list[dict], cwe: str) -> bool:
    return len(positive) == len(negative) == 3 and all(
        orchestrator.experiment_matches_target(SimpleNamespace(**item), cwe,
                                               target_path=SOURCE_PATH, driver_paths=())
        for item in positive
    ) and all(item.get("stage") == "run" and item.get("ok") is True
              and item.get("exit_code") == 0 for item in negative)


def freeze_identity(output: Path, identity: dict) -> None:
    path = output / "identity.json"
    if path.exists() and json.loads(path.read_text(encoding="utf-8")) != identity:
        raise ValueError("run identity changed; use a fresh output directory")
    write_json(path, identity)


class RecordingWorkbench:
    def __init__(self, delegate):
        self.delegate = delegate
        self.observations = []

    def run_experiment(self, *args, **kwargs):
        observation = self.delegate.run_experiment(*args, **kwargs)
        self.observations.append(asdict(observation))
        return observation


def analyze_target(client, root: Path, item: dict, profile: str, llm_config: dict) -> dict:
    budget = CxxAgentBudget(max_calls=MAX_CALLS, max_output_bytes=MAX_BYTES)
    bench = RecordingWorkbench(ReproWorkbench(client, budget, TIMEOUT))
    prompt = build_specialist_prompt(profile=profile)
    wire_calls = []
    original_send = orchestrator.send_semantic_request

    def record_send(resolved, system, user, timeout, call_budget):
        call = {"system": system, "user": user, "timeout": timeout}
        wire_calls.append(call)
        raw = original_send(resolved, system, user, timeout, call_budget)
        call["raw_reply"] = raw
        return raw

    started = time.monotonic()
    specialist_calls, critic_calls, diagnostics = [0], [0], []
    result = {"prompt_sha256": prompt.sha256, "knowledge_ids": prompt.knowledge_ids,
              "prompt_chars": len(prompt.text), "manual_validity": "pending"}
    try:
        # A scoped observer around the REAL transport, used only by this sequential CLI.
        with patch.object(orchestrator, "send_semantic_request", record_send):
            finding = orchestrator._process_target(
                TARGET, workspace=RepositoryWorkspace(root), repository_key=item["repository_key"],
                snapshot_hash=item["snapshot_hash"], bundle=None, candidate=None,
                resolved_llm=llm_config, budget=budget, mode="required", dialogue_rounds=1,
                timeout=TIMEOUT, deadline=started + DEADLINE, source_mode="repository",
                repro_workbench=bench, tool_analysis=None, diagnostics=diagnostics,
                specialist_calls=specialist_calls, critic_calls=critic_calls, specialist_prompt=prompt,
            )
        result.update(status="completed", **asdict(finding))
    except Exception as exc:
        # Exception type is useful without persisting provider credentials or URLs.
        result.update(status="error", error_type=type(exc).__name__)
    remaining = budget.remaining()
    result.update(wire_calls=wire_calls, observations=bench.observations,
                  diagnostics=diagnostics, elapsed_seconds=time.monotonic() - started,
                  specialist_calls=specialist_calls[0], critic_calls=critic_calls[0],
                  total_budget_calls=MAX_CALLS - remaining.calls,
                  charged_bytes=MAX_BYTES - remaining.bytes_remaining)
    return result


def replay_driver(client, snapshot_root: Path, case: dict, driver: str, cwe: str) -> dict:
    budget = CxxAgentBudget(max_calls=6, max_output_bytes=MAX_BYTES)
    bench = ReproWorkbench(client, budget, TIMEOUT)
    observations = {}
    for revision in ("vulnerable", "fixed"):
        item = case[revision]
        observations[revision] = [asdict(bench.run_experiment(
            item["repository_key"], item["snapshot_hash"], (SOURCE_PATH,), driver,
        )) for _ in range(3)]
    return {"replay": observations, "replay_discriminates": replay_discriminates(
        observations["vulnerable"], observations["fixed"], cwe,
    )}


def summarize(records: list[dict]) -> dict:
    summary = {}
    for profile in ("legacy", "structured"):
        selected = [r for r in records if r["profile"] == profile]
        summary[profile] = {
            "attempts": len(selected),
            "positive_attempts": sum(r["revision"] == "vulnerable" for r in selected),
            "negative_attempts": sum(r["revision"] == "fixed" for r in selected),
            "errors": sum(r["status"] == "error" for r in selected),
            "negative_findings": sum(r["revision"] == "fixed" and r.get("state") in UAF_FINDING_STATES for r in selected),
            "runtime_confirmed": sum(r.get("state") == "runtime-confirmed" for r in selected),
            "raw_discriminations": sum(r.get("replay_discriminates") is True for r in selected),
            "reviewed_valid_discriminations": sum(r.get("replay_discriminates") is True and r.get("manual_validity") == "valid" for r in selected),
            "pending_manual_review": sum(r.get("manual_validity") == "pending" for r in selected),
        }
    return summary


def summarize_paired(records: list[dict], exclusions: dict[str, str]) -> dict:
    """Paired-comparison summary with whole cases removed from every denominator.

    A case whose negative revision is not a valid control (for example a
    contaminated fixed sample) must leave both sides of the paired metrics,
    not just the false-positive count. ``summary.json`` keeps the untouched
    full-sample statistics; this artifact carries the exclusions and their
    reasons so anyone can recompute both views from the records.
    """

    kept = [r for r in records if r["case_id"] not in exclusions]
    return {
        "schema_version": 1,
        "scope": "paired comparison; excluded cases removed from both revisions and all denominators",
        "excluded_cases": dict(exclusions),
        "records_total": len(records),
        "records_used": len(kept),
        "full_sample_summary_stays_in": "summary.json",
        "profiles": summarize(kept),
    }


def parse_exclusions(values: list[str]) -> dict[str, str]:
    """Parse repeated CASE_ID or CASE_ID=REASON arguments into an ordered map."""

    exclusions: dict[str, str] = {}
    for value in values:
        case_id, _, reason = value.partition("=")
        case_id = case_id.strip()
        if not case_id:
            raise ValueError("exclusions must be CASE_ID or CASE_ID=REASON")
        exclusions[case_id] = reason.strip() or "operator-excluded"
    return exclusions


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--snapshot-root", type=Path, default=ROOT / "output/specialist-pilot/snapshots")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--controls-only", action="store_true")
    parser.add_argument("--analyzer-url", default="http://127.0.0.1:18091")
    parser.add_argument("--provider-url")
    parser.add_argument("--model")
    parser.add_argument("--disable-thinking", action="store_true",
                        help="merge {'thinking': {'type': 'disabled'}} into request_params; "
                             "the local gateway caps any generation at 60s, which "
                             "reasoning-first models exceed on Specialist-sized replies")
    parser.add_argument("--partition", choices=("all", "development", "holdout"), default="all")
    parser.add_argument("--case-limit", type=int)
    parser.add_argument("--repeats", type=int, default=3)
    parser.add_argument("--summarize-existing", action="store_true",
                        help="recompute summary-paired.json from the records already in "
                             "--output; never touches records or summary.json, makes no "
                             "model or analyzer calls")
    parser.add_argument("--exclude-case", action="append", default=[], metavar="CASE_ID=REASON",
                        help="drop one whole case (both revisions, all denominators) from "
                             "the paired summary; repeatable; also applied to runs that "
                             "finish with --execute")
    args = parser.parse_args(argv)
    exclusions = parse_exclusions(args.exclude_case)
    if args.summarize_existing:
        records = [json.loads(p.read_text(encoding="utf-8"))
                   for p in sorted((args.output / "records").glob("*.json"))]
        paired = summarize_paired(records, exclusions)
        write_json(args.output / "summary-paired.json", paired)
        print(json.dumps({"records": paired["records_used"], "excluded": list(exclusions)}))
        return 0
    manifest = prepare_snapshots(args.snapshot_root)
    args.output.mkdir(parents=True, exist_ok=True)
    write_json(args.output / "cases.json", manifest)
    if not args.execute and not args.controls_only:
        print("Snapshots prepared; no model calls or experiments executed.")
        return 0
    client = CxxMemoryAnalyzerClient(args.analyzer_url, TIMEOUT, 8 * MAX_BYTES)
    health = asdict(client.health())
    if not health["landlock_available"] or not health["process_isolation_available"]:
        raise ValueError("sandbox unavailable; refusing execution")
    if args.controls_only:
        results = [{"case_id": c["id"], **replay_driver(client, args.snapshot_root, c,
                    c["oracle_driver"], c["expected_cwe"])} for c in manifest["cases"]]
        write_json(args.output / "controls.json", results)
        print(json.dumps({"controls_passed": sum(r["replay_discriminates"] for r in results), "total": len(results)}))
        return 0 if all(r["replay_discriminates"] for r in results) else 2
    config = Settings.from_env().resolved_llm()
    if args.provider_url:
        config["base_url"] = args.provider_url.rstrip("/")
    if args.model:
        config["model"] = args.model
    if args.disable_thinking:
        config["request_params"] = {"thinking": {"type": "disabled"}}
    if not config.get("model") or not config.get("base_url"):
        raise ValueError("real model configuration is required")
    public_config = {k: v for k, v in config.items() if k not in {"api_key", "headers"}}
    fingerprints = {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest() for name in (
        "scripts/run_specialist_prompt_pilot.py", "lima/specialist_knowledge.py",
        "lima/agent_orchestrator.py", "lima/agent_repro_tools.py", "lima/uaf_llm_branch.py",
    )}
    freeze_identity(args.output, dict(model=public_config, health=health, sources=fingerprints,
        git_head=subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
        snapshot_manifest_sha256=hashlib.sha256(json.dumps(manifest, sort_keys=True).encode()).hexdigest(),
        cache=False, max_calls=MAX_CALLS, max_bytes=MAX_BYTES, timeout=TIMEOUT, deadline=DEADLINE,
        dialogue_rounds=1, temperature=0, token_usage="unavailable; charged_bytes is a proxy"))
    cases = manifest["cases"][:args.case_limit] if args.case_limit else manifest["cases"]
    schedule = build_schedule({"cases": cases}, repeats=args.repeats, partition=args.partition)
    for case_id, revision, repeat, profile in schedule:
        path = args.output / "records" / f"{case_id}-{revision}-{repeat}-{profile}.json"
        if path.exists():
            continue
        case = next(c for c in cases if c["id"] == case_id)
        item = case[revision]
        record = analyze_target(client, _repo_dir(args.snapshot_root, item["repository_key"]), item, profile, config)
        record.update(case_id=case_id, revision=revision, repeat=repeat, profile=profile,
                      partition=case["partition"], snapshot_hash=item["snapshot_hash"])
        # Persist before replay so a failed control cannot erase a completed analysis.
        write_json(path, record)
        if revision == "vulnerable" and record.get("state") == "runtime-confirmed":
            record.update(replay_driver(client, args.snapshot_root, case,
                                        record["poc_driver_code"], record["cwe"]))
            write_json(path, record)
        records = [json.loads(p.read_text(encoding="utf-8")) for p in sorted((args.output / "records").glob("*.json"))]
        write_json(args.output / "summary.json", summarize(records))
        write_json(args.output / "summary-paired.json", summarize_paired(records, exclusions))
        print(json.dumps({"case": case_id, "revision": revision, "repeat": repeat,
                          "profile": profile, "status": record["status"], "state": record.get("state"),
                          "seconds": round(record["elapsed_seconds"], 1)}, ensure_ascii=False), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
