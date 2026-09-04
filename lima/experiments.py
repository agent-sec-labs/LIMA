"""Durable, restart-safe execution for repository-disjoint evaluations."""

from __future__ import annotations

import hashlib
import json
import os
import re
import time
import uuid
from pathlib import Path
from typing import Any, Callable

from .real_world_evaluation import analyzer_fingerprint, load_real_world_dataset
from .store import utc_now


EXPERIMENT_MODES = frozenset({"deterministic", "retrieval", "llm-retrieval"})
LLM_MODES = frozenset({"llm-retrieval"})
CASE_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
TERMINAL_STATES = frozenset({
    "SUCCEEDED", "SUCCEEDED_WITH_WARNINGS", "CANCELLED",
})
RESUMABLE_STATES = frozenset({
    "FAILED", "NEEDS_ATTENTION", "CANCELLED",
})


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _canonical_sha256(value: Any) -> str:
    rendered = json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return _sha256_bytes(rendered)


def _usage_from_case(case_result: dict) -> dict[str, int]:
    usage = {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0}
    llm = case_result.get("llm")
    if not isinstance(llm, dict):
        return usage
    for revision in ("vulnerable", "fixed"):
        raw = (llm.get(revision) or {}).get("usage") or {}
        for key in usage:
            usage[key] += int(raw.get(key, 0) or 0)
    return usage


def _llm_warning(case_result: dict) -> str:
    llm = case_result.get("llm")
    if not isinstance(llm, dict):
        return "llm-result-missing"
    for revision in ("vulnerable", "fixed"):
        response = llm.get(revision) or {}
        if response.get("status") != "completed":
            return "llm-provider-failure"
        if response.get("contract_valid") is not True:
            return "llm-contract-invalid"
    return ""


class ExperimentRunner:
    """Run one fixed case at a time and persist every boundary before continuing."""

    def __init__(
        self,
        store: Any,
        dataset_root: str | Path,
        artifact_root: str | Path,
        evaluator_factory: Callable[[str], Any],
        *,
        llm_available: bool = False,
        llm_identity: dict[str, str] | None = None,
        default_max_llm_calls: int = 20,
        default_max_total_tokens: int = 100_000,
        dataset_loader: Callable[[str | Path], dict] = load_real_world_dataset,
        analyzer_identity: Callable[[], str] = analyzer_fingerprint,
    ) -> None:
        self.store = store
        self.dataset_root = Path(dataset_root).expanduser().resolve()
        self.artifact_root = Path(artifact_root).expanduser().resolve()
        self.evaluator_factory = evaluator_factory
        self.llm_available = llm_available
        self.llm_identity = dict(llm_identity or {})
        self.default_max_llm_calls = default_max_llm_calls
        self.default_max_total_tokens = default_max_total_tokens
        self.dataset_loader = dataset_loader
        self.analyzer_identity = analyzer_identity

    def _dataset_path(self, name: str) -> Path:
        relative = Path(name)
        if relative.is_absolute() or relative.suffix.lower() != ".json":
            raise ValueError("experiment dataset must be a relative JSON path")
        target = (self.dataset_root / relative).resolve()
        try:
            target.relative_to(self.dataset_root)
        except ValueError as exc:
            raise ValueError("experiment dataset escapes the configured root") from exc
        if not target.is_file():
            raise ValueError("experiment dataset does not exist")
        return target

    def _run_dir(self, run_id: str) -> Path:
        try:
            normalized = str(uuid.UUID(run_id))
        except ValueError as exc:
            raise ValueError("invalid experiment id") from exc
        if normalized != run_id:
            raise ValueError("invalid experiment id")
        return self.artifact_root / run_id

    def catalog(self) -> list[dict[str, Any]]:
        """Return safe dataset metadata without exposing holdout case labels."""
        if not self.dataset_root.is_dir():
            return []
        datasets: list[dict[str, Any]] = []
        for candidate in sorted(self.dataset_root.rglob("*.json")):
            try:
                resolved = candidate.resolve()
                relative = resolved.relative_to(self.dataset_root)
                if not resolved.is_file():
                    continue
                dataset = self.dataset_loader(resolved)
                cases = list(dataset.get("cases") or [])
                case_ids = [str(item.get("id", "")) for item in cases]
                if (
                    not 1 <= len(cases) <= 50
                    or any(not CASE_ID_PATTERN.fullmatch(item) for item in case_ids)
                    or len(set(case_ids)) != len(case_ids)
                ):
                    continue
                modes = ["deterministic", "retrieval"]
                if self.llm_available:
                    modes.append("llm-retrieval")
                datasets.append({
                    "path": relative.as_posix(),
                    "name": str(dataset.get("name") or relative.stem),
                    "evaluation_role": str(
                        dataset.get("evaluation_role", "development")
                    ),
                    "case_count": len(cases),
                    "modes": modes,
                    "dataset_file_sha256": _sha256_bytes(resolved.read_bytes()),
                })
            except (OSError, TypeError, ValueError, KeyError, json.JSONDecodeError):
                # A malformed or escaping file is not a runnable dataset and must
                # not make the entire management surface unavailable.
                continue
        return datasets

    @staticmethod
    def _atomic_json(path: Path, value: Any) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_name(path.name + ".tmp")
        rendered = json.dumps(value, ensure_ascii=False, indent=2) + "\n"
        with temporary.open("w", encoding="utf-8", newline="\n") as handle:
            handle.write(rendered)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)

    @staticmethod
    def _atomic_text(path: Path, value: str) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_name(path.name + ".tmp")
        with temporary.open("w", encoding="utf-8", newline="\n") as handle:
            handle.write(value)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)

    @staticmethod
    def _append_event(run_dir: Path, event: dict) -> None:
        target = run_dir / "events.jsonl"
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open("a", encoding="utf-8", newline="\n") as handle:
            handle.write(json.dumps(event, ensure_ascii=False, sort_keys=True) + "\n")
            handle.flush()
            os.fsync(handle.fileno())

    def _event(
        self, run_dir: Path, state: str, message: str, **detail: Any,
    ) -> None:
        self._append_event(run_dir, {
            "created_at": utc_now(), "state": state,
            "message": message[:500], "detail": detail,
        })

    def _persist_state(
        self, run_id: str, state: str, progress: dict,
        *, error: str = "", result: dict | None = None,
    ) -> None:
        self.store.update_experiment(
            run_id, state, progress, error=error, result=result
        )
        self._atomic_json(self._run_dir(run_id) / "state.json", {
            "run_id": run_id,
            "state": state,
            "progress": progress,
            "error": error[:2000],
            "updated_at": utc_now(),
        })

    def create(
        self, dataset_name: str, mode: str, tenant_id: str = "default",
        *, max_llm_calls: int | None = None,
        max_total_tokens: int | None = None,
    ) -> dict:
        if mode not in EXPERIMENT_MODES:
            raise ValueError("unsupported experiment mode")
        if mode in LLM_MODES and not self.llm_available:
            raise ValueError("LLM experiment mode requires a configured provider")
        dataset_path = self._dataset_path(dataset_name)
        dataset = self.dataset_loader(dataset_path)
        cases = list(dataset.get("cases") or [])
        if not 1 <= len(cases) <= 50:
            raise ValueError("experiment dataset must contain between 1 and 50 cases")
        case_ids = [str(item.get("id", "")) for item in cases]
        if (
            any(not CASE_ID_PATTERN.fullmatch(item) for item in case_ids)
            or len(set(case_ids)) != len(case_ids)
        ):
            raise ValueError("experiment case ids must be path-safe and unique")

        call_budget = (
            self.default_max_llm_calls if max_llm_calls is None else int(max_llm_calls)
        )
        token_budget = (
            self.default_max_total_tokens
            if max_total_tokens is None else int(max_total_tokens)
        )
        if not 0 <= call_budget <= 200:
            raise ValueError("experiment LLM call budget must be between 0 and 200")
        if not 1 <= token_budget <= 10_000_000:
            raise ValueError("experiment token budget must be between 1 and 10000000")

        run_id = str(uuid.uuid4())
        run_dir = self._run_dir(run_id)
        run_dir.mkdir(parents=True, exist_ok=False)
        raw_dataset = dataset_path.read_bytes()
        manifest = {
            "schema_version": 1,
            "run_id": run_id,
            "created_at": utc_now(),
            "tenant_id": tenant_id,
            "mode": mode,
            "dataset_path": dataset_path.relative_to(self.dataset_root).as_posix(),
            "dataset_file_sha256": _sha256_bytes(raw_dataset),
            "dataset_cases_sha256": _canonical_sha256(cases),
            "dataset_name": str(dataset.get("name", "")),
            "evaluation_role": str(dataset.get("evaluation_role", "development")),
            "case_ids": case_ids,
            "analyzer_sha256": self.analyzer_identity(),
            "llm": self.llm_identity if mode in LLM_MODES else {},
            "budgets": {
                "max_llm_calls": call_budget,
                "max_total_tokens": token_budget,
            },
            "secret_persisted": False,
        }
        progress = {
            "total_cases": len(cases), "completed_cases": 0,
            "current_case": "", "llm_calls": 0,
            "prompt_tokens": 0, "completion_tokens": 0,
            "total_tokens": 0, "warnings": 0,
        }
        self._atomic_json(run_dir / "manifest.json", manifest)
        self._atomic_json(run_dir / "state.json", {
            "run_id": run_id, "state": "QUEUED", "progress": progress,
            "error": "", "updated_at": utc_now(),
        })
        self._event(run_dir, "QUEUED", "experiment created")
        return self.store.create_experiment({
            "id": run_id, "tenant_id": tenant_id, "state": "QUEUED",
            "mode": mode, "dataset_path": manifest["dataset_path"],
            "manifest": manifest, "progress": progress,
            "created_at": manifest["created_at"],
        })

    def _load_verified_dataset(self, record: dict) -> dict:
        manifest = record["manifest"]
        dataset_path = self._dataset_path(record["dataset_path"])
        if _sha256_bytes(dataset_path.read_bytes()) != manifest["dataset_file_sha256"]:
            raise ValueError("experiment dataset file changed after creation")
        dataset = self.dataset_loader(dataset_path)
        if _canonical_sha256(dataset["cases"]) != manifest["dataset_cases_sha256"]:
            raise ValueError("experiment dataset cases changed after creation")
        if self.analyzer_identity() != manifest["analyzer_sha256"]:
            raise ValueError("experiment analyzer changed after creation")
        return dataset

    @staticmethod
    def _completed_case_payloads(rows: list[dict]) -> dict[str, dict]:
        completed = {}
        for row in rows:
            if row["status"] not in {"COMPLETED", "COMPLETED_WITH_WARNINGS"}:
                continue
            wrapper = row.get("result") or {}
            case = wrapper.get("case")
            if isinstance(case, dict):
                completed[str(row["case_id"])] = case
        return completed

    @staticmethod
    def _progress_from_rows(total: int, rows: list[dict]) -> dict:
        completed_rows = [
            row for row in rows
            if row["status"] in {"COMPLETED", "COMPLETED_WITH_WARNINGS"}
            and isinstance((row.get("result") or {}).get("case"), dict)
        ]
        accounted_rows = [
            row for row in rows if isinstance(row.get("result"), dict)
        ]
        progress = {
            "total_cases": total,
            "completed_cases": len(completed_rows),
            "current_case": "",
            "llm_calls": sum(
                int((row.get("result") or {}).get("llm_calls", 0))
                for row in accounted_rows
            ),
            "prompt_tokens": 0,
            "completion_tokens": 0,
            "total_tokens": 0,
            "warnings": sum(row["status"] == "COMPLETED_WITH_WARNINGS" for row in completed_rows),
        }
        for row in accounted_rows:
            usage = (row.get("result") or {}).get("usage") or {}
            for key in ("prompt_tokens", "completion_tokens", "total_tokens"):
                progress[key] += int(usage.get(key, 0) or 0)
        return progress

    def run(self, run_id: str, *, allow_ambiguous_retry: bool = False) -> dict:
        record = self.store.get_experiment(run_id)
        if not record:
            raise ValueError("experiment not found")
        if record["state"] in TERMINAL_STATES:
            return record
        run_dir = self._run_dir(run_id)
        mode = record["mode"]
        rows = self.store.list_experiment_cases(run_id)
        ambiguous = [row for row in rows if row["status"] == "AMBIGUOUS"]
        if ambiguous and not allow_ambiguous_retry:
            progress = self._progress_from_rows(
                len(record["manifest"]["case_ids"]), rows
            )
            self._persist_state(
                run_id, "NEEDS_ATTENTION", progress,
                error="an LLM request may have completed before its result was persisted",
            )
            return self.store.get_experiment(run_id) or {}
        if allow_ambiguous_retry:
            for row in ambiguous:
                self.store.save_experiment_case(
                    run_id, row["case_id"], "resume", "PENDING",
                    attempt=int(row.get("attempt", 1)) + 1,
                )

        started = time.perf_counter()
        current_case = ""
        current_stage = "PREFLIGHT"
        try:
            dataset = self._load_verified_dataset(record)
            evaluator = self.evaluator_factory(mode)
            rows = self.store.list_experiment_cases(run_id)
            completed = self._completed_case_payloads(rows)
            progress = self._progress_from_rows(len(dataset["cases"]), rows)
            self._persist_state(run_id, "RUNNING", progress)
            self._event(run_dir, "RUNNING", "experiment worker started")

            for case in dataset["cases"]:
                case_id = str(case["id"])
                if case_id in completed:
                    continue
                latest = self.store.get_experiment(run_id)
                if latest and latest.get("cancel_requested"):
                    self._persist_state(run_id, "CANCELLED", progress)
                    self._event(run_dir, "CANCELLED", "cancellation acknowledged")
                    return self.store.get_experiment(run_id) or {}
                budgets = record["manifest"]["budgets"]
                if mode in LLM_MODES and progress["llm_calls"] + 2 > budgets["max_llm_calls"]:
                    self._persist_state(
                        run_id, "BUDGET_EXHAUSTED", progress,
                        error="LLM call budget exhausted before the next paired case",
                    )
                    self._event(run_dir, "BUDGET_EXHAUSTED", "LLM call budget reached")
                    return self.store.get_experiment(run_id) or {}
                if progress["total_tokens"] >= budgets["max_total_tokens"]:
                    self._persist_state(
                        run_id, "BUDGET_EXHAUSTED", progress,
                        error="token budget exhausted before the next paired case",
                    )
                    self._event(run_dir, "BUDGET_EXHAUSTED", "token budget reached")
                    return self.store.get_experiment(run_id) or {}

                previous = next((row for row in rows if row["case_id"] == case_id), None)
                attempt = int((previous or {}).get("attempt", 0)) + 1
                current_case = case_id
                progress["current_case"] = case_id
                singleton = {**dataset, "cases": [case]}
                case_dir = run_dir / "cases" / case_id

                current_stage = "FETCHING"
                self.store.save_experiment_case(
                    run_id, case_id, current_stage, "RUNNING", attempt=attempt
                )
                self._event(run_dir, current_stage, "acquiring pinned snapshots", case_id=case_id)
                fetched = evaluator.fetch(singleton)
                self._atomic_json(case_dir / "fetch.json", fetched)

                current_stage = "LLM_IN_FLIGHT" if mode in LLM_MODES else "EVALUATING"
                self.store.save_experiment_case(
                    run_id, case_id, current_stage, current_stage, attempt=attempt
                )
                self._event(run_dir, current_stage, "case evaluation started", case_id=case_id)
                partial = evaluator.run(singleton, mode=mode)
                if len(partial.get("cases") or []) != 1:
                    raise ValueError("case evaluator returned an invalid result count")
                case_result = partial["cases"][0]
                if str(case_result.get("id", "")) != case_id:
                    raise ValueError("case evaluator returned the wrong identity")
                usage = _usage_from_case(case_result)
                warning = _llm_warning(case_result) if mode in LLM_MODES else ""
                wrapper = {
                    "case": case_result,
                    "fetch": fetched,
                    "usage": usage,
                    "llm_calls": (
                        int(((previous or {}).get("result") or {}).get("llm_calls", 0))
                        + (2 if mode in LLM_MODES else 0)
                    ),
                    "warning": warning,
                    "completed_at": utc_now(),
                }
                status = "COMPLETED_WITH_WARNINGS" if warning else "COMPLETED"
                self._atomic_json(case_dir / "result.json", wrapper)
                self.store.save_experiment_case(
                    run_id, case_id, "COMPLETED", status,
                    attempt=attempt, result=wrapper,
                )
                completed[case_id] = case_result
                rows = self.store.list_experiment_cases(run_id)
                progress = self._progress_from_rows(len(dataset["cases"]), rows)
                self._persist_state(run_id, "RUNNING", progress)
                self._event(
                    run_dir, status, "case artifact committed",
                    case_id=case_id, total_tokens=usage["total_tokens"],
                )

            current_case = ""
            current_stage = "AGGREGATING"
            progress["current_case"] = ""
            self._persist_state(run_id, current_stage, progress)
            result = evaluator.run(
                dataset, mode=mode, completed_cases=completed
            )
            result["experiment"] = {
                "run_id": run_id,
                "analyzer_sha256": record["manifest"]["analyzer_sha256"],
                "dataset_file_sha256": record["manifest"]["dataset_file_sha256"],
                "duration_seconds": round(time.perf_counter() - started, 3),
                "progress": progress,
                "secret_persisted": False,
            }
            reports = run_dir / "reports"
            self._atomic_json(reports / "summary.json", result)
            self._atomic_text(
                reports / "summary.md",
                self._markdown_summary(record["manifest"], result),
            )
            final_state = (
                "SUCCEEDED_WITH_WARNINGS" if progress["warnings"] else "SUCCEEDED"
            )
            self._persist_state(run_id, final_state, progress, result=result)
            self._event(run_dir, final_state, "experiment completed")
            self._write_checksums(run_dir)
            self._atomic_json(run_dir / "COMPLETE.json", {
                "run_id": run_id, "state": final_state,
                "completed_at": utc_now(), "secret_persisted": False,
            })
            return self.store.get_experiment(run_id) or {}
        except Exception as exc:
            error = "%s: %s" % (exc.__class__.__name__, str(exc)[:1500])
            rows = self.store.list_experiment_cases(run_id)
            progress = self._progress_from_rows(
                len(record["manifest"]["case_ids"]), rows
            )
            progress["current_case"] = current_case
            if mode in LLM_MODES and current_stage == "LLM_IN_FLIGHT" and current_case:
                previous = next(
                    (row for row in rows if row["case_id"] == current_case), {}
                )
                self.store.save_experiment_case(
                    run_id, current_case, current_stage, "AMBIGUOUS",
                    attempt=int(previous.get("attempt", 1)),
                    result={
                        "llm_calls": 2, "usage": {}, "ambiguous": True,
                        "recorded_at": utc_now(),
                    },
                    error=error,
                )
                state = "NEEDS_ATTENTION"
                error = (
                    "an LLM request may have completed before persistence; "
                    "explicit retry approval is required"
                )
                rows = self.store.list_experiment_cases(run_id)
                progress = self._progress_from_rows(
                    len(record["manifest"]["case_ids"]), rows
                )
                progress["current_case"] = current_case
            else:
                if current_case:
                    previous = next(
                        (row for row in rows if row["case_id"] == current_case), {}
                    )
                    self.store.save_experiment_case(
                        run_id, current_case, current_stage, "FAILED",
                        attempt=int(previous.get("attempt", 1)), error=error,
                    )
                state = "FAILED"
            self._persist_state(run_id, state, progress, error=error)
            self._event(run_dir, state, error, case_id=current_case, stage=current_stage)
            return self.store.get_experiment(run_id) or {}

    def prepare_resume(
        self, run_id: str, tenant_id: str,
        *, allow_ambiguous_retry: bool = False,
    ) -> dict:
        record = self.store.get_experiment(run_id, tenant_id)
        if not record:
            raise ValueError("experiment not found")
        if record["state"] in {"SUCCEEDED", "SUCCEEDED_WITH_WARNINGS"}:
            return record
        if record["state"] == "BUDGET_EXHAUSTED":
            raise ValueError(
                "experiment budgets are immutable; create a new experiment with a higher budget"
            )
        if record["state"] not in RESUMABLE_STATES and record["state"] != "QUEUED":
            raise ValueError("experiment is already running")
        ambiguous = [
            row for row in record.get("cases", []) if row["status"] == "AMBIGUOUS"
        ]
        if ambiguous and not allow_ambiguous_retry:
            raise ValueError(
                "ambiguous LLM calls require explicit retry approval with "
                "allow_ambiguous_retry=true"
            )
        self.store.reset_experiment_cancel(run_id)
        self._persist_state(run_id, "QUEUED", record["progress"])
        self._event(
            self._run_dir(run_id), "QUEUED", "experiment resume requested",
            allow_ambiguous_retry=allow_ambiguous_retry,
        )
        return self.store.get_experiment(run_id, tenant_id) or {}

    def cancel(self, run_id: str, tenant_id: str) -> bool:
        return self.store.request_experiment_cancel(run_id, tenant_id)

    @staticmethod
    def _markdown_summary(manifest: dict, result: dict) -> str:
        metrics = result.get("metrics") or {}
        progress = (result.get("experiment") or {}).get("progress") or {}
        lines = [
            "# LIMA repository-disjoint experiment",
            "",
            "- Run: `%s`" % manifest["run_id"],
            "- Mode: `%s`" % manifest["mode"],
            "- Dataset SHA-256: `%s`" % manifest["dataset_file_sha256"],
            "- Analyzer SHA-256: `%s`" % manifest["analyzer_sha256"],
            "- Cases: %s" % metrics.get("cases", 0),
            "- LLM calls: %s" % progress.get("llm_calls", 0),
            "- Total tokens: %s" % progress.get("total_tokens", 0),
            "- Warnings: %s" % progress.get("warnings", 0),
            "",
            "The machine-readable source of truth is `reports/summary.json`.",
            "Zero findings are not an automatic safety proof.",
            "",
        ]
        return "\n".join(lines)

    @staticmethod
    def _write_checksums(run_dir: Path) -> None:
        files = sorted(
            item for item in run_dir.rglob("*")
            if item.is_file() and item.name not in {"checksums.sha256", "COMPLETE.json"}
        )
        lines = []
        for item in files:
            relative = item.relative_to(run_dir).as_posix()
            lines.append("%s  %s" % (_sha256_bytes(item.read_bytes()), relative))
        ExperimentRunner._atomic_text(
            run_dir / "checksums.sha256", "\n".join(lines) + "\n"
        )
