import hashlib
import re
import uuid
from typing import Any, Dict, Optional

from .agents import MultiAgentCoordinator
from .auth import AuthManager
from .config import Settings
from .context_manager import ContextManager
from .evolution import EvolutionEngine
from .fixer import SafeFixer
from .github import GitHubAppAuthenticator, GitHubClient
from .harness import ReviewHarness
from .metrics import metrics
from .memory import MemoryManager
from .models import TaskState, TraceEvent
from .observability import AlertManager, Observability
from .postgres_store import create_store
from .report import to_markdown
from .reviewer import (
    OpenAICompatibleReviewer, ReliabilityRuleReviewer, SecurityRuleReviewer,
)
from .diff_parser import parse_unified_diff
from .skills import SkillRegistry
from .skill_evolution import DeclarativeSkillReviewer, SkillEvolutionEngine
from .store import utc_now
from .task_queue import PermanentTaskError, TaskQueue
from .rollout import ReleaseManager
from .verifier import RepairVerifier
from .repository_import import RepositoryImportPolicy
from .repository_scanner import RepositoryScanner
from .repository_triage import (
    RepositorySemanticTriage,
    RepositorySemanticTriageError,
)
from .experiments import ExperimentRunner, LLM_MODES
from .repair_preview import RepositoryRepairPreviewer
from .real_world_evaluation import (
    LLMSecurityTriageClient,
    RealWorldSecurityEvaluator,
    SnapshotStore,
)
from .workspace import RepositoryWorkspace


class ReviewService:
    def __init__(self, settings: Settings):
        self.settings = settings
        settings.validate_evolution()
        self.llm_config = settings.resolved_llm()
        if settings.repository_scan_llm_mode == "required" and not self.llm_config:
            raise ValueError(
                "required repository semantic triage needs an LLM provider"
            )
        self.store = create_store(settings.database_url, settings.db_path)
        self.context_manager = ContextManager(
            settings.context_max_tokens, settings.context_reserved_tokens
        )
        self.memory = MemoryManager(
            self.store, settings.memory_enabled, settings.memory_recall_limit,
            settings.memory_working_ttl_seconds,
        )
        self.observability = Observability(settings.otel_service_name, settings.otel_endpoint)
        self.registry = SkillRegistry(
            settings.skills_dir, settings.skill_sandbox, settings.skill_timeout_seconds,
            settings.skill_memory_mb, settings.skill_signing_key,
            settings.skill_container_image,
        )
        self.registry.register(
            "security-review", SecurityRuleReviewer(),
            "1.0.0", "Security, injection and secret detection",
        )
        self.registry.register(
            "reliability-review", ReliabilityRuleReviewer(),
            "1.0.0", "Reliability and observability review",
        )
        if self.llm_config:
            active = self.store.get_active_skill_version("llm-review")
            self.registry.register(
                "llm-review",
                self._build_llm_reviewer(active["prompt"] if active else ""),
                "1.0.0", "Context-aware AI code review via %s" % self.llm_config["provider"],
            )
        self.registry.reload()
        coordinator = self._build_coordinator(self.registry.reviewers())
        self.reviewer = coordinator
        self.harness = ReviewHarness(
            self.store, self.reviewer, settings.max_steps, settings.timeout_seconds,
            observability=self.observability,
        )
        self.github = GitHubClient(settings.github_token)
        self.fixer = SafeFixer(RepairVerifier(
            settings.repair_test_command, settings.repair_verify_timeout_seconds
        ))
        self.repair_previewer = RepositoryRepairPreviewer(self.fixer)
        self.auth = AuthManager(
            self.store, settings.auth_secret, settings.session_ttl_seconds,
            settings.bootstrap_admin_username, settings.bootstrap_admin_password,
            settings.default_tenant_id,
        )
        self.releases = ReleaseManager(self.store)
        self.alerts = AlertManager(
            self.store, settings.alert_failure_rate, settings.alert_min_samples
        )
        self.evolution = EvolutionEngine(
            self.store,
            reviewer_factory=self._build_llm_reviewer if self.llm_config else None,
            min_cases=settings.eval_min_cases,
            max_cases=settings.eval_max_cases,
            min_improvement=settings.eval_min_improvement,
            min_holdout_cases=settings.eval_min_holdout_cases,
            max_metric_regression=settings.eval_max_metric_regression,
        )
        self.skill_evolution = SkillEvolutionEngine(
            self.store,
            min_cases=settings.eval_min_cases,
            max_cases=settings.eval_max_cases,
            min_improvement=settings.eval_min_improvement,
            min_holdout_cases=settings.eval_min_holdout_cases,
            max_metric_regression=settings.eval_max_metric_regression,
        )
        self.repository_import = RepositoryImportPolicy(
            settings.repository_import_root
        )
        self.repository_scanner = RepositoryScanner(
            sast_mode=settings.repository_scan_sast_mode
        )
        self.repository_semantic_triage = self._build_repository_semantic_triage()
        self.experiment_runner = ExperimentRunner(
            self.store,
            settings.experiment_dataset_root,
            settings.experiment_artifact_root,
            self._build_experiment_evaluator,
            llm_available=bool(self.llm_config),
            llm_identity={
                "provider": str(self.llm_config.get("provider", "")),
                "model": str(self.llm_config.get("model", "")),
            },
            default_max_llm_calls=settings.experiment_max_llm_calls,
            default_max_total_tokens=settings.experiment_max_total_tokens,
        )
        self.queue = TaskQueue(
            self._process_queued, settings.async_workers, settings.redis_url,
            settings.queue_max_attempts, settings.queue_lease_seconds,
            self._on_dead_letter,
        )
        self.experiment_queue = TaskQueue(
            self._process_experiment_queued,
            settings.experiment_workers,
            settings.redis_url,
            1,
            settings.experiment_queue_lease_seconds,
            self._on_experiment_dead_letter,
            stream="lima:experiment:stream",
            dead_letter_stream="lima:experiment:dlq",
            group="lima-experiment-workers",
            thread_prefix="lima-experiment-worker",
        )

    def _build_llm_reviewer(self, prompt: str = "") -> OpenAICompatibleReviewer:
        if not self.llm_config:
            raise RuntimeError("no LLM provider is configured")
        return OpenAICompatibleReviewer(
            str(self.llm_config["base_url"]),
            str(self.llm_config["api_key"]),
            str(self.llm_config["model"]),
            self.settings.timeout_seconds,
            system_prompt=prompt,
            provider=str(self.llm_config["provider"]),
            extra_headers=dict(self.llm_config.get("headers") or {}),
        )

    def _build_repository_semantic_triage(self):
        mode = self.settings.repository_scan_llm_mode
        if mode == "off":
            return None
        if not self.llm_config:
            if mode == "required":
                raise ValueError(
                    "required repository semantic triage needs an LLM provider"
                )
            return None
        client = LLMSecurityTriageClient(
            base_url=str(self.llm_config["base_url"]),
            api_key=str(self.llm_config["api_key"]),
            model=str(self.llm_config["model"]),
            provider=str(self.llm_config["provider"]),
            extra_headers=dict(self.llm_config.get("headers") or {}),
            timeout_seconds=self.settings.repository_scan_llm_timeout_seconds,
            max_context_chars=self.settings.repository_scan_llm_max_context_chars,
            max_completion_tokens=(
                self.settings.repository_scan_llm_max_completion_tokens
            ),
        )
        return RepositorySemanticTriage(
            client,
            mode=mode,
            max_candidates=self.settings.repository_scan_llm_max_candidates,
        )

    def _build_experiment_evaluator(self, mode: str) -> RealWorldSecurityEvaluator:
        llm_client = None
        if mode in LLM_MODES:
            if not self.llm_config:
                raise ValueError("LLM experiment mode requires a configured provider")
            llm_client = LLMSecurityTriageClient(
                base_url=str(self.llm_config["base_url"]),
                api_key=str(self.llm_config["api_key"]),
                model=str(self.llm_config["model"]),
                provider=str(self.llm_config["provider"]),
                extra_headers=dict(self.llm_config.get("headers") or {}),
                timeout_seconds=self.settings.repository_scan_llm_timeout_seconds,
                max_context_chars=self.settings.repository_scan_llm_max_context_chars,
                max_completion_tokens=(
                    self.settings.repository_scan_llm_max_completion_tokens
                ),
            )
        return RealWorldSecurityEvaluator(
            SnapshotStore(self.settings.experiment_cache_root),
            scanner=RepositoryScanner(sast_mode="off", dataflow_enabled=False),
            llm_client=llm_client,
        )

    def create_experiment(
        self, dataset: str, mode: str, tenant_id: str,
        *, max_llm_calls: Optional[int] = None,
        max_total_tokens: Optional[int] = None,
    ) -> dict:
        record = self.experiment_runner.create(
            dataset, mode, tenant_id,
            max_llm_calls=max_llm_calls,
            max_total_tokens=max_total_tokens,
        )
        self.experiment_queue.submit({
            "run_id": record["id"], "tenant_id": tenant_id,
            "allow_ambiguous_retry": False,
        }, message_id=record["id"])
        return {
            "run_id": record["id"], "state": record["state"],
            "mode": record["mode"], "queue": self.experiment_queue.backend,
        }

    def get_experiment(self, run_id: str, tenant_id: str) -> Optional[dict]:
        return self.store.get_experiment(run_id, tenant_id)

    def list_experiments(self, tenant_id: str, limit: int = 50) -> list:
        return self.store.list_experiments(limit, tenant_id)

    def experiment_catalog(self) -> list:
        return self.experiment_runner.catalog()

    def cancel_experiment(self, run_id: str, tenant_id: str) -> bool:
        return self.experiment_runner.cancel(run_id, tenant_id)

    def resume_experiment(
        self, run_id: str, tenant_id: str,
        *, allow_ambiguous_retry: bool = False,
    ) -> dict:
        record = self.experiment_runner.prepare_resume(
            run_id, tenant_id,
            allow_ambiguous_retry=allow_ambiguous_retry,
        )
        if record["state"] == "QUEUED":
            self.experiment_queue.submit({
                "run_id": run_id, "tenant_id": tenant_id,
                "allow_ambiguous_retry": allow_ambiguous_retry,
            }, message_id="%s:%s" % (run_id, uuid.uuid4().hex[:8]))
        return {"run_id": run_id, "state": record["state"], "resumed": True}

    def _process_experiment_queued(self, payload: Dict[str, Any]) -> None:
        self.experiment_runner.run(
            str(payload["run_id"]),
            allow_ambiguous_retry=bool(payload.get("allow_ambiguous_retry")),
        )

    def _on_experiment_dead_letter(
        self, payload: Dict[str, Any], error: str,
    ) -> None:
        run_id = str(payload.get("run_id", ""))
        record = self.store.get_experiment(run_id) if run_id else None
        if record:
            self.store.update_experiment(
                run_id, "FAILED", record.get("progress") or {},
                error="experiment queue failure: %s" % error[:1500],
            )

    def close(self) -> None:
        self.queue.close()
        self.experiment_queue.close()

    def _build_coordinator(self, reviewers: list) -> MultiAgentCoordinator:
        return MultiAgentCoordinator(
            reviewers, max_workers=self.settings.agent_max_workers, store=self.store,
            agent_retries=self.settings.agent_retries,
            collaboration_rounds=self.settings.collaboration_rounds,
            context_manager=self.context_manager, memory_manager=self.memory,
            agent_loop_max_steps=self.settings.agent_loop_max_steps,
            agent_loop_timeout_seconds=self.settings.agent_loop_timeout_seconds,
        )

    def _candidate_reviewer(self, tenant_id: str):
        if not self.llm_config:
            return None
        deployment = self.store.get_deployment(tenant_id, "llm-review")
        if not deployment or deployment.get("candidate_version") is None:
            return None
        versions = self.store.list_skill_versions("llm-review")
        candidate = next(
            (item for item in versions
             if int(item["version"]) == int(deployment["candidate_version"])), None
        )
        return self._build_llm_reviewer(candidate["prompt"]) if candidate else None

    def _run_review(
        self, task_id: str, repository: str, pull_request: Optional[int],
        diff: str, tenant_id: str,
    ):
        task = self.store.get(task_id, tenant_id) or {}
        deployment = self.store.get_deployment(tenant_id, "llm-review")
        evolved = self._active_evolved_reviewers(tenant_id)
        if (
            (task.get("input") or {}).get("release_lane") == "canary"
            or (deployment and deployment.get("status") == "promoted")
        ):
            candidate = self._candidate_reviewer(tenant_id)
            if candidate:
                canary_reviewer = self._build_coordinator([
                    item for item in self.registry.reviewers()
                    if not isinstance(item, OpenAICompatibleReviewer)
                ] + evolved + [candidate])
                harness = ReviewHarness(
                    self.store, canary_reviewer, self.settings.max_steps,
                    self.settings.timeout_seconds, observability=self.observability,
                )
                return harness.run(task_id, repository, pull_request, diff, tenant_id)
        if evolved:
            tenant_reviewer = self._build_coordinator(
                self.registry.reviewers() + evolved
            )
            harness = ReviewHarness(
                self.store, tenant_reviewer, self.settings.max_steps,
                self.settings.timeout_seconds, observability=self.observability,
            )
            return harness.run(task_id, repository, pull_request, diff, tenant_id)
        return self.harness.run(task_id, repository, pull_request, diff, tenant_id)

    def _run_shadow(
        self, task_id: str, tenant_id: str, diff: str, primary_report,
    ) -> None:
        task = self.store.get(task_id, tenant_id) or {}
        if not (task.get("input") or {}).get("shadow"):
            return
        candidate = self._candidate_reviewer(tenant_id)
        if not candidate:
            self.store.audit(
                tenant_id, "system", "shadow.skipped", task_id,
                {"reason": "candidate reviewer is unavailable"},
            )
            return
        lane = (task.get("input") or {}).get("release_lane", "stable")
        primary = {
            "risk": primary_report.risk,
            "finding_keys": sorted(
                "%s:%s:%s" % (item.path, item.line, item.rule_id)
                for item in primary_report.findings
            ),
        }
        try:
            parsed = parse_unified_diff(diff)
            findings = candidate.review(diff, parsed)
            candidate_result = {
                "finding_keys": sorted(
                    "%s:%s:%s" % (item.path, item.line, item.rule_id)
                    for item in findings
                )
            }
            rollout = self.releases.observe_shadow(
                tenant_id, "llm-review", task_id, lane, primary, candidate_result
            )
            self.store.audit(
                tenant_id, "system", "shadow.completed", task_id,
                {"findings": len(findings), "candidate_output_used": False,
                 "rollout_status": (rollout or {}).get("status")},
            )
            metrics.inc("shadow_reviews_total")
        except Exception as exc:
            self.releases.observe_shadow(
                tenant_id, "llm-review", task_id, lane, primary, None, True
            )
            self.store.audit(
                tenant_id, "system", "shadow.failed", task_id, {"error": str(exc)[:500]}
            )
            metrics.inc("shadow_reviews_failed_total")

    def reload_skills(self) -> list:
        if self.llm_config:
            active = self.store.get_active_skill_version("llm-review")
            self.registry.register(
                "llm-review",
                self._build_llm_reviewer(active["prompt"] if active else ""),
                "1.0.0", "Context-aware AI code review via %s" % self.llm_config["provider"],
            )
        self.registry.reload()
        skills = self.registry.list()
        self.reviewer = self._build_coordinator(self.registry.reviewers())
        self.harness = ReviewHarness(
            self.store, self.reviewer, self.settings.max_steps, self.settings.timeout_seconds,
            observability=self.observability,
        )
        return skills

    def _active_evolved_reviewers(self, tenant_id: str) -> list:
        return [
            DeclarativeSkillReviewer(version["artifact"], int(version["version"]))
            for version in self.store.list_active_skill_artifacts(tenant_id)
        ]

    def list_skills(self, tenant_id: str) -> list:
        values = self.registry.list()
        values.extend({
            "name": version["skill_name"], "version": str(version["version"]),
            "description": version["artifact"].get(
                "description", "Replay-gated evolved skill"
            ),
            "source": "evolved-db", "sandboxed": True, "permissions": [],
            "artifact_sha256": version["artifact_sha256"],
        } for version in self.store.list_active_skill_artifacts(tenant_id))
        return values

    def _validate_review(self, repository: str, diff: str) -> None:
        if not repository or len(repository) > 250:
            raise ValueError("repository is required and must be at most 250 characters")
        size = len(diff.encode("utf-8"))
        if size == 0:
            raise ValueError("diff is required")
        if size > self.settings.max_diff_bytes:
            raise ValueError("diff exceeds maximum size of %d bytes" % self.settings.max_diff_bytes)

    def _create_task(
        self, repository: str, diff: str, pull_request: Optional[int], source: str,
        tenant_id: str = "default",
    ) -> str:
        task_id = str(uuid.uuid4())
        encoded = diff.encode("utf-8")
        assignment = self.releases.assignment(tenant_id, "llm-review", task_id)
        self.store.create(task_id, repository, pull_request, {
            "source": source, "diff_bytes": len(encoded), "diff_sha256": hashlib.sha256(encoded).hexdigest(),
            "release_lane": assignment["lane"], "shadow": assignment["shadow"],
        }, tenant_id)
        self.store.save_task_payload(task_id, diff)
        return task_id

    def _create_deferred_task(
        self, repository: str, pull_request: Optional[int], source: str,
        tenant_id: str, payload: Dict[str, Any],
    ) -> str:
        task_id = str(uuid.uuid4())
        assignment = self.releases.assignment(tenant_id, "llm-review", task_id)
        self.store.create(task_id, repository, pull_request, {
            "source": source, "diff_pending": True,
            "release_lane": assignment["lane"], "shadow": assignment["shadow"],
            **payload,
        }, tenant_id)
        return task_id

    def create_review(
        self, repository: str, diff: str, pull_request: Optional[int] = None,
        source: str = "api", tenant_id: str = "default",
    ) -> Dict[str, Any]:
        self._validate_review(repository, diff)
        self._authorize_repository(tenant_id, repository)
        task_id = self._create_task(repository, diff, pull_request, source, tenant_id)
        try:
            with self.observability.span(
                "review", task_id, task_id=task_id, tenant_id=tenant_id,
                repository=repository,
            ), metrics.timer("review_duration"):
                report = self._run_review(
                    task_id, repository, pull_request, diff, tenant_id
                )
            self._run_shadow(task_id, tenant_id, diff, report)
            metrics.inc("reviews_total")
            lane = (self.store.get(task_id, tenant_id).get("input") or {}).get(
                "release_lane", "stable"
            )
            self.releases.observe(tenant_id, "llm-review", False, lane)
            return {"task_id": task_id, "state": "SUCCESS", "report": report.to_dict()}
        except Exception:
            task = self.store.get(task_id, tenant_id) or {}
            lane = (task.get("input") or {}).get("release_lane", "stable")
            self.releases.observe(tenant_id, "llm-review", True, lane)
            self.alerts.evaluate(tenant_id)
            raise

    def enqueue_review(
        self, repository: str, diff: str, pull_request: Optional[int] = None,
        source: str = "api", github_issue_url: str = "", installation_id: Optional[int] = None,
        tenant_id: str = "default",
    ) -> Dict[str, Any]:
        self._validate_review(repository, diff)
        self._authorize_repository(tenant_id, repository)
        task_id = self._create_task(repository, diff, pull_request, source, tenant_id)
        self.queue.submit({
            "task_id": task_id, "repository": repository, "pull_request": pull_request,
            "github_issue_url": github_issue_url, "installation_id": installation_id,
            "tenant_id": tenant_id,
        }, message_id=task_id)
        metrics.inc("reviews_enqueued_total")
        return {"task_id": task_id, "state": "PENDING", "queue": self.queue.backend}

    def repository_scan_capabilities(self) -> Dict[str, Any]:
        result = self.repository_import.capabilities()
        result.update({
            "sast_mode": self.settings.repository_scan_sast_mode,
            "dataflow_enabled": True,
            "dataflow_scope": "repository-static-imports",
            "cross_file_dataflow": True,
            "supported_python_imports": [
                "import module", "import module as alias",
                "from module import function", "relative imports",
            ],
            "dataflow_max_call_depth": self.repository_scanner.python_dataflow.max_call_depth,
            "verified_repair_cwes": ["CWE-22", "CWE-78", "CWE-89"],
            "repair_strategies": [
                "argv-no-shell", "parameterized-sql", "confined-path",
            ],
            "repair_preview_supported": True,
            "repair_preview_writes_repository": False,
            "repair_preview_snapshot_pinned": True,
            "repair_gates": [
                "compile", "security-oracle", "differential-rescan",
                "repository-tests", "human-draft-pr-approval",
            ],
            "repair_tests_configured": bool(self.settings.repair_test_command),
            "semantic_triage_mode": self.settings.repository_scan_llm_mode,
            "semantic_triage_enabled": self.repository_semantic_triage is not None,
            "semantic_triage_provider": (
                str(self.llm_config.get("provider", "")) if self.llm_config else ""
            ),
            "semantic_triage_max_candidates": (
                self.settings.repository_scan_llm_max_candidates
            ),
            "semantic_triage_max_context_chars": (
                self.settings.repository_scan_llm_max_context_chars
            ),
            "semantic_triage_max_completion_tokens": (
                self.settings.repository_scan_llm_max_completion_tokens
            ),
            "max_files": self.settings.repository_scan_max_files,
            "max_file_bytes": self.settings.repository_scan_max_file_bytes,
            "max_total_bytes": self.settings.repository_scan_max_total_bytes,
        })
        return result

    def enqueue_repository_scan(
        self, repository_key: str, tenant_id: str = "default"
    ) -> Dict[str, Any]:
        key = self.repository_import.normalize_key(repository_key)
        self.repository_import.resolve(key)
        task_id = str(uuid.uuid4())
        self.store.create(task_id, key, None, {
            "source": "repository-import",
            "task_type": "repository_scan",
            "repository_key": key,
            "sast_mode": self.settings.repository_scan_sast_mode,
            "semantic_triage_mode": self.settings.repository_scan_llm_mode,
        }, tenant_id)
        self.queue.submit({
            "task_id": task_id,
            "task_type": "repository_scan",
            "repository_key": key,
            "tenant_id": tenant_id,
        }, message_id=task_id)
        metrics.inc("repository_scans_enqueued_total")
        return {
            "task_id": task_id,
            "task_type": "repository_scan",
            "repository": key,
            "state": "PENDING",
            "queue": self.queue.backend,
        }

    def _process_repository_scan(
        self, task_id: str, repository_key: str, tenant_id: str
    ) -> None:
        root = self.repository_import.resolve(repository_key)
        self.store.transition(
            task_id,
            TraceEvent(
                1, TaskState.PLANNING,
                "Validated repository key within the configured import root.",
                utc_now(),
            ),
        )
        workspace = RepositoryWorkspace(
            root,
            max_files=self.settings.repository_scan_max_files,
            max_file_bytes=self.settings.repository_scan_max_file_bytes,
            max_total_bytes=self.settings.repository_scan_max_total_bytes,
        )
        self.store.transition(
            task_id,
            TraceEvent(
                2, TaskState.EXECUTING,
                "Running bounded AST and SAST repository analysis.", utc_now(),
            ),
        )
        with self.observability.span(
            "repository.scan", task_id, task_id=task_id, tenant_id=tenant_id,
            repository=repository_key,
        ), metrics.timer("repository_scan_duration"):
            result = self.repository_scanner.scan(workspace)
        result.report.repository = repository_key
        result.report.collaboration["import_policy"] = {
            "repository_key": repository_key,
            "host_path_exposed": False,
            "repository_code_executed": False,
            "snapshot_sha256": result.inventory.fingerprint(),
            "snapshot_files": len(result.inventory.files),
        }
        if self.repository_semantic_triage is not None:
            try:
                with metrics.timer("repository_semantic_triage_duration"):
                    triage = self.repository_semantic_triage.run(
                        root,
                        result.report.adjudication,
                        result.report.findings,
                    )
            except RepositorySemanticTriageError as exc:
                metrics.inc("repository_semantic_triage_failed_total")
                raise PermanentTaskError(str(exc)) from exc
            if triage.findings:
                result.report.findings.extend(triage.findings)
                severity_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1}
                result.report.findings.sort(key=lambda item: (
                    -severity_rank.get(item.severity.value, 0),
                    item.path, item.line, item.rule_id,
                ))
                highest = max(
                    (severity_rank.get(item.severity.value, 0)
                     for item in result.report.findings),
                    default=0,
                )
                result.report.risk = (
                    "critical" if highest == 4 else
                    "high" if highest == 3 else
                    "medium" if highest == 2 else "low"
                )
                result.report.summary += (
                    " Hybrid semantic triage added %d evidence-backed finding%s."
                    % (len(triage.findings), "" if len(triage.findings) == 1 else "s")
                )
            result.report.adjudication = triage.adjudication
            result.report.collaboration["semantic_triage"] = triage.diagnostics
            if triage.diagnostics.get("status") == "completed":
                metrics.inc("repository_semantic_triage_completed_total")
            else:
                metrics.inc("repository_semantic_triage_degraded_total")
        else:
            result.report.collaboration["semantic_triage"] = {
                "mode": self.settings.repository_scan_llm_mode,
                "status": (
                    "disabled"
                    if self.settings.repository_scan_llm_mode == "off"
                    else "llm-not-configured"
                ),
                "secret_persisted": False,
            }
        self.store.succeed(
            task_id, result.report,
            TraceEvent(
                3, TaskState.SUCCESS,
                "Repository scan completed with %d candidate findings."
                % len(result.report.findings),
                utc_now(),
            ),
        )
        metrics.inc("repository_scans_total")

    def _process_queued(self, payload: Dict[str, Any]) -> None:
        task_id = payload["task_id"]
        task = self.store.get(task_id)
        if not task:
            raise PermanentTaskError("task record no longer exists")
        tenant_id = payload.get("tenant_id") or task.get("tenant_id") or "default"
        task_type = payload.get("task_type") or (task.get("input") or {}).get(
            "task_type", "review"
        )
        if task_type == "repository_scan":
            self._process_repository_scan(
                task_id,
                payload.get("repository_key")
                or (task.get("input") or {}).get("repository_key", ""),
                tenant_id,
            )
            return
        diff = self.store.get_task_payload(task_id)
        if diff is None and payload.get("diff_url"):
            client = (
                self.github_client_for_installation(payload.get("installation_id"))
                if payload.get("installation_id") else self.github
            )
            client.ensure_repository_access(payload["repository"])
            diff = client.fetch_diff(payload["diff_url"])
            self._validate_review(payload["repository"], diff)
            encoded = diff.encode("utf-8")
            self.store.save_task_payload(task_id, diff)
            self.store.update_task_input(task_id, {
                "diff_pending": False, "diff_bytes": len(encoded),
                "diff_sha256": hashlib.sha256(encoded).hexdigest(),
            })
        if diff is None:
            raise PermanentTaskError("task payload no longer exists")
        try:
            with self.observability.span(
                "review.async", task_id, task_id=task_id, tenant_id=tenant_id,
            ), metrics.timer("review_duration"):
                report = self._run_review(
                    task_id, payload["repository"], payload.get("pull_request"), diff,
                    tenant_id,
                )
            self._run_shadow(task_id, tenant_id, diff, report)
            metrics.inc("reviews_total")
            lane = (task.get("input") or {}).get("release_lane", "stable")
            self.releases.observe(tenant_id, "llm-review", False, lane)
            if payload.get("github_issue_url") and self.settings.auto_post_review:
                client = self.github_client_for_installation(payload.get("installation_id"))
                client.upsert_comment(
                    payload["github_issue_url"], to_markdown(report.to_dict()),
                    "<!-- lima-review:%s -->" % task_id,
                )
        except Exception:
            metrics.inc("reviews_failed_total")
            lane = (task.get("input") or {}).get("release_lane", "stable")
            self.releases.observe(tenant_id, "llm-review", True, lane)
            self.alerts.evaluate(tenant_id)
            raise

    def _on_dead_letter(self, payload: Dict[str, Any], error: str) -> None:
        task_id = payload.get("task_id", "")
        tenant_id = payload.get("tenant_id", "default")
        task = self.store.get(task_id, tenant_id) if task_id else None
        if task and task.get("state") not in {
            TaskState.SUCCESS.value, TaskState.FAILED.value, TaskState.CANCELLED.value,
        }:
            step = max(
                [int(item.get("step", 0)) for item in task.get("trace", [])] or [0]
            ) + 1
            self.store.fail(
                task_id, error,
                TraceEvent(
                    step, TaskState.FAILED,
                    "Task entered the dead-letter queue: %s" % error, utc_now(),
                ),
            )
        self.store.create_alert(
            tenant_id, "dlq:%s" % (task_id or "unknown"), "critical",
            "Task %s entered the dead-letter queue: %s" % (task_id, error),
        )
        metrics.inc("dead_letters_total")

    def handle_github_pull_request(
        self, payload: Dict[str, Any], delivery_id: str,
        payload_sha256: str, tenant_id: str = "",
    ) -> Dict[str, Any]:
        installation_id = (payload.get("installation") or {}).get("id")
        tenant_id = tenant_id or (
            self.store.installation_tenant(installation_id) if installation_id else None
        ) or self.settings.default_tenant_id
        if not self.store.claim_webhook(
            delivery_id, tenant_id, "pull_request", payload_sha256
        ):
            existing = self.store.get_webhook(delivery_id) or {}
            return {
                "duplicate": True, "task_id": existing.get("task_id"),
                "state": "PENDING" if existing.get("task_id") else "ACCEPTED",
            }
        action = payload.get("action")
        if action not in {"opened", "reopened", "synchronize"}:
            self.store.complete_webhook(delivery_id, None)
            return {"ignored": True, "reason": "unsupported pull_request action: %s" % action}
        pull = payload.get("pull_request") or {}
        repository = (payload.get("repository") or {}).get("full_name", "")
        number = payload.get("number")
        diff_url = pull.get("diff_url")
        if not repository or not isinstance(number, int) or not diff_url:
            raise ValueError("invalid GitHub pull_request payload")
        self._authorize_repository(tenant_id, repository)
        task_id = self._create_deferred_task(
            repository, number, "github-webhook", tenant_id,
            {"diff_url": diff_url},
        )
        self.queue.submit({
            "task_id": task_id, "repository": repository, "pull_request": number,
            "github_issue_url": pull.get("issue_url", ""),
            "installation_id": installation_id, "tenant_id": tenant_id,
            "diff_url": diff_url,
        }, message_id=task_id)
        metrics.inc("reviews_enqueued_total")
        result = {"task_id": task_id, "state": "PENDING", "queue": self.queue.backend}
        self.store.complete_webhook(delivery_id, result["task_id"])
        result["will_post_to_github"] = self.settings.auto_post_review
        return result

    def github_client_for_installation(self, installation_id: Optional[int] = None) -> GitHubClient:
        if installation_id is None:
            return self.github
        if not self.settings.github_app_id or not self.settings.github_private_key_path:
            raise ValueError("GitHub App credentials are not configured")
        token = GitHubAppAuthenticator(
            self.settings.github_app_id, self.settings.github_private_key_path
        ).installation_token(installation_id)
        return GitHubClient(token)

    def create_fix(
        self, task_id: str, installation_id: Optional[int] = None,
        tenant_id: Optional[str] = None,
    ) -> dict:
        task = self.store.get(task_id, tenant_id)
        if not task or not task.get("report"):
            raise ValueError("completed task not found")
        if task.get("pull_request") is None:
            raise ValueError("fix commits require a GitHub pull request task")
        actual_tenant = task.get("tenant_id") or tenant_id or "default"
        if not self.store.repository_allowed(actual_tenant, task["repository"], True):
            raise PermissionError("automatic repair is not enabled for this repository")
        result = self.fixer.create_fix_commits(
            self.github_client_for_installation(installation_id),
            task["repository"], task["pull_request"], task["report"],
        )
        metrics.inc("fix_runs_total")
        return result

    def create_repair_preview(
        self, task_id: str, tenant_id: Optional[str] = None,
    ) -> dict:
        task = self.store.get(task_id, tenant_id)
        if not task or task.get("state") != TaskState.SUCCESS.value or not task.get("report"):
            raise ValueError("completed repository scan task not found")
        if (task.get("input") or {}).get("task_type") != "repository_scan":
            raise ValueError("repair preview requires a repository scan task")
        repository_key = (task.get("input") or {}).get("repository_key") or task["repository"]
        root = self.repository_import.resolve(repository_key)
        workspace = RepositoryWorkspace(
            root,
            max_files=self.settings.repository_scan_max_files,
            max_file_bytes=self.settings.repository_scan_max_file_bytes,
            max_total_bytes=self.settings.repository_scan_max_total_bytes,
        )
        import_policy = (task["report"].get("collaboration") or {}).get(
            "import_policy", {}
        )
        expected = str(import_policy.get("snapshot_sha256", ""))
        if not expected:
            raise ValueError("scan predates snapshot pinning; run a new scan before previewing repairs")
        with metrics.timer("repair_preview_duration"):
            result = self.repair_previewer.preview(workspace, task["report"], expected)
        metrics.inc("repair_previews_total")
        return {"task_id": task_id, "repository": repository_key, **result}

    def record_feedback(
        self, task_id: str, category: str, finding: Optional[dict], note: str,
        tenant_id: Optional[str] = None,
    ) -> dict:
        task = self.store.get(task_id, tenant_id)
        if not task:
            raise ValueError("task not found")
        if task.get("state") != "SUCCESS" or not task.get("report"):
            raise ValueError("feedback requires a completed review task")
        if category not in {"false_positive", "missed_issue", "bad_fix", "accepted"}:
            raise ValueError("unsupported feedback category")
        self.store.record_failure_case(task_id, category, {"finding": finding, "note": note[:2000]})
        self.memory.remember_feedback(
            task.get("tenant_id") or tenant_id or "default", task["repository"],
            task_id, category, finding, note[:2000],
        )
        metrics.inc("feedback_total")
        return {"recorded": True, "category": category}

    def resume_task(self, task_id: str, tenant_id: Optional[str] = None) -> dict:
        task = self.store.get(task_id, tenant_id)
        if not task:
            raise ValueError("task not found")
        if task["state"] == "SUCCESS":
            return {"task_id": task_id, "state": "SUCCESS", "report": task["report"]}
        diff = self.store.get_task_payload(task_id)
        if diff is None:
            raise ValueError("task payload is no longer available")
        self.queue.submit({
            "task_id": task_id, "repository": task["repository"],
            "pull_request": task.get("pull_request"),
            "tenant_id": task.get("tenant_id", "default"),
        }, message_id=task_id)
        return {"task_id": task_id, "state": "PENDING", "resumed": True}

    def cancel_task(self, task_id: str, tenant_id: Optional[str] = None) -> bool:
        return self.store.request_cancel(task_id, tenant_id)

    def _authorize_repository(self, tenant_id: str, repository: str) -> None:
        if not self.store.repository_allowed(tenant_id, repository):
            raise PermissionError("repository is not authorized for this tenant")

    def list_repository_grants(self, tenant_id: str) -> list:
        return self.store.list_repository_grants(tenant_id)

    def grant_repository(
        self, tenant_id: str, repository: str, auto_fix: bool,
        actor: str = "",
    ) -> dict:
        repository = repository.strip()
        valid_name = (
            len(repository) <= 200
            and ".." not in repository
            and re.fullmatch(
                r"[A-Za-z0-9][A-Za-z0-9_.-]*/[A-Za-z0-9][A-Za-z0-9_.-]*",
                repository,
            )
        )
        if not valid_name:
            raise ValueError("repository must be a GitHub-style owner/name identifier")
        self.store.grant_repository(tenant_id, repository, bool(auto_fix))
        self.store.audit(
            tenant_id, actor or "api", "repository.grant", repository,
            {"auto_fix": bool(auto_fix)},
        )
        return {"repository": repository, "auto_fix": bool(auto_fix)}
