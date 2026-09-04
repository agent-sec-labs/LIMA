import hashlib
import re
import sys
import tempfile
import uuid
from pathlib import Path
from typing import Any, Dict, Optional

from .agents import MultiAgentCoordinator
from .auth import AuthManager
from .config import Settings
from .context_manager import ContextManager
from .cxx_memory import (
    REQUESTED_LAYERS,
    SUPPORTED_CWES,
    CxxAnalyzerHealth,
    CxxAnalyzerProtocolError,
    CxxAnalyzerUnavailable,
    CxxMemoryAnalyzerClient,
)
from .diff_parser import parse_unified_diff
from .evolution import EvolutionEngine
from .fixer import SafeFixer
from .github import GitHubAppAuthenticator, GitHubClient
from .harness import ReviewHarness
from .memory import MemoryManager
from .metrics import metrics
from .models import TaskState, TraceEvent
from .observability import AlertManager, Observability
from .postgres_store import create_store
from .repair_preview import RepositoryRepairPreviewer
from .report import to_markdown
from .reviewer import (
    OpenAICompatibleReviewer, ReliabilityRuleReviewer, SecurityRuleReviewer,
)
from .diff_parser import parse_unified_diff
from .skills import SkillRegistry
from .skill_evolution import DeclarativeSkillReviewer, SkillEvolutionEngine
from .store import utc_now
from .task_queue import PermanentTaskError, TaskQueue
from .task_failure import classify_exception
from .task_progress import (
    COMPLETED,
    FINALIZING,
    PREPARING_WORKSPACE,
    QUEUED,
    SEMANTIC_TRIAGE,
    TaskProgress,
)
from .rollout import ReleaseManager
from .verifier import RepairVerifier
from .repository_import import RepositoryImportPolicy
from .repository_cache import RepositoryCache
from .repair_workspace import RepairWorkspace
from .repository_materializer import GitHubMaterializer
from .repository_scanner import RepositoryScanner, coverage_warning_counts
from .repository_source import (
    GITHUB_SOURCE_TYPE,
    LOCAL_IMPORT_SOURCE_TYPE,
    RepositorySource,
    parse_repository_source,
)
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
from .workspace import (
    CXX_BUILD_EXTENSIONS,
    CXX_SOURCE_EXTENSIONS,
    DEFAULT_FILENAMES,
    RepositoryWorkspace,
)

DOCKER_REPOSITORY_CACHE_ROOT = Path("/var/lib/lima/repository-cache")


def classify_repository_cache_root(root: str) -> str:
    """Classify a cache root location for deployment visibility (#14).

    ``named-volume`` roots live under the docker compose mount,
    ``system-tmp`` roots are disposable by design; anything else is
    ``unmanaged`` and only merits a startup warning, never enforcement.
    """

    resolved = Path(root).expanduser().resolve()
    for label, base in (
        ("named-volume", DOCKER_REPOSITORY_CACHE_ROOT),
        ("system-tmp", Path(tempfile.gettempdir())),
    ):
        try:
            resolved.relative_to(base.expanduser().resolve())
            return label
        except ValueError:
            continue
    return "unmanaged"


def _warn_unmanaged_repository_cache_root(root: str) -> None:
    if classify_repository_cache_root(root) == "unmanaged":
        print(
            f"WARNING: repository cache root "
            f"'{Path(root).expanduser().resolve()}' is neither the docker "
            f"named volume mount ({DOCKER_REPOSITORY_CACHE_ROOT}) nor under "
            f"the system tmpdir; snapshots may not survive restarts and "
            f"host disk usage is unmanaged.",
            file=sys.stderr,
        )


class ScanProgressTracker:
    """Bridge pipeline stage events into the durable TaskProgress record.

    物化器与扫描器共用 ``pipeline_event(stage, message, **detail)`` 回调契约；
    同阶段重复事件只刷新计数，不重置 ``stage_started_at``。每次变化立即落库
    （轻量 UPDATE），报告仍由 ``store.succeed`` 单次最终提交。
    """

    def __init__(self, store, task_id: str, progress: TaskProgress) -> None:
        self._store = store
        self._task_id = task_id
        self.progress = progress

    @property
    def stage(self) -> str:
        return self.progress.stage

    def advance(self, stage: str, message: str = "") -> None:
        self.progress.advance(stage, message)
        self._flush()

    def pipeline_event(self, stage: str, message: str = "", **detail: Any) -> None:
        counters = {
            key: detail.pop(key)
            for key in ("current", "total", "unit")
            if key in detail
        }
        if stage != self.progress.stage:
            self.progress.advance(stage, message)
        elif message:
            self.progress.update(message)
        if counters:
            self.progress.update(
                current=counters.get("current"),
                total=counters.get("total"),
                unit=str(counters.get("unit", "")),
            )
        if detail:
            self.progress.update(detail=detail)
        self._flush()

    def complete(self, completion: dict[str, Any]) -> None:
        self.progress.advance(COMPLETED, "任务完成")
        self.progress.update(detail={"completion": completion})
        self._flush()

    def _flush(self) -> None:
        self._store.update_task_progress(self._task_id, self.progress.to_dict())


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
        cxx_memory_adapter = None
        if settings.cxx_memory_mode != "off":
            cxx_memory_adapter = CxxMemoryAnalyzerClient(
                settings.cxx_analyzer_url,
                timeout_seconds=settings.cxx_analysis_timeout_seconds,
                max_response_bytes=settings.cxx_max_response_bytes,
            )
        # 快照缓存与物化器惰性构建：local-import-only（默认）部署在启动时
        # 不得触碰文件系统；只读根文件系统的容器只在真正需要 GitHub 物化时
        # 才创建缓存目录，届时失败表现为单个任务失败而非服务崩溃。
        self._repository_cache: RepositoryCache | None = None
        # 物化只发生在异步 worker；测试可整体替换该实例注入离线 opener。
        self.repository_materializer: GitHubMaterializer | None = None
        self.repository_scanner = RepositoryScanner(
            sast_mode=settings.repository_scan_sast_mode,
            cxx_memory_mode=settings.cxx_memory_mode,
            cxx_memory_adapter=cxx_memory_adapter,
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
            on_retry=self._on_task_retry,
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
        health_status = "disabled"
        health_schema_version = None
        capabilities = None
        source_layer_available = False
        build_layer_available = False
        sanitizer_layer_available = False
        cxx_adapter = self.repository_scanner.cxx_memory_adapter
        if self.settings.cxx_memory_mode != "off" and cxx_adapter is not None:
            try:
                health = cxx_adapter.health()
            except CxxAnalyzerUnavailable:
                health_status = "unavailable"
            except CxxAnalyzerProtocolError:
                health_status = "invalid-response"
            else:
                if isinstance(health, CxxAnalyzerHealth):
                    health_status = "available"
                    health_schema_version = health.schema_version
                    capabilities = health.capabilities()
                    source_layer_available = health.source_available
                    build_layer_available = health.build_available
                    sanitizer_layer_available = bool(
                        health.build_available and health.test_configured
                    )
                else:
                    health_status = "invalid-response"
        allowed = self.settings.repository_scan_sources
        result.update({
            "scan_sources": {
                "configured": allowed,
                "local_import": allowed in {"local-import", "both"},
                "github": allowed in {"github", "both"},
            },
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
            "cxx_memory": {
                "mode": self.settings.cxx_memory_mode,
                # Kept for v1 clients; authoritative availability is health_status below.
                "analyzer_configured": bool(self.settings.cxx_analyzer_url),
                "health_status": health_status,
                "health_schema_version": health_schema_version,
                "capabilities": capabilities,
                "source_layer_available": source_layer_available,
                "build_layer_available": build_layer_available,
                "sanitizer_layer_available": sanitizer_layer_available,
                "supported_extensions": sorted(CXX_SOURCE_EXTENSIONS),
                "build_metadata_extensions": sorted(CXX_BUILD_EXTENSIONS),
                "build_metadata_filenames": sorted(DEFAULT_FILENAMES),
                "supported_cwes": sorted(SUPPORTED_CWES),
                "layers": list(REQUESTED_LAYERS),
                "build_configuration_status": "sidecar-managed",
                "test_configuration_status": "sidecar-managed",
                "automatic_repair": False,
            },
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
        return self._enqueue_scan_task(
            RepositorySource.local_import(key), tenant_id, label=key
        )

    def _ensure_repository_cache(self) -> RepositoryCache:
        """Lazily build the snapshot cache on first GitHub materialization."""

        if self._repository_cache is None:
            cache_root = (
                self.settings.repository_cache_root or "output/repository-cache"
            )
            _warn_unmanaged_repository_cache_root(cache_root)
            self._repository_cache = RepositoryCache(
                cache_root,
                ttl_seconds=self.settings.repository_cache_ttl_seconds,
                quota_bytes=self.settings.repository_cache_quota_bytes,
                min_free_bytes=self.settings.repository_cache_min_free_bytes,
                materialization_timeout_seconds=(
                    self.settings.repository_cache_materialization_timeout_seconds
                ),
            )
        return self._repository_cache

    def _materializer(self) -> GitHubMaterializer:
        if self.repository_materializer is None:
            self.repository_materializer = GitHubMaterializer(
                self._ensure_repository_cache(),
                # GitHub API 凭据接线：settings.github_token（LIMA_GITHUB_TOKEN）
                # 必须随构造传入——此前漏传导致所有远程扫描匿名调用，
                # 撞 60 次/小时的共享限额后被 GitHub 403 拒绝（2026-08-30 实证）。
                auth_token=self.settings.github_token,
            )
        return self.repository_materializer

    def compose_repair_workspace(
        self, task_id: str, entry, requested_paths: list[str]
    ) -> "RepairWorkspace":
        """Compose a disposable repair workspace for a worker-side task.

        仅接线（issue #16）：工作区由异步 worker 按任务创建与销毁，
        不经过任何 API 端点；源快照、缓存卷与 GitHub 均不被修改。
        """

        return RepairWorkspace.compose(
            self._ensure_repository_cache(),
            self.settings.repair_workspace_root or "output/repair-workspaces",
            task_id,
            entry,
            requested_paths,
        )

    def enqueue_repository_scan_source(
        self, source: RepositorySource | dict[str, str], tenant_id: str = "default"
    ) -> dict[str, Any]:
        """Queue a repository scan from a normalized source description.

        请求路径只做契约校验和来源枚举门禁，不做任何网络访问；
        GitHub ref 的解析与快照物化只发生在异步 worker 内。
        """

        normalized = parse_repository_source(source)
        allowed = self.settings.repository_scan_sources
        if normalized.type == GITHUB_SOURCE_TYPE:
            if allowed not in {"github", "both"}:
                metrics.inc("repository_scan_source_github_rejected_total")
                raise ValueError(
                    "github repository scans are disabled by "
                    "LIMA_REPOSITORY_SCAN_SOURCES"
                )
            return self._enqueue_scan_task(normalized, tenant_id)
        if allowed not in {"local-import", "both"}:
            metrics.inc("repository_scan_source_local_import_rejected_total")
            raise ValueError(
                "local-import repository scans are disabled by "
                "LIMA_REPOSITORY_SCAN_SOURCES"
            )
        self.repository_import.resolve(normalized.repository_key)
        return self._enqueue_scan_task(normalized, tenant_id)

    def _enqueue_scan_task(
        self, normalized: RepositorySource, tenant_id: str, label: str = ""
    ) -> dict[str, Any]:
        label = label or normalized.canonical_name or normalized.repository_key
        is_local = normalized.type == LOCAL_IMPORT_SOURCE_TYPE
        task_id = str(uuid.uuid4())
        scan_source = normalized.to_dict()
        task_input: dict[str, Any] = {
            "source": "repository-import" if is_local else "github-materializer",
            "task_type": "repository_scan",
            "scan_source": scan_source,
            "sast_mode": self.settings.repository_scan_sast_mode,
            "semantic_triage_mode": self.settings.repository_scan_llm_mode,
            "cxx_memory_mode": self.settings.cxx_memory_mode,
        }
        message: dict[str, Any] = {
            "task_id": task_id,
            "task_type": "repository_scan",
            "scan_source": scan_source,
            "tenant_id": tenant_id,
        }
        if is_local:
            task_input["repository_key"] = normalized.repository_key
            message["repository_key"] = normalized.repository_key
        self.store.create(task_id, label, None, task_input, tenant_id)
        # 任务实例化即开始进度跟踪（QUEUED），失败也始终有 progress 佐证 stage。
        self.store.update_task_progress(
            task_id,
            TaskProgress.begin(
                max_attempts=self.settings.queue_max_attempts
            ).to_dict(),
        )
        self.queue.submit(message, message_id=task_id)
        metrics.inc("repository_scans_enqueued_total")
        metrics.inc(
            f"repository_scan_source_{'local_import' if is_local else 'github'}_accepted_total"
        )
        return {
            "task_id": task_id,
            "scan_id": task_id,
            "task_type": "repository_scan",
            "repository": label,
            "source": scan_source,
            "state": "PENDING",
            "queue": self.queue.backend,
        }

    def _scan_progress_tracker(self, task_id: str) -> ScanProgressTracker:
        """Restore persisted progress (retry continuity) or begin a new one."""

        existing = (self.store.get(task_id) or {}).get("progress")
        if existing:
            progress = TaskProgress.from_dict(existing)
        else:
            progress = TaskProgress.begin(
                max_attempts=self.settings.queue_max_attempts
            )
        return ScanProgressTracker(self.store, task_id, progress)

    def _record_task_failure(
        self, task_id: str, exc: BaseException,
        tracker: ScanProgressTracker | None = None,
    ) -> None:
        """Persist the typed failure (stage preserved) before queue routing.

        显式 typed 失败（T3 物化器）原样保留；未分类异常经 classify_exception
        兜底，stage 取自当前 progress，保证 UI 不再只有裸异常字符串。
        """

        stage = tracker.stage if tracker is not None else ""
        failure = classify_exception(exc, stage)
        self.store.update_task_failure(task_id, failure.to_dict())

    def _process_repository_scan(
        self, task_id: str, repository_key: str, tenant_id: str,
        scan_source: dict[str, Any] | None = None,
    ) -> None:
        tracker = self._scan_progress_tracker(task_id)
        try:
            if scan_source:
                self._process_github_repository_scan(
                    task_id, scan_source, tenant_id, tracker
                )
                return
            tracker.pipeline_event(PREPARING_WORKSPACE, "正在准备本地导入工作区")
            root = self.repository_import.resolve(repository_key)
            self.store.transition(
                task_id,
                TraceEvent(
                    1, TaskState.PLANNING,
                    "Validated repository key within the configured import root.",
                    utc_now(),
                ),
            )
            self._execute_repository_scan(
                task_id, root, tenant_id, repository_key,
                {"repository_key": repository_key}, tracker,
            )
        except Exception as exc:
            self._record_task_failure(task_id, exc, tracker)
            raise

    def _process_github_repository_scan(
        self, task_id: str, scan_source: dict[str, Any], tenant_id: str,
        tracker: ScanProgressTracker,
    ) -> None:
        # 集成层唯一允许的网络调用：ref 钉死与 codeload 物化（缓存命中时零网络）。
        source = parse_repository_source(scan_source)
        materialized = self._materializer().materialize(
            source, progress_callback=tracker.pipeline_event
        )
        revision = materialized["resolved_revision"]
        metrics.inc(
            f"repository_scan_source_github_"
            f"{'cache_hit' if materialized['cache_hit'] else 'materialized'}_total"
        )
        # 扫描全程 pin 住快照，防止并发缓存清理在扫描进行中驱逐工作目录。
        with self._ensure_repository_cache().pin(source, revision):
            self.store.transition(
                task_id,
                TraceEvent(
                    1, TaskState.PLANNING,
                    "Materialized pinned GitHub snapshot at %s." % revision,
                    utc_now(),
                ),
            )
            self._execute_repository_scan(
                task_id, Path(materialized["path"]), tenant_id,
                source.canonical_name,
                {
                    "source": source.to_dict(),
                    "resolved_revision": revision,
                    "cache_hit": materialized["cache_hit"],
                    "archive_sha256": materialized["archive_sha256"],
                },
                tracker,
                materializer_warnings=materialized.get("warnings") or [],
            )

    def _execute_repository_scan(
        self, task_id: str, root: Path, tenant_id: str,
        repository_label: str, import_policy_extra: dict[str, Any],
        progress: ScanProgressTracker | None = None,
        materializer_warnings: list[dict[str, Any]] | None = None,
    ) -> None:
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
            repository=repository_label,
        ), metrics.timer("repository_scan_duration"):
            result = self.repository_scanner.scan(
                workspace,
                repository_key=repository_label,
                progress_callback=(
                    progress.pipeline_event if progress is not None else None
                ),
            )
        result.report.repository = repository_label
        result.report.collaboration["import_policy"] = {
            "host_path_exposed": False,
            "repository_code_executed": False,
            "snapshot_sha256": result.inventory.fingerprint(),
            "snapshot_files": len(result.inventory.files),
            **import_policy_extra,
        }
        if self.repository_semantic_triage is not None:
            if progress is not None:
                progress.pipeline_event(SEMANTIC_TRIAGE, "正在语义复核候选发现")
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
        # 冻结决策：任何 coverage-affecting skip ≥ 1 即 completed_with_warnings。
        warnings_by_reason = coverage_warning_counts(result.inventory)
        for warning in materializer_warnings or []:
            if warning.get("category") == "coverage":
                code = str(warning.get("code") or "COVERAGE_SKIPPED")
                warnings_by_reason[code] = warnings_by_reason.get(code, 0) + 1
        warning_count = sum(warnings_by_reason.values())
        completion: dict[str, Any] = {
            "status": (
                "completed_with_warnings" if warning_count else "completed"
            ),
            "warning_count": warning_count,
        }
        if warnings_by_reason:
            completion["warnings"] = warnings_by_reason
        if progress is not None:
            progress.pipeline_event(FINALIZING, "正在生成审计报告")
            # 先落 COMPLETED progress 再翻状态：避免轮询方看到
            # SUCCESS + 非 COMPLETED progress 的矛盾快照。
            progress.complete(completion)
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

    def _on_task_retry(
        self, payload: Dict[str, Any], attempt: int, max_attempts: int,
        exc: BaseException, delay: float,
    ) -> None:
        """Queue retry callback: bump progress attempt (scan tasks only).

        评审类任务没有 progress 记录，直接跳过；attempt 反映队列重试计数。
        """

        task_id = payload.get("task_id", "")
        if not task_id:
            return
        task = self.store.get(task_id)
        progress = (task or {}).get("progress")
        if not progress:
            return
        restored = TaskProgress.from_dict(progress)
        restored.attempt = min(attempt + 1, max_attempts)
        restored.advance(QUEUED, "任务将自动重试")
        self.store.update_task_progress(task_id, restored.to_dict())

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
            scan_source = payload.get("scan_source") or (
                task.get("input") or {}
            ).get("scan_source")
            if scan_source and scan_source.get("type") == "github":
                self._process_repository_scan(
                    task_id,
                    payload.get("repository_key")
                    or (task.get("input") or {}).get("repository_key", ""),
                    tenant_id,
                    scan_source,
                )
            else:
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
