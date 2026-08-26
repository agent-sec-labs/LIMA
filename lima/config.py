import os
import re
from dataclasses import dataclass
from typing import Dict, Iterable, Optional


_DOTENV_KEY = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_ENV_PREFIX = "LIMA_"
_LEGACY_ENV_PREFIX = "EVOAGENT_"


def _promote_legacy_environment() -> None:
    """Expose legacy settings through the LIMA namespace without logging secrets.

    ``LIMA_*`` always wins when both names are present.  This compatibility
    bridge lets existing deployments keep their current unmodified ``.env``
    during the product rename while all new documentation uses ``LIMA_*``.
    """
    for key, value in tuple(os.environ.items()):
        if not key.startswith(_LEGACY_ENV_PREFIX):
            continue
        lima_key = _ENV_PREFIX + key[len(_LEGACY_ENV_PREFIX):]
        os.environ.setdefault(lima_key, value)


def load_dotenv(paths: Optional[Iterable[str]] = None) -> None:
    """Load local dotenv files without overriding real process environment values.

    The project-root file has priority over ``lima/.env``.  This allows the
    latter to remain compatible with existing local setups while keeping the
    conventional root-level ``.env`` as the recommended location.
    """
    package_dir = os.path.dirname(os.path.abspath(__file__))
    project_root = os.path.dirname(package_dir)
    candidates = list(paths) if paths is not None else [
        os.path.join(project_root, ".env"),
        os.path.join(package_dir, ".env"),
    ]
    for path in candidates:
        try:
            with open(path, "r", encoding="utf-8-sig") as handle:
                lines = handle.readlines()
        except OSError:
            continue
        for raw_line in lines:
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("export "):
                line = line[7:].lstrip()
            if "=" not in line:
                continue
            key, value = (part.strip() for part in line.split("=", 1))
            if not _DOTENV_KEY.fullmatch(key):
                continue
            if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
                value = value[1:-1]
            os.environ.setdefault(key, value)
    _promote_legacy_environment()


load_dotenv()


def _int(name: str, default: int) -> int:
    value = int(os.getenv(name, str(default)))
    if value <= 0:
        raise ValueError("%s must be positive" % name)
    return value


def _bool(name: str, default: bool = False) -> bool:
    return os.getenv(name, str(default)).strip().lower() in {"1", "true", "yes", "on"}


def _non_negative_int(name: str, default: int) -> int:
    value = int(os.getenv(name, str(default)))
    if value < 0:
        raise ValueError("%s must be non-negative" % name)
    return value


@dataclass(frozen=True)
class Settings:
    host: str
    port: int
    db_path: str
    max_diff_bytes: int
    max_steps: int
    timeout_seconds: int
    llm_base_url: str
    llm_api_key: str
    llm_model: str
    github_webhook_secret: str
    github_token: str
    auto_post_review: bool
    database_url: str = ""
    redis_url: str = ""
    async_workers: int = 2
    agent_max_workers: int = 4
    agent_retries: int = 1
    collaboration_rounds: int = 2
    agent_loop_max_steps: int = 4
    agent_loop_timeout_seconds: int = 45
    context_max_tokens: int = 12000
    context_reserved_tokens: int = 2500
    memory_enabled: bool = True
    memory_recall_limit: int = 6
    memory_working_ttl_seconds: int = 86400
    skills_dir: str = "skills"
    github_app_id: str = ""
    github_app_slug: str = ""
    github_private_key_path: str = ""
    public_base_url: str = "http://127.0.0.1:8080"
    llm_provider: str = "local"
    deepseek_api_key: str = ""
    openrouter_api_key: str = ""
    openrouter_site_url: str = ""
    openrouter_app_name: str = "LIMA"
    eval_max_cases: int = 5
    eval_min_cases: int = 3
    eval_min_improvement: float = 0.01
    eval_min_holdout_cases: int = 2
    eval_max_metric_regression: float = 0.0
    auth_required: bool = False
    auth_secret: str = ""
    bootstrap_admin_username: str = ""
    bootstrap_admin_password: str = ""
    default_tenant_id: str = "default"
    session_ttl_seconds: int = 3600
    webhook_max_age_seconds: int = 600
    queue_max_attempts: int = 3
    queue_lease_seconds: int = 60
    skill_timeout_seconds: int = 30
    skill_memory_mb: int = 256
    skill_sandbox: bool = True
    skill_signing_key: str = ""
    skill_container_image: str = ""
    repair_test_command: str = ""
    repair_verify_timeout_seconds: int = 120
    otel_endpoint: str = ""
    otel_service_name: str = "lima"
    alert_failure_rate: float = 0.20
    alert_min_samples: int = 10
    alert_window_seconds: int = 900
    alert_webhook_url: str = ""
    alert_smtp_host: str = ""
    alert_email_to: str = ""
    continuous_eval_seconds: int = 0
    experiment_workers: int = 1
    experiment_queue_lease_seconds: int = 3600
    experiment_dataset_root: str = "evaluation_data"
    experiment_artifact_root: str = "output/experiments"
    experiment_cache_root: str = "output/experiment-cache"
    experiment_max_llm_calls: int = 20
    experiment_max_total_tokens: int = 100_000
    repository_import_root: str = ""
    repository_scan_sast_mode: str = "required"
    repository_scan_max_files: int = 5000
    repository_scan_max_file_bytes: int = 512 * 1024
    repository_scan_max_total_bytes: int = 20 * 1024 * 1024
    repository_scan_llm_mode: str = "off"
    repository_scan_llm_timeout_seconds: int = 60
    repository_scan_llm_max_candidates: int = 6
    repository_scan_llm_max_context_chars: int = 36_000
    repository_scan_llm_max_completion_tokens: int = 3_000

    def resolved_llm(self) -> Dict[str, object]:
        """Resolve a named provider to the existing OpenAI-compatible transport."""
        provider = self.llm_provider.strip().lower()
        if provider in {"", "local", "none"}:
            if self.llm_base_url or self.llm_api_key or self.llm_model:
                provider = "custom"
            else:
                return {}

        if provider == "deepseek":
            api_key = self.deepseek_api_key or self.llm_api_key
            if not api_key:
                raise ValueError("DeepSeek requires LIMA_DEEPSEEK_API_KEY")
            return {
                "provider": "deepseek",
                "base_url": self.llm_base_url or "https://api.deepseek.com",
                "api_key": api_key,
                "model": self.llm_model or "deepseek-v4-flash",
                "headers": {},
            }

        if provider in {"openrouter-deepseek-free", "openrouter_deepseek_free"}:
            api_key = self.openrouter_api_key or self.llm_api_key
            if not api_key:
                raise ValueError("OpenRouter requires LIMA_OPENROUTER_API_KEY")
            headers = {}
            if self.openrouter_site_url:
                headers["HTTP-Referer"] = self.openrouter_site_url
            if self.openrouter_app_name:
                headers["X-Title"] = self.openrouter_app_name
            return {
                "provider": "openrouter-deepseek-free",
                "base_url": self.llm_base_url or "https://openrouter.ai/api/v1",
                "api_key": api_key,
                "model": self.llm_model or "deepseek/deepseek-chat-v3-0324:free",
                "headers": headers,
            }

        if provider == "openrouter-free":
            api_key = self.openrouter_api_key or self.llm_api_key
            if not api_key:
                raise ValueError("OpenRouter requires LIMA_OPENROUTER_API_KEY")
            headers = {}
            if self.openrouter_site_url:
                headers["HTTP-Referer"] = self.openrouter_site_url
            if self.openrouter_app_name:
                headers["X-Title"] = self.openrouter_app_name
            return {
                "provider": "openrouter-free",
                "base_url": self.llm_base_url or "https://openrouter.ai/api/v1",
                "api_key": api_key,
                "model": self.llm_model or "openrouter/free",
                "headers": headers,
            }

        if provider == "custom":
            if not (self.llm_base_url and self.llm_api_key and self.llm_model):
                raise ValueError(
                    "Custom LLM requires LIMA_LLM_BASE_URL, "
                    "LIMA_LLM_API_KEY and LIMA_LLM_MODEL"
                )
            return {
                "provider": "custom",
                "base_url": self.llm_base_url,
                "api_key": self.llm_api_key,
                "model": self.llm_model,
                "headers": {},
            }
        raise ValueError("unsupported LIMA_LLM_PROVIDER: %s" % self.llm_provider)

    def validate_evolution(self) -> None:
        if self.eval_min_cases > self.eval_max_cases:
            raise ValueError("LIMA_EVAL_MIN_CASES cannot exceed LIMA_EVAL_MAX_CASES")
        if not 0.0 <= self.eval_min_improvement <= 1.0:
            raise ValueError("LIMA_EVAL_MIN_IMPROVEMENT must be between 0 and 1")
        if self.eval_min_holdout_cases > self.eval_max_cases:
            raise ValueError("LIMA_EVAL_MIN_HOLDOUT_CASES cannot exceed LIMA_EVAL_MAX_CASES")
        if not 0.0 <= self.eval_max_metric_regression <= 1.0:
            raise ValueError("LIMA_EVAL_MAX_METRIC_REGRESSION must be between 0 and 1")
        if self.auth_required and len(self.auth_secret.encode("utf-8")) < 32:
            raise ValueError(
                "LIMA_AUTH_SECRET must contain at least 32 bytes when authentication is enabled"
            )
        if bool(self.bootstrap_admin_username) != bool(self.bootstrap_admin_password):
            raise ValueError("bootstrap admin username and password must be configured together")
        if not 0.0 <= self.alert_failure_rate <= 1.0:
            raise ValueError("LIMA_ALERT_FAILURE_RATE must be between 0 and 1")
        if self.agent_max_workers < 1:
            raise ValueError("LIMA_AGENT_MAX_WORKERS must be at least 1")
        if self.agent_retries < 0:
            raise ValueError("LIMA_AGENT_RETRIES cannot be negative")
        if self.collaboration_rounds < 1:
            raise ValueError("LIMA_COLLABORATION_ROUNDS must be at least 1")
        if self.agent_loop_max_steps < 1:
            raise ValueError("LIMA_AGENT_LOOP_MAX_STEPS must be at least 1")
        if self.context_max_tokens < 512:
            raise ValueError("LIMA_CONTEXT_MAX_TOKENS must be at least 512")
        if not 0 <= self.context_reserved_tokens < self.context_max_tokens:
            raise ValueError(
                "LIMA_CONTEXT_RESERVED_TOKENS must be smaller than the context budget"
            )
        if self.repository_scan_sast_mode not in {"auto", "off", "required"}:
            raise ValueError(
                "LIMA_REPOSITORY_SCAN_SAST_MODE must be auto, off or required"
            )
        if self.repository_scan_llm_mode not in {"off", "auto", "required"}:
            raise ValueError(
                "LIMA_REPOSITORY_SCAN_LLM_MODE must be off, auto or required"
            )
        if min(
            self.repository_scan_max_files,
            self.repository_scan_max_file_bytes,
            self.repository_scan_max_total_bytes,
            self.repository_scan_llm_timeout_seconds,
            self.repository_scan_llm_max_candidates,
            self.repository_scan_llm_max_context_chars,
            self.repository_scan_llm_max_completion_tokens,
        ) < 1:
            raise ValueError("repository scan limits must be positive")

    @classmethod
    def from_env(cls) -> "Settings":
        return cls(
            host=os.getenv("LIMA_HOST", "127.0.0.1"),
            port=_int("LIMA_PORT", 8080),
            db_path=os.getenv("LIMA_DB_PATH", "lima.db"),
            max_diff_bytes=_int("LIMA_MAX_DIFF_BYTES", 1024 * 1024),
            max_steps=_int("LIMA_MAX_STEPS", 8),
            timeout_seconds=_int("LIMA_TIMEOUT_SECONDS", 120),
            llm_base_url=os.getenv("LIMA_LLM_BASE_URL", "").rstrip("/"),
            llm_api_key=os.getenv("LIMA_LLM_API_KEY", ""),
            llm_model=os.getenv("LIMA_LLM_MODEL", ""),
            github_webhook_secret=os.getenv("LIMA_GITHUB_WEBHOOK_SECRET", ""),
            github_token=os.getenv("LIMA_GITHUB_TOKEN", ""),
            auto_post_review=_bool("LIMA_AUTO_POST_REVIEW"),
            database_url=os.getenv("LIMA_DATABASE_URL", ""),
            redis_url=os.getenv("LIMA_REDIS_URL", ""),
            async_workers=_int("LIMA_ASYNC_WORKERS", 2),
            agent_max_workers=_int("LIMA_AGENT_MAX_WORKERS", 4),
            agent_retries=_non_negative_int("LIMA_AGENT_RETRIES", 1),
            collaboration_rounds=_int("LIMA_COLLABORATION_ROUNDS", 2),
            agent_loop_max_steps=_int("LIMA_AGENT_LOOP_MAX_STEPS", 4),
            agent_loop_timeout_seconds=_int("LIMA_AGENT_LOOP_TIMEOUT_SECONDS", 45),
            context_max_tokens=_int("LIMA_CONTEXT_MAX_TOKENS", 12000),
            context_reserved_tokens=_non_negative_int(
                "LIMA_CONTEXT_RESERVED_TOKENS", 2500
            ),
            memory_enabled=_bool("LIMA_MEMORY_ENABLED", True),
            memory_recall_limit=_int("LIMA_MEMORY_RECALL_LIMIT", 6),
            memory_working_ttl_seconds=_int(
                "LIMA_MEMORY_WORKING_TTL_SECONDS", 86400
            ),
            skills_dir=os.getenv("LIMA_SKILLS_DIR", "skills"),
            github_app_id=os.getenv("LIMA_GITHUB_APP_ID", ""),
            github_app_slug=os.getenv("LIMA_GITHUB_APP_SLUG", ""),
            github_private_key_path=os.getenv("LIMA_GITHUB_PRIVATE_KEY_PATH", ""),
            public_base_url=os.getenv("LIMA_PUBLIC_BASE_URL", "http://127.0.0.1:8080").rstrip("/"),
            llm_provider=os.getenv("LIMA_LLM_PROVIDER", "local"),
            deepseek_api_key=os.getenv("LIMA_DEEPSEEK_API_KEY", ""),
            openrouter_api_key=os.getenv("LIMA_OPENROUTER_API_KEY", ""),
            openrouter_site_url=os.getenv("LIMA_OPENROUTER_SITE_URL", ""),
            openrouter_app_name=os.getenv("LIMA_OPENROUTER_APP_NAME", "LIMA"),
            eval_max_cases=_int("LIMA_EVAL_MAX_CASES", 5),
            eval_min_cases=_int("LIMA_EVAL_MIN_CASES", 3),
            eval_min_improvement=float(os.getenv("LIMA_EVAL_MIN_IMPROVEMENT", "0.01")),
            eval_min_holdout_cases=_non_negative_int("LIMA_EVAL_MIN_HOLDOUT_CASES", 2),
            eval_max_metric_regression=float(
                os.getenv("LIMA_EVAL_MAX_METRIC_REGRESSION", "0")
            ),
            auth_required=_bool("LIMA_AUTH_REQUIRED", False),
            auth_secret=os.getenv("LIMA_AUTH_SECRET", ""),
            bootstrap_admin_username=os.getenv("LIMA_BOOTSTRAP_ADMIN_USERNAME", ""),
            bootstrap_admin_password=os.getenv("LIMA_BOOTSTRAP_ADMIN_PASSWORD", ""),
            default_tenant_id=os.getenv("LIMA_DEFAULT_TENANT_ID", "default"),
            session_ttl_seconds=_int("LIMA_SESSION_TTL_SECONDS", 3600),
            webhook_max_age_seconds=_int("LIMA_WEBHOOK_MAX_AGE_SECONDS", 600),
            queue_max_attempts=_int("LIMA_QUEUE_MAX_ATTEMPTS", 3),
            queue_lease_seconds=_int("LIMA_QUEUE_LEASE_SECONDS", 60),
            skill_timeout_seconds=_int("LIMA_SKILL_TIMEOUT_SECONDS", 30),
            skill_memory_mb=_int("LIMA_SKILL_MEMORY_MB", 256),
            skill_sandbox=_bool("LIMA_SKILL_SANDBOX", True),
            skill_signing_key=os.getenv("LIMA_SKILL_SIGNING_KEY", ""),
            skill_container_image=os.getenv("LIMA_SKILL_CONTAINER_IMAGE", ""),
            repair_test_command=os.getenv("LIMA_REPAIR_TEST_COMMAND", ""),
            repair_verify_timeout_seconds=_int("LIMA_REPAIR_VERIFY_TIMEOUT_SECONDS", 120),
            otel_endpoint=os.getenv("LIMA_OTEL_ENDPOINT", ""),
            otel_service_name=os.getenv("LIMA_OTEL_SERVICE_NAME", "lima"),
            alert_failure_rate=float(os.getenv("LIMA_ALERT_FAILURE_RATE", "0.20")),
            alert_min_samples=_int("LIMA_ALERT_MIN_SAMPLES", 10),
            alert_window_seconds=_int("LIMA_ALERT_WINDOW_SECONDS", 900),
            alert_webhook_url=os.getenv("LIMA_ALERT_WEBHOOK_URL", ""),
            alert_smtp_host=os.getenv("LIMA_ALERT_SMTP_HOST", ""),
            alert_email_to=os.getenv("LIMA_ALERT_EMAIL_TO", ""),
            continuous_eval_seconds=_non_negative_int(
                "LIMA_CONTINUOUS_EVAL_SECONDS", 0
            ),
            experiment_workers=_int("LIMA_EXPERIMENT_WORKERS", 1),
            experiment_queue_lease_seconds=_int(
                "LIMA_EXPERIMENT_QUEUE_LEASE_SECONDS", 3600
            ),
            experiment_dataset_root=os.getenv(
                "LIMA_EXPERIMENT_DATASET_ROOT", "evaluation_data"
            ),
            experiment_artifact_root=os.getenv(
                "LIMA_EXPERIMENT_ARTIFACT_ROOT", "output/experiments"
            ),
            experiment_cache_root=os.getenv(
                "LIMA_EXPERIMENT_CACHE_ROOT", "output/experiment-cache"
            ),
            experiment_max_llm_calls=_int(
                "LIMA_EXPERIMENT_MAX_LLM_CALLS", 20
            ),
            experiment_max_total_tokens=_int(
                "LIMA_EXPERIMENT_MAX_TOTAL_TOKENS", 100_000
            ),
            repository_import_root=os.getenv("LIMA_REPOSITORY_IMPORT_ROOT", ""),
            repository_scan_sast_mode=os.getenv(
                "LIMA_REPOSITORY_SCAN_SAST_MODE", "required"
            ).strip().lower(),
            repository_scan_max_files=_int(
                "LIMA_REPOSITORY_SCAN_MAX_FILES", 5000
            ),
            repository_scan_max_file_bytes=_int(
                "LIMA_REPOSITORY_SCAN_MAX_FILE_BYTES", 512 * 1024
            ),
            repository_scan_max_total_bytes=_int(
                "LIMA_REPOSITORY_SCAN_MAX_TOTAL_BYTES", 20 * 1024 * 1024
            ),
            repository_scan_llm_mode=os.getenv(
                "LIMA_REPOSITORY_SCAN_LLM_MODE", "off"
            ).strip().lower(),
            repository_scan_llm_timeout_seconds=_int(
                "LIMA_REPOSITORY_SCAN_LLM_TIMEOUT_SECONDS", 60
            ),
            repository_scan_llm_max_candidates=_int(
                "LIMA_REPOSITORY_SCAN_LLM_MAX_CANDIDATES", 6
            ),
            repository_scan_llm_max_context_chars=_int(
                "LIMA_REPOSITORY_SCAN_LLM_MAX_CONTEXT_CHARS", 36_000
            ),
            repository_scan_llm_max_completion_tokens=_int(
                "LIMA_REPOSITORY_SCAN_LLM_MAX_COMPLETION_TOKENS", 3_000
            ),
        )
