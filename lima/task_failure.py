"""Structured task failure taxonomy with retry semantics (observability epic T2).

Raw exception strings cannot answer the four questions users actually ask:
where did the task fail, why, is it worth retrying, and what should they do.
This module turns failures into typed objects:

- a fixed catalog of failure codes with category, default retryability and a
  user-facing suggestion;
- :class:`TaskFailure`, the serializable diagnostic payload;
- :class:`TaskFailureError`, the exception bridge that lets the task queue
  route retryable failures into the retry path and permanent ones straight
  into the dead-letter queue without inspecting message text;
- :func:`classify_exception`, a defensive mapper from legacy exception types
  (HTTPError / URLError / OSError / known message shapes) into the catalog.

Credentials never survive into failure payloads: technical detail passes the
same sanitizer used for task progress.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .task_progress import sanitize

CATEGORY_GITHUB = "github"
CATEGORY_ARCHIVE = "archive"
CATEGORY_CACHE = "cache"
CATEGORY_WORKSPACE = "workspace"
CATEGORY_SCANNER = "scanner"
CATEGORY_SEMANTIC = "semantic-triage"
CATEGORY_QUEUE = "queue"

GITHUB_NOT_FOUND = "GITHUB_NOT_FOUND"
GITHUB_AUTH_REQUIRED = "GITHUB_AUTH_REQUIRED"
GITHUB_RATE_LIMITED = "GITHUB_RATE_LIMITED"
GITHUB_NETWORK_ERROR = "GITHUB_NETWORK_ERROR"
GITHUB_TIMEOUT = "GITHUB_TIMEOUT"
GITHUB_INVALID_REF = "GITHUB_INVALID_REF"
ARCHIVE_TOO_LARGE = "ARCHIVE_TOO_LARGE"
ARCHIVE_INVALID = "ARCHIVE_INVALID"
ARCHIVE_UNSAFE_PATH = "ARCHIVE_UNSAFE_PATH"
ARCHIVE_TOO_MANY_FILES = "ARCHIVE_TOO_MANY_FILES"
ARCHIVE_MEMBER_TOO_LARGE = "ARCHIVE_MEMBER_TOO_LARGE"
ARCHIVE_DECOMPRESSION_LIMIT = "ARCHIVE_DECOMPRESSION_LIMIT"
CACHE_NO_SPACE = "CACHE_NO_SPACE"
CACHE_QUOTA_EXCEEDED = "CACHE_QUOTA_EXCEEDED"
CACHE_LOCK_TIMEOUT = "CACHE_LOCK_TIMEOUT"
CACHE_PUBLISH_FAILED = "CACHE_PUBLISH_FAILED"
WORKSPACE_FILE_LIMIT = "WORKSPACE_FILE_LIMIT"
WORKSPACE_SIZE_LIMIT = "WORKSPACE_SIZE_LIMIT"
WORKSPACE_INVALID = "WORKSPACE_INVALID"
SAST_FAILED = "SAST_FAILED"
STATIC_ANALYSIS_FAILED = "STATIC_ANALYSIS_FAILED"
SEMANTIC_TRIAGE_FAILED = "SEMANTIC_TRIAGE_FAILED"
SEMANTIC_PROVIDER_TIMEOUT = "SEMANTIC_PROVIDER_TIMEOUT"
SEMANTIC_INVALID_RESPONSE = "SEMANTIC_INVALID_RESPONSE"
QUEUE_RETRY_EXHAUSTED = "QUEUE_RETRY_EXHAUSTED"
TASK_INTERNAL_ERROR = "TASK_INTERNAL_ERROR"


@dataclass(frozen=True)
class FailureSpec:
    code: str
    category: str
    retryable: bool
    title: str
    message: str
    suggestion: str


def _spec(
    code: str, category: str, retryable: bool,
    title: str, message: str, suggestion: str,
) -> FailureSpec:
    return FailureSpec(code, category, retryable, title, message, suggestion)


FAILURE_CATALOG: dict[str, FailureSpec] = {
    spec.code: spec
    for spec in (
        # --- GitHub / 网络 -------------------------------------------------
        _spec(GITHUB_NOT_FOUND, CATEGORY_GITHUB, False,
              "无法找到 GitHub 仓库", "仓库或指定的 ref 不存在。",
              "确认仓库地址与 ref 是否正确；私有仓库需要配置访问凭据。"),
        _spec(GITHUB_AUTH_REQUIRED, CATEGORY_GITHUB, False,
              "GitHub 访问被拒绝", "当前凭据无权访问该仓库。",
              "检查服务端配置的 GitHub 凭据与仓库权限。"),
        _spec(GITHUB_RATE_LIMITED, CATEGORY_GITHUB, True,
              "GitHub 请求频率受限", "API 配额暂时耗尽。",
              "系统会自动重试；持续出现请在服务端配置凭据以提高配额。"),
        _spec(GITHUB_NETWORK_ERROR, CATEGORY_GITHUB, True,
              "无法连接 GitHub", "服务器与 GitHub 的网络连接出现临时错误。",
              "系统会自动重试；持续失败请检查服务器出口网络、DNS 或代理。"),
        _spec(GITHUB_TIMEOUT, CATEGORY_GITHUB, True,
              "GitHub 请求超时", "请求 GitHub 超过时间预算。",
              "系统会自动重试；大仓库可稍后重试或提高超时配置。"),
        _spec(GITHUB_INVALID_REF, CATEGORY_GITHUB, False,
              "无效的版本引用", "ref 无法解析为不可变 commit。",
              "确认分支/标签名称，或直接使用完整 commit SHA。"),
        # --- Archive -------------------------------------------------------
        _spec(ARCHIVE_TOO_LARGE, CATEGORY_ARCHIVE, False,
              "仓库归档过大", "下载内容超过归档大小上限。",
              "该仓库超出当前安全预算，无法审计；请检查仓库体积。"),
        _spec(ARCHIVE_INVALID, CATEGORY_ARCHIVE, False,
              "仓库归档无效", "归档损坏或不是有效的压缩包。",
              "归档内容无法安全解包，重复提交不会解决该问题。"),
        _spec(ARCHIVE_UNSAFE_PATH, CATEGORY_ARCHIVE, False,
              "归档包含不安全路径", "仓库内容触发路径安全策略。",
              "仓库中存在路径穿越条目；当前错误不是临时问题。"),
        _spec(ARCHIVE_TOO_MANY_FILES, CATEGORY_ARCHIVE, False,
              "归档条目过多", "文件数量超过工作区文件预算。",
              "该仓库超出当前扫描预算；请联系管理员调整上限。"),
        _spec(ARCHIVE_MEMBER_TOO_LARGE, CATEGORY_ARCHIVE, False,
              "单个文件过大", "归档内单文件超过大小上限。",
              "请检查仓库中是否存在超大文件。"),
        _spec(ARCHIVE_DECOMPRESSION_LIMIT, CATEGORY_ARCHIVE, False,
              "解压总量超限", "解压后的总字节数超过预算。",
              "该仓库超出当前扫描预算；请联系管理员调整上限。"),
        # --- Cache / Disk --------------------------------------------------
        _spec(CACHE_NO_SPACE, CATEGORY_CACHE, False,
              "缓存空间不足", "仓库缓存所在磁盘可用空间不足。",
              "请清理缓存或扩容 repository-cache 卷后重试。"),
        _spec(CACHE_QUOTA_EXCEEDED, CATEGORY_CACHE, False,
              "缓存配额耗尽", "快照缓存超过总配额。",
              "请等待缓存清理或提高配额配置。"),
        _spec(CACHE_LOCK_TIMEOUT, CATEGORY_CACHE, True,
              "缓存锁等待超时", "并发物化等待超时。",
              "系统会自动重试；持续出现请降低并发扫描数。"),
        _spec(CACHE_PUBLISH_FAILED, CATEGORY_CACHE, False,
              "快照发布失败", "快照无法写入缓存。",
              "请检查缓存卷可写性与磁盘状态。"),
        # --- Workspace -----------------------------------------------------
        _spec(WORKSPACE_FILE_LIMIT, CATEGORY_WORKSPACE, False,
              "工作区文件超限", "扫描文件数超过预算。",
              "请联系管理员调整扫描上限。"),
        _spec(WORKSPACE_SIZE_LIMIT, CATEGORY_WORKSPACE, False,
              "工作区容量超限", "扫描总字节数超过预算。",
              "请联系管理员调整扫描上限。"),
        _spec(WORKSPACE_INVALID, CATEGORY_WORKSPACE, False,
              "工作区无效", "快照无法作为安全工作区打开。",
              "请重新发起审计；若持续失败请检查快照缓存。"),
        # --- Scanner -------------------------------------------------------
        _spec(SAST_FAILED, CATEGORY_SCANNER, True,
              "SAST 引擎失败", "外部 SAST 引擎执行失败。",
              "系统会自动重试；持续出现请检查 SAST 安装。"),
        _spec(STATIC_ANALYSIS_FAILED, CATEGORY_SCANNER, True,
              "静态分析失败", "AST 或数据流分析执行失败。",
              "系统会自动重试；持续出现请提交任务日志给管理员。"),
        # --- Semantic triage -------------------------------------------------
        _spec(SEMANTIC_TRIAGE_FAILED, CATEGORY_SEMANTIC, True,
              "语义复核失败", "语义复核请求失败。",
              "系统会自动重试或按配置降级为人工复核。"),
        _spec(SEMANTIC_PROVIDER_TIMEOUT, CATEGORY_SEMANTIC, True,
              "语义复核超时", "模型请求超过时间预算。",
              "系统会自动重试或按配置降级为人工复核。"),
        _spec(SEMANTIC_INVALID_RESPONSE, CATEGORY_SEMANTIC, False,
              "语义复核响应无效", "模型输出不符合契约。",
              "该结果按安全策略不采用；可重新发起审计。"),
        # --- Queue / 系统 ---------------------------------------------------
        _spec(QUEUE_RETRY_EXHAUSTED, CATEGORY_QUEUE, False,
              "自动重试已耗尽", "多次自动重试后仍失败。",
              "请根据根因处理后再重新发起审计。"),
        _spec(TASK_INTERNAL_ERROR, CATEGORY_QUEUE, True,
              "任务内部错误", "发生未分类的内部错误。",
              "系统会自动重试；持续出现请提交任务日志给管理员。"),
    )
}


@dataclass
class TaskFailure:
    """A serializable, user-presentable description of why a task failed."""

    code: str
    category: str
    stage: str
    title: str
    message: str
    retryable: bool
    suggestion: str
    technical_detail: str = ""
    detail: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.code not in FAILURE_CATALOG:
            raise ValueError(f"unknown failure code: {self.code!r}")

    @classmethod
    def from_code(
        cls, code: str, stage: str = "", technical_detail: str = "", **detail: Any
    ) -> TaskFailure:
        spec = FAILURE_CATALOG.get(code)
        if spec is None:
            raise ValueError(f"unknown failure code: {code!r}")
        return cls(
            code=spec.code,
            category=spec.category,
            stage=stage,
            title=spec.title,
            message=spec.message,
            retryable=spec.retryable,
            suggestion=spec.suggestion,
            technical_detail=technical_detail,
            detail=dict(detail),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "code": self.code,
            "category": self.category,
            "stage": self.stage,
            "title": self.title,
            "message": self.message,
            "retryable": self.retryable,
            "suggestion": self.suggestion,
            "technical_detail": sanitize(self.technical_detail),
            "detail": sanitize(self.detail),
        }

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> TaskFailure:
        payload = {key: item for key, item in value.items() if key in cls.__dataclass_fields__}
        return cls(**payload)


class TaskFailureError(RuntimeError):
    """Exception carrying a structured :class:`TaskFailure`.

    The task queue routes ``retryable=False`` failures straight into the
    dead-letter queue and lets retryable ones follow the normal retry path.
    """

    def __init__(self, failure: TaskFailure) -> None:
        self.failure = failure
        super().__init__(f"{failure.code}: {failure.technical_detail or failure.message}")


def retry_exhausted_failure(root_cause: str, stage: str = "") -> TaskFailure:
    """Wrap the final retry-exhausted error while preserving the root cause."""

    return TaskFailure.from_code(
        QUEUE_RETRY_EXHAUSTED,
        stage=stage,
        technical_detail=root_cause,
        root_cause=root_cause[:2000],
    )


def classify_exception(exc: BaseException, stage: str = "") -> TaskFailure:
    """Map legacy exception types into the failure catalog.

    Explicitly typed exceptions win; message shapes are a defensive fallback
    for existing error strings until producers adopt typed failures.
    """

    if isinstance(exc, TaskFailureError):
        failure = TaskFailure.from_dict(exc.failure.to_dict())
        failure.stage = failure.stage or stage
        return failure

    text = str(exc)
    lowered = text.lower()

    http_code = getattr(exc, "code", None)
    if isinstance(http_code, int):
        if http_code == 404:
            return TaskFailure.from_code(GITHUB_NOT_FOUND, stage, text)
        if http_code in (401, 403):
            return TaskFailure.from_code(GITHUB_AUTH_REQUIRED, stage, text)
        if http_code == 429:
            return TaskFailure.from_code(GITHUB_RATE_LIMITED, stage, text)
        if http_code >= 500:
            return TaskFailure.from_code(GITHUB_NETWORK_ERROR, stage, text)
        if http_code == 408:
            return TaskFailure.from_code(GITHUB_TIMEOUT, stage, text)

    if "timed out" in lowered or "timeout" in lowered:
        return TaskFailure.from_code(GITHUB_TIMEOUT, stage, text)
    if "symbolic link" in lowered:
        return TaskFailure.from_code(ARCHIVE_UNSAFE_PATH, stage, text)
    if "unsafe path" in lowered or "escapes" in lowered:
        return TaskFailure.from_code(ARCHIVE_UNSAFE_PATH, stage, text)
    if "too many entries" in lowered or "too many files" in lowered:
        return TaskFailure.from_code(ARCHIVE_TOO_MANY_FILES, stage, text)
    if "decompression limit" in lowered:
        return TaskFailure.from_code(ARCHIVE_DECOMPRESSION_LIMIT, stage, text)
    if "member exceeds" in lowered or "per-file" in lowered:
        return TaskFailure.from_code(ARCHIVE_MEMBER_TOO_LARGE, stage, text)
    if "download limit" in lowered:
        return TaskFailure.from_code(ARCHIVE_TOO_LARGE, stage, text)
    if "not a valid zip" in lowered or "empty" in lowered:
        return TaskFailure.from_code(ARCHIVE_INVALID, stage, text)
    if "free space" in lowered or "no space" in lowered:
        return TaskFailure.from_code(CACHE_NO_SPACE, stage, text)
    ref_shaped = ("moving reference" in lowered or "invalid ref" in lowered)
    if ref_shaped or ("not exist" in lowered and "ref" in lowered):
        return TaskFailure.from_code(GITHUB_INVALID_REF, stage, text)
    if "connection" in lowered or "network" in lowered or "reset" in lowered or "dns" in lowered:
        return TaskFailure.from_code(GITHUB_NETWORK_ERROR, stage, text)

    # 未分类错误保持与现状一致的“可重试”语义。
    return TaskFailure.from_code(TASK_INTERNAL_ERROR, stage, text)


__all__ = [
    "FAILURE_CATALOG",
    "FailureSpec",
    "TaskFailure",
    "TaskFailureError",
    "classify_exception",
    "retry_exhausted_failure",
]
