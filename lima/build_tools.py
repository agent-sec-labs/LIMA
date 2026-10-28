"""Controlled build tools for the repository build agent (slice 2).

Seven structured tools are the model's entire build surface: inspect build
descriptions, propose a candidate plan, bind an approved dependency set,
execute configure through the bounded executor, read bounded failure
evidence, and export/validate the context package.  Tools accept structured
references and argv arrays only -- never a shell, a host path, a Docker
socket or a budget: those live in the trusted, code-built context.  All
references handed back to the model are relative to the artifacts root.
"""

from __future__ import annotations

import dataclasses
from collections.abc import Callable
from pathlib import Path, PurePosixPath
from typing import Any, Final

from lima.build_contracts import (
    BuildPlan,
    BuildPlanError,
    BuildPolicy,
    BuildRequest,
    ValidatedBuildPlan,
    plan_digest,
    validate_build_plan,
)
from lima.build_executor import BuildExecutionResult, BuildExecutor, BuildLimits
from lima.build_recipe import BuildRecipe, IncludeRoot
from lima.context_package import read_package
from lima.runtime import AgentTool, ToolRegistry

__all__ = ["register_build_tools", "BUILD_TOOL_NAMES"]

BUILD_TOOL_NAMES: Final = (
    "inspect_build_files",
    "propose_build_plan",
    "prepare_dependencies",
    "execute_configure",
    "inspect_build_failure",
    "export_context_package",
    "validate_context",
)

# Bounded failure evidence handed to the model per inspection.
_FAILURE_TAIL_BYTES: Final = 32 * 1024
_INSPECT_MAX_FILES: Final = 128
_INSPECT_MAX_DEPTH: Final = 4
_BUILD_FILE_NAMES: Final = frozenset(
    {"CMakeLists.txt", "CMakePresets.json", "CMakeUserPresets.json", ".gitmodules"}
)
_BUILD_FILE_PREFIXES: Final = ("README",)
_SKIPPED_DIRECTORIES: Final = frozenset({".git", "build", "_deps"})


@dataclasses.dataclass(slots=True)
class _ToolContext:
    """Trusted per-run state; built by code, never by the model."""

    request: BuildRequest
    policy: BuildPolicy
    snapshot_dir: Path
    artifacts_root: Path
    executor: BuildExecutor
    cancel: Callable[[], bool]
    pending_plan: ValidatedBuildPlan | None = None
    prepared_ref: str | None = None
    attempts: int = 0
    last_result: BuildExecutionResult | None = None
    package_ref: str | None = None
    # The plan identity the current package was produced by; a new plan or a
    # failed attempt invalidates the package reference.
    package_plan_digest: str | None = None


def _no_arguments_schema() -> dict[str, Any]:
    return {
        "type": "object",
        "properties": {},
        "required": [],
        "additionalProperties": False,
    }


def _tool_inspect_build_files(context: _ToolContext) -> dict[str, Any]:
    matches: list[dict[str, Any]] = []
    root = context.snapshot_dir
    if root.is_dir():
        for path in _walk_bounded(root, _INSPECT_MAX_DEPTH):
            name = path.name
            if name in _BUILD_FILE_NAMES or name.startswith(_BUILD_FILE_PREFIXES):
                matches.append(
                    {
                        "path": path.relative_to(root).as_posix(),
                        "bytes": path.stat().st_size,
                    }
                )
                if len(matches) >= _INSPECT_MAX_FILES:
                    break
    return {"ok": True, "files": matches, "truncated": len(matches) >= _INSPECT_MAX_FILES}


def _walk_bounded(root: Path, max_depth: int):
    def walk(directory: Path, depth: int):
        if depth > max_depth:
            return
        try:
            entries = sorted(directory.iterdir())
        except OSError:
            return
        for entry in entries:
            if entry.is_dir():
                if entry.name not in _SKIPPED_DIRECTORIES:
                    yield from walk(entry, depth + 1)
            else:
                yield entry

    yield from walk(root, 0)


def _tool_propose_build_plan(
    context: _ToolContext, *, plan: dict[str, Any]
) -> dict[str, Any]:
    try:
        parsed = BuildPlan.from_mapping(plan)
        validated = validate_build_plan(context.request, parsed, context.policy)
    except BuildPlanError as exc:
        return {"ok": False, "error": exc.reason}
    context.pending_plan = validated
    # Accepting a new plan invalidates any package produced under an older
    # one: it must never be exported as this plan's result.
    context.package_ref = None
    context.package_plan_digest = None
    return {
        "ok": True,
        "adapter": validated.plan.adapter,
        "dependency_set_ref": validated.plan.dependency_set_ref,
        "image": validated.dependency_set.image,
        "plan_digest": plan_digest(validated.plan),
    }


def _tool_prepare_dependencies(
    context: _ToolContext, *, dependency_set_ref: str
) -> dict[str, Any]:
    approved = context.policy.dependency_sets.get(dependency_set_ref)
    if approved is None:
        return {"ok": False, "error": f"dependency-set-not-approved:{dependency_set_ref}"}
    context.prepared_ref = dependency_set_ref
    return {"ok": True, "image": approved.image}


def _tool_execute_configure(context: _ToolContext) -> dict[str, Any]:
    validated = context.pending_plan
    if validated is None:
        return {"ok": False, "error": "no-validated-plan"}
    if context.prepared_ref != validated.plan.dependency_set_ref:
        return {"ok": False, "error": "dependencies-not-prepared"}
    budget = validated.budget
    if context.attempts >= budget.max_attempts:
        return {"ok": False, "error": "budget-exhausted-attempts"}
    try:
        recipe = _recipe_from(validated, context.policy)
    except BuildPlanError as exc:
        return {"ok": False, "error": f"recipe-conversion-failed:{exc.reason}"}
    context.attempts += 1
    attempt_ref = f"attempt-{context.attempts}"
    result = context.executor.execute(
        recipe,
        context.snapshot_dir,
        context.artifacts_root / attempt_ref,
        limits=BuildLimits(
            total_seconds=budget.total_seconds,
            step_seconds=budget.step_seconds,
            max_output_bytes=budget.max_output_bytes,
        ),
        cancel=context.cancel,
        revision=context.request.snapshot_hash,
    )
    context.last_result = result
    if not result.ok:
        # A failed attempt invalidates the current package reference too:
        # stale success must not survive as an exportable result.
        context.package_ref = None
        context.package_plan_digest = None
    approved_digest = validated.dependency_set.image_digest
    if (
        result.ok
        and approved_digest is not None
        and result.image_digest is not None
        and result.image_digest != approved_digest
    ):
        context.package_ref = None
        context.package_plan_digest = None
        return {
            "ok": False,
            "attempt": context.attempts,
            "error": "image-digest-mismatch",
            "approved": approved_digest,
            "executed": result.image_digest,
        }
    if result.ok:
        context.package_ref = f"{attempt_ref}/package"
        context.package_plan_digest = plan_digest(validated.plan)
    return {
        "ok": result.ok,
        "attempt": context.attempts,
        "failure_code": result.failure_code,
        "package_ref": f"{attempt_ref}/package" if result.ok else None,
        "steps": [
            {
                "step_id": step.step_id,
                "exit_code": step.exit_code,
                "timed_out": step.timed_out,
                # Root-relative so the reference round-trips through
                # inspect_build_failure unchanged.
                "stderr_ref": f"{attempt_ref}/{step.stderr_ref}",
            }
            for step in result.steps
        ],
    }


def _recipe_from(validated: ValidatedBuildPlan, policy: BuildPolicy) -> BuildRecipe:
    plan = validated.plan
    dependency_set = validated.dependency_set
    # Pin the approved digest when one exists: a mutable tag must never
    # decide which offline dependency image actually runs.
    image = (
        dependency_set.image
        if dependency_set.image_digest is None
        else f"{dependency_set.image}@{dependency_set.image_digest}"
    )
    return BuildRecipe(
        schema_version=1,
        name=f"build-agent-{validated.request.snapshot_hash[:12]}",
        image=image,
        repository=validated.request.repository_ref,
        source_mount=policy.source_mount,
        configure=plan.configure_argv,
        compdb_path=plan.expected_compdb,
        generated_globs=plan.generated_headers,
        include_roots=tuple(
            IncludeRoot(container=root.container, package=root.package)
            for root in plan.include_roots
        ),
    )


def _tool_inspect_build_failure(
    context: _ToolContext, *, step_ref: str
) -> dict[str, Any]:
    relative = PurePosixPath(step_ref)
    if (
        relative.is_absolute()
        or not step_ref
        or any(part in {"", ".", ".."} for part in relative.parts)
        or "\\" in step_ref
        or ":" in step_ref
    ):
        return {"ok": False, "error": "step-ref-invalid"}
    target = (context.artifacts_root / Path(*relative.parts)).resolve()
    if not target.is_relative_to(context.artifacts_root.resolve()) or not target.is_file():
        return {"ok": False, "error": "step-ref-invalid"}
    data = _read_file_tail(target, _FAILURE_TAIL_BYTES)
    size = target.stat().st_size
    marker = (
        f"[truncated: showing last {len(data)} of {size} bytes]\n"
        if size > len(data)
        else ""
    )
    # The marker line counts against the model-facing byte budget.
    if marker:
        data = data[len(marker.encode("utf8")) :]
    return {
        "ok": True,
        "step_ref": step_ref,
        "tail": marker + data.decode("utf8", errors="replace"),
    }


def _read_file_tail(path: Path, limit: int) -> bytes:
    size = path.stat().st_size
    with path.open("rb") as handle:
        handle.seek(max(0, size - limit))
        return handle.read()


def _tool_export_context_package(context: _ToolContext) -> dict[str, Any]:
    if context.package_ref is None:
        return {"ok": False, "error": "no-exported-package"}
    return {
        "ok": True,
        "package_ref": context.package_ref,
        "revision": context.request.snapshot_hash,
        "plan_digest": context.package_plan_digest,
    }


def _tool_validate_context(context: _ToolContext) -> dict[str, Any]:
    if context.package_ref is None:
        return {"ok": False, "error": "no-exported-package"}
    package_dir = context.artifacts_root / context.package_ref
    try:
        package = read_package(package_dir)
    except Exception:  # noqa: BLE001 - any reader failure is a bad package
        return {"ok": False, "error": "package-invalid"}
    if package.manifest.revision != context.request.snapshot_hash:
        return {"ok": False, "error": "snapshot-mismatch"}
    return {
        "ok": True,
        "snapshot_hash": context.request.snapshot_hash,
        "context_hash": package.manifest.context_hash,
        "plan_digest": context.package_plan_digest,
    }


def register_build_tools(
    registry: ToolRegistry,
    executor: BuildExecutor,
    policy: BuildPolicy,
    *,
    request: BuildRequest,
    snapshot_dir: Path,
    artifacts_root: Path,
    cancel: Callable[[], bool] = lambda: False,
) -> None:
    """Register the seven controlled build tools bound to one run.

    ``executor`` and ``policy`` are run-independent; ``request``,
    ``snapshot_dir`` and ``artifacts_root`` bind the tools to exactly one
    trusted snapshot and evidence root, so the model can never name a host
    path, an image, or a budget of its own.
    """

    context = _ToolContext(
        request=request,
        policy=policy,
        snapshot_dir=Path(snapshot_dir),
        artifacts_root=Path(artifacts_root),
        executor=executor,
        cancel=cancel,
    )
    registry.register(
        AgentTool(
            name="inspect_build_files",
            description=(
                "List build description files (CMakeLists, presets, README,"
                " submodule manifests) of the bound snapshot, bounded in"
                " count and depth."
            ),
            parameters=_no_arguments_schema(),
            handler=lambda: _tool_inspect_build_files(context),
        )
    )
    registry.register(
        AgentTool(
            name="propose_build_plan",
            description=(
                "Submit a candidate BuildPlan for validation. The plan is"
                " data only; it must match the request snapshot and component"
                " scope and use policy-approved adapter and dependency set."
            ),
            parameters={
                "type": "object",
                "properties": {"plan": {"type": "object"}},
                "required": ["plan"],
                "additionalProperties": False,
            },
            handler=lambda plan: _tool_propose_build_plan(context, plan=plan),
        )
    )
    registry.register(
        AgentTool(
            name="prepare_dependencies",
            description=(
                "Bind one deployment-approved offline dependency set; nothing"
                " outside the policy list can be selected and no network"
                " operation exists."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "dependency_set_ref": {"type": "string"}
                },
                "required": ["dependency_set_ref"],
                "additionalProperties": False,
            },
            handler=lambda dependency_set_ref: _tool_prepare_dependencies(
                context, dependency_set_ref=dependency_set_ref
            ),
        )
    )
    registry.register(
        AgentTool(
            name="execute_configure",
            description=(
                "Run one bounded configure attempt of the validated plan"
                " through the isolated executor. Attempts are counted against"
                " the frozen budget."
            ),
            parameters=_no_arguments_schema(),
            handler=lambda: _tool_execute_configure(context),
        )
    )
    registry.register(
        AgentTool(
            name="inspect_build_failure",
            description=(
                "Read a bounded tail of one step log from this run's"
                " artifacts. Only run-relative references are accepted."
            ),
            parameters={
                "type": "object",
                "properties": {"step_ref": {"type": "string"}},
                "required": ["step_ref"],
                "additionalProperties": False,
            },
            handler=lambda step_ref: _tool_inspect_build_failure(
                context, step_ref=step_ref
            ),
        )
    )
    registry.register(
        AgentTool(
            name="export_context_package",
            description=(
                "Report the exported context package reference of the latest"
                " successful attempt."
            ),
            parameters=_no_arguments_schema(),
            handler=lambda: _tool_export_context_package(context),
        )
    )
    registry.register(
        AgentTool(
            name="validate_context",
            description=(
                "Validate the exported package reads back and is bound to the"
                " request snapshot."
            ),
            parameters=_no_arguments_schema(),
            handler=lambda: _tool_validate_context(context),
        )
    )
