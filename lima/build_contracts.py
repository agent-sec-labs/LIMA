"""Build request, plan and policy contracts (build agent slice 2).

These types freeze the boundary between the model and the executor.  A
``BuildPlan`` is a candidate the model proposes as plain data; it only
becomes executable after :func:`validate_build_plan` binds it to one trusted
``BuildRequest`` (whose snapshot hash comes from the control plane, never
from the model) and one deployment-frozen ``BuildPolicy``.  Every rejection
carries a stable reason string and happens strictly before any container can
start.  Budgets are frozen data too: nothing in a plan can raise them.
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
import re
import unicodedata
from collections.abc import Mapping, Sequence
from typing import Final

__all__ = [
    "ANALYSIS_CONTEXT_GOAL",
    "ApprovedDependencySet",
    "BuildBudget",
    "BuildPlan",
    "BuildPlanError",
    "BuildPolicy",
    "BuildRequest",
    "IncludeRootSpec",
    "ValidatedBuildPlan",
    "plan_digest",
    "validate_build_plan",
]

ANALYSIS_CONTEXT_GOAL: Final = "analysis-context"

_PLAN_FIELDS: Final = (
    "snapshot_hash",
    "adapter",
    "component_scope",
    "configure_argv",
    "expected_compdb",
    "generated_headers",
    "include_roots",
    "dependency_set_ref",
)

_MAX_TEXT_FIELD_BYTES: Final = 512
_MAX_PATH_BYTES: Final = 1024
_MAX_ARGV_ITEM_BYTES: Final = 4096
_MAX_CONFIGURE_COMMANDS: Final = 64
_HEX64_PATTERN: Final = re.compile(r"[0-9a-f]{64}")
_WINDOWS_DRIVE_PATTERN: Final = re.compile(r"^[A-Za-z]:")
# Shell splices are inert once argv lists reach execve, but a model that
# emits them is telling us it thinks it is writing a shell command; refuse.
_UNSAFE_ARGUMENT_TOKENS: Final = ("&&", "|", "$(", "`")

# Configure-only argument surface for the cmake-linux adapter.  Tool-mode
# (-E), script (-P), build (--build) and install entry points are refused:
# the slice-1 goal is analysis-context configure, not arbitrary execution.
_CMAKE_VALUE_OPTIONS: Final = frozenset(
    {"-S", "-B", "-G", "-C", "--toolchain", "--preset", "--log-level"}
)
_CMAKE_FLAG_OPTIONS: Final = frozenset(
    {"--fresh", "--no-warn-unused-cli", "-Wdev", "-Wno-dev"}
)
_CMAKE_JOINED_PREFIXES: Final = ("-D", "-U", "-W", "-S", "-B")


class BuildPlanError(ValueError):
    """Fail-closed build contract violation with a stable reason string."""

    reason: str

    def __init__(self, reason: str) -> None:
        if not isinstance(reason, str) or not reason:
            raise TypeError("reason must be a non-empty str")
        self.reason = reason
        super().__init__(reason)


def _has_control_characters(value: str) -> bool:
    return any(unicodedata.category(char) == "Cc" for char in value)


def _nfc_text(value: object, field: str) -> str:
    if not isinstance(value, str):
        raise BuildPlanError(f"field-invalid:{field}")
    normalized = unicodedata.normalize("NFC", value)
    if (
        not normalized
        or _has_control_characters(normalized)
        or len(normalized.encode("utf-8")) > _MAX_TEXT_FIELD_BYTES
    ):
        raise BuildPlanError(f"field-invalid:{field}")
    return normalized


def _relative_path(value: object, field: str, *, allow_glob: bool) -> str:
    if not isinstance(value, str):
        raise BuildPlanError(f"field-invalid:{field}")
    normalized = unicodedata.normalize("NFC", value)
    if (
        not normalized
        or normalized.startswith("/")
        or "\\" in normalized
        or ":" in normalized
        or _has_control_characters(normalized)
        or len(normalized.encode("utf-8")) > _MAX_PATH_BYTES
        or any(
            segment in {"", ".", ".."} for segment in normalized.split("/")
        )
        or (not allow_glob and any(char in normalized for char in "*?["))
    ):
        raise BuildPlanError(f"field-invalid:{field}")
    return normalized


def _container_absolute(value: object, field: str) -> str:
    if not isinstance(value, str):
        raise BuildPlanError(f"field-invalid:{field}")
    normalized = unicodedata.normalize("NFC", value)
    if (
        not normalized.startswith("/")
        or normalized == "/"
        or normalized.endswith("/")
        or "\\" in normalized
        or ":" in normalized
        or _has_control_characters(normalized)
        or len(normalized.encode("utf-8")) > _MAX_PATH_BYTES
        or any(segment in {"", ".", ".."} for segment in normalized.split("/")[1:])
    ):
        raise BuildPlanError(f"field-invalid:{field}")
    return normalized


@dataclasses.dataclass(frozen=True, slots=True)
class BuildBudget:
    """Pilot budgets; frozen at request time and never model-adjustable."""

    max_attempts: int = 3
    max_model_calls: int = 8
    total_seconds: float = 1800.0
    step_seconds: float = 300.0
    max_output_bytes: int = 1024 * 1024

    def __post_init__(self) -> None:
        if (
            type(self.max_attempts) is not int
            or type(self.max_model_calls) is not int
            or type(self.max_output_bytes) is not int
            or not isinstance(self.total_seconds, int | float)
            or not isinstance(self.step_seconds, int | float)
        ):
            raise BuildPlanError("budget-invalid:types")
        if (
            self.max_attempts < 1
            or self.max_model_calls < 1
            or self.total_seconds <= 0
            or self.step_seconds <= 0
            or self.max_output_bytes < 1
        ):
            raise BuildPlanError("budget-invalid:values")

    def within_ceiling(self, ceiling: BuildBudget) -> bool:
        return (
            self.max_attempts <= ceiling.max_attempts
            and self.max_model_calls <= ceiling.max_model_calls
            and self.total_seconds <= ceiling.total_seconds
            and self.step_seconds <= ceiling.step_seconds
            and self.max_output_bytes <= ceiling.max_output_bytes
        )


@dataclasses.dataclass(frozen=True, slots=True)
class BuildRequest:
    """One trusted build task: snapshot, scope and budget are control-plane."""

    repository_ref: str
    snapshot_hash: str
    component_scope: tuple[str, ...]
    target_units: tuple[str, ...]
    toolchain_profile: str
    policy_ref: str
    budget: BuildBudget
    goal: str = ANALYSIS_CONTEXT_GOAL

    def __post_init__(self) -> None:
        if self.goal != ANALYSIS_CONTEXT_GOAL:
            raise BuildPlanError(f"goal-unsupported:{self.goal}")
        object.__setattr__(
            self, "repository_ref", _nfc_text(self.repository_ref, "repository_ref")
        )
        if (
            not isinstance(self.snapshot_hash, str)
            or _HEX64_PATTERN.fullmatch(self.snapshot_hash) is None
        ):
            raise BuildPlanError("snapshot-hash-invalid")
        object.__setattr__(
            self, "toolchain_profile", _nfc_text(self.toolchain_profile, "toolchain_profile")
        )
        object.__setattr__(
            self, "policy_ref", _nfc_text(self.policy_ref, "policy_ref")
        )
        for field in ("component_scope", "target_units"):
            value = getattr(self, field)
            if not isinstance(value, Sequence) or isinstance(value, str | bytes):
                raise BuildPlanError(f"field-invalid:{field}")
            object.__setattr__(
                self,
                field,
                tuple(
                    _relative_path(item, field, allow_glob=False)
                    for item in value
                ),
            )
            if not getattr(self, field):
                raise BuildPlanError(f"field-empty:{field}")
        if not isinstance(self.budget, BuildBudget):
            raise BuildPlanError("budget-invalid:not-a-budget")


@dataclasses.dataclass(frozen=True, slots=True)
class IncludeRootSpec:
    """One vendored include root as proposed in a plan."""

    container: str
    package: str

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "container", _container_absolute(self.container, "container")
        )
        object.__setattr__(
            self, "package", _relative_path(self.package, "package", allow_glob=False)
        )


def _parse_configure(value: object) -> tuple[tuple[str, ...], ...]:
    if not isinstance(value, Sequence) or isinstance(value, str | bytes):
        raise BuildPlanError("configure-argv-invalid:not-a-list")
    if not value or len(value) > _MAX_CONFIGURE_COMMANDS:
        raise BuildPlanError("configure-argv-invalid:count")
    commands: list[tuple[str, ...]] = []
    for argv in value:
        if not isinstance(argv, Sequence) or isinstance(argv, str | bytes):
            raise BuildPlanError("configure-argv-invalid:not-a-list")
        if not argv:
            raise BuildPlanError("configure-argv-invalid:empty")
        items: list[str] = []
        for item in argv:
            if (
                not isinstance(item, str)
                or not item
                or _has_control_characters(item)
                or len(item.encode("utf-8")) > _MAX_ARGV_ITEM_BYTES
            ):
                raise BuildPlanError("configure-argv-invalid:item")
            if (
                "\\" in item
                or _WINDOWS_DRIVE_PATTERN.match(item) is not None
                or any(token in item for token in _UNSAFE_ARGUMENT_TOKENS)
            ):
                raise BuildPlanError("configure-argument-unsafe")
            items.append(unicodedata.normalize("NFC", item))
        commands.append(tuple(items))
    return tuple(commands)


@dataclasses.dataclass(frozen=True, slots=True)
class BuildPlan:
    """A candidate plan the model proposes; validated separately."""

    snapshot_hash: str
    adapter: str
    component_scope: tuple[str, ...]
    configure_argv: tuple[tuple[str, ...], ...]
    expected_compdb: str
    generated_headers: tuple[str, ...]
    include_roots: tuple[IncludeRootSpec, ...]
    dependency_set_ref: str

    def __post_init__(self) -> None:
        if (
            not isinstance(self.snapshot_hash, str)
            or _HEX64_PATTERN.fullmatch(self.snapshot_hash) is None
        ):
            raise BuildPlanError("snapshot-hash-invalid")
        object.__setattr__(self, "adapter", _nfc_text(self.adapter, "adapter"))
        object.__setattr__(
            self,
            "component_scope",
            tuple(
                _relative_path(item, "component_scope", allow_glob=False)
                for item in _as_sequence(self.component_scope, "component_scope")
            ),
        )
        object.__setattr__(
            self, "configure_argv", _parse_configure(self.configure_argv)
        )
        object.__setattr__(
            self,
            "expected_compdb",
            _relative_path(self.expected_compdb, "expected_compdb", allow_glob=False),
        )
        object.__setattr__(
            self,
            "generated_headers",
            tuple(
                _relative_path(glob, "generated_headers", allow_glob=True)
                for glob in _as_sequence(self.generated_headers, "generated_headers")
            ),
        )
        object.__setattr__(
            self,
            "include_roots",
            tuple(self.include_roots),
        )
        for root in self.include_roots:
            if not isinstance(root, IncludeRootSpec):
                raise BuildPlanError("field-invalid:include_roots")
        object.__setattr__(
            self,
            "dependency_set_ref",
            _nfc_text(self.dependency_set_ref, "dependency_set_ref"),
        )

    @classmethod
    def from_mapping(cls, value: object) -> BuildPlan:
        """Parse one model-proposed mapping; unknown fields are rejected."""

        if not isinstance(value, Mapping):
            raise BuildPlanError("plan-not-mapping")
        for name in _PLAN_FIELDS:
            if name not in value:
                raise BuildPlanError(f"plan-field-missing:{name}")
        unknown = [name for name in value if name not in _PLAN_FIELDS]
        if unknown:
            raise BuildPlanError(f"plan-field-unknown:{unknown[0]}")
        if not isinstance(value["include_roots"], Sequence) or isinstance(
            value["include_roots"], str | bytes
        ):
            raise BuildPlanError("field-invalid:include_roots")
        roots: list[IncludeRootSpec] = []
        for index, entry in enumerate(value["include_roots"]):
            if not isinstance(entry, Mapping) or set(entry) != {"container", "package"}:
                raise BuildPlanError(f"field-invalid:include_roots[{index}]")
            roots.append(
                IncludeRootSpec(
                    container=entry["container"], package=entry["package"]
                )
            )
        return cls(
            snapshot_hash=value["snapshot_hash"],
            adapter=value["adapter"],
            component_scope=tuple(value["component_scope"]),
            configure_argv=tuple(value["configure_argv"]),
            expected_compdb=value["expected_compdb"],
            generated_headers=tuple(value["generated_headers"]),
            include_roots=tuple(roots),
            dependency_set_ref=value["dependency_set_ref"],
        )


def _as_sequence(value: object, field: str) -> Sequence[str]:
    if not isinstance(value, Sequence) or isinstance(value, str | bytes):
        raise BuildPlanError(f"field-invalid:{field}")
    return value


def _check_repo_relative_directive(value: str, label: str) -> None:
    if (
        not value
        or value.startswith("/")
        or "\\" in value
        or ":" in value
        or any(segment in {"", ".", ".."} for segment in value.split("/"))
    ):
        raise BuildPlanError(f"{label}-invalid:{value}")


def _validate_cmake_linux_configure(
    argv: tuple[str, ...], request: BuildRequest, policy: BuildPolicy
) -> None:
    """Adapter rules binding one cmake argv to the requested scope.

    Only the configure-only argument surface is accepted, the source and
    build directories must be explicit and repository-relative, and the
    actual source directory must fall inside the requested component scope
    (the repository root needs an explicit policy approval).
    """

    if argv[0] != "cmake":
        raise BuildPlanError(f"adapter-executable-invalid:{argv[0]}")
    source: str | None = None
    build_dir: str | None = None
    expect_value: str | None = None
    for token in argv[1:]:
        if expect_value is not None:
            if expect_value == "-S":
                source = token
            elif expect_value == "-B":
                build_dir = token
            expect_value = None
            continue
        if not token.startswith("-"):
            raise BuildPlanError(f"configure-argument-not-allowed:{token}")
        if token in _CMAKE_VALUE_OPTIONS:
            expect_value = token
            continue
        if token in _CMAKE_FLAG_OPTIONS or token.startswith(
            ("-D", "-U", "-W")
        ):
            continue
        if len(token) > 2 and token.startswith(_CMAKE_JOINED_PREFIXES):
            if token.startswith("-S"):
                source = token[2:]
            elif token.startswith("-B"):
                build_dir = token[2:]
            continue
        raise BuildPlanError(f"configure-argument-not-allowed:{token}")
    if expect_value is not None:
        raise BuildPlanError(f"configure-argument-not-allowed:{expect_value}")
    if source is None:
        raise BuildPlanError("configure-source-missing")
    if build_dir is None:
        raise BuildPlanError("configure-build-dir-missing")
    _check_repo_relative_directive(build_dir, "configure-build-dir")
    if source == ".":
        if not policy.allow_repository_root_configure:
            raise BuildPlanError("configure-source-out-of-scope:.")
        return
    _check_repo_relative_directive(source, "configure-source")
    if not any(
        source == component or source.startswith(component + "/")
        for component in request.component_scope
    ):
        raise BuildPlanError(f"configure-source-out-of-scope:{source}")


_ADAPTER_CONFIGURE_VALIDATORS: Final = {
    "cmake-linux": _validate_cmake_linux_configure,
}


@dataclasses.dataclass(frozen=True, slots=True)
class ApprovedDependencySet:
    """A deployment-approved offline dependency set bound to one image."""

    image: str
    image_digest: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "image", _nfc_text(self.image, "image"))
        if self.image_digest is not None:
            if (
                not isinstance(self.image_digest, str)
                or _HEX64_PATTERN.fullmatch(
                    self.image_digest.removeprefix("sha256:")
                )
                is None
            ):
                raise BuildPlanError("image-digest-invalid")
            # Normalize to the immutable reference form so the executor can
            # pin name@digest instead of trusting a mutable tag.
            object.__setattr__(
                self,
                "image_digest",
                "sha256:" + self.image_digest.removeprefix("sha256:"),
            )


@dataclasses.dataclass(frozen=True, slots=True)
class BuildPolicy:
    """Deployment-frozen limits: adapters, executables, images and budgets."""

    dependency_sets: Mapping[str, ApprovedDependencySet]
    adapters: frozenset[str] = frozenset({"cmake-linux"})
    allowed_executables: frozenset[str] = frozenset({"cmake"})
    budget_ceiling: BuildBudget = BuildBudget()
    source_mount: str = "/src"
    # Configuring the repository root touches every component at once; only
    # an explicit deployment approval allows plans to use -S .
    allow_repository_root_configure: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.dependency_sets, Mapping) or not all(
            isinstance(value, ApprovedDependencySet)
            for value in self.dependency_sets.values()
        ):
            raise BuildPlanError("policy-invalid:dependency_sets")
        if not self.adapters or not self.allowed_executables:
            raise BuildPlanError("policy-invalid:empty-allowlists")
        if not isinstance(self.budget_ceiling, BuildBudget):
            raise BuildPlanError("policy-invalid:budget-ceiling")
        object.__setattr__(
            self, "source_mount", _container_absolute(self.source_mount, "source_mount")
        )


@dataclasses.dataclass(frozen=True, slots=True)
class ValidatedBuildPlan:
    """A plan bound to one request and one approved dependency set."""

    request: BuildRequest
    plan: BuildPlan
    dependency_set: ApprovedDependencySet
    budget: BuildBudget


def plan_digest(plan: BuildPlan) -> str:
    """A stable digest over the plan identity, used to bind packages."""

    material = json.dumps(
        dataclasses.asdict(plan), sort_keys=True, ensure_ascii=False
    )
    return hashlib.sha256(material.encode("utf8")).hexdigest()


def validate_build_plan(
    request: BuildRequest, plan: BuildPlan, policy: BuildPolicy
) -> ValidatedBuildPlan:
    """The trusted gate between a candidate plan and the executor.

    A plan must target the requesting snapshot, exactly the requested
    component scope, a policy-approved adapter and a policy-approved
    dependency set; every configure argv must run a policy-approved
    executable under the adapter's configure-only argument rules, with its
    actual source directory bound to the requested scope; the request
    budget must stay under the deployment ceiling.  Any violation raises
    :class:`BuildPlanError` with a stable reason before a container is
    ever started.
    """

    if not isinstance(request, BuildRequest):
        raise BuildPlanError("request-invalid")
    if not isinstance(plan, BuildPlan):
        raise BuildPlanError("plan-invalid")
    if not isinstance(policy, BuildPolicy):
        raise BuildPlanError("policy-invalid")
    if plan.adapter not in policy.adapters:
        raise BuildPlanError(f"adapter-unsupported:{plan.adapter}")
    if plan.snapshot_hash != request.snapshot_hash:
        raise BuildPlanError("snapshot-mismatch")
    if plan.component_scope != request.component_scope:
        raise BuildPlanError("scope-mismatch")
    dependency_set = policy.dependency_sets.get(plan.dependency_set_ref)
    if dependency_set is None:
        raise BuildPlanError(f"dependency-set-not-approved:{plan.dependency_set_ref}")
    if not request.budget.within_ceiling(policy.budget_ceiling):
        raise BuildPlanError("budget-exceeds-policy")
    adapter_validator = _ADAPTER_CONFIGURE_VALIDATORS.get(plan.adapter)
    for argv in plan.configure_argv:
        if argv[0] not in policy.allowed_executables:
            raise BuildPlanError(f"executable-not-approved:{argv[0]}")
        if adapter_validator is not None:
            adapter_validator(argv, request, policy)
    return ValidatedBuildPlan(
        request=request,
        plan=plan,
        dependency_set=dependency_set,
        budget=request.budget,
    )
