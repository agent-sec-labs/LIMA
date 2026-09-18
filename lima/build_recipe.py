"""Declarative build recipes: parse ``recipe.yaml`` and execute it in a build
container to produce one analysis context package (workstream A, task A2).

A build recipe is the only sanctioned producer of the frozen A1 context
package format.  The recipe executor mounts a repository source tree into a
per-repository build container -- the "dirty room" that may need network and
root-installed dependencies -- runs the configure commands once, and exports
the compilation database plus the headers it references into a package that
the dependency-free analysis sandbox (the sterile room) consumes.

Execution phases of :func:`run_recipe_in_container`, all fail-closed (a
failed configure never writes a partial package):

1. run each ``configure`` argv inside the container working directory
   (``recipe.source_mount``); a non-zero exit aborts immediately;
2. read the exported compilation database and relativize the source-mount
   prefix (CMake exports absolute ``directory``/``file`` paths while A1
   requires repository-relative ones);
3. rewrite the vendored include-root prefixes to package prefixes via A1's
   :func:`~lima.context_package.rewrite_compdb_paths`;
4. collect the generated headers matched by ``generated_globs``, stored under
   ``generated/<source-root-relative path>``;
5. collect only the headers under ``include_roots`` that the compilation
   database actually references, via :func:`collect_referenced_headers`;
6. assemble the manifest with A1's ``build_manifest`` and write the package
   atomically with ``write_package``.

All container interaction goes through the injected :class:`ContainerRunner`
protocol, so tests drive the executor with a fake runner and never invoke
Docker; :class:`DockerContainerRunner` is the production implementation (one
``docker run`` per interaction, argv lists only, never a shell).
"""

from __future__ import annotations

import dataclasses
import json
import re
import shlex
import subprocess
import unicodedata
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import Final, Protocol

import yaml

from lima.context_package import (
    ContextManifest,
    build_manifest,
    rewrite_compdb_paths,
    write_package,
)

__all__ = [
    "CURRENT_RECIPE_SCHEMA_VERSION",
    "BuildRecipe",
    "BuildRecipeError",
    "ContainerRunner",
    "DockerContainerRunner",
    "IncludeRoot",
    "MountSpec",
    "collect_referenced_headers",
    "run_recipe_in_container",
]

CURRENT_RECIPE_SCHEMA_VERSION: Final[int] = 1

MAX_RECIPE_BYTES: Final = 256 * 1024
MAX_TEXT_FIELD_BYTES: Final = 512
MAX_PATH_BYTES: Final = 1024
MAX_ARGV_ITEM_BYTES: Final = 4096
MAX_CONFIGURE_COMMANDS: Final = 64

# Package root names owned by the A1 layout; include roots must not use them.
RESERVED_PACKAGE_ROOTS: Final = frozenset(
    {"context_manifest.json", "compile_commands.json", "generated"}
)

# A token head preceding a rewriteable prefix must be empty (a bare path) or a
# joined compiler option such as ``-I``, ``-isystem`` or ``--sysroot=``.
# Mirrors the boundary rule of A1's compdb rewriter.
_OPTION_HEAD_PATTERN: Final = re.compile(r"-[A-Za-z0-9+.\-]*=?")

# Include options that take a directory, and those that take one file.
_DIR_INCLUDE_OPTIONS: Final = frozenset(
    {"-I", "-isystem", "-iquote", "-idirafter", "-stdlib++-isystem"}
)
_FILE_INCLUDE_OPTIONS: Final = frozenset({"-include", "-imacros"})

_DOCKER_RUN_TIMEOUT_SECONDS: Final = 3600.0
_DOCKER_IO_TIMEOUT_SECONDS: Final = 300.0

# In-container file listing helper; requires python3 in the build image.
_LIST_GLOBS_SCRIPT: Final = (
    "import glob, os, sys\n"
    "for path in sorted(glob.glob(sys.argv[1], recursive=True)):\n"
    "    if os.path.isfile(path):\n"
    "        print(path)\n"
)


class BuildRecipeError(ValueError):
    """Fail-closed build recipe violation with a stable reason string."""

    reason: str

    def __init__(self, reason: str) -> None:
        if not isinstance(reason, str) or not reason:
            raise TypeError("reason must be a non-empty str")
        self.reason = reason
        super().__init__(reason)


# --------------------------------------------------------------- validation


def _has_control_characters(value: str) -> bool:
    return any(unicodedata.category(char) == "Cc" for char in value)


def _nfc_text(value: object, field: str) -> str:
    if not isinstance(value, str):
        raise BuildRecipeError(f"recipe-field-invalid:{field}")
    normalized = unicodedata.normalize("NFC", value)
    if (
        not normalized
        or _has_control_characters(normalized)
        or len(normalized.encode("utf-8")) > MAX_TEXT_FIELD_BYTES
    ):
        raise BuildRecipeError(f"recipe-field-invalid:{field}")
    return normalized


def _posix_absolute(value: object, field: str) -> str:
    """Validate an absolute container path such as ``/usr/include/qt5``."""

    if not isinstance(value, str):
        raise BuildRecipeError(f"recipe-field-invalid:{field}")
    normalized = unicodedata.normalize("NFC", value)
    if (
        not normalized.startswith("/")
        or normalized == "/"
        or normalized.endswith("/")
        or "\\" in normalized
        or ":" in normalized
        or _has_control_characters(normalized)
        or len(normalized.encode("utf-8")) > MAX_PATH_BYTES
        or any(segment in {"", ".", ".."} for segment in normalized.split("/")[1:])
    ):
        raise BuildRecipeError(f"recipe-field-invalid:{field}")
    return normalized


def _relative_path(value: object, field: str, *, allow_glob: bool) -> str:
    """Validate a source-root-relative posix path (optionally a glob)."""

    if not isinstance(value, str):
        raise BuildRecipeError(f"recipe-field-invalid:{field}")
    normalized = unicodedata.normalize("NFC", value)
    if (
        not normalized
        or normalized.startswith("/")
        or "\\" in normalized
        or ":" in normalized
        or _has_control_characters(normalized)
        or len(normalized.encode("utf-8")) > MAX_PATH_BYTES
        or any(segment in {"", ".", ".."} for segment in normalized.split("/"))
        or (not allow_glob and any(char in normalized for char in "*?["))
    ):
        raise BuildRecipeError(f"recipe-field-invalid:{field}")
    return normalized


# ------------------------------------------------------------ recipe objects


@dataclasses.dataclass(frozen=True, slots=True)
class IncludeRoot:
    """One vendored include root: a container directory and its package name."""

    container: str
    package: str

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "container", _posix_absolute(self.container, "container")
        )
        object.__setattr__(
            self,
            "package",
            _relative_path(self.package, "package", allow_glob=False),
        )
        if self.package.split("/")[0] in RESERVED_PACKAGE_ROOTS:
            raise BuildRecipeError(f"include-root-package-reserved:{self.package}")


@dataclasses.dataclass(frozen=True, slots=True)
class BuildRecipe:
    """A parsed, validated ``recipe.yaml`` (frozen schema v1)."""

    schema_version: int
    name: str
    image: str
    repository: str
    source_mount: str
    configure: tuple[tuple[str, ...], ...]
    compdb_path: str
    generated_globs: tuple[str, ...]
    include_roots: tuple[IncludeRoot, ...]

    def __post_init__(self) -> None:
        if (
            type(self.schema_version) is not int
            or self.schema_version != CURRENT_RECIPE_SCHEMA_VERSION
        ):
            raise BuildRecipeError(
                f"recipe-schema-version-unsupported:{self.schema_version!r}"
            )
        object.__setattr__(self, "name", _nfc_text(self.name, "name"))
        object.__setattr__(self, "image", _nfc_text(self.image, "image"))
        object.__setattr__(self, "repository", _nfc_text(self.repository, "repository"))
        object.__setattr__(
            self, "source_mount", _posix_absolute(self.source_mount, "source_mount")
        )
        object.__setattr__(self, "configure", _parse_configure(self.configure))
        object.__setattr__(
            self,
            "compdb_path",
            _relative_path(self.compdb_path, "compdb_path", allow_glob=False),
        )
        if not isinstance(self.generated_globs, Sequence) or isinstance(
            self.generated_globs, str | bytes
        ):
            raise BuildRecipeError("recipe-field-invalid:generated_globs")
        object.__setattr__(
            self,
            "generated_globs",
            tuple(
                _relative_path(glob, f"generated_globs[{index}]", allow_glob=True)
                for index, glob in enumerate(self.generated_globs)
            ),
        )
        if not isinstance(self.include_roots, Sequence) or isinstance(
            self.include_roots, str | bytes
        ):
            raise BuildRecipeError("recipe-field-invalid:include_roots")
        for root in self.include_roots:
            if not isinstance(root, IncludeRoot):
                raise BuildRecipeError("recipe-field-invalid:include_roots")
        roots = tuple(self.include_roots)
        object.__setattr__(self, "include_roots", roots)
        _check_include_roots(roots, self.source_mount)

    @classmethod
    def from_yaml(cls, text: str) -> BuildRecipe:
        """Parse and validate one recipe document (strict, fail-closed)."""

        if not isinstance(text, str):
            raise BuildRecipeError("recipe-text-invalid")
        if len(text.encode("utf-8")) > MAX_RECIPE_BYTES:
            raise BuildRecipeError("recipe-too-large")
        try:
            document = yaml.load(text, Loader=_StrictLoader)  # noqa: S506 - strict loader
        except yaml.YAMLError as exc:
            raise BuildRecipeError("recipe-yaml-invalid") from exc
        if not isinstance(document, Mapping):
            raise BuildRecipeError("recipe-not-mapping")

        known_fields: Final = (
            "schema_version",
            "name",
            "image",
            "repository",
            "source_mount",
            "configure",
            "compdb_path",
            "generated_globs",
            "include_roots",
        )
        for name in known_fields:
            if name not in document:
                raise BuildRecipeError(f"recipe-field-missing:{name}")
        unknown = [name for name in document if name not in known_fields]
        if unknown:
            raise BuildRecipeError(f"recipe-field-unknown:{unknown[0]}")

        if not isinstance(document["include_roots"], Sequence) or isinstance(
            document["include_roots"], str | bytes
        ):
            raise BuildRecipeError("recipe-field-invalid:include_roots")
        roots = tuple(
            _parse_include_root_entry(entry, index)
            for index, entry in enumerate(document["include_roots"])
        )
        return cls(
            schema_version=document["schema_version"],
            name=document["name"],
            image=document["image"],
            repository=document["repository"],
            source_mount=document["source_mount"],
            configure=document["configure"],
            compdb_path=document["compdb_path"],
            generated_globs=document["generated_globs"],
            include_roots=roots,
        )

    @classmethod
    def from_file(cls, path: Path) -> BuildRecipe:
        """Load and validate a recipe from ``recipe.yaml`` on disk."""

        try:
            text = Path(path).read_text(encoding="utf-8")
        except OSError as exc:
            raise BuildRecipeError("recipe-file-unreadable") from exc
        return cls.from_yaml(text)


def _parse_configure(value: object) -> tuple[tuple[str, ...], ...]:
    if not isinstance(value, Sequence) or isinstance(value, str | bytes):
        raise BuildRecipeError("recipe-field-invalid:configure")
    if not value:
        raise BuildRecipeError("recipe-field-invalid:configure")
    if len(value) > MAX_CONFIGURE_COMMANDS:
        raise BuildRecipeError("recipe-field-invalid:configure")
    commands: list[tuple[str, ...]] = []
    for argv in value:
        if not isinstance(argv, Sequence) or isinstance(argv, str | bytes) or not argv:
            raise BuildRecipeError("recipe-field-invalid:configure")
        items: list[str] = []
        for item in argv:
            if (
                not isinstance(item, str)
                or not item
                or _has_control_characters(item)
                or len(item.encode("utf-8")) > MAX_ARGV_ITEM_BYTES
            ):
                raise BuildRecipeError("recipe-field-invalid:configure")
            items.append(item)
        commands.append(tuple(items))
    return tuple(commands)


def _parse_include_root_entry(value: object, index: int) -> IncludeRoot:
    field = f"include_roots[{index}]"
    if not isinstance(value, Mapping):
        raise BuildRecipeError(f"recipe-field-invalid:{field}")
    unknown = [key for key in value if key not in {"container", "package"}]
    if unknown:
        raise BuildRecipeError(f"include-root-unknown-key:{field}.{unknown[0]}")
    if "container" not in value or "package" not in value:
        raise BuildRecipeError(f"recipe-field-missing:{field}")
    try:
        return IncludeRoot(container=value["container"], package=value["package"])
    except BuildRecipeError as exc:
        raise BuildRecipeError(f"{exc.reason}:{field}") from exc


def _check_include_roots(roots: Sequence[IncludeRoot], source_mount: str) -> None:
    packages = [root.package for root in roots]
    if len(set(packages)) != len(packages):
        raise BuildRecipeError("include-root-package-duplicate")
    for first in packages:
        for second in packages:
            if first != second and second.startswith(first + "/"):
                raise BuildRecipeError(f"include-root-package-nested:{second}")
    containers = [root.container for root in roots]
    if len(set(containers)) != len(containers):
        raise BuildRecipeError("include-root-container-duplicate")
    for container in containers:
        if container == source_mount or container.startswith(source_mount + "/"):
            raise BuildRecipeError(f"include-root-inside-source-mount:{container}")


# ------------------------------------------------------------- strict YAML


class _StrictLoader(yaml.SafeLoader):
    """SafeLoader that rejects duplicate mapping keys instead of last-wins."""


def _construct_strict_mapping(
    loader: _StrictLoader, node: yaml.MappingNode, deep: bool = False
) -> dict[object, object]:
    mapping: dict[object, object] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        try:
            duplicate = key in mapping
        except TypeError as exc:
            raise BuildRecipeError("recipe-yaml-key-unhashable") from exc
        if duplicate:
            raise BuildRecipeError(f"duplicate-yaml-key:{key}")
        mapping[key] = loader.construct_object(value_node, deep=deep)
    return mapping


_StrictLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _construct_strict_mapping
)


# -------------------------------------------------------- container runners


@dataclasses.dataclass(frozen=True, slots=True)
class MountSpec:
    """One host-to-container bind mount (``host_path`` at ``container_path``)."""

    host_path: str
    container_path: str


class ContainerRunner(Protocol):
    """The container interaction surface the executor depends on.

    ``run`` executes one argv list inside the container and returns
    ``(returncode, stdout)``; ``read_file`` reads one container file;
    ``list_globs`` lists the regular files matching one glob pattern
    (``*``, ``**`` and ``?``) relative to the container filesystem.  Tests
    inject a fake implementation of exactly this protocol.
    """

    def run(
        self, argv: Sequence[str], mounts: Sequence[MountSpec]
    ) -> tuple[int, str]: ...

    def read_file(self, container_path: str) -> bytes: ...

    def list_globs(self, pattern: str) -> list[str]: ...


class DockerContainerRunner:
    """Production :class:`ContainerRunner`: one ``docker run`` per interaction.

    Requires ``docker`` on PATH and a build image that ships ``python3``
    (the in-container glob listing helper).  Every invocation is an argv
    list executed without a shell; the persistent mounts and working
    directory are attached to read and listing calls so paths under the
    source mount resolve.
    """

    def __init__(
        self,
        image: str,
        *,
        mounts: Sequence[MountSpec] = (),
        workdir: str | None = None,
    ) -> None:
        self.image = image
        self.mounts = tuple(mounts)
        self.workdir = workdir

    def _docker_argv(
        self, argv: Sequence[str], mounts: Sequence[MountSpec]
    ) -> list[str]:
        full = ["docker", "run", "--rm"]
        for mount in mounts:
            host = mount.host_path.replace("\\", "/")
            full += ["-v", f"{host}:{mount.container_path}"]
        if self.workdir is not None:
            full += ["-w", self.workdir]
        return full + [self.image, *argv]

    def _run(
        self,
        argv: Sequence[str],
        mounts: Sequence[MountSpec],
        *,
        timeout: float,
    ) -> subprocess.CompletedProcess[bytes]:
        try:
            return subprocess.run(  # noqa: S603 - docker CLI, fixed argv list, no shell
                self._docker_argv(argv, mounts),
                capture_output=True,
                timeout=timeout,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise BuildRecipeError(f"docker-invocation-failed:{argv[0]}") from exc

    def run(
        self, argv: Sequence[str], mounts: Sequence[MountSpec] = ()
    ) -> tuple[int, str]:
        completed = self._run(
            list(argv), tuple(mounts) or self.mounts, timeout=_DOCKER_RUN_TIMEOUT_SECONDS
        )
        return completed.returncode, completed.stdout.decode("utf-8", errors="replace")

    def read_file(self, container_path: str) -> bytes:
        completed = self._run(
            ["cat", container_path], self.mounts, timeout=_DOCKER_IO_TIMEOUT_SECONDS
        )
        if completed.returncode != 0:
            raise BuildRecipeError(f"container-read-failed:{container_path}")
        return completed.stdout

    def list_globs(self, pattern: str) -> list[str]:
        completed = self._run(
            ["python3", "-c", _LIST_GLOBS_SCRIPT, pattern],
            self.mounts,
            timeout=_DOCKER_IO_TIMEOUT_SECONDS,
        )
        if completed.returncode != 0:
            raise BuildRecipeError(f"container-glob-failed:{pattern}")
        return [
            line for line in completed.stdout.decode("utf-8").splitlines() if line
        ]


# ------------------------------------------------------ source-path relativize


def _strip_source_prefix(token: str, source_mount: str) -> str:
    """Strip the source-mount prefix from one argv token.

    The prefix is only honored at a path boundary behind an empty or joined
    option head (the same rule as A1's rewriter), so ``/usr/src/x`` never
    loses ``/src``.  A token equal to the mount collapses to ``.``.
    """

    index = token.find(source_mount)
    while index != -1:
        end = index + len(source_mount)
        head = token[:index]
        head_ok = head == "" or _OPTION_HEAD_PATTERN.fullmatch(head) is not None
        if (end == len(token) or token[end] == "/") and head_ok:
            remainder = token[end:]
            if remainder.startswith("/"):
                remainder = remainder[1:]
            return token[:index] + (remainder if remainder else ".")
        index = token.find(source_mount, index + 1)
    return token


def _relativize_entry_path(value: object, source_mount: str, field: str) -> str:
    if not isinstance(value, str) or not value:
        raise BuildRecipeError(f"compdb-{field}-invalid")
    stripped = _strip_source_prefix(value, source_mount)
    if stripped in {"", "."} or stripped.startswith("/"):
        raise BuildRecipeError(f"compdb-{field}-not-repository-relative")
    return stripped


def _relativize_source_paths(compdb_text: str, source_mount: str) -> str:
    """Rewrite container-absolute repository paths to repository-relative ones.

    CMake exports absolute ``directory``/``file``/``output`` paths and
    absolute include flags rooted at the source mount; A1 requires
    repository-relative ``directory``/``file`` values.  Both the
    ``arguments`` array form and the ``command`` shell-string form are
    handled token-wise; absolute paths outside the source mount are
    rejected fail-closed.
    """

    try:
        document = json.loads(compdb_text)
    except json.JSONDecodeError as exc:
        raise BuildRecipeError("compdb-json-invalid") from exc
    if not isinstance(document, list):
        raise BuildRecipeError("compdb-not-array")
    for entry in document:
        if not isinstance(entry, dict):
            raise BuildRecipeError("compdb-entry-not-object")
        for field in ("directory", "file"):
            if field in entry:
                entry[field] = _relativize_entry_path(
                    entry[field], source_mount, field
                )
        if isinstance(entry.get("output"), str) and entry["output"]:
            entry["output"] = _strip_source_prefix(entry["output"], source_mount)
        arguments = entry.get("arguments")
        if isinstance(arguments, list):
            entry["arguments"] = [
                (
                    _strip_source_prefix(argument, source_mount)
                    if isinstance(argument, str)
                    else argument
                )
                for argument in arguments
            ]
        command = entry.get("command")
        if isinstance(command, str) and command:
            try:
                argv = shlex.split(command, posix=True)
            except ValueError as exc:
                raise BuildRecipeError("compdb-command-invalid") from exc
            entry["command"] = shlex.join(
                [_strip_source_prefix(argument, source_mount) for argument in argv]
            )
    return json.dumps(document, ensure_ascii=False, indent=2)


# --------------------------------------------------- referenced header filter


def _longest_root(value: str, roots: Sequence[IncludeRoot]) -> IncludeRoot | None:
    """The include root containing ``value``, longest container prefix wins."""

    best: IncludeRoot | None = None
    for root in roots:
        contained = value == root.container or value.startswith(root.container + "/")
        if contained and (best is None or len(root.container) > len(best.container)):
            best = root
    return best


def _iter_include_values(argv: Sequence[str]) -> tuple[tuple[str, str], ...]:
    """Extract ``(kind, value)`` include flags from one compiler argv.

    ``kind`` is ``"dir"`` for include-directory options (``-I``, ``-isystem``,
    ``-iquote``, ``-idirafter``, ``-stdlib++-isystem``) and ``"file"`` for
    forced-file options (``-include``, ``-imacros``).  Both the separate-value
    and the joined ``=``/``-I`` forms are handled.
    """

    values: list[tuple[str, str]] = []
    expect: str | None = None
    for token in argv:
        if expect is not None:
            values.append((expect, token))
            expect = None
            continue
        if token in _DIR_INCLUDE_OPTIONS:
            expect = "dir"
            continue
        if token in _FILE_INCLUDE_OPTIONS:
            expect = "file"
            continue
        head, separator, tail = token.partition("=")
        if separator and tail:
            if head in _DIR_INCLUDE_OPTIONS:
                values.append(("dir", tail))
                continue
            if head in _FILE_INCLUDE_OPTIONS:
                values.append(("file", tail))
                continue
        if token.startswith("-I") and len(token) > 2:
            values.append(("dir", token[2:]))
    return tuple(values)


def _under_directory(relative: str, directory: str) -> bool:
    if directory == "":
        return True
    return relative == directory or relative.startswith(directory + "/")


def collect_referenced_headers(
    compdb_text: str,
    include_roots: Sequence[IncludeRoot],
    root_files: Mapping[str, Sequence[str]],
    read_file: Callable[[str], bytes],
) -> dict[str, bytes]:
    """Collect only the include-root headers the compilation database references.

    The filter is directory-granularity plus direct file references: every
    ``-I``/``-isystem``/... flag value that falls under an include root marks
    that whole directory subtree for vendoring, and forced-file flags such as
    ``-include`` mark individual files.  This is what keeps a 2000-file Qt
    installation from being copied wholesale while never under-collecting (a
    referenced directory is always vendored completely, so the package can
    never miss a transitively included header).

    ``root_files`` maps each root's container path to its root-relative file
    listing; ``read_file`` reads a container-absolute path.  The result maps
    package-relative header paths to file contents.
    """

    if not isinstance(compdb_text, str):
        raise BuildRecipeError("compdb-text-invalid")
    roots = tuple(include_roots)
    for root in roots:
        if not isinstance(root, IncludeRoot):
            raise BuildRecipeError("include-root-invalid")
    try:
        document = json.loads(compdb_text)
    except json.JSONDecodeError as exc:
        raise BuildRecipeError("compdb-json-invalid") from exc
    if not isinstance(document, list):
        raise BuildRecipeError("compdb-not-array")

    referenced_dirs: dict[str, set[str]] = {root.container: set() for root in roots}
    referenced_files: dict[str, set[str]] = {root.container: set() for root in roots}
    for entry in document:
        if not isinstance(entry, dict):
            raise BuildRecipeError("compdb-entry-not-object")
        argv = entry.get("arguments")
        if not isinstance(argv, list):
            command = entry.get("command")
            if not isinstance(command, str) or not command:
                continue
            try:
                argv = shlex.split(command, posix=True)
            except ValueError as exc:
                raise BuildRecipeError("compdb-command-invalid") from exc
        for kind, value in _iter_include_values(argv):
            root = _longest_root(value, roots)
            if root is None:
                continue
            if kind == "dir":
                referenced_dirs[root.container].add(value)
            else:
                referenced_files[root.container].add(value)

    collected: dict[str, bytes] = {}
    for root in roots:
        directories = sorted(
            value[len(root.container) :].lstrip("/")
            for value in referenced_dirs[root.container]
        )
        files = sorted(
            value[len(root.container) + 1 :]
            for value in referenced_files[root.container]
            if value.startswith(root.container + "/")
        )
        for relative in sorted(root_files.get(root.container, ())):
            if not isinstance(relative, str):
                raise BuildRecipeError(f"root-listing-invalid:{root.container}")
            selected = relative in files or any(
                _under_directory(relative, directory) for directory in directories
            )
            if not selected:
                continue
            content = read_file(root.container + "/" + relative)
            if not isinstance(content, bytes):
                raise BuildRecipeError(
                    f"container-read-invalid:{root.container}/{relative}"
                )
            collected[root.package + "/" + relative] = content
    return collected


# ------------------------------------------------------------------ executor


def _container_relative(container_path: object, root: str) -> str | None:
    """A safe root-relative posix path for ``container_path``, or ``None``."""

    if not isinstance(container_path, str):
        return None
    if not container_path.startswith(root + "/"):
        return None
    relative = container_path[len(root) + 1 :]
    if any(segment in {"", ".", ".."} for segment in relative.split("/")):
        return None
    return relative


def run_recipe_in_container(
    recipe: BuildRecipe,
    source_dir: Path,
    *,
    work_dir: Path,
    revision: str = "unknown",
    docker_image: str | None = None,
    container_runner: ContainerRunner | None = None,
) -> ContextManifest:
    """Execute one recipe against ``source_dir`` and write a context package.

    The source tree is mounted at ``recipe.source_mount`` (the container's
    working directory), each configure command runs in order and any
    non-zero exit aborts without writing a package.  ``work_dir`` is the
    package output directory (A1's ``pkg_dir``); ``revision`` becomes the
    manifest revision (pass the repository git SHA for provenance).  Tests
    inject ``container_runner``; production defaults to
    :class:`DockerContainerRunner` with ``docker_image`` overriding
    ``recipe.image``.  Returns the finalized manifest, exactly what A1's
    ``read_package`` verifies.
    """

    if not isinstance(recipe, BuildRecipe):
        raise BuildRecipeError("recipe-invalid")
    source = Path(source_dir)
    if not source.is_dir():
        raise BuildRecipeError("source-directory-missing")
    mounts = (
        MountSpec(str(source.resolve()).replace("\\", "/"), recipe.source_mount),
    )
    runner = (
        container_runner
        if container_runner is not None
        else DockerContainerRunner(
            image=docker_image or recipe.image,
            mounts=mounts,
            workdir=recipe.source_mount,
        )
    )

    # 1. configure (fail closed: no package on any non-zero exit)
    for argv in recipe.configure:
        returncode, _stdout = runner.run(list(argv), mounts)
        if returncode != 0:
            raise BuildRecipeError(
                f"configure-command-failed:{argv[0]}:rc={returncode}"
            )

    # 2. read the exported compilation database
    compdb_container_path = recipe.source_mount + "/" + recipe.compdb_path
    compdb_bytes = runner.read_file(compdb_container_path)
    if not isinstance(compdb_bytes, bytes):
        raise BuildRecipeError(f"container-read-invalid:{compdb_container_path}")
    try:
        compdb_text = compdb_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise BuildRecipeError("compdb-decode-failed") from exc

    # 3. relativize repository paths, then rewrite vendored include prefixes
    relativized_text = _relativize_source_paths(compdb_text, recipe.source_mount)
    rewrite_map = {root.container: root.package for root in recipe.include_roots}
    rewritten_text = rewrite_compdb_paths(relativized_text, rewrite_map)

    # 4. collect generated headers under their source-root-relative names
    generated_files: dict[str, bytes] = {}
    for pattern in recipe.generated_globs:
        for container_path in runner.list_globs(
            recipe.source_mount + "/" + pattern
        ):
            relative = _container_relative(container_path, recipe.source_mount)
            if relative is None:
                raise BuildRecipeError(
                    f"generated-file-outside-source-root:{container_path}"
                )
            if relative not in generated_files:
                generated_files[relative] = runner.read_file(container_path)

    # 5. collect only the referenced headers under the include roots
    root_files: dict[str, list[str]] = {}
    for root in recipe.include_roots:
        listing = runner.list_globs(root.container + "/**")
        relatives = [
            relative
            for relative in (
                _container_relative(container_path, root.container)
                for container_path in listing
            )
            if relative is not None
        ]
        root_files[root.container] = sorted(set(relatives))
    header_files = collect_referenced_headers(
        relativized_text, recipe.include_roots, root_files, runner.read_file
    )

    # 6. manifest + atomic package write
    used_roots = sorted(
        {
            root.package
            for root in recipe.include_roots
            if any(path.startswith(root.package + "/") for path in header_files)
        }
    )
    manifest = build_manifest(
        repository=recipe.repository,
        revision=revision if isinstance(revision, str) and revision else "unknown",
        compdb=json.loads(rewritten_text),
        generated=sorted(generated_files),
        header_roots=used_roots,
        rewrites=rewrite_map,
        created_by=recipe.name,
    )
    return write_package(
        Path(work_dir),
        manifest,
        rewritten_text.encode("utf-8"),
        generated_files,
        header_files,
    )
