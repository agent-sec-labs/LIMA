"""Read-only git impact mining for the agent vulnerability platform.

Implements plan Task 7 (design section 7 "git 影响挖掘", section 5.3
offline discipline): locate the commit that introduced one line
(``git blame``), follow its propagation across branches
(``git branch --contains``) and release tags (``git tag --contains``),
and aggregate everything into an :class:`ImpactReport` whose
``known_commits`` tuple feeds :class:`lima.agent_report.DossierContext`
as the CVE commit window (Task 6).

Red lines pinned here (design section 5.3, 离线纪律):

- git is executed only through :func:`_run_git`; the first argument word
  must be one of the read-only subcommands ``blame``/``branch``/``log``/
  ``rev-parse``/``show``/``tag`` (whitelist first-word lock).  Write
  commands such as ``status``/``commit``/``push``/``reset`` are rejected
  before a process is ever spawned;
- the argument vector is always a list of plain strings executed with
  ``shell=False`` -- no string commands, no shell metacharacter can
  fragment an argument;
- every invocation carries a bounded timeout (default 30s) and the child
  is killed on expiry; transport failures surface as
  :class:`ImpactMiningError` instead of hanging or leaking exceptions;
- no network: the whitelisted subcommands are purely local
  object-database queries, so impact mining works fully offline;
- global/system git config (and with it arbitrary shell-expansion
  aliases) is disabled per invocation by pointing
  ``GIT_CONFIG_GLOBAL``/``GIT_CONFIG_SYSTEM`` at the null device;
  repository-local config is honoured, ambient user config cannot
  rewrite the command;
- EOL determinism: a working tree checked out with ``core.autocrlf``
  conversion would look uncommitted to blame once the global/system
  config is disabled, so blame retries once with an internal
  ``-c core.autocrlf=true`` before honestly reporting ``None``
  (see :func:`introducing_commit`);
- honesty (不猜): a missing file, an untracked path or a line past EOF
  yields ``None`` for the introducing commit, while an unknown revision
  in a branch/version query raises :class:`ImpactMiningError` -- this
  module never invents a nearby answer.

Line-drift statement (行漂移声明): ``git blame`` attributes the lines of
the *current working tree* file.  Any drift between a finding's recorded
line number and the working tree (edits between snapshot and analysis)
is the caller's responsibility (Task 6 dossier/report layer); this
module reports exactly what the given line resolves to and never guesses
a shifted position.

``since`` semantics: the introducing commit of a line is unique, so
``since`` acts as an honest window filter -- the commit is returned only
when its committer time (``%ct``, Unix epoch) is at or after the
ISO-8601 ``since`` boundary (naive timestamps are read as UTC; git
approxidate forms like ``2.weeks.ago`` are not accepted).  An
introduction predating ``since`` yields ``None`` rather than the nearest
later commit.

``known_commits`` semantics: the introduced commit plus the resolved tip
commit of every branch that contains it (tips via ``git rev-parse``),
deduplicated and sorted deterministically.
"""

from __future__ import annotations

import fnmatch
import os
import re
import subprocess
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Final

__all__ = [
    "ImpactMiningError",
    "ImpactReport",
    "affected_versions",
    "branch_contains",
    "branch_tip",
    "introducing_commit",
    "mine_impact",
    "set_git_binary",
]

_ALLOWED_SUBCOMMANDS: Final[frozenset[str]] = frozenset({
    "blame",
    "branch",
    "log",
    "rev-parse",
    "show",
    "tag",
})
_DEFAULT_TIMEOUT_SECONDS: Final = 30.0
_SHORT_HASH_RE: Final = re.compile(r"[0-9a-f]{7,}\Z")
_FULL_HASH_RE: Final = re.compile(r"[0-9a-f]{40}\Z")
_ZERO_HASH_RE: Final = re.compile(r"0+\Z")
_BRANCH_MARKER_RE: Final = re.compile(r"^[*+]\s+")
# "origin/HEAD -> origin/main" presentation lines carry no independent tip;
# rev-parsing them yields the literal arrow text (exit 128).
_SYMREF_RE: Final = re.compile(r"\s+->\s+")

_GIT_BINARY: str | None = None


class ImpactMiningError(RuntimeError):
    """A read-only git query was rejected, timed out or failed."""


@dataclass(frozen=True)
class ImpactReport:
    """Aggregate impact picture for one ``(path, line)`` finding.

    ``branches`` lists the branches containing the introduced commit
    (remote branches keep their ``<remote>/`` prefix as the remote
    marker); ``versions`` lists the version tags matching the glob that
    contain it; ``known_commits`` is the CVE commit window (introduced
    commit + branch tips).  Every sequence is deduplicated and sorted
    for deterministic output.
    """

    introduced_commit: str | None
    branches: tuple[str, ...] = ()
    versions: tuple[str, ...] = ()
    known_commits: tuple[str, ...] = ()


def set_git_binary(binary: str | None) -> None:
    """Override the git executable path (test hook); ``None`` restores
    the plain ``"git"`` PATH lookup."""

    global _GIT_BINARY
    _GIT_BINARY = binary


def _git_env() -> dict[str, str]:
    """Ambient environment minus global/system git config (no aliases)."""

    env = dict(os.environ)
    env["GIT_CONFIG_GLOBAL"] = os.devnull
    env["GIT_CONFIG_SYSTEM"] = os.devnull
    return env


def _run_git(
    repo_path: str | Path,
    args: Sequence[str],
    timeout: float = _DEFAULT_TIMEOUT_SECONDS,
    config: Mapping[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    """Run one whitelisted read-only git command inside ``repo_path``.

    The first word of ``args`` must be in the read-only whitelist, every
    entry must be a plain string, and the command runs as a list argv
    with ``shell=False`` under a hard timeout (kill on expiry).  The
    returned :class:`~subprocess.CompletedProcess` is *not* checked:
    callers decide how a non-zero exit maps to their honesty contract
    (``None`` vs :class:`ImpactMiningError`).  Rejections, timeouts and
    unspawnable binaries raise :class:`ImpactMiningError` directly.

    ``config`` entries are injected internally as ``-c key=value`` words
    between the binary and the subcommand; they are module-controlled
    constants and never part of the whitelisted argv.
    """

    if isinstance(args, (str, bytes)):
        raise ImpactMiningError(
            "git arguments must be a list of strings, not a single string"
        )
    argv = list(args)
    if not argv or any(not isinstance(arg, str) for arg in argv):
        raise ImpactMiningError(
            "git arguments must be a non-empty list of plain strings"
        )
    if argv[0] not in _ALLOWED_SUBCOMMANDS:
        allowed = ", ".join(sorted(_ALLOWED_SUBCOMMANDS))
        raise ImpactMiningError(
            f"git subcommand {argv[0]!r} is not allowed "
            f"(read-only whitelist: {allowed})"
        )
    config_words = [
        word
        for key, value in sorted((config or {}).items())
        for word in ("-c", f"{key}={value}")
    ]
    command = [_GIT_BINARY or "git", *config_words, *argv]
    try:
        return subprocess.run(  # noqa: S603 - whitelist-locked read-only argv list, shell=False
            command,
            cwd=str(repo_path),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            check=False,
            shell=False,
            env=_git_env(),
        )
    except subprocess.TimeoutExpired as exc:
        raise ImpactMiningError(
            f"git {argv[0]} timed out after {timeout}s and was killed"
        ) from exc
    except OSError as exc:
        raise ImpactMiningError(f"cannot execute the git binary: {exc}") from exc


def _stderr_tail(completed: subprocess.CompletedProcess[str]) -> str:
    lines = (completed.stderr or "").strip().splitlines()
    return lines[-1] if lines else "no stderr"


def _require_success(
    completed: subprocess.CompletedProcess[str], subcommand: str
) -> None:
    if completed.returncode != 0:
        raise ImpactMiningError(
            f"git {subcommand} failed with exit code {completed.returncode}: "
            f"{_stderr_tail(completed)}"
        )


def _validated_repo(repo_path: str | Path) -> Path:
    repo = Path(repo_path)
    if not repo.is_dir():
        raise ImpactMiningError(f"repository path is not a directory: {repo}")
    return repo


def _since_epoch(since: str) -> float:
    try:
        moment = datetime.fromisoformat(since)
    except (TypeError, ValueError) as exc:
        raise ImpactMiningError(
            f"since must be an ISO-8601 date or datetime, got {since!r}"
        ) from exc
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=UTC)
    return moment.timestamp()


def _commit_epoch(repo: Path, commit: str) -> int:
    completed = _run_git(repo, ["show", "-s", "--format=%ct", commit])
    _require_success(completed, "show")
    try:
        return int(completed.stdout.strip())
    except ValueError as exc:
        raise ImpactMiningError(
            f"cannot parse committer time for {commit}"
        ) from exc


def introducing_commit(
    repo_path: str | Path,
    path: str,
    line: int,
    since: str | None = None,
) -> str | None:
    """Full 40-hex commit that introduced the current content of one line.

    ``git blame -L <line>,<line> -- <path>`` runs against the current
    working tree (see the line-drift statement in the module docstring).
    A non-zero blame (missing file, untracked path, line past EOF) or an
    unparseable blame token yields ``None`` -- no guessing.  When
    ``since`` is given, the commit is returned only if its committer
    time is at or after the boundary, otherwise ``None``.

    EOL normalization ladder: because global/system git config is
    disabled for every invocation (alias hardening), a working tree
    checked out with ``core.autocrlf=true`` looks modified to the first
    blame (every line "Not Committed Yet", zero hash).  When the first
    blame reports an uncommitted line, the query is retried once with
    ``-c core.autocrlf=true`` (the conventional checkout-time
    normalization); if the line is still uncommitted it was genuinely
    edited after checkout and the honest answer is ``None``.
    """

    if isinstance(line, bool) or not isinstance(line, int) or line < 1:
        raise ImpactMiningError("line must be a 1-based integer")
    repo = _validated_repo(repo_path)
    token = _blame_token(repo, str(path), line, config=None)
    if token is not None and _ZERO_HASH_RE.fullmatch(token):
        token = _blame_token(
            repo, str(path), line, config={"core.autocrlf": "true"}
        )
    if token is None or _ZERO_HASH_RE.fullmatch(token):
        return None
    if not _SHORT_HASH_RE.fullmatch(token):
        return None
    resolved = _run_git(repo, ["rev-parse", token])
    if resolved.returncode != 0:
        return None
    full = resolved.stdout.strip()
    if not _FULL_HASH_RE.fullmatch(full):
        return None
    if since is not None and _commit_epoch(repo, full) < _since_epoch(since):
        return None
    return full


def _blame_token(
    repo: Path, path: str, line: int, config: Mapping[str, str] | None
) -> str | None:
    """First blame token for one line (short hash, ``^`` marker stripped)."""

    completed = _run_git(
        repo,
        ["blame", "-L", f"{line},{line}", "--", path],
        config=config,
    )
    if completed.returncode != 0:
        return None
    output = completed.stdout.strip().splitlines()
    if not output:
        return None
    return output[0].split(None, 1)[0].removeprefix("^")


def branch_contains(repo_path: str | Path, commit: str) -> tuple[str, ...]:
    """Sorted branches that contain ``commit``.

    Remote branches are returned with their ``<remote>/`` prefix (the
    ``remotes/`` presentation prefix of ``git branch -a`` is stripped,
    keeping ``origin/...`` as the remote marker).  An unknown or
    malformed revision raises :class:`ImpactMiningError`.
    """

    repo = _validated_repo(repo_path)
    if not isinstance(commit, str) or not commit:
        raise ImpactMiningError("commit must be non-empty text")
    completed = _run_git(repo, ["branch", "-a", "--contains", commit])
    _require_success(completed, "branch")
    names: set[str] = set()
    for raw in completed.stdout.splitlines():
        name = _BRANCH_MARKER_RE.sub("", raw.strip())
        if not name or name.startswith("("):
            continue  # "(HEAD detached at ...)" is not a branch name
        if _SYMREF_RE.search(name):
            continue  # "origin/HEAD -> origin/main": symbolic alias line
        if name.startswith("remotes/"):
            name = name.removeprefix("remotes/")
        names.add(name)
    return tuple(sorted(names))


def branch_tip(repo_path: str | Path, branch: str) -> str:
    """Full 40-hex tip commit of ``branch`` (``git rev-parse <branch>``)."""

    repo = _validated_repo(repo_path)
    completed = _run_git(repo, ["rev-parse", branch])
    _require_success(completed, "rev-parse")
    tip = completed.stdout.strip().splitlines()[0]
    if not _FULL_HASH_RE.fullmatch(tip):
        raise ImpactMiningError(
            f"git rev-parse did not resolve {branch!r} to a commit"
        )
    return tip


def affected_versions(
    repo_path: str | Path,
    commit: str,
    version_tags_glob: str = "v*",
) -> tuple[str, ...]:
    """Sorted version tags containing ``commit``, filtered by ``fnmatch`` glob.

    Tags whose commits reach ``commit`` via ancestry are the affected
    versions; the glob (``fnmatchcase``, default ``v*``) keeps release
    tags and drops unrelated refs.  No matching tag is an honest empty
    tuple; an unknown revision raises :class:`ImpactMiningError`.
    """

    repo = _validated_repo(repo_path)
    completed = _run_git(repo, ["tag", "--contains", commit])
    _require_success(completed, "tag")
    tags = {
        raw.strip() for raw in completed.stdout.splitlines() if raw.strip()
    }
    return tuple(sorted(
        tag for tag in tags if fnmatch.fnmatchcase(tag, version_tags_glob)
    ))


def mine_impact(
    repo_path: str | Path,
    path: str,
    line: int,
    since: str | None = None,
    version_glob: str = "v*",
) -> ImpactReport:
    """Aggregate introducing commit, branch spread and version range.

    When the introducing commit cannot be determined (missing file,
    drifted line, pre-``since`` introduction) the report is honestly
    empty instead of speculative; otherwise ``branches`` and
    ``versions`` come from the introduced commit and ``known_commits``
    is that commit plus every containing branch's tip.
    """

    introduced = introducing_commit(repo_path, path, line, since=since)
    if introduced is None:
        return ImpactReport(introduced_commit=None)
    branches = branch_contains(repo_path, introduced)
    versions = affected_versions(repo_path, introduced, version_glob)
    tips = {branch_tip(repo_path, branch) for branch in branches}
    return ImpactReport(
        introduced_commit=introduced,
        branches=branches,
        versions=versions,
        known_commits=tuple(sorted({introduced, *tips})),
    )
