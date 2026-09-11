"""Impact mining tests (plan Task 7, design sections 7 and 5.3).

Zero-network and read-only: the module under test may only run whitelisted
read-only git subcommands (blame/branch/rev-parse/show/tag) with list
argv and ``shell=False``; everything here runs against either a locally
constructed fixture repository or the real worktree with purely local
git object-database queries.  Red lines pinned here:

- introducing-commit location: blame pins the commit that introduced the
  current content of one line (fixture line 1 -> B, line 2 -> C); a
  missing file, an untracked path or a line past EOF yields ``None``
  (行漂移边界: no shifted-line guessing, the caller owns drift);
- branch propagation: a commit that lives only on ``feat`` is reported
  for ``feat`` and never for ``main``; an unknown revision raises
  ``ImpactMiningError`` instead of returning a guess;
- version ranges: ``git tag --contains`` filtered by an ``fnmatch`` glob
  (default ``v*``) with deterministic sorted output;
- known_commits: introduced commit plus the resolved tip of every branch
  containing it, deduplicated and sorted (feeds Task 6's
  ``DossierContext.known_commits`` CVE commit window);
- execution guard: write subcommands (status/commit/push) are rejected
  before spawn, shell-injection shaped first words are rejected, and the
  git binary path is injectable for tests.
"""

import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from lima import impact_mining
from lima.impact_mining import (
    ImpactMiningError,
    ImpactReport,
    _run_git,
    affected_versions,
    branch_contains,
    branch_tip,
    introducing_commit,
    mine_impact,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
UNKNOWN_COMMIT = "deadbeef" * 5

FixtureShas = dict[str, str]


def _fixture_git(repo: Path, *args: str) -> str:
    """Run one git command in the fixture repo (tests may use any git)."""

    completed = subprocess.run(  # noqa: S603 - test fixture drives real git directly
        ["git", "-C", str(repo), *args],  # noqa: S607 - git resolved from PATH
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )
    if completed.returncode != 0:
        raise AssertionError(
            f"fixture git {' '.join(args)} failed: {completed.stderr.strip()}"
        )
    return completed.stdout


def _build_fixture_repo(root: Path) -> FixtureShas:
    """Topology:  A -- C  on main (tags v1.0, old-tag at A; v2.0 at C)
                     \\-- B -- D  on feat (B rewrites line 1, D adds line 3).
    """

    repo = root / "fixture"
    repo.mkdir()
    _fixture_git(repo, "init", "-b", "main")
    _fixture_git(repo, "config", "user.name", "LIMA Fixture")
    _fixture_git(repo, "config", "user.email", "fixture@lima.invalid")
    core = repo / "core.cpp"
    core.write_text("line one\nline two\n", encoding="utf-8")
    _fixture_git(repo, "add", "core.cpp")
    _fixture_git(repo, "commit", "-m", "A: seed two lines")
    sha_a = _fixture_git(repo, "rev-parse", "HEAD").strip()
    _fixture_git(repo, "tag", "v1.0")
    _fixture_git(repo, "tag", "old-tag")
    _fixture_git(repo, "checkout", "-b", "feat")
    core.write_text("line one vulnerable\nline two\n", encoding="utf-8")
    _fixture_git(repo, "commit", "-am", "B: vulnerable line 1")
    sha_b = _fixture_git(repo, "rev-parse", "HEAD").strip()
    _fixture_git(repo, "checkout", "main")
    core.write_text("line one\nline two vulnerable\n", encoding="utf-8")
    _fixture_git(repo, "commit", "-am", "C: vulnerable line 2")
    sha_c = _fixture_git(repo, "rev-parse", "HEAD").strip()
    _fixture_git(repo, "tag", "v2.0")
    _fixture_git(repo, "checkout", "feat")
    core.write_text(
        "line one vulnerable\nline two\nline three\n", encoding="utf-8"
    )
    _fixture_git(repo, "commit", "-am", "D: feat-only third line")
    sha_d = _fixture_git(repo, "rev-parse", "HEAD").strip()
    _fixture_git(repo, "checkout", "main")
    return {"A": sha_a, "B": sha_b, "C": sha_c, "D": sha_d}


class FixtureRepositoryTests(unittest.TestCase):
    """Fixture-repo tests need a git binary; the analyzer sidecar has none."""
    """Introducing commit / branch containment / version range judgments."""

    def setUp(self) -> None:
        if shutil.which("git") is None:
            self.skipTest("impact-mining fixture tests require a git binary")
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.shas = _build_fixture_repo(Path(tmp.name))
        self.repo = Path(tmp.name) / "fixture"

    def _checkout(self, branch: str) -> None:
        _fixture_git(self.repo, "checkout", branch)

    def test_blame_locates_introducing_commit(self) -> None:
        # Blame follows the current working tree: line 1's rewrite lives on
        # feat (commit B), line 2's rewrite lives on main (commit C).
        self._checkout("feat")
        self.assertEqual(
            introducing_commit(self.repo, "core.cpp", 1), self.shas["B"]
        )
        self._checkout("main")
        self.assertEqual(
            introducing_commit(self.repo, "core.cpp", 2), self.shas["C"]
        )

    def test_branch_contains_reports_divergent_branches(self) -> None:
        self.assertEqual(
            branch_contains(self.repo, self.shas["B"]), ("feat",)
        )
        self.assertEqual(
            branch_contains(self.repo, self.shas["C"]), ("main",)
        )
        with self.assertRaises(ImpactMiningError):
            branch_contains(self.repo, UNKNOWN_COMMIT)

    def test_affected_versions_filter_by_glob(self) -> None:
        self.assertEqual(
            affected_versions(self.repo, self.shas["C"]), ("v2.0",)
        )
        # B never reached a tag: the honest answer is an empty tuple.
        self.assertEqual(affected_versions(self.repo, self.shas["B"]), ())
        # Widening the glob must expose the non-version tag too; v2.0
        # contains A as well because C descends from A (ancestry truth).
        self.assertEqual(
            affected_versions(self.repo, self.shas["A"], version_tags_glob="*"),
            ("old-tag", "v1.0", "v2.0"),
        )
        with self.assertRaises(ImpactMiningError):
            affected_versions(self.repo, UNKNOWN_COMMIT)

    def test_known_commits_includes_tips(self) -> None:
        self._checkout("feat")
        self.assertEqual(branch_tip(self.repo, "feat"), self.shas["D"])
        report = mine_impact(self.repo, "core.cpp", 1)
        self.assertIsInstance(report, ImpactReport)
        self.assertEqual(report.introduced_commit, self.shas["B"])
        self.assertEqual(report.branches, ("feat",))
        self.assertEqual(report.versions, ())
        self.assertIn(self.shas["B"], report.known_commits)
        self.assertIn(self.shas["D"], report.known_commits)
        self.assertEqual(
            report.known_commits,
            tuple(sorted(set(report.known_commits))),
        )

    def test_since_filters_introducing_commit(self) -> None:
        self._checkout("feat")
        self.assertEqual(
            introducing_commit(self.repo, "core.cpp", 1, since="2000-01-01"),
            self.shas["B"],
        )
        # An introduction older than the window is an honest no-answer.
        self.assertIsNone(
            introducing_commit(self.repo, "core.cpp", 1, since="2999-01-01")
        )
        with self.assertRaises(ImpactMiningError):
            introducing_commit(self.repo, "core.cpp", 1, since="not-a-date")

    def test_line_out_of_range_returns_none(self) -> None:
        # 行漂移边界: a line past EOF is reported as "cannot determine",
        # never as a shifted guess.
        self.assertIsNone(introducing_commit(self.repo, "core.cpp", 99))
        self.assertEqual(
            mine_impact(self.repo, "core.cpp", 99),
            ImpactReport(introduced_commit=None),
        )

    def test_missing_file_returns_none_introduced(self) -> None:
        self.assertIsNone(
            introducing_commit(self.repo, "does_not_exist.cpp", 1)
        )
        self.assertEqual(
            mine_impact(self.repo, "does_not_exist.cpp", 1),
            ImpactReport(introduced_commit=None),
        )

    def test_crlf_checkout_blame_uses_normalization_ladder(self) -> None:
        # Simulates a worktree materialized with core.autocrlf=true (CRLF
        # on disk, LF blob): the first blame sees "Not Committed Yet" and
        # the internal -c retry must still attribute the committed line.
        repo = self.repo
        _fixture_git(repo, "config", "core.autocrlf", "false")
        eol = repo / "eol.cpp"
        eol.write_text("alpha\nbeta\n", encoding="utf-8")
        _fixture_git(repo, "add", "eol.cpp")
        _fixture_git(repo, "commit", "-m", "E: LF blob")
        sha_e = _fixture_git(repo, "rev-parse", "HEAD").strip()
        eol.write_bytes(b"alpha\r\nbeta\r\n")
        self.assertEqual(
            introducing_commit(repo, "eol.cpp", 2), sha_e
        )


class GitGuardTests(unittest.TestCase):
    """Whitelist enforcement: only read-only subcommands ever spawn."""

    def setUp(self) -> None:
        if shutil.which("git") is None:
            self.skipTest("git-guard tests query the real worktree, needing git")
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.work = Path(tmp.name) / "scratch"
        self.work.mkdir()

    def test_symref_and_detached_lines_are_skipped(self):
        """Detached-HEAD and symref lines never reach rev-parse (exit 128).

        Mirrors and CI checkouts run ``git branch -a --contains`` on a
        detached HEAD, producing "(HEAD detached ...)" and
        "origin/HEAD -> origin/x" lines; mine_impact must skip both instead
        of feeding the arrow text into ``git rev-parse`` (which exits 128).

        Anchor note: the fixture asserts against whatever the current
        repository actually contains -- at least one branch name and at
        least one known commit must survive the symref/detached filter,
        and no arrow or detached-parenthesis text may leak through.
        """

        path = "lima/impact_mining.py"
        line = 5
        report = mine_impact(REPO_ROOT, path, line)

        self.assertTrue(report.branches, "no branch names survived the filter")
        self.assertTrue(all("->" not in b for b in report.branches), report.branches)
        self.assertTrue(all("(" not in b for b in report.branches))
        self.assertTrue(report.known_commits)

    def test_write_commands_rejected(self) -> None:
        for argv in (
            ["status"],
            ["commit", "-m", "bypass"],
            ["push", "origin", "main"],
        ):
            with self.subTest(argv=argv):
                with self.assertRaises(ImpactMiningError):
                    _run_git(self.work, argv)

    def test_shell_injection_shape_rejected(self) -> None:
        for argv in (
            ["log; push origin main"],
            ["blame && rm -rf /"],
            ["tag | tee pwned"],
        ):
            with self.subTest(argv=argv):
                with self.assertRaises(ImpactMiningError):
                    _run_git(self.work, argv)
        with self.assertRaises(ImpactMiningError):
            _run_git(self.work, [])
        with self.assertRaises(ImpactMiningError):
            _run_git(self.work, ["log", None])

    def test_git_binary_injection(self) -> None:
        impact_mining.set_git_binary(str(self.work / "no-such-git"))
        try:
            with self.assertRaises(ImpactMiningError):
                _run_git(self.work, ["rev-parse", "HEAD"])
        finally:
            impact_mining.set_git_binary(None)
        self.assertIsNone(impact_mining._GIT_BINARY)


class RealWorktreeIntegrationTests(unittest.TestCase):
    """Read-only integration against the actual worktree (zero network)."""

    def setUp(self) -> None:
        if shutil.which("git") is None:
            self.skipTest("real-worktree integration requires a git binary")

    def test_introducing_commit_on_real_worktree(self) -> None:
        path = "lima/agent_scout.py"
        line = 5
        expected = subprocess.run(  # noqa: S603 - read-only blame oracle for the comparison
            [  # noqa: S607 - git resolved from PATH
                "git", "-C", str(REPO_ROOT), "blame",
                "-L", f"{line},{line}", "--porcelain", "--", path,
            ],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=True,
        ).stdout.splitlines()[0].split()[0]
        self.assertRegex(expected, r"\A[0-9a-f]{40}\Z")
        self.assertEqual(
            introducing_commit(REPO_ROOT, path, line), expected
        )
        report = mine_impact(REPO_ROOT, path, line)
        # Detached-HEAD checkouts (mirrors) legitimately produce no local
        # branch names; the branch assertion only applies where the
        # repository state can contain one.
        head_state = subprocess.run(  # noqa: S603 - read-only probe
            ["git", "-C", str(REPO_ROOT), "branch", "--show-current"],  # noqa: S607
            capture_output=True, text=True,
        ).stdout.strip()
        if head_state:
            self.assertIn(head_state, report.branches)
        self.assertIn(expected, report.known_commits)
        self.assertTrue(report.known_commits)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
