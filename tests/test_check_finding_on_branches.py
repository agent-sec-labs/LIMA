"""Frozen tests for the master-finding -> Release/LTS alignment check."""

import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

SKIP = not shutil.which("git")


def _run_git(cwd: Path, *args: str) -> None:
    subprocess.run(
        ["git", "-C", str(cwd), *args],
        check=True,
        capture_output=True,
        text=True,
    )


def _make_repo(root: Path) -> Path:
    repo = root / "repo"
    repo.mkdir()
    _run_git(repo, "init", "-q", "-b", "main")
    _run_git(repo, "config", "user.email", "t@example.com")
    _run_git(repo, "config", "user.name", "t")
    (repo / "src").mkdir()
    (repo / "src" / "a.c").write_text("int v1(void) { return 1; }\n")
    _run_git(repo, "add", ".")
    _run_git(repo, "commit", "-q", "-m", "v1")
    # A release branch that never diverged on the audited file ...
    _run_git(repo, "branch", "release-unchanged")
    # ... and one where the audited file changed.
    (repo / "src" / "a.c").write_text("int v2(void) { return 2; }\n")
    _run_git(repo, "commit", "-q", "-am", "v2")
    _run_git(repo, "branch", "release-changed")
    # A branch where the audited file is gone.
    _run_git(repo, "rm", "-q", "src/a.c")
    _run_git(repo, "commit", "-q", "-m", "drop file")
    _run_git(repo, "branch", "release-absent")
    # Restore the file on main so its tip carries the finding.
    (repo / "src").mkdir(exist_ok=True)
    (repo / "src" / "a.c").write_text("int v2(void) { return 2; }\n")
    _run_git(repo, "add", ".")
    _run_git(repo, "commit", "-q", "-m", "restore for main")
    return repo


@unittest.skipIf(SKIP, "git is not installed")
class CheckFindingOnBranchesTests(unittest.TestCase):
    def setUp(self) -> None:
        self._root = tempfile.TemporaryDirectory(
            suffix="-finding-branches"
        )
        self.addCleanup(self._root.cleanup)
        self.repo = _make_repo(Path(self._root.name))
        self.script = (
            Path(__file__).resolve().parent.parent
            / "scripts"
            / "check_finding_on_branches.py"
        )

    def _main(self, *args: str) -> tuple[int, str]:
        proc = subprocess.run(
            [sys.executable, str(self.script), *args],
            capture_output=True,
            text=True,
            encoding="utf-8",
        )
        return proc.returncode, proc.stdout + proc.stderr

    def test_unchanged_branch_is_present_and_exits_zero(self):
        # main's tip restored v2, identical to release-changed: the
        # delete+restore history collapses in an endpoint diff.
        code, out = self._main(
            "--repo", str(self.repo), "--file", "src/a.c",
            "--base", "release-changed", "--ref", "main",
        )
        self.assertEqual(0, code, out)
        self.assertIn("[PRESENT-UNCHANGED] main", out)

    def test_changed_and_absent_branches_flag_review_and_print_diff(self):
        code, out = self._main(
            "--repo", str(self.repo), "--file", "src/a.c",
            "--base", "release-unchanged",
            "--ref", "release-changed", "--ref", "release-absent",
        )
        self.assertEqual(1, code, out)
        self.assertIn("[CHANGED] release-changed", out)
        self.assertIn("+int v2", out)
        self.assertIn("[ABSENT] release-absent", out)

    def test_unresolvable_ref_is_an_error(self):
        code, out = self._main(
            "--repo", str(self.repo), "--file", "src/a.c",
            "--ref", "no-such-ref",
        )
        self.assertEqual(1, code, out)
        self.assertIn("[ERROR] no-such-ref", out)


if __name__ == "__main__":
    unittest.main()
