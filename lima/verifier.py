"""Fail-closed compilation, security-oracle, rescan, and test gates for repairs."""
import ast
import os
import shlex
import subprocess
import tempfile
import time
import zipfile
from io import BytesIO
from collections import Counter
from typing import Dict

from .python_analyzer import PythonAstSecurityAnalyzer
from .python_dataflow import PythonDataflowAnalyzer


IGNORED_DIRECTORIES = {
    ".git", ".hg", ".mypy_cache", ".pytest_cache", ".tox", ".venv",
    "__pycache__", "build", "dist", "node_modules", "venv",
}
MAX_PYTHON_FILES = 2_000
MAX_FILE_BYTES = 512 * 1024
MAX_TOTAL_BYTES = 20 * 1024 * 1024
MAX_ARCHIVE_MEMBERS = 20_000
MAX_ARCHIVE_UNCOMPRESSED_BYTES = 200 * 1024 * 1024


def _ast_identity(node: ast.AST) -> str:
    return ast.dump(node, annotate_fields=True, include_attributes=False)


def _call_name(node: ast.AST) -> str:
    parts = []
    current = node
    while isinstance(current, ast.Attribute):
        parts.append(current.attr)
        current = current.value
    if isinstance(current, ast.Name):
        parts.append(current.id)
    return ".".join(reversed(parts))


class RepairVerifier:
    def __init__(self, test_command: str = "", timeout_seconds: int = 120):
        self.test_command = test_command
        self.timeout_seconds = timeout_seconds

    def verify_contents(self, files: Dict[str, str], repairs=None) -> dict:
        started = time.monotonic()
        checks = []
        trees = {}
        for path, content in files.items():
            if path.endswith(".py"):
                try:
                    trees[path] = ast.parse(content, filename=path)
                    compile(content, path, "exec")
                    checks.append({"name": "compile:%s" % path, "passed": True})
                except SyntaxError as exc:
                    checks.append({
                        "name": "compile:%s" % path, "passed": False,
                        "detail": "%s:%s: %s" % (path, exc.lineno, exc.msg),
                    })
        if all(item["passed"] for item in checks):
            checks.extend(self._verify_security_oracles(trees, repairs or []))
        return {
            "passed": bool(checks) and all(item["passed"] for item in checks),
            "checks": checks,
            "duration_seconds": round(time.monotonic() - started, 4),
        }

    def _verify_security_oracles(self, trees, repairs):
        checks = []
        for repair in repairs:
            path = str(repair.get("path", ""))
            cwe = str(repair.get("cwe", "unknown"))
            line = int(repair.get("line", 0))
            name = "security-oracle:%s:%s:%d" % (cwe, path, line)
            tree = trees.get(path)
            if tree is None:
                checks.append({"name": name, "passed": False,
                               "detail": "repaired Python file is missing"})
                continue
            nodes = list(ast.walk(tree))
            identities = Counter(_ast_identity(node) for node in nodes)
            original = str(repair.get("original_ast", ""))
            expected = str(repair.get("expected_ast", ""))
            if not original or not expected:
                checks.append({"name": name, "passed": False,
                               "detail": "repair manifest lacks AST identities"})
                continue
            expected_nodes = [node for node in nodes if _ast_identity(node) == expected]
            errors = []
            if identities[original]:
                errors.append("vulnerable AST is still present")
            if len(expected_nodes) != 1 or not isinstance(expected_nodes[0], ast.Call):
                errors.append("expected replacement call is not unique")
            else:
                errors.extend(self._strategy_errors(expected_nodes[0], repair, identities))
            checks.append({
                "name": name, "passed": not errors,
                "detail": "; ".join(errors) if errors else str(
                    repair.get("security_invariant", "verified")
                ),
            })
        return checks

    @staticmethod
    def _strategy_errors(call, repair, identities):
        strategy = str(repair.get("strategy", ""))
        oracle = repair.get("oracle") or {}
        errors = []
        if strategy == "argv-no-shell":
            if not call.args or not isinstance(call.args[0], (ast.List, ast.Tuple)):
                errors.append("command is not an argv sequence")
            elif (not call.args[0].elts
                  or not isinstance(call.args[0].elts[0], ast.Constant)
                  or not isinstance(call.args[0].elts[0].value, str)):
                errors.append("executable is not a fixed string")
            shell = [item.value for item in call.keywords if item.arg == "shell"]
            if (len(shell) != 1 or not isinstance(shell[0], ast.Constant)
                    or shell[0].value is not False):
                errors.append("shell=False is not explicit")
        elif strategy == "parameterized-sql":
            if (len(call.args) != 2 or not isinstance(call.args[0], ast.Constant)
                    or not isinstance(call.args[0].value, str)
                    or not isinstance(call.args[1], ast.Tuple)):
                errors.append("SQL is not a constant query plus tuple parameters")
            else:
                count = int(oracle.get("parameter_count", -1))
                placeholder = str(oracle.get("placeholder", ""))
                if count < 1 or len(call.args[1].elts) != count:
                    errors.append("SQL parameter arity changed")
                if not placeholder or call.args[0].value.count(placeholder) != count:
                    errors.append("SQL placeholder arity changed")
        elif strategy == "confined-path":
            if (not call.args or not isinstance(call.args[0], ast.Call)
                    or _call_name(call.args[0].func) != "_lima_resolve_under_base"):
                errors.append("path sink does not use the confinement helper")
            helper = str(repair.get("expected_helper_ast", ""))
            if not helper or identities[helper] != 1:
                errors.append("audited confinement helper is missing or modified")
        else:
            errors.append("unknown repair strategy")
        return errors

    def verify_worktree(self, root: str, require_tests: bool = False) -> dict:
        if not self.test_command:
            passed = not require_tests
            return {
                "passed": passed,
                "checks": [{
                    "name": "repository-tests-configured", "passed": passed,
                    "detail": (
                        "No test command configured; security repairs may not be published."
                        if require_tests else "No repository test command configured."
                    ),
                }],
            }
        root = os.path.abspath(root)
        if not os.path.isdir(root):
            raise ValueError("verification worktree does not exist")
        command = shlex.split(self.test_command, posix=os.name != "nt")
        started = time.monotonic()
        env = {
            key: value for key, value in os.environ.items()
            if key in {"PATH", "SYSTEMROOT", "WINDIR", "LANG", "LC_ALL", "TMP", "TEMP"}
        }
        env.update({"HTTP_PROXY": "", "HTTPS_PROXY": "", "ALL_PROXY": "", "NO_PROXY": "*"})
        with tempfile.TemporaryDirectory(prefix="lima-verify-") as temp:
            env["TMPDIR"] = temp
            try:
                result = subprocess.run(
                    command, cwd=root, env=env, text=True, capture_output=True,
                    encoding="utf-8", errors="replace",
                    timeout=self.timeout_seconds, check=False,
                )
                passed = result.returncode == 0
                detail = (result.stdout + "\n" + result.stderr)[-8000:]
            except (OSError, subprocess.TimeoutExpired) as exc:
                passed = False
                detail = (
                    "verification exceeded %d seconds" % self.timeout_seconds
                    if isinstance(exc, subprocess.TimeoutExpired) else str(exc)
                )
        return {
            "passed": passed,
            "checks": [{"name": "repository-tests", "passed": passed, "detail": detail}],
            "duration_seconds": round(time.monotonic() - started, 4),
        }

    def verify_archive(self, archive: bytes, files: Dict[str, str], repairs=None) -> dict:
        """Verify a patch in a bounded, isolated copy of the complete repository."""
        started = time.monotonic()
        repairs = repairs or []
        with tempfile.TemporaryDirectory(prefix="lima-repair-") as root:
            self._safe_extract(archive, root)
            entries = [item for item in os.scandir(root) if item.is_dir()]
            worktree = entries[0].path if len(entries) == 1 else root
            before = self._snapshot_python(worktree)
            for path, content in files.items():
                target = os.path.abspath(os.path.join(worktree, path))
                if not target.startswith(os.path.abspath(worktree) + os.sep):
                    raise ValueError("repair path escapes the repository")
                os.makedirs(os.path.dirname(target), exist_ok=True)
                with open(target, "w", encoding="utf-8", newline="") as handle:
                    handle.write(content)
            after = self._snapshot_python(worktree)
            content_result = self.verify_contents(files, repairs)
            checks = list(content_result["checks"])
            if content_result["passed"] and repairs:
                checks.extend(self.verify_differential(before, after, repairs)["checks"])
            if all(item["passed"] for item in checks):
                test_result = self.verify_worktree(worktree, require_tests=bool(repairs))
                checks.extend(test_result["checks"])
            return {
                "passed": bool(checks) and all(item["passed"] for item in checks),
                "checks": checks,
                "duration_seconds": round(time.monotonic() - started, 4),
            }

    def verify_differential(self, before, after, repairs):
        started = time.monotonic()
        checks = self._verify_differential_scan(before, after, repairs)
        return {
            "passed": bool(checks) and all(item["passed"] for item in checks),
            "checks": checks,
            "duration_seconds": round(time.monotonic() - started, 4),
        }

    @staticmethod
    def _safe_extract(archive, root):
        with zipfile.ZipFile(BytesIO(archive)) as bundle:
            members = bundle.infolist()
            if len(members) > MAX_ARCHIVE_MEMBERS:
                raise ValueError("repository archive contains too many entries")
            if sum(item.file_size for item in members) > MAX_ARCHIVE_UNCOMPRESSED_BYTES:
                raise ValueError("repository archive exceeds extraction limit")
            for member in members:
                normalized = os.path.normpath(member.filename).replace("\\", "/")
                if normalized.startswith("../") or normalized.startswith("/"):
                    raise ValueError("repository archive contains an unsafe path")
                target = os.path.abspath(os.path.join(root, normalized))
                if not target.startswith(os.path.abspath(root) + os.sep):
                    raise ValueError("repository archive escapes the sandbox")
                if member.is_dir():
                    continue
                os.makedirs(os.path.dirname(target), exist_ok=True)
                with bundle.open(member) as source, open(target, "wb") as destination:
                    while True:
                        chunk = source.read(64 * 1024)
                        if not chunk:
                            break
                        destination.write(chunk)

    @staticmethod
    def _snapshot_python(root):
        files = {}
        total = 0
        for current, directories, names in os.walk(root, followlinks=False):
            directories[:] = sorted(
                item for item in directories
                if item not in IGNORED_DIRECTORIES
                and not os.path.islink(os.path.join(current, item))
            )
            for name in sorted(names):
                if not name.endswith(".py"):
                    continue
                target = os.path.join(current, name)
                size = os.path.getsize(target)
                if size > MAX_FILE_BYTES:
                    raise ValueError("Python file exceeds repair verification limit: %s" % target)
                total += size
                if total > MAX_TOTAL_BYTES or len(files) >= MAX_PYTHON_FILES:
                    raise ValueError("repository exceeds repair verification limits")
                relative = os.path.relpath(target, root).replace("\\", "/")
                with open(target, "r", encoding="utf-8") as handle:
                    files[relative] = handle.read()
        return files

    @staticmethod
    def _verify_differential_scan(before, after, repairs):
        before_flow = PythonDataflowAnalyzer().analyze_project(before)
        after_flow = PythonDataflowAnalyzer().analyze_project(after)
        before_ast = [
            finding for path, content in before.items()
            for finding in PythonAstSecurityAnalyzer().analyze(path, content).findings
        ]
        after_ast = [
            finding for path, content in after.items()
            for finding in PythonAstSecurityAnalyzer().analyze(path, content).findings
        ]
        before_counts = Counter(
            (item.path, item.cwe) for item in before_ast + before_flow.findings
        )
        after_counts = Counter(
            (item.path, item.cwe) for item in after_ast + after_flow.findings
        )
        checks = []
        for repair in repairs:
            path = str(repair.get("path", ""))
            cwe = str(repair.get("cwe", ""))
            strategy = str(repair.get("strategy", ""))
            before_count = before_counts[(path, cwe)]
            after_count = after_counts[(path, cwe)]
            original = str(repair.get("original_ast", ""))
            try:
                before_tree = ast.parse(before[path], filename=path)
                original_count = sum(
                    _ast_identity(node) == original for node in ast.walk(before_tree)
                )
            except (KeyError, SyntaxError):
                original_count = 0
            # The exact helper oracle proves CWE-22 confinement. The generic taint
            # analyzer intentionally treats unknown helpers as taint-preserving.
            reduced = original_count == 1 and before_count > 0 and (
                after_count < before_count or strategy == "confined-path"
            )
            checks.append({
                "name": "differential-rescan:%s:%s" % (cwe, path),
                "passed": reduced,
                "detail": "original_ast=%d; target findings before=%d after=%d" % (
                    original_count, before_count, after_count
                ),
            })
        return checks
