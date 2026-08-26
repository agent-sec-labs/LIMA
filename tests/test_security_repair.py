import ast
import io
import os
import tempfile
import unittest
import zipfile
from pathlib import Path

from lima.fixer import SafeFixer
from lima.repair_preview import RepositoryRepairPreviewer
from lima.verifier import RepairVerifier
from lima.workspace import RepositoryWorkspace


def finding(path, line, rule_id, cwe):
    return {
        "path": path,
        "line": line,
        "rule_id": rule_id,
        "cwe": cwe,
        "verification_state": "dataflow-verified",
    }


def repository_archive(files):
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as bundle:
        for path, content in files.items():
            bundle.writestr("repo/" + path, content)
    return output.getvalue()


class SecurityRepairTemplateTests(unittest.TestCase):
    def test_explicitly_disabled_finding_cannot_create_repair_or_preview(self):
        source = (
            "import sqlite3\n"
            "value = input()\n"
            "cursor.execute('SELECT * FROM users WHERE id = ' + value)\n"
        )
        disabled = {
            **finding("app.py", 3, "SEC-SQL-CONCAT", "CWE-89"),
            "automatic_repair": False,
        }

        result = SafeFixer().apply(source, [disabled], "app.py")

        self.assertEqual([], result["rules"])
        self.assertEqual(source, result["content"])
        self.assertEqual("automatic-repair-disabled", result["blocked"][0]["reason"])

        with tempfile.TemporaryDirectory() as root:
            Path(root, "app.py").write_text(source, encoding="utf-8")
            preview = RepositoryRepairPreviewer().preview(
                RepositoryWorkspace(root), {"findings": [disabled]}
            )

        self.assertEqual("no-repair", preview["status"])
        self.assertEqual([], preview["patches"])
        self.assertEqual([], preview["repair_manifest"])
        self.assertEqual(
            "automatic-repair-disabled", preview["blocked_findings"][0]["reason"]
        )

    def test_cwe78_converts_fixed_command_to_argv_and_disables_shell(self):
        source = (
            "import subprocess\n"
            "def run():\n"
            "    value = input()\n"
            "    return subprocess.run('printf %s ' + value, shell=True)\n"
        )
        result = SafeFixer().apply(
            source, [finding("app.py", 4, "SEC-SUBPROCESS-SHELL", "CWE-78")], "app.py"
        )

        self.assertEqual(["SEC-SUBPROCESS-SHELL"], result["rules"])
        self.assertIn("subprocess.run(['printf', '%s', value], shell=False)", result["content"])
        self.assertEqual("argv-no-shell", result["repairs"][0]["strategy"])
        self.assertTrue(
            RepairVerifier().verify_contents(
                {"app.py": result["content"]}, result["repairs"]
            )["passed"]
        )

    def test_cwe78_rejects_dynamic_executable_and_shell_operators(self):
        dynamic = "import subprocess\nsubprocess.run(command + ' --safe', shell=True)\n"
        operators = "import subprocess\nsubprocess.run('echo ' + value + ' | tee out', shell=True)\n"

        first = SafeFixer().apply(
            dynamic, [finding("app.py", 2, "SEC-SUBPROCESS-SHELL", "CWE-78")], "app.py"
        )
        second = SafeFixer().apply(
            operators, [finding("app.py", 2, "SEC-SUBPROCESS-SHELL", "CWE-78")], "app.py"
        )

        self.assertEqual("dynamic-executable", first["blocked"][0]["reason"])
        self.assertEqual("shell-syntax-required", second["blocked"][0]["reason"])

    def test_cwe78_os_system_is_repaired_only_when_return_value_is_unused(self):
        source = "import os\nvalue = input()\nos.system('echo ' + value)\n"
        used = "import os\nvalue = input()\nstatus = os.system('echo ' + value)\n"

        repaired = SafeFixer().apply(
            source, [finding("app.py", 3, "SEC-OS-SYSTEM", "CWE-78")], "app.py"
        )
        blocked = SafeFixer().apply(
            used, [finding("app.py", 3, "SEC-OS-SYSTEM", "CWE-78")], "app.py"
        )

        self.assertIn("import subprocess as _lima_subprocess", repaired["content"])
        self.assertIn("shell=False, check=True", repaired["content"])
        self.assertEqual("os-system-result-is-used", blocked["blocked"][0]["reason"])

    def test_cwe89_uses_driver_paramstyle_and_preserves_value_expression(self):
        sqlite_source = (
            "import sqlite3\n"
            "user_id = input()\n"
            "cursor.execute('SELECT name FROM users WHERE id = ' + user_id)\n"
        )
        postgres_source = (
            "import psycopg\n"
            "user_id = input()\n"
            "cursor.execute(f'SELECT name FROM users WHERE id = {user_id}')\n"
        )

        sqlite_result = SafeFixer().apply(
            sqlite_source, [finding("db.py", 3, "SEC-SQL-CONCAT", "CWE-89")], "db.py"
        )
        postgres_result = SafeFixer().apply(
            postgres_source, [finding("db.py", 3, "SEC-SQL-CONCAT", "CWE-89")], "db.py"
        )

        self.assertIn("cursor.execute('SELECT name FROM users WHERE id = ?', (user_id,))", sqlite_result["content"])
        self.assertIn("cursor.execute('SELECT name FROM users WHERE id = %s', (user_id,))", postgres_result["content"])
        self.assertEqual("parameterized-sql", sqlite_result["repairs"][0]["strategy"])

    def test_cwe89_rejects_dynamic_schema_and_unknown_driver(self):
        dynamic_table = (
            "import sqlite3\n"
            "table = input()\n"
            "cursor.execute('SELECT * FROM ' + table + ' WHERE id = 1')\n"
        )
        unknown = (
            "user_id = input()\n"
            "cursor.execute('SELECT * FROM users WHERE id = ' + user_id)\n"
        )

        first = SafeFixer().apply(
            dynamic_table, [finding("db.py", 3, "SEC-SQL-CONCAT", "CWE-89")], "db.py"
        )
        second = SafeFixer().apply(
            unknown, [finding("db.py", 2, "SEC-SQL-CONCAT", "CWE-89")], "db.py"
        )

        self.assertEqual("dynamic-sql-structure", first["blocked"][0]["reason"])
        self.assertEqual("unknown-sql-paramstyle", second["blocked"][0]["reason"])

    def test_cwe22_adds_canonical_containment_helper_and_rejects_escape(self):
        with tempfile.TemporaryDirectory() as root:
            source = (
                "from pathlib import Path\n"
                "BASE_ROOT = Path(%r)\n"
                "def read_file(user_path):\n"
                "    return open(BASE_ROOT / user_path)\n"
            ) % root
            result = SafeFixer().apply(
                source, [finding("files.py", 4, "FLOW-PATH", "CWE-22")], "files.py"
            )

            self.assertEqual(["FLOW-PATH"], result["rules"])
            self.assertIn("_lima_resolve_under_base(BASE_ROOT, user_path)", result["content"])
            self.assertEqual("confined-path", result["repairs"][0]["strategy"])
            namespace = {}
            exec(compile(result["content"], "files.py", "exec"), namespace)
            resolver = namespace["_lima_resolve_under_base"]
            self.assertEqual(Path(root).resolve(), resolver(root, "."))
            with self.assertRaisesRegex(ValueError, "escapes allowed root"):
                resolver(root, "../outside.txt")

    def test_cwe22_rejects_unproven_root(self):
        source = "from pathlib import Path\ndef read(upload_root, name):\n    return open(upload_root / name)\n"
        result = SafeFixer().apply(
            source, [finding("files.py", 3, "FLOW-PATH", "CWE-22")], "files.py"
        )
        self.assertEqual("trusted-path-root-not-proven", result["blocked"][0]["reason"])

    def test_oracle_detects_a_tampered_generated_patch(self):
        source = "import subprocess\nvalue = input()\nsubprocess.run('echo ' + value, shell=True)\n"
        result = SafeFixer().apply(
            source, [finding("app.py", 3, "SEC-SUBPROCESS-SHELL", "CWE-78")], "app.py"
        )
        tampered = result["content"].replace("shell=False", "shell=True")
        verification = RepairVerifier().verify_contents(
            {"app.py": tampered}, result["repairs"]
        )
        self.assertFalse(verification["passed"])
        self.assertIn("expected replacement call is not unique", verification["checks"][-1]["detail"])

    def test_archive_gate_requires_tests_for_security_repairs(self):
        source = "import sqlite3\nvalue = input()\ncursor.execute('SELECT * FROM t WHERE id = ' + value)\n"
        result = SafeFixer().apply(
            source, [finding("app.py", 3, "FLOW-SQL", "CWE-89")], "app.py"
        )
        verification = RepairVerifier().verify_archive(
            repository_archive({"app.py": source}),
            {"app.py": result["content"]}, result["repairs"],
        )
        self.assertFalse(verification["passed"])
        self.assertEqual("repository-tests-configured", verification["checks"][-1]["name"])


class VerifiedRepairLoopTests(unittest.TestCase):
    def test_atomic_commit_and_draft_pr_follow_all_verification_gates(self):
        source = (
            "import sqlite3\n"
            "def lookup(cursor):\n"
            "    value = input()\n"
            "    return cursor.execute('SELECT name FROM users WHERE id = ' + value)\n"
        )
        regression_test = (
            "import unittest\n"
            "from unittest.mock import Mock, patch\n"
            "from app import lookup\n"
            "class RepairTests(unittest.TestCase):\n"
            "    def test_query_value_is_bound(self):\n"
            "        cursor = Mock()\n"
            "        with patch('builtins.input', return_value='1 OR 1=1'):\n"
            "            lookup(cursor)\n"
            "        cursor.execute.assert_called_once_with(\n"
            "            'SELECT name FROM users WHERE id = ?', ('1 OR 1=1',))\n"
        )

        class Client:
            def __init__(self):
                self.commit = None
                self.draft = None

            def get_pull_request(self, _repository, _pull_request):
                return {
                    "head": {"ref": "feature", "sha": "source-sha",
                             "repo": {"full_name": "org/repo"}},
                    "base": {"ref": "main"},
                }

            def get_file(self, _repository, path, _ref):
                self.assert_path = path
                return {"decoded_content": source, "sha": "blob-sha"}

            def download_archive(self, _repository, _sha):
                return repository_archive({"app.py": source, "test_app.py": regression_test})

            def create_atomic_commit(self, repository, branch, sha, files, message):
                self.commit = (repository, branch, sha, files, message)
                return {"sha": "repair-sha"}

            def create_draft_pull_request(self, repository, title, branch, base, body):
                self.draft = (repository, title, branch, base, body)
                return {"number": 9, "html_url": "https://example.test/pr/9"}

        client = Client()
        fixer = SafeFixer(RepairVerifier("python -m unittest discover -s .", 30))
        result = fixer.create_fix_commits(
            client, "org/repo", 7,
            {"findings": [finding("app.py", 4, "FLOW-SQL", "CWE-89")]},
        )

        self.assertIsNotNone(client.commit)
        self.assertIsNotNone(client.draft)
        self.assertEqual("repair-sha", result["commits"][0]["sha"])
        self.assertEqual(9, result["draft_pull_request"]["number"])
        self.assertEqual("parameterized-sql", result["repair_manifest"][0]["strategy"])
        names = {item["name"] for item in result["verification"]["checks"]}
        self.assertIn("security-oracle:CWE-89:app.py:4", names)
        self.assertIn("differential-rescan:CWE-89:app.py", names)
        self.assertIn("repository-tests", names)

    def test_failed_repository_test_prevents_any_github_write(self):
        source = (
            "import subprocess\n"
            "value = input()\n"
            "subprocess.run('echo ' + value, shell=True)\n"
        )

        class Client:
            def get_pull_request(self, _repository, _pull_request):
                return {
                    "head": {"ref": "feature", "sha": "source-sha",
                             "repo": {"full_name": "org/repo"}},
                    "base": {"ref": "main"},
                }

            def get_file(self, _repository, _path, ref):
                if ref != "source-sha":
                    raise AssertionError("repair input must be pinned to the PR commit")
                return {"decoded_content": source, "sha": "blob-sha"}

            def download_archive(self, _repository, _sha):
                return repository_archive({
                    "app.py": source,
                    "test_failure.py": (
                        "import unittest\n"
                        "class Failure(unittest.TestCase):\n"
                        "    def test_regression(self):\n"
                        "        self.fail('behavior changed')\n"
                    ),
                })

            def create_atomic_commit(self, *_args):
                raise AssertionError("a failed verification must not write a commit")

            def create_draft_pull_request(self, *_args):
                raise AssertionError("a failed verification must not create a PR")

        result = SafeFixer(
            RepairVerifier("python -m unittest discover -s .", 30)
        ).create_fix_commits(
            Client(), "org/repo", 8,
            {"findings": [finding(
                "app.py", 3, "SEC-SUBPROCESS-SHELL", "CWE-78"
            )]},
        )

        self.assertIsNone(result["branch"])
        self.assertEqual([], result["commits"])
        self.assertFalse(result["verification"]["passed"])
        self.assertEqual("repository-tests", result["verification"]["checks"][-1]["name"])


if __name__ == "__main__":
    unittest.main()
