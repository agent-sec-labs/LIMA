import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from lima.repository_scanner import RepositoryScanner
from lima.workspace import RepositoryWorkspace


def _cp1252_environment():
    """Reproduce the legacy standard streams used by Windows CI runners."""

    environment = os.environ.copy()
    environment["PYTHONUTF8"] = "0"
    environment["PYTHONIOENCODING"] = "cp1252"
    return environment


class RepositoryWorkspaceTests(unittest.TestCase):
    def test_inventory_includes_all_supported_cxx_extensions(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            supported = [
                "main.c", "main.cc", "main.cpp", "main.cxx", "main.h",
                "main.hh", "main.hpp", "main.hxx", "toolchain.cmake",
                "CMakeLists.txt",
            ]
            for name in supported:
                (root / name).write_text("// source\n", encoding="utf-8")
            for name in ("compiled.obj", "program.exe", "Makefile"):
                (root / name).write_text("not source\n", encoding="utf-8")

            inventory = RepositoryWorkspace(root).inventory()

            self.assertEqual(sorted(supported), sorted(item.path for item in inventory.files))
            self.assertEqual(3, inventory.skipped["unsupported-extension"])

    def test_import_area_is_not_recursively_scanned(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            imported = root / "repositories" / "other-project"
            imported.mkdir(parents=True)
            imported.joinpath("unsafe.py").write_text(
                "eval(user_input)\n", encoding="utf-8"
            )
            root.joinpath("app.py").write_text("safe = True\n", encoding="utf-8")

            inventory = RepositoryWorkspace(root).inventory()

            self.assertEqual(["app.py"], [item.path for item in inventory.files])
            self.assertEqual(1, inventory.skipped["ignored-directory"])

    def test_scan_repository_cli_runs_without_installing_package(self):
        project_root = Path(__file__).resolve().parents[1]
        script = project_root / "scripts" / "scan_repository.py"
        with tempfile.TemporaryDirectory() as temporary:
            repository = Path(temporary)
            (repository / "app.py").write_text("eval(user_input)\n", encoding="utf-8")
            completed = subprocess.run(
                [sys.executable, str(script), str(repository), "--format", "json"],
                cwd=project_root,
                capture_output=True,
                encoding="utf-8",
                env=_cp1252_environment(),
                text=True,
                timeout=30,
                check=False,
            )

            self.assertEqual(completed.returncode, 0, completed.stderr)
            payload = json.loads(completed.stdout)
            self.assertEqual(payload["findings"][0]["rule_id"], "SEC-EVAL")
            self.assertEqual("off", payload["collaboration"]["cxx_memory"]["mode"])

    def test_scan_repository_cli_requires_repository_key_for_cxx_analysis(self):
        project_root = Path(__file__).resolve().parents[1]
        script = project_root / "scripts" / "scan_repository.py"
        with tempfile.TemporaryDirectory() as temporary:
            repository = Path(temporary)
            (repository / "main.cpp").write_text(
                "int main() { return 0; }\n", encoding="utf-8"
            )

            completed = subprocess.run(
                [
                    sys.executable, str(script), str(repository),
                    "--cxx-memory", "auto", "--sast", "off",
                ],
                cwd=project_root,
                capture_output=True,
                encoding="utf-8",
                env=_cp1252_environment(),
                text=True,
                timeout=30,
                check=False,
            )

            self.assertEqual(2, completed.returncode)
            self.assertIn("--repository-key is required", completed.stderr)

    def test_scan_repository_cli_rejects_unsafe_cxx_repository_key(self):
        project_root = Path(__file__).resolve().parents[1]
        script = project_root / "scripts" / "scan_repository.py"
        with tempfile.TemporaryDirectory() as temporary:
            repository = Path(temporary)
            (repository / "main.cpp").write_text(
                "int main() { return 0; }\n", encoding="utf-8"
            )

            completed = subprocess.run(
                [
                    sys.executable, str(script), str(repository),
                    "--cxx-memory", "auto", "--repository-key", "../escape",
                    "--sast", "off",
                ],
                cwd=project_root,
                capture_output=True,
                encoding="utf-8",
                env=_cp1252_environment(),
                text=True,
                timeout=30,
                check=False,
            )

            self.assertEqual(2, completed.returncode)
            self.assertIn("invalid --repository-key", completed.stderr)

    def test_scan_cli_can_gate_only_verified_findings(self):
        project_root = Path(__file__).resolve().parents[1]
        script = project_root / "scripts" / "scan_repository.py"
        with tempfile.TemporaryDirectory() as temporary:
            repository = Path(temporary)
            source = repository / "app.py"
            source.write_text(
                "def evaluate(code):\n    return eval(code)\n", encoding="utf-8"
            )

            def run(*extra):
                return subprocess.run(
                    [
                        sys.executable, str(script), str(repository),
                        "--format", "json", "--sast", "off",
                        "--fail-on", "critical", *extra,
                    ],
                    cwd=project_root,
                    capture_output=True,
                    encoding="utf-8",
                    env=_cp1252_environment(),
                    text=True,
                    timeout=30,
                    check=False,
                )

            self.assertEqual(2, run().returncode)
            self.assertEqual(0, run("--verified-only").returncode)

            source.write_text(
                "@app.post('/evaluate')\n"
                "def evaluate(code):\n"
                "    return eval(code)\n",
                encoding="utf-8",
            )
            self.assertEqual(2, run("--verified-only").returncode)

    def test_inventory_is_bounded_deterministic_and_skips_sensitive_paths(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "z.py").write_text("print('z')\n", encoding="utf-8")
            (root / "a.py").write_text("print('a')\n", encoding="utf-8")
            (root / ".env").write_text("TOKEN=do-not-read\n", encoding="utf-8")
            (root / ".venv").mkdir()
            (root / ".venv" / "ignored.py").write_text("eval(data)\n", encoding="utf-8")
            (root / "blob.py").write_bytes(b"x" * 64)

            inventory = RepositoryWorkspace(root, max_file_bytes=32).inventory()

            self.assertEqual([item.path for item in inventory.files], ["a.py", "z.py"])
            self.assertEqual(inventory.skipped["sensitive-config"], 1)
            self.assertEqual(inventory.skipped["ignored-directory"], 1)
            self.assertEqual(inventory.skipped["file-size-limit"], 1)
            self.assertEqual(inventory.discovered_files, 2)
            self.assertEqual(inventory.file_coverage, 1.0)

    def test_inventory_prioritizes_production_source_over_examples_when_bounded(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "examples").mkdir()
            (root / "src").mkdir()
            (root / "examples" / "large.py").write_text("x" * 20, encoding="utf-8")
            (root / "src" / "security.py").write_text("safe = True\n", encoding="utf-8")

            inventory = RepositoryWorkspace(root, max_total_bytes=16).inventory()

            self.assertEqual(["src/security.py"], [item.path for item in inventory.files])
            self.assertTrue(inventory.truncated)
            self.assertEqual(inventory.discovered_files, 2)
            self.assertLess(inventory.file_coverage, 1.0)

    def test_read_text_rejects_repository_escape(self):
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            root = parent / "repository"
            root.mkdir()
            (root / "inside.py").write_text("safe = True\n", encoding="utf-8")
            (parent / "outside.py").write_text("secret = True\n", encoding="utf-8")
            workspace = RepositoryWorkspace(root)

            with self.assertRaisesRegex(ValueError, "escapes repository root"):
                workspace.read_text("../outside.py")

    def test_repository_scanner_reuses_local_security_findings(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "app.py").write_text(
                "password = 'not-a-real-secret'\nresult = eval(user_input)\n",
                encoding="utf-8",
            )

            result = RepositoryScanner(sast_mode="off").scan(RepositoryWorkspace(root))
            rules = {item.rule_id for item in result.report.findings}

            self.assertEqual(rules, {"SEC-EVAL", "SEC-HARDCODED-SECRET"})
            self.assertEqual(result.report.files_reviewed, ["app.py"])
            self.assertEqual(result.report.risk, "critical")
            self.assertFalse(result.inventory.truncated)

    def test_python_ast_scanner_ignores_comments_and_string_examples(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "examples.py").write_text(
                "# eval(user_input)\nexample = \"password = 'demo-secret'\"\n",
                encoding="utf-8",
            )
            (root / "unsafe.py").write_text(
                "import os\nimport pickle\nos.system(command)\npickle.loads(payload)\n",
                encoding="utf-8",
            )

            result = RepositoryScanner(sast_mode="off").scan(RepositoryWorkspace(root))
            identities = {(item.rule_id, item.path) for item in result.report.findings}

            self.assertNotIn(("SEC-EVAL", "examples.py"), identities)
            self.assertNotIn(("SEC-HARDCODED-SECRET", "examples.py"), identities)
            self.assertIn(("SEC-OS-SYSTEM", "unsafe.py"), identities)
            self.assertIn(("SEC-UNSAFE-DESERIALIZATION", "unsafe.py"), identities)

    def test_python_sql_rule_prefers_precision_when_parameters_are_bound(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "queries.py").write_text(
                "cursor.execute('SELECT * FROM users WHERE ' + clause, params)\n"
                "cursor.execute(f'SELECT * FROM users WHERE id = {user_id}')\n",
                encoding="utf-8",
            )

            result = RepositoryScanner(sast_mode="off").scan(RepositoryWorkspace(root))
            sql_findings = [
                item for item in result.report.findings if item.rule_id == "SEC-SQL-CONCAT"
            ]

            self.assertEqual(len(sql_findings), 1)
            self.assertEqual(sql_findings[0].line, 2)


if __name__ == "__main__":
    unittest.main()
