import ast
import os
import tempfile
import unittest
from pathlib import Path

from lima.fixer import SafeFixer
from lima.repair_preview import RepositoryRepairPreviewer
from lima.verifier import RepairVerifier
from lima.workspace import RepositoryWorkspace
from tests.test_repair_semantic_guards import old_path_patch


class RepairTrustBoundaryTests(unittest.TestCase):
    def test_relative_root_is_refused_by_planner_preview_and_oracle(self):
        source = (
            "from pathlib import Path\nBASE_ROOT=Path('approved')\n"
            "def read(name):\n return open(BASE_ROOT / name)\n"
        )
        finding = dict(
            path="app.py",
            line=4,
            cwe="CWE-22",
            rule_id="FLOW-PATH",
            verification_state="dataflow-verified",
        )
        result = SafeFixer().apply(source, [finding], "app.py")
        self.assertEqual([], result["repairs"])
        patched, manifest = old_path_patch(source)
        self.assertFalse(RepairVerifier().verify_contents({"app.py": patched}, manifest)["passed"])
        with tempfile.TemporaryDirectory() as root:
            Path(root, "app.py").write_text(source, encoding="utf-8")
            preview = RepositoryRepairPreviewer().preview(
                RepositoryWorkspace(root), {"findings": [finding]}
            )
        self.assertEqual("no-repair", preview["status"])

    def test_wrapper_is_refused_even_with_sqlite_import_and_hint(self):
        source = (
            "import sqlite3\n# lima: sql-paramstyle=qmark\n"
            "class LegacyCursor:\n def execute(self, statement, parameters=()):\n"
            "  return statement.replace('?', str(parameters))\n"
            "cursor=LegacyCursor()\nvalue=input()\n"
            "cursor.execute('SELECT * FROM users WHERE id = ' + value)\n"
        )
        finding = dict(
            path="app.py",
            line=8,
            cwe="CWE-89",
            rule_id="FLOW-SQL",
            verification_state="dataflow-verified",
        )
        self.assertEqual([], SafeFixer().apply(source, [finding], "app.py")["repairs"])
        patched = source.replace(
            "'SELECT * FROM users WHERE id = ' + value",
            "'SELECT * FROM users WHERE id = ?', (value,)",
        )
        call = next(
            n
            for n in ast.walk(ast.parse(patched))
            if isinstance(n, ast.Call)
            and isinstance(n.func, ast.Attribute)
            and n.func.attr == "execute"
        )
        original = next(
            n
            for n in ast.walk(ast.parse(source))
            if isinstance(n, ast.Call)
            and isinstance(n.func, ast.Attribute)
            and n.func.attr == "execute"
        )
        manifest = [
            dict(
                path="app.py",
                line=8,
                cwe="CWE-89",
                strategy="parameterized-sql",
                original_ast=ast.dump(original, include_attributes=False),
                expected_ast=ast.dump(call, include_attributes=False),
                oracle=dict(
                    parameter_count=1,
                    placeholder="?",
                    paramstyle="qmark",
                    driver_contract="sqlite3-standard-v1",
                ),
            )
        ]
        verification = RepairVerifier().verify_contents({"app.py": patched}, manifest)
        self.assertFalse(verification["passed"])
        self.assertIn("SQL driver binding is not proven", verification["checks"][-1]["detail"])
        with tempfile.TemporaryDirectory() as root:
            Path(root, "app.py").write_text(source, encoding="utf-8")
            preview = RepositoryRepairPreviewer().preview(
                RepositoryWorkspace(root), {"findings": [finding]}
            )
        self.assertEqual("no-repair", preview["status"])

    def test_oracle_rejects_tampered_driver_and_placeholder_claims(self):
        source = (
            "import sqlite3\nconnection=sqlite3.connect(':memory:')\n"
            "value=input()\nconnection.execute('SELECT * FROM t WHERE id = ' + value)\n"
        )
        finding = dict(
            path="app.py",
            line=4,
            cwe="CWE-89",
            rule_id="FLOW-SQL",
            verification_state="dataflow-verified",
        )
        result = SafeFixer().apply(source, [finding], "app.py")
        self.assertTrue(
            RepairVerifier().verify_contents({"app.py": result["content"]}, result["repairs"])[
                "passed"
            ]
        )
        result["repairs"][0]["oracle"]["placeholder"] = "%s"
        self.assertFalse(
            RepairVerifier().verify_contents({"app.py": result["content"]}, result["repairs"])[
                "passed"
            ]
        )

    def test_runtime_helper_rejects_relative_root_before_resolve(self):
        from lima.repair_bindings import PATH_HELPER_SOURCE

        namespace = {}
        # Execute only the fixed helper specification maintained in this repository.
        exec("from pathlib import Path as _LIMAPath\n" + PATH_HELPER_SOURCE, namespace)  # noqa: S102
        with self.assertRaisesRegex(ValueError, "absolute"):
            namespace["_lima_resolve_under_base"]("approved", "marker.txt")
        foreign_root = "/fixed" if os.name == "nt" else "C:/fixed"
        with self.assertRaisesRegex(ValueError, "absolute"):
            namespace["_lima_resolve_under_base"](foreign_root, "marker.txt")
