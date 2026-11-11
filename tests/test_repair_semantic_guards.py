"""Security meaning must survive template generation and independent verification."""

import ast
import unittest

from lima.fixer import SafeFixer
from lima.verifier import RepairVerifier

HELPER = """from pathlib import Path as _LIMAPath
def _lima_resolve_under_base(base, untrusted_path):
    root = _LIMAPath(base)
    if not root.is_absolute():
        raise ValueError('path root must be absolute')
    root = root.resolve()
    candidate = (root / untrusted_path).resolve()
    if candidate != root and root not in candidate.parents:
        raise ValueError('path escapes allowed root')
    return candidate
"""
ROOT_SETUP = "from pathlib import Path\nBASE_ROOT=Path('/safe')\n"


def identity(node):
    return ast.dump(node, annotate_fields=True, include_attributes=False)


def finding(source, cwe):
    tree = ast.parse(source)
    call = next(
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and (
            (cwe == "CWE-78" and isinstance(node.func, ast.Attribute) and node.func.attr == "run")
            or (cwe == "CWE-22" and isinstance(node.func, ast.Name) and node.func.id == "open")
        )
    )
    return {
        "path": "app.py",
        "line": call.lineno,
        "cwe": cwe,
        "rule_id": "SEC-SUBPROCESS-SHELL" if cwe == "CWE-78" else "FLOW-PATH",
        "verification_state": "dataflow-verified",
    }


def old_path_patch(source, helper=HELPER):
    original = next(
        n
        for n in ast.walk(ast.parse(source))
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id == "open"
    )
    patched = helper + source.replace(
        "open(BASE_ROOT / name)", "open(_lima_resolve_under_base(BASE_ROOT, name))"
    )
    expected = next(
        n
        for n in ast.walk(ast.parse(patched))
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id == "open"
    )
    helper_node = next(n for n in ast.parse(helper).body if isinstance(n, ast.FunctionDef))
    return patched, [
        {
            "path": "app.py",
            "line": original.lineno,
            "cwe": "CWE-22",
            "strategy": "confined-path",
            "original_ast": identity(original),
            "expected_ast": identity(expected),
            "expected_helper_ast": identity(helper_node),
        }
    ]


class RepairSemanticGuardsTests(unittest.TestCase):
    def test_unsafe_sources_cannot_reach_publication(self):
        sources = [
            (
                "import subprocess\nvalue=input()\n"
                "subprocess.run('python -c ' + value, shell=True)\n",
                "CWE-78",
            ),
            (ROOT_SETUP + "def read(BASE_ROOT,name):\n return open(BASE_ROOT / name)\n", "CWE-22"),
        ]

        class Client:
            def __init__(self, source):
                self.source = source

            def get_pull_request(self, *args):
                return {"head": {"sha": "a" * 40, "repo": {"full_name": "org/repo"}}}

            def get_file(self, repository, path, ref):
                return {"decoded_content": self.source}

            def download_archive(self, *args):
                raise AssertionError("blocked repairs must not download or publish")

            def create_atomic_commit(self, *args):
                raise AssertionError("blocked repairs must not publish")

        for source, cwe in sources:
            with self.subTest(cwe=cwe):
                result = SafeFixer().create_fix_commits(
                    Client(source),
                    "org/repo",
                    7,
                    {"findings": [finding(source, cwe)]},
                    expected_source_sha="a" * 40,
                )
                self.assertIsNone(result["branch"])
                self.assertTrue(result["blocked_findings"])

    def test_planner_abstains_for_unproven_command_semantics(self):
        for command in (
            "python -c ",
            "/usr/bin/python3 -c ",
            "sh -c ",
            "cmd /c ",
            "powershell -Command ",
            "env python -c ",
            "custom-wrapper ",
            "/untrusted/echo ",
            "find ",
            "printf ",
        ):
            source = (
                "import subprocess\nvalue = input()\n"
                f"subprocess.run({command!r} + value, shell=True)\n"
            )
            with self.subTest(command=command):
                result = SafeFixer().apply(source, [finding(source, "CWE-78")], "app.py")
                self.assertEqual([], result["repairs"])
                self.assertEqual(source, result["content"])

    def test_subprocess_overrides_cannot_bypass_approved_utility(self):
        for override in ("executable='python'", "**options", "env=environment", "cwd=directory"):
            source = (
                "import subprocess\nvalue = input()\nsubprocess.run('echo ' + value, shell=True, "
                + override
                + ")\n"
            )
            with self.subTest(override=override):
                result = SafeFixer().apply(source, [finding(source, "CWE-78")], "app.py")
                self.assertEqual([], result["repairs"])

    def test_oracle_rejects_forged_interpreter_manifest(self):
        for executable in ("python", "/usr/bin/python3", "sh", "unknown-wrapper"):
            original = ast.parse("subprocess.run('echo ' + value, shell=True)").body[0].value
            source = (
                "import subprocess\nvalue = input()\n"
                f"subprocess.run([{executable!r}, '-c', value], shell=False)\n"
            )
            expected = ast.parse(source).body[-1].value
            manifest = [
                {
                    "path": "app.py",
                    "line": 3,
                    "cwe": "CWE-78",
                    "strategy": "argv-no-shell",
                    "original_ast": identity(original),
                    "expected_ast": identity(expected),
                    "oracle": {"fixed_executable": executable},
                }
            ]
            with self.subTest(executable=executable):
                self.assertFalse(
                    RepairVerifier().verify_contents({"app.py": source}, manifest)["passed"]
                )

    def test_path_root_requires_actual_immutable_binding(self):
        sources = [
            ROOT_SETUP + "def read(BASE_ROOT,name):\n return open(BASE_ROOT / name)\n",
            ROOT_SETUP
            + ("def read(name):\n BASE_ROOT=Path(input())\n return open(BASE_ROOT / name)\n"),
            ROOT_SETUP + "BASE_ROOT=Path(input())\nname=input()\nopen(BASE_ROOT / name)\n",
            ROOT_SETUP
            + (
                "def read(name):\n global BASE_ROOT\n BASE_ROOT=Path(input())\n"
                " return open(BASE_ROOT / name)\n"
            ),
            ROOT_SETUP + "def read(name,Path):\n return open(Path('/safe') / name)\n",
            ROOT_SETUP
            + (
                "def read(name):\n from config import ROOT as BASE_ROOT\n"
                " return open(BASE_ROOT / name)\n"
            ),
            ROOT_SETUP
            + (
                "def outer(BASE_ROOT):\n def read(name):\n"
                "  return open(BASE_ROOT / name)\n return read\n"
            ),
            ROOT_SETUP
            + (
                "try:\n pass\nexcept Exception as BASE_ROOT:\n pass\n"
                "name=input()\nopen(BASE_ROOT / name)\n"
            ),
            ROOT_SETUP
            + (
                "match input():\n case {'root': BASE_ROOT}:\n  pass\n"
                "name=input()\nopen(BASE_ROOT / name)\n"
            ),
            ROOT_SETUP + "del BASE_ROOT\nname=input()\nopen(BASE_ROOT / name)\n",
            (
                "# lima: trusted-path-root=config.UPLOAD_ROOT\n"
                "name=input()\nopen(config.UPLOAD_ROOT / name)\n"
            ),
        ]
        for source in sources:
            with self.subTest(source=source):
                result = SafeFixer().apply(source, [finding(source, "CWE-22")], "app.py")
                self.assertEqual([], result["repairs"])
                if "open(BASE_ROOT / name)" in source:
                    patched, manifest = old_path_patch(source)
                    self.assertFalse(
                        RepairVerifier().verify_contents(
                            {"app.py": patched},
                            manifest,
                        )["passed"]
                    )

    def test_oracle_independently_rejects_shadowed_root(self):
        source = ROOT_SETUP + "def read(BASE_ROOT,name):\n return open(BASE_ROOT / name)\n"
        patched, manifest = old_path_patch(source)
        self.assertFalse(RepairVerifier().verify_contents({"app.py": patched}, manifest)["passed"])

    def test_oracle_does_not_trust_manifest_selected_helper(self):
        source = ROOT_SETUP + "name=input()\nopen(BASE_ROOT / name)\n"
        malicious = HELPER.replace(
            "if candidate != root and root not in candidate.parents:", "if False:"
        )
        patched, manifest = old_path_patch(source, malicious)
        self.assertFalse(RepairVerifier().verify_contents({"app.py": patched}, manifest)["passed"])

    def test_helper_name_binding_collisions_are_rejected(self):
        for parameter in ("_lima_resolve_under_base", "_LIMAPath"):
            source = (
                "from pathlib import Path\nBASE_ROOT=Path('/safe')\ndef read(name,"
                + parameter
                + "):\n return open(BASE_ROOT / name)\n"
            )
            with self.subTest(parameter=parameter):
                result = SafeFixer().apply(source, [finding(source, "CWE-22")], "app.py")
                self.assertEqual([], result["repairs"])
                patched, manifest = old_path_patch(source)
                self.assertFalse(
                    RepairVerifier().verify_contents({"app.py": patched}, manifest)["passed"]
                )

    def test_proven_global_root_keeps_working_in_nested_function(self):
        source = ROOT_SETUP + "def read(name):\n return open(BASE_ROOT / name)\n"
        for name in ("BASE_ROOT", "root"):
            text = source.replace("BASE_ROOT", name)
            with self.subTest(root=name):
                result = SafeFixer().apply(text, [finding(text, "CWE-22")], "app.py")
                self.assertEqual(1, len(result["repairs"]))
                self.assertTrue(
                    RepairVerifier().verify_contents(
                        {"app.py": result["content"]},
                        result["repairs"],
                    )["passed"]
                )
