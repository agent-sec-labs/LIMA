"""IP-0016 acceptance tests: security negatives for the inventory layer.

Matrix traceability (Packet v1.1 §13): security-negative row (>=4 cases) --
no execution, no import of target code, no host-path/content leakage, and a
static source scan of the module under test.
"""

from __future__ import annotations

import re
import unittest
from pathlib import Path
from typing import Any

from lima.contracts.profile import encode_profile_envelope
from tests.audit.fixtures.repo_shapes import profile_kwargs, workspace_with

MALICIOUS_SETUP_PY = (
    "import os\n"
    "\n"
    "target = os.path.join(\n"
    "    os.path.dirname(os.path.abspath(__file__))\n"
    "    if \"__file__\" in dir()\n"
    "    else os.getcwd(),\n"
    "    \"PWNED_SETUP_MARKER.txt\",\n"
    ")\n"
    "with open(target, \"w\", encoding=\"utf-8\") as handle:\n"
    "    handle.write(\"executed\")\n"
)

SIDE_EFFECT_MODULE = (
    "import os\n"
    "\n"
    "with open(\"PWNED_IMPORT_MARKER.txt\", \"w\", encoding=\"utf-8\") as handle:\n"
    "    handle.write(\"imported\")\n"

    "VALUE = 1\n"
)

LEAK_PROBE_SOURCE_MARKER = "LEAK_PROBE_SOURCE_9f3ac2"
LEAK_PROBE_ENV_MARKER = "leak-probe-env-value-7c31"


class SecurityTestBase(unittest.TestCase):
    audit: Any

    def setUp(self) -> None:
        import lima.audit as audit

        self.audit = audit

    def build(self, workspace: Any, **overrides: object) -> Any:
        return self.audit.build_repository_profile(
            workspace, **profile_kwargs(**overrides)
        )


class NoExecutionTests(SecurityTestBase):
    def test_malicious_setup_py_never_executed(self) -> None:
        files = {
            "setup.py": MALICIOUS_SETUP_PY,
            "pkg/__init__.py": "",
            "pkg/code.py": "VALUE = 1\n",
        }
        with workspace_with(files) as workspace:
            result = self.build(workspace)
            markers = [
                workspace.root / "PWNED_SETUP_MARKER.txt",
                Path.cwd() / "PWNED_SETUP_MARKER.txt",
            ]
            for marker in markers:
                self.assertFalse(marker.exists(), str(marker))
        self.assertIn("Python", [item.name for item in result.profile.languages])

    def test_import_side_effect_module_never_imported(self) -> None:
        files = {
            "evil.py": SIDE_EFFECT_MODULE,
            "normal.py": "VALUE = 2\n",
        }
        with workspace_with(files) as workspace:
            result = self.build(workspace)
            markers = [
                workspace.root / "PWNED_IMPORT_MARKER.txt",
                Path.cwd() / "PWNED_IMPORT_MARKER.txt",
            ]
            for marker in markers:
                self.assertFalse(marker.exists(), str(marker))
        self.assertIn("Python", [item.name for item in result.profile.languages])


class LeakageTests(SecurityTestBase):
    def test_payload_leaks_no_host_paths_or_source_content(self) -> None:
        files = {
            "pyproject.toml": (
                "[project]\nname = \"leaky\"\nrequires-python = \">=3.11\"\n"
            ),
            "app.py": f"{LEAK_PROBE_SOURCE_MARKER} = \"{LEAK_PROBE_ENV_MARKER}\"\n",
            ".env": f"API_KEY={LEAK_PROBE_ENV_MARKER}\n",
        }
        with workspace_with(files) as workspace:
            result = self.build(workspace)
            root = str(workspace.root)
            raw = encode_profile_envelope(result.envelope, result.profile).decode(
                "utf-8"
            )
        self.assertNotIn(root, raw)
        drive = root.split(":", 1)[0] + ":" if ":" in root else None
        if drive is not None:
            self.assertIsNone(re.search(re.escape(drive) + r"(\\\\|/)", raw))
        self.assertNotIn(LEAK_PROBE_SOURCE_MARKER, raw)
        self.assertNotIn(LEAK_PROBE_ENV_MARKER, raw)
        self.assertNotIn('"paths"', raw)
        payload_paths = [
            entry.path
            for entry in result.profile.entrypoints
        ] + [assignment.path for assignment in result.profile.code_roles]
        for path in payload_paths:
            self.assertFalse(path.startswith("/") or "\\" in path or ":" in path)


class StaticSourceTests(SecurityTestBase):
    def test_module_source_forbidden_imports_and_dynamic_execution(self) -> None:
        import inspect

        source = inspect.getsource(self.audit.inventory)
        for token in (
            "subprocess",
            "socket",
            "urllib",
            "requests",
            "importlib",
            "http.client",
        ):
            self.assertNotIn(token, source)
        self.assertIsNone(re.search(r"\bexec\s*\(", source))
        self.assertIsNone(re.search(r"\beval\s*\(", source))


if __name__ == "__main__":
    unittest.main()
