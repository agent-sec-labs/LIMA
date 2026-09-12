"""IP-0016 acceptance tests: identification rules, metrics, determinism, gaps.

Matrix traceability (Packet v1.1 §13): every test below maps to exactly one
matrix row -- shape identification (>=7), boundary (>=6), manifest layer (>=3),
code-role evidence (>=3), determinism (>=2), plus the frozen public API surface.
``lima.audit`` is imported in ``setUp`` so module absence (PI-DR4) fails each
case individually instead of hiding behind a module-level import error.
"""

from __future__ import annotations

import os
import time
import unittest
from typing import Any

from lima.contracts.common import SchemaVersion
from tests.audit.fixtures.repo_shapes import profile_kwargs, workspace_with

WORKSPACE_SKIP_REASONS = frozenset(
    {
        "ignored-directory",
        "symlink",
        "sensitive-config",
        "unsupported-extension",
        "unreadable",
        "file-size-limit",
        "file-limit",
        "total-size-limit",
        "binary",
        "non-utf8",
    }
)

PATH_CLASS_REASONS = frozenset(
    {"PATH_TEST_DIR", "PATH_DOCS_DIR", "PATH_EXAMPLE_DIR", "PATH_PATTERN_GENERATED"}
)
ROLE_REQUIRING_COMBINED_EVIDENCE = frozenset(
    {"generated", "test", "documentation", "example"}
)


class InventoryTestBase(unittest.TestCase):
    audit: Any

    def setUp(self) -> None:
        import lima.audit as audit

        self.audit = audit

    def build(self, workspace: Any, **overrides: object) -> Any:
        return self.audit.build_repository_profile(
            workspace, **profile_kwargs(**overrides)
        )

    def names(self, declarations: Any) -> list[str]:
        return [item.name for item in declarations]

    def gap_details(self, result: Any, gap_code: str) -> list[str]:
        return [
            gap.detail
            for gap in result.profile.coverage_gaps
            if gap.gap_code == gap_code
        ]


class RepositoryShapeTests(InventoryTestBase):
    """Packet §13 row: shape identification (>=7 cases)."""

    def test_application_shape_profile(self) -> None:
        files = {
            "pyproject.toml": (
                "[project]\nname = \"demo-app\"\nrequires-python = \">=3.11\"\n"
            ),
            "main.py": "from app import views\n\n\ndef main() -> None:\n    views.run()\n",
            "app/__init__.py": "",
            "app/views.py": "def run() -> None:\n    return None\n",
        }
        with workspace_with(files) as workspace:
            result = self.build(workspace)
        kinds = [kind.value for kind in result.profile.repository_kinds]
        self.assertIn("application", kinds)
        self.assertIn("Python", self.names(result.profile.languages))
        python = next(item for item in result.profile.languages if item.name == "Python")
        self.assertEqual(python.detection.value, "declared")
        self.assertEqual(python.source_artifact_ids, ("inventory",))
        self.assertEqual(result.profile.support_level.value, "supported")
        self.assertTrue(result.profile.execution_capability.buildable is False)
        self.assertTrue(result.profile.execution_capability.testable is False)
        self.assertFalse(result.profile.execution_capability.requires_network)
        self.assertFalse(result.profile.execution_capability.requires_services)
        self.assertFalse(result.profile.execution_capability.requires_gpu)
        self.assertFalse(result.profile.execution_capability.requires_external_credentials)
        self.assertIsNone(result.profile.component_path)
        entry_symbols = {entry.symbol for entry in result.profile.entrypoints}
        self.assertIn(None, entry_symbols)
        entry_paths = {entry.path for entry in result.profile.entrypoints}
        self.assertIn("main.py", entry_paths)
        for entry in result.profile.entrypoints:
            self.assertEqual(entry.source_artifact_ids, ("inventory",))

    def test_library_shape_profile(self) -> None:
        files = {
            "pyproject.toml": (
                "[project]\nname = \"demo-lib\"\nrequires-python = \">=3.11\"\n\n"
                "[build-system]\nrequires = [\"hatchling\"]\n"
                "build-backend = \"hatchling.build\"\n"
            ),
            "src/demo/__init__.py": "",
            "src/demo/core.py": "def core() -> int:\n    return 1\n",
        }
        with workspace_with(files) as workspace:
            result = self.build(workspace)
        kinds = [kind.value for kind in result.profile.repository_kinds]
        self.assertEqual(kinds, ["library"])
        self.assertEqual(self.names(result.profile.build_systems), ["hatchling"])
        self.assertEqual(self.names(result.profile.package_managers), [])
        self.assertEqual(result.profile.support_level.value, "supported")
        self.assertTrue(result.profile.execution_capability.buildable)
        self.assertFalse(result.profile.execution_capability.testable)

    def test_cli_shape_with_declared_scripts(self) -> None:
        files = {
            "pyproject.toml": (
                "[project]\nname = \"demo-cli\"\nrequires-python = \">=3.11\"\n\n"
                "[project.scripts]\ndemo = \"pkg.cli:main\"\n\n"
                "[build-system]\nrequires = [\"setuptools>=68\"]\n"
                "build-backend = \"setuptools.build_meta\"\n"
            ),
            "pkg/__init__.py": "",
            "pkg/cli.py": "def main() -> None:\n    return None\n",
        }
        with workspace_with(files) as workspace:
            result = self.build(workspace)
        kinds = [kind.value for kind in result.profile.repository_kinds]
        self.assertIn("cli", kinds)
        self.assertEqual(self.names(result.profile.build_systems), ["setuptools"])
        entries = {(entry.path, entry.symbol) for entry in result.profile.entrypoints}
        self.assertIn(("pkg/__init__.py", "demo"), entries)
        self.assertEqual(result.profile.support_level.value, "supported")

    def test_docs_only_shape_profile(self) -> None:
        files = {
            "README.md": "# Guide\n\nDocumentation only repository.\n",
            "docs/guide.md": "## Usage\n\nNothing to run.\n",
        }
        with workspace_with(files, extensions=(".md", ".rst")) as workspace:
            result = self.build(workspace)
        kinds = [kind.value for kind in result.profile.repository_kinds]
        self.assertEqual(kinds, ["docs_content"])
        self.assertEqual(self.names(result.profile.languages), [])
        self.assertEqual(result.profile.support_level.value, "unsupported")
        self.assertEqual(len(self.gap_details(result, "NO_LANGUAGES_DETECTED")), 1)
        self.assertEqual(result.profile.file_count, 2)
        self.assertEqual(result.profile.code_density_bp, 0)
        self.assertFalse(result.profile.execution_capability.buildable)
        self.assertFalse(result.profile.execution_capability.testable)

    def test_test_heavy_shape_roles_and_capability(self) -> None:
        files = {
            "pyproject.toml": (
                "[project]\nname = \"tested-lib\"\nrequires-python = \">=3.11\"\n\n"
                "[tool.pytest.ini_options]\ntestpaths = [\"tests\"]\n"
            ),
            "src/pkg/__init__.py": "",
            "src/pkg/core.py": "def core() -> int:\n    return 1\n",
            "tests/test_a.py": "import pytest\n\n\ndef test_a() -> None:\n    assert True\n",
            "tests/test_b.py": "def test_b() -> None:\n    assert True\n",
        }
        with workspace_with(files) as workspace:
            result = self.build(workspace)
        kinds = [kind.value for kind in result.profile.repository_kinds]
        self.assertIn("library", kinds)
        self.assertIn("pytest", self.names(result.profile.frameworks))
        self.assertTrue(result.profile.execution_capability.testable)
        test_roles = {
            assignment.path: assignment
            for assignment in result.profile.code_roles
            if assignment.role.value == "test"
        }
        self.assertEqual(set(test_roles), {"tests/test_a.py", "tests/test_b.py"})
        for assignment in test_roles.values():
            reasons = set(assignment.reason_codes)
            self.assertIn("PATH_TEST_DIR", reasons)
            self.assertIn("MANIFEST_TEST_CONFIG", reasons)
            self.assertEqual(assignment.source_artifact_ids, ("inventory",))

    def test_namespace_package_library_shape(self) -> None:
        files = {
            "pyproject.toml": (
                "[project]\nname = \"nspkg\"\nrequires-python = \">=3.11\"\n"
            ),
            "src/nspkg/mod.py": "VALUE = 1\n",
        }
        with workspace_with(files) as workspace:
            result = self.build(workspace)
        kinds = [kind.value for kind in result.profile.repository_kinds]
        self.assertEqual(kinds, ["library"])
        self.assertIn("Python", self.names(result.profile.languages))
        self.assertEqual(result.profile.support_level.value, "supported")

    def test_single_file_cli_shape(self) -> None:
        files = {"cli.py": "def main() -> None:\n    print(\"hello\")\n"}
        with workspace_with(files) as workspace:
            result = self.build(workspace)
        kinds = [kind.value for kind in result.profile.repository_kinds]
        self.assertIn("cli", kinds)
        self.assertIn("Python", self.names(result.profile.languages))
        self.assertEqual(result.profile.support_level.value, "partial")
        entries = {(entry.path, entry.symbol) for entry in result.profile.entrypoints}
        self.assertIn(("cli.py", None), entries)
        self.assertEqual(result.profile.code_density_bp, 10_000)
        self.assertEqual(self.names(result.profile.frameworks), [])


class BoundaryTests(InventoryTestBase):
    """Packet §13 row: boundary (>=6 cases)."""

    def test_empty_repository_profile(self) -> None:
        with workspace_with({}) as workspace:
            result = self.build(workspace)
        kinds = [kind.value for kind in result.profile.repository_kinds]
        self.assertEqual(kinds, ["unknown"])
        self.assertEqual(self.names(result.profile.languages), [])
        self.assertEqual(result.profile.support_level.value, "unsupported")
        self.assertEqual(len(self.gap_details(result, "NO_LANGUAGES_DETECTED")), 1)
        self.assertEqual(result.profile.file_count, 0)
        self.assertEqual(result.profile.total_bytes, 0)
        self.assertEqual(result.profile.max_file_bytes, 0)
        self.assertEqual(result.profile.entrypoints, ())
        capability = result.profile.execution_capability
        for flag in (
            "buildable",
            "testable",
            "requires_network",
            "requires_services",
            "requires_gpu",
            "requires_external_credentials",
        ):
            self.assertIs(getattr(capability, flag), False, flag)

    def test_go_only_repository_partial_support(self) -> None:
        files = {
            "main.go": "package main\n\nfunc main() {}\n",
            "go.mod": "module example.com/demo\n\ngo 1.22\n",
        }
        with workspace_with(files) as workspace:
            result = self.build(workspace)
        self.assertEqual(self.names(result.profile.languages), ["Go"])
        go = result.profile.languages[0]
        self.assertEqual(go.detection.value, "declared")
        self.assertEqual(self.names(result.profile.package_managers), ["go-modules"])
        self.assertEqual(result.profile.support_level.value, "partial")
        self.assertEqual(len(self.gap_details(result, "UNSUPPORTED_LANGUAGE")), 1)
        self.assertTrue(result.profile.execution_capability.buildable)

    def test_sensitive_config_skip_produces_gap(self) -> None:
        files = {
            "pyproject.toml": "[project]\nname = \"x\"\nrequires-python = \">=3.11\"\n",
            "lib.py": "VALUE = 1\n",
            ".env": "API_KEY=hunter2\n",
        }
        with workspace_with(files) as workspace:
            result = self.build(workspace)
        self.assertEqual(
            self.gap_details(result, "INVENTORY_SKIPPED"),
            ["reason=sensitive-config; count=1"],
        )
        self.assertEqual(result.profile.support_level.value, "supported")

    def test_hidden_python_files_are_inventoried(self) -> None:
        files = {
            "pyproject.toml": "[project]\nname = \"x\"\nrequires-python = \">=3.11\"\n",
            "app.py": "VALUE = 1\n",
            ".hidden.py": "VALUE = 2\n",
        }
        with workspace_with(files) as workspace:
            result = self.build(workspace)
        self.assertIn("Python", self.names(result.profile.languages))
        self.assertEqual(result.profile.file_count, 3)

    def test_binary_skip_ratio_and_gap(self) -> None:
        files = {
            "good.py": "VALUE = 1\n",
            "blob.py": b"\x00\x01\x02\x03binary\x00payload",
        }
        with workspace_with(files) as workspace:
            result = self.build(workspace)
        self.assertEqual(
            self.gap_details(result, "INVENTORY_SKIPPED"),
            ["reason=binary; count=1"],
        )
        self.assertEqual(result.profile.binary_ratio_bp, 5_000)
        self.assertIn("Python", self.names(result.profile.languages))

    def test_file_limit_budget_gap(self) -> None:
        files = {"a.py": "VALUE = 1\n", "b.py": "VALUE = 2\n"}
        with workspace_with(files, max_files=1) as workspace:
            result = self.build(workspace)
        self.assertEqual(
            self.gap_details(result, "BUDGET_EXHAUSTED"),
            ["reason=file-limit; count=1"],
        )
        self.assertEqual(result.profile.file_count, 1)


class ManifestLayerTests(InventoryTestBase):
    """Packet §13 row: manifest layer (>=3 cases)."""

    def test_manifest_toml_parse_error_gap(self) -> None:
        files = {
            "pyproject.toml": "this is [not valid toml {{{",
            "code.py": "VALUE = 1\n",
        }
        with workspace_with(files) as workspace:
            result = self.build(workspace)
        details = self.gap_details(result, "MANIFEST_PARSE_ERROR")
        self.assertEqual(len(details), 1)
        self.assertIn("pyproject.toml", details[0])
        self.assertIn("TOMLDecodeError", details[0])
        self.assertEqual(result.profile.support_level.value, "partial")
        self.assertIn("Python", self.names(result.profile.languages))

    def test_setup_py_syntax_error_gap(self) -> None:
        files = {
            "setup.py": "def broken(:\n    pass\n",
            "pkg/__init__.py": "",
        }
        with workspace_with(files) as workspace:
            result = self.build(workspace)
        details = self.gap_details(result, "MANIFEST_PARSE_ERROR")
        self.assertEqual(len(details), 1)
        self.assertIn("setup.py", details[0])
        self.assertIn("SyntaxError", details[0])
        self.assertIn("Python", self.names(result.profile.languages))

    def test_manifest_single_file_budget_gap(self) -> None:
        files = {
            "pyproject.toml": (
                "[project]\nname = \"budgeted\"\nrequires-python = \">=3.11\"\n\n"
                "[build-system]\nrequires = [\"setuptools>=68\"]\n"
                "build-backend = \"setuptools.build_meta\"\n"
            ),
            "code.py": "VALUE = 1\n",
        }
        budgets = self.audit.ProfileBudgets(manifest_max_bytes=32)
        options = self.audit.ProfileInventoryOptions(budgets=budgets)
        with workspace_with(files) as workspace:
            result = self.build(workspace, options=options)
        details = self.gap_details(result, "BUDGET_EXHAUSTED")
        self.assertEqual(len(details), 1)
        self.assertIn("pyproject.toml", details[0])
        self.assertEqual(self.gap_details(result, "MANIFEST_PARSE_ERROR"), [])
        self.assertEqual(self.names(result.profile.build_systems), [])


class CodeRoleEvidenceTests(InventoryTestBase):
    """Packet §13 row: code-role evidence (>=3 cases) plus the D5 invariant."""

    def test_generated_role_combined_evidence(self) -> None:
        files = {
            "pkg/__init__.py": "",
            "pkg/code.py": "from pkg import helpers\n\nVALUE = 1\n",
            "pkg/helpers.py": "VALUE = 2\n",
            "pkg/proto_pb2.py": "# generated code\nVALUE = 3\n",
        }
        with workspace_with(files) as workspace:
            result = self.build(workspace)
        generated = [
            assignment
            for assignment in result.profile.code_roles
            if assignment.role.value == "generated"
        ]
        self.assertEqual({assignment.path for assignment in generated}, {"pkg/proto_pb2.py"})
        for assignment in generated:
            reasons = set(assignment.reason_codes)
            self.assertIn("PATH_PATTERN_GENERATED", reasons)
            self.assertIn("NOT_IMPORTED_BY_PROD", reasons)
        self.assertGreater(result.profile.generated_ratio_bp, 0)

    def test_single_evidence_no_role_assignment(self) -> None:
        # pkg/code.py imports pkg.proto_pb2, so the generated-pattern file has
        # only the path-class evidence PATH_PATTERN_GENERATED: one evidence
        # class must not produce a role assignment (Packet D5).
        files = {
            "pkg/code.py": "import pkg.proto_pb2\n\nVALUE = pkg.proto_pb2.VALUE\n",
            "pkg/proto_pb2.py": "# generated code\nVALUE = 1\n",
        }
        with workspace_with(files) as workspace:
            result = self.build(workspace)
        generated = [
            assignment
            for assignment in result.profile.code_roles
            if assignment.role.value == "generated"
        ]
        self.assertEqual(generated, [])
        self.assertEqual(result.profile.generated_ratio_bp, 0)

    def test_combined_evidence_invariant_and_ordering(self) -> None:
        files = {
            "pyproject.toml": (
                "[project]\nname = \"tested-lib\"\nrequires-python = \">=3.11\"\n\n"
                "[tool.pytest.ini_options]\ntestpaths = [\"tests\"]\n"
            ),
            "src/pkg/__init__.py": "",
            "src/pkg/core.py": "def core() -> int:\n    return 1\n",
            "tests/test_a.py": "def test_a() -> None:\n    assert True\n",
            "pkg2/proto_pb2.py": "# generated code\n",
        }
        with workspace_with(files) as workspace:
            result = self.build(workspace)
        keys = [
            (assignment.role.value, assignment.path)
            for assignment in result.profile.code_roles
        ]
        self.assertEqual(keys, sorted(keys))
        for assignment in result.profile.code_roles:
            if assignment.role.value not in ROLE_REQUIRING_COMBINED_EVIDENCE:
                continue
            reasons = set(assignment.reason_codes)
            self.assertTrue(
                reasons & PATH_CLASS_REASONS and reasons - PATH_CLASS_REASONS,
                f"path + non-path evidence required for {assignment.path}",
            )
            self.assertGreaterEqual(len(reasons), 2)


class DeterminismTests(InventoryTestBase):
    """Packet §13 row: determinism (>=2 cases)."""

    FILES = {
        "pyproject.toml": (
            "[project]\nname = \"det-lib\"\nrequires-python = \">=3.11\"\n\n"
            "[build-system]\nrequires = [\"setuptools>=68\"]\n"
            "build-backend = \"setuptools.build_meta\"\n"
        ),
        "src/pkg/__init__.py": "",
        "src/pkg/core.py": "def core() -> int:\n    return 1\n",
        "tests/test_core.py": "def test_core() -> None:\n    assert True\n",
    }

    def test_deterministic_rebuild_identical_payload(self) -> None:
        with workspace_with(self.FILES) as workspace:
            first = self.build(workspace)
            second = self.build(workspace)
        self.assertEqual(first.profile.to_dict(), second.profile.to_dict())
        self.assertEqual(first.envelope.content_digest, second.envelope.content_digest)
        self.assertEqual(first.provenance_anchor_ids, ("inventory",))
        self.assertEqual(second.provenance_anchor_ids, ("inventory",))

    def test_mtime_independence(self) -> None:
        with workspace_with(self.FILES) as workspace:
            newer = time.time() + 10_000
            for item in workspace.root.rglob("*"):
                if item.is_file():
                    os.utime(item, (newer, newer))
            before = self.build(workspace)
        with workspace_with(self.FILES) as workspace:
            older = time.time() - 10_000
            for item in workspace.root.rglob("*"):
                if item.is_file():
                    os.utime(item, (older, older))
            after = self.build(workspace)
        self.assertEqual(before.profile.to_dict(), after.profile.to_dict())


class PublicApiSurfaceTests(InventoryTestBase):
    """Packet §6 D2 frozen constants, budgets, and option defaults."""

    def test_frozen_constants_and_gap_vocabulary(self) -> None:
        audit = self.audit
        self.assertEqual(audit.PROFILE_PROVENANCE_ANCHOR, "inventory")
        self.assertEqual(audit.GAP_UNSUPPORTED_LANGUAGE, "UNSUPPORTED_LANGUAGE")
        self.assertEqual(audit.GAP_BUDGET_EXHAUSTED, "BUDGET_EXHAUSTED")
        self.assertEqual(audit.GAP_MANIFEST_PARSE_ERROR, "MANIFEST_PARSE_ERROR")
        self.assertEqual(audit.GAP_NO_LANGUAGES_DETECTED, "NO_LANGUAGES_DETECTED")
        self.assertEqual(audit.GAP_INVENTORY_SKIPPED, "INVENTORY_SKIPPED")
        mapping = audit.SKIP_REASON_TO_GAP_DETAIL
        self.assertTrue(WORKSPACE_SKIP_REASONS.issubset(mapping.keys()))
        for reason, detail in mapping.items():
            self.assertIsInstance(reason, str)
            self.assertIsInstance(detail, str)
            self.assertTrue(detail)

    def test_profile_budgets_defaults_and_validation(self) -> None:
        audit = self.audit
        budgets = audit.ProfileBudgets()
        self.assertEqual(budgets.manifest_max_bytes, 262_144)
        self.assertEqual(budgets.max_manifest_files, 64)
        with self.assertRaises(ValueError):
            audit.ProfileBudgets(manifest_max_bytes=0)
        with self.assertRaises(ValueError):
            audit.ProfileBudgets(max_manifest_files=-1)
        options = audit.ProfileInventoryOptions()
        self.assertEqual(options.schema_version, SchemaVersion(4, 0))
        self.assertEqual(options.budgets.manifest_max_bytes, 262_144)
        result_fields = audit.ProfileBuildResult.__dataclass_fields__
        self.assertEqual(
            set(result_fields), {"profile", "envelope", "provenance_anchor_ids"}
        )


if __name__ == "__main__":
    unittest.main()
