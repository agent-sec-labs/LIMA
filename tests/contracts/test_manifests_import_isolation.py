"""Import isolation tests for the manifests module (IP-0012 packet sections 7, 13).

Dependency direction is frozen: manifests -> {codec, common, errors} only.
Importing manifests must not load any domain module, and importing any of the
twelve existing contract modules must not load manifests (twelve-module
reverse assertion). The contracts package top-level public API (IP-0001
18-symbol frozen face) must remain unchanged.
"""

import re
import subprocess
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
MANIFESTS_MODULE = REPO_ROOT / "lima" / "contracts" / "manifests.py"

FROZEN_MODULE_API = frozenset(
    {
        "TASK_MANIFEST_SCHEMA_NAME",
        "TOOL_BUNDLE_SCHEMA_NAME",
        "DEPENDENCY_MANIFEST_SCHEMA_NAME",
        "SANDBOX_RUN_SCHEMA_NAME",
        "ManifestReferenceKind",
        "OracleKind",
        "NetworkPolicy",
        "ManifestLink",
        "TaskManifest",
        "ToolBundle",
        "DependencyManifest",
        "SandboxRun",
        "decode_task_manifest_payload",
        "encode_task_manifest_payload",
        "decode_task_manifest_envelope",
        "encode_task_manifest_envelope",
        "decode_tool_bundle_payload",
        "encode_tool_bundle_payload",
        "decode_tool_bundle_envelope",
        "encode_tool_bundle_envelope",
        "decode_dependency_manifest_payload",
        "encode_dependency_manifest_payload",
        "decode_dependency_manifest_envelope",
        "encode_dependency_manifest_envelope",
        "decode_sandbox_run_payload",
        "encode_sandbox_run_payload",
        "decode_sandbox_run_envelope",
        "encode_sandbox_run_envelope",
    }
)

IP_0001_TOP_LEVEL_API = [
    "CURRENT_SCHEMA_MAJOR",
    "CURRENT_SCHEMA_MINOR",
    "DEFAULT_LIMITS",
    "JSONValue",
    "ContractErrorCode",
    "ContractError",
    "ContractLimits",
    "SchemaVersion",
    "ArtifactClassification",
    "RetentionClass",
    "ArtifactReference",
    "ArtifactBlobReference",
    "ArtifactEnvelope",
    "canonical_decode",
    "canonical_encode",
    "compute_content_digest",
    "decode_envelope",
    "encode_envelope",
]

ALLOWED_MODULE_ROOTS = frozenset(
    {
        "collections",
        "copy",
        "dataclasses",
        "enum",
        "hmac",
        "re",
        "typing",
        "unicodedata",
    }
)

ALLOWED_LIMA_MODULES = frozenset(
    {
        "lima",
        "lima.contracts",
        "lima.contracts.errors",
        "lima.contracts.codec",
        "lima.contracts.common",
        "lima.contracts.manifests",
    }
)

# The twelve existing contract modules (codec/common/errors/evidence/profile/
# aep/vep/rvr/workflow/execution/summary/__init__ represented by the package).
EXISTING_TWELVE_MODULES = [
    "lima.contracts",
    "lima.contracts.codec",
    "lima.contracts.common",
    "lima.contracts.errors",
    "lima.contracts.evidence",
    "lima.contracts.profile",
    "lima.contracts.aep",
    "lima.contracts.vep",
    "lima.contracts.rvr",
    "lima.contracts.workflow",
    "lima.contracts.execution",
    "lima.contracts.summary",
]

DOMAIN_MODULES = [
    "lima.contracts.evidence",
    "lima.contracts.profile",
    "lima.contracts.aep",
    "lima.contracts.vep",
    "lima.contracts.rvr",
    "lima.contracts.workflow",
    "lima.contracts.execution",
    "lima.contracts.summary",
]


class ManifestsImportIsolationTests(unittest.TestCase):
    def test_module_public_api_matches_frozen_symbol_set(self):
        import lima.contracts.manifests as manifests

        self.assertEqual(frozenset(manifests.__all__), FROZEN_MODULE_API)
        for name in sorted(FROZEN_MODULE_API):
            self.assertTrue(hasattr(manifests, name), name)
        self.assertEqual(manifests.TASK_MANIFEST_SCHEMA_NAME, "lima.task-manifest")
        self.assertEqual(manifests.TOOL_BUNDLE_SCHEMA_NAME, "lima.tool-bundle")
        self.assertEqual(
            manifests.DEPENDENCY_MANIFEST_SCHEMA_NAME, "lima.dependency-manifest"
        )
        self.assertEqual(manifests.SANDBOX_RUN_SCHEMA_NAME, "lima.sandbox-run")

    def test_clean_process_import_loads_no_domain_modules(self):
        script = (
            "import sys\n"
            "import lima.contracts.manifests\n"
            "loaded = sorted(sys.modules)\n"
            "print(' '.join(loaded))\n"
        )
        # noqa justification: fixed interpreter with an inline constant script;
        # no untrusted input reaches the command line.
        result = subprocess.run(  # noqa: S603
            [sys.executable, "-c", script],
            cwd=str(REPO_ROOT),
            capture_output=True,
            text=True,
            check=False,
            timeout=60,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        loaded = set(result.stdout.split())
        lima_loaded = {n for n in loaded if n == "lima" or n.startswith("lima.")}
        self.assertTrue(lima_loaded <= ALLOWED_LIMA_MODULES, sorted(lima_loaded))
        self.assertIn("lima.contracts.manifests", lima_loaded)
        for module in DOMAIN_MODULES:
            self.assertNotIn(module, lima_loaded)

    def test_in_process_import_leaves_domain_modules_unimported(self):
        import lima.contracts.manifests  # noqa: F401 -- import side effect under test

        for module in DOMAIN_MODULES:
            self.assertNotIn(module, sys.modules)

    def test_existing_twelve_modules_do_not_import_manifests(self):
        # Twelve-module reverse assertion: after importing each existing
        # contract module in a fresh interpreter, manifests must be absent.
        for module in EXISTING_TWELVE_MODULES:
            script = (
                "import sys\n"
                f"import {module}\n"
                "print('PRESENT' if 'lima.contracts.manifests' in sys.modules"
                " else 'ABSENT')\n"
            )
            with self.subTest(module=module):
                result = subprocess.run(  # noqa: S603
                    [sys.executable, "-c", script],
                    cwd=str(REPO_ROOT),
                    capture_output=True,
                    text=True,
                    check=False,
                    timeout=60,
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout.strip(), "ABSENT")

    def test_module_only_uses_allowed_imports(self):
        statement_pattern = re.compile(
            r"^[ \t]*(?:from[ \t]+([.\w]+)[ \t]+import|import[ \t]+([\w., \t]+))",
            re.MULTILINE,
        )
        source = MANIFESTS_MODULE.read_text(encoding="utf-8")
        roots: set[str] = set()
        for match in statement_pattern.finditer(source):
            if match.group(1) is not None:
                roots.add(match.group(1).split(".")[0].lstrip("."))
            else:
                for clause in match.group(2).split(","):
                    roots.add(clause.strip().split(" as ")[0].split(".")[0])
        roots.discard("")
        unexplained = roots - ALLOWED_MODULE_ROOTS - {"lima"}
        self.assertFalse(
            unexplained,
            f"manifests.py uses imports outside the frozen allowlist: {sorted(unexplained)}",
        )

    def test_import_does_not_change_lima_contracts_top_level_public_api(self):
        import lima.contracts as contracts

        self.assertEqual(list(contracts.__all__), IP_0001_TOP_LEVEL_API)
        before = {name for name in vars(contracts) if not name.startswith("_")}
        import lima.contracts.manifests  # noqa: F401 -- import side effect under test

        after = {name for name in vars(contracts) if not name.startswith("_")}
        self.assertEqual(before, after)
        self.assertEqual(list(contracts.__all__), IP_0001_TOP_LEVEL_API)


if __name__ == "__main__":
    unittest.main()
