"""Import isolation tests for the execution module (IP-0008 packet section 18.3)."""

import re
import subprocess
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
EXECUTION_MODULE = REPO_ROOT / "lima" / "contracts" / "execution.py"

FROZEN_MODULE_API = frozenset(
    {
        "PLAN_SCHEMA_NAME",
        "RUN_MANIFEST_SCHEMA_NAME",
        "PlanMode",
        "PlanStageType",
        "ReferenceKind",
        "ArtifactLink",
        "Plan",
        "RunManifest",
        "decode_plan_payload",
        "encode_plan_payload",
        "decode_plan_envelope",
        "encode_plan_envelope",
        "decode_run_manifest_payload",
        "encode_run_manifest_payload",
        "decode_run_manifest_envelope",
        "encode_run_manifest_envelope",
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

FORBIDDEN_MODULE_ROOTS = frozenset(
    {
        "socket",
        "ssl",
        "urllib",
        "http",
        "requests",
        "ftplib",
        "psycopg",
        "sqlite3",
        "redis",
        "docker",
        "openai",
        "anthropic",
    }
)

ALLOWED_LIMA_MODULES = frozenset(
    {
        "lima",
        "lima.contracts",
        "lima.contracts.errors",
        "lima.contracts.codec",
        "lima.contracts.common",
        "lima.contracts.execution",
    }
)


class ExecutionImportIsolationTests(unittest.TestCase):
    def test_module_public_api_matches_frozen_symbol_set(self):
        import lima.contracts.execution as execution

        self.assertEqual(frozenset(execution.__all__), FROZEN_MODULE_API)
        for name in sorted(FROZEN_MODULE_API):
            self.assertTrue(hasattr(execution, name), name)
        self.assertEqual(execution.PLAN_SCHEMA_NAME, "lima.plan")
        self.assertEqual(execution.RUN_MANIFEST_SCHEMA_NAME, "lima.run-manifest")

    def test_clean_process_import_has_no_db_network_docker_llm_service_or_legacy_models(self):
        script = (
            "import sys\n"
            "import lima.contracts.execution\n"
            f"forbidden = {sorted(FORBIDDEN_MODULE_ROOTS)!r}\n"
            "loaded = sorted(sys.modules)\n"
            "violations = [n for n in loaded if n.split('.')[0] in forbidden]\n"
            "lima_loaded = [n for n in loaded if n == 'lima' or n.startswith('lima.')]\n"
            "print(' '.join(violations))\n"
            "print(' '.join(lima_loaded))\n"
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
        violations_line, lima_line = result.stdout.splitlines()
        self.assertEqual(violations_line, "")
        lima_modules = set(lima_line.split())
        self.assertTrue(lima_modules <= ALLOWED_LIMA_MODULES, lima_line)
        self.assertIn("lima.contracts.execution", lima_modules)
        self.assertNotIn("lima.contracts.evidence", lima_modules)
        self.assertNotIn("lima.contracts.profile", lima_modules)
        self.assertNotIn("lima.contracts.aep", lima_modules)
        self.assertNotIn("lima.contracts.vep", lima_modules)
        self.assertNotIn("lima.contracts.rvr", lima_modules)
        self.assertNotIn("lima.contracts.workflow", lima_modules)

    def test_module_only_uses_allowed_imports(self):
        statement_pattern = re.compile(
            r"^[ \t]*(?:from[ \t]+([.\w]+)[ \t]+import|import[ \t]+([\w., \t]+))",
            re.MULTILINE,
        )
        source = EXECUTION_MODULE.read_text(encoding="utf-8")
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
            f"execution.py uses imports outside the frozen allowlist: {sorted(unexplained)}",
        )

    def test_import_does_not_change_lima_contracts_top_level_public_api(self):
        import lima.contracts as contracts

        self.assertEqual(list(contracts.__all__), IP_0001_TOP_LEVEL_API)
        before = {name for name in vars(contracts) if not name.startswith("_")}
        import lima.contracts.execution  # noqa: F401 -- import side effect under test

        after = {name for name in vars(contracts) if not name.startswith("_")}
        self.assertEqual(before, after)
        self.assertEqual(list(contracts.__all__), IP_0001_TOP_LEVEL_API)


if __name__ == "__main__":
    unittest.main()
