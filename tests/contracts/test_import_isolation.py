"""Import isolation tests: frozen public API and side-effect-free imports."""

import json
import re
import subprocess
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
CONTRACTS_PACKAGE = REPO_ROOT / "lima" / "contracts"

FROZEN_PUBLIC_API = frozenset(
    {
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
    }
)

ALLOWED_PRODUCTION_ROOTS = frozenset(
    {
        "collections",
        "copy",
        "dataclasses",
        "datetime",
        "enum",
        "hashlib",
        "hmac",
        "json",
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
    }
)

CONTRACT_MODULE_FILES = ("__init__.py", "errors.py", "codec.py", "common.py")


class ContractImportIsolationTests(unittest.TestCase):
    def test_public_api_matches_frozen_symbol_set(self):
        import lima.contracts as contracts

        self.assertEqual(frozenset(contracts.__all__), FROZEN_PUBLIC_API)
        for name in sorted(FROZEN_PUBLIC_API):
            self.assertTrue(hasattr(contracts, name), name)
        init_source = (CONTRACTS_PACKAGE / "__init__.py").read_text(encoding="utf-8")
        self.assertIsNone(
            re.search(r"^\s*(?:def|class)\s+\w+", init_source, re.MULTILINE),
            "__init__.py must only re-export, never define implementation",
        )

    def test_clean_process_import_has_no_db_network_docker_or_service_modules(self):
        script = (
            "import json\n"
            "import sys\n"
            "\n"
            "import lima.contracts\n"
            "\n"
            f"forbidden = {sorted(FORBIDDEN_MODULE_ROOTS)!r}\n"
            "loaded = sorted(sys.modules)\n"
            "violations = [name for name in loaded if name.split('.')[0] in forbidden]\n"
            "lima_loaded = [name for name in loaded if name == 'lima' or"
            " name.startswith('lima.')]\n"
            "print(json.dumps({'violations': violations, 'lima': lima_loaded}))\n"
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
        payload = json.loads(result.stdout)
        self.assertEqual(payload["violations"], [])
        self.assertIn("lima.contracts", payload["lima"])
        self.assertTrue(set(payload["lima"]) <= ALLOWED_LIMA_MODULES, payload["lima"])

    def test_contract_modules_only_use_allowed_imports(self):
        statement_pattern = re.compile(
            r"^[ \t]*(?:from[ \t]+([.\w]+)[ \t]+import|import[ \t]+([\w., \t]+))",
            re.MULTILINE,
        )
        for module_file in CONTRACT_MODULE_FILES:
            source = (CONTRACTS_PACKAGE / module_file).read_text(encoding="utf-8")
            roots: set[str] = set()
            for match in statement_pattern.finditer(source):
                if match.group(1) is not None:
                    roots.add(match.group(1).split(".")[0].lstrip("."))
                else:
                    for clause in match.group(2).split(","):
                        roots.add(clause.strip().split(" as ")[0].split(".")[0])
            roots.discard("")
            unexplained = roots - ALLOWED_PRODUCTION_ROOTS - {"lima"}
            self.assertFalse(
                unexplained,
                f"{module_file} uses imports outside the frozen allowlist: {sorted(unexplained)}",
            )


if __name__ == "__main__":
    unittest.main()
