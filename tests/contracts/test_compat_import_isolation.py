"""Import isolation tests for the legacy adapter module (IP-0013 PR4, AC-04).

Packet reference: ``docs/LIMA_Implementation_Packet_IP-0013_PR4_Legacy_Adapter.md``
sections 7/D7 at main ``3e04a045``: compat must not import profile/aep/vep/rvr/
workflow/execution/manifests nor any non-contracts ``lima`` module besides
``lima.models``, and importing any of the thirteen existing contract modules
must never load compat.
"""

import re
import subprocess
import sys
import unittest
from pathlib import Path

import lima.contracts.compat as compat_module  # noqa: F401 -- RED anchor

REPO_ROOT = Path(__file__).resolve().parents[2]
COMPAT_MODULE = REPO_ROOT / "lima" / "contracts" / "compat.py"

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

THIRTEEN_CONTRACT_MODULES = [
    "lima.contracts",
    "lima.contracts.aep",
    "lima.contracts.codec",
    "lima.contracts.common",
    "lima.contracts.errors",
    "lima.contracts.evidence",
    "lima.contracts.execution",
    "lima.contracts.manifests",
    "lima.contracts.profile",
    "lima.contracts.rvr",
    "lima.contracts.summary",
    "lima.contracts.vep",
    "lima.contracts.workflow",
]

FORBIDDEN_DOMAIN_MODULES = [
    "lima.contracts.profile",
    "lima.contracts.aep",
    "lima.contracts.vep",
    "lima.contracts.rvr",
    "lima.contracts.workflow",
    "lima.contracts.execution",
    "lima.contracts.manifests",
]

ALLOWED_LIMA_MODULES = frozenset(
    {
        "lima",
        "lima.models",
        "lima.contracts",
        "lima.contracts.errors",
        "lima.contracts.codec",
        "lima.contracts.common",
        "lima.contracts.evidence",
        "lima.contracts.summary",
        "lima.contracts.compat",
    }
)

FORBIDDEN_IMPORT_ROOTS = frozenset(
    {
        "profile",
        "aep",
        "vep",
        "rvr",
        "workflow",
        "execution",
        "manifests",
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


def _run_python(script: str) -> subprocess.CompletedProcess[str]:
    # noqa justification: fixed interpreter with an inline constant script;
    # no untrusted input reaches the command line.
    return subprocess.run(  # noqa: S603
        [sys.executable, "-c", script],
        cwd=str(REPO_ROOT),
        capture_output=True,
        text=True,
        check=False,
        timeout=60,
    )


class CompatImportIsolationTests(unittest.TestCase):
    """Dependency isolation (Packet D1/D7; category lower bound 4)."""

    def test_clean_process_import_of_compat_loads_no_forbidden_domain_modules(self):
        script = (
            "import sys\n"
            "import lima.contracts.compat\n"
            "lima_loaded = [n for n in sorted(sys.modules)"
            " if n == 'lima' or n.startswith('lima.')]\n"
            "print(' '.join(lima_loaded))\n"
        )
        result = _run_python(script)
        self.assertEqual(result.returncode, 0, result.stderr)
        loaded = set(result.stdout.split())
        self.assertTrue(loaded <= ALLOWED_LIMA_MODULES, sorted(loaded))
        self.assertIn("lima.contracts.compat", loaded)
        for module in FORBIDDEN_DOMAIN_MODULES:
            self.assertNotIn(module, loaded)

    def test_reverse_import_of_thirteen_modules_never_loads_compat(self):
        for module in THIRTEEN_CONTRACT_MODULES:
            with self.subTest(module=module):
                script = (
                    "import sys\n"
                    f"import {module}\n"
                    "print('YES' if 'lima.contracts.compat' in sys.modules"
                    " else 'NO')\n"
                )
                result = _run_python(script)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout.strip(), "NO")

    def test_compat_source_contains_no_forbidden_imports(self):
        statement_pattern = re.compile(
            r"^[ \t]*(?:from[ \t]+([.\w]+)[ \t]+import|import[ \t]+([\w., \t]+))",
            re.MULTILINE,
        )
        source = COMPAT_MODULE.read_text(encoding="utf-8")
        roots: set[str] = set()
        for match in statement_pattern.finditer(source):
            if match.group(1) is not None:
                roots.add(match.group(1).split(".")[0].lstrip("."))
            else:
                for clause in match.group(2).split(","):
                    roots.add(clause.strip().split(" as ")[0].split(".")[0])
        roots.discard("")
        violations = roots & FORBIDDEN_IMPORT_ROOTS
        self.assertFalse(
            violations,
            f"compat.py uses forbidden imports: {sorted(violations)}",
        )

    def test_importing_compat_keeps_contracts_top_level_api_frozen(self):
        import lima.contracts as contracts

        self.assertEqual(list(contracts.__all__), IP_0001_TOP_LEVEL_API)
        before = {name for name in vars(contracts) if not name.startswith("_")}
        self.assertIn("LEGACY_REASON_CODE", vars(compat_module))

        after = {name for name in vars(contracts) if not name.startswith("_")}
        self.assertEqual(before, after)
        self.assertEqual(list(contracts.__all__), IP_0001_TOP_LEVEL_API)


if __name__ == "__main__":
    unittest.main()
