"""Limited non-LF generality validation for the production scanner path.

Scope (the 2026-10-02 Maintainer-authorized #57 close-out handoff,
section 2): two small offline fixtures that are NOT LlamaFactory, both
walking the same existing production ``RepositoryScanner`` path under the
explicit offline scanner configuration -- no scanner copy, no LF
disguise, no rule modification:

- ``pylib-mini``: a Python-library-shaped sample with explicit positives
  (dynamic code execution, shell=True, a hardcoded secret) and their safe
  neighbors (explicit parser, argument array with shell=False, name-only
  references);
- ``docs-tests-mini``: a docs/test-heavy sample with no positives -- a
  measured zero, explicitly distinct from a scan failure.

**Honest detection-quality face (the 2026-10-02 fake-green correction).**
The raw observation on pylib-mini is **4 candidates, not 3**: the rule
also fires on the safe-neighbor line ``SERVICE_PASSWORD_ENV =
"SERVICE_PASSWORD"`` (``pylib/config.py:2``, SEC-HARDCODED-SECRET).  The
original projection to ``frozenset((path, rule_id))`` collapsed the two
same-file/same-rule findings and let the test claim "safe neighbors are
absent" while the scanner had flagged one -- a proven fake green.  The
assertions here therefore compare **per finding** (path, rule_id, line),
list the positives and the known false positive separately, and keep the
detection-quality requirement explicitly **unmet**: the false positive is
recorded as a known baseline conclusion of the current generic rules
(the scanner product logic is deliberately unchanged in this fix; no
sample deletion, no rule dodging, no whitelist, no coarse dedup).

Inputs are pinned: deterministic file bytes written without any LF-style
line-ending conversion (the source bytes are kept verbatim), a tree
digest computed by an independent transcription, saved before the move
and compared after it, the frozen explicit scanner configuration, and
the config-derived analyzer identity string.  Proven here, within
small-sample scope only:

- the shared scan path is reusable and repository-identity-independent:
  a rename/move keeps the semantic result (same per-finding face) while
  the provenance faces change honestly (the root labels differ);
- the result follows the content: replacing a positive with its safe
  neighbor removes exactly that finding (the known false positive stays);
- a docs/test-heavy sample can produce an honest measured zero with files
  actually scanned (not a failure, not an empty scan);
- the fixed LF identity values live in the LF benchmark adapter layer
  only: the production rule/scan modules carry no repository-specific
  identity strings (negative control), while the adapter does (usable for
  provenance, never a security-decision input).

NOT proven here (explicitly out of scope): cross-repository release pass,
statistical generalization, VEP/RVR, any complete V5 production
capability, or detection precision/recall beyond the four observed
candidates.  Everything runs offline in temp directories with zero
network, zero credentials and zero model calls.
"""

import ast
import hashlib
import json
import pathlib
import tempfile
import unittest

from lima.repository_scanner import RepositoryScanner
from lima.reviewer import SecurityRuleReviewer
from lima.workspace import RepositoryWorkspace

_REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent

#: The explicit offline scanner configuration (the b1_source discipline:
#: every disabling parameter passed explicitly; spelled out here against
#: the production constructor -- this is the production path, not a copy).
_SCANNER_SAST_MODE = "off"
_SCANNER_CXX_MEMORY_MODE = "off"
_SCANNER_CXX_AGENT_MODE = "off"
_SCANNER_DATAFLOW_ENABLED = True
_WORKSPACE_MAX_FILES = 5000
_WORKSPACE_MAX_FILE_BYTES = 512 * 1024
_WORKSPACE_MAX_TOTAL_BYTES = 20 * 1024 * 1024

#: The config-derived analyzer identity (tool-version face, frozen literal).
_ANALYZER_NAME = "repository-hybrid:python-ast+python-dataflow"

_PYLIB_FILES = {
    "pylib/__init__.py": '"""pylib-mini: a tiny library-shaped sample."""\n',
    "pylib/runner.py": (
        "import json\n"
        "\n"
        "\n"
        "def evaluate(user_expr):\n"
        "    # positive: dynamic code execution of external input\n"
        "    return eval(user_expr)\n"
        "\n"
        "\n"
        "def safe_evaluate(payload):\n"
        "    # safe neighbor: explicit parser, no execution semantics\n"
        "    return json.loads(payload)\n"
    ),
    "pylib/shellout.py": (
        "import subprocess\n"
        "\n"
        "\n"
        "def run_tool(command):\n"
        "    # positive: shell execution of a string command\n"
        "    return subprocess.run(command, shell=True)\n"
        "\n"
        "\n"
        "def run_tool_safely(command):\n"
        "    # safe neighbor: argument array with shell=False\n"
        "    return subprocess.run(command, shell=False, check=True)\n"
    ),
    "pylib/config.py": (
        "SERVICE_PASSWORD = \"s3cr3t-service-password\"  # positive: hardcoded\n"
        "SERVICE_PASSWORD_ENV = \"SERVICE_PASSWORD\"  # safe neighbor: name only\n"
    ),
}

#: The expected per-finding semantic face of pylib-mini, compared as
#: (path, rule_id, line) triples so that same-file/same-rule extra alerts
#: can never be collapsed away again.  The three positives:
_PYLIB_POSITIVE_FINDINGS = frozenset(
    {
        ("pylib/runner.py", "SEC-EVAL", 6),
        ("pylib/shellout.py", "SEC-SUBPROCESS-SHELL", 6),
        ("pylib/config.py", "SEC-HARDCODED-SECRET", 1),
    }
)
#: The fourth observed candidate: the generic secret rule also fires on
#: the safe-neighbor name-only reference ``SERVICE_PASSWORD_ENV =
#: "SERVICE_PASSWORD"``.  Recorded as a KNOWN FALSE POSITIVE (detection
#: quality honestly unmet); the scanner product logic is unchanged here.
_PYLIB_KNOWN_FALSE_POSITIVE = ("pylib/config.py", "SEC-HARDCODED-SECRET", 2)

#: The full raw observation: 4 candidates, not 3.
_PYLIB_ALL_FINDINGS = _PYLIB_POSITIVE_FINDINGS | {_PYLIB_KNOWN_FALSE_POSITIVE}

#: Safe-neighbor lines that must stay unflagged by their own rule faces
#: (the known false positive above is the honest exception, kept visible).
_PYLIB_CLEAN_NEIGHBOR_LINES = frozenset(
    {("pylib/runner.py", 11), ("pylib/shellout.py", 11)}
)

#: After the eval positive is replaced by its safe neighbor, exactly the
#: SEC-EVAL finding disappears; the known false positive stays.
_PYLIB_AFTER_SAFE_SWAP = _PYLIB_ALL_FINDINGS - {
    ("pylib/runner.py", "SEC-EVAL", 6)
}

_DOCS_FILES = {
    # Markdown stays in the sample as an honest out-of-inventory face:
    # the production default inventory has no .md extension, so these
    # bytes are present but not counted as scanned (identity-independent
    # production behavior, reported as-is rather than disguised).
    "README.md": (
        "# docs-tests-mini\n\nA documentation/test-heavy sample with no\n"
        "security positives: an honest measured zero.\n"
    ),
    "docs/usage.md": "# Usage\n\nRun the tests; there is no production code here.\n",
    "docs/schema.json": "{\n  \"name\": \"docs-tests-mini\",\n  \"version\": 1\n}\n",
    "config/app.conf": "mode = read-only\nlanguage = python\n",
    "tests/test_sample.py": "def test_sample():\n    assert True\n",
    "tests/test_docs_meta.py": (
        "def test_docs_meta():\n"
        "    assert \"docs-tests-mini\".startswith(\"docs\")\n"
    ),
}

#: Files the production default inventory actually scans (no .md face).
_DOCS_SCANNED_FILES = 4


def _tree_digest(root: pathlib.Path) -> str:
    """Independent transcription: sorted (relpath, file sha256) -> sha256."""
    entries = []
    for path in sorted(root.rglob("*")):
        if path.is_file():
            entries.append(
                (
                    path.relative_to(root).as_posix(),
                    hashlib.sha256(path.read_bytes()).hexdigest(),
                )
            )
    encoded = json.dumps(entries, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _write_files(target: pathlib.Path, files: dict[str, str]) -> None:
    """Write the fixture verbatim (source bytes, no line-ending surgery)."""
    for relative, text in files.items():
        path = target / pathlib.PurePosixPath(relative)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(text.encode("utf-8"))


def _scan(root: pathlib.Path):
    """The production scan path under the explicit offline configuration."""
    scanner = RepositoryScanner(
        [SecurityRuleReviewer()],
        sast_mode=_SCANNER_SAST_MODE,
        sast_adapters=[],
        cxx_memory_mode=_SCANNER_CXX_MEMORY_MODE,
        cxx_memory_adapter=None,
        cxx_agent_mode=_SCANNER_CXX_AGENT_MODE,
        cxx_agent_budget_factory=None,
        cxx_uaf_llm_factory=None,
        dataflow_enabled=_SCANNER_DATAFLOW_ENABLED,
        should_cancel=None,
    )
    workspace = RepositoryWorkspace(
        root,
        max_files=_WORKSPACE_MAX_FILES,
        max_file_bytes=_WORKSPACE_MAX_FILE_BYTES,
        max_total_bytes=_WORKSPACE_MAX_TOTAL_BYTES,
    )
    return scanner.scan(workspace)


def _semantic_face(result) -> frozenset[tuple[str, str, int]]:
    """The per-finding face: (path, rule_id, line), no set-collapsed rules.

    Line numbers are part of the stable identity: two findings in one file
    under one rule stay two findings (the 2026-10-02 fake-green
    correction -- the old ``(path, rule_id)`` projection hid a real alert
    on a safe-neighbor line).
    """
    return frozenset(
        (finding.path, finding.rule_id, finding.line)
        for finding in result.report.findings
    )


class TestNonLfScannerGenerality(unittest.TestCase):
    """Shared scanning path reusability, proven within small-sample scope."""

    def test_tree_digest_stable_across_materializations_and_byte_sensitive(self):
        # The input pin: two independent materializations of the same
        # fixture bytes produce the identical tree digest, and the digest
        # is byte-sensitive (a content change moves it).
        with tempfile.TemporaryDirectory() as temporary:
            parent = pathlib.Path(temporary)
            first = parent / "mat-one" / "pylib-mini"
            second = parent / "mat-two" / "pylib-mini"
            _write_files(first, _PYLIB_FILES)
            _write_files(second, _PYLIB_FILES)
            digest_one = _tree_digest(first)
            self.assertEqual(digest_one, _tree_digest(second))
            changed = dict(_PYLIB_FILES)
            changed["pylib/runner.py"] = changed["pylib/runner.py"].replace(
                "eval(user_expr)", "json.loads(user_expr)"
            )
            third = parent / "mat-three" / "pylib-mini"
            _write_files(third, changed)
            self.assertNotEqual(digest_one, _tree_digest(third))

    def test_pylib_mini_positives_and_safe_neighbors(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary) / "pylib-mini"
            _write_files(root, _PYLIB_FILES)
            result = _scan(root)
            self.assertEqual(result.report.reviewer, _ANALYZER_NAME)
            face = _semantic_face(result)
            # The raw observation is 4 candidates: every positive present,
            # plus the known false positive on the name-only safe neighbor.
            self.assertEqual(face, _PYLIB_ALL_FINDINGS)
            for positive in _PYLIB_POSITIVE_FINDINGS:
                self.assertIn(positive, face)
            self.assertIn(_PYLIB_KNOWN_FALSE_POSITIVE, face)
            # The other safe neighbors stay unflagged on their own lines.
            flagged_lines = {(path, line) for path, _, line in face}
            self.assertEqual(
                flagged_lines & _PYLIB_CLEAN_NEIGHBOR_LINES, set()
            )
            # Detection quality is honestly UNMET: the false positive is a
            # known baseline conclusion of the current generic rules; this
            # test records it, it does not bless it and it does not fix it.
            positives = face - {_PYLIB_KNOWN_FALSE_POSITIVE}
            self.assertEqual(len(result.report.findings), 4)
            self.assertEqual(len(positives), 3)
            # Every positive carries its CWE face.
            cwes = {
                (finding.path, finding.rule_id): finding.cwe
                for finding in result.report.findings
            }
            self.assertEqual(cwes[("pylib/runner.py", "SEC-EVAL")], "CWE-95")
            self.assertEqual(
                cwes[("pylib/shellout.py", "SEC-SUBPROCESS-SHELL")], "CWE-78"
            )
            self.assertEqual(
                cwes[("pylib/config.py", "SEC-HARDCODED-SECRET")], "CWE-798"
            )
            # Files were really scanned (measured coverage, not a failure).
            self.assertEqual(
                result.report.collaboration["scanned_files"], len(_PYLIB_FILES)
            )
            self.assertGreater(result.report.collaboration["scanned_files"], 0)

    def test_rename_keeps_semantics_provenance_changes_honestly(self):
        with tempfile.TemporaryDirectory() as temporary:
            parent = pathlib.Path(temporary)
            original = parent / "pylib-mini"
            _write_files(original, _PYLIB_FILES)
            before = _scan(original)
            # Save the tree digest BEFORE the move; compare with the value
            # measured AFTER it (the old test compared the moved tree with
            # itself, which proved nothing about rename stability).
            digest_before_move = _tree_digest(original)
            # Identity change: rename and move the whole sample.
            moved = parent / "renamed-deeper" / "totally-other-name"
            moved.parent.mkdir(parents=True)
            original.rename(moved)
            after = _scan(moved)
            # The semantic result is identical (all four candidates,
            # including the known false positive) ...
            self.assertEqual(_semantic_face(before), _semantic_face(after))
            self.assertEqual(_semantic_face(after), _PYLIB_ALL_FINDINGS)
            self.assertEqual(
                before.report.collaboration["scanned_files"],
                after.report.collaboration["scanned_files"],
            )
            # ... while the provenance faces change honestly (the realized
            # root labels follow the actual location, no disguise).
            self.assertNotEqual(before.report.repository, after.report.repository)
            self.assertNotEqual(before.inventory.root, after.inventory.root)
            # The tree digest is rename-stable (identity is not content).
            self.assertEqual(_tree_digest(moved), digest_before_move)

    def test_content_change_positive_to_safe_neighbor_changes_result(self):
        with tempfile.TemporaryDirectory() as temporary:
            parent = pathlib.Path(temporary)
            root = parent / "pylib-mini"
            _write_files(root, _PYLIB_FILES)
            before = _scan(root)
            # Replace the eval positive with its safe neighbor (rewrite the
            # whole fixture so the file bytes stay deterministic).
            swapped = dict(_PYLIB_FILES)
            swapped["pylib/runner.py"] = swapped["pylib/runner.py"].replace(
                "return eval(user_expr)", "return json.loads(user_expr)"
            )
            for relative in _PYLIB_FILES:
                (root / pathlib.PurePosixPath(relative)).unlink()
            _write_files(root, swapped)
            after = _scan(root)
            self.assertEqual(_semantic_face(before), _PYLIB_ALL_FINDINGS)
            self.assertEqual(_semantic_face(after), _PYLIB_AFTER_SAFE_SWAP)
            # Exactly the SEC-EVAL finding disappeared; nothing else moved,
            # and the known false positive stays visible through the swap.
            self.assertEqual(
                _semantic_face(before) - _semantic_face(after),
                {("pylib/runner.py", "SEC-EVAL", 6)},
            )
            self.assertIn(_PYLIB_KNOWN_FALSE_POSITIVE, _semantic_face(after))

    def test_docs_tests_mini_measured_zero_is_not_failure(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary) / "docs-tests-mini"
            _write_files(root, _DOCS_FILES)
            result = _scan(root)
            # An honest measured zero: inventoried files scanned (markdown
            # is out of the default inventory face and reported as such),
            # no findings, and the scan completed (a failure face would
            # raise, not return zero).
            self.assertEqual(result.report.findings, [])
            self.assertEqual(
                result.report.collaboration["scanned_files"], _DOCS_SCANNED_FILES
            )
            self.assertEqual(result.report.reviewer, _ANALYZER_NAME)
            # The only skip face is the honest unsupported-extension count
            # for the markdown bytes (not a coverage-affecting skip); no
            # other file was silently dropped.
            skipped = result.report.collaboration["skipped"]
            self.assertEqual(skipped, {"unsupported-extension": 2})

    def test_fixed_lf_identity_lives_only_in_the_benchmark_adapter(self):
        # Negative control: the production scan/rule modules carry no
        # LF-specific identity strings -- the fixed repository/SHA/dataset
        # values cannot be a security-decision input there.
        production_modules = [
            _REPO_ROOT / "lima" / "repository_scanner.py",
            _REPO_ROOT / "lima" / "python_analyzer.py",
            _REPO_ROOT / "lima" / "python_dataflow.py",
            _REPO_ROOT / "lima" / "reviewer.py",
            _REPO_ROOT / "lima" / "workspace.py",
        ]
        for module in production_modules:
            with self.subTest(module=module.name):
                self.assertTrue(module.is_file())
                source = module.read_text(encoding="utf-8")
                self.assertNotIn("llamafactory", source.lower())
                self.assertNotIn("7fcf5b3b", source.lower())
        # Positive control: the LF adapter layer does carry the frozen
        # identity values (provenance binding in the benchmark adapter).
        adapter = _REPO_ROOT / "benchmarks" / "v4" / "baseline" / "lf_baseline.py"
        source = adapter.read_text(encoding="utf-8")
        self.assertIn("llamafactory", source.lower())
        self.assertIn("7fcf5b3b", source.lower())
        # PC1 self-scan (offline, deterministic; no network imports).
        tree = ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"))
        roots = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    roots.add(alias.name.split(".")[0])
            elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
                roots.add(node.module.split(".")[0])
        self.assertEqual(roots & {"socket", "urllib", "requests", "http"}, set())


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
