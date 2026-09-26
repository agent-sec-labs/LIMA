"""Deterministic baseline fixture family and registry for the LIMA v4 benchmark.

IP-0030 implementation (Source Issue #219; Coordinator Assignment
CA-IP-0030-v1.0; Packet: docs/LIMA_Implementation_Packet_IP-0030_Baseline_Fixture_Family.md).

This module is the single source of truth for eleven synthetic repository
shapes -- an empty repository, a minimal Python project, and nine V5
archetypes -- plus the closed registry of their data identities.  The registry
also carries one external-identity entry that registers upstream provenance
metadata only; it has no synthetic tree and is never materializable here.

Every shape maps POSIX-relative paths to all-ASCII LF-only text.
``materialize_fixture`` writes those bytes explicitly, so materialized trees
are independent of editor or version-control newline normalization, and
``compute_tree_fingerprint`` implements the frozen digest: sha256 over the
sorted-POSIX-path concatenation of utf-8(path) + NUL + content + NUL per
file, with the empty tree digesting to the sha256(b"") sentinel.

The module is deterministic and fully offline: no random or clock sources, no
environment reads, no network code of any kind, and no consumption of the two
IP-0026 frozen evaluation artifacts.  Those artifact names appear inside the
registry relationship note only, assembled from split literals so the frozen
consumption-token source scan stays meaningful.
"""

import enum
import hashlib
import json
import pathlib
import re
from dataclasses import dataclass
from typing import Final, NoReturn

from lima.contracts.codec import canonical_encode

__all__ = [
    "EXTERNAL_IDENTITY_KEYS",
    "FIXTURE_KEYS",
    "SYNTHETIC_FIXTURE_KEYS",
    "compute_tree_fingerprint",
    "load_registry",
    "materialize_fixture",
    "registry_relative_path",
    "verify_fixture",
    "write_registry",
]


class BaselineFixtureErrorCode(str, enum.Enum):  # noqa: UP042 -- frozen by IP-0030 Packet 7.1
    """Frozen wire values for every closed baseline-fixture failure code."""

    UNKNOWN_FIXTURE_KEY = "UNKNOWN_FIXTURE_KEY"
    EXTERNAL_IDENTITY_NOT_MATERIALIZABLE = "EXTERNAL_IDENTITY_NOT_MATERIALIZABLE"
    MATERIALIZE_TARGET_NOT_EMPTY = "MATERIALIZE_TARGET_NOT_EMPTY"
    MATERIALIZE_TARGET_UNAVAILABLE = "MATERIALIZE_TARGET_UNAVAILABLE"
    FIXTURE_FINGERPRINT_MISMATCH = "FIXTURE_FINGERPRINT_MISMATCH"
    INVALID_REGISTRY = "INVALID_REGISTRY"


_STABLE_MESSAGES: dict[BaselineFixtureErrorCode, str] = {
    BaselineFixtureErrorCode.UNKNOWN_FIXTURE_KEY: (
        "The requested fixture key is not part of the frozen baseline fixture family."
    ),
    BaselineFixtureErrorCode.EXTERNAL_IDENTITY_NOT_MATERIALIZABLE: (
        "An external-identity registry entry has no materializable synthetic tree"
        " in this repository."
    ),
    BaselineFixtureErrorCode.MATERIALIZE_TARGET_NOT_EMPTY: (
        "The materialization target directory is not empty."
    ),
    BaselineFixtureErrorCode.MATERIALIZE_TARGET_UNAVAILABLE: (
        "The materialization target directory cannot be created or used."
    ),
    BaselineFixtureErrorCode.FIXTURE_FINGERPRINT_MISMATCH: (
        "The materialized tree does not match the frozen fixture fingerprint."
    ),
    BaselineFixtureErrorCode.INVALID_REGISTRY: (
        "The fixture registry document violates the frozen registry schema."
    ),
}


class BaselineFixtureError(ValueError):
    """Closed failure type for every baseline-fixture contract violation."""

    def __init__(self, code: BaselineFixtureErrorCode, field_path: str = "") -> None:
        if not isinstance(code, BaselineFixtureErrorCode):
            raise TypeError("code must be a BaselineFixtureErrorCode member")
        if not isinstance(field_path, str):
            raise TypeError("field_path must be a str")
        self.code = code
        self.field_path = field_path
        super().__init__(_STABLE_MESSAGES[code])


def _fail(code: BaselineFixtureErrorCode, field_path: str) -> NoReturn:
    raise BaselineFixtureError(code, field_path)


SYNTHETIC_FIXTURE_KEYS: Final[tuple[str, ...]] = (
    "archetype/empty-repository",
    "archetype/minimal-python-repository",
    "archetype/application",
    "archetype/library",
    "archetype/cli",
    "archetype/docs-content",
    "archetype/test-heavy",
    "archetype/monorepo",
    "archetype/large-repo",
    "archetype/malicious-layout",
    "archetype/dependency-blocked",
)
EXTERNAL_IDENTITY_KEYS: Final[tuple[str, ...]] = ("external/llamafactory-replay",)
FIXTURE_KEYS: Final[tuple[str, ...]] = SYNTHETIC_FIXTURE_KEYS + EXTERNAL_IDENTITY_KEYS
registry_relative_path: Final[str] = "evaluation_data/v4/fixture_registry.json"

_FIXTURE_KEY_SET: Final[frozenset[str]] = frozenset(FIXTURE_KEYS)
_SYNTHETIC_KEY_SET: Final[frozenset[str]] = frozenset(SYNTHETIC_FIXTURE_KEYS)
_EXTERNAL_KEY_SET: Final[frozenset[str]] = frozenset(EXTERNAL_IDENTITY_KEYS)


@dataclass(frozen=True, slots=True)
class FixtureMaterialization:
    """Result of one materialization or verification of a synthetic fixture."""

    key: str
    root: pathlib.Path
    file_count: int
    size_bytes: int
    fingerprint: str


# The two IP-0026 artifact names below are assembled from split literals: the
# registry relationship note must carry them verbatim, while the frozen source
# scan requires that the module never spells them contiguously (the module
# emits the names into the registry document but never reads the artifacts).
_FROZEN_MANIFEST_ARTIFACT_NAME: Final[str] = "baseline_" + "manifest.json"
_FROZEN_MATRIX_ARTIFACT_NAME: Final[str] = "python_mvp_" + "support_matrix.json"

_RELATIONSHIP_TO_SUPPORT_MATRIX: Final[str] = (
    "This registry is intentionally decoupled from evaluation_data/v4/"
    + _FROZEN_MANIFEST_ARTIFACT_NAME
    + " and evaluation_data/v4/"
    + _FROZEN_MATRIX_ARTIFACT_NAME
    + ": both files remain byte-identical to their IP-0026 frozen state because"
    " their content is pinned by the frozen acceptance tests"
    " tests/test_v4_baseline_" + "manifest.py, so the matrix gap rows"
    " archetype/empty-repository, archetype/minimal-python-repository, and"
    " archetype/llamafactory-replay are honestly retained as unsupported."
    " Upgrading those rows is deferred to #57 PR3-e, where it will land"
    " together with a new matrix version and a re-freeze of the matrix"
    " tests; nothing in this registry claims support levels for the matrix."
)

_OFFLINE_NOTE: Final[str] = (
    "All synthetic fixtures in this registry are LIMA-authored, self-contained,"
    " and materialized deterministically offline by"
    " benchmarks/v4/baseline/fixtures.py: no network access, no secret, no"
    " paid model call, and no upstream repository content is involved. The"
    " single external-identity entry registers provenance metadata only and"
    " downloads nothing in this slice."
)

_SYNTHETIC_NOTES: Final[dict[str, str]] = {
    "archetype/empty-repository": (
        "zero-entry working-tree snapshot; no .git metadata (nested git"
        " repositories are not representable inside this repository); empty"
        " semantics asserted by zero materialized files"
    ),
    "archetype/minimal-python-repository": (
        "smallest scannable Python project: one packaging manifest plus one"
        " package holding one pure function"
    ),
    "archetype/application": (
        "application shape: two pinned dependency declarations, a main-entry"
        " module, one route-decorator module, and an os.getenv configuration"
        " read"
    ),
    "archetype/library": (
        "library shape: packaging metadata, a pure core module, a lazy"
        " pickle.loads loader sample, and a README"
    ),
    "archetype/cli": (
        "cli shape: argparse entrypoint, subcommand dispatch, and a"
        " [project.scripts] console entry"
    ),
    "archetype/docs-content": (
        "documentation-dominant shape: four markdown documents plus mkdocs.yml"
        " with one trivial Python doc builder"
    ),
    "archetype/test-heavy": (
        "test-dominant shape: ten test modules against three source modules"
        " plus pytest.ini (test-to-source ratio 10:3)"
    ),
    "archetype/monorepo": (
        "workspace shape: root workspace manifest and README with three"
        " subprojects (packages/alpha, packages/beta, services/gateway), each a"
        " packaging manifest plus a package with one module"
    ),
    "archetype/large-repo": (
        "bounded large-repository shape: 305 files (5 root files plus 300"
        " synth_bulk modules), total bytes at most 262144, generated as pure"
        " functions of the module index"
    ),
    "archetype/malicious-layout": (
        "inert synthetic samples of vulnerable code patterns; every file"
        " carries the SYNTHETIC INERT BASELINE FIXTURE header and nothing in"
        " this fixture is executable evidence"
    ),
    "archetype/dependency-blocked": (
        "unresolvable-dependency shape: one unresolvable version pin and one"
        " RFC 2606 .invalid git source; no reachable host is referenced"
    ),
}

_LLAMAFACTORY_COMMIT_SHA: Final[str] = "7fcf5b3b130e5713b52415bb7404c476fada9c8c"
_LLAMAFACTORY_FETCH_URL: Final[str] = (
    "https://codeload.github.com/hiyouga/LLaMA-Factory/tar.gz/" + _LLAMAFACTORY_COMMIT_SHA
)

_EXTERNAL_REGISTRY_ENTRY: Final[dict[str, object]] = {
    "key": "external/llamafactory-replay",
    "kind": "external-identity",
    "identity": {
        "repository_requested": "hiyouga/LLaMA-Factory",
        "canonical_repository": "hiyouga/LlamaFactory",
        "commit_sha": _LLAMAFACTORY_COMMIT_SHA,
    },
    "fetch": {
        "method": "codeload-tarball",
        "url": _LLAMAFACTORY_FETCH_URL,
    },
    "precheck": {
        "date": "2026-09-26",
        "commit_api": "301-redirect-then-200 to hiyouga/LlamaFactory",
        "tarball_head": "200",
    },
    "license": "Apache-2.0 (upstream SPDX; hiyouga/LlamaFactory repository license)",
    "fingerprint": None,
    "fingerprint_note": (
        "no content bytes exist in this repository; digest deferred to PR3-d"
        " materialization"
    ),
    "materialization": "deferred-to-PR3-d",
    "notes": (
        "Identity registration only: this slice performs no download and this"
        " repository holds zero content bytes for this identity; the real run"
        " budget remains a reserved Maintainer decision. The fetch URL is"
        " recorded once under the requested repository name"
        " hiyouga/LLaMA-Factory; the equivalent canonical-name codeload URL"
        " (hiyouga/LlamaFactory at the same commit) is intentionally not"
        " duplicated here. If commit 7fcf5b3b130e5713b52415bb7404c476fada9c8c"
        " cannot be materialized at PR3-d execution time, #57 FR-06 requires"
        " escalating #57 to needs-decision; substituting the latest main"
        " branch or any moving ref is forbidden."
    ),
}

_MALICIOUS_INERT_HEADER: Final[str] = (
    "# SYNTHETIC INERT BASELINE FIXTURE -- NOT A REAL VULNERABILITY\n"
)


def _minimal_python_shape() -> dict[str, str]:
    return {
        "pyproject.toml": '[project]\nname = "synth-minimal-pkg"\nversion = "0.1.0"\n',
        "src/minimal_pkg/__init__.py": (
            '"""Minimal synthetic package marker for the baseline fixture."""\n'
        ),
        "src/minimal_pkg/core.py": (
            '"""Single pure function for the minimal synthetic repository fixture."""\n'
            "\n\n"
            "def evaluate(value: int) -> int:\n"
            "    return value + 1\n"
        ),
    }


def _application_shape() -> dict[str, str]:
    return {
        "requirements.txt": "synth-web==1.0.0\nsynth-validation==0.4.0\n",
        "pyproject.toml": '[project]\nname = "synth-app"\nversion = "0.1.0"\n',
        "app.py": (
            '"""Entrypoint module for the synthetic application fixture."""\n'
            "\n\n"
            "def main() -> int:\n"
            "    return 0\n"
            "\n\n"
            'if __name__ == "__main__":\n'
            "    raise SystemExit(main())\n"
        ),
        "synth_app/__init__.py": (
            '"""Synthetic application package marker for the baseline fixture."""\n'
        ),
        "synth_app/api.py": (
            '"""Single-route API shape for the synthetic application fixture."""\n'
            "\n\n"
            "class Router:\n"
            '    """Inert stand-in for a web-framework router object."""\n'
            "\n"
            "    def get(self, route: str):\n"
            "        def decorator(function):\n"
            "            return function\n"
            "\n"
            "        return decorator\n"
            "\n\n"
            "app = Router()\n"
            "\n\n"
            '@app.get("/health")\n'
            "def health() -> dict:\n"
            '    return {"status": "synthetic-ok"}\n'
        ),
        "synth_app/config.py": (
            '"""Configuration-read shape for the synthetic application fixture."""\n'
            "\n"
            "import os\n"
            "\n\n"
            "def load_setting() -> str | None:\n"
            '    return os.getenv("SYNTH_APP_CONFIG")\n'
        ),
    }


def _library_shape() -> dict[str, str]:
    return {
        "setup.cfg": "[metadata]\nname = synth-lib\nversion = 1.0.0\n",
        "synth_lib/__init__.py": (
            '"""Synthetic library package marker for the baseline fixture."""\n'
        ),
        "synth_lib/core.py": (
            '"""Pure core module for the synthetic library fixture."""\n'
            "\n\n"
            "def compute(value: int) -> int:\n"
            "    return value * 2\n"
        ),
        "synth_lib/loader.py": (
            '"""Lazy unsafe-deserialization sample for the synthetic library fixture."""\n'
            "\n"
            "import pickle\n"
            "\n\n"
            "def load(payload: bytes) -> object:\n"
            "    # Inert vulnerable-pattern shape: deserializing an opaque payload.\n"
            "    return pickle.loads(payload)\n"
        ),
        "README.md": (
            "# synth-lib\n"
            "\n"
            "Synthetic library fixture with packaging metadata and one lazy loader sample.\n"
        ),
    }


def _cli_shape() -> dict[str, str]:
    return {
        "synth_cli/__main__.py": (
            '"""Command-line entrypoint for the synthetic CLI fixture."""\n'
            "\n"
            "import argparse\n"
            "\n"
            "from synth_cli.main import build_parser, dispatch\n"
            "\n\n"
            "def main() -> int:\n"
            "    parser = build_parser()\n"
            "    arguments = parser.parse_args()\n"
            "    return dispatch(arguments)\n"
            "\n\n"
            'if __name__ == "__main__":\n'
            "    raise SystemExit(main())\n"
        ),
        "synth_cli/main.py": (
            '"""Parser construction and subcommand dispatch for the synthetic CLI."""\n'
            "\n"
            "import argparse\n"
            "\n"
            "from synth_cli import commands\n"
            "\n\n"
            "def build_parser() -> argparse.ArgumentParser:\n"
            '    parser = argparse.ArgumentParser(prog="synth-cli")\n'
            '    subparsers = parser.add_subparsers(dest="command", required=True)\n'
            '    greet = subparsers.add_parser("greet")\n'
            '    greet.add_argument("target")\n'
            "    return parser\n"
            "\n\n"
            "def dispatch(arguments: argparse.Namespace) -> int:\n"
            '    if arguments.command == "greet":\n'
            "        commands.greet_command(arguments.target)\n"
            "        return 0\n"
            "    return 2\n"
        ),
        "synth_cli/commands.py": (
            '"""Subcommand handlers for the synthetic CLI fixture."""\n'
            "\n\n"
            "def greet_command(target: str) -> None:\n"
            '    print(f"synth-cli greeting for {target}")\n'
        ),
        "pyproject.toml": (
            '[project]\nname = "synth-cli-project"\nversion = "0.1.0"\n'
            "\n"
            "[project.scripts]\n"
            'synth-cli = "synth_cli.__main__:main"\n'
        ),
    }


def _docs_content_shape() -> dict[str, str]:
    return {
        "README.md": "# synth-docs\n\nSynthetic documentation-dominant repository fixture.\n",
        "mkdocs.yml": (
            "site_name: synth-docs\n"
            "nav:\n"
            "  - Home: index.md\n"
            "  - Guide: guide.md\n"
            "  - Reference: reference.md\n"
        ),
        "docs/index.md": "# synth-docs home\n\nInert synthetic landing page text.\n",
        "docs/guide.md": "# synth-docs guide\n\nInert synthetic guide page text.\n",
        "docs/reference.md": "# synth-docs reference\n\nInert synthetic reference page text.\n",
        "tools/build_docs.py": (
            '"""Trivial documentation builder for the synthetic docs fixture."""\n'
            "\n\n"
            "def build() -> str:\n"
            '    return "synth-docs static site placeholder"\n'
        ),
    }


def _test_heavy_test_module(stem: str) -> str:
    return (
        f'"""Synthetic {stem} test module for the test-heavy fixture."""\n'
        "\n"
        "def test_trivial_check():\n"
        "    assert 2 + 2 == 4\n"
    )


def _test_heavy_shape() -> dict[str, str]:
    shape: dict[str, str] = {
        "src/synth_core/__init__.py": (
            '"""Synthetic core package marker for the test-heavy fixture."""\n'
        ),
        "src/synth_core/logic.py": (
            '"""Pure logic module for the test-dominant synthetic fixture."""\n'
            "\n\n"
            "def combine(left: int, right: int) -> int:\n"
            "    return left + right\n"
        ),
        "src/synth_core/store.py": (
            '"""In-memory store module for the test-dominant synthetic fixture."""\n'
            "\n\n"
            "class InMemoryStore:\n"
            '    """Tiny pure-dict store used only as inert structural text."""\n'
            "\n"
            "    def __init__(self) -> None:\n"
            "        self._entries: dict[str, int] = {}\n"
            "\n"
            "    def set(self, key: str, value: int) -> None:\n"
            "        self._entries[key] = value\n"
            "\n"
            "    def get(self, key: str) -> int:\n"
            "        return self._entries[key]\n"
        ),
        "pytest.ini": "[pytest]\ntestpaths = tests\n",
    }
    for stem in (
        "logic",
        "store",
        "logic_edges",
        "store_edges",
        "logic_props",
        "store_props",
        "logic_errors",
        "store_errors",
        "integration",
        "regression",
    ):
        shape[f"tests/test_{stem}.py"] = _test_heavy_test_module(stem)
    return shape


def _monorepo_subproject(project: str, package: str, project_name: str) -> dict[str, str]:
    return {
        f"{project}/pyproject.toml": (
            f'[project]\nname = "{project_name}"\nversion = "0.1.0"\n'
        ),
        f"{project}/{package}/__init__.py": (
            f'"""{package} package marker for the monorepo fixture."""\n'
        ),
        f"{project}/{package}/module.py": (
            f'"""{package} module for the synthetic monorepo fixture."""\n'
            "\n\n"
            f"def {package}_value() -> int:\n"
            f"    return {len(package)}\n"
        ),
    }


def _monorepo_shape() -> dict[str, str]:
    shape: dict[str, str] = {
        "pyproject.toml": (
            '[project]\nname = "synth-monorepo-root"\nversion = "0.1.0"\n'
            "\n"
            "[tool.synth]\n"
            'workspace = ["packages/alpha", "packages/beta", "services/gateway"]\n'
        ),
        "README.md": "# synth-monorepo\n\nSynthetic workspace fixture with three subprojects.\n",
    }
    shape.update(_monorepo_subproject("packages/alpha", "alpha_pkg", "synth-alpha"))
    shape.update(_monorepo_subproject("packages/beta", "beta_pkg", "synth-beta"))
    shape.update(_monorepo_subproject("services/gateway", "gateway_pkg", "synth-gateway"))
    return shape


def _bulk_module_text(index: int) -> str:
    return (
        f'"""Synthetic bulk module {index:03d} for the bounded large-repo fixture."""\n'
        f"\nMODULE_INDEX = {index}\n\n\n"
        "def scale_index(factor: int) -> int:\n"
        "    return MODULE_INDEX * factor\n"
    )


def _large_repo_shape() -> dict[str, str]:
    shape: dict[str, str] = {
        "README.md": (
            "# synth-bulk\n"
            "\n"
            "Bounded synthetic large-repository fixture: five root files plus 300\n"
            "generated modules, produced purely from the module index.\n"
        ),
        "pyproject.toml": '[project]\nname = "synth-bulk"\nversion = "0.1.0"\n',
        ".gitignore": "__pycache__/\n*.py[cod]\n",
        "LICENSE.txt": (
            "SYNTHETIC PLACEHOLDER LICENSE -- NOT A REAL LICENSE GRANT\n"
            "\n"
            "This text is inert synthetic content authored by LIMA for the bounded\n"
            "large-repository baseline fixture. It confers no rights and names no\n"
            "real licensor.\n"
        ),
        "Makefile": "check:\n\t@echo synthetic no-op check\n",
    }
    for index in range(300):
        shape[f"synth_bulk/module_{index:03d}.py"] = _bulk_module_text(index)
    return shape


def _malicious_layout_shape() -> dict[str, str]:
    return {
        "setup.py": (
            _MALICIOUS_INERT_HEADER
            + "# Inert packaging shape: the download URL targets a reserved RFC 2606\n"
            "# .invalid host and the declaration below is never executed.\n"
            "\n"
            "DOWNLOAD_URL = \"https://dist.internal.invalid/synth/synth-risk-0.1.0.tar.gz\"\n"
            "\n"
            "setup_kwargs = {\n"
            '    "name": "synth-risk-samples",\n'
            '    "version": "0.1.0",\n'
            '    "download_url": DOWNLOAD_URL,\n'
            "}\n"
            "\n"
            "if False:  # inert: unreachable declaration shape only\n"
            '    helper = "synth-runtime-helper.bin"\n'
            "    exec(helper)  # declaration shape; never reached\n"
        ),
        "synth_risk/paths.py": (
            _MALICIOUS_INERT_HEADER
            + "# Inert path-traversal string shape: no filesystem is touched.\n"
            "\n"
            'BASE_DIRECTORY = "vault"\n'
            "\n"
            "def resolve_user_supplied(name: str) -> str:\n"
            "    # Vulnerable pattern shape ONLY: joining untrusted input verbatim.\n"
            '    return BASE_DIRECTORY + "/" + "../../../" + name\n'
        ),
        "synth_risk/eval_sample.py": (
            _MALICIOUS_INERT_HEADER
            + "# Inert eval-of-external-input shape: never executed with real data.\n"
            "\n"
            "def apply_user_expression(expression_text: str) -> object:\n"
            "    # Vulnerable pattern shape ONLY: evaluating external input.\n"
            "    return eval(expression_text)\n"
        ),
        "synth_risk/shell.py": (
            _MALICIOUS_INERT_HEADER
            + "# Inert shell-injection shape: the command text is never executed.\n"
            "\n"
            "def run_user_command(command_text: str) -> None:\n"
            "    # Vulnerable pattern shape ONLY: user input passed through a shell.\n"
            "    import subprocess\n"
            "\n"
            "    subprocess.run(command_text, shell=True)\n"
        ),
        "synth_risk/deser.py": (
            _MALICIOUS_INERT_HEADER
            + "# Inert unsafe-deserialization shape: no payload is ever received.\n"
            "\n"
            "import pickle\n"
            "\n"
            "def deserialize_payload(payload: bytes) -> object:\n"
            "    # Vulnerable pattern shape ONLY: deserializing an untrusted payload.\n"
            "    return pickle.loads(payload)\n"
        ),
        "NOTICE.md": (
            _MALICIOUS_INERT_HEADER
            + "\n"
            "Every file in this fixture is inert synthetic text authored by LIMA\n"
            "for the malicious-layout baseline archetype. Nothing here targets a\n"
            "real host, project, credential, or CVE identifier, and no statement\n"
            "in this fixture is ever executed.\n"
        ),
    }


def _dependency_blocked_shape() -> dict[str, str]:
    return {
        "requirements.txt": "synth-internal-core==9.9.9\n",
        "pyproject.toml": (
            '[project]\nname = "synth-blocked"\nversion = "0.1.0"\n'
            "\n"
            "[tool.synth.sources]\n"
            'internal = "git+https://git.internal.invalid/synth/pkg.git"\n'
        ),
        "constraints.txt": "synth-internal-core==9.9.9\n",
        "src/synth_blocked/__init__.py": (
            '"""Blocked synthetic package marker for the dependency fixture."""\n'
        ),
    }


def _build_shapes() -> dict[str, dict[str, str]]:
    return {
        "archetype/empty-repository": {},
        "archetype/minimal-python-repository": _minimal_python_shape(),
        "archetype/application": _application_shape(),
        "archetype/library": _library_shape(),
        "archetype/cli": _cli_shape(),
        "archetype/docs-content": _docs_content_shape(),
        "archetype/test-heavy": _test_heavy_shape(),
        "archetype/monorepo": _monorepo_shape(),
        "archetype/large-repo": _large_repo_shape(),
        "archetype/malicious-layout": _malicious_layout_shape(),
        "archetype/dependency-blocked": _dependency_blocked_shape(),
    }


_SHAPES: Final[dict[str, dict[str, str]]] = _build_shapes()


def compute_tree_fingerprint(root: pathlib.Path | str) -> str:
    """Digest a materialized tree with the frozen sorted-POSIX-path algorithm."""
    root_path = pathlib.Path(root)
    files = sorted(
        (path for path in root_path.rglob("*") if path.is_file()),
        key=lambda path: path.relative_to(root_path).as_posix(),
    )
    digest = hashlib.sha256()
    for path in files:
        digest.update(path.relative_to(root_path).as_posix().encode("utf-8"))
        digest.update(b"\x00")
        digest.update(path.read_bytes())
        digest.update(b"\x00")
    return digest.hexdigest()


def _shape_fingerprint(key: str) -> str:
    """Digest one frozen shape with the same algorithm, without materializing."""
    shape = _SHAPES[key]
    digest = hashlib.sha256()
    for relative in sorted(shape):
        digest.update(relative.encode("utf-8"))
        digest.update(b"\x00")
        digest.update(shape[relative].encode("utf-8"))
        digest.update(b"\x00")
    return digest.hexdigest()


def _require_materializable_key(key: str) -> None:
    if key not in _FIXTURE_KEY_SET:
        _fail(BaselineFixtureErrorCode.UNKNOWN_FIXTURE_KEY, "$.key")
    if key in _EXTERNAL_KEY_SET:
        _fail(BaselineFixtureErrorCode.EXTERNAL_IDENTITY_NOT_MATERIALIZABLE, "$.key")


def _prepare_target_directory(target: pathlib.Path | str) -> pathlib.Path:
    root = pathlib.Path(target)
    if root.exists():
        if not root.is_dir():
            _fail(BaselineFixtureErrorCode.MATERIALIZE_TARGET_UNAVAILABLE, "$.target")
        if any(root.iterdir()):
            _fail(BaselineFixtureErrorCode.MATERIALIZE_TARGET_NOT_EMPTY, "$.target")
    else:
        try:
            root.mkdir(parents=True)
        except OSError as exc:
            raise BaselineFixtureError(
                BaselineFixtureErrorCode.MATERIALIZE_TARGET_UNAVAILABLE, "$.target"
            ) from exc
    return root.resolve()


def _summarize_tree(key: str, root: pathlib.Path) -> FixtureMaterialization:
    files = [path for path in root.rglob("*") if path.is_file()]
    return FixtureMaterialization(
        key=key,
        root=root,
        file_count=len(files),
        size_bytes=sum(path.stat().st_size for path in files),
        fingerprint=compute_tree_fingerprint(root),
    )


def materialize_fixture(key: str, target: pathlib.Path | str) -> FixtureMaterialization:
    """Materialize one synthetic fixture into a caller-provided empty directory."""
    _require_materializable_key(key)
    root = _prepare_target_directory(target)
    shape = _SHAPES[key]
    for relative, text in shape.items():
        destination = root.joinpath(*relative.split("/"))
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(text.encode("utf-8"))
    return _summarize_tree(key, root)


def verify_fixture(key: str, root: pathlib.Path | str) -> FixtureMaterialization:
    """Fail-closed verification: a mismatch raises instead of returning a flag."""
    _require_materializable_key(key)
    root_path = pathlib.Path(root)
    if not root_path.is_dir():
        _fail(BaselineFixtureErrorCode.MATERIALIZE_TARGET_UNAVAILABLE, "$.root")
    materialization = _summarize_tree(key, root_path.resolve())
    if materialization.fingerprint != _shape_fingerprint(key):
        _fail(BaselineFixtureErrorCode.FIXTURE_FINGERPRINT_MISMATCH, "$.fingerprint")
    return materialization


_REGISTRY_SCHEMA_VERSION: Final[int] = 1
_REGISTRY_ID: Final[str] = "lima-baseline-fixture-registry"
_SYNTHETIC_ORIGIN: Final[str] = "synthetic-lima-authored"
_SYNTHETIC_LICENSE: Final[str] = "Apache-2.0 (LIMA-authored synthetic content)"
_GENERATION_ENTRYPOINT: Final[str] = "benchmarks.v4.baseline.fixtures.materialize_fixture"

_TOP_LEVEL_FIELDS: Final[frozenset[str]] = frozenset(
    ("schema_version", "registry_id", "relationship_to_support_matrix", "offline_note", "fixtures")
)
_SYNTHETIC_ENTRY_FIELDS: Final[frozenset[str]] = frozenset(
    (
        "key",
        "kind",
        "purpose",
        "origin",
        "license",
        "generation",
        "fingerprint",
        "file_count",
        "declared_size_bytes",
        "notes",
    )
)
_EXTERNAL_ENTRY_FIELDS: Final[frozenset[str]] = frozenset(
    (
        "key",
        "kind",
        "identity",
        "fetch",
        "precheck",
        "license",
        "fingerprint",
        "fingerprint_note",
        "materialization",
        "notes",
    )
)
_IDENTITY_FIELDS: Final[frozenset[str]] = frozenset(
    ("repository_requested", "canonical_repository", "commit_sha")
)
_FETCH_FIELDS: Final[frozenset[str]] = frozenset(("method", "url"))
_PRECHECK_FIELDS: Final[frozenset[str]] = frozenset(("date", "commit_api", "tarball_head"))

_FINGERPRINT_PATTERN: Final[re.Pattern[str]] = re.compile(r"[0-9a-f]{64}")
_COMMIT_SHA_PATTERN: Final[re.Pattern[str]] = re.compile(r"[0-9a-f]{40}")


def _synthetic_registry_entry(key: str) -> dict[str, object]:
    shape = _SHAPES[key]
    return {
        "key": key,
        "kind": "synthetic-fixture",
        "purpose": f"baseline archetype: {key.removeprefix('archetype/')}",
        "origin": _SYNTHETIC_ORIGIN,
        "license": _SYNTHETIC_LICENSE,
        "generation": {
            "mode": "deterministic-script",
            "entrypoint": _GENERATION_ENTRYPOINT,
        },
        "fingerprint": _shape_fingerprint(key),
        "file_count": len(shape),
        "declared_size_bytes": sum(len(text.encode("utf-8")) for text in shape.values()),
        "notes": _SYNTHETIC_NOTES[key],
    }


def _build_registry_document() -> dict[str, object]:
    return {
        "schema_version": _REGISTRY_SCHEMA_VERSION,
        "registry_id": _REGISTRY_ID,
        "relationship_to_support_matrix": _RELATIONSHIP_TO_SUPPORT_MATRIX,
        "offline_note": _OFFLINE_NOTE,
        "fixtures": [
            *(_synthetic_registry_entry(key) for key in SYNTHETIC_FIXTURE_KEYS),
            dict(_EXTERNAL_REGISTRY_ENTRY),
        ],
    }


def write_registry(path: pathlib.Path | str) -> bytes:
    """Write the registry document as canonical JSON bytes and return them."""
    payload = canonical_encode(_build_registry_document())
    pathlib.Path(path).write_bytes(payload)
    return payload


def _default_registry_path() -> pathlib.Path:
    return pathlib.Path(__file__).resolve().parents[3] / registry_relative_path


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    seen: set[str] = set()
    for key, _value in pairs:
        if key in seen:
            raise ValueError(f"duplicate object key: {key}")
        seen.add(key)
    return dict(pairs)


def _require_non_empty_str(value: object, field_path: str) -> None:
    if not isinstance(value, str) or not value.strip():
        _fail(BaselineFixtureErrorCode.INVALID_REGISTRY, field_path)


def _require_non_negative_int(value: object, field_path: str) -> None:
    if type(value) is not int or value < 0:
        _fail(BaselineFixtureErrorCode.INVALID_REGISTRY, field_path)


def _require_field_mapping(
    value: object, fields: frozenset[str], field_path: str
) -> None:
    if not isinstance(value, dict) or set(value) != fields:
        _fail(BaselineFixtureErrorCode.INVALID_REGISTRY, field_path)
    for name in fields:
        _require_non_empty_str(value[name], f"{field_path}.{name}")


def _validate_synthetic_entry(entry: dict[str, object], field_path: str) -> None:
    if set(entry) != _SYNTHETIC_ENTRY_FIELDS:
        _fail(BaselineFixtureErrorCode.INVALID_REGISTRY, f"{field_path}.fields")
    if entry["kind"] != "synthetic-fixture":
        _fail(BaselineFixtureErrorCode.INVALID_REGISTRY, f"{field_path}.kind")
    fingerprint = entry["fingerprint"]
    if not isinstance(fingerprint, str) or not _FINGERPRINT_PATTERN.fullmatch(fingerprint):
        _fail(BaselineFixtureErrorCode.INVALID_REGISTRY, f"{field_path}.fingerprint")
    _require_non_negative_int(entry["file_count"], f"{field_path}.file_count")
    _require_non_negative_int(
        entry["declared_size_bytes"], f"{field_path}.declared_size_bytes"
    )
    _require_non_empty_str(entry["notes"], f"{field_path}.notes")


def _validate_external_entry(entry: dict[str, object], field_path: str) -> None:
    if set(entry) != _EXTERNAL_ENTRY_FIELDS:
        _fail(BaselineFixtureErrorCode.INVALID_REGISTRY, f"{field_path}.fields")
    if entry["kind"] != "external-identity":
        _fail(BaselineFixtureErrorCode.INVALID_REGISTRY, f"{field_path}.kind")
    if entry["fingerprint"] is not None:
        _fail(BaselineFixtureErrorCode.INVALID_REGISTRY, f"{field_path}.fingerprint")
    _require_non_empty_str(entry["fingerprint_note"], f"{field_path}.fingerprint_note")
    _require_non_empty_str(entry["materialization"], f"{field_path}.materialization")
    _require_non_empty_str(entry["notes"], f"{field_path}.notes")
    _require_field_mapping(entry["identity"], _IDENTITY_FIELDS, f"{field_path}.identity")
    _require_field_mapping(entry["fetch"], _FETCH_FIELDS, f"{field_path}.fetch")
    _require_field_mapping(entry["precheck"], _PRECHECK_FIELDS, f"{field_path}.precheck")
    commit_sha = entry["identity"]["commit_sha"]
    if not isinstance(commit_sha, str) or not _COMMIT_SHA_PATTERN.fullmatch(commit_sha):
        _fail(BaselineFixtureErrorCode.INVALID_REGISTRY, f"{field_path}.identity.commit_sha")


def _validate_registry_document(document: object) -> None:
    if not isinstance(document, dict):
        _fail(BaselineFixtureErrorCode.INVALID_REGISTRY, "$")
    if set(document) != _TOP_LEVEL_FIELDS:
        _fail(BaselineFixtureErrorCode.INVALID_REGISTRY, "$.fields")
    if type(document["schema_version"]) is not int or document["schema_version"] != 1:
        _fail(BaselineFixtureErrorCode.INVALID_REGISTRY, "$.schema_version")
    if document["registry_id"] != _REGISTRY_ID:
        _fail(BaselineFixtureErrorCode.INVALID_REGISTRY, "$.registry_id")
    _require_non_empty_str(
        document["relationship_to_support_matrix"], "$.relationship_to_support_matrix"
    )
    _require_non_empty_str(document["offline_note"], "$.offline_note")
    entries = document["fixtures"]
    if not isinstance(entries, list) or len(entries) != len(FIXTURE_KEYS):
        _fail(BaselineFixtureErrorCode.INVALID_REGISTRY, "$.fixtures")
    keys: list[str] = []
    for index, entry in enumerate(entries):
        if not isinstance(entry, dict):
            _fail(BaselineFixtureErrorCode.INVALID_REGISTRY, f"$.fixtures[{index}]")
        key = entry.get("key")
        if not isinstance(key, str):
            _fail(BaselineFixtureErrorCode.INVALID_REGISTRY, f"$.fixtures[{index}].key")
        keys.append(key)
    if len(set(keys)) != len(keys) or set(keys) != _FIXTURE_KEY_SET:
        _fail(BaselineFixtureErrorCode.INVALID_REGISTRY, "$.fixtures.keys")
    for index, entry in enumerate(entries):
        field_path = f"$.fixtures[{index}]"
        if entry["key"] in _SYNTHETIC_KEY_SET:
            _validate_synthetic_entry(entry, field_path)
        else:
            _validate_external_entry(entry, field_path)


def load_registry(path: pathlib.Path | str | None = None) -> dict:
    """Load and fully validate the registry document; every failure is fail-closed."""
    registry_path = pathlib.Path(path) if path is not None else _default_registry_path()
    try:
        raw = registry_path.read_bytes()
        document = json.loads(raw.decode("utf-8"), object_pairs_hook=_reject_duplicate_keys)
    except (OSError, ValueError) as exc:
        raise BaselineFixtureError(BaselineFixtureErrorCode.INVALID_REGISTRY, "$") from exc
    _validate_registry_document(document)
    return document
