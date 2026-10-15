"""Deterministic monorepo repository shapes for IP-0023 acceptance tests.

All shapes are plain ``dict[str, str | bytes]`` repo trees materialized through
:func:`monorepo_tree` / :func:`monorepo_workspace`, which pin ``newline="\\n"``
(LF wire convention, PI-DR1/PI-DR6) and follow the ``repo_shapes.workspace_with``
precedent: a per-call temporary directory, a :class:`RepositoryWorkspace`, no
network, no code execution. Only stdlib and ``lima.workspace`` are imported at
module scope; the module under test (``lima.audit.component_graph``) is
imported lazily by the tests so the module-absence RED anchor (PI-DR4) stays
observable per test case.

Shape catalogue (Packet v5.1 section 6 anchors in brackets):

- ``GOLDEN_MONOREPO`` -- collaboration root manifest (uv workspace) + two
  child components + one unassigned ``.py``; the golden payload shape.
- ``NESTED_ROOT_SERVICES_PACKAGES`` -- root ``[project]`` component with
  nested ``services/api`` and ``packages/core`` children. [#1/#9/#10]
- ``ROOT_ONLY`` / ``ZERO_COMPONENT`` -- single root component / no anchors. [#3]
- ``WORKSPACE_MANIFEST_MEMBERS`` -- collaboration manifest, no root component. [#4]
- ``UNASSIGNED_SCATTER`` -- scattered ``.py`` outside any anchor. [#5]
- ``EMPTY_COMPONENT_DIR`` -- manifest-anchored component without ``.py``. [#6]
- ``SECRET_ANCHOR_REPO`` -- secret-shaped anchor subtree. [#8/#26]
- ``SRC_LAYOUT_CROSS`` -- ``src`` layout cross-component import (RULE-02). [#11]
- ``BUILD_CONFIG_SRC_ROOT`` -- setuptools ``where = ["src"]`` module root. [#12]
- ``NAMESPACE_PACKAGES`` -- namespace (no ``__init__.py``) name candidates. [#13]
- ``RELATIVE_PACKAGE_IMPORTS`` -- relative imports in package context. [#14]
- ``DUPLICATE_MODULE_NAMES`` -- self-first + ambiguous resolution. [#15]
- ``UNKNOWN_IMPORT_REPO`` -- P5 unknown import carrier. [#16]
- ``KNOWN_EXTERNAL_REPO`` -- stdlib + declared third-party imports. [#17]
- ``DYNAMIC_IMPORT_REPO`` -- ``importlib.import_module`` site. [#18/#75]
- ``POLICY_INHERITANCE_REPO`` -- ignored dir + non-admitted extension + child. [#19]
- ``CALLER_CAP_REPO`` -- five ``.py`` under one anchor for caller caps. [#20]
- ``IDENTICAL_CONTENT_PAIR`` -- byte-identical twin components (API-05). [#35]
- ``CONTENT_CHANGE_REPO`` / ``CONTENT_CHANGE_EDIT`` -- one edit delta. [#37]
- ``T6_ADMISSION_SKIPPED_REPO`` -- oversize/binary/non-utf8 ``.py`` files. [#53]
- ``METADATA_ONLY_ANCHORS`` -- four former-blind-spot manifest kinds. [#54]
- ``SAME_NAME_DIR_REPO`` -- ``a/b`` anchor next to unrelated ``a/other/b``. [#55]
- ``PARENT_CHILD_MANIFESTS`` -- root + child component manifests. [#56/#70]
- ``PARSE_ERROR_REPO`` -- one syntactically broken ``.py``. [#31]
- ``EDGE_CAP_REPO`` -- one resolved edge + two unknown imports. [#22/#74/#79]
- ``EVIDENCE_CAP_REPO`` -- repeated import lines for the evidence cap. [#22]
- ``UNASSIGNED_CAP_REPO`` -- scattered ``.py`` beyond the list cap. [#22]
- ``MODEL_CALL_REPO`` -- model-worthy candidates for the aggregate envelope. [#21]
- ``MIXED_DOMAIN_LOSS_REPO`` -- non-utf8 in both channels (R2 shape). [#77]
"""

from __future__ import annotations

import shutil
import tempfile
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from pathlib import Path

from lima.workspace import RepositoryWorkspace

#: Fixed six-ID header shared by every golden/oracle per-component build
#: (Packet v5.1 section 5.2.1: six IDs are passed through unchanged to every
#: per-component profile build; the producer is fixed to the component-graph
#: module for builder-side per-component profiles).
MONOREPO_PROFILE_KWARGS: dict[str, str] = {
    "tenant_id": "tenant-monorepo",
    "task_id": "task-monorepo",
    "workflow_id": "workflow-monorepo",
    "stage_attempt_id": "stage-monorepo",
    "artifact_id": "artifact-monorepo-graph",
    "repository_snapshot_digest": "6" * 64,
}
COMPONENT_GRAPH_PRODUCER = "lima.audit.component_graph"

GOLDEN_MONOREPO: dict[str, str] = {
    # Collaboration manifest: non-empty tool.uv.workspace.members and no
    # [project] table -> no root component (Packet v5.1 section 5.1.1).
    "pyproject.toml": (
        "[tool.uv.workspace]\n"
        'members = ["services/api", "packages/core"]\n'
    ),
    # Unassigned .py: no admitted anchor contains it (the collaboration
    # manifest anchors nothing), so it must land in unassigned_files.
    "main.py": (
        "import os\n"
        "\n"
        "\n"
        "def root_utility():\n"
        "    return os.getcwd()\n"
    ),
    # services/api: S1 pyproject + S2-only requirements.txt (two manifests on
    # one anchor); imports: flask (declared via requirements.txt -> P4b),
    # core (unique in names(packages/core) -> P2 resolved, line 2 evidence),
    # missing_zeta (P5 unknown import, line 3).
    "services/api/pyproject.toml": (
        "[project]\n"
        "name = \"api\"\n"
        "version = \"0.1.0\"\n"
    ),
    "services/api/requirements.txt": "flask==3.0.0\n",
    "services/api/api.py": (
        "import flask\n"
        "import core\n"
        "import missing_zeta\n"
        "\n"
        "\n"
        "def handler(payload):\n"
        "    return flask.jsonify(core.value(payload))\n"
    ),
    # packages/core: src layout with content evidence (src/core/__init__.py),
    # so src is a module root and "core" enters the top-level name table.
    "packages/core/pyproject.toml": (
        "[project]\n"
        "name = \"core\"\n"
        "version = \"0.2.0\"\n"
    ),
    "packages/core/src/core/__init__.py": "__all__ = [\"model\"]\n",
    "packages/core/src/core/model.py": (
        "def value(payload):\n"
        "    return payload\n"
    ),
}

NESTED_ROOT_SERVICES_PACKAGES: dict[str, str] = {
    "pyproject.toml": (
        "[project]\n"
        "name = \"root-app\"\n"
        "version = \"1.0.0\"\n"
    ),
    "main.py": (
        "import os\n"
        "\n"
        "\n"
        "def entry():\n"
        "    return os.getcwd()\n"
    ),
    "services/api/pyproject.toml": (
        "[project]\n"
        "name = \"api\"\n"
        "version = \"0.1.0\"\n"
    ),
    "services/api/api.py": "def api_handler():\n    return None\n",
    "packages/core/pyproject.toml": (
        "[project]\n"
        "name = \"core\"\n"
        "version = \"0.2.0\"\n"
    ),
    "packages/core/src/core/__init__.py": "__all__ = []\n",
    "packages/core/src/core/model.py": (
        "def value(payload):\n"
        "    return payload\n"
    ),
}

ROOT_ONLY: dict[str, str] = {
    "pyproject.toml": "[project]\nname = \"solo\"\nversion = \"1.0.0\"\n",
    "solo.py": "def run():\n    return 1\n",
}

ZERO_COMPONENT: dict[str, str] = {
    "loose/a.py": "def a():\n    return 1\n",
    "loose/b.py": "def b():\n    return 2\n",
}

WORKSPACE_MANIFEST_MEMBERS: dict[str, str] = {
    "pyproject.toml": (
        "[tool.uv.workspace]\n"
        'members = ["libraries/utils"]\n'
    ),
    "libraries/utils/pyproject.toml": (
        "[project]\n"
        "name = \"utils\"\n"
        "version = \"0.3.0\"\n"
    ),
    "libraries/utils/utils.py": "def util():\n    return 3\n",
}

UNASSIGNED_SCATTER: dict[str, str] = {
    "tools/pyproject.toml": "[project]\nname = \"tools\"\nversion = \"2.0\"\n",
    "tools/tool.py": "def tool():\n    return 4\n",
    "alpha.py": "def alpha():\n    return 5\n",
    "beta/beta.py": "def beta():\n    return 6\n",
}

EMPTY_COMPONENT_DIR: dict[str, str] = {
    "pyproject.toml": "[project]\nname = \"host\"\nversion = \"1.0\"\n",
    "host.py": "def host():\n    return 7\n",
    "docs_only/pyproject.toml": (
        "[project]\n"
        "name = \"docs-only\"\n"
        "version = \"0.0.1\"\n"
    ),
}

SECRET_ANCHOR_REPO: dict[str, str] = {
    "pyproject.toml": "[project]\nname = \"host\"\nversion = \"1.0\"\n",
    "good.py": "def good():\n    return 8\n",
    "secrets/pyproject.toml": (
        "[project]\n"
        "name = \"hidden\"\n"
        "version = \"0.0.1\"\n"
    ),
    "secrets/main.py": "def hidden():\n    return 9\n",
}

SRC_LAYOUT_CROSS: dict[str, str] = {
    "a/pyproject.toml": "[project]\nname = \"alpha\"\nversion = \"1.0\"\n",
    "a/src/alpha/__init__.py": "__all__ = []\n",
    "a/a_main.py": "import beta\n\n\ndef use():\n    return beta\n",
    "b/pyproject.toml": "[project]\nname = \"beta\"\nversion = \"1.0\"\n",
    "b/src/beta/__init__.py": "__all__ = []\n",
    "b/b_main.py": "def beta_use():\n    return 1\n",
}

BUILD_CONFIG_SRC_ROOT: dict[str, str] = {
    # (b)-only evidence: the declared root ``libs`` is not ``src``, so the
    # name ``cfglib`` resolves only through the setuptools ``where`` key.
    "appc/pyproject.toml": "[project]\nname = \"appc\"\nversion = \"1.0\"\n",
    "appc/app_main.py": "import cfglib\n\n\ndef use():\n    return cfglib\n",
    "cfgcom/pyproject.toml": (
        "[project]\n"
        "name = \"cfgcom\"\n"
        "version = \"1.0\"\n"
        "\n"
        "[tool.setuptools.packages.find]\n"
        "where = [\"libs\"]\n"
    ),
    "cfgcom/libs/cfglib/__init__.py": "__all__ = []\n",
}

NAMESPACE_PACKAGES: dict[str, str] = {
    # Namespace candidates (no __init__.py): "solo_ns" unique to first
    # resolves cross-component; "nsp" defined by both -> ambiguous for a
    # third-party importer.
    "first/pyproject.toml": "[project]\nname = \"first\"\nversion = \"1.0\"\n",
    "first/nsp/sub.py": "def first_sub():\n    return 1\n",
    "first/solo_ns/mod.py": "def solo_mod():\n    return 2\n",
    "second/pyproject.toml": "[project]\nname = \"second\"\nversion = \"1.0\"\n",
    "second/nsp/other.py": "def second_other():\n    return 3\n",
    "second/user.py": "import solo_ns\n\n\ndef use():\n    return solo_ns\n",
    "host/pyproject.toml": "[project]\nname = \"host\"\nversion = \"1.0\"\n",
    "host/host_user.py": "import nsp\n\n\ndef use_nsp():\n    return nsp\n",
}

RELATIVE_PACKAGE_IMPORTS: dict[str, str] = {
    # app/mod.py sits directly under the app module root (physical context).
    # ``from ..shared.thing`` (level 2) walks to the repo root and lands
    # inside the shared anchor -> resolved; ``from ...waypoint`` (level 3)
    # walks past the repo root -> unresolved. pkgd/pkg/inner.py uses a
    # level-1 intra-package import -> no edge.
    "app/pyproject.toml": "[project]\nname = \"app\"\nversion = \"1.0\"\n",
    "app/mod.py": (
        "from ..shared.thing import value\n"
        "from ...waypoint import gone\n"
        "\n"
        "\n"
        "def use():\n"
        "    return value, gone\n"
    ),
    "shared/pyproject.toml": "[project]\nname = \"shared\"\nversion = \"1.0\"\n",
    "shared/thing.py": "def value():\n    return 28\n",
    "pkgd/pyproject.toml": "[project]\nname = \"pkgd\"\nversion = \"1.0\"\n",
    "pkgd/pkg/__init__.py": "__all__ = []\n",
    "pkgd/pkg/leaf.py": "def leaf_value():\n    return 29\n",
    "pkgd/pkg/inner.py": "from .leaf import leaf_value\n",
}

DUPLICATE_MODULE_NAMES: dict[str, str] = {
    "one/pyproject.toml": "[project]\nname = \"one\"\nversion = \"1.0\"\n",
    "one/shared/__init__.py": "__all__ = []\n",
    "one/self_user.py": "import shared\n\n\ndef use_own():\n    return shared\n",
    "two/pyproject.toml": "[project]\nname = \"two\"\nversion = \"1.0\"\n",
    "two/shared/__init__.py": "__all__ = []\n",
    "host/pyproject.toml": "[project]\nname = \"host\"\nversion = \"1.0\"\n",
    "host/host_user.py": "import shared\n\n\ndef use_shared():\n    return shared\n",
}

UNKNOWN_IMPORT_REPO: dict[str, str] = {
    "pyproject.toml": "[project]\nname = \"unknowns\"\nversion = \"1.0\"\n",
    "main.py": (
        "import missing_alpha\n"
        "import missing_beta\n"
        "import missing_alpha\n"
        "\n"
        "\n"
        "def run():\n"
        "    return missing_alpha, missing_beta\n"
    ),
}

KNOWN_EXTERNAL_REPO: dict[str, str] = {
    "pyproject.toml": (
        "[project]\n"
        "name = \"externals\"\n"
        "version = \"1.0\"\n"
        "dependencies = [\"flask==3.0.0\"]\n"
    ),
    "main.py": (
        "import os\n"
        "import json\n"
        "import flask\n"
        "\n"
        "\n"
        "def run():\n"
        "    return os, json, flask\n"
    ),
    "extras/requirements.txt": "boto3==1.34.0\n",
    "extras/m.py": "import boto3\n\n\ndef cloud():\n    return boto3\n",
}

DYNAMIC_IMPORT_REPO: dict[str, str] = {
    "pyproject.toml": "[project]\nname = \"dynamic\"\nversion = \"1.0\"\n",
    "lazy.py": (
        "import importlib\n"
        "\n"
        "\n"
        "def load(name):\n"
        "    return importlib.import_module(name)\n"
    ),
    "plain.py": "def plain():\n    return 11\n",
}

POLICY_INHERITANCE_REPO: dict[str, str] = {
    "pyproject.toml": "[project]\nname = \"policyhost\"\nversion = \"1.0\"\n",
    "main.py": "def main():\n    return 12\n",
    "child/pyproject.toml": "[project]\nname = \"child\"\nversion = \"0.1\"\n",
    "child/mod.py": "def mod():\n    return 13\n",
    "legacy/dead/pyproject.toml": (
        "[project]\n"
        "name = \"legacy\"\n"
        "version = \"0.1\"\n"
    ),
    "legacy/dead/legacy_mod.py": "def legacy_mod():\n    return 14\n",
    "child/data.json": '{"kind": "not-python"}\n',
}

CALLER_CAP_REPO: dict[str, str] = {
    "pyproject.toml": "[project]\nname = \"caprepo\"\nversion = \"1.0\"\n",
    "one.py": "def one():\n    return 1\n",
    "two.py": "def two():\n    return 2\n",
    "three.py": "def three():\n    return 3\n",
    "four.py": "def four():\n    return 4\n",
    "five.py": "def five():\n    return 5\n",
}

IDENTICAL_CONTENT_PAIR: dict[str, str] = {
    "twin_a/pyproject.toml": "[project]\nname = \"twin\"\nversion = \"1.0\"\n",
    "twin_a/twin.py": (
        "import os\n"
        "\n"
        "\n"
        "def twin_value():\n"
        "    return os.getcwd()\n"
    ),
    "twin_b/pyproject.toml": "[project]\nname = \"twin\"\nversion = \"1.0\"\n",
    "twin_b/twin.py": (
        "import os\n"
        "\n"
        "\n"
        "def twin_value():\n"
        "    return os.getcwd()\n"
    ),
}

CONTENT_CHANGE_REPO: dict[str, str] = {
    "single/pyproject.toml": "[project]\nname = \"single\"\nversion = \"1.0\"\n",
    "single/thing.py": "def thing(payload):\n    return payload\n",
    "bystander/pyproject.toml": (
        "[project]\n"
        "name = \"bystander\"\n"
        "version = \"1.0\"\n"
    ),
    "bystander/watch.py": "def watch():\n    return 15\n",
}

#: The single content edit for #37: replaces ``single/thing.py`` with a
#: tainted command-execution flow (source -> sink), changing the component's
#: RAM facts universe (a sensitive-sink finding appears) and therefore the
#: RAM and semantic digests, plus the Profile source-keyword view; every
#: other byte of the snapshot stays identical.
CONTENT_CHANGE_EDIT: dict[str, str] = {
    "single/thing.py": (
        "import os\n"
        "from framework import request\n"
        "\n"
        "\n"
        "def run_command(request):\n"
        '    os.system(request.args.get("cmd"))\n'
        "    return 1\n"
    ),
}

T6_ADMISSION_SKIPPED_REPO: dict[str, str | bytes] = {
    "pyproject.toml": "[project]\nname = \"skips\"\nversion = \"1.0\"\n",
    "good.py": "def good():\n    return 16\n",
    # Oversize .py (relative to a small caller max_file_bytes): the stat-size
    # check skips it as file-size-limit before any read.
    "oversize.py": "x = 0\n" + ("#" + "y" * 200 + "\n") * 20,
    # A real NUL byte inside the first 8 KiB -> binary skip.
    "binary.py": b"def binary():\n    return b'\x00data'\n",
    # Invalid UTF-8 bytes -> non-utf8 skip.
    "nonutf8.py": b"def broken():\n    s = '\xff\xfe'\n",
    # Exempt-key contrast: unsupported extension never triggers T6.
    "notes.md": "# notes\n",
    # Exempt-key contrast: an ignored directory (build) never triggers T6.
    "build/guide.py": "def guide():\n    return 17\n",
}

METADATA_ONLY_ANCHORS: dict[str, str] = {
    "setup.cfg": "[metadata]\nname = meta-only\nversion = 1.0\n",
    "requirements.txt": "flask==3.0.0\n",
    "go.mod": "module example.com/meta\n\ngo 1.21\n",
    "pom.xml": (
        "<project>\n"
        "  <modelVersion>4.0.0</modelVersion>\n"
        "  <groupId>com.example</groupId>\n"
        "  <artifactId>meta</artifactId>\n"
        "</project>\n"
    ),
    "script.py": "import flask\n\n\ndef run():\n    return flask\n",
    "nested/note.py": "def note():\n    return 18\n",
}

SAME_NAME_DIR_REPO: dict[str, str] = {
    "a/pyproject.toml": "[project]\nname = \"a\"\nversion = \"1.0\"\n",
    "a/top.py": "def top():\n    return 19\n",
    "a/b/pyproject.toml": "[project]\nname = \"ab\"\nversion = \"1.0\"\n",
    "a/b/b_marker.py": "def marker():\n    return 20\n",
    "a/other/b/collide.py": "def collide():\n    return 21\n",
}

PARENT_CHILD_MANIFESTS: dict[str, str] = {
    "pyproject.toml": "[project]\nname = \"parent\"\nversion = \"1.0\"\n",
    "requirements.txt": "flask==3.0.0\n",
    "main.py": "import flask\n\n\ndef run():\n    return flask\n",
    "services/pyproject.toml": "[project]\nname = \"svc\"\nversion = \"0.1\"\n",
    "services/requirements.txt": "django==5.0\n",
    "services/svc.py": "import django\n\n\ndef svc():\n    return django\n",
}

PARSE_ERROR_REPO: dict[str, str] = {
    "pyproject.toml": "[project]\nname = \"broken\"\nversion = \"1.0\"\n",
    "good.py": "def good():\n    return 22\n",
    "broken.py": "def broken(:\n    return 23\n",
}

EDGE_CAP_REPO: dict[str, str] = {
    # Mixed flow: one resolved edge (b -> a via src-layout name "shared")
    # plus two unknown imports (a/missing_alpha, b/missing_zeta).
    "a/pyproject.toml": "[project]\nname = \"edgea\"\nversion = \"1.0\"\n",
    "a/src/shared/__init__.py": "__all__ = []\n",
    "a/use.py": "import missing_alpha\n",
    "b/pyproject.toml": "[project]\nname = \"edgeb\"\nversion = \"1.0\"\n",
    "b/call.py": "import shared\nimport missing_zeta\n",
}

EVIDENCE_CAP_REPO: dict[str, str] = {
    "pyproject.toml": "[project]\nname = \"evcap\"\nversion = \"1.0\"\n",
    "main.py": "import shared\n" * 8 + "\n\ndef run():\n    return shared\n",
    "dep/pyproject.toml": "[project]\nname = \"dep\"\nversion = \"1.0\"\n",
    "dep/shared/__init__.py": "__all__ = []\n",
}

UNASSIGNED_CAP_REPO: dict[str, str] = {
    "tools/pyproject.toml": "[project]\nname = \"ucap\"\nversion = \"1.0\"\n",
    "tools/tool.py": "def tool():\n    return 24\n",
    "u1.py": "def u1():\n    return 25\n",
    "u2.py": "def u2():\n    return 26\n",
}

MODEL_CALL_REPO: dict[str, str] = {
    "alpha/pyproject.toml": "[project]\nname = \"alpha\"\nversion = \"1.0\"\n",
    "alpha/alpha_sink.py": (
        "import os\n"
        "from framework import request\n"
        "\n"
        "\n"
        "def run_command(request):\n"
        "    os.system(request.args.get(\"cmd\"))\n"
    ),
    "beta/pyproject.toml": "[project]\nname = \"beta\"\nversion = \"1.0\"\n",
    "beta/beta_sink.py": (
        "import pickle\n"
        "from framework import request\n"
        "\n"
        "\n"
        "def load(request):\n"
        "    return pickle.loads(request.args.get(\"payload\"))\n"
    ),
}

MIXED_DOMAIN_LOSS_REPO: dict[str, str | bytes] = {
    "pyproject.toml": "[project]\nname = \"domains\"\nversion = \"1.0\"\n",
    "main.py": "def main():\n    return 27\n",
    # Non-utf8 .py in the main inventory (source-inventory domain, count 1).
    "bad.py": b"def bad():\n    return '\xff\xfe'\n",
    # Two non-utf8 channel manifests under cfg/ (metadata-channel, count 2).
    "cfg/requirements.txt": b"flask==3.0.0\xff\n",
    "cfg/setup.cfg": b"[metadata]\xff\n",
}

#: #69 (CL-02/API-META repair shape): one S2-only manifest + one source file.
S2ONLY_MANIFEST_REPO: dict[str, str] = {
    "requirements.txt": "flask==3.0.0\n",
    "main.py": "import flask\n\n\ndef run():\n    return flask\n",
}

#: #66 (channel read failure): one manifest whose per-file read exceeds the
#: workspace max_file_bytes bound (default 512 KiB) -> channel unreadable.
CHANNEL_UNREADABLE_REPO: dict[str, str] = {
    "huge/requirements.txt": "#" + "z" * 600_000 + "\n",
    "huge/big.py": "def big():\n    return 29\n",
}

#: #73 collaboration-manifest kinds (no root component, members anchor).
COLLAB_PACKAGE_JSON_REPO: dict[str, str] = {
    "package.json": (
        "{\n"
        '  "name": "root",\n'
        '  "workspaces": ["pkgs/one"]\n'
        "}\n"
    ),
    "pkgs/one/package.json": "{\n  \"name\": \"one\"\n}\n",
    "pkgs/one/one.py": "def one():\n    return 30\n",
}

COLLAB_CARGO_REPO: dict[str, str] = {
    "Cargo.toml": "[workspace]\nmembers = [\"crates/tiny\"]\n",
    "crates/tiny/Cargo.toml": "[package]\nname = \"tiny\"\nversion = \"0.1.0\"\n",
    "crates/tiny/lib.rs": "pub fn tiny() -> u32 {\n    31\n}\n",
}


def many_component_repo(count: int) -> dict[str, str]:
    """Return a repo with ``count`` manifest-anchored components (for T1)."""

    members = ", ".join(f'"c{index:02d}"' for index in range(count))
    files: dict[str, str] = {
        "pyproject.toml": "[tool.uv.workspace]\n" f"members = [{members}]\n"
    }
    for index in range(count):
        files[f"c{index:02d}/pyproject.toml"] = (
            "[project]\n"
            f"name = \"c{index:02d}\"\n"
            "version = \"1.0\"\n"
        )
        files[f"c{index:02d}/mod.py"] = (
            f"def mod_{index:02d}():\n    return {index}\n"
        )
    return files


def monorepo_tree(files: Mapping[str, str | bytes]) -> Path:
    """Materialize ``files`` under a fresh temporary directory and return it."""

    root = Path(tempfile.mkdtemp(prefix="lima-ip0023-"))
    for rel in sorted(files):
        target = root / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        content = files[rel]
        if isinstance(content, bytes):
            target.write_bytes(content)
        else:
            target.write_text(content, encoding="utf-8", newline="\n")
    return root


@contextmanager
def monorepo_workspace(
    files: Mapping[str, str | bytes],
    **workspace_limits: object,
) -> Iterator[tuple[Path, RepositoryWorkspace]]:
    """Yield ``(root, workspace)`` for a materialized monorepo tree (LF pinned)."""

    root = monorepo_tree(files)
    try:
        yield root, RepositoryWorkspace(root, **workspace_limits)  # type: ignore[arg-type]
    finally:
        shutil.rmtree(root, ignore_errors=True)


def sentinel_empty_digest() -> str:
    """Return the sha256(b"") sentinel pinned by DR-IP-0016-01."""

    return "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
