"""Five frozen repository shapes for the IP-0021 golden matrix (Packet §5.5).

All shapes are plain ``dict[str, str]`` repo shapes materialized through
``tests.audit.fixtures.repo_shapes.workspace_with``, which pins
``newline="\\n"`` (PI-DR1/PI-DR6, LF wire convention). No bytes are written
by this module itself; no platform behaviour is relied upon; no code in any
shape is ever executed by the audit chain. The modules under test are
imported lazily by the tests so the module-absence RED anchor (PI-DR4)
stays observable per test case.
"""

from __future__ import annotations

SHAPE_NAMES: tuple[str, ...] = (
    "application",
    "library",
    "cli",
    "docs",
    "test-heavy",
)

#: ``application``: framework manifest + endpoint decorators + external
#: sources + one tainted command-execution sink (>= 4 files).
APPLICATION_REPO: dict[str, str] = {
    "requirements.txt": "fastapi==0.110.0\nuvicorn==0.29.0\npydantic==2.6.4\n",
    "api.py": (
        "import os\n"
        "from framework import request\n"
        "\n"
        "\n"
        "@app.get('/items')\n"
        "def list_items(request):\n"
        "    return request.args.get('q')\n"
    ),
    "app.py": (
        "class Handlers:\n"
        "    @router.post('/submit')\n"
        "    def submit(self):\n"
        "        return None\n"
    ),
    "runner.py": (
        "import os\n"
        "\n"
        "\n"
        "def config_dir():\n"
        "    return os.getenv('APP_CONFIG')\n"
    ),
    "danger.py": (
        "import os\n"
        "from framework import request\n"
        "\n"
        "\n"
        "def run_command(request):\n"
        "    os.system(request.args.get('cmd'))\n"
    ),
}

#: ``library``: packaging manifest + no endpoints + few sinks, aligned with
#: the IP-0016 ``library_profile_golden.json`` style (>= 4 files).
LIBRARY_REPO: dict[str, str] = {
    "setup.cfg": "[metadata]\nname = sample-lib\nversion = 1.0\n",
    "sample_lib/__init__.py": "__all__ = ['core']\n",
    "sample_lib/core.py": (
        "def compute(value):\n"
        "    return value + 1\n"
    ),
    "sample_lib/loader.py": (
        "import pickle\n"
        "\n"
        "\n"
        "def load(payload):\n"
        "    return pickle.loads(payload)\n"
    ),
    "README.md": "# sample-lib\n\nA demonstration library shape.\n",
}

#: ``cli``: ``__main__.py``/argparse entrypoint + command-execution sink
#: (>= 4 files).
CLI_REPO: dict[str, str] = {
    "cli/__main__.py": (
        "import sys\n"
        "\n"
        "if __name__ == '__main__':\n"
        "    sys.exit(main())\n"
    ),
    "cli/cli.py": (
        "import argparse\n"
        "import os\n"
        "\n"
        "\n"
        "def build_parser():\n"
        "    parser = argparse.ArgumentParser(prog='sample-cli')\n"
        "    return parser\n"
        "\n"
        "\n"
        "def run(target):\n"
        "    os.system(target)\n"
    ),
    "cli/commands.py": (
        "import os\n"
        "\n"
        "\n"
        "def default_root():\n"
        "    return os.getenv('CLI_ROOT')\n"
    ),
    "README.md": "# sample-cli\n\nRun with ``python -m cli``.\n",
}

#: ``docs``: markdown-only, zero Python files; exercises the frozen
#: no-languages path (>= 4 files).
DOCS_REPO: dict[str, str] = {
    "README.md": "# docs-only\n\nNo Python in this shape.\n",
    "docs/guide.md": "# Guide\n\nStep one.\n",
    "docs/api.md": "# API\n\nDescriptions.\n",
    "CONTRIBUTING.md": "# Contributing\n\nSend patches.\n",
}

#: ``test-heavy``: tests/ dominance + mock usage + dynamic import signal
#: (>= 4 files).
TEST_HEAVY_REPO: dict[str, str] = {
    "src/app.py": (
        "def handle(value):\n"
        "    return value + 1\n"
    ),
    "src/__init__.py": "",
    "tests/conftest.py": (
        "import os\n"
        "\n"
        "\n"
        "def fixture_root():\n"
        "    return os.getenv('TEST_TMP')\n"
    ),
    "tests/test_app.py": (
        "from unittest import mock\n"
        "\n"
        "from src import app\n"
        "\n"
        "\n"
        "def test_handle():\n"
        "    with mock.patch.object(app, 'handle', return_value=2):\n"
        "        assert app.handle(1) == 2\n"
    ),
    "tests/test_loader.py": (
        "import importlib\n"
        "\n"
        "\n"
        "def test_dynamic():\n"
        "    module = importlib.import_module('src.app')\n"
        "    assert module.handle(1) == 2\n"
    ),
}

SHAPES: dict[str, dict[str, str]] = {
    "application": APPLICATION_REPO,
    "library": LIBRARY_REPO,
    "cli": CLI_REPO,
    "docs": DOCS_REPO,
    "test-heavy": TEST_HEAVY_REPO,
}


def assert_lf_only() -> None:
    """Guard the fixture-level LF convention: no ``\\r`` in any shape text."""
    for name in SHAPE_NAMES:
        for path, text in SHAPES[name].items():
            assert "\r" not in text, (name, path)
