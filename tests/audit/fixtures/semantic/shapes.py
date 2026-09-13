"""Deterministic repository shapes for IP-0019 semantic prioritizer tests.

All shapes are materialized via
``tests.audit.fixtures.repo_shapes.workspace_with`` which pins
``newline="\\n"`` (PI-DR1/PI-DR6). Shapes intentionally exercise the B-7
collision prerequisite: many tainted sinks in one file all carry
``symbol=None`` in ``PythonRamFacts``.
"""

from __future__ import annotations

_MANY_SINK_FUNCTIONS = 12


def _sink_function(name: str) -> str:
    return (
        f"def {name}(request):\n"
        "    return os.system(request.args.get('cmd'))\n"
        "\n"
        "\n"
    )


MANY_SINK_REPO: dict[str, str] = {
    "danger.py": (
        "import os\n"
        "from framework import request\n"
        "\n"
        "\n"
        + "".join(_sink_function(f"run_{index}") for index in range(_MANY_SINK_FUNCTIONS))
    ),
}


SINK_TAINTED_REPO: dict[str, str] = {
    "danger.py": (
        "import os\n"
        "from framework import request\n"
        "\n"
        "\n"
        "def run_command(request):\n"
        "    cmd = request.args.get('cmd')\n"
        "    os.system(cmd)\n"
    ),
}

MIXED_REPO: dict[str, str] = {
    "sinks.py": (
        "import os\n"
        "import pickle\n"
        "from framework import request\n"
        "\n"
        "\n"
        "def run_eval(request):\n"
        "    return eval(request.args.get('expr'))\n"
        "\n"
        "\n"
        "def run_command(request):\n"
        "    return os.system(request.args.get('cmd'))\n"
        "\n"
        "\n"
        "def run_sql(request):\n"
        "    return db.cursor().execute(request.args.get('q'))\n"
        "\n"
        "\n"
        "def run_path(request):\n"
        "    return open(request.args.get('p')).read()\n"
        "\n"
        "\n"
        "def run_deser(request):\n"
        "    return pickle.loads(request.args.get('d'))\n"
    ),
    "api.py": (
        "from framework import request\n"
        "\n"
        "\n"
        "@app.get('/items')\n"
        "def list_items(request):\n"
        "    return request.args.get('q')\n"
    ),
    "edges.py": (
        "from framework import request\n"
        "\n"
        "\n"
        "def caller(request):\n"
        "    return missing_target(request.args.get('q'))\n"
    ),
}
