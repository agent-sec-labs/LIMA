"""Deterministic repository shapes for IP-0018 RAM facts acceptance tests.

Fixtures are plain ``dict[str, str]`` repo shapes materialized through
``tests.audit.fixtures.repo_shapes.workspace_with`` (which pins ``newline="\\n"``
per PI-DR1/PI-DR6). No bytes are written by this module itself; no platform
behaviour is relied upon. The module under test (``lima.audit``) is imported
lazily by the tests so the module-absence RED anchor (PI-DR4) stays observable
per test case.
"""

from __future__ import annotations

ENDPOINT_REPO: dict[str, str] = {
    "api.py": (
        "import os\n"
        "\n"
        "\n"
        "@some_app.get('/items')\n"
        "def list_items():\n"
        "    return []\n"
    ),
    "app.py": (
        "class Handlers:\n"
        "    @router.post('/submit')\n"
        "    def submit(self):\n"
        "        return None\n"
    ),
}

ENDPOINT_EMPTY_REPO: dict[str, str] = {
    "plain.py": (
        "def helper(value):\n"
        "    return value + 1\n"
    ),
}

SOURCE_REPO: dict[str, str] = {
    "envs.py": (
        "import os\n"
        "\n"
        "\n"
        "def from_env():\n"
        "    return os.getenv('HOME')\n"
    ),
    "web.py": (
        "from framework import request\n"
        "\n"
        "\n"
        "def read_query(request):\n"
        "    return request.args.get('q')\n"
    ),
    "bodies.py": (
        "def read_body(payload_json):\n"
        "    return payload_json.json\n"
    ),
}

SOURCE_NEGATIVE_REPO: dict[str, str] = {
    "local.py": (
        "def compute():\n"
        "    value = 41\n"
        "    local = value + 1\n"
        "    return local\n"
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

SINK_CONSTANT_REPO: dict[str, str] = {
    "safe.py": (
        "import os\n"
        "\n"
        "\n"
        "def run_fixed():\n"
        "    os.system('ls')\n"
    ),
}

BOUNDARY_SAME_FILE_REPO: dict[str, str] = {
    "service.py": (
        "import os\n"
        "\n"
        "\n"
        "@app.get('/x')\n"
        "def handler():\n"
        "    return os.getenv('TOKEN')\n"
    ),
    "other.py": (
        "import os\n"
        "\n"
        "\n"
        "def background():\n"
        "    return os.getenv('SECRET_KEY')\n"
    ),
}

UNRESOLVED_REPO: dict[str, str] = {
    "edges.py": (
        "from framework import request\n"
        "\n"
        "\n"
        "def caller(request):\n"
        "    return missing_target(request.args.get('q'))\n"
    ),
}

UNRESOLVED_PLAIN_REPO: dict[str, str] = {
    "edges.py": (
        "def caller():\n"
        "    return missing_target(1)\n"
    ),
}

UNRESOLVED_EMPTY_REPO: dict[str, str] = {
    "edges.py": (
        "from framework import request\n"
        "\n"
        "\n"
        "def callee(request):\n"
        "    return request.args.get('q')\n"
        "\n"
        "\n"
        "def caller(request):\n"
        "    return callee(request)\n"
    ),
}

UNRESOLVED_BUDGET_REPO: dict[str, str] = {
    "multi.py": (
        "from framework import request\n"
        "\n"
        "\n"
        "def caller(request):\n"
        "    q = request.args.get('q')\n"
        "    a = first_missing(q)\n"
        "    b = second_missing(q)\n"
        "    c = third_missing(q)\n"
        "    return a, b, c\n"
    ),
}

DYNAMIC_IMPORT_REPO: dict[str, str] = {
    "loader.py": (
        "import importlib\n"
        "\n"
        "\n"
        "def load(name):\n"
        "    return importlib.import_module(name)\n"
    ),
}

AMBIGUOUS_REPO: dict[str, str] = {
    "pkg.py": "VALUE = 1\n",
    "pkg/__init__.py": "OTHER = 2\n",
}

TWO_FLOW_REPO: dict[str, str] = {
    "one.py": (
        "import os\n"
        "from framework import request\n"
        "\n"
        "\n"
        "def run(request):\n"
        "    os.system(request.args.get('cmd'))\n"
    ),
    "two.py": (
        "import subprocess\n"
        "from framework import request\n"
        "\n"
        "\n"
        "def run(request):\n"
        "    subprocess.run(request.args.get('cmd'), shell=True)\n"
    ),
}

PYTHON_FILE_BUDGET_REPO: dict[str, str] = {
    "a_first.py": "A = 1\n",
    "b_second.py": "B = 2\n",
}

SECRET_REPO: dict[str, str] = {
    "secret.py": (
        "TOKEN_VALUE = 'AKIAIOSFODNN7EXAMPLE'\n"
        "\n"
        "\n"
        "def leak():\n"
        "    return TOKEN_VALUE\n"
    ),
}

MALICIOUS_SETUP_REPO: dict[str, str] = {
    "setup.py": (
        "import os\n"
        "\n"
        "os.environ['LIMA_IP0018_PWNED'] = '1'\n"
        "raise RuntimeError('setup hook must never execute')\n"
    ),
    "main.py": (
        "def value():\n"
        "    return 3\n"
    ),
}
