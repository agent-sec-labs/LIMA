"""PKT-IP-0022-R4 probes: Maintainer problem 1 (symbol='-' production chain)
and problem 3 (entrypoints.symbol script-name surface) @main behavior.

Baseline: 30bdfaa13ac72572d65ccb2567ae8702923c4187 (lima/** identical on
docs/ip-0022-packet @8b43ba9).

P-R4-1  Profile: a manifest script literally named '-' produces
        entrypoints.symbol='-' (real production path at the Profile layer).
P-R4-2  Profile: a secret-shaped script name leaks verbatim into
        entrypoints.symbol + to_dict() (problem 3 replication); the resolved
        target path (pkg/__init__.py) is benign, so the v4 path-segment
        filter can never catch it.
P-R4-3  Semantic ranked chain: enumerate every production source of
        ranked symbol (the five RAM inventories) and confirm none can emit
        the literal '-'. Sources (source-traced):
          - entrypoints: ast.FunctionDef.name (Python identifier, no '-')
          - external_sources: enclosing FunctionDef.name or None
          - trust_boundaries / sensitive_sinks: None
          - unresolved_edges: _call_name() dotted identifiers or the
            "<dynamic-call>" sentinel
        Profile entrypoints (the only '-' producer, P-R4-1) are NOT an input
        to build_python_ram_facts / the semantic ranked chain.
P-R4-4  Wire: flipping ranked[0].symbol from None to '-' keeps candidate_id
        and all five digests valid -> accepted at main (X4-7 RED basis).
"""
import json
import sys

sys.path.insert(0, ".")

from tests.audit.fixtures.repo_shapes import profile_kwargs, workspace_with  # noqa: E402
from lima.audit import inventory as inv  # noqa: E402
from lima.audit import ram as ramm  # noqa: E402
from lima.audit import ram_schema  # noqa: E402


def profile_of(repo):
    with workspace_with(repo) as ws:
        return inv.build_repository_profile(ws, **profile_kwargs())


print("=== P-R4-1: script name '-' -> entrypoints.symbol='-' ===")
p = profile_of({
    "pyproject.toml": '[project.scripts]\n"-" = "pkg.cli:main"\ncli2 = "pkg.cli:main"\n',
    "pkg/__init__.py": "x = 1\n",
    "pkg/cli.py": "def main():\n    pass\n",
})
print("entrypoints:", [(e.path, e.symbol) for e in p.profile.entrypoints])

print("=== P-R4-2: secret-shaped script name -> entrypoints.symbol leak ===")
p2 = profile_of({
    "pyproject.toml": '[project.scripts]\ntoken_FAKESECRET123 = "pkg.cli:main"\n',
    "pkg/__init__.py": "x = 1\n",
    "pkg/cli.py": "def main():\n    pass\n",
})
print("entrypoints:", [(e.path, e.symbol) for e in p2.profile.entrypoints])
print("to_dict occurrences of token_FAKESECRET123:",
      json.dumps(p2.profile.to_dict()).count("token_FAKESECRET123"))
print("skip gaps:", [g.detail for g in p2.profile.coverage_gaps])

print("=== P-R4-3: ranked symbol sources (full production chain) ===")
SINK = (
    "import os\nfrom framework import request\n\n\ndef run_command(request):\n"
    "    cmd = request.args.get('cmd')\n    os.system(cmd)\n"
)
with workspace_with({
    "app.py": SINK,
    "endpoints.py": (
        "from framework import route\n\n@route('/x')\ndef handler():\n    pass\n"
    ),
    "dyn.py": (
        "def f(tainted, resolve):\n    return resolve(tainted)\n"
    ),
}) as ws:
    result = ramm.build_python_ram_facts(ws)
facts = result.facts
symbols = sorted({
    e.symbol
    for section in (
        facts.entrypoints, facts.external_sources,
        facts.sensitive_sinks, facts.trust_boundaries, facts.unresolved_edges,
    )
    for e in section
    if e.symbol is not None
})
print("observed symbols:", symbols)
print("any literal '-':", "-" in symbols)

print("=== P-R4-4: wire accepts symbol None -> '-' flip (gap basis) ===")
import copy  # noqa: E402
import tests.audit.test_ram_schema as trs  # noqa: E402
payload = copy.deepcopy(trs.MINIMAL_PAYLOAD)
ranked = payload["semantic"]["ranked"][0]
print("before:", ranked["symbol"], ranked["candidate_id"])
ranked["symbol"] = "-"
try:
    ram_schema.validate_ram_wire_payload(payload)
    print("validate: ACCEPTED (symbol flip undetectable at main)")
except Exception as exc:  # pragma: no cover
    print("validate: rejected:", exc)
