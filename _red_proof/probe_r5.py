"""PKT-IP-0022-R5 probes (DR-04-B v3 fact base).

Reproduces, end to end on main-equivalent code, that a legal #58
AttackSurfaceEntry with symbol == "-" flows through the two public frozen
entrances and validates at the wire layer (P-R5-1), and that the None and
'-' symbol shapes collide on candidate_id (P-R5-2). No product code is
modified; read-only evidence gathering only.
"""

from __future__ import annotations

import dataclasses
import importlib

from tests.audit.fixtures.repo_shapes import profile_kwargs, workspace_with

SINK_CODE = (
    "import os\n"
    "from framework import request\n"
    "\n"
    "\n"
    "def run_command(request):\n"
    "    cmd = request.args.get('cmd')\n"
    "    os.system(cmd)\n"
)


def ram_module():
    return importlib.import_module("lima.audit.ram")


def sp_module():
    return importlib.import_module("lima.audit.semantic_prioritizer")


def rs_module():
    return importlib.import_module("lima.audit.ram_schema")


def _scan_repo():
    ram = ram_module()
    with workspace_with({"danger.py": SINK_CODE, "pkg/__init__.py": "x = 1\n"}) as ws:
        return ram.build_python_ram_facts(ws)


def _facts_with_dash_symbol(facts):
    ram = ram_module()
    profile = importlib.import_module("lima.contracts.profile")
    # Move one sink entry into entrypoints with symbol='-' (legal per #58:
    # symbol is str|None with no vocabulary check).
    sink = facts.facts.sensitive_sinks[0]
    dash_entry = profile.AttackSurfaceEntry(
        path=sink.path,
        reason_codes=sink.reason_codes,
        source_artifact_ids=sink.source_artifact_ids,
        symbol="-",
    )
    inner = dataclasses.replace(
        facts.facts, entrypoints=facts.facts.entrypoints + (dash_entry,)
    )
    return dataclasses.replace(facts, facts=inner)


def probe_p_r5_1_roundtrip_with_dash_symbol():
    sp = sp_module()
    rs = rs_module()
    facts = _facts_with_dash_symbol(_scan_repo())
    # Entrance 1: build_semantic_top_n ACCEPTS facts carrying symbol='-'.
    result = sp.build_semantic_top_n(facts.facts)
    dash_entries = [e for e in facts.facts.entrypoints if e.symbol == "-"]
    assert dash_entries, "arrange: dash entry missing"
    # Entrance 2: ram_wire_payload ACCEPTS the result (wire symbol='-').
    payload = rs.ram_wire_payload(facts, result)
    ranked_symbols = [item["symbol"] for item in payload["semantic"]["ranked"]]
    # Validation: the full round trip PASSES on main.
    rs.validate_ram_wire_payload(payload)
    return {"ranked_symbols": ranked_symbols, "validate": "PASSED"}


def probe_p_r5_2_none_dash_candidate_id_collision():
    sp = sp_module()
    facts = _facts_with_dash_symbol(_scan_repo())
    result = sp.build_semantic_top_n(facts.facts)
    ids = [c.candidate_id for c in result.ranked]
    dash_ids = [cid for cid in ids if cid.endswith(":-#1") or ":-#" in cid]
    # Also build the same repo with the identical entry but symbol=None.
    none_facts = _facts_with_dash_symbol(_scan_repo())
    import lima.contracts.profile as profile

    none_entry = dataclasses.replace(none_facts.facts.entrypoints[-1], symbol=None)
    inner = dataclasses.replace(
        none_facts.facts,
        entrypoints=none_facts.facts.entrypoints[:-1] + (none_entry,),
    )
    none_facts = dataclasses.replace(none_facts, facts=inner)
    none_result = sp.build_semantic_top_n(none_facts.facts)
    dash_set = {c.candidate_id for c in result.ranked}
    none_set = {c.candidate_id for c in none_result.ranked}
    return {
        "dash_ids_sample": dash_ids[:3],
        "intersection_none_dash": sorted(dash_set & none_set),
    }


def probe_p_r5_3_none_to_dash_wire_tamper_accepted():
    """None -> '-' flip on an otherwise real chain: candidate_id and all five
    digests stay valid, and main ACCEPTS the tampered payload (X4-7 base)."""
    rs = rs_module()
    facts = _scan_repo()
    payload = _real_payload(facts)
    idx = next(
        i
        for i, item in enumerate(payload["semantic"]["ranked"])
        if item["symbol"] is None
    )
    payload["semantic"]["ranked"][idx]["symbol"] = "-"
    try:
        rs.validate_ram_wire_payload(payload)
        return {"tamper": "ACCEPTED (gap reproduced)"}
    except Exception as exc:  # noqa: BLE001
        return {"tamper": f"rejected: {exc}"}


def _real_payload(facts):
    sp = sp_module()
    rs = rs_module()
    result = sp.build_semantic_top_n(facts.facts)
    return rs.ram_wire_payload(facts, result)


if __name__ == "__main__":
    print("P-R5-1 dash-symbol round trip:", probe_p_r5_1_roundtrip_with_dash_symbol())
    print("P-R5-2 None/'-' candidate_id collision:", probe_p_r5_2_none_dash_candidate_id_collision())
    print("P-R5-3 None->'-' wire tamper:", probe_p_r5_3_none_to_dash_wire_tamper_accepted())
