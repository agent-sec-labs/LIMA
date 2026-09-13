"""RED proof tests for IP-0022 Packet v5 R5 revision (PKT-IP-0022-R5,
DR-IP-0022-04-B v3: public API round-trip contract).

Baseline: 30bdfaa13ac72572d65ccb2567ae8702923c4187 (origin/main).

Fact base (probe_r5.py, personally reproduced end to end on main):
the #58 contract admits AttackSurfaceEntry(symbol='-'), and such a fact set
flows through BOTH public frozen entrances (build_semantic_top_n,
ram_wire_payload) and then PASSES validate_ram_wire_payload -- the full
generate-then-validate round trip holds for the '-' shape on main, and the
None and '-' shapes collide on candidate_id. DR-04-B v3 therefore narrows
the input domain at the entrances (typed rejection) instead of only
rejecting '-' at the wire layer.

Division of labour with the X4 series (xaudit file):
- X8-0    real-scan round-trip GREEN anchor (legal inputs keep round-tripping);
- X8-1/2  ENTRY negatives: both public entrances must raise a typed
          ContractError for symbol == "-" (RED on main: both ACCEPT);
- X4-7    WIRE negative (kept in the xaudit file): a None -> '-' flip on the
          wire must be rejected by validate_ram_wire_payload -- with the
          entrance rejection in force, a wire '-' can only be an anomaly or
          tamper, so the wire rule is consistent with, not redundant to, the
          entry rules;
- X4-1/2/3 kind/path/symbol binding negatives kept unchanged (no regression).
"""

from __future__ import annotations

import dataclasses
import importlib
import unittest

from lima.contracts.errors import ContractError
from tests.audit.fixtures.repo_shapes import workspace_with

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


def _scan(repo):
    ram = ram_module()
    with workspace_with(repo) as ws:
        return ram.build_python_ram_facts(ws)


def _facts_with_dash_entrypoint(facts):
    profile = importlib.import_module("lima.contracts.profile")
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


class X8PublicApiRoundTripContractTests(unittest.TestCase):
    """DR-04-B v3 (R5): round-trip guarantee via typed entry rejection."""

    def test_real_scan_round_trip_validates(self):
        # X8-0 GREEN anchor: a real temporary repo scanned through the full
        # public chain (scan -> build_python_ram_facts -> build_semantic_top_n
        # -> ram_wire_payload -> validate_ram_wire_payload) round-trips.
        # Passes at the baseline and must keep passing after the fix.
        sp = sp_module()
        rs = rs_module()
        result = _scan({"danger.py": SINK_CODE, "pkg/__init__.py": "x = 1\n"})
        semantic = sp.build_semantic_top_n(result.facts)
        payload = rs.ram_wire_payload(result, semantic)
        rs.validate_ram_wire_payload(payload)  # must not raise

    def test_build_semantic_top_n_rejects_dash_symbol_entry(self):
        # X8-1 ENTRY negative (RED on main: ACCEPTED, round trip passes --
        # probe P-R5-1). Target: build_semantic_top_n must raise a typed
        # ContractError(INVALID_FIELD_VALUE) pointing at the offending
        # facts symbol slot when any of the five inventories carries
        # symbol == "-" (the candidate_id '-' slot then unambiguously
        # encodes symbol=None).
        sp = sp_module()
        facts = _facts_with_dash_entrypoint(
            _scan({"danger.py": SINK_CODE, "pkg/__init__.py": "x = 1\n"})
        )
        with self.assertRaises(ContractError) as ctx:
            sp.build_semantic_top_n(facts.facts)
        self.assertIn("symbol", str(ctx.exception))

    def test_ram_wire_payload_rejects_dash_symbol_ranked(self):
        # X8-2 ENTRY negative (RED on main: ACCEPTED): defends against a
        # caller hand-constructing SemanticTopNResult. A ranked entry with
        # symbol == "-" must be rejected at the ram_wire_payload entrance
        # with a typed ContractError (defence in depth with X8-1: this is
        # the only other public producer of the wire semantic section).
        sp = sp_module()
        rs = rs_module()
        result = _scan({"danger.py": SINK_CODE, "pkg/__init__.py": "x = 1\n"})
        semantic = sp.build_semantic_top_n(result.facts)
        idx = next(
            i for i, c in enumerate(semantic.ranked) if c.symbol is not None
        )
        tampered_ranked = (
            semantic.ranked[:idx]
            + (dataclasses.replace(semantic.ranked[idx], symbol="-"),)
            + semantic.ranked[idx + 1 :]
        )
        tampered = dataclasses.replace(semantic, ranked=tampered_ranked)
        with self.assertRaises(ContractError) as ctx:
            rs.ram_wire_payload(result, tampered)
        self.assertIn("symbol", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
