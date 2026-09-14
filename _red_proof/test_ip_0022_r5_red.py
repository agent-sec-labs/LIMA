"""RED proof tests for IP-0022 Packet v5 R5/R6 revision (PKT-IP-0022-R5 +
PKT-IP-0022-R6, DR-IP-0022-04-B v3 -- RESOLVED-MAINTAINER: both rulings
approved: public API round-trip contract via entrance-domain narrowing).

Baseline: 30bdfaa13ac72572d65ccb2567ae8702923c4187 (origin/main).

Fact base (probe_r5.py, personally reproduced end to end on main):
the #58 contract admits AttackSurfaceEntry(symbol='-'), and such a fact set
flows through BOTH public frozen entrances (build_semantic_top_n,
ram_wire_payload) and then PASSES validate_ram_wire_payload -- the full
generate-then-validate round trip holds for the '-' shape on main, and the
None and '-' shapes collide on candidate_id. The Maintainer approved the
DR-04-B v3 rulings 1+2: narrow the input domain at the entrances with a
TYPED rejection (exact error code INVALID_FIELD_VALUE + exact field_path).

R6 expansion (Maintainer frozen-test requirement): X8-1 is expanded to one
case per facts inventory -- entrypoints / external_sources /
sensitive_sinks / trust_boundaries / unresolved_edges -- each asserting the
exact error code (ContractErrorCode.INVALID_FIELD_VALUE) and the exact
field position ("$.facts.<section>[i].symbol"). Production scans emit
symbol=None for sinks/trust_boundaries, so the '-' entries are injected
with dataclasses.replace -- all five inventories hold AttackSurfaceEntry,
which proves the entrance check is generic over the inventories rather
than tailored to one section.

Division of labour with the X4 series (xaudit file):
- X8-0    real-scan round-trip GREEN anchor (legal inputs keep round-tripping);
- X8-1a-e ENTRY negatives: build_semantic_top_n must raise a typed
          ContractError for symbol == "-" in each of the five facts
          inventories (RED on main: ACCEPTED, round trip passes);
- X8-2    ENTRY negative: ram_wire_payload must reject a hand-constructed
          SemanticTopNResult whose ranked carries symbol == "-" with the
          exact code + "$.semantic_result.ranked[i].symbol" position;
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

from lima.contracts.errors import ContractError, ContractErrorCode
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


def _facts_with_dash_in_section(facts, section):
    """Append a symbol='-' copy of an existing entry to one of the five
    inventories. All five inventories hold AttackSurfaceEntry tuples, so a
    replace-injection is valid even for sections whose production entries
    always carry symbol=None (sinks / trust_boundaries). Returns the mutated
    build result and the appended index (the expected pointer slot)."""
    entries = getattr(facts.facts, section)
    donor = facts.facts.external_sources[0]
    dash_entry = dataclasses.replace(donor, symbol="-")
    inner = dataclasses.replace(
        facts.facts, **{section: entries + (dash_entry,)}
    )
    return dataclasses.replace(facts, facts=inner), len(entries)


def _assert_typed_rejection(case, ctx, field_path):
    # Exact code + exact field position (Maintainer frozen-test requirement).
    case.assertIs(ctx.exception.code, ContractErrorCode.INVALID_FIELD_VALUE)
    case.assertEqual(ctx.exception.field_path, field_path)


class X8PublicApiRoundTripContractTests(unittest.TestCase):
    """DR-04-B v3 (R5, R6): round-trip guarantee via typed entry rejection."""

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

    def _entry_negative(self, section):
        # X8-1a..e ENTRY negatives (R6 expansion of X8-1; RED on main:
        # ACCEPTED, round trip passes -- probe P-R5-1). Maintainer approved
        # ruling 1: build_semantic_top_n must raise a typed
        # ContractError(INVALID_FIELD_VALUE) with the exact facts symbol
        # slot "$.facts.<section>[i].symbol" when ANY of the five
        # inventories carries symbol == "-" (the candidate_id '-' slot then
        # unambiguously encodes symbol=None). Sections whose production
        # entries always carry symbol=None are exercised via
        # dataclasses.replace injection, proving the entrance check is
        # generic over the inventories.
        sp = sp_module()
        base = _scan({"danger.py": SINK_CODE, "pkg/__init__.py": "x = 1\n"})
        facts, idx = _facts_with_dash_in_section(base, section)
        with self.assertRaises(ContractError) as ctx:
            sp.build_semantic_top_n(facts.facts)
        _assert_typed_rejection(self, ctx, f"$.facts.{section}[{idx}].symbol")

    def test_x8_1a_build_semantic_top_n_rejects_dash_symbol_entrypoints(self):
        self._entry_negative("entrypoints")

    def test_x8_1b_build_semantic_top_n_rejects_dash_symbol_external_sources(self):
        self._entry_negative("external_sources")

    def test_x8_1c_build_semantic_top_n_rejects_dash_symbol_sensitive_sinks(self):
        # Production sinks always carry symbol=None; the '-' entry is
        # injected with dataclasses.replace (in-scope per the Maintainer
        # ruling: verifies the entrance validation is generic).
        self._entry_negative("sensitive_sinks")

    def test_x8_1d_build_semantic_top_n_rejects_dash_symbol_trust_boundaries(self):
        # Production trust boundaries always carry symbol=None; injected.
        self._entry_negative("trust_boundaries")

    def test_x8_1e_build_semantic_top_n_rejects_dash_symbol_unresolved_edges(self):
        self._entry_negative("unresolved_edges")

    def test_ram_wire_payload_rejects_dash_symbol_ranked(self):
        # X8-2 ENTRY negative (RED on main: ACCEPTED): defends against a
        # caller hand-constructing SemanticTopNResult. A ranked entry with
        # symbol == "-" must be rejected at the ram_wire_payload entrance
        # with the exact typed error (Maintainer ruling 1: code
        # INVALID_FIELD_VALUE + position "$.semantic_result.ranked[i].symbol";
        # defence in depth with X8-1: this is the only other public
        # producer of the wire semantic section).
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
        _assert_typed_rejection(
            self, ctx, f"$.semantic_result.ranked[{idx}].symbol"
        )


if __name__ == "__main__":
    unittest.main()
