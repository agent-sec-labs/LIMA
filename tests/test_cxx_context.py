"""Deterministic bounded context indexing over verified C/C++ snapshots."""

import unittest
from pathlib import Path

from lima.cxx_context import CxxContextIndex
from lima.workspace import RepositoryWorkspace

FIXTURES = Path(__file__).parent / "fixtures" / "cxx_agent_context"


def build_index() -> CxxContextIndex:
    workspace = RepositoryWorkspace(FIXTURES)
    return CxxContextIndex.build(workspace, workspace.inventory())


class CxxContextIndexTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.index = build_index()

    def test_index_binds_the_snapshot_fingerprint(self):
        self.assertEqual(64, len(self.index.snapshot_sha256))
        again = build_index()
        self.assertEqual(self.index.snapshot_sha256, again.snapshot_sha256)
        self.assertEqual(self.index.symbols, again.symbols)
        self.assertEqual(self.index.calls, again.calls)
        self.assertEqual(self.index.resource_events, again.resource_events)

    def test_symbols_carry_qualified_names_and_line_ranges(self):
        by_id = {symbol.qualified_name: symbol for symbol in self.index.symbols}
        for name in (
            "read_value",
            "write_value",
            "Session::open",
            "Session::close",
            "Session::read",
            "create_session",
            "header_length",
        ):
            self.assertIn(name, by_id, name)
        read_value = by_id["read_value"]
        self.assertEqual("buffer.c", read_value.file)
        self.assertEqual("c", read_value.language)
        self.assertLessEqual(read_value.start_line, read_value.end_line)
        opened = by_id["Session::open"]
        self.assertEqual("session.cpp", opened.file)
        self.assertEqual("c++", opened.language)
        self.assertEqual("method", opened.kind)
        self.assertEqual("function", by_id["create_session"].kind)

    def test_types_are_indexed_with_definition_sites(self):
        types = {item.name: item for item in self.index.types}
        for name in ("Header", "Decoder", "Session"):
            self.assertIn(name, types, name)
        self.assertEqual("protocol.hpp", types["Header"].file)
        self.assertEqual("session.cpp", types["Session"].file)
        self.assertGreaterEqual(types["Decoder"].start_line, 1)

    def test_calls_record_caller_callee_and_file_lines(self):
        edges = {
            (edge.caller, edge.callee)
            for edge in self.index.calls
        }
        self.assertIn(("write_value", "read_value"), edges)
        self.assertIn(("create_session", "open"), edges)
        self.assertIn(("destroy_session", "close"), edges)
        self.assertIn(("make_scaled", "scale_value"), edges)
        self.assertIn(("make_scaled", "malloc"), edges)
        for edge in self.index.calls:
            self.assertGreaterEqual(edge.line, 1)
            self.assertTrue(edge.file)
            self.assertTrue(edge.callee)

    def test_definition_lines_do_not_create_fictional_self_edges(self):
        edges = {
            (edge.caller, edge.callee, edge.file)
            for edge in self.index.calls
        }
        for symbol in self.index.symbols:
            self.assertNotIn(
                (symbol.qualified_name, symbol.qualified_name.split("::")[-1], symbol.file),
                edges,
                f"fictional self edge for {symbol.qualified_name}",
            )

    def test_allman_and_namespace_functions_are_indexed(self):
        by_id = {symbol.qualified_name: symbol for symbol in self.index.symbols}
        self.assertIn("scale_value", by_id)
        self.assertIn("make_scaled", by_id)
        self.assertEqual("allman.c", by_id["scale_value"].file)
        self.assertLess(by_id["scale_value"].start_line, by_id["scale_value"].end_line)

    def test_exact_end_lines_are_reported(self):
        by_id = {symbol.qualified_name: symbol for symbol in self.index.symbols}
        self.assertEqual(21, by_id["Session::close"].end_line)
        self.assertEqual(18, by_id["Session::close"].start_line)
        types = {item.name: item for item in self.index.types}
        self.assertEqual(6, types["Header"].end_line)

    def test_resource_events_cover_allocations_and_releases(self):
        events = {
            (event.event, event.api, event.function)
            for event in self.index.resource_events
        }
        self.assertIn(("allocate", "malloc", "make_buffer"), events)
        self.assertIn(("release", "free", "release_buffer"), events)
        self.assertIn(("allocate", "new[]", "Session::open"), events)
        self.assertIn(("release", "delete[]", "Session::close"), events)
        self.assertIn(("allocate", "new", "create_session"), events)
        self.assertIn(("release", "delete", "destroy_session"), events)

    def test_buffer_and_length_apis_are_referenced(self):
        references = {
            (reference.api, reference.function)
            for reference in self.index.references
        }
        self.assertIn(("memset", "make_buffer"), references)

    def test_parse_gaps_are_reported_not_guessed(self):
        gaps = {gap.file: gap for gap in self.index.coverage.parse_gaps}
        self.assertIn("macro_tricky.c", gaps)
        self.assertTrue(gaps["macro_tricky.c"].reason)
        self.assertEqual(
            {"buffer.c", "session.cpp", "protocol.hpp", "allman.c"},
            {item.file for item in self.index.coverage.indexed_files},
        )
        self.assertEqual(5, self.index.coverage.source_files_total)
        self.assertEqual(4, len(self.index.coverage.indexed))

    def test_no_call_edges_escapes_the_snapshot_inventory(self):
        inventory_files = {
            item.path for item in build_index_inventory_files()
        }
        for collection in (
            self.index.symbols,
            self.index.types,
        ):
            for record in collection:
                self.assertIn(record.file, inventory_files)
        for edge in self.index.calls:
            self.assertIn(edge.file, inventory_files)

    def test_index_ignores_non_c_files(self):
        for record in self.index.symbols:
            self.assertNotIn(".json", record.file)
        indexed = self.index.coverage.indexed_files_as_strings()
        self.assertNotIn("manifest.json", indexed)
        self.assertEqual(5, self.index.coverage.source_files_total)
        self.assertEqual(4, len(indexed))

    def test_determinism_covers_every_collection(self):
        again = build_index()
        self.assertEqual(self.index.types, again.types)
        self.assertEqual(self.index.references, again.references)
        self.assertEqual(self.index.coverage, again.coverage)


def build_index_inventory_files():
    workspace = RepositoryWorkspace(FIXTURES)
    return workspace.inventory().files


if __name__ == "__main__":
    unittest.main()
