"""Deterministic bounded context indexing over verified C/C++ snapshots."""

import hashlib
import tempfile
import unittest
from pathlib import Path

from lima.cxx_context import CxxContextIndex
from lima.workspace import RepositoryWorkspace, WorkspaceFile, WorkspaceInventory

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


class _InlineWorkspace:
    """Minimal workspace stand-in over in-memory snapshot text."""

    def __init__(self, files):
        self.files = files

    def read_text(self, path):
        return self.files[path]


def build_inline_index(files):
    entries = []
    for path, text in files.items():
        raw = text.encode("utf-8")
        entries.append(
            WorkspaceFile(
                path=path,
                size=len(raw),
                sha256=hashlib.sha256(raw).hexdigest(),
                line_count=text.count("\n"),
            )
        )
    inventory = WorkspaceInventory(root="<inline>", files=entries)
    return CxxContextIndex.build(_InlineWorkspace(files), inventory)


def real_line_count(text):
    """Number of real lines under U+000A accounting (no phantom line)."""
    return text.count("\n") + (0 if text.endswith("\n") else 1)


FORM_FEED_SOURCE = (
    "int before_form_feed(void) {\n"
    "    return 1;\f\n"
    "}\n"
    "int after_form_feed(void) {\n"
    "    return 2;\n"
    "}\n"
)

FORM_FEED_CALL_SOURCE = (
    "int first_user(void) {\n"
    "    return helper(1);\f\n"
    "}\n"
    "int second_user(void) {\n"
    "    return helper(2);\n"
    "}\n"
)

TAIL_SOURCE = "int caller_fn(void) {\n    helper(1);\n}"


class CxxContextLineAccountingTests(unittest.TestCase):
    """Line numbers count U+000A only, matching unified-diff/editor numbering."""

    def test_form_feed_does_not_shift_subsequent_line_numbers(self):
        index = build_inline_index({"paged.c": FORM_FEED_SOURCE})
        by_id = {symbol.qualified_name: symbol for symbol in index.symbols}
        self.assertEqual((1, 3), (by_id["before_form_feed"].start_line,
                                  by_id["before_form_feed"].end_line))
        # splitlines() would treat the form feed as a line break and place
        # this function at lines 5-7; U+000A accounting keeps it at 4-6.
        self.assertEqual((4, 6), (by_id["after_form_feed"].start_line,
                                  by_id["after_form_feed"].end_line))
        self.assertEqual((1, 6), (min(s.start_line for s in index.symbols),
                                  max(s.end_line for s in index.symbols)))

    def test_call_lines_keep_newline_accounting_across_form_feed(self):
        index = build_inline_index({"paged.c": FORM_FEED_CALL_SOURCE})
        edges = {(edge.caller, edge.callee, edge.line) for edge in index.calls}
        self.assertIn(("first_user", "helper", 2), edges)
        # splitlines() would report this call at line 6.
        self.assertIn(("second_user", "helper", 5), edges)
        self.assertTrue(all(line <= 6 for _, _, line in edges))

    def test_trailing_newline_phantom_line_is_never_indexed(self):
        index = build_inline_index({"tail.c": TAIL_SOURCE + "\n"})
        self.assertEqual((), index.coverage.parse_gaps)
        by_id = {symbol.qualified_name: symbol for symbol in index.symbols}
        self.assertEqual((1, 3), (by_id["caller_fn"].start_line,
                                  by_id["caller_fn"].end_line))
        self.assertEqual(
            {("caller_fn", "helper", 2)}, {
                (edge.caller, edge.callee, edge.line) for edge in index.calls
            }
        )
        total = real_line_count(TAIL_SOURCE + "\n")
        for record in index.symbols:
            self.assertLessEqual(record.end_line, total)

    def test_with_and_without_trailing_newline_agree(self):
        without = build_inline_index({"tail.c": TAIL_SOURCE})
        with_newline = build_inline_index({"tail.c": TAIL_SOURCE + "\n"})
        self.assertEqual(without.symbols, with_newline.symbols)
        self.assertEqual(without.calls, with_newline.calls)
        self.assertEqual(without.types, with_newline.types)

    def test_last_real_line_is_indexable_without_trailing_newline(self):
        # The closing brace is the last real line; an unconditional phantom
        # drop would swallow it and report end_line 2.
        index = build_inline_index({"tail.c": TAIL_SOURCE})
        by_id = {symbol.qualified_name: symbol for symbol in index.symbols}
        self.assertEqual((1, 3), (by_id["caller_fn"].start_line,
                                  by_id["caller_fn"].end_line))
        self.assertEqual(
            {("caller_fn", "helper", 2)}, {
                (edge.caller, edge.callee, edge.line) for edge in index.calls
            }
        )


class CrlfRepositoryWorkspaceTests(unittest.TestCase):
    """Real-workspace regression: CRLF files must index without drift gaps.

    The inventory hashes exact file bytes; a universal-newline-translating
    read_text would hash different bytes and misreport every CRLF file as
    snapshot-drift (observed on the real-world ResInsight smoke run).
    """

    SOURCE = (
        "void alloc_buf(void) {\n"
        "    char *p = malloc(16);\n"
        "    free(p);\n"
        "}\n"
    )

    def test_crlf_file_indexes_without_snapshot_drift(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "crlf.c").write_bytes(
                self.SOURCE.replace("\n", "\r\n").encode("utf-8")
            )
            workspace = RepositoryWorkspace(root)
            inventory = workspace.inventory()
            index = CxxContextIndex.build(workspace, inventory)
            self.assertEqual([], list(index.coverage.parse_gaps))
            self.assertEqual(("crlf.c",), index.coverage.indexed)
            self.assertTrue(index.symbols)
            self.assertTrue(index.resource_events)
            # Round-trip: read_text must preserve the exact CRLF bytes the
            # inventory hashed.
            self.assertEqual(
                hashlib.sha256(
                    workspace.read_text("crlf.c").encode("utf-8")
                ).hexdigest(),
                inventory.files[0].sha256,
            )



if __name__ == "__main__":
    unittest.main()
