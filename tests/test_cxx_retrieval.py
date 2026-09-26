"""Tests for label-free repository and pull-request candidate retrieval."""

import dataclasses
import unittest
from pathlib import Path

from lima.cxx_context import (
    ApiReference,
    CallEdge,
    CxxContextIndex,
    IndexCoverage,
    ResourceEvent,
    SymbolRecord,
)
from lima.cxx_retrieval import (
    SCORE_ALLOCATION,
    SCORE_CALL_NEIGHBORHOOD,
    SCORE_LENGTH_API,
    SCORE_PR_CHANGED,
    SCORE_PR_NEIGHBOR,
    SCORE_RELEASE,
    SEED_ALLOCATION,
    SEED_CALL_NEIGHBORHOOD,
    SEED_LENGTH_API,
    SEED_PR_CHANGED,
    SEED_REASONS,
    SEED_RELEASE,
    RetrievalBudget,
    RetrievalCandidate,
    RetrievalContextFile,
    RetrievalRun,
    retrieve_pull_request,
    retrieve_repository,
)
from lima.workspace import RepositoryWorkspace


def sym(name, path, start, end, kind="function", language="c"):
    return SymbolRecord(
        qualified_name=name,
        file=path,
        start_line=start,
        end_line=end,
        kind=kind,
        language=language,
    )


def make_index(*, symbols=(), calls=(), references=(), resource_events=(), sha="a" * 64):
    symbols = tuple(symbols)
    return CxxContextIndex(
        snapshot_sha256=sha,
        symbols=symbols,
        types=(),
        calls=tuple(calls),
        references=tuple(references),
        resource_events=tuple(resource_events),
        coverage=IndexCoverage(
            indexed=(),
            parse_gaps=(),
            source_files_total=0,
            symbols_indexed=len(symbols),
            types_indexed=0,
            calls_indexed=len(tuple(calls)),
            resource_events_indexed=len(tuple(resource_events)),
        ),
    )


def build_pr_index():
    return make_index(
        symbols=[
            sym("Session::read", "src/session.cpp", 40, 60, kind="method", language="c++"),
            sym("read_wrapper", "src/wrapper.c", 5, 8),
            sym("make_buffer", "src/buffer.c", 10, 20),
        ],
        calls=[
            CallEdge("read_wrapper", "read", "src/wrapper.c", 6),
            CallEdge("Session::read", "memcpy", "src/session.cpp", 50),
        ],
        references=[ApiReference("memcpy", "Session::read", "src/session.cpp", 50)],
        resource_events=[
            ResourceEvent("allocate", "malloc", "make_buffer", "src/buffer.c", 12),
        ],
    )


class RetrievalBudgetTests(unittest.TestCase):
    def test_defaults_match_task_limits(self):
        budget = RetrievalBudget()
        self.assertEqual(100, budget.max_candidates)
        self.assertEqual(12, budget.max_context_files)
        self.assertEqual(1200, budget.max_context_lines)

    def test_non_positive_or_non_integer_limits_are_rejected(self):
        for kwargs in (
            {"max_candidates": 0},
            {"max_candidates": -1},
            {"max_context_files": 0},
            {"max_context_files": -3},
            {"max_context_lines": 0},
            {"max_context_lines": -10},
            {"max_candidates": True},
            {"max_context_lines": 2.5},
        ):
            with self.assertRaises(ValueError):
                RetrievalBudget(**kwargs)

    def test_result_records_are_frozen(self):
        run = retrieve_repository(make_index(), RetrievalBudget())
        with self.assertRaises(dataclasses.FrozenInstanceError):
            run.context_lines = 7
        candidate = RetrievalCandidate("src/a.c", 1, "f", SEED_ALLOCATION, 1)
        with self.assertRaises(dataclasses.FrozenInstanceError):
            candidate.score = 9
        context_file = RetrievalContextFile("src/a.c", 1)
        with self.assertRaises(dataclasses.FrozenInstanceError):
            context_file.allocated_lines = 2
        budget = RetrievalBudget()
        with self.assertRaises(dataclasses.FrozenInstanceError):
            budget.max_candidates = 5


class RepositoryRetrievalTests(unittest.TestCase):
    def test_allocation_and_release_events_become_candidates(self):
        index = make_index(
            symbols=[
                sym("make_buffer", "src/buffer.c", 10, 20),
                sym("release_buffer", "src/buffer.c", 30, 40),
                sym("untouched", "src/other.c", 1, 5),
            ],
            resource_events=[
                ResourceEvent("allocate", "malloc", "make_buffer", "src/buffer.c", 12),
                ResourceEvent("release", "free", "release_buffer", "src/buffer.c", 32),
            ],
        )
        run = retrieve_repository(index, RetrievalBudget())
        self.assertEqual(
            {
                ("src/buffer.c", 10, "make_buffer", SEED_ALLOCATION, SCORE_ALLOCATION),
                ("src/buffer.c", 30, "release_buffer", SEED_RELEASE, SCORE_RELEASE),
            },
            {(c.path, c.line, c.symbol, c.seed_reason, c.score) for c in run.candidates},
        )

    def test_boundary_length_apis_become_candidates(self):
        index = make_index(
            symbols=[sym("fill_header", "src/protocol.c", 4, 18)],
            references=[ApiReference("memset", "fill_header", "src/protocol.c", 9)],
        )
        run = retrieve_repository(index, RetrievalBudget())
        self.assertEqual(1, len(run.candidates))
        candidate = run.candidates[0]
        self.assertEqual(
            ("src/protocol.c", 4, "fill_header"),
            (candidate.path, candidate.line, candidate.symbol),
        )
        self.assertEqual(SEED_LENGTH_API, candidate.seed_reason)
        self.assertEqual(SCORE_LENGTH_API, candidate.score)

    def test_scores_add_across_sources_with_priority_seed(self):
        index = make_index(
            symbols=[sym("copy_into", "src/copy.c", 2, 12)],
            references=[ApiReference("memcpy", "copy_into", "src/copy.c", 5)],
            resource_events=[
                ResourceEvent("allocate", "malloc", "copy_into", "src/copy.c", 4),
                ResourceEvent("release", "free", "copy_into", "src/copy.c", 8),
            ],
        )
        run = retrieve_repository(index, RetrievalBudget())
        self.assertEqual(1, len(run.candidates))
        candidate = run.candidates[0]
        self.assertEqual(SEED_ALLOCATION, candidate.seed_reason)
        self.assertEqual(
            SCORE_ALLOCATION + SCORE_RELEASE + SCORE_LENGTH_API, candidate.score
        )

    def test_call_neighbors_of_resource_functions_become_candidates(self):
        index = make_index(
            symbols=[
                sym("make_buffer", "src/buffer.c", 10, 20),
                sym("ensure_space", "src/buffer.c", 21, 30),
                sym("use_buffer", "src/use.c", 5, 9),
            ],
            resource_events=[
                ResourceEvent("allocate", "malloc", "make_buffer", "src/buffer.c", 12),
            ],
            calls=[
                CallEdge("use_buffer", "make_buffer", "src/use.c", 6),
                CallEdge("make_buffer", "ensure_space", "src/buffer.c", 13),
                CallEdge("make_buffer", "external_thing", "src/buffer.c", 14),
            ],
        )
        run = retrieve_repository(index, RetrievalBudget())
        self.assertEqual(
            {
                ("src/buffer.c", 10, "make_buffer", SEED_ALLOCATION, SCORE_ALLOCATION),
                (
                    "src/buffer.c", 21, "ensure_space",
                    SEED_CALL_NEIGHBORHOOD, SCORE_CALL_NEIGHBORHOOD,
                ),
                (
                    "src/use.c", 5, "use_buffer",
                    SEED_CALL_NEIGHBORHOOD, SCORE_CALL_NEIGHBORHOOD,
                ),
            },
            {(c.path, c.line, c.symbol, c.seed_reason, c.score) for c in run.candidates},
        )


class PullRequestRetrievalTests(unittest.TestCase):
    def test_changed_symbols_expand_to_direct_callers(self):
        run = retrieve_pull_request(
            build_pr_index(), {"src/session.cpp": [55, 55, 57]}, RetrievalBudget()
        )
        self.assertEqual(
            {
                (
                    "src/session.cpp", 40, "Session::read",
                    SEED_PR_CHANGED, SCORE_PR_CHANGED + SCORE_LENGTH_API,
                ),
                (
                    "src/wrapper.c", 5, "read_wrapper",
                    SEED_CALL_NEIGHBORHOOD, SCORE_PR_NEIGHBOR,
                ),
                ("src/buffer.c", 10, "make_buffer", SEED_ALLOCATION, SCORE_ALLOCATION),
            },
            {(c.path, c.line, c.symbol, c.seed_reason, c.score) for c in run.candidates},
        )
        self.assertEqual(
            ["Session::read", "make_buffer", "read_wrapper"],
            [c.symbol for c in run.candidates],
        )
        self.assertEqual(0, run.unassigned_changed_lines)

    def test_changed_lines_outside_symbols_are_reported(self):
        index = build_pr_index()
        run = retrieve_pull_request(
            index, {"src/session.cpp": [200], "src/nowhere.c": [3]}, RetrievalBudget()
        )
        self.assertEqual(2, run.unassigned_changed_lines)
        self.assertEqual(
            {
                (
                    "src/session.cpp", 40, "Session::read",
                    SEED_LENGTH_API, SCORE_LENGTH_API,
                ),
                ("src/buffer.c", 10, "make_buffer", SEED_ALLOCATION, SCORE_ALLOCATION),
            },
            {(c.path, c.line, c.symbol, c.seed_reason, c.score) for c in run.candidates},
        )
        duplicated = retrieve_pull_request(
            index, {"src/nowhere.c": [7, 7]}, RetrievalBudget()
        )
        self.assertEqual(1, duplicated.unassigned_changed_lines)

    def test_invalid_pull_request_inputs_are_rejected(self):
        index = build_pr_index()
        for changed in (
            {"/abs/path.c": [1]},
            {"C:/abs/path.c": [1]},
            {"src\\..\\escape.c": [1]},
            {"src/../escape.c": [1]},
            {"src/ok.c": [0]},
            {"src/ok.c": [-1]},
            {"src/ok.c": ["3"]},
            [("src/ok.c", [1])],
        ):
            with self.assertRaises(ValueError):
                retrieve_pull_request(index, changed, RetrievalBudget())


class DeterminismTests(unittest.TestCase):
    def test_equal_scores_tie_break_lexicographically_not_by_labels(self):
        index = make_index(
            symbols=[
                sym("vulnerable_xxx", "src/tie.c", 7, 9),
                sym("aaa_yyy", "src/tie.c", 7, 9),
            ],
            resource_events=[
                ResourceEvent("allocate", "malloc", "vulnerable_xxx", "src/tie.c", 8),
                ResourceEvent("allocate", "malloc", "aaa_yyy", "src/tie.c", 8),
            ],
        )
        run = retrieve_repository(index, RetrievalBudget())
        self.assertEqual(2, len(run.candidates))
        self.assertEqual(3, run.candidates[0].score)
        self.assertEqual(3, run.candidates[1].score)
        self.assertEqual(
            ["aaa_yyy", "vulnerable_xxx"], [c.symbol for c in run.candidates]
        )

    def test_repeated_calls_return_equal_runs(self):
        index = build_pr_index()
        budget = RetrievalBudget()
        changed = {"src/session.cpp": [42]}
        self.assertEqual(
            retrieve_pull_request(index, changed, budget),
            retrieve_pull_request(index, changed, budget),
        )
        self.assertEqual(
            retrieve_repository(index, budget),
            retrieve_repository(index, budget),
        )

    def test_seed_reasons_stay_within_the_fixed_vocabulary(self):
        self.assertEqual(
            {
                "pr-changed-symbol",
                "allocation-event",
                "release-event",
                "length-api",
                "call-neighborhood",
            },
            set(SEED_REASONS),
        )
        run = retrieve_pull_request(
            build_pr_index(), {"src/session.cpp": [42]}, RetrievalBudget()
        )
        for candidate in run.candidates:
            self.assertIn(candidate.seed_reason, SEED_REASONS)


class BudgetLimitTests(unittest.TestCase):
    def test_candidate_cap_truncates_and_counts_uncovered(self):
        names = [f"f_{i:03d}" for i in range(1, 151)]
        symbols = [sym(name, "src/many.c", i, i) for i, name in enumerate(names, 1)]
        events = [
            ResourceEvent("allocate", "malloc", name, "src/many.c", i)
            for i, name in enumerate(names, 1)
        ]
        run = retrieve_repository(
            make_index(symbols=symbols, resource_events=events), RetrievalBudget()
        )
        self.assertEqual(100, len(run.candidates))
        self.assertEqual(50, run.uncovered_candidates)
        self.assertEqual(1, run.candidates[0].line)
        self.assertEqual(100, run.candidates[99].line)
        self.assertEqual(1, len(run.context_files))
        self.assertEqual(100, run.context_lines)
        self.assertEqual(0, run.uncovered_files)

    def test_file_cap_counts_uncovered_files(self):
        symbols = [
            sym(f"f_{i:02d}", f"src/f{i:02d}.c", 1, 10) for i in range(15)
        ]
        events = [
            ResourceEvent("allocate", "malloc", f"f_{i:02d}", f"src/f{i:02d}.c", 2)
            for i in range(15)
        ]
        run = retrieve_repository(
            make_index(symbols=symbols, resource_events=events), RetrievalBudget()
        )
        self.assertEqual(15, len(run.candidates))
        self.assertEqual(0, run.uncovered_candidates)
        self.assertEqual(12, len(run.context_files))
        self.assertEqual(3, run.uncovered_files)
        self.assertEqual(120, run.context_lines)

    def test_line_budget_truncates_allocation_and_leaves_files_uncovered(self):
        index = make_index(
            symbols=[sym("big", "src/a.c", 1, 100), sym("small", "src/b.c", 1, 5)],
            resource_events=[
                ResourceEvent("allocate", "malloc", "big", "src/a.c", 2),
                ResourceEvent("allocate", "malloc", "small", "src/b.c", 2),
            ],
        )
        run = retrieve_repository(index, RetrievalBudget(max_context_lines=10))
        self.assertEqual(2, len(run.candidates))
        self.assertEqual(0, run.uncovered_candidates)
        self.assertEqual(10, run.context_lines)
        self.assertEqual(1, len(run.context_files))
        self.assertEqual(
            ("src/a.c", 10),
            (run.context_files[0].path, run.context_files[0].allocated_lines),
        )
        self.assertEqual(1, run.uncovered_files)

    def test_context_files_report_merged_allocated_lines(self):
        index = make_index(
            symbols=[
                sym("first", "src/x.c", 1, 10),
                sym("second", "src/x.c", 5, 8),
                sym("third", "src/y.c", 5, 15),
            ],
            resource_events=[
                ResourceEvent("allocate", "malloc", "first", "src/x.c", 2),
                ResourceEvent("allocate", "malloc", "second", "src/x.c", 6),
                ResourceEvent("allocate", "malloc", "third", "src/y.c", 6),
            ],
        )
        run = retrieve_repository(index, RetrievalBudget())
        self.assertEqual(
            [("src/x.c", 10), ("src/y.c", 11)],
            [(f.path, f.allocated_lines) for f in run.context_files],
        )
        self.assertEqual(21, run.context_lines)
        self.assertEqual(
            sum(f.allocated_lines for f in run.context_files), run.context_lines
        )


LABELED_NAMES = (
    "parse_vulnerable_header_CVE_2024_0001",
    "fixed_release_path",
    "helper_vulnerable",
)
NEUTRAL_NAMES = ("parse_input_header", "other_release_path", "helper_worker")


def paired_index(names):
    parser, releaser, helper = names
    return make_index(
        sha="c" * 64,
        symbols=[
            sym(parser, "src/parse.c", 10, 30),
            sym(releaser, "src/parse.c", 40, 60),
            sym(helper, "src/parse.c", 70, 80),
        ],
        calls=[
            CallEdge(parser, helper, "src/parse.c", 15),
            CallEdge(releaser, helper, "src/parse.c", 45),
        ],
        references=[ApiReference("memcpy", parser, "src/parse.c", 20)],
        resource_events=[
            ResourceEvent("release", "free", releaser, "src/parse.c", 50),
            ResourceEvent("allocate", "malloc", helper, "src/parse.c", 72),
        ],
    )


def projection(run):
    return [(c.path, c.line, c.seed_reason, c.score) for c in run.candidates]


class LabelBlindnessTests(unittest.TestCase):
    def test_label_like_metadata_never_changes_retrieval_output(self):
        budget = RetrievalBudget()
        changed = {"src/parse.c": [12]}
        labeled_repo = retrieve_repository(paired_index(LABELED_NAMES), budget)
        neutral_repo = retrieve_repository(paired_index(NEUTRAL_NAMES), budget)
        self.assertEqual(projection(neutral_repo), projection(labeled_repo))
        self.assertEqual(neutral_repo.context_files, labeled_repo.context_files)
        self.assertEqual(
            (
                neutral_repo.context_lines,
                neutral_repo.uncovered_candidates,
                neutral_repo.uncovered_files,
                neutral_repo.unassigned_changed_lines,
            ),
            (
                labeled_repo.context_lines,
                labeled_repo.uncovered_candidates,
                labeled_repo.uncovered_files,
                labeled_repo.unassigned_changed_lines,
            ),
        )
        labeled_pr = retrieve_pull_request(paired_index(LABELED_NAMES), changed, budget)
        neutral_pr = retrieve_pull_request(paired_index(NEUTRAL_NAMES), changed, budget)
        self.assertEqual(projection(neutral_pr), projection(labeled_pr))
        self.assertEqual(neutral_pr.context_files, labeled_pr.context_files)

    def test_tie_channel_stays_lexicographic_under_label_names(self):
        index = make_index(
            symbols=[
                sym("helper_CVE_2024_0001_vulnerable", "src/tie.c", 7, 9),
                sym("aaa_helper", "src/tie.c", 7, 9),
            ],
            resource_events=[
                ResourceEvent(
                    "allocate", "malloc",
                    "helper_CVE_2024_0001_vulnerable", "src/tie.c", 8,
                ),
                ResourceEvent("allocate", "malloc", "aaa_helper", "src/tie.c", 8),
            ],
        )
        run = retrieve_repository(index, RetrievalBudget())
        self.assertEqual(2, len(run.candidates))
        self.assertEqual(SCORE_ALLOCATION, run.candidates[0].score)
        self.assertEqual(
            run.candidates[0].score, run.candidates[1].score
        )
        self.assertEqual(
            ["aaa_helper", "helper_CVE_2024_0001_vulnerable"],
            [c.symbol for c in run.candidates],
        )

    def test_candidate_schema_carries_no_label_fields(self):
        self.assertEqual(
            ("path", "line", "symbol", "seed_reason", "score"),
            tuple(field.name for field in dataclasses.fields(RetrievalCandidate)),
        )
        self.assertEqual(
            (
                "candidates",
                "context_files",
                "context_lines",
                "uncovered_candidates",
                "uncovered_files",
                "snapshot_sha256",
                "unassigned_changed_lines",
            ),
            tuple(field.name for field in dataclasses.fields(RetrievalRun)),
        )


class EmptyInputTests(unittest.TestCase):
    def test_empty_index_returns_empty_run(self):
        run = retrieve_repository(make_index(sha="d" * 64), RetrievalBudget())
        self.assertEqual((), run.candidates)
        self.assertEqual((), run.context_files)
        self.assertEqual(0, run.context_lines)
        self.assertEqual(0, run.uncovered_candidates)
        self.assertEqual(0, run.uncovered_files)
        self.assertEqual(0, run.unassigned_changed_lines)
        self.assertEqual("d" * 64, run.snapshot_sha256)

    def test_empty_change_set_returns_empty_run(self):
        run = retrieve_pull_request(build_pr_index(), {}, RetrievalBudget())
        self.assertEqual((), run.candidates)
        self.assertEqual((), run.context_files)
        self.assertEqual(0, run.context_lines)
        self.assertEqual(0, run.unassigned_changed_lines)

    def test_changes_on_empty_index_count_as_unassigned(self):
        run = retrieve_pull_request(
            make_index(), {"src/new.c": [3]}, RetrievalBudget()
        )
        self.assertEqual((), run.candidates)
        self.assertEqual((), run.context_files)
        self.assertEqual(1, run.unassigned_changed_lines)


FIXTURES = Path(__file__).parent / "fixtures" / "cxx_agent_context"


def build_fixture_index():
    workspace = RepositoryWorkspace(FIXTURES)
    return CxxContextIndex.build(workspace, workspace.inventory())


class EndToEndFixtureTests(unittest.TestCase):
    """Guards the retrieval contract against CxxContextIndex drift."""

    @classmethod
    def setUpClass(cls):
        cls.index = build_fixture_index()

    def _changed_lines(self):
        symbol = next(
            record
            for record in self.index.symbols
            if record.qualified_name == "make_buffer"
        )
        return {symbol.file: [symbol.start_line]}

    def test_repository_retrieval_over_real_fixture_index(self):
        run = retrieve_repository(self.index, RetrievalBudget())
        self.assertTrue(run.candidates)
        self.assertTrue(run.context_files)
        indexed = set(self.index.coverage.indexed)
        for candidate in run.candidates:
            self.assertIn(candidate.path, indexed, candidate.symbol)
            self.assertIn(candidate.seed_reason, SEED_REASONS)
        for context_file in run.context_files:
            self.assertIn(context_file.path, indexed)
        self.assertEqual(
            sum(f.allocated_lines for f in run.context_files), run.context_lines
        )
        self.assertGreater(run.context_lines, 0)
        self.assertEqual(self.index.snapshot_sha256, run.snapshot_sha256)
        self.assertEqual(0, run.uncovered_candidates)
        self.assertEqual(0, run.uncovered_files)

    def test_pull_request_expansion_over_real_fixture_index(self):
        run = retrieve_pull_request(
            self.index, self._changed_lines(), RetrievalBudget()
        )
        self.assertTrue(run.candidates)
        changed = [
            c for c in run.candidates if c.seed_reason == SEED_PR_CHANGED
        ]
        self.assertEqual(1, len(changed))
        self.assertEqual("make_buffer", changed[0].symbol)
        self.assertEqual(0, run.unassigned_changed_lines)
        indexed = set(self.index.coverage.indexed)
        for candidate in run.candidates:
            self.assertIn(candidate.path, indexed, candidate.symbol)

    def test_real_fixture_retrieval_is_deterministic(self):
        changed = self._changed_lines()
        self.assertEqual(
            retrieve_repository(self.index, RetrievalBudget()),
            retrieve_repository(self.index, RetrievalBudget()),
        )
        self.assertEqual(
            retrieve_pull_request(self.index, changed, RetrievalBudget()),
            retrieve_pull_request(self.index, changed, RetrievalBudget()),
        )


if __name__ == "__main__":
    unittest.main()
