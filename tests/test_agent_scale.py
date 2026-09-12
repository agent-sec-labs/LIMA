"""Scaling facilities tests (plan Task 9).

Design section 8 (``docs/superpowers/specs/2026-09-12-agent-vuln-platform-
design.md``): caching (snapshot + input-hash keys), bounded parallelism that
never changes the deterministic result order, and change detection between
two content inventories.  Zero network: the orchestrator roundtrip reuses the
offline harness of ``test_agent_orchestrator`` (scripted transports and a
scripted ``run_experiment`` double).  Red lines pinned here:

- Cache keys are deterministic for identical inputs, isolated by namespace,
  self-healing on corrupt entries and atomic on write.
- Parallelism affects the wall clock only: results are aggregated in
  ``order_key`` order, failures are collected (never swallowed) and the
  thread count never exceeds ``min(parallelism, len(items))``.
- ``detect_changed_files`` is a pure three-way diff with sorted, stable
  output.
- Feeding a ``ResultCache`` into :func:`run_platform_review` replays the
  cached per-target outcomes with zero Specialist/Critic wire calls and zero
  sandbox experiments, and the outcome is dataclass-equal to the fresh run.
"""

import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from lima.agent_orchestrator import run_platform_review
from lima.agent_scale import (
    ResultCache,
    ScaledFailure,
    detect_changed_files,
    map_bounded,
)
from lima.cxx_agent_tools import CxxAgentBudget

# The offline platform harness lives in the sibling test module; make the
# import work for both ``unittest discover -s tests`` and
# ``python -m unittest tests.test_agent_scale`` invocations.
sys.path.insert(0, str(Path(__file__).resolve().parent))
import test_agent_orchestrator as harness  # noqa: E402

# ---------------------------------------------------------------- helpers


class _Recorder:
    """Counts concurrent executions and tracks the observed peak."""

    def __init__(self):
        self._lock = threading.Lock()
        self._active = 0
        self.peak = 0
        self.calls = 0

    def __call__(self, item):
        with self._lock:
            self._active += 1
            self.calls += 1
            self.peak = max(self.peak, self._active)
        time.sleep(0.03)
        with self._lock:
            self._active -= 1
        return item * 10


def _identity_key(item):
    return item


# ------------------------------------------------------------ ResultCache


class ResultCacheTests(unittest.TestCase):
    """Deterministic snapshot + input-hash keyed cache semantics."""

    def test_put_get_roundtrip(self):
        cache = ResultCache(Path(tempfile.mkdtemp(suffix="-cache")), "ns")
        key = cache.key_for("snapshot=abc", "target=lead-001")
        cache.put(key, {"state": "runtime-confirmed", "line": 30})
        self.assertEqual(
            {"state": "runtime-confirmed", "line": 30}, cache.get(key),
        )
        self.assertEqual({"hits": 1, "misses": 0}, cache.stats())

    def test_key_is_stable_and_order_insensitive(self):
        cache = ResultCache(Path(tempfile.mkdtemp(suffix="-cache")), "ns")
        first = cache.key_for("a", "b", "c")
        second = cache.key_for("c", "b", "a")
        self.assertEqual(first, second)
        self.assertEqual(64, len(first))
        self.assertNotEqual(first, cache.key_for("a", "b", "d"))

    def test_namespace_isolates_identical_inputs(self):
        root = Path(tempfile.mkdtemp(suffix="-cache"))
        left = ResultCache(root, "platform-review-v1")
        right = ResultCache(root, "platform-review-v2")
        self.assertNotEqual(left.key_for("x"), right.key_for("x"))

    def test_miss_returns_none_and_counts(self):
        cache = ResultCache(Path(tempfile.mkdtemp(suffix="-cache")), "ns")
        self.assertIsNone(cache.get(cache.key_for("absent")))
        self.assertEqual({"hits": 0, "misses": 1}, cache.stats())

    def test_corrupt_entry_self_heals(self):
        root = Path(tempfile.mkdtemp(suffix="-cache"))
        cache = ResultCache(root, "ns")
        key = cache.key_for("k")
        corrupt = root / f"{key}.json"
        corrupt.write_text("{not json", encoding="utf-8")
        self.assertIsNone(cache.get(key))
        self.assertFalse(corrupt.exists(), "the corrupt entry must be deleted")
        self.assertEqual({"hits": 0, "misses": 1}, cache.stats())
        cache.put(key, {"recovered": True})
        self.assertEqual({"recovered": True}, cache.get(key))

    def test_entries_persist_across_instances(self):
        root = Path(tempfile.mkdtemp(suffix="-cache"))
        writer = ResultCache(root, "ns")
        key = writer.key_for("snapshot=s1")
        writer.put(key, {"state": "abstain"})
        reader = ResultCache(root, "ns")
        self.assertEqual({"state": "abstain"}, reader.get(key))
        self.assertEqual({"hits": 1, "misses": 0}, reader.stats())


# ------------------------------------------------------------ map_bounded


class MapBoundedTests(unittest.TestCase):
    """Bounded parallelism that never changes the deterministic order."""

    def test_parallel_results_equal_sequential_results(self):
        items = [5, 3, 9, 1, 7, 2, 8, 4, 6]
        sequential, sequential_failures = map_bounded(
            _Recorder(), items, 1, order_key=_identity_key,
        )
        parallel, parallel_failures = map_bounded(
            _Recorder(), items, 4, order_key=_identity_key,
        )
        self.assertEqual(sequential, parallel)
        self.assertEqual(sequential_failures, parallel_failures)
        self.assertEqual([item * 10 for item in sorted(items)], sequential)

    def test_results_follow_order_key_not_completion(self):
        # Earlier items sleep longer, so completion order is reversed; the
        # aggregation must still follow order_key.
        def slow_first(item):
            time.sleep(0.02 * (4 - item))
            return item

        results, failures = map_bounded(
            slow_first, [3, 2, 1], 3, order_key=_identity_key,
        )
        self.assertEqual([1, 2, 3], results)
        self.assertEqual([], failures)

    def test_failures_are_collected_not_swallowed(self):
        def fail_on_even(item):
            if item % 2 == 0:
                raise ValueError(f"boom {item}")
            return item

        items = [4, 1, 3, 2]
        results, failures = map_bounded(
            fail_on_even, items, 2, order_key=_identity_key,
        )
        self.assertEqual([1, 3], results)
        self.assertEqual(2, len(failures))
        self.assertTrue(
            all(isinstance(failure, ScaledFailure) for failure in failures),
        )
        self.assertEqual(
            [2, 4], [failure.item for failure in failures],
            "failures must be reported in order_key order too",
        )
        self.assertEqual("boom 2", str(failures[0].exception))

    def test_thread_count_is_capped_at_parallelism(self):
        recorder = _Recorder()
        results, failures = map_bounded(
            recorder, list(range(9)), 3, order_key=_identity_key,
        )
        self.assertEqual(9, len(results))
        self.assertEqual([], failures)
        self.assertLessEqual(recorder.peak, 3)
        self.assertGreater(recorder.peak, 1, "parallelism must actually run")

    def test_threads_never_exceed_item_count(self):
        recorder = _Recorder()
        results, failures = map_bounded(
            recorder, [1, 2], 8, order_key=_identity_key,
        )
        self.assertEqual([10, 20], results)
        self.assertEqual([], failures)
        self.assertLessEqual(recorder.peak, 2)

    def test_empty_items(self):
        results, failures = map_bounded(lambda item: item, [], 4, order_key=str)
        self.assertEqual([], results)
        self.assertEqual([], failures)

    def test_invalid_parallelism_rejected(self):
        for bad in (0, -1, True, 1.5, "4"):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    map_bounded(lambda item: item, [1], bad, order_key=str)


# ---------------------------------------------------- detect_changed_files


class DetectChangedFilesTests(unittest.TestCase):
    """Pure three-way inventory diff with sorted stable output."""

    def test_added_modified_removed_are_detected(self):
        old = {"src/a.cpp": "aa", "src/b.cpp": "bb", "src/c.cpp": "cc"}
        new = {"src/b.cpp": "bb", "src/c.cpp": "cd", "src/d.cpp": "dd"}
        added, modified, removed = detect_changed_files(old, new)
        self.assertEqual(("src/d.cpp",), added)
        self.assertEqual(("src/c.cpp",), modified)
        self.assertEqual(("src/a.cpp",), removed)

    def test_identical_inventories_yield_empty_diff(self):
        inventory = {"src/a.cpp": "aa", "src/b.cpp": "bb"}
        added, modified, removed = detect_changed_files(inventory, dict(inventory))
        self.assertEqual((), added)
        self.assertEqual((), modified)
        self.assertEqual((), removed)

    def test_output_is_sorted_and_deterministic(self):
        old = {"z.cpp": "1", "a.cpp": "1", "m.cpp": "1", "gone.cpp": "1"}
        new = {"z.cpp": "2", "a.cpp": "2", "m.cpp": "2", "new2.cpp": "x",
               "new1.cpp": "x"}
        added, modified, removed = detect_changed_files(old, new)
        self.assertEqual(("new1.cpp", "new2.cpp"), added)
        self.assertEqual(("a.cpp", "m.cpp", "z.cpp"), modified)
        self.assertEqual(("gone.cpp",), removed)
        again = detect_changed_files(old, new)
        self.assertEqual((added, modified, removed), again)

    def test_invalid_inventories_rejected(self):
        for old, new in (
            ({"": "aa"}, {}),
            ({"a.cpp": ""}, {}),
            ({"a.cpp": 5}, {}),
            ([("a.cpp", "aa")], {}),
            ({"a.cpp": "aa"}, {"a.cpp": None}),
        ):
            with self.subTest(old=old, new=new):
                with self.assertRaises(ValueError):
                    detect_changed_files(old, new)


# ------------------------------------------------- orchestrator integration


class _NoExperimentWorkbench:
    """Guards the cache roundtrip: any experiment call fails the test."""

    def run_experiment(self, *args, **kwargs):
        raise AssertionError("a cache hit must not run sandbox experiments")


class OrchestratorParallelEquivalenceTests(unittest.TestCase):
    """run_platform_review(parallelism>1) preserves the deterministic order."""

    def test_parallel_outcome_equals_sequential_outcome(self):
        # Two leads escalate to two targets; the scripted per-role replies
        # are identical for every target, so the outcome cannot depend on
        # scheduling.  Both runs must aggregate in Scout target order.
        second_lead = harness.ScoutLead(
            lead_id="lead-002",
            path=harness.UNIT,
            line=14,
            summary="release of p at line 20 precedes the use at line 30",
            seed="uaf-release-event",
            score=0,
        )
        workbench_observations = [
            harness.clean_run(),
            harness.clean_run(),
            harness.clean_run(),
            harness.clean_run(),
        ]

        def _run(parallelism):
            root = tempfile.mkdtemp(suffix="-agent-scale-parallel")
            workspace = harness._write_cxx_repo(root)
            transport = harness.ScriptedPlatformTransport(
                # One identical reply per target: scheduling cannot change
                # which script a target consumes.
                specialist=[harness.hypothesis_json(), harness.hypothesis_json()],
                critic=[harness.critic_json(), harness.critic_json()],
            )
            try:
                with (
                    patch(
                        "lima.agent_scout.post_chat_completion_text",
                        harness.scout_target_transport([]),
                    ),
                    patch(
                        "lima.uaf_llm_branch.post_chat_completion_text",
                        transport,
                    ),
                ):
                    return run_platform_review(
                        harness.FakeUafAnalyzer(),
                        workspace,
                        repository_key=harness.REPO_KEY,
                        snapshot_hash=harness.SNAPSHOT,
                        translation_units=(harness.UNIT,),
                        mode="auto",
                        budget=CxxAgentBudget(
                            max_calls=64, max_output_bytes=1_048_576,
                        ),
                        llm_config=dict(harness.RESOLVED_LLM),
                        repro_workbench=harness.FakeWorkbench(
                            list(workbench_observations),
                        ),
                        leads=(harness.LEAD, second_lead),
                        dialogue_rounds=1,
                        source_mode="repository",
                        parallelism=parallelism,
                    )
            finally:
                harness._rmtree(root)

        sequential = _run(1)
        parallel = _run(4)
        # The Scout's deterministic target order is
        # (confidence, path, line): line 14 escalates before line 30.
        self.assertEqual(
            ["lead-002", "lead-001"],
            [target.target_id for target in sequential.targets],
        )
        self.assertEqual(sequential, parallel)
        self.assertEqual(2, parallel.stats.target_count)
        self.assertEqual(2, parallel.stats.specialist_calls)
        self.assertEqual(2, parallel.stats.experiment_count)


class OrchestratorCacheRoundtripTests(unittest.TestCase):
    """run_platform_review(cache=...) replays targets without new work."""

    def test_orchestrator_cache_roundtrip(self):
        root = tempfile.mkdtemp(suffix="-agent-scale-cache")
        cache_dir = Path(root) / "scale-cache"
        workspace = harness._write_cxx_repo(root)
        first_cache = ResultCache(cache_dir, "platform-review-v1")
        first_transport = harness.ScriptedPlatformTransport(
            specialist=[harness.hypothesis_json(driver="int first() { return 0; }")],
            critic=[harness.critic_json(
                assessment="revise-experiment",
                revised_driver="int revised() { FREE_THEN_USE; }",
            )],
        )
        first_workbench = harness.FakeWorkbench(
            [harness.clean_run(), harness.uaf_hit()],
        )
        try:
            with (
                patch(
                    "lima.agent_scout.post_chat_completion_text",
                    harness.scout_target_transport([]),
                ),
                patch(
                    "lima.uaf_llm_branch.post_chat_completion_text",
                    first_transport,
                ),
            ):
                first = run_platform_review(
                    harness.FakeUafAnalyzer(),
                    workspace,
                    repository_key=harness.REPO_KEY,
                    snapshot_hash=harness.SNAPSHOT,
                    translation_units=(harness.UNIT,),
                    mode="auto",
                    budget=CxxAgentBudget(
                        max_calls=64, max_output_bytes=1_048_576,
                    ),
                    llm_config=dict(harness.RESOLVED_LLM),
                    repro_workbench=first_workbench,
                    leads=(harness.LEAD,),
                    dialogue_rounds=1,
                    source_mode="repository",
                    cache=first_cache,
                )
            self.assertEqual(1, len(first.targets))
            self.assertEqual("runtime-confirmed", first.targets[0].state)
            self.assertEqual(1, len(first.findings))
            self.assertEqual({"hits": 0, "misses": 1}, first_cache.stats())
            self.assertEqual(2, first.stats.experiment_count)
            self.assertEqual(1, first.stats.specialist_calls)
            self.assertEqual(1, first.stats.critic_calls)

            # Second run over the same cache directory: a guard transport
            # and a guard workbench fail the test on any LLM/experiment
            # call, proving the target replay came from the cache.
            guard_transport = harness.GuardTransport()
            second_cache = ResultCache(cache_dir, "platform-review-v1")
            with (
                patch(
                    "lima.agent_scout.post_chat_completion_text",
                    harness.scout_target_transport([]),
                ),
                patch(
                    "lima.uaf_llm_branch.post_chat_completion_text",
                    guard_transport,
                ),
            ):
                second = run_platform_review(
                    harness.FakeUafAnalyzer(),
                    workspace,
                    repository_key=harness.REPO_KEY,
                    snapshot_hash=harness.SNAPSHOT,
                    translation_units=(harness.UNIT,),
                    mode="auto",
                    budget=CxxAgentBudget(
                        max_calls=64, max_output_bytes=1_048_576,
                    ),
                    llm_config=dict(harness.RESOLVED_LLM),
                    repro_workbench=_NoExperimentWorkbench(),
                    leads=(harness.LEAD,),
                    dialogue_rounds=1,
                    source_mode="repository",
                    cache=second_cache,
                )
        finally:
            harness._rmtree(root)
        self.assertEqual([], guard_transport.calls)
        self.assertEqual(first.targets, second.targets)
        self.assertEqual(
            first.stats.experiment_count, second.stats.experiment_count,
        )
        self.assertEqual(0, second.stats.specialist_calls)
        self.assertEqual(0, second.stats.critic_calls)
        self.assertEqual({"hits": 1, "misses": 0}, second_cache.stats())


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
