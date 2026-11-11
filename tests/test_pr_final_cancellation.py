import os
import tempfile
import unittest

from lima.harness import ReviewHarness
from lima.reviewer import LocalRuleReviewer
from lima.runtime import RuntimeCancelled
from lima.store import TaskStore

DIFF = "--- a/x.py\n+++ b/x.py\n@@ -1 +1 @@\n-old\n+eval(value)\n"


class CancelAfterFinalReviewHarness(ReviewHarness):
    """Request cancellation after the final runtime node has produced its report."""

    def _reviewing(self, state):
        result = super()._reviewing(state)
        self.store.request_cancel(state["task_id"])
        return result


class CancelBeforeAtomicSuccessStore(TaskStore):
    """Inject cancellation in the gap immediately before atomic success publication."""

    def succeed_unless_cancelled(self, task_id, report, event):
        self.request_cancel(task_id)
        return super().succeed_unless_cancelled(task_id, report, event)


class FinalCancellationTests(unittest.TestCase):
    def setUp(self):
        handle, self.path = tempfile.mkstemp(suffix=".db")
        os.close(handle)

    def tearDown(self):
        os.unlink(self.path)

    def assert_cancelled_without_report(self, store, harness_type=ReviewHarness):
        task_id = "cancel-final-review"
        store.create(task_id, "demo/repo", 7, {"source": "test"})

        with self.assertRaises(RuntimeCancelled):
            harness_type(store, LocalRuleReviewer()).run(task_id, "demo/repo", 7, DIFF)

        task = store.get(task_id)
        self.assertEqual("CANCELLED", task["state"])
        self.assertIsNone(task["report"])
        self.assertEqual(
            ["PLANNING", "EXECUTING", "REVIEWING", "CANCELLED"],
            [event["state"] for event in task["trace"]],
        )

    def test_cancellation_after_final_node_does_not_publish_success(self):
        self.assert_cancelled_without_report(
            TaskStore(self.path), CancelAfterFinalReviewHarness,
        )

    def test_cancellation_immediately_before_atomic_success_does_not_return_report(self):
        self.assert_cancelled_without_report(CancelBeforeAtomicSuccessStore(self.path))


if __name__ == "__main__":
    unittest.main()
