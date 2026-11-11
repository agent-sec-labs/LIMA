"""Webhook recovery keeps one durable logical task across publication failures."""

import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from contextlib import nullcontext
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from lima.config import Settings
from lima.rollout import ReleaseManager
from lima.service import ReviewService
from lima.store import TaskStore
from lima.task_queue import PermanentTaskError, TaskQueue


def event():
    return {
        "action": "opened",
        "number": 8,
        "repository": {"full_name": "org/repo"},
        "pull_request": {
            "head": {"sha": "a" * 40},
            "base": {"sha": "b" * 40},
            "diff_url": "https://github.com/org/repo/pull/8.diff",
        },
    }


class WebhookRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.store = TaskStore(str(Path(self.temp.name) / "tasks.db"))
        self.store.grant_repository("default", "org/repo", False)
        self.service = object.__new__(ReviewService)
        self.service.store = self.store
        self.service.settings = SimpleNamespace(
            default_tenant_id="default",
            auto_post_review=False,
            github_app_id="",
            github_private_key_path="",
            github_installation_tenants="{}",
        )
        self.service.releases = ReleaseManager(self.store)
        self.service.queue = SimpleNamespace(backend="redis-streams", submit=Mock())
        self.service._webhook_dispatch_lock = threading.Lock()

    def deliver(self):
        return self.service.handle_github_pull_request(event(), "delivery", "digest")

    def test_enqueue_failure_is_recovered_by_redelivery_with_same_task(self):
        self.service.queue.submit.side_effect = ConnectionError("XADD failed")
        with self.assertRaises(ConnectionError):
            self.deliver()
        first_task = self.store.list_tasks()[0]["id"]
        self.service.queue.submit.side_effect = None
        result = self.deliver()
        self.assertEqual(first_task, result["task_id"])
        self.assertEqual(2, self.service.queue.submit.call_count)
        self.assertEqual(1, len(self.store.list_tasks()))
        self.assertEqual(first_task, self.store.get_webhook("delivery")["task_id"])

    def test_ack_loss_requeues_same_logical_task(self):
        accepted = []

        def lost_ack(payload, message_id=""):
            accepted.append((payload["task_id"], message_id))
            raise ConnectionError("published, response lost")

        self.service.queue.submit.side_effect = lost_ack
        with self.assertRaises(ConnectionError):
            self.deliver()
        self.service.queue.submit.side_effect = lambda payload, message_id="": accepted.append(
            (payload["task_id"], message_id)
        )
        self.deliver()
        self.assertEqual(2, len(accepted))
        self.assertEqual(accepted[0], accepted[1])
        self.assertEqual(1, len(self.store.list_tasks()))

    def test_queue_success_followed_by_db_ack_failure_is_recoverable(self):
        with patch.object(
            self.store, "mark_webhook_dispatched", side_effect=RuntimeError("DB ACK lost")
        ):
            with self.assertRaisesRegex(RuntimeError, "DB ACK lost"):
                self.deliver()
        first = self.service.queue.submit.call_args.args[0]["task_id"]
        self.assertEqual(first, self.deliver()["task_id"])
        self.assertEqual(2, self.service.queue.submit.call_count)
        self.assertEqual([], self.store.pending_webhook_outbox())

    def test_pending_outbox_survives_store_reopen_without_redelivery(self):
        self.service.queue.submit.side_effect = ConnectionError("offline")
        with self.assertRaises(ConnectionError):
            self.deliver()
        task_id = self.store.list_tasks()[0]["id"]
        self.service.store = TaskStore(self.store.path)
        self.service.queue.submit.side_effect = None
        self.service._dispatch_webhook_outbox()
        self.assertEqual(task_id, self.service.queue.submit.call_args.args[0]["task_id"])
        self.assertEqual([], self.service.store.pending_webhook_outbox())

    def test_service_startup_automatically_dispatches_persisted_outbox(self):
        self.service.queue.submit.side_effect = ConnectionError("offline")
        with self.assertRaises(ConnectionError):
            self.deliver()
        expected_task = self.store.list_tasks()[0]["id"]
        delivered = []
        completed = threading.Event()

        def handle(payload):
            delivered.append(payload["task_id"])
            completed.set()

        settings = Settings(
            host="127.0.0.1",
            port=0,
            db_path=self.store.path,
            max_diff_bytes=10000,
            max_steps=8,
            timeout_seconds=120,
            llm_base_url="",
            llm_api_key="",
            llm_model="",
            github_webhook_secret="",
            github_token="",
            auto_post_review=False,
        )
        with patch.object(ReviewService, "_process_queued", side_effect=handle):
            restarted = ReviewService(settings)
            try:
                self.assertTrue(completed.wait(2))
                self.assertEqual([expected_task], delivered)
                self.assertEqual([], restarted.store.pending_webhook_outbox())
            finally:
                restarted.close()

    def test_concurrent_redeliveries_create_one_task(self):
        with ThreadPoolExecutor(max_workers=4) as executor:
            results = list(executor.map(lambda _: self.deliver(), range(8)))
        self.assertEqual(1, len({item["task_id"] for item in results}))
        self.assertEqual(1, len(self.store.list_tasks()))

    def test_successful_duplicate_does_not_publish_again(self):
        first = self.deliver()
        second = self.deliver()
        self.assertEqual(first["task_id"], second["task_id"])
        self.assertEqual(1, self.service.queue.submit.call_count)

    def test_transaction_rolls_back_delivery_and_task_on_outbox_failure(self):
        with self.store._connect() as conn:
            conn.execute(
                "CREATE TRIGGER fail_outbox BEFORE INSERT ON webhook_outbox "
                "BEGIN SELECT RAISE(ABORT, 'injected'); END"
            )
        with self.assertRaisesRegex(Exception, "injected"):
            self.deliver()
        self.assertEqual([], self.store.list_tasks())
        self.assertIsNone(self.store.get_webhook("delivery"))

    def test_invalid_sha_does_not_poison_delivery_id(self):
        invalid = event()
        invalid["pull_request"]["head"]["sha"] = "branch"
        with self.assertRaises(ValueError):
            self.service.handle_github_pull_request(invalid, "delivery", "digest")
        self.assertIsNone(self.store.get_webhook("delivery"))

    def test_different_payload_cannot_reuse_delivery(self):
        self.deliver()
        with self.assertRaisesRegex(ValueError, "different payload"):
            self.service.handle_github_pull_request(event(), "delivery", "other")

    def test_queue_maintenance_retries_after_failure_and_stops_on_close(self):
        queue = TaskQueue(lambda _: None, workers=1)
        recovered = threading.Event()
        attempts = []

        def maintenance():
            attempts.append(1)
            if len(attempts) == 1:
                raise ConnectionError("temporary failure")
            recovered.set()

        try:
            queue.set_maintenance(maintenance, interval=0.01)
            self.assertTrue(recovered.wait(2))
        finally:
            queue.close()
        self.assertFalse(queue._maintenance_thread.is_alive())

    def test_worker_uses_saved_commit_pair_instead_of_mutable_diff_url(self):
        self.store.create(
            "pinned",
            "org/repo",
            8,
            {
                "source": "github-webhook",
                "head_sha": "a" * 40,
                "base_sha": "b" * 40,
                "github_auth": {"mode": "pat"},
            },
        )
        diff = "--- a/a.py\n+++ b/a.py\n@@ -1 +1 @@\n-old\n+new\n"
        self.service.github = Mock()
        self.service.github.fetch_diff_at_commits.return_value = diff
        self.service.github.fetch_diff.side_effect = AssertionError(
            "mutable URL must not be fetched"
        )
        self.service.settings.max_diff_bytes = 10000
        self.service.observability = SimpleNamespace(span=lambda *a, **kw: nullcontext())
        received = []
        self.service._run_review = lambda *args: received.append(args[3]) or object()
        self.service._run_shadow = lambda *args: None
        self.service._process_queued(
            {
                "task_id": "pinned",
                "repository": "org/repo",
                "pull_request": 8,
                "diff_url": "https://github.com/org/repo/pull/8.diff",
            }
        )
        self.assertEqual([diff], received)
        self.assertEqual(diff, self.store.get_task_payload("pinned"))
        self.service.github.fetch_diff_at_commits.assert_called_once_with(
            "org/repo",
            "b" * 40,
            "a" * 40,
            max_bytes=10000,
        )

    def test_pinned_diff_metadata_and_payload_roll_back_together(self):
        self.store.create(
            "atomic-diff", "org/repo", 8, {"head_sha": "a" * 40, "base_sha": "b" * 40}
        )
        with self.store._connect() as conn:
            conn.execute(
                "CREATE TRIGGER fail_diff_metadata BEFORE UPDATE ON tasks "
                "BEGIN SELECT RAISE(ABORT, 'metadata failed'); END"
            )
        with self.assertRaisesRegex(Exception, "metadata failed"):
            self.store.save_pinned_webhook_diff("atomic-diff", "diff", "b" * 40, "a" * 40)
        self.assertIsNone(self.store.get_task_payload("atomic-diff"))
        self.assertNotIn("diff_source", self.store.get("atomic-diff")["input"])

    def test_legacy_checkpoint_without_payload_cannot_gain_pinned_provenance(self):
        self.store.create(
            "legacy",
            "org/repo",
            8,
            {
                "source": "github-webhook",
                "head_sha": "a" * 40,
                "base_sha": "b" * 40,
                "github_auth": {"mode": "pat"},
            },
        )
        self.store.save_checkpoint("legacy", "executing", {"findings": []})
        self.service.settings.max_diff_bytes = 10000
        self.service.github = Mock()
        self.service.github.fetch_diff_at_commits.side_effect = AssertionError(
            "must refuse legacy checkpoint"
        )
        with self.assertRaisesRegex(PermanentTaskError, "unpinned"):
            self.service._process_queued(
                {"task_id": "legacy", "repository": "org/repo", "pull_request": 8}
            )
