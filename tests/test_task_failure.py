"""Structured task failure taxonomy and retry semantics (observability epic T2)."""

from __future__ import annotations

import io
import json
import time
import unittest
import urllib.error

from lima.task_failure import (
    ARCHIVE_UNSAFE_PATH,
    FAILURE_CATALOG,
    GITHUB_AUTH_REQUIRED,
    GITHUB_NETWORK_ERROR,
    GITHUB_NOT_FOUND,
    GITHUB_RATE_LIMITED,
    GITHUB_TIMEOUT,
    QUEUE_RETRY_EXHAUSTED,
    TASK_INTERNAL_ERROR,
    TaskFailure,
    TaskFailureError,
    classify_exception,
    retry_exhausted_failure,
)
from lima.task_queue import PermanentTaskError, TaskQueue

MINIMUM_CODE_SET = {
    "GITHUB_NOT_FOUND", "GITHUB_AUTH_REQUIRED", "GITHUB_RATE_LIMITED",
    "GITHUB_NETWORK_ERROR", "GITHUB_TIMEOUT", "GITHUB_INVALID_REF",
    "ARCHIVE_TOO_LARGE", "ARCHIVE_INVALID", "ARCHIVE_UNSAFE_PATH",
    "ARCHIVE_TOO_MANY_FILES", "ARCHIVE_MEMBER_TOO_LARGE",
    "ARCHIVE_DECOMPRESSION_LIMIT",
    "CACHE_NO_SPACE", "CACHE_QUOTA_EXCEEDED", "CACHE_LOCK_TIMEOUT",
    "CACHE_PUBLISH_FAILED",
    "SAST_FAILED", "STATIC_ANALYSIS_FAILED", "SEMANTIC_TRIAGE_FAILED",
    "QUEUE_RETRY_EXHAUSTED", "TASK_INTERNAL_ERROR",
}


def http_error(code: int) -> urllib.error.HTTPError:
    return urllib.error.HTTPError(
        "https://api.github.com/repos/o/r", code, "status", {}, io.BytesIO(b"")
    )


class FailureCatalogTests(unittest.TestCase):
    def test_catalog_covers_minimum_taxonomy(self):
        self.assertTrue(
            MINIMUM_CODE_SET.issubset(FAILURE_CATALOG),
            MINIMUM_CODE_SET - set(FAILURE_CATALOG),
        )

    def test_every_spec_is_complete(self):
        for code, spec in FAILURE_CATALOG.items():
            with self.subTest(code=code):
                self.assertTrue(spec.title)
                self.assertTrue(spec.message)
                self.assertTrue(spec.suggestion)
                self.assertIsInstance(spec.retryable, bool)
                self.assertTrue(spec.category)

    def test_unknown_code_is_rejected(self):
        with self.assertRaises(ValueError):
            TaskFailure.from_code("NOT_A_CODE")


class TaskFailureTests(unittest.TestCase):
    def test_from_code_carries_catalog_semantics(self):
        failure = TaskFailure.from_code(
            GITHUB_NETWORK_ERROR, stage="DOWNLOADING_ARCHIVE",
            technical_detail="URLError: connection reset",
        )
        self.assertTrue(failure.retryable)
        self.assertEqual("github", failure.category)
        self.assertEqual("DOWNLOADING_ARCHIVE", failure.stage)
        self.assertIn("网络", failure.message)
        self.assertTrue(failure.suggestion)

    def test_roundtrip_via_dict(self):
        failure = TaskFailure.from_code(
            ARCHIVE_UNSAFE_PATH, stage="VALIDATING_ARCHIVE",
            technical_detail="boom", path="a/b.txt",
        )
        restored = TaskFailure.from_dict(failure.to_dict())
        self.assertEqual(failure.to_dict(), restored.to_dict())

    def test_persisted_failure_never_contains_credentials(self):
        canary = "ghp_" + "supersecret"
        failure = TaskFailure.from_code(
            GITHUB_TIMEOUT,
            technical_detail=f"Bearer {canary} while downloading",
        )
        rendered = str(failure.to_dict())
        self.assertNotIn(canary, rendered)
        self.assertIn("[redacted]", rendered)

    def test_error_bridge_carries_failure(self):
        failure = TaskFailure.from_code(GITHUB_NOT_FOUND)
        error = TaskFailureError(failure)
        self.assertIs(failure, error.failure)
        self.assertIn(GITHUB_NOT_FOUND, str(error))

    def test_retry_exhausted_preserves_root_cause(self):
        failure = retry_exhausted_failure("connection reset mid-download")
        self.assertEqual(QUEUE_RETRY_EXHAUSTED, failure.code)
        self.assertFalse(failure.retryable)
        self.assertIn("connection reset mid-download", failure.to_dict()["detail"]["root_cause"])


class ClassifyExceptionTests(unittest.TestCase):
    def test_http_codes_map_to_typed_failures(self):
        cases = [
            (http_error(404), GITHUB_NOT_FOUND, False),
            (http_error(403), GITHUB_AUTH_REQUIRED, False),
            (http_error(429), GITHUB_RATE_LIMITED, True),
            (http_error(503), GITHUB_NETWORK_ERROR, True),
            (http_error(408), GITHUB_TIMEOUT, True),
        ]
        for exc, code, retryable in cases:
            with self.subTest(code=code):
                failure = classify_exception(exc, stage="RESOLVING_REVISION")
                self.assertEqual(code, failure.code)
                self.assertEqual(retryable, failure.retryable)
                self.assertEqual("RESOLVING_REVISION", failure.stage)

    def test_message_shapes_map_defensively(self):
        cases = [
            ("repository archive contains a symbolic link", ARCHIVE_UNSAFE_PATH, False),
            ("connection reset by peer", GITHUB_NETWORK_ERROR, True),
            ("URLError: timed out", GITHUB_TIMEOUT, True),
        ]
        for text, code, retryable in cases:
            with self.subTest(text=text):
                failure = classify_exception(RuntimeError(text))
                self.assertEqual(code, failure.code)
                self.assertEqual(retryable, failure.retryable)

    def test_task_failure_error_roundtrips_through_classifier(self):
        original = TaskFailure.from_code(GITHUB_RATE_LIMITED, stage="CHECKING_CACHE")
        restored = classify_exception(TaskFailureError(original))
        self.assertEqual(original.code, restored.code)
        self.assertEqual("CHECKING_CACHE", restored.stage)
        self.assertTrue(restored.retryable)

    def test_unknown_exception_falls_back_to_retryable_internal(self):
        failure = classify_exception(RuntimeError("something odd"))
        self.assertEqual(TASK_INTERNAL_ERROR, failure.code)
        self.assertTrue(failure.retryable)


class QueueRetrySemanticsTests(unittest.TestCase):
    def _wait_for_dlq(self, queue_ref: TaskQueue, expected: int, timeout: float = 5.0) -> None:
        import time as _time

        deadline = _time.monotonic() + timeout
        while _time.monotonic() < deadline:
            if len(queue_ref.dead_letters()) >= expected:
                return
            _time.sleep(0.02)

    def test_permanent_task_failure_error_skips_retry_budget(self):
        attempts = []

        def handler(payload):
            attempts.append(payload["task_id"])
            raise TaskFailureError(
                TaskFailure.from_code(ARCHIVE_UNSAFE_PATH, stage="VALIDATING_ARCHIVE")
            )

        queue_ref = TaskQueue(handler, workers=1, max_attempts=3)
        try:
            queue_ref.submit({"task_id": "t1"})
            self._wait_for_dlq(queue_ref, 1)
            self.assertEqual(1, len(attempts), "永久失败不得消耗重试预算")
            self.assertIn(ARCHIVE_UNSAFE_PATH, queue_ref.dead_letters()[0]["error"])
        finally:
            queue_ref.close()

    def test_retryable_failure_error_retries_then_succeeds(self):
        calls = {"n": 0}
        retry_events = []

        def handler(payload):
            calls["n"] += 1
            if calls["n"] == 1:
                raise TaskFailureError(
                    TaskFailure.from_code(GITHUB_NETWORK_ERROR, technical_detail="reset")
                )

        queue_ref = TaskQueue(
            handler, workers=1, max_attempts=3,
            on_retry=lambda payload, attempt, max_attempts, error, delay:
                retry_events.append((attempt, max_attempts, delay)),
        )
        try:
            queue_ref.submit({"task_id": "t2"})
            import time as _time

            deadline = _time.monotonic() + 5
            while calls["n"] < 2 and _time.monotonic() < deadline:
                _time.sleep(0.02)
            self.assertEqual(2, calls["n"])
            self.assertEqual([], queue_ref.dead_letters())
            self.assertEqual(1, len(retry_events))
            attempt, max_attempts, delay = retry_events[0]
            self.assertEqual(1, attempt)
            self.assertEqual(3, max_attempts)
            self.assertGreater(delay, 0)
        finally:
            queue_ref.close()

    def test_retry_exhaustion_dead_letters_with_root_cause(self):
        def handler(payload):
            raise RuntimeError("connection reset mid-download")

        queue_ref = TaskQueue(handler, workers=1, max_attempts=2)
        try:
            queue_ref.submit({"task_id": "t3"})
            self._wait_for_dlq(queue_ref, 1)
            item = queue_ref.dead_letters()[0]
            self.assertEqual(2, item["attempt"])
            self.assertIn("connection reset mid-download", item["error"])
        finally:
            queue_ref.close()

    def test_permanent_task_error_behavior_is_unchanged(self):
        def handler(payload):
            raise PermanentTaskError("repository scan is disabled")

        queue_ref = TaskQueue(handler, workers=1, max_attempts=3)
        try:
            queue_ref.submit({"task_id": "t4"})
            self._wait_for_dlq(queue_ref, 1)
            self.assertEqual(1, queue_ref.dead_letters()[0]["attempt"])
        finally:
            queue_ref.close()

    def test_on_retry_receives_payload_reference(self):
        seen = []

        def handler(payload):
            if payload["task_id"] == "first":
                raise TaskFailureError(
                    TaskFailure.from_code(GITHUB_TIMEOUT)
                )

        queue_ref = TaskQueue(
            handler, workers=1, max_attempts=2,
            on_retry=lambda payload, attempt, max_attempts, error, delay:
                seen.append((payload["task_id"], attempt)),
        )
        try:
            queue_ref.submit({"task_id": "first"})
            import time as _time

            deadline = _time.monotonic() + 5
            while not seen and _time.monotonic() < deadline:
                _time.sleep(0.02)
            self.assertEqual(("first", 1), seen[0])
        finally:
            queue_ref.close()

    def test_redis_delivery_renews_lease_while_handler_is_running(self):
        class RecordingRedis:
            def __init__(self):
                self.claims = []

            def xclaim(self, stream, group, consumer, min_idle_time, message_ids):
                self.claims.append(
                    (stream, group, consumer, min_idle_time, tuple(message_ids))
                )

        redis = RecordingRedis()

        def handler(_payload):
            time.sleep(0.38)

        queue_ref = TaskQueue(handler, workers=1, lease_seconds=0.3)
        queue_ref._redis = redis
        try:
            delivered = queue_ref._deliver_with_lease_heartbeat(
                "123-0",
                {
                    "message_id": "task-with-long-handler",
                    "attempt": 0,
                    "payload": {"task_id": "task-with-long-handler"},
                    "submitted_at": time.time(),
                },
            )

            self.assertTrue(delivered)
            self.assertGreaterEqual(len(redis.claims), 2)
            for stream, group, consumer, min_idle_time, message_ids in redis.claims:
                self.assertEqual(queue_ref.stream, stream)
                self.assertEqual(queue_ref.group, group)
                self.assertEqual(queue_ref.consumer, consumer)
                self.assertEqual(0, min_idle_time)
                self.assertEqual(("123-0",), message_ids)
        finally:
            queue_ref._redis = None
            queue_ref.close()

    def test_reclaim_does_not_prefetch_messages_that_cannot_be_heartbeated(self):
        class LeaseAwareRedis:
            def __init__(self):
                self.now_ms = 0
                self.entries = {
                    "1-0": {"envelope": json.dumps({
                        "message_id": "first", "attempt": 0,
                        "payload": {"task_id": "first"}, "submitted_at": 0,
                    })},
                    "2-0": {"envelope": json.dumps({
                        "message_id": "second", "attempt": 0,
                        "payload": {"task_id": "second"}, "submitted_at": 0,
                    })},
                }
                self.pending = {
                    redis_id: ("stalled-worker", -10_000)
                    for redis_id in self.entries
                }
                self.acked = set()

            def advance(self, milliseconds):
                self.now_ms += milliseconds

            def xautoclaim(
                self, _stream, _group, consumer, min_idle_time, start_id, count
            ):
                del start_id
                eligible = [
                    redis_id for redis_id, (_owner, claimed_at) in self.pending.items()
                    if redis_id not in self.acked
                    and self.now_ms - claimed_at >= min_idle_time
                ][:count]
                for redis_id in eligible:
                    self.pending[redis_id] = (consumer, self.now_ms)
                return "0-0", [(redis_id, self.entries[redis_id]) for redis_id in eligible], []

            def xclaim(self, _stream, _group, consumer, min_idle_time, message_ids):
                del min_idle_time
                for redis_id in message_ids:
                    self.pending[redis_id] = (consumer, self.now_ms)

            def xack(self, _stream, _group, redis_id):
                self.acked.add(redis_id)

        redis = LeaseAwareRedis()
        executed = []
        first_worker = TaskQueue(lambda _payload: None, workers=1, lease_seconds=1)
        second_worker = TaskQueue(lambda _payload: None, workers=1, lease_seconds=1)
        first_worker.consumer = "first-worker"
        second_worker.consumer = "second-worker"
        first_worker._redis = redis
        second_worker._redis = redis

        def handler(payload):
            task_id = payload["task_id"]
            executed.append(task_id)
            if task_id == "first":
                # Model the first handler running past its lease while its own
                # heartbeat remains current. The prefetched second entry has no
                # heartbeat and is therefore reclaimable by another worker.
                redis.advance(first_worker.lease_seconds * 1000 + 1)
                redis.xclaim(
                    first_worker.stream, first_worker.group, first_worker.consumer,
                    min_idle_time=0, message_ids=["1-0"],
                )
                second_worker._reclaim_stale()

        first_worker.handler = handler
        second_worker.handler = handler
        try:
            first_worker._reclaim_stale()

            self.assertEqual(1, executed.count("first"))
            self.assertEqual(
                1, executed.count("second"),
                "a stale prefetched message must not execute in both workers",
            )
        finally:
            first_worker._redis = None
            second_worker._redis = None
            first_worker.close()
            second_worker.close()


if __name__ == "__main__":
    unittest.main()
