"""Durable task delivery with ACK, leases, retry backoff and a dead-letter queue."""
import json
import queue
import socket
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Callable, Dict, Optional

from .task_failure import TaskFailureError

RetryCallback = Callable[[dict[str, Any], int, int, BaseException, float], None]


class PermanentTaskError(RuntimeError):
    """An error that must not be retried."""


class TaskQueue:
    STREAM = "lima:review:stream"
    DLQ = "lima:review:dlq"
    GROUP = "lima-workers"

    def __init__(
        self, handler: Callable[[Dict[str, Any]], None], workers: int = 2,
        redis_url: str = "", max_attempts: int = 3, lease_seconds: int = 60,
        on_dead_letter: Optional[Callable[[Dict[str, Any], str], None]] = None,
        *, stream: str = "", dead_letter_stream: str = "", group: str = "",
        thread_prefix: str = "lima-worker",
        on_retry: RetryCallback | None = None,
    ):
        self.handler = handler
        self.redis_url = redis_url
        self.max_attempts = max_attempts
        self.lease_seconds = lease_seconds
        self.on_dead_letter = on_dead_letter
        # T2：重试即将发生时的可观测回调（payload/attempt/max/error/delay）。
        self.on_retry = on_retry
        self.stream = stream or self.STREAM
        self.dead_letter_stream = dead_letter_stream or self.DLQ
        self.group = group or self.GROUP
        self._executor = ThreadPoolExecutor(
            max_workers=workers, thread_name_prefix=thread_prefix
        )
        self._redis = None
        self._memory: queue.Queue = queue.Queue()
        self._memory_dlq = []
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self.consumer = "%s-%s" % (socket.gethostname(), uuid.uuid4().hex[:8])
        if redis_url:
            try:
                import redis
            except ImportError as exc:
                raise RuntimeError("Redis mode requires: pip install redis") from exc
            self._redis = redis.Redis.from_url(redis_url, decode_responses=True)
            self._redis.ping()
            try:
                self._redis.xgroup_create(self.stream, self.group, id="0", mkstream=True)
            except redis.ResponseError as exc:
                if "BUSYGROUP" not in str(exc):
                    raise
            for _ in range(workers):
                self._executor.submit(self._redis_worker)

    @property
    def backend(self) -> str:
        return "redis-streams" if self._redis else "memory-acked"

    def submit(self, payload: Dict[str, Any], message_id: str = "") -> str:
        envelope = {
            "message_id": message_id or str(payload.get("task_id") or uuid.uuid4()),
            "attempt": 0,
            "payload": payload,
            "submitted_at": time.time(),
        }
        if self._redis:
            self._redis.xadd(self.stream, {"envelope": json.dumps(envelope, ensure_ascii=False)})
        else:
            self._executor.submit(self._deliver, envelope)
        return envelope["message_id"]

    def _deliver(self, envelope: Dict[str, Any]) -> bool:
        envelope["attempt"] = int(envelope.get("attempt", 0)) + 1
        try:
            self.handler(envelope["payload"])
            return True
        except PermanentTaskError as exc:
            self._dead_letter(envelope, str(exc))
            return False
        except TaskFailureError as exc:
            if not exc.failure.retryable:
                # 分类为永久失败的错误直接进死信，不浪费重试预算。
                self._dead_letter(envelope, str(exc))
                return False
            self._schedule_retry(envelope, exc)
            return False
        except Exception as exc:
            self._schedule_retry(envelope, exc)
            return False

    def _schedule_retry(
        self, envelope: dict[str, Any], exc: BaseException
    ) -> None:
        if envelope["attempt"] >= self.max_attempts:
            self._dead_letter(envelope, str(exc))
            return
        if self._redis:
            if self.on_retry:
                self.on_retry(
                    envelope.get("payload") or {}, envelope["attempt"],
                    self.max_attempts, exc, 0.0,
                )
            self._redis.xadd(self.stream, {
                "envelope": json.dumps(envelope, ensure_ascii=False)
            })
        else:
            delay = min(2 ** (envelope["attempt"] - 1), 10)
            if self.on_retry:
                self.on_retry(
                    envelope.get("payload") or {}, envelope["attempt"],
                    self.max_attempts, exc, float(delay),
                )
            timer = threading.Timer(delay, self._submit_memory, args=(envelope,))
            timer.daemon = True
            timer.start()

    def _submit_memory(self, envelope: Dict[str, Any]) -> None:
        if not self._stop.is_set():
            self._executor.submit(self._deliver, envelope)

    def _redis_worker(self) -> None:
        while not self._stop.is_set():
            self._reclaim_stale()
            messages = self._redis.xreadgroup(
                self.group, self.consumer, {self.stream: ">"}, count=1, block=1000
            )
            for _stream, entries in messages:
                for redis_id, fields in entries:
                    try:
                        envelope = json.loads(fields["envelope"])
                    except Exception as exc:
                        envelope = {
                            "message_id": redis_id, "attempt": self.max_attempts,
                            "payload": {}, "submitted_at": time.time(),
                        }
                        self._dead_letter(envelope, "invalid queue envelope: %s" % exc)
                        self._redis.xack(self.stream, self.group, redis_id)
                        continue
                    try:
                        self._deliver(envelope)
                        # ACK only after work completed or was safely requeued/DLQed.
                        self._redis.xack(self.stream, self.group, redis_id)
                    except Exception:
                        # Infrastructure failure: leave pending for lease recovery.
                        continue

    def _reclaim_stale(self) -> None:
        try:
            result = self._redis.xautoclaim(
                self.stream, self.group, self.consumer,
                min_idle_time=self.lease_seconds * 1000, start_id="0-0", count=10,
            )
            entries = result[1] if len(result) > 1 else []
            for redis_id, fields in entries:
                envelope = json.loads(fields["envelope"])
                self._deliver(envelope)
                self._redis.xack(self.stream, self.group, redis_id)
        except Exception:
            # Redis versions without XAUTOCLAIM still process new entries.
            return

    def _dead_letter(self, envelope: Dict[str, Any], error: str) -> None:
        item = {**envelope, "error": error[:2000], "failed_at": time.time()}
        if self._redis:
            self._redis.xadd(
                self.dead_letter_stream,
                {"envelope": json.dumps(item, ensure_ascii=False)},
            )
        else:
            with self._lock:
                self._memory_dlq.append(item)
        if self.on_dead_letter:
            self.on_dead_letter(envelope.get("payload") or {}, item["error"])

    def dead_letters(self, limit: int = 100) -> list:
        if self._redis:
            rows = self._redis.xrevrange(
                self.dead_letter_stream, count=max(1, min(limit, 500))
            )
            return [json.loads(fields["envelope"]) for _id, fields in rows]
        with self._lock:
            return list(reversed(self._memory_dlq[-limit:]))

    def replay_dead_letter(self, message_id: str) -> bool:
        for item in self.dead_letters(500):
            if item.get("message_id") == message_id:
                payload = item.get("payload") or {}
                self.submit(payload, message_id=message_id)
                return True
        return False

    def close(self) -> None:
        """Stop accepting work and wait for in-flight handlers to release resources."""
        self._stop.set()
        self._executor.shutdown(wait=True, cancel_futures=True)
        if self._redis:
            close = getattr(self._redis, "close", None)
            if close:
                close()
