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


class DeferredTaskError(Exception):
    """The task is deferred (e.g., a shared budget is exhausted).

    额度延期不是执行失败：释放 worker 并延迟重新调度，但不递增失败
    attempt、不进死信。delay_seconds 仅作用于内存队列的定时器；Redis
    模式沿既有重试路径立即重投。
    """

    def __init__(self, message: str = "", delay_seconds: float = 5.0) -> None:
        super().__init__(message or "task deferred")
        self.delay_seconds = max(0.1, float(delay_seconds))


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
        # 每个队列自己的延迟集合：扫描与实验队列共享 Redis 后端时，
        # 到期成员只回到自己的 stream，不会交叉投递（#348 第六轮 F1）。
        self._deferred_key = f"{self.stream}:deferred"
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
        except DeferredTaskError as exc:
            # 延期不是失败：回退本次递增的 attempt，按 delay 重排，不
            # 消耗失败重试预算、不进死信（#348 第四轮 F1）。
            envelope["attempt"] = max(0, int(envelope.get("attempt", 1)) - 1)
            self._schedule_deferred(envelope, exc.delay_seconds)
            return False
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

    def _schedule_deferred(
        self, envelope: Dict[str, Any], delay_seconds: float
    ) -> None:
        """Reschedule one deferred task without consuming retry budget.

        Redis 路径使用持久化延迟集合（ZSET）：以到期时间戳为 score 写
        入，不立即 xadd——worker 循环中的 _promote_expired_deferred 到
        期后才转投回 stream，延期窗口内不重执行 handler、不占扫描
        worker、不消耗失败预算（#348 第五轮 P2）。内存路径用 Timer。
        """
        if self._redis:
            not_before = time.time() + max(0.0, delay_seconds)
            self._redis.zadd(
                self._deferred_key,
                {json.dumps(envelope, ensure_ascii=False): not_before},
            )
        else:
            timer = threading.Timer(
                delay_seconds, self._submit_memory, args=(envelope,)
            )
            timer.daemon = True
            timer.start()

    # Lua: publish-then-remove.  The member's existence is checked,
    # then XADD publishes to this queue's stream; only after a successful
    # publish does ZREM drop the member from the deferred set.  If XADD
    # errors (e.g. WRONGTYPE) the member survives in the ZSET for the
    # next cycle — Redis Lua is atomic (no interleaving) but does NOT
    # roll back on runtime errors, so publish-first is the only ordering
    # that cannot lose a task (round-7 P1).
    _PROMOTE_LUA = """
if redis.call('ZSCORE', KEYS[1], ARGV[1]) == false then
    return 0
end
redis.call('XADD', KEYS[2], '*', 'envelope', ARGV[1])
redis.call('ZREM', KEYS[1], ARGV[1])
return 1
"""

    def _promote_expired_deferred(self) -> None:
        """Move due deferred envelopes back into the stream (Redis only).

        到期成员经 Lua 原子转投（存在检查 → XADD 发布 → ZREM 移除，
        同一原子块）。发布失败时成员留在 ZSET 供下轮重试——Redis Lua
        不回滚运行时错误，所以只有"先发布后删除"不会丢任务。异常被
        捕获使 worker 循环继续运行。
        """
        if not self._redis:
            return
        now = time.time()
        try:
            due = self._redis.zrangebyscore(
                self._deferred_key, "-inf", now, start=0, num=10
            )
        except Exception:
            return
        for envelope_json in due:
            try:
                self._redis.eval(
                    self._PROMOTE_LUA,
                    2,
                    self._deferred_key,
                    self.stream,
                    envelope_json,
                )
            except Exception:
                # Infrastructure failure: the member stays in the ZSET
                # (Lua is atomic — ZREM without XADD cannot happen), the
                # worker loop continues, and the next cycle retries.
                continue

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

    def _deliver_with_lease_heartbeat(
        self, redis_id: str, envelope: Dict[str, Any]
    ) -> bool:
        """Keep a pending Redis message leased while its handler is running."""
        finished = threading.Event()
        interval = max(0.1, self.lease_seconds / 3)

        def renew_lease() -> None:
            while not finished.wait(interval):
                try:
                    # Claiming the already-owned message resets its pending idle time.
                    self._redis.xclaim(
                        self.stream, self.group, self.consumer,
                        min_idle_time=0, message_ids=[redis_id],
                    )
                except Exception:
                    # A transient heartbeat failure must not hide the handler result.
                    continue

        heartbeat = threading.Thread(
            target=renew_lease,
            name="lima-lease-heartbeat",
            daemon=True,
        )
        heartbeat.start()
        try:
            return self._deliver(envelope)
        finally:
            finished.set()
            heartbeat.join()

    def _redis_worker(self) -> None:
        while not self._stop.is_set():
            self._promote_expired_deferred()
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
                        self._deliver_with_lease_heartbeat(redis_id, envelope)
                        # ACK only after work completed or was safely requeued/DLQed.
                        self._redis.xack(self.stream, self.group, redis_id)
                    except Exception:
                        # Infrastructure failure: leave pending for lease recovery.
                        continue

    def _reclaim_stale(self) -> None:
        try:
            result = self._redis.xautoclaim(
                self.stream, self.group, self.consumer,
                min_idle_time=self.lease_seconds * 1000, start_id="0-0", count=1,
            )
            entries = result[1] if len(result) > 1 else []
            for redis_id, fields in entries:
                envelope = json.loads(fields["envelope"])
                self._deliver_with_lease_heartbeat(redis_id, envelope)
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
