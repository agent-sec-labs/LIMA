"""GitHub materializer: ref pinning, hardened fetching and cache publication."""

import io
import json
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
import zipfile
from pathlib import Path
from unittest import mock

from lima.repository_cache import RepositoryCache
from lima.repository_materializer import (
    GitHubMaterializer,
    TaskFailureError,
    _WhitelistedRedirectHandler,
)
from lima.repository_source import RepositorySource


def assert_typed_failure(testcase, code: str, stage: str, call):
    """Assert that ``call`` raises a TaskFailureError with the given code/stage."""
    with testcase.assertRaises(TaskFailureError) as caught:
        call()
    failure = caught.exception.failure
    testcase.assertEqual(code, failure.code)
    testcase.assertEqual(stage, failure.stage)
    testcase.assertTrue(failure.technical_detail or failure.message)
    return failure

GITHUB = RepositorySource.github("agent-sec-labs/LIMA")
SHA = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"
OTHER_SHA = "b1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b"


def build_archive(
    files: dict[str, str | bytes] | None = None,
    symlinks: dict[str, str] | None = None,
    member_names: list[str] | None = None,
) -> bytes:
    """Build a codeload-shaped zip; file values may be str or raw bytes."""
    """Build a codeload-shaped zip under a single ``repo-main/`` directory.

    ``member_names`` builds literal archive entries verbatim (used for
    traversal-shaped names that must not carry the normal prefix).
    """

    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as bundle:
        for name, data in (files or {}).items():
            payload = data.encode("utf-8") if isinstance(data, str) else data
            bundle.writestr("repo-main/" + name, payload)
        for name, target in (symlinks or {}).items():
            info = zipfile.ZipInfo("repo-main/" + name)
            info.external_attr = (0o120000 << 16) | 0o644
            bundle.writestr(info, target)
        for name in member_names or []:
            bundle.writestr(name, "payload")
    return buffer.getvalue()


class FakeResponse:
    def __init__(self, payload: bytes, delay: float = 0.0) -> None:
        self._payload = payload
        self._delay = delay

    def read(self, size: int = -1) -> bytes:
        if self._delay:
            time.sleep(self._delay)
            self._delay = 0.0
        if size is None or size < 0:
            chunk, self._payload = self._payload, b""
        else:
            chunk, self._payload = self._payload[:size], self._payload[size:]
        return chunk

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


class FakeOpener:
    """Route api.github.com / codeload.github.com requests to canned data."""

    def __init__(
        self,
        commit_sha: str = SHA,
        archive: bytes = b"",
        download_failures: int = 0,
        resolve_failures: int = 0,
        download_delay: float = 0.0,
        gate: threading.Event | None = None,
    ) -> None:
        self.commit_sha = commit_sha
        self.archive = archive
        self.download_failures = download_failures
        self.resolve_failures = resolve_failures
        self.download_delay = download_delay
        self.gate = gate
        self.urls: list[str] = []
        self.downloads = 0
        self.resolves = 0

    def __call__(self, request, timeout=None):
        url = request.full_url
        self.urls.append(url)
        if url.startswith("https://api.github.com/repos/"):
            self.resolves += 1
            if self.resolves <= self.resolve_failures:
                raise urllib.error.HTTPError(url, 404, "Not Found", {}, io.BytesIO(b""))
            return FakeResponse(json.dumps({"sha": self.commit_sha}).encode())
        if url.startswith("https://codeload.github.com/"):
            self.downloads += 1
            if self.downloads <= self.download_failures:
                raise urllib.error.URLError("connection reset mid-download")
            if self.gate is not None:
                self.gate.wait(timeout=30)
            return FakeResponse(self.archive, delay=self.download_delay)
        raise AssertionError(f"unexpected request url: {url}")

    @property
    def network_requests(self) -> int:
        return len(self.urls)


ARCHIVE = build_archive(
    {"src/app.py": "print('hello')\n", "README.md": "# demo\n", "pkg/__init__.py": ""}
)


class MaterializerTestCase(unittest.TestCase):
    def setUp(self):
        self.cache_root = tempfile.mkdtemp(suffix="-t2cache")
        self.cache = RepositoryCache(
            self.cache_root, ttl_seconds=3600, quota_bytes=10 * 1024 * 1024,
            min_free_bytes=1,
        )
        self.addCleanup(self._remove_root)

    def _remove_root(self):
        import shutil

        shutil.rmtree(self.cache_root, ignore_errors=True)

    def make_materializer(self, _extra=None, **opener_kwargs):
        self.opener = FakeOpener(**opener_kwargs)
        self.materializer = GitHubMaterializer(
            self.cache, opener=self.opener, **(_extra or {})
        )
        return self.materializer

    def snapshot_files(self, result: dict) -> dict[str, str]:
        root = Path(result["path"])
        return {
            item.relative_to(root).as_posix(): item.read_text(encoding="utf-8")
            for item in sorted(root.rglob("*"))
            if item.is_file()
        }


class MaterializationTests(MaterializerTestCase):
    def test_lookup_miss_fanout_download(self):
        self.make_materializer(archive=ARCHIVE)
        result = self.materializer.materialize(GITHUB, SHA)

        self.assertFalse(result["cache_hit"])
        self.assertEqual(SHA, result["resolved_revision"])
        self.assertEqual(
            "print('hello')\n",
            self.snapshot_files(result)["src/app.py"],
        )
        self.assertRegex(result["archive_sha256"], r"^[0-9a-f]{64}$")
        # 已发布：cache 侧可独立命中
        entry = self.cache.lookup(GITHUB, SHA)
        self.assertIsNotNone(entry)
        self.assertEqual(SHA, entry.resolved_revision)
        self.assertEqual(1, self.opener.downloads)

    def test_lookup_hit_fanout_coverage(self):
        self.make_materializer(archive=ARCHIVE)
        self.materializer.materialize(GITHUB, SHA)
        requests_before = self.opener.network_requests

        result = self.materializer.materialize(GITHUB, SHA)

        self.assertTrue(result["cache_hit"])
        self.assertEqual(requests_before, self.opener.network_requests)

    def test_ref_resolution_pin(self):
        self.make_materializer(archive=ARCHIVE)
        result = self.materializer.materialize(GITHUB, "main")

        self.assertEqual("main", result["requested_ref"])
        self.assertEqual(SHA, result["resolved_revision"])
        self.assertEqual(1, self.opener.resolves)
        # 解析结果记录在缓存条目（snapshot 元数据）中
        self.assertEqual(SHA, self.cache.lookup(GITHUB, SHA).resolved_revision)
        # 同一移动 ref 二次物化：解析后命中缓存，不再下载
        again = self.materializer.materialize(GITHUB, "main")
        self.assertTrue(again["cache_hit"])
        self.assertEqual(1, self.opener.downloads)

    def test_ref_resolution_failure(self):
        self.make_materializer(archive=ARCHIVE, resolve_failures=1)
        assert_typed_failure(
            self, "GITHUB_NOT_FOUND", "RESOLVING_REVISION",
            lambda: self.materializer.materialize(GITHUB, "main"),
        )
        # 解析失败不得产生任何缓存条目或残留
        stats = self.cache.stats()
        self.assertEqual(0, stats["entries"])
        self.assertEqual(0, stats["staging"])
        self.assertEqual(0, stats["locks"])

    def test_materialization_timeout(self):
        self.make_materializer(archive=ARCHIVE, download_delay=1.5)
        materializer = GitHubMaterializer(
            self.cache, opener=self.opener, timeout_seconds=1
        )
        assert_typed_failure(
            self, "GITHUB_TIMEOUT", "DOWNLOADING_ARCHIVE",
            lambda: materializer.materialize(GITHUB, SHA),
        )
        self.assertEqual(0, self.cache.stats()["entries"])
        self.assertEqual(0, self.cache.stats()["locks"])

    def test_archive_budget_enforced(self):
        # 成员数超限：构造 10_001 个成员
        huge = build_archive({f"f{i:05d}.txt": "x" for i in range(10_001)})
        self.make_materializer(archive=huge)
        assert_typed_failure(
            self, "ARCHIVE_TOO_MANY_FILES", "VALIDATING_ARCHIVE",
            lambda: self.materializer.materialize(GITHUB, SHA),
        )
        self.assertEqual(0, self.cache.stats()["entries"])

        # 解压总量超限：将预算临时调小后用真实归档触发
        small = build_archive({"big.txt": "y" * 4096})
        self.make_materializer(archive=small)
        with mock.patch(
            "lima.repository_materializer.MAX_UNCOMPRESSED_BYTES", 1024
        ):
            assert_typed_failure(
                self, "ARCHIVE_DECOMPRESSION_LIMIT", "VALIDATING_ARCHIVE",
                lambda: self.materializer.materialize(GITHUB, SHA),
            )
        self.assertEqual(0, self.cache.stats()["entries"])
        self.assertEqual(0, self.cache.stats()["staging"])

    def test_path_traversal_rejected(self):
        dangerous = [
            # 带 repo-main 前缀的相对穿越 / 符号链接
            build_archive(member_names=["repo-main/../evil.txt"]),
            build_archive(member_names=["repo-main/dir/../../up.txt"]),
            build_archive(symlinks={"link.txt": "target"}),
            # 不带前缀的绝对路径成员
            build_archive(member_names=["/abs.txt"]),
        ]
        expected = [
            ("ARCHIVE_UNSAFE_PATH", "repo-main/../evil.txt"),
            ("ARCHIVE_UNSAFE_PATH", "repo-main/dir/../../up.txt"),
            # 仅含 symlink 的归档：条目全部被跳过后快照为空，发布拒绝。
            ("CACHE_PUBLISH_FAILED", "symlink-link.txt"),
            ("ARCHIVE_UNSAFE_PATH", "/abs.txt"),
        ]
        stages = {
            "ARCHIVE_UNSAFE_PATH": "VALIDATING_ARCHIVE",
            "CACHE_PUBLISH_FAILED": "PREPARING_WORKSPACE",
        }
        for (code, _marker), archive in zip(expected, dangerous, strict=True):
            self.make_materializer(archive=archive)
            assert_typed_failure(
                self, code, stages[code],
                lambda: self.materializer.materialize(GITHUB, SHA),
            )
        self.assertEqual(0, self.cache.stats()["entries"])

    def test_no_secrets_in_snapshot(self):
        canary = "ghp_supersecret_token_value"
        self.opener = FakeOpener(archive=ARCHIVE)
        self.materializer = GitHubMaterializer(
            self.cache, opener=self.opener, auth_token=canary
        )
        result = self.materializer.materialize(GITHUB, SHA)

        for name, content in self.snapshot_files(result).items():
            self.assertNotIn(canary, content, name)
        manifest = json.loads(
            (Path(result["path"]) / "manifest.json").read_text(encoding="utf-8")
        )
        self.assertNotIn(canary, json.dumps(manifest))
        self.assertNotIn(canary, json.dumps(result))

    def test_resume_after_interruption(self):
        self.make_materializer(archive=ARCHIVE, download_failures=1)
        assert_typed_failure(
            self, "GITHUB_NETWORK_ERROR", "DOWNLOADING_ARCHIVE",
            lambda: self.materializer.materialize(GITHUB, SHA),
        )
        # 中断后不留任何部分数据或锁
        self.assertEqual(0, self.cache.stats()["entries"])
        self.assertEqual(0, self.cache.stats()["staging"])
        self.assertEqual(0, self.cache.stats()["locks"])

        result = self.materializer.materialize(GITHUB, SHA)
        self.assertFalse(result["cache_hit"])
        self.assertEqual(2, self.opener.downloads)
        self.assertEqual(
            "print('hello')\n", self.snapshot_files(result)["src/app.py"]
        )

    def test_dedup_concurrent_materialization(self):
        gate = threading.Event()
        self.make_materializer(archive=ARCHIVE, gate=gate)
        owner_result: dict = {}
        waiter_result: dict = {}
        errors: list = []

        def worker(target: dict):
            try:
                target.update(self.materializer.materialize(GITHUB, SHA))
            except Exception as exc:  # pragma: no cover - 防御性收集
                errors.append(exc)

        owner = threading.Thread(target=worker, args=(owner_result,))
        owner.start()
        # 等 owner 拿到预留并进入被门控阻塞的下载
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline and self.opener.downloads == 0:
            time.sleep(0.01)
        self.assertEqual(1, self.opener.downloads)

        waiter = threading.Thread(target=worker, args=(waiter_result,))
        waiter.start()
        time.sleep(0.3)  # 让 waiter 稳定进入 wait_for_publish 轮询
        gate.set()
        owner.join(timeout=10)
        waiter.join(timeout=10)

        self.assertEqual([], errors)
        self.assertFalse(owner_result["cache_hit"])
        self.assertTrue(waiter_result["cache_hit"])
        self.assertEqual(waiter_result["key"], owner_result["key"])
        # 同一身份只下载一次
        self.assertEqual(1, self.opener.downloads)
        self.assertEqual(1, self.cache.stats()["entries"])


class MaterializerProgressTests(MaterializerTestCase):
    def collect_events(self, **materializer_kwargs):
        events = []

        def callback(stage, message, **detail):
            events.append((stage, message, detail))

        self.make_materializer(**materializer_kwargs)
        result = self.materializer.materialize(GITHUB, SHA, progress_callback=callback)
        return events, result

    def test_progress_events_report_all_stages(self):
        events, result = self.collect_events(archive=ARCHIVE)
        stages = [stage for stage, _, _ in events]
        # SHA ref：无解析阶段；命中缓存前的检查在下载前
        self.assertEqual("CHECKING_CACHE", stages[0])
        self.assertIn("DOWNLOADING_ARCHIVE", stages)
        self.assertIn("VALIDATING_ARCHIVE", stages)
        self.assertEqual("PREPARING_WORKSPACE", stages[-1])
        self.assertEqual([], result["warnings"])

    def test_moving_ref_reports_resolving_stage_first(self):
        events = []

        def callback(stage, message, **detail):
            events.append((stage, detail))

        self.make_materializer(archive=ARCHIVE)
        self.materializer.materialize(GITHUB, "main", progress_callback=callback)
        self.assertEqual("RESOLVING_REVISION", events[0][0])
        self.assertEqual({"requested_ref": "main"}, events[0][1])
        self.assertEqual(
            {"resolved_revision": SHA}, events[1][1]
        )

    def test_cache_hit_reports_without_download(self):
        self.make_materializer(archive=ARCHIVE)
        self.materializer.materialize(GITHUB, SHA)
        events = []

        def callback(stage, message, **detail):
            events.append((stage, detail))

        result = self.materializer.materialize(GITHUB, SHA, progress_callback=callback)
        self.assertTrue(result["cache_hit"])
        self.assertEqual(2, len(events))
        self.assertEqual("CHECKING_CACHE", events[0][0])
        self.assertTrue(events[1][1].get("cache_hit"))

    def test_download_progress_is_throttled_by_bytes(self):
        # 不可压缩字节：下载字节数即归档字节数。
        # SHA-256 链式扩展：确定性且不可压缩的测试字节流。
        import hashlib

        chunks = []
        digest = b"lima-throttle-fixture"
        remaining = 5 * 1024 * 1024
        while remaining > 0:
            digest = hashlib.sha256(digest).digest()
            chunks.append(digest)
            remaining -= len(digest)
        blob = b"".join(chunks)[: 5 * 1024 * 1024]
        big = build_archive({"blob.bin": blob})
        events, _ = self.collect_events(
            archive=big,
            _extra={
                "progress_throttle_bytes": 2 * 1024 * 1024,
                "progress_throttle_interval": 3600.0,
            },
        )
        download_events = [
            detail for stage, _, detail in events if stage == "DOWNLOADING_ARCHIVE"
        ]
        # 5 MiB / 2 MiB 节流：约 3 次回调，而不是每 1 MiB 一次（5+ 次）。
        self.assertLessEqual(len(download_events), 4)
        self.assertGreaterEqual(len(download_events), 2)
        self.assertGreater(download_events[-1]["current"], 4 * 1024 * 1024)

    def test_symlink_is_skipped_with_warning_and_scan_continues(self):
        mixed = build_archive(
            {"app.py": "print('ok')\n"},
            symlinks={"link.py": "app.py"},
        )
        events, result = self.collect_events(archive=mixed)
        self.assertFalse(result["cache_hit"])
        self.assertEqual(
            [{
                "code": "SYMLINK_SKIPPED",
                "category": "coverage",
                "path": "link.py",
                "message": "符号链接未被跟随，已从快照中跳过。",
            }],
            result["warnings"],
        )
        # 快照内绝不创建 symlink；普通文件照常物化
        snapshot_root = Path(result["path"])
        self.assertFalse((snapshot_root / "link.py").exists())
        self.assertFalse((snapshot_root / "link.py").is_symlink())
        self.assertEqual(
            "print('ok')\n",
            (snapshot_root / "app.py").read_text(encoding="utf-8"),
        )
        self.assertIn("PREPARING_WORKSPACE", [s for s, _, _ in events])

    def test_multiple_symlinks_are_all_reported(self):
        mixed = build_archive(
            {"a.py": "1\n", "b.py": "2\n"},
            symlinks={"l1": "a.py", "l2": "b.py"},
        )
        _, result = self.collect_events(archive=mixed)
        self.assertEqual(
            ["l1", "l2"], [item["path"] for item in result["warnings"]]
        )


class MaterializerContractTests(unittest.TestCase):
    def test_local_import_source_is_rejected(self):
        cache_root = tempfile.mkdtemp(suffix="-t2contract")
        self.addCleanup(lambda: __import__("shutil").rmtree(cache_root, True))
        cache = RepositoryCache(cache_root, min_free_bytes=1)
        materializer = GitHubMaterializer(cache, opener=FakeOpener())
        with self.assertRaises(ValueError):
            materializer.materialize(RepositorySource.local_import("team/project"))

    def test_redirect_outside_allowlist_is_refused(self):
        handler = _WhitelistedRedirectHandler()
        request = urllib.request.Request("https://codeload.github.com/a/b/zip/x")
        with self.assertRaises(TaskFailureError):
            handler.redirect_request(
                request, None, 302, "Found", {}, "https://evil.example.com/payload"
            )

    def test_empty_and_invalid_archives_are_refused(self):
        cache_root = tempfile.mkdtemp(suffix="-t2empty")
        self.addCleanup(lambda: __import__("shutil").rmtree(cache_root, True))
        cache = RepositoryCache(cache_root, min_free_bytes=1)
        opener = FakeOpener(archive=b"not-a-zip")
        materializer = GitHubMaterializer(cache, opener=opener)
        assert_typed_failure(
            self, "ARCHIVE_INVALID", "VALIDATING_ARCHIVE",
            lambda: materializer.materialize(GITHUB, SHA),
        )
        opener.archive = b""
        assert_typed_failure(
            self, "ARCHIVE_INVALID", "DOWNLOADING_ARCHIVE",
            lambda: materializer.materialize(GITHUB, OTHER_SHA),
        )
        self.assertEqual(0, cache.stats()["entries"])


if __name__ == "__main__":
    unittest.main()
