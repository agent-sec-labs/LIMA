"""Bounded RepositorySnapshot cache: TTL, quota, dedup and atomic publication."""

import json
import os
import tempfile
import time
import unittest

from lima.repository_cache import (
    RepositoryCache,
    RepositoryCacheError,
    compute_cache_key,
    resolve_cache_identity,
)
from lima.repository_source import RepositorySource

GITHUB = RepositorySource.github("agent-sec-labs/LIMA")
OTHER_REPO = RepositorySource.github("agent-sec-labs/lima-docs")
LOCAL = RepositorySource.local_import("team/project")

SHA_A = "a" * 40
SHA_B = "b" * 40


class RepositoryCacheTests(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp(suffix="-cache")
        self.cache = RepositoryCache(
            self.root,
            ttl_seconds=3600,
            quota_bytes=10 * 1024 * 1024,
            min_free_bytes=1,
            materialization_timeout_seconds=3600,
            pin_ttl_seconds=3600,
        )
        self.addCleanup(self._remove_root)

    def _remove_root(self):
        import shutil

        shutil.rmtree(self.root, ignore_errors=True)

    # ------------------------------------------------------------------
    # helpers
    # ------------------------------------------------------------------

    def materialize(self, source, revision, files):
        """Owner-side materialization: reserve, write files, publish."""

        reservation = self.cache.reserve(source, revision)
        self.assertTrue(reservation.owner)
        for relative, content in files.items():
            path = reservation.staging_path / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding="utf-8")
        return reservation.publish()

    def backdate_entry(self, entry, age_seconds):
        manifest_path = entry.path / "manifest.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        manifest["created_at"] = time.time() - age_seconds
        manifest_path.write_text(
            json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8"
        )

    def set_last_access(self, key, age_seconds):
        marker = self.cache.access_root / key
        marker.touch(exist_ok=True)
        stamp = time.time() - age_seconds
        os.utime(marker, (stamp, stamp))

    # ------------------------------------------------------------------
    # 1. lookup miss -> hit
    # ------------------------------------------------------------------

    def test_lookup_miss_then_hit(self):
        self.assertIsNone(self.cache.lookup(GITHUB, SHA_A))

        entry = self.materialize(GITHUB, SHA_A, {"src/app.py": "print('hi')\n"})

        hit = self.cache.lookup(GITHUB, SHA_A)
        self.assertIsNotNone(hit)
        self.assertEqual(entry.key, hit.key)
        self.assertEqual(SHA_A, hit.resolved_revision)
        self.assertEqual("github", hit.source["provider"])
        self.assertEqual("agent-sec-labs/lima", hit.source["canonical_name"])
        self.assertEqual(1, hit.file_count)
        self.assertEqual(
            "print('hi')\n", self.cache.read_text(hit, "src/app.py")
        )
        # 请求相同身份的不同 revision 仍然 miss。
        self.assertIsNone(self.cache.lookup(GITHUB, SHA_B))
        self.assertIsNone(self.cache.lookup(OTHER_REPO, SHA_A))

    # ------------------------------------------------------------------
    # 2. published snapshots are immutable; first publisher wins
    # ------------------------------------------------------------------

    def test_snapshot_immutable_after_publication(self):
        first = self.materialize(GITHUB, SHA_A, {"file.txt": "first-content"})
        fingerprint_before = first.content_fingerprint

        second = self.materialize(GITHUB, SHA_A, {"file.txt": "SECOND-CONTENT"})
        # 重复发布保留先到者：返回的是已有条目，内容不被覆盖。
        self.assertEqual(first.key, second.key)
        self.assertEqual(fingerprint_before, second.content_fingerprint)

        hit = self.cache.lookup(GITHUB, SHA_A)
        self.assertEqual("first-content", self.cache.read_text(hit, "file.txt"))
        self.assertEqual(fingerprint_before, hit.content_fingerprint)

    # ------------------------------------------------------------------
    # 3. TTL expiry
    # ------------------------------------------------------------------

    def test_ttl_cleanup(self):
        entry = self.materialize(GITHUB, SHA_A, {"file.txt": "x"})
        self.backdate_entry(entry, age_seconds=self.cache.ttl_seconds + 10)

        report = self.cache.cleanup()

        self.assertEqual(1, report["ttl_expired"])
        self.assertIsNone(self.cache.lookup(GITHUB, SHA_A))

    def test_ttl_respects_recently_created_entries(self):
        self.materialize(GITHUB, SHA_A, {"file.txt": "x"})
        report = self.cache.cleanup()
        self.assertEqual(0, report["ttl_expired"])
        self.assertIsNotNone(self.cache.lookup(GITHUB, SHA_A))

    # ------------------------------------------------------------------
    # 4. LRU eviction under quota
    # ------------------------------------------------------------------

    def test_lru_cleanup_under_quota(self):
        old_entry = self.materialize(GITHUB, SHA_A, {"a.txt": "a" * 2048})
        new_entry = self.materialize(OTHER_REPO, SHA_A, {"b.txt": "b" * 2048})
        self.cache.quota_bytes = 2048  # 只能容纳一个条目
        self.set_last_access(old_entry.key, age_seconds=1000)
        self.set_last_access(new_entry.key, age_seconds=1)

        report = self.cache.cleanup()

        self.assertGreaterEqual(report["lru_evicted"], 1)
        self.assertIsNone(self.cache.lookup(GITHUB, SHA_A, touch=False))
        self.assertIsNotNone(self.cache.lookup(OTHER_REPO, SHA_A, touch=False))
        self.assertLessEqual(self.cache.stats()["total_bytes"], 2048)

    # ------------------------------------------------------------------
    # 5. concurrent materialization deduplication
    # ------------------------------------------------------------------

    def test_deduplication_of_concurrent_materialization(self):
        first = self.cache.reserve(GITHUB, SHA_A)
        self.assertTrue(first.owner)

        # 同一身份的并发预留：不是 owner，且没有 staging 目录，绝不重复物化。
        second = self.cache.reserve(GITHUB, SHA_A)
        self.assertFalse(second.owner)
        self.assertIsNone(second.staging_path)

        path = first.staging_path / "src/main.py"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("value = 1\n", encoding="utf-8")
        first.publish()

        # 等待方最终读到唯一的已发布条目。
        hit = self.cache.wait_for_publish(GITHUB, SHA_A, timeout_seconds=5)
        self.assertIsNotNone(hit)
        self.assertEqual(1, self.cache.stats()["entries"])

    def test_lock_holder_crash_is_recovered_after_timeout(self):
        dead = self.cache.reserve(GITHUB, SHA_A)
        self.assertTrue(dead.owner)
        # 模拟持有者崩溃：锁目录残留且超过物化超时。
        stale_stamp = time.time() - (self.cache.materialization_timeout_seconds + 5)
        os.utime(self.cache._lock_path(dead.key), (stale_stamp, stale_stamp))

        recovered = self.cache.reserve(GITHUB, SHA_A)
        self.assertTrue(recovered.owner)

    # ------------------------------------------------------------------
    # 6. atomic publication: no partial visibility
    # ------------------------------------------------------------------

    def test_atomic_publication_no_partial_visibility(self):
        reservation = self.cache.reserve(GITHUB, SHA_A)
        (reservation.staging_path / "half-written.txt").write_text(
            "partial", encoding="utf-8"
        )
        # staging 内容对 lookup 永远不可见。
        self.assertIsNone(self.cache.lookup(GITHUB, SHA_A))
        with reservation:
            pass  # 退出 with 且未 publish：自动释放
        self.assertFalse(reservation.owner)
        self.assertIsNone(self.cache.lookup(GITHUB, SHA_A))
        # 崩溃残留的锁与 staging 不阻塞后续物化。
        again = self.cache.reserve(GITHUB, SHA_A)
        self.assertTrue(again.owner)
        again.abort()

    def test_empty_snapshot_publication_is_refused(self):
        reservation = self.cache.reserve(GITHUB, SHA_A)
        with self.assertRaises(RepositoryCacheError):
            reservation.publish()
        # 拒绝发布同样要释放预留。
        self.assertFalse(reservation.owner)
        fresh = self.cache.reserve(GITHUB, SHA_A)
        self.assertTrue(fresh.owner)
        fresh.abort()

    # ------------------------------------------------------------------
    # 7. unknown source identity stays a miss
    # ------------------------------------------------------------------

    def test_lookup_miss_for_unknown_source(self):
        self.assertIsNone(self.cache.lookup(LOCAL, "c" * 64))
        report = self.cache.cleanup()
        self.assertEqual(
            {
                "stale_staging_removed": 0,
                "stale_locks_removed": 0,
                "stale_pins_removed": 0,
                "orphan_entries_removed": 0,
                "ttl_expired": 0,
                "lru_evicted": 0,
                "bytes_freed": 0,
            },
            report,
        )
        self.assertEqual(0, self.cache.stats()["entries"])

    # ------------------------------------------------------------------
    # 8. incomplete entries are cleaned up safely
    # ------------------------------------------------------------------

    def test_incomplete_entry_cleanup(self):
        reservation = self.cache.reserve(GITHUB, SHA_A)
        (reservation.staging_path / "partial.txt").write_text("x", encoding="utf-8")
        # 模拟崩溃：既不 publish 也不 abort，且时间越过物化超时。
        stale = time.time() - (self.cache.materialization_timeout_seconds + 5)
        os.utime(reservation.staging_path, (stale, stale))
        os.utime(self.cache._lock_path(reservation.key), (stale, stale))

        report = self.cache.cleanup()

        self.assertEqual(1, report["stale_staging_removed"])
        self.assertEqual(1, report["stale_locks_removed"])
        self.assertEqual(0, report["orphan_entries_removed"])
        # 孤儿条目（有目录、无合法 manifest）同样被移除且不可见。
        orphan = self.cache.entries_root / ("f" * 64)
        orphan.mkdir()
        (orphan / "junk.txt").write_text("junk", encoding="utf-8")
        report = self.cache.cleanup()
        self.assertEqual(1, report["orphan_entries_removed"])
        # 清理后可以正常重新物化。
        self.materialize(GITHUB, SHA_A, {"ok.txt": "ok"})
        self.assertIsNotNone(self.cache.lookup(GITHUB, SHA_A))

    # ------------------------------------------------------------------
    # 9. active (pinned) snapshots are never evicted
    # ------------------------------------------------------------------

    def test_active_snapshot_is_not_evicted(self):
        entry = self.materialize(GITHUB, SHA_A, {"file.txt": "important" * 128})
        self.cache.quota_bytes = 1  # 配额形同虚设，必须驱逐
        self.backdate_entry(entry, age_seconds=self.cache.ttl_seconds + 10)

        with self.cache.pin(GITHUB, SHA_A) as pinned:
            self.assertEqual(entry.key, pinned.key)
            report = self.cache.cleanup()
            self.assertEqual(0, report["ttl_expired"])
            self.assertEqual(0, report["lru_evicted"])
            self.assertIsNotNone(self.cache.lookup(GITHUB, SHA_A))

        # 释放 pin 后同一状态会被清理。
        report = self.cache.cleanup()
        self.assertEqual(1, report["ttl_expired"])
        self.assertIsNone(self.cache.lookup(GITHUB, SHA_A))

    def test_stale_pin_does_not_block_eviction(self):
        entry = self.materialize(GITHUB, SHA_A, {"file.txt": "data"})
        marker = self.cache.pins_root / f"{entry.key}.deadbeefcafe"
        marker.write_text("123", encoding="utf-8")
        stale = time.time() - (self.cache.pin_ttl_seconds + 5)
        os.utime(marker, (stale, stale))
        self.cache.quota_bytes = 1

        report = self.cache.cleanup()

        self.assertEqual(1, report["stale_pins_removed"])
        self.assertEqual(1, report["lru_evicted"])

    # ------------------------------------------------------------------
    # free-space protection
    # ------------------------------------------------------------------

    def test_free_space_protection_blocks_publish(self):
        current_free = self.cache._free_bytes()
        self.cache.min_free_bytes = current_free + 1024 * 1024

        reservation = self.cache.reserve(GITHUB, SHA_A)
        (reservation.staging_path / "file.txt").write_text("x" * 1024, encoding="utf-8")
        with self.assertRaises(RepositoryCacheError):
            reservation.publish()

        # fail-closed 后预留被释放，不留下锁或 staging。
        self.assertFalse(reservation.owner)
        self.assertEqual(0, self.cache.stats()["locks"])
        self.assertEqual(0, self.cache.stats()["staging"])

    # ------------------------------------------------------------------
    # identity contract
    # ------------------------------------------------------------------

    def test_moving_refs_and_bad_revisions_are_rejected(self):
        for bad in ("main", "HEAD", "", "z" * 40, "a" * 39, "A" * 41):
            with self.assertRaises(ValueError):
                resolve_cache_identity(GITHUB, bad)

    def test_cache_key_binds_full_identity(self):
        base = resolve_cache_identity(GITHUB, SHA_A)
        different_revision = resolve_cache_identity(GITHUB, SHA_B)
        different_repo = resolve_cache_identity(OTHER_REPO, SHA_A)
        different_provider = resolve_cache_identity(LOCAL, "c" * 64)
        keys = {
            compute_cache_key(base),
            compute_cache_key(different_revision),
            compute_cache_key(different_repo),
            compute_cache_key(different_provider),
        }
        self.assertEqual(4, len(keys))

    def test_read_text_rejects_boundary_escapes(self):
        entry = self.materialize(GITHUB, SHA_A, {"inside.txt": "ok"})
        for escape in ("../manifest.json", "src/../../escape.txt", "/etc/passwd"):
            with self.assertRaises(ValueError):
                self.cache.read_text(entry, escape)

    def test_manifest_records_bounded_file_inventory(self):
        files = {f"dir/f{i:03d}.txt": str(i) for i in range(5)}
        entry = self.materialize(GITHUB, SHA_A, files)
        manifest = json.loads(
            (entry.path / "manifest.json").read_text(encoding="utf-8")
        )
        self.assertEqual(5, manifest["file_count"])
        self.assertEqual(5, len(manifest["files"]))
        for record in manifest["files"]:
            self.assertIn(record["path"], files)
            self.assertEqual(len(files[record["path"]]), record["size"])
            self.assertRegex(record["sha256"], r"^[0-9a-f]{64}$")
        self.assertRegex(manifest["content_fingerprint"], r"^[0-9a-f]{64}$")
        self.assertEqual(1, manifest["schema_version"])


if __name__ == "__main__":
    unittest.main()
