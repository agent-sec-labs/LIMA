"""Disposable repair workspaces over pinned repository snapshots (issue #16)."""

from __future__ import annotations

import io
import tempfile
import unittest
import zipfile
from pathlib import Path

from lima.repair_workspace import (
    RepairWorkspace,
    RepairWorkspaceError,
    RepairWorkspaceLimits,
    repair_relevant_paths,
)
from lima.repository_cache import RepositoryCache
from lima.repository_source import RepositorySource

GITHUB = RepositorySource.github("agent-sec-labs/LIMA")
SHA = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"


def publish_snapshot(cache: RepositoryCache, files: dict[str, str]) -> None:
    """Publish a snapshot through the cache's public reserve/publish path."""

    from lima.repository_materializer import GitHubMaterializer

    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as bundle:
        for name, data in files.items():
            bundle.writestr("repo-main/" + name, data)
    archive = buffer.getvalue()

    class _Response:
        def __init__(self, payload: bytes) -> None:
            self._payload = payload

        def read(self, size: int = -1) -> bytes:
            if size is None or size < 0:
                chunk, self._payload = self._payload, b""
            else:
                chunk, self._payload = self._payload[:size], self._payload[size:]
            return chunk

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

    def opener(request, timeout=None):
        return _Response(archive)

    materializer = GitHubMaterializer(cache, opener=opener)
    materializer.materialize(GITHUB, SHA)


class RepairWorkspaceTests(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp(suffix="-t7")
        self.cache_root = str(Path(self.root, "cache"))
        self.base_root = str(Path(self.root, "repair-workspaces"))
        self.cache = RepositoryCache(
            self.cache_root, ttl_seconds=3600, quota_bytes=10 * 1024 * 1024,
            min_free_bytes=1,
        )
        publish_snapshot(self.cache, {
            "app.py": "print('app')\n",
            "pkg/__init__.py": "",
            "pkg/service.py": "VALUE = 1\n",
            "docs/readme.txt": "docs\n",
        })
        self.entry = self.cache.lookup(GITHUB, SHA)
        self.assertIsNotNone(self.entry)
        self.addCleanup(self._cleanup)

    def _cleanup(self):
        import shutil

        shutil.rmtree(self.root, ignore_errors=True)

    def compose(self, task_id="task-1", paths=None, **kwargs):
        return RepairWorkspace.compose(
            self.cache, self.base_root, task_id, self.entry,
            paths if paths is not None else ["app.py", "pkg/service.py"],
            **kwargs,
        )

    def active_pins(self) -> int:
        return len(list(self.cache.pins_root.glob(f"{self.entry.key}.*")))

    def test_workspace_copy_holds_pin_during_lifetime(self):
        self.assertEqual(0, self.active_pins())
        with self.compose() as workspace:
            # 生命周期内：pin 标记存在，缓存清理不驱逐该条目
            self.assertEqual(1, self.active_pins())
            self.cache.cleanup()
            self.assertIsNotNone(self.cache.lookup(GITHUB, SHA, touch=False))
            self.assertTrue(workspace.root.is_dir())
        # dispose 后：pin 释放，配额清理随时可以驱逐该条目
        self.assertEqual(0, self.active_pins())

    def test_workspace_copy_is_bounded_by_relevant_subset(self):
        with self.compose(paths=["app.py"]) as workspace:
            self.assertEqual(["app.py"], workspace.file_paths())
        with self.compose(paths=["pkg/service.py", "pkg/__init__.py"]) as workspace:
            self.assertEqual(
                ["pkg/__init__.py", "pkg/service.py"], workspace.file_paths()
            )

    def test_workspace_copy_refuses_existing_directory(self):
        target = Path(self.base_root, "task-1")
        target.mkdir(parents=True)
        (target / "keep.txt").write_text("precious", encoding="utf-8")
        with self.assertRaisesRegex(RepairWorkspaceError, "already exists"):
            self.compose(task_id="task-1")
        # 既有内容不被覆盖
        self.assertEqual(
            "precious", (target / "keep.txt").read_text(encoding="utf-8")
        )
        # 拒绝后不留 pin
        self.assertEqual(0, self.active_pins())

    def test_workspace_copy_does_not_follow_symlinks(self):
        # 纵深防御：即使快照里混入 symlink 也拒绝拷贝，绝不跟随目标。
        # 向已发布快照塞 symlink 仅为构造测试前提，结束即删；无 symlink
        # 权限的平台（如非管理员 Windows）跳过本用例。
        evil = self.entry.path / "evil.py"
        try:
            evil.symlink_to(self.entry.path / "app.py")
        except OSError as exc:
            self.skipTest(f"symlink creation unavailable: {exc}")
        try:
            with self.assertRaisesRegex(RepairWorkspaceError, "regular file"):
                self.compose(paths=["evil.py"])
        finally:
            evil.unlink()

    def test_workspace_dispose_removes_directory(self):
        workspace = self.compose()
        self.assertTrue(workspace.root.is_dir())
        workspace.dispose()
        self.assertFalse(workspace.root.exists())
        workspace.dispose()  # 幂等

    def test_dispose_runs_on_exception(self):
        try:
            with self.compose():
                raise RuntimeError("repair crashed mid-flight")
        except RuntimeError:
            pass
        self.assertFalse(Path(self.base_root, "task-1").exists())
        self.assertEqual(0, self.active_pins())

    def test_workspace_is_never_a_cache_entry(self):
        entries_before = sorted(
            item.name for item in self.cache.entries_root.iterdir()
        )
        with self.compose(paths=["app.py"]) as workspace:
            # 工作区目录不在缓存布局内，也不会被发布回缓存
            self.assertNotIn(str(self.cache.entries_root), str(workspace.root))
        self.assertEqual(
            entries_before,
            sorted(item.name for item in self.cache.entries_root.iterdir()),
        )
        self.assertEqual(1, self.cache.stats()["entries"])

    def test_workspace_copy_respects_file_budgets(self):
        # 单文件预算：用小预算触发真实拷贝拒绝
        limits = RepairWorkspaceLimits(max_file_bytes=4)
        with self.assertRaisesRegex(RepairWorkspaceError, "per-file budget"):
            self.compose(paths=["app.py"], limits=limits)
        # 文件数预算
        limits = RepairWorkspaceLimits(max_files=1)
        with self.assertRaisesRegex(RepairWorkspaceError, "file budget"):
            self.compose(paths=["app.py", "pkg/service.py"], limits=limits)
        # 总量预算
        limits = RepairWorkspaceLimits(max_total_bytes=8)
        with self.assertRaisesRegex(RepairWorkspaceError, "total workspace"):
            self.compose(paths=["app.py", "pkg/service.py"], limits=limits)
        # 预算拒绝后不留任务目录
        self.assertFalse(
            self.cache._has_fresh_pin(self.entry.key, __import__("time").time())
        )

    def test_empty_subset_and_unsafe_task_ids_are_refused(self):
        with self.assertRaisesRegex(RepairWorkspaceError, "without any files"):
            self.compose(paths=[])
        with self.assertRaisesRegex(RepairWorkspaceError, "safe directory"):
            self.compose(task_id="../escape")
        with self.assertRaisesRegex(RepairWorkspaceError, "safe directory"):
            self.compose(task_id="a/b")

    def test_workspace_io_stays_inside_boundary(self):
        with self.compose(paths=["app.py"]) as workspace:
            self.assertEqual("print('app')\n", workspace.read_text("app.py"))
            workspace.write_text("app.py", "print('patched')\n")
            self.assertEqual(
                "print('patched')\n", (workspace.root / "app.py").read_text(
                    encoding="utf-8"
                )
            )
            # 写入只影响工作区副本，源快照不变
            self.assertEqual(
                "print('app')\n",
                (self.entry.path / "app.py").read_text(encoding="utf-8"),
            )
            with self.assertRaisesRegex(RepairWorkspaceError, "escapes"):
                workspace.read_text("../secrets.txt")
            with self.assertRaisesRegex(RepairWorkspaceError, "escapes"):
                workspace.write_text("../evil.txt", "x")

    def test_repair_relevant_paths_helper(self):
        report = {
            "findings": [
                {"path": "app.py", "cwe": "CWE-78"},
                {"path": "app.py", "cwe": "CWE-78"},
                {"path": "db.py", "cwe": "CWE-89"},
                {"path": "notes.txt", "cwe": "CWE-79"},
                {"path": "", "cwe": "CWE-78"},
            ]
        }
        self.assertEqual(
            ["app.py", "db.py"],
            repair_relevant_paths(report, {"CWE-22", "CWE-78", "CWE-89"}),
        )


if __name__ == "__main__":
    unittest.main()
