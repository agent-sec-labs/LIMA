"""Repository scan pipeline integration: GitHub materialization into async scans.

All tests run offline: GitHubMaterializer instances are rebuilt around a fake
opener so no test ever reaches the network (issue #13 constraint 6).
"""

import email.message
import io
import json
import tempfile
import time
import unittest
import urllib.error
import zipfile
from pathlib import Path

from lima.config import Settings
from lima.repository_materializer import GitHubMaterializer
from lima.repository_scanner import RepositoryScanner, coverage_warning_counts
from lima.service import ReviewService
from lima.task_progress import STAGE_ORDER
from lima.workspace import RepositoryWorkspace, WorkspaceInventory

SHA = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"
GITHUB_SOURCE = {
    "type": "github",
    "url": "https://github.com/agent-sec-labs/LIMA",
    "ref": SHA,
}

SNAPSHOT_FILES = {
    "app.py": (
        "from executor import evaluate_expression\n"
        "\n"
        "@app.post('/evaluate')\n"
        "def run(user_input):\n"
        "    return evaluate_expression(user_input)\n"
    ),
    "executor.py": "def evaluate_expression(value):\n    return eval(value)\n",
}


def build_archive(files: dict[str, object]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as bundle:
        for name, data in files.items():
            bundle.writestr("repo-main/" + name, data)
    return buffer.getvalue()


def build_archive_with_symlink(
    files: dict[str, object], link_name: str, target: str
) -> bytes:
    """Archive carrying a symlink member (never created on extraction)."""

    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as bundle:
        for name, data in files.items():
            bundle.writestr("repo-main/" + name, data)
        info = zipfile.ZipInfo("repo-main/" + link_name)
        info.external_attr = 0o120777 << 16
        bundle.writestr(info, target)
    return buffer.getvalue()


ARCHIVE = build_archive(SNAPSHOT_FILES)


class FakeResponse:
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


class FakeOpener:
    def __init__(
        self, commit_sha: str = SHA, archive: bytes = ARCHIVE,
        resolve_http_status: int = 0,
    ) -> None:
        self.commit_sha = commit_sha
        self.archive = archive
        self.resolve_http_status = resolve_http_status
        self.urls: list[str] = []
        self.downloads = 0
        self.resolves = 0

    def __call__(self, request, timeout=None):
        url = request.full_url
        self.urls.append(url)
        if url.startswith("https://api.github.com/repos/"):
            self.resolves += 1
            if self.resolve_http_status >= 400:
                raise urllib.error.HTTPError(
                    url, self.resolve_http_status, "github error",
                    email.message.Message(), io.BytesIO(b"{}"),
                )
            return FakeResponse(json.dumps({"sha": self.commit_sha}).encode())
        if url.startswith("https://codeload.github.com/"):
            self.downloads += 1
            return FakeResponse(self.archive)
        raise AssertionError(f"unexpected request url: {url}")

    @property
    def network_requests(self) -> int:
        return len(self.urls)


def make_settings(db_path: str, cache_root: str, sources: str,
                  import_root: str = "") -> Settings:
    offline_provider = ""
    return Settings(
        host="127.0.0.1", port=8080, db_path=db_path, max_diff_bytes=10000,
        max_steps=8, timeout_seconds=120, llm_base_url=offline_provider,
        llm_api_key=offline_provider, llm_model=offline_provider,
        github_webhook_secret=offline_provider, github_token=offline_provider,
        auto_post_review=False,
        repository_import_root=import_root,
        repository_scan_sources=sources,
        repository_scan_sast_mode="off",
        repository_cache_root=cache_root,
        # CI 只读容器的 /tmp tmpfs 仅 256MB；测试快照极小，
        # 用最低余量地板避免触发发布前的磁盘余量保护。
        repository_cache_min_free_bytes=1,
    )


def wait_terminal(service: ReviewService, task_id: str, tenant: str) -> dict:
    task = None
    for _ in range(400):
        task = service.store.get(task_id, tenant)
        if task and task["state"] in {"SUCCESS", "FAILED"}:
            return task
        time.sleep(0.01)
    return task or {}


class GitHubScanIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp(suffix="-t4")
        self.db_path = str(Path(self.root, "state.db"))
        self.cache_root = str(Path(self.root, "cache"))
        self.addCleanup(self._cleanup)

    def _cleanup(self):
        import shutil

        shutil.rmtree(self.root, ignore_errors=True)

    def make_service(self, sources: str, import_root: str = "") -> tuple:
        self.service = ReviewService(make_settings(
            self.db_path, self.cache_root, sources, import_root,
        ))
        self.addCleanup(self.service.queue.close)
        self.opener = FakeOpener()
        self.service.repository_materializer = GitHubMaterializer(
            self.service._ensure_repository_cache(), opener=self.opener
        )
        return self.service, self.opener

    def test_github_scan_end_to_end_offline(self):
        service, opener = self.make_service("github")
        created = service.enqueue_repository_scan_source(GITHUB_SOURCE, "tenant-a")

        # 响应契约：scan_id 与归一化后的 source
        self.assertEqual(created["task_id"], created["scan_id"])
        self.assertEqual(
            {
                "type": "github", "provider": "github",
                "canonical_name": "agent-sec-labs/lima",
                "requested_ref": SHA, "repository_key": "",
            },
            created["source"],
        )
        # 请求路径零网络：ref 解析与下载只发生在 worker
        self.assertEqual(0, opener.network_requests)

        task = wait_terminal(service, created["task_id"], "tenant-a")
        self.assertEqual("SUCCESS", task["state"])
        self.assertEqual("agent-sec-labs/lima", task["report"]["repository"])
        # T4：终态 progress 持久化（COMPLETED + 完成载荷，无覆盖性跳过）
        self.assertEqual("COMPLETED", task["progress"]["stage"])
        self.assertEqual(len(STAGE_ORDER), task["progress"]["stage_index"])
        completion = task["progress"]["detail"]["completion"]
        self.assertEqual("completed", completion["status"])
        self.assertEqual(0, completion["warning_count"])
        policy = task["report"]["collaboration"]["import_policy"]
        self.assertEqual(SHA, policy["resolved_revision"])
        self.assertFalse(policy["cache_hit"])
        self.assertRegex(policy["archive_sha256"], r"^[0-9a-f]{64}$")
        self.assertFalse(policy["host_path_exposed"])
        self.assertFalse(policy["repository_code_executed"])
        # 数据流链路在物化快照上照常工作
        finding = task["report"]["findings"][0]
        self.assertEqual("SEC-EVAL", finding["rule_id"])
        self.assertEqual("dataflow-verified", finding["verification_state"])
        # 下载恰好一次；扫描结束后 pin 全部释放
        self.assertEqual(1, opener.downloads)
        self.assertEqual([], list(service._ensure_repository_cache().pins_root.iterdir()))
        # 快照已在缓存中，可被后续任务复用
        self.assertEqual(1, service._ensure_repository_cache().stats()["entries"])

    def test_github_cache_hit_zero_network(self):
        service, opener = self.make_service("github")
        first = service.enqueue_repository_scan_source(GITHUB_SOURCE, "tenant-a")
        self.assertEqual("SUCCESS", wait_terminal(service, first["task_id"], "tenant-a")["state"])
        requests_after_first = opener.network_requests

        second = service.enqueue_repository_scan_source(GITHUB_SOURCE, "tenant-a")
        task = wait_terminal(service, second["task_id"], "tenant-a")

        self.assertEqual("SUCCESS", task["state"])
        self.assertTrue(task["report"]["collaboration"]["import_policy"]["cache_hit"])
        # 命中缓存后整条流水线零网络
        self.assertEqual(requests_after_first, opener.network_requests)
        self.assertEqual(1, opener.downloads)

    def test_ref_resolution_runs_in_worker_only(self):
        service, opener = self.make_service("github")
        moving = {"type": "github", "url": "https://github.com/o/r", "ref": "main"}
        created = service.enqueue_repository_scan_source(moving, "tenant-a")
        self.assertEqual(0, opener.network_requests)

        task = wait_terminal(service, created["task_id"], "tenant-a")

        self.assertEqual("SUCCESS", task["state"])
        self.assertEqual(1, opener.resolves)
        policy = task["report"]["collaboration"]["import_policy"]
        self.assertEqual(SHA, policy["resolved_revision"])
        self.assertEqual("main", policy["source"]["requested_ref"])

    def test_github_source_disabled_by_default(self):
        service, _ = self.make_service("local-import")
        with self.assertRaisesRegex(ValueError, "disabled"):
            service.enqueue_repository_scan_source(GITHUB_SOURCE, "tenant-a")
        self.assertEqual([], service.store.list_tasks(10, "tenant-a"))

    def test_local_import_disabled_under_github_only(self):
        service, _ = self.make_service("github")
        with self.assertRaisesRegex(ValueError, "disabled"):
            service.enqueue_repository_scan("team/project", "tenant-a")
        with self.assertRaisesRegex(ValueError, "disabled"):
            service.enqueue_repository_scan_source(
                {"type": "local-import", "repository_key": "team/project"},
                "tenant-a",
            )

    def test_backward_compatible_key_envelope(self):
        import_root = Path(self.root, "imports", "team", "project")
        import_root.mkdir(parents=True)
        for name, content in SNAPSHOT_FILES.items():
            (import_root / name).write_text(content, encoding="utf-8")
        service, opener = self.make_service(
            "both", import_root=str(Path(self.root, "imports"))
        )

        created = service.enqueue_repository_scan("team/project", "tenant-a")

        self.assertEqual(created["task_id"], created["scan_id"])
        self.assertEqual("local-import", created["source"]["type"])
        self.assertEqual("team/project", created["source"]["repository_key"])
        self.assertEqual("team/project", created["repository"])
        task = wait_terminal(service, created["task_id"], "tenant-a")
        self.assertEqual("SUCCESS", task["state"])
        self.assertEqual(
            "team/project",
            task["report"]["collaboration"]["import_policy"]["repository_key"],
        )
        # local-import 流水线从不触达 GitHub 物化器
        self.assertEqual(0, opener.network_requests)
        self.assertEqual(0, service._ensure_repository_cache().stats()["entries"])

    def test_github_scan_report_contains_no_host_paths(self):
        service, _ = self.make_service("github")
        created = service.enqueue_repository_scan_source(GITHUB_SOURCE, "tenant-a")
        task = wait_terminal(service, created["task_id"], "tenant-a")

        payload = json.dumps(task, ensure_ascii=False)
        self.assertNotIn(str(Path(self.cache_root).resolve()), payload)
        self.assertNotIn(str(Path(self.root).resolve()), payload)

    def test_scan_task_begins_progress_at_enqueue(self):
        service, _ = self.make_service("github")
        created = service.enqueue_repository_scan_source(GITHUB_SOURCE, "tenant-a")

        # progress 在 submit 之前落库：无论 worker 多快，记录必须已存在且 attempt=1
        task = service.store.get(created["task_id"], "tenant-a")
        self.assertIsNotNone(task["progress"])
        self.assertEqual(1, task["progress"]["attempt"])
        self.assertEqual(
            service.settings.queue_max_attempts,
            task["progress"]["max_attempts"],
        )
        wait_terminal(service, created["task_id"], "tenant-a")

    def test_github_scan_records_stage_traversal(self):
        service, _ = self.make_service("github")
        recorded: list[str] = []
        original = service.store.update_task_progress

        def recording(task_id, progress):
            recorded.append(progress["stage"])
            original(task_id, progress)

        service.store.update_task_progress = recording
        moving = {"type": "github", "url": "https://github.com/o/r", "ref": "main"}
        created = service.enqueue_repository_scan_source(moving, "tenant-a")
        task = wait_terminal(service, created["task_id"], "tenant-a")

        self.assertEqual("SUCCESS", task["state"])
        stages = set(recorded)
        # 移动 ref 全链路：解析→缓存→下载→校验→发布→盘点→数据流→AST→收尾→完成
        # （SAST off、语义复核未配置属于可达阶段跳过，符合契约）
        for expected in (
            "QUEUED", "RESOLVING_REVISION", "CHECKING_CACHE",
            "DOWNLOADING_ARCHIVE", "VALIDATING_ARCHIVE", "PREPARING_WORKSPACE",
            "INVENTORY", "DATAFLOW_ANALYSIS", "AST_ANALYSIS",
            "FINALIZING", "COMPLETED",
        ):
            self.assertIn(expected, stages)
        self.assertEqual(["COMPLETED"], recorded[-1:])

    def test_scan_completion_marks_coverage_warnings(self):
        # 覆盖性跳过两类：物化器 symlink（SYMLINK_SKIPPED）+ 工作区 non-utf8
        archive = build_archive_with_symlink(
            {**SNAPSHOT_FILES, "broken.py": b"\xff\xff\xff not utf8"},
            "link.py", "app.py",
        )
        service, opener = self.make_service("github")
        service.repository_materializer = GitHubMaterializer(
            service._ensure_repository_cache(),
            opener=FakeOpener(archive=archive),
        )
        created = service.enqueue_repository_scan_source(GITHUB_SOURCE, "tenant-a")
        task = wait_terminal(service, created["task_id"], "tenant-a")

        self.assertEqual("SUCCESS", task["state"])
        completion = task["progress"]["detail"]["completion"]
        # 冻结决策：任何 coverage-affecting skip ≥ 1 即标记，无阈值配置
        self.assertEqual("completed_with_warnings", completion["status"])
        self.assertEqual(2, completion["warning_count"])
        self.assertEqual(
            {"SYMLINK_SKIPPED": 1, "non-utf8": 1}, completion["warnings"]
        )

    def test_scan_failure_persists_typed_failure_with_stage(self):
        service, opener = self.make_service("github")
        service.repository_materializer = GitHubMaterializer(
            service._ensure_repository_cache(),
            opener=FakeOpener(resolve_http_status=404),
        )
        moving = {"type": "github", "url": "https://github.com/o/r", "ref": "main"}
        created = service.enqueue_repository_scan_source(moving, "tenant-a")
        task = wait_terminal(service, created["task_id"], "tenant-a")

        self.assertEqual("FAILED", task["state"])
        failure = task["failure"]
        self.assertEqual("GITHUB_NOT_FOUND", failure["code"])
        self.assertEqual("RESOLVING_REVISION", failure["stage"])
        self.assertFalse(failure["retryable"])
        self.assertTrue(failure["suggestion"])
        # progress 停在失败阶段，作为失败位置佐证一并保留
        self.assertEqual("RESOLVING_REVISION", task["progress"]["stage"])

    def test_queue_retry_bumps_progress_attempt(self):
        service, _ = self.make_service("github")
        created = service.enqueue_repository_scan_source(GITHUB_SOURCE, "tenant-a")
        task_id = created["task_id"]
        self.assertEqual("SUCCESS", wait_terminal(service, task_id, "tenant-a")["state"])

        service._on_task_retry(
            {"task_id": task_id}, 1, 3, RuntimeError("transient"), 0.0,
        )
        progress = service.store.get(task_id, "tenant-a")["progress"]
        self.assertEqual(2, progress["attempt"])
        self.assertEqual("QUEUED", progress["stage"])


class ScannerProgressTests(unittest.TestCase):
    """Scanner-level progress callback contract and throttling."""

    def setUp(self):
        self.root = Path(tempfile.mkdtemp(suffix="-scan-progress"))
        self.addCleanup(lambda: __import__("shutil").rmtree(self.root, ignore_errors=True))

    def _scan(self, file_count: int) -> list[dict]:
        for index in range(file_count):
            (self.root / f"mod_{index:03d}.py").write_text(
                f"value_{index} = {index}\n", encoding="utf-8",
            )
        events: list[dict] = []

        def callback(stage, message, **detail):
            events.append({"stage": stage, "message": message, **detail})

        RepositoryScanner(sast_mode="off").scan(
            RepositoryWorkspace(self.root), progress_callback=callback,
        )
        return events

    def test_progress_covers_inventory_dataflow_and_throttled_ast(self):
        events = self._scan(60)
        stages = [item["stage"] for item in events]

        self.assertEqual(
            ["INVENTORY", "INVENTORY", "DATAFLOW_ANALYSIS", "DATAFLOW_ANALYSIS"],
            stages[:4],
        )
        ast_events = [item for item in events if item["stage"] == "AST_ANALYSIS"]
        currents = [item.get("current") for item in ast_events]
        # 首条 current=0；每 25 个文件或 500ms 发一条；最后一条收口到全量
        self.assertEqual(0, currents[0])
        self.assertIn(25, currents)
        self.assertEqual(60, currents[-1])
        self.assertEqual(60, ast_events[-1]["total"])
        self.assertEqual("files", ast_events[-1]["unit"])
        self.assertLessEqual(len(ast_events), 6)

    def test_coverage_warning_counts_exclude_scope_policy_skips(self):
        inventory = WorkspaceInventory(
            root="workspace", skipped={
                "ignored-directory": 5,
                "unsupported-extension": 40,
                "sensitive-config": 3,
                "symlink": 2,
                "non-utf8": 1,
            },
        )
        self.assertEqual(
            {"non-utf8": 1, "symlink": 2}, coverage_warning_counts(inventory)
        )


if __name__ == "__main__":
    unittest.main()
