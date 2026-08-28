"""Repository scan pipeline integration: GitHub materialization into async scans.

All tests run offline: GitHubMaterializer instances are rebuilt around a fake
opener so no test ever reaches the network (issue #13 constraint 6).
"""

import io
import json
import tempfile
import time
import unittest
import zipfile
from pathlib import Path

from lima.config import Settings
from lima.repository_materializer import GitHubMaterializer
from lima.service import ReviewService

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


def build_archive(files: dict[str, str]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as bundle:
        for name, data in files.items():
            bundle.writestr("repo-main/" + name, data)
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
    def __init__(self, commit_sha: str = SHA, archive: bytes = ARCHIVE) -> None:
        self.commit_sha = commit_sha
        self.archive = archive
        self.urls: list[str] = []
        self.downloads = 0
        self.resolves = 0

    def __call__(self, request, timeout=None):
        url = request.full_url
        self.urls.append(url)
        if url.startswith("https://api.github.com/repos/"):
            self.resolves += 1
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


if __name__ == "__main__":
    unittest.main()
