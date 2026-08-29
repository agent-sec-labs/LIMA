"""Runtime storage deployment contract (issue #14 / T5).

Cross-platform offline checks for the docker named volumes, the idempotent
volume bootstrap, the ``__ephemeral__`` cache-root semantics and the startup
visibility warning for unmanaged cache roots.
"""

from __future__ import annotations

import io
import os
import tempfile
import unittest
import unittest.mock
from pathlib import Path

from lima.config import Settings
from lima.service import (
    ReviewService,
    _warn_unmanaged_repository_cache_root,
    classify_repository_cache_root,
)

ROOT = Path(__file__).resolve().parents[1]


def compose_text() -> str:
    return (ROOT / "docker-compose.yml").read_text(encoding="utf-8")


class ComposeStorageContractTests(unittest.TestCase):
    def test_compose_declares_distinct_named_volumes(self):
        text = compose_text()
        self.assertIn("repository_cache:\n    name: lima-repository-cache", text)
        self.assertIn("repair_workspace:\n    name: lima-repair-workspace", text)
        # Two distinct volumes: the cache and repair scratch space never share storage.
        self.assertNotIn("name: lima-repository-cache\n    name:", text)

    def test_compose_mounts_cache_volume_and_env(self):
        text = compose_text()
        self.assertIn(
            "repository_cache:/var/lib/lima/repository-cache", text
        )
        self.assertIn(
            "LIMA_REPOSITORY_CACHE_ROOT: "
            "${LIMA_REPOSITORY_CACHE_ROOT:-/var/lib/lima/repository-cache}",
            text,
        )

    def test_repair_workspace_volume_is_reserved_not_mounted(self):
        text = compose_text()
        # Declared for the future T7 repair sidecar but deliberately NOT
        # mounted into the lima service in this issue: least privilege —
        # the main process gains no write access before the repair workflow
        # exists. All mount syntaxes are covered: long form (source:target),
        # short list form (- repair_workspace) and read-only variants.
        self.assertNotIn("repair_workspace:/", text)
        self.assertNotIn("- repair_workspace", text)
        # The volume only ever appears as the top-level declaration.
        self.assertEqual(
            1, text.count("repair_workspace:"),
            "repair_workspace must appear exactly once (top-level declaration)",
        )

    def test_storage_trust_domains_are_mounted_with_expected_access(self):
        # /repositories → lima, read-only; /var/lib/lima/repository-cache →
        # lima, read-write; /repair-workspaces → not mounted in T5 (#14).
        text = compose_text()
        self.assertIn(":/repositories:ro", text)
        self.assertIn("repository_cache:/var/lib/lima/repository-cache\n", text)
        self.assertNotIn("/var/lib/lima/repository-cache:ro", text)
        self.assertNotIn("repair-workspaces", text.replace(
            "lima-repair-workspace", ""
        ))

    def test_security_posture_is_not_weakened(self):
        text = compose_text()
        for required in ("read_only: true", "cap_drop:", "- ALL", "tmpfs:"):
            self.assertIn(required, text)

    def test_dockerfile_precreates_cache_dir_as_non_root(self):
        dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
        self.assertIn(
            'install -d -o "${APP_UID}" -g "${APP_GID}"', dockerfile
        )
        self.assertIn("/var/lib/lima/repository-cache", dockerfile)

    def test_volume_bootstrap_is_idempotent_and_covers_new_volumes(self):
        script = (ROOT / "scripts" / "lima.ps1").read_text(encoding="utf-8")
        self.assertIn("'lima-repository-cache'", script)
        self.assertIn("'lima-repair-workspace'", script)
        self.assertIn("docker volume create", script)
        self.assertIn("idempotent", script)


class CacheRootSemanticsTests(unittest.TestCase):
    def test_default_cache_root_is_unchanged(self):
        with unittest.mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("LIMA_REPOSITORY_CACHE_ROOT", None)
            settings = Settings.from_env()
        self.assertEqual("output/repository-cache", settings.repository_cache_root)

    def test_explicit_root_passthrough(self):
        with unittest.mock.patch.dict(
            os.environ, {"LIMA_REPOSITORY_CACHE_ROOT": "/srv/cache"}
        ):
            settings = Settings.from_env()
        self.assertEqual("/srv/cache", settings.repository_cache_root)

    def test_ephemeral_magic_value_maps_to_system_tmpdir(self):
        with unittest.mock.patch.dict(
            os.environ, {"LIMA_REPOSITORY_CACHE_ROOT": "__ephemeral__"}
        ):
            settings = Settings.from_env()
        expected = Path(tempfile.gettempdir()) / "lima-repository-cache"
        self.assertEqual(str(expected), settings.repository_cache_root)

    def test_env_example_keeps_empty_default(self):
        example = (ROOT / ".env.example").read_text(encoding="utf-8")
        self.assertIn("LIMA_REPOSITORY_CACHE_ROOT=\n", example)

    def test_classification_covers_all_locations(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            self.assertEqual(
                "system-tmp", classify_repository_cache_root(tmpdir)
            )
            self.assertEqual(
                "system-tmp",
                classify_repository_cache_root(
                    str(Path(tmpdir) / "lima-repository-cache")
                ),
            )
        self.assertEqual("named-volume", classify_repository_cache_root(
            "/var/lib/lima/repository-cache"
        ))
        self.assertEqual(
            "named-volume",
            classify_repository_cache_root(
                "/var/lib/lima/repository-cache/nested"
            ),
        )
        self.assertEqual(
            "unmanaged", classify_repository_cache_root("output/repository-cache")
        )

    def test_warning_is_emitted_for_unmanaged_roots_only(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            for root, expect_warning in (
                ("/var/lib/lima/repository-cache", False),
                (tmpdir, False),
                ("output/repository-cache", True),
            ):
                stderr = io.StringIO()
                with unittest.mock.patch("sys.stderr", stderr):
                    _warn_unmanaged_repository_cache_root(root)
                output = stderr.getvalue()
                if expect_warning:
                    self.assertIn("WARNING:", output)
                    self.assertIn("repository cache root", output)
                else:
                    self.assertEqual("", output)

    def test_lazy_cache_init_emits_warning_exactly_once(self):
        # 用 spy 包裹真实警告函数：惰性初始化恰好触发一次，且参数就是
        # 配置的缓存根。使用系统 tmpdir 下的可写根（system-tmp 类，无实际
        # 告警输出），保证只读容器内 /tmp 之外无可写路径时测试依然成立。
        import lima.service as service_module

        with tempfile.TemporaryDirectory() as tmpdir:
            offline_provider = ""
            settings = Settings(
                host="127.0.0.1", port=8080,
                db_path=str(Path(tmpdir, "state.db")), max_diff_bytes=10000,
                max_steps=8, timeout_seconds=120,
                llm_base_url=offline_provider, llm_api_key=offline_provider,
                llm_model=offline_provider, github_webhook_secret=offline_provider,
                github_token=offline_provider, auto_post_review=False,
                repository_cache_root=str(Path(tmpdir, "cache")),
                repository_cache_min_free_bytes=1,
            )
            service = ReviewService(settings)
            self.addCleanup(service.queue.close)
            with unittest.mock.patch.object(
                service_module,
                "_warn_unmanaged_repository_cache_root",
                wraps=service_module._warn_unmanaged_repository_cache_root,
            ) as spy:
                service._ensure_repository_cache()
                service._ensure_repository_cache()  # second call: lazy singleton
            self.assertEqual(1, spy.call_count)
            self.assertEqual(
                str(Path(tmpdir, "cache")), spy.call_args[0][0]
            )
            self.assertEqual(
                str(Path(tmpdir, "cache").resolve()),
                str(service._ensure_repository_cache().root),
            )


if __name__ == "__main__":
    unittest.main()
