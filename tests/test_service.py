import os
import tempfile
import time
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from lima.config import Settings
from lima.cxx_memory import REQUESTED_LAYERS, SUPPORTED_CWES
from lima.service import AgentDetectionRequestError, ReviewService
from lima.workspace import (
    CXX_BUILD_EXTENSIONS,
    CXX_SOURCE_EXTENSIONS,
    DEFAULT_FILENAMES,
)


class ServiceTests(unittest.TestCase):
    def setUp(self):
        handle, self.path = tempfile.mkstemp(suffix=".db")
        os.close(handle)
        self.settings = Settings(
            host="127.0.0.1", port=8080, db_path=self.path, max_diff_bytes=10000,
            max_steps=8, timeout_seconds=120, llm_base_url="", llm_api_key="", llm_model="",
            github_webhook_secret="", github_token="", auto_post_review=False,
        )

    def tearDown(self):
        os.unlink(self.path)

    def test_end_to_end_review(self):
        diff = "--- a/a.py\n+++ b/a.py\n@@ -1 +1 @@\n-old\n+eval(data)\n"
        service = ReviewService(self.settings)
        result = service.create_review("org/repo", diff, 1)
        task = service.store.get(result["task_id"])
        service.queue.close()
        self.assertEqual("SUCCESS", result["state"])
        self.assertEqual("SEC-EVAL", result["report"]["findings"][0]["rule_id"])
        self.assertEqual(
            "plan-challenge-revise-evidence-verify-arbitrate",
            result["report"]["collaboration"]["protocol"],
        )
        self.assertGreater(result["report"]["collaboration"]["messages"], 0)
        self.assertEqual(
            "agreement-required-for-auto-clear-v1",
            result["report"]["adjudication"]["policy"],
        )
        self.assertEqual(
            "alert", result["report"]["adjudication"]["overall_disposition"]
        )
        self.assertEqual(
            "multi-agent-verification-approved-risk",
            result["report"]["adjudication"]["decisions"][0]["reason"],
        )
        self.assertEqual(
            result["report"]["adjudication"], task["report"]["adjudication"]
        )
        self.assertIn(
            "arbitration_decision", {item["kind"] for item in task["collaboration"]}
        )

    def test_rejects_large_diff(self):
        service = ReviewService(self.settings)
        with self.assertRaises(ValueError):
            service.create_review("org/repo", "x" * 10001)

    @patch("lima.service.CxxMemoryAnalyzerClient")
    def test_service_injects_configured_cxx_analyzer_client(self, client_class):
        client = client_class.return_value
        # Review round 3: the analyzer client is built only on explicit
        # opt-in, so the injection test enables the mode itself.
        settings = replace(self.settings, cxx_memory_mode="auto")

        service = ReviewService(settings)
        try:
            client_class.assert_called_once_with(
                self.settings.cxx_analyzer_url,
                timeout_seconds=self.settings.cxx_analysis_timeout_seconds,
                max_response_bytes=self.settings.cxx_max_response_bytes,
            )
            self.assertIs(client, service.repository_scanner.cxx_memory_adapter)
            self.assertEqual("auto", service.repository_scanner.cxx_memory_mode)
        finally:
            service.queue.close()

    @patch("lima.service.CxxMemoryAnalyzerClient")
    def test_service_skips_cxx_client_by_default(self, client_class):
        # Review round 3: default settings must not construct (or call) the
        # sidecar client; existing scans stay on their previous baseline.
        service = ReviewService(self.settings)
        try:
            client_class.assert_not_called()
            self.assertIsNone(service.repository_scanner.cxx_memory_adapter)
            self.assertEqual("off", service.repository_scanner.cxx_memory_mode)
        finally:
            service.queue.close()

    @patch("lima.service.CxxMemoryAnalyzerClient")
    def test_service_does_not_construct_cxx_client_when_disabled(self, client_class):
        settings = replace(self.settings, cxx_memory_mode="off")

        service = ReviewService(settings)
        try:
            client_class.assert_not_called()
            self.assertIsNone(service.repository_scanner.cxx_memory_adapter)
        finally:
            service.queue.close()

    def test_cxx_agent_capabilities_report_platform_only_topology(self):
        # Retirement Task 1: C++ PR scanning is offline; the repository
        # platform chain is the only advertised agent surface.
        settings = replace(
            self.settings, cxx_memory_mode="auto", cxx_agent_mode="auto"
        )
        service = ReviewService(settings)
        try:
            capabilities = service.repository_scan_capabilities()
            cxx = capabilities["cxx_agent"]
            self.assertFalse(cxx["pull_request_scan"])
            self.assertTrue(cxx["repository_scan"])
            self.assertFalse(cxx["automatic_repair"])
        finally:
            service.queue.close()

    def test_cxx_agent_capabilities_false_when_memory_off(self):
        # Review #225: with no sidecar adapter, the platform chain cannot
        # run and must not claim repository_scan capability.
        settings = replace(self.settings, cxx_agent_mode="auto")
        service = ReviewService(settings)
        try:
            capabilities = service.repository_scan_capabilities()
            cxx = capabilities["cxx_agent"]
            self.assertFalse(cxx["repository_scan"])
        finally:
            service.queue.close()

    def test_service_has_no_cxx_pr_injection(self):
        # The legacy PR snapshot flow and its merge reviewer are gone while
        # generic Python PR review keeps its single-result persistence.
        import inspect

        import lima.service as service_module

        source = inspect.getsource(service_module)
        self.assertNotIn("_CxxAgentMergeReviewer", source)
        self.assertNotIn("_review_pull_request_snapshot", source)

    def test_repository_scan_capabilities_describe_cxx_layers_without_url(self):
        settings = replace(self.settings, cxx_memory_mode="auto")
        service = ReviewService(settings)
        try:
            capabilities = service.repository_scan_capabilities()
            cxx = capabilities["cxx_memory"]

            self.assertEqual("auto", cxx["mode"])
            self.assertTrue(cxx["analyzer_configured"])
            self.assertEqual(sorted(CXX_SOURCE_EXTENSIONS), cxx["supported_extensions"])
            self.assertEqual(
                sorted(CXX_BUILD_EXTENSIONS), cxx["build_metadata_extensions"]

            )
            self.assertEqual(sorted(DEFAULT_FILENAMES), cxx["build_metadata_filenames"])
            self.assertEqual(sorted(SUPPORTED_CWES), cxx["supported_cwes"])
            self.assertEqual(list(REQUESTED_LAYERS), cxx["layers"])
            self.assertEqual("sidecar-managed", cxx["build_configuration_status"])
            self.assertEqual("sidecar-managed", cxx["test_configuration_status"])
            self.assertFalse(cxx["automatic_repair"])
            self.assertNotIn(self.settings.cxx_analyzer_url, str(capabilities))
        finally:
            service.queue.close()

    def test_repository_scan_forwards_normalized_repository_key(self):
        with tempfile.TemporaryDirectory() as temporary:
            repository = Path(temporary, "team", "project")
            repository.mkdir(parents=True)
            (repository / "app.py").write_text("safe = True\n", encoding="utf-8")
            settings = replace(
                self.settings,
                repository_import_root=temporary,
                repository_scan_sast_mode="off",
                cxx_memory_mode="off",
            )
            service = ReviewService(settings)
            try:
                with patch.object(
                    service.repository_scanner,
                    "scan",
                    wraps=service.repository_scanner.scan,
                ) as scan:
                    created = service.enqueue_repository_scan("team/project")
                    for _ in range(200):
                        task = service.store.get(created["task_id"])
                        if task and task["state"] in {"SUCCESS", "FAILED"}:
                            break
                        time.sleep(0.01)

                self.assertEqual("SUCCESS", task["state"])
                self.assertEqual("team/project", scan.call_args.kwargs["repository_key"])
            finally:
                service.queue.close()
    def test_required_repository_semantic_triage_needs_a_model(self):
        settings = Settings(**{
            **self.settings.__dict__,
            "repository_scan_llm_mode": "required",
        })

        with self.assertRaisesRegex(ValueError, "needs an LLM provider"):
            ReviewService(settings)

    def test_completed_review_feedback_is_persisted_and_listed_per_task(self):
        diff = "--- a/a.py\n+++ b/a.py\n@@ -1 +1 @@\n-old\n+eval(data)\n"
        service = ReviewService(self.settings)
        result = service.create_review("org/repo", diff, 1)
        task_id = result["task_id"]

        feedback = service.record_feedback(
            task_id, "false_positive", result["report"]["findings"][0], "不是实际风险",
        )

        self.assertEqual({"recorded": True, "category": "false_positive"}, feedback)
        cases = service.store.list_task_failure_cases(task_id, "default")
        self.assertEqual(1, len(cases))
        self.assertEqual("false_positive", cases[0]["category"])
        self.assertEqual("SEC-EVAL", cases[0]["payload"]["finding"]["rule_id"])
        service.queue.close()


class AgentDetectionEnqueueTests(unittest.TestCase):
    """按任务开启智能体检测的三态矩阵与入队快照（方案 §3.1/§3.2）。

    快照语义：模式在入队时解析一次并写入 task input / 队列消息，worker
    与重试都使用该快照；共享 scanner 的模式与工厂装配不受单次请求影响。
    """

    def setUp(self):
        handle, self.path = tempfile.mkstemp(suffix=".db")
        os.close(handle)
        # LIFO：先注册的清理最后执行——库文件删除必须等所有 service 关闭。
        self.addCleanup(os.unlink, self.path)
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        repository = Path(self.temporary.name, "team", "project")
        repository.mkdir(parents=True)
        (repository / "app.py").write_text("safe = True\n", encoding="utf-8")
        self.base = Settings(
            host="127.0.0.1", port=8080, db_path=self.path, max_diff_bytes=10000,
            max_steps=8, timeout_seconds=120, llm_base_url="", llm_api_key="",
            llm_model="", github_webhook_secret="", github_token="",
            auto_post_review=False, repository_import_root=self.temporary.name,
            repository_scan_sast_mode="off", cxx_memory_mode="off",
        )

    def _service(self, **overrides) -> ReviewService:
        service = ReviewService(replace(self.base, **overrides))
        self.addCleanup(service.queue.close)
        return service

    @staticmethod
    def _llm_overrides() -> dict:
        # custom provider 三件套齐备即可解析出 llm_config，不发起网络请求。
        return {
            "llm_provider": "custom",
            "llm_base_url": "http://127.0.0.1:9/v1",
            "llm_api_key": "unit-test-key",
            "llm_model": "unit-test-model",
        }

    def _task_input(self, service: ReviewService, created: dict) -> dict:
        return service.store.get(created["task_id"])["input"]

    def _wait_terminal(self, service: ReviewService, task_id: str) -> dict:
        task = {}
        for _ in range(200):
            task = service.store.get(task_id)
            if task and task["state"] in {"SUCCESS", "FAILED"}:
                break
            time.sleep(0.01)
        return task

    def test_absent_field_snapshots_server_default(self):
        # 旧客户端不传字段：off/auto/required 分别快照原模式，行为不变。
        for mode, expected in (
            ("off", "off"), ("auto", "auto"),
            ("required", "required"),
        ):
            with self.subTest(mode=mode):
                # required 部署的既有 config 约束：需要模型与事实分析器。
                overrides = {"cxx_agent_mode": mode}
                if mode == "required":
                    overrides.update(
                        cxx_agent_model="unit-test-model", cxx_memory_mode="auto"
                    )
                service = self._service(**overrides)
                # 只验证入队快照：拦截 submit，避免 required 任务在
                # worker 里因无真实 Sidecar 而反复重试。
                with patch.object(service.queue, "submit"):
                    created = service.enqueue_repository_scan("team/project")
                task_input = self._task_input(service, created)
                self.assertIsNone(task_input["agent_detection"])
                self.assertEqual(
                    expected, task_input["effective_cxx_agent_mode"]
                )

    def test_true_upgrades_off_to_auto_and_keeps_factories_assembled(self):
        service = self._service(cxx_memory_mode="auto", **self._llm_overrides())
        created = service.enqueue_repository_scan(
            "team/project", agent_detection=True
        )
        task_input = self._task_input(service, created)
        self.assertTrue(task_input["agent_detection"])
        self.assertEqual("auto", task_input["effective_cxx_agent_mode"])
        # 共享 scanner 状态不被任务改写；全局 off 不再导致工厂缺席。
        self.assertEqual("off", service.repository_scanner.cxx_agent_mode)
        self.assertIsNotNone(service.repository_scanner.cxx_agent_budget_factory)
        self.assertIsNotNone(service.repository_scanner.cxx_uaf_llm_factory)

    def test_false_disables_this_task_and_leaves_server_default_intact(self):
        service = self._service(cxx_agent_mode="auto")
        disabled = service.enqueue_repository_scan(
            "team/project", agent_detection=False
        )
        disabled_input = self._task_input(service, disabled)
        self.assertFalse(disabled_input["agent_detection"])
        self.assertEqual("off", disabled_input["effective_cxx_agent_mode"])
        # 后续不传字段的任务仍按服务端默认，不受上一次关闭影响。
        default = service.enqueue_repository_scan("team/project")
        self.assertEqual(
            "auto", self._task_input(service, default)["effective_cxx_agent_mode"]
        )

    def test_false_is_rejected_under_required_policy(self):
        # required 部署必须配置模型与事实分析器（config 的既有约束）。
        service = self._service(
            cxx_agent_mode="required",
            cxx_agent_model="unit-test-model",
            cxx_memory_mode="auto",
        )
        with self.assertRaises(AgentDetectionRequestError) as ctx:
            service.enqueue_repository_scan("team/project", agent_detection=False)
        self.assertEqual("agent-detection-required", ctx.exception.code)

    def test_true_without_llm_is_named_unavailable(self):
        service = self._service(cxx_memory_mode="auto")
        with self.assertRaises(AgentDetectionRequestError) as ctx:
            service.enqueue_repository_scan("team/project", agent_detection=True)
        self.assertEqual("agent-detection-unavailable", ctx.exception.code)
        self.assertIn("LLM", str(ctx.exception))

    def test_true_without_facts_analyzer_is_named_analyzer_unavailable(self):
        service = self._service(cxx_memory_mode="off", **self._llm_overrides())
        with self.assertRaises(AgentDetectionRequestError) as ctx:
            service.enqueue_repository_scan("team/project", agent_detection=True)
        self.assertEqual(
            "agent-detection-analyzer-unavailable", ctx.exception.code
        )

    def test_github_source_snapshots_the_same_switch_and_message(self):
        # GitHub 来源与本地 repository_key 同一开关语义；队列消息携带
        # 快照模式，重试沿用同一份（不在本测试里真的物化远端仓库）。
        service = self._service(
            repository_scan_sources="both",
            cxx_memory_mode="auto",
            **self._llm_overrides(),
        )
        with patch.object(service.queue, "submit") as submit:
            created = service.enqueue_repository_scan_source(
                {"type": "github", "url": "https://github.com/team/project"},
                agent_detection=True,
            )
        task_input = self._task_input(service, created)
        self.assertTrue(task_input["agent_detection"])
        self.assertEqual("auto", task_input["effective_cxx_agent_mode"])
        message = submit.call_args.args[0]
        self.assertEqual("auto", message["effective_cxx_agent_mode"])

    def test_worker_uses_snapshot_mode_not_shared_scanner_state(self):
        service = self._service(cxx_agent_mode="auto")
        with patch.object(
            service.repository_scanner, "scan",
            wraps=service.repository_scanner.scan,
        ) as scan:
            created = service.enqueue_repository_scan(
                "team/project", agent_detection=False
            )
            task = self._wait_terminal(service, created["task_id"])
        self.assertEqual("SUCCESS", task["state"])
        self.assertEqual("off", scan.call_args.kwargs["cxx_agent_mode"])
        self.assertEqual("auto", service.repository_scanner.cxx_agent_mode)

    def test_platform_llm_factory_keeps_provider_default_model(self):
        # 复审问题 1 复现：全局 off + DeepSeek（未显式指定模型）+ 按任务
        # 开启——工厂必须保留 provider 已解析的默认模型，不得用空串覆盖。
        service = self._service(
            llm_provider="deepseek", deepseek_api_key="unit-test-key",
        )
        factory = service.repository_scanner.cxx_uaf_llm_factory
        self.assertIsNotNone(factory)
        resolved = factory()
        self.assertEqual("deepseek-v4-flash", resolved["model"])
        self.assertEqual("deepseek", resolved["provider"])

        # 显式 LIMA_CXX_AGENT_MODEL 覆盖仍然生效（模型不能被调用方指定，
        # 只由管理员配置决定）。
        overridden = self._service(
            llm_provider="deepseek",
            deepseek_api_key="unit-test-key",
            cxx_agent_model="cxx-custom-model",
        )
        self.assertEqual(
            "cxx-custom-model",
            overridden.repository_scanner.cxx_uaf_llm_factory()["model"],
        )

        # capabilities 的 model 展示与工厂同源：不显示空串。
        visible = self._service(
            llm_provider="deepseek",
            deepseek_api_key="unit-test-key",
            cxx_agent_mode="auto",
        )
        caps = visible.repository_scan_capabilities()["cxx_agent"]
        self.assertEqual("deepseek-v4-flash", caps["model"])

    def test_capabilities_expose_per_request_contract(self):
        service = self._service(
            cxx_agent_mode="auto", cxx_memory_mode="auto", **self._llm_overrides()
        )
        cxx = service.repository_scan_capabilities()["cxx_agent"]
        self.assertTrue(cxx["per_request_switch"])
        self.assertTrue(cxx["llm_configured"])
        self.assertTrue(cxx["analyzer_configured"])
        self.assertEqual(
            service.settings.cxx_agent_max_calls, cxx["max_agent_calls"]
        )

        required = self._service(
            cxx_agent_mode="required",
            cxx_agent_model="unit-test-model",
            cxx_memory_mode="auto",
        )
        self.assertFalse(
            required.repository_scan_capabilities()["cxx_agent"]["per_request_switch"]
        )

        unconfigured = self._service(cxx_agent_mode="off")
        caps = unconfigured.repository_scan_capabilities()["cxx_agent"]
        self.assertFalse(caps["llm_configured"])
        self.assertFalse(caps["analyzer_configured"])


if __name__ == "__main__":
    unittest.main()
