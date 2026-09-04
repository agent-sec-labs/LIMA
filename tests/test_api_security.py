"""HTTP 安全边界回归测试。

覆盖三项安全修复：
- ``GET /github/setup`` 不再执行任何服务端写入，只把安装参数转发给管理台；
  登记动作由已认证管理员通过 ``POST /v1/github/installations`` 完成，
  并绑定注册者租户、写入审计日志。
- 未处理的 POST 异常返回通用 500，不向客户端泄露内部异常详情。
- ``repository_allowed`` 对自动修复（GitHub 写操作）fail-closed：
  没有显式 ``auto_fix`` 授权时拒绝；授权通过 ``/v1/repository-grants`` 管理。
"""
import http.client
import json
import os
import tempfile
import threading
import unittest
from http.server import ThreadingHTTPServer

from lima.api import ApiHandler
from lima.auth import hash_password
from lima.config import Settings
from lima.models import ReviewReport, TaskState, TraceEvent
from lima.service import ReviewService
from lima.store import TaskStore

AUTH_SIGNING_KEY = "unit-test-auth-secret-0123456789abcdef"
BOOTSTRAP_CREDENTIAL = "bootstrap-password"


def make_settings(db_path: str) -> Settings:
    return Settings(
        host="127.0.0.1", port=0, db_path=db_path, max_diff_bytes=100000,
        max_steps=8, timeout_seconds=120, llm_base_url="", llm_api_key="",
        llm_model="", github_webhook_secret="", github_token="",
        auto_post_review=False, auth_required=True, auth_secret=AUTH_SIGNING_KEY,
        bootstrap_admin_username="admin", bootstrap_admin_password=BOOTSTRAP_CREDENTIAL,
    )


class ApiSecurityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        handle, cls.db_path = tempfile.mkstemp(suffix=".db")
        os.close(handle)
        cls.service = ReviewService(make_settings(cls.db_path))
        cls.tenant = cls.service.settings.default_tenant_id
        cls.service.store.create_user(
            "auditor-user", "audrey", hash_password("auditor-password"),
            cls.tenant, "auditor",
        )
        handler = type("TestApiHandler", (ApiHandler,), {
            "service": cls.service, "settings": cls.service.settings,
        })
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        cls.port = cls.server.server_address[1]
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.service.close()
        os.unlink(cls.db_path)

    def request(self, method, path, token="", body=None):
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        headers = {}
        if token:
            headers["Authorization"] = "Bearer " + token
        payload = None
        if body is not None:
            payload = json.dumps(body).encode("utf-8")
            headers["Content-Type"] = "application/json"
        try:
            connection.request(method, path, body=payload, headers=headers)
            response = connection.getresponse()
            raw = response.read().decode("utf-8")
            response_headers = dict(response.getheaders())
            status = response.status
        finally:
            connection.close()
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError:
            parsed = raw
        return status, response_headers, parsed

    def login(self, username, password):
        status, _, body = self.request(
            "POST", "/v1/auth/login",
            body={"username": username, "password": password},
        )
        self.assertEqual(200, status, body)
        return body["access_token"]

    def audit_actions(self):
        return [event["action"] for event in self.service.store.list_audit(self.tenant)]

    def test_github_setup_get_never_writes_installations(self):
        status, headers, _ = self.request(
            "GET", "/github/setup?installation_id=42&account=octo")
        self.assertEqual(302, status)
        location = headers.get("Location", "")
        # T10：回跳目标切换到 React 设置页（legacy #github-install 已退役）。
        self.assertTrue(location.startswith("/app/#/settings?"), location)
        self.assertIn("github_installation=42", location)
        # 未认证的浏览器回跳不得产生任何登记副作用
        self.assertIsNone(self.service.store.installation_tenant(42))

    def test_root_redirects_to_react_app_and_fails_closed_without_build(self):
        from unittest import mock

        from lima import api as api_module

        with tempfile.TemporaryDirectory() as dist:
            with mock.patch.object(api_module, "APP_DIST_ROOT", dist):
                status, headers, _ = self.request("GET", "/")
        self.assertEqual(302, status)
        self.assertEqual("/app/", headers.get("Location"))

        with mock.patch.object(
            api_module, "APP_DIST_ROOT", os.path.join(tempfile.gettempdir(), "lima-absent-dist")
        ):
            status, _, body = self.request("GET", "/")
        self.assertEqual(404, status, body)
        self.assertEqual("frontend build not present", body.get("error"))

    def test_github_setup_rejects_invalid_installation_id(self):
        for value in ("", "abc", "-3", "12;drop"):
            status, _, _ = self.request(
                "GET", "/github/setup?installation_id=" + value)
            self.assertEqual(400, status, value)

    def test_installation_registration_requires_manage(self):
        self.assertIsNone(self.service.store.installation_tenant(501))
        status, _, _ = self.request("POST", "/v1/github/installations", body={
            "installation_id": 501, "account": "octo",
        })
        self.assertEqual(403, status)
        self.assertIsNone(self.service.store.installation_tenant(501))

        auditor = self.login("audrey", "auditor-password")
        status, _, body = self.request(
            "POST", "/v1/github/installations", token=auditor,
            body={"installation_id": 501, "account": "octo"},
        )
        self.assertEqual(403, status)
        self.assertIsNone(self.service.store.installation_tenant(501))

        admin = self.login("admin", BOOTSTRAP_CREDENTIAL)
        status, _, body = self.request(
            "POST", "/v1/github/installations", token=admin,
            body={"installation_id": 501, "account": "octo"},
        )
        self.assertEqual(201, status)
        self.assertEqual(self.tenant, body["tenant_id"])
        self.assertEqual(self.tenant, self.service.store.installation_tenant(501))
        self.assertIn("github.installation.register", self.audit_actions())

        status, _, _ = self.request(
            "POST", "/v1/github/installations", token=admin,
            body={"installation_id": 0},
        )
        self.assertEqual(400, status)

    def test_unhandled_error_returns_generic_500(self):
        admin = self.login("admin", BOOTSTRAP_CREDENTIAL)
        original = self.service.create_review

        def exploding_review(*args, **kwargs):
            raise RuntimeError("internal secret path D:\\secret-token")

        self.service.create_review = exploding_review
        try:
            status, _, body = self.request(
                "POST", "/v1/reviews", token=admin,
                body={"repository": "org/repo", "diff": "+eval(data)\n"},
            )
        finally:
            self.service.create_review = original
        self.assertEqual(500, status)
        self.assertEqual("operation failed", body.get("error"))
        self.assertNotIn("detail", body)
        self.assertNotIn("secret", json.dumps(body))

    def test_repository_grants_api_requires_manage(self):
        auditor = self.login("audrey", "auditor-password")
        status, _, _ = self.request("GET", "/v1/repository-grants", token=auditor)
        self.assertEqual(403, status)
        status, _, _ = self.request(
            "POST", "/v1/repository-grants", token=auditor,
            body={"repository": "org/repo", "auto_fix": True},
        )
        self.assertEqual(403, status)

    def test_repository_grants_api_manages_autofix_grants(self):
        admin = self.login("admin", BOOTSTRAP_CREDENTIAL)
        status, _, body = self.request("GET", "/v1/repository-grants", token=admin)
        self.assertEqual(200, status)
        before = len(body["grants"])

        status, _, body = self.request(
            "POST", "/v1/repository-grants", token=admin,
            body={"repository": "../escape", "auto_fix": True},
        )
        self.assertEqual(400, status)

        status, _, body = self.request(
            "POST", "/v1/repository-grants", token=admin,
            body={"repository": "org/repo", "auto_fix": "yes"},
        )
        self.assertEqual(400, status)

        status, _, body = self.request(
            "POST", "/v1/repository-grants", token=admin,
            body={"repository": "org/pinned", "auto_fix": True},
        )
        self.assertEqual(201, status)
        self.assertEqual({"repository": "org/pinned", "auto_fix": True}, body)
        self.assertTrue(self.service.store.repository_allowed(
            self.tenant, "org/pinned", True))

        status, _, body = self.request("GET", "/v1/repository-grants", token=admin)
        self.assertEqual(200, status)
        self.assertEqual(before + 1, len(body["grants"]))
        self.assertIn("repository.grant", self.audit_actions())

    def test_create_fix_denied_without_explicit_grant(self):
        store = self.service.store
        store.create("fix-task", "org/repo", 7, {}, "tenant-fix")
        store.succeed(
            "fix-task",
            ReviewReport(repository="org/repo", pull_request=7,
                         summary="done", risk="low"),
            TraceEvent(1, TaskState.SUCCESS, "done", "2026-01-01T00:00:00Z"),
        )
        with self.assertRaises(PermissionError):
            self.service.create_fix("fix-task", tenant_id="tenant-fix")


class RepositoryGrantPolicyTests(unittest.TestCase):
    def setUp(self):
        handle, self.path = tempfile.mkstemp(suffix=".db")
        os.close(handle)
        self.store = TaskStore(self.path)

    def tearDown(self):
        os.unlink(self.path)

    def test_auto_fix_fails_closed_without_explicit_grant(self):
        tenant = "tenant-a"
        # 零授权租户：只读审查保持放行（兼容默认部署），自动修复 fail-closed。
        self.assertTrue(self.store.repository_allowed(tenant, "org/any"))
        self.assertFalse(self.store.repository_allowed(tenant, "org/any", True))

        self.store.grant_repository(tenant, "org/allowed", auto_fix=True)
        self.assertTrue(self.store.repository_allowed(tenant, "org/allowed", True))
        # 一旦配置了授权列表，未列出的仓库审查与修复都必须拒绝。
        self.assertFalse(self.store.repository_allowed(tenant, "org/other"))
        self.assertFalse(self.store.repository_allowed(tenant, "org/other", True))

        self.store.grant_repository(tenant, "org/readonly", auto_fix=False)
        self.assertTrue(self.store.repository_allowed(tenant, "org/readonly"))
        self.assertFalse(self.store.repository_allowed(tenant, "org/readonly", True))

    def test_list_repository_grants_is_tenant_scoped(self):
        self.store.grant_repository("t1", "org/a", True)
        self.store.grant_repository("t2", "org/b", False)
        self.assertEqual(
            [{"repository": "org/a", "auto_fix": True}],
            self.store.list_repository_grants("t1"),
        )
        self.assertEqual(
            [{"repository": "org/b", "auto_fix": False}],
            self.store.list_repository_grants("t2"),
        )
        self.assertEqual([], self.store.list_repository_grants("t3"))


if __name__ == "__main__":
    unittest.main()
