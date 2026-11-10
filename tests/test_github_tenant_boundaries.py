"""Installation ownership and task credentials remain tenant-bound."""

import json
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from lima.models import ReviewReport, TaskState, TraceEvent
from lima.service import ReviewService
from lima.store import TaskStore


class GitHubTenantBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.store = TaskStore(str(Path(self.temporary.name, "tasks.db")))
        self.store.save_installation(111, "org-a", "tenant-a")
        self.store.save_installation(222, "org-b", "tenant-b")
        self.service = object.__new__(ReviewService)
        self.service.store = self.store
        self.service.settings = SimpleNamespace(
            github_app_id="app",
            github_private_key_path="key",
            default_tenant_id="default",
            github_installation_tenants='{"111":"tenant-a","222":"tenant-b"}',
            auto_post_review=False,
        )
        self.service.github = mock.sentinel.global_pat
        self.service.fixer = mock.Mock()
        self.service.fixer.create_fix_commits.return_value = {}
        self.service.releases = SimpleNamespace(
            assignment=lambda *a: {"lane": "stable", "shadow": False}
        )
        self.service.queue = SimpleNamespace(backend="test", submit=mock.Mock())
        self.service._dispatch_webhook_outbox = mock.Mock()

    def task(self, auth):
        self.store.create(
            "abc",
            "org/repo",
            7,
            {
                "head_sha": "a" * 40,
                "diff_source": "pinned-compare-v1",
                "github_auth": auth,
            },
            "tenant-a",
        )
        self.store.grant_repository("tenant-a", "org/repo", auto_fix=True)
        self.store.succeed(
            "abc",
            ReviewReport("org/repo", 7, "done", "low"),
            TraceEvent(1, TaskState.SUCCESS, "done", "2026-11-10T00:00:00Z"),
        )

    def test_cross_tenant_installation_is_rejected_before_token_request(self):
        self.task({"mode": "app", "installation_id": 111})
        with mock.patch("lima.service.GitHubAppAuthenticator") as authenticator:
            with self.assertRaises(PermissionError):
                self.service.create_fix("abc", 222, "tenant-a")
            authenticator.assert_not_called()
        self.service.fixer.create_fix_commits.assert_not_called()

    def test_omitted_parameter_uses_task_installation_instead_of_global_pat(self):
        self.task({"mode": "app", "installation_id": 111})
        with mock.patch("lima.service.GitHubAppAuthenticator") as authenticator:
            authenticator.return_value.installation_token.return_value = "fixture-token"
            self.service.create_fix("abc", tenant_id="tenant-a")
            authenticator.return_value.installation_token.assert_called_once_with(111)
        self.assertIsNot(
            self.service.fixer.create_fix_commits.call_args.args[0], self.service.github
        )

    def test_legacy_task_without_credential_binding_cannot_fall_back(self):
        self.task(None)
        with self.assertRaises(PermissionError):
            self.service.create_fix("abc", tenant_id="tenant-a")

    def test_installation_owner_cannot_be_replaced(self):
        with self.assertRaises(PermissionError):
            self.store.save_installation(222, "org-b", "tenant-a")
        self.assertEqual("tenant-b", self.store.installation_tenant(222))
        self.store.save_installation(222, "new-label", "tenant-b")

    def test_app_webhook_unknown_missing_or_conflicting_tenant_is_rejected(self):
        for identity, override in ((999, ""), (None, ""), (222, "tenant-a")):
            payload = {
                "action": "opened",
                "repository": {"full_name": "org/repo"},
                "number": 7,
                "installation": {"id": identity} if identity is not None else {},
                "pull_request": {
                    "diff_url": "https://github.com/org/repo/pull/7.diff",
                    "head": {"sha": "a" * 40},
                    "base": {"sha": "b" * 40},
                },
            }
            with (
                self.subTest(identity=identity, override=override),
                self.assertRaises(PermissionError),
            ):
                self.service.handle_github_pull_request(payload, str(identity), "digest", override)
        self.service._dispatch_webhook_outbox.assert_not_called()

    def test_unapproved_initial_registration_is_rejected(self):
        with self.assertRaises(PermissionError):
            self.service.register_github_installation(333, "unproven", "tenant-a")
        self.assertIsNone(self.store.installation_tenant(333))

    def test_server_provisioned_registration_is_idempotent(self):
        self.service.register_github_installation(111, "label", "tenant-a")
        self.assertEqual("tenant-a", self.store.installation_tenant(111))

    def test_configured_owner_must_match_registered_owner(self):
        self.task({"mode": "app", "installation_id": 111})
        self.service.settings.github_installation_tenants = json.dumps({"111": "tenant-b"})
        with mock.patch("lima.service.GitHubAppAuthenticator") as authenticator:
            with self.assertRaises(PermissionError):
                self.service.create_fix("abc", tenant_id="tenant-a")
            authenticator.assert_not_called()

    def test_pat_is_single_tenant_and_cannot_override_bound_app(self):
        self.service.settings.github_app_id = ""
        self.service.settings.github_private_key_path = ""
        self.assertEqual({"mode": "pat"}, self.service._github_auth_binding("default"))
        with self.assertRaises(PermissionError):
            self.service._github_auth_binding("tenant-a")
        with self.assertRaises(PermissionError):
            self.service._github_auth_binding("default", 222)

    def test_unknown_invalid_and_duplicate_config_entries_fail_closed(self):
        from lima.github_identity import installation_bindings, installation_id

        for value in (True, False, "111", 0, -1, 2**63):
            with self.subTest(value=value), self.assertRaises(ValueError):
                installation_id(value)
        for value in ("[]", '{"01":"tenant"}', '{"1":" "}', '{"1":"a","1":"b"}'):
            with self.subTest(value=value), self.assertRaises(ValueError):
                installation_bindings(value)

    def test_registered_app_webhook_persists_the_credential_binding(self):
        payload = {
            "action": "opened",
            "repository": {"full_name": "org/repo"},
            "number": 7,
            "installation": {"id": 111},
            "pull_request": {
                "diff_url": "https://github.com/org/repo/pull/7.diff",
                "head": {"sha": "a" * 40},
                "base": {"sha": "b" * 40},
            },
        }
        result = self.service.handle_github_pull_request(payload, "known", "digest")
        task = self.store.get(result["task_id"], "tenant-a")
        self.assertEqual({"mode": "app", "installation_id": 111}, task["input"]["github_auth"])

    def test_concurrent_stores_cannot_replace_an_installation_owner(self):
        barrier = threading.Barrier(2)

        def save(tenant):
            store = TaskStore(str(Path(self.temporary.name, "tasks.db")))
            barrier.wait(timeout=10)
            try:
                store.save_installation(333, "org", tenant)
                return tenant
            except PermissionError:
                return None

        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(save, ("tenant-a", "tenant-b")))
        self.assertEqual(1, sum(result is not None for result in results))
        self.assertEqual(
            next(result for result in results if result), self.store.installation_tenant(333)
        )

    def test_postgres_upsert_semantics_reject_owner_replacement(self):
        # Exercise the PostgreSQL statement against SQLite's compatible UPSERT
        # grammar; this verifies its predicate, not a live PostgreSQL deployment.
        from lima.postgres_store import PostgresTaskStore

        service = object.__new__(PostgresTaskStore)

        @contextmanager
        def connect():
            with self.store._connect() as connection:
                yield SimpleNamespace(
                    execute=lambda sql, args: connection.execute(sql.replace("%s", "?"), args)
                )

        service._connect = connect
        with self.assertRaises(PermissionError):
            service.save_installation(222, "org-b", "tenant-a")
        service.save_installation(222, "label", "tenant-b")
        self.assertEqual("tenant-b", self.store.installation_tenant(222))
