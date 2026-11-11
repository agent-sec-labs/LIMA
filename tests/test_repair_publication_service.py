"""The public repair entry point passes immutable audit identity to publication."""

import unittest
from unittest import mock

from lima.config import Settings
from lima.service import ReviewService


class RepairPublicationServiceTests(unittest.TestCase):
    def _service(self, *, state="SUCCESS", head="a" * 40):
        task = {
            "state": state, "repository": "org/repo", "pull_request": 7,
            "tenant_id": "default", "input": {
                "head_sha": head,
                "diff_source": "pinned-compare-v1",
                "github_auth": {"mode": "pat"},
            },
            "report": {"findings": []},
        }

        class Store:
            def get(self, task_id, tenant_id=None):
                return task

            def repository_allowed(self, *args):
                return True

        class Fixer:
            def create_fix_commits(self, *args, **kwargs):
                return {"source_sha": kwargs.get("expected_source_sha")}

        service = object.__new__(ReviewService)
        service.store = Store()
        service.fixer = Fixer()
        service.github_client_for_installation = (
            lambda installation_id=None, *, tenant_id: object()
        )
        return service

    def test_passes_audited_head_to_fixer(self):
        result = self._service().create_fix("task")
        self.assertEqual(result["source_sha"], "a" * 40)

    def test_failed_task_cannot_publish_retained_report(self):
        with self.assertRaisesRegex(ValueError, "completed"):
            self._service(state="FAILED").create_fix("task")

    def test_old_mutable_diff_report_cannot_publish_even_with_head_sha(self):
        service = self._service()
        del service.store.get("task")["input"]["diff_source"]
        with self.assertRaisesRegex(ValueError, "repair-source-unverified"):
            service.create_fix("task")

    def test_missing_or_short_source_identity_is_refused(self):
        for head in ("", "abc", "feature", "a" * 39):
            with self.subTest(head=head), self.assertRaisesRegex(ValueError, "repair-source"):
                self._service(head=head).create_fix("task")

    def test_sandbox_image_is_explicit_deployment_configuration(self):
        with mock.patch.dict(
            "os.environ", {"LIMA_REPAIR_SANDBOX_IMAGE": "approved:local"}, clear=True,
        ):
            settings = Settings.from_env()
        self.assertEqual(settings.repair_sandbox_image, "approved:local")
