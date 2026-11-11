"""A scan renews only its own lease and stops renewal before cleanup."""

import threading
import unittest
from dataclasses import replace
from unittest import mock

from tests import test_verified_view_registration_wiring as wiring


class RenewalTests(unittest.TestCase):
    def test_service_lease_loss_aborts_scan_then_stops_renewal_before_release(self):
        from lima.build_agent import SUCCEEDED
        from lima.cxx_memory import CxxAnalyzerUnavailable
        from lima.verified_context_lease import VerifiedContextLease
        from tests import test_verified_view_execution_holders as holders
        from tests.test_build_consumption_wiring import make_build_result

        service, sidecar = holders.ExecutionHolderTests._service_with_sidecar(self)
        leases = []
        released_after_stop = []

        class Adapter:
            def register_verified_view(self, snapshot, view, *, holder=None):
                return sidecar.client.register_verified_view(snapshot, view, holder=holder)

            def renew_verified_view(self, snapshot, digest, *, holder):
                return False

            def unregister_verified_view(self, snapshot, digest, *, holder=None):
                released_after_stop.append(not leases[0].thread.is_alive())
                return sidecar.client.unregister_verified_view(snapshot, digest, holder=holder)

        service.repository_scanner.cxx_memory_adapter = Adapter()
        with mock.patch.object(service.queue, "submit"):
            task = service.enqueue_repository_scan("team/project", build_agent_mode="required")
        build = replace(
            make_build_result(SUCCEEDED, "run-1/pkg"),
            snapshot_hash=sidecar.snapshot_hash, artifact_digest=sidecar.digest,
        )

        def new_lease(renew):
            lease = VerifiedContextLease(renew, interval_seconds=0.01)
            leases.append(lease)
            return lease

        def scan(workspace, **kwargs):
            self.assertTrue(leases[0].lost.wait(2))
            kwargs["should_cancel"]()
            self.fail("lost lease allowed scan to continue")

        with (
            mock.patch.object(service, "_run_build_agent", return_value=build),
            mock.patch.object(service, "_consume_build_context", return_value=sidecar.view),
            mock.patch("lima.service.VerifiedContextLease", side_effect=new_lease),
            mock.patch.object(service.repository_scanner, "scan", side_effect=scan),
        ):
            with self.assertRaisesRegex(CxxAnalyzerUnavailable, "verified-context-lease-lost"):
                service._execute_repository_scan(
                    task["task_id"], sidecar.repository, "default", "team/project", {},
                    cxx_agent_mode="auto", build_agent_mode="required",
                )
        self.assertEqual(released_after_stop, [True])
        self.assertFalse(sidecar.client.confirmed_verified_view(
            sidecar.snapshot_hash, sidecar.digest,
        ))

    def test_http_renewal_requires_existing_matching_holder(self):
        case = wiring.SubprocessCrossProcessTests()
        self.addCleanup(case.doCleanups)
        case.setUp()
        self.assertTrue(case.client.register_verified_view(
            case.snapshot_hash, case.view, holder="live",
        ))
        self.assertTrue(case.client.renew_verified_view(
            case.snapshot_hash, case.digest, holder="live",
        ))
        self.assertFalse(case.client.renew_verified_view(
            case.snapshot_hash, case.digest, holder="not-owned",
        ))
        case.client.unregister_verified_view(case.snapshot_hash, case.digest, holder="live")
        self.assertFalse(case.client.renew_verified_view(
            case.snapshot_hash, case.digest, holder="live",
        ))

    def test_failed_renewal_is_observable_and_close_joins_worker(self):
        from lima.verified_context_lease import VerifiedContextLease

        attempted = threading.Event()

        def renew():
            attempted.set()
            return False

        lease = VerifiedContextLease(renew, interval_seconds=0.01)
        lease.start()
        self.addCleanup(lease.close)
        self.assertTrue(attempted.wait(2))
        self.assertTrue(lease.lost.wait(2))
        lease.close()
        self.assertFalse(lease.thread.is_alive())
