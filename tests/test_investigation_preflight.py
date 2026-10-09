"""Failure-sensitive checks for the reusable #264 offline rehearsal."""

import copy
import hashlib
import json
import socket
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from benchmarks.v4.preflight import investigation as probe


class InvestigationPreflightTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.records = {case: probe.run_case(case) for case in probe.CASES}

    def test_real_service_cases_preserve_scoped_claims(self):
        for case, record in self.records.items():
            with self.subTest(case=case):
                probe.validate_case(record)
                self.assertEqual(record["acceptance_264_real_model"], "not-demonstrated")
                self.assertEqual(record["network_attempts"], [])
        dynamic = self.records["dynamic-observation"]["report"]
        self.assertEqual(dynamic["risk"], "critical")
        self.assertEqual(len(dynamic["findings"]), 1)
        self.assertEqual(dynamic["adjudication"]["overall_disposition"], "needs_review")

    def test_tool_feedback_removal_is_detected(self):
        record = copy.deepcopy(self.records["dynamic-observation"])
        record["transcript"][-1]["messages"][-1]["content"] = "final without tool feedback"
        with self.assertRaisesRegex(ValueError, "feed the next"):
            probe.validate_case(record)

    def test_discovery_downgrade_and_evidence_loss_are_detected(self):
        original = self.records["module-discovery"]
        for mutation in ("risk", "evidence"):
            record = copy.deepcopy(original)
            if mutation == "risk":
                record["report"]["risk"] = "low"
            else:
                for decision in record["report"]["adjudication"]["decisions"]:
                    decision.pop("investigation_evidence_refs", None)
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                probe.validate_case(record)

    def test_snapshot_usage_and_mode_binding_are_checked(self):
        for key, replacement in (
            ("snapshot_digest", "0" * 64),
            ("scripted_transport_calls", 0),
            ("real_model_requests", 1),
            ("acceptance_264_real_model", "PASS"),
        ):
            record = copy.deepcopy(self.records["dynamic-observation"])
            record[key] = replacement
            with self.subTest(key=key), self.assertRaises(ValueError):
                probe.validate_case(record)

    def test_roundtrip_and_tamper_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            bundle = Path(directory) / "bundle"
            with patch.object(
                probe, "run_case", side_effect=lambda case: copy.deepcopy(self.records[case])
            ):
                probe.write_bundle(bundle)
            self.assertEqual(probe.validate_bundle(bundle)["real_model_requests"], 0)
            target = bundle / "module-timeout.json"
            record = json.loads(target.read_bytes())
            record["report"]["adjudication"]["overall_disposition"] = "clear"
            target.write_bytes(json.dumps(record).encode("utf-8"))
            with self.assertRaisesRegex(ValueError, "digest mismatch"):
                probe.validate_bundle(bundle)
            # Even updating the inventory hash cannot make an invalid outcome pass.
            manifest_path = bundle / "manifest.json"
            manifest = json.loads(manifest_path.read_bytes())
            manifest["files"][target.name] = hashlib.sha256(target.read_bytes()).hexdigest()
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "must not clear"):
                probe.validate_bundle(bundle)
            with patch.object(probe, "runtime_sources", return_value={}):
                with self.assertRaisesRegex(ValueError, "invalid offline manifest"):
                    probe.validate_bundle(bundle)
            with self.assertRaises(FileExistsError):
                probe.write_bundle(bundle)

    def test_manifest_cannot_select_arbitrary_artifact_paths(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "manifest.json").write_text(
                json.dumps(
                    {
                        "schema": "lima.offline-investigation-preflight.v1",
                        "mode": "scripted-offline",
                        "real_model_requests": 0,
                        "acceptance_264_real_model": "not-demonstrated",
                        "files": {"../outside.json": "0" * 64},
                    }
                ),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "invalid offline manifest"):
                probe.validate_bundle(root)

    def test_accidental_socket_use_is_blocked_and_cannot_pass(self):
        def attempt_network(transport, *args, **kwargs):
            socket.create_connection(("offline.invalid", 80))

        with patch.object(probe.OfflineTransport, "__call__", new=attempt_network):
            with self.assertRaisesRegex(ValueError, "network attempt"):
                probe.run_case("module-timeout")


if __name__ == "__main__":
    unittest.main()
