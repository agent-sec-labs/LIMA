"""Manifests domain payload tests (IP-0012 packet sections 7-13).

Frozen acceptance surface for the four manifest schemas (Task / ToolBundle /
Dependency / SandboxRun). Wire shapes, vocabularies, caps, invariants, golden
digest chains (real codec precomputation) and the manifests -> RunManifest
typed-path assertions (packet section 9, decision D3) are pinned here.

The module under test is imported in ``setUpClass`` so that in the RED state
(before ``lima/contracts/manifests.py`` is delivered) every test fails with
``ModuleNotFoundError: No module named 'lima.contracts.manifests'`` — the
single, explicit causal anchor of the frozen RED.
"""

import unittest
from pathlib import Path

from lima.contracts.codec import canonical_decode, compute_content_digest
from lima.contracts.common import SchemaVersion
from lima.contracts.errors import ContractError, ContractErrorCode
from lima.contracts.execution import decode_run_manifest_payload

V4 = SchemaVersion(4, 0)
V42 = SchemaVersion(4, 2)
FIXTURES = Path(__file__).resolve().parent / "fixtures"

# Frozen golden payload digests (IP-0001 codec precomputation; recomputed and
# byte-pinned by the tests below; cross-referenced between full fixtures).
D_TASK_MIN = "f5132c621edd58edbffd7408083ee303350c6236b27d2748f2906add4110d264"
D_TASK_FULL = "4f877245988a8fda3a4347e21f5c222960ea285a0c15ba35881ef4daf0bf6c7c"
D_TB_MIN = "50b8e53b62946b5dcb01a972754aad4b1bf6c69f05bc9525c7e0ee6aa7490ff6"
D_TB_FULL = "11d92b92c8da9ff61a4ebc8c65bcb26ad1c8f7d208074c0251910c215c327ccc"
D_DEP_MIN = "eaab702a3530635dd7b096c93990d3bc76117f04b89dd2163a5c16bed6e70e61"
D_DEP_FULL = "777741bef97042ea8e69d1c1483b796cfd42d5f6d427980a46232fcd7c79a511"
D_SB_MIN = "c774dbc55810606c924d87f46abd4280381fb13b3cfc4c707e18dc26c274c885"
D_SB_FULL = "398929c2277b99d45b30d28920921d787ee11112e44ec7b08e13bbb1ce8b066f"

GOLDEN_DIGESTS = {
    "task_manifest_v4_golden.json": D_TASK_MIN,
    "task_manifest_full_v4_golden.json": D_TASK_FULL,
    "tool_bundle_v4_golden.json": D_TB_MIN,
    "tool_bundle_full_v4_golden.json": D_TB_FULL,
    "dependency_manifest_v4_golden.json": D_DEP_MIN,
    "dependency_manifest_full_v4_golden.json": D_DEP_FULL,
    "sandbox_run_v4_golden.json": D_SB_MIN,
    "sandbox_run_full_v4_golden.json": D_SB_FULL,
}


def _wire(name):
    return canonical_decode((FIXTURES / name).read_bytes())


def _link_wire(kind, artifact_id, digest):
    return {
        "kind": kind,
        "artifact_id": artifact_id,
        "content_digest": digest,
        "schema_version": "4.0",
    }


def _task_wire(**overrides):
    wire = {
        "revision": 1,
        "hypothesis_ids": ["hyp-0001"],
        "tool_bundles": [],
        "dependencies": [],
        "harness_commands": [["python", "-m", "lima.mine", "--task", "task-0001"]],
        "oracle_kind": "deterministic_exit",
        "network_policy": "deny_all",
    }
    wire.update(overrides)
    return wire


def _tb_wire(**overrides):
    wire = {
        "revision": 1,
        "entries": [
            {
                "name": "tool-minimal-0001",
                "checksum": "a" * 64,
                "size_bytes": 1024,
                "executable": True,
                "license_word": "NOASSERTION",
            }
        ],
    }
    wire.update(overrides)
    return wire


def _dep_wire(**overrides):
    wire = {
        "revision": 1,
        "lock_digest": "d" * 64,
        "entries": [
            {
                "package": "pkg-minimal-0001",
                "version_str": "1.0.0",
                "source_kind": "registry",
                "checksum": "e" * 64,
                "offline_replay": True,
            }
        ],
    }
    wire.update(overrides)
    return wire


def _sb_wire(**overrides):
    wire = {
        "task": _link_wire("lima.task-manifest", "task-manifest-0001", D_TASK_MIN),
        "image_digest": "3" * 64,
        "tool_bundles": [],
        "mounts": ["workspace"],
        "commands": [["ls", "workspace"]],
        "resource_limits": {"cpu_seconds": 3600, "memory_mb": 4096, "max_processes": 64},
        "network_policy": "deny_all",
        "exit_code": 0,
        "log_artifact_ids": ["log-0001"],
    }
    wire.update(overrides)
    return wire


class _RejectionMixin:
    def _assert_rejected(self, invoke, code, field_path=None):
        with self.assertRaises(ContractError) as ctx:
            invoke()
        self.assertIs(ctx.exception.code, code)
        if field_path is not None:
            self.assertEqual(ctx.exception.field_path, field_path)
        return ctx.exception


class SchemaLiteralTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import lima.contracts.manifests

        cls.manifests = lima.contracts.manifests

    def test_schema_name_literals_and_reference_kind_are_frozen(self):
        self.assertEqual(self.manifests.TASK_MANIFEST_SCHEMA_NAME, "lima.task-manifest")
        self.assertEqual(self.manifests.TOOL_BUNDLE_SCHEMA_NAME, "lima.tool-bundle")
        self.assertEqual(
            self.manifests.DEPENDENCY_MANIFEST_SCHEMA_NAME, "lima.dependency-manifest"
        )
        self.assertEqual(self.manifests.SANDBOX_RUN_SCHEMA_NAME, "lima.sandbox-run")
        self.assertEqual(
            {member.value for member in self.manifests.ManifestReferenceKind},
            {
                "lima.task-manifest",
                "lima.tool-bundle",
                "lima.dependency-manifest",
                "lima.sandbox-run",
            },
        )


class TaskManifestPayloadTests(_RejectionMixin, unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import lima.contracts.manifests

        cls.manifests = lima.contracts.manifests

    def test_minimal_golden_decodes_and_round_trips(self):
        wire = _wire("task_manifest_v4_golden.json")
        task = self.manifests.decode_task_manifest_payload(wire, schema_version=V4)
        self.assertEqual(self.manifests.encode_task_manifest_payload(task), wire)

    def test_full_golden_reference_chain_digests_match_codec_recompute(self):
        wire = _wire("task_manifest_full_v4_golden.json")
        self.assertEqual(
            wire["tool_bundles"][0]["content_digest"],
            compute_content_digest(_wire("tool_bundle_full_v4_golden.json")),
        )
        self.assertEqual(
            wire["dependencies"][0]["content_digest"],
            compute_content_digest(_wire("dependency_manifest_full_v4_golden.json")),
        )
        task = self.manifests.decode_task_manifest_payload(wire, schema_version=V4)
        self.assertEqual(self.manifests.encode_task_manifest_payload(task), wire)

    def test_future_minor_unknown_fields_round_trip_preserved(self):
        wire = _task_wire(x_future_setting={"mode": "probe"})
        task = self.manifests.decode_task_manifest_payload(wire, schema_version=V42)
        self.assertEqual(self.manifests.encode_task_manifest_payload(task), wire)

    def test_current_minor_unknown_field_rejected(self):
        self._assert_rejected(
            lambda: self.manifests.decode_task_manifest_payload(
                _task_wire(x_future_setting={"mode": "probe"}), schema_version=V4
            ),
            ContractErrorCode.UNKNOWN_FIELD,
        )

    def test_rejects_missing_or_mistyped_required_fields(self):
        wire = _task_wire()
        del wire["network_policy"]
        self._assert_rejected(
            lambda: self.manifests.decode_task_manifest_payload(wire, schema_version=V4),
            ContractErrorCode.REQUIRED_FIELD_MISSING,
            "$.network_policy",
        )
        self._assert_rejected(
            lambda: self.manifests.decode_task_manifest_payload(
                _task_wire(revision="1"), schema_version=V4
            ),
            ContractErrorCode.INVALID_FIELD_TYPE,
            "$.revision",
        )

    def test_rejects_revision_below_one(self):
        self._assert_rejected(
            lambda: self.manifests.decode_task_manifest_payload(
                _task_wire(revision=0), schema_version=V4
            ),
            ContractErrorCode.INVALID_FIELD_VALUE,
            "$.revision",
        )

    def test_rejects_unknown_enum_values(self):
        self._assert_rejected(
            lambda: self.manifests.decode_task_manifest_payload(
                _task_wire(oracle_kind="fuzzy_match"), schema_version=V4
            ),
            ContractErrorCode.UNKNOWN_ENUM_VALUE,
            "$.oracle_kind",
        )
        self._assert_rejected(
            lambda: self.manifests.decode_task_manifest_payload(
                _task_wire(network_policy="allow_all"), schema_version=V4
            ),
            ContractErrorCode.UNKNOWN_ENUM_VALUE,
            "$.network_policy",
        )

    def test_rejects_unsorted_or_duplicate_links(self):
        links = [
            _link_wire("lima.tool-bundle", "tool-bundle-0002", "1" * 64),
            _link_wire("lima.tool-bundle", "tool-bundle-0001", "2" * 64),
        ]
        exception = self._assert_rejected(
            lambda: self.manifests.decode_task_manifest_payload(
                _task_wire(tool_bundles=links), schema_version=V4
            ),
            ContractErrorCode.INVALID_FIELD_VALUE,
        )
        self.assertTrue(exception.field_path.startswith("$.tool_bundles"))
        self._assert_rejected(
            lambda: self.manifests.decode_task_manifest_payload(
                _task_wire(hypothesis_ids=["hyp-0002", "hyp-0002"]), schema_version=V4
            ),
            ContractErrorCode.INVALID_FIELD_VALUE,
        )

    def test_rejects_cap_overflow(self):
        bundles = [
            _link_wire(
                "lima.tool-bundle", f"tool-bundle-{index:04d}", f"{index % 10}" * 64
            )
            for index in range(9)
        ]
        self._assert_rejected(
            lambda: self.manifests.decode_task_manifest_payload(
                _task_wire(tool_bundles=bundles), schema_version=V4
            ),
            ContractErrorCode.MAX_ARRAY_LENGTH_EXCEEDED,
            "$.tool_bundles",
        )
        hypotheses = [f"hyp-{index:04d}" for index in range(33)]
        self._assert_rejected(
            lambda: self.manifests.decode_task_manifest_payload(
                _task_wire(hypothesis_ids=hypotheses), schema_version=V4
            ),
            ContractErrorCode.MAX_ARRAY_LENGTH_EXCEEDED,
            "$.hypothesis_ids",
        )
        commands = [[f"cmd-{index:04d}"] for index in range(17)]
        self._assert_rejected(
            lambda: self.manifests.decode_task_manifest_payload(
                _task_wire(harness_commands=commands), schema_version=V4
            ),
            ContractErrorCode.MAX_ARRAY_LENGTH_EXCEEDED,
            "$.harness_commands",
        )

    def test_rejects_link_kind_mismatch(self):
        dependencies = [
            _link_wire("lima.tool-bundle", "dependency-manifest-0001", "1" * 64)
        ]
        self._assert_rejected(
            lambda: self.manifests.decode_task_manifest_payload(
                _task_wire(dependencies=dependencies), schema_version=V4
            ),
            ContractErrorCode.INVALID_FIELD_VALUE,
        )

    def test_rejects_harness_command_vocabulary_violations(self):
        self._assert_rejected(
            lambda: self.manifests.decode_task_manifest_payload(
                _task_wire(harness_commands=[["/bin/sh", "-c"]]), schema_version=V4
            ),
            ContractErrorCode.INVALID_FIELD_VALUE,
        )
        self._assert_rejected(
            lambda: self.manifests.decode_task_manifest_payload(
                _task_wire(harness_commands=[["python", "a;b"]]), schema_version=V4
            ),
            ContractErrorCode.INVALID_FIELD_VALUE,
        )
        long_command = [f"arg-{index:04d}" for index in range(33)]
        self._assert_rejected(
            lambda: self.manifests.decode_task_manifest_payload(
                _task_wire(harness_commands=[long_command]), schema_version=V4
            ),
            ContractErrorCode.MAX_ARRAY_LENGTH_EXCEEDED,
        )
        self._assert_rejected(
            lambda: self.manifests.decode_task_manifest_payload(
                _task_wire(harness_commands=[["python", "x" * 513]]), schema_version=V4
            ),
            ContractErrorCode.MAX_STRING_LENGTH_EXCEEDED,
        )


class ToolBundlePayloadTests(_RejectionMixin, unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import lima.contracts.manifests

        cls.manifests = lima.contracts.manifests

    def test_minimal_and_full_goldens_decode_and_round_trip(self):
        for name in ("tool_bundle_v4_golden.json", "tool_bundle_full_v4_golden.json"):
            wire = _wire(name)
            bundle = self.manifests.decode_tool_bundle_payload(wire, schema_version=V4)
            self.assertEqual(self.manifests.encode_tool_bundle_payload(bundle), wire)

    def test_full_golden_entries_are_sorted_and_licenses_are_worded(self):
        wire = _wire("tool_bundle_full_v4_golden.json")
        names = [entry["name"] for entry in wire["entries"]]
        self.assertEqual(names, sorted(names))
        self.assertEqual(
            [entry["license_word"] for entry in wire["entries"]],
            ["Apache-2.0", "MIT"],
        )

    def test_rejects_unsorted_or_duplicate_entries(self):
        entries = [
            {"name": "tool-b", "checksum": "1" * 64, "size_bytes": 1,
             "executable": False, "license_word": "MIT"},
            {"name": "tool-a", "checksum": "2" * 64, "size_bytes": 1,
             "executable": False, "license_word": "MIT"},
        ]
        exception = self._assert_rejected(
            lambda: self.manifests.decode_tool_bundle_payload(
                _tb_wire(entries=entries), schema_version=V4
            ),
            ContractErrorCode.INVALID_FIELD_VALUE,
        )
        self.assertTrue(exception.field_path.startswith("$.entries"))

    def test_rejects_cap_overflow(self):
        entries = [
            {"name": f"tool-{index:04d}", "checksum": f"{index % 10}" * 64,
             "size_bytes": 0, "executable": False, "license_word": "NOASSERTION"}
            for index in range(257)
        ]
        self._assert_rejected(
            lambda: self.manifests.decode_tool_bundle_payload(
                _tb_wire(entries=entries), schema_version=V4
            ),
            ContractErrorCode.MAX_ARRAY_LENGTH_EXCEEDED,
            "$.entries",
        )

    def test_rejects_bad_checksums_and_licenses(self):
        uppercase = [dict(_tb_wire()["entries"][0], checksum="A" * 64)]
        self._assert_rejected(
            lambda: self.manifests.decode_tool_bundle_payload(
                _tb_wire(entries=uppercase), schema_version=V4
            ),
            ContractErrorCode.INVALID_FIELD_VALUE,
        )
        url_license = [
            dict(_tb_wire()["entries"][0], license_word="https://example.com/mit")
        ]
        self._assert_rejected(
            lambda: self.manifests.decode_tool_bundle_payload(
                _tb_wire(entries=url_license), schema_version=V4
            ),
            ContractErrorCode.INVALID_FIELD_VALUE,
        )

    def test_rejects_size_bytes_out_of_range_and_mistyped_flags(self):
        negative = [dict(_tb_wire()["entries"][0], size_bytes=-1)]
        self._assert_rejected(
            lambda: self.manifests.decode_tool_bundle_payload(
                _tb_wire(entries=negative), schema_version=V4
            ),
            ContractErrorCode.INTEGER_OUT_OF_RANGE,
        )
        overflow = [dict(_tb_wire()["entries"][0], size_bytes=1 << 63)]
        self._assert_rejected(
            lambda: self.manifests.decode_tool_bundle_payload(
                _tb_wire(entries=overflow), schema_version=V4
            ),
            ContractErrorCode.INTEGER_OUT_OF_RANGE,
        )
        truthy = [dict(_tb_wire()["entries"][0], executable=1)]
        self._assert_rejected(
            lambda: self.manifests.decode_tool_bundle_payload(
                _tb_wire(entries=truthy), schema_version=V4
            ),
            ContractErrorCode.INVALID_FIELD_TYPE,
        )


class DependencyManifestPayloadTests(_RejectionMixin, unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import lima.contracts.manifests

        cls.manifests = lima.contracts.manifests

    def test_minimal_and_full_goldens_decode_and_round_trip(self):
        for name in (
            "dependency_manifest_v4_golden.json",
            "dependency_manifest_full_v4_golden.json",
        ):
            wire = _wire(name)
            manifest = self.manifests.decode_dependency_manifest_payload(
                wire, schema_version=V4
            )
            self.assertEqual(
                self.manifests.encode_dependency_manifest_payload(manifest), wire
            )

    def test_rejects_unknown_source_kind_and_bad_version_str(self):
        entries = [dict(_dep_wire()["entries"][0], source_kind="git")]
        self._assert_rejected(
            lambda: self.manifests.decode_dependency_manifest_payload(
                _dep_wire(entries=entries), schema_version=V4
            ),
            ContractErrorCode.UNKNOWN_ENUM_VALUE,
        )
        shell = [dict(_dep_wire()["entries"][0], version_str="1.0.0;rm -rf")]
        self._assert_rejected(
            lambda: self.manifests.decode_dependency_manifest_payload(
                _dep_wire(entries=shell), schema_version=V4
            ),
            ContractErrorCode.INVALID_FIELD_VALUE,
        )

    def test_rejects_bad_lock_digest_and_mistyped_flag(self):
        self._assert_rejected(
            lambda: self.manifests.decode_dependency_manifest_payload(
                _dep_wire(lock_digest="d" * 63), schema_version=V4
            ),
            ContractErrorCode.INVALID_FIELD_VALUE,
            "$.lock_digest",
        )
        entries = [dict(_dep_wire()["entries"][0], offline_replay="yes")]
        self._assert_rejected(
            lambda: self.manifests.decode_dependency_manifest_payload(
                _dep_wire(entries=entries), schema_version=V4
            ),
            ContractErrorCode.INVALID_FIELD_TYPE,
        )

    def test_rejects_cap_overflow(self):
        entries = [
            {"package": f"pkg-{index:04d}", "version_str": "1.0.0",
             "source_kind": "registry", "checksum": f"{index % 10}" * 64,
             "offline_replay": False}
            for index in range(513)
        ]
        self._assert_rejected(
            lambda: self.manifests.decode_dependency_manifest_payload(
                _dep_wire(entries=entries), schema_version=V4
            ),
            ContractErrorCode.MAX_ARRAY_LENGTH_EXCEEDED,
            "$.entries",
        )


class SandboxRunPayloadTests(_RejectionMixin, unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import lima.contracts.manifests

        cls.manifests = lima.contracts.manifests

    def test_minimal_and_full_goldens_decode_and_round_trip(self):
        for name in ("sandbox_run_v4_golden.json", "sandbox_run_full_v4_golden.json"):
            wire = _wire(name)
            run = self.manifests.decode_sandbox_run_payload(wire, schema_version=V4)
            self.assertEqual(self.manifests.encode_sandbox_run_payload(run), wire)

    def test_full_golden_reference_chain_digests_match_codec_recompute(self):
        wire = _wire("sandbox_run_full_v4_golden.json")
        self.assertEqual(
            wire["task"]["content_digest"],
            compute_content_digest(_wire("task_manifest_full_v4_golden.json")),
        )
        self.assertEqual(
            wire["tool_bundles"][0]["content_digest"],
            compute_content_digest(_wire("tool_bundle_full_v4_golden.json")),
        )

    def test_full_golden_exit_code_none_is_preserved_not_collapsed(self):
        wire = _wire("sandbox_run_full_v4_golden.json")
        run = self.manifests.decode_sandbox_run_payload(wire, schema_version=V4)
        encoded = self.manifests.encode_sandbox_run_payload(run)
        self.assertIs(encoded["exit_code"], None)

    def test_network_policy_consistency_with_task_is_enforced(self):
        wire = _sb_wire(network_policy="egress_allowlist")
        self._assert_rejected(
            lambda: self.manifests.decode_sandbox_run_payload(wire, schema_version=V4),
            ContractErrorCode.INVALID_FIELD_VALUE,
        )

    def test_rejects_mount_vocabulary_violations(self):
        absolute = _sb_wire(mounts=["/etc/passwd"])
        self._assert_rejected(
            lambda: self.manifests.decode_sandbox_run_payload(absolute, schema_version=V4),
            ContractErrorCode.INVALID_FIELD_VALUE,
        )
        traversal = _sb_wire(mounts=["data/../secrets"])
        self._assert_rejected(
            lambda: self.manifests.decode_sandbox_run_payload(traversal, schema_version=V4),
            ContractErrorCode.INVALID_FIELD_VALUE,
        )
        mounts = [f"mnt-{index:04d}" for index in range(65)]
        self._assert_rejected(
            lambda: self.manifests.decode_sandbox_run_payload(
                _sb_wire(mounts=mounts), schema_version=V4
            ),
            ContractErrorCode.MAX_ARRAY_LENGTH_EXCEEDED,
            "$.mounts",
        )

    def test_rejects_resource_limit_violations(self):
        limits = {"cpu_seconds": 0, "memory_mb": 4096, "max_processes": 64}
        self._assert_rejected(
            lambda: self.manifests.decode_sandbox_run_payload(
                _sb_wire(resource_limits=limits), schema_version=V4
            ),
            ContractErrorCode.INTEGER_OUT_OF_RANGE,
        )
        limits = {"cpu_seconds": 3600, "memory_mb": (1 << 21) + 1, "max_processes": 64}
        self._assert_rejected(
            lambda: self.manifests.decode_sandbox_run_payload(
                _sb_wire(resource_limits=limits), schema_version=V4
            ),
            ContractErrorCode.INTEGER_OUT_OF_RANGE,
        )
        limits = {"cpu_seconds": 3600, "memory_mb": 4096, "max_processes": 4097}
        self._assert_rejected(
            lambda: self.manifests.decode_sandbox_run_payload(
                _sb_wire(resource_limits=limits), schema_version=V4
            ),
            ContractErrorCode.INTEGER_OUT_OF_RANGE,
        )
        limits = {"cpu_seconds": True, "memory_mb": 4096, "max_processes": 64}
        self._assert_rejected(
            lambda: self.manifests.decode_sandbox_run_payload(
                _sb_wire(resource_limits=limits), schema_version=V4
            ),
            ContractErrorCode.INVALID_FIELD_TYPE,
        )
        limits = {"cpu_seconds": 3600, "max_processes": 64}
        self._assert_rejected(
            lambda: self.manifests.decode_sandbox_run_payload(
                _sb_wire(resource_limits=limits), schema_version=V4
            ),
            ContractErrorCode.REQUIRED_FIELD_MISSING,
        )

    def test_exit_code_boundaries(self):
        for bad in (-129, 256):
            self._assert_rejected(
                lambda bad=bad: self.manifests.decode_sandbox_run_payload(
                    _sb_wire(exit_code=bad), schema_version=V4
                ),
                ContractErrorCode.INVALID_FIELD_VALUE,
            )
        self._assert_rejected(
            lambda: self.manifests.decode_sandbox_run_payload(
                _sb_wire(exit_code=True), schema_version=V4
            ),
            ContractErrorCode.INVALID_FIELD_TYPE,
        )
        for good in (-128, 255):
            self.manifests.decode_sandbox_run_payload(
                _sb_wire(exit_code=good), schema_version=V4
            )

    def test_rejects_image_digest_tag_strings(self):
        self._assert_rejected(
            lambda: self.manifests.decode_sandbox_run_payload(
                _sb_wire(image_digest="sha256:latest"), schema_version=V4
            ),
            ContractErrorCode.INVALID_FIELD_VALUE,
            "$.image_digest",
        )


class GoldenDigestTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import lima.contracts.manifests

        cls.manifests = lima.contracts.manifests

    def test_all_golden_payload_digests_match_frozen_constants(self):
        for name, digest in GOLDEN_DIGESTS.items():
            self.assertEqual(
                compute_content_digest(_wire(name)),
                digest,
                name,
            )

    def test_run_manifest_golden_resource_ids_resolve_to_manifest_literals(self):
        wire = _wire("run_manifest_v4_golden.json")
        manifest = decode_run_manifest_payload(wire, schema_version=V4)
        self.assertTrue(
            set(manifest.resource_artifact_ids)
            <= {"sandbox-run-0001", "tool-bundle-0001"}
        )
        # Typed path is wire-value equality (packet D3): no execution symbol is
        # needed to compare the frozen lineage literals with manifest constants.
        self.assertEqual(self.manifests.SANDBOX_RUN_SCHEMA_NAME, "lima.sandbox-run")
        self.assertEqual(self.manifests.TOOL_BUNDLE_SCHEMA_NAME, "lima.tool-bundle")
        self.assertIn(
            "lima.sandbox-run",
            {m.value for m in self.manifests.ManifestReferenceKind},
        )
        self.assertIn(
            "lima.tool-bundle",
            {m.value for m in self.manifests.ManifestReferenceKind},
        )


if __name__ == "__main__":
    unittest.main()
