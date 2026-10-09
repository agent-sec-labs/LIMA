"""#93 public-contract consumer checks; no changes to #60 fixtures/classifier."""

import copy
import json
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from benchmarks.v4.preflight.profile_consumer import (
    PROFILE_SAMPLE,
    ProfileBinding,
    consume_profile,
    main,
    run_profile_probe,
)
from lima.contracts.codec import canonical_encode, compute_content_digest
from lima.contracts.common import SchemaVersion
from lima.contracts.errors import ContractError
from lima.contracts.profile import (
    CodeRole,
    CodeRoleAssignment,
    SupportLevel,
    decode_profile_envelope,
    decode_profile_payload,
    encode_profile_envelope,
    encode_profile_payload,
)


class ProfileConsumerPreflightTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.record = run_profile_probe()
        cls.data = canonical_encode(cls.record["profile_envelope"])
        cls.envelope, cls.profile = decode_profile_envelope(cls.data)
        cls.binding = ProfileBinding(
            **{field: getattr(cls.envelope, field) for field in ProfileBinding.__dataclass_fields__}
        )

    def _data_for(self, **changes):
        profile = replace(self.profile, **changes)
        payload = encode_profile_payload(profile)
        envelope = replace(
            self.envelope, payload=payload, content_digest=compute_content_digest(payload)
        )
        return encode_profile_envelope(envelope, profile)

    def _assignment(self, role, path):
        return CodeRoleAssignment(
            role, path, ("NOT_IMPORTED_BY_PROD", "PATH_TEST_DIR"), ("inventory",)
        )

    def test_actual_producer_contexts_roundtrip_with_provenance(self):
        contexts = {c["path"]: c for c in self.record["contexts"]}
        self.assertEqual(contexts["tests/test_core.py"]["roles"], ["test"])
        self.assertEqual(contexts["examples/demo.py"]["roles"], ["example"])
        self.assertEqual(contexts["src/probe/auto_pb2.py"]["roles"], ["generated"])
        for path in PROFILE_SAMPLE:
            self.assertEqual(consume_profile(self.data, self.binding, path), contexts[path])
            self.assertEqual(contexts[path]["qualification"], "not-run")
            self.assertEqual(contexts[path]["lineage"][0]["artifact_id"], "inventory")
        self.assertTrue(self.record["source_unchanged"])
        # The producer does not assign a production role here; do not invent one.
        self.assertEqual(contexts["src/probe/core.py"]["role_status"], "missing")
        self.assertTrue(contexts["src/probe/core.py"]["context_required"])

    def test_every_public_role_is_consumed_without_qualification(self):
        # Valid wire assignments test enum consumption, not classifier inference.
        for role in CodeRole:
            data = self._data_for(code_roles=(self._assignment(role, "scope"),))
            with self.subTest(role=role.value):
                context = consume_profile(data, self.binding, "scope/code.py")
                self.assertEqual(context["roles"], [role.value])
                self.assertEqual(context["assignments"][0]["source_artifact_ids"], ["inventory"])
                self.assertEqual(context["qualification"], "not-run")

    def test_overlapping_roles_remain_ambiguous(self):
        data = self._data_for(
            code_roles=(
                self._assignment(CodeRole.PRODUCTION, "pkg"),
                self._assignment(CodeRole.TEST, "pkg/test.py"),
            )
        )
        context = consume_profile(data, self.binding, "pkg/test.py")
        self.assertEqual(context["roles"], ["production", "test"])
        self.assertEqual(context["role_status"], "ambiguous")
        self.assertTrue(context["context_required"])
        self.assertEqual(
            consume_profile(data, self.binding, "pkg2/test.py")["role_status"], "missing"
        )

    def test_identity_is_bound_to_all_expected_context_fields(self):
        for field in self.binding.__dataclass_fields__:
            wrong = replace(self.binding, **{field: "different"})
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, field):
                consume_profile(self.data, wrong, "tests/test_core.py")

    def test_frozen_producer_fixture_is_consumable_and_missing_role_is_not_invented(self):
        fixture = Path(__file__).parent / "audit/fixtures/library_profile_golden.json"
        profile = decode_profile_payload(
            json.loads(fixture.read_bytes()), schema_version=SchemaVersion(4, 0)
        )
        payload = encode_profile_payload(profile)
        envelope = replace(
            self.envelope, payload=payload, content_digest=compute_content_digest(payload)
        )
        data = encode_profile_envelope(envelope, profile)
        context = consume_profile(data, self.binding, "src/library/core.py")
        self.assertEqual(context["roles"], [])
        self.assertTrue(context["context_required"])
        self.assertEqual(context["qualification"], "not-run")

    def test_partial_and_unsupported_profiles_require_context_even_with_a_role(self):
        for level in (SupportLevel.PARTIAL, SupportLevel.UNSUPPORTED):
            data = self._data_for(support_level=level)
            with self.subTest(level=level.value):
                context = consume_profile(data, self.binding, "tests/test_core.py")
                self.assertEqual(context["role_status"], "bound")
                self.assertTrue(context["context_required"])

    def test_bad_query_paths_and_outside_component_are_rejected(self):
        for path in (
            "../x.py",
            "/x.py",
            "tests\\x.py",
            "C:/x.py",
            "tests//x.py",
            "tests/./x.py",
            "x\x00.py",
        ):
            with self.subTest(path=path), self.assertRaises(ValueError):
                consume_profile(self.data, self.binding, path)
        data = self._data_for(component_path="src/probe")
        with self.assertRaisesRegex(ValueError, "outside"):
            consume_profile(data, self.binding, "src/probe2/core.py")

    def test_digest_lineage_and_unknown_role_rejections_use_public_codec(self):
        document = copy.deepcopy(self.record["profile_envelope"])
        document["payload"]["code_roles"][0]["role"] = "unrecognized-future-role"
        document["content_digest"] = compute_content_digest(document["payload"])
        with self.assertRaises(ContractError):
            consume_profile(canonical_encode(document), self.binding, "tests/test_core.py")
        document = copy.deepcopy(self.record["profile_envelope"])
        document["lineage"] = []
        with self.assertRaises(ContractError):
            consume_profile(canonical_encode(document), self.binding, "tests/test_core.py")
        document = copy.deepcopy(self.record["profile_envelope"])
        document["payload"]["file_count"] += 1
        with self.assertRaises(ContractError):
            consume_profile(canonical_encode(document), self.binding, "tests/test_core.py")

    def test_output_is_independent_and_cli_preserves_previous_evidence(self):
        context = consume_profile(self.data, self.binding, "tests/test_core.py")
        context["assignments"][0]["source_artifact_ids"].clear()
        self.assertEqual(
            consume_profile(self.data, self.binding, "tests/test_core.py")["assignments"][0][
                "source_artifact_ids"
            ],
            ["inventory"],
        )
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "profile.json"
            self.assertEqual(main(["--output", str(output)]), 0)
            self.assertEqual(json.loads(output.read_bytes())["qualification"], "not-run")
            original = output.read_bytes()
            with self.assertRaises(FileExistsError):
                main(["--output", str(output)])
            self.assertEqual(output.read_bytes(), original)


if __name__ == "__main__":
    unittest.main()
