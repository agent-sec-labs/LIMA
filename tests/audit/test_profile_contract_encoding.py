"""IP-0016 acceptance tests: contract encoding, round-trip, golden, digest sentinel.

Matrix traceability (Packet v1.1 §13): contract encoding row (>=3 cases)
including the two DR-IP-0016-01 digest cases and the V5-FR-01 import-face
dependency-boundary assertion.
"""

from __future__ import annotations

import ast
import importlib
import inspect
import json
import unittest
from pathlib import Path
from typing import Any

from lima.contracts.errors import ContractError, ContractErrorCode
from lima.contracts.profile import decode_profile_envelope, encode_profile_envelope
from tests.audit.fixtures.repo_shapes import (
    GOLDEN_LIBRARY_PROFILE,
    profile_kwargs,
    sentinel_empty_digest,
    workspace_with,
)

GOLDEN_LIBRARY_FILES = {
    "pyproject.toml": (
        "[project]\nname = \"golden-lib\"\nrequires-python = \">=3.11\"\n\n"
        "[build-system]\nrequires = [\"hatchling\"]\n"
        "build-backend = \"hatchling.build\"\n"
    ),
    "src/golden/__init__.py": "",
    "src/golden/core.py": "def core() -> int:\n    return 1\n",
}

FORBIDDEN_RUNTIME_MODULES = frozenset(
    {"subprocess", "socket", "urllib", "requests", "http"}
)
FORBIDDEN_LIMA_MODULES = frozenset(
    {
        "lima.python_dataflow",
        "lima.semantic_retrieval",
        "lima.repository_scanner",
        "lima.service",
        "lima.api",
        "lima.store",
        "lima.sandbox",
    }
)


class ContractEncodingTestBase(unittest.TestCase):
    audit: Any

    def setUp(self) -> None:
        import lima.audit as audit

        self.audit = audit

    def build(self, workspace: Any, **overrides: object) -> Any:
        return self.audit.build_repository_profile(
            workspace, **profile_kwargs(**overrides)
        )


class GoldenProfileTests(ContractEncodingTestBase):
    def test_library_golden_profile_fixture(self) -> None:
        with workspace_with(GOLDEN_LIBRARY_FILES) as workspace:
            result = self.build(workspace)
        expected = json.dumps(
            result.profile.to_dict(), sort_keys=True, separators=(",", ":")
        )
        golden = GOLDEN_LIBRARY_PROFILE.read_text(encoding="utf-8").strip()
        self.assertEqual(expected, golden)
        self.assertTrue(Path(GOLDEN_LIBRARY_PROFILE).is_file())


class EnvelopeRoundTripTests(ContractEncodingTestBase):
    def test_envelope_round_trip_decode(self) -> None:
        with workspace_with(GOLDEN_LIBRARY_FILES) as workspace:
            result = self.build(workspace)
        raw = encode_profile_envelope(result.envelope, result.profile)
        envelope, profile = decode_profile_envelope(raw)
        self.assertEqual(profile.to_dict(), result.profile.to_dict())
        self.assertEqual(envelope.content_digest, result.envelope.content_digest)
        self.assertEqual(envelope.schema_name, "lima.repository-profile")
        self.assertEqual(len(envelope.lineage), 1)
        self.assertEqual(envelope.lineage[0].artifact_id, "inventory")
        self.assertEqual(envelope.lineage[0].tenant_id, "tenant-test")
        self.assertEqual(
            envelope.lineage[0].repository_snapshot_digest, "1" * 64
        )


class DigestSentinelTests(ContractEncodingTestBase):
    """DR-IP-0016-01 (Packet v1.1 §6): sentinel default and empty-string rejection."""

    def test_default_digest_sentinel_applied(self) -> None:
        sentinel = sentinel_empty_digest()
        self.assertEqual(
            sentinel, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        )
        with workspace_with(GOLDEN_LIBRARY_FILES) as workspace:
            result = self.build(workspace)
        self.assertEqual(result.envelope.policy_digest, sentinel)
        self.assertEqual(result.envelope.toolchain_digest, sentinel)

    def test_empty_digest_string_rejected(self) -> None:
        with workspace_with(GOLDEN_LIBRARY_FILES) as workspace:
            with self.assertRaises(ContractError) as caught:
                self.build(workspace, policy_digest="")
        self.assertEqual(caught.exception.code, ContractErrorCode.INVALID_FIELD_VALUE)
        with workspace_with(GOLDEN_LIBRARY_FILES) as workspace:
            with self.assertRaises(ContractError) as caught:
                self.build(workspace, toolchain_digest="")
        self.assertEqual(caught.exception.code, ContractErrorCode.INVALID_FIELD_VALUE)


class ImportFaceTests(ContractEncodingTestBase):
    """V5-FR-01: the profile layer must not depend on RAM/semantic modules."""

    def test_audit_module_import_face_dependency_boundary(self) -> None:
        module = importlib.import_module("lima.audit.inventory")
        source = inspect.getsource(module)
        tree = ast.parse(source)
        imported: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module)
        for name in sorted(imported):
            root = name.split(".", 1)[0]
            self.assertNotIn(root, FORBIDDEN_RUNTIME_MODULES, name)
            self.assertNotIn(name, FORBIDDEN_LIMA_MODULES, name)


if __name__ == "__main__":
    unittest.main()
