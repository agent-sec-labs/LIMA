"""RED proof tests for IP-0022 Packet v4 (PKT-IP-0022-XAUDIT, DR-IP-0022-04).

Packet: IP-0022-PACKET/v4 (cross-audit negatives X1-X8)
Baseline: 30bdfaa13ac72572d65ccb2567ae8702923c4187 (origin/main)

Every test below MUST fail at the baseline because the target behaviour is
missing. Arrangement paths are the same repo_shapes fixtures exercised green
by the frozen suites (801 passed). X3 is gated on DR-04-A (frozen IP-0016
detail template); X4 on DR-04-B (frozen IP-0021 validation sequence); both
are recorded here as the RED proof of the gap, not implemented ahead of
authorization.
"""

from __future__ import annotations

import copy
import importlib
import json
import unittest

from tests.audit.fixtures.repo_shapes import profile_kwargs, workspace_with

SINK_CODE = (
    "import os\n"
    "from framework import request\n"
    "\n"
    "\n"
    "def run_command(request):\n"
    "    cmd = request.args.get('cmd')\n"
    "    os.system(cmd)\n"
)

GHP_BASENAME = f"ghp_{'a' * 36}.py"


def inv_module():
    return importlib.import_module("lima.audit.inventory")


def ram_module():
    return importlib.import_module("lima.audit.ram")


def rs_module():
    return importlib.import_module("lima.audit.ram_schema")


def sp_module():
    return importlib.import_module("lima.audit.semantic_prioritizer")


def build_profile(repo):
    inv = inv_module()
    with workspace_with(repo) as ws:
        return inv.build_repository_profile(ws, **profile_kwargs())


def minimal_payload():
    tests = importlib.import_module("tests.audit.test_ram_schema")
    return copy.deepcopy(tests.MINIMAL_PAYLOAD)


class X1SensitiveDirectorySegmentCodeRoleTests(unittest.TestCase):
    """X1: sensitive directory *segment* must not leak into code_roles."""

    def test_sensitive_directory_segment_excluded_from_code_roles(self):
        result = build_profile(
            {
                "tests/secrets/anything.py": "import os\nos.system('x')\n",
                "pkg/__init__.py": "x = 1\n",
            }
        )
        role_paths = [a.path for a in result.profile.code_roles]
        self.assertFalse(
            any("secrets" in path for path in role_paths),
            f"sensitive directory segment leaked into code_roles: {role_paths}",
        )


class X2SensitiveDirectorySegmentRamTests(unittest.TestCase):
    """X2: sensitive directory segment must not leak into RAM facts."""

    def test_sensitive_directory_segment_excluded_from_ram(self):
        ram = ram_module()
        with workspace_with(
            {"secrets/danger.py": SINK_CODE, "danger.py": SINK_CODE}
        ) as ws:
            result = ram.build_python_ram_facts(ws)
        paths = [entry.path for entry in result.facts.sensitive_sinks]
        self.assertFalse(
            any(path.startswith("secrets/") for path in paths),
            f"sensitive directory segment leaked into RAM sinks: {paths}",
        )


class X3ManifestErrorDetailRedactionTests(unittest.TestCase):
    """X3 (DR-04-A): manifest gap detail must not carry the raw manifest path.

    At the baseline the frozen IP-0016 template ``manifest={relative_path}``
    publishes the full repo-relative path (including sensitive directory
    segments and sensitive basenames) into Profile coverage_gaps.
    """

    def test_manifest_parse_error_detail_free_of_sensitive_path(self):
        result = build_profile(
            {
                "pkg/__init__.py": "x = 1\n",
                "token/pyproject.toml": b"\xff\xfe not utf8",
            }
        )
        details = [g.detail for g in result.profile.coverage_gaps]
        self.assertFalse(
            any("token/pyproject.toml" in detail for detail in details),
            f"manifest parse-error detail carries the raw path: {details}",
        )

    def test_oversized_manifest_budget_detail_free_of_sensitive_path(self):
        inv = inv_module()
        kwargs = profile_kwargs()
        with workspace_with(
            {
                "pkg/__init__.py": "x = 1\n",
                f"requirements-{GHP_BASENAME[12:]}": "os==1.0\n",
            }
        ) as ws:
            kwargs_budget = dict(
                kwargs, profile_budgets=inv.ProfileBudgets(manifest_max_bytes=1)
            )
            result = inv.build_repository_profile(ws, **kwargs_budget)
        details = [g.detail for g in result.profile.coverage_gaps]
        self.assertFalse(
            any("ghp_" in detail for detail in details),
            f"manifest budget detail carries a secret-shaped basename: {details}",
        )


class X4WireConsistencyTests(unittest.TestCase):
    """X4 (DR-04-B): candidate_id <-> kind/path/symbol consistency + strict
    path segment rules (packet-owned v4 strengthening of the v3 path check)."""

    def setUp(self):
        rs = rs_module()
        self.validate = rs.validate_ram_wire_payload
        self.payload = minimal_payload()

    def test_candidate_id_kind_path_symbol_mismatch_rejected(self):
        payload = self.payload
        payload["semantic"]["ranked"][0]["candidate_id"] = (
            "sensitive-sink:other.py:-#1"
        )
        with self.assertRaises(Exception) as ctx:
            self.validate(payload)
        self.assertIn("candidate_id", str(ctx.exception))

    def test_candidate_id_symbol_slot_mismatch_rejected(self):
        payload = self.payload
        payload["semantic"]["ranked"][0]["candidate_id"] = (
            "sensitive-sink:danger.py:some_symbol#1"
        )
        with self.assertRaises(Exception):
            self.validate(payload)

    def test_candidate_id_ordinal_not_digits_already_rejected(self):
        # Regression anchor (not RED): the frozen IP-0021 pattern already
        # rejects a non-digit ordinal; kept to prove no weakening in v4.
        payload = self.payload
        payload["semantic"]["ranked"][0]["candidate_id"] = (
            "sensitive-sink:danger.py:-#one"
        )
        with self.assertRaises(Exception):
            self.validate(payload)

    def test_empty_path_segment_rejected(self):
        payload = self.payload
        payload["ram"]["sensitive_sinks"][0]["path"] = "a//b.py"
        with self.assertRaises(Exception):
            self.validate(payload)

    def test_dot_segment_rejected(self):
        payload = self.payload
        payload["ram"]["sensitive_sinks"][0]["path"] = "./danger.py"
        with self.assertRaises(Exception):
            self.validate(payload)

    def test_control_character_path_rejected(self):
        payload = self.payload
        payload["ram"]["sensitive_sinks"][0]["path"] = "da\x01nger.py"
        with self.assertRaises(Exception):
            self.validate(payload)


class X5AdmissionSkipSemanticsTests(unittest.TestCase):
    """X5: AdmissionSkip semantics (count-once, gap ordering, RAM-only trace)."""

    def test_same_path_hit_by_entrypoint_and_role_counted_once(self):
        # pyproject script target == a tests-dir file that would also be a
        # code-role candidate: the skip must be counted exactly once.
        result = build_profile(
            {
                "pyproject.toml": (
                    "[project.scripts]\ncli = \"tests.api_key_helper:main\"\n"
                ),
                "tests/api_key_helper.py": "def main():\n    pass\n",
                "pkg/__init__.py": "x = 1\n",
            }
        )
        details = [
            g.detail
            for g in result.profile.coverage_gaps
            if "sensitive-filename" in g.detail
        ]
        self.assertEqual(len(details), 1, f"expected exactly one gap: {details}")
        self.assertIn("count=1", details[0])

    def test_ram_only_build_records_admission_skips(self):
        ram = ram_module()
        with workspace_with({GHP_BASENAME: SINK_CODE, "danger.py": SINK_CODE}) as ws:
            result = ram.build_python_ram_facts(ws)
        skips = getattr(result, "admission_skips", None)
        self.assertIsNotNone(
            skips, "RamFactsBuildResult must carry admission_skips (RAM-only path)"
        )
        self.assertTrue(any(s.reason == "sensitive-filename" for s in skips))
        self.assertTrue(
            all(not hasattr(s, "path") for s in skips),
            "skip records must not carry the raw filename",
        )


class X6MinimalPayloadFiveDigestTests(unittest.TestCase):
    """X6: MINIMAL_PAYLOAD migration to five self-consistent digests (v4
    finalizes the v3 'D2 takes all-true values' clause)."""

    def _recomputed(self):
        tests = importlib.import_module("tests.audit.test_ram_schema")
        payload = copy.deepcopy(tests.MINIMAL_PAYLOAD)
        sp = sp_module()
        codec = importlib.import_module("lima.contracts.codec")
        ram_digest = codec.compute_content_digest(payload["ram"])
        options = sp.SemanticOptions()
        config_digest = sp.semantic_config_digest(options)
        ranked = tuple(
            sp.SemanticCandidate(
                candidate_id=item["candidate_id"],
                kind=item["kind"],
                path=item["path"],
                symbol=item["symbol"],
                score=item["score"],
                rank=item["rank"],
                category=item["category"],
                rationale=item["rationale"],
                key_flow_steps=tuple(item["key_flow_steps"]),
            )
            for item in payload["semantic"]["ranked"]
        )
        result_digest = sp._result_digest(
            config_digest=config_digest,
            input_facts_digest=ram_digest,
            ranked=ranked,
            total_candidates=payload["semantic"]["total_candidates"],
            coverage_gaps=(),
        )
        payload["identity"]["ram_facts_digest"] = ram_digest
        payload["identity"]["semantic_config_digest"] = config_digest
        payload["identity"]["semantic_result_digest"] = result_digest
        payload["identity"]["prompt_digest"] = codec.compute_content_digest(
            options.prompt_template
        )
        payload["identity"]["model_digest"] = codec.compute_content_digest(
            options.model_id
        )
        return payload, ram_digest, config_digest, result_digest

    def test_five_digest_slots_distinct_and_true_valued(self):
        payload, ram_digest, config_digest, result_digest = self._recomputed()
        identity = payload["identity"]
        values = {
            identity["ram_facts_digest"],
            identity["semantic_config_digest"],
            identity["semantic_result_digest"],
            identity["prompt_digest"],
            identity["model_digest"],
        }
        # five mutually distinct true recomputations (no shared placeholder)
        self.assertEqual(len(values), 5)
        self.assertNotIn("0" * 64, values)
        self.assertEqual(identity["ram_facts_digest"], ram_digest)
        self.assertEqual(identity["semantic_config_digest"], config_digest)
        self.assertEqual(identity["semantic_result_digest"], result_digest)

    def test_wire_digest_recomputed_from_migrated_identity(self):
        payload, *_ = self._recomputed()
        rs = rs_module()
        wire = rs.ram_wire_digest(payload)
        self.assertNotEqual(wire, "0" * 64)
        self.assertEqual(wire, rs.ram_wire_digest(payload))


if __name__ == "__main__":
    unittest.main()
