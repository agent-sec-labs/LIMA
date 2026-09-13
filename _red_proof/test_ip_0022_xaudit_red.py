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
import re
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
        # R4 / DR-04-A finalized design: the replacement identifier is the
        # manifest scan ordinal (index into the sorted _manifest_candidates
        # enumeration), deterministic and free of any path/filename fragment.
        self.assertTrue(
            any(
                re.search(r"manifest-index=\d+; error=", detail)
                for detail in details
            ),
            f"manifest error detail must use the manifest-index identifier: {details}",
        )

    def test_oversized_manifest_budget_detail_free_of_sensitive_path(self):
        inv = inv_module()
        kwargs = profile_kwargs()
        options = inv.ProfileInventoryOptions(
            budgets=inv.ProfileBudgets(manifest_max_bytes=1)
        )
        with workspace_with(
            {
                "pkg/__init__.py": "x = 1\n",
                # full ghp_ token (v1 of this test sliced it off -- arrange
                # defect 4b found in the XAUDIT-FIX falsification round)
                f"requirements-{GHP_BASENAME[:-3]}.txt": "os==1.0\n",
            }
        ) as ws:
            result = inv.build_repository_profile(ws, options=options, **kwargs)
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

    def test_candidate_id_none_dash_disambiguation_tamper_rejected(self):
        # X4-7 (DR-04-B v3, R5: WIRE-layer negative; entry negatives are
        # X8-1/X8-2 in test_ip_0022_r5_red.py -- division of labour recorded
        # here): the '-' slot in candidate_id is the serialized form of
        # symbol=None ONLY. A literal symbol == "-" must be rejected at the
        # wire layer: without this rule, flipping symbol between None and
        # '-' leaves candidate_id and every digest unchanged (the ranked
        # digest subset excludes symbol), so the three fields are not fully
        # bound. With the R5 entrance rejection in force, a wire '-' can
        # only be an anomaly or tamper, making this rule consistent with --
        # not redundant to -- the entry rejections. R5 fact base (probe
        # P-R5-1): the full round trip with a legal symbol='-' fact set
        # currently PASSES on main, so "the default scan chain never
        # produces '-'" cannot justify a wire-only rejection by itself.
        payload = self.payload
        payload["semantic"]["ranked"][0]["symbol"] = "-"
        with self.assertRaises(Exception) as ctx:
            self.validate(payload)
        self.assertIn("symbol", str(ctx.exception))


class X7SensitiveScriptNameAdmissionTests(unittest.TestCase):
    """X7 (problem 3, included in IP-0022 per R4 ruling): a manifest script
    *name* that is secret-shaped must not surface as
    ``profile.entrypoints[i].symbol`` (S1/S4/S8), and the rejection must be
    counted through the public sensitive-filename skip channel."""

    def _repo(self):
        return {
            "pyproject.toml": (
                "[project.scripts]\n"
                'token_FAKESECRET123 = "pkg.cli:main"\n'
                'safe_cli = "pkg.cli:main"\n'
            ),
            "pkg/__init__.py": "x = 1\n",
            "pkg/cli.py": "def main():\n    pass\n",
        }

    def test_sensitive_script_name_excluded_from_entrypoints(self):
        result = build_profile(self._repo())
        symbols = [e.symbol for e in result.profile.entrypoints]
        self.assertFalse(
            any(s and "FAKESECRET" in s for s in symbols),
            f"sensitive script name leaked into entrypoints.symbol: {symbols}",
        )
        self.assertIn("safe_cli", symbols)
        serialized = json.dumps(result.profile.to_dict(), ensure_ascii=False)
        self.assertNotIn("FAKESECRET", serialized)

    def test_sensitive_script_name_skip_counted(self):
        result = build_profile(self._repo())
        details = [
            g.detail
            for g in result.profile.coverage_gaps
            if "sensitive-filename" in g.detail
        ]
        self.assertEqual(
            len(details), 1, f"expected exactly one skip gap: {details}"
        )
        self.assertIn("count=1", details[0])


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
        # R4 amendment (problem 3 co-fix): the RAM-only path must also publish
        # the skip count through the public coverage_gaps channel, not only the
        # internal admission_skips trace.
        details = [
            gap.detail
            for gap in result.facts.coverage_gaps
            if "sensitive-filename" in gap.detail
        ]
        self.assertEqual(
            len(details),
            1,
            f"expected one public coverage gap for the skip: {details}",
        )
        self.assertIn("count=1", details[0])


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
