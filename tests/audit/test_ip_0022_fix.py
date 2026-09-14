"""Frozen acceptance tests for IP-0022 (#60-Fix pre-closure blockers).

Packet: IP-0022-PACKET/v6 (PKT-IP-0022-FREEZE, 2026-09-14)
Frozen Test Commit baseline: docs/ip-0022-packet head at freeze time
(based on main 30bdfaa13ac72572d65ccb2567ae8702923c4187)

F1: secret-shaped filename admission rejection (heuristic superset, four
    filter points: profile entrypoints path+name, code roles, RAM candidates).
F2: wire payload integrity (path segment rules, five identity digest
    recomputations, candidate_id binding, None/'-' disambiguation).

This file merges the retired ``_red_proof/`` drafts (evidence index with
SHA-256 values lives in Packet §4b):
- test_ip_0022_fix_red.py   (D1'' M/G series, 23 cases)
- test_ip_0022_xaudit_red.py (X series, 17 cases incl. 3 anchors)
- test_ip_0022_r5_red.py    (X8 series, 8 cases incl. 1 anchor)

v6 freeze-round amendments (Maintainer dispatch):
- X8-1c structure-valid construction: appending an entry to
  sensitive_sinks now appends to the parallel sink_rule_ids/sink_cwes
  tuples in lockstep, so the baseline failure is the missing target
  behaviour (ContractError not raised), not an arrange ValueError.
- X3-3/X3-4: multi-candidate manifest cases asserting the TRUE sorted
  ordinal (sensitive manifest at index 1), defeating an implementation
  that always writes 0.

Expected at the frozen commit (pre-implementation): 47 failed / 4 passed
(51 cases; the D1'''''' 43 RED base + M18 + R3 + X3-3 + X3-4).
The 4 passing cases are GREEN anchors (X4-0, X6 x2, X8-0) that must stay
green both before and after the fix; deleting or weakening them is
forbidden (frozen-surface rule).
"""

from __future__ import annotations

import copy
import dataclasses
import importlib
import json
import re
import unittest
from pathlib import Path
from typing import Any

from lima.contracts.errors import ContractError, ContractErrorCode
from tests.audit.fixtures.repo_shapes import profile_kwargs, workspace_with

GHP_FILENAME = f"ghp_{'a' * 36}.py"
AKIA_FILENAME = f"AKIA{'Q' * 16}.py"
JWT_FILENAME = f"eyJ{'b' * 15}.{'c' * 15}.py"
GHP_BASENAME = GHP_FILENAME  # same token-shaped basename for manifest cases

SINK_CODE = (
    "import os\n"
    "from framework import request\n"
    "\n"
    "\n"
    "def run_command(request):\n"
    "    cmd = request.args.get('cmd')\n"
    "    os.system(cmd)\n"
)

SECRET_SINK_REPO: dict[str, str] = {
    "danger.py": SINK_CODE,
    GHP_FILENAME: SINK_CODE,
}

SINK_TAINTED_REPO = {
    "danger.py": SINK_CODE,
}

_GOLDEN_DIR = Path(__file__).resolve().parent / "fixtures" / "golden_matrix" / "golden"


def ram_module() -> Any:
    return importlib.import_module("lima.audit.ram")


def sp_module() -> Any:
    return importlib.import_module("lima.audit.semantic_prioritizer")


def rs_module() -> Any:
    return importlib.import_module("lima.audit.ram_schema")


def inv_module() -> Any:
    return importlib.import_module("lima.audit.inventory")


def build_chain(repo: dict[str, str]):
    ram = ram_module()
    sp = sp_module()
    with workspace_with(repo) as workspace:
        ram_result = ram.build_python_ram_facts(workspace)
    semantic_result = sp.build_semantic_top_n(ram_result.facts)
    return ram_result, semantic_result


def build_profile(repo: dict[str, str]):
    inv = inv_module()
    with workspace_with(repo) as workspace:
        return inv.build_repository_profile(workspace, **profile_kwargs())


def all_entry_paths(facts) -> list[str]:
    return [
        entry.path
        for inventory in (
            facts.entrypoints,
            facts.external_sources,
            facts.sensitive_sinks,
            facts.trust_boundaries,
            facts.unresolved_edges,
        )
        for entry in inventory
    ]


class _PromptCapturingClient:
    """Minimal SemanticModelClient stand-in that records every prompt."""

    def __init__(self) -> None:
        self.calls: list[str] = []

    def complete(self, prompt: str, *, timeout_seconds: int) -> str:
        self.calls.append(prompt)
        return "[]"


class F1SecretFilenameAdmissionTests(unittest.TestCase):
    """F1: secret-shaped filenames must be rejected at admission so they
    never reach RAM facts, the Top-N board, prompt text, or the wire."""

    def test_secret_shaped_path_helper_is_heuristic_superset(self):
        """M1' (DR-IP-0022-02 §1): heuristic superset interception."""
        inv = inv_module()
        helper = getattr(inv, "is_secret_shaped_path")
        # (a) superset: all five frozen token shapes still hit
        self.assertTrue(helper(f"ghp_{'a'*36}.py"))
        self.assertTrue(helper(f"AKIA{'Q'*16}.py"))
        self.assertTrue(helper(f"eyJ{'b'*15}.{'c'*15}.py"))
        self.assertTrue(helper(f"xoxb-{'c'*12}.py"))
        self.assertTrue(helper("key.pem"))
        # (b) Maintainer-observed samples must hit
        self.assertTrue(helper("token_FAKESECRET123.py"))
        self.assertTrue(helper("sk_live_ABC123xyztoken.py"))
        # (c) prefix family extensions
        self.assertTrue(helper(f"gho_{'a'*36}.py"))
        self.assertTrue(helper("sk_test_ABC123xyztoken.py"))
        self.assertTrue(
            helper(
                "github_pat_11ABCDEFGH0123456789_"
                "abcdefghijklmnopqrstuvwxyz1234567890.py"
            )
        )
        self.assertTrue(helper("id_rsa.pem"))
        self.assertTrue(helper("id_ed25519"))
        # (d) keyword family (segment-bounded, plural tolerated)
        self.assertTrue(helper("my_secret.py"))
        self.assertTrue(helper("secrets.py"))
        self.assertTrue(helper("api_key.py"))
        self.assertTrue(helper("apikey.py"))
        self.assertTrue(helper("password_reset.py"))
        self.assertTrue(helper("credential_store.py"))
        # (e) high-entropy base62 run >= 20 chars, no separator
        self.assertTrue(helper("ZFk8dQ2vNc7bX1mR4tYw.py"))
        # (f) frozen false-positive negatives must NOT hit
        for benign in (
            "tokenizer.py",
            "tokenization.py",
            "keyboard_layout.py",
            "monkey_patch.py",
            "keynote.md",
            "api.py",
            "danger.py",
            "safe.py",
            "cli.py",
            "application.py",
            "library_profile_golden.json",
        ):
            self.assertFalse(helper(benign), benign)
        # (g) path form: check applies to the basename
        self.assertTrue(helper(f"pkg/{'ZFk8dQ2vNc7bX1mR4tYw'}.py"))
        # (h) v4 segment semantics: any path segment may hit
        self.assertTrue(helper("tests/secrets/anything.py"))
        self.assertFalse(helper("tests/tokenizer/anything.py"))

    def test_ram_facts_exclude_secret_shaped_filename(self):
        ram_result, _ = build_chain(SECRET_SINK_REPO)
        paths = all_entry_paths(ram_result.facts)
        self.assertTrue(paths, "arrange sanity: non-secret entries exist")
        self.assertFalse(
            any("ghp_" in path for path in paths),
            f"secret-shaped filename leaked into RAM facts: {paths}",
        )

    def test_ram_facts_exclude_akia_shaped_filename(self):
        repo = {"danger.py": SINK_CODE, AKIA_FILENAME: SINK_CODE}
        ram_result, _ = build_chain(repo)
        paths = all_entry_paths(ram_result.facts)
        self.assertFalse(any("AKIA" in path for path in paths), str(paths))

    def test_ram_facts_exclude_jwt_shaped_filename(self):
        repo = {"danger.py": SINK_CODE, JWT_FILENAME: SINK_CODE}
        ram_result, _ = build_chain(repo)
        paths = all_entry_paths(ram_result.facts)
        self.assertFalse(any(path.startswith("eyJ") for path in paths), str(paths))

    def test_profile_skip_reason_vocabulary_extended(self):
        inv = inv_module()
        self.assertIn("sensitive-filename", inv.SKIP_REASON_TO_GAP_DETAIL)

    def test_secret_filename_skip_reported_as_typed_gap(self):
        result = build_profile(SECRET_SINK_REPO)
        details = [
            gap.detail
            for gap in getattr(result.profile, "coverage_gaps", ())
            if "sensitive-filename" in gap.detail
        ]
        self.assertTrue(
            details,
            "skipped-by-reason summary must surface as a typed coverage gap",
        )
        self.assertIn("count=1", details[0])

    def test_profile_entrypoints_exclude_manifest_script_secret_target(self):
        repo = {
            "pyproject.toml": (
                "[project]\n"
                'name = "x"\n'
                "version = \"0.1.0\"\n"
                "\n"
                "[project.scripts]\n"
                f'leak = "{GHP_FILENAME[:-3]}:run_command"\n'
                'safe = "safe_cli:main"\n'
            ),
            GHP_FILENAME: SINK_CODE,
            "safe_cli.py": "def main():\n    pass\n",
        }
        result = build_profile(repo)
        entry_paths = [entry.path for entry in result.profile.entrypoints]
        self.assertIn(
            "safe_cli.py",
            entry_paths,
            "arrange sanity: manifest scripts were parsed and resolved",
        )
        self.assertFalse(
            any("ghp_" in path for path in entry_paths),
            f"secret-shaped script target became an entrypoint: {entry_paths}",
        )

    def test_topn_ranked_board_excludes_secret_shaped_filename(self):
        _, semantic_result = build_chain(SECRET_SINK_REPO)
        self.assertTrue(semantic_result.ranked, "arrange sanity: board non-empty")
        ranked_paths = [item.path for item in semantic_result.ranked]
        self.assertFalse(
            any("ghp_" in path for path in ranked_paths), str(ranked_paths)
        )

    def test_prompt_text_excludes_secret_shaped_filename(self):
        ram_result, _ = build_chain(SECRET_SINK_REPO)
        client = _PromptCapturingClient()
        sp = sp_module()
        sp.build_semantic_top_n(
            ram_result.facts,
            options=sp.SemanticOptions(model_id="fake-model"),
            model_client=client,
        )
        self.assertTrue(client.calls, "arrange sanity: model was called")
        joined = "".join(client.calls)
        self.assertNotIn(
            "ghp_", joined, "secret-shaped filename leaked into prompt text"
        )

    def test_wire_payload_excludes_secret_shaped_filename(self):
        ram_result, semantic_result = build_chain(SECRET_SINK_REPO)
        payload = rs_module().ram_wire_payload(ram_result, semantic_result)
        self.assertNotIn("ghp_", json.dumps(payload, sort_keys=True))


class F2WireValidatorTests(unittest.TestCase):
    """F2: validate_ram_wire_payload path rejection + digest binding."""

    @classmethod
    def setUpClass(cls):
        cls.ram_result, cls.semantic_result = build_chain(SINK_TAINTED_REPO)

    def fresh_payload(self) -> dict:
        rs = rs_module()
        payload = rs.ram_wire_payload(self.ram_result, self.semantic_result)
        # sanity: the honest payload validates at the baseline contract
        rs.validate_ram_wire_payload(payload)
        return payload

    def _entry_section(self, payload: dict) -> tuple[str, int]:
        for section in ("sensitive_sinks", "entrypoints", "external_sources"):
            items = payload["ram"].get(section) or []
            if items:
                return f"ram.{section}", 0
        raise AssertionError("arrange sanity: no entry section in payload")

    def test_absolute_posix_path_rejected(self):
        rs = rs_module()
        payload = self.fresh_payload()
        section, index = self._entry_section(payload)
        payload["ram"][section.split(".")[1]][index]["path"] = "/etc/app/danger.py"
        with self.assertRaises(ContractError):
            rs.validate_ram_wire_payload(payload)

    def test_windows_drive_absolute_path_rejected(self):
        rs = rs_module()
        payload = self.fresh_payload()
        section, index = self._entry_section(payload)
        payload["ram"][section.split(".")[1]][index]["path"] = "C:\\repo\\danger.py"
        with self.assertRaises(ContractError):
            rs.validate_ram_wire_payload(payload)

    def test_parent_traversal_path_rejected(self):
        rs = rs_module()
        for bad in ("../danger.py", "pkg/../../danger.py"):
            payload = self.fresh_payload()
            section, index = self._entry_section(payload)
            payload["ram"][section.split(".")[1]][index]["path"] = bad
            with self.assertRaises(ContractError):
                rs.validate_ram_wire_payload(payload)

    def test_traversal_in_ranked_path_rejected(self):
        rs = rs_module()
        payload = self.fresh_payload()
        payload["semantic"]["ranked"][0]["path"] = "../outside/danger.py"
        with self.assertRaises(ContractError):
            rs.validate_ram_wire_payload(payload)

    def test_embedded_wire_digest_mismatch_rejected(self):
        rs = rs_module()
        payload = self.fresh_payload()
        honest = payload["identity"]["wire_digest"]
        tampered = ("0" if honest[0] != "0" else "1") + honest[1:]
        payload["identity"]["wire_digest"] = tampered
        with self.assertRaises(ContractError):
            rs.validate_ram_wire_payload(payload)

    def test_stale_digest_after_build_config_change_rejected(self):
        rs = rs_module()
        payload = self.fresh_payload()
        payload["build"]["semantic"]["seed"] += 1
        with self.assertRaises(ContractError):
            rs.validate_ram_wire_payload(payload)

    def test_payload_tamper_with_synced_wire_digest_still_rejected(self):
        """M17: re-syncing the transport header must not launder a tamper."""
        rs = rs_module()
        payload = self.fresh_payload()
        payload["ram"]["sensitive_sinks"][0]["path"] = "pkg/other_target.py"
        payload["identity"]["wire_digest"] = rs.ram_wire_digest(payload)
        self.assertEqual(
            payload["identity"]["wire_digest"], rs.ram_wire_digest(payload)
        )
        with self.assertRaises(ContractError):
            rs.validate_ram_wire_payload(payload)

    def test_semantic_ranked_tamper_with_synced_wire_digest_still_rejected(self):
        """M17-semantic: same laundering against semantic.ranked."""
        rs = rs_module()
        payload = self.fresh_payload()
        payload["semantic"]["ranked"][0]["rationale"] = "tampered rationale"
        payload["identity"]["wire_digest"] = rs.ram_wire_digest(payload)
        with self.assertRaises(ContractError):
            rs.validate_ram_wire_payload(payload)

    def test_wire_digest_helpers_recompute_true_chain_digests(self):
        """M18: the three dict-side helpers recompute the true chain digests
        (and model_digest binds build.semantic.model_id)."""
        rs = rs_module()
        ram_result, semantic_result = build_chain(SINK_TAINTED_REPO)
        payload = rs.ram_wire_payload(ram_result, semantic_result)
        codec = importlib.import_module("lima.contracts.codec")
        self.assertEqual(
            rs.ram_facts_digest_from_wire(payload),
            payload["identity"]["ram_facts_digest"],
        )
        self.assertEqual(
            rs.semantic_config_digest_from_wire(payload),
            payload["identity"]["semantic_config_digest"],
        )
        self.assertEqual(
            rs.semantic_result_digest_from_wire(payload),
            payload["identity"]["semantic_result_digest"],
        )
        self.assertEqual(
            codec.compute_content_digest(payload["build"]["semantic"]["model_id"]),
            payload["identity"]["model_digest"],
        )


class G1ProfileCodeRolesTests(unittest.TestCase):
    """G1: secret-shaped filenames must not surface in Profile code_roles."""

    def test_profile_code_roles_exclude_secret_shaped_filename(self):
        result = build_profile(
            {
                "tests/token_FAKESECRET123.py": "import os\nos.system('x')\n",
                "safe.py": "x = 1\n",
            }
        )
        role_paths = [a.path for a in result.profile.code_roles]
        self.assertFalse(
            any("FAKESECRET" in path for path in role_paths),
            f"secret-shaped filename leaked into Profile code_roles: {role_paths}",
        )

    def test_profile_serialization_free_of_secret_shaped_filename(self):
        result = build_profile(
            {
                "tests/token_FAKESECRET123.py": "import os\nos.system('x')\n",
                "safe.py": "x = 1\n",
            }
        )
        text = json.dumps(result.profile.to_dict(), sort_keys=True, default=str)
        self.assertNotIn("FAKESECRET", text)

    def test_profile_secret_filename_skip_counted(self):
        result = build_profile(
            {
                "tests/token_FAKESECRET123.py": "import os\nos.system('x')\n",
                "safe.py": "x = 1\n",
            }
        )
        details = [
            gap.detail
            for gap in result.profile.coverage_gaps
            if "sensitive-filename" in gap.detail
        ]
        self.assertTrue(details)
        self.assertIn("count=1", details[0])


class G2WireMigrationTests(unittest.TestCase):
    """G2: model_digest slot + all-zero placeholder rejection (the frozen
    MINIMAL_PAYLOAD itself is migrated to five self-consistent true digests
    in test_ram_schema.py, authorized edit; the placeholder negative below
    is constructed independently)."""

    @classmethod
    def setUpClass(cls):
        cls.ram_result, cls.semantic_result = build_chain(SINK_TAINTED_REPO)

    def test_model_digest_tamper_rejected(self):
        rs = rs_module()
        payload = rs.ram_wire_payload(self.ram_result, self.semantic_result)
        rs.validate_ram_wire_payload(payload)
        honest = payload["identity"]["model_digest"]
        tampered = ("0" if honest[0] != "0" else "1") + honest[1:]
        payload["identity"]["model_digest"] = tampered
        with self.assertRaises(ContractError):
            rs.validate_ram_wire_payload(payload)

    def test_minimal_payload_placeholder_digests_rejected(self):
        """G2-2: an all-zero placeholder identity is inconsistent and must
        be rejected (RED at the frozen commit: baseline is lenient)."""
        import tests.audit.test_ram_schema as trs

        rs = rs_module()
        placeholder = copy.deepcopy(trs.MINIMAL_PAYLOAD)
        for key in (
            "ram_facts_digest",
            "semantic_config_digest",
            "semantic_result_digest",
            "prompt_digest",
            "model_digest",
            "wire_digest",
        ):
            placeholder["identity"][key] = "0" * 64
        with self.assertRaises(ContractError):
            rs.validate_ram_wire_payload(placeholder)


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


def _manifest_gap_details(result) -> list[str]:
    return [g.detail for g in result.profile.coverage_gaps]


class X3ManifestErrorDetailRedactionTests(unittest.TestCase):
    """X3 (DR-04-A finalized design, pending re-review): manifest gap detail
    must carry the manifest-index stable identifier, never the raw path."""

    def test_manifest_parse_error_detail_free_of_sensitive_path(self):
        result = build_profile(
            {
                "pkg/__init__.py": "x = 1\n",
                "token/pyproject.toml": b"\xff\xfe not utf8",
            }
        )
        details = _manifest_gap_details(result)
        self.assertFalse(
            any("token/pyproject.toml" in detail for detail in details),
            f"manifest parse-error detail carries the raw path: {details}",
        )
        self.assertTrue(
            any(
                re.search(r"manifest-index=\d+; error=", detail)
                for detail in details
            ),
            f"manifest error detail must use the manifest-index identifier: {details}",
        )

    def test_oversized_manifest_budget_detail_free_of_sensitive_path(self):
        inv = inv_module()
        options = inv.ProfileInventoryOptions(
            budgets=inv.ProfileBudgets(manifest_max_bytes=1)
        )
        with workspace_with(
            {
                "pkg/__init__.py": "x = 1\n",
                f"requirements-{GHP_BASENAME[:-3]}.txt": "os==1.0\n",
            }
        ) as ws:
            result = inv.build_repository_profile(ws, options=options, **profile_kwargs())
        details = _manifest_gap_details(result)
        self.assertFalse(
            any("ghp_" in detail for detail in details),
            f"manifest budget detail carries a secret-shaped basename: {details}",
        )

    def test_manifest_parse_error_index_is_true_sorted_ordinal(self):
        """X3-3 (v6): two manifest candidates -- the sensitive one is at
        sorted index 1. An implementation that always writes 0 fails."""
        sensitive = f"requirements-{GHP_BASENAME[:-3]}.txt"
        result = build_profile(
            {
                "pkg/__init__.py": "x = 1\n",
                "Cargo.toml": "]]]bad\n",  # sorted manifest candidate 0
                sensitive: b"\xff\xfe not utf8",  # sorted candidate 1
            }
        )
        details = _manifest_gap_details(result)
        self.assertIn(
            "manifest-index=1; error=UnicodeDecodeError",
            details,
            f"sensitive manifest must be identified by its TRUE sorted ordinal "
            f"(index 1): {details}",
        )
        self.assertTrue(
            any("manifest-index=0; error=TOMLDecodeError" in d for d in details),
            f"the benign candidate (Cargo.toml) must be at index 0: {details}",
        )
        self.assertFalse(any("ghp_" in d for d in details), details)

    def test_manifest_budget_index_is_true_sorted_ordinal(self):
        """X3-4 (v6): same true-ordinal requirement for the budget branch."""
        inv = inv_module()
        content = "# padding line\n" * 40
        sensitive = f"requirements-{GHP_BASENAME[:-3]}.txt"
        options = inv.ProfileInventoryOptions(
            budgets=inv.ProfileBudgets(manifest_max_bytes=16)
        )
        with workspace_with(
            {
                "pkg/__init__.py": "x = 1\n",
                "Cargo.toml": content,
                sensitive: content,
            }
        ) as ws:
            result = inv.build_repository_profile(ws, options=options, **profile_kwargs())
        details = _manifest_gap_details(result)
        self.assertIn(
            f"manifest-index=1; bytes={len(content.encode('utf-8'))}; limit=16",
            details,
            f"sensitive manifest budget gap must carry its TRUE sorted ordinal "
            f"(index 1): {details}",
        )
        self.assertTrue(
            any(
                f"manifest-index=0; bytes={len(content.encode('utf-8'))}; limit=16"
                in d
                for d in details
            ),
            f"the benign candidate (Cargo.toml) must be at index 0: {details}",
        )
        self.assertFalse(any("ghp_" in d for d in details), details)


def minimal_payload() -> dict:
    tests = importlib.import_module("tests.audit.test_ram_schema")
    return copy.deepcopy(tests.MINIMAL_PAYLOAD)


class X4WireConsistencyTests(unittest.TestCase):
    """X4 (DR-04-B approved): candidate_id binding + strict path segments."""

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
        # X4-0 GREEN anchor (frozen IP-0021 pattern; proves no weakening).
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
        # X4-7 wire-layer negative (DR-04-B v3 ruling 2): a literal
        # symbol == "-" on the wire must be rejected; with the entrance
        # rejections (X8) in force a wire '-' can only be an anomaly or
        # tamper.
        payload = self.payload
        payload["semantic"]["ranked"][0]["symbol"] = "-"
        with self.assertRaises(Exception) as ctx:
            self.validate(payload)
        self.assertIn("symbol", str(ctx.exception))


class X5AdmissionSkipSemanticsTests(unittest.TestCase):
    """X5: count-once per path and the RAM-only admission skip trace."""

    def test_same_path_hit_by_entrypoint_and_role_counted_once(self):
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
    """X6 (GREEN anchors): the migrated MINIMAL_PAYLOAD carries five
    mutually distinct, true, recomputable digests."""

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


class X7SensitiveScriptNameAdmissionTests(unittest.TestCase):
    """X7: a secret-shaped manifest script NAME must not surface as
    entrypoints[i].symbol, and the skip must be publicly counted."""

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


def _scan(repo):
    ram = ram_module()
    with workspace_with(repo) as ws:
        return ram.build_python_ram_facts(ws)


def _facts_with_dash_in_section(result, section):
    """Append a symbol='-' entry to one of the five inventories.

    Structure-valid construction (v6 fix): sensitive_sinks is parallel to
    sink_rule_ids / sink_cwes, so those tuples grow in lockstep (a known
    rule id / cwe) -- otherwise _collect_candidates raises an unrelated
    parallelism ValueError before the missing target behaviour is reached.
    The other four inventories have no parallel structures (verified
    against the PythonRamFacts field table). Returns the mutated build
    result and the appended index.
    """
    facts = result.facts
    entries = getattr(facts, section)
    donor = facts.external_sources[0]
    dash_entry = dataclasses.replace(donor, symbol="-")
    updates = {section: entries + (dash_entry,)}
    if section == "sensitive_sinks":
        updates["sink_rule_ids"] = facts.sink_rule_ids + ("FLOW-COMMAND",)
        updates["sink_cwes"] = facts.sink_cwes + ("CWE-78",)
    inner = dataclasses.replace(facts, **updates)
    return dataclasses.replace(result, facts=inner), len(entries)


def _assert_typed_rejection(case, ctx, field_path):
    # Exact code + exact field position (Maintainer frozen-test requirement).
    case.assertIs(ctx.exception.code, ContractErrorCode.INVALID_FIELD_VALUE)
    case.assertEqual(ctx.exception.field_path, field_path)


class X8PublicApiRoundTripContractTests(unittest.TestCase):
    """DR-04-B v3 (RESOLVED-MAINTAINER): round-trip guarantee via typed
    entry rejection of the literal symbol '-'."""

    def test_real_scan_round_trip_validates(self):
        # X8-0 GREEN anchor: legal inputs keep round-tripping end to end.
        sp = sp_module()
        rs = rs_module()
        result = _scan({"danger.py": SINK_CODE, "pkg/__init__.py": "x = 1\n"})
        semantic = sp.build_semantic_top_n(result.facts)
        payload = rs.ram_wire_payload(result, semantic)
        rs.validate_ram_wire_payload(payload)  # must not raise

    def _entry_negative(self, section):
        # X8-1a..e: typed rejection of symbol == '-' in each of the five
        # facts inventories (RED on main: accepted, round trip passes).
        sp = sp_module()
        base = _scan({"danger.py": SINK_CODE, "pkg/__init__.py": "x = 1\n"})
        facts, idx = _facts_with_dash_in_section(base, section)
        with self.assertRaises(ContractError) as ctx:
            sp.build_semantic_top_n(facts.facts)
        _assert_typed_rejection(self, ctx, f"$.facts.{section}[{idx}].symbol")

    def test_x8_1a_build_semantic_top_n_rejects_dash_symbol_entrypoints(self):
        self._entry_negative("entrypoints")

    def test_x8_1b_build_semantic_top_n_rejects_dash_symbol_external_sources(self):
        self._entry_negative("external_sources")

    def test_x8_1c_build_semantic_top_n_rejects_dash_symbol_sensitive_sinks(self):
        # Production sinks always carry symbol=None; the '-' entry is
        # injected with dataclasses.replace AND parallel rule tuples kept
        # in lockstep (v6 structure-valid construction).
        self._entry_negative("sensitive_sinks")

    def test_x8_1d_build_semantic_top_n_rejects_dash_symbol_trust_boundaries(self):
        # Production trust boundaries always carry symbol=None; injected.
        self._entry_negative("trust_boundaries")

    def test_x8_1e_build_semantic_top_n_rejects_dash_symbol_unresolved_edges(self):
        self._entry_negative("unresolved_edges")

    def test_ram_wire_payload_rejects_dash_symbol_ranked(self):
        # X8-2: defends against a caller hand-constructing
        # SemanticTopNResult with symbol == '-' in ranked.
        sp = sp_module()
        rs = rs_module()
        result = _scan({"danger.py": SINK_CODE, "pkg/__init__.py": "x = 1\n"})
        semantic = sp.build_semantic_top_n(result.facts)
        idx = next(
            i for i, c in enumerate(semantic.ranked) if c.symbol is not None
        )
        tampered_ranked = (
            semantic.ranked[:idx]
            + (dataclasses.replace(semantic.ranked[idx], symbol="-"),)
            + semantic.ranked[idx + 1 :]
        )
        tampered = dataclasses.replace(semantic, ranked=tampered_ranked)
        with self.assertRaises(ContractError) as ctx:
            rs.ram_wire_payload(result, tampered)
        _assert_typed_rejection(
            self, ctx, f"$.semantic_result.ranked[{idx}].symbol"
        )


class R3GoldenZeroHitAnchorTests(unittest.TestCase):
    """R3: the heuristic (incl. the id_ family) has ZERO hits across the
    golden fixtures' path-like strings and fixture repo filenames."""

    @staticmethod
    def _walk_strings(node, out: list[str]) -> None:
        if isinstance(node, dict):
            for value in node.values():
                R3GoldenZeroHitAnchorTests._walk_strings(value, out)
        elif isinstance(node, list):
            for value in node:
                R3GoldenZeroHitAnchorTests._walk_strings(value, out)
        elif isinstance(node, str):
            out.append(node)

    def test_goldens_and_fixture_repos_zero_hit(self):
        inv = inv_module()
        helper = inv.is_secret_shaped_path
        path_like: list[str] = []
        for golden_file in sorted(_GOLDEN_DIR.glob("*.json")):
            strings: list[str] = []
            self._walk_strings(json.loads(golden_file.read_text(encoding="utf-8")), strings)
            path_like.extend(
                s for s in strings if "/" in s or s.endswith(".py")
            )
        shapes = importlib.import_module(
            "tests.audit.fixtures.golden_matrix.shapes"
        )
        for repo in shapes.SHAPES.values():
            path_like.extend(repo.keys())
        self.assertTrue(path_like, "arrange sanity: collected path-like strings")
        hits = [s for s in path_like if helper(s)]
        self.assertEqual(
            hits,
            [],
            f"heuristic must have zero hits on golden/fixture paths: {hits}",
        )


if __name__ == "__main__":
    unittest.main()
