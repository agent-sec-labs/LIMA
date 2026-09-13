"""RED proof tests for IP-0022 (#60-Fix pre-closure blockers).

Packet: IP-0022-PACKET/v3 (PKT-IP-0022-D1R3, 2026-09-13; v1 D1, v2 D1R2)
Baseline: 30bdfaa13ac72572d65ccb2567ae8702923c4187 (origin/main)

Every test below MUST fail at the baseline because the target behaviour is
missing (F1 secret-shaped filename admission rejection, F2 wire validator
path rejection + embedded-digest consistency). None of them may fail because
of arrange defects: each arrange path is exercised green by the existing
frozen suites (tests/audit, tests/contracts @30bdfaa, 801 passed).

These tests are NOT the Frozen Test Commit. They live in a scratch directory
and are attached to the D1 handoff as the RED negative-case proof; the frozen
version lands in tests/audit/ in the D2 round after the Packet PR merges.
"""

from __future__ import annotations

import importlib
import json
import unittest

from tests.audit.fixtures.repo_shapes import workspace_with

GHP_FILENAME = f"ghp_{'a' * 36}.py"
AKIA_FILENAME = f"AKIA{'Q' * 16}.py"
JWT_FILENAME = f"eyJ{'b' * 15}.{'c' * 15}.py"

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


class _PromptCapturingClient:
    """Minimal SemanticModelClient stand-in that records every prompt."""

    def __init__(self) -> None:
        self.calls: list[str] = []

    def complete(self, prompt: str, *, timeout_seconds: int) -> str:
        self.calls.append(prompt)
        return "[]"


def ram_module() -> object:
    return importlib.import_module("lima.audit.ram")


def sp_module() -> object:
    return importlib.import_module("lima.audit.semantic_prioritizer")


def rs_module() -> object:
    return importlib.import_module("lima.audit.ram_schema")


def inv_module() -> object:
    return importlib.import_module("lima.audit.inventory")


def build_chain(repo: dict[str, str]):
    ram = ram_module()
    sp = sp_module()
    with workspace_with(repo) as workspace:
        ram_result = ram.build_python_ram_facts(workspace)
    semantic_result = sp.build_semantic_top_n(ram_result.facts)
    return ram_result, semantic_result


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


class F1SecretFilenameAdmissionTests(unittest.TestCase):
    """F1: secret-shaped filenames must be rejected at AttackSurfaceEntry
    admission (upstream), so they never reach any of the four downstream
    layers: RAM facts, Top-N ranked board, prompt text, wire payload."""

    def test_secret_shaped_path_helper_is_heuristic_superset(self):
        """M1' (DR-IP-0022-02 §1): heuristic superset interception.

        The admission pattern is a heuristic SUPERSET of the five frozen
        token shapes: every token shape must hit, the two Maintainer-observed
        samples must hit, and the frozen false-positive negatives must NOT
        hit. It is no longer asserted equal to _SECRET_TOKEN_PATTERN.
        """
        inv = inv_module()
        helper = getattr(inv, "is_secret_shaped_path")
        # (a) superset: all five frozen token shapes still hit
        self.assertTrue(helper(f"ghp_{'a'*36}.py"))
        self.assertTrue(helper(f"AKIA{'Q'*16}.py"))
        self.assertTrue(helper(f"eyJ{'b'*15}.{'c'*15}.py"))
        self.assertTrue(helper(f"xoxb-{'c'*12}.py"))
        self.assertTrue(helper("key.pem"))  # keyword: private[_-]?key family
        # (b) Maintainer-observed samples must hit
        self.assertTrue(helper("token_FAKESECRET123.py"))
        self.assertTrue(helper("sk_live_ABC123xyztoken.py"))
        # (c) prefix family extensions
        self.assertTrue(helper(f"gho_{'a'*36}.py"))
        self.assertTrue(helper("sk_test_ABC123xyztoken.py"))
        self.assertTrue(helper("github_pat_11ABCDEFGH0123456789_abcdefghijklmnopqrstuvwxyz1234567890.py"))
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
        # (g) path form: check applies to basename
        self.assertTrue(helper(f"pkg/{'ZFk8dQ2vNc7bX1mR4tYw'}.py"))

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
        inv = inv_module()
        with workspace_with(SECRET_SINK_REPO) as workspace:
            result = inv.build_repository_profile(
                workspace,
                tenant_id="t",
                task_id="task",
                workflow_id="w",
                stage_attempt_id="s",
                artifact_id="a",
                repository_snapshot_digest="0" * 64,
            )
        profile = result.profile
        details = [
            gap.detail
            for gap in getattr(profile, "coverage_gaps", ())
            if "sensitive-filename" in gap.detail
        ]
        self.assertTrue(
            details,
            "skipped-by-reason summary must surface as a typed coverage gap",
        )
        self.assertIn("count=1", details[0])

    def test_profile_entrypoints_exclude_manifest_script_secret_target(self):
        inv = inv_module()
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
        with workspace_with(repo) as workspace:
            result = inv.build_repository_profile(
                workspace,
                tenant_id="t",
                task_id="task",
                workflow_id="w",
                stage_attempt_id="s",
                artifact_id="a",
                repository_snapshot_digest="0" * 64,
            )
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
    """F2: validate_ram_wire_payload must reject non-repo-relative-POSIX
    entry paths and identity.wire_digest values that disagree with
    ram_wire_digest(payload)."""

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
        from lima.contracts.errors import ContractError

        rs = rs_module()
        payload = self.fresh_payload()
        section, index = self._entry_section(payload)
        payload["ram"][section.split(".")[1]][index]["path"] = "/etc/app/danger.py"
        with self.assertRaises(ContractError):
            rs.validate_ram_wire_payload(payload)

    def test_windows_drive_absolute_path_rejected(self):
        from lima.contracts.errors import ContractError

        rs = rs_module()
        payload = self.fresh_payload()
        section, index = self._entry_section(payload)
        payload["ram"][section.split(".")[1]][index]["path"] = "C:\\repo\\danger.py"
        with self.assertRaises(ContractError):
            rs.validate_ram_wire_payload(payload)

    def test_parent_traversal_path_rejected(self):
        from lima.contracts.errors import ContractError

        rs = rs_module()
        for bad in ("../danger.py", "pkg/../../danger.py"):
            payload = self.fresh_payload()
            section, index = self._entry_section(payload)
            payload["ram"][section.split(".")[1]][index]["path"] = bad
            with self.assertRaises(ContractError):
                rs.validate_ram_wire_payload(payload)

    def test_traversal_in_ranked_path_rejected(self):
        from lima.contracts.errors import ContractError

        rs = rs_module()
        payload = self.fresh_payload()
        payload["semantic"]["ranked"][0]["path"] = "../outside/danger.py"
        with self.assertRaises(ContractError):
            rs.validate_ram_wire_payload(payload)

    def test_embedded_wire_digest_mismatch_rejected(self):
        from lima.contracts.errors import ContractError

        rs = rs_module()
        payload = self.fresh_payload()
        honest = payload["identity"]["wire_digest"]
        tampered = ("0" if honest[0] != "0" else "1") + honest[1:]
        payload["identity"]["wire_digest"] = tampered
        with self.assertRaises(ContractError):
            rs.validate_ram_wire_payload(payload)

    def test_stale_digest_after_build_config_change_rejected(self):
        from lima.contracts.errors import ContractError

        rs = rs_module()
        payload = self.fresh_payload()
        payload["build"]["semantic"]["seed"] += 1
        with self.assertRaises(ContractError):
            rs.validate_ram_wire_payload(payload)

    def test_payload_tamper_with_synced_wire_digest_still_rejected(self):
        """M17 (DR-IP-0022-02 §2): tampering a ram payload path AND
        re-syncing the transport header digest must NOT launder the tamper.

        wire_digest only covers build+identity slots; payload integrity is
        carried by identity.ram_facts_digest recomputation over the ram
        section. The mutated path is itself legal repo-relative POSIX, so
        only the identity digest check can catch it.
        """
        from lima.contracts.errors import ContractError

        rs = rs_module()
        payload = self.fresh_payload()
        payload["ram"]["sensitive_sinks"][0]["path"] = "pkg/other_target.py"
        payload["identity"]["wire_digest"] = rs.ram_wire_digest(payload)
        # transport header is now honest again -- tamper must still fail
        self.assertEqual(
            payload["identity"]["wire_digest"], rs.ram_wire_digest(payload)
        )
        with self.assertRaises(ContractError):
            rs.validate_ram_wire_payload(payload)

    def test_semantic_ranked_tamper_with_synced_wire_digest_still_rejected(self):
        """M17-semantic: same laundering attempt against semantic.ranked
        (caught by identity.semantic_result_digest recomputation)."""
        from lima.contracts.errors import ContractError

        rs = rs_module()
        payload = self.fresh_payload()
        payload["semantic"]["ranked"][0]["rationale"] = "tampered rationale"
        payload["identity"]["wire_digest"] = rs.ram_wire_digest(payload)
        with self.assertRaises(ContractError):
            rs.validate_ram_wire_payload(payload)


class G1ProfileCodeRolesTests(unittest.TestCase):
    """G1 (DR-IP-0022-03): secret-shaped filenames must not surface in the
    public Profile surface either -- code_roles carried
    tests/token_FAKESECRET123.py as CodeRole.TEST at the baseline."""

    def build_profile(self, repo: dict[str, str]):
        inv = inv_module()
        with workspace_with(repo) as workspace:
            result = inv.build_repository_profile(
                workspace,
                tenant_id="t",
                task_id="task",
                workflow_id="w",
                stage_attempt_id="s",
                artifact_id="a",
                repository_snapshot_digest="0" * 64,
            )
        return result

    def test_profile_code_roles_exclude_secret_shaped_filename(self):
        result = self.build_profile(
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
        result = self.build_profile(
            {
                "tests/token_FAKESECRET123.py": "import os\nos.system('x')\n",
                "safe.py": "x = 1\n",
            }
        )
        profile = result.profile
        text = json.dumps(profile.to_dict(), sort_keys=True, default=str)
        self.assertNotIn("FAKESECRET", text)

    def test_profile_secret_filename_skip_counted(self):
        result = self.build_profile(
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
    """G2 (DR-IP-0022-03): B' migration compatibility + model_digest slot."""

    @classmethod
    def setUpClass(cls):
        cls.ram_result, cls.semantic_result = build_chain(SINK_TAINTED_REPO)

    def test_model_digest_tamper_rejected(self):
        """identity.model_digest must equal compute_content_digest(
        build.semantic.model_id); a tampered value must be rejected."""
        from lima.contracts.errors import ContractError

        rs = rs_module()
        payload = rs.ram_wire_payload(self.ram_result, self.semantic_result)
        rs.validate_ram_wire_payload(payload)
        honest = payload["identity"]["model_digest"]
        tampered = ("0" if honest[0] != "0" else "1") + honest[1:]
        payload["identity"]["model_digest"] = tampered
        with self.assertRaises(ContractError):
            rs.validate_ram_wire_payload(payload)

    def test_minimal_payload_placeholder_digests_rejected(self):
        """The frozen MINIMAL_PAYLOAD carries all-zero placeholder digests
        (HEX64 = '0'*64). Under route B' such an inconsistent payload must
        be REJECTED; the D2 migration rebuilds it as a self-consistent
        fixture (all identity digests true recomputes)."""
        from lima.contracts.errors import ContractError

        import tests.audit.test_ram_schema as trs

        rs = rs_module()
        self.assertEqual(trs.HEX64, "0" * 64)
        self.assertIsNone(rs.validate_ram_wire_payload(trs.MINIMAL_PAYLOAD))  # baseline lenience (RED anchor)
        with self.assertRaises(ContractError):
            rs.validate_ram_wire_payload(trs.MINIMAL_PAYLOAD)


if __name__ == "__main__":
    unittest.main()
