"""Frozen acceptance tests for the IP-0020 vault port default-disabled contract.

Anchors (per Packet IP-0020 v1.2 erratum, DR-IP-0020-4R): FR-N05-04,
§8.1 as revised by Packet §17.F4' (backend metadata, zero backend echo),
§9 T1/T5; assertion mapping = Packet §18 #7 (revision, not deletion).
Dual-runner safe: unittest.TestCase only, no pytest API (PI-DR6-bis).
"""

from __future__ import annotations

import dataclasses
import inspect
import pathlib
import unittest

from lima.evidence_privacy import vault_port as vp
from lima.evidence_privacy.errors import PrivacyError, PrivacyErrorCode
from lima.evidence_privacy.models import SinkContext, TenantPolicy

# T5 §9: no registered backend in IP-0020 (structural fail-closed guarantee).
FAKE_BACKEND = "not-a-registered-backend"
SINK = SinkContext(sink_kind="log", purpose="test", tenant_id="tenant-a", tenant_key=b"k-a" * 16)
POLICY = TenantPolicy(policy_version="v1")


def assert_backend_hygiene(testcase, exc, expected_backend):
    """F4' §17.F4'/§18 #7: errors carry backend metadata only.

    The PrivacyError context must expose backend_len/backend_registered
    (never the backend name under a "backend" key) and its str()/repr()
    must not echo the backend plaintext.
    """
    text = str(exc) + repr(exc)
    testcase.assertNotIn("FAKE_BACKEND", text)
    if expected_backend is not None:
        testcase.assertNotIn(expected_backend, text)
    context = exc.context
    testcase.assertIn("backend_len", context)
    testcase.assertIn("backend_registered", context)
    testcase.assertNotIn("backend", context)
    if expected_backend is None:
        testcase.assertIsNone(context["backend_len"])
        testcase.assertFalse(context["backend_registered"])
    else:
        testcase.assertEqual(context["backend_len"], len(expected_backend))
        testcase.assertIs(context["backend_registered"], False)


def _source_text() -> str:
    # FR-N05-04 §8.1/§9 T1: module source hygiene grep target.
    return pathlib.Path(inspect.getfile(vp)).read_text(encoding="utf-8")


class VaultPortDefaultDisabledTests(unittest.TestCase):
    """FR-N05-04 §8.1.1 + §9 T1: default construction is the closed state."""

    def test_default_config_is_disabled(self) -> None:
        # FR-N05-04 §8.1.1: no-arg construction must be the "off" state.
        config = vp.VaultPortConfig()
        self.assertFalse(config.enabled)
        # §8.1.1: every field carries a default (none is MISSING) so the
        # no-arg constructor is always the closed state.
        for field in dataclasses.fields(vp.VaultPortConfig):
            self.assertFalse(
                field.default is dataclasses.MISSING
                and field.default_factory is dataclasses.MISSING,
                field.name,
            )

    def test_no_registered_backends(self) -> None:
        # FR-N05-04 §8.1.3 / §9 T5: backend registry is the empty set.
        self.assertEqual(vp.VAULT_BACKEND_PORT_NAMES, frozenset())


class ValidateVaultConfigNineBranchTests(unittest.TestCase):
    """FR-N05-04 §8.1.3: all nine frozen validation branches, one per test."""

    def test_branch_1_disabled_config_passes(self) -> None:
        # §8.1.3 rule 1: enabled=False passes unconditionally.
        vp.validate_vault_config(vp.VaultPortConfig())

    def test_branch_2_disabled_with_other_fields_still_passes(self) -> None:
        # §8.1.3 rule 1: closed state is the safe state; other fields do not error.
        vp.validate_vault_config(
            vp.VaultPortConfig(enabled=False, ttl_seconds=None, encryption_required=False)
        )

    def test_branch_3_enabled_without_backend_rejected(self) -> None:
        # §8.1.3 rule 2: enabled=True + backend None -> reject.
        # F4' §18 #7: context carries backend_len/backend_registered metadata
        # (backend_len None when no backend); no backend plaintext anywhere.
        with self.assertRaises(PrivacyError) as ctx:
            vp.validate_vault_config(vp.VaultPortConfig(enabled=True))
        self.assertIs(ctx.exception.code, PrivacyErrorCode.POLICY_ERROR)
        assert_backend_hygiene(self, ctx.exception, None)

    def test_branch_4_enabled_with_unregistered_backend_rejected(self) -> None:
        # §8.1.3 rule 3: any backend not in the (empty) registry -> reject.
        with self.assertRaises(PrivacyError) as ctx:
            vp.validate_vault_config(vp.VaultPortConfig(enabled=True, backend=FAKE_BACKEND))
        self.assertIs(ctx.exception.code, PrivacyErrorCode.POLICY_ERROR)
        assert_backend_hygiene(self, ctx.exception, FAKE_BACKEND)  # F4' §18 #7

    def test_branch_5_enabled_missing_ttl_rejected(self) -> None:
        # §8.1.3 rule 4: enabled=True + ttl_seconds None -> reject.
        with self.assertRaises(PrivacyError) as ctx:
            vp.validate_vault_config(
                vp.VaultPortConfig(enabled=True, backend=FAKE_BACKEND, ttl_seconds=None)
            )
        self.assertIs(ctx.exception.code, PrivacyErrorCode.POLICY_ERROR)

    def test_branch_6_enabled_nonpositive_ttl_rejected(self) -> None:
        # §8.1.3 rule 4: ttl_seconds <= 0 -> reject.
        for bad_ttl in (0, -1):
            with self.subTest(ttl=bad_ttl):
                with self.assertRaises(PrivacyError) as ctx:
                    vp.validate_vault_config(
                        vp.VaultPortConfig(enabled=True, backend=FAKE_BACKEND, ttl_seconds=bad_ttl)
                    )
                self.assertIs(ctx.exception.code, PrivacyErrorCode.POLICY_ERROR)
                assert_backend_hygiene(self, ctx.exception, FAKE_BACKEND)  # F4' §18 #7

    def test_branch_7_encryption_not_required_rejected(self) -> None:
        # §8.1.3 rule 5: enabled=True + not encryption_required -> reject.
        with self.assertRaises(PrivacyError) as ctx:
            vp.validate_vault_config(
                vp.VaultPortConfig(enabled=True, backend=FAKE_BACKEND, encryption_required=False)
            )
        self.assertIs(ctx.exception.code, PrivacyErrorCode.POLICY_ERROR)
        assert_backend_hygiene(self, ctx.exception, FAKE_BACKEND)  # F4' §18 #7

    def test_branch_8_audit_access_not_required_rejected(self) -> None:
        # §8.1.3 rule 6: enabled=True + not audit_access_required -> reject.
        with self.assertRaises(PrivacyError) as ctx:
            vp.validate_vault_config(
                vp.VaultPortConfig(enabled=True, backend=FAKE_BACKEND, audit_access_required=False)
            )
        self.assertIs(ctx.exception.code, PrivacyErrorCode.POLICY_ERROR)
        assert_backend_hygiene(self, ctx.exception, FAKE_BACKEND)  # F4' §18 #7

    def test_branch_9_backend_set_while_disabled_rejected(self) -> None:
        # §8.1.3 rule 7: backend configured but not enabled = drift -> reject.
        with self.assertRaises(PrivacyError) as ctx:
            vp.validate_vault_config(vp.VaultPortConfig(enabled=False, backend=FAKE_BACKEND))
        self.assertIs(ctx.exception.code, PrivacyErrorCode.POLICY_ERROR)
        assert_backend_hygiene(self, ctx.exception, FAKE_BACKEND)  # F4' §18 #7


class AcquireVaultAccessNoReturnTests(unittest.TestCase):
    """FR-N05-04 §8.1.4 + §9 T1: the sole acquisition entry never returns."""

    def test_acquire_default_config_raises_no_backend(self) -> None:
        # §8.1.4: valid sink/policy + default (disabled) config still fails
        # closed with INTERNAL_REDACTION_FAILURE ("no registered backend").
        with self.assertRaises(PrivacyError) as ctx:
            vp.acquire_vault_access(vp.VaultPortConfig(), sink=SINK, policy=POLICY)
        self.assertIs(ctx.exception.code, PrivacyErrorCode.INTERNAL_REDACTION_FAILURE)
        self.assertEqual(ctx.exception.field_path, "vault.access")
        # §8.1.5: error str/repr must not carry tenant credential material.
        text = str(ctx.exception) + repr(ctx.exception)
        self.assertNotIn("k-a", text)

    def test_acquire_enabled_with_fake_backend_rejected(self) -> None:
        # §8.1.4 + §9 T1: enabled=True with an unregistered backend name is
        # rejected by validation before anything else can succeed.
        with self.assertRaises(PrivacyError) as ctx:
            vp.acquire_vault_access(
                vp.VaultPortConfig(enabled=True, backend=FAKE_BACKEND),
                sink=SINK,
                policy=POLICY,
            )
        self.assertIs(ctx.exception.code, PrivacyErrorCode.POLICY_ERROR)
        assert_backend_hygiene(self, ctx.exception, FAKE_BACKEND)  # F4' §18 #7

    def test_acquire_reuses_port_validation_unknown_sink(self) -> None:
        # §8.1.4: sink kind outside the policy allowlist -> UNKNOWN_SINK (no
        # vault special-casing that relaxes port semantics).
        policy = TenantPolicy(policy_version="v1", sink_allowlist=frozenset({"api"}))
        sink = SinkContext(sink_kind="log", tenant_id="tenant-a", tenant_key=b"k-a" * 16)
        with self.assertRaises(PrivacyError) as ctx:
            vp.acquire_vault_access(vp.VaultPortConfig(), sink=sink, policy=policy)
        self.assertIs(ctx.exception.code, PrivacyErrorCode.UNKNOWN_SINK)

    def test_acquire_reuses_port_validation_missing_tenant_key(self) -> None:
        # §8.1.4: missing tenant credentials -> MISSING_TENANT_KEY.
        sink = SinkContext(sink_kind="log", tenant_id="tenant-a", tenant_key=b"")
        with self.assertRaises(PrivacyError) as ctx:
            vp.acquire_vault_access(vp.VaultPortConfig(), sink=sink, policy=POLICY)
        self.assertIs(ctx.exception.code, PrivacyErrorCode.MISSING_TENANT_KEY)

    def test_acquire_no_success_return_even_with_injected_backend(self) -> None:
        # §9 T1: monkeypatch the backend registry to inject a name; with a
        # fully "valid-looking" enabled config the call must STILL raise
        # (NoReturn holds under any injection).
        original = vp.VAULT_BACKEND_PORT_NAMES
        try:
            vp.VAULT_BACKEND_PORT_NAMES = frozenset({FAKE_BACKEND})
            config = vp.VaultPortConfig(enabled=True, backend=FAKE_BACKEND, ttl_seconds=3600)
            with self.assertRaises(PrivacyError) as ctx:
                vp.acquire_vault_access(config, sink=SINK, policy=POLICY)
            self.assertIs(ctx.exception.code, PrivacyErrorCode.INTERNAL_REDACTION_FAILURE)
        finally:
            vp.VAULT_BACKEND_PORT_NAMES = original
        # No path above returned normally; registry restored unchanged.
        self.assertEqual(vp.VAULT_BACKEND_PORT_NAMES, original)


class VaultPortSourceHygieneTests(unittest.TestCase):
    """FR-N05-04 §8.1.1/§8.1.2 + §9 T1/T5: module-level hygiene greps."""

    def test_no_environment_variable_reads(self) -> None:
        # §8.1.1/§9 T1: no os.environ / getenv anywhere in the module.
        source = _source_text()
        self.assertNotIn("os.environ", source)
        self.assertNotIn("getenv", source)

    def test_signatures_do_not_accept_secret_material(self) -> None:
        # §8.1.2: no public callable accepts secret-ish parameters and no
        # config field carries value payloads.
        forbidden = {"secret", "raw", "credential", "token"}
        for name, obj in vars(vp).items():
            if inspect.isfunction(obj):
                params = set(inspect.signature(obj).parameters)
                self.assertFalse(params & forbidden, name)
        for field in dataclasses.fields(vp.VaultPortConfig):
            self.assertNotIn(field.name, forbidden)
        self.assertEqual(
            [f.name for f in dataclasses.fields(vp.VaultPortConfig)],
            ["enabled", "backend", "ttl_seconds", "encryption_required", "audit_access_required"],
        )


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
