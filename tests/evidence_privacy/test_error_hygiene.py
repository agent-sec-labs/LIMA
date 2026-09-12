# IP-0015 Evidence Privacy Core - frozen acceptance tests (P&V owned).
# Packet: docs/LIMA_Implementation_Packet_IP-0015_Evidence_Privacy_Core.md v1.0
# Frozen Test Commit v2 (DR-IP-0015-03 erratum 2026-09-12): converted from
# v1 bare-function style to unittest.TestCase style 1:1; assertions,
# boundary values, and requirement-ID anchors are unchanged from v1 (97e0b63).
"""Error hygiene & static resource-contract tests (Packet 8.5/8.6; NFR-N05-03, SEC-N05-01/03)."""

from __future__ import annotations

import importlib
import inspect
import pkgutil
import unittest

from lima.evidence_privacy import (
    EvidencePayload,
    PrivacyError,
    PrivacyErrorCode,
    SinkContext,
    TenantPolicy,
    sanitize_for_sink,
)

SECRET = "ghp_abcdefghijklmnop"  # noqa: S105 - synthetic test token
KEY = b"\x55" * 32

EXPECTED_CODES = {
    "INVALID_FIELD_TYPE",
    "INVALID_FIELD_VALUE",
    "UNKNOWN_SINK",
    "MISSING_TENANT_KEY",
    "POLICY_ERROR",
    "RESOURCE_LIMIT_EXCEEDED",
    "MAX_DEPTH_EXCEEDED",
    "MAX_ITEMS_EXCEEDED",
    "MAX_STRING_LENGTH_EXCEEDED",
    "TIME_BUDGET_EXCEEDED",
    "UNSUPPORTED_PAYLOAD_KIND",
    "INTERNAL_REDACTION_FAILURE",
}


class ErrorHygieneTests(unittest.TestCase):
    def test_error_code_enum_frozen(self):
        # Packet 8.6: PrivacyErrorCode values are the frozen uppercase set.
        values = {c.value for c in PrivacyErrorCode}
        self.assertEqual(values, EXPECTED_CODES)

    def test_error_str_has_code_field_path_only(self):
        # Packet 8.6 / NFR-N05-03: __str__ carries code/field_path, no raw values.
        err = PrivacyError(
            PrivacyErrorCode.INVALID_FIELD_VALUE,
            field_path="value",
            context={"value_length": 18, "value_kind": "string"},
        )
        s = str(err)
        self.assertIn("INVALID_FIELD_VALUE", s)
        self.assertNotIn(SECRET, s)
        self.assertTrue(hasattr(err, "code") and hasattr(err, "field_path") and hasattr(err, "context"))

    def test_error_context_metadata_only(self):
        # Packet 8.6: context may carry only non-value metadata (length/kind).
        err = PrivacyError(
            PrivacyErrorCode.MAX_STRING_LENGTH_EXCEEDED,
            context={"value_length": 9, "value_kind": "string"},
        )
        self.assertTrue(all(k in ("value_length", "value_kind") for k in err.context))

    def test_real_errors_do_not_leak_secret(self):
        # NFR-N05-03 / SEC-N05-03: all rejection paths keep the raw value out of
        # str(exc) and repr(exc).
        cases = [
            # (payload, bad sink kwargs)
            (EvidencePayload(payload_kind="structured_json", value={"password": SECRET}),
             {"sink_kind": "vault", "tenant_id": "t", "tenant_key": KEY}),
            (EvidencePayload(payload_kind="text", value=SECRET),
             {"sink_kind": "log", "tenant_id": "t", "tenant_key": b""}),
        ]
        for payload, sink_kwargs in cases:
            with self.subTest(sink_kwargs=sink_kwargs):
                with self.assertRaises(PrivacyError) as ei:
                    sanitize_for_sink(
                        payload,
                        SinkContext(**sink_kwargs),
                        TenantPolicy.resolve(policy_version="v1"),
                    )
                self.assertNotIn(SECRET, str(ei.exception))
                self.assertNotIn(SECRET[:4], repr(ei.exception))

    def test_error_is_exception_and_typed(self):
        # Packet 8.6: PrivacyError is Exception subclass with typed code.
        self.assertTrue(issubclass(PrivacyError, Exception))
        err = PrivacyError(PrivacyErrorCode.UNKNOWN_SINK)
        self.assertIsInstance(err.code, PrivacyErrorCode)

    def test_static_no_logging_or_env_or_fs_write(self):
        # SEC-N05-01 / Packet 8.5: package source contains no logging, no
        # os.environ, no file-open, no subprocess, no socket.
        import lima.evidence_privacy as pkg

        banned = ("import logging", "getLogger", "os.environ", "open(", "subprocess", "socket")
        for mod_info in pkgutil.iter_modules(pkg.__path__):
            mod = importlib.import_module(f"lima.evidence_privacy.{mod_info.name}")
            src = inspect.getsource(mod)
            for token in banned:
                self.assertNotIn(token, src, (mod_info.name, token))

    def test_no_module_level_mutating_globals(self):
        # Packet 8.2: no global mutable state; reimport keeps behaviour (spot).
        import lima.evidence_privacy as pkg

        src = inspect.getsource(pkg)
        self.assertNotIn("tenant_key", src.split("\n")[0])  # no key at module header
        import importlib as il

        il.reload(pkg)
        self.assertTrue(callable(pkg.sanitize_for_sink))

    def test_wrapped_internal_error_stable_no_traceback_values(self):
        # AC/T-N05-04 / SEC-N05-02: wrapped error message is stable & value-free.
        import lima.evidence_privacy.port as port_mod

        original = port_mod.classify_payload

        def boom(*a, **k):
            raise ValueError("ctx contains " + SECRET)

        port_mod.classify_payload = boom
        try:
            with self.assertRaises(PrivacyError) as ei:
                sanitize_for_sink(
                    EvidencePayload(payload_kind="text", value="x" * 8),
                    SinkContext(sink_kind="log", tenant_id="t", tenant_key=KEY),
                    TenantPolicy.resolve(policy_version="v1"),
                )
            self.assertEqual(ei.exception.code, PrivacyErrorCode.INTERNAL_REDACTION_FAILURE)
            self.assertNotIn(SECRET, str(ei.exception))
        finally:
            port_mod.classify_payload = original


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
