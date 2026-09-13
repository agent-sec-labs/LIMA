"""Raw-secret vault port contract: default-disabled and structurally fail-closed.

Packet IP-0020 §8.1 (FR-N05-04): this module is the configuration and access
contract layer for a future raw-secret vault adapter. It intentionally ships
no backend: ``VAULT_BACKEND_PORT_NAMES`` is the empty frozen set, so validation
rejects every enable attempt, and the sole acquisition entry point never
returns. The port is a contract surface, not a data channel: no signature
accepts secret material, and no environment variable, global mutable state, or
auto-enable hook exists that could flip the default-disabled posture.

Consumed via the module path ``lima.evidence_privacy.vault_port``; the package
``__all__`` stays at its frozen 13 symbols (Packet §7.2, DR-IP-0020-1).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final, NoReturn

from lima.evidence_privacy.errors import PrivacyError, PrivacyErrorCode
from lima.evidence_privacy.models import SinkContext, TenantPolicy

__all__ = [
    "VAULT_BACKEND_PORT_NAMES",
    "VAULT_PORT_DISABLED_MESSAGE",
    "VaultBackendDescriptor",
    "VaultPortConfig",
    "acquire_vault_access",
    "validate_vault_config",
]

VAULT_PORT_DISABLED_MESSAGE: Final[str] = (
    "vault port is disabled by default; enabling requires an approved backend "
    "adapter (out of scope for IP-0020)"
)


@dataclass(frozen=True, slots=True)
class VaultBackendDescriptor:
    """Capability descriptor a future backend adapter must publish (Packet §8.1)."""

    name: str
    supports_ttl: bool
    supports_encryption: bool
    supports_audit_access: bool


# Packet §8.1.3: the registered-backend registry is empty in IP-0020, which is
# the structural fail-closed guarantee: no configuration can name a valid
# backend, so "enabled" can never become usable. Read at call time so that any
# future registration is an explicit, reviewable code change (never ambient).
VAULT_BACKEND_PORT_NAMES: Final[frozenset[str]] = frozenset()


@dataclass(frozen=True, slots=True)
class VaultPortConfig:
    """Vault port configuration; the no-argument construction is the closed state.

    Every field carries a default (Packet §8.1.1) so there is no construction
    path that yields an implicitly enabled port.
    """

    enabled: bool = False
    backend: str | None = None
    ttl_seconds: int | None = None
    encryption_required: bool = True
    audit_access_required: bool = True


def _rejection(config: VaultPortConfig, field_path: str) -> PrivacyError:
    """Value-free ``POLICY_ERROR`` carrying only enabled/backend metadata (§8.1.5)."""
    return PrivacyError(
        PrivacyErrorCode.POLICY_ERROR,
        field_path=field_path,
        context={"enabled": config.enabled, "backend": config.backend},
    )


def validate_vault_config(config: VaultPortConfig) -> None:
    """Validate ``config`` against the frozen nine-branch rule set (Packet §8.1.3).

    The disabled state is the safe state: ``enabled=False`` passes unless a
    backend is configured (configuration drift, rejected fail-closed). Any
    enabled combination is rejected because the backend registry is empty.
    """
    if not isinstance(config, VaultPortConfig):
        raise PrivacyError(
            PrivacyErrorCode.INVALID_FIELD_TYPE,
            field_path="config",
            context={"value_kind": type(config).__name__},
        )
    if not config.enabled:
        # Rule 7: a backend configured while disabled is an enablement precursor.
        if config.backend is not None:
            raise _rejection(config, "vault.backend")
        # Rule 1 (a+b): disabled passes; no other field triggers an error.
        return
    # Rule 2: enabled without a backend.
    if config.backend is None:
        raise _rejection(config, "vault.backend")
    # Rule 3: any backend outside the registry -- with the registry empty, every
    # enable attempt is rejected (structural, not a point check).
    if config.backend not in VAULT_BACKEND_PORT_NAMES:
        raise _rejection(config, "vault.backend")
    # Rule 4: enabled without a positive TTL.
    if config.ttl_seconds is None or config.ttl_seconds <= 0:
        raise PrivacyError(
            PrivacyErrorCode.POLICY_ERROR,
            field_path="vault.ttl_seconds",
            context={
                "enabled": config.enabled,
                "backend": config.backend,
                "ttl_seconds": config.ttl_seconds,
            },
        )
    # Rule 5: encryption must be required.
    if not config.encryption_required:
        raise _rejection(config, "vault.encryption_required")
    # Rule 6: audit access must be required.
    if not config.audit_access_required:
        raise _rejection(config, "vault.audit_access_required")


def acquire_vault_access(
    config: VaultPortConfig,
    *,
    sink: SinkContext,
    policy: TenantPolicy,
) -> NoReturn:
    """Sole vault acquisition entry; never returns in IP-0020 (Packet §8.1.4).

    Validation runs first, then the exact sink/tenant checks of
    ``sanitize_for_sink`` (no vault-specific relaxation), and even a fully
    valid request fails closed with ``INTERNAL_REDACTION_FAILURE`` because no
    backend exists. Errors carry value-free context only (§8.1.5).
    """
    validate_vault_config(config)
    if not isinstance(sink, SinkContext):
        raise PrivacyError(
            PrivacyErrorCode.INVALID_FIELD_TYPE,
            field_path="sink",
            context={"value_kind": type(sink).__name__},
        )
    if not isinstance(policy, TenantPolicy):
        raise PrivacyError(
            PrivacyErrorCode.INVALID_FIELD_TYPE,
            field_path="policy",
            context={"value_kind": type(policy).__name__},
        )
    if sink.sink_kind not in policy.sink_allowlist:
        raise PrivacyError(
            PrivacyErrorCode.UNKNOWN_SINK,
            field_path="sink_kind",
            context={"sink_kind_length": len(sink.sink_kind)},
        )
    tenant_key = sink.tenant_key
    if not isinstance(tenant_key, bytes) or not tenant_key:
        raise PrivacyError(PrivacyErrorCode.MISSING_TENANT_KEY, field_path="tenant_key")
    tenant_id = sink.tenant_id
    if (
        not isinstance(tenant_id, str)
        or not tenant_id
        or len(tenant_id.encode("utf-8")) > 128
    ):
        raise PrivacyError(
            PrivacyErrorCode.INVALID_FIELD_VALUE,
            field_path="tenant_id",
            context={"value_kind": type(tenant_id).__name__},
        )
    raise PrivacyError(
        PrivacyErrorCode.INTERNAL_REDACTION_FAILURE,
        field_path="vault.access",
        context={"reason": "no registered backend"},
    )
