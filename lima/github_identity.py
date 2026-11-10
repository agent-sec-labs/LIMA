"""Deployment-provisioned GitHub installation ownership (never client claims)."""

import json


def installation_id(value):
    if type(value) is not int or not 0 < value < 2**63:
        raise ValueError("installation_id must be a positive 64-bit integer")
    return value


def installation_bindings(raw):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate installation ownership entry")
            result[key] = value
        return result

    try:
        value = json.loads(raw or "{}", object_pairs_hook=unique)
    except (TypeError, json.JSONDecodeError) as exc:
        raise ValueError("GitHub installation ownership must be a JSON object") from exc
    if not isinstance(value, dict):
        raise ValueError("GitHub installation ownership must be a JSON object")
    for key, tenant in value.items():
        if (
            not key.isascii()
            or not key.isdigit()
            or key != str(int(key))
            or not 0 < int(key) < 2**63
        ):
            raise ValueError("installation ownership keys must be canonical positive IDs")
        if (
            not isinstance(tenant, str)
            or not tenant.strip()
            or tenant != tenant.strip()
            or len(tenant) > 128
        ):
            raise ValueError("installation ownership requires bounded tenant IDs")
    return {int(key): tenant for key, tenant in value.items()}
