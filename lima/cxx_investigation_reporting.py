"""Bounded report projections of actual C/C++ investigation records."""

import json

from .platform_contracts import privacy_text


def _scrub(value):
    if isinstance(value, str):
        return privacy_text(value)
    if isinstance(value, dict):
        return {key: _scrub(item) for key, item in value.items()}
    if isinstance(value, (tuple, list)):
        return [_scrub(item) for item in value]
    if value is None or isinstance(value, (bool, int, float)):
        return value
    return privacy_text(str(value))


def investigation_summary(trace: dict, *, byte_limit: int = 128 * 1024) -> dict:
    """Keep trace details whole, or return an explicit count-only projection."""
    summary = {
        "strategy": trace.get("strategy", "scout"),
        "stop_reason": trace.get("stop_reason", "incomplete"),
        "action_count": len(trace.get("actions", [])),
        "child_count": len(trace.get("children", [])),
        "hypothesis_count": len(trace.get("hypothesis_history", [])),
    }
    value = _scrub({**trace, **summary})
    if len(json.dumps(value, ensure_ascii=True).encode("utf-8")) <= byte_limit:
        return value
    return _scrub({**summary, "detail_omissions": ["investigation:byte-budget"]})
