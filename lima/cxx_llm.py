"""Unwrap one enclosing Markdown code fence from a provider reply.

Retirement Task 2 trim: the strict step client and its tool/argument
schema machinery served the retired seven-role chain; only this shared
provider-convention helper remains.
"""

from __future__ import annotations


def unwrap_fenced_json(raw: str) -> str:
    """Unwrap exactly one enclosing Markdown code fence, nothing else.

    Many OpenAI-compatible providers (and several Gemini/Claude tiers) wrap
    JSON replies in a single `````json ... ````` block. That wrapper is a
    well-defined provider convention, not model-authored ambiguity, so the
    one-block form is unwrapped before the strict parser runs. Anything else
    -- prose around JSON, several blocks, an unterminated fence -- is left
    untouched and therefore still rejected by ``parse_untrusted_json``.
    """
    stripped = raw.strip()
    if not stripped.startswith("```"):
        return raw
    first_newline = stripped.find("\n")
    if first_newline < 0:
        return raw
    opening = stripped[:first_newline].strip()
    if opening not in {"```", "```json", "```JSON"}:
        return raw
    if not stripped.endswith("```"):
        return raw
    inner = stripped[first_newline + 1:].strip()
    if not inner.endswith("```"):
        return raw
    inner = inner[: inner.rfind("```")].strip()
    if "```" in inner:
        return raw
    return inner


__all__ = [
    "unwrap_fenced_json",
]
