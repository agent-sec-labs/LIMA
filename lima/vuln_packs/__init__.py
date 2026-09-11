"""Vulnerability-type pack plugin interface (plan Task 5, design section 4).

The platform kernel (orchestration, tools, reproduction workbench, evidence
grades, reporting) is bug-class agnostic.  Every bug class ships as one
frozen :class:`VulnPack` carrying the five per-class assets the design
names: Specialist knowledge, triage seed patterns, PoC driver template
names, ASan/UBSan interpretation rules and the CWE mapping.  Adding a
future pack (information disclosure, injection, ...) is data plus one
:func:`register_pack` call -- never a kernel change.

Packs are data, not behaviour: nothing here executes.  Matching semantics
stay with the consumers (the orchestrator matches marker substrings against
lowered sanitizer error types; the triage layer matches seed regexes
against source text).  :func:`runtime_markers` is the one derived view the
orchestrator consumes: the effective CWE -> marker-substring table.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass


@dataclass(frozen=True)
class VulnPack:
    """One bug-class pack: the five design-section-4 assets, frozen.

    ``asan_markers`` maps each covered CWE to the lowercase sanitizer
    error-type substrings that confirm a hypothesis of that class (one
    error type can confirm several classes -- e.g. ASan's
    ``heap-buffer-overflow`` is both CWE-787 writes and CWE-125 reads --
    so the mapping is keyed by CWE, not by marker).  ``driver_templates``
    names resolve in ``lima.repro_templates.DRIVER_TEMPLATES``.
    """

    name: str
    cwe_ids: frozenset[str]
    specialist_prompt_addendum: str
    seed_patterns: tuple[str, ...]
    driver_templates: tuple[str, ...]
    asan_markers: Mapping[str, tuple[str, ...]]
    integer_overflow_markers: Mapping[str, str]


def runtime_markers(pack: VulnPack) -> dict[str, tuple[str, ...]]:
    """The effective error-type matching table for ``pack``.

    Maps every covered CWE to the lowercase error-type substrings that
    confirm a hypothesis of that class: the pack's ASan marker table plus
    the UBSan-style markers folded in per their CWE mapping.
    """

    merged = {cwe: tuple(markers) for cwe, markers in pack.asan_markers.items()}
    for marker, cwe in pack.integer_overflow_markers.items():
        merged[cwe] = merged.get(cwe, ()) + (marker.lower(),)
    return merged


_PACKS: dict[str, VulnPack] = {}


def register_pack(pack: VulnPack) -> None:
    """Register one pack; duplicate names are a configuration error."""

    if pack.name in _PACKS:
        raise ValueError(f"vulnerability pack {pack.name!r} is already registered")
    _PACKS[pack.name] = pack


def get_pack(name: str) -> VulnPack:
    """Return the registered pack ``name`` (KeyError when unknown)."""

    try:
        return _PACKS[name]
    except KeyError:
        raise KeyError(f"unknown vulnerability pack: {name!r}") from None


def list_packs() -> tuple[str, ...]:
    """The sorted registry of available pack names."""

    return tuple(sorted(_PACKS))


from .memory import MEMORY_PACK  # noqa: E402 -- data module needs VulnPack above

register_pack(MEMORY_PACK)


__all__ = [
    "MEMORY_PACK",
    "VulnPack",
    "get_pack",
    "list_packs",
    "register_pack",
    "runtime_markers",
]
