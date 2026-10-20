"""Frozen legacy rendering and explicit knowledge selection boundaries."""
import hashlib
from dataclasses import FrozenInstanceError, replace

import pytest

from lima import specialist_knowledge as knowledge
from lima.agent_orchestrator import _system_platform_specialist, _target_cache_fingerprints
from lima.agent_scout import ScoutTarget


def test_legacy_matches_frozen_pre_split_prompt():
    bundle = knowledge.build_specialist_prompt(profile="legacy")
    assert bundle.sha256 == "000cbb56e0ca4f7a8e5998231f91362fdad96442e40175e85d401c94f6a558f3"
    assert len(bundle.text) == 10454
    assert _system_platform_specialist() == bundle.text
    with pytest.raises(FrozenInstanceError):
        bundle.text = "changed"


def test_structured_default_covers_all_mechanisms_without_component_recipes():
    bundle = knowledge.build_specialist_prompt(profile="structured")
    assert set(knowledge.MECHANISM_CARDS) <= set(bundle.knowledge_ids)
    for cwe in ("CWE-416", "CWE-415", "CWE-787", "CWE-125", "CWE-476", "CWE-190"):
        assert cwe in bundle.text
    for marker in ("XML_", "CVE-2022-43680", "expat", "avrcp", "dsoftbus"):
        assert marker not in bundle.text
    for marker in (
        "API contract", "negative control", "unresolved_assumptions", "UBSan",
        "evidence chain", "falsify the hypothesis", "suspicious code",
    ):
        assert marker in bundle.text
    assert bundle.sha256 == hashlib.sha256(bundle.text.encode()).hexdigest()


def test_selection_is_canonical_and_supports_multiple_mechanisms():
    first = knowledge.build_specialist_prompt(
        profile="structured", mechanism_ids=("bounds", "lifetime", "bounds"),
    )
    second = knowledge.build_specialist_prompt(
        profile="structured", mechanism_ids=("lifetime", "bounds"),
    )
    assert first == second
    assert "integer" not in first.knowledge_ids
    assert "lifetime" in first.knowledge_ids


@pytest.mark.parametrize("kwargs", [
    {"profile": "unknown"},
    {"profile": "structured", "mechanism_ids": ("unknown",)},
    {"profile": "structured", "component_id": "unknown"},
    {"profile": "legacy", "component_id": "expat"},
    {"profile": "legacy", "mechanism_ids": ("bounds",)},
])
def test_unknown_or_ignored_selections_are_rejected(kwargs):
    with pytest.raises(ValueError):
        knowledge.build_specialist_prompt(**kwargs)


def test_component_recipe_requires_explicit_selection():
    bundle = knowledge.build_specialist_prompt(profile="structured", component_id="expat")
    assert "known-vulnerability reproduction" in bundle.text
    assert "XML_ExternalEntityParserCreate" in bundle.text
    assert "avrcp" not in bundle.text
    assert "component:expat" in bundle.knowledge_ids


def test_future_pack_addenda_never_auto_load_into_generic_structured(monkeypatch):
    from dataclasses import replace

    from lima.vuln_packs import get_pack

    fake = replace(
        get_pack("memory"),
        name="fake",
        specialist_prompt_addendum="FAKE-PACK-ADDENDUM-MARKER",
    )
    monkeypatch.setattr("lima.vuln_packs.get_pack", lambda name: fake)
    monkeypatch.setattr("lima.vuln_packs.list_packs", lambda: ("memory", "fake"))
    bundle = knowledge.build_specialist_prompt(profile="structured")
    assert "FAKE-PACK-ADDENDUM-MARKER" not in bundle.text
    legacy = knowledge.build_specialist_prompt(profile="legacy")
    assert "FAKE-PACK-ADDENDUM-MARKER" in legacy.text


def test_prompt_content_change_invalidates_cache(monkeypatch):
    base = knowledge.build_specialist_prompt(profile="structured")
    target = ScoutTarget("target", "src/target.cpp", 1, "inspect source", "high")
    kwargs = dict(repository_key="repo", snapshot_hash="a" * 64,
                  mode="auto", source_mode="repository", dialogue_rounds=1)
    key = _target_cache_fingerprints(target, specialist_prompt=base, **kwargs)
    monkeypatch.setitem(knowledge.MECHANISM_CARDS, "bounds",
                        knowledge.MECHANISM_CARDS["bounds"] + " Changed evidence requirement.")
    changed = knowledge.build_specialist_prompt(profile="structured")
    assert key != _target_cache_fingerprints(target, specialist_prompt=changed, **kwargs)
    with pytest.raises(ValueError):
        replace(base, sha256="0" * 64)
