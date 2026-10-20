"""Pilot validity boundaries, independent of external services."""
import json
from pathlib import Path

import pytest

from scripts import run_specialist_prompt_pilot as pilot


def test_prepare_freezes_pairs_and_neutral_model_inputs(tmp_path):
    manifest = pilot.prepare_snapshots(tmp_path)
    assert len(manifest["cases"]) == 6
    assert sum(c["partition"] == "holdout" for c in manifest["cases"]) >= 2
    for case in manifest["cases"]:
        for revision in ("vulnerable", "fixed"):
            item = case[revision]
            context = pilot.target_context(pilot._repo_dir(tmp_path, item["repository_key"]))
            assert case["id"] not in context
            assert "vulnerable" not in context and "fixed" not in context
            assert "expected_cwe" not in context
            assert pilot._repo_dir(tmp_path, item["repository_key"]).joinpath("src/target.cpp").is_file()
            assert len(item["snapshot_hash"]) == 64
    assert pilot.prepare_snapshots(tmp_path) == manifest
    source = pilot._repo_dir(
        tmp_path, manifest["cases"][0]["vulnerable"]["repository_key"]
    ) / "src/target.cpp"
    source.write_text("tampered", encoding="utf-8")
    with pytest.raises(ValueError, match="changed"):
        pilot.verify_snapshots(tmp_path, manifest)


def test_stale_snapshot_manifest_without_mount_prefix_is_rejected(tmp_path):
    manifest = pilot.prepare_snapshots(tmp_path)
    for case in manifest["cases"]:
        for revision in ("vulnerable", "fixed"):
            item = case[revision]
            item["repository_key"] = Path(item["repository_key"]).name
    (tmp_path / "manifest.json").write_text(
        json.dumps(manifest), encoding="utf-8",
    )
    with pytest.raises(ValueError, match="snapshot root prefix"):
        pilot.prepare_snapshots(tmp_path)


def test_schedule_is_paired_and_interleaved():
    manifest = {"cases": [{"id": "a", "partition": "development"},
                          {"id": "b", "partition": "holdout"}]}
    schedule = pilot.build_schedule(manifest, repeats=3, partition="all")
    assert len(schedule) == 24
    for first, second in zip(schedule[::2], schedule[1::2]):
        assert first[:3] == second[:3]
        assert {first[3], second[3]} == {"legacy", "structured"}
    assert len(pilot.build_schedule(manifest, repeats=3, partition="development")) == 12


def test_fixed_crash_and_compile_failure_do_not_count_as_discrimination():
    hit = {"stage": "run", "ok": False, "error_type": "heap-use-after-free",
           "faulting_file": "src/target.cpp"}
    clean = {"stage": "run", "ok": True, "exit_code": 0}
    assert pilot.replay_discriminates([hit] * 3, [clean] * 3, "CWE-416")
    assert not pilot.replay_discriminates([hit] * 3, [hit] * 3, "CWE-416")
    assert not pilot.replay_discriminates([hit] * 3, [{"stage": "compile", "ok": False}] * 3, "CWE-416")
    assert not pilot.replay_discriminates([hit] * 2, [clean] * 2, "CWE-416")


def test_model_failures_remain_in_denominator_and_manual_review_is_required():
    records = [
        {"profile": "legacy", "revision": "vulnerable", "status": "error"},
        {"profile": "legacy", "revision": "vulnerable", "status": "completed",
         "state": "runtime-confirmed", "manual_validity": "pending",
         "replay_discriminates": True},
        {"profile": "legacy", "revision": "fixed", "status": "completed",
         "state": "semantic-supported"},
    ]
    summary = pilot.summarize(records)["legacy"]
    assert summary["positive_attempts"] == 2
    assert summary["errors"] == 1
    assert summary["negative_findings"] == 1
    assert summary["reviewed_valid_discriminations"] == 0
    assert summary["pending_manual_review"] == 1


def test_existing_run_identity_cannot_be_reused_with_different_model(tmp_path):
    pilot.freeze_identity(tmp_path, {"model": "one"})
    pilot.freeze_identity(tmp_path, {"model": "one"})
    with pytest.raises(ValueError, match="identity"):
        pilot.freeze_identity(tmp_path, {"model": "two"})


def test_source_pair_manifest_is_serializable(tmp_path):
    manifest = pilot.prepare_snapshots(tmp_path)
    assert json.loads(json.dumps(manifest)) == manifest


def test_summarize_paired_removes_excluded_case_from_both_sides_and_denominators():
    def record(case, revision, state, disc=None):
        return {"case_id": case, "revision": revision, "profile": "legacy",
                "status": "completed", "state": state, "replay_discriminates": disc,
                "manual_validity": "pending"}

    records = [
        record("good", "vulnerable", "runtime-confirmed", True),
        record("good", "fixed", "abstain"),
        record("bad", "vulnerable", "runtime-confirmed", True),
        record("bad", "fixed", "runtime-confirmed"),
    ]
    paired = pilot.summarize_paired(
        records, {"bad": "fixed revision is a contaminated control"}
    )
    assert paired["records_total"] == 4 and paired["records_used"] == 2
    assert paired["excluded_cases"] == {"bad": "fixed revision is a contaminated control"}
    legacy = paired["profiles"]["legacy"]
    assert legacy["positive_attempts"] == 1 and legacy["negative_attempts"] == 1
    assert legacy["runtime_confirmed"] == 1 and legacy["raw_discriminations"] == 1
    assert legacy["negative_findings"] == 0


def test_exclusion_arguments_parse_id_and_reason():
    assert pilot.parse_exclusions(["a", "b=why", "c = padded "]) == {
        "a": "operator-excluded", "b": "why", "c": "padded",
    }
    with pytest.raises(ValueError):
        pilot.parse_exclusions(["=missing-id"])
