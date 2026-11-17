import json


def test_trace_projection_scrubs_free_text_and_preserves_evidence_ids():
    from lima.cxx_investigation_reporting import investigation_summary
    trace = {"strategy": "team", "stop_reason": "final", "actions": [
        {"tool": "read_source", "purpose": "check ownership"}],
        "evidence": {"e1": {"text": "password = 'super-secret-value'"}}}
    summary = investigation_summary(trace)
    assert "super-secret-value" not in json.dumps(summary)
    assert "e1" in summary["evidence"]
    assert summary["actions"][0]["tool"] == "read_source"


def test_oversized_trace_reports_omission_with_counts():
    from lima.cxx_investigation_reporting import investigation_summary
    trace = {"strategy": "team", "stop_reason": "budget-exhausted",
             "actions": [{"purpose": "inspect buffer lifetime"}] * 100,
             "children": [{"role": "ownership"}]}
    summary = investigation_summary(trace, byte_limit=500)
    assert summary["action_count"] == 100
    assert summary["child_count"] == 1
    assert summary["detail_omissions"] == ["investigation:byte-budget"]
    assert len(json.dumps(summary).encode()) <= 500
