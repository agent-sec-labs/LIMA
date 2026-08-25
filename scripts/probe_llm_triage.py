"""Run one sanitized provider-compatibility and JSON-contract probe."""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from lima.config import Settings
from lima.real_world_evaluation import LLMSecurityTriageClient, LLMTriageError
from lima.semantic_retrieval import SecurityInvariant, SemanticCandidate


def main() -> int:
    resolved = Settings.from_env().resolved_llm()
    if not resolved:
        raise ValueError("LLM mode is not configured")
    client = LLMSecurityTriageClient(
        base_url=str(resolved["base_url"]),
        api_key=str(resolved["api_key"]),
        model=str(resolved["model"]),
        provider=str(resolved["provider"]),
        extra_headers=dict(resolved.get("headers") or {}),
    )
    candidate = SemanticCandidate(
        path="probe/safe_query.py",
        qualname="UserRepository.find_by_id",
        start_line=1,
        end_line=3,
        category="sql",
        score=20,
        signals=("sql", "parameter"),
        code=(
            "def find_by_id(cursor, user_id):\n"
            "    cursor.execute('SELECT name FROM users WHERE id = %s', [user_id])\n"
            "    return cursor.fetchone()\n"
        ),
        invariants=(SecurityInvariant(
            identifier="sql-parameter-boundary",
            category="sql",
            status="mitigation",
            summary="The value is supplied through the database parameter channel.",
        ),),
    )
    try:
        result = client.triage_candidates([candidate])
    except LLMTriageError as exc:
        print(json.dumps({
            "status": "failed",
            "error": str(exc),
            "usage": exc.usage,
            "latency_ms": exc.latency_ms,
            "finish_reason": exc.finish_reason,
        }, ensure_ascii=False, indent=2))
        return 1
    passed = (
        result["status"] == "completed"
        and result["contract_valid"]
        and result["is_vulnerable"] is False
    )
    print(json.dumps({
        "status": result["status"],
        "passed": passed,
        "provider": result["provider"],
        "model": result["model"],
        "contract_valid": result["contract_valid"],
        "contract_errors": result["contract_errors"],
        "is_vulnerable": result["is_vulnerable"],
        "usage": result["usage"],
        "latency_ms": result["latency_ms"],
        "prompt_sha256": result["prompt_sha256"],
    }, ensure_ascii=False, indent=2))
    return 0 if passed else 2


if __name__ == "__main__":
    raise SystemExit(main())
