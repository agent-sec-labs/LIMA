"""Reproducible constraint evaluation for deterministic security repairs."""

from __future__ import annotations

import hashlib
import json
import math
import statistics
import time
from collections import Counter
from pathlib import Path

from .fixer import SafeFixer


SUPPORTED_CWES = frozenset({"CWE-22", "CWE-78", "CWE-89"})


def _ratio(numerator: int, denominator: int) -> float:
    return round(numerator / denominator, 4) if denominator else 0.0


def load_repair_dataset(path: str | Path) -> dict:
    source = Path(path)
    payload = json.loads(source.read_text(encoding="utf-8"))
    if payload.get("schema_version") != 1 or not isinstance(payload.get("cases"), list):
        raise ValueError("repair dataset must use schema_version 1 and contain cases")
    seen = set()
    for case in payload["cases"]:
        case_id = str(case.get("id", ""))
        cwe = str(case.get("cwe", "")).upper()
        expected = case.get("expected") or {}
        finding = case.get("finding") or {}
        if not case_id or case_id in seen:
            raise ValueError("repair case ids must be non-empty and unique")
        seen.add(case_id)
        if cwe not in SUPPORTED_CWES:
            raise ValueError("repair case %s has unsupported CWE" % case_id)
        if expected.get("decision") not in {"repair", "abstain"}:
            raise ValueError("repair case %s has an invalid expected decision" % case_id)
        if not isinstance(case.get("source"), str) or not case["source"]:
            raise ValueError("repair case %s is missing source" % case_id)
        if not finding.get("path") or int(finding.get("line", 0)) < 1:
            raise ValueError("repair case %s has an invalid finding location" % case_id)
        compile(case["source"], str(finding["path"]), "exec")
    return payload


class RepairConstraintEvaluator:
    """Measure verified repairs and correct abstentions on fixed repair inputs."""

    def __init__(self, fixer: SafeFixer | None = None) -> None:
        self.fixer = fixer or SafeFixer()

    def run(self, dataset: dict) -> dict:
        canonical = json.dumps(
            dataset["cases"], ensure_ascii=False, sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        results = []
        latencies = []
        failure_categories = Counter()
        by_cwe = {}
        generated = 0
        oracle_passed = 0
        correct_repairs = 0
        correct_abstentions = 0
        unsafe_patch_escapes = 0

        for case in dataset["cases"]:
            started = time.perf_counter()
            finding = {
                **case["finding"],
                "cwe": case["cwe"],
                "verification_state": case["finding"].get(
                    "verification_state", "dataflow-verified"
                ),
            }
            result = self.fixer.apply(
                case["source"], [finding], str(finding["path"])
            )
            verification = (
                self.fixer.verifier.verify_contents(
                    {str(finding["path"]): result["content"]},
                    result.get("repairs", []),
                )
                if result.get("rules") else {"passed": False, "checks": []}
            )
            latency_ms = round((time.perf_counter() - started) * 1000, 3)
            latencies.append(latency_ms)
            patched = bool(result.get("rules"))
            generated += int(patched)
            oracle_passed += int(patched and verification["passed"])
            expected = case["expected"]
            actual_strategy = (
                result.get("repairs", [{}])[0].get("strategy", "")
                if result.get("repairs") else ""
            )
            blocked_reason = (
                result.get("blocked", [{}])[0].get("reason", "")
                if result.get("blocked") else ""
            )
            category = ""
            if expected["decision"] == "repair":
                passed = patched and verification["passed"] and (
                    not expected.get("strategy")
                    or actual_strategy == expected["strategy"]
                )
                correct_repairs += int(passed)
                if not patched:
                    category = "repair-not-generated"
                elif not verification["passed"]:
                    category = "security-oracle-failed"
                elif actual_strategy != expected.get("strategy"):
                    category = "strategy-mismatch"
            else:
                passed = not patched and (
                    not expected.get("reason")
                    or blocked_reason == expected["reason"]
                )
                correct_abstentions += int(passed)
                unsafe_patch_escapes += int(patched)
                if patched:
                    category = "unsafe-patch-escaped"
                elif blocked_reason != expected.get("reason"):
                    category = "wrong-abstention-reason"
            if category:
                failure_categories[category] += 1
            cwe_stats = by_cwe.setdefault(case["cwe"], {
                "cases": 0, "passed": 0, "repair_cases": 0,
                "abstain_cases": 0,
            })
            cwe_stats["cases"] += 1
            cwe_stats["passed"] += int(passed)
            cwe_stats[expected["decision"] + "_cases"] += 1
            results.append({
                "id": case["id"],
                "cwe": case["cwe"],
                "expected": expected["decision"],
                "actual": "repair" if patched else "abstain",
                "strategy": actual_strategy,
                "blocked_reason": blocked_reason,
                "oracle_passed": bool(patched and verification["passed"]),
                "passed": passed,
                "failure_category": category,
                "changed_lines": int(
                    result.get("patch_metrics", {}).get("changed_lines", 0)
                ),
                "latency_ms": latency_ms,
            })

        repair_cases = sum(
            item["expected"]["decision"] == "repair" for item in dataset["cases"]
        )
        abstain_cases = len(dataset["cases"]) - repair_cases
        for values in by_cwe.values():
            values["constraint_accuracy"] = _ratio(values["passed"], values["cases"])
        ordered = sorted(latencies)
        p95_index = max(0, min(len(ordered) - 1, math.ceil(len(ordered) * 0.95) - 1))
        return {
            "schema_version": 1,
            "dataset": dataset.get("name", "unnamed"),
            "dataset_sha256": hashlib.sha256(canonical).hexdigest(),
            "scope": "conditional-on-verified-finding",
            "metrics": {
                "cases": len(results),
                "repair_cases": repair_cases,
                "abstain_cases": abstain_cases,
                "generated_patches": generated,
                "verified_repair_rate": _ratio(correct_repairs, repair_cases),
                "correct_abstention_rate": _ratio(correct_abstentions, abstain_cases),
                "constraint_accuracy": _ratio(
                    correct_repairs + correct_abstentions, len(results)
                ),
                "oracle_pass_rate": _ratio(oracle_passed, generated),
                "unsafe_patch_escape_rate": _ratio(
                    unsafe_patch_escapes, abstain_cases
                ),
                "latency_ms_mean": round(statistics.fmean(latencies), 3),
                "latency_ms_p95": ordered[p95_index],
            },
            "by_cwe": dict(sorted(by_cwe.items())),
            "failure_categories": dict(sorted(failure_categories.items())),
            "cases": results,
            "limitations": [
                "Synthetic-controlled cases evaluate repair constraints after a finding is verified.",
                "They do not measure end-to-end vulnerability detection recall or real-project patch correctness.",
            ],
        }
