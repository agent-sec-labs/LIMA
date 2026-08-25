"""Versioned, replay-gated evolution for executable review skills.

The evolved artifact is deliberately declarative.  Feedback may change matching
behaviour, but it cannot inject Python or acquire host permissions.  Every
candidate is replayed against validation and holdout datasets before activation.
"""
import hashlib
import json
import re
import threading
import uuid
from typing import Any, Callable, Dict, List, Optional

from .diff_parser import parse_unified_diff
from .evolution import RegressionEvaluator
from .models import Finding, Severity
from .reviewer import Reviewer
from .store import utc_now


ARTIFACT_SCHEMA_VERSION = 1
RULE_ID = re.compile(r"[A-Z][A-Z0-9_-]{1,79}")
SKILL_NAME = re.compile(r"evolved-[a-z0-9][a-z0-9_-]{0,72}")


def _canonical_json(value: dict) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _sha256(value: dict) -> str:
    return hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()


def validate_artifact(artifact: dict, expected_name: str = "") -> dict:
    """Validate and normalize an untrusted declarative skill artifact."""
    if not isinstance(artifact, dict):
        raise ValueError("skill artifact must be an object")
    name = str(artifact.get("name", expected_name)).strip().lower()
    if expected_name and name != expected_name:
        raise ValueError("skill artifact name must match skill_name")
    if not SKILL_NAME.fullmatch(name):
        raise ValueError("evolved skill names must start with 'evolved-'")
    raw_rules = artifact.get("rules", [])
    if not isinstance(raw_rules, list) or len(raw_rules) > 100:
        raise ValueError("skill artifact rules must be a list with at most 100 items")

    rules = []
    identities = set()
    for raw in raw_rules:
        if not isinstance(raw, dict):
            raise ValueError("each evolved skill rule must be an object")
        rule_id = str(raw.get("rule_id", "")).strip().upper()
        if not RULE_ID.fullmatch(rule_id):
            raise ValueError("invalid evolved skill rule_id: %s" % rule_id)
        try:
            severity = Severity(str(raw.get("severity", "medium")).lower()).value
        except ValueError as exc:
            raise ValueError("invalid severity for rule %s" % rule_id) from exc
        match = str(raw.get("match", "")).strip()
        if not match or len(match) > 240 or "\n" in match or "\r" in match:
            raise ValueError("rule %s match must be a single non-empty line" % rule_id)
        identity = (rule_id, match, bool(raw.get("ignore_case", False)))
        if identity in identities:
            raise ValueError("duplicate evolved skill rule: %s" % rule_id)
        identities.add(identity)
        confidence = float(raw.get("confidence", .85))
        if not 0.0 <= confidence <= 1.0:
            raise ValueError("rule confidence must be between 0 and 1")
        include_paths = raw.get("include_paths", [])
        exclude_paths = raw.get("exclude_paths", ["tests/"])
        if not isinstance(include_paths, list) or not isinstance(exclude_paths, list):
            raise ValueError("rule path filters must be lists")
        if any(not isinstance(item, str) or len(item) > 200 for item in include_paths + exclude_paths):
            raise ValueError("invalid rule path filter")
        rules.append({
            "rule_id": rule_id,
            "severity": severity,
            "match": match,
            "ignore_case": bool(raw.get("ignore_case", False)),
            "include_paths": include_paths,
            "exclude_paths": exclude_paths,
            "title": str(raw.get("title") or ("Confirmed %s finding" % rule_id))[:200],
            "explanation": str(raw.get("explanation") or "A confirmed feedback pattern was found on an added line.")[:2000],
            "fix": str(raw.get("fix") or "Replace the unsafe construct with a constrained alternative.")[:2000],
            "test": str(raw.get("test") or "Add a regression test covering the confirmed failure mode.")[:2000],
            "confidence": round(confidence, 4),
        })
    rules.sort(key=lambda item: (item["rule_id"], item["match"]))
    return {
        "schema_version": ARTIFACT_SCHEMA_VERSION,
        "name": name,
        "description": str(artifact.get("description") or "Replay-gated rules learned from confirmed review feedback")[:500],
        "permissions": [],
        "rules": rules,
    }


class DeclarativeSkillReviewer(Reviewer):
    """Execute a validated evolved artifact without eval, imports or subprocesses."""

    def __init__(self, artifact: dict, version: Optional[int] = None):
        self.artifact = validate_artifact(artifact, str(artifact.get("name", "")))
        self.version = version
        self.name = self.artifact["name"] + ("@%s" % version if version is not None else "")

    def review(self, diff: str, parsed) -> List[Finding]:
        findings = []
        seen = set()
        for line in parsed.added_lines:
            for rule in self.artifact["rules"]:
                if rule["include_paths"] and not any(line.path.startswith(p) for p in rule["include_paths"]):
                    continue
                if any(line.path.startswith(p) for p in rule["exclude_paths"]):
                    continue
                content = line.content.lower() if rule["ignore_case"] else line.content
                needle = rule["match"].lower() if rule["ignore_case"] else rule["match"]
                key = (rule["rule_id"], line.path, line.line)
                if needle not in content or key in seen:
                    continue
                seen.add(key)
                findings.append(Finding(
                    rule_id=rule["rule_id"], severity=Severity(rule["severity"]),
                    title=rule["title"], explanation=rule["explanation"],
                    path=line.path, line=line.line, evidence=line.content.strip()[:240],
                    fix=rule["fix"], test=rule["test"], confidence=rule["confidence"],
                ))
        return findings


class SkillEvolutionEngine:
    """Create, replay, activate and roll back declarative skill versions."""

    def __init__(
        self, store, reviewer_factory: Optional[Callable[[dict], Reviewer]] = None,
        min_cases: int = 3, max_cases: int = 100, min_improvement: float = .01,
        min_holdout_cases: int = 2, max_metric_regression: float = 0.0,
    ):
        self.store = store
        self.reviewer_factory = reviewer_factory or (lambda artifact: DeclarativeSkillReviewer(artifact))
        self.min_cases = min_cases
        self.max_cases = max_cases
        self.min_improvement = min_improvement
        self.min_holdout_cases = min_holdout_cases
        self.max_metric_regression = max_metric_regression
        self._lock = threading.RLock()

    @staticmethod
    def empty_artifact(skill_name: str) -> dict:
        return validate_artifact({"name": skill_name, "rules": []}, skill_name)

    def _factory(self, serialized: str) -> Reviewer:
        return self.reviewer_factory(json.loads(serialized))

    @staticmethod
    def _redact_holdout(metrics: Dict[str, Any]) -> Dict[str, Any]:
        return {key: value for key, value in metrics.items() if key not in {"case_results", "errors"}}

    def _non_regressing(self, candidate: dict, baseline: dict) -> bool:
        protected = ["score", "precision", "recall", "high_severity_recall", "success_rate"]
        if baseline.get("positive_cases", 0):
            protected.append("severity_accuracy")
        if baseline.get("clean_cases", 0):
            protected.append("clean_accuracy")
        return all(
            float(candidate.get(name, 0)) + self.max_metric_regression
            >= float(baseline.get(name, 0)) for name in protected
        )

    def status(
        self, skill_name: str = "evolved-review", tenant_id: str = "default",
    ) -> Dict[str, Any]:
        validation = self.store.list_evaluation_cases("validation", True, self.max_cases)
        holdout = self.store.list_evaluation_cases("holdout", True, self.max_cases)
        active = self.store.get_active_skill_artifact(skill_name, tenant_id)
        return {
            "tenant_id": tenant_id, "skill_name": skill_name,
            "active_version": active.get("version") if active else None,
            "active_artifact_sha256": active.get("artifact_sha256") if active else None,
            "validation_cases": len(validation), "holdout_cases": len(holdout),
            "minimum_cases": self.min_cases, "minimum_holdout_cases": self.min_holdout_cases,
            "minimum_improvement": self.min_improvement,
            "maximum_metric_regression": self.max_metric_regression,
            "ready": len(validation) >= self.min_cases and len(holdout) >= self.min_holdout_cases,
        }

    def propose(
        self, skill_name: str, artifact: dict, tenant_id: str = "default",
    ) -> Dict[str, Any]:
        skill_name = skill_name.strip().lower()
        candidate_artifact = validate_artifact(artifact, skill_name)
        with self._lock:
            return self._propose(skill_name, candidate_artifact, tenant_id)

    def _propose(self, skill_name: str, artifact: dict, tenant_id: str) -> Dict[str, Any]:
        active = self.store.get_active_skill_artifact(skill_name, tenant_id)
        if active and active["artifact_sha256"] == _sha256(artifact):
            return {
                "version": self._public_version(active), "decision": "deferred",
                "reason": "candidate skill artifact is identical to the active version",
                "candidate": {}, "baseline": {}, "candidate_holdout": {},
                "baseline_holdout": {}, "gates": {}, "run_id": None,
            }
        baseline_artifact = active["artifact"] if active else self.empty_artifact(skill_name)
        validation = self.store.list_evaluation_cases("validation", True, self.max_cases)
        holdout = self.store.list_evaluation_cases("holdout", True, self.max_cases)
        decision = "deferred"
        reason = ""
        gates = {
            "artifact_valid": True,
            "validation_dataset_ready": len(validation) >= self.min_cases,
            "holdout_dataset_ready": len(holdout) >= self.min_holdout_cases,
            "evaluation_success": None, "validation_improvement": None,
            "validation_non_regression": None, "holdout_non_regression": None,
        }
        evaluator = RegressionEvaluator(self._factory)
        baseline_metrics = self._empty_metrics(len(validation))
        candidate_metrics = self._empty_metrics(len(validation))
        baseline_holdout = self._empty_metrics(len(holdout))
        candidate_holdout = self._empty_metrics(len(holdout))
        if len(validation) < self.min_cases:
            reason = "candidate saved but the validation dataset is smaller than the activation minimum"
        elif len(holdout) < self.min_holdout_cases:
            reason = "candidate saved but the holdout dataset is smaller than the activation minimum"
        else:
            baseline_metrics = evaluator.run(_canonical_json(baseline_artifact), validation)
            candidate_metrics = evaluator.run(_canonical_json(artifact), validation)
            baseline_holdout = evaluator.run(_canonical_json(baseline_artifact), holdout)
            candidate_holdout = evaluator.run(_canonical_json(artifact), holdout)
            no_errors = not (
                baseline_metrics["errors"] or candidate_metrics["errors"]
                or baseline_holdout["errors"] or candidate_holdout["errors"]
            )
            improved = candidate_metrics["score"] >= baseline_metrics["score"] + self.min_improvement
            validation_safe = self._non_regressing(candidate_metrics, baseline_metrics)
            holdout_safe = self._non_regressing(candidate_holdout, baseline_holdout)
            gates.update({
                "evaluation_success": no_errors, "validation_improvement": improved,
                "validation_non_regression": validation_safe,
                "holdout_non_regression": holdout_safe,
            })
            if no_errors and improved and validation_safe and holdout_safe:
                decision = "activated"
                reason = "candidate skill improved validation and passed holdout non-regression"
            else:
                decision = "rejected"
                failures = []
                if not no_errors:
                    failures.append("evaluation failed")
                if not improved:
                    failures.append("validation improvement was below threshold")
                if not validation_safe:
                    failures.append("a protected validation metric regressed")
                if not holdout_safe:
                    failures.append("a protected holdout metric regressed")
                reason = "; ".join(failures)

        version = self.store.save_skill_artifact(
            skill_name, artifact, candidate_metrics.get("score", 0.0),
            decision == "activated", tenant_id,
        )
        run = {
            "id": str(uuid.uuid4()), "tenant_id": tenant_id, "skill_name": skill_name,
            "candidate_version": version["version"],
            "baseline_version": active.get("version") if active else None,
            "decision": decision, "candidate_score": candidate_metrics.get("score", 0.0),
            "baseline_score": baseline_metrics.get("score", 0.0),
            "metrics": {
                "candidate": candidate_metrics, "baseline": baseline_metrics,
                "candidate_holdout": self._redact_holdout(candidate_holdout),
                "baseline_holdout": self._redact_holdout(baseline_holdout),
                "gates": gates, "reason": reason,
                "reproducibility": {
                    "artifact_schema_version": ARTIFACT_SCHEMA_VERSION,
                    "candidate_artifact_sha256": version["artifact_sha256"],
                    "baseline_artifact_sha256": active.get("artifact_sha256") if active else _sha256(baseline_artifact),
                },
            }, "created_at": utc_now(),
        }
        self.store.save_skill_evolution_run(run)
        return {
            "version": version, "decision": decision, "reason": reason,
            "candidate": candidate_metrics, "baseline": baseline_metrics,
            "candidate_holdout": self._redact_holdout(candidate_holdout),
            "baseline_holdout": self._redact_holdout(baseline_holdout),
            "gates": gates, "run_id": run["id"],
        }

    def auto_propose(self, skill_name: str = "evolved-review", tenant_id: Optional[str] = None) -> Dict[str, Any]:
        skill_name = skill_name.strip().lower()
        if not SKILL_NAME.fullmatch(skill_name):
            raise ValueError("evolved skill names must start with 'evolved-'")
        failures = self.store.list_failure_cases(True, 100, tenant_id)
        tenant_id = tenant_id or "default"
        active = self.store.get_active_skill_artifact(skill_name, tenant_id)
        artifact = dict(active["artifact"]) if active else self.empty_artifact(skill_name)
        rules = [dict(item) for item in artifact["rules"]]
        used_ids = []
        learned = []
        removed = []
        for case in failures:
            finding = (case.get("payload") or {}).get("finding") or {}
            rule_id = str(finding.get("rule_id", "")).strip().upper()
            if not RULE_ID.fullmatch(rule_id):
                continue
            if case.get("category") == "false_positive":
                before = len(rules)
                rules = [rule for rule in rules if rule["rule_id"] != rule_id]
                if len(rules) != before:
                    removed.append(rule_id)
                    used_ids.append(case["id"])
                continue
            if case.get("category") != "missed_issue":
                continue
            evidence = str(finding.get("evidence", "")).strip()
            if not evidence:
                evidence = self._evidence_from_task(case["task_id"], finding)
            if not evidence or len(evidence) > 240 or "\n" in evidence or "\r" in evidence:
                continue
            raw_rule = {
                "rule_id": rule_id, "severity": finding.get("severity", "medium"),
                "match": evidence, "ignore_case": False,
                "include_paths": [], "exclude_paths": ["tests/"],
                "title": finding.get("title"), "explanation": finding.get("explanation"),
                "fix": finding.get("fix"), "test": finding.get("test"),
                "confidence": finding.get("confidence", .85),
            }
            normalized = validate_artifact({"name": skill_name, "rules": [raw_rule]}, skill_name)["rules"][0]
            if not any(
                rule["rule_id"] == normalized["rule_id"] and rule["match"] == normalized["match"]
                for rule in rules
            ):
                rules.append(normalized)
                learned.append(rule_id)
                used_ids.append(case["id"])
        candidate = validate_artifact({**artifact, "name": skill_name, "rules": rules}, skill_name)
        if not used_ids:
            return {
                "version": None, "decision": "deferred",
                "reason": "no supported skill mutation signal was found in unresolved feedback",
                "failure_cases_used": len(failures), "learned_rule_ids": [],
                "removed_rule_ids": [], "run_id": None,
            }
        result = self.propose(skill_name, candidate, tenant_id)
        result.update({
            "failure_cases_used": len(used_ids),
            "learned_rule_ids": sorted(set(learned)),
            "removed_rule_ids": sorted(set(removed)),
        })
        if result["decision"] == "activated":
            self.store.resolve_failure_cases(used_ids)
        return result

    def _evidence_from_task(self, task_id: str, finding: dict) -> str:
        diff = self.store.get_task_payload(task_id)
        if not diff:
            return ""
        try:
            path = str(finding.get("path", ""))
            line = int(finding.get("line", 0))
            for changed in parse_unified_diff(diff).added_lines:
                if changed.path == path and changed.line == line:
                    return changed.content.strip()
        except (TypeError, ValueError):
            return ""
        return ""

    def rollback(
        self, skill_name: str, version: int, tenant_id: str = "default",
    ) -> bool:
        return self.store.activate_skill_artifact(skill_name, version, tenant_id)

    @staticmethod
    def _empty_metrics(cases: int) -> Dict[str, Any]:
        return {
            "schema_version": 2, "reviewer": "", "score": 0.0,
            "precision": 0.0, "recall": 0.0, "f1": 0.0,
            "severity_accuracy": 0.0, "high_severity_recall": 0.0,
            "clean_accuracy": 0.0, "cases": cases, "positive_cases": 0,
            "clean_cases": 0, "expected_findings": 0, "predicted_findings": 0,
            "successful_cases": 0, "success_rate": 0.0, "errors": [],
            "case_results": [],
        }

    @staticmethod
    def _public_version(value: dict) -> dict:
        return {
            key: value[key] for key in (
                "tenant_id", "skill_name", "version", "score", "active", "parent_version",
                "artifact_sha256", "created_at",
            ) if key in value
        }
