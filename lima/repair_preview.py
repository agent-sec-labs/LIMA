"""Read-only repair previews for authorized repository snapshots."""

from __future__ import annotations

import difflib
import hashlib
import time

from .fixer import SafeFixer
from .workspace import RepositoryWorkspace


PREVIEW_CWES = frozenset({"CWE-22", "CWE-78", "CWE-89"})
MAX_PREVIEW_DIFF_BYTES = 1024 * 1024


class RepositoryRepairPreviewer:
    """Plan and statically verify patches without changing the source repository."""

    def __init__(self, fixer: SafeFixer | None = None) -> None:
        self.fixer = fixer or SafeFixer()

    def preview(
        self, workspace: RepositoryWorkspace, report: dict,
        expected_fingerprint: str = "",
    ) -> dict:
        started = time.monotonic()
        inventory = workspace.inventory()
        fingerprint = inventory.fingerprint()
        if inventory.truncated:
            raise ValueError("repair preview requires a complete bounded repository snapshot")
        if expected_fingerprint and fingerprint != expected_fingerprint:
            raise ValueError("repository changed after scanning; run a new scan before previewing repairs")

        snapshot = dict(workspace.iter_text(inventory))
        python_before = {
            path: content for path, content in snapshot.items() if path.endswith(".py")
        }
        findings = [
            item for item in report.get("findings", [])
            if str(item.get("cwe", "")).upper() in PREVIEW_CWES
        ]
        by_path = {}
        for item in findings:
            by_path.setdefault(str(item.get("path", "")), []).append(item)

        changed = {}
        repairs = []
        blocked = []
        rules = set()
        changed_lines = 0
        strategies = set()
        for path, scoped in sorted(by_path.items()):
            content = snapshot.get(path)
            if content is None:
                blocked.extend({
                    "path": path,
                    "line": int(item.get("line", 0)),
                    "rule_id": str(item.get("rule_id", "")),
                    "cwe": str(item.get("cwe", "")),
                    "reason": "finding-file-not-in-snapshot",
                } for item in scoped)
                continue
            result = self.fixer.apply(content, scoped, path)
            blocked.extend({"path": path, **item} for item in result.get("blocked", []))
            if not result.get("rules"):
                continue
            changed[path] = result["content"]
            repairs.extend(result.get("repairs", []))
            rules.update(result["rules"])
            metrics = result.get("patch_metrics", {})
            changed_lines += int(metrics.get("changed_lines", 0))
            strategies.update(metrics.get("strategies", []))

        if not changed:
            return {
                "status": "no-repair",
                "snapshot_sha256": fingerprint,
                "files_changed": 0,
                "patches": [],
                "repair_manifest": [],
                "blocked_findings": blocked,
                "verification": {"passed": False, "checks": []},
                "publication_ready": False,
                "note": "No finding satisfied all deterministic repair constraints.",
                "duration_seconds": round(time.monotonic() - started, 4),
            }

        content_result = self.fixer.verifier.verify_contents(changed, repairs)
        python_after = dict(python_before)
        python_after.update({
            path: content for path, content in changed.items() if path.endswith(".py")
        })
        differential = (
            self.fixer.verifier.verify_differential(python_before, python_after, repairs)
            if content_result["passed"] else {"passed": False, "checks": []}
        )
        checks = content_result["checks"] + differential["checks"]
        passed = bool(checks) and all(item["passed"] for item in checks)
        patches = []
        total_diff_bytes = 0
        for path, content in sorted(changed.items()):
            patch = "\n".join(difflib.unified_diff(
                snapshot[path].splitlines(), content.splitlines(),
                fromfile="a/" + path, tofile="b/" + path, lineterm="",
            )) + "\n"
            total_diff_bytes += len(patch.encode("utf-8"))
            patches.append({"path": path, "diff": patch})
        if total_diff_bytes > MAX_PREVIEW_DIFF_BYTES:
            raise ValueError("generated repair preview exceeds the response size limit")

        return {
            "status": "verified-preview" if passed else "blocked",
            "snapshot_sha256": fingerprint,
            "files_changed": len(changed),
            "changed_lines": changed_lines,
            "rules": sorted(rules),
            "strategies": sorted(strategies),
            "patches": patches,
            "repair_manifest": [self._public_manifest(item) for item in repairs],
            "blocked_findings": blocked,
            "verification": {"passed": passed, "checks": checks},
            "publication_ready": False,
            "note": (
                "Static repair preview verified. Repository tests and GitHub publication "
                "are intentionally reserved for the PR repair workflow."
                if passed else "Preview was blocked by an independent verification gate."
            ),
            "duration_seconds": round(time.monotonic() - started, 4),
        }

    @staticmethod
    def _public_manifest(item: dict) -> dict:
        result = {
            key: value for key, value in item.items()
            if key not in {"original_ast", "expected_ast", "expected_helper_ast"}
        }
        for key in ("original_ast", "expected_ast", "expected_helper_ast"):
            if item.get(key):
                result[key + "_sha256"] = hashlib.sha256(
                    str(item[key]).encode("utf-8")
                ).hexdigest()
        return result
