import ast
import re
from typing import Dict, List

from .github import GitHubClient, ResponseTooLarge
from .security_repair import RULE_CWE, PythonSecurityRepairEngine
from .verifier import MAX_FILE_BYTES, RepairVerifier
from .repair_publication import publish_repair

SUPPORTED_AUTOFIX_RULES = {
    "REL-DEBUG-PRINT",
    "SEC-HARDCODED-SECRET",
    "SEC-SUBPROCESS-SHELL",
    "SEC-OS-SYSTEM",
    "SEC-SQL-CONCAT",
    "SEC-PATH-TRAVERSAL",
    "FLOW-COMMAND",
    "FLOW-SQL",
    "FLOW-PATH",
}
REPAIR_VERIFICATION_STATES = {
    "syntax-verified",
    "corroborated",
    "dataflow-verified",
    "confirmed",
}
_COMMIT_SHA = re.compile(r"[0-9a-f]{40}\Z")


class SafeFixer:
    """Creates conservative fixes on a dedicated branch; never writes to the PR head."""

    def propose_line(self, line: str, finding: dict) -> str:
        rule = finding.get("rule_id")
        if rule == "REL-DEBUG-PRINT":
            return ""
        if rule == "SEC-SUBPROCESS-SHELL":
            return re.sub(r"shell\s*=\s*True", "shell=False", line)
        if rule == "SEC-HARDCODED-SECRET":
            match = re.match(r"(\s*)([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(['\"]).+?\3\s*$", line)
            if match:
                return '%s%s = os.environ["%s"]' % (match.group(1), match.group(2), match.group(2).upper())
        return line

    def apply(self, content: str, findings: List[dict], path: str) -> Dict[str, object]:
        scoped = [item for item in findings if item.get("path") == path]
        eligible = [
            item for item in scoped if self.repair_eligibility(item)["eligible"]
        ]
        blocked = [
            {
                "rule_id": item.get("rule_id", ""),
                "line": item.get("line", 0),
                "reason": self.repair_eligibility(item)["reason"],
            }
            for item in scoped if not self.repair_eligibility(item)["eligible"]
        ]
        constrained = [
            item for item in eligible
            if str(item.get("cwe") or RULE_CWE.get(str(item.get("rule_id")), ""))
            in {"CWE-78", "CWE-89", "CWE-22"}
        ]
        if constrained:
            result = self.security_engine.repair(content, constrained, path)
            result["blocked"] = blocked + list(result.get("blocked", [])) + [
                {
                    "rule_id": item.get("rule_id", ""),
                    "line": item.get("line", 0),
                    "reason": "mixed-repair-batch-deferred",
                }
                for item in eligible if item not in constrained
            ]
            return result
        if path.endswith(".py") and hasattr(ast, "unparse"):
            structured = self._apply_python_ast(content, eligible, path)
            if structured["rules"]:
                structured["blocked"] = blocked
                return structured
        lines = content.splitlines()
        changed = []
        needs_os = False
        for finding in sorted(eligible, key=lambda x: x.get("line", 0), reverse=True):
            index = int(finding.get("line", 0)) - 1
            if index < 0 or index >= len(lines):
                continue
            replacement = self.propose_line(lines[index], finding)
            if replacement != lines[index]:
                needs_os = needs_os or "os.environ" in replacement
                lines[index] = replacement
                changed.append(finding.get("rule_id"))
        if needs_os and not any(re.match(r"\s*(import os|from os import)", line) for line in lines):
            lines.insert(0, "import os")
        return {
            "content": "\n".join(lines) + ("\n" if content.endswith("\n") else ""),
            "rules": changed,
            "blocked": blocked,
            "repairs": [],
            "patch_metrics": {"changed_lines": len(changed), "strategies": []},
        }

    def _apply_python_ast(
        self, content: str, findings: List[dict], path: str,
    ) -> Dict[str, object]:
        targets = {
            (int(item.get("line", 0)), item.get("rule_id"))
            for item in findings if item.get("path") == path
        }
        changed = []
        needs_os = False

        class Transformer(ast.NodeTransformer):
            def visit_Expr(inner, node):
                if (
                    (node.lineno, "REL-DEBUG-PRINT") in targets
                    and isinstance(node.value, ast.Call)
                    and isinstance(node.value.func, ast.Name)
                    and node.value.func.id == "print"
                ):
                    changed.append("REL-DEBUG-PRINT")
                    return None
                return inner.generic_visit(node)

            def visit_Call(inner, node):
                node = inner.generic_visit(node)
                if (node.lineno, "SEC-SUBPROCESS-SHELL") in targets:
                    for keyword in node.keywords:
                        if (
                            keyword.arg == "shell"
                            and isinstance(keyword.value, ast.Constant)
                            and keyword.value.value is True
                        ):
                            keyword.value = ast.Constant(False)
                            changed.append("SEC-SUBPROCESS-SHELL")
                return node

            def visit_Assign(inner, node):
                nonlocal needs_os
                node = inner.generic_visit(node)
                if (
                    (node.lineno, "SEC-HARDCODED-SECRET") in targets
                    and len(node.targets) == 1
                    and isinstance(node.targets[0], ast.Name)
                    and isinstance(node.value, ast.Constant)
                    and isinstance(node.value.value, str)
                ):
                    name = node.targets[0].id
                    node.value = ast.Subscript(
                        value=ast.Attribute(
                            value=ast.Name(id="os", ctx=ast.Load()),
                            attr="environ", ctx=ast.Load(),
                        ),
                        slice=ast.Constant(name.upper()), ctx=ast.Load(),
                    )
                    needs_os = True
                    changed.append("SEC-HARDCODED-SECRET")
                return node

        try:
            tree = Transformer().visit(ast.parse(content, filename=path))
        except SyntaxError:
            return {"content": content, "rules": []}
        if not changed:
            return {"content": content, "rules": []}
        if needs_os and not any(
            isinstance(node, (ast.Import, ast.ImportFrom))
            and (
                (isinstance(node, ast.Import) and any(alias.name == "os" for alias in node.names))
                or (isinstance(node, ast.ImportFrom) and node.module == "os")
            )
            for node in tree.body
        ):
            tree.body.insert(0, ast.Import(names=[ast.alias(name="os")]))
        ast.fix_missing_locations(tree)
        value = ast.unparse(tree) + "\n"
        compile(value, path, "exec")
        return {
            "content": value,
            "rules": sorted(set(changed)),
            "repairs": [],
            "patch_metrics": {
                "changed_lines": len(set(changed)), "strategies": []
            },
        }

    def __init__(self, verifier: RepairVerifier = None):
        self.verifier = verifier or RepairVerifier()
        self.security_engine = PythonSecurityRepairEngine()

    @staticmethod
    def _publication_blocked(
        source_sha: str | None,
        blocked_findings: list[dict],
        *,
        failure_code: str,
        note: str,
        verification: dict | None = None,
        repair_manifest: list[dict] | None = None,
    ) -> dict:
        """Return a stable no-write publication result."""

        result = {
            "branch": None,
            "source_sha": source_sha,
            "commits": [],
            "blocked_findings": blocked_findings,
            "failure_code": failure_code,
            "note": note,
        }
        if verification is not None:
            result["verification"] = verification
        if repair_manifest is not None:
            result["repair_manifest"] = repair_manifest
        return result

    @staticmethod
    def _publication_verification_passed(
        verification: dict, repairs: list[dict], files: dict[str, str],
    ) -> bool:
        """Require all publication gates and a real sandbox execution receipt."""

        if verification.get("passed") is not True:
            return False
        sandbox = verification.get("sandbox")
        if not isinstance(sandbox, dict) or not all(
            sandbox.get(field) is True
            for field in ("configured", "executed", "stop_confirmed", "passed")
        ):
            return False
        if not isinstance(sandbox.get("image_id"), str) or not re.fullmatch(
            r"sha256:[0-9a-f]{64}", sandbox["image_id"]
        ):
            return False
        checks = verification.get("checks")
        if not isinstance(checks, list) or not checks:
            return False
        if any(
            not isinstance(check, dict) or check.get("passed") is not True
            for check in checks
        ):
            return False
        passed = {
            str(check.get("name", ""))
            for check in checks
        }
        if any(
            f"compile:{path}" not in passed
            for path in files
        ):
            return False
        for repair in repairs:
            path = str(repair.get("path", ""))
            cwe = str(repair.get("cwe", "unknown"))
            try:
                line = int(repair.get("line", 0))
            except (TypeError, ValueError):
                return False
            if f"security-oracle:{cwe}:{path}:{line}" not in passed:
                return False
            if f"differential-rescan:{cwe}:{path}" not in passed:
                return False
        return "repository-tests" in passed

    @staticmethod
    def _display_check_name(value: object) -> str:
        """Escape controls so untrusted names cannot forge body rows."""

        return "".join(
            character if character.isprintable() else f"\\u{ord(character):04x}"
            for character in str(value)
        )

    @staticmethod
    def _verification_body(verification: dict) -> str:
        """Describe only checks actually returned by the verifier."""

        checks = verification.get("checks") or []
        rendered = [
            f"- {SafeFixer._display_check_name(item.get('name', 'unnamed'))}: "
            f"{'passed' if item.get('passed') is True else 'failed'}"
            for item in checks if isinstance(item, dict)
        ]
        sandbox = verification.get("sandbox") or {}
        return (
            f"Automated deterministic security repair for source commit "
            f"{SafeFixer._display_check_name(verification.get('source_sha', 'unknown'))}.\n\n"
            "Verified publication gates:\n"
            + "\n".join(rendered)
            + "\n\nSandbox receipt: "
            f"executed={sandbox.get('executed') is True}; "
            f"stop_confirmed={sandbox.get('stop_confirmed') is True}; "
            f"passed={sandbox.get('passed') is True}.\n"
            "Human approval is still required."
        )

    @staticmethod
    def repair_eligibility(finding: dict) -> Dict[str, object]:
        if finding.get("automatic_repair") is False:
            return {"eligible": False, "reason": "automatic-repair-disabled"}
        rule_id = str(finding.get("rule_id", ""))
        state = str(finding.get("verification_state", "candidate"))
        if rule_id not in SUPPORTED_AUTOFIX_RULES:
            return {"eligible": False, "reason": "unsupported-rule"}
        cwe = str(finding.get("cwe") or RULE_CWE.get(rule_id, ""))
        if cwe in {"CWE-78", "CWE-89", "CWE-22"} and state not in {
            "dataflow-verified", "confirmed",
        }:
            return {"eligible": False, "reason": "requires-dataflow-verification"}
        if state not in REPAIR_VERIFICATION_STATES:
            return {"eligible": False, "reason": "unverified-finding"}
        return {
            "eligible": True,
            "reason": (
                "verified-constrained-security-repair"
                if cwe in {"CWE-78", "CWE-89", "CWE-22"}
                else "verified-deterministic-rule"
            ),
        }

    def create_fix_commits(
        self,
        client: GitHubClient,
        repository: str,
        pull_request: int,
        report: dict,
        *,
        expected_source_sha: str | None = None,
        publication_store=None,
        publication_scope=None,
    ) -> dict:
        """Publish only repairs bound to the audited immutable PR head."""

        planned = []
        blocked_findings = []
        by_path = {}
        for finding in report.get("findings", []):
            eligibility = self.repair_eligibility(finding)
            if not eligibility["eligible"]:
                blocked_findings.append({
                    "path": finding.get("path", ""),
                    "line": finding.get("line", 0),
                    "rule_id": finding.get("rule_id", ""),
                    "reason": eligibility["reason"],
                })
                continue
            by_path.setdefault(finding["path"], []).append(finding)
        # An all-blocked report is an informational response: do not fetch a
        # PR or source files just to report eligibility.
        if not by_path:
            return {
                "branch": None, "source_sha": expected_source_sha, "commits": [],
                "blocked_findings": blocked_findings,
                "note": "No verified finding was eligible for deterministic automatic repair.",
            }
        if len(by_path) >= 300:
            return self._publication_blocked(
                expected_source_sha, blocked_findings, failure_code="repair-input-too-large",
                note="A repair publication supports at most 299 modified files.",
            )
        if not isinstance(expected_source_sha, str) or not _COMMIT_SHA.fullmatch(
            expected_source_sha
        ):
            return self._publication_blocked(
                None, blocked_findings,
                failure_code="repair-source-stale",
                note="Repair publication requires the audited immutable source SHA.",
            )

        pull = client.get_pull_request(repository, pull_request)
        live_source_sha = str((pull.get("head") or {}).get("sha") or "")
        if live_source_sha != expected_source_sha:
            return self._publication_blocked(
                expected_source_sha, blocked_findings,
                failure_code="repair-source-stale",
                note="Repair source changed after the audit; re-analysis is required.",
            )
        source_repository = (
            (pull.get("head") or {}).get("repo", {}).get("full_name") or repository
        )
        source_total = 0
        for path, findings in by_path.items():
            try:
                current = client.get_file(source_repository, path, expected_source_sha)
                size = len(current["decoded_content"].encode("utf-8"))
                source_total += size
                if size > MAX_FILE_BYTES or source_total > 20 * 1024 * 1024:
                    raise ResponseTooLarge("repair source exceeds the source byte budget")
            except ResponseTooLarge:
                return self._publication_blocked(
                    expected_source_sha, blocked_findings, failure_code="repair-input-too-large",
                    note="Repair source exceeded its bounded input budget.",
                )
            result = self.apply(current["decoded_content"], findings, path)
            blocked_findings.extend([
                {"path": path, **item} for item in result.get("blocked", [])
            ])
            if not result["rules"]:
                continue
            planned.append((path, current, result))
        if not planned:
            return {"branch": None, "source_sha": expected_source_sha, "commits": [],
                    "blocked_findings": blocked_findings,
                    "note": "No verified finding was eligible for deterministic automatic repair."}
        files = {path: result["content"] for path, _current, result in planned}
        repairs = [
            repair for _path, _current, result in planned
            for repair in result.get("repairs", [])
        ]
        repaired_paths = {str(repair.get("path", "")) for repair in repairs}
        unsupported_paths = sorted(set(files) - repaired_paths)
        if unsupported_paths:
            return self._publication_blocked(
                expected_source_sha, blocked_findings,
                failure_code="repair-manifest-missing",
                note="Repair publication requires an independent repair manifest for every file.",
                repair_manifest=repairs,
            )
        if not self.verifier.test_command:
            return self._publication_blocked(
                expected_source_sha, blocked_findings,
                failure_code="repository-tests-not-configured",
                note="Repair publication requires a configured sandbox repository test command.",
                repair_manifest=repairs,
            )
        verification = self.verifier.verify_contents(files, repairs)
        if verification["passed"]:
            try:
                if callable(getattr(client, "download_archive_file", None)):
                    with client.download_archive_file(source_repository, expected_source_sha) as archive:
                        verification = self.verifier.verify_archive(archive, files, repairs)
                else:
                    # Non-HTTP adapters must satisfy the same compressed budget.
                    archive = client.download_archive(source_repository, expected_source_sha)
                    if len(archive) > 64 * 1024 * 1024:
                        raise ResponseTooLarge("repair archive exceeds the archive byte budget")
                    verification = self.verifier.verify_archive(archive, files, repairs)
            except ResponseTooLarge:
                return self._publication_blocked(
                    expected_source_sha, blocked_findings, failure_code="repair-input-too-large",
                    note="Repair archive exceeded its bounded input budget.", repair_manifest=repairs,
                )
        verification["source_sha"] = expected_source_sha
        if not self._publication_verification_passed(verification, repairs, files):
            return self._publication_blocked(
                expected_source_sha, blocked_findings,
                failure_code="repair-verification-failed",
                note=(
                    "Repair was blocked because publication verification was "
                    "incomplete or failed."
                ),
                verification=verification,
                repair_manifest=repairs,
            )
        # A PR may move while its complete archive is being verified.  This
        # final read is deliberately immediately before the first write.
        latest = client.get_pull_request(repository, pull_request)
        latest_sha = str((latest.get("head") or {}).get("sha") or "")
        if latest_sha != expected_source_sha:
            return self._publication_blocked(
                expected_source_sha, blocked_findings,
                failure_code="repair-source-stale",
                note="Repair source changed during verification; re-analysis is required.",
                verification=verification,
                repair_manifest=repairs,
            )
        if publication_store is None or not publication_scope:
            return self._publication_blocked(
                expected_source_sha, blocked_findings,
                failure_code="repair-publication-store-unconfigured",
                note="Publication requires a durable operation store and a bounded file set.",
                verification=verification, repair_manifest=repairs,
            )
        commits = [{
            "paths": sorted(files),
            "rules": sorted({
                rule for _path, _current, result in planned for rule in result["rules"]
            }),
            "sha": None,
        }]
        patch_metrics = {
            "files_changed": len(files),
            "changed_lines": sum(
                int(result.get("patch_metrics", {}).get("changed_lines", 0))
                for _path, _current, result in planned
            ),
            "strategies": sorted({
                strategy for _path, _current, result in planned
                for strategy in result.get("patch_metrics", {}).get("strategies", [])
            }),
        }
        response = {
            "branch": None,
            "source_sha": expected_source_sha,
            "commits": commits,
            "verification": verification,
            "repair_manifest": repairs,
            "patch_metrics": patch_metrics,
            "blocked_findings": blocked_findings,
            "note": (
                "Verified repairs were published as one atomic commit in a "
                "draft pull request."
            ),
        }
        response["_base"] = pull.get("base", {}).get("ref", "main")
        return publish_repair(
            client, publication_store, publication_scope,
            repository=repository, pull_request=pull_request, source_sha=expected_source_sha,
            files=files, verification=verification, repairs=repairs, response=response,
            test_command=self.verifier.test_command, body=self._verification_body(verification),
        )
