import ast
import re
from datetime import datetime, timezone
from typing import Dict, List

from .github import GitHubClient
from .security_repair import PythonSecurityRepairEngine, RULE_CWE
from .verifier import RepairVerifier


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

    def create_fix_commits(self, client: GitHubClient, repository: str, pull_request: int, report: dict) -> dict:
        pull = client.get_pull_request(repository, pull_request)
        source_sha = pull["head"]["sha"]
        source_repository = pull["head"].get("repo", {}).get("full_name") or repository
        stamp = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
        branch = "lima/fix-pr-%d-%s" % (pull_request, stamp)
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
        for path, findings in by_path.items():
            current = client.get_file(source_repository, path, source_sha)
            result = self.apply(current["decoded_content"], findings, path)
            blocked_findings.extend([
                {"path": path, **item} for item in result.get("blocked", [])
            ])
            if not result["rules"]:
                continue
            planned.append((path, current, result))
        if not planned:
            return {"branch": None, "source_sha": source_sha, "commits": [],
                    "blocked_findings": blocked_findings,
                    "note": "No verified finding was eligible for deterministic automatic repair."}
        files = {path: result["content"] for path, _current, result in planned}
        repairs = [
            repair for _path, _current, result in planned
            for repair in result.get("repairs", [])
        ]
        verification = self.verifier.verify_contents(files, repairs)
        if verification["passed"] and (repairs or self.verifier.test_command):
            archive = client.download_archive(source_repository, source_sha)
            verification = self.verifier.verify_archive(archive, files, repairs)
        if not verification["passed"]:
            return {
                "branch": None, "source_sha": source_sha, "commits": [],
                "verification": verification,
                "blocked_findings": blocked_findings,
                "note": "Repair was blocked because at least one verification gate failed.",
            }
        commit = client.create_atomic_commit(
            repository, branch, source_sha, files,
            "fix: apply verified LIMA repairs for PR #%d" % pull_request,
        )
        draft = client.create_draft_pull_request(
            repository,
            "fix: verified LIMA repairs for #%d" % pull_request,
            branch, pull.get("base", {}).get("ref", "main"),
            (
                "Automated deterministic security repair. Compilation, independent security "
                "oracles, full-repository differential rescan, and configured regression tests passed. "
                "Human approval is still required."
            ),
        )
        commits = [{
            "paths": sorted(files),
            "rules": sorted({
                rule for _path, _current, result in planned for rule in result["rules"]
            }),
            "sha": commit.get("sha"),
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
        return {"branch": branch, "source_sha": source_sha, "commits": commits,
                "draft_pull_request": {
                    "number": draft.get("number"), "url": draft.get("html_url")
                },
                "verification": verification,
                "repair_manifest": repairs,
                "patch_metrics": patch_metrics,
                "blocked_findings": blocked_findings,
                "note": "Verified repairs were published as one atomic commit in a draft pull request."}
