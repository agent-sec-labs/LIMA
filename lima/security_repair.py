"""Constrained Python repair templates for evidence-verified security findings."""

from __future__ import annotations

import ast
import copy
import difflib
import re
import shlex
from dataclasses import dataclass
from typing import Any


RULE_CWE = {
    "FLOW-COMMAND": "CWE-78",
    "SEC-OS-SYSTEM": "CWE-78",
    "SEC-SUBPROCESS-SHELL": "CWE-78",
    "FLOW-SQL": "CWE-89",
    "SEC-SQL-CONCAT": "CWE-89",
    "FLOW-PATH": "CWE-22",
    "SEC-PATH-TRAVERSAL": "CWE-22",
}
SHELL_CALLS = {
    "subprocess.run",
    "subprocess.call",
    "subprocess.Popen",
    "subprocess.check_call",
    "subprocess.check_output",
}
OS_SHELL_CALLS = {"os.system"}
PATH_CALLS = {
    "open",
    "builtins.open",
    "io.open",
    "os.open",
    "send_file",
    "starlette.responses.FileResponse",
}
SHELL_META = re.compile(r"[;&|<>`$\n\r*?\[\]{}]")
SQL_VALUE_CONTEXT = re.compile(
    r"(?:=|<>|!=|<=|>=|<|>|\bLIKE|\bLIMIT|\bOFFSET)\s*$",
    re.IGNORECASE,
)
TRUSTED_ROOT_NAME = re.compile(
    r"(?:^|_)(?:base|root|dir|directory|upload_root|download_root)$",
    re.IGNORECASE,
)


def _call_name(node: ast.AST) -> str:
    parts: list[str] = []
    current = node
    while isinstance(current, ast.Attribute):
        parts.append(current.attr)
        current = current.value
    if isinstance(current, ast.Name):
        parts.append(current.id)
    return ".".join(reversed(parts))


def _ast_identity(node: ast.AST) -> str:
    return ast.dump(node, annotate_fields=True, include_attributes=False)


@dataclass(frozen=True)
class TextEdit:
    start: int
    end: int
    replacement: str


@dataclass
class PlannedRepair:
    edit: TextEdit
    manifest: dict[str, Any]
    requirements: set[str]


class PythonSecurityRepairEngine:
    """Generate a patch only when a narrow security invariant can be proven."""

    def repair(self, content: str, findings: list[dict], path: str) -> dict:
        try:
            tree = ast.parse(content, filename=path)
        except SyntaxError as exc:
            return {
                "content": content,
                "rules": [],
                "repairs": [],
                "blocked": [self._blocked(item, "source-syntax-error") for item in findings],
                "diagnostic": "%s:%s: %s" % (path, exc.lineno or 0, exc.msg),
            }

        parents = {
            id(child): parent
            for parent in ast.walk(tree)
            for child in ast.iter_child_nodes(parent)
        }
        plans: list[PlannedRepair] = []
        blocked: list[dict] = []
        occupied: list[tuple[int, int]] = []

        for finding in sorted(findings, key=lambda item: int(item.get("line", 0))):
            cwe = str(finding.get("cwe") or RULE_CWE.get(str(finding.get("rule_id")), ""))
            line = int(finding.get("line", 0))
            candidates = [
                node for node in ast.walk(tree)
                if isinstance(node, ast.Call)
                and int(getattr(node, "lineno", 0)) == line
                and self._matches_cwe(node, cwe)
            ]
            if len(candidates) != 1:
                reason = "repair-target-not-found" if not candidates else "ambiguous-repair-target"
                blocked.append(self._blocked(finding, reason))
                continue
            call = candidates[0]
            if cwe == "CWE-78":
                plan, reason = self._plan_command(content, tree, call, parents, finding, path)
            elif cwe == "CWE-89":
                plan, reason = self._plan_sql(content, tree, call, finding, path)
            elif cwe == "CWE-22":
                plan, reason = self._plan_path(content, tree, call, finding, path)
            else:
                plan, reason = None, "unsupported-cwe"
            if not plan:
                blocked.append(self._blocked(finding, reason))
                continue
            if any(plan.edit.start < end and plan.edit.end > start for start, end in occupied):
                blocked.append(self._blocked(finding, "overlapping-repair-target"))
                continue
            occupied.append((plan.edit.start, plan.edit.end))
            plans.append(plan)

        if not plans:
            return {
                "content": content, "rules": [], "repairs": [], "blocked": blocked,
                "patch_metrics": {"changed_lines": 0, "strategies": []},
            }

        requirements = set().union(*(item.requirements for item in plans))
        preamble, preamble_reason = self._preamble(tree, content, requirements)
        if preamble_reason:
            return {
                "content": content,
                "rules": [],
                "repairs": [],
                "blocked": blocked + [
                    self._blocked(finding, preamble_reason) for finding in findings
                    if str(finding.get("rule_id")) in {
                        item.manifest["rule_id"] for item in plans
                    }
                ],
                "patch_metrics": {"changed_lines": 0, "strategies": []},
            }

        edits = [item.edit for item in plans]
        if preamble:
            insertion = self._preamble_offset(tree, content)
            separator = "\n" if insertion and content[insertion - 1] not in "\r\n" else ""
            edits.append(TextEdit(insertion, insertion, separator + preamble))
        repaired = content
        for edit in sorted(edits, key=lambda item: (item.start, item.end), reverse=True):
            repaired = repaired[:edit.start] + edit.replacement + repaired[edit.end:]
        try:
            compile(repaired, path, "exec")
        except SyntaxError:
            return {
                "content": content,
                "rules": [],
                "repairs": [],
                "blocked": blocked + [
                    self._blocked(finding, "generated-syntax-error") for finding in findings
                ],
                "patch_metrics": {"changed_lines": 0, "strategies": []},
            }

        manifests = [item.manifest for item in plans]
        if "confined-path" in requirements:
            helper = self._path_helper_ast()
            helper_identity = _ast_identity(helper)
            for manifest in manifests:
                if manifest["strategy"] == "confined-path":
                    manifest["expected_helper_ast"] = helper_identity
        return {
            "content": repaired,
            "rules": sorted({item["rule_id"] for item in manifests}),
            "repairs": manifests,
            "blocked": blocked,
            "patch_metrics": {
                "changed_lines": self._changed_lines(content, repaired),
                "strategies": sorted({item["strategy"] for item in manifests}),
            },
        }

    @staticmethod
    def _blocked(finding: dict, reason: str) -> dict:
        return {
            "rule_id": str(finding.get("rule_id", "")),
            "cwe": str(finding.get("cwe") or RULE_CWE.get(str(finding.get("rule_id")), "")),
            "line": int(finding.get("line", 0)),
            "reason": reason,
        }

    @staticmethod
    def _matches_cwe(call: ast.Call, cwe: str) -> bool:
        name = _call_name(call.func)
        if cwe == "CWE-78":
            return name in SHELL_CALLS | OS_SHELL_CALLS
        if cwe == "CWE-89":
            return isinstance(call.func, ast.Attribute) and call.func.attr in {"execute", "query"}
        if cwe == "CWE-22":
            return name in PATH_CALLS
        return False

    def _plan_command(
        self, content: str, tree: ast.Module, call: ast.Call,
        parents: dict[int, ast.AST], finding: dict, path: str,
    ) -> tuple[PlannedRepair | None, str]:
        name = _call_name(call.func)
        if not call.args:
            return None, "missing-command-argument"
        argv, reason = self._command_argv(call.args[0])
        if reason:
            return None, reason
        requirements: set[str] = set()
        replacement = ast.Call(
            func=copy.deepcopy(call.func),
            args=[
                ast.List(elts=[copy.deepcopy(item) for item in argv], ctx=ast.Load()),
                *[copy.deepcopy(item) for item in call.args[1:]],
            ],
            keywords=copy.deepcopy(call.keywords),
        )
        strategy = "argv-no-shell"
        if name in SHELL_CALLS:
            if not self._imports_module(tree, "subprocess"):
                return None, "subprocess-binding-not-proven"
            shell_keywords = [item for item in replacement.keywords if item.arg == "shell"]
            if len(shell_keywords) != 1 or not (
                isinstance(shell_keywords[0].value, ast.Constant)
                and shell_keywords[0].value.value is True
            ):
                return None, "shell-true-not-found"
            shell_keywords[0].value = ast.Constant(False)
        elif name == "os.system":
            if not self._imports_module(tree, "os"):
                return None, "os-binding-not-proven"
            if not isinstance(parents.get(id(call)), ast.Expr):
                return None, "os-system-result-is-used"
            replacement = ast.Call(
                func=ast.Attribute(
                    value=ast.Name(id="_lima_subprocess", ctx=ast.Load()),
                    attr="run", ctx=ast.Load(),
                ),
                args=[ast.List(elts=argv, ctx=ast.Load())],
                keywords=[
                    ast.keyword(arg="shell", value=ast.Constant(False)),
                    ast.keyword(arg="check", value=ast.Constant(True)),
                ],
            )
            requirements.add("subprocess-alias")
        else:
            return None, "unsupported-command-api"
        ast.fix_missing_locations(replacement)
        return self._planned(
            content, call, replacement, finding, path, strategy, requirements,
            root_cause="Untrusted data is interpreted by a command shell.",
            invariant="The executable is static, untrusted values are separate argv entries, and shell parsing is disabled.",
            oracle={"fixed_executable": ast.literal_eval(argv[0]), "shell": False},
        ), ""

    def _command_argv(self, node: ast.AST) -> tuple[list[ast.expr], str]:
        segments = self._segments(node)
        if segments is None:
            return [], "unsupported-command-shape"
        argv: list[ast.expr] = []
        for index, (kind, value) in enumerate(segments):
            if kind == "literal":
                literal = str(value)
                if SHELL_META.search(literal):
                    return [], "shell-syntax-required"
                try:
                    argv.extend(ast.Constant(item) for item in shlex.split(literal, posix=True))
                except ValueError:
                    return [], "invalid-static-command"
                continue
            previous = segments[index - 1][1] if index > 0 and segments[index - 1][0] == "literal" else ""
            following = segments[index + 1][1] if index + 1 < len(segments) and segments[index + 1][0] == "literal" else ""
            if (previous and not str(previous)[-1].isspace()) or (
                following and not str(following)[0].isspace()
            ):
                return [], "dynamic-command-token-boundary"
            argv.append(value)
        if not argv or not isinstance(argv[0], ast.Constant) or not isinstance(argv[0].value, str):
            return [], "dynamic-executable"
        if len(argv) < 2:
            return [], "no-dynamic-command-argument"
        if not any(not isinstance(item, ast.Constant) for item in argv[1:]):
            return [], "no-dynamic-command-argument"
        return argv, ""

    def _plan_sql(
        self, content: str, tree: ast.Module, call: ast.Call,
        finding: dict, path: str,
    ) -> tuple[PlannedRepair | None, str]:
        if not isinstance(call.func, ast.Attribute) or call.func.attr != "execute":
            return None, "unsupported-sql-api"
        receiver = _call_name(call.func.value).split(".")[-1]
        if not re.search(r"(?:cursor|cur|connection|conn|db)$", receiver, re.IGNORECASE):
            return None, "sql-driver-binding-not-proven"
        if len(call.args) != 1 or call.keywords:
            return None, "sql-call-already-has-parameters"
        style, reason = self._sql_paramstyle(content, tree)
        if reason:
            return None, reason
        segments = self._segments(call.args[0])
        if segments is None:
            return None, "unsupported-sql-shape"
        placeholder = "?" if style == "qmark" else "%s"
        query = ""
        parameters: list[ast.expr] = []
        for kind, value in segments:
            if kind == "literal":
                query += str(value)
                continue
            if not SQL_VALUE_CONTEXT.search(query):
                return None, "dynamic-sql-structure"
            query += placeholder
            parameters.append(value)
        if not parameters:
            return None, "no-dynamic-sql-value"
        normalized = query.strip().rstrip(";")
        if ";" in normalized:
            return None, "multiple-sql-statements"
        if not re.match(r"^(SELECT|INSERT|UPDATE|DELETE)\b", normalized, re.IGNORECASE):
            return None, "unsupported-sql-statement"
        replacement = ast.Call(
            func=call.func,
            args=[
                ast.Constant(query),
                ast.Tuple(elts=parameters, ctx=ast.Load()),
            ],
            keywords=[],
        )
        ast.fix_missing_locations(replacement)
        return self._planned(
            content, call, replacement, finding, path, "parameterized-sql", set(),
            root_cause="Untrusted values are concatenated into SQL syntax.",
            invariant="SQL structure is constant and every untrusted value is bound through the driver parameter API.",
            oracle={
                "paramstyle": style,
                "placeholder": placeholder,
                "parameter_count": len(parameters),
            },
        ), ""

    @staticmethod
    def _sql_paramstyle(content: str, tree: ast.Module) -> tuple[str, str]:
        explicit = re.search(
            r"lima:\s*sql-paramstyle\s*=\s*(qmark|format)",
            "\n".join(content.splitlines()[:30]), re.IGNORECASE,
        )
        if explicit:
            return explicit.group(1).lower(), ""
        modules: set[str] = set()
        for node in tree.body:
            if isinstance(node, ast.Import):
                modules.update(alias.name.split(".")[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                modules.add(node.module.split(".")[0])
        qmark = "sqlite3" in modules
        formatted = bool(modules & {"psycopg", "psycopg2", "mysql", "pymysql"})
        if qmark and formatted:
            return "", "ambiguous-sql-paramstyle"
        if qmark:
            return "qmark", ""
        if formatted:
            return "format", ""
        return "", "unknown-sql-paramstyle"

    def _plan_path(
        self, content: str, tree: ast.Module, call: ast.Call,
        finding: dict, path: str,
    ) -> tuple[PlannedRepair | None, str]:
        if not call.args:
            return None, "missing-path-argument"
        source = call.args[0]
        base: ast.expr | None = None
        untrusted: ast.expr | None = None
        if isinstance(source, ast.BinOp) and isinstance(source.op, ast.Div):
            base, untrusted = source.left, source.right
        elif (
            isinstance(source, ast.Call)
            and _call_name(source.func) == "os.path.join"
            and len(source.args) == 2
            and not source.keywords
        ):
            base, untrusted = source.args
        if base is None or untrusted is None:
            return None, "unsupported-path-shape"
        if not self._trusted_root(base, tree, content):
            return None, "trusted-path-root-not-proven"
        if isinstance(untrusted, ast.Constant):
            return None, "no-dynamic-path-component"
        helper_call = ast.Call(
            func=ast.Name(id="_lima_resolve_under_base", ctx=ast.Load()),
            args=[base, untrusted], keywords=[],
        )
        replacement = ast.Call(
            func=call.func,
            args=[helper_call, *call.args[1:]],
            keywords=list(call.keywords),
        )
        ast.fix_missing_locations(replacement)
        return self._planned(
            content, call, replacement, finding, path, "confined-path",
            {"confined-path"},
            root_cause="An untrusted path component is used without canonical containment validation.",
            invariant="The canonical target must equal the trusted root or remain one of its descendants.",
            oracle={
                "follows_symlinks_before_containment_check": True,
                "atomic_open": False,
                "residual_risk": (
                    "A concurrent filesystem mutation after validation requires an OS sandbox "
                    "or descriptor-relative open for complete mitigation."
                ),
            },
        ), ""

    @classmethod
    def _trusted_root(cls, node: ast.AST, tree: ast.Module, content: str) -> bool:
        if cls._static_path_expression(node):
            return True
        name = _call_name(node)
        if not name or not TRUSTED_ROOT_NAME.search(name.split(".")[-1]):
            return False
        annotations = re.findall(
            r"lima:\s*trusted-path-root\s*=\s*([A-Za-z_][A-Za-z0-9_.]*)",
            "\n".join(content.splitlines()[:30]), re.IGNORECASE,
        )
        if name.lower() in {item.lower() for item in annotations}:
            return True
        if not isinstance(node, ast.Name):
            return False
        for statement in tree.body:
            if isinstance(statement, (ast.Assign, ast.AnnAssign)):
                targets = statement.targets if isinstance(statement, ast.Assign) else [statement.target]
                value = statement.value
                if value is not None and any(
                    isinstance(target, ast.Name) and target.id == node.id for target in targets
                ):
                    return cls._static_path_expression(value)
        return False

    @classmethod
    def _static_path_expression(cls, node: ast.AST) -> bool:
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return bool(node.value)
        if (
            isinstance(node, ast.Call)
            and _call_name(node.func) in {"Path", "pathlib.Path"}
            and len(node.args) == 1
            and not node.keywords
        ):
            return cls._static_path_expression(node.args[0])
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Div):
            return cls._static_path_expression(node.left) and (
                isinstance(node.right, ast.Constant)
                and isinstance(node.right.value, str)
                and bool(node.right.value)
            )
        return False

    def _planned(
        self, content: str, original: ast.Call, replacement: ast.Call,
        finding: dict, path: str, strategy: str, requirements: set[str],
        *, root_cause: str, invariant: str, oracle: dict,
    ) -> PlannedRepair:
        start, end = self._node_offsets(content, original)
        manifest = {
            "path": path,
            "line": int(finding.get("line", 0)),
            "rule_id": str(finding.get("rule_id", "")),
            "cwe": str(finding.get("cwe") or RULE_CWE.get(str(finding.get("rule_id")), "")),
            "strategy": strategy,
            "root_cause": root_cause,
            "security_invariant": invariant,
            "oracle": oracle,
            "original_ast": _ast_identity(original),
            "expected_ast": _ast_identity(replacement),
        }
        return PlannedRepair(
            TextEdit(start, end, ast.unparse(replacement)), manifest, requirements
        )

    @staticmethod
    def _segments(node: ast.AST) -> list[tuple[str, Any]] | None:
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return [("literal", node.value)]
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            left = PythonSecurityRepairEngine._segments(node.left)
            right = PythonSecurityRepairEngine._segments(node.right)
            if left is None or right is None:
                return None
            return left + right
        if isinstance(node, ast.JoinedStr):
            result: list[tuple[str, Any]] = []
            for value in node.values:
                if isinstance(value, ast.Constant) and isinstance(value.value, str):
                    result.append(("literal", value.value))
                elif isinstance(value, ast.FormattedValue) and value.conversion == -1 and value.format_spec is None:
                    result.append(("expr", value.value))
                else:
                    return None
            return result
        if isinstance(node, ast.expr):
            return [("expr", node)]
        return None

    @staticmethod
    def _imports_module(tree: ast.Module, module: str) -> bool:
        imported = any(
            isinstance(node, ast.Import)
            and any(alias.name == module and alias.asname is None for alias in node.names)
            for node in tree.body
        )
        if not imported:
            return False
        for node in ast.walk(tree):
            if isinstance(node, ast.arg) and node.arg == module:
                return False
            if isinstance(node, ast.Name) and node.id == module and isinstance(node.ctx, ast.Store):
                return False
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) \
                    and node.name == module:
                return False
        return True

    @staticmethod
    def _path_helper_ast() -> ast.FunctionDef:
        helper_source = (
            "def _lima_resolve_under_base(base, untrusted_path):\n"
            "    root = _LIMAPath(base).resolve()\n"
            "    candidate = (root / untrusted_path).resolve()\n"
            "    if candidate != root and root not in candidate.parents:\n"
            "        raise ValueError('path escapes allowed root')\n"
            "    return candidate\n"
        )
        return ast.parse(helper_source).body[0]

    def _preamble(
        self, tree: ast.Module, content: str, requirements: set[str]
    ) -> tuple[str, str]:
        identifiers = {
            node.id for node in ast.walk(tree) if isinstance(node, ast.Name)
        }
        definitions = {
            node.name for node in tree.body
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
        }
        pieces: list[str] = []
        if "subprocess-alias" in requirements:
            if "_lima_subprocess" in identifiers:
                return "", "repair-helper-name-collision"
            pieces.append("import subprocess as _lima_subprocess\n")
        if "confined-path" in requirements:
            if {"_LIMAPath", "_lima_resolve_under_base"} & (identifiers | definitions):
                return "", "repair-helper-name-collision"
            pieces.append("from pathlib import Path as _LIMAPath\n")
            pieces.append("\n" + ast.unparse(self._path_helper_ast()) + "\n")
        return ("".join(pieces) + ("\n" if pieces else "")), ""

    @staticmethod
    def _preamble_offset(tree: ast.Module, content: str) -> int:
        insertion_line = 0
        body = list(tree.body)
        if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant) and isinstance(body[0].value.value, str):
            insertion_line = int(getattr(body.pop(0), "end_lineno", 0))
        for node in body:
            if isinstance(node, ast.ImportFrom) and node.module == "__future__":
                insertion_line = int(getattr(node, "end_lineno", insertion_line))
            else:
                break
        lines = content.splitlines(keepends=True)
        return sum(len(item) for item in lines[:insertion_line])

    @staticmethod
    def _node_offsets(content: str, node: ast.AST) -> tuple[int, int]:
        lines = content.splitlines(keepends=True)

        def offset(line_number: int, byte_column: int) -> int:
            line = lines[line_number - 1]
            char_column = len(line.encode("utf-8")[:byte_column].decode("utf-8"))
            return sum(len(item) for item in lines[:line_number - 1]) + char_column

        return (
            offset(int(node.lineno), int(node.col_offset)),
            offset(int(node.end_lineno), int(node.end_col_offset)),
        )

    @staticmethod
    def _changed_lines(before: str, after: str) -> int:
        matcher = difflib.SequenceMatcher(a=before.splitlines(), b=after.splitlines())
        return sum(
            max(old_end - old_start, new_end - new_start)
            for tag, old_start, old_end, new_start, new_end in matcher.get_opcodes()
            if tag != "equal"
        )
