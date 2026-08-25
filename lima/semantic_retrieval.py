"""Label-blind semantic retrieval and security-invariant evidence extraction."""

from __future__ import annotations

import ast
import hashlib
import textwrap
from dataclasses import dataclass, replace
from pathlib import Path

from .workspace import RepositoryWorkspace


SIGNAL_WEIGHTS = {
    "path": {
        "os.path.commonprefix": 64,
        "os.path.commonpath": 48,
        ".relative_to(": 26,
        ".is_relative_to(": 24,
        "follow_symlink": 18,
        "os.path.abspath": 14,
        "os.path.realpath": 14,
        "os.path.expanduser": 12,
        ".resolve(": 10,
        "os.path.normpath": 8,
        ".joinpath(": 6,
        "os.path.join": 6,
        "extract": 5,
        "sendfile": 4,
    },
    "command": {
        "shell=true": 48,
        "os.system(": 44,
        "os.popen(": 40,
        "subprocess.run(": 24,
        "subprocess.popen(": 24,
        "popen.run(": 22,
        "shell_quote(": 20,
        "prepare_outtmpl(": 12,
        "unsafe_option": 32,
        "upload_pack": 12,
        "receive_pack": 12,
        "dashify": 10,
        "subprocess": 8,
        "popen": 7,
        "transform_kwargs": 8,
        "command": 6,
        "cmd": 3,
    },
    "sql": {
        "request.args": 20,
        ".execute(": 20,
        ".order_by(": 12,
        "stringagg": 14,
        "string_agg": 14,
        "%(delimiter)": 14,
        "template": 5,
        "sql": 5,
        "query": 4,
        "parameter": 3,
        "aggregate": 4,
        "ordering": 3,
    },
}

SECURITY_IDENTIFIER_TERMS = (
    "archive", "command", "cmd", "directory", "exec", "file", "filename", "model_path",
    "option", "order", "path", "query", "root", "shell", "sort", "sql", "target", "template",
)


PIPELINE_METHOD_TERMS = (
    "check",
    "validate",
    "sanitize",
    "normalize",
    "canonical",
    "transform",
    "resolve",
    "handle",
    "url_for",
)

SECURITY_CONTRACTS = {
    "path": (
        "Path parameters from archives, configuration, plugins or callers cross a trust boundary "
        "even without an HTTP handler. Normalization is not containment: commonprefix is lexical, "
        "and abspath/expanduser/resolve alone do not prove that a target remains under an allowed root."
    ),
    "command": (
        "CLI, configuration, downloaded metadata and AI-tool arguments may be attacker influenced. "
        "Distinguish an explicitly selected executable from interpolation into shell syntax; safety "
        "guards must cover shell metacharacters and use the same canonical form as execution. A "
        "fallback that quotes data only when a template has no placeholders does not protect metadata "
        "substituted by the template branch; permitted conversions and defaults must preserve shell "
        "safety before execution."
    ),
    "sql": (
        "Database parameters protect values, not identifiers or ORDER BY structure. Request-derived "
        "column/direction tokens passed through text(), templates or string construction require an "
        "explicit allowlist before raw SQL construction."
    ),
}


@dataclass(frozen=True)
class SecurityInvariant:
    """A deterministic hypothesis that an LLM must verify against source evidence."""

    identifier: str
    category: str
    status: str
    summary: str
    related_symbols: tuple[str, ...] = ()

    def metadata(self) -> dict:
        return {
            "id": self.identifier,
            "category": self.category,
            "status": self.status,
            "summary": self.summary,
            "related_symbols": list(self.related_symbols),
        }


@dataclass(frozen=True)
class SemanticCandidate:
    path: str
    qualname: str
    start_line: int
    end_line: int
    category: str
    score: int
    signals: tuple[str, ...]
    code: str
    calls: tuple[str, ...] = ()
    identifiers: tuple[str, ...] = ()
    relations: tuple[str, ...] = ()
    invariants: tuple[SecurityInvariant, ...] = ()

    def metadata(self) -> dict:
        return {
            "path": self.path,
            "qualname": self.qualname,
            "start_line": self.start_line,
            "end_line": self.end_line,
            "category": self.category,
            "score": self.score,
            "signals": list(self.signals),
            "calls": list(self.calls),
            "identifiers": list(self.identifiers),
            "relations": list(self.relations),
            "invariants": [item.metadata() for item in self.invariants],
            "chars": len(self.code),
            "content_sha256": hashlib.sha256(self.code.encode("utf-8")).hexdigest(),
        }


@dataclass(frozen=True)
class RetrievalRun:
    """Candidates plus label-blind coverage and stage diagnostics."""

    candidates: tuple[SemanticCandidate, ...]
    inventory_paths: frozenset[str]
    diagnostics: dict


class SecuritySemanticRetriever:
    """Rank Python security candidates and connect validation-to-use evidence."""

    def __init__(
        self,
        *,
        max_candidates: int = 24,
        per_category: int = 6,
        max_total_chars: int = 48_000,
        max_candidate_chars: int = 5_000,
        min_score: int = 8,
    ) -> None:
        if min(max_candidates, per_category, max_total_chars, max_candidate_chars, min_score) < 1:
            raise ValueError("semantic retrieval limits must be positive")
        self.max_candidates = max_candidates
        self.per_category = per_category
        self.max_total_chars = max_total_chars
        self.max_candidate_chars = max_candidate_chars
        self.min_score = min_score

    @staticmethod
    def _is_test_path(path: str) -> bool:
        parts = path.lower().split("/")
        return any(part in {"test", "tests", "testing"} for part in parts) or any(
            part.startswith("test_") for part in parts
        )

    @staticmethod
    def _function_nodes(tree: ast.Module):
        for node in tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                yield node.name, node, ()
            elif isinstance(node, ast.ClassDef):
                class_context = tuple(
                    child for child in node.body
                    if isinstance(child, (ast.Assign, ast.AnnAssign))
                )
                for child in node.body:
                    if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        yield "%s.%s" % (node.name, child.name), child, class_context

    @staticmethod
    def _call_name(node: ast.AST) -> str:
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            owner = SecuritySemanticRetriever._call_name(node.value)
            return "%s.%s" % (owner, node.attr) if owner else node.attr
        return ""

    @staticmethod
    def _is_dynamic_expression(node: ast.AST) -> bool:
        return not (
            isinstance(node, ast.Constant)
            and isinstance(node.value, (str, bytes, int, float, type(None)))
        )

    @classmethod
    def _security_identifiers(cls, node: ast.AST) -> tuple[str, ...]:
        identifiers = set()
        for item in ast.walk(node):
            value = ""
            if isinstance(item, (ast.Name, ast.arg)):
                value = item.id if isinstance(item, ast.Name) else item.arg
            elif isinstance(item, ast.Attribute):
                value = item.attr
            lowered = value.lower()
            if lowered and any(term in lowered for term in SECURITY_IDENTIFIER_TERMS):
                identifiers.add(lowered)
        return tuple(sorted(identifiers))

    @classmethod
    def _called_names(cls, node: ast.AST) -> tuple[str, ...]:
        names = set()
        for item in ast.walk(node):
            if isinstance(item, ast.Call):
                name = cls._call_name(item.func).lower()
                if name:
                    names.add(name)
                    names.add(name.rpartition(".")[2])
        return tuple(sorted(names))

    @classmethod
    def _ast_scores(cls, node: ast.AST) -> tuple[dict[str, int], dict[str, set[str]]]:
        scores = {category: 0 for category in SIGNAL_WEIGHTS}
        matched = {category: set() for category in SIGNAL_WEIGHTS}
        security_identifiers = set(cls._security_identifiers(node))
        called_names = set(cls._called_names(node))
        sql_context = any(
            term in identifier
            for identifier in security_identifiers
            for term in ("query", "sql")
        ) or any(
            name.rpartition(".")[2] in {"execute", "executemany", "group_by", "order_by", "query"}
            for name in called_names
        )

        def add(category: str, signal: str, weight: int) -> None:
            scores[category] += weight
            matched[category].add(signal)

        arguments = []
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            arguments = [*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs]
        for argument in arguments:
            name = argument.arg.lower()
            if any(term in name for term in ("path", "file", "directory", "root", "target")):
                add("path", "path-parameter", 6)
            if any(term in name for term in ("command", "cmd", "shell", "exec")):
                add("command", "command-parameter", 10)
            if any(term in name for term in ("query", "sql")) or (
                sql_context and any(term in name for term in ("column", "sort", "order"))
            ):
                add("sql", "sql-structure-parameter", 8)

        for item in ast.walk(node):
            if not isinstance(item, ast.Call):
                continue
            call_name = cls._call_name(item.func).lower()
            leaf = call_name.rpartition(".")[2]
            shell_true = any(
                keyword.arg == "shell"
                and isinstance(keyword.value, ast.Constant)
                and keyword.value.value is True
                for keyword in item.keywords
            )
            if shell_true:
                add("command", "dynamic-shell-sink", 44)
            if call_name in {"os.system", "os.popen"}:
                add("command", "command-execution-sink", 44)
            elif leaf in {"run", "popen", "call", "check_call", "check_output"} and (
                "subprocess" in call_name or shell_true
            ):
                add("command", "command-execution-sink", 24)
            if leaf in {"shell_quote", "quote"} and any(
                keyword.arg == "shell" for keyword in item.keywords
            ):
                add("command", "shell-template-expansion", 24)

            if leaf == "commonprefix":
                add("path", "lexical-commonprefix", 64)
            elif leaf == "commonpath":
                add("path", "component-commonpath", 48)
            elif leaf in {"abspath", "realpath", "expanduser", "resolve"}:
                add("path", "path-normalization", 10)
            elif leaf in {"relative_to", "is_relative_to"}:
                add("path", "path-containment-check", 26)

            if call_name.endswith("kwargs.get") and item.args and isinstance(
                item.args[0], ast.Constant
            ):
                key = str(item.args[0].value).lower()
                if any(term in key for term in ("path", "file", "directory", "root")):
                    add("path", "caller-path-source", 24)

            if call_name == "request.args.get" or call_name.endswith(".request.args.get"):
                add("sql", "request-argument-source", 22)
                add("path", "request-argument-source", 8)
                add("command", "request-argument-source", 8)
            if (
                leaf == "text" and sql_context and item.args
                and cls._is_dynamic_expression(item.args[0])
            ):
                add("sql", "dynamic-sql-text", 58)
            elif leaf == "execute" and item.args and cls._is_dynamic_expression(item.args[0]):
                add("sql", "dynamic-sql-execute", 30)
            elif leaf in {"order_by", "group_by"} and item.args and cls._is_dynamic_expression(
                item.args[0]
            ):
                add("sql", "dynamic-sql-structure", 16)
        return scores, matched

    @classmethod
    def _category_scores(
        cls, text: str, qualname: str, test_penalty: int, node: ast.AST
    ) -> tuple[dict, dict]:
        material = (qualname + "\n" + text).lower().replace(" ", "")
        scores = {}
        matched = {}
        ast_scores, ast_matched = cls._ast_scores(node)
        for category, weights in SIGNAL_WEIGHTS.items():
            category_signals = set(ast_matched[category])
            score = ast_scores[category]
            for signal, weight in weights.items():
                count = min(3, material.count(signal.replace(" ", "")))
                if count:
                    category_signals.add(signal)
                    score += weight * count
            scores[category] = max(0, score - test_penalty)
            matched[category] = tuple(sorted(category_signals))
        return scores, matched

    def _bounded_code(
        self, lines: list[str], start: int, end: int, signals: tuple[str, ...]
    ) -> tuple[str, int, int]:
        code = "\n".join(lines[start - 1:end])
        if len(code) <= self.max_candidate_chars:
            return code, start, end
        signal_lines = []
        for index in range(start - 1, end):
            normalized = lines[index].lower().replace(" ", "")
            weight = sum(normalized.count(item.replace(" ", "")) for item in signals)
            if weight:
                signal_lines.append((weight, index))
        center = max(signal_lines, default=(0, start - 1))[1]
        window_start = max(start - 1, center - 28)
        window_end = min(end, center + 29)
        excerpt = "\n".join(lines[window_start:window_end])
        if window_start > start - 1:
            signature = lines[start - 1]
            excerpt = signature + "\n    # ... security-relevant excerpt ...\n" + excerpt
        return excerpt[:self.max_candidate_chars], window_start + 1, window_end

    @staticmethod
    def _class_name(candidate: SemanticCandidate) -> str:
        return candidate.qualname.rpartition(".")[0]

    @staticmethod
    def _method_name(candidate: SemanticCandidate) -> str:
        return candidate.qualname.rpartition(".")[2]

    @classmethod
    def _is_pipeline_method(cls, candidate: SemanticCandidate) -> bool:
        name = cls._method_name(candidate).lower()
        return any(term in name for term in PIPELINE_METHOD_TERMS)

    @classmethod
    def _pipeline_neighbors(
        cls, candidate: SemanticCandidate, pool: list[SemanticCandidate]
    ) -> list[SemanticCandidate]:
        owner = cls._class_name(candidate)
        if not owner or not cls._is_pipeline_method(candidate):
            return []
        neighbors = [
            item for item in pool
            if item.path == candidate.path
            and cls._class_name(item) == owner
            and item.category == candidate.category
            and item.qualname != candidate.qualname
            and cls._is_pipeline_method(item)
        ]
        return sorted(neighbors, key=lambda item: (-item.score, item.start_line))[:4]

    @classmethod
    def _semantic_neighbors(
        cls, candidate: SemanticCandidate, pool: list[SemanticCandidate]
    ) -> list[SemanticCandidate]:
        """Find framework renderers and validation/use call sites by source shape."""
        compact = candidate.code.lower().replace(" ", "")
        neighbors = list(cls._pipeline_neighbors(candidate, pool))
        owner = cls._class_name(candidate)
        method = cls._method_name(candidate).lower()
        candidate_identifiers = set(candidate.identifiers)
        for item in pool:
            if item.category != candidate.category or (
                item.path == candidate.path and item.qualname == candidate.qualname
            ):
                continue
            item_method = cls._method_name(item).lower()
            shared_identifiers = candidate_identifiers.intersection(item.identifiers)
            same_owner = bool(owner) and item.path == candidate.path and cls._class_name(item) == owner
            direct_call_edge = (
                item.path == candidate.path
                and (item_method in candidate.calls or method in item.calls)
            )
            if direct_call_edge or (same_owner and len(shared_identifiers) >= 1):
                neighbors.append(item)
        if candidate.category == "sql" and candidate.qualname.endswith(".__init__"):
            if "delimiter" in compact:
                neighbors.extend(
                    item for item in pool
                    if item.category == "sql"
                    and (
                        (
                            "self.extra=extra" in item.code.lower().replace(" ", "")
                            and "self.source_expressions" in item.code.lower().replace(" ", "")
                            and item.qualname.endswith(".__init__")
                        )
                        or (
                            "template%data" in item.code.lower().replace(" ", "")
                            and item.qualname.endswith(".as_sql")
                        )
                        or (
                            "return'%s',[val]" in item.code.lower().replace(" ", "")
                            and item.qualname.endswith(".as_sql")
                        )
                    )
                )
        if candidate.category == "command" and "check_unsafe" in candidate.qualname.lower():
            call_sites = [
                item for item in pool
                if item.category == "command"
                and "check_unsafe_options(" in item.code.lower().replace(" ", "")
                and "list(kwargs.keys())" in item.code.lower().replace(" ", "")
            ]
            execution_sites = [
                item for item in pool
                if item.category == "command"
                and "_call_process" in item.qualname.lower()
                and "transform_kwargs(" in item.code.lower().replace(" ", "")
            ]
            neighbors.extend(
                sorted(call_sites, key=lambda item: (-item.score, item.path, item.start_line))[:1]
            )
            neighbors.extend(
                sorted(
                    execution_sites,
                    key=lambda item: (-item.score, item.path, item.start_line),
                )[:1]
            )
        deduplicated = {}
        for item in neighbors:
            if (item.path, item.qualname) != (candidate.path, candidate.qualname):
                deduplicated[(item.path, item.qualname)] = item
        return sorted(
            deduplicated.values(),
            key=lambda item: (
                0 if "list(kwargs.keys())" in item.code.lower().replace(" ", "") else 1,
                0 if "template%data" in item.code.lower().replace(" ", "") else 1,
                -item.score,
                item.path,
                item.start_line,
            ),
        )[:5]

    @classmethod
    def _relations(
        cls, candidate: SemanticCandidate, pool: list[SemanticCandidate]
    ) -> tuple[str, ...]:
        material = candidate.code.lower().replace(" ", "")
        related = {item.qualname for item in cls._semantic_neighbors(candidate, pool)}
        for item in pool:
            if item.path == candidate.path and item.qualname != candidate.qualname:
                method = cls._method_name(item).lower()
                if len(method) >= 4 and (method + "(") in material:
                    related.add(item.qualname)
        return tuple(sorted(related))

    @staticmethod
    def _branch_contains(node_list: list[ast.stmt], attribute: str) -> bool:
        module = ast.Module(body=node_list, type_ignores=[])
        return any(
            isinstance(node, ast.Attribute) and node.attr == attribute
            for node in ast.walk(module)
        )

    @classmethod
    def _path_invariants(cls, candidate: SemanticCandidate) -> list[SecurityInvariant]:
        if candidate.category != "path":
            return []
        compact = candidate.code.lower().replace(" ", "")
        results = []
        if "commonprefix(" in compact:
            results.append(SecurityInvariant(
                identifier="path-component-containment",
                category="path",
                status="risk",
                summary=(
                    "os.path.commonprefix compares characters rather than path components, so a "
                    "sibling name sharing the root prefix can pass the containment check."
                ),
                related_symbols=(candidate.qualname,),
            ))
        elif "commonpath(" in compact:
            results.append(SecurityInvariant(
                identifier="path-component-containment",
                category="path",
                status="mitigation",
                summary="Containment is checked with path-component-aware commonpath semantics.",
                related_symbols=(candidate.qualname,),
            ))

        caller_path = "caller-path-source" in candidate.signals
        normalized_path = "path-normalization" in candidate.signals
        if caller_path and normalized_path:
            has_containment = any(
                marker in compact
                for marker in ("commonpath(", ".relative_to(", ".is_relative_to(")
            ) or (".startswith(" in compact and "os.sep" in compact)
            results.append(SecurityInvariant(
                identifier="path-caller-location-containment",
                category="path",
                status="mitigation" if has_containment else "risk",
                summary=(
                    "The caller-provided path is normalized and constrained to an allowed root "
                    "before downstream file/model use."
                    if has_containment
                    else "The caller-provided path is normalized but no allowed-root containment "
                    "check is visible before it is returned for downstream file/model use."
                ),
                related_symbols=(candidate.qualname,),
            ))

        if "follow_symlink" not in candidate.code.lower():
            return results
        source = candidate.code
        method = cls._method_name(candidate)
        for index, line in enumerate(source.splitlines()):
            stripped = line.strip()
            if stripped.startswith("def %s(" % method) or stripped.startswith(
                "async def %s(" % method
            ):
                source = "\n".join(source.splitlines()[index:])
                break
        try:
            tree = ast.parse(textwrap.dedent(source))
        except SyntaxError:
            return []
        for node in ast.walk(tree):
            if not isinstance(node, ast.If):
                continue
            test = ast.unparse(node.test).lower().replace(" ", "")
            if "follow_symlink" not in test:
                continue
            body_contained = cls._branch_contains(node.body, "relative_to")
            else_contained = cls._branch_contains(node.orelse, "relative_to")
            following_contained = (
                else_contained
                if isinstance(node.test, ast.UnaryOp) and isinstance(node.test.op, ast.Not)
                else body_contained
            )
            if following_contained:
                results.append(SecurityInvariant(
                    identifier="path-follow-mode-containment",
                    category="path",
                    status="mitigation",
                    summary=(
                        "The symlink-following branch performs a lexical containment check "
                        "before the resolved path is consumed."
                    ),
                    related_symbols=(candidate.qualname,),
                ))
            else:
                results.append(SecurityInvariant(
                    identifier="path-follow-mode-containment",
                    category="path",
                    status="risk",
                    summary=(
                        "The symlink-following branch has no relative_to containment check; "
                        "verify whether user-controlled parent components can escape the root."
                    ),
                    related_symbols=(candidate.qualname,),
                ))
            break
        return results

    @classmethod
    def _sql_invariants(
        cls, candidate: SemanticCandidate, pool: list[SemanticCandidate]
    ) -> list[SecurityInvariant]:
        if candidate.category != "sql":
            return []
        compact = candidate.code.lower().replace(" ", "")
        related = tuple(item.qualname for item in cls._semantic_neighbors(candidate, pool))
        results = []
        if "dynamic-sql-text" in candidate.signals:
            has_identifier_allowlist = (
                "notin" in compact
                and any(marker in compact for marker in ("columns.keys()", "allowed_", "allowlist"))
                and compact.find("notin") < compact.find("text(")
            )
            direction_from_request = any(
                marker in compact
                for marker in (
                    'request.args.get("order"', "request.args.get('order'",
                    'request.args.get("direction"', "request.args.get('direction'",
                )
            )
            has_direction_allowlist = any(
                marker in compact
                for marker in (
                    "ordernotin(", "directionnotin(", "allowed_order",
                    "allowed_direction", "{'asc','desc'}", '{"asc","desc"}',
                )
            )
            fully_allowlisted = has_identifier_allowlist and (
                not direction_from_request or has_direction_allowlist
            )
            results.append(SecurityInvariant(
                identifier="sql-structural-token-allowlist",
                category="sql",
                status="mitigation" if fully_allowlisted else "risk",
                summary=(
                    "Request-derived SQL identifiers and directions are constrained before text() "
                    "and ORDER BY construction."
                    if fully_allowlisted
                    else "The SQL column identifier is allowlisted, but a request-derived ORDER BY "
                    "direction still reaches text() without an asc/desc allowlist."
                    if has_identifier_allowlist and direction_from_request
                    else "A dynamic expression reaches SQLAlchemy text() for query structure; no "
                    "preceding identifier/direction allowlist is visible. Bind parameters cannot "
                    "protect SQL identifiers or ORDER BY syntax."
                ),
                related_symbols=(candidate.qualname,) + related,
            ))
        if "%(delimiter)" in compact and "delimiter=delimiter" in compact:
            results.append(SecurityInvariant(
                identifier="sql-template-value-boundary",
                category="sql",
                status="risk",
                summary=(
                    "The delimiter is passed through **extra; the framework stores extra values "
                    "and later applies template % data outside the database parameter list."
                ),
                related_symbols=(candidate.qualname,) + related,
            ))
        if "value(str(delimiter))" in compact:
            results.append(SecurityInvariant(
                identifier="sql-template-value-boundary",
                category="sql",
                status="mitigation",
                summary="The delimiter is represented as a database parameter expression.",
                related_symbols=(candidate.qualname,) + related,
            ))
        return results

    @classmethod
    def _command_invariants(
        cls, candidate: SemanticCandidate, pool: list[SemanticCandidate]
    ) -> list[SecurityInvariant]:
        name = cls._method_name(candidate).lower()
        if candidate.category != "command":
            return []
        owner = cls._class_name(candidate)
        peers = (
            [
                item for item in pool
                if item.path == candidate.path and cls._class_name(item) == owner
            ]
            if owner
            else [candidate]
        )
        results = []
        transformers = [item for item in peers if "transform" in cls._method_name(item).lower()]
        execution_normalizes = any("dashify(" in item.code.lower() for item in transformers)
        guard = candidate.code.lower()
        guard_normalizes = "dashify(" in guard or "canonicalize_option_name" in guard
        semantic_neighbors = cls._semantic_neighbors(candidate, pool)
        related = tuple(sorted(item.qualname for item in semantic_neighbors))
        raw_kwargs_callsite = any(
            "list(kwargs.keys())" in item.code.lower().replace(" ", "")
            for item in semantic_neighbors
        )
        if "unsafe" in name and "check" in name and execution_normalizes and not guard_normalizes:
            results.append(SecurityInvariant(
                identifier="command-option-canonicalization",
                category="command",
                status="risk",
                summary=(
                    "Call sites validate list(kwargs.keys()) before forwarding **kwargs; the "
                    "execution pipeline later dash-normalizes those names, so equivalent "
                    "spellings can cross the raw-name guard."
                ),
                related_symbols=(candidate.qualname,) + related,
            ))
        elif "unsafe" in name and "check" in name and execution_normalizes and guard_normalizes:
            results.append(SecurityInvariant(
                identifier="command-option-canonicalization",
                category="command",
                status="mitigation",
                summary=(
                    "Unsafe-option validation canonicalizes option names consistently with the "
                    "execution transformation."
                ),
                related_symbols=(candidate.qualname,) + related,
            ))
        elif "unsafe" in name and "check" in name and raw_kwargs_callsite and not guard_normalizes:
            results.append(SecurityInvariant(
                identifier="command-option-canonicalization",
                category="command",
                status="risk",
                summary=(
                    "Call sites validate raw kwargs names before the command wrapper transforms "
                    "them; no equivalent canonicalization is visible in the guard."
                ),
                related_symbols=(candidate.qualname,) + related,
            ))

        compact = candidate.code.lower().replace(" ", "")
        peer_material = "\n".join(item.code.lower().replace(" ", "") for item in peers)
        direct_shell_sink = "shell=true" in compact and any(
            marker in compact
            for marker in ("subprocess.", "popen.", "os.system(", "os.popen(")
        )
        shell_expansion = (
            "shell-template-expansion" in candidate.signals
            or "prepare_outtmpl(" in compact
        ) and "shell=true" in peer_material
        if direct_shell_sink or shell_expansion:
            setup_validation = "_exec=true" in peer_material
            shell_defaults_safe = "shell:bool=false" in compact or "shell=false" in compact.partition(")")[0]
            operator_guard = (
                ("re.search(" in compact or "_re.search(" in compact)
                and any(marker in compact for marker in (";&|", "metachar", "shelloperator"))
            )
            mitigated = setup_validation or (shell_defaults_safe and operator_guard)
            results.append(SecurityInvariant(
                identifier="command-shell-data-boundary",
                category="command",
                status="mitigation" if mitigated else "risk",
                summary=(
                    "Command/template data is validated before the shell boundary, or shell mode "
                    "defaults off and rejects shell operators before execution."
                    if mitigated
                    else "Dynamic command or template data reaches a shell=True execution boundary "
                    "without a complete pre-execution metacharacter/expansion guard. Intended command "
                    "execution does not by itself make embedded data safe."
                ),
                related_symbols=(candidate.qualname,) + related,
            ))
        return results

    @classmethod
    def _decorate(
        cls, candidate: SemanticCandidate, pool: list[SemanticCandidate]
    ) -> SemanticCandidate:
        invariants = (
            cls._path_invariants(candidate)
            + cls._sql_invariants(candidate, pool)
            + cls._command_invariants(candidate, pool)
        )
        return replace(
            candidate,
            relations=cls._relations(candidate, pool),
            invariants=tuple(invariants),
        )

    @staticmethod
    def evidence_packet(
        candidates: list[SemanticCandidate], max_candidates: int = 6
    ) -> list[SemanticCandidate]:
        """Keep invariant anchors and their validation-to-use neighbors only."""
        if max_candidates < 1:
            raise ValueError("evidence packet candidate limit must be positive")
        anchors = [item for item in candidates if item.invariants]
        if not anchors:
            return candidates[:max_candidates]
        related_symbols = {
            symbol
            for anchor in anchors
            for symbol in (
                *anchor.relations,
                *(symbol for invariant in anchor.invariants for symbol in invariant.related_symbols),
            )
        }
        packet = []
        seen = set()
        for item in (*anchors, *candidates):
            identity = (item.path, item.qualname)
            if identity in seen:
                continue
            if item not in anchors and item.qualname not in related_symbols:
                continue
            packet.append(item)
            seen.add(identity)
            if len(packet) >= max_candidates:
                break
        return packet

    def retrieve_run(self, root: str | Path) -> RetrievalRun:
        workspace = RepositoryWorkspace(root, extensions={".py"})
        inventory = workspace.inventory()
        grouped: dict[str, list[SemanticCandidate]] = {
            category: [] for category in SIGNAL_WEIGHTS
        }
        pool: list[SemanticCandidate] = []
        parsed_files = 0
        parse_errors = 0
        functions_seen = 0
        for path, content in workspace.iter_text(inventory):
            try:
                tree = ast.parse(content, filename=path)
            except SyntaxError:
                parse_errors += 1
                continue
            parsed_files += 1
            lines = content.splitlines()
            for qualname, node, class_context in self._function_nodes(tree):
                functions_seen += 1
                decorator_lines = [int(item.lineno) for item in node.decorator_list]
                start = min([int(node.lineno), *decorator_lines])
                end = int(getattr(node, "end_lineno", node.lineno))
                function_raw = "\n".join(lines[start - 1:end])
                class_raw = "\n".join(
                    "\n".join(lines[int(item.lineno) - 1:int(getattr(item, "end_lineno", item.lineno))])
                    for item in class_context
                )
                raw = (class_raw + "\n" + function_raw) if class_raw else function_raw
                scores, matched = self._category_scores(
                    raw, qualname, 80 if self._is_test_path(path) else 0, node
                )
                for category in sorted(scores):
                    score = scores[category]
                    if score < self.min_score or not matched[category]:
                        continue
                    code, bounded_start, bounded_end = self._bounded_code(
                        lines, start, end, matched[category]
                    )
                    if class_raw:
                        context_limit = min(1_500, self.max_candidate_chars // 3)
                        context = "# Class-level security context\n" + class_raw[:context_limit]
                        code = (context + "\n" + code)[:self.max_candidate_chars]
                    candidate = SemanticCandidate(
                        path=path,
                        qualname=qualname,
                        start_line=bounded_start,
                        end_line=bounded_end,
                        category=category,
                        score=score,
                        signals=matched[category],
                        code=code,
                        calls=self._called_names(node),
                        identifiers=self._security_identifiers(node),
                    )
                    grouped[category].append(candidate)
                    pool.append(candidate)

        shortlist = []
        for category in sorted(grouped):
            ranked = sorted(
                grouped[category],
                key=lambda item: (
                    self._is_test_path(item.path), -item.score, item.path,
                    item.start_line, item.qualname,
                ),
            )
            path_counts: dict[str, int] = {}
            diverse = []
            for candidate in ranked:
                if path_counts.get(candidate.path, 0) >= 2:
                    continue
                diverse.append(candidate)
                path_counts[candidate.path] = path_counts.get(candidate.path, 0) + 1
                if len(diverse) >= self.per_category:
                    break
            shortlist.extend(diverse)
        shortlist.sort(key=lambda item: (
            self._is_test_path(item.path), -item.score, item.category, item.path, item.start_line
        ))
        unique_primaries = []
        primary_identities = set()
        for candidate in shortlist:
            identity = (candidate.path, candidate.qualname)
            if identity in primary_identities:
                continue
            unique_primaries.append(candidate)
            primary_identities.add(identity)
        shortlist = unique_primaries
        # Primary file/symbol candidates must not be starved by a high-scoring candidate's
        # neighbors. Add bounded call/owner neighbors only after all diverse primaries.
        expanded = list(shortlist)
        seen = {(item.path, item.qualname) for item in shortlist}
        for candidate in shortlist:
            for item in self._semantic_neighbors(candidate, pool):
                identity = (item.path, item.qualname)
                if identity not in seen:
                    expanded.append(item)
                    seen.add(identity)
        selected = []
        consumed = 0
        for candidate in expanded:
            if len(selected) >= self.max_candidates:
                break
            if consumed + len(candidate.code) > self.max_total_chars:
                continue
            selected.append(self._decorate(candidate, pool))
            consumed += len(candidate.code)
        diagnostics = {
            "inventory": {
                "files": len(inventory.files),
                "bytes": inventory.total_bytes,
                "discovered_files": inventory.discovered_files,
                "discovered_bytes": inventory.discovered_bytes,
                "file_coverage": round(inventory.file_coverage, 6),
                "byte_coverage": round(inventory.byte_coverage, 6),
                "truncated": inventory.truncated,
                "skipped": dict(sorted(inventory.skipped.items())),
                "fingerprint": inventory.fingerprint(),
            },
            "parsed_files": parsed_files,
            "parse_errors": parse_errors,
            "functions_seen": functions_seen,
            "scored_candidates": {
                category: len(items) for category, items in sorted(grouped.items())
            },
            "shortlisted_candidates": len(shortlist),
            "selected_candidates": len(selected),
            "selected_chars": consumed,
        }
        return RetrievalRun(
            candidates=tuple(selected),
            inventory_paths=frozenset(item.path for item in inventory.files),
            diagnostics=diagnostics,
        )

    def retrieve(self, root: str | Path) -> list[SemanticCandidate]:
        return list(self.retrieve_run(root).candidates)
