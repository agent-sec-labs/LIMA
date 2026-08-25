"""Bounded repository-level source-to-sink analysis for Python projects."""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from pathlib import PurePosixPath

from .models import EvidenceRecord, Finding, Severity


STRICT_SANITIZERS = {
    "bool",
    "decimal.Decimal",
    "float",
    "int",
    "ipaddress.ip_address",
    "uuid.UUID",
}
TAINT_PRESERVING_CALLS = {
    "Path",
    "PurePath",
    "builtins.bytearray",
    "builtins.bytes",
    "builtins.dict",
    "builtins.list",
    "builtins.repr",
    "builtins.set",
    "builtins.str",
    "builtins.tuple",
    "bytearray",
    "bytes",
    "dict",
    "list",
    "ntpath.join",
    "os.path.join",
    "pathlib.Path",
    "pathlib.PurePath",
    "posixpath.join",
    "repr",
    "set",
    "str",
    "tuple",
}
TAINT_PRESERVING_METHODS = {
    "casefold",
    "decode",
    "encode",
    "format",
    "format_map",
    "join",
    "lower",
    "lstrip",
    "replace",
    "rstrip",
    "strip",
    "upper",
}
ENDPOINT_DECORATORS = {
    "route",
    "api_route",
    "get",
    "post",
    "put",
    "patch",
    "delete",
    "websocket",
}
DIRECT_SOURCE_CALLS = {
    "input": "console input",
    "builtins.input": "console input",
    "os.getenv": "environment variable",
}
REQUEST_SOURCE_SUFFIXES = {
    "args.get": "request query parameter",
    "form.get": "request form field",
    "values.get": "request value",
    "cookies.get": "request cookie",
    "headers.get": "request header",
    "GET.get": "request query parameter",
    "POST.get": "request form field",
    "get_json": "request JSON body",
}
REQUEST_SOURCE_ATTRIBUTES = {
    "data": "request body",
    "json": "request JSON body",
    "body": "request body",
    "stream": "request stream",
}


def _call_name(node: ast.AST) -> str:
    parts: list[str] = []
    current = node
    while isinstance(current, ast.Attribute):
        parts.append(current.attr)
        current = current.value
    if isinstance(current, ast.Name):
        parts.append(current.id)
    return ".".join(reversed(parts))


@dataclass(frozen=True)
class FlowStep:
    path: str
    line: int
    kind: str
    snippet: str


@dataclass
class TaintTrace:
    label: str
    steps: list[FlowStep] = field(default_factory=list)

    def extended(self, step: FlowStep) -> "TaintTrace":
        values = list(self.steps)
        identity = (step.path, step.line, step.kind, step.snippet)
        if identity not in {
            (item.path, item.line, item.kind, item.snippet) for item in values
        }:
            values.append(step)
        return TaintTrace(self.label, values[-12:])

    @classmethod
    def merge(cls, traces: list["TaintTrace"]) -> "TaintTrace | None":
        traces = [item for item in traces if item is not None]
        if not traces:
            return None
        steps: list[FlowStep] = []
        seen = set()
        labels = []
        for trace in traces:
            if trace.label not in labels:
                labels.append(trace.label)
            for step in trace.steps:
                identity = (step.path, step.line, step.kind, step.snippet)
                if identity not in seen:
                    steps.append(step)
                    seen.add(identity)
        return cls(" + ".join(labels[:3]), steps[-12:])


@dataclass
class PythonDataflowResult:
    findings: list[Finding] = field(default_factory=list)
    parse_error: str = ""
    functions_indexed: int = 0
    interprocedural_edges: int = 0
    truncated_calls: int = 0
    unresolved_calls: int = 0
    modules_indexed: int = 0
    cross_file_edges: int = 0
    dynamic_import_sites: int = 0
    ambiguous_modules: int = 0
    parse_errors: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class ModuleInfo:
    name: str
    path: str
    tree: ast.Module
    lines: tuple[str, ...]
    is_package: bool


@dataclass(frozen=True)
class FunctionSymbol:
    key: str
    module: str
    name: str
    path: str
    node: ast.FunctionDef | ast.AsyncFunctionDef


@dataclass(frozen=True)
class Sink:
    rule_id: str
    cwe: str
    severity: Severity
    title: str
    explanation: str
    fix: str
    test: str
    argument: ast.AST


class PythonDataflowAnalyzer:
    """Track untrusted values through direct statically resolved project calls."""

    def __init__(self, max_call_depth: int = 4) -> None:
        if max_call_depth < 1:
            raise ValueError("max_call_depth must be at least 1")
        self.max_call_depth = max_call_depth

    @staticmethod
    def _module_name(path: str) -> tuple[str, bool]:
        normalized = path.replace("\\", "/").lstrip("./")
        pure = PurePosixPath(normalized)
        parts = list(pure.parts)
        is_package = bool(parts and parts[-1] == "__init__.py")
        if is_package:
            parts = parts[:-1]
        elif parts:
            parts[-1] = PurePosixPath(parts[-1]).stem
        return (".".join(parts) or "__root__", is_package)

    def analyze(self, path: str, content: str) -> PythonDataflowResult:
        return self.analyze_project({path: content})

    def analyze_project(self, files: dict[str, str]) -> PythonDataflowResult:
        self.findings: list[Finding] = []
        self.seen: set[tuple[str, str, int]] = set()
        self.modules: dict[str, ModuleInfo] = {}
        self.module_functions: dict[str, dict[str, FunctionSymbol]] = {}
        self.function_aliases: dict[str, dict[str, FunctionSymbol]] = {}
        self.module_aliases: dict[str, dict[str, str]] = {}
        self.symbol_by_node: dict[int, FunctionSymbol] = {}
        self.node_modules: dict[int, ModuleInfo] = {}
        self.call_shadowed_names: dict[int, frozenset[str]] = {}
        self.call_stack: list[str] = []
        self.return_collectors: list[list[TaintTrace]] = []
        self.call_cache: dict[tuple, TaintTrace | None] = {}
        self.call_edges: set[tuple[str, str, str, int]] = set()
        self.cross_file_call_edges: set[tuple[str, str, str, int]] = set()
        self.truncated_calls = 0
        self.unresolved_call_sites: set[tuple[str, int, str]] = set()
        self.dynamic_import_sites: set[tuple[str, int]] = set()
        parse_errors: dict[str, str] = {}
        module_candidates: dict[str, list[ModuleInfo]] = {}

        for path, content in sorted(files.items()):
            try:
                tree = ast.parse(content, filename=path)
            except SyntaxError as exc:
                parse_errors[path] = "%s:%s: %s" % (
                    path, exc.lineno or 0, exc.msg
                )
                continue
            module_name, is_package = self._module_name(path)
            info = ModuleInfo(
                module_name, path, tree, tuple(content.splitlines()), is_package
            )
            module_candidates.setdefault(module_name, []).append(info)

        ambiguous_modules = {
            name for name, candidates in module_candidates.items()
            if len(candidates) > 1
        }
        self.modules = {
            name: candidates[0] for name, candidates in module_candidates.items()
            if len(candidates) == 1
        }
        for module, info in self.modules.items():
            for node in ast.walk(info.tree):
                self.node_modules[id(node)] = info
                if (
                    isinstance(node, ast.Call)
                    and _call_name(node.func) in {"__import__", "importlib.import_module"}
                ):
                    self.dynamic_import_sites.add(
                        (info.path, int(getattr(node, "lineno", 0)))
                    )
            functions: dict[str, FunctionSymbol] = {}
            for item in info.tree.body:
                if not isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    continue
                symbol = FunctionSymbol(
                    "%s:%s" % (module, item.name), module, item.name,
                    info.path, item,
                )
                functions[item.name] = symbol
                self.symbol_by_node[id(item)] = symbol
            self.module_functions[module] = functions

        self._index_imports()
        self._index_shadowed_names()
        for info in sorted(self.modules.values(), key=lambda item: item.path):
            self._process_block(info.tree.body, {})

        first_error = next(iter(parse_errors.values()), "")
        return PythonDataflowResult(
            findings=self.findings,
            parse_error=first_error,
            parse_errors=parse_errors,
            functions_indexed=sum(len(item) for item in self.module_functions.values()),
            interprocedural_edges=len(self.call_edges),
            truncated_calls=self.truncated_calls,
            unresolved_calls=len(self.unresolved_call_sites),
            modules_indexed=len(self.modules),
            cross_file_edges=len(self.cross_file_call_edges),
            dynamic_import_sites=len(self.dynamic_import_sites),
            ambiguous_modules=len(ambiguous_modules),
        )

    def _context(self, node: ast.AST) -> ModuleInfo:
        return self.node_modules[id(node)]

    def _resolve_from_module(
        self, current: ModuleInfo, imported: str | None, level: int
    ) -> str:
        if level <= 0:
            return imported or ""
        package = current.name if current.is_package else current.name.rpartition(".")[0]
        parts = [item for item in package.split(".") if item]
        remove = max(0, level - 1)
        if remove:
            parts = parts[:-remove] if remove <= len(parts) else []
        if imported:
            parts.extend(item for item in imported.split(".") if item)
        return ".".join(parts)

    def _index_imports(self) -> None:
        for module, info in self.modules.items():
            module_aliases: dict[str, str] = {}
            function_aliases: dict[str, FunctionSymbol] = {}
            for statement in info.tree.body:
                if isinstance(statement, ast.Import):
                    for alias in statement.names:
                        if alias.name not in self.modules:
                            continue
                        if alias.asname:
                            module_aliases[alias.asname] = alias.name
                elif isinstance(statement, ast.ImportFrom):
                    target = self._resolve_from_module(
                        info, statement.module, statement.level
                    )
                    for alias in statement.names:
                        if alias.name == "*":
                            continue
                        local_name = alias.asname or alias.name
                        direct = self.module_functions.get(target, {}).get(alias.name)
                        submodule = "%s.%s" % (target, alias.name) if target else alias.name
                        if direct and submodule not in self.modules:
                            function_aliases[local_name] = direct
                        elif submodule in self.modules and direct is None:
                            module_aliases[local_name] = submodule
            self.module_aliases[module] = module_aliases
            self.function_aliases[module] = function_aliases

    @staticmethod
    def _argument_names(node: ast.FunctionDef | ast.AsyncFunctionDef) -> set[str]:
        values = {
            item.arg for item in [
                *node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs,
            ]
        }
        if node.args.vararg:
            values.add(node.args.vararg.arg)
        if node.args.kwarg:
            values.add(node.args.kwarg.arg)
        return values

    def _index_shadowed_names(self) -> None:
        analyzer = self

        class BindingCollector(ast.NodeVisitor):
            def __init__(inner) -> None:
                inner.store_names: set[str] = set()
                inner.definition_names: set[str] = set()
                inner.import_names: set[str] = set()

            def visit_Name(inner, node: ast.Name) -> None:
                if isinstance(node.ctx, ast.Store):
                    inner.store_names.add(node.id)

            def visit_FunctionDef(inner, node: ast.FunctionDef) -> None:
                inner.definition_names.add(node.name)

            def visit_AsyncFunctionDef(inner, node: ast.AsyncFunctionDef) -> None:
                inner.definition_names.add(node.name)

            def visit_ClassDef(inner, node: ast.ClassDef) -> None:
                inner.definition_names.add(node.name)

            def visit_Lambda(inner, node: ast.Lambda) -> None:
                return

            def visit_Import(inner, node: ast.Import) -> None:
                for alias in node.names:
                    inner.import_names.add(alias.asname or alias.name.split(".")[0])

            def visit_ImportFrom(inner, node: ast.ImportFrom) -> None:
                for alias in node.names:
                    if alias.name != "*":
                        inner.import_names.add(alias.asname or alias.name)

        class CallCollector(ast.NodeVisitor):
            def __init__(inner) -> None:
                inner.calls: list[ast.Call] = []

            def visit_Call(inner, node: ast.Call) -> None:
                inner.calls.append(node)
                inner.generic_visit(node)

            def visit_FunctionDef(inner, node: ast.FunctionDef) -> None:
                return

            def visit_AsyncFunctionDef(inner, node: ast.AsyncFunctionDef) -> None:
                return

            def visit_ClassDef(inner, node: ast.ClassDef) -> None:
                return

            def visit_Lambda(inner, node: ast.Lambda) -> None:
                return

        def register_scope(
            statements: list[ast.stmt], initial: set[str],
            supported_import_names: set[str],
            supported_definition_names: set[str] | None = None,
        ) -> None:
            bindings = BindingCollector()
            calls = CallCollector()
            for statement in statements:
                bindings.visit(statement)
                calls.visit(statement)
            shadowed = frozenset(
                initial
                | bindings.store_names
                | (
                    bindings.definition_names
                    - set(supported_definition_names or ())
                )
                | (bindings.import_names - supported_import_names)
            )
            for call in calls.calls:
                analyzer.call_shadowed_names[id(call)] = shadowed
            for statement in statements:
                for node in ast.walk(statement):
                    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        nested_supported = set()
                        nested_bindings = (
                            set(shadowed) | analyzer._argument_names(node)
                        )
                        register_scope(
                            node.body, nested_bindings, nested_supported, set()
                        )

        for module, info in self.modules.items():
            supported = (
                set(self.module_aliases.get(module, {}))
                | set(self.function_aliases.get(module, {}))
            )
            register_scope(
                info.tree.body, set(), supported,
                set(self.module_functions.get(module, {})),
            )

    def _resolve_call(self, node: ast.Call) -> FunctionSymbol | None:
        context = self._context(node)
        functions = self.module_functions.get(context.name, {})
        shadowed = self.call_shadowed_names.get(id(node), frozenset())
        if isinstance(node.func, ast.Name):
            if node.func.id in shadowed:
                return None
            return (
                functions.get(node.func.id)
                or self.function_aliases.get(context.name, {}).get(node.func.id)
            )
        if not isinstance(node.func, ast.Attribute):
            return None
        call_name = _call_name(node.func)
        prefix, separator, function_name = call_name.rpartition(".")
        if not separator:
            return None
        first, dot, remainder = prefix.partition(".")
        if first in shadowed:
            return None
        target_module = prefix if prefix in self.modules else ""
        alias_target = self.module_aliases.get(context.name, {}).get(first)
        if alias_target:
            target_module = alias_target + (("." + remainder) if dot else "")
        return self.module_functions.get(target_module, {}).get(function_name)

    def _snippet(self, node: ast.AST) -> str:
        context = self._context(node)
        line = max(1, int(getattr(node, "lineno", 1)))
        return context.lines[line - 1].strip()[:240] if line <= len(context.lines) else ""

    def _step(self, node: ast.AST, kind: str) -> FlowStep:
        context = self._context(node)
        return FlowStep(
            context.path, max(1, int(getattr(node, "lineno", 1))),
            kind, self._snippet(node),
        )

    def _source(self, node: ast.AST, label: str) -> TaintTrace:
        return TaintTrace(label, [self._step(node, "taint-source")])

    @staticmethod
    def _is_request_name(name: str) -> bool:
        return name == "request" or ".request." in "." + name + "." or name.startswith("request.")

    def _direct_source(self, node: ast.AST) -> TaintTrace | None:
        if isinstance(node, ast.Call):
            name = _call_name(node.func)
            if name in DIRECT_SOURCE_CALLS:
                return self._source(node, DIRECT_SOURCE_CALLS[name])
            if self._is_request_name(name):
                for suffix, label in REQUEST_SOURCE_SUFFIXES.items():
                    if name.endswith(suffix):
                        return self._source(node, label)
        if isinstance(node, ast.Subscript):
            name = _call_name(node.value)
            if name == "sys.argv":
                return self._source(node, "command-line argument")
            if name in {"os.environ", "request.args", "request.form", "request.values",
                        "request.cookies", "request.headers", "request.GET", "request.POST"}:
                return self._source(node, "untrusted mapping value")
        if isinstance(node, ast.Attribute):
            name = _call_name(node)
            if self._is_request_name(name):
                for suffix, label in REQUEST_SOURCE_ATTRIBUTES.items():
                    if name.endswith("." + suffix):
                        return self._source(node, label)
        return None

    def _expr_taint(
        self, node: ast.AST | None, environment: dict[str, TaintTrace]
    ) -> TaintTrace | None:
        if node is None:
            return None
        if isinstance(node, ast.Call):
            symbol = self._resolve_call(node)
            if symbol:
                return self._analyze_indexed_call(node, symbol, environment)
        direct = self._direct_source(node)
        if direct:
            return direct
        if isinstance(node, ast.Name):
            return environment.get(node.id)
        if isinstance(node, ast.Call):
            name = _call_name(node.func)
            if name in STRICT_SANITIZERS:
                return None
            traces = [self._expr_taint(item, environment) for item in node.args]
            traces.extend(
                self._expr_taint(item.value, environment) for item in node.keywords
            )
            receiver_trace = None
            if isinstance(node.func, ast.Attribute):
                receiver_trace = self._expr_taint(node.func.value, environment)
                traces.append(receiver_trace)
            merged = TaintTrace.merge(traces)
            if self._sink(node):
                return merged
            if (
                name in TAINT_PRESERVING_CALLS
                or (
                    isinstance(node.func, ast.Attribute)
                    and node.func.attr in TAINT_PRESERVING_METHODS
                )
            ):
                return merged
            if merged:
                context = self._context(node)
                self.unresolved_call_sites.add(
                    (
                        context.path, int(getattr(node, "lineno", 0)),
                        name or "<dynamic-call>",
                    )
                )
            return None
        if isinstance(node, ast.Attribute):
            return self._expr_taint(node.value, environment)
        if isinstance(node, ast.Subscript):
            return TaintTrace.merge([
                self._expr_taint(node.value, environment),
                self._expr_taint(node.slice, environment),
            ])
        if isinstance(node, ast.JoinedStr):
            return TaintTrace.merge([
                self._expr_taint(item.value, environment)
                for item in node.values if isinstance(item, ast.FormattedValue)
            ])
        if isinstance(node, ast.BinOp):
            return TaintTrace.merge([
                self._expr_taint(node.left, environment),
                self._expr_taint(node.right, environment),
            ])
        if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            return TaintTrace.merge([
                self._expr_taint(item, environment) for item in node.elts
            ])
        if isinstance(node, ast.Dict):
            return TaintTrace.merge([
                self._expr_taint(item, environment)
                for item in [*node.keys, *node.values] if item is not None
            ])
        if isinstance(node, ast.IfExp):
            return TaintTrace.merge([
                self._expr_taint(node.body, environment),
                self._expr_taint(node.orelse, environment),
            ])
        if isinstance(node, (ast.BoolOp, ast.Compare)):
            return TaintTrace.merge([
                self._expr_taint(item, environment)
                for item in ast.iter_child_nodes(node)
            ])
        if isinstance(node, (ast.UnaryOp, ast.Await, ast.Yield, ast.YieldFrom)):
            return self._expr_taint(getattr(node, "operand", None) or getattr(node, "value", None), environment)
        return None

    @staticmethod
    def _trace_signature(trace: TaintTrace | None) -> tuple:
        if trace is None:
            return ()
        return (
            trace.label,
            tuple(
                (item.path, item.line, item.kind, item.snippet)
                for item in trace.steps
            ),
        )

    def _bound_call_environment(
        self,
        call: ast.Call,
        symbol: FunctionSymbol,
        caller_environment: dict[str, TaintTrace],
    ) -> dict[str, TaintTrace]:
        function = symbol.node
        positional_parameters = [*function.args.posonlyargs, *function.args.args]
        keyword_parameters = {
            item.arg: item for item in [*positional_parameters, *function.args.kwonlyargs]
        }
        bound: dict[str, list[TaintTrace]] = {}

        def bind(parameter: ast.arg | None, trace: TaintTrace | None) -> None:
            if parameter is None or trace is None:
                return
            edge_kind = (
                "cross-file-call-edge"
                if self._context(call).name != symbol.module else "call-edge"
            )
            enriched = trace.extended(self._step(call, edge_kind))
            enriched = enriched.extended(self._step(parameter, "callee-parameter"))
            bound.setdefault(parameter.arg, []).append(enriched)

        for index, argument in enumerate(call.args):
            trace = self._expr_taint(argument, caller_environment)
            if isinstance(argument, ast.Starred):
                bind(function.args.vararg, trace)
            elif index < len(positional_parameters):
                bind(positional_parameters[index], trace)
            else:
                bind(function.args.vararg, trace)

        for keyword in call.keywords:
            trace = self._expr_taint(keyword.value, caller_environment)
            if keyword.arg is None:
                bind(function.args.kwarg, trace)
            else:
                bind(keyword_parameters.get(keyword.arg) or function.args.kwarg, trace)

        result: dict[str, TaintTrace] = {}
        for name, traces in bound.items():
            merged = TaintTrace.merge(traces)
            if merged:
                result[name] = merged
        return result

    def _analyze_indexed_call(
        self,
        call: ast.Call,
        symbol: FunctionSymbol,
        caller_environment: dict[str, TaintTrace],
    ) -> TaintTrace | None:
        function = symbol.node
        bound = self._bound_call_environment(call, symbol, caller_environment)
        signature = tuple(
            (name, self._trace_signature(trace)) for name, trace in sorted(bound.items())
        )
        cache_key = (id(call), symbol.key, signature)
        context = self._context(call)
        caller = self.call_stack[-1] if self.call_stack else "<module:%s>" % context.name
        edge = (caller, symbol.key, context.path, int(getattr(call, "lineno", 0)))
        self.call_edges.add(edge)
        if context.name != symbol.module:
            self.cross_file_call_edges.add(edge)
        if cache_key in self.call_cache:
            return self.call_cache[cache_key]
        if symbol.key in self.call_stack or len(self.call_stack) >= self.max_call_depth:
            self.truncated_calls += 1
            self.call_cache[cache_key] = None
            return None

        self.call_stack.append(symbol.key)
        self.return_collectors.append([])
        try:
            self._process_block(function.body, bound)
            returned = TaintTrace.merge(self.return_collectors[-1])
        finally:
            self.return_collectors.pop()
            self.call_stack.pop()
        self.call_cache[cache_key] = returned
        return returned

    @staticmethod
    def _safe_yaml_loader(node: ast.Call) -> bool:
        return any(
            item.arg == "Loader" and _call_name(item.value).endswith("SafeLoader")
            for item in node.keywords
        )

    def _sink(self, node: ast.Call) -> Sink | None:
        name = _call_name(node.func)
        if name in {"eval", "exec", "builtins.eval", "builtins.exec"} and node.args:
            return Sink(
                "FLOW-EVAL", "CWE-95", Severity.CRITICAL,
                "外部数据流入动态代码执行",
                "有界数据流证明外部可控值到达 eval/exec 动态执行汇点。",
                "移除动态执行，改用显式解析器、白名单命令或安全数据格式。",
                "使用代码注入载荷验证外部数据无法到达动态执行函数。",
                node.args[0],
            )
        if name in {"os.system", "os.popen", "commands.getoutput",
                    "commands.getstatusoutput"} and node.args:
            return Sink(
                "FLOW-COMMAND", "CWE-78", Severity.HIGH,
                "外部数据流入 Shell 命令",
                "有界数据流证明外部可控值到达系统 Shell 命令执行汇点。",
                "使用 shell=False 的参数数组，并对白名单命令及参数做类型校验。",
                "使用分号、管道、命令替换与变量展开载荷验证命令边界。",
                node.args[0],
            )
        if name in {
            "subprocess.run", "subprocess.call", "subprocess.Popen",
            "subprocess.check_call", "subprocess.check_output",
        } and node.args and any(
            item.arg == "shell" and isinstance(item.value, ast.Constant)
            and item.value.value is True for item in node.keywords
        ):
            return Sink(
                "FLOW-COMMAND", "CWE-78", Severity.HIGH,
                "外部数据流入 shell=True 子进程",
                "有界数据流证明外部可控值到达 shell=True 的子进程调用。",
                "传递参数数组并保持 shell=False，限制可执行文件与参数集合。",
                "覆盖 Shell 元字符与命令替换载荷，验证其只作为普通参数。",
                node.args[0],
            )
        if (
            isinstance(node.func, ast.Attribute)
            and name.split(".")[-1] in {"execute", "executemany", "query", "raw"}
            and node.args
        ):
            return Sink(
                "FLOW-SQL", "CWE-89", Severity.HIGH,
                "外部数据流入 SQL 结构",
                "有界数据流证明外部可控值进入 SQL 语句结构。",
                "使用数据库驱动参数占位符，将查询结构与数据参数严格分离。",
                "加入引号、注释符与布尔表达式载荷验证参数化边界。",
                node.args[0],
            )
        if name in {
            "pickle.load", "pickle.loads", "dill.load", "dill.loads",
            "marshal.loads", "yaml.unsafe_load", "yaml.load",
        } and node.args and not (name == "yaml.load" and self._safe_yaml_loader(node)):
            return Sink(
                "FLOW-DESERIALIZATION", "CWE-502", Severity.HIGH,
                "外部数据流入危险反序列化",
                "有界数据流证明外部数据到达具有对象构造或执行语义的反序列化汇点。",
                "使用 JSON 等无执行语义格式并校验结构，禁止反序列化不可信对象流。",
                "使用构造对象载荷验证入口安全拒绝，同时覆盖正常数据。",
                node.args[0],
            )
        if name in {"open", "builtins.open", "io.open", "os.open", "send_file",
                    "starlette.responses.FileResponse"} and node.args:
            return Sink(
                "FLOW-PATH", "CWE-22", Severity.HIGH,
                "外部数据流入文件路径汇点",
                "有界数据流证明外部可控值被用作文件路径，可能越过预期目录边界。",
                "在固定根目录下解析规范路径，并验证解析结果仍位于允许根目录内。",
                "覆盖 ../、绝对路径、符号链接和编码变体，验证目录边界。",
                node.args[0],
            )
        if name.endswith("send_from_directory") and len(node.args) > 1:
            return Sink(
                "FLOW-PATH", "CWE-22", Severity.HIGH,
                "外部数据流入文件下载路径",
                "有界数据流证明外部可控值被用作目录内文件路径。",
                "规范化文件名并验证解析路径仍位于固定下载根目录内。",
                "覆盖目录穿越、绝对路径和编码变体。",
                node.args[1],
            )
        if name.endswith(".open") and isinstance(node.func, ast.Attribute):
            return Sink(
                "FLOW-PATH", "CWE-22", Severity.HIGH,
                "外部数据流入路径对象打开操作",
                "有界数据流证明外部可控路径对象被打开。",
                "在固定根目录下解析路径并执行包含关系检查。",
                "覆盖目录穿越、绝对路径和符号链接。",
                node.func.value,
            )
        return None

    def _inspect_calls(
        self, node: ast.AST, environment: dict[str, TaintTrace]
    ) -> None:
        analyzer = self
        root = node

        class CurrentStatementVisitor(ast.NodeVisitor):
            def generic_visit(inner, candidate):
                if isinstance(candidate, ast.stmt) and candidate is not root:
                    return
                super().generic_visit(candidate)

            def visit_Lambda(inner, candidate):
                return

            def visit_Call(inner, candidate):
                symbol = analyzer._resolve_call(candidate)
                sink = None if symbol else analyzer._sink(candidate)
                if symbol:
                    analyzer._expr_taint(candidate, environment)
                elif sink:
                    trace = analyzer._expr_taint(sink.argument, environment)
                    if trace:
                        analyzer._add_finding(candidate, sink, trace)
                inner.generic_visit(candidate)

        CurrentStatementVisitor().visit(node)

    def _add_finding(self, node: ast.Call, sink: Sink, trace: TaintTrace) -> None:
        context = self._context(node)
        line = max(1, int(getattr(node, "lineno", 1)))
        identity = (context.path, sink.rule_id, line)
        if identity in self.seen:
            return
        self.seen.add(identity)
        steps = list(trace.steps)
        steps.append(self._step(node, "taint-sink"))
        records = [
            EvidenceRecord(
                source="python-dataflow",
                kind=item.kind,
                path=item.path,
                line=item.line,
                snippet=item.snippet,
                rule_id=sink.rule_id,
                cwe=sink.cwe,
                confidence=0.97,
            )
            for item in steps
        ]
        self.findings.append(Finding(
            rule_id=sink.rule_id,
            severity=sink.severity,
            title=sink.title,
            explanation=sink.explanation,
            path=context.path,
            line=line,
            evidence="%s -> %s" % (trace.label, self._snippet(node)),
            fix=sink.fix,
            test=sink.test,
            confidence=0.97,
            cwe=sink.cwe,
            source="python-dataflow",
            evidence_kind="source-to-sink",
            verification_state="dataflow-verified",
            evidence_records=records,
        ))

    def _is_endpoint(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
        for decorator in node.decorator_list:
            value = decorator.func if isinstance(decorator, ast.Call) else decorator
            name = _call_name(value)
            last = name.split(".")[-1]
            prefix = name.rsplit(".", 1)[0] if "." in name else ""
            if last in ENDPOINT_DECORATORS and (
                last in {"route", "api_route"} or prefix in {"app", "router", "bp", "blueprint"}
            ):
                return True
        return False

    def _analyze_function(
        self, node: ast.FunctionDef | ast.AsyncFunctionDef
    ) -> None:
        environment: dict[str, TaintTrace] = {}
        if self._is_endpoint(node):
            arguments = [
                *node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs
            ]
            if node.args.vararg:
                arguments.append(node.args.vararg)
            if node.args.kwarg:
                arguments.append(node.args.kwarg)
            for argument in arguments:
                if argument.arg not in {"self", "cls"}:
                    environment[argument.arg] = self._source(
                        argument, "endpoint parameter '%s'" % argument.arg
                    )
        symbol = self.symbol_by_node.get(id(node))
        context = self._context(node)
        stack_key = symbol.key if symbol else "%s:%s@%s" % (
            context.name, node.name, int(getattr(node, "lineno", 0))
        )
        if stack_key in self.call_stack:
            self.truncated_calls += 1
            return
        self.call_stack.append(stack_key)
        self.return_collectors.append([])
        try:
            self._process_block(node.body, environment)
        finally:
            self.return_collectors.pop()
            self.call_stack.pop()

    def _assign(
        self, target: ast.AST, trace: TaintTrace | None,
        environment: dict[str, TaintTrace],
    ) -> None:
        if isinstance(target, ast.Name):
            if trace:
                environment[target.id] = trace
            else:
                environment.pop(target.id, None)
        elif isinstance(target, (ast.Tuple, ast.List)):
            for item in target.elts:
                self._assign(item, trace, environment)
        elif isinstance(target, ast.Starred):
            self._assign(target.value, trace, environment)

    @staticmethod
    def _merge_environments(
        values: list[dict[str, TaintTrace]]
    ) -> dict[str, TaintTrace]:
        result: dict[str, TaintTrace] = {}
        for key in set().union(*(item.keys() for item in values)):
            trace = TaintTrace.merge([
                environment.get(key) for environment in values
                if environment.get(key) is not None
            ])
            if trace:
                result[key] = trace
        return result

    def _process_block(
        self, statements: list[ast.stmt], environment: dict[str, TaintTrace]
    ) -> dict[str, TaintTrace]:
        current = dict(environment)
        for statement in statements:
            current = self._process_statement(statement, current)
            if isinstance(statement, (ast.Return, ast.Raise, ast.Break, ast.Continue)):
                break
        return current

    def _process_statement(
        self, statement: ast.stmt, environment: dict[str, TaintTrace]
    ) -> dict[str, TaintTrace]:
        current = dict(environment)
        if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef)):
            self._analyze_function(statement)
            current.pop(statement.name, None)
            return current
        if isinstance(statement, ast.ClassDef):
            for item in statement.body:
                if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    self._analyze_function(item)
            return current

        self._inspect_calls(statement, current)
        if isinstance(statement, ast.Return):
            trace = self._expr_taint(statement.value, current)
            if trace and self.return_collectors:
                self.return_collectors[-1].append(
                    trace.extended(self._step(statement, "return-propagation"))
                )
        elif isinstance(statement, (ast.Assign, ast.AnnAssign, ast.NamedExpr)):
            value = statement.value
            trace = self._expr_taint(value, current)
            if trace:
                trace = trace.extended(self._step(statement, "taint-propagation"))
            targets = statement.targets if isinstance(statement, ast.Assign) else [statement.target]
            for target in targets:
                self._assign(target, trace, current)
        elif isinstance(statement, ast.AugAssign):
            trace = TaintTrace.merge([
                self._expr_taint(statement.target, current),
                self._expr_taint(statement.value, current),
            ])
            if trace:
                trace = trace.extended(self._step(statement, "taint-propagation"))
            self._assign(statement.target, trace, current)
        elif isinstance(statement, ast.If):
            branches = [self._process_block(statement.body, dict(current))]
            branches.append(
                self._process_block(statement.orelse, dict(current))
                if statement.orelse else dict(current)
            )
            current = self._merge_environments(branches)
        elif isinstance(statement, (ast.For, ast.AsyncFor)):
            loop_environment = dict(current)
            trace = self._expr_taint(statement.iter, current)
            if trace:
                trace = trace.extended(self._step(statement, "taint-propagation"))
            self._assign(statement.target, trace, loop_environment)
            body = self._process_block(statement.body, loop_environment)
            alternate = self._process_block(statement.orelse, dict(current))
            current = self._merge_environments([current, body, alternate])
        elif isinstance(statement, ast.While):
            body = self._process_block(statement.body, dict(current))
            alternate = self._process_block(statement.orelse, dict(current))
            current = self._merge_environments([current, body, alternate])
        elif isinstance(statement, (ast.With, ast.AsyncWith)):
            nested = dict(current)
            for item in statement.items:
                if item.optional_vars is not None:
                    trace = self._expr_taint(item.context_expr, current)
                    self._assign(item.optional_vars, trace, nested)
            current = self._merge_environments([
                current, self._process_block(statement.body, nested)
            ])
        elif isinstance(statement, ast.Try):
            branches = [
                dict(current),
                self._process_block(statement.body, dict(current)),
            ]
            branches.extend(
                self._process_block(handler.body, dict(current))
                for handler in statement.handlers
            )
            if statement.orelse:
                branches.append(self._process_block(statement.orelse, dict(current)))
            current = self._merge_environments(branches)
            if statement.finalbody:
                current = self._process_block(statement.finalbody, current)
        elif isinstance(statement, ast.Delete):
            for target in statement.targets:
                self._assign(target, None, current)
        return current
