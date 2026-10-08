"""AST-backed Python vulnerability candidate analysis."""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field

from .models import Finding, Severity


SECRET_NAME = re.compile(r"(?i)(password|passwd|api_?key|secret|token)")


@dataclass
class PythonAnalysisResult:
    findings: list[Finding] = field(default_factory=list)
    parse_error: str = ""


def _call_name(node: ast.AST) -> str:
    parts: list[str] = []
    current = node
    while isinstance(current, ast.Attribute):
        parts.append(current.attr)
        current = current.value
    if isinstance(current, ast.Name):
        parts.append(current.id)
    return ".".join(reversed(parts))


def _dotted_name(node: ast.AST) -> str:
    """The full dotted name when every receiver is a plain ``Name``.

    ``builtins.eval`` / ``subprocess.run`` resolve to their dotted name;
    receivers like ``Metrics()`` or ``objects[0]`` are expressions whose
    binding the AST alone cannot resolve, so they return ``""`` -- the
    2026-10-03 root-cause fix: flattening them onto the bare last segment
    made ordinary object methods collide with built-ins.
    """
    parts: list[str] = []
    current = node
    while isinstance(current, ast.Attribute):
        parts.append(current.attr)
        current = current.value
    if not isinstance(current, ast.Name):
        return ""
    parts.append(current.id)
    return ".".join(reversed(parts))


def _default_values(args: ast.arguments) -> list[ast.expr]:
    """A signature's default-value expressions (evaluated at def site)."""
    values: list[ast.expr] = list(args.defaults)
    values.extend(item for item in args.kw_defaults if item is not None)
    return values


class _ScopeBindings:
    """Per-scope lexical binding sets for scope-correct built-in shadowing.

    The 2026-10-03 regression flattened every binding file-wide, so a
    same-name method, parameter or import alias anywhere suppressed a
    genuine bare ``eval``/``exec`` call everywhere else.  This collector
    restores actual lexical visibility:

    - module-level bindings own the name for the whole module;
    - a parameter (including ``*args``/``**kwargs``/keyword-only), a local
      ``def``/``class`` name, an assignment target, an import alias, a
      loop/``with``/``except`` target or a named expression binds only
      inside its function/lambda/comprehension scope (a named expression
      inside a comprehension binds in the containing non-comprehension
      scope, per PEP 572);
    - a class body binds only code directly inside that body, so a method
      named ``eval`` never shadows the built-in for any other scope.

    ``global``/``nonlocal`` declarations are not resolved across scopes;
    their assignments stay local to the declaring function, which can only
    make the analyzer louder than Python, never silently quieter.  No name
    lists, repository paths, class names or sample allowlists are involved.
    """

    def __init__(self, tree: ast.Module) -> None:
        self.kinds: dict[int, str] = {id(tree): "module"}
        self.bindings: dict[int, set[str]] = {id(tree): set()}
        self._collect_children(tree, self.bindings[id(tree)],
                               self.bindings[id(tree)])

    def _new_scope(self, node: ast.AST, kind: str,
                   names: set[str] | None = None) -> set[str]:
        own = set(names or ())
        self.kinds[id(node)] = kind
        self.bindings[id(node)] = own
        return own

    @staticmethod
    def _arg_names(args: ast.arguments) -> set[str]:
        names = {
            item.arg
            for item in (
                list(args.posonlyargs) + list(args.args)
                + list(args.kwonlyargs)
            )
        }
        for extra in (args.vararg, args.kwarg):
            if extra is not None:
                names.add(extra.arg)
        return names

    def _bind_target(self, target: ast.AST, bound: set[str]) -> None:
        if isinstance(target, ast.Name):
            bound.add(target.id)
        elif isinstance(target, (ast.Tuple, ast.List)):
            for item in target.elts:
                self._bind_target(item, bound)
        elif isinstance(target, ast.Starred):
            self._bind_target(target.value, bound)

    def _collect_children(self, node: ast.AST, bound: set[str],
                          container: set[str]) -> None:
        for child in ast.iter_child_nodes(node):
            self._collect_node(child, bound, container)

    def _collect_node(self, node: ast.AST, bound: set[str],
                      container: set[str]) -> None:
        """Collect the names ``node`` binds at actual lexical visibility.

        ``bound`` is the current scope's set; ``container`` is the nearest
        non-comprehension scope, where named expressions bind.
        """
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            bound.add(node.name)
            own = self._new_scope(
                node, "function", self._arg_names(node.args)
            )
            for part in node.decorator_list:
                self._collect_node(part, bound, container)
            for part in _default_values(node.args):
                self._collect_node(part, bound, container)
            for stmt in node.body:
                self._collect_node(stmt, own, own)
        elif isinstance(node, ast.Lambda):
            own = self._new_scope(
                node, "function", self._arg_names(node.args)
            )
            for part in _default_values(node.args):
                self._collect_node(part, bound, container)
            self._collect_node(node.body, own, own)
        elif isinstance(node, ast.ClassDef):
            bound.add(node.name)
            own = self._new_scope(node, "class")
            for part in node.decorator_list + node.bases + node.keywords:
                self._collect_node(part, bound, container)
            for stmt in node.body:
                self._collect_node(stmt, own, own)
        elif isinstance(node, (ast.ListComp, ast.SetComp, ast.GeneratorExp,
                               ast.DictComp)):
            own = self._new_scope(node, "comprehension")
            for generator in node.generators:
                self._bind_target(generator.target, own)
                self._collect_node(generator.iter, own, container)
                for condition in generator.ifs:
                    self._collect_node(condition, own, container)
            if isinstance(node, ast.DictComp):
                self._collect_node(node.key, own, container)
                self._collect_node(node.value, own, container)
            else:
                self._collect_node(node.elt, own, container)
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            for alias in node.names:
                if isinstance(node, ast.Import):
                    bound.add(alias.asname or alias.name.split(".")[0])
                else:
                    bound.add(alias.asname or alias.name)
        elif isinstance(node, ast.Assign):
            for target in node.targets:
                self._bind_target(target, bound)
            self._collect_node(node.value, bound, container)
        elif isinstance(node, (ast.AnnAssign, ast.AugAssign)):
            # An annotation without a value declares but does not bind.
            if not isinstance(node, ast.AnnAssign) or node.value is not None:
                self._bind_target(node.target, bound)
            if node.value is not None:
                self._collect_node(node.value, bound, container)
        elif isinstance(node, (ast.For, ast.AsyncFor)):
            self._bind_target(node.target, bound)
            self._collect_node(node.iter, bound, container)
            for stmt in node.body + node.orelse:
                self._collect_node(stmt, bound, container)
        elif isinstance(node, (ast.With, ast.AsyncWith)):
            for item in node.items:
                self._collect_node(item.context_expr, bound, container)
                if item.optional_vars is not None:
                    self._bind_target(item.optional_vars, bound)
            for stmt in node.body:
                self._collect_node(stmt, bound, container)
        elif isinstance(node, ast.NamedExpr):
            container.add(node.target.id)
            self._collect_node(node.value, bound, container)
        elif isinstance(node, ast.ExceptHandler):
            if node.name:
                bound.add(node.name)
            for stmt in node.body:
                self._collect_node(stmt, bound, container)
        else:
            self._collect_children(node, bound, container)


#: Values that are pure identifiers cannot be distinguished from
#: enum/mode/name references by lexical shape alone.
_IDENTIFIER_LIKE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")

#: Markup delimiters mark template/marker text (template interpolation,
#: input markers), not credential material.
_MARKUP_TEXT = re.compile(r"[<>|]")


def _credential_shape(value: str) -> str:
    """Classify a string literal's credential plausibility by generic shape.

    ``"strong"``: mixes character classes and/or carries enough length and
    non-identifier structure to be plausible secret material (e.g. API key
    prefixes, base64 blobs, mixed-case tokens with digits/separators).
    ``"marker"``: template/marker text.
    ``"identifier"``: a pure identifier or enum-like word -- a naming or
    configuration reference, not evidence of secret material (stays
    visible as a low-severity candidate; lexical rules cannot decide it).
    """
    if _MARKUP_TEXT.search(value):
        return "marker"
    if _IDENTIFIER_LIKE.fullmatch(value):
        return "identifier"
    has_digit = any(ch.isdigit() for ch in value)
    has_symbol = any(not ch.isalnum() and ch not in "_-" for ch in value)
    mixed_case = value != value.lower() and value != value.upper()
    if len(value) >= 16 and (has_digit or mixed_case or has_symbol):
        return "strong"
    if has_digit and (mixed_case or has_symbol):
        return "strong"
    if mixed_case and len(value) >= 12:
        return "strong"
    return "identifier"


class PythonAstSecurityAnalyzer(ast.NodeVisitor):
    """Emit high-signal candidates from Python syntax rather than raw text."""

    def analyze(self, path: str, content: str) -> PythonAnalysisResult:
        self.path = path
        self.lines = content.splitlines()
        self.findings: list[Finding] = []
        self.seen: set[tuple[str, int]] = set()
        try:
            tree = ast.parse(content, filename=path)
        except SyntaxError as exc:
            return PythonAnalysisResult(
                parse_error="%s:%s: %s" % (path, exc.lineno or 0, exc.msg)
            )
        self._bindings = _ScopeBindings(tree)
        self._scopes: list[ast.AST] = []
        self.visit(tree)
        return PythonAnalysisResult(findings=self.findings)

    def _add(
        self,
        node: ast.AST,
        rule_id: str,
        severity: Severity,
        title: str,
        explanation: str,
        fix: str,
        test: str,
        confidence: float = 0.9,
        cwe: str = "",
        verification_state: str = "candidate",
    ) -> None:
        line_number = int(getattr(node, "lineno", 1))
        identity = (rule_id, line_number)
        if identity in self.seen:
            return
        self.seen.add(identity)
        evidence = self.lines[line_number - 1].strip()[:240] if self.lines else ""
        self.findings.append(
            Finding(
                rule_id=rule_id,
                severity=severity,
                title=title,
                explanation=explanation,
                path=self.path,
                line=line_number,
                evidence=evidence,
                fix=fix,
                test=test,
                confidence=confidence,
                cwe=cwe,
                source="python-ast",
                evidence_kind="ast-call" if isinstance(node, ast.Call) else "ast-assignment",
                verification_state=verification_state,
            )
        )

    def _push_scope(self, node: ast.AST) -> None:
        self._scopes.append(node)

    def _pop_scope(self) -> None:
        self._scopes.pop()

    def _name_bound_at(self, name: str) -> bool:
        """Whether ``name`` is lexically bound at the current position.

        Module bindings apply module-wide; function/lambda/comprehension
        bindings at their own scope; a class body's bindings only to code
        directly inside that body -- never across a function boundary.
        """
        direct = True
        for scope in reversed(self._scopes):
            if self._bindings.kinds[id(scope)] == "class" and not direct:
                continue
            if name in self._bindings.bindings[id(scope)]:
                return True
            direct = False
        return False

    def visit_Module(self, node: ast.Module) -> None:
        self._push_scope(node)
        self.generic_visit(node)
        self._pop_scope()

    def _visit_function(self, node) -> None:
        # Decorators and default values evaluate in the enclosing scope.
        for part in node.decorator_list:
            self.visit(part)
        for part in _default_values(node.args):
            self.visit(part)
        self._push_scope(node)
        for stmt in node.body:
            self.visit(stmt)
        self._pop_scope()

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._visit_function(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._visit_function(node)

    def visit_Lambda(self, node: ast.Lambda) -> None:
        for part in _default_values(node.args):
            self.visit(part)
        self._push_scope(node)
        self.visit(node.body)
        self._pop_scope()

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        for part in node.decorator_list + node.bases + node.keywords:
            self.visit(part)
        self._push_scope(node)
        for stmt in node.body:
            self.visit(stmt)
        self._pop_scope()

    def _visit_comprehension(self, node) -> None:
        self._push_scope(node)
        self.generic_visit(node)
        self._pop_scope()

    def visit_ListComp(self, node: ast.ListComp) -> None:
        self._visit_comprehension(node)

    def visit_SetComp(self, node: ast.SetComp) -> None:
        self._visit_comprehension(node)

    def visit_DictComp(self, node: ast.DictComp) -> None:
        self._visit_comprehension(node)

    def visit_GeneratorExp(self, node: ast.GeneratorExp) -> None:
        self._visit_comprehension(node)

    def visit_Call(self, node: ast.Call) -> None:
        name = _call_name(node.func)
        dotted = _dotted_name(node.func)
        # Dynamic-execution rule (2026-10-03 scope-correct binding fix):
        # the built-in is asserted only for a bare ``eval``/``exec`` Name
        # that no lexically visible binding shadows -- checked at the call
        # site's actual scope, never file-wide -- or an explicit
        # ``builtins.eval``/``builtins.exec`` dotted reference.  Ordinary
        # methods on resolvable receivers (``m.eval()``,
        # ``self.session.eval``) are not claims; a receiver this layer
        # cannot uniquely resolve (``objects[0].eval(...)``,
        # ``Gauge().eval(...)``) stays visible as a candidate-level finding
        # with a distinct face instead of silently disappearing.
        if dotted in {"builtins.eval", "builtins.exec"} or (
            isinstance(node.func, ast.Name)
            and node.func.id in {"eval", "exec"}
            and not self._name_bound_at(node.func.id)
        ):
            self._add(
                node, "SEC-EVAL", Severity.CRITICAL,
                "动态代码执行可能导致注入",
                "代码调用了 Python 动态执行函数；外部可控参数可能导致任意代码执行。",
                "改用显式解析器、命令映射或严格白名单，不执行输入文本。",
                "使用恶意表达式和边界输入验证输入不会作为 Python 代码执行。",
                0.98,
                cwe="CWE-95",
            )
        elif (
            isinstance(node.func, ast.Attribute)
            and node.func.attr in {"eval", "exec"}
            and not dotted
        ):
            self._add(
                node, "SEC-EVAL", Severity.LOW,
                "接收者无法唯一解析的动态执行样式调用（候选）",
                "调用形如 <不可唯一解析的接收者>.eval/.exec：词法层无法确定该"
                "绑定是内置动态执行还是普通对象方法，按候选保留供调查层复核，"
                "不冒充已证实的内置调用。",
                "解析接收者的实际类型后再定性；若确为内置 eval/exec，改用显式"
                "解析器、命令映射或严格白名单，不执行输入文本。",
                "为接收者补充类型或运行时证据后复查该调用的定性结论。",
                0.4,
                cwe="CWE-95",
            )
        if name in {
            "subprocess.run", "subprocess.call", "subprocess.Popen",
            "subprocess.check_call", "subprocess.check_output",
        } and any(
            item.arg == "shell" and isinstance(item.value, ast.Constant)
            and item.value.value is True for item in node.keywords
        ):
            self._add(
                node, "SEC-SUBPROCESS-SHELL", Severity.HIGH,
                "Shell 调用存在命令注入风险",
                "subprocess 使用 shell=True，会放大字符串拼接或外部参数的注入风险。",
                "传递参数数组并保持 shell=False；对允许的命令和参数做白名单验证。",
                "覆盖分号、管道、命令替换和空格等恶意参数。",
                0.96,
                cwe="CWE-78",
            )
        if name in {"os.system", "os.popen", "commands.getoutput", "commands.getstatusoutput"}:
            self._add(
                node, "SEC-OS-SYSTEM", Severity.HIGH,
                "命令执行 API 需要外部输入验证",
                "该 API 通过系统 Shell 执行字符串，外部可控数据可能造成命令注入。",
                "改用 shell=False 的 subprocess 参数数组，并对白名单参数做类型与范围验证。",
                "加入命令分隔符、变量展开和命令替换载荷的回归测试。",
                0.9,
                cwe="CWE-78",
            )
        if name in {"pickle.load", "pickle.loads", "dill.load", "dill.loads", "marshal.loads"}:
            self._add(
                node, "SEC-UNSAFE-DESERIALIZATION", Severity.HIGH,
                "不安全反序列化可能执行任意代码",
                "对不可信数据使用 Python 对象反序列化可能触发攻击者控制的构造逻辑。",
                "使用 JSON 等无执行语义的格式，并校验结构；不要反序列化不可信对象流。",
                "使用构造过的对象载荷验证入口会被拒绝，且正常数据仍可读取。",
                0.95,
                cwe="CWE-502",
            )
        if name in {"yaml.load", "yaml.unsafe_load"}:
            loader_is_safe = any(
                item.arg == "Loader" and _call_name(item.value).endswith("SafeLoader")
                for item in node.keywords
            )
            if name == "yaml.unsafe_load" or not loader_is_safe:
                self._add(
                    node, "SEC-UNSAFE-YAML", Severity.HIGH,
                    "YAML 反序列化未使用安全加载器",
                    "默认或不安全 YAML Loader 可能构造具有执行副作用的 Python 对象。",
                    "使用 yaml.safe_load 或显式 SafeLoader，并校验解析后的数据结构。",
                    "加入带 Python 对象标签的恶意 YAML，断言加载被拒绝。",
                    0.94,
                    cwe="CWE-502",
                )
        if name.split(".")[-1] in {"execute", "query"} and node.args:
            query = node.args[0]
            if isinstance(query, ast.JoinedStr) or (
                isinstance(query, ast.BinOp) and len(node.args) == 1
            ):
                self._add(
                    node, "SEC-SQL-CONCAT", Severity.HIGH,
                    "SQL 语句疑似动态拼接",
                    "SQL 调用接收了格式化或运算拼接表达式，外部数据可能改变查询结构。",
                    "使用数据库驱动的参数占位符，将 SQL 结构与数据参数分离。",
                    "加入引号、注释符和布尔表达式载荷，验证其只被作为数据处理。",
                    0.92,
                    cwe="CWE-89",
                )
        self.generic_visit(node)

    def _secret_finding(self, node: ast.AST, target_names: list[str],
                        value: str) -> None:
        """Emit the hardcoded-secret finding with credential-shape honesty.

        Lexical shape alone cannot prove a credential: identifier-shaped or
        marker-shaped values are naming/enum/template references and are
        kept visible as a low-severity candidate instead of an unfounded
        HIGH active alert (the 2026-10-03 root-cause fix; no repository,
        path or token-name allowlists are involved).
        """
        if not (len(value) >= 4 and any(SECRET_NAME.search(n) for n in target_names)):
            return
        shape = _credential_shape(value)
        references_name = _IDENTIFIER_LIKE.fullmatch(value) and any(
            value.upper() in name.upper() for name in target_names
        )
        if shape == "strong" and not references_name:
            self._add(
                node, "SEC-HARDCODED-SECRET", Severity.HIGH,
                "疑似硬编码凭据",
                "敏感变量被赋予字符串常量，提交后可能通过历史记录、日志或制品泄露。",
                "从环境变量或密钥管理服务读取，并轮换已经暴露的凭据。",
                "验证缺少密钥时安全失败，且日志和报告不会泄露密钥内容。",
                0.9,
                cwe="CWE-798",
                verification_state="syntax-verified",
            )
            return
        if shape == "marker":
            title = "命名与凭据词重合的模板/标记文本"
            explanation = (
                "敏感命名的变量被赋予了模板或输入标记文本；词法规则无法"
                "确认凭据语义，按低危候选保留供复核。"
            )
        elif references_name:
            title = "疑似名称引用而非凭据值"
            explanation = (
                "敏感命名的变量被赋予了与其名称对应的标识符文本"
                "（常见于环境变量名/配置键引用）；词法规则无法确认凭据语义。"
            )
        else:
            title = "命名与凭据词重合的标识符/枚举值"
            explanation = (
                "敏感命名的变量被赋予了标识符或枚举样式文本；词法规则无法"
                "确认凭据语义，按低危候选保留供复核。"
            )
        self._add(
            node, "SEC-HARDCODED-SECRET", Severity.LOW,
            title,
            explanation,
            "若确为凭据请改从环境变量或密钥管理服务读取；否则重命名变量"
            "以避免凭据语义误导。",
            "复核该值的来源与用途；仅在确为凭据时按凭据处理。",
            0.4,
            cwe="CWE-798",
            verification_state="candidate",
        )

    def visit_Assign(self, node: ast.Assign) -> None:
        if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
            names = [_call_name(item) for item in node.targets]
            self._secret_finding(node, names, node.value.value)
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        if (
            isinstance(node.value, ast.Constant)
            and isinstance(node.value.value, str)
        ):
            self._secret_finding(
                node, [_call_name(node.target)], node.value.value
            )
        self.generic_visit(node)
