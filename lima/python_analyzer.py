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
        self._bound_names = self._collect_bound_names(tree)
        self.visit(tree)
        return PythonAnalysisResult(findings=self.findings)

    @staticmethod
    def _collect_bound_names(tree: ast.Module) -> set[str]:
        """Every name the file binds (defs, classes, assignments, imports).

        Used to discriminate a locally shadowed ``eval``/``exec`` from the
        built-in: a file that defines, assigns or imports a name owns that
        binding, and a bare call to it is not a call to the built-in.
        File-scope approximation; deeper binding precision stays explicitly
        unresolved (reported by the investigation layer, never guessed).
        """
        bound: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef,
                                 ast.ClassDef)):
                bound.add(node.name)
            elif isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        bound.add(target.id)
                    elif isinstance(target, (ast.Tuple, ast.List)):
                        bound.update(
                            item.id for item in target.elts
                            if isinstance(item, ast.Name)
                        )
            elif isinstance(node, ast.AnnAssign) and isinstance(
                node.target, ast.Name
            ):
                bound.add(node.target.id)
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    bound.add(alias.asname or alias.name.split(".")[0])
            elif isinstance(node, ast.ImportFrom):
                for alias in node.names:
                    bound.add(alias.asname or alias.name)
            elif isinstance(node, (ast.For, ast.comprehension)):
                if isinstance(node.target, ast.Name):
                    bound.add(node.target.id)
            elif isinstance(node, ast.withitem) and isinstance(
                node.optional_vars, ast.Name
            ):
                bound.add(node.optional_vars.id)
            elif isinstance(node, ast.ExceptHandler) and node.name:
                bound.add(node.name)
        return bound

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

    def visit_Call(self, node: ast.Call) -> None:
        name = _call_name(node.func)
        dotted = _dotted_name(node.func)
        # Dynamic-execution rule (2026-10-03 binding fix): the built-in is
        # only claimed for a bare, unshadowed ``eval``/``exec`` Name or an
        # explicit ``builtins.eval``/``builtins.exec`` dotted reference.
        # Ordinary object methods (``Metrics().eval``, ``self.session.eval``)
        # and locally shadowed names no longer collide with the built-in.
        is_builtin_dynamic = (
            dotted in {"builtins.eval", "builtins.exec"}
            or (
                isinstance(node.func, ast.Name)
                and node.func.id in {"eval", "exec"}
                and node.func.id not in self._bound_names
            )
        )
        if is_builtin_dynamic:
            self._add(
                node, "SEC-EVAL", Severity.CRITICAL,
                "动态代码执行可能导致注入",
                "代码调用了 Python 动态执行函数；外部可控参数可能导致任意代码执行。",
                "改用显式解析器、命令映射或严格白名单，不执行输入文本。",
                "使用恶意表达式和边界输入验证输入不会作为 Python 代码执行。",
                0.98,
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
