"""AST / restricted-CFG UAF fact extraction with fail-closed completeness.

Task 4 of the UAF v2 plan (design ``docs/superpowers/specs/2026-09-10-cxx-uaf-v2-design.md``
sections 3.1/3.2/7).  Two stages live here:

1. :func:`extract_ast_json` runs the audited ``clang-14`` driver through the
   managed sandbox executor (:func:`cxx_analyzer.execution.run_step` -- never
   a bare subprocess) with ``-fsyntax-only -Xclang -ast-dump=json`` plus
   ``-Xclang -detailed-preprocessing-record``.  The detailed preprocessing
   record is what makes macro-expanded key statements observable: the dump
   then contains ``MacroExpansion`` decls whose source ranges can be tested
   for overlap with function bodies.  Only the resolver's *semantic*
   arguments (``-I``/``-D``/``-std``/...) are forwarded; the repository's
   compiler binary and output flags never reach execution.  A missing,
   truncated or unparseable dump yields ``(None, [gap])`` and the unit is
   served as ``extraction: unavailable``.
2. :func:`extract_uaf_facts` is a pure function over the parsed AST.  It
   emits the eleven first-phase wire fact kinds (design section 7.2) for the
   supported subset -- plain ``new``/``malloc`` allocations, ``delete``/
   ``free`` releases, ``*p`` dereferences, ``p->member`` accesses and simple
   local raw-pointer alias copies/rebinds -- and answers the restricted-CFG
   completeness question.  The supported CFG syntax is a closed whitelist:
   straight-line statements, nested ``if``/``else`` and side-effect-free
   short-circuit operators.  Everything else (loops, switch, goto, exceptions,
   RAII destructors, lambda bodies, coroutines, indirect calls, template
   instantiations, macro-expanded key ranges, unsupported statements) records
   a fixed lowercase coverage gap and forces ``cfg_complete=False``; no fact
   is ever invented for a construct the whitelist does not support.

Fail-closed red lines implemented here:

- The AST dump carries no Clang USRs, so ``function_usr`` is a stable
  synthesized key (``path#name@line``) and ``usr-synthesized`` is recorded
  every time it is used.  Downstream PASS is forbidden without a real USR;
  fabricating one here would hide that fact from the pipeline.
- ``object_id`` is deliberately *not* emitted: design section 7.1 derives it
  from the function USR, and a substitute sidecar identity is forbidden.
  The main process derives object identity from the wire fields.
- The extractor never imports the main-process ``lima`` package: wire facts
  are plain dicts and typed construction is Task 5's job.
"""

from __future__ import annotations

import bisect
import hashlib
import itertools
import json
from collections.abc import Sequence
from pathlib import Path
from typing import Any, Final

from .build_context import semantic_arguments
from .execution import run_step
from .languages import language_for_path

__all__ = [
    "MAX_AST_JSON_BYTES",
    "MAX_FACTS_PER_UNIT",
    "MAX_UNIT_GAPS",
    "build_line_offsets",
    "extract_ast_json",
    "extract_uaf_facts",
]

# Budgets (fail closed).
MAX_AST_JSON_BYTES: Final = 16 * 1024 * 1024
MAX_FACTS_PER_UNIT: Final = 1024
MAX_UNIT_GAPS: Final = 64

# Fixed coverage-gap vocabulary (lowercase, hyphenated).
GAP_AST_UNAVAILABLE: Final = "ast-unavailable"
GAP_AST_OUTPUT_LIMIT: Final = "ast-output-limit"
GAP_AST_JSON_INVALID: Final = "ast-json-invalid"
GAP_AST_ERROR_DIAGNOSTIC: Final = "ast-error-diagnostic"
GAP_AST_LINE_UNAVAILABLE: Final = "ast-line-unavailable"
GAP_USR_SYNTHESIZED: Final = "usr-synthesized"
GAP_ARRAY_NEW: Final = "array-new"
GAP_LIFETIME_RESTART: Final = "lifetime-restart"
GAP_COMPLEX_USE: Final = "complex-use-expression"
GAP_FACT_BUDGET: Final = "fact-budget-exhausted"
GAP_CFG_LOOP: Final = "cfg-loop"
GAP_CFG_SWITCH: Final = "cfg-switch"
GAP_CFG_GOTO: Final = "cfg-goto"
GAP_CFG_EXCEPTION: Final = "cfg-exception"
GAP_SHORT_CIRCUIT: Final = "short-circuit-side-effect"
GAP_DESTRUCTOR: Final = "destructor-control-flow"
GAP_LAMBDA: Final = "lambda-body"
GAP_COROUTINE: Final = "coroutine"
GAP_INDIRECT_CALL: Final = "indirect-call"
GAP_TEMPLATE: Final = "template-instantiation"
GAP_MACRO: Final = "macro-expansion"
GAP_CFG_UNSUPPORTED: Final = "cfg-unsupported"

# Gaps that answer the restricted-CFG whitelist (cfg_complete becomes False).
CFG_GAP_NAMES: Final = frozenset(
    {
        GAP_CFG_LOOP,
        GAP_CFG_SWITCH,
        GAP_CFG_GOTO,
        GAP_CFG_EXCEPTION,
        GAP_SHORT_CIRCUIT,
        GAP_DESTRUCTOR,
        GAP_LAMBDA,
        GAP_COROUTINE,
        GAP_INDIRECT_CALL,
        GAP_TEMPLATE,
        GAP_MACRO,
        GAP_CFG_UNSUPPORTED,
    }
)

_STRUCTURED_CFG_GAPS: Final = {
    "ForStmt": GAP_CFG_LOOP,
    "WhileStmt": GAP_CFG_LOOP,
    "DoStmt": GAP_CFG_LOOP,
    "CXXForRangeStmt": GAP_CFG_LOOP,
    "SwitchStmt": GAP_CFG_SWITCH,
    "GotoStmt": GAP_CFG_GOTO,
    "IndirectGotoStmt": GAP_CFG_GOTO,
    "LabelStmt": GAP_CFG_GOTO,
    "CXXTryStmt": GAP_CFG_EXCEPTION,
    "CXXCatchStmt": GAP_CFG_EXCEPTION,
    "SEHTryStmt": GAP_CFG_EXCEPTION,
    "SEHExceptStmt": GAP_CFG_EXCEPTION,
    "SEHFinallyStmt": GAP_CFG_EXCEPTION,
}

# Statement kinds the walker recurses into structurally.  Expression
# statements are everything else matching _is_expression_kind; anything else
# in a statement position records ``cfg-unsupported`` (fail closed).
STMT_KINDS: Final = frozenset(
    {
        "CompoundStmt",
        "IfStmt",
        "ForStmt",
        "WhileStmt",
        "DoStmt",
        "SwitchStmt",
        "CaseStmt",
        "DefaultStmt",
        "LabelStmt",
        "GotoStmt",
        "IndirectGotoStmt",
        "BreakStmt",
        "ContinueStmt",
        "ReturnStmt",
        "DeclStmt",
        "NullStmt",
        "AttributedStmt",
        "CXXTryStmt",
        "CXXCatchStmt",
        "CXXForRangeStmt",
        "CoroutineBodyStmt",
        "SEHTryStmt",
        "SEHExceptStmt",
        "SEHFinallyStmt",
    }
)
_NON_EXPR_SUFFIX_OPERATOR_KINDS: Final = frozenset(
    {"UnaryOperator", "BinaryOperator", "CompoundAssignOperator"}
)

_ASSIGN_OPCODES: Final = frozenset(
    {"=", "+=", "-=", "*=", "/=", "%=", "<<=", ">>=", "&=", "|=", "^="}
)
_ALLOCATION_CALLS: Final = {"malloc": "malloc", "calloc": "calloc", "realloc": "realloc"}
_BUILTIN_TYPE_BASES: Final = frozenset(
    {
        "void",
        "_Bool",
        "bool",
        "char",
        "signed char",
        "unsigned char",
        "short",
        "unsigned short",
        "int",
        "unsigned int",
        "long",
        "unsigned long",
        "long long",
        "unsigned long long",
        "float",
        "double",
        "long double",
        "wchar_t",
        "char16_t",
        "char32_t",
        "char8_t",
        "size_t",
        "ssize_t",
        "ptrdiff_t",
        "intptr_t",
        "uintptr_t",
    }
)
_TYPE_IGNORE_PREFIXES: Final = ("const ", "volatile ", "struct ", "class ", "enum ")


# ------------------------------------------------------------------ helpers


def build_line_offsets(source_bytes: bytes) -> tuple[int, ...]:
    """Return the start offset of every source line (for offset bisecting).

    Fallback for clang dumps whose location objects carry only ``offset``
    (no ``line``): line number = ``bisect_right(offsets, offset)``.
    """

    offsets = [0]
    for index, byte in enumerate(source_bytes):
        if byte == 0x0A:
            offsets.append(index + 1)
    return tuple(offsets)


def _line_of(location: Any, line_offsets: Sequence[int] | None) -> int | None:
    """Resolve one dump location to a 1-based line, or ``None``."""

    if not isinstance(location, dict):
        return None
    value = location.get("line")
    if type(value) is int and value >= 1:
        return value
    offset = location.get("offset")
    if type(offset) is int and offset >= 0 and line_offsets:
        index = bisect.bisect_right(line_offsets, offset)
        if index >= 1:
            return index
    return None


def _fact_range(node: dict, line_offsets: Sequence[int] | None) -> tuple[int, int] | None:
    """One node's (begin, end) line pair, or ``None`` when unresolvable."""

    source_range = node.get("range")
    if isinstance(source_range, dict):
        begin = _line_of(source_range.get("begin"), line_offsets)
        end = _line_of(source_range.get("end"), line_offsets)
        if begin is None:
            begin = end
        if end is None:
            end = begin
        if begin is not None and end >= begin:
            return (begin, end)
        return None
    line = _line_of(node.get("loc"), line_offsets)
    return (line, line) if line is not None else None


def _unwrap_expression(node: dict) -> dict:
    """Descend through casts and parens to the underlying expression."""

    seen = node
    for _ in range(32):
        kind = seen.get("kind")
        if kind in {"ImplicitCastExpr", "ParenExpr", "CStyleCastExpr", "UnaryOperator"}:
            children = seen.get("inner")
            # A cast/paren unwraps; a unary operator only unwraps for address-of.
            if kind == "UnaryOperator" and seen.get("opcode") != "&":
                break
            if isinstance(children, list) and children and isinstance(children[0], dict):
                seen = children[0]
                continue
        break
    return seen


def _direct_pointer_name(node: Any) -> str | None:
    """The local raw-pointer variable name a use expression binds to."""

    if not isinstance(node, dict):
        return None
    unwrapped = _unwrap_expression(node)
    if unwrapped.get("kind") != "DeclRefExpr":
        return None
    referenced = unwrapped.get("referencedDecl")
    if not isinstance(referenced, dict):
        return None
    name = referenced.get("name")
    if not isinstance(name, str) or not name:
        return None
    qual_type = _qual_type(unwrapped)
    if qual_type is not None and "*" not in qual_type:
        return None
    return name


def _qual_type(node: dict) -> str | None:
    type_info = node.get("type")
    if isinstance(type_info, dict):
        value = type_info.get("qualType")
        if isinstance(value, str):
            return value
    return None


def _callee_name(call: dict) -> str | None:
    """Resolve a direct callee name; ``None`` means indirect/unresolvable."""

    children = call.get("inner")
    if not isinstance(children, list) or not children:
        return None
    callee = _unwrap_expression(children[0])
    if callee.get("kind") != "DeclRefExpr":
        return None
    referenced = callee.get("referencedDecl")
    if not isinstance(referenced, dict):
        return None
    name = referenced.get("name")
    return name if isinstance(name, str) and name else None


def _is_expression_kind(kind: str) -> bool:
    return kind.endswith("Expr") or kind in _NON_EXPR_SUFFIX_OPERATOR_KINDS


def _has_side_effect(node: dict) -> bool:
    kind = node.get("kind")
    if kind == "CallExpr" or kind in {"CXXNewExpr", "CXXDeleteExpr", "CXXThrowExpr"}:
        return True
    if kind in {"BinaryOperator", "CompoundAssignOperator"} and (
        node.get("opcode") in _ASSIGN_OPCODES
    ):
        return True
    if kind == "UnaryOperator" and node.get("opcode") in {"++", "--"}:
        return True
    children = node.get("inner")
    if isinstance(children, list):
        return any(isinstance(child, dict) and _has_side_effect(child) for child in children)
    return False


def _manages_local_storage(qual_type: str) -> bool:
    """Whether a local variable's type may run a non-trivial destructor."""

    if "*" in qual_type:
        return False
    base = qual_type.split("[", 1)[0].strip()
    changed = True
    while changed:
        changed = False
        for prefix in _TYPE_IGNORE_PREFIXES:
            if base.startswith(prefix):
                base = base[len(prefix) :].strip()
                changed = True
    return base not in _BUILTIN_TYPE_BASES


def _walk_nodes(root: dict, *, skip_lambda: bool = False) -> Any:
    """Yield every dict node of the dump subtree (pre-order)."""

    stack = [root]
    while stack:
        node = stack.pop()
        if not isinstance(node, dict):
            continue
        yield node
        if skip_lambda and node.get("kind") == "LambdaExpr":
            continue
        children = node.get("inner")
        if isinstance(children, list):
            stack.extend(child for child in children if isinstance(child, dict))


def _contains_template_decl(root: dict) -> bool:
    for node in _walk_nodes(root):
        kind = node.get("kind")
        if isinstance(kind, str) and kind.endswith("Decl") and "Template" in kind:
            return True
        if node.get("isTemplateInstantiation") is True:
            return True
    return False


def _has_error_diagnostics(root: dict) -> bool:
    diagnostics = root.get("diagnostics")
    if not isinstance(diagnostics, list):
        return False
    for entry in diagnostics:
        if isinstance(entry, dict):
            severity = entry.get("severity")
            if isinstance(severity, str) and severity.lower() in {"error", "fatal"}:
                return True
    return False


def _macro_expansion_ranges(root: dict) -> list[tuple[int, int]]:
    """Byte-offset ranges of ``MacroExpansion`` decls (detailed record)."""

    ranges: list[tuple[int, int]] = []
    for node in _walk_nodes(root):
        if node.get("kind") != "MacroExpansion":
            continue
        source_range = node.get("range")
        if not isinstance(source_range, dict):
            continue
        begin = source_range.get("begin")
        end = source_range.get("end")
        if (
            isinstance(begin, dict)
            and isinstance(end, dict)
            and type(begin.get("offset")) is int
            and type(end.get("offset")) is int
        ):
            ranges.append((begin["offset"], end["offset"]))
    return ranges


def _overlaps(body_offsets: tuple[int, int] | None, macro: tuple[int, int]) -> bool:
    if body_offsets is None:
        return True  # cannot refute the overlap: fail closed
    return macro[0] <= body_offsets[1] and body_offsets[0] <= macro[1]


def _function_body(function: dict) -> dict | None:
    children = function.get("inner")
    if not isinstance(children, list):
        return None
    for child in children:
        if isinstance(child, dict) and child.get("kind") in {"CompoundStmt", "CoroutineBodyStmt"}:
            return child
    return None


def _iter_functions(root: dict) -> Any:
    """Yield ``FunctionDecl`` nodes with a body, never inside lambdas."""

    for node in _walk_nodes(root, skip_lambda=True):
        if node.get("kind") == "FunctionDecl" and _function_body(node) is not None:
            yield node


# ------------------------------------------------------------- fact assembly


class _UnitSink:
    """Ordered, bounded collector for one translation unit's facts and gaps."""

    def __init__(self, translation_unit: str, canonical_path: str) -> None:
        self._translation_unit = translation_unit
        self._canonical_path = canonical_path
        self.facts: list[dict[str, object]] = []
        self.gaps: list[str] = []
        self._seen_gaps: set[str] = set()
        self._ordinals: dict[tuple, int] = {}
        self.allocation_by_pointer: dict[str, str] = {}

    def add_gap(self, gap: str) -> None:
        if gap in self._seen_gaps or len(self.gaps) >= MAX_UNIT_GAPS:
            return
        self._seen_gaps.add(gap)
        self.gaps.append(gap)

    def next_ordinal(self, key: tuple) -> int:
        ordinal = self._ordinals.get(key, 0) + 1
        self._ordinals[key] = ordinal
        return ordinal

    def add_fact(
        self,
        *,
        kind: str,
        function_usr: str,
        source_range: tuple[int, int],
        cfg_block: int,
        api: str = "",
        pointer_id: str = "",
        source_pointer_id: str = "",
        related_fact_ids: Sequence[str] = (),
    ) -> str:
        if len(self.facts) >= MAX_FACTS_PER_UNIT:
            self.add_gap(GAP_FACT_BUDGET)
            return ""
        ordinal_key = (kind, api, pointer_id, source_pointer_id, source_range, function_usr)
        ordinal = self.next_ordinal(ordinal_key)
        material = {
            "api": api,
            "canonical_path": self._canonical_path,
            "function_usr": function_usr,
            "kind": kind,
            "ordinal": ordinal,
            "pointer_id": pointer_id,
            "range": [source_range[0], source_range[1]],
            "source_pointer_id": source_pointer_id,
        }
        encoded = json.dumps(material, sort_keys=True, separators=(",", ":")).encode("utf-8")
        fact_id = hashlib.sha256(encoded).hexdigest()
        fact: dict[str, object] = {
            "fact_id": fact_id,
            "kind": kind,
            "translation_unit": self._translation_unit,
            "canonical_path": self._canonical_path,
            "function_usr": function_usr,
            "source_range": [source_range[0], source_range[1]],
            "cfg_block": cfg_block,
        }
        if kind == "allocation":
            fact["allocation_api"] = api
            fact["pointer_id"] = pointer_id
        elif kind == "release":
            fact["release_api"] = api
            fact["pointer_id"] = pointer_id
            fact["related_fact_ids"] = list(dict.fromkeys(related_fact_ids))
        elif kind in {"dereference", "member-access"}:
            fact["pointer_id"] = pointer_id
        elif kind == "alias-copy":
            fact["pointer_id"] = pointer_id
            fact["source_pointer_id"] = source_pointer_id
        elif kind in {"points-to", "rebind"}:
            fact["pointer_id"] = pointer_id
            fact["source_pointer_id"] = source_pointer_id
            fact["related_fact_ids"] = list(dict.fromkeys(related_fact_ids))
        self.facts.append(fact)
        if kind == "allocation" and pointer_id:
            self.allocation_by_pointer[pointer_id] = fact_id
        return fact_id


class _FunctionContext:
    def __init__(
        self, function_usr: str, sink: _UnitSink, line_offsets: Sequence[int] | None
    ) -> None:
        self.function_usr = function_usr
        self.sink = sink
        self.line_offsets = line_offsets


def _fact_source_range(node: dict, context: _FunctionContext) -> tuple[int, int] | None:
    source_range = _fact_range(node, context.line_offsets)
    if source_range is None:
        context.sink.add_gap(GAP_AST_LINE_UNAVAILABLE)
    return source_range


def _handle_new(
    node: dict, target_pointer: str | None, cfg_block: int, context: _FunctionContext
) -> str | None:
    """Emit one ``allocation`` fact for a supported ``new``; return its id."""

    if node.get("isArray") is True:
        context.sink.add_gap(GAP_ARRAY_NEW)
        return None
    if "placementArgs" in node or "placement" in node:
        # placement new restarts a lifetime on existing storage: a phase-1
        # non-goal, so it is recorded as a gap instead of an allocation.
        context.sink.add_gap(GAP_LIFETIME_RESTART)
        return None
    source_range = _fact_source_range(node, context)
    if source_range is None:
        return None
    return context.sink.add_fact(
        kind="allocation",
        function_usr=context.function_usr,
        source_range=source_range,
        cfg_block=cfg_block,
        api="new",
        pointer_id=target_pointer or "",
    )


def _handle_allocation_call(
    call: dict,
    api: str,
    target_pointer: str | None,
    cfg_block: int,
    context: _FunctionContext,
) -> str | None:
    source_range = _fact_source_range(call, context)
    if source_range is None:
        return None
    return context.sink.add_fact(
        kind="allocation",
        function_usr=context.function_usr,
        source_range=source_range,
        cfg_block=cfg_block,
        api=api,
        pointer_id=target_pointer or "",
    )


def _handle_call(
    call: dict, target_pointer: str | None, cfg_block: int, context: _FunctionContext
) -> str | None:
    """Extract allocation/release facts from one call expression."""

    name = _callee_name(call)
    if name is None:
        # An unresolvable callee could be an indirect alloc/free: fail closed.
        context.sink.add_gap(GAP_INDIRECT_CALL)
        _scan_children(call, None, cfg_block, context)
        return None
    if name in _ALLOCATION_CALLS:
        fact_id = _handle_allocation_call(
            call, _ALLOCATION_CALLS[name], target_pointer, cfg_block, context
        )
        _scan_children(call, None, cfg_block, context)
        return fact_id
    if name == "free":
        source_range = _fact_source_range(call, context)
        children = call.get("inner")
        arguments = children[1:] if isinstance(children, list) else []
        pointer = _direct_pointer_name(arguments[0]) if arguments else None
        if source_range is not None:
            related: list[str] = []
            if pointer and pointer in context.sink.allocation_by_pointer:
                related.append(context.sink.allocation_by_pointer[pointer])
            context.sink.add_fact(
                kind="release",
                function_usr=context.function_usr,
                source_range=source_range,
                cfg_block=cfg_block,
                api="free",
                pointer_id=pointer or "",
                related_fact_ids=related,
            )
        for argument in arguments:
            _scan_expression(argument, cfg_block, context, target_pointer=None)
        return None
    _scan_children(call, None, cfg_block, context)
    return None


def _scan_children(
    node: dict, target_pointer: str | None, cfg_block: int, context: _FunctionContext
) -> str | None:
    """Scan children; return the first top-level allocation fact id seen."""

    children = node.get("inner")
    if isinstance(children, list):
        for child in children:
            if isinstance(child, dict):
                allocation_id = _scan_expression(
                    child, cfg_block, context, target_pointer=target_pointer
                )
                if allocation_id is not None:
                    return allocation_id
    return None


def _scan_expression(
    node: dict,
    cfg_block: int,
    context: _FunctionContext,
    *,
    target_pointer: str | None = None,
) -> str | None:
    """Walk one expression tree; return a top-level allocation fact id.

    ``target_pointer`` threads the pointer variable an initializer or
    assignment binds, so allocation facts carry their owning pointer.
    Lambda bodies are never descended (gap instead); coroutine and throw
    markers are recorded while the tree keeps being walked.
    """

    kind = node.get("kind")
    if kind == "LambdaExpr":
        context.sink.add_gap(GAP_LAMBDA)
        return None
    if kind == "StmtExpr":
        context.sink.add_gap(GAP_CFG_UNSUPPORTED)
        return None
    if kind == "CXXThrowExpr":
        context.sink.add_gap(GAP_CFG_EXCEPTION)
    if isinstance(kind, str) and ("Coroutine" in kind or kind == "CXXAwaitExpr"):
        context.sink.add_gap(GAP_COROUTINE)
    if kind in {"CXXMemberCallExpr", "CXXOperatorCallExpr"}:
        # Member/operator calls resolve virtually or through objects: an
        # unresolvable lifecycle transition fails closed as indirect.
        context.sink.add_gap(GAP_INDIRECT_CALL)
        _scan_children(node, None, cfg_block, context)
        return None
    if kind == "CallExpr":
        return _handle_call(node, target_pointer, cfg_block, context)
    if kind == "CXXNewExpr":
        fact_id = _handle_new(node, target_pointer, cfg_block, context)
        _scan_children(node, None, cfg_block, context)
        return fact_id
    if kind == "CXXDeleteExpr":
        children = node.get("inner")
        operand = children[0] if isinstance(children, list) and children else None
        pointer = _direct_pointer_name(operand)
        source_range = _fact_source_range(node, context)
        if source_range is not None:
            related: list[str] = []
            if pointer and pointer in context.sink.allocation_by_pointer:
                related.append(context.sink.allocation_by_pointer[pointer])
            context.sink.add_fact(
                kind="release",
                function_usr=context.function_usr,
                source_range=source_range,
                cfg_block=cfg_block,
                api="delete",
                pointer_id=pointer or "",
                related_fact_ids=related,
            )
        if isinstance(operand, dict):
            _scan_expression(operand, cfg_block, context, target_pointer=None)
        return None
    if kind == "UnaryOperator":
        opcode = node.get("opcode")
        children = node.get("inner")
        operand = children[0] if isinstance(children, list) and children else None
        if opcode in {"*", "deref"}:
            pointer = _direct_pointer_name(operand)
            if pointer is not None:
                source_range = _fact_source_range(node, context)
                if source_range is not None:
                    context.sink.add_fact(
                        kind="dereference",
                        function_usr=context.function_usr,
                        source_range=source_range,
                        cfg_block=cfg_block,
                        pointer_id=pointer,
                    )
            else:
                context.sink.add_gap(GAP_COMPLEX_USE)
            if isinstance(operand, dict):
                _scan_expression(operand, cfg_block, context, target_pointer=None)
            return None
        return _scan_children(node, None, cfg_block, context)
    if kind == "MemberExpr":
        if node.get("isArrow") is True:
            children = node.get("inner")
            base = children[0] if isinstance(children, list) and children else None
            pointer = _direct_pointer_name(base)
            if pointer is not None:
                source_range = _fact_source_range(node, context)
                if source_range is not None:
                    context.sink.add_fact(
                        kind="member-access",
                        function_usr=context.function_usr,
                        source_range=source_range,
                        cfg_block=cfg_block,
                        pointer_id=pointer,
                    )
            else:
                context.sink.add_gap(GAP_COMPLEX_USE)
            if isinstance(base, dict):
                _scan_expression(base, cfg_block, context, target_pointer=None)
            return None
        _scan_children(node, None, cfg_block, context)
        return None
    if kind in {"BinaryOperator", "CompoundAssignOperator"}:
        return _scan_binary(node, cfg_block, context)
    return _scan_children(node, target_pointer, cfg_block, context)


def _scan_binary(node: dict, cfg_block: int, context: _FunctionContext) -> str | None:
    opcode = node.get("opcode")
    children = node.get("inner")
    if not isinstance(children, list) or len(children) < 2:
        _scan_children(node, None, cfg_block, context)
        return None
    lhs, rhs = children[0], children[1]
    if opcode in {"&&", "||"}:
        if _has_side_effect(node):
            context.sink.add_gap(GAP_SHORT_CIRCUIT)
        _scan_children(node, None, cfg_block, context)
        return None
    if opcode == "=" and isinstance(lhs, dict):
        pointer = _direct_pointer_name(lhs)
        if pointer is not None and isinstance(rhs, dict):
            allocation_id = _scan_expression(rhs, cfg_block, context, target_pointer=pointer)
            source_range = _fact_source_range(node, context)
            if source_range is not None:
                if allocation_id is not None:
                    context.sink.add_fact(
                        kind="rebind",
                        function_usr=context.function_usr,
                        source_range=source_range,
                        cfg_block=cfg_block,
                        pointer_id=pointer,
                        source_pointer_id="",
                        related_fact_ids=[allocation_id],
                    )
                else:
                    source_pointer = _direct_pointer_name(rhs)
                    if source_pointer is not None:
                        context.sink.add_fact(
                            kind="alias-copy",
                            function_usr=context.function_usr,
                            source_range=source_range,
                            cfg_block=cfg_block,
                            pointer_id=pointer,
                            source_pointer_id=source_pointer,
                        )
            _scan_expression(lhs, cfg_block, context, target_pointer=None)
            return None
    _scan_expression(lhs, cfg_block, context, target_pointer=None)
    if isinstance(rhs, dict):
        _scan_expression(rhs, cfg_block, context, target_pointer=None)
    return None


def _handle_decl_stmt(stmt: dict, cfg_block: int, context: _FunctionContext) -> None:
    children = stmt.get("inner")
    if not isinstance(children, list):
        return
    for child in children:
        if not isinstance(child, dict) or child.get("kind") != "VarDecl":
            continue
        qual_type = _qual_type(child)
        if qual_type is not None and _manages_local_storage(qual_type):
            context.sink.add_gap(GAP_DESTRUCTOR)
        init_children = child.get("inner")
        init = (
            init_children[0]
            if isinstance(init_children, list)
            and init_children
            and isinstance(init_children[0], dict)
            else None
        )
        name = child.get("name")
        pointer_name = name if isinstance(name, str) and name else None
        if init is None:
            continue
        if pointer_name is None:
            _scan_expression(init, cfg_block, context, target_pointer=None)
            continue
        allocation_id = _scan_expression(init, cfg_block, context, target_pointer=pointer_name)
        source_range = _fact_source_range(stmt, context)
        if source_range is None:
            continue
        if allocation_id is not None:
            context.sink.add_fact(
                kind="points-to",
                function_usr=context.function_usr,
                source_range=source_range,
                cfg_block=cfg_block,
                pointer_id=pointer_name,
                source_pointer_id="",
                related_fact_ids=[allocation_id],
            )
        else:
            source_pointer = _direct_pointer_name(init)
            if source_pointer is not None:
                context.sink.add_fact(
                    kind="alias-copy",
                    function_usr=context.function_usr,
                    source_range=source_range,
                    cfg_block=cfg_block,
                    pointer_id=pointer_name,
                    source_pointer_id=source_pointer,
                )


def _visit_statement(stmt: dict, counter: itertools.count, context: _FunctionContext) -> None:
    kind = stmt.get("kind")
    cfg_block = next(counter)
    structured_gap = _STRUCTURED_CFG_GAPS.get(kind if isinstance(kind, str) else "")
    if structured_gap is not None:
        context.sink.add_gap(structured_gap)
    if kind == "CoroutineBodyStmt" or (isinstance(kind, str) and "Coroutine" in kind):
        context.sink.add_gap(GAP_COROUTINE)
    if kind == "DeclStmt":
        _handle_decl_stmt(stmt, cfg_block, context)
        return
    if kind == "CompoundStmt":
        children = stmt.get("inner")
        if isinstance(children, list):
            for child in children:
                if not isinstance(child, dict):
                    continue
                _visit_child(child, counter, context)
        return
    children = stmt.get("inner")
    if not isinstance(children, list):
        return
    for child in children:
        if not isinstance(child, dict):
            continue
        child_kind = child.get("kind")
        if child_kind in STMT_KINDS:
            _visit_statement(child, counter, context)
        elif isinstance(child_kind, str) and _is_expression_kind(child_kind):
            _scan_expression(child, cfg_block, context, target_pointer=None)
        else:
            # Unknown statement-position node: fail closed, but still scan
            # any expression children so facts are not silently lost.
            context.sink.add_gap(GAP_CFG_UNSUPPORTED)
            for grandchild in child.get("inner") or []:
                if (
                    isinstance(grandchild, dict)
                    and isinstance(grandchild.get("kind"), str)
                    and _is_expression_kind(grandchild["kind"])
                ):
                    _scan_expression(grandchild, cfg_block, context, target_pointer=None)


def _visit_child(child: dict, counter: itertools.count, context: _FunctionContext) -> None:
    if child.get("kind") in STMT_KINDS:
        _visit_statement(child, counter, context)
        return
    cfg_block = next(counter)
    child_kind = child.get("kind")
    if isinstance(child_kind, str) and _is_expression_kind(child_kind):
        _scan_expression(child, cfg_block, context, target_pointer=None)
    else:
        context.sink.add_gap(GAP_CFG_UNSUPPORTED)
        for grandchild in child.get("inner") or []:
            if (
                isinstance(grandchild, dict)
                and isinstance(grandchild.get("kind"), str)
                and _is_expression_kind(grandchild["kind"])
            ):
                _scan_expression(grandchild, cfg_block, context, target_pointer=None)


# ------------------------------------------------------------ public stages


def extract_ast_json(
    snapshot: Any,
    source_path: str,
    arguments: Sequence[str],
    working_directory: str,
    deadline: Any,
    *,
    timeout_seconds: int,
) -> tuple[dict | None, list[str] | None]:
    """Run the audited clang driver and parse one bounded ``-ast-dump=json``.

    The compiler is always a pinned ``clang-14``/``clang++-14`` driver chosen
    from the source language (never the repository's own ``arguments[0]``);
    only the resolver's semantic arguments are forwarded.  Returns
    ``(ast, None)`` or ``(None, [gap])`` with ``ast-unavailable``,
    ``ast-output-limit`` or ``ast-json-invalid``.
    """

    driver = _driver_for(source_path, arguments)
    argv = [
        driver,
        "-fsyntax-only",
        "-Xclang",
        "-ast-dump=json",
        "-Xclang",
        "-detailed-preprocessing-record",
        *semantic_arguments(arguments),
        source_path,
    ]
    execution = run_step(
        argv,
        snapshot,
        working_directory or ".",
        timeout_seconds,
        MAX_AST_JSON_BYTES,
        None,
        deadline=deadline,
    )
    if execution.status != "completed":
        return None, [GAP_AST_UNAVAILABLE]
    if execution.output_truncated:
        return None, [GAP_AST_OUTPUT_LIMIT]
    try:
        parsed = json.loads(execution.stdout)
    except (json.JSONDecodeError, ValueError, TypeError, RecursionError):
        return None, [GAP_AST_JSON_INVALID]
    if not isinstance(parsed, dict) or parsed.get("kind") != "TranslationUnitDecl":
        return None, [GAP_AST_JSON_INVALID]
    return parsed, None


def _driver_for(source_path: str, arguments: Sequence[str]) -> str:
    compiler = arguments[0] if arguments else ""
    try:
        is_cxx = language_for_path(source_path) == "c++"
    except ValueError:
        is_cxx = False
    if "++" in Path(compiler).name or is_cxx:
        return "clang++-14"
    return "clang-14"


def extract_uaf_facts(
    ast_json: Any,
    translation_unit: str,
    canonical_path: str,
    line_offsets: Sequence[int] | None = None,
) -> dict[str, object]:
    """Extract wire facts + completeness from one parsed clang AST dump.

    Pure and deterministic: identical ASTs produce identical fact ids.
    Returns ``{"facts": [...], "coverage": {"ast_complete", "cfg_complete",
    "semantic_gaps"}}``.  ``cfg_complete`` is true exactly when every
    function stayed inside the restricted-CFG whitelist.
    """

    sink = _UnitSink(translation_unit, canonical_path)
    if (
        not isinstance(ast_json, dict)
        or ast_json.get("kind") != "TranslationUnitDecl"
    ):
        return {
            "facts": [],
            "coverage": {
                "ast_complete": False,
                "cfg_complete": False,
                "semantic_gaps": [GAP_AST_JSON_INVALID],
            },
        }

    ast_complete = not _has_error_diagnostics(ast_json)
    if not ast_complete:
        sink.add_gap(GAP_AST_ERROR_DIAGNOSTIC)
    has_templates = _contains_template_decl(ast_json)
    if has_templates:
        sink.add_gap(GAP_TEMPLATE)
    macro_ranges = _macro_expansion_ranges(ast_json)

    for function in _iter_functions(ast_json):
        body = _function_body(function)
        if body is None:  # pragma: no cover - _iter_functions guarantees this
            continue
        function_name = function.get("name") if isinstance(function.get("name"), str) else ""
        body_bounds = _range_bounds_offsets(body)
        if any(_overlaps(body_bounds, macro) for macro in macro_ranges):
            sink.add_gap(GAP_MACRO)
        body_line = _line_of(body.get("loc"), line_offsets) or 0
        function_usr = f"{canonical_path}#{function_name}@{body_line}"
        sink.add_gap(GAP_USR_SYNTHESIZED)
        context = _FunctionContext(function_usr, sink, line_offsets)
        _visit_statement(body, itertools.count(1), context)

    gaps = sink.gaps
    return {
        "facts": sink.facts,
        "coverage": {
            "ast_complete": ast_complete,
            "cfg_complete": not any(gap in CFG_GAP_NAMES for gap in gaps),
            "semantic_gaps": list(gaps),
        },
    }


def _range_bounds_offsets(body: dict) -> tuple[int, int] | None:
    """Best-effort byte-offset bounds of a body range; ``None`` when absent."""

    source_range = body.get("range")
    if isinstance(source_range, dict):
        begin = source_range.get("begin")
        end = source_range.get("end")
        if (
            isinstance(begin, dict)
            and isinstance(end, dict)
            and type(begin.get("offset")) is int
            and type(end.get("offset")) is int
        ):
            return (begin["offset"], end["offset"])
    return None
