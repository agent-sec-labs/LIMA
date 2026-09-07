"""Bounded, read-only agent tools over the fixed C/C++ snapshot index.

Security boundary (design spec section 7):

* Read-only: every tool reads only from the in-memory snapshot index and the
  injected snapshot reader. This module performs no write operations, no
  network access and no subprocess execution.
* Path validation is threefold: every path must be a plain relative POSIX
  ``str`` (shared :func:`lima.cxx_retrieval._validate_changed_path` rules),
  it must be part of the index coverage (``coverage.indexed``), and any
  non-``str`` value such as ``pathlib.Path`` is rejected outright. Validation
  completes before the reader is touched, so unindexed or escaping paths
  never reach the content layer.
* Budgets are atomic: each invocation deducts ``calls`` plus the exact
  output size (files/lines/bytes where applicable) in one locked
  transaction. Either the whole deduction fits or nothing is charged and no
  content is returned. The per-call cap and the cumulative cap share one
  pool bounded by ``max_output_bytes``, so a single response can never
  exceed the cap and the task total can never exceed it either. The billed
  size is the payload only -- the UTF-8 bytes of the returned ``content``
  (snippet tools) or of the canonical JSON payload (list tools); the
  response envelope (field names, hashes, snapshot id) is not billed.
* Evidence isolation: ``get_tool_evidence`` is registered only in the
  evidence registry; the review registry rejects it as an unknown tool.
* Injection stance: source text, queries and identifiers are always data.
  Code content is returned verbatim with its SHA-256; queries are literal
  substrings; candidate ids are opaque keys. Nothing in this module
  interprets, executes or evaluates caller-controlled strings.

Deduction order per invocation: validate arguments -> resolve data from the
index/reader -> build the exact response -> atomically consume ``calls``
plus the response's actual files/lines/bytes -> return. A failed deduction
leaves the budget completely untouched (no content, and because the
transaction is atomic there is no call charge to refund); a failed argument
validation or a failed read likewise charges nothing.
"""

from __future__ import annotations

import hashlib
import json
import threading
from collections.abc import Callable
from dataclasses import asdict, dataclass
from typing import Any, Protocol

from .cxx_context import CxxContextIndex, SymbolRecord
from .cxx_retrieval import (
    _matching_callee_symbols,
    _name_matches,
    _symbol_lookups,
    _validate_changed_path,
)
from .models import EvidenceRecord
from .runtime import AgentTool, ToolRegistry

MAX_SYMBOL_LIMIT = 200


class AgentBudgetExceeded(RuntimeError):
    """The task-level agent tool budget cannot cover one more response."""


class SnapshotReader(Protocol):
    """Read-only snapshot text access (production: ``RepositoryWorkspace``)."""

    def read_text(self, path: str) -> str:
        """Return the fixed snapshot text of one validated relative path."""


@dataclass(frozen=True)
class RemainingBudget:
    """Read-only snapshot of the budget remaining; never mutates the pool."""

    calls: int
    files: int
    lines: int
    bytes_remaining: int


class _Usage:
    """Mutable per-task usage guarded by the owning budget's lock."""

    __slots__ = ("files_read", "used_bytes", "used_calls", "used_files", "used_lines")

    def __init__(self) -> None:
        self.used_calls = 0
        self.used_files = 0
        self.used_lines = 0
        self.used_bytes = 0
        self.files_read: set[str] = set()


@dataclass(frozen=True)
class CxxAgentBudget:
    """Task-level tool budget: immutable caps, lock-guarded mutable usage.

    All deductions go through :meth:`consume`, a single-lock atomic
    transaction: the four remaining amounts are checked together and either
    every one of them fits or nothing is charged and
    :class:`AgentBudgetExceeded` is raised.

    Equality and repr cover only the four caps: instances with equal caps
    are deliberately the same configuration even while their mutable usage
    differs.
    """

    max_calls: int = 40
    max_context_files: int = 12
    max_context_lines: int = 1200
    max_output_bytes: int = 1_048_576

    def __post_init__(self) -> None:
        for name in (
            "max_calls",
            "max_context_files",
            "max_context_lines",
            "max_output_bytes",
        ):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
                raise ValueError(f"{name} must be a positive integer, got {value!r}")
        object.__setattr__(self, "_lock", threading.Lock())
        object.__setattr__(self, "_usage", _Usage())

    def consume(
        self,
        *,
        calls: int = 0,
        files: int = 0,
        lines: int = 0,
        bytes: int = 0,
        file_path: str | None = None,
    ) -> None:
        """Atomically deduct one combined demand or charge nothing at all.

        ``file_path`` deduplicates the ``files`` charge: the first charge for
        a snapshot path costs ``files``; later charges for the same path cost
        zero files because the file already sits in the pool.
        """
        amounts = (("calls", calls), ("files", files), ("lines", lines), ("bytes", bytes))
        for name, value in amounts:
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise ValueError(
                    f"budget amount {name} must be a non-negative integer, got {value!r}"
                )
        with self._lock:
            usage = self._usage
            charge_files = files
            if files and file_path is not None and file_path in usage.files_read:
                charge_files = 0
            checks = (
                ("calls", usage.used_calls, calls, self.max_calls),
                ("files", usage.used_files, charge_files, self.max_context_files),
                ("lines", usage.used_lines, lines, self.max_context_lines),
                ("bytes", usage.used_bytes, bytes, self.max_output_bytes),
            )
            for name, used, request, cap in checks:
                if used + request > cap:
                    raise AgentBudgetExceeded(
                        f"agent tool budget exhausted for {name}: "
                        f"needs {request} more, only {cap - used} remaining"
                    )
            usage.used_calls += calls
            usage.used_files += charge_files
            usage.used_lines += lines
            usage.used_bytes += bytes
            if charge_files and file_path is not None:
                usage.files_read.add(file_path)

    def consume_call(self) -> None:
        """Charge one tool invocation."""
        self.consume(calls=1)

    def consume_files(self, count: int = 1) -> None:
        """Charge snapshot files against the context-file pool."""
        self.consume(files=count)

    def consume_lines(self, count: int = 1) -> None:
        """Charge code lines against the context-line pool."""
        self.consume(lines=count)

    def consume_bytes(self, count: int = 1) -> None:
        """Charge UTF-8 output bytes against the output pool."""
        self.consume(bytes=count)

    def remaining(self) -> RemainingBudget:
        """Return a frozen read-only snapshot of what is left."""
        with self._lock:
            usage = self._usage
            return RemainingBudget(
                calls=self.max_calls - usage.used_calls,
                files=self.max_context_files - usage.used_files,
                lines=self.max_context_lines - usage.used_lines,
                bytes_remaining=self.max_output_bytes - usage.used_bytes,
            )


@dataclass(frozen=True)
class SymbolHit:
    """One indexed symbol match; ``symbol_id`` equals ``qualified_name``."""

    symbol_id: str
    qualified_name: str
    file: str
    start_line: int
    end_line: int
    kind: str
    snapshot_sha256: str


@dataclass(frozen=True)
class SymbolRef:
    """One resolved symbol reference; ``symbol_id`` equals ``qualified_name``."""

    symbol_id: str
    qualified_name: str
    file: str
    line: int
    snapshot_sha256: str


@dataclass(frozen=True)
class CodeSnippet:
    """A verified snapshot range; ``sha256`` is the UTF-8 SHA-256 of ``content``."""

    path: str
    start_line: int
    end_line: int
    content: str
    sha256: str
    snapshot_sha256: str


class _ToolContext:
    """Shared read-only view over one snapshot index for the tool handlers."""

    __slots__ = ("budget", "by_location", "by_name", "indexed", "index", "reader")

    def __init__(self, index: CxxContextIndex, reader: SnapshotReader, budget) -> None:
        self.index = index
        self.indexed = frozenset(index.coverage.indexed)
        self.reader = reader
        self.budget = budget
        self.by_location, self.by_name = _symbol_lookups(index)


def _payload_bytes(payload: Any) -> int:
    """UTF-8 size of the canonical JSON rendering of a tool response."""
    rendered = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return len(rendered.encode("utf-8"))


def _sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _require_text(value: Any, field_name: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{field_name} must be a string, got {type(value).__name__}")
    return value


def _require_line_number(value: Any, field_name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise ValueError(f"{field_name} must be a positive integer, got {value!r}")
    return value


def _require_limit(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError("limit must be an integer")
    if not 1 <= value <= MAX_SYMBOL_LIMIT:
        raise ValueError(f"limit must be between 1 and {MAX_SYMBOL_LIMIT}")
    return value


def _validated_path(ctx: _ToolContext, path: str) -> str:
    """Shared escape checks plus indexed-coverage membership; reader untouched."""
    _validate_changed_path(path)
    if path not in ctx.indexed:
        raise ValueError(f"path is not part of the indexed snapshot: {path!r}")
    return path


def _refs_for_records(records: list[SymbolRecord], snapshot_sha256: str) -> list[SymbolRef]:
    unique: dict[tuple[str, int, str], SymbolRecord] = {}
    for record in records:
        unique[(record.file, record.start_line, record.qualified_name)] = record
    refs = [
        SymbolRef(
            symbol_id=record.qualified_name,
            qualified_name=record.qualified_name,
            file=record.file,
            line=record.start_line,
            snapshot_sha256=snapshot_sha256,
        )
        for record in unique.values()
    ]
    refs.sort(key=lambda ref: (ref.file, ref.line, ref.qualified_name))
    return refs


def _record_payload(records: list[Any]) -> list[dict[str, Any]]:
    return [asdict(record) for record in records]


def _search_symbols_handler(ctx: _ToolContext) -> Callable[..., list[SymbolHit]]:
    def search_symbols(query: str, limit: int = 20) -> list[SymbolHit]:
        """Substring-search indexed symbols; the query is literal text."""
        text = _require_text(query, "query")
        bounded = _require_limit(limit)
        hits = [
            SymbolHit(
                symbol_id=record.qualified_name,
                qualified_name=record.qualified_name,
                file=record.file,
                start_line=record.start_line,
                end_line=record.end_line,
                kind=record.kind,
                snapshot_sha256=ctx.index.snapshot_sha256,
            )
            for record in ctx.index.symbols
            if text in record.qualified_name
        ]
        hits.sort(key=lambda hit: (hit.file, hit.start_line, hit.qualified_name))
        hits = hits[:bounded]
        ctx.budget.consume(
            calls=1, bytes=_payload_bytes(_record_payload(hits))
        )
        return hits

    return search_symbols


def _read_code_snippet_handler(ctx: _ToolContext) -> Callable[..., CodeSnippet]:
    def read_code_snippet(path: str, start_line: int, end_line: int) -> CodeSnippet:
        """Read a validated 1-based closed line range of one indexed file.

        Lines are counted on U+000A (LF) only, matching the index, the
        unified-diff hunk and editor line numbering; a trailing newline
        leaves one phantom empty element that is not a readable line.
        ``end_line`` beyond the file's actual line count is rejected, not
        truncated: the spec requires valid line ranges and rejecting keeps
        the returned range, the charged lines and the auditable hash exactly
        the ones requested.
        """
        _require_text(path, "path")
        start = _require_line_number(start_line, "start_line")
        end = _require_line_number(end_line, "end_line")
        if start > end:
            raise ValueError(f"start_line {start} must not exceed end_line {end}")
        _validated_path(ctx, path)
        lines = ctx.reader.read_text(path).split("\n")
        if lines and lines[-1] == "":
            lines = lines[:-1]
        if end > len(lines):
            raise ValueError(
                f"end_line {end} exceeds the {len(lines)} lines of the indexed {path!r}"
            )
        content = "\n".join(lines[start - 1:end])
        ctx.budget.consume(
            calls=1,
            files=1,
            lines=end - start + 1,
            bytes=len(content.encode("utf-8")),
            file_path=path,
        )
        return CodeSnippet(
            path=path,
            start_line=start,
            end_line=end,
            content=content,
            sha256=_sha256_text(content),
            snapshot_sha256=ctx.index.snapshot_sha256,
        )

    return read_code_snippet


def _find_callers_handler(ctx: _ToolContext) -> Callable[..., list[SymbolRef]]:
    def find_callers(symbol_id: str, limit: int = 20) -> list[SymbolRef]:
        """List indexed symbols whose written call edges resolve to the symbol."""
        _require_text(symbol_id, "symbol_id")
        bounded = _require_limit(limit)
        refs: list[SymbolRef] = []
        if symbol_id in ctx.by_name:
            callers: list[SymbolRecord] = []
            for edge in ctx.index.calls:
                if _name_matches(symbol_id, edge.callee):
                    callers.extend(ctx.by_name.get(edge.caller, ()))
            refs = _refs_for_records(callers, ctx.index.snapshot_sha256)[:bounded]
        ctx.budget.consume(calls=1, bytes=_payload_bytes(_record_payload(refs)))
        return refs

    return find_callers


def _find_callees_handler(ctx: _ToolContext) -> Callable[..., list[SymbolRef]]:
    def find_callees(symbol_id: str, limit: int = 20) -> list[SymbolRef]:
        """List indexed symbols this symbol's written call edges resolve to."""
        _require_text(symbol_id, "symbol_id")
        bounded = _require_limit(limit)
        refs: list[SymbolRef] = []
        if symbol_id in ctx.by_name:
            targets: list[SymbolRecord] = []
            for edge in ctx.index.calls:
                if edge.caller == symbol_id:
                    targets.extend(_matching_callee_symbols(ctx.by_name, edge.callee))
            refs = _refs_for_records(targets, ctx.index.snapshot_sha256)[:bounded]
        ctx.budget.consume(calls=1, bytes=_payload_bytes(_record_payload(refs)))
        return refs

    return find_callees


def _find_references_handler(ctx: _ToolContext) -> Callable[..., list[SymbolRef]]:
    def find_references(symbol_id: str, limit: int = 40) -> list[SymbolRef]:
        """List length-API references recorded inside the named symbol."""
        _require_text(symbol_id, "symbol_id")
        bounded = _require_limit(limit)
        refs: list[SymbolRef] = []
        if symbol_id in ctx.by_name:
            found = [ref for ref in ctx.index.references if ref.function == symbol_id]
            found.sort(key=lambda ref: (ref.file, ref.line, ref.api))
            refs = [
                SymbolRef(
                    symbol_id=ref.api,
                    qualified_name=ref.api,
                    file=ref.file,
                    line=ref.line,
                    snapshot_sha256=ctx.index.snapshot_sha256,
                )
                for ref in found
            ][:bounded]
        ctx.budget.consume(calls=1, bytes=_payload_bytes(_record_payload(refs)))
        return refs

    return find_references


def _get_type_definition_handler(ctx: _ToolContext) -> Callable[..., CodeSnippet | None]:
    def get_type_definition(type_name: str) -> CodeSnippet | None:
        """Return the indexed definition snippet of one exact type name.

        Same-name types resolve deterministically to the smallest
        ``(file, start_line)``. Types whose recorded file fails the
        indexed-coverage path validation are silently skipped; when no
        candidate remains the tool returns ``None`` with the call-only
        charge, so the skip stays observable through the budget. The line
        range comes from the index (not the caller) and is defensively
        clamped to the file's actual line count on U+000A accounting.
        """
        _require_text(type_name, "type_name")
        candidates = []
        for record in ctx.index.types:
            if record.name != type_name:
                continue
            try:
                _validated_path(ctx, record.file)
            except ValueError:
                continue
            candidates.append(record)
        if not candidates:
            ctx.budget.consume(calls=1, bytes=0)
            return None
        record = min(candidates, key=lambda item: (item.file, item.start_line))
        lines = ctx.reader.read_text(record.file).split("\n")
        if lines and lines[-1] == "":
            lines = lines[:-1]
        start = max(1, record.start_line)
        end = min(max(start, record.end_line), len(lines))
        content = "\n".join(lines[start - 1:end])
        ctx.budget.consume(
            calls=1,
            files=1,
            lines=end - start + 1,
            bytes=len(content.encode("utf-8")),
            file_path=record.file,
        )
        return CodeSnippet(
            path=record.file,
            start_line=start,
            end_line=end,
            content=content,
            sha256=_sha256_text(content),
            snapshot_sha256=ctx.index.snapshot_sha256,
        )

    return get_type_definition


def _get_tool_evidence_handler(
    evidence_lookup: Callable[[str], list[EvidenceRecord]],
    budget: CxxAgentBudget,
) -> Callable[..., list[EvidenceRecord]]:
    def get_tool_evidence(candidate_id: str) -> list[EvidenceRecord]:
        """Fetch stored tool evidence for one opaque candidate id."""
        _require_text(candidate_id, "candidate_id")
        records = evidence_lookup(candidate_id)
        if not isinstance(records, list):
            raise ValueError("evidence lookup must return a list of records")
        budget.consume(calls=1, bytes=_payload_bytes(_record_payload(records)))
        return list(records)

    return get_tool_evidence


def _object_schema(properties: dict[str, Any], required: list[str]) -> dict[str, Any]:
    return {
        "type": "object",
        "properties": properties,
        "required": required,
        "additionalProperties": False,
    }


_LIMIT_SCHEMA = {"type": "integer", "minimum": 1, "maximum": MAX_SYMBOL_LIMIT}


def _review_tools(ctx: _ToolContext) -> list[AgentTool]:
    return [
        AgentTool(
            "search_symbols",
            "Substring-search indexed snapshot symbols (literal text, deterministic order).",
            _object_schema(
                {"query": {"type": "string"}, "limit": dict(_LIMIT_SCHEMA)},
                ["query"],
            ),
            _search_symbols_handler(ctx),
        ),
        AgentTool(
            "read_code_snippet",
            "Read a validated 1-based closed line range from one indexed snapshot file.",
            _object_schema(
                {
                    "path": {"type": "string"},
                    "start_line": {"type": "integer", "minimum": 1},
                    "end_line": {"type": "integer", "minimum": 1},
                },
                ["path", "start_line", "end_line"],
            ),
            _read_code_snippet_handler(ctx),
        ),
        AgentTool(
            "find_callers",
            "List indexed symbols whose written call edges resolve to this symbol.",
            _object_schema(
                {"symbol_id": {"type": "string"}, "limit": dict(_LIMIT_SCHEMA)},
                ["symbol_id"],
            ),
            _find_callers_handler(ctx),
        ),
        AgentTool(
            "find_callees",
            "List indexed symbols this symbol's written call edges resolve to.",
            _object_schema(
                {"symbol_id": {"type": "string"}, "limit": dict(_LIMIT_SCHEMA)},
                ["symbol_id"],
            ),
            _find_callees_handler(ctx),
        ),
        AgentTool(
            "find_references",
            "List length-API references recorded inside this symbol.",
            _object_schema(
                {"symbol_id": {"type": "string"}, "limit": dict(_LIMIT_SCHEMA)},
                ["symbol_id"],
            ),
            _find_references_handler(ctx),
        ),
        AgentTool(
            "get_type_definition",
            "Return the indexed definition snippet of a type by exact name, or None.",
            _object_schema({"type_name": {"type": "string"}}, ["type_name"]),
            _get_type_definition_handler(ctx),
        ),
    ]


def build_review_registry(
    index: CxxContextIndex, reader: SnapshotReader, budget: CxxAgentBudget
) -> ToolRegistry:
    """Registry with exactly the six review-stage tools (no evidence access)."""
    return ToolRegistry(_review_tools(_ToolContext(index, reader, budget)))


def build_evidence_registry(
    index: CxxContextIndex,
    reader: SnapshotReader,
    budget: CxxAgentBudget,
    evidence_lookup: Callable[[str], list[EvidenceRecord]],
) -> ToolRegistry:
    """Registry with the six review tools plus ``get_tool_evidence``."""
    ctx = _ToolContext(index, reader, budget)
    return ToolRegistry(
        _review_tools(ctx)
        + [
            AgentTool(
                "get_tool_evidence",
                "Fetch stored tool evidence records for one opaque candidate id.",
                _object_schema({"candidate_id": {"type": "string"}}, ["candidate_id"]),
                _get_tool_evidence_handler(evidence_lookup, budget),
            )
        ]
    )


__all__ = [
    "AgentBudgetExceeded",
    "CxxAgentBudget",
    "CodeSnippet",
    "MAX_SYMBOL_LIMIT",
    "RemainingBudget",
    "SnapshotReader",
    "SymbolHit",
    "SymbolRef",
    "build_evidence_registry",
    "build_review_registry",
]
