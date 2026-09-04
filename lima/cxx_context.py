"""Deterministic, bounded symbol/type/call/resource indexing over snapshots.

The index is a conservative first pass: line-oriented scanning with brace
tracking, never a guess. Anything that cannot be parsed reliably is reported
as a coverage gap, and no call edge is emitted without a resolved caller
inside a tracked function body. Calls record the callee exactly as written;
no points-to resolution is attempted. Output ordering is fully deterministic
so identical snapshots produce identical indexes.

Contract: the caller must pass an inventory captured from the same working
tree at the same moment; every file is re-hashed during indexing and any
drift becomes a coverage gap instead of an out-of-band record.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from pathlib import PurePosixPath

from .workspace import (
    CXX_SOURCE_EXTENSIONS,
    RepositoryWorkspace,
    WorkspaceInventory,
)

MAX_PARSE_GAPS = 64
MAX_RECORDS = 20_000

_FUNCTION_HEAD = re.compile(
    r"^(?:[A-Za-z_][\w:<>,\s\"']*[\"\s\*&]+)?"
    r"(?P<name>[A-Za-z_]\w*(?:::~?[A-Za-z_]\w*)+|[A-Za-z_]\w*)"
    r"\s*\([^;{}]*\)\s*(?:const\s*)?(?:noexcept\s*)?(?:override\s*)?"
    r"(?:final\s*)?\{"
)
_HEAD_NO_BRACE = re.compile(
    r"^(?:[A-Za-z_][\w:<>,\s\"']*[\"\s\*&]+)?"
    r"(?P<name>[A-Za-z_]\w*(?:::~?[A-Za-z_]\w*)+|[A-Za-z_]\w*)"
    r"\s*\([^;{}]*\)\s*(?:const\s*)?(?:noexcept\s*)?(?:override\s*)?"
    r"(?:final\s*)?\s*$"
)
_CLASS_DEF = re.compile(
    r"^\s*(?:template\s*<[^>]*>\s*)?"
    r"(?P<kind>class|struct|union|enum(?:\s+class)?)\s+"
    r"(?P<name>[A-Za-z_]\w*)"
)
_TYPE_DEF = re.compile(
    r"^\s*typedef\s+[\w\s\*\[\]<>,:]+?\s+(?P<name>[A-Za-z_]\w*)\s*[;\[]"
)
_USING_DEF = re.compile(r"^\s*using\s+(?P<name>[A-Za-z_]\w*)\s*=")
_CALL = re.compile(r"\b(?P<callee>[A-Za-z_]\w*)\s*\(")
_MULTI_LINE_DEFINE = re.compile(r"^\s*#define\s+(?P<name>[A-Za-z_]\w*)\b.*\\\s*$")
_SCOPE_OPENER = re.compile(
    r"^\s*(?:namespace\b|extern\s*\"|}\s*else\s*\{|try\s*\{|do\s*\{)"
)
_KEYWORDS = frozenset(
    {
        "if", "for", "while", "switch", "return", "sizeof", "catch",
        "defined", "static_assert", "alignof", "typeof", "offsetof",
        "new", "delete", "throw", "else", "do", "case", "default",
    }
)
_ALLOC_APIS = frozenset({"malloc", "calloc", "realloc", "strdup"})
_RELEASE_APIS = frozenset({"free"})
_LENGTH_APIS = frozenset(
    {
        "memcpy", "memmove", "memset", "strcpy", "strncpy", "strcat",
        "strncat", "strlen", "snprintf", "sprintf",
    }
)
_NEW_ARRAY = re.compile(r"\bnew\s+[A-Za-z_][\w:<>,\s]*\[")
_NEW_PLAIN = re.compile(r"\bnew\b")
_DELETE_ARRAY = re.compile(r"\bdelete\s*\[\s*\]")
_DELETE_PLAIN = re.compile(r"\bdelete\b")


@dataclass(frozen=True)
class SymbolRecord:
    qualified_name: str
    file: str
    start_line: int
    end_line: int
    kind: str
    language: str


@dataclass(frozen=True)
class TypeRecord:
    name: str
    file: str
    start_line: int
    end_line: int
    kind: str


@dataclass(frozen=True)
class CallEdge:
    caller: str
    callee: str
    file: str
    line: int


@dataclass(frozen=True)
class ResourceEvent:
    event: str
    api: str
    function: str
    file: str
    line: int


@dataclass(frozen=True)
class ApiReference:
    api: str
    function: str
    file: str
    line: int


@dataclass(frozen=True)
class ParseGap:
    file: str
    reason: str


@dataclass(frozen=True)
class IndexedFile:
    file: str


@dataclass(frozen=True)
class IndexCoverage:
    indexed: tuple[str, ...]
    parse_gaps: tuple[ParseGap, ...]
    source_files_total: int
    symbols_indexed: int
    types_indexed: int
    calls_indexed: int
    resource_events_indexed: int

    @property
    def indexed_files(self) -> tuple[IndexedFile, ...]:
        return tuple(IndexedFile(file) for file in self.indexed)

    def indexed_files_as_strings(self) -> tuple[str, ...]:
        return self.indexed


@dataclass(frozen=True)
class CxxContextIndex:
    snapshot_sha256: str
    symbols: tuple[SymbolRecord, ...]
    types: tuple[TypeRecord, ...]
    calls: tuple[CallEdge, ...]
    references: tuple[ApiReference, ...]
    resource_events: tuple[ResourceEvent, ...]
    coverage: IndexCoverage

    @classmethod
    def build(
        cls,
        workspace: RepositoryWorkspace,
        inventory: WorkspaceInventory,
    ) -> CxxContextIndex:
        inventory_by_path = {item.path: item for item in inventory.files}
        files = sorted(
            (
                item
                for item in inventory.files
                if PurePosixPath(item.path).suffix.lower() in CXX_SOURCE_EXTENSIONS
            ),
            key=lambda item: item.path,
        )
        symbols: list[SymbolRecord] = []
        types: list[TypeRecord] = []
        calls: list[CallEdge] = []
        references: list[ApiReference] = []
        resource_events: list[ResourceEvent] = []
        gaps: list[ParseGap] = []
        indexed: list[str] = []

        for item in files:
            try:
                text = workspace.read_text(item.path)
            except (OSError, ValueError):
                gaps.append(ParseGap(item.path, "unreadable"))
                continue
            digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
            expected = inventory_by_path.get(item.path)
            if expected is None or digest != expected.sha256:
                gaps.append(ParseGap(item.path, "snapshot-drift"))
                continue
            try:
                result = _index_file(item.path, text)
            except _ParseFailure as exc:
                gaps.append(ParseGap(item.path, exc.reason))
                continue
            indexed.append(item.path)
            symbols.extend(result[0])
            types.extend(result[1])
            calls.extend(result[2])
            references.extend(result[3])
            resource_events.extend(result[4])
            if len(gaps) >= MAX_PARSE_GAPS:
                break

        symbols.sort(
            key=lambda record: (record.file, record.start_line, record.qualified_name)
        )
        types.sort(key=lambda record: (record.file, record.start_line, record.name))
        calls.sort(key=lambda edge: (edge.file, edge.line, edge.caller, edge.callee))
        references.sort(
            key=lambda ref: (ref.file, ref.line, ref.api, ref.function)
        )
        resource_events.sort(
            key=lambda event: (event.file, event.line, event.api, event.function)
        )
        symbols = symbols[:MAX_RECORDS]
        types = types[:MAX_RECORDS]
        calls = calls[:MAX_RECORDS]
        references = references[:MAX_RECORDS]
        resource_events = resource_events[:MAX_RECORDS]
        coverage = IndexCoverage(
            indexed=tuple(indexed),
            parse_gaps=tuple(gaps),
            source_files_total=len(files),
            symbols_indexed=len(symbols),
            types_indexed=len(types),
            calls_indexed=len(calls),
            resource_events_indexed=len(resource_events),
        )
        return cls(
            snapshot_sha256=inventory.fingerprint(),
            symbols=tuple(symbols),
            types=tuple(types),
            calls=tuple(calls),
            references=tuple(references),
            resource_events=tuple(resource_events),
            coverage=coverage,
        )


class _ParseFailure(Exception):
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


def _strip_comments_and_strings(text: str) -> str:
    """Blank out comment and string-literal bodies, preserving line structure."""

    result: list[str] = []
    in_block_comment = False
    in_string: str | None = None
    for line in text.splitlines():
        output: list[str] = []
        index = 0
        while index < len(line):
            if in_block_comment:
                close = line.find("*/", index)
                if close < 0:
                    output.append(" " * (len(line) - index))
                    index = len(line)
                else:
                    output.append(" " * (close + 2 - index))
                    index = close + 2
                    in_block_comment = False
                continue
            if in_string:
                character = line[index]
                if character == "\\" and index + 1 < len(line):
                    output.append("  ")
                    index += 2
                    continue
                if character == in_string:
                    in_string = None
                output.append(character)
                index += 1
                continue
            character = line[index]
            if character == "/" and line[index : index + 2] == "//":
                output.append(" " * (len(line) - index))
                break
            if character == "/" and line[index : index + 2] == "/*":
                in_block_comment = True
                output.append("  ")
                index += 2
                continue
            if character in "\"'":
                in_string = character
                output.append(character)
                index += 1
                continue
            output.append(character)
            index += 1
        result.append("".join(output))
    return "\n".join(result)


def _language_for(path: str) -> str:
    return "c" if PurePosixPath(path).suffix.lower() in {".c", ".h"} else "c++"


def _macro_gap(cleaned: str) -> str | None:
    """Detect multi-line macros expanded outside the preprocessor."""

    names = [
        match.group("name")
        for match in (
            _MULTI_LINE_DEFINE.match(raw) for raw in cleaned.splitlines()
        )
        if match
    ]
    for macro in names:
        pattern = re.compile(rf"\b{re.escape(macro)}\b")
        for raw in cleaned.splitlines():
            if raw.lstrip().startswith("#"):
                continue
            if pattern.search(raw):
                return macro
    return None


def _current_function(stack: list[tuple[str, str, int]]) -> tuple[str, int] | None:
    for kind, name, line in reversed(stack):
        if kind == "function":
            return (name, line)
    return None


def _in_scope_only(stack: list[tuple[str, str, int]]) -> bool:
    return all(kind == "scope" for kind, _, _ in stack)


def _scan_calls(
    line: str,
    body_start: int,
    caller: str,
    path: str,
    number: int,
    calls: list[CallEdge],
    references: list[ApiReference],
    resource_events: list[ResourceEvent],
) -> None:
    """Scan only the body fragment after a head's opening brace."""

    for call_match in _CALL.finditer(line, body_start):
        callee = call_match.group("callee")
        if callee in _KEYWORDS:
            continue
        calls.append(
            CallEdge(caller=caller, callee=callee, file=path, line=number)
        )
        if callee in _LENGTH_APIS:
            references.append(
                ApiReference(api=callee, function=caller, file=path, line=number)
            )
        if callee in _ALLOC_APIS:
            resource_events.append(
                ResourceEvent(
                    event="allocate", api=callee, function=caller,
                    file=path, line=number,
                )
            )
        elif callee in _RELEASE_APIS:
            resource_events.append(
                ResourceEvent(
                    event="release", api=callee, function=caller,
                    file=path, line=number,
                )
            )
    if _NEW_ARRAY.search(line):
        resource_events.append(
            ResourceEvent(
                event="allocate", api="new[]", function=caller,
                file=path, line=number,
            )
        )
    elif _NEW_PLAIN.search(line):
        resource_events.append(
            ResourceEvent(
                event="allocate", api="new", function=caller,
                file=path, line=number,
            )
        )
    if _DELETE_ARRAY.search(line):
        resource_events.append(
            ResourceEvent(
                event="release", api="delete[]", function=caller,
                file=path, line=number,
            )
        )
    elif _DELETE_PLAIN.search(line):
        resource_events.append(
            ResourceEvent(
                event="release", api="delete", function=caller,
                file=path, line=number,
            )
        )


def _index_file(
    path: str, text: str
) -> tuple[
    list[SymbolRecord], list[TypeRecord], list[CallEdge],
    list[ApiReference], list[ResourceEvent],
]:
    cleaned = _strip_comments_and_strings(text)
    offending_macro = _macro_gap(cleaned)
    if offending_macro is not None:
        raise _ParseFailure(
            f"untracked multi-line macro expansion: {offending_macro}"
        )

    lines = cleaned.splitlines()
    symbols: list[SymbolRecord] = []
    types: list[TypeRecord] = []
    calls: list[CallEdge] = []
    references: list[ApiReference] = []
    resource_events: list[ResourceEvent] = []

    # Each entry: (kind, name, line) with kind in function/scope/other.
    stack: list[tuple[str, str, int]] = []
    pending_head: tuple[str, int] | None = None

    for number, line in enumerate(lines, start=1):
        class_match = _CLASS_DEF.search(line)
        type_match = _TYPE_DEF.search(line)
        using_match = _USING_DEF.search(line)

        if class_match:
            types.append(
                TypeRecord(
                    name=class_match.group("name"),
                    file=path,
                    start_line=number,
                    end_line=_type_end(lines, number),
                    kind=class_match.group("kind").split()[0],
                )
            )
        if type_match:
            types.append(
                TypeRecord(
                    name=type_match.group("name"),
                    file=path,
                    start_line=number,
                    end_line=number,
                    kind="typedef",
                )
            )
        if using_match:
            types.append(
                TypeRecord(
                    name=using_match.group("name"),
                    file=path,
                    start_line=number,
                    end_line=number,
                    kind="alias",
                )
            )

        head_name: str | None = None
        head_brace: int = -1
        if _in_scope_only(stack):
            match = _FUNCTION_HEAD.match(line)
            if match and match.group("name") not in _KEYWORDS:
                head_name = match.group("name")
                head_brace = line.index("{", match.end("name"))
            elif pending_head is not None and line.lstrip().startswith("{"):
                head_name = pending_head[0]
                head_brace = line.index("{")
            else:
                candidate = _HEAD_NO_BRACE.match(line)
                if candidate and candidate.group("name") not in _KEYWORDS:
                    pending_head = (candidate.group("name"), number)
                elif pending_head is not None:
                    pending_head = None
        if pending_head is not None and line.lstrip().startswith("{") is False:
            if head_name is None and _in_scope_only(stack):
                follow = _HEAD_NO_BRACE.match(line)
                if not follow:
                    pending_head = None

        if head_name is not None:
            symbols.append(
                SymbolRecord(
                    qualified_name=head_name,
                    file=path,
                    start_line=(
                        pending_head[1]
                        if pending_head and line.lstrip().startswith("{")
                        else number
                    ),
                    end_line=number,
                    kind="method" if "::" in head_name else "function",
                    language="c++" if "::" in head_name else _language_for(path),
                )
            )

        current = _current_function(stack)
        if current is not None:
            caller = current[0]
            body_start = head_brace + 1 if head_brace >= 0 else 0
            _scan_calls(
                line, body_start, caller, path, number,
                calls, references, resource_events,
            )
        elif head_name is None:
            pass

        # Brace bookkeeping: attribute each opener on the line.
        opens_function = head_name
        opens_scope = _SCOPE_OPENER.match(line) or class_match
        for position, character in enumerate(line):
            if character == "{":
                if opens_function is not None and position == line.find("{"):
                    stack.append(("function", opens_function, number))
                    opens_function = None
                elif opens_scope is not None and not _current_function(stack):
                    stack.append(("scope", "", number))
                    opens_scope = None
                else:
                    stack.append(("other", "", number))
            elif character == "}":
                if not stack:
                    raise _ParseFailure(
                        f"unbalanced closing brace at line {number}"
                    )
                kind, name, start = stack.pop()
                if kind == "function":
                    for index, symbol in enumerate(symbols):
                        if (
                            symbol.qualified_name == name
                            and symbol.start_line == start
                        ):
                            symbols[index] = SymbolRecord(
                                qualified_name=symbol.qualified_name,
                                file=symbol.file,
                                start_line=symbol.start_line,
                                end_line=number,
                                kind=symbol.kind,
                                language=symbol.language,
                            )
                            break

    if stack:
        raise _ParseFailure(
            f"unbalanced braces at end of file (depth {len(stack)})"
        )

    return symbols, types, calls, references, resource_events


def _type_end(lines: list[str], start: int) -> int:
    depth = 0
    for number in range(start, len(lines) + 1):
        line = lines[number - 1]
        depth += line.count("{") - line.count("}")
        if depth <= 0 and ("}" in line or line.rstrip().endswith(";")):
            return number
    return start


__all__ = [
    "ApiReference",
    "CallEdge",
    "CxxContextIndex",
    "IndexCoverage",
    "IndexedFile",
    "ParseGap",
    "ResourceEvent",
    "SymbolRecord",
    "TypeRecord",
]
