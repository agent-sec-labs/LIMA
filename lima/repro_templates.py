"""PoC driver templates for the agent reproduction workbench (design §5.1).

One minimal, self-contained C++ skeleton per memory-safety class.  Each
template declares every ``#include`` it needs, so a rendered template is a
standalone translation unit plus the target declarations the agent fills
in from the snapshot.

Placeholder convention: a closed ``{{UPPER_CASE}}`` vocabulary, replaced
verbatim by :func:`render_driver`.

* ``{{HEADER_DECL}}`` -- declaration block the target call needs (types,
  prototypes or ``#include`` lines copied from the snapshot).
* ``{{TARGET_FUNC}}`` -- the target function name.
* ``{{TARGET_ARGS}}`` -- the C++ argument list for that call; reference the
  ``poc_object``/``poc_buffer`` driver variables where the pattern needs to
  hand driver-state to the target.

Templates are a convenience starting point, never a security boundary: an
agent may ignore them entirely and write fully custom ``driver_code`` --
model-generated drivers and rendered templates enter the same sandbox
under the same budget either way (design invariant 5).  Rendering is pure
string substitution: no compilation, no file, and no network side effects.
"""

from __future__ import annotations

import re

PLACEHOLDER_NAMES = frozenset({"HEADER_DECL", "TARGET_FUNC", "TARGET_ARGS"})

_PLACEHOLDER_PATTERN = re.compile(r"\{\{([A-Z_]+)\}\}")

HEAP_UAF_TEMPLATE = """\
// PoC driver template: heap-use-after-free (CWE-416).
// Pattern: allocate a heap object, free it, then call the target function
// with the dangling pointer so the target touches freed memory.
// HEADER_DECL: declarations the target call needs (types + prototype or
// snapshot includes). TARGET_FUNC: target function name. TARGET_ARGS:
// argument list -- reference poc_object to pass the freed pointer.
{{HEADER_DECL}}
#include <cstdio>
#include <cstring>

int main() {
    unsigned char *poc_object = new unsigned char[64];
    std::memset(poc_object, 0, 64);
    delete[] poc_object;  // freed here (ASan freed-by frame)
    std::printf("calling target\\n");
    {{TARGET_FUNC}}({{TARGET_ARGS}});  // target reuses freed memory
    return 0;
}
"""

DOUBLE_FREE_TEMPLATE = """\
// PoC driver template: double-free (CWE-415).
// Pattern: allocate a heap buffer, free it once here, then call the target
// function so it frees the same memory again.  If the target takes
// ownership and frees its argument, calling it twice with one object also
// works -- adapt the body freely; this file is only a starting point.
// TARGET_ARGS: cast poc_object to the parameter type the target expects.
{{HEADER_DECL}}
#include <cstdio>
#include <cstdlib>

int main() {
    void *poc_object = std::malloc(64);
    if (poc_object == nullptr) {
        return 1;
    }
    std::free(poc_object);  // first free (ASan freed-by frame)
    std::printf("calling target\\n");
    {{TARGET_FUNC}}({{TARGET_ARGS}});  // target frees the same memory again
    return 0;
}
"""

HEAP_OVERFLOW_TEMPLATE = """\
// PoC driver template: heap-buffer-overflow (CWE-787 write family).
// Pattern: allocate an intentionally small heap buffer, then call the
// target function with a length or index that makes it write past the
// buffer end.  TARGET_ARGS: pass poc_buffer plus a size that exceeds 8.
{{HEADER_DECL}}
#include <cstdio>
#include <cstring>

int main() {
    unsigned char *poc_buffer = new unsigned char[8];  // deliberately small
    std::memset(poc_buffer, 0, 8);
    std::printf("calling target\\n");
    {{TARGET_FUNC}}({{TARGET_ARGS}});  // target writes past the 8-byte buffer
    delete[] poc_buffer;
    return 0;
}
"""

NULL_DEREF_TEMPLATE = """\
// PoC driver template: null pointer dereference (CWE-476).
// Pattern: call the target function with a null pointer where it
// dereferences without a guard.  TARGET_ARGS: pass nullptr (or a null
// member/handle) for the vulnerable parameter.  ASan reports this as SEGV
// on an unknown address rather than a named heap error.
{{HEADER_DECL}}
#include <cstdio>

int main() {
    std::printf("calling target\\n");
    {{TARGET_FUNC}}({{TARGET_ARGS}});  // e.g. "nullptr" for a pointer parameter
    return 0;
}
"""

INTEGER_OVERFLOW_TEMPLATE = """\
// PoC driver template: integer overflow to memory corruption (CWE-190).
// Pattern: the target computes its allocation size as count * sizeof(T) in
// a width-limited integer; a large count overflows that multiplication
// first, malloc receives the wrapped small size, and the target then
// writes the full logical count into the small buffer.  TARGET_ARGS: pass
// poc_count (the oversized count) and poc_buffer to the target so it
// repeats the overflowing size math on its own side.
{{HEADER_DECL}}
#include <cstdio>
#include <cstdlib>
#include <cstring>

int main() {
    int poc_count = 1073741825;  // (INT_MAX / sizeof(int)) + 1: wraps
    int total = poc_count * static_cast<int>(sizeof(int));  // overflows
    if (total <= 0) {
        return 1;
    }
    unsigned char *poc_buffer =
        static_cast<unsigned char *>(std::malloc((size_t)total));
    if (poc_buffer == nullptr) {
        return 1;
    }
    std::memset(poc_buffer, 0, (size_t)total);
    std::printf("calling target\\n");
    {{TARGET_FUNC}}({{TARGET_ARGS}});  // target's size arithmetic overflows
    std::free(poc_buffer);
    return 0;
}
"""

GENERIC_CALL_TEMPLATE = """\
// PoC driver template: generic call (defect triggered inside the target).
// Pattern: no caller-side memory orchestration -- just invoke the target
// function and let its own internals trigger the defect.  Use this when
// the hypothesis needs no special caller state, or as the base for a
// fully custom driver body.
{{HEADER_DECL}}
#include <cstdio>

int main() {
    std::printf("calling target\\n");
    {{TARGET_FUNC}}({{TARGET_ARGS}});
    return 0;
}
"""

DRIVER_TEMPLATES: dict[str, str] = {
    "heap-uaf": HEAP_UAF_TEMPLATE,
    "double-free": DOUBLE_FREE_TEMPLATE,
    "heap-overflow": HEAP_OVERFLOW_TEMPLATE,
    "null-deref": NULL_DEREF_TEMPLATE,
    "integer-overflow": INTEGER_OVERFLOW_TEMPLATE,
    "generic-call": GENERIC_CALL_TEMPLATE,
}

TEMPLATE_NAMES = frozenset(DRIVER_TEMPLATES)


def list_templates() -> list[str]:
    """Return the sorted template catalogue."""

    return sorted(DRIVER_TEMPLATES)


def _template_placeholders(template: str) -> set[str]:
    return set(_PLACEHOLDER_PATTERN.findall(template))


def render_driver(template_name: str, **placeholders: str) -> str:
    """Render one driver template with every placeholder replaced.

    The contract is closed: an unknown template, a missing placeholder, an
    unknown placeholder or a non-string placeholder value all raise
    ``ValueError``.  Values are substituted verbatim -- escaping or
    validating their C++ content is the agent loop's job, and the sandbox
    owns the consequences either way.
    """

    if template_name not in DRIVER_TEMPLATES:
        raise ValueError(f"unknown PoC driver template: {template_name!r}")
    template = DRIVER_TEMPLATES[template_name]
    required = _template_placeholders(template)
    missing = required - set(placeholders)
    unknown = set(placeholders) - required
    if missing:
        raise ValueError(
            f"template {template_name!r} is missing placeholders: {sorted(missing)}"
        )
    if unknown:
        raise ValueError(
            f"template {template_name!r} does not use placeholders: {sorted(unknown)}"
        )
    rendered = template
    for name, value in placeholders.items():
        if not isinstance(value, str):
            raise ValueError(f"placeholder {name} must be a string, got {type(value).__name__}")
        rendered = rendered.replace("{{" + name + "}}", value)
    return rendered


__all__ = [
    "DRIVER_TEMPLATES",
    "PLACEHOLDER_NAMES",
    "TEMPLATE_NAMES",
    "list_templates",
    "render_driver",
]
