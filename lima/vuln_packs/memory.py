"""The memory-safety vulnerability pack (plan Task 5, design section 4).

Six classes, one pack: heap use-after-free (CWE-416), double free
(CWE-415), heap buffer overflow writes (CWE-787), buffer overflow reads
(CWE-125), null pointer dereference (CWE-476) and integer overflow leading
to memory corruption (CWE-190).  The first four entries consolidate what
the platform orchestrator hard-coded before the pack existed -- moved
verbatim, behaviour preserved -- and the last two extend the pack.

Marker data follows the sanitizers' own vocabulary: AddressSanitizer
reports a null dereference as ``SEGV on unknown address ...`` rather than a
named heap error, and integer overflow itself is a UBSan diagnosis
(``signed-integer-overflow`` & co.), so CWE-190 carries no plain-ASan
marker -- its rules live in ``integer_overflow_markers``.  A wrapped size
that later overflows the heap surfaces as ``heap-buffer-overflow``, which
stays bound to CWE-787/125 and never claims CWE-190.
"""

from __future__ import annotations

from . import VulnPack

MEMORY_PACK = VulnPack(
    name="memory",
    cwe_ids=frozenset({
        "CWE-416", "CWE-415", "CWE-787", "CWE-125", "CWE-476", "CWE-190",
    }),
    specialist_prompt_addendum=(
        "\n\nMemory bug-class knowledge:\n"
        "- CWE-416 use-after-free: the object's lifetime ended (free/delete) "
        "before the hypothesized access; exclude rebinds and lifetime "
        "restarts before claiming the class.\n"
        "- CWE-415 double-free: one allocation reaches two release sites; "
        "ownership transfer and error-path cleanup make this plausible.\n"
        "- CWE-787 heap buffer overflow (write family): a write index or "
        "length beyond the allocation; check the real allocation size "
        "against the largest possible write.\n"
        "- CWE-125 buffer overflow (read family): the same arithmetic on the "
        "read side; off-by-one lengths and missing NUL terminators are "
        "typical.\n"
        "- CWE-476 null pointer dereference: an access through a pointer "
        "that can be null on this path (failed allocation, optional lookup, "
        "caller passes null) with no guard; AddressSanitizer reports the "
        "fault as SEGV on an unknown (often 0x0) address, not a named heap "
        "error.\n"
        "- CWE-190 integer overflow to memory corruption: allocation-size "
        "arithmetic (count * sizeof(T), n + m) computed in a width-limited "
        "integer; the wrapped size allocates a small buffer while the code "
        "later writes or reads the full logical size.  Confirm with "
        "UBSan-style signed/unsigned-integer-overflow reports; a downstream "
        "heap-buffer-overflow alone stays CWE-787/125.\n"
    ),
    seed_patterns=(
        # Null pointer dereference: pointer member access, null spellings
        # and null-guard shapes (a deref pattern with no guard nearby).
        "->",
        r"\bnull(ptr)?\b",
        r"== *(0|null|nullptr)\b",
        r"if *\( *[!]? *[a-z_]+ *\)",
        # Integer overflow to memory corruption: length arithmetic feeding
        # an allocator (size computed before the malloc, overflow first).
        r"malloc\([^)]*\*",
        r"realloc\([^)]*\*",
        r"[a-z_]+ *\* *sizeof",
        r"sizeof\([^)]*\) *\* *[a-z_]+",
    ),
    driver_templates=(
        "heap-uaf",
        "double-free",
        "heap-overflow",
        "null-deref",
        "integer-overflow",
    ),
    # ASan error-type substrings per hypothesized CWE class.  The four
    # legacy entries are the pre-pack orchestrator table, verbatim.
    # ``buffer-overflow`` deliberately matches CWE-787 and CWE-125 alike:
    # the error type alone does not carry the read/write distinction.
    asan_markers={
        "CWE-416": ("use-after-free",),
        "CWE-415": ("double-free",),
        "CWE-787": ("buffer-overflow",),
        "CWE-125": ("buffer-overflow",),
        "CWE-476": ("segv on unknown address",),
        "CWE-190": (),
    },
    # UBSan-style integer-overflow diagnostics (substring -> CWE).  Folded
    # into the effective matching table by vuln_packs.runtime_markers.
    integer_overflow_markers={
        "signed-integer-overflow": "CWE-190",
        "unsigned-integer-overflow": "CWE-190",
        "cannot be represented in type": "CWE-190",
    },
)
