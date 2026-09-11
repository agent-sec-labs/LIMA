"""Memory vulnerability pack tests (plan Task 5).

Design section 4 (``docs/superpowers/specs/2026-09-12-agent-vuln-platform-
design.md``): the platform kernel is bug-class agnostic; every bug class
ships as one frozen :class:`lima.vuln_packs.VulnPack` carrying the five
per-class assets -- Specialist knowledge, triage seed patterns, PoC driver
template names, ASan/UBSan interpretation rules and the CWE mapping.
Red lines pinned here:

- The memory pack covers exactly six classes: the four legacy classes
  (CWE-416/415/787/125) plus the two new ones (CWE-476 null dereference,
  CWE-190 integer overflow to memory corruption).
- Equivalence lock: the legacy ASan marker mappings in the pack are
  item-by-item identical to the table the orchestrator hard-coded before
  Task 5 -- consuming the pack changed zero legacy behaviour.
- The orchestrator derives its matching table and its hypothesis CWE
  vocabulary from the pack; the new classes walk the same closed loop
  (hypothesis -> experiment -> runtime-confirmed) under fakes.
- New-type paired fixtures exist for both new classes and are syntactically
  valid C (compiled when a C compiler is available, text-checked always).
"""

import inspect
import json
import re
import shutil
import subprocess
import tempfile
import unittest
from dataclasses import FrozenInstanceError
from pathlib import Path
from unittest.mock import patch

from lima.agent_orchestrator import (
    _SYSTEM_PLATFORM_SPECIALIST,
    PLATFORM_HYPOTHESIS_FIELDS,
    PlatformFormatError,
    _experiment_hit,
    parse_hypothesis_reply,
    run_platform_review,
)
from lima.agent_repro_tools import ExperimentObservation
from lima.agent_scout import ScoutLead
from lima.cxx_agent_tools import CxxAgentBudget
from lima.repro_templates import DRIVER_TEMPLATES, render_driver
from lima.workspace import RepositoryWorkspace

try:  # pack plugin interface (RED until implemented)
    from lima.vuln_packs import (
        MEMORY_PACK,
        VulnPack,
        get_pack,
        list_packs,
        runtime_markers,
    )
except ImportError:  # pragma: no cover - RED phase
    MEMORY_PACK = None

REPO_KEY = "team/project"
SNAPSHOT = "b" * 64
UNIT = "src/deref.c"
LEAD_LINE = 11  # the unguarded "return s->field;" in the vulnerable fixture

RESOLVED_LLM = {
    "provider": "custom",
    "base_url": "https://llm.example.invalid/v1",
    "api_key": "k",
    "model": "test-model",
    "headers": {},
}

FIXTURE_ROOT = Path(__file__).parent / "fixtures" / "vuln_packs" / "memory"
NULL_DEREF_VULNERABLE = (
    FIXTURE_ROOT / "null_deref" / "vulnerable" / "src" / "deref.c"
)
NULL_DEREF_FIXED = FIXTURE_ROOT / "null_deref" / "fixed" / "src" / "deref.c"
INT_OVERFLOW_VULNERABLE = (
    FIXTURE_ROOT / "int_overflow" / "vulnerable" / "src" / "overflow.c"
)
INT_OVERFLOW_FIXED = FIXTURE_ROOT / "int_overflow" / "fixed" / "src" / "overflow.c"

# The legacy table exactly as agent_orchestrator hard-coded it before the
# pack existed.  The pack must carry it verbatim (equivalence lock).
_LEGACY_ASAN_CWE_MARKERS = {
    "CWE-416": ("use-after-free",),
    "CWE-415": ("double-free",),
    "CWE-787": ("buffer-overflow",),
    "CWE-125": ("buffer-overflow",),
}


# ================================================================== pack


class MemoryPackContractTests(unittest.TestCase):
    """The memory pack is a complete, immutable, registered VulnPack."""

    def test_memory_pack_covers_six_cwes(self):
        self.assertIsNotNone(MEMORY_PACK)
        self.assertEqual("memory", MEMORY_PACK.name)
        self.assertEqual(
            frozenset({
                "CWE-416", "CWE-415", "CWE-787", "CWE-125",
                "CWE-476", "CWE-190",
            }),
            MEMORY_PACK.cwe_ids,
        )
        # The legacy four are still covered; the two new classes extend.
        self.assertTrue({"CWE-416", "CWE-415", "CWE-787", "CWE-125"}
                        .issubset(MEMORY_PACK.cwe_ids))
        self.assertTrue(MEMORY_PACK.specialist_prompt_addendum.strip())
        # Per-class knowledge, at least one paragraph per covered CWE.
        for cwe in MEMORY_PACK.cwe_ids:
            self.assertIn(cwe, MEMORY_PACK.specialist_prompt_addendum)
        # Registry access.
        self.assertIs(MEMORY_PACK, get_pack("memory"))
        self.assertIn("memory", list_packs())
        with self.assertRaises(KeyError):
            get_pack("no-such-pack")
        # Packs are frozen data: knowledge is versioned, not mutated.
        with self.assertRaises(FrozenInstanceError):
            MEMORY_PACK.name = "other"
        self.assertIsInstance(MEMORY_PACK, VulnPack)

    def test_memory_pack_driver_templates_resolve(self):
        for name in MEMORY_PACK.driver_templates:
            self.assertIn(name, DRIVER_TEMPLATES)
        # Both new classes have their own PoC driver template.
        self.assertIn("null-deref", MEMORY_PACK.driver_templates)
        self.assertIn("integer-overflow", MEMORY_PACK.driver_templates)
        # The four legacy classes keep theirs.
        for legacy in ("heap-uaf", "double-free", "heap-overflow"):
            self.assertIn(legacy, MEMORY_PACK.driver_templates)


class AsanMarkerEquivalenceTests(unittest.TestCase):
    """Legacy marker mappings moved verbatim; new classes add markers."""

    def test_asan_markers_cover_legacy_and_new(self):
        markers = runtime_markers(MEMORY_PACK)
        # Equivalence lock: the four legacy mappings are item-by-item
        # identical to the pre-pack hard-coded table.
        for cwe, expected in _LEGACY_ASAN_CWE_MARKERS.items():
            self.assertEqual(expected, markers[cwe])
        # The new classes have runtime interpretation rules too.
        self.assertTrue(markers["CWE-476"])
        self.assertTrue(markers["CWE-190"])
        self.assertIn("signed-integer-overflow", markers["CWE-190"])
        # Markers are lowercase substring matchers, as the orchestrator
        # matches them against the lowercased ASan error type.
        for cwe_markers in markers.values():
            for marker in cwe_markers:
                self.assertEqual(marker, marker.lower())
        # UBSan-style overflow markers map to CWE-190 only.
        self.assertTrue(MEMORY_PACK.integer_overflow_markers)
        for cwe in MEMORY_PACK.integer_overflow_markers.values():
            self.assertEqual("CWE-190", cwe)

    def test_hit_semantics_unchanged_for_legacy_and_extended_for_new(self):
        def observation(error_type):
            return ExperimentObservation(
                ok=True, stage="run", exit_code=-9, error_type=error_type,
                faulting_line=LEAD_LINE, freed_line=None, allocated_line=None,
                diagnostics=(), raw_tail="",
            )

        # Legacy four: byte-for-byte the pre-pack behaviour.
        self.assertTrue(_experiment_hit(
            observation("heap-use-after-free"), "CWE-416"))
        self.assertTrue(_experiment_hit(
            observation("double-free"), "CWE-415"))
        self.assertTrue(_experiment_hit(
            observation("heap-buffer-overflow"), "CWE-787"))
        self.assertTrue(_experiment_hit(
            observation("heap-buffer-overflow"), "CWE-125"))
        self.assertFalse(_experiment_hit(
            observation("heap-use-after-free"), "CWE-787"))
        # New classes: SEGV confirms a null-deref hypothesis; the UBSan
        # signed-integer-overflow marker confirms CWE-190.
        self.assertTrue(_experiment_hit(
            observation("SEGV on unknown address 0x000000000000"), "CWE-476"))
        self.assertTrue(_experiment_hit(
            observation("signed-integer-overflow"), "CWE-190"))
        # Cross-class hits still do not confirm.
        self.assertFalse(_experiment_hit(
            observation("SEGV on unknown address 0x000000000000"), "CWE-416"))
        self.assertFalse(_experiment_hit(
            observation("signed-integer-overflow"), "CWE-787"))
        # A clean run confirms nothing, for any class.
        clean = ExperimentObservation(
            ok=True, stage="run", exit_code=0, error_type=None,
            faulting_line=None, freed_line=None, allocated_line=None,
            diagnostics=(), raw_tail="",
        )
        for cwe in MEMORY_PACK.cwe_ids:
            self.assertFalse(_experiment_hit(clean, cwe))


class OrchestratorPackWiringTests(unittest.TestCase):
    """The orchestrator consumes the pack; no second hard-coded table."""

    def test_orchestrator_uses_pack_markers(self):
        import lima.agent_orchestrator as orchestrator

        # The matching table is derived from the pack, not re-hard-coded.
        self.assertEqual(
            dict(runtime_markers(MEMORY_PACK)),
            orchestrator._ASAN_CWE_MARKERS,
        )
        source = inspect.getsource(orchestrator)
        self.assertIn("MEMORY_PACK", source)
        self.assertNotIn('"use-after-free"', source)
        self.assertNotIn('"double-free"', source)
        self.assertNotIn('"buffer-overflow"', source)
        # The hypothesis contract vocabulary comes from the pack: the new
        # classes parse, unknown classes still reject.
        known = frozenset({"lead-476"})
        reply = json.dumps({
            "target_id": "lead-476",
            "hypothesis": "read_field dereferences s without a null guard",
            "trigger_path": ["caller_with_null", "read_field"],
            "cwe": "CWE-476",
            "driver_code": "int main() { return *(int *)0; }",
            "experiment_design": "run read_field(NULL) under ASan",
            "unresolved_assumptions": [],
        })
        self.assertEqual(PLATFORM_HYPOTHESIS_FIELDS, set(json.loads(reply)))
        hypothesis = parse_hypothesis_reply(reply, known)
        self.assertEqual("CWE-476", hypothesis.cwe)
        overflow = json.dumps({
            "target_id": "lead-476",
            "hypothesis": "count * sizeof(int) wraps before malloc",
            "trigger_path": ["make_table", "malloc"],
            "cwe": "CWE-190",
            "driver_code": "int main() { return make_table(0x40000001) != 0; }",
            "experiment_design": "large count into make_table under ASan",
            "unresolved_assumptions": [],
        })
        self.assertEqual("CWE-190", parse_hypothesis_reply(overflow, known).cwe)
        forged = reply.replace("CWE-476", "CWE-999")
        with self.assertRaises(PlatformFormatError):
            parse_hypothesis_reply(forged, known)
        # The Specialist prompt carries the pack knowledge and the extended
        # closed CWE enumeration; the legacy enumeration stays verbatim.
        for cwe in MEMORY_PACK.cwe_ids:
            self.assertIn(cwe, _SYSTEM_PLATFORM_SPECIALIST)
        self.assertIn(
            '"cwe":"CWE-416|CWE-415|CWE-787|CWE-125|CWE-476|CWE-190"',
            _SYSTEM_PLATFORM_SPECIALIST,
        )
        self.assertIn(MEMORY_PACK.specialist_prompt_addendum,
                      _SYSTEM_PLATFORM_SPECIALIST)


class SeedPatternTests(unittest.TestCase):
    """Triage seed patterns are valid, lowercase, non-empty regex data."""

    def test_seed_patterns_are_nonempty_and_lowercase(self):
        self.assertTrue(MEMORY_PACK.seed_patterns)
        for pattern in MEMORY_PACK.seed_patterns:
            self.assertTrue(pattern)
            self.assertEqual(pattern, pattern.lower())
            re.compile(pattern)  # must be a valid regex fragment
        joined = "\n".join(MEMORY_PACK.seed_patterns)
        # Both new bug classes contribute triage seeds.
        self.assertIn("->", joined)
        self.assertIn("sizeof", joined)
        self.assertIn("malloc", joined)


# =============================================================== templates


class IntegerOverflowTemplateTests(unittest.TestCase):
    """The integer-overflow driver template renders like its siblings."""

    def test_integer_overflow_template_renders(self):
        self.assertIn("integer-overflow", DRIVER_TEMPLATES)
        rendered = render_driver(
            "integer-overflow",
            HEADER_DECL="int *make_table(int count);",
            TARGET_FUNC="make_table",
            TARGET_ARGS="poc_count",
        )
        self.assertIn("int main()", rendered)
        self.assertIn("malloc", rendered)
        self.assertIn("make_table(poc_count)", rendered)
        self.assertNotIn("{{", rendered)
        # The closed placeholder contract is unchanged.
        with self.assertRaises(ValueError):
            render_driver(
                "integer-overflow", HEADER_DECL="", TARGET_FUNC="",
            )  # missing TARGET_ARGS
        with self.assertRaises(ValueError):
            render_driver(
                "integer-overflow", HEADER_DECL="", TARGET_FUNC="",
                TARGET_ARGS="", EXTRA="",
            )  # unknown placeholder
        with self.assertRaises(ValueError):
            render_driver(
                "no-such-template", HEADER_DECL="", TARGET_FUNC="",
                TARGET_ARGS="",
            )


# ================================================================ fixtures


def _c_compiler():
    for name in ("clang", "gcc", "cc"):
        found = shutil.which(name)
        if found:
            return found
    return None


class NewTypeFixtureTests(unittest.TestCase):
    """Paired vulnerable/fixed fixtures exist for both new classes."""

    def test_new_type_fixtures_compile(self):
        cases = [
            # Vulnerable: unguarded dereference reached with a null argument.
            (NULL_DEREF_VULNERABLE,
             ["s->field", "return read_field(NULL);"], ["if (s =="]),
            # Fixed: the guard returns instead of faulting.
            (NULL_DEREF_FIXED,
             ["s->field", "if (s == NULL)", "return read_field(NULL);"], []),
            # Vulnerable: the size product is truncated to int before malloc.
            (INT_OVERFLOW_VULNERABLE,
             ["(int)(count * sizeof(int))", "malloc(total)", "memset"],
             ["SIZE_MAX"]),
            # Fixed: size_t arithmetic behind an explicit range check.
            (INT_OVERFLOW_FIXED,
             ["size_t total", "(size_t)count * sizeof(int)", "SIZE_MAX"],
             ["int total ="]),
        ]
        for path, must_contain, must_not_contain in cases:
            with self.subTest(fixture=str(path)):
                text = path.read_text(encoding="utf-8")
                self.assertTrue(text.strip())
                for fragment in must_contain:
                    self.assertIn(fragment, text)
                for fragment in must_not_contain:
                    self.assertNotIn(fragment, text)
        compiler = _c_compiler()
        if compiler is None:
            # No C compiler on this host: text assertions above stand in.
            self.skipTest("no C compiler available; text assertions only")
        for path, _, _ in cases:
            with self.subTest(fixture=str(path)):
                completed = subprocess.run(  # noqa: S603 - fixed local fixture
                    [compiler, "-fsyntax-only", str(path)],
                    capture_output=True, text=True, timeout=60,
                )
                self.assertEqual(
                    0, completed.returncode,
                    f"{path} failed to parse: {completed.stderr}",
                )


# ================================================== end-to-end (new class)


LEAD = ScoutLead(
    lead_id="lead-476",
    path=UNIT,
    line=LEAD_LINE,
    summary="read_field dereferences s without a null guard; caller passes NULL",
    seed="null-deref-call",
    score=0,
)

NULL_DEREF_SOURCE = NULL_DEREF_VULNERABLE.read_text(encoding="utf-8")

NULL_DEREF_DRIVER = (
    "struct S { int field; };\n"
    "int read_field(struct S *s);\n"
    "int main() { return read_field(0); }\n"
)


def hypothesis_json(cwe="CWE-476", driver=NULL_DEREF_DRIVER):
    return json.dumps({
        "target_id": LEAD.lead_id,
        "hypothesis": "read_field dereferences s without a null guard and "
                      "the caller passes NULL",
        "trigger_path": ["caller_with_null", "read_field", "s->field"],
        "cwe": cwe,
        "driver_code": driver,
        "experiment_design": "compile deref.c with a driver calling "
                             "read_field(NULL) and run under ASan",
        "unresolved_assumptions": [],
    })


class OneShotSpecialistTransport:
    """Specialist wire double serving exactly one scripted reply."""

    def __init__(self, reply):
        self.reply = reply
        self.calls = 0

    def __call__(self, provider, base_url, api_key, payload, timeout,
                 extra_headers=None, max_bytes=None):
        self.calls += 1
        return self.reply


def scout_target_transport():
    """Escalate the reviewed lead as a scout target (house pattern)."""

    def transport(provider, base_url, api_key, payload, timeout,
                  extra_headers=None, max_bytes=None):
        user = payload["messages"][1]["content"]
        lead_id = next(
            line.split(": ", 1)[1]
            for line in user.splitlines()
            if line.startswith("- lead_id: ")
        )
        return json.dumps([{
            "lead_id": lead_id,
            "verdict": "target",
            "reason": "unguarded pointer member access on a null-able path",
            "confidence": "high",
        }])

    return transport


class FakeWorkbench:
    """Scripted ``run_experiment`` double recording every driver."""

    def __init__(self, observations):
        self.observations = list(observations)
        self.calls = []

    def run_experiment(
        self, repository_key, snapshot_hash, source_files, driver_code,
    ):
        self.calls.append((
            repository_key, snapshot_hash, tuple(source_files), driver_code,
        ))
        return self.observations.pop(0)


def segv_hit():
    """A null dereference surfaces as SEGV on a low unknown address."""

    return ExperimentObservation(
        ok=True, stage="run", exit_code=-11,
        error_type="SEGV on unknown address 0x000000000000",
        faulting_line=LEAD_LINE, freed_line=None, allocated_line=None,
        diagnostics=(), raw_tail="The signal is caused by a READ memory access.",
    )


class NullDerefEndToEndTests(unittest.TestCase):
    """The new class walks the full closed loop under fakes."""

    def test_null_deref_hypothesis_experiments_hit(self):
        root = tempfile.mkdtemp(suffix="-vuln-packs-null-deref")
        try:
            source_path = Path(root, UNIT)
            source_path.parent.mkdir(parents=True, exist_ok=True)
            source_path.write_bytes(NULL_DEREF_SOURCE.encode("utf-8"))
            workspace = RepositoryWorkspace(root)
            transport = OneShotSpecialistTransport(hypothesis_json())
            workbench = FakeWorkbench([segv_hit()])
            with patch(
                "lima.agent_scout.post_chat_completion_text",
                scout_target_transport(),
            ):
                with patch(
                    "lima.uaf_llm_branch.post_chat_completion_text",
                    transport,
                ):
                    outcome = run_platform_review(
                        None,
                        workspace,
                        repository_key=REPO_KEY,
                        snapshot_hash=SNAPSHOT,
                        mode="auto",
                        budget=CxxAgentBudget(
                            max_calls=64, max_output_bytes=1_048_576,
                        ),
                        llm_config=dict(RESOLVED_LLM),
                        repro_workbench=workbench,
                        leads=(LEAD,),
                    )
        finally:
            shutil.rmtree(root, ignore_errors=True)

        self.assertEqual(1, len(outcome.targets))
        target = outcome.targets[0]
        # The new class reaches runtime-confirmed through executed ASan
        # evidence, exactly like the legacy four.
        self.assertEqual("runtime-confirmed", target.state)
        self.assertEqual("CWE-476", target.cwe)
        self.assertEqual(1, len(outcome.findings))
        # The experiment ledger records the hit with the SEGV error type.
        self.assertEqual(1, len(target.experiment_log))
        entry = target.experiment_log[0]
        self.assertTrue(entry["hit"])
        self.assertEqual("SEGV on unknown address 0x000000000000",
                         entry["error_type"])
        self.assertEqual(LEAD_LINE, entry["faulting_line"])
        self.assertEqual(1, len(workbench.calls))
        self.assertEqual(1, transport.calls)
        self.assertEqual(0, outcome.stats.critic_calls)
        # The hit binds executed runtime evidence.
        self.assertTrue(any(
            record.kind == "runtime" and record.source == "asan"
            for record in target.evidence_records
        ))


if __name__ == "__main__":
    unittest.main()
