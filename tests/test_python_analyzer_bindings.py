"""Scope-correct builtin-call binding tests (Assignment 265A, A1).

Frozen acceptance surface for the 2026-10-03 scope/binding regression in
the AST analyzer's dynamic-execution rule.  Five boundaries (the task
book §四.A1 wording, frozen by the Assignment):

1. an ordinary object method is not claimed as a builtin call just
   because its last segment shares the builtin name;
2. a genuine bare builtin call and an explicit builtin reference stay
   reported even when a same-name method exists elsewhere in the file;
3. parameters, local definitions, import aliases and nested scopes are
   handled at their actual visibility, not file-wide;
4. a binding that cannot be uniquely resolved at this level stays
   visible as a candidate -- never posed as a proven risk and never
   silently dropped;
5. no repository name, path, class name, fixed field name or sample
   allowlist drives the decision.

All snippets are synthetic.  The "builtin claim face" is defined
differentially: whatever (severity, confidence) face the analyzer emits
for a genuine bare builtin call (the control snippet) is the asserted
claim; a shadowed or unresolvable binding must never carry that same
face, and an unresolvable receiver must still be visible with a
different, candidate-level face.  This keeps the freeze independent of
the exact severity/confidence numbers the implementation chooses.
"""

import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from lima.python_analyzer import PythonAstSecurityAnalyzer

#: Control: an unshadowed bare builtin call must stay reported (line 2).
_CONTROL_BARE = (
    "def dispatch(blob):\n"
    "    return eval(blob)\n"
)
_CONTROL_BARE_LINE = 2

#: Boundary 1: ordinary object methods on bound or constructed receivers.
_METHOD_RECEIVERS = (
    "class Gauge:\n"                                    # 1
    "    def eval(self, code):\n"                       # 2
    "        return len(code)\n"                        # 3
    "\n"                                               # 4
    "\n"                                               # 5
    "def render():\n"                                   # 6
    "    gauge = Gauge()\n"                             # 7
    "    return gauge.eval('1 + 1') + Gauge().eval('2 + 2')\n"  # 8
)

#: Boundary 2: bare builtin calls while a same-name method lives in an
#: unrelated class scope (lines 7 and 11).
_BARE_CALLS_WITH_SAME_NAME_METHOD = (
    "class Envelope:\n"                                 # 1
    "    def eval(self, code):\n"                       # 2
    "        return len(code)\n"                        # 3
    "\n"                                               # 4
    "\n"                                               # 5
    "def dispatch(blob):\n"                             # 6
    "    return eval(blob)\n"                           # 7
    "\n"                                               # 8
    "\n"                                               # 9
    "def compile_item(text):\n"                         # 10
    "    return exec(text)\n"                           # 11
)

#: Boundary 2 (name independence): same shape, every identifier renamed.
_BARE_CALLS_RENAMED = (
    "class Wrapper:\n"                                  # 1
    "    def eval(self, code):\n"                       # 2
    "        return len(code)\n"                        # 3
    "\n"                                               # 4
    "\n"                                               # 5
    "def consume(item):\n"                              # 6
    "    return eval(item)\n"                           # 7
)

#: Boundary 2: explicit builtin references while a same-name method
#: exists elsewhere (line 10).
_EXPLICIT_BUILTIN_WITH_METHOD = (
    "import builtins\n"                                 # 1
    "\n"                                               # 2
    "\n"                                               # 3
    "class Envelope:\n"                                 # 4
    "    def eval(self, code):\n"                       # 5
    "        return len(code)\n"                        # 6
    "\n"                                               # 7
    "\n"                                               # 8
    "def dispatch(blob):\n"                             # 9
    "    return builtins.eval(blob) or builtins.exec(blob)\n"  # 10
)

#: Boundary 3: a parameter shadows the builtin inside its function only.
_PARAMETER_SHADOW = (
    "def apply_rule(payload, eval):\n"                  # 1
    "    return eval(payload)\n"                        # 2
)

#: Boundary 3: a local definition shadows only its own function; the
#: sibling function still calls the builtin (line 8).
_LOCAL_DEF_SHADOW = (
    "def route(request):\n"                             # 1
    "    def eval(code):\n"                             # 2
    "        return str(code)\n"                        # 3
    "    return eval(request.body)\n"                   # 4
    "\n"                                               # 5
    "\n"                                               # 6
    "def elsewhere(blob):\n"                            # 7
    "    return eval(blob)\n"                           # 8
)

#: Boundary 3: a function-local import alias shadows only that function;
#: the sibling still calls the builtin (line 7).
_FUNC_IMPORT_ALIAS = (
    "def helper():\n"                                   # 1
    "    import json as eval\n"                         # 2
    "    return eval('{\"k\": 1}')\n"                   # 3
    "\n"                                               # 4
    "\n"                                               # 5
    "def main(blob):\n"                                 # 6
    "    return eval(blob)\n"                           # 7
)

#: Boundary 3 (guard): a module-level import alias owns the name for the
#: whole module scope, so no builtin claim may fire (line 5).
_MODULE_IMPORT_ALIAS = (
    "import tarfile as eval\n"                          # 1
    "\n"                                               # 2
    "\n"                                               # 3
    "def main(blob):\n"                                 # 4
    "    return eval(blob)\n"                           # 5
)

#: Boundary 4: the receiver cannot be resolved at this level, so the
#: call must stay visible as a candidate (line 2).
_UNRESOLVABLE_RECEIVER = (
    "def run(frames, index, payload):\n"                # 1
    "    return frames[index].eval(payload)\n"          # 2
)

#: Boundary 5: identical shape under completely different names (line 2).
_UNRESOLVABLE_RECEIVER_RENAMED = (
    "def run(registry, key, blob):\n"                   # 1
    "    return registry[key].eval(blob)\n"             # 2
)


def _sec_eval_faces(result, line):
    return {
        (item.severity, round(item.confidence, 2))
        for item in result.findings
        if item.rule_id == "SEC-EVAL" and item.line == line
    }


class BuiltinBindingTests(unittest.TestCase):
    @staticmethod
    def analyze(source):
        return PythonAstSecurityAnalyzer().analyze("<bindings-probe>", source)

    def builtin_claim_faces(self):
        faces = _sec_eval_faces(self.analyze(_CONTROL_BARE), _CONTROL_BARE_LINE)
        self.assertTrue(
            faces, "control: a genuine bare builtin call must emit SEC-EVAL"
        )
        return faces

    def assert_builtin_claim(self, source, line):
        faces = _sec_eval_faces(self.analyze(source), line)
        self.assertTrue(
            faces & self.builtin_claim_faces(),
            f"expected the builtin dynamic-execution claim at line {line}",
        )

    def assert_no_builtin_claim(self, source, line):
        faces = _sec_eval_faces(self.analyze(source), line)
        self.assertFalse(
            faces & self.builtin_claim_faces(),
            "a binding shadowed at its actual visibility must not carry "
            f"the builtin claim face at line {line}",
        )

    def assert_visible_candidate(self, source, line):
        faces = _sec_eval_faces(self.analyze(source), line)
        self.assertTrue(
            faces,
            f"an unresolvable binding must stay visible at line {line}",
        )
        self.assertFalse(
            faces & self.builtin_claim_faces(),
            "an unresolvable binding must not carry the asserted builtin "
            f"face at line {line}",
        )

    def test_object_method_receivers_are_not_builtin_claims(self):
        # Boundary 1 (guard for the 2026-10-03 receiver fix).
        self.assert_no_builtin_claim(_METHOD_RECEIVERS, 8)

    def test_bare_builtin_calls_survive_same_name_method_elsewhere(self):
        # Boundary 2: file-level flattening must not erase genuine bare
        # builtin calls; both eval and exec are asserted.
        self.assert_builtin_claim(_BARE_CALLS_WITH_SAME_NAME_METHOD, 7)
        self.assert_builtin_claim(_BARE_CALLS_WITH_SAME_NAME_METHOD, 11)

    def test_explicit_builtin_reference_survives_same_name_method(self):
        # Boundary 2: explicit builtins.eval / builtins.exec references.
        self.assert_builtin_claim(_EXPLICIT_BUILTIN_WITH_METHOD, 10)

    def test_parameter_binding_shadows_builtin_at_its_visibility(self):
        # Boundary 3: a parameter named like the builtin owns the name
        # inside its function; the call is not a builtin claim.
        self.assert_no_builtin_claim(_PARAMETER_SHADOW, 2)

    def test_local_def_shadow_is_scoped_to_own_function(self):
        # Boundary 3: the inner definition shadows only inside route
        # (line 4); the sibling function still calls the builtin (line 8).
        self.assert_no_builtin_claim(_LOCAL_DEF_SHADOW, 4)
        self.assert_builtin_claim(_LOCAL_DEF_SHADOW, 8)

    def test_function_import_alias_is_scoped_to_own_function(self):
        # Boundary 3: the alias binds only inside helper (line 3); main
        # still calls the builtin (line 7).
        self.assert_no_builtin_claim(_FUNC_IMPORT_ALIAS, 3)
        self.assert_builtin_claim(_FUNC_IMPORT_ALIAS, 7)

    def test_module_import_alias_shadows_whole_module_scope(self):
        # Boundary 3 (guard): module-level aliases stay module-wide.
        self.assert_no_builtin_claim(_MODULE_IMPORT_ALIAS, 5)

    def test_unresolvable_receiver_stays_visible_candidate(self):
        # Boundary 4: neither a silent drop nor an asserted builtin claim.
        self.assert_visible_candidate(_UNRESOLVABLE_RECEIVER, 2)

    def test_unresolvable_receiver_decision_is_name_independent(self):
        # Boundary 5: renamed containers/indices/parameters produce the
        # identical candidate face set -- decisions follow binding shape,
        # not identifier names or any sample list.
        base = _sec_eval_faces(self.analyze(_UNRESOLVABLE_RECEIVER), 2)
        renamed = _sec_eval_faces(self.analyze(_UNRESOLVABLE_RECEIVER_RENAMED), 2)
        self.assertTrue(base and renamed)
        self.assertEqual(base, renamed)
        self.assertFalse(base & self.builtin_claim_faces())
        self.assertFalse(renamed & self.builtin_claim_faces())
        # Boundary 2/5: renamed same-name-method shape still reports the
        # genuine bare builtin.
        self.assert_builtin_claim(_BARE_CALLS_RENAMED, 7)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
