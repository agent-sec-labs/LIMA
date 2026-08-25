import tempfile
import unittest
from pathlib import Path

from lima.python_dataflow import PythonDataflowAnalyzer
from lima.report import to_markdown
from lima.repository_scanner import RepositoryScanner
from lima.workspace import RepositoryWorkspace


class PythonDataflowAnalyzerTests(unittest.TestCase):
    def analyze(self, content: str):
        return PythonDataflowAnalyzer().analyze("app.py", content)

    def test_request_value_flows_through_assignments_into_shell(self):
        result = self.analyze(
            "def run():\n"
            "    command = request.args.get('command')\n"
            "    rendered = 'echo ' + command\n"
            "    os.system(rendered)\n"
        )

        self.assertEqual(1, len(result.findings))
        finding = result.findings[0]
        self.assertEqual("FLOW-COMMAND", finding.rule_id)
        self.assertEqual("CWE-78", finding.cwe)
        self.assertEqual("dataflow-verified", finding.verification_state)
        self.assertEqual("python-dataflow", finding.source)
        self.assertEqual("taint-source", finding.evidence_records[0].kind)
        self.assertEqual("taint-sink", finding.evidence_records[-1].kind)
        self.assertEqual({2, 3, 4}, {item.line for item in finding.evidence_records})

    def test_decorated_endpoint_parameter_is_a_source(self):
        result = self.analyze(
            "@app.post('/evaluate')\n"
            "def evaluate(code):\n"
            "    return eval(code)\n"
        )

        self.assertEqual(["FLOW-EVAL"], [item.rule_id for item in result.findings])
        self.assertIn("endpoint parameter 'code'", result.findings[0].evidence)

    def test_ordinary_function_parameter_is_not_assumed_untrusted(self):
        result = self.analyze(
            "def evaluate(code):\n"
            "    return eval(code)\n"
        )

        self.assertEqual([], result.findings)

    def test_parameterized_sql_does_not_taint_query_structure(self):
        result = self.analyze(
            "def lookup():\n"
            "    user_id = request.args.get('id')\n"
            "    cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))\n"
        )

        self.assertEqual([], result.findings)

    def test_dynamic_sql_structure_is_verified(self):
        result = self.analyze(
            "def lookup():\n"
            "    user_id = request.args.get('id')\n"
            "    query = f'SELECT * FROM users WHERE id = {user_id}'\n"
            "    cursor.execute(query)\n"
        )

        self.assertEqual(["FLOW-SQL"], [item.rule_id for item in result.findings])
        self.assertEqual("CWE-89", result.findings[0].cwe)

    def test_strict_conversion_and_safe_reassignment_cut_taint(self):
        converted = self.analyze(
            "def run():\n"
            "    value = int(request.args.get('value'))\n"
            "    os.system('echo ' + str(value))\n"
        )
        reassigned = self.analyze(
            "def run():\n"
            "    value = request.args.get('value')\n"
            "    value = 'constant'\n"
            "    os.system(value)\n"
        )

        self.assertEqual([], converted.findings)
        self.assertEqual([], reassigned.findings)

    def test_deserialization_and_path_sinks_are_covered(self):
        result = self.analyze(
            "def consume():\n"
            "    payload = request.data\n"
            "    pickle.loads(payload)\n"
            "    filename = request.args.get('name')\n"
            "    open(filename, 'rb')\n"
        )

        self.assertEqual(
            {"FLOW-DESERIALIZATION", "FLOW-PATH"},
            {item.rule_id for item in result.findings},
        )

    def test_endpoint_parameter_reaches_sink_in_same_file_helper(self):
        result = self.analyze(
            "def launch(command):\n"
            "    os.system(command)\n"
            "\n"
            "@app.post('/run')\n"
            "def run(command):\n"
            "    launch(command)\n"
        )

        self.assertEqual(["FLOW-COMMAND"], [item.rule_id for item in result.findings])
        kinds = [item.kind for item in result.findings[0].evidence_records]
        self.assertEqual(
            ["taint-source", "call-edge", "callee-parameter", "taint-sink"],
            kinds,
        )
        self.assertEqual(2, result.functions_indexed)
        self.assertEqual(1, result.interprocedural_edges)
        self.assertEqual(0, result.truncated_calls)

    def test_helper_return_propagates_back_to_caller(self):
        result = self.analyze(
            "def normalize(value):\n"
            "    return value.strip()\n"
            "\n"
            "@app.post('/run')\n"
            "def run(command):\n"
            "    normalized = normalize(command)\n"
            "    os.system(normalized)\n"
        )

        self.assertEqual(["FLOW-COMMAND"], [item.rule_id for item in result.findings])
        kinds = {item.kind for item in result.findings[0].evidence_records}
        self.assertIn("call-edge", kinds)
        self.assertIn("callee-parameter", kinds)
        self.assertIn("return-propagation", kinds)

    def test_keyword_only_argument_is_bound_across_call(self):
        result = self.analyze(
            "def launch(*, command):\n"
            "    os.system(command)\n"
            "\n"
            "@app.post('/run')\n"
            "def run(user_input):\n"
            "    launch(command=user_input)\n"
        )

        self.assertEqual(["FLOW-COMMAND"], [item.rule_id for item in result.findings])
        self.assertIn(
            "callee-parameter",
            {item.kind for item in result.findings[0].evidence_records},
        )

    def test_sanitizer_inside_helper_cuts_return_taint(self):
        result = self.analyze(
            "def parse_identifier(value):\n"
            "    return int(value)\n"
            "\n"
            "@app.post('/run')\n"
            "def run(user_input):\n"
            "    identifier = parse_identifier(user_input)\n"
            "    os.system('echo ' + str(identifier))\n"
        )

        self.assertEqual([], result.findings)

    def test_recursive_call_is_bounded_and_not_claimed_as_verified(self):
        result = self.analyze(
            "def recurse(value):\n"
            "    return recurse(value)\n"
            "\n"
            "@app.post('/run')\n"
            "def run(user_input):\n"
            "    return recurse(user_input)\n"
        )

        self.assertEqual([], result.findings)
        self.assertGreaterEqual(result.truncated_calls, 1)
        self.assertEqual(2, result.interprocedural_edges)

    def test_call_depth_budget_degrades_instead_of_overclaiming(self):
        analyzer = PythonDataflowAnalyzer(max_call_depth=2)
        result = analyzer.analyze(
            "app.py",
            "def final(value):\n"
            "    return eval(value)\n"
            "\n"
            "def forward(value):\n"
            "    return final(value)\n"
            "\n"
            "@app.post('/run')\n"
            "def run(user_input):\n"
            "    return forward(user_input)\n",
        )

        self.assertEqual([], result.findings)
        self.assertGreaterEqual(result.truncated_calls, 1)

    def test_bare_local_execute_is_not_misclassified_as_sql(self):
        result = self.analyze(
            "def execute(value):\n"
            "    return eval(value)\n"
            "\n"
            "@app.post('/run')\n"
            "def run(user_input):\n"
            "    return execute(user_input)\n"
        )

        self.assertEqual(["FLOW-EVAL"], [item.rule_id for item in result.findings])

    def test_unresolved_external_call_is_counted_and_not_overclaimed(self):
        result = self.analyze(
            "@app.post('/run')\n"
            "def run(user_input):\n"
            "    command = external.normalize(user_input)\n"
            "    os.system(command)\n"
        )

        self.assertEqual([], result.findings)
        self.assertEqual(1, result.unresolved_calls)

    def test_known_string_and_path_transforms_preserve_taint(self):
        result = self.analyze(
            "@app.post('/download')\n"
            "def download(user_input):\n"
            "    filename = os.path.join('/srv/files', user_input.strip())\n"
            "    return open(filename, 'rb')\n"
        )

        self.assertEqual(["FLOW-PATH"], [item.rule_id for item in result.findings])
        self.assertEqual(0, result.unresolved_calls)


class PythonProjectDataflowTests(unittest.TestCase):
    def analyze(self, files: dict[str, str], max_call_depth: int = 4):
        return PythonDataflowAnalyzer(max_call_depth=max_call_depth).analyze_project(files)

    def test_module_import_alias_reaches_sink_in_another_file(self):
        result = self.analyze({
            "app.py": (
                "import services.executor as executor\n"
                "\n"
                "@app.post('/evaluate')\n"
                "def endpoint(user_input):\n"
                "    return executor.evaluate(user_input)\n"
            ),
            "services/executor.py": (
                "def evaluate(value):\n"
                "    return eval(value)\n"
            ),
        })

        self.assertEqual(["FLOW-EVAL"], [item.rule_id for item in result.findings])
        finding = result.findings[0]
        self.assertEqual("services/executor.py", finding.path)
        records = finding.evidence_records
        self.assertEqual("app.py", records[0].path)
        self.assertIn("cross-file-call-edge", {item.kind for item in records})
        self.assertEqual("services/executor.py", records[-1].path)
        self.assertEqual(2, result.modules_indexed)
        self.assertEqual(1, result.cross_file_edges)

    def test_from_import_alias_propagates_return_to_caller(self):
        result = self.analyze({
            "app.py": (
                "from helpers import normalize as clean\n"
                "\n"
                "@app.post('/run')\n"
                "def endpoint(user_input):\n"
                "    command = clean(user_input)\n"
                "    os.system(command)\n"
            ),
            "helpers.py": (
                "def normalize(value):\n"
                "    return value.strip()\n"
            ),
        })

        self.assertEqual(["FLOW-COMMAND"], [item.rule_id for item in result.findings])
        records = result.findings[0].evidence_records
        self.assertIn("return-propagation", {item.kind for item in records})
        self.assertEqual(
            {"app.py", "helpers.py"}, {item.path for item in records}
        )

    def test_relative_import_supports_two_cross_file_hops(self):
        result = self.analyze({
            "app.py": (
                "from pkg.service import forward\n"
                "\n"
                "@app.post('/evaluate')\n"
                "def endpoint(user_input):\n"
                "    return forward(user_input)\n"
            ),
            "pkg/__init__.py": "",
            "pkg/service.py": (
                "from .sink import evaluate\n"
                "\n"
                "def forward(value):\n"
                "    return evaluate(value)\n"
            ),
            "pkg/sink.py": (
                "def evaluate(value):\n"
                "    return eval(value)\n"
            ),
        })

        self.assertEqual(["FLOW-EVAL"], [item.rule_id for item in result.findings])
        self.assertEqual("pkg/sink.py", result.findings[0].path)
        self.assertEqual(2, result.cross_file_edges)
        self.assertEqual(4, result.modules_indexed)

    def test_cross_file_strict_sanitizer_cuts_taint(self):
        result = self.analyze({
            "app.py": (
                "from helpers import parse_identifier\n"
                "\n"
                "@app.post('/run')\n"
                "def endpoint(user_input):\n"
                "    identifier = parse_identifier(user_input)\n"
                "    os.system('echo ' + str(identifier))\n"
            ),
            "helpers.py": (
                "def parse_identifier(value):\n"
                "    return int(value)\n"
            ),
        })

        self.assertEqual([], result.findings)
        self.assertEqual(1, result.cross_file_edges)

    def test_circular_cross_file_calls_are_bounded(self):
        result = self.analyze({
            "app.py": (
                "from a import recurse\n"
                "\n"
                "@app.post('/run')\n"
                "def endpoint(user_input):\n"
                "    return recurse(user_input)\n"
            ),
            "a.py": (
                "from b import bounce\n"
                "def recurse(value):\n"
                "    return bounce(value)\n"
            ),
            "b.py": (
                "from a import recurse\n"
                "def bounce(value):\n"
                "    return recurse(value)\n"
            ),
        })

        self.assertEqual([], result.findings)
        self.assertGreaterEqual(result.truncated_calls, 1)
        self.assertGreaterEqual(result.cross_file_edges, 3)

    def test_dynamic_import_is_visible_but_not_overclaimed(self):
        result = self.analyze({
            "app.py": (
                "@app.post('/run')\n"
                "def endpoint(user_input):\n"
                "    module = importlib.import_module('helpers')\n"
                "    command = module.normalize(user_input)\n"
                "    os.system(command)\n"
            ),
            "helpers.py": (
                "def normalize(value):\n"
                "    return value.strip()\n"
            ),
        })

        self.assertEqual([], result.findings)
        self.assertEqual(1, result.dynamic_import_sites)
        self.assertEqual(1, result.unresolved_calls)

    def test_ambiguous_module_names_fail_closed(self):
        result = self.analyze({
            "app.py": (
                "import pkg\n"
                "@app.post('/run')\n"
                "def endpoint(user_input):\n"
                "    return pkg.evaluate(user_input)\n"
            ),
            "pkg.py": "def evaluate(value):\n    return eval(value)\n",
            "pkg/__init__.py": "def evaluate(value):\n    return eval(value)\n",
        })

        self.assertEqual([], result.findings)
        self.assertEqual(1, result.ambiguous_modules)
        self.assertEqual(1, result.unresolved_calls)

    def test_imported_function_shadowed_by_parameter_is_not_resolved(self):
        result = self.analyze({
            "app.py": (
                "from helpers import evaluate\n"
                "\n"
                "@app.post('/run')\n"
                "def endpoint(evaluate, user_input):\n"
                "    return evaluate(user_input)\n"
            ),
            "helpers.py": (
                "def evaluate(value):\n"
                "    return eval(value)\n"
            ),
        })

        self.assertEqual([], result.findings)
        self.assertEqual(0, result.cross_file_edges)
        self.assertEqual(1, result.unresolved_calls)

    def test_imported_function_shadowed_by_assignment_is_not_resolved(self):
        result = self.analyze({
            "app.py": (
                "from helpers import evaluate\n"
                "evaluate = external_handler\n"
                "\n"
                "@app.post('/run')\n"
                "def endpoint(user_input):\n"
                "    return evaluate(user_input)\n"
            ),
            "helpers.py": (
                "def evaluate(value):\n"
                "    return eval(value)\n"
            ),
        })

        self.assertEqual([], result.findings)
        self.assertEqual(0, result.cross_file_edges)
        self.assertEqual(1, result.unresolved_calls)

    def test_parse_error_in_one_module_does_not_hide_other_findings(self):
        result = self.analyze({
            "broken.py": "def broken(:\n",
            "app.py": (
                "@app.post('/evaluate')\n"
                "def endpoint(user_input):\n"
                "    return eval(user_input)\n"
            ),
        })

        self.assertEqual(["FLOW-EVAL"], [item.rule_id for item in result.findings])
        self.assertEqual({"broken.py"}, set(result.parse_errors))
        self.assertIn("broken.py", result.parse_error)


class RepositoryDataflowFusionTests(unittest.TestCase):
    def test_cross_file_flow_is_fused_at_sink_and_reported(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            root.joinpath("app.py").write_text(
                "from executor import evaluate\n"
                "\n"
                "@app.post('/evaluate')\n"
                "def endpoint(user_input):\n"
                "    return evaluate(user_input)\n",
                encoding="utf-8",
            )
            root.joinpath("executor.py").write_text(
                "def evaluate(value):\n"
                "    return eval(value)\n",
                encoding="utf-8",
            )

            result = RepositoryScanner(sast_mode="off").scan(
                RepositoryWorkspace(root)
            )

            self.assertEqual(1, len(result.report.findings))
            finding = result.report.findings[0]
            self.assertEqual("executor.py", finding.path)
            self.assertEqual("SEC-EVAL", finding.rule_id)
            self.assertEqual("dataflow-verified", finding.verification_state)
            self.assertEqual("python-ast+python-dataflow", finding.source)
            metrics = result.report.collaboration
            self.assertEqual("repository-static-imports", metrics["dataflow_scope"])
            self.assertEqual(1, metrics["cross_file_call_edges"])
            self.assertEqual(2, metrics["dataflow_modules_indexed"])

    def test_same_file_helper_flow_is_fused_and_reported(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            root.joinpath("app.py").write_text(
                "def evaluate_expression(value):\n"
                "    return eval(value)\n"
                "\n"
                "@app.post('/evaluate')\n"
                "def endpoint(user_input):\n"
                "    return evaluate_expression(user_input)\n",
                encoding="utf-8",
            )

            result = RepositoryScanner(sast_mode="off").scan(
                RepositoryWorkspace(root)
            )

            self.assertEqual(1, len(result.report.findings))
            finding = result.report.findings[0]
            self.assertEqual("SEC-EVAL", finding.rule_id)
            self.assertEqual("dataflow-verified", finding.verification_state)
            kinds = {item.kind for item in finding.evidence_records}
            self.assertIn("call-edge", kinds)
            self.assertIn("callee-parameter", kinds)
            metrics = result.report.collaboration
            self.assertEqual("repository-static-imports", metrics["dataflow_scope"])
            self.assertEqual(2, metrics["dataflow_functions_indexed"])
            self.assertEqual(1, metrics["interprocedural_call_edges"])
            markdown = to_markdown(result.report.to_dict())
            self.assertIn("Call edges: `1`", markdown)

    def test_ast_and_dataflow_become_one_verified_finding(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            root.joinpath("app.py").write_text(
                "@app.post('/evaluate')\n"
                "def evaluate(code):\n"
                "    return eval(code)\n",
                encoding="utf-8",
            )

            result = RepositoryScanner(sast_mode="off").scan(
                RepositoryWorkspace(root)
            )

            self.assertEqual(1, len(result.report.findings))
            finding = result.report.findings[0]
            self.assertEqual("SEC-EVAL", finding.rule_id)
            self.assertEqual("CWE-95", finding.cwe)
            self.assertEqual("dataflow-verified", finding.verification_state)
            self.assertEqual("python-ast+python-dataflow", finding.source)
            self.assertEqual("source-to-sink", finding.evidence_kind)
            self.assertGreaterEqual(len(finding.evidence_records), 3)
            self.assertEqual(
                1, result.report.collaboration["dataflow_verified_findings"]
            )
            self.assertEqual(
                1, result.report.collaboration["corroborated_findings"]
            )
            markdown = to_markdown(result.report.to_dict())
            self.assertIn("Source-to-sink path", markdown)
            self.assertIn("taint-source", markdown)

    def test_ast_candidate_stays_unverified_without_a_source(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            root.joinpath("library.py").write_text(
                "def evaluate(code):\n"
                "    return eval(code)\n",
                encoding="utf-8",
            )

            result = RepositoryScanner(sast_mode="off").scan(
                RepositoryWorkspace(root)
            )

            self.assertEqual(1, len(result.report.findings))
            self.assertEqual(
                "candidate", result.report.findings[0].verification_state
            )
            self.assertEqual(
                0, result.report.collaboration["dataflow_verified_findings"]
            )

    def test_dataflow_can_be_disabled_for_ablation(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            root.joinpath("app.py").write_text(
                "@app.post('/evaluate')\n"
                "def evaluate(code):\n"
                "    return eval(code)\n",
                encoding="utf-8",
            )

            result = RepositoryScanner(
                sast_mode="off", dataflow_enabled=False
            ).scan(RepositoryWorkspace(root))

            self.assertEqual("candidate", result.report.findings[0].verification_state)
            self.assertFalse(result.report.collaboration["dataflow_enabled"])
            self.assertNotIn("python-dataflow", result.report.reviewer)


if __name__ == "__main__":
    unittest.main()
