import tempfile
import unittest
from pathlib import Path

from lima.semantic_retrieval import (
    SecurityInvariant,
    SecuritySemanticRetriever,
    SemanticCandidate,
)


class SecuritySemanticRetrievalTests(unittest.TestCase):
    def test_generic_security_api_semantics_retrieve_unseen_root_cause_shapes(self):
        files = {
            "src/paths.py": (
                "import os\n"
                "def contains(root, target):\n"
                "    root = os.path.abspath(root)\n"
                "    target = os.path.abspath(target)\n"
                "    return os.path.commonprefix([root, target]) == root\n"
            ),
            "src/custom.py": (
                "import os\n"
                "class Custom:\n"
                "    @classmethod\n"
                "    def locate(cls, **kwargs):\n"
                "        model_path = kwargs.get('model_path')\n"
                "        return os.path.abspath(os.path.expanduser(model_path))\n"
            ),
            "src/template_exec.py": (
                "class Runner:\n"
                "    def expand(self, cmd, info):\n"
                "        return cmd.replace('{}', shell_quote(info['filepath'], shell=True))\n"
                "    def run(self, cmd, info):\n"
                "        rendered = self.expand(cmd, info)\n"
                "        return Popen.run(rendered, shell=True)\n"
            ),
            "src/tool.py": (
                "import subprocess\n"
                "def execute(command: str, shell: bool = True):\n"
                "    return subprocess.run(command, shell=True)\n"
            ),
            "src/query.py": (
                "def list_rows():\n"
                "    sort = request.args.get('sort', 'id')\n"
                "    order = request.args.get('order', 'asc')\n"
                "    clause = text(sort + ' ' + order)\n"
                "    return session.query(User).order_by(clause).all()\n"
            ),
        }
        with tempfile.TemporaryDirectory() as root:
            base = Path(root)
            for name, content in files.items():
                target = base / name
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(content, encoding="utf-8")
            run = SecuritySemanticRetriever().retrieve_run(base)

        identities = {(item.path, item.qualname) for item in run.candidates}
        self.assertTrue({
            ("src/paths.py", "contains"),
            ("src/custom.py", "Custom.locate"),
            ("src/template_exec.py", "Runner.expand"),
            ("src/tool.py", "execute"),
            ("src/query.py", "list_rows"),
        }.issubset(identities))
        risk_ids = {
            invariant.identifier
            for candidate in run.candidates
            for invariant in candidate.invariants
            if invariant.status == "risk"
        }
        self.assertTrue({
            "path-component-containment",
            "path-caller-location-containment",
            "command-shell-data-boundary",
            "sql-structural-token-allowlist",
        }.issubset(risk_ids))
        self.assertEqual(run.diagnostics["selected_candidates"], len(run.candidates))
        self.assertEqual(run.diagnostics["inventory"]["file_coverage"], 1.0)

    def test_generic_mitigations_are_distinguished_from_risky_api_use(self):
        with tempfile.TemporaryDirectory() as root:
            base = Path(root)
            (base / "fixed.py").write_text(
                "import os, re, subprocess\n"
                "def contains(root, target):\n"
                "    return os.path.commonpath([os.path.abspath(root), os.path.abspath(target)]) == os.path.abspath(root)\n"
                "def locate(**kwargs):\n"
                "    value = os.path.abspath(os.path.expanduser(kwargs.get('model_path')))\n"
                "    allowed = os.path.abspath('/models')\n"
                "    if not value.startswith(allowed + os.sep) and value != allowed:\n"
                "        raise ValueError(value)\n"
                "    return value\n"
                "def execute(command: str, shell: bool = False):\n"
                "    if shell and re.search(r'[;&|`$]', command):\n"
                "        raise ValueError(command)\n"
                "    return subprocess.run(command, shell=True) if shell else subprocess.run([command])\n"
                "def list_rows():\n"
                "    sort = request.args.get('sort', 'id')\n"
                "    if sort not in User.__table__.columns.keys():\n"
                "        sort = 'id'\n"
                "    return session.query(User).order_by(text(sort + ' asc')).all()\n",
                encoding="utf-8",
            )
            candidates = SecuritySemanticRetriever().retrieve(base)

        states = {
            (invariant.identifier, invariant.status)
            for candidate in candidates
            for invariant in candidate.invariants
        }
        self.assertIn(("path-component-containment", "mitigation"), states)
        self.assertIn(("path-caller-location-containment", "mitigation"), states)
        self.assertIn(("command-shell-data-boundary", "mitigation"), states)
        self.assertIn(("sql-structural-token-allowlist", "mitigation"), states)

    def test_sql_column_allowlist_does_not_hide_unchecked_direction(self):
        with tempfile.TemporaryDirectory() as root:
            Path(root, "query.py").write_text(
                "def list_rows():\n"
                "    sort = request.args.get('sort', 'id')\n"
                "    if sort not in User.__table__.columns.keys():\n"
                "        sort = 'id'\n"
                "    order = request.args.get('order', 'asc')\n"
                "    return query.order_by(text(sort + ' ' + order)).all()\n",
                encoding="utf-8",
            )
            candidates = SecuritySemanticRetriever().retrieve(root)

        invariant = next(
            invariant
            for candidate in candidates
            for invariant in candidate.invariants
            if invariant.identifier == "sql-structural-token-allowlist"
        )
        self.assertEqual("risk", invariant.status)
        self.assertIn("direction", invariant.summary)

    def test_balanced_label_blind_retrieval_finds_three_root_cause_shapes(self):
        with tempfile.TemporaryDirectory() as root:
            base = Path(root)
            Path(base, "paths.py").write_text(
                "from pathlib import Path\n"
                "class Static:\n"
                "    async def handle(self, filename):\n"
                "        unresolved = self.directory.joinpath(filename)\n"
                "        path = unresolved.resolve()\n"
                "        path.relative_to(self.directory)\n",
                encoding="utf-8",
            )
            Path(base, "commands.py").write_text(
                "class Git:\n"
                "    @classmethod\n"
                "    def check_unsafe_options(cls, options, unsafe_options):\n"
                "        for option in options:\n"
                "            if option in unsafe_options:\n"
                "                raise ValueError(option)\n",
                encoding="utf-8",
            )
            Path(base, "sql.py").write_text(
                "class StringAgg:\n"
                "    template = \"STRING_AGG(%(expressions)s, '%(delimiter)s')\"\n"
                "    def __init__(self, expression, delimiter):\n"
                "        self.delimiter = delimiter\n",
                encoding="utf-8",
            )
            candidates = SecuritySemanticRetriever().retrieve(base)
        identities = {(item.path, item.qualname) for item in candidates}
        self.assertIn(("paths.py", "Static.handle"), identities)
        self.assertIn(("commands.py", "Git.check_unsafe_options"), identities)
        self.assertIn(("sql.py", "StringAgg.__init__"), identities)
        self.assertEqual({"path", "command", "sql"}, {item.category for item in candidates})

    def test_context_budget_and_metadata_are_bounded(self):
        with tempfile.TemporaryDirectory() as root:
            Path(root, "app.py").write_text(
                "def execute_command(value):\n"
                "    command = value\n"
                + "    command = command.strip()\n" * 500
                + "    return subprocess.Popen(command, shell=True)\n",
                encoding="utf-8",
            )
            candidates = SecuritySemanticRetriever(
                max_total_chars=1200, max_candidate_chars=1000
            ).retrieve(root)
        self.assertLessEqual(sum(len(item.code) for item in candidates), 1200)
        self.assertTrue(all("code" not in item.metadata() for item in candidates))
        self.assertTrue(all(len(item.metadata()["content_sha256"]) == 64 for item in candidates))

    def test_production_candidate_outranks_similar_regression_test(self):
        with tempfile.TemporaryDirectory() as root:
            base = Path(root)
            Path(base, "package").mkdir()
            Path(base, "tests").mkdir()
            implementation = (
                "class StringAgg:\n"
                "    template = \"STRING_AGG(%(expressions)s, '%(delimiter)s')\"\n"
                "    def __init__(self, expression, delimiter):\n"
                "        self.delimiter = delimiter\n"
            )
            Path(base, "package", "aggregates.py").write_text(
                implementation, encoding="utf-8"
            )
            Path(base, "tests", "test_aggregates.py").write_text(
                "def test_stringagg_delimiter_sql_template_ordering():\n"
                "    delimiter = \"'\"\n"
                "    assert stringagg(delimiter, ordering='x')\n",
                encoding="utf-8",
            )
            candidates = SecuritySemanticRetriever(per_category=1).retrieve(base)
        sql = [item for item in candidates if item.category == "sql"]
        self.assertEqual("package/aggregates.py", sql[0].path)

    def test_shortlist_preserves_file_diversity_before_expanding_neighbors(self):
        with tempfile.TemporaryDirectory() as root:
            base = Path(root)
            noisy_methods = "\n".join(
                "    def run_%d(self, command):\n"
                "        return subprocess.run(command, shell=True)" % index
                for index in range(8)
            )
            (base / "noisy.py").write_text(
                "class Noisy:\n" + noisy_methods + "\n", encoding="utf-8"
            )
            (base / "separate.py").write_text(
                "def execute(command):\n"
                "    return subprocess.run(command, shell=True)\n",
                encoding="utf-8",
            )

            candidates = SecuritySemanticRetriever(
                per_category=3, max_candidates=6
            ).retrieve(base)

        self.assertIn(
            ("separate.py", "execute"),
            {(item.path, item.qualname) for item in candidates},
        )

    def test_previous_function_signals_do_not_leak_into_next_function(self):
        with tempfile.TemporaryDirectory() as root:
            Path(root, "paths.py").write_text(
                "import os\n"
                "def contained(root, target):\n"
                "    return os.path.commonpath([root, target]) == root\n"
                "def unrelated():\n"
                "    return 0o777\n",
                encoding="utf-8",
            )
            candidates = SecuritySemanticRetriever().retrieve(root)

        path_symbols = {
            item.qualname for item in candidates if item.category == "path"
        }
        self.assertIn("contained", path_symbols)
        self.assertNotIn("unrelated", path_symbols)

    def test_generic_text_constructor_is_not_treated_as_dynamic_sql(self):
        with tempfile.TemporaryDirectory() as root:
            Path(root, "render.py").write_text(
                "def render(message, sort_items=True):\n"
                "    card = Text(message)\n"
                "    if sort_items:\n"
                "        card.sort()\n"
                "    return Panel(card)\n",
                encoding="utf-8",
            )
            candidates = SecuritySemanticRetriever().retrieve(root)

        self.assertNotIn(
            ("render.py", "render", "sql"),
            {(item.path, item.qualname, item.category) for item in candidates},
        )

    def test_console_cursor_and_column_names_are_not_database_evidence(self):
        with tempfile.TemporaryDirectory() as root:
            Path(root, "console.py").write_text(
                "def move_cursor_to_column(cursor, column):\n"
                "    return SetConsoleCursorPosition(cursor, column)\n",
                encoding="utf-8",
            )
            candidates = SecuritySemanticRetriever().retrieve(root)

        self.assertNotIn(
            ("console.py", "move_cursor_to_column", "sql"),
            {(item.path, item.qualname, item.category) for item in candidates},
        )

    def test_candidate_identity_is_not_duplicated_across_categories(self):
        with tempfile.TemporaryDirectory() as root:
            Path(root, "mixed.py").write_text(
                "def run(command, sort):\n"
                "    clause = text(sort + ' asc')\n"
                "    subprocess.run(command, shell=True)\n"
                "    return query.order_by(clause)\n",
                encoding="utf-8",
            )
            candidates = SecuritySemanticRetriever().retrieve(root)

        identities = [(item.path, item.qualname) for item in candidates]
        self.assertEqual(len(identities), len(set(identities)))

    def test_security_invariants_discriminate_risky_and_mitigated_pairs(self):
        vulnerable = {
            "path_case.py": (
                "from pathlib import Path\n"
                "class Static:\n"
                "    async def handle(self, value):\n"
                "        path = self.root.joinpath(value).resolve()\n"
                "        if not self.follow_symlinks:\n"
                "            path.relative_to(self.root)\n"
                "        return path\n"
            ),
            "command_case.py": (
                "class Git:\n"
                "    def check_unsafe_options(self, options, unsafe_options):\n"
                "        return [x for x in options if x in unsafe_options]\n"
                "    def transform_kwargs(self, **kwargs):\n"
                "        return ['--' + dashify(name) for name in kwargs]\n"
            ),
            "sql_case.py": (
                "class StringAgg:\n"
                "    template = \"STRING_AGG(%(expressions)s, '%(delimiter)s')\"\n"
                "    def __init__(self, expression, delimiter):\n"
                "        super().__init__(expression, delimiter=delimiter)\n"
            ),
        }
        fixed = {
            "path_case.py": (
                "from pathlib import Path\n"
                "class Static:\n"
                "    async def handle(self, value):\n"
                "        unresolved = self.root.joinpath(value)\n"
                "        if self.follow_symlinks:\n"
                "            path = Path(os.path.normpath(unresolved))\n"
                "            path.relative_to(self.root)\n"
                "            path = path.resolve()\n"
                "        else:\n"
                "            path = unresolved.resolve()\n"
                "            path.relative_to(self.root)\n"
                "        return path\n"
            ),
            "command_case.py": (
                "class Git:\n"
                "    def check_unsafe_options(self, options, unsafe_options):\n"
                "        return [self.canonicalize_option_name(x) for x in options]\n"
                "    def canonicalize_option_name(self, value):\n"
                "        return dashify(value.lstrip('-'))\n"
                "    def transform_kwargs(self, **kwargs):\n"
                "        return ['--' + dashify(name) for name in kwargs]\n"
            ),
            "sql_case.py": (
                "class StringAgg:\n"
                "    template = '%(function)s(%(expressions)s)'\n"
                "    def __init__(self, expression, delimiter):\n"
                "        delimiter_expr = Value(str(delimiter))\n"
                "        super().__init__(expression, delimiter_expr)\n"
            ),
        }
        with tempfile.TemporaryDirectory() as root:
            base = Path(root)
            for revision, files in (("vulnerable", vulnerable), ("fixed", fixed)):
                directory = base / revision
                directory.mkdir()
                for name, content in files.items():
                    (directory / name).write_text(content, encoding="utf-8")
            retriever = SecuritySemanticRetriever()
            vulnerable_candidates = retriever.retrieve(base / "vulnerable")
            fixed_candidates = retriever.retrieve(base / "fixed")

        vulnerable_states = {
            (item.identifier, item.status)
            for candidate in vulnerable_candidates for item in candidate.invariants
        }
        fixed_states = {
            (item.identifier, item.status)
            for candidate in fixed_candidates for item in candidate.invariants
        }
        self.assertEqual(
            {
                ("path-follow-mode-containment", "risk"),
                ("command-option-canonicalization", "risk"),
                ("sql-template-value-boundary", "risk"),
            },
            vulnerable_states,
        )
        self.assertEqual(
            {
                ("path-follow-mode-containment", "mitigation"),
                ("command-option-canonicalization", "mitigation"),
                ("sql-template-value-boundary", "mitigation"),
            },
            fixed_states,
        )
        command_guard = next(
            item for item in vulnerable_candidates
            if item.qualname == "Git.check_unsafe_options"
        )
        self.assertIn("Git.transform_kwargs", command_guard.relations)
        packet = SecuritySemanticRetriever.evidence_packet(vulnerable_candidates)
        packet_symbols = {item.qualname for item in packet}
        self.assertIn("Git.check_unsafe_options", packet_symbols)
        self.assertIn("Git.transform_kwargs", packet_symbols)
        self.assertTrue(all(item.invariants or item.qualname in command_guard.relations
                            for item in packet))

    def test_nested_request_path_handler_is_retrieved_and_requires_containment(self):
        vulnerable = (
            "import os\n"
            "class Manager:\n"
            "    def add_routes(self):\n"
            "        @routes.get('/preview/{filename:.*}')\n"
            "        async def preview(request):\n"
            "            filename = request.match_info.get('filename')\n"
            "            target = os.path.join(self.root, filename)\n"
            "            return Image.open(target)\n"
        )
        fixed = vulnerable.replace(
            "            return Image.open(target)\n",
            "            if not is_within_directory(self.root, target):\n"
            "                raise PermissionError(target)\n"
            "            return Image.open(target)\n",
        )
        with tempfile.TemporaryDirectory() as root:
            base = Path(root)
            (base / "vulnerable").mkdir()
            (base / "fixed").mkdir()
            (base / "vulnerable" / "manager.py").write_text(vulnerable, encoding="utf-8")
            (base / "fixed" / "manager.py").write_text(fixed, encoding="utf-8")
            retriever = SecuritySemanticRetriever()
            vulnerable_candidates = retriever.retrieve(base / "vulnerable")
            fixed_candidates = retriever.retrieve(base / "fixed")

        identity = "Manager.add_routes.preview"
        self.assertIn(identity, {item.qualname for item in vulnerable_candidates})
        states = {
            (invariant.identifier, invariant.status)
            for candidates in (vulnerable_candidates, fixed_candidates)
            for item in candidates if item.qualname == identity
            for invariant in item.invariants
        }
        self.assertIn(("path-request-location-containment", "risk"), states)
        self.assertIn(("path-request-location-containment", "mitigation"), states)

    def test_interpreter_exec_and_structured_dispatch_are_distinguished(self):
        vulnerable = (
            "class Wrapper:\n"
            "    def other(self, query):\n"
            "        context = {'self': self}\n"
            "        exec(f'result = {query}', context)\n"
            "        return context['result']\n"
        )
        fixed = (
            "class Wrapper:\n"
            "    def other(self, query):\n"
            "        params = json.loads(query)\n"
            "        function = getattr(self.api, params['function'])\n"
            "        return function(*params.get('args', []))\n"
            "    def reflect(self, name):\n"
            "        return getattr(self, name)\n"
        )
        with tempfile.TemporaryDirectory() as root:
            base = Path(root)
            (base / "vulnerable").mkdir()
            (base / "fixed").mkdir()
            (base / "vulnerable" / "wrapper.py").write_text(vulnerable, encoding="utf-8")
            (base / "fixed" / "wrapper.py").write_text(fixed, encoding="utf-8")
            retriever = SecuritySemanticRetriever()
            vulnerable_candidates = retriever.retrieve(base / "vulnerable")
            fixed_candidates = retriever.retrieve(base / "fixed")

        def state(candidates):
            candidate = next(item for item in candidates if item.qualname == "Wrapper.other")
            invariant = next(
                item for item in candidate.invariants
                if item.identifier == "command-interpreter-data-boundary"
            )
            return candidate.category, invariant.status, candidate.score

        vulnerable_state = state(vulnerable_candidates)
        fixed_state = state(fixed_candidates)
        self.assertEqual(("command", "risk"), vulnerable_state[:2])
        self.assertEqual(("command", "mitigation"), fixed_state[:2])
        self.assertGreaterEqual(fixed_state[2], 120)
        vulnerable_candidate = next(
            item for item in vulnerable_candidates if item.qualname == "Wrapper.other"
        )
        self.assertIn("interpreter-template-expansion", vulnerable_candidate.signals)
        self.assertNotIn("Wrapper.reflect", {item.qualname for item in fixed_candidates})

    def test_file_model_provenance_requires_explicit_marker_validation(self):
        vulnerable = (
            "class FileDataDict(TypedDict):\n"
            "    path: str\n"
            "    meta: dict\n"
            "class FileData(BaseModel):\n"
            "    path: str\n"
            "    meta: dict = {'_type': 'FileData'}\n"
            "    def is_none(self):\n"
            "        return self.path is None\n"
        )
        fixed = (
            "class FileData(BaseModel):\n"
            "    path: str\n"
            "    meta: dict = {'_type': 'FileData'}\n"
            "    @model_validator(mode='before')\n"
            "    def validate_model(cls, value):\n"
            "        if not is_file_obj_with_meta(value):\n"
            "            raise ValueError(value)\n"
            "        return value\n"
        )
        with tempfile.TemporaryDirectory() as root:
            base = Path(root)
            (base / "vulnerable").mkdir()
            (base / "fixed").mkdir()
            (base / "vulnerable" / "models.py").write_text(vulnerable, encoding="utf-8")
            (base / "fixed" / "models.py").write_text(fixed, encoding="utf-8")
            for revision in ("vulnerable", "fixed"):
                (base / revision / "cache.py").write_text(
                    "async def async_move_files_to_cache(data):\n"
                    "    return await async_traverse(data, is_file_obj_with_meta)\n",
                    encoding="utf-8",
                )
                (base / revision / "pipeline.py").write_text(
                    "def preprocess(inputs, data_model):\n"
                    "    cached = async_move_files_to_cache(inputs, check_in_upload_folder=True)\n"
                    "    return data_model.model_validate(cached)\n",
                    encoding="utf-8",
                )
                (base / revision / "output.py").write_text(
                    "def postprocess(result):\n"
                    "    return async_move_files_to_cache(result, postprocess=True)\n",
                    encoding="utf-8",
                )
                (base / revision / "component.py").write_text(
                    "def _process_single_file(file_data):\n"
                    "    with open(file_data.path, 'rb') as handle:\n"
                    "        return handle.read()\n",
                    encoding="utf-8",
                )
            retriever = SecuritySemanticRetriever()
            vulnerable_candidates = retriever.retrieve(base / "vulnerable")
            fixed_candidates = retriever.retrieve(base / "fixed")

        def provenance(candidates):
            candidate = next(item for item in candidates if item.qualname == "FileData")
            state = next(
                item.status for item in candidate.invariants
                if item.identifier == "path-file-object-provenance"
            )
            return state, candidate.score

        vulnerable_state = provenance(vulnerable_candidates)
        fixed_state = provenance(fixed_candidates)
        self.assertEqual("risk", vulnerable_state[0])
        self.assertEqual("mitigation", fixed_state[0])
        self.assertGreaterEqual(vulnerable_state[1], 160)
        self.assertNotIn("FileDataDict", {
            item.qualname for item in vulnerable_candidates
        })
        vulnerable_model = next(
            item for item in vulnerable_candidates if item.qualname == "FileData"
        )
        self.assertIn("preprocess", vulnerable_model.relations)
        self.assertTrue({
            "FileData", "preprocess", "async_move_files_to_cache",
            "_process_single_file",
        }.issubset({
            item.qualname
            for item in SecuritySemanticRetriever.evidence_packet(vulnerable_candidates)
        }))
        sink = next(
            item for item in vulnerable_candidates
            if item.qualname == "_process_single_file"
        )
        self.assertIn("component-file-read-sink", sink.signals)
        output = next(
            item for item in vulnerable_candidates if item.qualname == "postprocess"
        )
        self.assertFalse(any(
            item.identifier == "path-file-object-provenance"
            for item in output.invariants
        ))

    def test_structural_partition_clause_guard_is_ranked_and_distinguished(self):
        vulnerable = (
            "class SQLColumnCheckOperator:\n"
            "    sql_template = 'SELECT * FROM table WHERE {partition_clause}'\n"
            "    def __init__(self, partition_clause=None):\n"
            "        self.partition_clause = partition_clause\n"
        )
        fixed = vulnerable.replace(
            "self.partition_clause = partition_clause",
            "self.partition_clause = _initialize_partition_clause(partition_clause)",
        )
        with tempfile.TemporaryDirectory() as root:
            base = Path(root)
            (base / "vulnerable").mkdir()
            (base / "fixed").mkdir()
            (base / "vulnerable" / "sql.py").write_text(vulnerable, encoding="utf-8")
            (base / "fixed" / "sql.py").write_text(fixed, encoding="utf-8")
            retriever = SecuritySemanticRetriever(per_category=1)
            vulnerable_candidates = retriever.retrieve(base / "vulnerable")
            fixed_candidates = retriever.retrieve(base / "fixed")

        def boundary(candidates):
            candidate = next(
                item for item in candidates
                if item.qualname == "SQLColumnCheckOperator.__init__"
            )
            return next(
                item.status for item in candidate.invariants
                if item.identifier == "sql-partition-clause-boundary"
            )

        self.assertEqual("risk", boundary(vulnerable_candidates))
        self.assertEqual("mitigation", boundary(fixed_candidates))

    def test_evidence_packet_preserves_categories_and_fills_budget(self):
        def candidate(index, category, invariant=False):
            invariants = ()
            if invariant:
                invariants = (SecurityInvariant(
                    identifier="risk-%d" % index,
                    category=category,
                    status="risk",
                    summary="risk",
                ),)
            return SemanticCandidate(
                path="src/%d.py" % index,
                qualname="candidate_%d" % index,
                start_line=1,
                end_line=2,
                category=category,
                score=100 - index,
                signals=("signal",),
                code="def candidate_%d(): pass\n" % index,
                invariants=invariants,
            )

        candidates = [
            candidate(0, "command", True), candidate(1, "command"),
            candidate(2, "path", True), candidate(3, "path"),
            candidate(4, "sql", True), candidate(5, "sql"),
            candidate(6, "command"), candidate(7, "path"),
        ]
        default_packet = SecuritySemanticRetriever.evidence_packet(candidates)
        packet = SecuritySemanticRetriever.evidence_packet(candidates, 6)
        self.assertEqual(8, len(default_packet))
        self.assertEqual(6, len(packet))
        self.assertEqual({"command", "path", "sql"}, {item.category for item in packet})

    def test_evidence_packet_keeps_second_independent_invariant_anchor(self):
        def candidate(index, category, invariant_id, status="risk"):
            return SemanticCandidate(
                path="src/%d.py" % index,
                qualname="candidate_%d" % index,
                start_line=1,
                end_line=2,
                category=category,
                score=100 - index,
                signals=("signal",),
                code="def candidate_%d(): pass\n" % index,
                invariants=(SecurityInvariant(
                    identifier=invariant_id,
                    category=category,
                    status=status,
                    summary="hypothesis",
                ),),
            )

        candidates = [
            candidate(0, "command", "command-boundary"),
            candidate(1, "sql", "sql-boundary"),
            candidate(2, "path", "path-boundary"),
            candidate(3, "command", "command-boundary"),
            candidate(4, "command", "command-boundary"),
            candidate(5, "sql", "sql-boundary", "mitigation"),
        ]
        packet = SecuritySemanticRetriever.evidence_packet(candidates, 6)
        packet_symbols = {item.qualname for item in packet}
        self.assertIn("candidate_3", packet_symbols)
        self.assertIn("candidate_5", packet_symbols)

    def test_platform_file_open_is_kept_as_shell_mitigation_evidence(self):
        with tempfile.TemporaryDirectory() as root:
            Path(root, "viewer.py").write_text(
                "import os\n"
                "class WindowsViewer:\n"
                "    def show_file(self, path):\n"
                "        os.startfile(path)\n"
                "        return 1\n",
                encoding="utf-8",
            )
            candidates = SecuritySemanticRetriever().retrieve(root)

        candidate = next(
            item for item in candidates if item.qualname == "WindowsViewer.show_file"
        )
        self.assertIn(
            ("command-shell-data-boundary", "mitigation"),
            {(item.identifier, item.status) for item in candidate.invariants},
        )


if __name__ == "__main__":
    unittest.main()
