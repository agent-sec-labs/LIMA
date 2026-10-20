"""Live engine regression for the C++ syntax used in ResInsight."""

import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from cxx_analyzer.source_scan import parse_semgrep_json, recognized_host_semgrep_unavailability


class StructuredBindingEngineTests(unittest.TestCase):
    @unittest.skipUnless(shutil.which("semgrep"), "requires the packaged Semgrep engine")
    def test_range_loop_binding_never_turns_parser_gaps_into_clean_evidence(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "source.cpp").write_text(
                "#include <map>\n"
                "void modern() {\n"
                "  std::map<int, int> values;\n"
                "  for (const auto& [key, value] : values) { consume(key, value); }\n"
                "  int buffer[2] = {0, 1};\n"
                "  buffer[2] = 42;\n"
                "}\n",
                encoding="utf8",
            )
            result = subprocess.run(  # noqa: S603 - fixed local Semgrep regression executable.
                [
                    shutil.which("semgrep"),
                    "--json",
                    "--quiet",
                    "--metrics=off",
                    "--disable-version-check",
                    "--no-rewrite-rule-ids",
                    "--config",
                    str(Path(__file__).resolve().parents[1] / "cxx_analyzer/rules/cxx-memory.yml"),
                    ".",
                ],
                cwd=root,
                capture_output=True,
                text=True,
                timeout=45,
                env={**os.environ, "HOME": temporary},
            )
        if recognized_host_semgrep_unavailability(result.returncode, result.stderr):
            self.skipTest("host Semgrep cannot initialize its certificate store")
        self.assertEqual(0, result.returncode, result.stderr)
        data = json.loads(result.stdout)
        for item in data["results"]:
            item["path"] = item["path"].replace("\\", "/")
        findings, diagnostics = parse_semgrep_json(json.dumps(data), {"source.cpp"})
        if data["errors"]:
            # Current community engines cannot lower this structured binding.
            # A future engine may support it; neither case may claim false safety.
            self.assertEqual((), findings)
            self.assertIn("semgrep-reported-errors", diagnostics)
        else:
            self.assertEqual([], diagnostics)
            self.assertTrue(
                any(item.rule_id == "cxx.source.oob-write.constant-index" for item in findings)
            )


if __name__ == "__main__":
    unittest.main()
