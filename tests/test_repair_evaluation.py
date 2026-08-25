import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from lima.repair_evaluation import RepairConstraintEvaluator, load_repair_dataset


ROOT = Path(__file__).resolve().parents[1]
DATASET = ROOT / "evaluation_data" / "security_repair_cases.json"


class RepairConstraintEvaluationTests(unittest.TestCase):
    def test_fixed_dataset_has_balanced_cwes_and_all_constraints_pass(self):
        dataset = load_repair_dataset(DATASET)
        result = RepairConstraintEvaluator().run(dataset)

        self.assertEqual(18, result["metrics"]["cases"])
        self.assertEqual(9, result["metrics"]["repair_cases"])
        self.assertEqual(9, result["metrics"]["abstain_cases"])
        self.assertEqual(1.0, result["metrics"]["verified_repair_rate"])
        self.assertEqual(1.0, result["metrics"]["correct_abstention_rate"])
        self.assertEqual(0.0, result["metrics"]["unsafe_patch_escape_rate"])
        self.assertEqual({}, result["failure_categories"])
        self.assertEqual(
            {"CWE-22": 6, "CWE-78": 6, "CWE-89": 6},
            {key: value["cases"] for key, value in result["by_cwe"].items()},
        )
        self.assertEqual(64, len(result["dataset_sha256"]))

    def test_cli_writes_reproducible_json_report(self):
        with tempfile.TemporaryDirectory() as root:
            output = Path(root, "repair-evaluation.json")
            completed = subprocess.run(
                [
                    sys.executable, str(ROOT / "scripts" / "run_repair_evaluation.py"),
                    "--dataset", str(DATASET), "--output", str(output),
                    "--min-constraint-accuracy", "1.0",
                ],
                cwd=ROOT, text=True, capture_output=True, check=False,
            )
            self.assertEqual(0, completed.returncode, completed.stderr)
            result = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(1.0, result["metrics"]["constraint_accuracy"])


if __name__ == "__main__":
    unittest.main()
