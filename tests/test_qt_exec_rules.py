"""Qt event loops are not dynamic-code-execution findings."""

import unittest

from lima.diff_parser import parse_unified_diff
from lima.reviewer import SecurityRuleReviewer


class QtExecRuleTests(unittest.TestCase):
    def review_line(self, path, content):
        diff = f"--- a/{path}\n+++ b/{path}\n@@ -0,0 +1 @@\n+{content}\n"
        return SecurityRuleReviewer().review(diff, parse_unified_diff(diff))

    def test_qt_event_loop_and_dialog_exec_are_not_code_execution_candidates(self):
        for path, content in (
            ("ApplicationExeCode/RiaMain.cpp", "exitCode = QCoreApplication::instance()->exec();"),
            ("dialog.cpp", "int ret = msgBox.exec();"),
            ("event.hpp", "return loop.exec();"),
            ("event.CPP", "return app.exec();"),
        ):
            with self.subTest(path=path):
                self.assertNotIn("SEC-EVAL", [x.rule_id for x in self.review_line(path, content)])

    def test_python_and_javascript_dynamic_execution_remains_detected(self):
        for path, content in (
            ("app.py", "eval(user_input)"),
            ("app.py", "exec(code)"),
            ("app.js", "eval(userInput)"),
        ):
            with self.subTest(path=path, content=content):
                self.assertIn("SEC-EVAL", [x.rule_id for x in self.review_line(path, content)])


if __name__ == "__main__":
    unittest.main()
