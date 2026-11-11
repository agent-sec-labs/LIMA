"""Lexical acceptance tests for statically anchored repair roots."""

import ast
import unittest

from lima.repair_path_anchors import absolute_path_expression


class AbsolutePathAnchorTests(unittest.TestCase):
    def test_accepts_absolute_literal_path_expressions(self):
        for source in (
            "'/fixed'",
            "'C:/fixed'",
            "r'\\\\server\\share\\fixed'",
            "Path('/fixed')",
            "pathlib.Path('C:/fixed')",
            "Path('/fixed') / 'child'",
            "Path('C:/fixed') / 'child'",
        ):
            with self.subTest(source=source):
                self.assertEqual(
                    True, absolute_path_expression(ast.parse(source, mode="eval").body)
                )

    def test_rejects_nonabsolute_or_dynamic_path_expressions(self):
        for source in (
            "''",
            "'.'",
            "'approved'",
            "'C:relative'",
            "r'\\root-relative'",
            "'a\\x00b'",
            "root",
            "Path(root)",
            "Path('/fixed', 'extra')",
            "Path('/fixed', mode='x')",
            "other.Path('/fixed')",
            "Path('C:/fixed') / 'D:relative'",
            "Path('/fixed') / dynamic_part",
            "Path('/fixed') / ''",
        ):
            with self.subTest(source=source):
                self.assertEqual(
                    False, absolute_path_expression(ast.parse(source, mode="eval").body)
                )
