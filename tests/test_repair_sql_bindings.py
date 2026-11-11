"""Proof tests for SQLite receivers used by automatic SQL repairs."""

import ast
import unittest

from lima.repair_sql_bindings import sql_receiver_proven


def execute_call(source: str) -> tuple[ast.Module, ast.Call]:
    tree = ast.parse(source)
    return tree, next(
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "execute"
    )


class SqlReceiverProofTests(unittest.TestCase):
    def test_proves_real_sqlite_module_connection_and_cursor(self) -> None:
        tree, call = execute_call(
            "import sqlite3\n"
            "connection = sqlite3.connect(':memory:')\n"
            "cursor = connection.cursor()\n"
            "cursor.execute('SELECT 1')\n"
        )
        self.assertTrue(sql_receiver_proven(tree, call))

    def test_proves_aliased_module_connection_used_in_function(self) -> None:
        tree, call = execute_call(
            "import sqlite3 as database\n"
            "connection = database.connect('app.db')\n"
            "def lookup(value):\n"
            "    cursor = connection.cursor()\n"
            "    return cursor.execute('SELECT ?', (value,))\n"
        )
        self.assertTrue(sql_receiver_proven(tree, call))

    def test_proves_from_import_and_patched_oracle_call(self) -> None:
        source = (
            "from sqlite3 import connect as open_database\n"
            "def lookup(value):\n"
            "    connection = open_database('app.db')\n"
            "    cursor = connection.cursor()\n"
            "    return cursor.execute('SELECT ?', (value,))\n"
        )
        tree, call = execute_call(source)
        self.assertTrue(sql_receiver_proven(tree, call))

        patched_tree, patched_call = execute_call(
            source.replace("'SELECT ?'", "'SELECT ? LIMIT 1'")
        )
        self.assertTrue(sql_receiver_proven(patched_tree, patched_call))

    def test_proves_inline_cursor_and_direct_connection_receivers(self) -> None:
        sources = (
            (
                "import sqlite3; cursor = sqlite3.connect(':memory:').cursor(); "
                "cursor.execute('SELECT 1').fetchall()\n"
            ),
            (
                "import sqlite3\nconnection = sqlite3.connect(':memory:')\n"
                "connection.execute('SELECT 1').fetchall()\n"
            ),
            (
                "import sqlite3\ncursor = sqlite3.connect(':memory:').cursor()\n"
                "def read():\n    return cursor.execute('SELECT 1').fetchall()\n"
            ),
        )
        for source in sources:
            with self.subTest(source=source):
                tree, call = execute_call(source)
                self.assertTrue(sql_receiver_proven(tree, call))

    def test_rejects_custom_wrapper_unbound_names_and_comments(self) -> None:
        sources = (
            (
                "def connect(path): return object()\nconn = connect('db')\n"
                "cur = conn.cursor()\ncur.execute('x')\n"
            ),
            "cursor.execute('SELECT 1')\n",
            "# sqlite3.connect(':memory:')\ncursor.execute('SELECT 1')\n",
        )
        for source in sources:
            with self.subTest(source=source):
                tree, call = execute_call(source)
                self.assertFalse(sql_receiver_proven(tree, call))

    def test_rejects_factories_conditionals_shadowing_mutation_and_escapes(self) -> None:
        sources = (
            (
                "import sqlite3\nconn = sqlite3.connect('db', factory=Custom)\n"
                "cur = conn.cursor()\ncur.execute('x')\n"
            ),
            (
                "import sqlite3\nif enabled:\n    conn = sqlite3.connect('db')\n"
                "cur = conn.cursor()\ncur.execute('x')\n"
            ),
            (
                "import sqlite3\ndef lookup(sqlite3):\n    conn = sqlite3.connect('db')\n"
                "    cur = conn.cursor()\n    cur.execute('x')\n"
            ),
            (
                "import sqlite3\nconn = sqlite3.connect('db')\nconn.row_factory = object\n"
                "cur = conn.cursor()\ncur.execute('x')\n"
            ),
            (
                "import sqlite3\nconn = sqlite3.connect('db')\naudit(conn)\n"
                "cur = conn.cursor()\ncur.execute('x')\n"
            ),
            (
                "import sqlite3\nconn = sqlite3.connect('db')\ncur = conn.cursor()\n"
                "alias = cur\nalias.execute('x')\n"
            ),
            (
                "import sqlite3\ntry:\n    pass\nexcept Exception as conn:\n    pass\n"
                "conn = sqlite3.connect('db')\ncur = conn.cursor()\ncur.execute('x')\n"
            ),
            (
                "import sqlite3\nmatch value:\n    case {'conn': conn}:\n        pass\n"
                "conn = sqlite3.connect('db')\ncur = conn.cursor()\ncur.execute('x')\n"
            ),
            (
                "import sqlite3\nfrom other import *\nconn = sqlite3.connect('db')\n"
                "cur = conn.cursor()\ncur.execute('x')\n"
            ),
            (
                "import sqlite3\nimport sqlite3 as other\nother.connect = Legacy\n"
                "conn = sqlite3.connect('db')\ncur = conn.cursor()\ncur.execute('x')\n"
            ),
            (
                "import sqlite3, sqlite3 as other\nconn = sqlite3.connect('db')\n"
                "cur = conn.cursor()\ncur.execute('x')\n"
            ),
            (
                "import sqlite3\ndef mutate():\n    import sqlite3 as other\n"
                "    other.connect = Legacy\nconn = sqlite3.connect('db')\n"
                "cur = conn.cursor()\ncur.execute('x')\n"
            ),
        )
        for source in sources:
            with self.subTest(source=source):
                tree, call = execute_call(source)
                self.assertFalse(sql_receiver_proven(tree, call))
