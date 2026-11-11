"""Lexical checks for statically absolute ``pathlib`` expressions."""

import ast
from pathlib import PurePosixPath, PureWindowsPath


def _literal_string(node: ast.AST) -> str | None:
    if not isinstance(node, ast.Constant) or not isinstance(node.value, str):
        return None
    if not node.value or "\x00" in node.value:
        return None
    return node.value


def _path_constructor_string(node: ast.AST) -> str | None:
    if not isinstance(node, ast.Call) or len(node.args) != 1 or node.keywords:
        return None
    if isinstance(node.func, ast.Name):
        allowed = node.func.id == "Path"
    elif isinstance(node.func, ast.Attribute):
        allowed = (
            node.func.attr == "Path"
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "pathlib"
        )
    else:
        allowed = False
    return _literal_string(node.args[0]) if allowed else None


def _path_values(node: ast.AST) -> tuple[PurePosixPath, PureWindowsPath] | None:
    value = _path_constructor_string(node)
    if value is not None:
        return PurePosixPath(value), PureWindowsPath(value)
    if not isinstance(node, ast.BinOp) or not isinstance(node.op, ast.Div):
        return None
    left = _path_values(node.left)
    right = _literal_string(node.right)
    if left is None or right is None:
        return None
    return left[0] / right, left[1] / right


def absolute_path_expression(node: ast.AST) -> bool:
    """Return whether *node* is a purely lexical, anchored path expression.

    Binding/import authenticity is deliberately outside this narrow helper.
    """
    literal = _literal_string(node)
    if literal is not None:
        paths = PurePosixPath(literal), PureWindowsPath(literal)
    else:
        paths = _path_values(node)
    return paths is not None and (paths[0].is_absolute() or paths[1].is_absolute())
