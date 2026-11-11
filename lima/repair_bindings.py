"""Conservative binding proofs for the bounded Python repair subset.

Ambiguous bindings (including unrelated scopes) are rejected rather than
guessing which dynamic Python value will reach a repaired sink.
"""

import ast

from .repair_path_anchors import absolute_path_expression

PATH_HELPER_SOURCE = """def _lima_resolve_under_base(base, untrusted_path):
    root = _LIMAPath(base)
    if not root.is_absolute():
        raise ValueError('path root must be absolute')
    root = root.resolve()
    candidate = (root / untrusted_path).resolve()
    if candidate != root and root not in candidate.parents:
        raise ValueError('path escapes allowed root')
    return candidate
"""


def bindings(tree: ast.AST, name: str) -> list[ast.AST]:
    """Collect all binding/deletion forms, not just Name(Store) nodes."""
    found = []
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Name)
            and node.id == name
            and isinstance(node.ctx, ast.Store | ast.Del)
        ):
            found.append(node)
        elif isinstance(node, ast.arg) and node.arg == name:
            found.append(node)
        elif (
            isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef)
            and node.name == name
        ):
            found.append(node)
        elif isinstance(node, ast.Import):
            found.extend(
                alias for alias in node.names if (alias.asname or alias.name.split(".")[0]) == name
            )
        elif isinstance(node, ast.ImportFrom):
            found.extend(
                alias
                for alias in node.names
                if alias.name == "*" or (alias.asname or alias.name) == name
            )
        elif isinstance(node, ast.ExceptHandler) and node.name == name:
            found.append(node)
        elif isinstance(node, ast.MatchAs | ast.MatchStar) and node.name == name:
            found.append(node)
        elif isinstance(node, ast.MatchMapping) and node.rest == name:
            found.append(node)
        elif isinstance(node, ast.Global | ast.Nonlocal) and name in node.names:
            found.append(node)
        elif isinstance(node, ast.Attribute | ast.Subscript) and isinstance(
            node.ctx, ast.Store | ast.Del
        ):
            base = node.value
            while isinstance(base, ast.Attribute | ast.Subscript):
                base = base.value
            if isinstance(base, ast.Name) and base.id == name:
                found.append(node)
    return found


def has_dynamic_namespace(tree: ast.AST) -> bool:
    return any(
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id in {"exec", "eval", "globals", "locals", "setattr", "delattr"}
        for node in ast.walk(tree)
    )


def module_import_proven(tree: ast.Module, name: str, module: str, member: str = "") -> bool:
    candidates = []
    for node in tree.body:
        if (
            member
            and isinstance(node, ast.ImportFrom)
            and node.module == module
            and node.level == 0
        ):
            candidates.extend(
                a for a in node.names if a.name == member and (a.asname or a.name) == name
            )
        elif not member and isinstance(node, ast.Import):
            candidates.extend(
                a for a in node.names if a.name == module and (a.asname or a.name) == name
            )
    return (
        not has_dynamic_namespace(tree)
        and len(candidates) == 1
        and bindings(tree, name) == candidates
    )


def static_path_proven(node: ast.AST, tree: ast.Module) -> bool:
    if not absolute_path_expression(node):
        return False
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return True
    if isinstance(node, ast.Call) and len(node.args) == 1 and not node.keywords:
        constructor = node.func
        allowed = (
            isinstance(constructor, ast.Name)
            and constructor.id == "Path"
            and module_import_proven(tree, "Path", "pathlib", "Path")
        ) or (
            isinstance(constructor, ast.Attribute)
            and constructor.attr == "Path"
            and isinstance(constructor.value, ast.Name)
            and constructor.value.id == "pathlib"
            and module_import_proven(tree, "pathlib", "pathlib")
        )
        return allowed and static_path_proven(node.args[0], tree)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Div):
        return (
            static_path_proven(node.left, tree)
            and isinstance(node.right, ast.Constant)
            and isinstance(node.right.value, str)
            and bool(node.right.value)
        )
    return False


def trusted_root_proven(node: ast.AST, tree: ast.Module) -> bool:
    if has_dynamic_namespace(tree):
        return False
    if static_path_proven(node, tree):
        return True
    if not isinstance(node, ast.Name):
        return False
    # Only one unconditional module assignment may provide a named root.
    # A parameter, closure binding, later assignment or delete invalidates it.
    found = bindings(tree, node.id)
    if len(found) != 1:
        return False
    for statement in tree.body:
        if isinstance(statement, ast.Assign) and len(statement.targets) == 1:
            target = statement.targets[0]
        elif isinstance(statement, ast.AnnAssign):
            target = statement.target
        else:
            continue
        if target is found[0] and statement.value is not None:
            return static_path_proven(statement.value, tree)
    return False
