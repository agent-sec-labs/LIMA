"""Conservative lexical proof for SQLite cursor receivers."""

import ast

from .repair_bindings import bindings as _existing_bindings

_DYNAMIC_NAMESPACE = {"exec", "eval", "globals", "locals", "vars", "setattr", "delattr"}
_CONNECTION_METHODS = {
    "cursor",
    "execute",
    "executemany",
    "executescript",
    "commit",
    "rollback",
    "close",
}
_CURSOR_METHODS = {"execute", "executemany", "executescript", "close"}


def _parents(tree: ast.AST) -> dict[ast.AST, ast.AST]:
    return {child: node for node in ast.walk(tree) for child in ast.iter_child_nodes(node)}


def _contains_dynamic_namespace(tree: ast.Module) -> bool:
    return any(
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id in _DYNAMIC_NAMESPACE
        for node in ast.walk(tree)
    )


def _scope_for(
    tree: ast.Module, target: ast.AST
) -> ast.Module | ast.FunctionDef | ast.AsyncFunctionDef | None:
    def visit(node: ast.AST, scopes: list[ast.AST]) -> list[ast.AST] | None:
        if node is target:
            return scopes
        next_scopes = scopes
        if isinstance(node, ast.ClassDef):
            next_scopes = [*scopes, node]
        elif isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            next_scopes = [*scopes, node]
        for child in ast.iter_child_nodes(node):
            found = visit(child, next_scopes)
            if found is not None:
                return found
        return None

    scopes = visit(tree, [])
    if scopes is None or any(isinstance(scope, ast.ClassDef) for scope in scopes):
        return None
    functions = [
        scope for scope in scopes if isinstance(scope, ast.FunctionDef | ast.AsyncFunctionDef)
    ]
    return functions[-1] if functions else tree


def _statements(scope: ast.Module | ast.FunctionDef | ast.AsyncFunctionDef) -> list[ast.stmt]:
    return scope.body


def _assignment(
    scope: ast.Module | ast.FunctionDef | ast.AsyncFunctionDef, name: str, before: ast.AST
) -> ast.Assign | ast.AnnAssign | None:
    matches: list[ast.Assign | ast.AnnAssign] = []
    for statement in _statements(scope):
        if isinstance(statement, ast.Assign) and len(statement.targets) == 1:
            target = statement.targets[0]
        elif isinstance(statement, ast.AnnAssign) and statement.value is not None:
            target = statement.target
        else:
            continue
        if isinstance(target, ast.Name) and target.id == name:
            matches.append(statement)
    if len(matches) != 1 or not _precedes(matches[0], before):
        return None
    return matches[0]


def _precedes(left: ast.AST, right: ast.AST) -> bool:
    return (left.lineno, left.col_offset) < (right.lineno, right.col_offset)


def _bindings(tree: ast.Module, name: str) -> list[ast.AST]:
    return _existing_bindings(tree, name)


def _is_only_binding(tree: ast.Module, name: str, expected: ast.AST) -> bool:
    return _bindings(tree, name) == [expected]


def _module_constructor(tree: ast.Module, node: ast.AST) -> tuple[str, ast.alias] | None:
    if not isinstance(node, ast.Call) or len(node.args) != 1 or node.keywords:
        return None
    if not isinstance(node.args[0], ast.Constant) or not isinstance(node.args[0].value, str):
        return None
    sqlite_imports = [
        alias
        for statement in ast.walk(tree)
        if isinstance(statement, ast.Import)
        for alias in statement.names
        if alias.name == "sqlite3" or alias.name.startswith("sqlite3.")
    ]
    sqlite_imports.extend(
        alias
        for statement in ast.walk(tree)
        if isinstance(statement, ast.ImportFrom)
        and statement.module is not None
        and (statement.module == "sqlite3" or statement.module.startswith("sqlite3."))
        for alias in statement.names
    )
    if len(sqlite_imports) != 1:
        return None
    if (
        isinstance(node.func, ast.Attribute)
        and node.func.attr == "connect"
        and isinstance(node.func.value, ast.Name)
    ):
        name = node.func.value.id
        for statement in tree.body:
            if isinstance(statement, ast.Import):
                for alias in statement.names:
                    if alias.name == "sqlite3" and (alias.asname or "sqlite3") == name:
                        return (name, alias) if _precedes(alias, node) else None
    if isinstance(node.func, ast.Name):
        name = node.func.id
        for statement in tree.body:
            if (
                isinstance(statement, ast.ImportFrom)
                and statement.module == "sqlite3"
                and statement.level == 0
            ):
                for alias in statement.names:
                    if alias.name == "connect" and (alias.asname or "connect") == name:
                        return (name, alias) if _precedes(alias, node) else None
    return None


def _approved_loads(
    tree: ast.Module, name: str, kind: str, parents: dict[ast.AST, ast.AST]
) -> bool:
    allowed_methods = _CONNECTION_METHODS if kind == "connection" else _CURSOR_METHODS
    for node in ast.walk(tree):
        if not isinstance(node, ast.Name) or node.id != name or not isinstance(node.ctx, ast.Load):
            continue
        parent = parents.get(node)
        if kind == "module":
            valid = (
                isinstance(parent, ast.Attribute)
                and parent.value is node
                and parent.attr == "connect"
                and isinstance(parents.get(parent), ast.Call)
                and parents[parent].func is parent
            )
        elif kind == "connect":
            valid = isinstance(parent, ast.Call) and parent.func is node
        else:
            call = parents.get(parent) if isinstance(parent, ast.Attribute) else None
            valid = (
                isinstance(parent, ast.Attribute)
                and parent.value is node
                and parent.attr in allowed_methods
                and isinstance(call, ast.Call)
                and call.func is parent
            )
            if valid and parent.attr == "cursor" and (call.args or call.keywords):
                valid = False
        if not valid:
            return False
    return True


def sql_receiver_proven(tree: ast.Module, call: ast.Call) -> bool:
    """Prove that an ``execute`` call is reached through a local SQLite cursor.

    This intentionally proves only direct, unconditional construction; callers
    must separately validate SQL shape and parameterization.
    """
    if _contains_dynamic_namespace(tree):
        return False
    if not isinstance(call.func, ast.Attribute) or call.func.attr != "execute":
        return False
    if not isinstance(call.func.value, ast.Name):
        return False
    receiver_name = call.func.value.id
    receiver_scope = _scope_for(tree, call)
    if receiver_scope is None:
        return False
    receiver_assignment = _assignment(receiver_scope, receiver_name, call)
    if receiver_assignment is None and receiver_scope is not tree:
        receiver_scope = tree
        receiver_assignment = _assignment(receiver_scope, receiver_name, call)
    if receiver_assignment is None:
        return False
    receiver_target = (
        receiver_assignment.targets[0]
        if isinstance(receiver_assignment, ast.Assign)
        else receiver_assignment.target
    )
    if not _is_only_binding(tree, receiver_name, receiver_target):
        return False
    receiver_value = receiver_assignment.value
    receiver_kind = "connection"
    connection_name: str | None = None
    constructor_call: ast.AST = receiver_value
    if (
        isinstance(receiver_value, ast.Call)
        and not receiver_value.args
        and not receiver_value.keywords
        and isinstance(receiver_value.func, ast.Attribute)
        and receiver_value.func.attr == "cursor"
    ):
        receiver_kind = "cursor"
        cursor_base = receiver_value.func.value
        if isinstance(cursor_base, ast.Name):
            connection_name = cursor_base.id
            connection_assignment = _assignment(
                receiver_scope, connection_name, receiver_assignment
            )
            if connection_assignment is None and receiver_scope is not tree:
                connection_assignment = _assignment(tree, connection_name, receiver_assignment)
            if connection_assignment is None:
                return False
            connection_target = (
                connection_assignment.targets[0]
                if isinstance(connection_assignment, ast.Assign)
                else connection_assignment.target
            )
            if not _is_only_binding(tree, connection_name, connection_target):
                return False
            constructor_call = connection_assignment.value
        else:
            constructor_call = cursor_base
    constructor = _module_constructor(tree, constructor_call)
    if constructor is None:
        return False
    constructor_name, constructor_binding = constructor
    if not _is_only_binding(tree, constructor_name, constructor_binding):
        return False
    parents = _parents(tree)
    constructor_kind = "module" if isinstance(constructor_call.func, ast.Attribute) else "connect"
    return (
        _approved_loads(tree, constructor_name, constructor_kind, parents)
        and (
            connection_name is None or _approved_loads(tree, connection_name, "connection", parents)
        )
        and _approved_loads(tree, receiver_name, receiver_kind, parents)
    )
