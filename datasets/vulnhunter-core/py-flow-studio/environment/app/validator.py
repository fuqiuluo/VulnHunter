"""Static syntax and signature preflight for custom pipeline operators."""

from __future__ import annotations

import ast
import importlib.util
from typing import Any


class ValidationError(ValueError):
    """Raised when operator source fails syntax or structural checks."""


def inspect_operator_code(source: str) -> dict[str, Any]:
    """Validate Python operator source via AST and bytecode compilation without runtime evaluation."""
    try:
        tree = ast.parse(source, filename="<operator>", mode="exec")
    except SyntaxError as exc:
        raise ValidationError(f"Syntax error at line {exc.lineno}: {exc.msg}") from exc

    imports: list[str] = []
    missing_imports: list[str] = []
    functions: dict[str, list[str]] = {}

    for node in tree.body:
        if isinstance(node, ast.Import):
            for alias in node.names:
                top_pkg = alias.name.split(".")[0]
                imports.append(alias.name)
                if importlib.util.find_spec(top_pkg) is None:
                    missing_imports.append(alias.name)
        elif isinstance(node, ast.ImportFrom) and node.module:
            top_pkg = node.module.split(".")[0]
            imports.append(node.module)
            if importlib.util.find_spec(top_pkg) is None:
                missing_imports.append(node.module)
        elif isinstance(node, ast.FunctionDef):
            try:
                compile(ast.Module(body=[node], type_ignores=[]), "<operator>", "exec")
            except SyntaxError as exc:
                raise ValidationError(f"Function compilation failed: {exc.msg}") from exc
            functions[node.name] = [arg.arg for arg in node.args.args]

    if not functions:
        raise ValidationError("Operator module must define at least one top-level function")

    return {
        "imports": imports,
        "missing_imports": missing_imports,
        "functions": functions,
    }
