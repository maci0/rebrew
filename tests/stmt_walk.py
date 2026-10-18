"""Statement walk for suite scans that only read statements.

``ast.walk`` visits every expression. Import and class scans do not read
those nodes. This walk still enters every statement body, including ``if``,
``try``, ``match``, functions and classes, so a nested import stays visible.
"""

from __future__ import annotations

import ast
from collections.abc import Iterator

_NESTED = ("body", "orelse", "finalbody", "handlers", "cases")


def iter_statements(tree: ast.AST) -> Iterator[ast.stmt]:
    """Yield every statement under *tree*, including ones nested in bodies."""
    stack: list[ast.AST] = [tree]
    while stack:
        node = stack.pop()
        for field in _NESTED:
            children = getattr(node, field, None)
            if isinstance(children, list):
                stack.extend(children)
        if isinstance(node, ast.stmt):
            yield node
