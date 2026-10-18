"""Statement walk: nested imports stay visible, expression size does not."""

from __future__ import annotations

import ast

from stmt_walk import iter_statements


def _import_names(source: str) -> set[str]:
    names: set[str] = set()
    for node in iter_statements(ast.parse(source)):
        if isinstance(node, ast.Import):
            names.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            names.add(node.module)
    return names


def test_nested_imports_are_visible() -> None:
    """An import in a function, class, branch, handler, or match arm counts."""
    source = (
        "import top\n"
        "def f(x):\n"
        "    import inside_func\n"
        "    if x:\n"
        "        import inside_if\n"
        "    else:\n"
        "        import inside_else\n"
        "    try:\n"
        "        import inside_try\n"
        "    except Exception:\n"
        "        import inside_except\n"
        "    finally:\n"
        "        import inside_finally\n"
        "    match x:\n"
        "        case 1:\n"
        "            import inside_match\n"
        "class C:\n"
        "    import inside_class\n"
    )
    assert _import_names(source) == {
        "top",
        "inside_func",
        "inside_if",
        "inside_else",
        "inside_try",
        "inside_except",
        "inside_finally",
        "inside_match",
        "inside_class",
    }


def test_expression_size_does_not_change_the_statement_count() -> None:
    """The walk's cost is the statement count, which does not move with load.

    A longer arithmetic expression adds nodes ``ast.walk`` would visit and
    adds none here. The two sizes must report the same statement count.
    """

    def count(terms: int) -> int:
        source = "def f():\n    return " + " + ".join(["1"] * terms) + "\nimport os\n"
        return sum(1 for _ in iter_statements(ast.parse(source)))

    assert count(2) == count(400) == 3
