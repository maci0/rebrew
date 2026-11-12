"""cast_rewrite.py - Rewrite raw ``(T *) 0xVA`` casts and declare the globals that replace them.

Shared by ``source symbolize`` (names from base relocations) and ``data pair`` (names
paired across two targets).
"""

from __future__ import annotations

from typing import Any


def rewrite_casts(
    text: str, targets: dict[str, dict[int, str]], skip: set[str]
) -> tuple[str, list[dict[str, Any]]]:
    """Replace each targeted ``(T *) 0xVA`` constant inside its own function's body.

    Returns the new text and one ``{function, value, expression, count}`` row
    per target. A function in *skip* keeps its body.
    """
    from rebrew.c_parser import pointer_cast_literals

    counts: dict[tuple[str, int], int] = {
        (function, value): 0 for function, values in targets.items() for value in values
    }
    raw = text.encode("utf-8", errors="surrogateescape")
    edits = [
        lit
        for lit in pointer_cast_literals(text)
        if lit.function not in skip and lit.value in targets.get(lit.function, {})
    ]
    for lit in sorted(edits, key=lambda item: item.start, reverse=True):
        expression = targets[lit.function][lit.value]
        raw = raw[: lit.start] + expression.encode("ascii") + raw[lit.end :]
        counts[(lit.function, lit.value)] += 1
    rows = [
        {
            "function": function,
            "value": f"0x{value:08x}",
            "expression": targets[function][value],
            "count": count,
            "skipped": function in skip,
        }
        for (function, value), count in sorted(counts.items())
    ]
    return raw.decode("utf-8", errors="surrogateescape"), rows


def declare_externs(text: str, names: list[str]) -> tuple[str, list[str]]:
    """Append ``extern char NAME[];`` to the file's first one-line top-level extern.

    A new line would shift every later line number, which was measured to
    change MSVC6 code generation in some translation units. A name already
    declared or defined at file scope is left out. Returns the new text and
    the names declared.
    """
    from rebrew.c_parser import find_extern_variables, mask_msvc_syntax, parse_c_source

    lines = text.splitlines(keepends=True)
    tree, raw = parse_c_source(mask_msvc_syntax(text))
    nodes = tree.root_node.children
    variables = [
        var
        for var in find_extern_variables(text, include_definitions=True)
        if any(
            node.type == "declaration"
            and node.start_point.row <= var.line - 1 <= node.end_point.row
            for node in nodes
        )
    ]
    declared = {var.name for var in variables}
    wanted = [name for name in dict.fromkeys(names) if name not in declared]
    if not wanted:
        return text, []
    anchor = next(
        (
            var.line
            for var in variables
            if var.line == var.end_line
            and lines[var.line - 1].lstrip().startswith("extern")
            and lines[var.line - 1].rstrip().endswith(";")
        ),
        None,
    )
    if anchor is None:
        # Only gaps between top-level AST nodes are outside comments and directives.
        first_body = next(
            (node.start_byte for node in nodes if node.type == "function_definition"), len(raw)
        )
        blank = None
        offset = 0
        for i, line in enumerate(lines):
            end = offset + len(line.encode("utf-8", errors="surrogateescape"))
            if end > first_body:
                break
            if not line.strip() and not any(
                node.start_byte < end and offset < node.end_byte for node in nodes
            ):
                blank = i
                break
            offset = end
        if blank is None:
            raise ValueError("no one-line top-level extern declaration or empty line to declare in")
        anchor = blank + 1
        decls = " ".join(f"extern char {name}[];" for name in wanted)
        lines[blank] = decls + (lines[blank] if lines[blank] in ("\n", "\r\n") else "\n")
        return "".join(lines), wanted
    line = lines[anchor - 1]
    body = line.rstrip("\r\n")
    lines[anchor - 1] = (
        body.rstrip() + "".join(f" extern char {name}[];" for name in wanted) + line[len(body) :]
    )
    return "".join(lines), wanted
