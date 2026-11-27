"""Preserve source-relative header resolution when moving C definitions."""

lazy import os
lazy from pathlib import Path

lazy from rebrew.c_parser import parse_c_source


def rebase_includes(text: str, source_dir: Path, output_dir: Path) -> str:
    """Respell existing quoted headers relative to the destination directory.

    System headers and names not found beside the original source keep their
    spelling and configured include-path lookup. AST-selected directives avoid
    changing include-like text in comments or string literals.
    """
    tree, raw = parse_c_source(text)
    pending = [tree.root_node]
    edits: list[tuple[int, int, bytes]] = []
    while pending:
        node = pending.pop()
        pending.extend(node.named_children)
        if node.type != "preproc_include":
            continue
        path = node.child_by_field_name("path")
        if path is None or path.type != "string_literal":
            continue
        name = raw[path.start_byte + 1 : path.end_byte - 1].decode(
            "utf-8", errors="surrogateescape"
        )
        if Path(name).is_absolute():
            continue
        target = (source_dir / name).resolve()
        if not target.is_file():
            continue
        rebased = Path(os.path.relpath(target, output_dir.resolve())).as_posix()
        edits.append(
            (path.start_byte + 1, path.end_byte - 1, rebased.encode("utf-8", "surrogateescape"))
        )
    for start, end, replacement in sorted(edits, reverse=True):
        raw = raw[:start] + replacement + raw[end:]
    return raw.decode("utf-8", errors="surrogateescape")
