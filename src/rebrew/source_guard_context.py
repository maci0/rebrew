"""Exact, read-only preprocessor context for reviewed source organization."""

lazy from pathlib import Path
lazy from typing import Any

lazy from rebrew.c_parser import (
    comment_nodes,
    declares_function,
    find_function_name_in_node,
    parse_c_source,
    prototype_name_span,
    prototype_type_key,
)
lazy from rebrew.source_layout import mask_for_parse


def _prototype_key(text: str) -> str | None:
    tree, raw = parse_c_source(text)
    masked = bytearray(raw)
    for comment in comment_nodes(tree):
        for position in range(comment.start_byte, comment.end_byte):
            if masked[position] not in (10, 13):
                masked[position] = 32
    return prototype_type_key(masked.decode("utf-8", errors="surrogateescape"))


def guard_contexts(files: list[Path]) -> dict[str, Any]:
    """Describe exact original directives and definitions without changing source.

    Byte offsets use the UTF-8 representation used by the C parser. A branch
    chain retains every preceding if/elif directive, so its meaning is not
    reduced to the text of an else or elif alone.
    """
    definitions: list[dict[str, Any]] = []
    declarations: dict[str, list[dict[str, Any]]] = {}
    inputs = []
    for path in sorted(files):
        text = path.read_bytes().decode("utf-8", errors="surrogateescape")
        raw = text.encode("utf-8", errors="surrogateescape")
        tree, _ = parse_c_source(mask_for_parse(raw))
        if tree.root_node.has_error:
            raise ValueError(f"{path}: C/preprocessor parse is incomplete; cannot plan guards")
        inputs.append({"file": str(path), "source": text})

        def walk(
            node: Any,
            guards: tuple[dict[str, Any], ...],
            raw: bytes = raw,
            path: Path = path,
        ) -> None:
            if node.type in {"preproc_if", "preproc_ifdef", "preproc_elif", "preproc_else"}:
                end = raw.find(b"\n", node.start_byte)
                if end < 0:
                    raise ValueError(f"{path}: unterminated preprocessor directive")
                # A continued directive is a single semantic unit.
                while raw[node.start_byte : end].rstrip(b"\r").endswith(b"\\"):
                    end = raw.find(b"\n", end + 1)
                    if end < 0:
                        raise ValueError(f"{path}: unterminated continued directive")
                line_start = raw.rfind(b"\n", 0, node.start_byte) + 1
                if raw[line_start : node.start_byte].strip():
                    raise ValueError(f"{path}: directive does not start on a clean line")
                guards += (
                    {
                        "directive": raw[line_start : end + 1].decode(
                            "utf-8", errors="surrogateescape"
                        ),
                        "start": line_start,
                        "end": end + 1,
                        "group_end": node.end_byte,
                    },
                )
            if node.type == "function_definition":
                declarator = node.child_by_field_name("declarator")
                name = find_function_name_in_node(declarator, raw) if declarator else None
                if not name:
                    raise ValueError(f"{path}: function definition has no parseable name")
                body = node.child_by_field_name("body")
                if body is None:
                    raise ValueError(f"{path}: function definition has no parseable body")
                prototype = (
                    raw[node.start_byte : body.start_byte]
                    .decode("utf-8", "surrogateescape")
                    .rstrip()
                    + ";"
                )
                key = _prototype_key(prototype)
                if key is None:
                    raise ValueError(f"{path}: cannot compare the prototype of {name}")
                declarations.setdefault(name, []).append(
                    {
                        "file": str(path),
                        "declaration": prototype,
                        "type_key": key,
                        "start": node.start_byte,
                        "end": body.start_byte,
                        "guards": list(guards),
                    }
                )
                definitions.append(
                    {
                        "file": str(path),
                        "name": name,
                        "start": node.start_byte,
                        "end": node.end_byte,
                        "guards": list(guards),
                    }
                )
                return
            if node.type == "declaration":
                declarators = node.children_by_field_name("declarator")
                if len(declarators) > 1 and any(declares_function(d) for d in declarators):
                    raise ValueError(
                        f"{path}: multiple function declarators require separate review"
                    )
                declaration = raw[node.start_byte : node.end_byte].decode(
                    "utf-8", "surrogateescape"
                )
                span = prototype_name_span(declaration)
                key = _prototype_key(declaration) if span else None
                if any(declares_function(d) for d in declarators) and (not span or not key):
                    raise ValueError(f"{path}: cannot compare function declaration")
                if span and key:
                    declarations.setdefault(span[0], []).append(
                        {
                            "file": str(path),
                            "declaration": declaration,
                            "type_key": key,
                            "start": node.start_byte,
                            "end": node.end_byte,
                            "guards": list(guards),
                        }
                    )
                return
            for child in node.named_children:
                walk(child, guards)

        walk(tree.root_node, ())
    conflicts = [
        {"name": name, "declarations": rows, "overlap": "unassessed"}
        for name, rows in declarations.items()
        if len({row["type_key"] for row in rows}) > 1
    ]
    return {
        "inputs": inputs,
        "definitions": definitions,
        "declaration_conflicts": conflicts,
        "source_changed": False,
        "rewrite_supported": False,
    }
