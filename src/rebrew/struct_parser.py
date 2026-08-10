"""struct_parser.py – Extract struct/typedef definitions from C source via tree-sitter.

Walks the AST of a C file and yields raw text of any ``typedef struct { ... }``
or standalone ``struct { ... };`` definitions.
"""

from collections.abc import Iterator
from pathlib import Path
from typing import Any

from rebrew.c_parser import _get_ts_parser
from rebrew.utils import detect_source_encoding


def _iter_definitions(filepath: Path, *, all_type_defs: bool) -> Iterator[str]:
    """Yield struct/typedef definitions from *filepath*.

    With ``all_type_defs``, yields every ``typedef`` (e.g. ``typedef unsigned
    int uint32_t;``); otherwise only typedefs whose body contains a struct.
    """
    result = _get_ts_parser()
    if result is None:
        return
    parser, _ = result

    try:
        code_bytes = filepath.read_bytes()
    except OSError:
        return

    encoding = detect_source_encoding(code_bytes)
    tree = parser.parse(code_bytes)

    def walk(node: Any) -> Iterator[str]:
        if node.type == "type_definition":
            text = code_bytes[node.start_byte : node.end_byte]
            if all_type_defs or (b"struct" in text and b"{" in text):
                yield text.decode(encoding)
        elif node.type == "struct_specifier":
            if node.parent and node.parent.type != "type_definition":
                struct_text = code_bytes[node.start_byte : node.end_byte]
                if b"{" in struct_text:
                    end_byte = node.end_byte
                    next_sibling = node.next_sibling
                    if next_sibling and next_sibling.type == ";":
                        end_byte = next_sibling.end_byte
                    full_text = code_bytes[node.start_byte : end_byte]
                    yield full_text.decode(encoding)
        else:
            for child in node.children:
                yield from walk(child)

    yield from walk(tree.root_node)


def extract_structs_from_file(filepath: Path) -> Iterator[str]:
    """Parse a C file and yield struct/typedef-struct definitions with bodies.

    Does not include standalone typedefs (use ``extract_type_definitions`` for those).
    Returns empty if tree-sitter is unavailable or file unreadable.
    """
    yield from _iter_definitions(filepath, all_type_defs=False)


def extract_type_definitions(filepath: Path) -> Iterator[str]:
    """Parse a C file and yield all type definitions (typedefs AND structs).

    Unlike :func:`extract_structs_from_file`, also captures standalone typedefs
    like ``typedef unsigned int uint32_t;`` that don't contain struct bodies.
    """
    yield from _iter_definitions(filepath, all_type_defs=True)


def extract_enums_from_file(filepath: Path) -> Iterator[str]:
    """Parse a C file and yield enum definitions with bodies.

    Yields both forms, ready for Ghidra's ``parse-c-structure`` CParser::

        enum Color { RED, GREEN, BLUE };
        typedef enum { UP, DOWN } Direction;

    Returns empty if tree-sitter is unavailable or the file is unreadable.
    """
    result = _get_ts_parser()
    if result is None:
        return
    parser, _ = result

    try:
        code_bytes = filepath.read_bytes()
    except OSError:
        return

    encoding = detect_source_encoding(code_bytes)
    tree = parser.parse(code_bytes)

    def walk(node: Any) -> Iterator[str]:
        if node.type == "type_definition":
            text = code_bytes[node.start_byte : node.end_byte]
            if b"enum" in text and b"{" in text:
                yield text.decode(encoding)  # typedef enum { ... } Name;
        elif node.type == "enum_specifier":
            if node.parent and node.parent.type != "type_definition":
                text = code_bytes[node.start_byte : node.end_byte]
                if b"{" in text:
                    end_byte = node.end_byte
                    next_sibling = node.next_sibling
                    if next_sibling and next_sibling.type == ";":
                        end_byte = next_sibling.end_byte
                    yield code_bytes[node.start_byte : end_byte].decode(encoding)
        else:
            for child in node.children:
                yield from walk(child)

    yield from walk(tree.root_node)
