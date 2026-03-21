"""struct_parser.py – Extract struct/typedef definitions from C source via tree-sitter.

Walks the AST of a C file and yields raw text of any ``typedef struct { ... }``
or standalone ``struct { ... };`` definitions.
"""

from collections.abc import Iterator
from pathlib import Path
from typing import Any

_ts_parser: Any = None
_ts_language: Any = None


def _get_ts_parser() -> tuple[Any, Any] | None:
    """Return a cached (parser, language) pair, or None if tree-sitter is unavailable."""
    global _ts_parser, _ts_language  # noqa: PLW0603
    if _ts_parser is not None:
        return _ts_parser, _ts_language
    try:
        import tree_sitter_c
        from tree_sitter import Language, Parser
    except ImportError:
        return None
    _ts_language = Language(tree_sitter_c.language())
    _ts_parser = Parser(_ts_language)
    return _ts_parser, _ts_language


def extract_structs_from_file(filepath: Path) -> Iterator[str]:
    """Parse a C file and yield struct/typedef-struct definitions with bodies.

    Does not include standalone typedefs (use ``extract_type_definitions`` for those).
    Returns empty if tree-sitter is unavailable or file unreadable.
    """
    result = _get_ts_parser()
    if result is None:
        return
    parser, _ = result

    try:
        code_bytes = filepath.read_bytes()
    except OSError:
        return

    tree = parser.parse(code_bytes)

    def walk(node: Any) -> Iterator[str]:
        if node.type == "type_definition":
            text = code_bytes[node.start_byte : node.end_byte]
            if b"struct" in text and b"{" in text:
                yield text.decode("utf-8", errors="replace")
        elif node.type == "struct_specifier":
            if node.parent and node.parent.type != "type_definition":
                text = code_bytes[node.start_byte : node.end_byte]
                if b"{" in text:
                    end_byte = node.end_byte
                    next_sibling = node.next_sibling
                    if next_sibling and next_sibling.type == ";":
                        end_byte = next_sibling.end_byte
                    full_text = code_bytes[node.start_byte : end_byte]
                    yield full_text.decode("utf-8", errors="replace")
        else:
            for child in node.children:
                yield from walk(child)

    yield from walk(tree.root_node)


def extract_type_definitions(filepath: Path) -> Iterator[str]:
    """Parse a C file and yield all type definitions (typedefs AND structs).

    Unlike :func:`extract_structs_from_file`, also captures standalone typedefs
    like ``typedef unsigned int uint32_t;`` that don't contain struct bodies.
    """
    result = _get_ts_parser()
    if result is None:
        return
    parser, _ = result

    try:
        code_bytes = filepath.read_bytes()
    except OSError:
        return

    tree = parser.parse(code_bytes)

    def walk(node: Any) -> Iterator[str]:
        if node.type == "type_definition":
            text = code_bytes[node.start_byte : node.end_byte].decode("utf-8", errors="replace")
            yield text
        elif node.type == "struct_specifier":
            if node.parent and node.parent.type != "type_definition":
                struct_text = code_bytes[node.start_byte : node.end_byte]
                if b"{" in struct_text:
                    end_byte = node.end_byte
                    next_sibling = node.next_sibling
                    if next_sibling and next_sibling.type == ";":
                        end_byte = next_sibling.end_byte
                    full_text = code_bytes[node.start_byte : end_byte]
                    yield full_text.decode("utf-8", errors="replace")
        else:
            for child in node.children:
                yield from walk(child)

    yield from walk(tree.root_node)
