"""struct_parser.py – Extract struct/typedef definitions from C source via tree-sitter.

Walks the AST of a C file and yields raw text of any ``typedef struct { ... }``
or standalone ``struct { ... };`` definitions.
"""

import logging
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from rebrew.c_parser import get_ts_parser
from rebrew.utils import detect_source_encoding

logger = logging.getLogger(__name__)


def _iter_definitions(
    filepath: Path,
    *,
    keyword: bytes = b"struct",
    all_type_defs: bool = False,
) -> Iterator[str]:
    """Yield definitions of one specifier kind (``struct``/``enum``) from *filepath*.

    Yields ``type_definition`` nodes whose body contains *keyword* (or every
    typedef when ``all_type_defs``), plus bare specifier nodes with a body,
    each extended through a following ``;``.
    """
    result = get_ts_parser()
    if result is None:
        return
    parser, _ = result

    try:
        code_bytes = filepath.read_bytes()
    except OSError as exc:
        logger.warning("cannot read %s for type definitions: %s", filepath, exc)
        return

    encoding = detect_source_encoding(code_bytes)
    tree = parser.parse(code_bytes)
    specifier_type = f"{keyword.decode('ascii')}_specifier"

    def balanced(text: bytes) -> bool:
        """True when every ``{`` in *text* is closed.

        A span the tree closed early (error recovery) is exactly what Ghidra's
        ``parse-c-structure`` rejects, so it is not a definition to hand over:
        half a struct is a parse failure, not a partial answer.
        """
        return text.count(b"{") == text.count(b"}")

    def usable(text: bytes) -> bool:
        """True when Ghidra's ``parse-c-structure`` can read the span verbatim.

        A NUL ends the payload the plugin hands its C parser, so a span
        carrying one truncates there and the rest of the definition never
        arrives.
        """
        return b"\x00" not in text

    def walk(node: Any) -> Iterator[str]:
        if node.type == "type_definition":
            text = code_bytes[node.start_byte : node.end_byte]
            if not usable(text):
                return
            if all_type_defs or (keyword in text and b"{" in text):
                if b"{" in text and not balanced(text):
                    return
                # Match read_source_text: undefined CP1252 bytes → U+FFFD,
                # not UnicodeDecodeError that skips the rest of the file.
                yield text.decode(encoding, errors="replace")
        elif node.type == specifier_type:
            if node.parent and node.parent.type != "type_definition":
                text = code_bytes[node.start_byte : node.end_byte]
                if b"{" in text:
                    end_byte = node.end_byte
                    next_sibling = node.next_sibling
                    if next_sibling and next_sibling.type == ";":
                        end_byte = next_sibling.end_byte
                    span = code_bytes[node.start_byte : end_byte]
                    if not balanced(span) or not usable(span):
                        return
                    yield span.decode(encoding, errors="replace")
        else:
            for child in node.children:
                yield from walk(child)

    yield from walk(tree.root_node)


def extract_structs_from_file(filepath: Path) -> Iterator[str]:
    """Parse a C file and yield struct/typedef-struct definitions with bodies.

    Does not include standalone typedefs (use ``extract_type_definitions`` for those).
    Returns empty if tree-sitter is unavailable or the file is unreadable
    (logged as a warning).
    """
    yield from _iter_definitions(filepath, keyword=b"struct")


def extract_type_definitions(filepath: Path) -> Iterator[str]:
    """Parse a C file and yield all type definitions (typedefs AND structs).

    Unlike :func:`extract_structs_from_file`, also captures standalone typedefs
    like ``typedef unsigned int uint32_t;`` that don't contain struct bodies.
    """
    yield from _iter_definitions(filepath, keyword=b"struct", all_type_defs=True)


def extract_enums_from_file(filepath: Path) -> Iterator[str]:
    """Parse a C file and yield enum definitions with bodies.

    Yields both forms, ready for Ghidra's ``parse-c-structure`` CParser::

        enum Color { RED, GREEN, BLUE };
        typedef enum { UP, DOWN } Direction;

    Returns empty if tree-sitter is unavailable or the file is unreadable
    (logged as a warning).
    """
    yield from _iter_definitions(filepath, keyword=b"enum")


def replace_type_definition(source: str, name: str, definition: str) -> str:
    """Replace a single named typedef or struct/enum definition through the C AST.

    Both the replacement and the selected definition must be unambiguous.
    Multiple declarations or malformed replacement text raise ValueError.
    """
    from rebrew.c_parser import node_text, parse_c_source

    def named(node: Any, raw: bytes) -> bool:
        declarator = node.child_by_field_name("declarator")
        if node.type == "type_definition" and declarator is not None:
            return node_text(declarator, raw) == name
        if node.type in {"struct_specifier", "enum_specifier"}:
            identifier = node.child_by_field_name("name")
            return identifier is not None and node_text(identifier, raw) == name
        return False

    new_tree, new_raw = parse_c_source(definition)
    declarations = [n for n in new_tree.root_node.named_children if n.type != "comment"]
    if new_tree.root_node.has_error or len(declarations) != 1:
        raise ValueError("replacement must be one complete type declaration")
    declaration = declarations[0]
    candidate = declaration
    if candidate.type == "declaration":
        candidate = candidate.child_by_field_name("type")
    if candidate is None or not named(candidate, new_raw):
        raise ValueError(f"replacement does not define {name!r}")
    tree, raw = parse_c_source(source)
    matches: list[tuple[int, int]] = []
    pending = [tree.root_node]
    while pending:
        node = pending.pop()
        if named(node, raw):
            end = node.end_byte
            if (
                node.type != "type_definition"
                and node.next_sibling
                and node.next_sibling.type == ";"
            ):
                end = node.next_sibling.end_byte
            matches.append((int(node.start_byte), int(end)))
        else:
            pending.extend(reversed(node.children))
    if len(matches) != 1:
        raise ValueError(f"expected one definition of {name!r}, found {len(matches)}")
    start, end = matches[0]
    return (raw[:start] + definition.encode("utf-8", errors="surrogateescape") + raw[end:]).decode(
        "utf-8", errors="surrogateescape"
    )
