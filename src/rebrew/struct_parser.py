"""struct_parser.py – Extract struct/typedef definitions from C source via tree-sitter.

Walks the AST of a C file and yields raw text of any ``typedef struct { ... }``
or standalone ``struct { ... };`` definitions.  Used by ``sync.py`` to push
struct definitions to Ghidra's Data Type Manager.
"""

from collections.abc import Iterator
from pathlib import Path


def extract_structs_from_file(filepath: Path) -> Iterator[str]:
    """Parse a C file using tree-sitter and yield raw strings of struct/typedef definitions."""
    try:
        import tree_sitter_c
        from tree_sitter import Language, Parser
    except ImportError:
        return

    C_LANGUAGE = Language(tree_sitter_c.language())
    parser = Parser(C_LANGUAGE)

    try:
        code_bytes = filepath.read_bytes()
    except OSError:
        return

    tree = parser.parse(code_bytes)

    def walk(node):
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
