"""signature_parser.py – Extract function signatures from C source via tree-sitter.

Walks the AST of a C file and yields ``(function_name, signature_string)``
tuples for each function definition found.  The signature includes the return
type, calling convention, name, and parameter list, terminated with a semicolon
so it can be passed directly to Ghidra's ``set-function-prototype`` command.
"""

from collections.abc import Iterator
from pathlib import Path


def extract_function_signatures(filepath: Path) -> Iterator[tuple[str, str]]:
    """Parse a C file using tree-sitter and yield (function_name, signature_string)."""
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

    def get_function_name(node) -> str | None:
        if node.type == "function_declarator":
            for child in node.children:
                if child.type == "identifier":
                    return code_bytes[child.start_byte : child.end_byte].decode(
                        "utf-8", errors="replace"
                    )
                res = get_function_name(child)
                if res:
                    return res
        else:
            for child in node.children:
                res = get_function_name(child)
                if res:
                    return res
        return None

    def walk(node):
        if node.type == "function_definition":
            compound_stmt = None
            decl_node = None

            for child in node.children:
                if child.type == "compound_statement":
                    compound_stmt = child
                elif child.type in ("function_declarator", "pointer_declarator", "declaration"):
                    decl_node = child

            if not decl_node:
                decl_node = node

            if compound_stmt:
                sig_bytes = code_bytes[node.start_byte : compound_stmt.start_byte].strip()
                # Ghidra's parser expects a trailing semicolon for set-function-prototype
                sig_str = sig_bytes.decode("utf-8", errors="replace") + ";"

                name = get_function_name(decl_node)
                if name:
                    yield name, sig_str
        else:
            for child in node.children:
                yield from walk(child)

    yield from walk(tree.root_node)
