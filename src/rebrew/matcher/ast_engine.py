"""ast_engine.py - Core infrastructure for AST-based mutations.

Uses tree-sitter to parse C code into an AST and provides utilities
for manipulating it.
"""

import tree_sitter as ts
import tree_sitter_c as tsc

# Initialize tree-sitter parser for C
_C_LANGUAGE = ts.Language(tsc.language())
_parser = ts.Parser(_C_LANGUAGE)


def parse_c_ast(source: bytes | str) -> ts.Tree:
    """Parse C source code into a tree-sitter AST."""
    if isinstance(source, str):
        source = source.encode("utf-8")
    return _parser.parse(source)


def quick_validate_ast(source: bytes | str) -> bool:
    """Validate C source code using tree-sitter instead of regex.

    This replaces the old `quick_validate` which relied on heuristics.
    Returns True if the code has no gross syntax errors.
    """
    tree = parse_c_ast(source)
    return not tree.root_node.has_error


class ASTMutator:
    """Base class/namespace for AST-based mutations.

    Provides helpers to replace nodes in the source.
    """

    @staticmethod
    def replace_node(source: bytes, node: ts.Node, replacement: bytes) -> bytes:
        """Replace the text of a node with new bytes."""
        return source[: node.start_byte] + replacement + source[node.end_byte :]
