"""signature_parser.py – Extract function signatures from C source via tree-sitter.

Walks the AST of a C file and yields ``(function_name, signature_string)``
tuples for each function definition found.  The signature includes the return
type, calling convention, name, and parameter list, terminated with a semicolon
so it can be passed directly to Ghidra's ``set-function-prototype`` command.
"""

import re
from collections.abc import Iterator
from pathlib import Path
from typing import Any

_PTR_NOSPACE_RE = re.compile(r"([a-zA-Z0-9_])\*")
_CALLING_CONV_RE = re.compile(r"\b__(?:cdecl|stdcall|fastcall)\b\s*")
_DECLSPEC_RE = re.compile(r"__declspec\s*\(\s*\w+\s*\)\s*")
_MULTI_SPACE_RE = re.compile(r"  +")


def _normalize_signature(sig: str) -> str:
    """Strip MSVC-specific syntax that Ghidra's CParser does not accept."""
    sig = _DECLSPEC_RE.sub("", sig)
    sig = _CALLING_CONV_RE.sub("", sig)
    sig = re.sub(r"\bRBW_\w+\b\s*", "", sig)
    sig = re.sub(r"\bconst\b\s*", "", sig)
    sig = re.sub(r"\bvolatile\b\s*", "", sig)
    # Inline function-pointer params -> void * (CParser doesn't handle them)
    sig = re.sub(r"\w[\w\s\*]*\(\*\s*(\w+)\)\s*\([^)]*\)", r"void * \1", sig)
    sig = _PTR_NOSPACE_RE.sub(r"\1 *", sig)
    sig = sig.rstrip("; ")
    sig = sig.replace("\n", " ").replace("\r", "")
    sig = _MULTI_SPACE_RE.sub(" ", sig)
    return sig.strip()


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

    def get_function_name(node: Any) -> str | None:
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

    def walk(node: Any) -> Iterator[tuple[str, str]]:
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
                sig_str = sig_bytes.decode("utf-8", errors="replace")

                name = get_function_name(decl_node)
                if name:
                    yield name, _normalize_signature(sig_str)
        else:
            for child in node.children:
                yield from walk(child)

    yield from walk(tree.root_node)
