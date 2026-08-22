"""signature_parser.py – Extract function signatures from C source via tree-sitter.

Walks the AST of a C file and yields ``(function_name, signature_string)``
tuples for each function definition found.  The signature includes the return
type, name, and parameter list, without a trailing semicolon.

Signatures are normalised for Ghidra's CParser: MSVC calling conventions
(``__cdecl``, ``__stdcall``, etc.), ``__declspec``, ``const``/``volatile``
qualifiers, and function-pointer parameters are stripped or simplified.
"""

import re
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from rebrew.c_parser import get_ts_parser
from rebrew.utils import detect_source_encoding

_PTR_NOSPACE_RE = re.compile(r"([a-zA-Z0-9_])\*")
_CALLING_CONV_RE = re.compile(r"\b__(?:cdecl|stdcall|fastcall|thiscall)\b\s*")
_DECLSPEC_RE = re.compile(r"__declspec\s*\(\s*\w+\s*\)\s*")
_MULTI_SPACE_RE = re.compile(r"  +")
_RBW_RE = re.compile(r"\bRBW_\w+\b\s*")
_CONST_RE = re.compile(r"\bconst\b\s*")
_VOLATILE_RE = re.compile(r"\bvolatile\b\s*")
_FUNCPTR_RE = re.compile(r"\w[\w\s\*]*\(\*\s*(\w+)\)\s*\([^)]*\)")


def _normalize_signature(sig: str) -> str:
    """Strip syntax that Ghidra's CParser does not accept (MSVC extensions, const/volatile, function pointers)."""
    sig = _DECLSPEC_RE.sub("", sig)
    sig = _CALLING_CONV_RE.sub("", sig)
    sig = _RBW_RE.sub("", sig)
    sig = _CONST_RE.sub("", sig)
    sig = _VOLATILE_RE.sub("", sig)
    # Inline function-pointer params -> void * (CParser doesn't handle them)
    sig = _FUNCPTR_RE.sub(r"void * \1", sig)
    sig = _PTR_NOSPACE_RE.sub(r"\1 *", sig)
    sig = sig.rstrip("; ")
    sig = sig.replace("\n", " ").replace("\r", "")
    sig = _MULTI_SPACE_RE.sub(" ", sig)
    return sig.strip()


def extract_function_signatures(filepath: Path) -> Iterator[tuple[str, str]]:
    """Parse a C file using tree-sitter and yield (function_name, signature_string).

    Signatures are normalized (MSVC extensions stripped) for Ghidra CParser
    compatibility.  Returns empty if tree-sitter is unavailable or file unreadable.
    """
    result = get_ts_parser()
    if result is None:
        return
    parser, _ = result

    try:
        code_bytes = filepath.read_bytes()
    except OSError:
        return

    encoding = detect_source_encoding(code_bytes)
    tree = parser.parse(code_bytes)

    def get_function_name(node: Any) -> str | None:
        if node.type == "function_declarator":
            for child in node.children:
                if child.type == "identifier":
                    return code_bytes[child.start_byte : child.end_byte].decode(encoding)
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
                sig_str = sig_bytes.decode(encoding)

                name = get_function_name(decl_node)
                if name:
                    yield name, _normalize_signature(sig_str)
        else:
            for child in node.children:
                yield from walk(child)

    yield from walk(tree.root_node)
