"""c_parser.py – Shared tree-sitter C parsing utilities for rebrew.

Provides AST-based extraction of C function definitions, extern function
declarations, and extern variable declarations.  Replaces the fragile regex
parsers that previously lived in annotation.py, crt_match.py, depgraph.py,
and data.py.

Tree-sitter natively distinguishes function definitions from declarations,
and function declarators from variable declarators, eliminating all heuristic
regex patterns.
"""

from __future__ import annotations

import logging
import threading
from dataclasses import dataclass
from typing import Any

logger = logging.getLogger(__name__)

# MSVC calling conventions and declspecs that tree-sitter's standard C grammar
# doesn't recognise as keywords — they get parsed as identifiers.  We filter
# them out when extracting function names.
_CALLING_CONVENTIONS = frozenset(
    {
        "__cdecl",
        "__stdcall",
        "__fastcall",
        "__thiscall",
        "__clrcall",
        "__vectorcall",
        "WINAPI",
        "CALLBACK",
        "APIENTRY",
        "REBREW_NAKED",
        "_CRTIMP",
    }
)

# ---------------------------------------------------------------------------
# Lazy tree-sitter initialisation
# ---------------------------------------------------------------------------

_parser: Any = None
_language: Any = None
_parser_lock = threading.Lock()


def _get_parser() -> tuple[Any, Any]:
    """Return a (parser, language) pair, lazily initialised."""
    global _parser, _language  # noqa: PLW0603
    if _parser is not None:
        return _parser, _language

    with _parser_lock:
        # Double-check after acquiring lock
        if _parser is not None:
            return _parser, _language

        try:
            import tree_sitter_c
            from tree_sitter import Language, Parser
        except ImportError:
            raise ImportError(
                "tree-sitter and tree-sitter-c are required.  "
                "Install with: uv pip install tree-sitter tree-sitter-c"
            )

        _language = Language(tree_sitter_c.language())
        _parser = Parser(_language)
        return _parser, _language


def _parse(source: str | bytes) -> Any:
    """Parse C source and return the tree-sitter Tree."""
    parser, _ = _get_parser()
    if isinstance(source, str):
        source = source.encode("utf-8")
    return parser.parse(source), source


# ---------------------------------------------------------------------------
# Node helpers
# ---------------------------------------------------------------------------


def _node_text(node: Any, source_bytes: bytes) -> str:
    """Return the source text for a tree-sitter node."""
    return source_bytes[node.start_byte : node.end_byte].decode("utf-8", errors="replace")


def _strip_cc(source: str) -> str:
    """Remove MSVC calling conventions from C source so tree-sitter can parse it.

    Tree-sitter's standard C grammar doesn't recognise ``__cdecl`` etc.,
    so they confuse the parser.  We strip them before feeding the source
    to tree-sitter when we need a structural parse.
    """
    import re

    pattern = r"\b(" + "|".join(re.escape(cc) for cc in _CALLING_CONVENTIONS) + r")\b"
    return re.sub(pattern, "", source)


def _find_child(node: Any, *types: str) -> Any | None:
    """Return the first child matching any of *types*, or None."""
    for child in node.children:
        if child.type in types:
            return child
    return None


def _find_function_name(declarator: Any, source_bytes: bytes) -> str | None:
    """Recursively walk a declarator to find the function name identifier."""
    if declarator.type == "function_declarator":
        for child in declarator.children:
            if child.type == "identifier":
                return _node_text(child, source_bytes)
            # Parenthesised declarator: int (*name)(...)
            if child.type == "parenthesized_declarator":
                name = _find_function_name(child, source_bytes)
                if name:
                    return name
    elif declarator.type == "pointer_declarator" or declarator.type == "parenthesized_declarator":
        for child in declarator.children:
            name = _find_function_name(child, source_bytes)
            if name:
                return name
    elif declarator.type == "identifier":
        return _node_text(declarator, source_bytes)
    else:
        for child in declarator.children:
            name = _find_function_name(child, source_bytes)
            if name:
                return name
    return None


def _find_declarator_name(declarator: Any, source_bytes: bytes) -> str | None:
    """Recursively walk a declarator to find the variable/function name identifier."""
    if declarator.type == "identifier":
        return _node_text(declarator, source_bytes)
    if declarator.type == "array_declarator":
        # int foo[10] — name is in the first child
        for child in declarator.children:
            if child.type == "identifier":
                return _node_text(child, source_bytes)
            if child.type in ("pointer_declarator", "array_declarator"):
                name = _find_declarator_name(child, source_bytes)
                if name:
                    return name
    if declarator.type == "pointer_declarator":
        for child in declarator.children:
            name = _find_declarator_name(child, source_bytes)
            if name:
                return name
    if declarator.type == "init_declarator":
        for child in declarator.children:
            if child.type != "=" and child.type not in ("number_literal", "string_literal"):
                name = _find_declarator_name(child, source_bytes)
                if name:
                    return name
    # Function declarator — this is a function declaration, not a variable
    if declarator.type == "function_declarator":
        return None  # Caller should skip this
    for child in declarator.children:
        name = _find_declarator_name(child, source_bytes)
        if name:
            return name
    return None


def _has_function_declarator(node: Any) -> bool:
    """Return True if *node* or any descendant is a function_declarator."""
    if node.type == "function_declarator":
        return True
    return any(_has_function_declarator(child) for child in node.children)


def _count_pointer_depth(declarator: Any) -> int:
    """Count pointer depth (number of * in pointer_declarator chain)."""
    depth = 0
    node = declarator
    while node.type == "pointer_declarator":
        depth += 1
        # The actual declarator is the non-* child
        for child in node.children:
            if child.type != "*":
                node = child
                break
        else:
            break
    return depth


def _extract_array_suffix(declarator: Any, source_bytes: bytes) -> str:
    """Extract array suffix like '[10]' or '[]' from an array_declarator."""
    if declarator.type != "array_declarator":
        return ""
    parts = []
    node = declarator
    while node.type == "array_declarator":
        # Find the bracketed size
        for child in node.children:
            if child.type == "[":
                # Grab from [ to ]
                bracket_start = child.start_byte
                for sibling in node.children:
                    if sibling.type == "]":
                        bracket_end = sibling.end_byte
                        parts.append(
                            source_bytes[bracket_start:bracket_end].decode(
                                "utf-8", errors="replace"
                            )
                        )
                        break
                break
        # Recurse into nested array
        inner = _find_child(node, "array_declarator", "identifier", "pointer_declarator")
        if inner and inner.type == "array_declarator":
            node = inner
        else:
            break
    return "".join(parts)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def extract_function_name_and_proto(source: str) -> tuple[str, str] | None:
    """Extract the first function definition's name and prototype from C source.

    Returns ``(name, prototype_string)`` or ``None`` if no function definition
    is found.  The prototype includes the return type, calling convention, name,
    and parameter list (without the body).

    Replaces ``_C_FUNC_IDENT_RE`` in ``annotation.py``.
    """
    try:
        tree, src_bytes = _parse(source)
    except ImportError:
        return None

    def walk(node: Any) -> tuple[str, str] | None:
        if node.type == "function_definition":
            # Find the compound_statement (body) to extract prototype
            compound = _find_child(node, "compound_statement")
            if compound:
                proto_bytes = src_bytes[node.start_byte : compound.start_byte].strip()
                proto = proto_bytes.decode("utf-8", errors="replace").strip()
            else:
                proto = _node_text(node, src_bytes)

            # Find function name from the declarator
            declarator = _find_child(node, "function_declarator", "pointer_declarator")
            if declarator is None:
                # Try deeper: sometimes the declarator is nested
                for child in node.children:
                    name = _find_function_name(child, src_bytes)
                    if name:
                        return name, proto
                return None

            name = _find_function_name(declarator, src_bytes)
            if name:
                return name, proto
            return None

        for child in node.children:
            result = walk(child)
            if result:
                return result
        return None

    return walk(tree.root_node)


def extract_function_name_from_line(line: str) -> tuple[str, str] | None:
    """Try to extract a function name and prototype from a single code line.

    Appends ``{}`` to the line so tree-sitter can recognize it as a function
    definition.  This replaces the ``_C_FUNC_IDENT_RE`` regex in annotation
    parsers where code is examined line-by-line.

    Returns ``(name, prototype)`` or ``None``.  The *prototype* is the cleaned
    original line (with calling conventions preserved) without trailing ``{``.
    """
    stripped = line.strip().rstrip("{;").strip()
    if not stripped:
        return None
    # Strip MSVC calling conventions so tree-sitter can parse the function
    cleaned = _strip_cc(stripped)
    result = extract_function_name_and_proto(cleaned + " {}")
    if result:
        name, _ = result
        return name, stripped
    return None


def find_c_function_definitions(source: str) -> list[tuple[str, int]]:
    """Find all C function definitions and return ``[(name, line), ...]``.

    *line* is 1-based.  Replaces ``_C_FUNCTION_RE`` in ``crt_match.py``.
    """
    try:
        tree, src_bytes = _parse(_strip_cc(source))
    except ImportError:
        return []

    results: list[tuple[str, int]] = []

    def walk(node: Any) -> None:
        if node.type == "function_definition":
            for child in node.children:
                name = _find_function_name(child, src_bytes)
                if name:
                    line = node.start_point[0] + 1  # 0-indexed → 1-indexed
                    results.append((name, line))
                    break
        else:
            for child in node.children:
                walk(child)

    walk(tree.root_node)
    return results


def find_extern_function_names(source: str) -> list[str]:
    """Find function names from ``extern`` function declarations.

    Returns a list of function names.  Replaces ``_EXTERN_FUNC_RE`` in
    ``depgraph.py``.
    """
    try:
        tree, src_bytes = _parse(_strip_cc(source))
    except ImportError:
        return []

    results: list[str] = []

    def walk(node: Any) -> None:
        if node.type == "declaration":
            # Check for extern storage class
            has_extern = False
            for child in node.children:
                if (
                    child.type == "storage_class_specifier"
                    and _node_text(child, src_bytes) == "extern"
                ):
                    has_extern = True
                    break

            if has_extern:
                # Look for function_declarator in the declarator chain
                for child in node.children:
                    if _has_function_declarator(child):
                        name = _find_function_name(child, src_bytes)
                        if name:
                            results.append(name)
                        break
        else:
            for child in node.children:
                walk(child)

    walk(tree.root_node)
    return results


# ---------------------------------------------------------------------------
# Extern variable parsing (replaces _EXTERN_RE + _is_function_decl in data.py)
# ---------------------------------------------------------------------------


@dataclass
class ExternVar:
    """A parsed extern variable declaration."""

    name: str
    type_str: str  # e.g. "int", "char *", "unsigned short"
    array_suffix: str  # e.g. "[10]", "[]", ""


def find_extern_variables(source: str) -> list[ExternVar]:
    """Find extern variable (non-function) declarations.

    Tree-sitter naturally distinguishes function declarations (which have
    ``function_declarator`` nodes) from variable declarations (which have
    plain ``identifier`` or ``pointer_declarator`` + ``identifier``).
    This eliminates the ``_is_function_decl()`` heuristic entirely.

    Replaces ``_EXTERN_RE`` + ``_is_function_decl()`` in ``data.py``.
    """
    try:
        tree, src_bytes = _parse(_strip_cc(source))
    except ImportError:
        return []

    results: list[ExternVar] = []

    def walk(node: Any) -> None:
        if node.type == "declaration":
            has_extern = False
            has_dllimport = False
            for child in node.children:
                if (
                    child.type == "storage_class_specifier"
                    and _node_text(child, src_bytes) == "extern"
                ):
                    has_extern = True
                # Check for __declspec(dllimport) — skip these
                if child.type == "declaration_specifiers" or child.type == "ms_declspec_modifier":
                    text = _node_text(child, src_bytes)
                    if "dllimport" in text:
                        has_dllimport = True
                # Also check top-level children for __declspec
                text = _node_text(child, src_bytes)
                if "dllimport" in text:
                    has_dllimport = True

            if not has_extern or has_dllimport:
                for child in node.children:
                    walk(child)
                return

            # Skip if any declarator in this declaration is a function declarator
            for child in node.children:
                if _has_function_declarator(child):
                    return  # This is a function declaration, not a variable

            # Extract type specifiers
            type_parts: list[str] = []
            for child in node.children:
                if child.type in (
                    "type_qualifier",
                    "primitive_type",
                    "sized_type_specifier",
                    "type_identifier",
                    "struct_specifier",
                    "enum_specifier",
                    "union_specifier",
                ):
                    type_parts.append(_node_text(child, src_bytes))

            type_str = " ".join(type_parts) if type_parts else ""

            # Extract declarator(s) — each is a variable
            for child in node.children:
                if child.type in (
                    "init_declarator",
                    "pointer_declarator",
                    "array_declarator",
                    "identifier",
                ):
                    # Count pointer depth
                    ptr_depth = (
                        _count_pointer_depth(child) if child.type == "pointer_declarator" else 0
                    )

                    # For init_declarator, look inside
                    decl = child
                    if child.type == "init_declarator":
                        inner = _find_child(
                            child, "pointer_declarator", "array_declarator", "identifier"
                        )
                        if inner:
                            decl = inner
                            ptr_depth = (
                                _count_pointer_depth(decl)
                                if decl.type == "pointer_declarator"
                                else 0
                            )

                    # Get array suffix
                    array_suffix = ""
                    # Walk to find array_declarator
                    arr_node = decl
                    while arr_node and arr_node.type == "pointer_declarator":
                        for ac in arr_node.children:
                            if ac.type != "*":
                                arr_node = ac
                                break
                        else:
                            break
                    if arr_node and arr_node.type == "array_declarator":
                        array_suffix = _extract_array_suffix(arr_node, src_bytes)

                    name = _find_declarator_name(decl, src_bytes)
                    if name:
                        full_type = type_str
                        if ptr_depth:
                            full_type += " " + "*" * ptr_depth
                        if array_suffix:
                            full_type += array_suffix
                        results.append(
                            ExternVar(name=name, type_str=full_type, array_suffix=array_suffix)
                        )
        else:
            for child in node.children:
                walk(child)

    walk(tree.root_node)
    return results
