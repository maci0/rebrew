"""c_parser.py – Shared tree-sitter C parsing utilities for rebrew.

Provides AST-based extraction of C function definitions, extern function
declarations, and extern variable declarations.

Tree-sitter natively distinguishes function definitions from declarations,
and function declarators from variable declarators, eliminating all heuristic
regex patterns.
"""

from __future__ import annotations

import hashlib
import logging
import re
import threading
from bisect import bisect_left
from collections import OrderedDict
from collections.abc import Callable
from dataclasses import dataclass, field
from itertools import pairwise
from typing import Any

from rebrew.utils import parse_c_integer_literal

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

# Pre-compiled regex for stripping calling conventions (used by strip_cc).
_CC_PATTERN = re.compile(
    r"\b("
    + "|".join(re.escape(cc) for cc in sorted(_CALLING_CONVENTIONS, key=len, reverse=True))
    + r")\b"
)
# Strip whole __declspec(...) constructs (e.g. __declspec(naked),
# __declspec(dllimport), __declspec(align(16))) — tree-sitter's standard C
# grammar doesn't know them.  Allow any content up to the matching ')',
# including a nested (...) such as align(16).
_DECLSPEC_PATTERN = re.compile(r"__declspec\s*\((?:[^()]*|\([^)]*\))*\)")

# ---------------------------------------------------------------------------
# Lazy tree-sitter initialisation
# ---------------------------------------------------------------------------

_language: Any = None
_parser_lock = threading.Lock()
# Per-thread parsers: tree-sitter TSParser is per-thread state and the GIL is
# released inside ts_parser_parse, so a shared parser is a C-level data race
# under concurrent GA workers.
_tls = threading.local()


def _get_parser() -> tuple[Any, Any]:
    """Return a (parser, language) pair, lazily initialised.

    The language is initialised once under a lock; each thread then gets its
    own Parser instance (tree-sitter's TSParser is per-thread state).
    """
    global _language
    if _language is None:
        with _parser_lock:
            if _language is None:
                try:
                    import tree_sitter_c
                    from tree_sitter import Language
                except ImportError as exc:
                    raise ImportError(
                        "tree-sitter and tree-sitter-c are required.  "
                        "Install with: uv pip install tree-sitter tree-sitter-c"
                    ) from exc
                _language = Language(tree_sitter_c.language())

    tls_parser = getattr(_tls, "parser", None)
    if tls_parser is None:
        from tree_sitter import Parser

        tls_parser = Parser(_language)
        _tls.parser = tls_parser
    return tls_parser, _language


def get_ts_parser() -> tuple[Any, Any] | None:
    """Return a cached (parser, language) pair, or None if tree-sitter is unavailable."""
    try:
        return _get_parser()
    except ImportError:
        return None


# One tree per distinct body, per thread.  ``scan_globals`` parses each
# source twice (externs, then roles).  The map is thread-local because a
# shared tree is not safe for concurrent walks.  ``parser.parse`` without an
# old tree does not invalidate a tree already stored here.  Sources above
# the size cap are parsed and forgotten.
# ``scan_globals`` parses each source twice. 512 dropped the first half of a
# 2000-file tree, so the second pass re-parsed it (20 ms vs 1 ms, +8 MB RSS
# at 2000). 8192 matches the source-text memo. Raise it when a larger scan
# shows up in a profile.
_PARSE_MEMO_MAX = 8192
_PARSE_MEMO_MAX_BYTES = 256 * 1024


def parse_c_source(source: str | bytes) -> tuple[Any, bytes]:
    """Parse C source and return (tree, source_bytes) as a tuple."""
    parser, _ = _get_parser()
    if isinstance(source, str):
        # surrogateescape keeps compile-path lossless round-trips intact;
        # clean Unicode (read_source_text) encodes as ordinary UTF-8.
        source = source.encode("utf-8", errors="surrogateescape")
    # bytes pass through unchanged.  tree-sitter is byte-oriented; the old
    # UTF-8 errors="replace" re-encode turned each invalid byte into the
    # three-byte U+FFFD sequence and shifted every later node offset — a
    # cp1252 0xE9 before a string literal made protected_spans miss it.
    memo: OrderedDict[bytes, tuple[Any, bytes]] | None = None
    key: bytes | None = None
    if len(source) <= _PARSE_MEMO_MAX_BYTES:
        memo = getattr(_tls, "parse_memo", None)
        if memo is None:
            memo = OrderedDict()
            _tls.parse_memo = memo
        key = hashlib.sha256(source).digest()
        hit = memo.get(key)
        if hit is not None:
            memo.move_to_end(key)
            return hit
    parsed = (parser.parse(source), source)
    if key is not None and memo is not None:
        memo[key] = parsed
        memo.move_to_end(key)
        while len(memo) > _PARSE_MEMO_MAX:
            memo.popitem(last=False)
    return parsed


# ---------------------------------------------------------------------------
# Node helpers
# ---------------------------------------------------------------------------


def node_text(node: Any, source_bytes: bytes) -> str:
    """Return the source text for a tree-sitter node."""
    return source_bytes[node.start_byte : node.end_byte].decode("utf-8", errors="surrogateescape")


def array_type_shape(
    type_str: str, *, int_bits: int = 32
) -> tuple[str, tuple[int | str | None, ...]]:
    """Normalize a type's array bounds without changing its source spelling.

    Unknown expressions stay strings; only an omitted bound becomes None.
    Folding stays within nonnegative signed-int values to avoid assuming C
    overflow, unsigned conversions or target-specific long widths.
    """
    normalized = " ".join(type_str.split()).replace(" *", "*")
    base, bracket, suffix = normalized.partition("[")
    if not bracket:
        return normalized, ()
    tree, source = parse_c_source(f"int __rebrew_array[{suffix};")
    if tree.root_node.has_error or len(tree.root_node.named_children) != 1:
        return normalized, ()
    declarator = tree.root_node.named_children[0].child_by_field_name("declarator")
    limit = (1 << (int_bits - 1)) - 1

    def fold(node: Any, depth: int = 0) -> int | None:
        if node is None or depth > 32:
            return None
        value = None
        if node.type == "number_literal":
            try:
                value = parse_c_integer_literal(node_text(node, source))
            except ValueError:
                return None
        elif node.type == "parenthesized_expression":
            return fold(node.named_children[0], depth + 1)
        elif node.type == "binary_expression":
            left = fold(node.child_by_field_name("left"), depth + 1)
            right = fold(node.child_by_field_name("right"), depth + 1)
            if left is None or right is None:
                return None
            operator = node.child_by_field_name("operator")
            if operator is not None:
                match node_text(operator, source):
                    case "+":
                        value = left + right
                    case "-":
                        value = left - right
                    case "*":
                        value = left * right
                    case _:
                        return None
        # ponytail: other operators/macros stay symbolic; fold them when needed.
        return value if value is not None and 0 <= value <= limit else None

    dimensions: list[int | str | None] = []
    while declarator is not None and declarator.type == "array_declarator":
        size = declarator.child_by_field_name("size")
        value = fold(size)
        dimensions.insert(
            0, value if value is not None or size is None else node_text(size, source)
        )
        declarator = declarator.child_by_field_name("declarator")
    if declarator is None or declarator.type != "identifier":
        return normalized, ()
    return base.strip(), tuple(dimensions)


def protected_spans(source: str | bytes) -> list[tuple[int, int]]:
    """Byte spans of text a rename must NOT rewrite: literals and macro names.

    ``rebrew source rename`` documents that macros and string literals are not
    rewritten; a plain regex substitution over the raw text rewrote
    ``puts("foo")`` into ``puts("bar")``, changing the data an already
    byte-matched function emits.

    Returns sorted, non-overlapping ``(start, end)`` byte offsets for every
    string/character literal and for the NAME of a ``#define`` (the macro's own
    definition keeps its name; its uses elsewhere are still renamed).

    :raises ImportError: tree-sitter is unavailable.
    """
    tree, _data = parse_c_source(source)
    spans: list[tuple[int, int]] = []

    def _walk(node: Any) -> None:
        if node.type in ("string_literal", "char_literal"):
            spans.append((int(node.start_byte), int(node.end_byte)))
        elif node.type in ("preproc_def", "preproc_function_def"):
            name = node.child_by_field_name("name")
            if name is not None:
                spans.append((int(name.start_byte), int(name.end_byte)))
        for child in node.children:
            _walk(child)

    _walk(tree.root_node)
    return sorted(spans)


def strip_cc(source: str) -> str:
    """Remove MSVC calling conventions from C source before tree-sitter parsing.

    Tree-sitter's standard C grammar doesn't recognise ``__cdecl``,
    ``__stdcall``, etc., causing parse errors.
    """
    return _DECLSPEC_PATTERN.sub("", _CC_PATTERN.sub("", source))


def _find_child(node: Any, *types: str) -> Any | None:
    """Return the first child matching any of *types*, or None."""
    for child in node.children:
        if child.type in types:
            return child
    return None


def find_function_name_in_node(declarator: Any, source_bytes: bytes) -> str | None:
    """Recursively walk a declarator to find the function name identifier."""
    if declarator.type == "function_declarator":
        for child in declarator.children:
            if child.type == "identifier":
                return node_text(child, source_bytes)
            # Parenthesised declarator: int (*name)(...)
            if child.type == "parenthesized_declarator":
                name = find_function_name_in_node(child, source_bytes)
                if name:
                    return name
    elif declarator.type in ("pointer_declarator", "parenthesized_declarator"):
        # The name lives in the nested function_declarator; look for it FIRST
        # so Borland convention keywords that tree-sitter marks as ERROR
        # (e.g. ``void far *pascal f(...)`` — ``far``/``pascal`` are not C89
        # keywords) are not mistaken for the name.
        for child in declarator.children:
            if child.type == "function_declarator":
                name = find_function_name_in_node(child, source_bytes)
                if name:
                    return name
        for child in declarator.children:
            name = find_function_name_in_node(child, source_bytes)
            if name:
                return name
    elif declarator.type == "identifier":
        return node_text(declarator, source_bytes)
    else:
        for child in declarator.children:
            name = find_function_name_in_node(child, source_bytes)
            if name:
                return name
    return None


def _find_declarator_name(declarator: Any, source_bytes: bytes) -> str | None:
    """Recursively walk a declarator to find the variable/function name identifier."""
    if declarator.type == "identifier":
        return node_text(declarator, source_bytes)
    if declarator.type == "array_declarator":
        # int foo[10] — name is an identifier child of the array_declarator
        for child in declarator.children:
            if child.type == "identifier":
                return node_text(child, source_bytes)
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
    while node is not None and node.type == "pointer_declarator":
        depth += 1
        node = _find_child(node, "pointer_declarator")
    return depth


def _extract_array_suffix(declarator: Any, source_bytes: bytes) -> str:
    """Extract array suffix like '[10]' or '[]' from an array_declarator."""
    if declarator.type != "array_declarator":
        return ""
    parts = []
    node = declarator
    while node.type == "array_declarator":
        for child in node.children:
            if child.type == "[":
                bracket_start = child.start_byte
                bracket_open_end = child.end_byte
                for sibling in node.children:
                    if sibling.type == "]":
                        # A truncated declarator (``extern int a[;``) makes
                        # tree-sitter emit a zero-width ``]`` where the close
                        # bracket would be.  Slicing on it yields a dangling
                        # suffix (``[``) that leaves the bracket unbalanced in
                        # the type string, so only a ``]`` lying strictly after
                        # the ``[`` closes a well-formed span.
                        if (
                            getattr(sibling, "is_missing", False)
                            or sibling.end_byte <= bracket_open_end
                        ):
                            break
                        span = source_bytes[bracket_start : sibling.end_byte].decode(
                            "utf-8", errors="surrogateescape"
                        )
                        if not span.endswith("]") or span.count("[") != span.count("]"):
                            break
                        parts.append(span)
                        break
                break
        inner = _find_child(node, "array_declarator", "identifier", "pointer_declarator")
        if inner and inner.type == "array_declarator":
            node = inner
        else:
            break
    # tree-sitter nests array_declarators outermost-bracket-first, so
    # ``foo[10][5]`` collects "[5]" then "[10]" — the source spells
    # "[10][5]" and the suffix must match.
    return "".join(reversed(parts))


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def iter_function_name_and_proto(source: str) -> list[tuple[str, str]]:
    """Return ``(name, prototype)`` for every function definition in *source*.

    The prototype includes the return type, calling convention, name, and
    parameter list (without the body).  Definitions inside ERROR fragments are
    skipped.  This is the shared primitive behind
    :func:`extract_function_name_and_proto`, which takes the first match.
    """
    try:
        tree, src_bytes = parse_c_source(source)
    except ImportError:
        return []

    results: list[tuple[str, str]] = []

    def walk(node: Any) -> None:
        if node.type == "function_definition":
            compound = _find_child(node, "compound_statement")
            if compound:
                proto_bytes = src_bytes[node.start_byte : compound.start_byte].strip()
                proto = proto_bytes.decode("utf-8", errors="surrogateescape").strip()
                # Normalise CRLF prototypes to LF so the returned proto is
                # stable regardless of the source file's line endings.
                proto = proto.replace("\r\n", "\n").replace("\r", "\n")
            else:
                proto = node_text(node, src_bytes)

            declarator = _find_child(node, "function_declarator", "pointer_declarator")
            name: str | None = None
            if declarator is not None:
                name = find_function_name_in_node(declarator, src_bytes)
            else:
                # Try deeper: sometimes the declarator is nested
                for child in node.children:
                    name = find_function_name_in_node(child, src_bytes)
                    if name:
                        break
            if name:
                results.append((name, proto))
            return

        # Skip ERROR nodes (tree-sitter marks unparseable fragments as ERROR);
        # recursing into them produces spurious matches.
        if node.type == "ERROR":
            return
        for child in node.children:
            walk(child)

    walk(tree.root_node)
    return results


def extract_function_name_and_proto(source: str) -> tuple[str, str] | None:
    """Extract the first function definition's name and prototype from C source.

    Returns ``(name, prototype_string)`` or ``None`` if no function definition
    is found.  The prototype includes the return type, calling convention, name,
    and parameter list (without the body).

    """
    results = iter_function_name_and_proto(source)
    return results[0] if results else None


def extract_function_name_from_line(line: str) -> tuple[str, str] | None:
    """Try to extract a function name and prototype from a single code line.

    Appends ``{}`` to the line so tree-sitter can recognize it as a function
    definition.

    Returns ``(name, prototype)`` or ``None``.  The *prototype* is the cleaned
    original line (with calling conventions preserved) without trailing ``{``.
    """
    # Strip BOM if present (files saved with UTF-8 BOM have it on the first line).
    if line.startswith("\ufeff"):
        line = line.lstrip("\ufeff")
    stripped = line.strip().rstrip("{;").strip()
    if not stripped:
        return None
    # Strip MSVC calling conventions so tree-sitter can parse the function
    cleaned = strip_cc(stripped)
    try:
        result = extract_function_name_and_proto(cleaned + " {}")
    except UnicodeEncodeError:
        return None
    if result:
        name, _ = result
        return name, stripped
    return None


def find_c_function_definitions(source: str) -> list[tuple[str, int]]:
    """Find all C function definitions and return ``[(name, line), ...]``.

    *line* is 1-based.
    """
    if not source or not source.strip():
        return []
    try:
        tree, src_bytes = parse_c_source(strip_cc(source))
    except ImportError:
        return []

    results: list[tuple[str, int]] = []

    def walk(node: Any) -> None:
        if node.type == "function_definition":
            # The declarator field only: an unknown macro before the name
            # (``int ZEXPORT deflate(...)``) is an ERROR identifier child.
            declarator = node.child_by_field_name("declarator")
            name = find_function_name_in_node(declarator, src_bytes) if declarator else None
            if name:
                results.append((name, node.start_point[0] + 1))  # 1-based line
        else:
            for child in node.children:
                walk(child)

    walk(tree.root_node)
    return results


def find_extern_function_names(source: str) -> list[str]:
    """Find function names from ``extern`` function declarations."""
    if not source or not source.strip():
        return []
    try:
        tree, src_bytes = parse_c_source(strip_cc(source))
    except ImportError:
        return []

    results: list[str] = []

    def walk(node: Any) -> None:
        if node.type == "declaration":
            has_extern = False
            for child in node.children:
                if (
                    child.type == "storage_class_specifier"
                    and node_text(child, src_bytes) == "extern"
                ):
                    has_extern = True
                    break

            if has_extern:
                for child in node.children:
                    if _has_function_declarator(child):
                        name = find_function_name_in_node(child, src_bytes)
                        if name:
                            results.append(name)
                        break
        else:
            for child in node.children:
                walk(child)

    walk(tree.root_node)
    return results


# ---------------------------------------------------------------------------
# Extern variable parsing
# ---------------------------------------------------------------------------


@dataclass
class ExternVar:
    """A parsed extern variable declaration."""

    name: str
    type_str: str  # e.g. "int", "char *", "unsigned short"
    array_suffix: str  # e.g. "[10]", "[]", ""
    declaration: str = field(default="", compare=False)
    line: int = field(default=0, compare=False)
    end_line: int = field(default=0, compare=False)


def _variable_name(node: Any, source: bytes) -> str | None:
    """Follow a declarator's name, excluding parameters and initializers."""
    while node is not None:
        if node.type == "identifier":
            return node_text(node, source)
        inner = node.child_by_field_name("declarator")
        if inner is None and node.type == "parenthesized_declarator":
            inner = next(iter(node.named_children), None)
        node = inner
    return None


def _declares_function(node: Any) -> bool:
    """Distinguish a function from storage containing a function pointer."""
    closest = ""
    while node is not None:
        if node.type in {"function_declarator", "pointer_declarator", "array_declarator"}:
            closest = node.type
        inner = node.child_by_field_name("declarator")
        if inner is None and node.type == "parenthesized_declarator":
            inner = next(iter(node.named_children), None)
        node = inner
    return closest == "function_declarator"


def _file_scope(node: Any) -> bool:
    parent = node.parent
    while parent is not None and parent.type.startswith("preproc_"):
        parent = parent.parent
    return parent is not None and parent.type == "translation_unit"


# Substrings that make :func:`_variable_tree` rewrite the parser input.
# Anything else is already a faithful parse, so the token walk is skipped.
_VARIABLE_TREE_MARKERS: tuple[str, ...] = ("__asm", "_asm", *sorted(_CALLING_CONVENTIONS))


def _recall_variable_tree(source: str) -> tuple[Any, bytes] | None:
    """Return a same-thread normalization of *source*, if one is still cached."""
    if len(source) > _PARSE_MEMO_MAX_BYTES:
        return None
    memo: OrderedDict[str, tuple[Any, bytes]] | None = getattr(_tls, "variable_tree_memo", None)
    if memo is None:
        return None
    hit = memo.get(source)
    if hit is None:
        return None
    memo.move_to_end(source)
    return hit


def _store_variable_tree(source: str, parsed: tuple[Any, bytes]) -> None:
    """Remember *parsed* for a later scan of the same text on this thread."""
    if len(source) > _PARSE_MEMO_MAX_BYTES:
        return
    memo: OrderedDict[str, tuple[Any, bytes]] | None = getattr(_tls, "variable_tree_memo", None)
    if memo is None:
        memo = OrderedDict()
        _tls.variable_tree_memo = memo
    memo[source] = parsed
    memo.move_to_end(source)
    while len(memo) > _PARSE_MEMO_MAX:
        memo.popitem(last=False)


def _variable_tree(source: str) -> tuple[Any, bytes]:
    """Normalize MSVC syntax using tree-sitter tokens, preserving asm operands.

    The C grammar misparses MSVC assembly labels and may absorb declarations
    after the function into its body. Replace assembly with C expressions for
    its symbolic operands before scanning scopes. Strings/comments/macros remain
    opaque; calling conventions are masked only in the parser input. Returned
    source bytes retain their spelling at the same offsets as the parsed tree.

    A source with no assembly and no calling-convention token is returned from
    the first parse. A second scan of the same text on this thread reuses that
    result. The cache is thread-local and capped, same as :func:`parse_c_source`.
    """
    cached = _recall_variable_tree(source)
    if cached is not None:
        return cached
    if not any(marker in source for marker in _VARIABLE_TREE_MARKERS):
        parsed = parse_c_source(source)
        _store_variable_tree(source, parsed)
        return parsed
    tree, raw = parse_c_source(source)
    tokens: list[tuple[str, int, int, int, str]] = []
    cursor = tree.walk()
    newlines = [i for i, byte in enumerate(raw) if byte == 10]
    opaque = {"comment", "string_literal", "char_literal", "preproc_arg"}
    while True:
        node = cursor.node
        terminal = node.type in opaque or node.child_count == 0
        if terminal and not node.is_missing:
            tokens.append(
                (
                    node.type,
                    node.start_byte,
                    node.end_byte,
                    bisect_left(newlines, node.start_byte),
                    node_text(node, raw),
                )
            )
        if not terminal and cursor.goto_first_child():
            continue
        while not cursor.goto_next_sibling():
            if not cursor.goto_parent():
                break
        else:
            continue
        break

    registers = {
        "eax",
        "ebx",
        "ecx",
        "edx",
        "esi",
        "edi",
        "esp",
        "ebp",
        "eip",
        "ax",
        "bx",
        "cx",
        "dx",
        "si",
        "di",
        "sp",
        "bp",
        "ip",
        "al",
        "ah",
        "bl",
        "bh",
        "cl",
        "ch",
        "dl",
        "dh",
        "cs",
        "ds",
        "es",
        "fs",
        "gs",
        "ss",
        "st",
    } | {f"{prefix}{n}" for prefix in ("mm", "xmm", "cr", "dr") for n in range(16)}
    qualifiers = {
        "byte",
        "word",
        "dword",
        "qword",
        "tbyte",
        "ptr",
        "offset",
        "short",
        "near",
        "far",
    }
    edits: list[tuple[int, int, bytes]] = []
    convention_spans: list[tuple[int, int]] = []
    i = 0
    while i < len(tokens):
        kind, start, end, row, text = tokens[i]
        if kind not in opaque and text in _CALLING_CONVENTIONS:
            convention_spans.append((start, end))
        if kind in opaque or text not in {"__asm", "_asm"} or i + 1 == len(tokens):
            i += 1
            continue
        if tokens[i + 1][4] == "(":  # GNU asm expressions are valid C grammar.
            i += 1
            continue
        block = tokens[i + 1][0] == "{"
        first = i + 2 if block else i + 1
        j, depth = first, 1
        while j < len(tokens):
            token = tokens[j]
            if block:
                depth += int(token[0] == "{") - int(token[0] == "}")
                if depth == 0:
                    break
            elif token[3] != row or token[0] == "}" or token[4] in {"__asm", "_asm"}:
                break
            j += 1
        if block and j == len(tokens):  # An unterminated block cannot establish scope.
            i += 1
            continue
        body = tokens[first:j]
        labels = {a[4] for a, b in pairwise(body) if b[0] == ":"}
        names: set[str] = set()
        opcode_row = -1
        prefix = False
        comment_row = -1
        for asm_kind, _start, _end, token_row, word in body:
            if asm_kind == ";":
                comment_row = token_row
            if token_row == comment_row or asm_kind not in {"identifier", "type_identifier"}:
                continue
            if word in labels or word in {"__asm", "_asm"}:
                continue
            if token_row != opcode_row or prefix:
                opcode_row = token_row
                prefix = word.lower() in {"rep", "repe", "repne", "repz", "repnz", "lock"}
                continue
            if word.lower() not in registers | qualifiers:
                names.add(word)
        stop = tokens[j][2] if block else (tokens[j][1] if j < len(tokens) else len(raw))
        expressions = " ".join(name + ";" for name in sorted(names))
        replacement = ("{ " + expressions + " }" if block else expressions or ";").encode()
        replacement += b"\n" * raw[start:stop].count(b"\n")
        edits.append((start, stop, replacement))
        i = j + 1 if block else j
    parser_bytes = raw
    for start, end in convention_spans:
        parser_bytes = parser_bytes[:start] + b" " * (end - start) + parser_bytes[end:]
    for start, end, replacement in reversed(edits):
        raw = raw[:start] + replacement + raw[end:]
        parser_bytes = parser_bytes[:start] + replacement + parser_bytes[end:]
    tree, _ = parse_c_source(parser_bytes)
    parsed = (tree, raw)
    _store_variable_tree(source, parsed)
    return parsed


def find_extern_variables(
    source: str,
    *,
    include_definitions: bool = False,
    function_filter: Callable[[int], bool] | None = None,
) -> list[ExternVar]:
    """Find extern variable (non-function) declarations.

    Tree-sitter naturally distinguishes function declarations (which have
    ``function_declarator`` nodes) from variable declarations (which have
    plain ``identifier`` or ``pointer_declarator`` + ``identifier``).

    With *include_definitions*, file-scope **definitions** are returned too
    (``char g_t[4] = {...};``), not only ``extern`` declarations.  A
    definition is where a global's real type lives, so a caller comparing
    types across files -- conflict detection above all -- sees nothing useful
    without them: a definition typed ``int[4]`` in one file against an
    ``extern short`` in another is exactly the mismatch worth reporting, and it
    is invisible while only ``extern`` is parsed.  Off by default because the
    existing callers ask specifically about declarations.
    """
    if not source or not source.strip():
        return []
    try:
        tree, src_bytes = _variable_tree(source)
    except ImportError:
        return []

    results: list[ExternVar] = []

    def walk(node: Any) -> None:
        if (
            node.type == "function_definition"
            and function_filter is not None
            and not function_filter(src_bytes.count(b"\n", 0, node.start_byte) + 1)
        ):
            return
        if node.type == "declaration":
            has_extern = False
            has_dllimport = False
            for child in node.children:
                if (
                    child.type == "storage_class_specifier"
                    and node_text(child, src_bytes) == "extern"
                ):
                    has_extern = True
                text = node_text(child, src_bytes)
                if child.type == "ms_declspec_modifier" and "dllimport" in text:
                    has_dllimport = True

            # A definition qualifies only at file scope: a local `int i = 0;`
            # inside a function body is not a global and must not be reported.
            at_file_scope = _file_scope(node)
            if not (has_extern or (include_definitions and at_file_scope)) or has_dllimport:
                for child in node.children:
                    walk(child)
                return

            type_parts: list[str] = [
                node_text(child, src_bytes)
                for child in node.children
                if child.type
                in (
                    "type_qualifier",
                    "primitive_type",
                    "sized_type_specifier",
                    "type_identifier",
                    "struct_specifier",
                    "enum_specifier",
                    "union_specifier",
                )
            ]

            type_str = " ".join(type_parts) if type_parts else ""

            first_result = len(results)
            for child in node.children_by_field_name("declarator"):
                if _declares_function(child):
                    continue
                if _has_function_declarator(child):
                    decl = (
                        child.child_by_field_name("declarator")
                        if child.type == "init_declarator"
                        else child
                    )
                    name = _variable_name(decl, src_bytes)
                    if name is None:
                        continue
                    # Remove names from the declarator, leaving its pointer and
                    # parameter types. Named parameters do not change its type.
                    removed: list[tuple[int, int]] = []
                    stack = [decl]
                    while stack:
                        part = stack.pop()
                        if part.type == "identifier" and _variable_name(
                            decl, src_bytes
                        ) == node_text(part, src_bytes):
                            removed.append((part.start_byte, part.end_byte))
                        if part.type == "parameter_declaration":
                            parameter = part.child_by_field_name("declarator")
                            parameter_name = _variable_name(parameter, src_bytes)
                            if parameter_name:
                                pending = [parameter]
                                while pending:
                                    parameter_node = pending.pop()
                                    if (
                                        parameter_node.type == "identifier"
                                        and node_text(parameter_node, src_bytes) == parameter_name
                                    ):
                                        removed.append(
                                            (parameter_node.start_byte, parameter_node.end_byte)
                                        )
                                    pending.extend(parameter_node.named_children)
                        stack.extend(part.named_children)
                    spelling = src_bytes[decl.start_byte : decl.end_byte]
                    for start, end in sorted(set(removed), reverse=True):
                        spelling = (
                            spelling[: start - decl.start_byte] + spelling[end - decl.start_byte :]
                        )
                    compact = " ".join(spelling.decode("utf-8", errors="surrogateescape").split())
                    compact = compact.replace("( ", "(").replace(" )", ")").replace(" ,", ",")
                    results.append(
                        ExternVar(
                            name=name,
                            type_str=type_str + " " + compact,
                            array_suffix="",
                        )
                    )
                    continue
                if child.type in (
                    "init_declarator",
                    "pointer_declarator",
                    "array_declarator",
                    "identifier",
                ):
                    ptr_depth = (
                        _count_pointer_depth(child) if child.type == "pointer_declarator" else 0
                    )

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

                    array_suffix = ""
                    arr_node = decl
                    while arr_node and arr_node.type == "pointer_declarator":
                        arr_node = _find_child(arr_node, "pointer_declarator", "array_declarator")
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
            for variable in results[first_result:]:
                variable.line = src_bytes.count(b"\n", 0, node.start_byte) + 1
                variable.end_line = src_bytes.count(b"\n", 0, node.end_byte) + 1
                variable.declaration = node_text(node, src_bytes)
        else:
            for child in node.children:
                walk(child)

    walk(tree.root_node)
    return results


def find_variable_roles(
    source: str, *, function_filter: Callable[[int], bool] | None = None
) -> tuple[set[str], set[str], set[str]]:
    """Return file definitions, extern declarations, and syntactic variable uses.

    This is a source inventory, not a preprocessor or linker verdict. Declaration
    names, member names, strings, and locally shadowed names are not uses. A
    tentative file-scope definition owns storage; an initialized extern does too.
    """
    tree, src = _variable_tree(source)
    definitions: set[str] = set()
    declarations: set[str] = set()
    uses: set[str] = set()

    def walk(node: Any, shadows: set[str], file_scope: bool = False) -> None:
        if node.type.startswith("preproc_"):
            # Raw conditional branches can contain source facts; macro bodies
            # are not C expression references and require preprocessing.
            if node.type in {"preproc_if", "preproc_ifdef", "preproc_else", "preproc_elif"}:
                for child in node.named_children:
                    if child not in (
                        node.child_by_field_name("condition"),
                        node.child_by_field_name("name"),
                    ):
                        walk(child, shadows, file_scope)
            return
        if node.type == "function_definition":
            if function_filter is not None and not function_filter(
                src.count(b"\n", 0, node.start_byte) + 1
            ):
                return
            local = set(shadows)
            declarator = node.child_by_field_name("declarator")
            if declarator is not None:
                stack = [declarator]
                while stack:
                    part = stack.pop()
                    if part.type == "parameter_declaration":
                        name = _variable_name(part.child_by_field_name("declarator"), src)
                        if name:
                            local.add(name)
                    else:
                        stack.extend(part.named_children)
            body = node.child_by_field_name("body")
            if body is not None:
                walk(body, local)
            return
        if node.type in {"compound_statement", "for_statement"}:
            local = set(shadows)
            for child in node.named_children:
                walk(child, local)
            return
        if node.type == "declaration":
            has_extern = any(
                c.type == "storage_class_specifier" and node_text(c, src) == "extern"
                for c in node.named_children
            )
            imported = any(
                child.type == "ms_declspec_modifier" and "dllimport" in node_text(child, src)
                for child in node.named_children
            )
            for declarator in node.children_by_field_name("declarator"):
                name = _variable_name(declarator, src)
                if not name or _declares_function(declarator):
                    continue
                value = declarator.child_by_field_name("value")
                if file_scope:
                    if not imported and (not has_extern or value is not None):
                        definitions.add(name)
                    else:
                        declarations.add(name)
                elif not has_extern:
                    shadows.add(name)
                if value is not None:
                    walk(value, shadows)
            return
        if node.type == "identifier":
            name = node_text(node, src)
            if name not in shadows:
                uses.add(name)
            return
        for child in node.named_children:
            walk(child, shadows, file_scope)

    for node in tree.root_node.named_children:
        walk(node, set(), True)
    return definitions, declarations, uses


# ---------------------------------------------------------------------------
# Plain declaration type extraction (regex fallback for single lines)
# ---------------------------------------------------------------------------

_DECL_TYPE_RE = re.compile(
    r"^(?:extern\s+)?(?P<type>.+?)\s+\b(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*(?P<arr>\[.*\])?\s*;?\s*$"
)


def type_from_declaration(decl: str, var_name: str) -> str | None:
    """Extract the C type string for *var_name* from a single declaration line.

    Shared by data annotation / header generation and BinSync global export —
    lives here so callers do not reach into ``rebrew.binsync``.
    """
    decl = decl.strip().rstrip(";").strip()
    if not decl or var_name not in decl:
        return None
    m = _DECL_TYPE_RE.match(decl + ";")
    if m and m.group("name") == var_name:
        t = m.group("type").strip()
        arr = (m.group("arr") or "").strip()
        if arr:
            t = f"{t}{arr}"
        return t or None
    idx = decl.find(var_name)
    if idx > 0:
        prefix = decl[:idx].strip()
        if prefix.startswith("extern "):
            prefix = prefix[7:].strip()
        suffix = decl[idx + len(var_name) :].strip()
        if suffix.startswith("["):
            prefix = f"{prefix}{suffix}"
        if prefix:
            return prefix
    return None


def _mask_cc(source: str) -> str:
    """Hide compiler extensions while retaining AST byte offsets in the original text."""
    return _DECLSPEC_PATTERN.sub(
        lambda m: " " * len(m.group()), _CC_PATTERN.sub(lambda m: " " * len(m.group()), source)
    )


def prototype_name_span(prototype: str) -> tuple[str, int, int] | None:
    """Return the function identifier and its byte span in a C declarator."""
    tree, source = parse_c_source(_mask_cc(prototype.rstrip(";") + ";"))
    for declaration in tree.root_node.children:
        declarator = declaration.child_by_field_name("declarator")
        if declarator is None:
            continue
        name = find_function_name_in_node(declarator, source)
        if not name:
            continue
        pending = [declarator]
        while pending:
            node = pending.pop()
            if node.type == "identifier" and node_text(node, source) == name:
                return name, int(node.start_byte), int(node.end_byte)
            pending.extend(reversed(node.children))
    return None


def replace_function_prototype(source: str, name: str, prototype: str) -> str:
    """Replace one definition's signature through the AST, preserving its body and name.

    Raises ValueError when the signature or the selected definition cannot be
    found. Names sync separately, so the received declarator's identifier is
    replaced by the existing function name before application.
    """
    span = prototype_name_span(prototype)
    if span is None:
        raise ValueError("prototype has no function declarator")
    _remote_name, start, end = span
    encoded = prototype.rstrip().rstrip(";").encode("utf-8", errors="surrogateescape")
    signature = encoded[:start] + name.encode("ascii") + encoded[end:]
    tree, parsed = parse_c_source(_mask_cc(source))
    raw = source.encode("utf-8", errors="surrogateescape")
    pending = [tree.root_node]
    while pending:
        node = pending.pop()
        if node.type == "function_definition":
            declarator = node.child_by_field_name("declarator")
            body = node.child_by_field_name("body")
            if (
                declarator is not None
                and body is not None
                and find_function_name_in_node(declarator, parsed) == name
            ):
                updated = (
                    raw[: node.start_byte] + signature.rstrip() + b" " + raw[body.start_byte :]
                )
                return updated.decode("utf-8", errors="surrogateescape")
        elif node.type != "ERROR":
            pending.extend(reversed(node.children))
    raise ValueError(f"no function definition for {name!r}")
