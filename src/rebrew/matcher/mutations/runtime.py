"""runtime.py — shared helpers for the GA mutation operators.

The tree-sitter plumbing every operator uses: capture extraction, the
optional target-range scope, the query cursor, and the single-application
query runner.
"""

from __future__ import annotations

import re
import threading
lazy import random
lazy from collections.abc import Callable
lazy from typing import Any

lazy import tree_sitter as ts

lazy from rebrew.matcher.ast_engine import (
    decode_source,
    encode_source,
    parse_c_ast,
    replace_node,
)
lazy from rebrew.matcher.mutations.queries import QUERY_ASSIGN_ZERO, LazyQuery

__all__ = [
    "MUTATION_ATTEMPTS",
    "POSTFIX_PARENTS",
    "POSTFIX_SAFE",
    "RE_FUNC_PRAGMA",
    "RE_GUARD_CLAUSE",
    "RE_RET_FALSE_LABEL",
    "RE_RET_FALSE_LABEL_NL",
    "RE_SINK_RETURN",
    "apply_query_once",
    "assign_zero_targets",
    "brace_block",
    "cap1",
    "cap_bytes",
    "capture",
    "case_value_text",
    "commute_operands",
    "find_function_body_insert_pos",
    "first_caps",
    "get_target_range",
    "operand_bytes",
    "pick_match",
    "query_cursor",
    "set_target_range",
    "statement_region_start",
    "toggle_zero_assignment",
    "under_postfix",
]


def capture(match_or_captures: Any, name: str) -> Any:
    """Return a named tree-sitter capture, preserving the runtime value.

    Accepts either a tree-sitter ``Match`` tuple (``(node, captures)``) or a
    captures dict.  tree-sitter's type stubs type captures inconsistently
    (``Node`` vs ``list[Node]``), so the return is ``Any``; callers keep their
    existing ``isinstance`` guards where the value's shape matters.
    """
    captures = (
        match_or_captures[1] if not isinstance(match_or_captures, dict) else match_or_captures
    )
    return captures.get(name)


# Max attempts to find a valid mutation before giving up and returning source unchanged.
MUTATION_ATTEMPTS = 10

# Pre-compiled regex for ret_false label removal (used in GA hot path).
# ``\r?`` so CRLF sources strip the label line the same as LF (bare ``\n``
# left the CR behind and failed to match the label+newline form entirely).
RE_RET_FALSE_LABEL_NL = re.compile(r"^[ \t]*ret_false:[ \t]*\r?\n", flags=re.MULTILINE)
RE_RET_FALSE_LABEL = re.compile(r"^[ \t]*ret_false:[ \t]*", flags=re.MULTILINE)

# Function-level pragma line, kept with the function body by split_preamble_body.
RE_FUNC_PRAGMA = re.compile(
    r"^[ \t]*#pragma[ \t]+(?:optimize|intrinsic|function|check_stack|auto_inline)\b",
    re.MULTILINE,
)

# Pre-compiled regex for mut_sink_return (GA hot path).
RE_SINK_RETURN = re.compile(rb"(\w+)\s*=\s*([^;]+);\s*\n\s*goto\s+end\s*;")

# Pre-compiled regex for mut_guard_clause (GA hot path).
RE_GUARD_CLAUSE = re.compile(
    rb"([ \t]*)if\s*\(([^)]+)\)\s*\{([^}]+)return\s+([^;]+);\s*\}\s*\n\s*\1return\s+([^;]+);"
)


def first_caps(capture_dict: dict[str, list[ts.Node]]) -> dict[str, ts.Node]:
    """Extract the first node from each capture group in a tree-sitter match."""
    return {k: v[0] for k, v in capture_dict.items()}


def cap_bytes(source: bytes, captures: dict[str, ts.Node], name: str) -> bytes:
    """Return the *source* bytes spanned by capture *name*."""
    node = captures[name]
    return source[node.start_byte : node.end_byte]


def cap1(match_or_captures: Any, name: str) -> Any:
    """First node of capture *name*, or ``None`` when absent (a list head)."""
    value = capture(match_or_captures, name)
    return value[0] if isinstance(value, list) else value


def case_value_text(source: bytes, case_node: ts.Node) -> bytes | None:
    """Text of the case value: the last child before ``:`` in a ``case_statement``."""
    value: bytes | None = None
    for child in case_node.children:
        if child.type == ":":
            break
        if child.type != "case":
            value = source[child.start_byte : child.end_byte].strip()
    return value


#: Expressions that bind at least as tightly as a postfix operator, so they
#: can stand as the operand of ``[]``, ``.``, ``->``, ``+`` or ``*`` as-is.
POSTFIX_SAFE = frozenset(
    {
        "identifier",
        "number_literal",
        "char_literal",
        "string_literal",
        "parenthesized_expression",
        "field_expression",
        "subscript_expression",
        "call_expression",
    }
)

#: Parents that apply a postfix operator to their first operand.
POSTFIX_PARENTS = frozenset(
    {"field_expression", "subscript_expression", "call_expression", "update_expression"}
)


def operand_bytes(source: bytes, captures: dict[str, ts.Node], name: str) -> bytes:
    """Capture *name*'s bytes, parenthesized unless already postfix-safe.

    Splicing a subexpression into a tighter context (a cast or ``i + 1`` as
    a subscript base) without grouping silently changes what it computes.
    """
    text = cap_bytes(source, captures, name)
    return text if captures[name].type in POSTFIX_SAFE else b"(" + text + b")"


def under_postfix(node: ts.Node) -> bool:
    """True when *node*'s parent applies a postfix operator to it."""
    return node.parent is not None and node.parent.type in POSTFIX_PARENTS


def brace_block(body: bytes) -> bytes:
    """Wrap *body* in ``{ }`` unless it is already braced.

    A bare ``if (c) x;`` spliced into an ``if``/``else`` re-binds the final
    ``else`` to the inner ``if`` (dangling else), flipping branch outcomes;
    a braced body cannot.
    """
    if body.startswith(b"{") and body.endswith(b"}"):
        return body
    return b"{ " + body + b" }"


# Optional scope limiting GA mutations to the target function's byte range.
# The GA sets it around each mutation to the function's range in that
# source; every query then only matches inside the function, which is the
# only code that gets scored — querying
# the whole multi-function file (e.g. a 79KB seed) cost ~270x more per
# mutation and churned sibling functions whose bytes are never compared.
_target_range = threading.local()


def set_target_range(start: int | None, end: int | None) -> None:
    """Restrict mutation queries to bytes [start, end) of the queried text (None clears).

    ``mutate_code`` converts the GA's full-source range to body coordinates
    before querying; direct ``cursor`` users pass coordinates of whatever
    text they parse.
    """
    _target_range.range = (start, end) if start is not None and end is not None else None


def get_target_range() -> tuple[int, int] | None:
    """The byte range ``set_target_range`` last applied on this thread, or None.

    ``mutate_code`` narrows the range to body coordinates and must put the
    caller's range back afterwards; a mutation that does not pass through
    ``mutate_code`` (crossover) would otherwise inherit the narrowed window.
    """
    rng: tuple[int, int] | None = getattr(_target_range, "range", None)
    return rng


def query_cursor(query: ts.Query | LazyQuery) -> ts.QueryCursor:
    """QueryCursor over a (possibly lazy) query — unwraps LazyQuery."""
    if isinstance(query, LazyQuery):
        query = query._get()
    assert isinstance(query, ts.Query)
    cursor = ts.QueryCursor(query)
    rng = getattr(_target_range, "range", None)
    if rng is not None:
        cursor.set_byte_range(*rng)
    return cursor


def pick_match(
    b_source: bytes, query: ts.Query | LazyQuery, rng: random.Random
) -> dict[str, ts.Node] | None:
    """Captures of one random match of *query* over *b_source*, or None."""
    matches = query_cursor(query).matches(parse_c_ast(b_source).root_node)
    if not matches:
        return None
    return first_caps(rng.choice(matches)[1])


def assign_zero_targets(b_source: bytes, tree: ts.Tree) -> list[tuple[dict[str, ts.Node], bytes]]:
    """``var = 0`` matches paired with their ``var`` text, ready to rewrite.

    Skips an assignment that is a for-loop initializer, and any ``var`` that
    is a member access or subscript (``a.b``, ``a->b``, ``a[i]``), so only
    plain identifiers are returned.
    """
    targets: list[tuple[dict[str, ts.Node], bytes]] = []
    for m in query_cursor(QUERY_ASSIGN_ZERO).matches(tree.root_node):
        caps = first_caps(m[1])
        parent = caps["expr"].parent
        if parent and parent.type == "for_statement":
            continue
        var = cap_bytes(b_source, caps, "var")
        if b"." in var or b"->" in var or b"[" in var:
            continue
        targets.append((caps, var))
    return targets


def toggle_zero_assignment(
    s: str,
    rng: random.Random,
    *,
    forward_fn: Callable[[bytes], bytes],
    reverse_query: ts.Query | LazyQuery,
    reverse_replacement: bytes,
) -> str | None:
    """Toggle ``var = 0`` against its reverse form."""
    b_source = encode_source(s)
    tree = parse_c_ast(b_source)
    candidates: list[tuple[dict[str, ts.Node], bytes, str]] = []
    for caps, var in assign_zero_targets(b_source, tree):
        candidates.append((caps, forward_fn(var), "expr"))
    cursor = query_cursor(reverse_query)
    for m in cursor.matches(tree.root_node):
        caps = first_caps(m[1])
        var = b_source[caps["var"].start_byte : caps["var"].end_byte]
        candidates.append((caps, var + reverse_replacement, "expr"))
    if not candidates:
        return None
    caps, replacement, target_key = rng.choice(candidates)
    target = caps[target_key]
    result = b_source[: target.start_byte] + replacement + b_source[target.end_byte :]
    return decode_source(result)


def find_function_body_insert_pos(source: bytes, ref_byte: int) -> int | None:
    """Find the insert position for a declaration at the top of the enclosing function body.

    Walks up the tree-sitter AST from *ref_byte* to find the enclosing
    ``function_definition`` → ``compound_statement`` and returns the byte
    offset right after the opening ``{``.  Returns *None* if no enclosing
    function body is found.

    This is used to hoist variable declarations so that they comply with
    C89 scoping rules (all declarations before any statements).
    """
    tree = parse_c_ast(source)
    node = tree.root_node.descendant_for_byte_range(ref_byte, ref_byte)
    while node is not None:
        if node.type == "compound_statement":
            parent = node.parent
            if parent is not None and parent.type == "function_definition":
                return int(node.start_byte) + 1
        node = node.parent
    return None


def statement_region_start(block: ts.Node) -> int:
    """Byte offset where a statement may be inserted into *block*.

    C89 puts block declarations before the first statement, so a statement
    belongs after the last leading declaration; a declaration appended here
    would be ``error C2143`` for MSVC6.  Returns the offset just after ``{``
    when the block declares nothing, which is also where a *declaration*
    belongs (:func:`find_function_body_insert_pos`).
    """
    offset = int(block.start_byte) + 1
    for node in block.children:
        if node.type in ("declaration", "type_definition"):
            offset = int(node.end_byte)
    return offset


def apply_query_once(
    source: bytes,
    query: ts.Query | LazyQuery,
    repl: Callable[[dict[str, ts.Node]], bytes],
    rng: random.Random,
) -> bytes | None:
    """Apply an AST query and replace one matched occurrence."""
    tree = parse_c_ast(source)
    cursor = query_cursor(query)
    matches = cursor.matches(tree.root_node)

    if not matches:
        return None

    _, captures = rng.choice(matches)
    single_captures = first_caps(captures)

    target_node = capture(single_captures, "stmt") or capture(single_captures, "expr")
    if not target_node:
        return None

    replacement = repl(single_captures)

    return replace_node(source, target_node, replacement)


def commute_operands(
    s: str, rng: random.Random, query: ts.Query | LazyQuery, op_str: bytes
) -> str | None:
    """Generic commutative operand swap for the given binary operator query."""
    b_source = encode_source(s)

    def _repl(captures: dict[str, ts.Node]) -> bytes:
        left = cap_bytes(b_source, captures, "left")
        right = cap_bytes(b_source, captures, "right")
        if left == right:
            return cap_bytes(b_source, captures, "expr")
        return right + b" " + op_str + b" " + left

    res = apply_query_once(b_source, query, _repl, rng)
    if not res:
        return None
    res_str = decode_source(res)
    return res_str if res_str != s else None
