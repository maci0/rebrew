"""runtime.py — shared helpers for the GA mutation operators.

The tree-sitter plumbing every operator uses: capture extraction, the
optional target-range scope, the query cursor, and the single-application
query runner.
"""

from __future__ import annotations

import random
import re
import threading
from collections.abc import Callable
from typing import Any

import tree_sitter as ts

from rebrew.matcher.ast_engine import parse_c_ast, replace_node
from rebrew.matcher.mutations.queries import _LazyQuery


def _capture(match_or_captures: Any, name: str) -> Any:
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
_MUTATION_ATTEMPTS = 10

# Pre-compiled regex for ret_false label removal (used in GA hot path).
_RE_RET_FALSE_LABEL_NL = re.compile(r"^[ \t]*ret_false:[ \t]*\n", flags=re.MULTILINE)
_RE_RET_FALSE_LABEL = re.compile(r"^[ \t]*ret_false:[ \t]*", flags=re.MULTILINE)

# Pre-compiled regex for mut_return_to_goto (GA hot path).
# Pre-compiled regex for mut_sink_return (GA hot path).
_RE_FUNC_PRAGMA = re.compile(
    r"^[ \t]*#pragma[ \t]+(?:optimize|intrinsic|function|check_stack|auto_inline)\b",
    re.MULTILINE,
)


_RE_SINK_RETURN = re.compile(rb"(\w+)\s*=\s*([^;]+);\s*\n\s*goto\s+end\s*;")

# Pre-compiled regex for mut_guard_clause (GA hot path).
_RE_GUARD_CLAUSE = re.compile(
    rb"([ \t]*)if\s*\(([^)]+)\)\s*\{([^}]+)return\s+([^;]+);\s*\}\s*\n\s*\1return\s+([^;]+);"
)


def _first_caps(capture_dict: dict[str, list[ts.Node]]) -> dict[str, ts.Node]:
    """Extract the first node from each capture group in a tree-sitter match."""
    return {k: v[0] for k, v in capture_dict.items()}


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
# The GA sets this once per run; every mutation query then only matches
# inside the function, which is the only code that gets scored — querying
# the whole multi-function file (e.g. a 79KB seed) cost ~270x more per
# mutation and churned sibling functions whose bytes are never compared.
_target_range = threading.local()


def set_target_range(start: int | None, end: int | None) -> None:
    """Restrict mutation queries to bytes [start, end) of the queried text (None clears).

    ``mutate_code`` converts the GA's full-source range to body coordinates
    before querying; direct ``_cursor`` users pass coordinates of whatever
    text they parse.
    """
    _target_range.range = (start, end) if start is not None and end is not None else None


def _cursor(query: ts.Query | _LazyQuery) -> ts.QueryCursor:
    """QueryCursor over a (possibly lazy) query — unwraps _LazyQuery."""
    if isinstance(query, _LazyQuery):
        query = query._get()
    assert isinstance(query, ts.Query)
    cursor = ts.QueryCursor(query)
    rng = getattr(_target_range, "range", None)
    if rng is not None:
        cursor.set_byte_range(*rng)
    return cursor


# --- Query Definitions ---
# We define tree-sitter queries here for performance


def _find_function_body_insert_pos(source: bytes, ref_byte: int) -> int | None:
    """Find the insert position for a declaration at the top of the enclosing function body.

    Walks up the tree-sitter AST from *ref_byte* to find the enclosing
    ``function_definition`` → ``compound_statement`` and returns the byte
    offset right after the opening ``{``.  Returns *None* if no enclosing
    function body is found.

    This is used to hoist variable declarations so that they comply with
    C89 scoping rules (all declarations before any statements).
    """
    tree = parse_c_ast(source)
    # Find the deepest node at ref_byte and walk up to find function body
    node = tree.root_node.descendant_for_byte_range(ref_byte, ref_byte)
    while node is not None:
        if node.type == "compound_statement":
            parent = node.parent
            if parent is not None and parent.type == "function_definition":
                # Return position right after the opening brace
                return int(node.start_byte) + 1
        node = node.parent
    return None


def _statement_region_start(block: ts.Node) -> int:
    """Byte offset where a statement may be inserted into *block*.

    C89 puts block declarations before the first statement, so a statement
    belongs after the last leading declaration; a declaration appended here
    would be ``error C2143`` for MSVC6.  Returns the offset just after ``{``
    when the block declares nothing, which is also where a *declaration*
    belongs (:func:`_find_function_body_insert_pos`).
    """
    offset = int(block.start_byte) + 1
    for node in block.children:
        if node.type in ("declaration", "type_definition"):
            offset = int(node.end_byte)
    return offset


def _apply_query_once(
    source: bytes,
    query: ts.Query | _LazyQuery,
    repl: Callable[[dict[str, ts.Node]], bytes],
    rng: random.Random,
) -> bytes | None:
    """Apply an AST query and replace one matched occurrence."""
    tree = parse_c_ast(source)
    if isinstance(query, _LazyQuery):
        query = query._get()
    cursor = _cursor(query)
    matches = cursor.matches(tree.root_node)

    if not matches:
        return None

    # Match is a tuple of (pattern_index, dict_of_captures)
    # We want a random match
    _, captures = rng.choice(matches)

    # captures is a dict mapping capture name (e.g. "expr") to a list of Nodes
    # We assume one node per capture name in our queries
    single_captures = _first_caps(captures)

    target_node = _capture(single_captures, "stmt") or _capture(single_captures, "expr")
    if not target_node:
        return None

    replacement = repl(single_captures)

    return replace_node(source, target_node, replacement)


def _commute_operands(
    s: str, rng: random.Random, query: ts.Query | _LazyQuery, op_str: bytes
) -> str | None:
    """Generic commutative operand swap for the given binary operator query."""
    b_source = s.encode("utf-8")

    def _repl(captures: dict[str, ts.Node]) -> bytes:
        left = b_source[captures["left"].start_byte : captures["left"].end_byte]
        right = b_source[captures["right"].start_byte : captures["right"].end_byte]
        if left == right:
            return b_source[captures["expr"].start_byte : captures["expr"].end_byte]
        return right + b" " + op_str + b" " + left

    res = _apply_query_once(b_source, query, _repl, rng)
    if not res:
        return None
    res_str = res.decode("utf-8")
    return res_str if res_str != s else None
