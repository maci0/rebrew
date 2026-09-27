"""ast_engine.py - AST-based mutation infrastructure for the GA engine.

Provides tree-sitter C parsing, node extraction, and source-level
manipulation helpers used by :mod:`rebrew.matcher.mutator`.
"""

import threading
from collections import OrderedDict

import tree_sitter as ts
import tree_sitter_c as tsc

C_LANGUAGE = ts.Language(tsc.language())

# tree-sitter documents TSParser as per-thread state; batch GA runs N worker
# threads through mutate_code/quick_validate concurrently, and the GIL is
# released inside ts_parser_parse — a shared parser is a C-level data race
# (corrupted ASTs or a segfault).  One parser per thread, like the capstone
# TLS pattern used elsewhere.
_tls = threading.local()


def _get_parser() -> ts.Parser:
    parser = getattr(_tls, "parser", None)
    if parser is None:
        parser = ts.Parser(C_LANGUAGE)
        _tls.parser = parser
    return parser


#: Retained parse trees, keyed by source bytes, in LRU order.  The bound is on
#: source bytes, not entries: a tree costs far more than the text it was
#: parsed from, so a sweep that mutates a function through 258k combinations
#: parks a full tree per distinct mutant until the process exits, and an
#: entry-count bound made the real limit the heap.  Measuring by source size
#: keeps the memo's working set (one unchanged body per running worker) inside
#: the budget at any ``-j``, and a miss is only a re-parse, never a wrong tree.
_PARSE_TREE_MAX_BYTES = 16 * 1024 * 1024
_PARSE_TREE_MEMO: OrderedDict[bytes, tuple[ts.Tree, int]] = OrderedDict()
_PARSE_TREE_MEMO_BYTES = 0
_PARSE_TREE_LOCK = threading.Lock()


def clear_parse_tree_memo() -> None:
    """Drop every retained parse tree."""
    global _PARSE_TREE_MEMO_BYTES
    with _PARSE_TREE_LOCK:
        _PARSE_TREE_MEMO.clear()
        _PARSE_TREE_MEMO_BYTES = 0


def _parse_c_ast_cached(source: bytes) -> ts.Tree:
    """Parse C source into a tree-sitter AST, memoized by source text.

    The GA mutation loop re-parses the same unchanged body on every attempt
    (a mutation that returns None leaves the body byte-identical); caching
    the tree for the common unchanged case avoids ~hundreds of full parses
    per generation.  A successful mutation changes the text and misses the
    cache naturally.  ``tree-sitter`` trees are read-only after creation, so
    sharing a cached tree is safe.
    """
    with _PARSE_TREE_LOCK:
        hit = _PARSE_TREE_MEMO.get(source)
        if hit is not None:
            _PARSE_TREE_MEMO.move_to_end(source)
            return hit[0]
    tree = _get_parser().parse(source)
    global _PARSE_TREE_MEMO_BYTES
    with _PARSE_TREE_LOCK:
        stale = _PARSE_TREE_MEMO.pop(source, None)
        if stale is not None:
            _PARSE_TREE_MEMO_BYTES -= stale[1]
        _PARSE_TREE_MEMO[source] = (tree, len(source))
        _PARSE_TREE_MEMO_BYTES += len(source)
        # The newest entry survives even when it alone exceeds the budget, so
        # one oversized body is still memoized for the next mutation attempt.
        while len(_PARSE_TREE_MEMO) > 1 and _PARSE_TREE_MEMO_BYTES > _PARSE_TREE_MAX_BYTES:
            _, evicted = _PARSE_TREE_MEMO.popitem(last=False)
            _PARSE_TREE_MEMO_BYTES -= evicted[1]
    return tree


def encode_source(source: str) -> bytes:
    """Encode GA source text to the on-disk bytes tree-sitter parses.

    GA seeds arrive from :func:`rebrew.utils.read_compile_source`, which
    decodes with ``surrogateescape`` so a cp1252 or Shift-JIS source keeps
    every on-disk byte.  The inverse must use the same handler: a plain
    ``"utf-8"`` encode raises ``UnicodeEncodeError`` on the lone surrogate
    a non-UTF-8 byte became (cp1252 ``Caf\xe9`` -> U+DCE9), so every
    mutation of such a source would die before its first generation.
    """
    return source.encode("utf-8", errors="surrogateescape")


def decode_source(source: bytes) -> str:
    """Decode mutated source bytes back to GA text, inverse of encode_source.

    Keeps the byte identity the compile round-trip depends on: a plain
    ``"utf-8"`` decode raises on the same legacy bytes, and
    ``errors="replace"`` would silently rewrite them to U+FFFD and change
    the string literals MSVC emits.
    """
    return source.decode("utf-8", errors="surrogateescape")


def parse_c_ast(source: bytes | str) -> ts.Tree:
    """Parse C source code into a tree-sitter AST."""
    if isinstance(source, str):
        source = encode_source(source)
    return _parse_c_ast_cached(source)


def replace_node(source: bytes, node: ts.Node, replacement: bytes) -> bytes:
    """Replace the text of a node with new bytes."""
    return source[: node.start_byte] + replacement + source[node.end_byte :]
