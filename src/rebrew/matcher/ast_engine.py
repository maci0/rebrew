"""ast_engine.py - AST-based mutation infrastructure for the GA engine.

Provides tree-sitter C parsing, node extraction, and source-level
manipulation helpers used by :mod:`rebrew.matcher.mutator`.
"""

import functools
import threading

import tree_sitter as ts
import tree_sitter_c as tsc

# Initialize tree-sitter parser for C
_C_LANGUAGE = ts.Language(tsc.language())

# tree-sitter documents TSParser as per-thread state; batch GA runs N worker
# threads through mutate_code/quick_validate concurrently, and the GIL is
# released inside ts_parser_parse — a shared parser is a C-level data race
# (corrupted ASTs or a segfault).  One parser per thread, like the capstone
# TLS pattern used elsewhere.
_tls = threading.local()


def _get_parser() -> ts.Parser:
    parser = getattr(_tls, "parser", None)
    if parser is None:
        parser = ts.Parser(_C_LANGUAGE)
        _tls.parser = parser
    return parser


@functools.lru_cache(maxsize=256)
def _parse_c_ast_cached(source: bytes) -> ts.Tree:
    """Parse C source into a tree-sitter AST, memoized by source text.

    The GA mutation loop re-parses the same unchanged body on every attempt
    (a mutation that returns None leaves the body byte-identical); caching
    the tree for the common unchanged case avoids ~hundreds of full parses
    per generation.  A successful mutation changes the text and misses the
    cache naturally.  ``tree-sitter`` trees are read-only after creation, so
    sharing a cached tree is safe.
    """
    return _get_parser().parse(source)


def parse_c_ast(source: bytes | str) -> ts.Tree:
    """Parse C source code into a tree-sitter AST."""
    if isinstance(source, str):
        source = source.encode("utf-8")
    return _parse_c_ast_cached(source)


def replace_node(source: bytes, node: ts.Node, replacement: bytes) -> bytes:
    """Replace the text of a node with new bytes."""
    return source[: node.start_byte] + replacement + source[node.end_byte :]
