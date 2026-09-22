"""ast_engine.py - AST-based mutation infrastructure for the GA engine.

Provides tree-sitter C parsing, node extraction, and source-level
manipulation helpers used by :mod:`rebrew.matcher.mutator`.
"""

import functools
import threading

import tree_sitter as ts
import tree_sitter_c as tsc

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
