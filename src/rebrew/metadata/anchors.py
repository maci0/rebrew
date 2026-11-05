"""Address-only source anchors bound to the next declaration by syntax."""

from __future__ import annotations

import re
import threading
from collections import OrderedDict
from dataclasses import dataclass
lazy import unicodedata
lazy from string import Template

lazy from rebrew.c_parser import (
    comment_nodes,
    find_c_function_definitions,
    find_extern_variables,
    function_signatures,
    parse_c_source,
)
lazy from rebrew.config import (
    DEFAULT_ADDRESS_COMMENT_REGEX,
    DEFAULT_ADDRESS_COMMENTS,
    AddressCommentFormat,
)
lazy from rebrew.metadata.pascal import pascal_syntax

_COMMENT_MASK = bytes(byte if byte in (10, 13) else 32 for byte in range(256))

#: Metadata tags that may not appear as ``KEY: value`` comments.  Module scope
#: keeps the ~40-entry set out of every per-file call; ``metadata_comments``
#: runs once per source in anchor discovery.
_RESERVED_METADATA_KEYS = frozenset(
    {
        "ORIGIN",
        "NAME",
        "TYPE",
        "KIND",
        "FILE",
        "MODULE",
        "VA",
        "STORAGE_KIND",
        "BACKING",
        "LINK_SYMBOL",
        "FUNCTION",
        "STUB",
        "LIBRARY",
        "GLOBAL",
        "DATA",
        "VTABLE",
        "STRING",
        "SUPPORT",
        "STATUS",
        "STATUS_HISTORY",
        "BINDING_HISTORY",
        "SIZE",
        "CFLAGS",
        "TOOLCHAIN",
        "BLOCKER",
        "BLOCKER_DELTA",
        "SOURCE",
        "NOTE",
        "GHIDRA",
        "ANALYSIS",
        "SKIP",
        "GLOBALS",
        "LOCALS",
        "COMMENTS",
        "PROVE_CONSTRAINTS",
        "ORIGINS",
        "VERIFICATION",
        "UPDATED_BY",
        "UPDATED_AT",
        "STRUCT",
        "CALLERS",
        "SECTION",
        "SYMBOL",
        "PROTOTYPE",
    }
)


@dataclass(frozen=True)
class AddressAnchor:
    """An address and the declaration it immediately precedes; no stored state."""

    module: str
    va: int
    line: int
    definition_line: int
    name: str
    kind: str
    prototype: str = ""


def address_comment(module: str, va: int, *, syntax: AddressCommentFormat | None = None) -> str:
    """Render an address-only comment using the selected dialect (default C89)."""
    syntax = syntax or DEFAULT_ADDRESS_COMMENTS
    if not module or any(c.isspace() for c in module) or any(c in module for c in "/*{}()"):
        raise ValueError("an address anchor needs one target module name")
    if va < 0:
        raise ValueError("an address anchor cannot have a negative address")
    return Template(syntax.render_template).substitute(
        module=unicodedata.normalize("NFC", module), va=f"0x{va:08x}"
    )


def _declarations(source: str) -> dict[int, list[tuple[str, str, str]]]:
    """Index existing AST declaration inventories by their first source line."""
    declarations: dict[int, list[tuple[str, str, str]]] = {}
    prototypes = function_signatures(source)
    for name, line in find_c_function_definitions(source):
        declarations.setdefault(line, []).append((name, "FUNCTION", prototypes.get(name, "")))
    for var in find_extern_variables(source, include_definitions=True):
        declarations.setdefault(var.line, []).append((var.name, "DATA", ""))
    return declarations


# Reused by function/data scans and related targets; retain values, never ASTs.
_ANCHOR_CACHE: OrderedDict[tuple[str, AddressCommentFormat], tuple[AddressAnchor, ...]] = (
    OrderedDict()
)
_ANCHOR_CACHE_CHARS = 0
_ANCHOR_CACHE_MAX_CHARS = 8 * 1024 * 1024
_ANCHOR_CACHE_MAX_ENTRIES = 8192
_ANCHOR_LOCK = threading.RLock()


def parse_address_anchors(
    source: str, *, syntax: AddressCommentFormat | None = None
) -> list[AddressAnchor]:
    """Bind optional ADDRESS comments to declarations, cached by complete content.

    Results are immutable records returned in a fresh list. Edits invalidate by
    content; invalid input is never cached. Retention is bounded by characters
    and entries so repeated scans do not retain unbounded source or AST state.
    """
    global _ANCHOR_CACHE_CHARS
    syntax = syntax or DEFAULT_ADDRESS_COMMENTS
    if syntax.regex == DEFAULT_ADDRESS_COMMENT_REGEX and "ADDRESS:" not in source:
        return []
    key = (source, syntax)
    with _ANCHOR_LOCK:
        if key in _ANCHOR_CACHE:
            _ANCHOR_CACHE.move_to_end(key)
            return list(_ANCHOR_CACHE[key])
    result = _parse_address_anchors(source, syntax)
    if len(source) <= _ANCHOR_CACHE_MAX_CHARS:
        with _ANCHOR_LOCK:
            if key not in _ANCHOR_CACHE:
                _ANCHOR_CACHE[key] = tuple(result)
                _ANCHOR_CACHE_CHARS += len(source)
                while (
                    len(_ANCHOR_CACHE) > _ANCHOR_CACHE_MAX_ENTRIES
                    or _ANCHOR_CACHE_CHARS > _ANCHOR_CACHE_MAX_CHARS
                ):
                    evicted, _ = _ANCHOR_CACHE.popitem(last=False)
                    _ANCHOR_CACHE_CHARS -= len(evicted[0])
    return list(result)


def _parse_address_anchors(source: str, syntax: AddressCommentFormat) -> list[AddressAnchor]:
    """Bind full-line ADDRESS comments to exactly the next C declaration.

    Stacked addresses can identify one declaration in several targets. Comments
    and blank lines are skipped; intervening code, directives, ambiguous multiple
    declarators and dangling anchors are errors. Text inside strings is not an
    anchor. Extern declarations are views and do not establish storage ownership.
    """
    if syntax.style == "delphi":
        src = source.encode("utf-8", errors="surrogateescape")
        masked, comments, declarations = pascal_syntax(src)
    else:
        tree, src = parse_c_source(source)
        comments = [(node.start_byte, node.end_byte) for node in comment_nodes(tree)]
        masked = bytearray(src)
        declarations = None
    pattern = re.compile(syntax.regex)
    pending: list[tuple[str, int, int]] = []
    for start_byte, end_byte in comments:
        comment = src[start_byte:end_byte].decode("utf-8", errors="surrogateescape")
        if comment.startswith("//"):
            comment = comment.removesuffix("\r")
        if syntax.style != "delphi":
            masked[start_byte:end_byte] = src[start_byte:end_byte].translate(_COMMENT_MASK)
        body = comment_body(comment)
        match = pattern.fullmatch(body)
        if match is None and not body.startswith("ADDRESS:"):
            continue
        line = src.count(b"\n", 0, start_byte) + 1
        start = src.rfind(b"\n", 0, start_byte) + 1
        end = src.find(b"\n", end_byte)
        end = len(src) if end < 0 else end
        if (
            match is None
            or "\n" in comment
            or "\r" in comment
            or src[start:start_byte].strip()
            or src[end_byte:end].strip()
        ):
            raise ValueError(f"line {line}: expected a full-line ADDRESS: MODULE 0xVA comment")
        module, address = match["module"], match["va"]
        if (
            not module
            or any(c.isspace() for c in module)
            or not address
            or not re.fullmatch(r"0x[0-9a-fA-F]+", address)
        ):
            raise ValueError(f"line {line}: expected module and hexadecimal va captures")
        pending.append((unicodedata.normalize("NFC", module), int(address, 16), line))
    if not pending:
        return []
    if declarations is None:
        declarations = _declarations(source)
    lines = bytes(masked).splitlines()
    result: list[AddressAnchor] = []
    for module, va, line in pending:
        following = line
        while following < len(lines) and not lines[following].strip():
            following += 1
        choices = declarations.get(following + 1, [])
        if len(choices) != 1:
            raise ValueError(f"line {line}: address must precede exactly one declaration")
        name, kind, prototype = choices[0]
        result.append(AddressAnchor(module, va, line, following + 1, name, kind, prototype))
    return result


def add_address_anchor(
    source: str, module: str, va: int, name: str, *, syntax: AddressCommentFormat | None = None
) -> str:
    """Add an address above each definition/declaration of *name*, idempotently."""
    syntax = syntax or DEFAULT_ADDRESS_COMMENTS
    declarations = (
        pascal_syntax(source.encode("utf-8", errors="surrogateescape"))[2]
        if syntax.style == "delphi"
        else _declarations(source)
    )
    lines_to_anchor = {
        line for line, choices in declarations.items() if any(row[0] == name for row in choices)
    }
    if not lines_to_anchor:
        raise ValueError(f"cannot place address anchor: no declaration of {name!r}")
    for anchor in parse_address_anchors(source, syntax=syntax):
        if anchor.module == module and anchor.va == va and anchor.name == name:
            lines_to_anchor.discard(anchor.definition_line)
    newline = "\r\n" if "\r\n" in source else "\n"
    lines = source.splitlines(keepends=True)
    for line in sorted(lines_to_anchor, reverse=True):
        lines.insert(line - 1, address_comment(module, va, syntax=syntax) + newline)
    return "".join(lines)


def comment_body(comment: str) -> str:
    """Remove one lexical comment delimiter, retaining only its stripped body."""
    if comment.startswith("{"):
        return comment[1:-1].strip()
    if comment.startswith(("/*", "(*")):
        return comment[2:-2].strip()
    return comment[2:].strip()


def metadata_comments(
    source: str, *, syntax: AddressCommentFormat | None = None
) -> list[tuple[int, str]]:
    """Find forbidden metadata tags in actual comments, without reading values."""
    if ":" not in source:
        return []
    if syntax is not None and syntax.style == "delphi":
        src = source.encode("utf-8", errors="surrogateescape")
        _, comments, _ = pascal_syntax(src)
        return [
            (src.count(b"\n", 0, start) + 1, key)
            for start, end in comments
            if (
                key := comment_body(
                    src[start:end].decode("utf-8", errors="surrogateescape")
                ).partition(":")[0]
            )
            in _RESERVED_METADATA_KEYS
        ]
    tree, src = parse_c_source(source)
    found: list[tuple[int, str]] = []
    for node in comment_nodes(tree):
        parent = node.parent
        # A tuple constant, not a set literal: this predicate runs once per
        # ancestor of every comment, and a fresh set per step is pure overhead.
        while parent is not None and parent.type not in (
            "function_definition",
            "compound_statement",
        ):
            parent = parent.parent
        if parent is not None:
            continue
        text = src[node.start_byte : node.end_byte].decode("utf-8", errors="surrogateescape")
        body = text[2:-2].strip() if text.startswith("/*") else text[2:].strip()
        key, separator, _value = body.partition(":")
        if separator and key in _RESERVED_METADATA_KEYS:
            found.append((node.start_point[0] + 1, key))
    return found
