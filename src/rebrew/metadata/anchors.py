"""Address-only source anchors bound to the next C declaration by syntax."""

from __future__ import annotations

import re
import threading
import unicodedata
from collections import OrderedDict
from dataclasses import dataclass

from rebrew.c_parser import (
    find_c_function_definitions,
    find_extern_variables,
    function_signatures,
    parse_c_source,
)

_ADDRESS_RE = re.compile(r"ADDRESS:\s+(\S+)\s+(0x[0-9a-fA-F]+)\s*\Z")
_COMMENT_MASK = bytes(byte if byte in (10, 13) else 32 for byte in range(256))


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


def address_comment(module: str, va: int) -> str:
    """Render a compiler-independent, address-only comment (including C89)."""
    if not module or any(c.isspace() for c in module) or any(c in module for c in "/*"):
        raise ValueError("an address anchor needs one target module name")
    if va < 0:
        raise ValueError("an address anchor cannot have a negative address")
    return f"/* ADDRESS: {unicodedata.normalize('NFC', module)} 0x{va:08x} */"


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
_ANCHOR_CACHE: OrderedDict[str, tuple[AddressAnchor, ...]] = OrderedDict()
_ANCHOR_CACHE_CHARS = 0
_ANCHOR_CACHE_MAX_CHARS = 8 * 1024 * 1024
_ANCHOR_CACHE_MAX_ENTRIES = 8192
_ANCHOR_LOCK = threading.RLock()


def parse_address_anchors(source: str) -> list[AddressAnchor]:
    """Bind optional ADDRESS comments to declarations, cached by complete content.

    Results are immutable records returned in a fresh list. Edits invalidate by
    content; invalid input is never cached. Retention is bounded by characters
    and entries so repeated scans do not retain unbounded source or AST state.
    """
    global _ANCHOR_CACHE_CHARS
    if "ADDRESS:" not in source:
        return []
    with _ANCHOR_LOCK:
        if source in _ANCHOR_CACHE:
            _ANCHOR_CACHE.move_to_end(source)
            return list(_ANCHOR_CACHE[source])
    result = _parse_address_anchors(source)
    if len(source) <= _ANCHOR_CACHE_MAX_CHARS:
        with _ANCHOR_LOCK:
            if source not in _ANCHOR_CACHE:
                _ANCHOR_CACHE[source] = tuple(result)
                _ANCHOR_CACHE_CHARS += len(source)
                while (
                    len(_ANCHOR_CACHE) > _ANCHOR_CACHE_MAX_ENTRIES
                    or _ANCHOR_CACHE_CHARS > _ANCHOR_CACHE_MAX_CHARS
                ):
                    evicted, _ = _ANCHOR_CACHE.popitem(last=False)
                    _ANCHOR_CACHE_CHARS -= len(evicted)
    return list(result)


def _parse_address_anchors(source: str) -> list[AddressAnchor]:
    """Bind full-line ADDRESS comments to exactly the next C declaration.

    Stacked addresses can identify one declaration in several targets. Comments
    and blank lines are skipped; intervening code, directives, ambiguous multiple
    declarators and dangling anchors are errors. Text inside strings is not an
    anchor. Extern declarations are views and do not establish storage ownership.
    """
    if "ADDRESS:" not in source:
        return []
    tree, src = parse_c_source(source)
    masked = bytearray(src)
    pending: list[tuple[str, int, int]] = []
    stack = [tree.root_node]
    while stack:
        node = stack.pop()
        if node.type != "comment":
            stack.extend(reversed(node.named_children))
            continue
        comment = src[node.start_byte : node.end_byte].decode("utf-8")
        masked[node.start_byte : node.end_byte] = src[node.start_byte : node.end_byte].translate(
            _COMMENT_MASK
        )
        body = comment[2:-2].strip() if comment.startswith("/*") else comment[2:].strip()
        if not body.startswith("ADDRESS:"):
            continue
        line = node.start_point[0] + 1
        start = src.rfind(b"\n", 0, node.start_byte) + 1
        end = src.find(b"\n", node.end_byte)
        end = len(src) if end < 0 else end
        match = _ADDRESS_RE.fullmatch(body)
        if (
            match is None
            or node.start_point[0] != node.end_point[0]
            or src[start : node.start_byte].strip()
            or src[node.end_byte : end].strip()
        ):
            raise ValueError(f"line {line}: expected a full-line ADDRESS: MODULE 0xVA comment")
        pending.append((unicodedata.normalize("NFC", match[1]), int(match[2], 16), line))
    if not pending:
        return []
    declarations = _declarations(source)
    lines = bytes(masked).splitlines()
    result: list[AddressAnchor] = []
    for module, va, line in pending:
        following = line
        while following < len(lines) and not lines[following].strip():
            following += 1
        choices = declarations.get(following + 1, [])
        if len(choices) != 1:
            raise ValueError(f"line {line}: address must precede exactly one C declaration")
        name, kind, prototype = choices[0]
        result.append(AddressAnchor(module, va, line, following + 1, name, kind, prototype))
    return result


def add_address_anchor(source: str, module: str, va: int, name: str) -> str:
    """Add an address above each definition/declaration of *name*, idempotently."""
    declarations = _declarations(source)
    lines_to_anchor = {
        line for line, choices in declarations.items() if any(row[0] == name for row in choices)
    }
    if not lines_to_anchor:
        raise ValueError(f"cannot place address anchor: no declaration of {name!r}")
    for anchor in parse_address_anchors(source):
        if anchor.module == module and anchor.va == va and anchor.name == name:
            lines_to_anchor.discard(anchor.definition_line)
    newline = "\r\n" if "\r\n" in source else "\n"
    lines = source.splitlines(keepends=True)
    for line in sorted(lines_to_anchor, reverse=True):
        lines.insert(line - 1, address_comment(module, va) + newline)
    return "".join(lines)


def metadata_comments(source: str) -> list[tuple[int, str]]:
    """Find forbidden metadata tags in actual comments, without reading values."""
    if ":" not in source:
        return []
    reserved = {
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
    tree, src = parse_c_source(source)
    found: list[tuple[int, str]] = []
    stack = [tree.root_node]
    while stack:
        node = stack.pop()
        if node.type in {"function_definition", "compound_statement"}:
            continue
        if node.type != "comment":
            stack.extend(reversed(node.named_children))
            continue
        text = src[node.start_byte : node.end_byte].decode("utf-8")
        body = text[2:-2].strip() if text.startswith("/*") else text[2:].strip()
        key, separator, _value = body.partition(":")
        if separator and key in reserved:
            found.append((node.start_point[0] + 1, key))
    return found
