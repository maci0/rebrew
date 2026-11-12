"""Offset-preserving structural view of an MSVC preprocessor output."""

from __future__ import annotations

lazy import bisect
lazy import hashlib
lazy import posixpath
lazy import re
lazy import unicodedata
lazy from pathlib import Path
lazy from typing import Any

lazy from rebrew.c_parser import (
    declares_function,
    find_declarator_name,
    find_function_name_in_node,
    find_variable_roles,
    parse_c_source,
)
lazy from rebrew.source_layout import mask_buffer_inplace

_LINE = re.compile(rb'(?m)^[ \t]*#line[ \t]+[0-9]+[ \t]+"((?:\\.|[^"\\])*)"[^\r\n]*')
_MODIFIER = re.compile(rb"\b(?:_inline|_cdecl|_stdcall|_fastcall)\b")
_ANONYMOUS_FIELD = re.compile(rb"[ \t\r\n]*int[ \t\r\n]*:[ \t\r\n]*[0-9]+[ \t\r\n]*;")


def _protect_literals(raw: bytearray) -> list[tuple[int, int, bytes]]:
    """Keep extension-looking text inside comments and literals opaque to masking."""
    protected = []
    i = 0
    n = len(raw)
    # Integer compares: ``raw[i:i+2] == b"//"`` built a 2-byte slice per byte
    # of the translation unit, and ``ord`` was recomputed for every byte.
    newline, cr, hash_, slash, star = 10, 13, 35, 47, 42
    quote_d, quote_s, backslash, x_byte = 34, 39, 92, 120
    # Searching back to byte 0 for the previous newline on every '#' made the
    # walk quadratic in the line length. Advance the line start as the walk
    # passes each newline instead.
    line_start = 0
    while i < n:
        start = i
        byte = raw[i]
        nxt = raw[i + 1] if i + 1 < n else -1
        if byte == newline:
            line_start = i + 1
        elif byte == hash_ and not raw[line_start:i].strip(b" \t"):
            # A #line marker is blanked whole later; its quoted path is not a literal.
            marker = _LINE.match(raw, line_start)
            if marker is not None:
                i = marker.end()
                continue
        if byte == slash and nxt == slash:
            end = raw.find(b"\n", i + 2)
            end = n if end < 0 else end
        elif byte == slash and nxt == star:
            end = raw.find(b"*/", i + 2)
            if end < 0:
                break
            end += 2
        elif byte in (quote_d, quote_s):
            quote = byte
            i += 1
            while i < n:
                if raw[i] == backslash:
                    i += 2
                    continue
                if raw[i] == quote:
                    i += 1
                    break
                i += 1
            end = min(n, i)
        else:
            i += 1
            continue
        original = bytes(raw[start:end])
        # Keep delimiters: the C parser must still see literals and comments.
        left, right = (
            (2, 2)
            if original.startswith(b"/*")
            else (2, 0)
            if original.startswith(b"//")
            else (1, 1)
        )
        for pos in range(start + left, end - right):
            if raw[pos] != newline and raw[pos] != cr:
                raw[pos] = x_byte
        protected.append((start, end, original))
        i = end
    return protected


def parse_msvc_preprocessed(raw: bytes) -> dict[str, Any]:
    """Parse an offset-preserving view; never infer ABI or marker provenance.

    The parser view blanks compiler-generated line markers and MSVC syntax; the
    original bytes remain authoritative. Unknown syntax stays explicit.
    """
    view = bytearray(raw)
    protected = _protect_literals(view)
    markers: list[dict[str, Any]] = []
    for match in _LINE.finditer(bytes(view)):
        marker_match = _LINE.match(raw, match.start())
        if marker_match is None:
            raise ValueError("preprocessor line marker could not be decoded")
        path = marker_match.group(1).replace(b"\\\\", b"\\").decode("utf-8", "surrogateescape")
        markers.append({"start": match.start(), "end": match.end(), "reported_path": path})
        view[match.start() : match.end()] = b" " * (match.end() - match.start())
    protected = [
        (start, end, original)
        for start, end, original in protected
        if not any(marker["start"] <= start < marker["end"] for marker in markers)
    ]
    # Blank in place: a fresh ``bytes(view)`` plus a new bytearray copied the
    # whole translation unit twice more before the parser ever saw it.
    for match in _MODIFIER.finditer(view):
        start, end = match.span()
        view[start:end] = b" " * (end - start)
    mask_buffer_inplace(view)
    for start, end, original in protected:
        # An asm span may intentionally blank a protected literal or comment.
        if any(view[pos] == ord("x") for pos in range(start, end)):
            view[start:end] = original
    tree, _ = parse_c_source(bytes(view))
    diagnostics = []
    anonymous_bitfields = []
    pending = [tree.root_node]
    while pending:
        node = pending.pop()
        if node.type == "ERROR" or node.is_missing:
            parent = node.parent
            if (
                node.is_missing
                and node.type == "field_identifier"
                and parent is not None
                and parent.type == "field_declaration"
                and _ANONYMOUS_FIELD.fullmatch(raw[parent.start_byte : parent.end_byte])
            ):
                anonymous_bitfields.append({"start": parent.start_byte, "end": parent.end_byte})
            else:
                diagnostics.append(
                    {"kind": node.type, "start": node.start_byte, "end": node.end_byte}
                )
            continue
        # A node without an error descendant cannot hold a diagnostic, so the
        # walk skips its children instead of visiting every expression node.
        if node.has_error:
            pending.extend(reversed(node.children))
    return {
        "tree": tree,
        "source_sha256": hashlib.sha256(raw).hexdigest(),
        "view": bytes(view),
        "markers": markers,
        "anonymous_bitfields": anonymous_bitfields,
        "unknown_syntax": diagnostics,
        "parse_complete": not diagnostics,
        "marker_origins_proven": False,
        "abi_proven": False,
    }


def reported_source_functions(
    raw: bytes, report: dict[str, Any], source: Path, *, expected_names: set[str] | None = None
) -> dict[str, tuple[int, int]]:
    """Inventory every own-source top-level definition using reported line markers.

    Reported marker paths are not authenticated origins. Internal markers,
    unnamed or duplicate definitions and unexpected sets require review.
    """
    if hashlib.sha256(raw).hexdigest() != report["source_sha256"] or not report["parse_complete"]:
        raise ValueError("preprocessed parser input is stale or incomplete")

    def normalize(path: str) -> str:
        path = path.replace("\\", "/")
        if path.lower().startswith("z:/"):
            path = path[2:]
        return unicodedata.normalize("NFC", posixpath.normpath(path)).casefold()

    wanted = normalize(str(source.resolve()))
    markers = report["markers"]
    starts = [item["start"] for item in markers]
    found: dict[str, tuple[int, int]] = {}
    previous_end = 0
    for node in report["tree"].root_node.named_children:
        if node.type != "function_definition":
            if node.type != "comment":
                previous_end = node.end_byte
            continue
        index = bisect.bisect_right(starts, node.start_byte) - 1
        if index < 0:
            raise ValueError("function has no preceding preprocessor line marker")
        if normalize(markers[index]["reported_path"]) != wanted:
            previous_end = node.end_byte
            continue
        prefix = bytearray(raw[previous_end : node.start_byte])
        for item in markers:
            start = max(item["start"], previous_end)
            end = min(item["end"], node.start_byte)
            if start < end:
                prefix[start - previous_end : end - previous_end] = b" " * (end - start)
        if prefix.strip():
            raise ValueError("masked or unparsed text precedes an own-source function")
        declarator = node.child_by_field_name("declarator")
        name = find_function_name_in_node(declarator, raw) if declarator is not None else None
        if not name or name in found:
            raise ValueError("own-source function name is missing or duplicated")
        if bisect.bisect_left(starts, node.end_byte) != bisect.bisect_right(
            starts, node.start_byte
        ):
            raise ValueError("function contains a preprocessor line marker")
        found[name] = (node.start_byte, node.end_byte)
        previous_end = node.end_byte
    if expected_names is not None and set(found) != expected_names:
        raise ValueError("own-source function inventory differs from the expected set")
    return found


def _unparsed_prefix(raw: bytes, start: int, end: int, markers: list[dict[str, Any]]) -> bool:
    prefix = bytearray(raw[start:end])
    for item in markers:
        left, right = max(item["start"], start), min(item["end"], end)
        if left < right:
            prefix[left - start : right - start] = b" " * (right - left)
    return bool(prefix.strip())


def reported_declaration_scopes(
    raw: bytes, report: dict[str, Any], source: Path, *, expected_names: set[str] | None = None
) -> dict[str, Any]:
    """List ordered preceding declarations for syntactic uses in reported functions.

    This inventory is not semantic binding, ABI, marker-origin or provider proof.
    """
    functions = reported_source_functions(raw, report, source, expected_names=expected_names)
    declarations: dict[str, list[dict[str, Any]]] = {}
    previous_end = 0
    for node in report["tree"].root_node.named_children:
        if node.type == "comment":
            continue
        boundary = previous_end
        previous_end = node.end_byte
        if node.type == "declaration":
            declarators = node.children_by_field_name("declarator")
            for declarator in declarators:
                function = declares_function(declarator)
                name = (
                    find_function_name_in_node(declarator, raw)
                    if function
                    else find_declarator_name(declarator, raw)
                )
                if name:
                    declarations.setdefault(name, []).append(
                        {
                            "kind": "function_declaration" if function else "object_declaration",
                            "start": node.start_byte,
                            "end": node.end_byte,
                            "raw": raw[node.start_byte : node.end_byte],
                            "multiple_declarators": len(declarators) != 1,
                            "prefix_start": boundary,
                        }
                    )
        elif node.type == "function_definition":
            declarator = node.child_by_field_name("declarator")
            body = node.child_by_field_name("body")
            name = find_function_name_in_node(declarator, raw) if declarator is not None else None
            if name and body is not None:
                declarations.setdefault(name, []).append(
                    {
                        "kind": "function_definition",
                        "start": node.start_byte,
                        "end": body.start_byte,
                        "raw": raw[node.start_byte : body.start_byte],
                        "multiple_declarators": False,
                        "prefix_start": boundary,
                    }
                )
    scopes: dict[str, Any] = {}
    for name, (start, end) in functions.items():
        _, _, uses = find_variable_roles(raw[start:end].decode("utf-8", "surrogateescape"))
        scopes[name] = {}
        for symbol in sorted(uses):
            visible = [item for item in declarations.get(symbol, []) if item["start"] < start]
            if any(
                _unparsed_prefix(raw, item["prefix_start"], item["start"], report["markers"])
                for item in visible
            ):
                raise ValueError("masked or unparsed text precedes a visible declaration")
            scopes[name][symbol] = [
                {key: value for key, value in item.items() if key != "prefix_start"}
                for item in visible
            ]
    return {
        "functions": scopes,
        "reference_classification_proven": False,
        "declaration_extents_proven": False,
        "typedef_or_pragma_context_proven": False,
        "marker_origins_proven": False,
        "abi_proven": False,
        "provider_proven": False,
    }


__all__ = ["parse_msvc_preprocessed", "reported_declaration_scopes", "reported_source_functions"]
