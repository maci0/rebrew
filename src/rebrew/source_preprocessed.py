"""Offset-preserving structural view of an MSVC preprocessor output."""

from __future__ import annotations

lazy import bisect
lazy import hashlib
lazy import posixpath
lazy import re
lazy from pathlib import Path
lazy from typing import Any

lazy from rebrew.c_parser import find_function_name_in_node, parse_c_source
lazy from rebrew.source_layout import mask_for_parse

_LINE = re.compile(rb'(?m)^[ \t]*#line[ \t]+[0-9]+[ \t]+"((?:\\.|[^"\\])*)"[^\r\n]*')
_MODIFIER = re.compile(rb"\b(?:_inline|_cdecl|_stdcall|_fastcall)\b")
_ANONYMOUS_FIELD = re.compile(rb"[ \t\r\n]*int[ \t\r\n]*:[ \t\r\n]*[0-9]+[ \t\r\n]*;")


def _protect_literals(raw: bytearray) -> list[tuple[int, int, bytes]]:
    """Keep extension-looking text inside comments and literals opaque to masking."""
    protected = []
    i = 0
    while i < len(raw):
        start = i
        if raw[i : i + 2] == b"//":
            end = raw.find(b"\n", i + 2)
            end = len(raw) if end < 0 else end
        elif raw[i : i + 2] == b"/*":
            end = raw.find(b"*/", i + 2)
            if end < 0:
                break
            end += 2
        elif raw[i] in (ord('"'), ord("'")):
            quote = raw[i]
            i += 1
            while i < len(raw):
                if raw[i] == ord("\\"):
                    i += 2
                    continue
                if raw[i] == quote:
                    i += 1
                    break
                i += 1
            end = min(i, len(raw))
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
            if raw[pos] not in (10, 13):
                raw[pos] = ord("x")
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
    view = bytearray(_MODIFIER.sub(lambda match: b" " * len(match.group()), bytes(view)))
    view = bytearray(mask_for_parse(bytes(view)))
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
        return posixpath.normpath(path).casefold()

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


__all__ = ["parse_msvc_preprocessed", "reported_source_functions"]
