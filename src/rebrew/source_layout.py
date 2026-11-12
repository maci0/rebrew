"""Parser-backed top-level C source spans and attached comments."""

import re
from dataclasses import dataclass, field
lazy import bisect
lazy from typing import Any

lazy from rebrew.c_parser import (
    declares_function,
    find_function_name_in_node,
    node_text,
    parse_c_structure,
)

__all__ = [
    "SourceSpan",
    "decode_span",
    "gap_is_blank",
    "mask_buffer_inplace",
    "mask_for_parse",
    "source_layout",
    "span_extent",
]

_PREAMBLE_TYPES = frozenset(
    {
        "preproc_include",
        "preproc_def",
        "preproc_function_def",
        "preproc_call",
        "type_definition",
        "struct_specifier",
        "enum_specifier",
        "union_specifier",
    }
)
_COND_TYPES = frozenset({"preproc_if", "preproc_ifdef", "preproc_elif", "preproc_else"})


@dataclass
class SourceSpan:
    """One top-level slice of the source, in file order."""

    kind: str
    start: int
    end: int
    name: str = ""
    static: bool = False
    inside_pp: bool = False
    proto: str = ""
    extern_line: str | None = None
    names: tuple[str, ...] = ()
    attached: list[int] = field(default_factory=list)


def decode_span(raw: bytes, start: int, end: int) -> str:
    """Decode ``raw[start:end]`` preserving non-UTF-8 bytes as surrogates."""
    return raw[start:end].decode("utf-8", errors="surrogateescape")


def gap_is_blank(raw: bytes, start: int, end: int) -> bool:
    """True when the span holds only ASCII whitespace."""
    return raw[start:end].strip(b" \t\r\n") == b""


def _declarator_name(declarator: Any, raw: bytes) -> str | None:
    node = declarator
    if node is not None and node.type == "init_declarator":
        node = node.child_by_field_name("declarator")
    while node is not None:
        if node.type == "identifier":
            return node_text(node, raw)
        nxt = node.child_by_field_name("declarator")
        if nxt is None and node.type == "parenthesized_declarator":
            nxt = next((child for child in node.named_children), None)
        if nxt is None and node.type == "ERROR":
            nxt = next(
                (child for child in node.named_children if child.type != "identifier"),
                None,
            )
        node = nxt
    return None


def _extern_line(node: Any, raw: bytes) -> str | None:
    """``extern`` declaration text for one object definition, without its initializer."""
    declarators = node.children_by_field_name("declarator")
    objects = [item for item in declarators if not declares_function(item)]
    if len(objects) != 1 or _declarator_name(objects[0], raw) is None:
        return None
    cuts: list[tuple[int, int]] = []
    for item in objects:
        if item.type != "init_declarator":
            continue
        value = item.child_by_field_name("value")
        if value is None:
            continue
        equals = next((child for child in item.children if child.type == "="), None)
        cuts.append(((equals or value).start_byte, value.end_byte))
    text = raw[node.start_byte : node.end_byte]
    for start, end in sorted(cuts, reverse=True):
        text = text[: start - node.start_byte] + text[end - node.start_byte :]
    body = text.decode("utf-8", errors="surrogateescape").strip()
    if body.endswith(";"):
        body = body[:-1].rstrip()
    collapsed = " ".join(body.split())
    if not collapsed or collapsed.startswith("extern"):
        return (collapsed + ";") if collapsed else None
    return f"extern {collapsed};"


def _declaration_span(node: Any, raw: bytes, *, inside_pp: bool) -> SourceSpan:
    words = {
        node_text(child, raw) for child in node.children if child.type == "storage_class_specifier"
    }
    if "typedef" in words:
        return SourceSpan("preamble", node.start_byte, node.end_byte)
    declarators = node.children_by_field_name("declarator")
    if not declarators:
        return SourceSpan("preamble", node.start_byte, node.end_byte)
    if all(declares_function(item) for item in declarators):
        return SourceSpan("preamble", node.start_byte, node.end_byte)
    has_value = any(
        item.type == "init_declarator" and item.child_by_field_name("value") is not None
        for item in declarators
    )
    if "extern" in words and not has_value:
        return SourceSpan("preamble", node.start_byte, node.end_byte)
    names = tuple(
        name
        for item in declarators
        if not declares_function(item) and (name := _declarator_name(item, raw))
    )
    uncertain = len(declarators) != 1 or len(names) != 1
    return SourceSpan(
        "storage",
        node.start_byte,
        node.end_byte,
        name=names[0] if len(names) == 1 else "",
        static="static" in words,
        inside_pp=inside_pp,
        extern_line=None if uncertain or "static" in words else _extern_line(node, raw),
        names=names,
    )


def _contains_code(node: Any, raw: bytes) -> bool:
    if node.type == "function_definition":
        return True
    if node.type == "declaration":
        return _declaration_span(node, raw, inside_pp=False).kind == "storage"
    return any(_contains_code(child, raw) for child in node.named_children)


def _function_span(node: Any, raw: bytes, *, inside_pp: bool) -> SourceSpan | None:
    declarator = node.child_by_field_name("declarator")
    name = find_function_name_in_node(declarator, raw) if declarator is not None else None
    if not name:
        return None
    compound = next((child for child in node.children if child.type == "compound_statement"), None)
    proto = ""
    if compound is not None:
        proto = " ".join(decode_span(raw, node.start_byte, compound.start_byte).split())
    static = any(
        child.type == "storage_class_specifier" and node_text(child, raw) == "static"
        for child in node.children
    )
    return SourceSpan(
        "function",
        node.start_byte,
        node.end_byte,
        name=name,
        static=static,
        inside_pp=inside_pp,
        proto=proto,
    )


def _collect_spans(node: Any, raw: bytes, *, inside_pp: bool, acc: list[SourceSpan]) -> None:
    if node.type == "function_definition":
        span = _function_span(node, raw, inside_pp=inside_pp)
        acc.append(
            span
            if span is not None
            else SourceSpan("function", node.start_byte, node.end_byte, inside_pp=inside_pp)
        )
        return
    if node.type in _COND_TYPES:
        if _contains_code(node, raw):
            for child in node.named_children:
                _collect_spans(child, raw, inside_pp=True, acc=acc)
        else:
            acc.append(SourceSpan("preamble", node.start_byte, node.end_byte))
        return
    if node.type == "declaration":
        acc.append(_declaration_span(node, raw, inside_pp=inside_pp))
        return
    if node.type in _PREAMBLE_TYPES or node.type == "comment":
        kind = "comment" if node.type == "comment" else "preamble"
        end = node.end_byte
        # `struct t {...};` parses as a bare specifier followed by an anonymous
        # `;`.  The named-children walk never sees the `;`, so the span ended
        # at `}` and every merged preamble lost it.
        follower = node.next_sibling
        if kind == "preamble" and follower is not None and follower.type == ";":
            end = follower.end_byte
        acc.append(SourceSpan(kind, node.start_byte, end))
        return


#: MSVC calling-convention keywords.  The C grammar does not know them, so
#: ``Type* __cdecl f(void) {...}`` with a typedef'd return type parses as an
#: error and the function is lost; blanking them keeps every byte offset.
_CALLING_CONVENTION_RE = re.compile(rb"\b__(?:cdecl|stdcall|fastcall|thiscall)\b")


_ASM_RE = re.compile(rb"\b__asm\b[ \t]*(\{)?")


def _blank(raw: bytearray, start: int, end: int) -> None:
    """Overwrite raw[start:end] with spaces, keeping newlines so line numbers hold."""
    for i in range(start, end):
        if raw[i] not in b"\r\n":
            raw[i] = 0x20


def _blank_spans(out: bytearray, pattern: re.Pattern[bytes]) -> None:
    """Overwrite each *pattern* match with spaces, keeping the buffer length."""
    for match in pattern.finditer(out):
        start, end = match.span()
        out[start:end] = b" " * (end - start)


def mask_for_parse(raw: bytes) -> bytes:
    """*raw* with the constructs the C grammar cannot parse blanked, same length.

    Calling-convention keywords and ``__asm`` bodies.  ``__asm { ... }`` becomes an
    empty block and a brace-less ``__asm ...`` runs to the end of its line.
    """
    out = bytearray(raw)
    _blank_spans(out, _CALLING_CONVENTION_RE)
    _mask_asm(out)
    return bytes(out)


def mask_buffer_inplace(out: bytearray) -> bytearray:
    """Blank calling conventions and ``__asm`` bodies in *out*, in place.

    Same result as :func:`mask_for_parse` without copying the translation unit.
    """
    _blank_spans(out, _CALLING_CONVENTION_RE)
    _mask_asm(out)
    return out


def _mask_asm(out: bytearray) -> None:
    """Blank ``__asm`` bodies in *out*. An unclosed brace leaves *out* as-is."""
    pos = 0
    while (m := _ASM_RE.search(out, pos)) is not None:
        if m.group(1) is None:
            end = out.find(b"\n", m.end())
            end = len(out) if end < 0 else end
            statement = bytes(out[m.end() : end])
            if not any(token in statement for token in (b'"', b"'", b"//", b"/*")):
                suffix = len(statement.rstrip(b" \t\r"))
                while suffix and statement[suffix - 1] == ord("}"):
                    suffix -= 1
                if suffix < len(statement.rstrip(b" \t\r")):
                    end = m.end() + suffix
            _blank(out, m.start(), end)
            out[m.start()] = 0x3B  # `;` keeps the statement well formed
            pos = end
            continue
        depth = 0
        end = m.end()
        for i in range(m.end() - 1, len(out)):
            if out[i] == 0x7B:
                depth += 1
            elif out[i] == 0x7D:
                depth -= 1
                if depth == 0:
                    end = i
                    break
        else:
            return
        _blank(out, m.start(), m.end() - 1)
        _blank(out, m.end(), end)
        pos = end + 1


def source_layout(text: str) -> tuple[bytes, list[SourceSpan]]:
    """Top-level spans of *text* with conditional-region and comment ownership.

    Returns the UTF-8 bytes actually parsed and every top-level span in file
    order: function definitions, storage declarations, preprocessor/preamble
    nodes and comments.  Offsets are byte offsets into the returned bytes, so
    callers slice that value rather than ``text``.  A function or storage span
    that starts inside an ``#if``/``#ifdef`` region carries ``inside_pp``, and
    lists the comments directly above it (blank lines allowed) in ``attached``,
    by index into the returned list.
    """
    raw = text.encode("utf-8", errors="surrogateescape")
    tree, _, conditional_regions = parse_c_structure(mask_for_parse(raw))
    spans: list[SourceSpan] = []
    for child in tree.root_node.named_children:
        _collect_spans(child, raw, inside_pp=False, acc=spans)
    # Furthest end over regions sorted by start: a span lies in some region
    # when the prefix maximum of regions starting at or before it reaches past
    # its start. The per-span ``any`` over every region was quadratic on a
    # file with many ``#if`` regions.
    region_starts: list[int] = []
    region_max_end: list[int] = []
    for start, end in sorted(conditional_regions):
        region_starts.append(start)
        region_max_end.append(max(region_max_end[-1] if region_max_end else 0, end))
    for span in spans:
        if span.kind not in {"function", "storage"}:
            continue
        index = bisect.bisect_right(region_starts, span.start) - 1
        if index >= 0 and region_max_end[index] > span.start:
            span.inside_pp = True
    spans.sort(key=lambda span: span.start)
    for index, span in enumerate(spans):
        if span.kind != "comment":
            continue
        owner: SourceSpan | None = None
        cursor = span.end
        # Index rather than ``spans[index + 1:]``: the slice copied the whole
        # remaining list once per comment.
        for next_index in range(index + 1, len(spans)):
            nxt = spans[next_index]
            if not gap_is_blank(raw, cursor, nxt.start):
                break
            if nxt.kind == "comment":
                cursor = nxt.end
                continue
            if nxt.kind in {"function", "storage"}:
                owner = nxt
            break
        if owner is not None:
            owner.attached.append(index)
    return raw, spans


def span_extent(raw: bytes, span: SourceSpan, spans: list[SourceSpan]) -> tuple[int, int]:
    """Byte range of *span* including attached leading comments and a trailing newline."""
    start = span.start
    for index in span.attached:
        start = min(start, spans[index].start)
    end = span.end
    if raw.startswith(b"\r\n", end):
        end += 2
    elif raw.startswith(b"\n", end):
        end += 1
    return start, end
