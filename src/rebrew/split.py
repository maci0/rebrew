"""split.py – Split a multi-function C file into single-function files.

Reads a C translation unit containing multiple ``// FUNCTION:`` annotation
blocks and writes one output file per function, preserving the shared preamble
in every output file.  With ``--va``, a single function can be extracted into
its own file while the block is removed from the original source.

A migrated file has no marker block.  The same commands then resolve the
function through ``rebrew-functions.toml``, slice that C definition, and
retarget every row that shares it.  File-scope storage stays in the original.
"""

from __future__ import annotations

import os
import shutil
import unicodedata
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, TypedDict

import typer

from rebrew.annotation import (
    FUNCTION_MARKERS,
    NEW_FUNC_CAPTURE_RE,
    NEW_KV_RE,
    block_markers,
    parse_c_file_multi,
    split_annotation_sections,
)
from rebrew.c_parser import (
    extract_function_name_from_line,
    find_function_name_in_node,
    find_variable_roles,
    node_text,
    parse_c_source,
)
from rebrew.cli import (
    TargetOption,
    confirm_abort,
    console,
    error_exit,
    json_print,
    require_config,
)
from rebrew.metadata import (
    identity_file,
    load_metadata,
    record_migrated_markers,
    validate_identity_file,
)
from rebrew.sources import (
    iter_sources,
    source_exts,
    target_marker,
)
from rebrew.utils import (
    atomic_write_text,
    preset_module_key,
    read_source_text,
    rel_display_path,
    source_newline,
    split_source_lines,
    strip_comment_blocks,
)

app = typer.Typer(
    help="Split multi-function C files into single-function files.",
    rich_markup_mode="rich",
    epilog=(
        "[bold]Examples:[/bold]\n\n"
        "  rebrew source split src/game/funcs.c · · · · · · · · Split all functions into individual files\n\n"
        "  rebrew source split src/game/funcs.c --va 0x10003da0 · Extract one function by VA\n\n"
        "  rebrew source split src/game/funcs.c --dry-run · · · · Preview without writing files\n\n"
        "  rebrew source split src/game/funcs.c --output out · · Custom output directory\n\n"
        "  rebrew source split src/game/funcs.c --force · · · · · Overwrite existing output files\n\n"
        "[dim]Each output file gets the shared preamble (includes, typedefs) plus one function. "
        "With --va, the function is extracted and removed from the original source.[/dim]"
    ),
)


class _BlockMeta(TypedDict):
    """Metadata extracted from a single ``// FUNCTION:`` annotation block."""

    module: str
    va: int
    symbol: str


def _block_metadata(block: str) -> _BlockMeta | None:
    """Extract marker metadata and first annotation key-values for one block.

    Returns ``None`` when the block contains no recognisable
    ``// FUNCTION: <MODULE> 0x<VA>`` marker.
    """
    lines = split_source_lines(block)
    marker_idx: int | None = None
    marker_match = None
    for idx, line in enumerate(lines):
        m = NEW_FUNC_CAPTURE_RE.match(line.strip())
        if m:
            marker_idx = idx
            marker_match = m
            break

    if marker_idx is None or marker_match is None:
        return None

    kv: dict[str, str] = {}
    c_func_name = ""
    for line in lines[marker_idx + 1 :]:
        stripped = line.strip()
        if not stripped:
            continue
        kv_match = NEW_KV_RE.match(stripped)
        if kv_match:
            kv[kv_match.group("key").upper()] = kv_match.group("value").strip()
            continue
        if stripped.startswith("//"):
            continue
        # Try to extract function name from C definition (same regex as annotation.py).
        # Skip forward declarations (ending with ';').
        if not c_func_name and not stripped.rstrip().endswith(";"):
            func_result = extract_function_name_from_line(stripped)
            if func_result:
                c_func_name = func_result[0]
        break

    return _BlockMeta(
        module=marker_match.group("module"),
        va=int(marker_match.group("va"), 16),
        symbol=c_func_name,
    )


def _build_output_name(symbol: str, va: int, ext: str) -> str:
    """Generate output filename from the C name or a fallback VA.

    Callers pass the definition's identifier, so a leading ``_`` is part of
    the name. Stripping every ``_`` stored both ``_foo`` and ``__foo`` as
    ``foo.c``.
    """
    stem = unicodedata.normalize("NFC", symbol).strip()
    if not stem:
        stem = f"func_{va:08x}"
    # Sanitize: keep only ASCII filename-safe characters so a hostile symbol
    # (e.g. "../../x") cannot escape the output directory and non-ASCII
    # letters (NFC vs NFD spellings, DOS 8.3 toolchains) never reach a filename.
    stem = "".join(
        c if ((c.isascii() and c.isalnum()) or c in "_$?.-") else "_" for c in stem
    ).strip(".")
    if not stem:
        stem = f"func_{va:08x}"
    return f"{stem}{ext}"


# --- Marker-less split -------------------------------------------------------
# A pure-C file has no // FUNCTION: block.  Extents come from the tree-sitter
# spans of the original text, so the slice keeps the file's bytes, encoding,
# and newlines.  Storage definitions are not copied: a non-static object the
# extracted function uses becomes an extern, and a static or a preprocessor
# wrapped dependency is refused.

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


def _decode(raw: bytes, start: int, end: int) -> str:
    return raw[start:end].decode("utf-8", errors="surrogateescape")


def _gap_is_blank(raw: bytes, start: int, end: int) -> bool:
    return raw[start:end].strip(b" \t\r\n") == b""


def _outer_is_function(declarator: Any) -> bool:
    """True when *declarator* declares a function, not an object."""
    node = declarator
    if node is not None and node.type == "init_declarator":
        node = node.child_by_field_name("declarator")
    saw_object = False
    while node is not None:
        if node.type == "function_declarator" and not saw_object:
            return True
        # tree-sitter parses a bare `__cdecl` as ms_call_modifier and does
        # not link the function through the declarator field. The function
        # is the next named sibling.
        if node.type == "ms_call_modifier" and node.parent is not None:
            sibs = list(node.parent.named_children)
            idx = next((i for i, child in enumerate(sibs) if child.id == node.id), -1)
            nxt_fn = (
                next(
                    (child for child in sibs[idx + 1 :] if child.type == "function_declarator"),
                    None,
                )
                if idx >= 0
                else None
            )
            if nxt_fn is not None and not saw_object:
                return True
        # A calling convention between `*` and the name is an ERROR node.
        # tree-sitter then parses the return type as a pointer and the
        # function as its declarator. That pointer is not a pointer to a
        # function, so the function still wins.
        if (
            node.type == "pointer_declarator"
            and any(child.type == "ERROR" for child in node.named_children)
            and any(child.type == "function_declarator" for child in node.named_children)
        ):
            return True
        if node.type in {"pointer_declarator", "array_declarator"}:
            saw_object = True
        nxt = node.child_by_field_name("declarator")
        if nxt is None and node.type == "parenthesized_declarator":
            nxt = next((child for child in node.named_children), None)
        node = nxt
    return False


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
            nxt = next((child for child in node.named_children if child.type != "identifier"), None)
        node = nxt
    return None


def _extern_line(node: Any, raw: bytes) -> str | None:
    """``extern`` declaration text for one object definition, without its initializer."""
    declarators = node.children_by_field_name("declarator")
    objects = [item for item in declarators if not _outer_is_function(item)]
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
    if all(_outer_is_function(item) for item in declarators):
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
        if not _outer_is_function(item) and (name := _declarator_name(item, raw))
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
    if not name or node.has_error:
        return None
    compound = next((child for child in node.children if child.type == "compound_statement"), None)
    proto = ""
    if compound is not None:
        proto = " ".join(_decode(raw, node.start_byte, compound.start_byte).split())
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
        acc.append(SourceSpan(kind, node.start_byte, node.end_byte))
        return


def _source_spans(text: str) -> tuple[bytes, list[SourceSpan]]:
    raw = text.encode("utf-8", errors="surrogateescape")
    tree, _ = parse_c_source(raw)
    spans: list[SourceSpan] = []
    for child in tree.root_node.named_children:
        _collect_spans(child, raw, inside_pp=False, acc=spans)
    spans.sort(key=lambda span: span.start)
    for index, span in enumerate(spans):
        if span.kind != "comment":
            continue
        owner: SourceSpan | None = None
        cursor = span.end
        for nxt in spans[index + 1 :]:
            if not _gap_is_blank(raw, cursor, nxt.start):
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


def _extent(raw: bytes, span: SourceSpan, spans: list[SourceSpan]) -> tuple[int, int]:
    start = span.start
    for index in span.attached:
        start = min(start, spans[index].start)
    end = span.end
    if raw.startswith(b"\r\n", end):
        end += 2
    elif raw.startswith(b"\n", end):
        end += 1
    return start, end


def row_labels(entry: dict[str, Any]) -> set[str]:
    """Linker symbols and C names on one row.

    The symbol is also stored as its C name. ``hook@@12`` matches
    ``hook``, and ``__foo`` matches ``_foo``. Stripping one ``_`` from
    the name turned the C function ``_foo`` into ``foo``.
    """
    from rebrew.rename_ops import c_name_from_symbol

    names: set[str] = set()
    for key in ("symbol", "name"):
        value = str(entry.get(key) or "").strip()
        if value:
            names.add(value)
    symbol = str(entry.get("symbol") or "").strip()
    if symbol:
        c_name = c_name_from_symbol(symbol)
        if c_name:
            names.add(c_name)
    return names


def stored_file_matches(stored: str, rel: str) -> bool:
    """True when *stored* is *rel* or a path suffix of it."""
    stored = stored.replace("\\", "/")
    if not stored:
        return False
    parts = rel.split("/")
    return stored in {"/".join(parts[i:]) for i in range(len(parts))}


def _uses_at(text: str, line: int) -> tuple[set[str], set[str]]:
    """Names used by the function at *line*, and names also used by an initializer."""
    _, _, initializers = find_variable_roles(text, function_filter=lambda _line: False)
    _, _, combined = find_variable_roles(text, function_filter=lambda number: number == line)
    return combined - initializers, combined & initializers


def _file_borne(line: str) -> bool:
    body = line.strip()
    if body.startswith("//"):
        body = body[2:].strip()
    elif body.startswith("/*") and body.endswith("*/"):
        body = body[2:-2].strip()
    else:
        return False
    key, _, value = body.partition(":")
    key = key.strip().upper()
    if key in {"STRUCT", "CALLERS"}:
        return True
    return key == "SOURCE" and value.strip().upper() == "NAKED"


def _overlaps(start: int, end: int, extents: list[tuple[int, int]]) -> bool:
    return any(start < ext_end and end > ext_start for ext_start, ext_end in extents)


def _preamble_text(
    raw: bytes, spans: list[SourceSpan], extents: list[tuple[int, int]], *, sole: bool
) -> str:
    """Shared includes, macros, typedefs, and externs, in source order.

    Comments attached to a function or object stay with that owner.  A
    file-level naked, struct, or callers fence is copied only when the file
    has one function, so a second function does not inherit it.
    """
    attached = {index for span in spans for index in span.attached}
    copyable = [
        span
        for index, span in enumerate(spans)
        if span.kind == "preamble" or (span.kind == "comment" and index not in attached)
    ]
    pieces: list[str] = []
    for index, span in enumerate(copyable):
        end = span.end
        following = next((item.start for item in spans if item.start >= span.end), len(raw))
        nxt = copyable[index + 1].start if index + 1 < len(copyable) else following
        boundary = min(nxt, following)
        if _gap_is_blank(raw, end, boundary):
            end = boundary
        if _overlaps(span.start, end, extents):
            continue
        pieces.append(_decode(raw, span.start, end))
    text = "".join(pieces)
    if sole:
        return text
    return "".join(line for line in text.splitlines(keepends=True) if not _file_borne(line))


def source_layout(text: str) -> tuple[bytes, list[SourceSpan]]:
    """Top-level spans of *text*, in source order.

    Span offsets are into the UTF-8 encoding of *text* (surrogateescape).
    """
    return _source_spans(text)


def span_extent(raw: bytes, span: SourceSpan, spans: list[SourceSpan]) -> tuple[int, int]:
    """Byte range of *span*, including a comment attached above it and one trailing newline."""
    return _extent(raw, span, spans)


def shared_preamble(
    raw: bytes,
    spans: list[SourceSpan],
    extents: list[tuple[int, int]],
    *,
    sole: bool,
) -> str:
    """Includes, macros, typedefs, and externs that are not part of *extents*."""
    return _preamble_text(raw, spans, extents, sole=sole)


def _matching_rows(
    entries: dict[tuple[str, int], dict[str, Any]],
    rel: str,
    definition: str,
) -> list[tuple[str, int, dict[str, Any]]]:
    rows: list[tuple[str, int, dict[str, Any]]] = []
    for (module, va), entry in entries.items():
        marker = str(entry.get("marker_type") or "FUNCTION")
        if marker not in FUNCTION_MARKERS:
            continue
        if not stored_file_matches(str(entry.get("file") or ""), rel):
            continue
        if definition not in row_labels(entry):
            continue
        rows.append((module, va, entry))
    return rows


def _split_markerless(
    *,
    cfg: Any,
    source_path: Path,
    text: str,
    encoding: str,
    va: str | None,
    output_dir: str | None,
    dry_run: bool,
    force: bool,
    json_output: bool,
    out_ext: str,
) -> None:
    """Split a pure-C file from its function rows.  ``error_exit`` does not return."""
    meta = getattr(cfg, "metadata_dir", None)
    if meta is None:
        error_exit("No metadata directory configured", json_mode=json_output)
    rel = os.path.relpath(source_path, meta).replace(os.sep, "/")
    try:
        raw, spans = _source_spans(text)
    except ImportError as exc:
        error_exit(str(exc), json_mode=json_output)
    functions = [span for span in spans if span.kind == "function"]
    stores = [span for span in spans if span.kind == "storage"]
    entries = load_metadata(meta)
    eol = source_newline(text)

    selected: list[SourceSpan]
    requested: int | None = None
    if va is not None:
        va_cleaned = va.removeprefix("0x").removeprefix("0X")
        try:
            target_va = int(va_cleaned, 16)
        except ValueError:
            error_exit(f"Invalid VA (must be hex): {va}", json_mode=json_output)
        marker = preset_module_key(cfg.marker) if cfg.marker else ""
        matched = [
            (module, row_va, entry)
            for (module, row_va), entry in entries.items()
            if row_va == target_va
            and (not marker or preset_module_key(module) == marker)
            and str(entry.get("marker_type") or "FUNCTION") in FUNCTION_MARKERS
        ]
        if not matched:
            error_exit(
                f"No function row for VA 0x{target_va:08x} in {source_path.name}",
                json_mode=json_output,
            )
        if len(matched) > 1:
            error_exit(
                f"Ambiguous function row for VA 0x{target_va:08x}",
                json_mode=json_output,
            )
        _module, _row_va, entry = matched[0]
        requested = target_va
        if not stored_file_matches(str(entry.get("file") or ""), rel):
            error_exit(
                f"Function row 0x{target_va:08x} names {entry.get('file') or 'no file'}, not {rel}",
                json_mode=json_output,
            )
        names = row_labels(entry)
        found = [span for span in functions if span.name in names]
        if not found:
            error_exit(
                f"No C definition for VA 0x{target_va:08x} in {source_path.name}",
                json_mode=json_output,
            )
        if len(found) > 1 or len(names & {span.name for span in functions}) > 1:
            error_exit(
                f"Ambiguous C definition for VA 0x{target_va:08x} in {source_path.name}",
                json_mode=json_output,
            )
        selected = found
    else:
        grouped: list[SourceSpan] = []
        marker = preset_module_key(cfg.marker) if cfg.marker else ""
        for span in functions:
            rows = [
                row
                for row in _matching_rows(entries, rel, span.name)
                if not marker or preset_module_key(row[0]) == marker
            ]
            if rows:
                grouped.append(span)
        if len(grouped) < 2:
            error_exit(
                "Input must contain at least two // FUNCTION: blocks to split, "
                "or two function rows for this file. "
                "Use --va to extract a single function instead.",
                json_mode=json_output,
            )
        selected = grouped

    extents = {id(span): _extent(raw, span, spans) for span in selected}
    problems: list[str] = []
    for span in selected:
        if span.inside_pp or not span.proto:
            problems.append(f"{span.name} is inside a preprocessor conditional or did not parse")
            continue
        line = raw.count(b"\n", 0, span.start) + 1
        direct, leaked = _uses_at(text, line)
        watched = {item.name for item in functions} | {item.name for item in stores if item.name}
        if leaked & watched:
            problems.append(
                f"{span.name} has an uncertain reference ({', '.join(sorted(leaked & watched))})"
            )
        for other in functions:
            if other is span:
                continue
            if other.static and other.name in direct:
                problems.append(f"{span.name} depends on static {other.name}")
            if span.static and span.name in _uses_at(text, raw.count(b"\n", 0, other.start) + 1)[0]:
                problems.append(f"static {span.name} is used by {other.name}")
        for store in stores:
            if store.name not in direct:
                continue
            if store.static or store.inside_pp or not store.extern_line:
                problems.append(
                    f"{span.name} depends on {store.name}, which stays in {source_path.name}"
                )
    if problems:
        error_exit(problems[0], json_mode=json_output)

    out_parent = Path(output_dir).resolve() if output_dir else source_path.parent.resolve()
    plans: list[dict[str, Any]] = []
    seen_paths: dict[Path, str] = {}
    claimed: dict[tuple[str, int], str] = {}
    for span in selected:
        rows = _matching_rows(entries, rel, span.name)
        if requested is not None:
            rows.sort(key=lambda item: item[1] != requested)
        if not rows:
            error_exit(
                f"No function row for {span.name} in {source_path.name}", json_mode=json_output
            )
        own_va = rows[0][1]
        out_name = _build_output_name(span.name, own_va, out_ext)
        if va is not None and output_dir is None:
            stem = source_path.stem + source_path.suffix.replace(".", "_")
            dest_dir = source_path.parent / stem
        else:
            dest_dir = out_parent
        out_path = dest_dir / out_name
        if out_path.resolve() == source_path.resolve():
            error_exit(f"Output path is the source file: {out_path}", json_mode=json_output)
        prior = seen_paths.get(out_path)
        if prior is not None:
            error_exit(
                f"Duplicate output filename '{out_name}': {prior} and {span.name} "
                "both map to it. Nothing was written.",
                json_mode=json_output,
            )
        seen_paths[out_path] = span.name
        for module, row_va, _entry in rows:
            previous = claimed.get((module, row_va))
            if previous is not None:
                error_exit(
                    f"Row {module}.0x{row_va:08x} matches {previous} and {span.name}. "
                    "Nothing was written.",
                    json_mode=json_output,
                )
            claimed[(module, row_va)] = span.name
        try:
            new_file = validate_identity_file(identity_file(out_path, meta))
        except ValueError as exc:
            error_exit(str(exc), json_mode=json_output)
        plans.append(
            {"span": span, "rows": rows, "path": out_path, "file": new_file, "dir": dest_dir}
        )

    conflicts = [plan["path"] for plan in plans if not force and plan["path"].exists()]
    if conflicts:
        error_exit(
            f"Output file already exists: {conflicts[0]} "
            f"({len(conflicts)} conflict(s) total, nothing was written; "
            "re-run with --force to overwrite)",
            json_mode=json_output,
        )

    sole = len(functions) == 1
    preamble = _preamble_text(raw, spans, list(extents.values()), sole=sole)
    rendered: list[tuple[dict[str, Any], str]] = []
    for plan in plans:
        span = plan["span"]
        direct, _leaked = _uses_at(text, raw.count(b"\n", 0, span.start) + 1)
        extras: list[str] = []
        for store in stores:
            if store.name in direct and store.extern_line:
                extras.append(store.extern_line)
        for other in functions:
            if other is span or other.name not in direct or not other.proto:
                continue
            proto = other.proto.strip()
            if proto.startswith("static"):
                continue
            if not proto.endswith(";"):
                proto += ";"
            extras.append(proto)
        start, end = extents[id(span)]
        body = _decode(raw, start, end)
        parts = [preamble]
        if extras:
            if parts[-1] and not parts[-1].endswith(("\n", "\r")):
                parts.append(eol)
            parts.append(eol.join(extras) + eol)
        if parts[-1] and not parts[-1].endswith("\n"):
            parts.append(eol)
        parts.append(body)
        content = "".join(parts)
        if not content.endswith("\n"):
            content += eol
        rendered.append((plan, content))

    remove_ranges = [extents[id(plan["span"])] for plan in plans]
    remainder_raw = raw
    for start, end in sorted(remove_ranges, reverse=True):
        remainder_raw = remainder_raw[:start] + remainder_raw[end:]
    remainder = remainder_raw.decode("utf-8", errors="surrogateescape")
    leftover_functions = [span for span in functions if id(span) not in extents]
    drop_source = not leftover_functions and not stores

    files_json = []
    for plan, _content in rendered:
        files_json.append(
            {
                "source": rel_display_path(source_path, cfg.reversed_dir),
                "va": f"0x{plan['rows'][0][1]:08x}",
                "symbol": plan["span"].name,
                "output": rel_display_path(plan["path"], plan["dir"]),
                "retargeted": [
                    f"{module}.0x{row_va:08x}" for module, row_va, _entry in plan["rows"]
                ],
            }
        )

    if not dry_run and not force:
        if json_output:
            error_exit(
                "Split removes the extracted function from the source file. "
                "Pass --force to apply it in --json mode, or use --dry-run to preview.",
                json_mode=True,
            )
        confirm_abort(
            f"Split will remove {len(selected)} function(s) from {source_path.name}. Continue?"
        )

    if not dry_run:
        created: list[Path] = []
        source_bytes = source_path.read_bytes()
        bak_path = source_path.with_suffix(source_path.suffix + ".bak")
        bak_created = False
        try:
            for plan, content in rendered:
                plan["dir"].mkdir(parents=True, exist_ok=True)
                atomic_write_text(plan["path"], content, encoding=encoding)
                created.append(plan["path"])
            if drop_source:
                if not bak_path.exists():
                    shutil.copy2(source_path, bak_path)
                    bak_created = True
                source_path.unlink()
                if not json_output:
                    console.print(
                        f"  [dim]Backed up {source_path.name} → {bak_path.name} "
                        "(no remaining functions)[/dim]"
                    )
            else:
                atomic_write_text(source_path, remainder, encoding=encoding)
            identity_rows = [
                {"module": module, "va": row_va, "identity": {"file": plan["file"]}}
                for plan, _content in rendered
                for module, row_va, _entry in plan["rows"]
            ]
            record_migrated_markers(meta, identity_rows)
        except Exception as exc:
            if bak_created:
                bak_path.unlink(missing_ok=True)
            source_path.write_bytes(source_bytes)
            for path in created:
                path.unlink(missing_ok=True)
            error_exit(
                f"Split did not finish ({exc}). The source was restored.",
                json_mode=json_output,
            )

    if json_output:
        json_print(
            {
                "source": str(source_path),
                "output_dir": str(rendered[0][0]["dir"] if rendered else out_parent),
                "count": len(rendered),
                "dry_run": dry_run,
                "files": files_json,
            }
        )
        return

    action = "Would split" if dry_run else "Split"
    console.print(
        f"[bold green]{action}[/] [bold]{len(rendered)}[/] function(s) from {source_path.name}"
    )
    for item in files_json:
        console.print(f"  {item['output']} ← [cyan]{item['va']}[/] {item['symbol']}")


@app.callback(invoke_without_command=True)
def main(
    source: str | None = typer.Argument(None, help="Path to a multi-function source file"),
    va: str | None = typer.Option(
        None, "--va", help="Extract a single function by VA (hex) into its own file"
    ),
    output_dir: str | None = typer.Option(None, "--output", "-o", help="Output directory"),
    dry_run: bool = typer.Option(False, "--dry-run", help="Preview changes without writing"),
    force: bool = typer.Option(
        False,
        "--force",
        help="Overwrite existing output files; also skips the --va extraction prompt",
    ),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
    target: str | None = TargetOption,
) -> None:
    """Split a multi-function C file into one file per function block.

    With --va, extract a single function into its own file (preamble included).
    Without --va, split ALL functions into individual files.
    """
    if source is None:
        error_exit("Source file argument is required", json_mode=json_output)

    cfg = require_config(target=target, json_mode=json_output)
    source_path = Path(source)
    if not source_path.exists() or not source_path.is_file():
        error_exit(f"Source file not found: {source_path}", json_mode=json_output)

    expected_exts = set(source_exts(cfg)) or {".c"}
    # iter_sources matches extensions case-insensitively (FOO.C counts as .c,
    # documented), so the explicit-file check must too.
    if source_path.suffix.lower() not in {e.lower() for e in expected_exts}:
        error_exit(
            f"Source must match configured extension(s) '{','.join(sorted(expected_exts))}': {source_path.name}",
            json_mode=json_output,
        )

    out_dir = Path(output_dir).resolve() if output_dir else source_path.parent.resolve()
    # One extension for the output name: ``cfg.source_ext`` may be a
    # comma-separated list (".c,.cpp"), and the split piece belongs to the same
    # language as its source file, so the input's own suffix is kept.
    exts = source_exts(cfg) or [".c"]
    out_ext = source_path.suffix or exts[0]

    try:
        text, encoding = read_source_text(source_path)
    except OSError as exc:
        error_exit(f"Failed to read source: {exc}", json_mode=json_output)

    preamble, blocks = split_annotation_sections(text)
    if not blocks:
        _split_markerless(
            cfg=cfg,
            source_path=source_path,
            text=text,
            encoding=encoding,
            va=va,
            output_dir=output_dir,
            dry_run=dry_run,
            force=force,
            json_output=json_output,
            out_ext=out_ext,
        )
        return

    # --va mode: extract a single function block
    if va is not None:
        va_cleaned = va.removeprefix("0x").removeprefix("0X")
        try:
            target_va = int(va_cleaned, 16)
        except ValueError:
            error_exit(f"Invalid VA (must be hex): {va}", json_mode=json_output)

        matched_block: str | None = None
        matched_meta: _BlockMeta | None = None
        matched_idx: int | None = None
        for idx, block in enumerate(blocks):
            meta = _block_metadata(block)
            if meta is None:
                continue
            # A stacked shared block carries one marker per target: match
            # when ANY marker names this target at the requested VA (the
            # first marker is whichever was stacked last, not this target).
            markers = block_markers(block) or [(meta["module"], meta["va"])]
            hit = any(
                (not cfg.marker or preset_module_key(mod) == preset_module_key(cfg.marker))
                and va == target_va
                for mod, va in markers
            )
            if not hit:
                continue
            matched_block = block
            matched_meta = meta
            matched_idx = idx
            break

        if matched_block is None or matched_meta is None or matched_idx is None:
            error_exit(
                f"No function block found for VA 0x{target_va:08x} in {source_path.name}",
                json_mode=json_output,
            )

        symbol = matched_meta["symbol"]
        out_name = _build_output_name(symbol, target_va, out_ext)
        # Default to a subdirectory named after the source file: sim.c -> sim_c/
        if output_dir is None:
            stem = source_path.stem + source_path.suffix.replace(".", "_")
            va_out_dir = source_path.parent / stem
        else:
            va_out_dir = Path(output_dir)
        out_path = va_out_dir / out_name

        if not force and out_path.exists():
            error_exit(f"Output file already exists: {out_path}", json_mode=json_output)

        result_info = {
            "source": rel_display_path(source_path, cfg.reversed_dir),
            "va": f"0x{target_va:08x}",
            "symbol": symbol,
            "output": rel_display_path(out_path, va_out_dir),
        }

        if not dry_run and not force:
            if json_output:
                error_exit(
                    "--va removes the extracted block from the source file. "
                    "Pass --force to apply it in --json mode, or use --dry-run to preview.",
                    json_mode=True,
                )
            confirm_abort(
                f"Extract will remove 0x{target_va:08x} from {source_path.name}. Continue?"
            )

        if not dry_run:
            va_out_dir.mkdir(parents=True, exist_ok=True)
            out_preamble = strip_comment_blocks(preamble)
            # strip_comment_blocks removes the trailing newline; re-add a
            # separator so the marker is not glued onto the last preamble line,
            # in the source's own line ending (a hardcoded "\n" left a CRLF
            # source with mixed endings).
            eol = source_newline(preamble + matched_block)
            out_content = out_preamble + eol + matched_block if out_preamble else matched_block
            atomic_write_text(out_path, out_content, encoding=encoding)
            try:
                # Remove the extracted block from the source file (by index,
                # not identity)
                remaining = [b for i, b in enumerate(blocks) if i != matched_idx]
                if remaining:
                    atomic_write_text(source_path, preamble + "".join(remaining), encoding=encoding)
                else:
                    # Back up the original before removing (recoverable via .bak).
                    # Only when absent: a retry after a partial failure, or a
                    # later extract that again empties the source, must not
                    # overwrite the first-run stub/source backup (same rule as
                    # match_batch.update_stub_to_matched).
                    bak_path = source_path.with_suffix(source_path.suffix + ".bak")
                    if not bak_path.exists():
                        shutil.copy2(source_path, bak_path)
                    source_path.unlink()
                    if not json_output:
                        console.print(
                            f"  [dim]Backed up {source_path.name} → {bak_path.name} "
                            f"(no remaining functions)[/dim]"
                        )
            except Exception:
                # The output file was already written; roll it back so a
                # failed split leaves no half-applied artifact behind and a
                # re-run starts clean (the source still holds the block).
                import contextlib

                with contextlib.suppress(OSError):
                    out_path.unlink()
                raise

        if json_output:
            json_print(
                {
                    "source": str(source_path),
                    "output_dir": str(va_out_dir),
                    "count": 1,
                    "dry_run": dry_run,
                    "files": [result_info],
                }
            )
        else:
            action = "Would extract" if dry_run else "Extracted"
            console.print(
                f"[bold green]{action}[/] 0x{target_va:08x} ({symbol or 'unnamed'}) → {out_path.name}"
            )
        return

    # Full split mode: split ALL functions into individual files
    if len(blocks) < 2:
        error_exit(
            "Input must contain at least two // FUNCTION: blocks to split. "
            "Use --va to extract a single function instead.",
            json_mode=json_output,
        )

    entries = parse_c_file_multi(
        source_path, target_name=target_marker(cfg), metadata_dir=cfg.metadata_dir
    )
    if len(entries) < 2:
        error_exit(
            f"No splittable blocks found for target '{cfg.marker}'",
            json_mode=json_output,
        )

    existing_sources = set(iter_sources(out_dir, cfg)) if out_dir.exists() else set()
    planned: list[dict[str, str]] = []
    # (block_text, out_path) for phase 2 — only blocks that passed the
    # module filter and are not pre-existing.
    to_write: list[tuple[str, Path]] = []
    split_count = 0
    # Phase 1 — validate EVERY output path before writing ANY file.  The old
    # interleaved check-then-write aborted mid-batch on the first existing
    # output, leaving blocks 1..N-1 written — and every re-run then failed on
    # block 1's now-existing file, so the split could never complete without
    # --force (renaming/overwriting).  Two-phase: report every conflict up
    # front, write nothing on any conflict (rename.py's pattern).
    conflicts: list[Path] = []
    planned_paths: dict[Path, int] = {}
    for block in blocks:
        meta = _block_metadata(block)
        if meta is None:
            continue
        if cfg.marker and preset_module_key(meta["module"]) != preset_module_key(cfg.marker):
            continue

        block_va = meta["va"]
        symbol = meta["symbol"]
        out_name = _build_output_name(symbol, block_va, out_ext)
        out_path = out_dir / out_name

        # Two blocks can sanitize to the same filename (same C name after
        # sanitization); writing both would silently destroy the first.
        prior_va = planned_paths.get(out_path)
        if prior_va is not None:
            error_exit(
                f"Duplicate output filename '{out_name}': VAs 0x{prior_va:08x} and "
                f"0x{block_va:08x} both map to it — nothing was written. Fix the "
                "duplicate annotation first (lint E013) or extract one block via --va.",
                json_mode=json_output,
            )
        planned_paths[out_path] = block_va

        if not force and (out_path.exists() or out_path in existing_sources):
            conflicts.append(out_path)
            continue

        planned.append(
            {
                "source": rel_display_path(source_path, cfg.reversed_dir),
                "va": f"0x{block_va:08x}",
                "symbol": symbol,
                "output": rel_display_path(out_path, out_dir),
            }
        )
        to_write.append((block, out_path))
        split_count += 1

    if conflicts:
        error_exit(
            f"Output file already exists: {conflicts[0]} "
            f"({len(conflicts)} conflict(s) total — nothing was written; "
            f"re-run with --force to overwrite)",
            json_mode=json_output,
        )

    if split_count < 2:
        error_exit(
            f"Need at least two matching blocks for target '{cfg.marker}' to split",
            json_mode=json_output,
        )

    # Phase 2 — all paths validated: write every block.
    if not dry_run and to_write:
        out_dir.mkdir(parents=True, exist_ok=True)
        out_preamble = strip_comment_blocks(preamble)
        eol = source_newline(preamble)
        for block, out_path in to_write:
            out_content = out_preamble + eol + block if out_preamble else block
            atomic_write_text(out_path, out_content, encoding=encoding)

    if json_output:
        json_print(
            {
                "source": str(source_path),
                "output_dir": str(out_dir),
                "count": split_count,
                "dry_run": dry_run,
                "files": planned,
            }
        )
        return

    action = "Would split" if dry_run else "Split"
    console.print(
        f"{action} [bold]{split_count}[/] functions from {source_path.name} into {split_count} files"
    )
    for item in planned:
        console.print(f"  {item['output']} ← [cyan]{item['va']}[/]")


def main_entry() -> None:
    """Run the Typer CLI application."""
    from rebrew.cli import run_standalone

    run_standalone(main)


if __name__ == "__main__":
    main_entry()
