"""merge.py - Merge single-function C files into one multi-function file.

Combines multiple source files into a single compilation unit, deduplicating
preamble lines and sorting function definitions by virtual address.

With ``--shared``, twin files (same body, different target modules — the
per-target copies ``source import-related`` makes) collapse into one
stacked block per body (one ``/* ADDRESS: <module> <va> */`` anchor per
target, ADR-022): the migration path from N copies to one shared file.  Bodies
that differ between targets are refused, never averaged.

The command reads each function row, copies that C definition and its
file-scope objects into the output, and retargets every row that names an
input.  ``--dry-run`` writes nothing.
"""

import re
from dataclasses import dataclass, field
lazy import hashlib
lazy import json
lazy from collections.abc import Callable
lazy from pathlib import Path
lazy from typing import Any

import typer
from typer.models import TyperPath

from rebrew.cli import (
    EXPECTED_DIGEST_HELP,
    TargetOption,
    confirm_abort,
    console,
    error_exit,
    json_print,
    require_config,
)
lazy from rebrew import source_paths
lazy from rebrew.c_parser import CALLING_CONVENTION
lazy from rebrew.config import ProjectConfig
lazy from rebrew.metadata.anchors import add_address_anchor, parse_address_anchors
lazy from rebrew.metadata.bindings import (
    FUNCTION_KINDS,
)
lazy from rebrew.metadata.data import load_data_metadata, record_data_rows
lazy from rebrew.metadata.functions import (
    identity_file,
    load_metadata,
    record_function_rows,
    stored_file_matches,
    validate_identity_file,
)
lazy from rebrew.sources import (
    iter_sources,
    source_exts,
)
lazy from rebrew.split import (
    SourceSpan,
    row_labels,
    shared_preamble,
    source_layout,
    span_extent,
)
lazy from rebrew.utils import (
    atomic_write_bytes,
    atomic_write_text,
    preset_module_key,
    read_source_text,
    rel_display_path,
    source_newline,
    split_source_lines,
    strip_comment_blocks,
)

app = typer.Typer(
    help="Merge single-function C files into one multi-function file.",
    rich_markup_mode="rich",
    epilog=(
        "[bold]Examples:[/bold]\n\n"
        "  # Merge two files\n"
        "  rebrew source merge src/game/func1.c src/game/func2.c --output merged.c\n\n"
        "  # Merge entire directory\n"
        "  rebrew source merge src/game/ --output all_funcs.c\n\n"
        "  # Merge and delete originals\n"
        "  rebrew source merge src/game/ --output merged.c --delete\n\n"
        "  # Hoist declarations to the top\n"
        "  rebrew source merge src/game/ --output merged.c --consolidate\n\n"
        "[dim]Shared preambles (includes, typedefs) are deduplicated. Optional address anchors follow their declarations. Definitions are selected through canonical metadata.[/dim]"
    ),
)

# ---------------------------------------------------------------------------
# --consolidate: hoist/deduplicate declarations in a merged TU
# ---------------------------------------------------------------------------

_INCLUDE_RE = re.compile(r"^\s*#\s*include\s+")
_EXTERN_RE = re.compile(r"^\s*extern\s+")
_TYPEDEF_RE = re.compile(r"^\s*typedef\s+")
_PRAGMA_INTRINSIC_RE = re.compile(r"^\s*#\s*pragma\s+intrinsic\s*\(")
_BLOCK_COMMENT_RE = re.compile(r"/\*.*?\*/")
_LINE_COMMENT_RE = re.compile(r"//.*")
_EXTERN_NAME_PAREN_RE = re.compile(
    r"\(\s*" + CALLING_CONVENTION + r"\*+\s*(?:(?:const|volatile)\b\s*)*(\w+)"
)
_EXTERN_NAME_BRACKET_RE = re.compile(r"(\w+)\s*[\[\(]")
_EXTERN_NAME_TAIL_RE = re.compile(r"(\w+)\s*$")
_ARG_NAME_RE = re.compile(r"\b[a-z_]\w*(?=\s*[,)])")
_INTRINSIC_ARGS_RE = re.compile(r"intrinsic\s*\(([^)]+)\)")


def _extract_extern_name(decl: str) -> str | None:
    """The symbol name from an extern declaration."""
    d = decl.strip().rstrip(";").strip()
    d = _BLOCK_COMMENT_RE.sub("", d).strip()
    # ``int (*fp)(void)``, ``int (* const rows[2])[4]``, ``char (__cdecl *row)[4]``.
    # The convention and qualifier are not the symbol. Tested before the plain
    # declarator rule or the base type matches instead of the symbol.
    m = _EXTERN_NAME_PAREN_RE.search(d)
    if m:
        return m.group(1)
    m = _EXTERN_NAME_BRACKET_RE.search(d)
    if m:
        return m.group(1)
    m = _EXTERN_NAME_TAIL_RE.search(d)
    return m.group(1) if m else None


def _extern_specificity(decl: str) -> int:
    """Higher = more specific/better declaration when conflicts exist."""
    score = 0
    for pat in ("void*", "void *", "char*", "char *", "short*", "short *"):
        if pat in decl:
            score += 2
    if "unsigned" in decl:
        score += 1
    score += len(_ARG_NAME_RE.findall(decl)) * 3
    if "..." in decl:
        score += 5
    if "struct" in decl:
        score += 2
    if "const" in decl:
        score += 1
    return score


@dataclass
class ExternReport:
    """Outcome of :func:`_resolve_externs`: kept decls plus dropped/conflicting evidence."""

    resolved: list[str] = field(default_factory=list)
    dropped: list[str] = field(default_factory=list)
    conflicts: dict[str, list[str]] = field(default_factory=dict)


def _resolve_externs(externs: list[str]) -> ExternReport:
    """Deduplicate externs, keeping the most specific declaration per symbol.

    Unparseable lines are dropped (reported in ``dropped``); distinct
    spellings for one symbol resolve by specificity (reported in
    ``conflicts``).  Callers warn on both so a lost ``extern`` never merges
    silently.
    """
    by_name: dict[str, list[str]] = {}
    order: list[str] = []
    dropped: list[str] = []
    for ext in externs:
        name = _extract_extern_name(ext)
        if name is None:
            dropped.append(ext)
            continue
        if name not in by_name:
            order.append(name)
        by_name.setdefault(name, []).append(ext)
    out: list[str] = []
    conflicts: dict[str, list[str]] = {}
    for name in order:
        unique = list(dict.fromkeys(by_name[name]))
        if len(unique) > 1:
            conflicts[name] = unique
        out.append(max(unique, key=_extern_specificity) if len(unique) > 1 else unique[0])
    return ExternReport(resolved=out, dropped=dropped, conflicts=conflicts)


def _pragma_funcs(pragmas: list[str]) -> set[str]:
    funcs: set[str] = set()
    for p in pragmas:
        m = _INTRINSIC_ARGS_RE.search(p)
        if m:
            funcs.update(f.strip() for f in m.group(1).split(",") if f.strip())
    return funcs


def _ends_declaration(line: str) -> bool:
    """True if *line*'s code portion (comments stripped) ends a ``;``-terminated declaration."""
    code = _BLOCK_COMMENT_RE.sub("", line)
    code = _LINE_COMMENT_RE.sub("", code)
    return code.rstrip().endswith(";")


def consolidate_declarations(text: str, *, syntax: Any = None) -> tuple[str, ExternReport]:
    """Hoist unique includes/externs/typedefs/intrinsics to the top of *text*.

    Each merged function block carries its own declarations, which conflict
    when compiled as a single TU.  The pass moves unique declarations to a
    header, resolves conflicting extern signatures by specificity, merges
    ``#pragma intrinsic`` lists, and strips the moved lines from the bodies.
    Also drops the legacy ``#include "rebrew_types.h"`` (the file no longer
    exists).  Returns ``(merged_text, extern_report)`` so callers can warn on
    dropped or conflicting externs instead of losing them silently.
    """
    lines = text.splitlines(keepends=True)
    includes: list[str] = []
    externs: list[str] = []
    typedefs: list[str] = []
    pragmas: list[str] = []
    from rebrew.metadata.anchors import parse_address_anchors

    address_bound_lines = {
        a.definition_line - 1
        for a in parse_address_anchors(text, syntax=syntax)
        if a.kind == "DATA"
    }
    lines_to_remove: set[int] = set()

    i = 0
    while i < len(lines):
        stripped = lines[i].strip()
        if stripped == '#include "rebrew_types.h"':
            lines_to_remove.add(i)
        elif _INCLUDE_RE.match(stripped):
            includes.append(stripped)
            lines_to_remove.add(i)
        elif _EXTERN_RE.match(stripped):
            # Keep declaration-bound data addresses attached to their declaration.
            if i in address_bound_lines:
                i += 1
                continue
            # An extern can span lines (`extern int f(int a,` / `int b);`).
            # Taking only the first line drops its newline, so the next
            # declaration glues onto it. Consume through the semicolon.
            chunk = [lines[i]]
            j = i
            while not _ends_declaration(chunk[-1]):
                j += 1
                if j >= len(lines) or lines[j].lstrip().startswith("#"):
                    break
                chunk.append(lines[j])
            if _ends_declaration(chunk[-1]):
                externs.append(" ".join(part.strip() for part in chunk))
                lines_to_remove.update(range(i, j + 1))
                i = j
            else:
                externs.append(stripped)
                lines_to_remove.add(i)
        elif _TYPEDEF_RE.match(stripped):
            # hoist multi-line typedefs (``typedef struct {...} X_t;``) whole:
            # consume until braces balance and the closing semicolon appears,
            # else leave them in place
            chunk = [lines[i]]
            j = i
            depth = stripped.count("{") - stripped.count("}")
            while depth > 0 or not _ends_declaration(chunk[-1]):
                j += 1
                if j >= len(lines):
                    break
                chunk.append(lines[j])
                s2 = lines[j].strip()
                depth += s2.count("{") - s2.count("}")
            if depth == 0 and _ends_declaration(chunk[-1]):
                typedefs.append("".join(chunk).strip())
                lines_to_remove.update(range(i, j + 1))
                i = j
        elif _PRAGMA_INTRINSIC_RE.match(stripped):
            pragmas.append(stripped)
            lines_to_remove.add(i)
        i += 1

    header: list[str] = []
    uniq_includes = [inc for inc in dict.fromkeys(includes) if "rebrew_types" not in inc]
    if uniq_includes:
        header += [inc + "\n" for inc in uniq_includes] + ["\n"]
    if typedefs:
        header += [td + "\n" for td in dict.fromkeys(typedefs)] + ["\n"]
    funcs = _pragma_funcs(pragmas)
    if funcs:
        header.append("#pragma intrinsic(" + ", ".join(sorted(funcs)) + ")\n\n")
    report = _resolve_externs(externs)
    if report.resolved:
        header += [(ext if ext.endswith(";") else ext + ";") + "\n" for ext in report.resolved]
        header.append("\n")

    body_lines: list[str] = []
    prev_blank = False
    for i, line in enumerate(lines):
        if i in lines_to_remove:
            continue
        stripped = line.strip()
        if not stripped:
            if prev_blank:
                continue
            prev_blank = True
        else:
            prev_blank = False
        body_lines.append(line)
    while body_lines and body_lines[0].strip() == "":
        body_lines.pop(0)

    out = "".join(header) + "".join(body_lines)
    if not out.endswith("\n"):
        out += "\n"
    return out, report


def normalize_body(block: str, *, syntax: Any = None) -> str:
    """The same C body across targets, excluding only its address anchors."""
    removed = {a.line for a in parse_address_anchors(block, syntax=syntax)}
    return "\n".join(
        line.rstrip() for i, line in enumerate(block.splitlines(), 1) if i not in removed
    ).strip()


def block_metadata(block: str, *, syntax: Any = None) -> dict[str, Any] | None:
    """The first address group in a declaration-bound block."""
    anchors = parse_address_anchors(block, syntax=syntax)
    return {"module": anchors[0].module, "va": anchors[0].va} if anchors else None


def merge_preambles(preambles: list[str]) -> str:
    """Merge preambles with include-line dedup and collapsed blank lines.

    Comment blocks (e.g. Ghidra decompilation references) are stripped before
    merging: they are per-function noise, and a naive union of multiple
    preambles leaves the ``/* */`` nesting malformed so the merged file does
    not compile (C2143 on orphaned comment lines).

    Deduplicate includes, externs, complete one-line typedefs and intrinsics.
    Multiline typedef openings must stay: identical opening lines can begin
    different declarations. The compiler arbitrates conflicting declarations.
    """
    seen_decl: set[str] = set()
    merged_lines: list[str] = []

    for preamble in preambles:
        for line in split_source_lines(strip_comment_blocks(preamble)):
            if not line.strip():
                if merged_lines and merged_lines[-1]:
                    merged_lines.append("")
                continue
            if (
                _INCLUDE_RE.match(line)
                or _EXTERN_RE.match(line)
                or (
                    _TYPEDEF_RE.match(line)
                    and line.rstrip().endswith(";")
                    and line.count("{") == line.count("}")
                )
                or _PRAGMA_INTRINSIC_RE.match(line)
            ):
                if line in seen_decl:
                    continue
                seen_decl.add(line)
            merged_lines.append(line)

    while merged_lines and not merged_lines[-1]:
        merged_lines.pop()

    if not merged_lines:
        return ""
    return "\n".join(merged_lines) + "\n\n"


def _collect_input_files(
    paths: list[str], cfg: ProjectConfig, exclude: Path | None = None
) -> list[Path]:
    """Resolve input arguments into unique source-file paths.

    *exclude* (the merge output) is skipped when a directory argument finds it:
    a directory that already contains a previous merge output would otherwise
    feed it back in as an input, so ``--force`` re-runs failed with a
    duplicate-VA error. A file named explicitly is kept even when it is the
    output: that is an in-place merge of other files into it.
    """
    expected_exts = set(source_exts(cfg)) or {".c"}
    lowered_exts = {e.lower() for e in expected_exts}
    resolved_exclude = exclude.resolve() if exclude is not None else None
    files: list[Path] = []
    seen: set[Path] = set()

    for raw in paths:
        p = Path(raw)
        if p.is_dir():
            for src in iter_sources(p, cfg):
                if resolved_exclude is not None and src.resolve() == resolved_exclude:
                    continue
                if src not in seen:
                    seen.add(src)
                    files.append(src)
            continue

        if not p.exists() or not p.is_file():
            continue
        # iter_sources matches case-insensitively (FOO.C counts as .c).
        if p.suffix.lower() not in lowered_exts:
            continue
        if p not in seen:
            seen.add(p)
            files.append(p)

    return files


# --- Definition merge --------------------------------------------------------
# The output keeps each C definition and the file-scope objects defined beside
# it.  Rows whose file names an input move to the output.  A file-level naked,
# struct, or callers fence is
# dropped, because the result has a second function.

_NO_VA = 2**63


def _norm_c(text: str) -> str:
    normalized = text.replace("\r\n", "\n").replace("\r", "\n")
    lines = [line.rstrip() for line in normalized.split("\n")]
    while lines and lines[0] == "":
        lines.pop(0)
    while lines and lines[-1] == "":
        lines.pop()
    return "\n".join(lines)


@dataclass
class _Piece:
    """One definition copied into the merged file."""

    name: str
    text: str
    norm: str
    rows: list[tuple[str, int, str]]
    va: int
    providers: set[str] = field(default_factory=set)


@dataclass
class _InputLayout:
    """Preamble and definitions from one migrated input, in source order."""

    rel: str
    preamble: str
    va: int
    stores: list[_Piece]
    functions: list[_Piece]
    #: Data rows naming this file that no object in it defines (an extern
    #: declaration, a compiler literal).  They move to the output with the code
    #: that uses them; nothing is lost because the row never anchored a definition.
    carried: list[tuple[str, int, str]]


def _definition_problem(span: SourceSpan, filename: str, *, function: bool) -> str | None:
    """Refuse a conditional, unparsed, or unnamed definition before any write."""
    broken = span.inside_pp or not span.name or (function and not span.proto)
    if not broken:
        return None
    label = span.name or ("a function" if function else "an object")
    return f"{label} in {filename} is inside a preprocessor conditional or did not parse"


def _take_rows(
    name: str,
    candidates: list[tuple[str, int, dict[str, Any]]],
    claimed: dict[tuple[str, int], str],
    seen: set[tuple[str, int]],
    *,
    noun: str,
) -> tuple[list[tuple[str, int, str]], list[str]]:
    """Rows whose symbol or name is *name*.  One row cannot name two definitions."""
    rows: list[tuple[str, int, str]] = []
    problems: list[str] = []
    for module, va, entry in candidates:
        if name not in row_labels(entry):
            continue
        key = (module, va)
        previous = claimed.get(key)
        if previous is not None and previous != name:
            problems.append(f"{noun} {module}.0x{va:08x} matches {previous} and {name}")
            continue
        claimed[key] = name
        seen.add(key)
        rows.append((module, va, str(entry.get("file") or "")))
    return rows, problems


def _make_piece(
    span: SourceSpan,
    raw: bytes,
    spans: list[SourceSpan],
    rows: list[tuple[str, int, str]],
) -> _Piece:
    """Definition text for *span*, with a file-level fence removed."""
    start, end = span_extent(raw, span, spans)
    body = raw[start:end].decode("utf-8", errors="surrogateescape")
    return _Piece(
        name=span.name,
        text=body,
        norm=_norm_c(raw[span.start : span.end].decode("utf-8", errors="surrogateescape")),
        rows=rows,
        va=min((row_va for _module, row_va, _old in rows), default=_NO_VA),
    )


def _append_definition(
    span: SourceSpan,
    raw: bytes,
    spans: list[SourceSpan],
    candidates: list[tuple[str, int, dict[str, Any]]],
    claimed: dict[tuple[str, int], str],
    seen: set[tuple[str, int]],
    filename: str,
    pieces: list[_Piece],
    problems: list[str],
    *,
    function: bool,
) -> None:
    """Copy one definition, with its row when the store has one.

    A non-static function needs a row; a static helper does not. A file-scope
    object takes a matching data row, which moves with it.
    """
    problem = _definition_problem(span, filename, function=function)
    if problem is not None:
        problems.append(problem)
        return
    rows, claim_problems = _take_rows(
        span.name, candidates, claimed, seen, noun="Row" if function else "Data row"
    )
    problems.extend(claim_problems)
    if function and not span.static and not rows:
        problems.append(f"{span.name} in {filename} has no function row")
    pieces.append(_make_piece(span, raw, spans, rows))


def _missing_rows(
    candidates: list[tuple[str, int, dict[str, Any]]],
    seen: set[tuple[str, int]],
    filename: str,
    rel: str,
    *,
    data: bool,
) -> list[str]:
    """Rows for this file that no copied definition claimed."""
    noun = "Data row" if data else "Row"
    gap = "object" if data else "C definition"
    return [
        f"{noun} {module}.0x{va:08x} names {entry.get('file') or rel} "
        f"and no {gap} in {filename} matches"
        for module, va, entry in candidates
        if (module, va) not in seen
    ]


def _function_rows(
    entries: dict[tuple[str, int], dict[str, Any]], rel: str
) -> list[tuple[str, int, dict[str, Any]]]:
    return [
        (module, va, entry)
        for (module, va), entry in entries.items()
        if str(entry.get("kind") or "FUNCTION") in FUNCTION_KINDS
        and stored_file_matches(str(entry.get("file") or ""), rel)
    ]


def _data_rows(
    entries: dict[tuple[str, int], dict[str, Any]], rel: str
) -> list[tuple[str, int, dict[str, Any]]]:
    return [
        (module, va, entry)
        for (module, va), entry in entries.items()
        if stored_file_matches(str(entry.get("file") or ""), rel)
    ]


def _layout_one(
    file_path: Path,
    raw: bytes,
    spans: list[SourceSpan],
    meta: Any,
    entries: dict[tuple[str, int], dict[str, Any]],
    data_entries: dict[tuple[str, int], dict[str, Any]],
    claimed: dict[tuple[str, int], str],
    claimed_data: dict[tuple[str, int], str],
    output_dir: Path,
    prior_output: str,
) -> tuple[_InputLayout, list[str]]:
    """Preamble, storage, and functions from one migrated input."""
    rel = identity_file(file_path, meta)
    functions = [span for span in spans if span.kind == "function"]
    stores = [span for span in spans if span.kind == "storage"]
    file_rows = _function_rows(entries, rel)
    file_data = _data_rows(data_entries, rel)
    # A force rerun may retain its old inputs after rows moved to the output.
    names = {span.name for span in functions}
    data_names = {name for span in stores for name in span.names}
    file_rows.extend(
        row
        for row in _function_rows(entries, prior_output)
        if row_labels(row[2]) & names and row not in file_rows
    )
    file_data.extend(
        row
        for row in _data_rows(data_entries, prior_output)
        if row_labels(row[2]) & data_names and row not in file_data
    )

    problems: list[str] = []
    func_pieces: list[_Piece] = []
    seen_funcs: set[tuple[str, int]] = set()
    for span in functions:
        _append_definition(
            span,
            raw,
            spans,
            file_rows,
            claimed,
            seen_funcs,
            file_path.name,
            func_pieces,
            problems,
            function=True,
        )
    problems.extend(_missing_rows(file_rows, seen_funcs, file_path.name, rel, data=False))
    store_pieces: list[_Piece] = []
    seen_data: set[tuple[str, int]] = set()
    for span in stores:
        _append_definition(
            span,
            raw,
            spans,
            file_data,
            claimed_data,
            seen_data,
            file_path.name,
            store_pieces,
            problems,
            function=False,
        )
    carried = [
        (module, va, str(entry.get("file") or rel))
        for module, va, entry in file_data
        if (module, va) not in seen_data
    ]
    layout = _InputLayout(
        rel=rel,
        preamble=source_paths.rebase_includes(
            shared_preamble(raw, spans, []), file_path.parent, output_dir
        ),
        va=min((piece.va for piece in func_pieces), default=_NO_VA),
        stores=store_pieces,
        functions=func_pieces,
        carried=carried,
    )
    return layout, problems


def _note_encoding(enc: str, current: str, legacy: set[str]) -> str:
    if enc in ("utf-8", "utf-8-sig"):
        return current
    legacy.add(enc)
    return enc


def _read_layouts(
    meta: Any,
    input_files: list[Path],
    entries: dict[tuple[str, int], dict[str, Any]],
    data_entries: dict[tuple[str, int], dict[str, Any]],
    output_dir: Path,
    json_output: bool,
    prior_output: str,
    readings: dict[Path, tuple[str, str]] | None = None,
    guarded_masks: dict[Path, str] | None = None,
) -> tuple[list[_InputLayout], list[str], str, str]:
    """Read every input.  The last non-UTF-8 source encoding wins."""
    layouts: list[_InputLayout] = []
    problems: list[str] = []
    claimed: dict[tuple[str, int], str] = {}
    claimed_data: dict[tuple[str, int], str] = {}
    legacy_encodings: set[str] = set()
    out_encoding = "utf-8"
    input_eol = "\n"
    for file_path in input_files:
        from rebrew.config import address_comments_for_file

        syntax = address_comments_for_file(file_path)
        try:
            text, enc = (
                readings[file_path.resolve()]
                if readings is not None
                else read_source_text(file_path)
            )
        except OSError as exc:
            error_exit(f"Failed to read {file_path}: {exc}", json_mode=json_output)
        out_encoding = _note_encoding(enc, out_encoding, legacy_encodings)
        input_eol = source_newline(text)
        try:
            from rebrew.metadata.bindings import source_bindings

            validation_lines = text.splitlines(keepends=True)
            if prior_output:
                # --force explicitly reuses inputs whose rows moved to this output.
                for anchor in parse_address_anchors(text, syntax=syntax):
                    store = data_entries if anchor.kind == "DATA" else entries
                    row = store.get((anchor.module, anchor.va), {})
                    if stored_file_matches(str(row.get("file") or ""), prior_output) and (
                        anchor.name in row_labels(row)
                    ):
                        validation_lines[anchor.line - 1] = "\n"
            source_bindings("".join(validation_lines), file_path, None, None, meta)
            raw, spans = source_layout(
                guarded_masks[file_path.resolve()] if guarded_masks is not None else text
            )
        except (ImportError, ValueError) as exc:
            error_exit(f"{exc}. Nothing was written.", json_mode=json_output)
        layout, layout_problems = _layout_one(
            file_path,
            raw,
            spans,
            meta,
            entries,
            data_entries,
            claimed,
            claimed_data,
            output_dir,
            prior_output,
        )
        layouts.append(layout)
        problems.extend(layout_problems)
    if len(legacy_encodings) > 1:
        problems.append(
            f"input files use conflicting source encodings ({', '.join(sorted(legacy_encodings))})"
        )
    return layouts, problems, out_encoding, input_eol


def _union_rows(prior: _Piece, piece: _Piece) -> None:
    prior.providers.update(piece.providers)
    seen_keys = {row[:2] for row in prior.rows}
    for row in piece.rows:
        if row[:2] not in seen_keys:
            prior.rows.append(row)
            seen_keys.add(row[:2])


def _accept_storage(
    seen: dict[str, _Piece],
    ordered: list[_Piece],
    piece: _Piece,
    *,
    json_output: bool,
) -> None:
    prior = seen.get(piece.name)
    if prior is None:
        seen[piece.name] = piece
        ordered.append(piece)
        return
    if prior.norm != piece.norm:
        error_exit(
            f"{piece.name} differs between inputs. Nothing was written.",
            json_mode=json_output,
        )
    _union_rows(prior, piece)


def _accept_function(
    seen: dict[str, _Piece],
    ordered: list[_Piece],
    piece: _Piece,
    *,
    shared: bool,
    json_output: bool,
) -> None:
    prior = seen.get(piece.name)
    if prior is None:
        seen[piece.name] = piece
        ordered.append(piece)
        return
    if shared and prior.norm == piece.norm:
        _union_rows(prior, piece)
        return
    if shared:
        error_exit(
            f"Refusing shared merge: {piece.name} differs between inputs. Nothing was written.",
            json_mode=json_output,
        )
    error_exit(
        f"{piece.name} is defined in more than one input. Nothing was written.",
        json_mode=json_output,
    )


def _require_merged_functions(
    func_out: list[_Piece], *, shared: bool, target_module_name: str, json_output: bool
) -> None:
    if not any(piece.rows for piece in func_out):
        error_exit(
            "No function row matches the input files. Nothing was written.",
            json_mode=json_output,
        )
    if len(func_out) < 2 and not shared:
        error_exit(
            f"Need at least two functions for target '{target_module_name}'",
            json_mode=json_output,
        )
    if shared and not func_out:
        error_exit("No functions found in input files", json_mode=json_output)


def _target_va(layout: _InputLayout, target_module_name: str) -> int:
    """Lowest function VA of *layout* under *target_module_name*, else under any module."""
    own = [
        va
        for piece in layout.functions
        for module, va, _old in piece.rows
        if preset_module_key(module) == preset_module_key(target_module_name)
    ]
    return min(own, default=layout.va)


def _assemble_pieces(
    layouts: list[_InputLayout],
    *,
    shared: bool,
    target_module_name: str,
    json_output: bool,
    providers: dict[str, set[str]] | None = None,
) -> tuple[list[_Piece], list[_Piece]]:
    """Storage first, then functions.  Files are ordered by their lowest function VA.

    The VA is the active target's own: a shared body also carries rows for other
    targets, and a client VA below the server image would sort it ahead of code
    that precedes it in the linked order.
    """
    for layout in layouts:
        original = (
            providers[layout.rel]
            if providers is not None
            else {
                preset_module_key(module)
                for piece in layout.functions
                for module, _va, _file in piece.rows
            }
        )
        for piece in [*layout.functions, *layout.stores]:
            piece.providers = set(original)
    layouts.sort(key=lambda item: (_target_va(item, target_module_name), item.rel))
    store_out: list[_Piece] = []
    seen_store: dict[str, _Piece] = {}
    for layout in layouts:
        for piece in layout.stores:
            _accept_storage(seen_store, store_out, piece, json_output=json_output)
    func_out: list[_Piece] = []
    seen_func: dict[str, _Piece] = {}
    for layout in layouts:
        for piece in layout.functions:
            _accept_function(seen_func, func_out, piece, shared=shared, json_output=json_output)
    _require_merged_functions(
        func_out, shared=shared, target_module_name=target_module_name, json_output=json_output
    )
    expected = set().union(*(piece.providers for piece in [*store_out, *func_out]))
    if providers is not None and set().union(*providers.values()) != expected:
        error_exit(
            "Merging would lose an input's target participation. "
            "Preserve storage/support-only inputs separately. Nothing was written.",
            json_mode=json_output,
        )
    for piece in [*store_out, *func_out] if providers is not None else []:
        extra = expected - piece.providers
        if extra:
            error_exit(
                f"Merging {piece.name} would change target participation: "
                f"new provider in {', '.join(sorted(extra))}. "
                "Review target guards before merging. Nothing was written.",
                json_mode=json_output,
            )
    last: dict[str, tuple[int, str]] = {}
    for piece in func_out:
        for module, va, _row in piece.rows:
            key = preset_module_key(module)
            prior = last.get(key)
            if prior is not None and va < prior[0]:
                error_exit(
                    f"Merged definition order contradicts {module} native order: "
                    f"{piece.name} ({va:#x}) follows {prior[1]} ({prior[0]:#x}). "
                    "Review an interleaved source organization plan. Nothing was written.",
                    json_mode=json_output,
                )
            last[key] = (va, piece.name)
    return store_out, func_out


def _compose_definitions(
    layouts: list[_InputLayout],
    store_out: list[_Piece],
    func_out: list[_Piece],
    *,
    input_eol: str,
    syntax: Any = None,
) -> str:
    parts: list[str] = []
    preamble = merge_preambles([layout.preamble for layout in layouts])
    if preamble.strip():
        parts.append(preamble.strip("\r\n"))
    for piece in [*store_out, *func_out]:
        text = piece.text
        for module, va, _ in piece.rows:
            text = add_address_anchor(text, module, va, piece.name, syntax=syntax)
        if text.strip():
            parts.append(text.strip("\r\n"))
    merged_text = "\n\n".join(parts) + "\n"
    if input_eol == "\r\n":
        merged_text = re.sub(r"\r\n|\r|\n", input_eol, merged_text)
    return merged_text


def _warn_externs(report: ExternReport) -> None:
    for dropped in report.dropped:
        console.print(f"[yellow]merge: dropped unparseable extern {dropped!r}[/yellow]")
    resolved_by_name: dict[str, str] = {}
    for decl in report.resolved:
        decl_name = _extract_extern_name(decl)
        if decl_name is not None:
            resolved_by_name.setdefault(decl_name, decl)
    for name, variants in report.conflicts.items():
        kept = resolved_by_name.get(name, "")
        console.print(
            f"[yellow]merge: conflicting externs for {name}: "
            f"kept {kept!r} over {[variant for variant in variants if variant != kept]!r}[/yellow]"
        )


def _merge_payload(
    *,
    output_path: Path,
    func_out: list[_Piece],
    input_files: list[Path],
    cfg: Any,
    dry_run: bool,
    delete: bool,
    consolidate: bool,
    extern_report: ExternReport | None,
) -> dict[str, Any]:
    function_rows = [row for piece in func_out for row in piece.rows]
    return {
        "output": str(output_path),
        "count": len(func_out),
        "input_count": len(input_files),
        "dry_run": dry_run,
        "deleted": bool(delete and not dry_run),
        "consolidated": consolidate,
        "inputs": [rel_display_path(path, cfg.reversed_dir) for path in input_files],
        "vas": [f"0x{va:08x}" for va in sorted({va for _module, va, _old in function_rows})],
        "extern_dropped": extern_report.dropped if extern_report else [],
        "extern_conflicts": dict(extern_report.conflicts) if extern_report else {},
        "retargeted": [f"{module}.0x{va:08x}" for module, va, _old in function_rows],
    }


def _stop_before_write(
    *,
    dry_run: bool,
    force: bool,
    delete: bool,
    json_output: bool,
    output_path: Path,
    input_files: list[Path],
    func_out: list[_Piece],
    payload: dict[str, Any],
) -> bool:
    """Confirm a retarget, or print a dry run and return True."""
    if not dry_run and not force:
        if json_output:
            error_exit(
                "Merge retargets rows onto the output file. "
                "Pass --force to apply it in --json mode, or use --dry-run to preview.",
                json_mode=True,
                kind="confirmation_required",
                hint="Pass --force to skip the prompt.",
            )
        extra = f" and delete {len(input_files)} input file(s)" if delete else ""
        confirm_abort(f"Merge will retarget rows onto {output_path.name}{extra}. Continue?")
    if not dry_run:
        return False
    if json_output:
        json_print(payload)
        return True
    console.print(
        f"Would merge [bold]{len(func_out)}[/] functions from {len(input_files)} files "
        f"into {output_path.name}"
    )
    return True


def _rollback_output(output_path: Path, previous: bytes | None) -> None:
    """Restore *output_path* to *previous*, logging but never raising.

    A rollback failure must not mask the original error, so OSError is
    swallowed after a warning; callers still report the original failure.
    """
    import logging

    try:
        if previous is None:
            output_path.unlink(missing_ok=True)
        else:
            # Restore atomically so a concurrent reader never sees a half-written
            # merge output and a crash cannot truncate the previous file.
            atomic_write_bytes(output_path, previous)
    except OSError as exc:
        logging.getLogger(__name__).warning(
            "merge: could not restore %s after failure: %s", output_path, exc
        )


def _retarget_rows(
    meta: Any,
    rows: list[tuple[str, int, str]],
    *,
    new_file: str | None,
) -> None:
    """Point *rows* at *new_file*, or back at the file each row had."""
    payload = [
        {
            "module": module,
            "va": va,
            "identity": {"file": new_file if new_file is not None else old},
        }
        for module, va, old in rows
        if new_file is not None or old
    ]
    if not payload:
        return
    record_function_rows(meta, payload)


def _retarget_data_rows(
    meta: Any,
    rows: list[tuple[str, int, str]],
    *,
    new_file: str | None,
) -> None:
    payload = [
        {
            "module": module,
            "va": va,
            "identity": {"file": new_file if new_file is not None else old},
        }
        for module, va, old in rows
        if new_file is not None or old
    ]
    if not payload:
        return
    record_data_rows(meta, payload)


def _undo_retarget(
    meta: Any,
    function_rows: list[tuple[str, int, str]],
    data_rows: list[tuple[str, int, str]],
    *,
    functions_done: bool,
    data_done: bool,
    exc: Exception,
    json_output: bool,
) -> None:
    try:
        if data_done:
            _retarget_data_rows(meta, data_rows, new_file=None)
        if functions_done:
            _retarget_rows(meta, function_rows, new_file=None)
    except Exception as undo_exc:
        error_exit(
            f"Merge did not finish ({exc}). The output was restored "
            f"and the row retarget could not be undone ({undo_exc}).",
            json_mode=json_output,
        )
    error_exit(
        f"Merge did not finish ({exc}). The output was restored.",
        json_mode=json_output,
    )


def _commit_definitions(
    *,
    meta: Any,
    new_file: str,
    output_path: Path,
    merged_text: str,
    out_encoding: str,
    function_rows: list[tuple[str, int, str]],
    data_rows: list[tuple[str, int, str]],
    json_output: bool,
    publisher: Callable[[Path, bytes], None] | None = None,
) -> None:
    previous = output_path.read_bytes() if output_path.exists() else None
    functions_done = False
    data_done = False
    try:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        if publisher is None:
            atomic_write_text(output_path, merged_text, encoding=out_encoding)
        else:
            publisher(output_path, merged_text.encode(out_encoding))
        if function_rows:
            _retarget_rows(meta, function_rows, new_file=new_file)
            functions_done = True
        if data_rows:
            _retarget_data_rows(meta, data_rows, new_file=new_file)
            data_done = True
    except UnicodeEncodeError as exc:
        if publisher is None:
            _rollback_output(output_path, previous)
        offending = exc.object[exc.start : exc.end]
        error_exit(
            f"merged source cannot be encoded as {out_encoding} "
            f"(offending text {offending!r}); convert the inputs to a common "
            "encoding first",
            json_mode=json_output,
        )
    except Exception as exc:
        if publisher is not None:
            error_exit(f"Merge could not publish or retarget: {exc}", json_mode=json_output)
        _rollback_output(output_path, previous)
        _undo_retarget(
            meta,
            function_rows,
            data_rows,
            functions_done=functions_done,
            data_done=data_done,
            exc=exc,
            json_output=json_output,
        )


def _delete_inputs(input_files: list[Path], output_path: Path) -> None:
    for file_path in input_files:
        if file_path.resolve() == output_path.resolve():
            continue
        file_path.unlink(missing_ok=True)


def _report_merge(
    *,
    json_output: bool,
    payload: dict[str, Any],
    func_out: list[_Piece],
    input_files: list[Path],
    output_path: Path,
    delete: bool,
) -> None:
    if json_output:
        json_print(payload)
        return
    console.print(
        f"Merged [bold]{len(func_out)}[/] functions from {len(input_files)} files "
        f"into {output_path.name}"
    )
    if delete:
        console.print("Deleted original input files after merge")
        return
    console.print(
        "[dim]Rows now name the output. Re-run with --delete to remove the input copies.[/dim]"
    )


def _destination(cfg: Any, output_path: Path, json_output: bool) -> tuple[Any, str]:
    meta = getattr(cfg, "metadata_dir", None)
    if meta is None:
        error_exit("No metadata directory configured", json_mode=json_output)
    try:
        new_file = validate_identity_file(identity_file(output_path, meta))
    except ValueError as exc:
        error_exit(str(exc), json_mode=json_output)
    return meta, new_file


def _merge_include_inputs(
    cfg: Any, input_files: list[Path]
) -> tuple[
    list[Path],
    list[Any],
    dict[str, str],
    list[tuple[str, str, tuple[str, ...]]],
    list[tuple[str, tuple[str, ...]]],
]:
    """Pin every resolved include and per-directory compiler override across targets."""
    from rebrew.metadata.coordinated import path_identity_digest
    from rebrew.source_contracts import contract_contexts
    from rebrew.source_organization import organization_configs

    config_path = cfg.root / "rebrew-project.toml"
    before = (
        config_path.read_bytes() if config_path.is_file() else None,
        path_identity_digest(config_path),
    )
    configurations = organization_configs(cfg)
    if (
        config_path.read_bytes() if config_path.is_file() else None,
        path_identity_digest(config_path),
    ) != before:
        raise ValueError("project config changed while loading targets")
    matching = [c for c in configurations if c.target_name == cfg.target_name]
    if cfg.target_name and not matching:
        raise ValueError("selected target disappeared; reload before review")
    if matching and matching[0].as_dict() != cfg.as_dict():
        raise ValueError("target configuration is stale; reload before review")
    selected = {path.resolve() for path in input_files}
    watched: set[Path] = set()
    observed_inputs: dict[str, str] = {}
    shadows: list[tuple[str, str, tuple[str, ...]]] = []
    probes: list[tuple[str, tuple[str, ...]]] = []
    for context in configurations:
        observed: dict[Path, bytes] = {}
        lexical: list[tuple[Path, Path]] = []
        identities: dict[Path, dict[str, Any]] = {}
        closure, unknown = contract_contexts(
            context,
            selected_sources=selected,
            observed_contents=observed,
            lexical_includes=lexical,
            observed_identities=identities,
            include_shadows=shadows,
            include_probes=probes,
        )
        if unknown:
            item = unknown[0]
            raise ValueError(
                f"{context.target_name}: include closure is incomplete or changed for "
                f"{item['context']}: {', '.join(item.get('missing', []))}"
            )
        watched.update(path.resolve() for path in closure if path.resolve() not in selected)
        for path, resolved in lexical:
            if identities[path]["links"]:
                raise ValueError(f"{path}: symlinked include search context requires manual review")
            if (
                path.resolve() != resolved
                or resolved.read_bytes() != observed[resolved]
                or path_identity_digest(path) != json.dumps(identities[path], sort_keys=True)
            ):
                raise ValueError(f"{path}: include changed while loading closure")
            watched.add(path.absolute())
            key = "path-identity:" + str(path.absolute())
            identity = json.dumps(identities[path], sort_keys=True)
            if key in observed_inputs and observed_inputs[key] != identity:
                raise ValueError(f"{path}: include identity differs across target contexts")
            observed_inputs[key] = identity
        for path, content in observed.items():
            if path.read_bytes() != content:
                raise ValueError(f"{path}: include changed while loading closure")
            key = str(path.resolve())
            digest = hashlib.sha256(content).hexdigest()
            if key in observed_inputs and observed_inputs[key] != digest:
                raise ValueError(f"{path}: include differs across target contexts")
            observed_inputs[key] = digest
        for _, _, roots in shadows:
            watched.update(Path(root).absolute() for root in roots)
        for _, roots in probes:
            watched.update(Path(root).absolute() for root in roots)
        for source in selected:
            for parent in (source.parent, *source.parents):
                if parent == context.root.resolve().parent:
                    break
                watched.add(parent / "rebrew-libraries.toml")
    return (
        sorted(watched),
        configurations,
        observed_inputs,
        sorted(set(shadows)),
        sorted(set(probes)),
    )


def _merge_definitions(
    *,
    cfg: Any,
    input_files: list[Path],
    output_path: Path,
    dry_run: bool,
    force: bool,
    delete: bool,
    consolidate: bool,
    shared: bool,
    json_output: bool,
    expected_digest: str | None = None,
    guarded_interleave: bool = False,
) -> None:
    """Merge pure-C files from their rows.  ``error_exit`` does not return."""
    meta, new_file = _destination(cfg, output_path, json_output)
    transaction_inputs = None
    transaction_paths = [*input_files, output_path]
    source_texts = {}
    watched: list[Path] = []
    observed_inputs: dict[str, str] = {}
    shadows: list[tuple[str, str, tuple[str, ...]]] = []
    probes: list[tuple[str, tuple[str, ...]]] = []
    configurations: list[Any] = []
    readings: dict[Path, tuple[str, str]] | None = None
    if getattr(cfg, "root", None) is not None:
        from rebrew.metadata.coordinated import coordinated_inputs, path_identity_digest

        try:
            config_path = cfg.root / "rebrew-project.toml"
            config_before = (
                config_path.read_bytes() if config_path.is_file() else None,
                path_identity_digest(config_path),
            )
            watched, configurations, observed_inputs, shadows, probes = _merge_include_inputs(
                cfg, input_files
            )
            transaction_inputs = coordinated_inputs(
                Path(meta), transaction_paths, watched=watched, discovery_roots=[cfg.reversed_dir]
            )
            if any(transaction_inputs.get(k) != v for k, v in observed_inputs.items()):
                raise ValueError("includes changed while planning merge")
            if (
                config_path.read_bytes() if config_path.is_file() else None,
                path_identity_digest(config_path),
            ) != config_before:
                raise ValueError("project config changed while planning merge")
            readings = {path.resolve(): read_source_text(path) for path in input_files}
            for path, (text, encoding) in readings.items():
                if (
                    hashlib.sha256(text.encode(encoding)).hexdigest()
                    != transaction_inputs[str(path)]
                ):
                    raise ValueError(f"{path} changed or cannot round-trip; review a new preview")
            source_texts = {
                identity_file(path, meta): readings[path.resolve()][0] for path in input_files
            }
        except (OSError, ValueError) as exc:
            error_exit(str(exc), json_mode=json_output)
    guarded_masks = None
    guarded_parameters: set[str] = set()
    guarded_preamble = ""
    guarded_require_gd = False
    review: dict[str, Any] = {}
    wrappers: dict[Path, tuple[str, str]] = {}
    if guarded_interleave:
        if transaction_inputs is None or readings is None or not delete or consolidate or shared:
            error_exit(
                "guarded interleave requires a project, --delete and no --consolidate or --shared",
                json_mode=json_output,
            )
        if not dry_run and expected_digest is None:
            error_exit("guarded interleave apply requires --expected-digest", json_mode=json_output)
        from rebrew.guarded_merge import prepare_guarded_inputs
        from rebrew.source_organization import review_organization

        try:
            review = review_organization(
                configurations,
                [path.resolve() for path in input_files],
                destination=output_path.resolve(),
                shared=shared,
            )
            if review["problems"] or review["unknown"]:
                raise ValueError(
                    "guarded interleave requires complete, conflict-free organization review"
                )
            guarded_masks, wrappers, guarded_parameters, guarded_preamble, guarded_require_gd = (
                prepare_guarded_inputs(readings)
            )
        except (OSError, ValueError) as exc:
            error_exit(str(exc), json_mode=json_output)
    entries = load_metadata(meta)
    data_entries = load_data_metadata(meta)
    layouts, problems, out_encoding, input_eol = _read_layouts(
        meta,
        input_files,
        entries,
        data_entries,
        output_path.parent,
        json_output,
        new_file if force and output_path.exists() else "",
        readings,
        guarded_masks,
    )
    if problems:
        error_exit(f"{problems[0]}. Nothing was written.", json_mode=json_output)
    syntax = getattr(cfg, "address_comments", None)
    providers: dict[str, set[str]] | None = None
    if getattr(cfg, "root", None) is not None:
        from rebrew.source_selection import collect_target_sources

        providers = {layout.rel: set() for layout in layouts}
        for context in configurations:
            selected, _foreign = collect_target_sources(context, context.module)
            selected_paths = {path.resolve() for path in selected}
            for layout in layouts:
                if (Path(meta) / layout.rel).resolve() in selected_paths:
                    providers[layout.rel].add(str(context.target_name or context.module))
    if guarded_interleave:
        from rebrew.guarded_merge import interleave_guarded, validate_guarded_flags

        try:
            assert providers is not None
            wrapped = interleave_guarded(
                layouts,
                {layout.rel: wrappers[(Path(meta) / layout.rel).resolve()] for layout in layouts},
                providers,
                shared=shared,
            )
            store_out: list[_Piece] = []
            func_out = [piece for piece, _guard in wrapped]
            validate_guarded_flags(
                {piece.name for piece in func_out} | guarded_parameters,
                configurations,
                review,
                require_gd=guarded_require_gd,
            )
            parts = [guarded_preamble] if guarded_preamble else []
            active = ("", "")
            for piece, guard in wrapped:
                if guard != active:
                    if active[1]:
                        parts.append(active[1])
                    if guard[0]:
                        parts.append(guard[0])
                    active = guard
                text = piece.text
                for module, va, _old in piece.rows:
                    text = add_address_anchor(text, module, va, piece.name, syntax=syntax)
                parts.append(text if text.endswith(("\n", "\r")) else text + input_eol)
            if active[1]:
                parts.append(active[1])
            merged_text = "".join(parts)
        except (OSError, ValueError) as exc:
            error_exit(str(exc), json_mode=json_output)
    else:
        store_out, func_out = _assemble_pieces(
            layouts,
            shared=shared,
            target_module_name=str(cfg.module),
            json_output=json_output,
            providers=providers,
        )
        merged_text = _compose_definitions(
            layouts, store_out, func_out, input_eol=input_eol, syntax=syntax
        )
    extern_report: ExternReport | None = None
    if consolidate:
        merged_text, extern_report = consolidate_declarations(merged_text, syntax=syntax)
        _warn_externs(extern_report)
    payload = _merge_payload(
        output_path=output_path,
        func_out=func_out,
        input_files=input_files,
        cfg=cfg,
        dry_run=dry_run,
        delete=delete,
        consolidate=consolidate,
        extern_report=extern_report,
    )
    if guarded_interleave:
        payload["merged_source"] = merged_text
        payload["guarded_interleave"] = True
    definitions: tuple[Any, ...] = ()
    files: tuple[Any, ...] = ()
    if transaction_inputs is not None:
        from rebrew.metadata.coordinated import coordinated_inputs
        from rebrew.metadata.source_provenance import plan_source_rehome

        try:
            current_watched, _, current_observed, current_shadows, current_probes = (
                _merge_include_inputs(cfg, input_files)
            )
            if (
                current_watched != watched
                or current_observed != observed_inputs
                or current_shadows != shadows
                or current_probes != probes
                or (
                    coordinated_inputs(
                        Path(meta),
                        transaction_paths,
                        watched=watched,
                        discovery_roots=[cfg.reversed_dir],
                    )
                    != transaction_inputs
                )
            ):
                raise ValueError("merge inputs changed during planning")
            definitions, files = plan_source_rehome(Path(meta), source_texts, new_file, merged_text)
            digest = hashlib.sha256(
                json.dumps(
                    {
                        "inputs": transaction_inputs,
                        "output": str(output_path.resolve()),
                        "merged": hashlib.sha256(merged_text.encode(out_encoding)).hexdigest(),
                        "delete": delete,
                        "shared": shared,
                        "consolidate": consolidate,
                        "target": str(cfg.module),
                        "guarded_interleave": guarded_interleave,
                    },
                    sort_keys=True,
                ).encode()
            ).hexdigest()
            payload["input_digest"] = digest
            if expected_digest is not None and expected_digest != digest:
                raise ValueError("merge inputs changed; review a new preview")
        except (OSError, ValueError, UnicodeError) as exc:
            error_exit(str(exc), json_mode=json_output)
    elif expected_digest is not None:
        error_exit("digest-guarded merge requires a project configuration", json_mode=json_output)
    if _stop_before_write(
        dry_run=dry_run,
        force=force,
        delete=delete,
        json_output=json_output,
        output_path=output_path,
        input_files=input_files,
        func_out=func_out,
        payload=payload,
    ):
        return
    function_rows = [row for piece in func_out for row in piece.rows]
    data_rows = [row for piece in store_out for row in piece.rows] + [
        row for layout in layouts for row in layout.carried
    ]
    if transaction_inputs is None:
        _commit_definitions(
            meta=meta,
            new_file=new_file,
            output_path=output_path,
            merged_text=merged_text,
            out_encoding=out_encoding,
            function_rows=function_rows,
            data_rows=data_rows,
            json_output=json_output,
        )
        if delete:
            _delete_inputs(input_files, output_path)
    else:
        from rebrew.metadata.coordinated import coordinated_transaction
        from rebrew.metadata.source_provenance import replace_source_metadata
        from rebrew.metadata.storage import metadata_store

        stage = transaction_paths if delete else [output_path]
        try:

            def validate_resolution() -> None:
                current, contexts, observations, current_shadows, current_probes = (
                    _merge_include_inputs(cfg, input_files)
                )
                if (
                    current != watched
                    or observations != observed_inputs
                    or current_shadows != shadows
                    or current_probes != probes
                    or [context.as_dict() for context in contexts]
                    != [context.as_dict() for context in configurations]
                ):
                    raise ValueError("include resolution changed; review a new merge preview")

            def validate_after_publication() -> None:
                from rebrew.compiler.cache import shadow_unchanged, unresolved_still_missing
                from rebrew.metadata.coordinated import path_identity_digest
                from rebrew.metadata.storage import managed_metadata_filenames

                if not shadow_unchanged(shadows) or not unresolved_still_missing(probes):
                    raise ValueError("include resolution changed during merge")
                for path in [*watched, cfg.root / "rebrew-project.toml"]:
                    absolute = path.absolute()
                    if path_identity_digest(path) != transaction_inputs.get(
                        "path-identity:" + str(absolute)
                    ):
                        raise ValueError(f"{path}: include path changed during merge")
                    resolved = path.resolve()
                    digest = (
                        metadata_store(resolved).digest()
                        if resolved.name in managed_metadata_filenames()
                        else hashlib.sha256(resolved.read_bytes()).hexdigest()
                        if resolved.is_file()
                        else None
                    )
                    if digest != transaction_inputs.get(str(resolved)):
                        raise ValueError(f"{path}: include content changed during merge")

            with coordinated_transaction(
                Path(meta),
                transaction_paths,
                stage=stage,
                expected_inputs=transaction_inputs,
                watched=watched,
                discovery_roots=[cfg.reversed_dir],
                validate=validate_resolution,
                validate_after=validate_after_publication,
            ) as staged:
                _commit_definitions(
                    meta=meta,
                    new_file=new_file,
                    output_path=output_path,
                    merged_text=merged_text,
                    out_encoding=out_encoding,
                    function_rows=function_rows,
                    data_rows=data_rows,
                    json_output=json_output,
                    publisher=staged.publish,
                )
                store = metadata_store(Path(meta) / "rebrew-functions.toml")
                replace_source_metadata(
                    Path(meta), definitions, files, expected_hash=store.digest()
                )
        except (OSError, ValueError, UnicodeError) as exc:
            error_exit(str(exc), json_mode=json_output)
    _report_merge(
        json_output=json_output,
        payload=payload,
        func_out=func_out,
        input_files=input_files,
        output_path=output_path,
        delete=delete,
    )


@app.callback(invoke_without_command=True)
def main(
    sources: list[str] = typer.Argument(
        ..., help="Input source files (or directories)", click_type=TyperPath(path_type=str)
    ),
    output: str = typer.Option(
        ..., "--output", "-o", help="Output merged source file", click_type=TyperPath(path_type=str)
    ),
    dry_run: bool = typer.Option(False, "--dry-run", help="Preview changes without writing"),
    force: bool = typer.Option(
        False,
        "--force",
        help="Overwrite existing output and skip merge/delete confirmation prompts",
    ),
    delete: bool = typer.Option(
        False, "--delete", help="Delete input files after successful merge"
    ),
    consolidate: bool = typer.Option(
        False,
        "--consolidate",
        help="Hoist unique includes/externs/typedefs/intrinsics to the top of the merged TU",
    ),
    shared: bool = typer.Option(
        False,
        "--shared",
        help="Combine identical bodies across targets into one definition with stacked "
        "ADDRESS anchors; retarget all input metadata rows. Different bodies are refused",
    ),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
    expected_digest: str | None = typer.Option(
        None, "--expected-digest", help=EXPECTED_DIGEST_HELP
    ),
    guarded_interleave: bool = typer.Option(
        False,
        "--guarded-interleave",
        help="Review bounded simple guards and interleave by all-target native order",
    ),
    target: str | None = TargetOption,
) -> None:
    """Merge multiple single-function files into one multi-function file."""
    if not sources:
        error_exit("Merge requires at least two source files", json_mode=json_output)

    cfg = require_config(target=target, json_mode=json_output)
    # Direct main() calls in tests leave typer OptionInfo sentinels in place
    # of real bools (every option param is affected, not just this one) —
    # coerce so a sentinel never enables the shared path by truthiness.
    shared = shared is True
    output_path = Path(output)
    input_files = _collect_input_files(sources, cfg, exclude=output_path)
    if len(input_files) < 2:
        error_exit("Merge requires at least two source files", json_mode=json_output)

    if output_path.exists() and not force:
        error_exit(f"Output file already exists: {output_path}", json_mode=json_output)

    _merge_definitions(
        cfg=cfg,
        input_files=input_files,
        output_path=output_path,
        dry_run=dry_run is True,
        force=force is True,
        delete=delete is True,
        consolidate=consolidate is True,
        shared=shared,
        json_output=json_output is True,
        expected_digest=expected_digest if isinstance(expected_digest, str) else None,
        guarded_interleave=guarded_interleave is True,
    )


def main_entry() -> None:
    """Run the Typer CLI application."""
    from rebrew.cli import run_standalone

    run_standalone(main)


if __name__ == "__main__":
    main_entry()
