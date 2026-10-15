"""merge.py - Merge single-function C files into one multi-function file.

Combines multiple annotated source files into a single compilation unit,
deduplicating preamble lines and sorting function blocks by virtual address.

With ``--shared``, twin files (same body, different target markers — the
per-target copies ``cross-import`` used to make) collapse into one stacked
block per body (one ``// FUNCTION: <target> <va>`` marker per target,
ADR-022): the migration path from N copies to one shared file.  Bodies
that differ between targets are refused, never averaged.

A migrated file has no marker block.  The same command reads each function
row, copies that C definition and its file-scope objects into the output,
and retargets every row that names an input.  ``--dry-run`` writes nothing.
"""

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import typer
from typer.models import TyperPath

from rebrew import source_paths
from rebrew.c_parser import CALLING_CONVENTION
from rebrew.cli import (
    TargetOption,
    confirm_abort,
    console,
    error_exit,
    json_print,
    require_config,
)
from rebrew.config import ProjectConfig
from rebrew.metadata.anchors import add_address_anchor, parse_address_anchors
from rebrew.metadata.bindings import (
    FUNCTION_KINDS,
)
from rebrew.metadata.data import load_data_metadata, record_data_rows
from rebrew.metadata.functions import (
    identity_file,
    load_metadata,
    record_function_rows,
    stored_file_matches,
    validate_identity_file,
)
from rebrew.sources import (
    iter_sources,
    source_exts,
)
from rebrew.split import (
    SourceSpan,
    row_labels,
    shared_preamble,
    source_layout,
    span_extent,
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


def _extract_extern_name(decl: str) -> str | None:
    """The symbol name from an extern declaration."""
    d = decl.strip().rstrip(";").strip()
    d = re.sub(r"/\*.*?\*/", "", d).strip()
    # ``int (*fp)(void)``, ``int (* const rows[2])[4]``, ``char (__cdecl *row)[4]``.
    # The convention and qualifier are not the symbol. Tested before the plain
    # declarator rule or the base type matches instead of the symbol.
    m = re.search(
        r"\(\s*" + CALLING_CONVENTION + r"\*+\s*(?:(?:const|volatile)\b\s*)*(\w+)",
        d,
    )
    if m:
        return m.group(1)
    m = re.search(r"(\w+)\s*[\[(]", d)
    if m:
        return m.group(1)
    m = re.search(r"(\w+)\s*$", d)
    return m.group(1) if m else None


def _extern_specificity(decl: str) -> int:
    """Higher = more specific/better declaration when conflicts exist."""
    score = 0
    for pat in ("void*", "void *", "char*", "char *", "short*", "short *"):
        if pat in decl:
            score += 2
    if "unsigned" in decl:
        score += 1
    score += len(re.findall(r"\b[a-z_]\w*(?=\s*[,)])", decl)) * 3
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
        m = re.search(r"intrinsic\s*\(([^)]+)\)", p)
        if m:
            funcs.update(f.strip() for f in m.group(1).split(",") if f.strip())
    return funcs


def _ends_declaration(line: str) -> bool:
    """True if *line*'s code portion (comments stripped) ends a ``;``-terminated declaration."""
    code = re.sub(r"/\*.*?\*/", "", line)
    code = re.sub(r"//.*", "", code)
    return code.rstrip().endswith(";")


def consolidate_declarations(text: str) -> tuple[str, ExternReport]:
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
        a.definition_line - 1 for a in parse_address_anchors(text) if a.kind == "DATA"
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


def normalize_body(block: str) -> str:
    """The same C body across targets, excluding only its address anchors."""
    removed = {a.line for a in parse_address_anchors(block)}
    return "\n".join(
        line.rstrip() for i, line in enumerate(block.splitlines(), 1) if i not in removed
    ).strip()


def block_metadata(block: str) -> dict[str, Any] | None:
    """The first address group in a declaration-bound block."""
    anchors = parse_address_anchors(block)
    return {"module": anchors[0].module, "va": anchors[0].va} if anchors else None


def merge_preambles(preambles: list[str]) -> str:
    """Merge preambles with include-line dedup and collapsed blank lines.

    Comment blocks (e.g. Ghidra decompilation references) are stripped before
    merging: they are per-function noise, and a naive union of multiple
    preambles leaves the ``/* */`` nesting malformed so the merged file does
    not compile (C2143 on orphaned comment lines).

    Only ``#include`` lines dedup: exact-line union of anything else eats
    repeated structural lines (a lone ``{`` opening five different structs
    collapses to one, corrupting every struct after the first).  Divergent
    typedefs/prototypes from different inputs are all kept — the compiler,
    not the merge, arbitrates conflicts.
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
                or _TYPEDEF_RE.match(line)
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


# --- Marker-less merge -------------------------------------------------------
# A pure-C file has no // FUNCTION: block.  The output keeps each C definition
# and the file-scope objects defined beside it.  Rows whose file names an
# input move to the output.  A file-level naked, struct, or callers fence is
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


def _append_function(
    span: SourceSpan,
    raw: bytes,
    spans: list[SourceSpan],
    candidates: list[tuple[str, int, dict[str, Any]]],
    claimed: dict[tuple[str, int], str],
    seen: set[tuple[str, int]],
    filename: str,
    pieces: list[_Piece],
    problems: list[str],
) -> None:
    """Copy one function.  A non-static definition needs a row; a static helper does not."""
    problem = _definition_problem(span, filename, function=True)
    if problem is not None:
        problems.append(problem)
        return
    rows, claim_problems = _take_rows(span.name, candidates, claimed, seen, noun="Row")
    problems.extend(claim_problems)
    if not span.static and not rows:
        problems.append(f"{span.name} in {filename} has no function row")
    pieces.append(_make_piece(span, raw, spans, rows))


def _append_storage(
    span: SourceSpan,
    raw: bytes,
    spans: list[SourceSpan],
    candidates: list[tuple[str, int, dict[str, Any]]],
    claimed: dict[tuple[str, int], str],
    seen: set[tuple[str, int]],
    filename: str,
    pieces: list[_Piece],
    problems: list[str],
) -> None:
    """Copy one file-scope object.  A matching data row moves with it."""
    problem = _definition_problem(span, filename, function=False)
    if problem is not None:
        problems.append(problem)
        return
    rows, claim_problems = _take_rows(span.name, candidates, claimed, seen, noun="Data row")
    problems.extend(claim_problems)
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
        _append_function(
            span, raw, spans, file_rows, claimed, seen_funcs, file_path.name, func_pieces, problems
        )
    problems.extend(_missing_rows(file_rows, seen_funcs, file_path.name, rel, data=False))
    store_pieces: list[_Piece] = []
    seen_data: set[tuple[str, int]] = set()
    for span in stores:
        _append_storage(
            span,
            raw,
            spans,
            file_data,
            claimed_data,
            seen_data,
            file_path.name,
            store_pieces,
            problems,
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
) -> tuple[list[_InputLayout], list[str], str, str]:
    """Read every input.  The last legacy encoding wins, as on the marker path."""
    layouts: list[_InputLayout] = []
    problems: list[str] = []
    claimed: dict[tuple[str, int], str] = {}
    claimed_data: dict[tuple[str, int], str] = {}
    legacy_encodings: set[str] = set()
    out_encoding = "utf-8"
    input_eol = "\n"
    for file_path in input_files:
        try:
            text, enc = read_source_text(file_path)
        except OSError as exc:
            error_exit(f"Failed to read {file_path}: {exc}", json_mode=json_output)
        out_encoding = _note_encoding(enc, out_encoding, legacy_encodings)
        input_eol = source_newline(text)
        try:
            from rebrew.metadata.bindings import source_bindings

            validation_lines = text.splitlines(keepends=True)
            if prior_output:
                # --force explicitly reuses inputs whose rows moved to this output.
                for anchor in parse_address_anchors(text):
                    store = data_entries if anchor.kind == "DATA" else entries
                    row = store.get((anchor.module, anchor.va), {})
                    if stored_file_matches(str(row.get("file") or ""), prior_output) and (
                        anchor.name in row_labels(row)
                    ):
                        validation_lines[anchor.line - 1] = "\n"
            source_bindings("".join(validation_lines), file_path, None, None, meta)
            raw, spans = source_layout(text)
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
    func_out: list[_Piece], *, shared: bool, marker: str, json_output: bool
) -> None:
    if not any(piece.rows for piece in func_out):
        error_exit(
            "No function row matches the input files. Nothing was written.",
            json_mode=json_output,
        )
    if len(func_out) < 2 and not shared:
        error_exit(
            f"Need at least two functions for target '{marker}'",
            json_mode=json_output,
        )
    if shared and not func_out:
        error_exit("No functions found in input files", json_mode=json_output)


def _target_va(layout: _InputLayout, marker: str) -> int:
    """Lowest function VA of *layout* under module *marker*, else under any module."""
    own = [
        va
        for piece in layout.functions
        for module, va, _old in piece.rows
        if preset_module_key(module) == preset_module_key(marker)
    ]
    return min(own, default=layout.va)


def _assemble_pieces(
    layouts: list[_InputLayout], *, shared: bool, marker: str, json_output: bool
) -> tuple[list[_Piece], list[_Piece]]:
    """Storage first, then functions.  Files are ordered by their lowest function VA.

    The VA is the active target's own: a shared body also carries rows for other
    targets, and a client VA below the server image would sort it ahead of code
    that precedes it in the linked order.
    """
    layouts.sort(key=lambda item: (_target_va(item, marker), item.rel))
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
    _require_merged_functions(func_out, shared=shared, marker=marker, json_output=json_output)
    return store_out, func_out


def _compose_definitions(
    layouts: list[_InputLayout],
    store_out: list[_Piece],
    func_out: list[_Piece],
    *,
    input_eol: str,
) -> str:
    parts: list[str] = []
    preamble = merge_preambles([layout.preamble for layout in layouts])
    if preamble.strip():
        parts.append(preamble.strip("\r\n"))
    for piece in [*store_out, *func_out]:
        text = piece.text
        for module, va, _ in piece.rows:
            text = add_address_anchor(text, module, va, piece.name)
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
    store_out: list[_Piece],
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
    if previous is None:
        output_path.unlink(missing_ok=True)
    else:
        output_path.write_bytes(previous)


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
    except Exception:
        error_exit(
            f"Merge did not finish ({exc}). The output was restored "
            "and the row retarget could not be undone.",
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
) -> None:
    previous = output_path.read_bytes() if output_path.exists() else None
    functions_done = False
    data_done = False
    try:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        atomic_write_text(output_path, merged_text, encoding=out_encoding)
        if function_rows:
            _retarget_rows(meta, function_rows, new_file=new_file)
            functions_done = True
        if data_rows:
            _retarget_data_rows(meta, data_rows, new_file=new_file)
            data_done = True
    except UnicodeEncodeError as exc:
        _rollback_output(output_path, previous)
        offending = exc.object[exc.start : exc.end]
        error_exit(
            f"merged source cannot be encoded as {out_encoding} "
            f"(offending text {offending!r}); convert the inputs to a common "
            "encoding first",
            json_mode=json_output,
        )
    except Exception as exc:
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
) -> None:
    """Merge pure-C files from their rows.  ``error_exit`` does not return."""
    meta, new_file = _destination(cfg, output_path, json_output)
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
    )
    if problems:
        error_exit(f"{problems[0]}. Nothing was written.", json_mode=json_output)
    store_out, func_out = _assemble_pieces(
        layouts, shared=shared, marker=str(cfg.marker), json_output=json_output
    )
    merged_text = _compose_definitions(layouts, store_out, func_out, input_eol=input_eol)
    extern_report: ExternReport | None = None
    if consolidate:
        merged_text, extern_report = consolidate_declarations(merged_text)
        _warn_externs(extern_report)
    payload = _merge_payload(
        output_path=output_path,
        func_out=func_out,
        store_out=store_out,
        input_files=input_files,
        cfg=cfg,
        dry_run=dry_run,
        delete=delete,
        consolidate=consolidate,
        extern_report=extern_report,
    )
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
    _commit_definitions(
        meta=meta,
        new_file=new_file,
        output_path=output_path,
        merged_text=merged_text,
        out_encoding=out_encoding,
        function_rows=[row for piece in func_out for row in piece.rows],
        data_rows=[row for piece in store_out for row in piece.rows]
        + [row for layout in layouts for row in layout.carried],
        json_output=json_output,
    )
    if delete:
        _delete_inputs(input_files, output_path)
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
    )


def main_entry() -> None:
    """Run the Typer CLI application."""
    from rebrew.cli import run_standalone

    run_standalone(main)


if __name__ == "__main__":
    main_entry()
