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

from rebrew.annotation import (
    DATA_MARKERS,
    FUNCTION_MARKERS,
    NEW_FUNC_CAPTURE_RE,
    NEW_KV_RE,
    block_markers,
    parse_c_file_text,
    split_annotation_sections,
)
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
from rebrew.data_metadata import load_data_metadata, record_migrated_data_markers
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
from rebrew.split import (
    SourceSpan,
    row_labels,
    shared_preamble,
    source_layout,
    span_extent,
    stored_file_matches,
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
        "  rebrew source merge src/game/func1.c src/game/func2.c --output merged.c · Merge two files\n\n"
        "  rebrew source merge src/game/ --output all_funcs.c · · · · · · · · · · · Merge entire directory\n\n"
        "  rebrew source merge src/game/ --output merged.c --delete · · · · · · · · Merge and delete originals\n\n"
        "  rebrew source merge src/game/ --output merged.c --consolidate · · · · · · Hoist declarations to the top\n\n"
        "[dim]Shared preambles (includes, typedefs) are deduplicated. "
        "An unmigrated file keeps its // FUNCTION: markers. "
        "A migrated file is copied from its function rows.[/dim]"
    ),
)

# ---------------------------------------------------------------------------
# --consolidate: hoist/deduplicate declarations in a merged TU
# ---------------------------------------------------------------------------

_INCLUDE_RE = re.compile(r"^\s*#\s*include\s+")
_EXTERN_RE = re.compile(r"^\s*extern\s+")
_TYPEDEF_RE = re.compile(r"^\s*typedef\s+")
_PRAGMA_INTRINSIC_RE = re.compile(r"^\s*#\s*pragma\s+intrinsic\s*\(")
_GLOBAL_COMMENT_RE = re.compile(r"^\s*(?://|/\*)\s*GLOBAL:")


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
    global_comments: dict[int, str] = {}
    lines_to_remove: set[int] = set()

    i = 0
    while i < len(lines):
        stripped = lines[i].strip()
        if stripped == '#include "rebrew_types.h"':
            lines_to_remove.add(i)
        elif _INCLUDE_RE.match(stripped):
            includes.append(stripped)
            lines_to_remove.add(i)
        elif _GLOBAL_COMMENT_RE.match(stripped):
            global_comments[i] = stripped
        elif _EXTERN_RE.match(stripped):
            # a GLOBAL: comment above an extern documents the global — keep it
            if i > 0 and _GLOBAL_COMMENT_RE.match(lines[i - 1].strip()):
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
    """The block minus identity lines: markers and their SIZE lines.

    Two per-target copies of one function differ exactly here (module, VA,
    and the destination's canonical SIZE); the C body must be identical.
    Everything else — code, comments, other KV lines — compares exactly.
    """
    kept: list[str] = []
    for line in block.splitlines():
        stripped = line.strip()
        if NEW_FUNC_CAPTURE_RE.match(stripped):
            continue
        kv = NEW_KV_RE.match(stripped) if stripped.startswith(("//", "/*")) else None
        if kv and kv.group("key").upper() == "SIZE":
            continue
        kept.append(line.rstrip())
    return "\n".join(kept).strip()


def _stack_twin_blocks(blocks: list[str]) -> str:
    """One stacked block from twin blocks sharing a normalized body.

    Each input's marker (+ its SIZE line when present) is preserved above
    the single shared body, so per-target VA/SIZE survive the collapse.
    """
    marker_lines: list[str] = []
    body_lines: list[str] | None = None
    for block in blocks:
        head: list[str] = []
        rest: list[str] = []
        seen_code = False
        for line in block.splitlines():
            stripped = line.strip()
            if not seen_code and (
                NEW_FUNC_CAPTURE_RE.match(stripped)
                or (
                    stripped.startswith(("//", "/*"))
                    and (kv := NEW_KV_RE.match(stripped))
                    and kv.group("key").upper() == "SIZE"
                )
            ):
                head.append(line.rstrip())
                continue
            seen_code = True
            rest.append(line.rstrip())
        marker_lines.extend(head)
        if body_lines is None:
            body_lines = rest
    while body_lines and not body_lines[0].strip():
        body_lines.pop(0)
    while body_lines and not body_lines[-1].strip():
        body_lines.pop()
    return "\n".join(marker_lines + ["", *(body_lines or [])]) + "\n"


def _collapse_twins(
    blocks_with_va: list[tuple[int, str]], json_output: bool
) -> list[tuple[int, str]]:
    """Collapse same-body blocks into one stacked block per body.

    Groups by normalized body (:func:`normalize_body`).  A group whose
    blocks name ≥2 distinct modules is one function in several targets:
    emit a single stacked block (markers + SIZE lines preserved, one shared
    body).  A group with one distinct module passes through unchanged.

    Two blocks with the same function NAME but different bodies are NOT
    twins — they diverged between targets and no single body serves both.
    Merging them would silently ship one target's bytes to the other, so
    refuse with the names instead.
    """
    from rebrew.c_parser import extract_function_name_from_line

    groups: dict[str, list[tuple[int, str]]] = {}
    order: list[str] = []
    for va, block in blocks_with_va:
        key = normalize_body(block)
        if key not in groups:
            groups[key] = []
            order.append(key)
        groups[key].append((va, block))

    out: list[tuple[int, str]] = []
    for key in order:
        group = groups[key]
        modules = {mod for _, b in group for mod, _ in block_markers(b)}
        if len(modules) < 2:
            out.extend(group)
            continue
        stacked = _stack_twin_blocks([b for _, b in group])
        out.append((min(va for va, _ in group), stacked))

    # Divergent twins: same C symbol, different bodies.  Find them by name
    # across groups (a name appearing in ≥2 groups with different bodies).
    # Candidate lines must look like definitions: block-comment continuations
    # (`* ...`) fool the extractor into prose symbols (`adjacent`), masking
    # the real divergence (guild ls_LoadSavegameHeader merged two full TUs).
    names: dict[str, set[str]] = {}
    for key in order:
        for _, block in groups[key]:
            sym = ""
            for line in block.splitlines():
                stripped = line.strip()
                if not stripped or stripped.startswith(("//", "/*", "#", "*")):
                    continue
                if stripped.rstrip().endswith(";") or "(" not in stripped:
                    continue
                got = extract_function_name_from_line(stripped)
                if got:
                    sym = got[0]
                    break
            if sym:
                names.setdefault(sym, set()).add(key)
    divergent = sorted(sym for sym, keys in names.items() if len(keys) > 1)
    if divergent:
        from rebrew.cli import error_exit as _exit

        _exit(
            "Refusing shared merge: these functions differ between targets "
            f"({', '.join(divergent)}) — one body cannot serve both. Merge "
            "only the identical twins, or keep per-target files.",
            json_mode=json_output,
        )
    return out


def block_metadata(block: str) -> dict[str, Any] | None:
    """Extract marker module/VA from a function block."""
    for line in block.splitlines():
        marker = NEW_FUNC_CAPTURE_RE.match(line.strip())
        if marker:
            return {
                "module": marker.group("module"),
                "va": int(marker.group("va"), 16),
            }
    return None


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

    *exclude* (the merge output) is skipped: a directory argument that already
    contains a previous merge output would otherwise feed it back in as an
    input, so ``--force`` re-runs failed with a duplicate-VA error.
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
        if resolved_exclude is not None and p.resolve() == resolved_exclude:
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


def _file_borne_line(line: str) -> bool:
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


def _drop_file_borne(text: str) -> str:
    return "".join(line for line in text.splitlines(keepends=True) if not _file_borne_line(line))


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
    body = _drop_file_borne(raw[start:end].decode("utf-8", errors="surrogateescape"))
    return _Piece(
        name=span.name,
        text=body,
        norm=_norm_c(body),
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
        if str(entry.get("marker_type") or "FUNCTION") in FUNCTION_MARKERS
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
) -> tuple[_InputLayout, list[str]]:
    """Preamble, storage, and functions from one migrated input."""
    rel = identity_file(file_path, meta)
    functions = [span for span in spans if span.kind == "function"]
    stores = [span for span in spans if span.kind == "storage"]
    file_rows = _function_rows(entries, rel)
    file_data = _data_rows(data_entries, rel)
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
    problems.extend(_missing_rows(file_data, seen_data, file_path.name, rel, data=True))
    layout = _InputLayout(
        rel=rel,
        preamble=shared_preamble(raw, spans, [], sole=False),
        va=min((piece.va for piece in func_pieces), default=_NO_VA),
        stores=store_pieces,
        functions=func_pieces,
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
    json_output: bool,
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
            raw, spans = source_layout(text)
        except ImportError as exc:
            error_exit(str(exc), json_mode=json_output)
        layout, layout_problems = _layout_one(
            file_path, raw, spans, meta, entries, data_entries, claimed, claimed_data
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


def _assemble_pieces(
    layouts: list[_InputLayout], *, shared: bool, marker: str, json_output: bool
) -> tuple[list[_Piece], list[_Piece]]:
    """Storage first, then functions.  Files are ordered by their lowest function VA."""
    layouts.sort(key=lambda item: (item.va, item.rel))
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


def _compose_markerless(
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
    for piece in store_out:
        if piece.text.strip():
            parts.append(piece.text.strip("\r\n"))
    for piece in func_out:
        if piece.text.strip():
            parts.append(piece.text.strip("\r\n"))
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


def _markerless_payload(
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
    record_migrated_markers(meta, payload)


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
    record_migrated_data_markers(meta, payload)


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


def _commit_markerless(
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


def _report_markerless(
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


def _merge_markerless(
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
        meta, input_files, entries, data_entries, json_output
    )
    if problems:
        error_exit(f"{problems[0]}. Nothing was written.", json_mode=json_output)
    store_out, func_out = _assemble_pieces(
        layouts, shared=shared, marker=str(cfg.marker), json_output=json_output
    )
    merged_text = _compose_markerless(layouts, store_out, func_out, input_eol=input_eol)
    extern_report: ExternReport | None = None
    if consolidate:
        merged_text, extern_report = consolidate_declarations(merged_text)
        _warn_externs(extern_report)
    payload = _markerless_payload(
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
    _commit_markerless(
        meta=meta,
        new_file=new_file,
        output_path=output_path,
        merged_text=merged_text,
        out_encoding=out_encoding,
        function_rows=[row for piece in func_out for row in piece.rows],
        data_rows=[row for piece in store_out for row in piece.rows],
        json_output=json_output,
    )
    if delete:
        _delete_inputs(input_files, output_path)
    _report_markerless(
        json_output=json_output,
        payload=payload,
        func_out=func_out,
        input_files=input_files,
        output_path=output_path,
        delete=delete,
    )


@app.callback(invoke_without_command=True)
def main(
    sources: list[str] | None = typer.Argument(None, help="Input source files (or directories)"),
    output: str = typer.Option(..., "--output", "-o", help="Output merged source file"),
    dry_run: bool = typer.Option(False, "--dry-run", help="Preview changes without writing"),
    force: bool = typer.Option(
        False,
        "--force",
        help="Overwrite output if it exists, skip the --delete confirmation, "
        "and apply a migrated merge without a prompt",
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
        help="Collapse twin files (same body, different target markers) into "
        "one stacked block per body (one // FUNCTION: marker per target). "
        "A migrated file keeps one C definition and retargets every row "
        "that names an input. Bodies that differ are refused, never merged",
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

    marked = False
    plain = False
    for file_path in input_files:
        try:
            preview, _preview_enc = read_source_text(file_path)
        except OSError as exc:
            error_exit(f"Failed to read {file_path}: {exc}", json_mode=json_output)
        _preview_preamble, preview_blocks = split_annotation_sections(preview)
        if preview_blocks:
            marked = True
        else:
            plain = True
    if marked and plain:
        error_exit(
            "Merge inputs mix marker blocks and migrated files. "
            "Migrate every file, or merge the marker files on their own.",
            json_mode=json_output,
        )
    if plain:
        _merge_markerless(
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
        return

    preambles: list[str] = []
    blocks_with_va: list[tuple[int, str]] = []
    included_inputs: list[Path] = []
    # Keyed (module, va) like lint E013: two targets sharing one VA (DLLs
    # at the same base) are distinct functions, not duplicates.
    seen_vas: set[tuple[str, int]] = set()

    # Output is a new file; if any input is a legacy encoding (cp1252/
    # shift_jis), write the merged result in that encoding so non-ASCII
    # comment bytes round-trip instead of being U+FFFD-corrupted.
    out_encoding = "utf-8"
    legacy_encodings: set[str] = set()
    # Line ending the inputs use (the last one read wins; mixed-ending inputs
    # are already inconsistent), so the output is not a mix of the CRLF
    # inside each block and the LF of the joins between them.
    input_eol = "\n"

    for file_path in input_files:
        # One read serves both the annotation parse and the section split —
        # parse_c_file_multi would re-read and re-decode the same file.
        try:
            text, enc = read_source_text(file_path)
        except OSError as exc:
            error_exit(f"Failed to read {file_path}: {exc}", json_mode=json_output)

        annotations = parse_c_file_text(
            text, file_path, None if shared else target_marker(cfg), None, cfg.metadata_dir
        )
        if not annotations:
            continue

        # Recorded AFTER the target/annotation filter: a file that contributes
        # nothing must not dictate the output encoding (it caused a false
        # "conflicting source encodings" abort and spurious encode failures).
        if enc not in ("utf-8", "utf-8-sig"):
            out_encoding = enc
            legacy_encodings.add(enc)

        preamble, blocks = split_annotation_sections(text)
        preambles.append(preamble)
        input_eol = source_newline(text)
        included_inputs.append(file_path)

        for block in blocks:
            meta = block_metadata(block)
            if meta is None:
                continue
            module = str(meta["module"])
            if (
                not shared
                and cfg.marker
                and preset_module_key(module) != preset_module_key(cfg.marker)
            ):
                continue
            va = meta["va"]
            key = (preset_module_key(module), va)
            if key in seen_vas:
                error_exit(
                    f"Duplicate VA 0x{va:08x} across input files — merge would "
                    "create duplicate FUNCTION markers (lint E013). Fix the "
                    "duplicate annotation first.",
                    json_mode=json_output,
                )
            seen_vas.add(key)
            blocks_with_va.append((va, block.strip("\n")))

    if shared:
        blocks_with_va = _collapse_twins(blocks_with_va, json_output)

    if len(blocks_with_va) < 2 and not shared:
        error_exit(
            f"Need at least two matching function blocks for target '{cfg.marker}'",
            json_mode=json_output,
        )
    if shared and not blocks_with_va:
        error_exit("No function blocks found in input files", json_mode=json_output)

    if len(legacy_encodings) > 1:
        # One output has one encoding; two legacy inputs cannot both round-trip.
        error_exit(
            "input files use conflicting source encodings "
            f"({', '.join(sorted(legacy_encodings))}); merge writes a single encoding — "
            "convert the inputs to UTF-8 first",
            json_mode=json_output,
        )

    extern_report: ExternReport | None = None
    merged_preamble = merge_preambles(preambles)

    # Data definition blocks (every marker in ``DATA_MARKERS``: GLOBAL, DATA,
    # VTABLE, STRING) sort before code blocks: C89 needs declarations before
    # use, and VA order alone can place a string table after its function (a
    # GOLDTL 0x40xxxx function sorts before SERVER 0x1002xxxx data it
    # references).  Within each class, VA ascending.
    def _block_rank(block: str) -> int:
        for line in block.splitlines():
            m = NEW_FUNC_CAPTURE_RE.match(line.strip())
            if m:
                return 0 if m.group("type") in DATA_MARKERS else 1
        return 1

    ranked = sorted(blocks_with_va, key=lambda x: (_block_rank(x[1]), x[0]))
    sorted_blocks = [block for _, block in ranked]
    merged_text = merged_preamble + "\n\n".join(sorted_blocks) + "\n"
    if input_eol == "\r\n":
        # Blocks carry their own CRLF, the joins above an LF, and the \r that
        # strip("\n") left at each block's tail; normalise all three.
        merged_text = re.sub(r"\r\n|\r|\n", input_eol, merged_text)
    if consolidate:
        merged_text, extern_report = consolidate_declarations(merged_text)
        for dropped in extern_report.dropped:
            console.print(f"[yellow]merge: dropped unparseable extern {dropped!r}[/yellow]")
        # resolved is scanned once per conflict name below; index it instead.
        resolved_by_name: dict[str, str] = {}
        for decl in extern_report.resolved:
            decl_name = _extract_extern_name(decl)
            if decl_name is not None:
                resolved_by_name.setdefault(decl_name, decl)
        for name, variants in extern_report.conflicts.items():
            kept = resolved_by_name.get(name, "")
            console.print(
                f"[yellow]merge: conflicting externs for {name}: "
                f"kept {kept!r} over {[v for v in variants if v != kept]!r}[/yellow]"
            )

    if delete and not dry_run and not force:
        if json_output:
            error_exit(
                "--delete removes input files after merge. "
                "Pass --force to apply it in --json mode, or omit --delete.",
                json_mode=True,
            )
        confirm_abort(f"Delete {len(included_inputs)} input file(s) after merge?")

    if not dry_run:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        try:
            atomic_write_text(output_path, merged_text, encoding=out_encoding)
        except UnicodeEncodeError as exc:
            offending = exc.object[exc.start : exc.end]
            error_exit(
                f"merged source cannot be encoded as {out_encoding} "
                f"(offending text {offending!r}); convert the inputs to a common "
                "encoding first",
                json_mode=json_output,
            )
        if delete:
            for file_path in included_inputs:
                if file_path.resolve() == output_path.resolve():
                    continue
                file_path.unlink(missing_ok=True)

    payload = {
        "output": str(output_path),
        "count": len(sorted_blocks),
        "input_count": len(included_inputs),
        "dry_run": dry_run,
        "deleted": bool(delete and not dry_run),
        "consolidated": consolidate,
        "inputs": [rel_display_path(p, cfg.reversed_dir) for p in included_inputs],
        "vas": [f"0x{va:08x}" for va, _ in sorted(blocks_with_va, key=lambda x: x[0])],
        "extern_dropped": extern_report.dropped if extern_report else [],
        "extern_conflicts": dict(extern_report.conflicts) if extern_report else {},
    }
    if json_output:
        json_print(payload)
        return

    action = "Would merge" if dry_run else "Merged"
    console.print(
        f"{action} [bold]{len(sorted_blocks)}[/] functions from {len(included_inputs)} files "
        f"into {output_path.name}"
    )
    if delete and not dry_run:
        console.print("Deleted original input files after merge")
    elif shared and not dry_run and not delete:
        console.print(
            "[dim]Twins are now stacked in the output — re-run with --delete "
            "to remove the redundant copies.[/dim]"
        )


def main_entry() -> None:
    """Run the Typer CLI application."""
    from rebrew.cli import run_standalone

    run_standalone(main)


if __name__ == "__main__":
    main_entry()
