"""merge.py - Merge single-function C files into one multi-function file.

Combines multiple annotated source files into a single compilation unit,
deduplicating preamble lines and sorting function blocks by virtual address.

With ``--shared``, twin files (same body, different target markers — the
per-target copies ``cross-import`` used to make) collapse into one stacked
block per body (one ``// FUNCTION: <target> <va>`` marker per target,
ADR-022): the migration path from N copies to one shared file.  Bodies
that differ between targets are refused, never averaged.
"""

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import typer

from rebrew.annotation import (
    NEW_FUNC_CAPTURE_RE,
    NEW_KV_RE,
    block_markers,
    parse_c_file_text,
    split_annotation_sections,
)
from rebrew.cli import (
    TargetOption,
    console,
    error_exit,
    json_print,
    require_config,
)
from rebrew.config import ProjectConfig
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
    strip_comment_blocks,
)

app = typer.Typer(
    help="Merge single-function C files into one multi-function file.",
    rich_markup_mode="rich",
    epilog=(
        "[bold]Examples:[/bold]\n\n"
        "  rebrew merge src/game/func1.c src/game/func2.c -o merged.c · Merge two files\n\n"
        "  rebrew merge src/game/ -o all_funcs.c · · · · · · · · · · · Merge entire directory\n\n"
        "  rebrew merge src/game/ -o merged.c --delete · · · · · · · · Merge and delete originals\n\n"
        "  rebrew merge src/game/ -o merged.c --consolidate · · · · · · Hoist declarations to the top\n\n"
        "[dim]Shared preambles (includes, typedefs) are deduplicated. "
        "Each function block retains its // FUNCTION: marker.[/dim]"
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
    # function pointer: ``int (*fp)(void)`` — must be tested before the plain
    # declarator rule or the base type matches instead of the symbol
    m = re.search(r"\(\s*\*\s*(\w+)", d)
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
        header += [ext if ext.endswith(";") else ext + ";" for ext in report.resolved]
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


def _normalize_body(block: str) -> str:
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

    Groups by normalized body (:func:`_normalize_body`).  A group whose
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
        key = _normalize_body(block)
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


def _block_metadata(block: str) -> dict[str, Any] | None:
    """Extract marker module/VA from a function block."""
    for line in block.splitlines():
        marker = NEW_FUNC_CAPTURE_RE.match(line.strip())
        if marker:
            return {
                "module": marker.group("module"),
                "va": int(marker.group("va"), 16),
            }
    return None


def _merge_preambles(preambles: list[str]) -> str:
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
        for line in strip_comment_blocks(preamble).splitlines():
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


@app.callback(invoke_without_command=True)
def main(
    sources: list[str] | None = typer.Argument(None, help="Input source files (or directories)"),
    output: str = typer.Option(..., "--output", "-o", help="Output merged source file"),
    dry_run: bool = typer.Option(False, "--dry-run", help="Preview changes without writing"),
    force: bool = typer.Option(False, "--force", help="Overwrite output if it exists"),
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
        "Bodies that differ are refused, never merged",
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
        if enc != "utf-8":
            out_encoding = enc
            legacy_encodings.add(enc)

        preamble, blocks = split_annotation_sections(text)
        preambles.append(preamble)
        included_inputs.append(file_path)

        for block in blocks:
            meta = _block_metadata(block)
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
    merged_preamble = _merge_preambles(preambles)

    # DATA/GLOBAL definition blocks sort before FUNCTION blocks: C89 needs
    # declarations before use, and VA order alone can place a string table
    # after its function (a GOLDTL 0x40xxxx function sorts before SERVER
    # 0x1002xxxx data it references).  Within each class, VA ascending.
    def _block_rank(block: str) -> int:
        for line in block.splitlines():
            m = NEW_FUNC_CAPTURE_RE.match(line.strip())
            if m:
                return 0 if m.group("type") in ("DATA", "GLOBAL") else 1
        return 1

    ranked = sorted(blocks_with_va, key=lambda x: (_block_rank(x[1]), x[0]))
    sorted_blocks = [block for _, block in ranked]
    merged_text = merged_preamble + "\n\n".join(sorted_blocks) + "\n"
    if consolidate:
        merged_text, extern_report = consolidate_declarations(merged_text)
        for dropped in extern_report.dropped:
            console.print(f"[yellow]merge: dropped unparseable extern {dropped!r}[/yellow]")
        for name, variants in extern_report.conflicts.items():
            kept = next((d for d in extern_report.resolved if _extract_extern_name(d) == name), "")
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
        typer.confirm(
            f"Delete {len(included_inputs)} input file(s) after merge?", abort=True, err=True
        )

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
