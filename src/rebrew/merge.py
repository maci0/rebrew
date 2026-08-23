"""merge.py - Merge single-function C files into one multi-function file.

Combines multiple annotated source files into a single compilation unit,
deduplicating preamble lines and sorting function blocks by virtual address.
"""

import re
from pathlib import Path
from typing import Any

import typer
from rich.console import Console

from rebrew.annotation import (
    NEW_FUNC_CAPTURE_RE,
    parse_c_file_text,
    split_annotation_sections,
)
from rebrew.cli import (
    TargetOption,
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
    read_source_text,
    rel_display_path,
    strip_comment_blocks,
)

console = Console(stderr=True)

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


def _resolve_externs(externs: list[str]) -> list[str]:
    """Deduplicate externs, keeping the most specific declaration per symbol."""
    by_name: dict[str, list[str]] = {}
    order: list[str] = []
    for ext in externs:
        name = _extract_extern_name(ext)
        if name is None:
            continue
        if name not in by_name:
            order.append(name)
        by_name.setdefault(name, []).append(ext)
    out = []
    for name in order:
        unique = list(dict.fromkeys(by_name[name]))
        out.append(max(unique, key=_extern_specificity) if len(unique) > 1 else unique[0])
    return out


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


def consolidate_declarations(text: str) -> str:
    """Hoist unique includes/externs/typedefs/intrinsics to the top of *text*.

    Each merged function block carries its own declarations, which conflict
    when compiled as a single TU.  The pass moves unique declarations to a
    header, resolves conflicting extern signatures by specificity, merges
    ``#pragma intrinsic`` lists, and strips the moved lines from the bodies.
    Also drops the legacy ``#include "rebrew_types.h"`` (the file no longer
    exists).
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
    resolved = _resolve_externs(externs)
    if resolved:
        header += [ext if ext.endswith(";") else ext + ";" for ext in resolved]
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
    return out if out.endswith("\n") else out + "\n"


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
    """Merge preambles with exact-line dedup and collapsed blank lines.

    Comment blocks (e.g. Ghidra decompilation references) are stripped before
    dedup: they are per-function noise, and a naive union of multiple
    preambles leaves the ``/* */`` nesting malformed so the merged file does
    not compile (C2143 on orphaned comment lines).
    """
    seen: set[str] = set()
    merged_lines: list[str] = []

    for preamble in preambles:
        for line in strip_comment_blocks(preamble).splitlines():
            if not line.strip():
                if merged_lines and merged_lines[-1]:
                    merged_lines.append("")
                continue
            if line in seen:
                continue
            seen.add(line)
            merged_lines.append(line)

    while merged_lines and not merged_lines[-1]:
        merged_lines.pop()

    if not merged_lines:
        return ""
    return "\n".join(merged_lines) + "\n\n"


def _collect_input_files(paths: list[str], cfg: ProjectConfig) -> list[Path]:
    """Resolve input arguments into unique source-file paths."""
    expected_exts = set(source_exts(cfg)) or {".c"}
    files: list[Path] = []
    seen: set[Path] = set()

    for raw in paths:
        p = Path(raw)
        if p.is_dir():
            for src in iter_sources(p, cfg):
                if src not in seen:
                    seen.add(src)
                    files.append(src)
            continue

        if not p.exists() or not p.is_file():
            continue
        if p.suffix not in expected_exts:
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
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
    target: str | None = TargetOption,
) -> None:
    """Merge multiple single-function files into one multi-function file."""
    if not sources:
        error_exit("Merge requires at least two source files", json_mode=json_output)

    cfg = require_config(target=target, json_mode=json_output)
    input_files = _collect_input_files(sources, cfg)
    if len(input_files) < 2:
        error_exit("Merge requires at least two source files", json_mode=json_output)

    output_path = Path(output)
    if output_path.exists() and not force:
        error_exit(f"Output file already exists: {output_path}", json_mode=json_output)

    preambles: list[str] = []
    blocks_with_va: list[tuple[int, str]] = []
    included_inputs: list[Path] = []
    seen_vas: set[int] = set()

    # Output is a new file; if any input is a legacy encoding (cp1252/
    # shift_jis), write the merged result in that encoding so non-ASCII
    # comment bytes round-trip instead of being U+FFFD-corrupted.
    out_encoding = "utf-8"

    for file_path in input_files:
        # One read serves both the annotation parse and the section split —
        # parse_c_file_multi would re-read and re-decode the same file.
        try:
            text, enc = read_source_text(file_path)
        except OSError as exc:
            error_exit(f"Failed to read {file_path}: {exc}", json_mode=json_output)
        if enc != "utf-8":
            out_encoding = enc

        annotations = parse_c_file_text(text, file_path, target_marker(cfg), None, cfg.metadata_dir)
        if not annotations:
            continue

        preamble, blocks = split_annotation_sections(text)
        preambles.append(preamble)
        included_inputs.append(file_path)

        for block in blocks:
            meta = _block_metadata(block)
            if meta is None:
                continue
            module = str(meta["module"])
            if cfg.marker and module.lower() != cfg.marker.lower():
                continue
            va = meta["va"]
            if va in seen_vas:
                error_exit(
                    f"Duplicate VA 0x{va:08x} across input files — merge would "
                    "create duplicate FUNCTION markers (lint E013). Fix the "
                    "duplicate annotation first.",
                    json_mode=json_output,
                )
            seen_vas.add(va)
            blocks_with_va.append((va, block.strip("\n")))

    if len(blocks_with_va) < 2:
        error_exit(
            f"Need at least two matching function blocks for target '{cfg.marker}'",
            json_mode=json_output,
        )

    merged_preamble = _merge_preambles(preambles)
    sorted_blocks = [block for _, block in sorted(blocks_with_va, key=lambda x: x[0])]
    merged_text = merged_preamble + "\n\n".join(sorted_blocks) + "\n"
    if consolidate:
        merged_text = consolidate_declarations(merged_text)

    if delete and not dry_run and not force:
        if json_output:
            error_exit(
                "--delete removes input files after merge. "
                "Pass --force to apply it in --json mode, or omit --delete.",
                json_mode=True,
            )
        typer.confirm(f"Delete {len(included_inputs)} input file(s) after merge?", abort=True)

    if not dry_run:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        atomic_write_text(output_path, merged_text, encoding=out_encoding)
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
    }
    if json_output:
        json_print(payload)
        return

    console.print(
        f"Merged [bold]{len(sorted_blocks)}[/] functions from {len(included_inputs)} files "
        f"into {output_path.name}"
    )
    if delete and not dry_run:
        console.print("Deleted original input files after merge")


def main_entry() -> None:
    """Run the Typer CLI application."""
    app()


if __name__ == "__main__":
    main_entry()
