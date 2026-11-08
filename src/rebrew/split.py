"""split.py – Split a multi-function C file into single-function files.

Resolves each C definition through its managed function row in
``rebrew-functions.toml`` and writes one output file per function, preserving
the shared preamble in every output file.  With ``--va``, a single function
can be extracted into its own file while its definition is removed from the
original source.  File-scope storage stays in the original; no legacy
annotation block is read.
"""

from __future__ import annotations

lazy import bisect
lazy import os
lazy import shutil
lazy import unicodedata
lazy from pathlib import Path
lazy from typing import Any

import typer
from typer.models import TyperPath

from rebrew.cli import (
    TargetOption,
    confirm_abort,
    console,
    error_exit,
    json_print,
    require_config,
)
lazy from rebrew.c_parser import (
    declares_function as declares_function,
)
lazy from rebrew.c_parser import (
    find_function_name_in_node as find_function_name_in_node,
)
lazy from rebrew.c_parser import (
    find_variable_roles,
)
lazy from rebrew.c_parser import (
    node_text as node_text,
)
lazy from rebrew.c_parser import (
    parse_c_structure as parse_c_structure,
)
lazy from rebrew.metadata.bindings import (
    FUNCTION_KINDS,
)
lazy from rebrew.metadata.functions import (
    identity_file,
    load_metadata,
    record_function_rows,
    stored_file_matches,
    validate_identity_file,
)
lazy from rebrew.source_layout import (
    SourceSpan as SourceSpan,
)
lazy from rebrew.source_layout import (
    decode_span,
    gap_is_blank,
)
lazy from rebrew.source_layout import (
    source_layout as source_layout,
)
lazy from rebrew.source_layout import (
    span_extent as span_extent,
)
lazy from rebrew.source_paths import rebase_includes
lazy from rebrew.sources import (
    source_exts,
)
lazy from rebrew.utils import (
    atomic_write_bytes,
    atomic_write_text,
    preset_module_key,
    read_source_text,
    rel_display_path,
    source_newline,
)

app = typer.Typer(
    help="Split multi-function C files into single-function files.",
    rich_markup_mode="rich",
    epilog=(
        "[bold]Examples:[/bold]\n\n"
        "  # Split all functions into individual files\n"
        "  rebrew source split src/game/funcs.c\n\n"
        "  # Extract one function by VA\n"
        "  rebrew source split src/game/funcs.c --va 0x10003da0\n\n"
        "  # Pick one of two definitions under exclusive branches\n"
        "  rebrew source split src/game/funcs.c --va 0x10003da0 --occurrence 2\n\n"
        "  # Preview without writing files\n"
        "  rebrew source split src/game/funcs.c --dry-run\n\n"
        "  # Custom output directory\n"
        "  rebrew source split src/game/funcs.c --output out\n\n"
        "  # Overwrite existing output files\n"
        "  rebrew source split src/game/funcs.c --force\n\n"
        "[dim]Each output file gets the shared preamble (includes, typedefs) plus one function. With --va, the function is extracted and removed from the original source.[/dim]"
    ),
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


# --- Definition split --------------------------------------------------------
# Extents come from the tree-sitter spans of the original text, so the slice
# keeps the file's bytes, encoding, and newlines.  Storage definitions are not
# copied: a non-static object the extracted function uses becomes an extern,
# and a static or a preprocessor wrapped dependency is refused.


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


def _uses_at(raw: bytes, span: SourceSpan) -> set[str]:
    """Read this definition's uses without including file-scope initializers."""
    _, _, uses = find_variable_roles(decode_span(raw, span.start, span.end))
    return uses


def _overlaps(start: int, end: int, extents: list[tuple[int, int]]) -> bool:
    return any(start < ext_end and end > ext_start for ext_start, ext_end in extents)


def shared_preamble(raw: bytes, spans: list[SourceSpan], extents: list[tuple[int, int]]) -> str:
    """Shared includes, macros, typedefs, and externs, in source order.

    Comments attached to a function or object stay with that owner.  A
    Optional addresses move with the declaration they precede.
    """
    attached = {index for span in spans for index in span.attached}
    copyable = [
        span
        for index, span in enumerate(spans)
        if span.kind == "preamble" or (span.kind == "comment" and index not in attached)
    ]
    # Next span start at or after a position, in O(log n); the per-piece
    # generator scan over every span was quadratic on comment-heavy files.
    starts = sorted(span.start for span in spans)
    pieces: list[str] = []
    for index, span in enumerate(copyable):
        end = span.end
        following_index = bisect.bisect_left(starts, span.end)
        following = starts[following_index] if following_index < len(starts) else len(raw)
        nxt = copyable[index + 1].start if index + 1 < len(copyable) else following
        boundary = min(nxt, following)
        if gap_is_blank(raw, end, boundary):
            end = boundary
        if _overlaps(span.start, end, extents):
            continue
        pieces.append(decode_span(raw, span.start, end))
    return "".join(pieces)


def _matching_rows(
    entries: dict[tuple[str, int], dict[str, Any]],
    rel: str,
    definition: str,
) -> list[tuple[str, int, dict[str, Any]]]:
    rows: list[tuple[str, int, dict[str, Any]]] = []
    for (module, va), entry in entries.items():
        kind = str(entry.get("kind") or "FUNCTION")
        if kind not in FUNCTION_KINDS:
            continue
        if not stored_file_matches(str(entry.get("file") or ""), rel):
            continue
        if definition not in row_labels(entry):
            continue
        rows.append((module, va, entry))
    return rows


def _split_definitions(
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
    occurrence: int | None = None,
) -> None:
    """Split a pure-C file from its function rows.  ``error_exit`` does not return."""
    meta = getattr(cfg, "metadata_dir", None)
    if meta is None:
        error_exit("No metadata directory configured", json_mode=json_output)
    rel = os.path.relpath(source_path, meta).replace(os.sep, "/")
    if occurrence is not None and va is None:
        error_exit("--occurrence requires --va", json_mode=json_output)
    try:
        raw, spans = source_layout(text)
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
        target_module_name = preset_module_key(cfg.module) if cfg.module else ""
        matched = [
            (module, row_va, entry)
            for (module, row_va), entry in entries.items()
            if row_va == target_va
            and (not target_module_name or preset_module_key(module) == target_module_name)
            and str(entry.get("kind") or "FUNCTION") in FUNCTION_KINDS
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
        found = sorted(
            (span for span in functions if span.name in names),
            key=lambda span: span.start,
        )
        if not found:
            error_exit(
                f"No C definition for VA 0x{target_va:08x} in {source_path.name}",
                json_mode=json_output,
            )
        if len(found) > 1 or len(names & {span.name for span in functions}) > 1:
            if occurrence is None:
                error_exit(
                    f"Ambiguous C definition for VA 0x{target_va:08x} in {source_path.name}; "
                    "select one with --occurrence N",
                    json_mode=json_output,
                )
            if not 1 <= occurrence <= len(found):
                error_exit(
                    f"--occurrence {occurrence} is outside the {len(found)} definition(s) "
                    f"for VA 0x{target_va:08x} in {source_path.name}",
                    json_mode=json_output,
                )
            found = [found[occurrence - 1]]
        selected = found
    else:
        grouped: list[SourceSpan] = []
        target_module_name = preset_module_key(cfg.module) if cfg.module else ""
        for span in functions:
            rows = [
                row
                for row in _matching_rows(entries, rel, span.name)
                if not target_module_name or preset_module_key(row[0]) == target_module_name
            ]
            if rows:
                grouped.append(span)
        if len(grouped) < 2:
            error_exit(
                "Input must contain at least two function definitions to split, "
                "or two function rows for this file. "
                "Use --va to extract a single function instead.",
                json_mode=json_output,
            )
        selected = grouped

    extents = {id(span): span_extent(raw, span, spans) for span in selected}
    problems: list[str] = []
    for span in selected:
        if span.inside_pp or not span.proto:
            problems.append(f"{span.name} is inside a preprocessor conditional or did not parse")
            continue
        direct = _uses_at(raw, span)
        for other in functions:
            if other is span:
                continue
            if other.static and other.name in direct:
                problems.append(f"{span.name} depends on static {other.name}")
            if span.static and span.name in _uses_at(raw, other):
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
                f"No function row for {span.name} in {source_path.name}",
                json_mode=json_output,
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
            {
                "span": span,
                "rows": rows,
                "path": out_path,
                "file": new_file,
                "dir": dest_dir,
            }
        )

    conflicts = [plan["path"] for plan in plans if not force and plan["path"].exists()]
    if conflicts:
        error_exit(
            f"Output file already exists: {conflicts[0]} "
            f"({len(conflicts)} conflict(s) total, nothing was written; "
            "re-run with --force to overwrite)",
            json_mode=json_output,
        )

    preamble = shared_preamble(raw, spans, list(extents.values()))
    rendered: list[tuple[dict[str, Any], str]] = []
    for plan in plans:
        span = plan["span"]
        direct = _uses_at(raw, span)
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
        body = decode_span(raw, start, end)
        parts = [preamble]
        if extras:
            if parts[-1] and not parts[-1].endswith(("\n", "\r")):
                parts.append(eol)
            parts.append(eol.join(extras) + eol)
        if parts[-1] and not parts[-1].endswith("\n"):
            parts.append(eol)
        parts.append(body)
        content = rebase_includes("".join(parts), source_path.parent, plan["path"].parent)
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
                kind="confirmation_required",
                hint="Pass --force to skip the prompt.",
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
            record_function_rows(meta, identity_rows)
        except Exception as exc:
            import logging

            if bak_created:
                bak_path.unlink(missing_ok=True)
            # Restore atomically: the source is read by other commands while
            # this runs, and a crash mid-restore must not leave it truncated.
            # A restore failure must not mask the original error, and the
            # created outputs must still be cleaned up.
            restore_exc: Exception | None = None
            try:
                atomic_write_bytes(source_path, source_bytes)
            except OSError as restore_exc:
                logging.getLogger(__name__).warning(
                    "split: could not restore %s after failure: %s", source_path, restore_exc
                )
            for path in created:
                path.unlink(missing_ok=True)
            detail = f" ({restore_exc})" if restore_exc is not None else ""
            error_exit(
                f"Split did not finish ({exc}). The source was restored{detail}.",
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
    source: str = typer.Argument(
        ...,
        help="Path to a multi-function source file",
        click_type=TyperPath(path_type=str),
    ),
    va: str | None = typer.Option(
        None, "--va", help="Extract a single function by VA (hex) into its own file"
    ),
    occurrence: int | None = typer.Option(
        None,
        "--occurrence",
        min=1,
        help=(
            "1-based C definition to pick when a VA has several definitions, for example "
            "under mutually exclusive preprocessor branches"
        ),
    ),
    output_dir: str | None = typer.Option(
        None,
        "--output",
        "-o",
        help="Output directory",
        click_type=TyperPath(path_type=str),
    ),
    dry_run: bool = typer.Option(False, "--dry-run", help="Preview changes without writing"),
    force: bool = typer.Option(
        False,
        "--force",
        help="Overwrite existing output files; also skips the --va extraction prompt",
    ),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
    target: str | None = TargetOption,
) -> None:
    """Split a multi-function C file into one file per function definition.

    With --va, extract a single function into its own file (preamble included). Without --va, split ALL functions into individual files.
    """
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

    exts = source_exts(cfg) or [".c"]
    try:
        text, encoding = read_source_text(source_path)
        from rebrew.metadata.bindings import source_bindings

        source_bindings(text, source_path, None, None, cfg.metadata_dir)
    except (OSError, ValueError) as exc:
        error_exit(str(exc), json_mode=json_output)
    _split_definitions(
        cfg=cfg,
        source_path=source_path,
        text=text,
        encoding=encoding,
        va=va,
        occurrence=occurrence,
        output_dir=output_dir,
        dry_run=dry_run,
        force=force,
        json_output=json_output,
        out_ext=source_path.suffix or exts[0],
    )


def main_entry() -> None:
    """Run the Typer CLI application."""
    from rebrew.cli import run_standalone

    run_standalone(main)


if __name__ == "__main__":
    main_entry()
