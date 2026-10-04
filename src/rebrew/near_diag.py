"""near_diag.py — the ``rebrew diagnose near`` command.

Compiles the C source, extracts the target bytes, and hands the pair to
:mod:`rebrew.near_analysis`, which classifies the delta.  This module owns the
CLI surface: argument parsing, the Rich output, BLOCKER metadata writes, and
``--catalog``.  The analysis itself lives in the library so the GA engine and
``probe`` can reach it without importing a command.
"""

from __future__ import annotations

import contextlib
import re
from pathlib import Path
from typing import Any

import typer
from rich.console import Console
from rich.table import Table

from rebrew.analysis import DEFAULT_CS_ARCH, DEFAULT_CS_MODE
from rebrew.cli import (
    TargetOption,
    console,
    error_exit,
    json_print,
    parse_va,
    require_config,
)
from rebrew.near_analysis import analyze, blocker_text, catalog_markdown
from rebrew.utils import untrusted_ident
from rebrew.workspace.status import NEAR_MATCH_CANDIDATE_STATUSES


class _DiagnoseError(RuntimeError):
    """Raised when a single function cannot be diagnosed (extract/compile/parse)."""


def _diagnose_one(
    cfg: Any,
    source_path: Path,
    ann: Any,
    va_int: int,
    size_val: int,
    fix_blocker: bool,
    dry_run: bool = False,
    name_to_va: dict[str, int] | None = None,
) -> dict[str, Any]:
    """Compile and classify ONE function; returns the analysis result.

    *name_to_va* is the ``build_name_to_va`` map; batch mode builds it once
    and passes it in, since building it rescans every source.

    The result dict gains a ``blocker_written`` key (bool).  Raises
    :class:`_DiagnoseError` when the target bytes cannot be extracted or the
    source does not compile — single mode turns that into an error_exit,
    batch mode records it per-function and keeps going.
    """

    from rebrew.binary_loader import extract_raw_bytes
    from rebrew.coff_reloc import build_iat_region, build_name_to_va, smart_reloc_compare
    from rebrew.compile import compile_to_obj
    from rebrew.compile_overrides import resolve_compile_overrides
    from rebrew.matcher.parsers import parse_obj_symbol_and_relocs

    target_bytes = extract_raw_bytes(cfg.target_binary, va_int, size_val)
    if not target_bytes:
        raise _DiagnoseError(f"Failed to extract target bytes at 0x{va_int:08x}")

    toolchain, cflags = resolve_compile_overrides(
        cfg,
        Path(source_path).resolve().parent,
        getattr(ann, "toolchain", ""),
        getattr(ann, "cflags", ""),
        getattr(ann, "module", ""),
    )
    from rebrew.temp_dirs import writable_temp_dir

    workdir = writable_temp_dir("rebrew_near_diag_")
    try:
        obj_path, err = compile_to_obj(
            cfg,
            source_path,
            cflags.split(),
            workdir,
            toolchain=toolchain,
        )
        if obj_path is None:
            raise _DiagnoseError(f"Compile error: {err}")
        symbol = ann.symbol or ""
        compiled_bytes, reloc_dict, full_relocs = parse_obj_symbol_and_relocs(obj_path, symbol)
        if compiled_bytes is None:
            raise _DiagnoseError(f"Symbol '{symbol or '(none)'}' not found in compiled .obj")
    finally:
        from rebrew.temp_dirs import remove_temp_dir

        with contextlib.suppress(OSError):
            remove_temp_dir(workdir)

    # Mask ONLY the relocation sites that survive the same DIR32/REL32 address
    # validation as `rebrew test` / `rebrew verify` — an invalid reloc (wrong
    # call target or global address) is a REAL byte delta, not reloc noise.
    # Without this, near-diag reported "RELOC-level" for functions the
    # canonical status path classifies NEAR_MATCHING (e.g. _CreateListenSocket
    # in guild: 8 real bytes beyond the validated reloc sites).
    reloc_offsets: set[int] = set()
    coff_relocs = full_relocs if full_relocs else reloc_dict
    if coff_relocs:
        if name_to_va is None:
            name_to_va = build_name_to_va(cfg)
        cmp_obj = compiled_bytes
        cmp_tgt = target_bytes
        if len(cmp_obj) > len(cmp_tgt):
            cmp_obj = cmp_obj[: len(cmp_tgt)]
        else:
            cmp_tgt = cmp_tgt[: len(cmp_obj)]
        if cmp_obj:
            _matched, _mc, _tot, valid_relocs, _invalid = smart_reloc_compare(
                cmp_obj,
                cmp_tgt,
                coff_relocs,
                name_to_va=name_to_va,
                section_va=va_int,
                iat_region=build_iat_region(cfg),
            )
            reloc_offsets = set(valid_relocs)

    result = analyze(
        target_bytes,
        compiled_bytes,
        reloc_offsets,
        va_int,
        cs_arch=getattr(cfg, "capstone_arch", DEFAULT_CS_ARCH),
        cs_mode=getattr(cfg, "capstone_mode", DEFAULT_CS_MODE),
    )
    blocker_written = False
    if fix_blocker and not result["verdict"].startswith("MATCH"):
        from rebrew.metadata import (
            GA_CEILING_PREFIX,
            get_entry,
            update_field,
            update_source_status,
        )

        existing_blocker = (get_entry(cfg.metadata_dir, va_int, ann.module) or {}).get(
            "blocker", ""
        ) or ""
        if existing_blocker.startswith(GA_CEILING_PREFIX):
            # A GA_CEILING marker is the terminal classification (register- or
            # encoding-only delta, not byte-reproducible from C — written when
            # the GA exhausted).  Replacing it with a plain verdict would
            # silently reopen the GA loop; leave it and say so.
            result["blocker_skipped_ceiling"] = True
        elif dry_run:
            blocker_written = True  # would write, but --dry-run skips it
        else:
            update_field(
                cfg.metadata_dir,
                va_int,
                "blocker",
                blocker_text(result),
                module=ann.module,
                updated_by="near-diag",
            )
            # A blocker note implies NEAR_MATCHING — keep the documented state
            # consistent so status reports count it as documented, not as a
            # bare STUB.
            update_source_status(
                cfg.metadata_dir,
                "NEAR_MATCHING",
                ann.module,
                va_int,
                clear_blockers=False,
            )
            blocker_written = True
    result["blocker_written"] = blocker_written
    return result


def _print_first_mismatch(
    console: Console, first: dict[str, Any] | None, indent: str = "  "
) -> None:
    """Render the decisive first-mismatch diagnosis (dtk ``dol diff`` style).

    The earliest differing instruction is the one to look at first — the
    category it carries is usually the dominant one, and fixing it often
    fixes the whole function.
    """
    if not first:
        return
    offset = f"0x{first['offset']:x}"
    cat = first["category"]
    if first["compiled"]:
        console.print(
            f"{indent}[dim]first mismatch:[/dim] {offset} [{cat}] "
            f"target: {untrusted_ident(first['target'])}  "
            f"vs  compiled: {untrusted_ident(first['compiled'])}"
        )
    else:
        console.print(
            f"{indent}[dim]first mismatch:[/dim] {offset} [{cat}] "
            f"target has extra instruction: {untrusted_ident(first['target'])}"
        )


def _run_all_batch(cfg: Any, fix_blocker: bool, json_output: bool, dry_run: bool = False) -> None:
    """Classify every NEAR_MATCHING function in the project (--all).

    Mirrors ``prove --all`` collection: iterate sources, keep annotations with
    status NEAR_MATCHING and a known size.  Per-function failures are recorded
    in the results list instead of aborting the batch.
    """
    from rebrew.annotation import parse_c_file_multi
    from rebrew.sources import iter_sources, target_marker

    sources = list(iter_sources(cfg.reversed_dir, cfg))
    tm = target_marker(cfg)
    candidates: list[tuple[Path, Any]] = []
    all_annos: list[Any] = []
    skipped_files: list[str] = []
    for src in sources:
        try:
            annos = parse_c_file_multi(src, target_name=tm, metadata_dir=cfg.metadata_dir)
        except Exception as exc:  # one bad file must not kill the batch
            skipped_files.append(f"{src.name}: {exc}")
            continue
        all_annos.extend(annos)
        for a in annos:
            # Mirror prove --all: SIZE_MISMATCH functions are equally valid
            # classification targets (they do not byte-match and deserve a
            # blocker note); NEAR_MATCHING is not the only candidate status.
            if a.status in NEAR_MATCH_CANDIDATE_STATUSES and a.size:
                candidates.append((src, a))

    if not candidates:
        if json_output:
            json_print(
                {
                    "total": 0,
                    "classified": 0,
                    "failed": 0,
                    "skipped_files": skipped_files,
                    "results": [],
                }
            )
        else:
            console.print("[dim]No NEAR_MATCHING/SIZE_MISMATCH functions found to diagnose.[/dim]")
            for skip in skipped_files:
                console.print(f"[yellow]  skipped: {untrusted_ident(skip)}[/yellow]")
        return

    if not json_output:
        console.print(f"\n[bold]Diagnosing {len(candidates)} NEAR_MATCHING function(s)[/bold]\n")

    from rebrew.coff_reloc import build_name_to_va

    name_to_va = build_name_to_va(cfg, annotations=all_annos)
    classified = 0
    failed = 0
    results: list[dict[str, Any]] = []
    for i, (src, ann) in enumerate(candidates, 1):
        symbol = ann.symbol or src.name
        if not json_output:
            console.print(
                f"[bold][{i}/{len(candidates)}][/bold] {untrusted_ident(symbol)} (0x{ann.va:08x})"
            )
        entry: dict[str, Any] = {
            "source": str(src),
            "symbol": symbol,
            "va": f"0x{ann.va:08x}",
            "verdict": None,
            "suggestion": None,
            "mutations": [],
            "blocker_written": False,
            "error": None,
        }
        try:
            result = _diagnose_one(
                cfg, src, ann, ann.va, ann.size, fix_blocker, dry_run, name_to_va=name_to_va
            )
        except _DiagnoseError as e:
            failed += 1
            if not json_output:
                console.print(f"  [yellow]ERROR:[/yellow] {e}")
            entry["error"] = str(e)
            results.append(entry)
            continue
        classified += 1
        if not json_output:
            console.print(
                f"  [bold]{result['verdict']}[/bold] — {untrusted_ident(result['suggestion'][:60])}"
            )
            _print_first_mismatch(console, result.get("first_mismatch"), indent="    ")
            if result.get("mutations"):
                console.print(
                    "    [dim]GA mutations to try:[/dim] " + ", ".join(result["mutations"])
                )
        entry.update(
            {
                "verdict": result["verdict"],
                "suggestion": result["suggestion"],
                "mutations": result.get("mutations", []),
                "first_mismatch": result.get("first_mismatch"),
                "blocker_written": result["blocker_written"],
            }
        )
        results.append(entry)

    if json_output:
        json_print(
            {
                "total": len(candidates),
                "classified": classified,
                "failed": failed,
                "skipped_files": skipped_files,
                "results": results,
            }
        )
        return

    console.print()
    if skipped_files:
        console.print(
            f"[yellow]  {len(skipped_files)} source file(s) skipped (unparseable):[/yellow]"
        )
        for skip in skipped_files[:5]:
            console.print(f"    {untrusted_ident(skip)}")
    console.print("[bold]━━━ near-diag Summary ━━━[/bold]")
    console.print(f"  [bold]{classified}[/bold] classified")
    if failed:
        console.print(f"  [yellow bold]{failed}[/yellow bold] failed")
    if fix_blocker:
        written = sum(1 for r in results if r["blocker_written"])
        verb = "would write" if dry_run else "written"
        console.print(f"  [green bold]{written}[/green bold] BLOCKER metadata {verb}")


app = typer.Typer(
    help="Classify why a NEAR_MATCHING function does not byte-match.",
    rich_markup_mode="rich",
    epilog=(
        "[bold]Examples:[/bold]\n\n"
        "  rebrew diagnose near src/game/func.c · · · · · Classify the delta\n\n"
        "  rebrew diagnose near src/game/func.c --json · · Machine-readable\n\n"
        "  rebrew diagnose near --all --fix-blocker · · · Classify + document all NEAR_MATCHING\n\n"
        "[dim]Categories: register (same insn, different regs), equivalent\n"
        "(semantically equal instruction selection), reloc (relocation-masked),\n"
        "structural (different layout). The verdict suggests whether the delta\n"
        "is likely solvable via C-level changes.[/dim]"
    ),
)


@app.callback(invoke_without_command=True)
def main(
    source: str = typer.Argument(None, help="C source file for the function to diagnose"),
    all_funcs: bool = typer.Option(
        False, "--all", help="Classify every NEAR_MATCHING function in the project"
    ),
    va: str | None = typer.Option(None, "--va", help="Target VA in hex (default: from annotation)"),
    size: int | None = typer.Option(
        None, "--size", help="Target size in bytes (default: from annotation)"
    ),
    fix_blocker: bool = typer.Option(
        False,
        "--fix-blocker",
        help="Write the verdict as BLOCKER metadata for the function (skipped on a match)",
    ),
    catalog: bool = typer.Option(
        False,
        "--catalog",
        help="Print the symptom index (delta category → suggestion → GA mutations)",
    ),
    dry_run: bool = typer.Option(False, "--dry-run", help="Preview changes without writing"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
    target: str | None = TargetOption,
) -> None:
    """Compile SOURCE and classify its byte delta against the target function."""
    if catalog:
        if not json_output:
            print(catalog_markdown(), end="")
        return

    from rebrew.annotation import parse_c_file_multi
    from rebrew.sources import target_marker

    cfg = require_config(target=target, json_mode=json_output)

    if all_funcs:
        if source:
            error_exit("A SOURCE argument cannot be combined with --all", json_mode=json_output)
        if va:
            error_exit("--va cannot be combined with --all", json_mode=json_output)
        _run_all_batch(cfg, fix_blocker, json_output, dry_run)
        return

    if not source:
        error_exit(
            "A SOURCE argument is required (or pass --all to classify every "
            "NEAR_MATCHING function)",
            json_mode=json_output,
        )

    from rebrew.cli import require_source_arg

    # Accept a hex VA or symbol name in addition to a .c path, like
    # `rebrew diff`/`rebrew prove`/`rebrew test` — a VA resolves to its
    # source file via the catalog.
    raw_source = source  # keep the original positional (may itself be a VA)
    source = str(require_source_arg(cfg, source, json_mode=json_output))
    source_path = Path(source).resolve()

    annos = parse_c_file_multi(
        source_path, target_name=target_marker(cfg), metadata_dir=cfg.metadata_dir
    )
    if not annos:
        error_exit(f"No annotations found in {source}", json_mode=json_output)
    va_from_flag = bool(va)  # explicit --va: user override, annotation optional
    va_int = parse_va(va, json_mode=json_output) if va else None
    if va_int is None and re.match(r"^0[xX][0-9a-fA-F]+$", raw_source):
        # The positional argument itself was a hex VA.
        va_int = parse_va(raw_source, json_mode=json_output)
    if va_int is None and not Path(raw_source).exists():
        from rebrew.utils import fold_ident

        want_sym = fold_ident(raw_source.strip()).lstrip("_")
        for a in annos:
            for ident in (a.symbol or "", a.name or ""):
                if fold_ident(ident.strip()).lstrip("_") == want_sym:
                    va_int = a.va
                    break
            if va_int is not None:
                break
    if va_int is None:
        va_int = annos[0].va
    # In a multi-function file, pick the annotation matching the requested VA
    # (the first annotation is the wrong function — it has its own VA/size).
    # When the VA was DERIVED (positional/file) and no annotation matches,
    # refuse rather than silently diagnosing the wrong function with its
    # cflags/symbol/size.  An explicit --va is a user override — the file's
    # compile settings are still intended.
    ann = annos[0]
    matched_annotation = False
    for candidate in annos:
        if candidate.va == va_int:
            ann = candidate
            matched_annotation = True
            break
    if not matched_annotation and not va_from_flag:
        error_exit(
            f"No annotation for VA 0x{va_int:08x} in {source_path.name} — "
            "the resolved file covers different functions",
            json_mode=json_output,
        )
    size_val = size or ann.size
    if not va_int or not size_val:
        error_exit(
            "Cannot determine target VA/size — pass --va and --size or add them to the annotation",
            json_mode=json_output,
        )

    try:
        result = _diagnose_one(cfg, source_path, ann, va_int, size_val, fix_blocker, dry_run)
    except _DiagnoseError as e:
        error_exit(str(e), json_mode=json_output)
    blocker_written = result["blocker_written"]

    if json_output:
        json_print(result)
        return

    table = Table(title=f"Delta classification for 0x{va_int:08x}", show_header=True)
    table.add_column("Category", style="bold")
    table.add_column("Bytes", justify="right")
    table.add_column("% of total", justify="right")
    for cat, data in result["categories"].items():
        if data["bytes"]:
            table.add_row(cat, str(data["bytes"]), f"{data['percent']:.1f}")
    console.print(table)
    console.print(f"[bold]{result['verdict']}[/bold]")
    console.print(untrusted_ident(result["suggestion"]))
    _print_first_mismatch(console, result.get("first_mismatch"))
    if result.get("mutations"):
        console.print("[dim]GA mutations to try:[/dim] " + ", ".join(result["mutations"]))
    if blocker_written:
        # `blocker_written` is also True under --dry-run (the caller previews
        # the write), so the wording must follow the mode — the batch path in
        # this module already prints "would write".
        verb = "would write BLOCKER metadata:" if dry_run else "Wrote BLOCKER metadata:"
        console.print(f"[green]{verb}[/green] {untrusted_ident(blocker_text(result)[:80])}...")


def main_entry() -> None:
    """Run the Typer CLI application."""
    from rebrew.cli import run_standalone

    run_standalone(main)


if __name__ == "__main__":
    main_entry()
