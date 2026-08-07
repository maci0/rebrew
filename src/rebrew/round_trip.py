"""``rebrew round-trip`` — splice matched function bytes back into the target PE.

Pipeline: enumerate every EXACT/RELOC function from rebrew-function.toml,
compile each via the existing compile_and_compare path, apply COFF relocations
against the active target's function + data catalogs, splice the patched
bytes into a byte copy of the original PE at each function's file offset,
SHA-256 the result, write ``<binary>.reasm`` next to the original, exit
non-zero on any unexpected byte mismatch.

PROVEN functions are deliberately skipped — their bytes differ from the
original by design (semantic equivalence, not byte equivalence) — and are
reported as ``skipped_proven`` without altering the spliced PE.
"""

from __future__ import annotations

import hashlib
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import typer
from rich.console import Console, Group
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from rebrew.binary_loader import BinaryInfo, SectionInfo, load_binary, va_to_file_offset
from rebrew.cli import (
    EXIT_MISMATCH,
    EXIT_OK,
    STATUS_COLORS,
    TargetOption,
    error_exit,
    iter_annotations,
    iter_sources,
    json_print,
    require_config,
    target_marker,
)
from rebrew.compile import compile_to_obj
from rebrew.config import ProjectConfig
from rebrew.core.matching import (
    UnresolvedSymbolError,
    apply_coff_relocations,
    build_symbol_resolver,
)
from rebrew.matcher.parsers import (
    CoffRelocRecord,
    parse_obj_relocs_full,
    parse_obj_symbol_bytes,
)
from rebrew.metadata import get_entry

console = Console(stderr=True)

app = typer.Typer(
    help="Splice every matched function back into the target PE and verify byte equality.",
    rich_markup_mode="rich",
)


@app.callback(invoke_without_command=True)
def main(
    out: Path | None = typer.Option(
        None, "--out", help="Override output PE path (default: <binary>.reasm next to target)"
    ),
    no_write: bool = typer.Option(
        False, "--no-write", help="Skip writing the reassembled PE; still emit the report"
    ),
    symbol_filter: str | None = typer.Option(
        None, "--filter", help="Only round-trip functions whose symbol contains this substring"
    ),
    strict_catalog: bool = typer.Option(
        False,
        "--strict-catalog",
        help="Exit non-zero when any EXACT/RELOC function hits an unresolved catalog symbol",
    ),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
    target: str | None = TargetOption,
) -> None:
    cfg = require_config(target=target, json_mode=json_output)
    raise typer.Exit(
        _run_round_trip(
            cfg,
            out=out,
            no_write=no_write,
            symbol_filter=symbol_filter,
            json_output=json_output,
            strict_catalog=strict_catalog,
        )
    )


@dataclass
class _SpliceFn:
    symbol: str
    va: int
    size: int
    status: str
    path: Path
    module: str
    cflags: list[str]


def _collect_splice_set(
    cfg: ProjectConfig, symbol_filter: str | None
) -> tuple[list[_SpliceFn], list[_SpliceFn], int]:
    """Walk every annotated function, partition into splice set, PROVEN-skip set, and other count.

    Returns (splice_list, proven_list, other_count) where other_count includes functions
    with metadata but status not in {EXACT, RELOC, PROVEN} (e.g. NEAR_MATCHING, STUB, missing).
    """
    splice: list[_SpliceFn] = []
    proven: list[_SpliceFn] = []
    other_count = 0
    for path, anns in iter_annotations(
        iter_sources(cfg.reversed_dir, cfg),
        target=target_marker(cfg),
        metadata_dir=cfg.metadata_dir,
    ):
        for ann in anns:
            if symbol_filter and symbol_filter not in ann.symbol:
                continue
            md = get_entry(cfg.metadata_dir, ann.va, ann.module)  # canonical: (dir, va, module)
            status = md.get("status", "STUB")
            # iter_annotations(..., metadata_dir=...) already merges cflags into the
            # annotation, so prefer ann.cflags as the single source of truth.
            # Fall back to the project-default cflags (e.g. ``/O2 /Gd``) — without
            # this fallback, functions whose metadata has no explicit ``cflags`` key
            # would compile with only ``base_cflags`` (missing ``/O2``), producing
            # frame-pointer prologues that don't match the original optimized code.
            cflags_str = (
                getattr(ann, "cflags", "")
                or md.get("cflags", "")
                or getattr(cfg, "cflags", "")
                or ""
            )
            fn = _SpliceFn(
                symbol=ann.symbol,
                va=ann.va,
                size=int(md.get("size", 0) or 0),
                status=status,
                path=path,
                module=ann.module,
                cflags=cflags_str.split(),
            )
            if status in ("EXACT", "RELOC"):
                splice.append(fn)
            elif status == "PROVEN":
                proven.append(fn)
            else:
                other_count += 1
    return splice, proven, other_count


def _compile_and_extract(
    cfg: ProjectConfig, fn: _SpliceFn, work_dir: Path
) -> tuple[bytes, list[CoffRelocRecord], dict[str, bytes], bool, str]:
    """Compile fn.path inside ``work_dir`` and pull out (text, relocs, str_syms, ok, detail).

    Returns ``(text_bytes, reloc_records, str_symbols, ok, detail)`` where ``str_symbols``
    is a mapping of ``{symbol_name: string_bytes}`` for any MSVC-generated string
    constants (`$SG<N>`) referenced by the function. On compile failure ``ok`` is
    False and ``detail`` carries the compiler error; ``text`` is empty and ``relocs`` is [].
    """
    obj_path, err = compile_to_obj(cfg, fn.path, fn.cflags, work_dir)
    if obj_path is None:
        return b"", [], {}, False, err or "compile failed"

    text, _reloc_offsets = parse_obj_symbol_bytes(obj_path, fn.symbol)
    if text is None:
        return b"", [], {}, False, f"symbol {fn.symbol} not found in .obj"
    relocs = parse_obj_relocs_full(obj_path, fn.symbol)
    str_syms = _extract_string_symbols(obj_path, {r.symbol for r in relocs})
    return bytes(text), relocs, str_syms, True, ""


def _sg_key(name: str) -> str:
    """Normalize MSVC ``$SG`` / ``_$SG`` symbol names for membership tests."""
    return name.lstrip("_") if name.startswith("_") else name


def _extract_string_symbols(obj_path: str | Path, symbol_names: set[str]) -> dict[str, bytes]:
    """Extract bytes for MSVC ``$SG<N>`` string constants referenced by relocations.

    These compiler-generated names refer to inline string literals placed in
    ``.rdata$<N>`` or ``.data`` of the .obj. Returns ``{sym_name: bytes}`` keyed
    by the **reloc-side** symbol name (so later resolve/apply steps see the same
    spelling the reloc table used). Content includes the trailing NUL so target
    scans match whole strings, not prefixes of longer ones.
    """
    sg_by_key: dict[str, str] = {}
    for s in symbol_names:
        if "$SG" in s:
            sg_by_key[_sg_key(s)] = s
    if not sg_by_key:
        return {}
    import lief

    coff = lief.COFF.parse(str(obj_path))
    if coff is None:
        return {}
    out: dict[str, bytes] = {}
    for sym in coff.symbols:
        name = sym.name or ""
        reloc_name = sg_by_key.get(_sg_key(name))
        if reloc_name is None or sym.section is None:
            continue
        sec_data = bytes(sym.section.content)
        start = sym.value
        if start < 0 or start >= len(sec_data):
            continue
        # Include the NUL terminator so target search cannot match a prefix.
        end = sec_data.find(b"\x00", start)
        content = sec_data[start:] if end < 0 else sec_data[start : end + 1]
        if content:
            out[reloc_name] = content
    return out


def _resolve_string_symbols_in_target(
    target_bytes: bytes,
    str_syms: dict[str, bytes],
    sections: dict[str, SectionInfo],  # SectionInfo dict from BinaryInfo
) -> dict[str, int]:
    """Find each string literal in the target's .rdata/.data and return VAs.

    *str_syms* values should be NUL-terminated (see :func:`_extract_string_symbols`)
    so a short literal cannot bind to a longer string that shares its prefix.
    """
    found: dict[str, int] = {}
    # Scan .rdata and .data sections only.
    candidate_secs = []
    for name in (".rdata", ".data"):
        sec = sections.get(name)
        if sec is not None:
            candidate_secs.append((sec.va, sec.size, sec.file_offset))
    for sym_name, content in str_syms.items():
        if not content:
            continue
        for sec_va, sec_size, file_off in candidate_secs:
            pos = target_bytes.find(content, file_off, file_off + sec_size)
            if pos >= 0:
                # Convert file offset to VA.
                found[sym_name] = sec_va + (pos - file_off)
                break
    return found


def _run_round_trip(
    cfg: ProjectConfig,
    *,
    out: Path | None,
    no_write: bool,
    symbol_filter: str | None,
    json_output: bool,
    strict_catalog: bool = False,
) -> int:
    """Top-level orchestration. Returns the process exit code."""
    if cfg.image_base == 0:
        error_exit(
            "round-trip requires a non-zero image_base in rebrew-project.toml",
            json_mode=json_output,
        )
    try:
        original = cfg.target_binary.read_bytes()
    except FileNotFoundError:
        error_exit(f"target binary missing: {cfg.target_binary}", json_mode=json_output)

    reasm = bytearray(original)
    # info is loaded lazily — only parsed when at least one function reaches
    # the file-offset lookup.  This avoids touching LIEF when the splice set
    # is empty or every entry fails compilation.
    info: BinaryInfo | None = None

    splice_set, proven_set, other_count = _collect_splice_set(cfg, symbol_filter)
    funcs_by_va, data_by_name = _load_catalogs(cfg)
    resolve_va = build_symbol_resolver(funcs_by_va, data_by_name)

    mismatches: list[dict[str, str | None]] = []
    skipped_catalog: list[dict[str, str | None]] = []  # entries we can't splice due to catalog gaps
    spliced_vas: set[str] = set()
    extra_string_syms: dict[str, int] = {}
    with tempfile.TemporaryDirectory(prefix="rebrew-rt-") as td:
        work_dir = Path(td)
        for fn in splice_set:
            text, relocs, str_syms, ok, detail = _compile_and_extract(cfg, fn, work_dir)
            if not ok:
                mismatches.append(_mismatch(fn, "compile_drift", detail))
                continue
            # Resolve MSVC $SG<N> strings by matching their content in the target.
            if str_syms:
                if info is None:
                    info = load_binary(cfg.target_binary)
                resolved = _resolve_string_symbols_in_target(info.data, str_syms, info.sections)
                extra_string_syms.update(resolved)
                # Rebuild the resolver to include the new symbols.
                merged_data = dict(data_by_name)
                merged_data.update(extra_string_syms)
                resolve_va = build_symbol_resolver(funcs_by_va, merged_data)
            try:
                patched = apply_coff_relocations(
                    text,
                    relocs,
                    resolve_va,
                    section_va=fn.va,
                )
            except UnresolvedSymbolError as exc:
                # Catalog gap — we can't splice but the original bytes are still
                # in the reasm buffer, so SHA equality is preserved.  Don't count
                # this as a mismatch by default; --strict-catalog fails the run.
                skipped_catalog.append(_mismatch(fn, "unresolved_symbol", exc.symbol))
                continue
            except NotImplementedError as exc:
                mismatches.append(_mismatch(fn, "reloc_application_failed", str(exc)))
                continue
            if fn.size <= 0:
                mismatches.append(_mismatch(fn, "oversize", "size <= 0 in metadata"))
                continue
            # va_to_file_offset does not raise; it falls back to (va - text_va + text_raw_offset).
            # The downstream oversize check catches any VA that would write outside the buffer.
            if info is None:
                info = load_binary(cfg.target_binary)
            offset = va_to_file_offset(info, fn.va)
            end = offset + fn.size
            if end > len(reasm) or len(patched) < fn.size:
                mismatches.append(_mismatch(fn, "oversize", None))
                continue
            # Sanity: patched bytes must match the original at this offset.
            # Split reasons so diagnosis is accurate:
            #   - no relocs applied → compile_drift (wrong code / cflags / size)
            #   - relocs applied → catalog_resolution_drift (wrong symbol VA)
            original_slice = bytes(original[offset:end])
            if bytes(patched[: fn.size]) != original_slice:
                first_diff = next((i for i in range(fn.size) if patched[i] != original_slice[i]), 0)
                reason = "catalog_resolution_drift" if relocs else "compile_drift"
                mismatches.append(
                    _mismatch(
                        fn,
                        reason,
                        f"first byte diff at offset 0x{first_diff:x}",
                    )
                )
                continue
            reasm[offset:end] = patched[: fn.size]
            spliced_vas.add(f"0x{fn.va:08x}")

    sha_original = hashlib.sha256(bytes(original)).hexdigest()
    sha_reasm = hashlib.sha256(bytes(reasm)).hexdigest()
    # Match = byte-exactness of the rebuilt PE AND no verification failures.
    # Passthrough fallbacks keep the SHA equal even when a splice fails, but a
    # mismatch (compile drift, oversize, reloc failure, drift) means a function
    # in the splice set was not verified — the round trip is incomplete, so the
    # CLI exits non-zero (docs: "exit 1 on mismatch").  Catalog gaps are
    # informational unless --strict-catalog is set.
    catalog_ok = not strict_catalog or not skipped_catalog
    # Also fail under --strict-catalog when the splice set was non-empty but
    # nothing was actually verified (pure passthrough of claimed EXACT/RELOC).
    nothing_verified = strict_catalog and bool(splice_set) and not spliced_vas and not mismatches
    match = not mismatches and sha_original == sha_reasm and catalog_ok and not nothing_verified

    out_path = out or cfg.target_binary.with_suffix(cfg.target_binary.suffix + ".reasm")
    if not no_write:
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_bytes(bytes(reasm))

    # Byte-coverage accounting: how much of .text came from our compilation
    # versus passthrough from the input PE.
    spliced_bytes = sum(
        fn.size for fn in splice_set if f"0x{fn.va:08x}" in spliced_vas and fn.size > 0
    )
    proven_bytes = sum(fn.size for fn in proven_set if fn.size > 0)
    # Keep the lazy-LIEF contract (see the `info` comment above): when nothing
    # reached the file-offset lookup, don't parse the binary — coverage is 0.
    text_size = info.text_size if info is not None else 0
    passthrough_bytes = max(text_size - spliced_bytes - proven_bytes, 0)

    report = {
        "schema_version": 1,
        "target": cfg.target_name,
        "binary": str(cfg.target_binary),
        "arch": getattr(cfg, "arch", ""),
        "out": str(out_path) if not no_write else None,
        "sha256_original": sha_original,
        "sha256_reasm": sha_reasm,
        "match": match,
        "strict_catalog": strict_catalog,
        "spliced": len(spliced_vas),
        "skipped_proven": len(proven_set),
        "skipped_other": other_count,
        "skipped_catalog": skipped_catalog,
        "mismatches": mismatches,
        "byte_coverage": {
            "text_size": text_size,
            "spliced_bytes": spliced_bytes,
            "proven_bytes": proven_bytes,
            "passthrough_bytes": passthrough_bytes,
            "spliced_pct": round(100.0 * spliced_bytes / text_size, 2) if text_size else 0.0,
            "passthrough_pct": (
                round(100.0 * passthrough_bytes / text_size, 2) if text_size else 0.0
            ),
        },
    }
    if json_output:
        json_print(report)
    else:
        _render_rich(report)

    return EXIT_OK if match else EXIT_MISMATCH


def _mismatch(fn: _SpliceFn, reason: str, detail: str | None) -> dict[str, str | None]:
    return {
        "symbol": fn.symbol,
        "va": f"0x{fn.va:08x}",
        "status": fn.status,
        "reason": reason,
        "detail": detail,
    }


def _load_catalogs(cfg: ProjectConfig) -> tuple[dict[int, str], dict[str, int]]:
    """Build the function ``{va: name}`` map + the data ``{name: va}`` map.

    Sources, in priority order:
      * Function VAs: union of ``cfg.dll_exports`` and every annotated function in
        ``cfg.reversed_dir`` (annotations are the canonical inter-function name source
        for the active target).
      * Data names: union of every ``rebrew-data.toml`` reachable from the source tree,
        filtered to the active target's marker (``ann.module``).
    """
    from rebrew.data_metadata import load_data_metadata

    marker = target_marker(cfg)  # honors cfg.marker overrides
    funcs: dict[int, str] = dict(cfg.dll_exports)  # base layer: PE exports
    annotated_dirs: set[Path] = set()
    # Scan source files plus any sibling headers (e.g. library_msvc.h) for
    # LIBRARY/FUNCTION annotations.  Headers carry CRT and Win32 symbol VAs.
    sources = list(iter_sources(cfg.reversed_dir, cfg))
    for h in cfg.reversed_dir.rglob("*.h"):
        sources.append(h)
    for path, anns in iter_annotations(
        sources,
        target=marker,
        metadata_dir=cfg.metadata_dir,
    ):
        annotated_dirs.add(path.parent)
        for ann in anns:
            if ann.module == marker and ann.name:
                funcs[ann.va] = ann.name

    # Data names live in cfg.metadata_dir/rebrew-data.toml — not under each
    # annotated source's parent directory.
    data: dict[str, int] = {}
    for (mod, va), meta in load_data_metadata(cfg.metadata_dir).items():
        if mod == marker and meta.get("name"):
            data[meta["name"]] = va
    return funcs, data


def _render_rich(report: dict[str, Any]) -> None:
    """Rich panel + table summary, aligned with ``rebrew status`` and ``rebrew verify --summary``."""
    binary_path = report.get("binary", "")
    binary_name = Path(binary_path).name if binary_path else ""
    arch = report.get("arch", "")
    match = report.get("match", False)
    mismatches = report.get("mismatches", [])
    spliced = report.get("spliced", 0)
    skipped_proven = report.get("skipped_proven", 0)
    skipped_other = report.get("skipped_other", 0)
    sha_orig = report.get("sha256_original", "")
    sha_reasm = report.get("sha256_reasm", "")
    out_path = report.get("out")
    byte_coverage = report.get("byte_coverage", {}) or {}

    # --- Panel header ---
    header_parts: list[str] = []
    if binary_name:
        header_parts.append(f"[bold]{binary_name}[/bold]")
    if binary_path:
        header_parts.append(f"[dim]{binary_path}[/dim]")
    if arch:
        header_parts.append(f"[dim]({arch})[/dim]")
    title = "[bold]Rebrew Round-Trip[/bold]"
    if header_parts:
        title += "  " + "  ".join(header_parts)

    # --- Stats line ---
    skipped_catalog = report.get("skipped_catalog", []) or []
    n_catalog = len(skipped_catalog)
    n_mismatch = len(mismatches)

    # --- Coverage bar (include catalog gaps so incompleteness is visible) ---
    total = spliced + skipped_proven + skipped_other + n_catalog + n_mismatch
    bar_items: list[Text] = []
    if total > 0:
        bar_width = 40
        filled = int(bar_width * spliced / total)
        bar_text = Text()
        bar_text.append("  Spliced  ", style="bold")
        bar_text.append("█" * filled, style="green")
        bar_text.append("░" * (bar_width - filled), style="dim")
        bar_text.append(f"  {spliced}/{total}", style="bold")
        bar_items.append(bar_text)

    stats_parts: list[str] = [
        f"[green]spliced: {spliced}[/green]",
        f"[cyan]proven skipped: {skipped_proven}[/cyan]",
        f"[dim]other skipped: {skipped_other}[/dim]",
    ]
    if n_catalog:
        stats_parts.append(f"[yellow]catalog gaps: {n_catalog}[/yellow]")
    if n_mismatch:
        stats_parts.append(f"[red]mismatches: {n_mismatch}[/red]")
    stats_text = Text.from_markup("  " + "  ·  ".join(stats_parts))

    # --- SHA lines ---
    sha_orig_disp = sha_orig[:16] if sha_orig else "-"
    sha_reasm_disp = sha_reasm[:16] if sha_reasm else "-"
    sha_orig_text = Text.from_markup(f"  [dim]Original:[/dim] [cyan]{sha_orig_disp}[/cyan]")
    sha_reasm_text = Text.from_markup(f"  [dim]Reasm:   [/dim] [cyan]{sha_reasm_disp}[/cyan]")

    summary_items: list[Text] = [
        *bar_items,
        Text(""),  # spacer
        stats_text,
    ]

    # --- Byte coverage breakdown ---
    if byte_coverage.get("text_size", 0) > 0:
        text_size = byte_coverage["text_size"]
        spliced_b = byte_coverage.get("spliced_bytes", 0)
        proven_b = byte_coverage.get("proven_bytes", 0)
        passthru_b = byte_coverage.get("passthrough_bytes", 0)
        spliced_pct = byte_coverage.get("spliced_pct", 0.0)
        passthru_pct = byte_coverage.get("passthrough_pct", 0.0)
        bar_width = 40
        sp_filled = int(bar_width * spliced_b / text_size) if text_size else 0
        pr_filled = int(bar_width * proven_b / text_size) if text_size else 0
        pass_filled = max(bar_width - sp_filled - pr_filled, 0)
        byte_bar = Text()
        byte_bar.append("  .text    ", style="bold")
        byte_bar.append("█" * sp_filled, style="green")
        if pr_filled:
            byte_bar.append("█" * pr_filled, style="cyan")
        byte_bar.append("░" * pass_filled, style="dim")
        byte_bar.append(
            f"  {spliced_b:,}/{text_size:,}B compiled ({spliced_pct:.1f}%)",
            style="bold",
        )
        summary_items.append(byte_bar)
        breakdown = Text.from_markup(
            f"  [green]compiled: {spliced_b:,}B ({spliced_pct:.1f}%)[/green]  ·  "
            f"[cyan]proven: {proven_b:,}B[/cyan]  ·  "
            f"[dim]passthrough: {passthru_b:,}B ({passthru_pct:.1f}%)[/dim]"
        )
        summary_items.append(breakdown)
        summary_items.append(Text(""))

    summary_items.append(sha_orig_text)
    summary_items.append(sha_reasm_text)

    if out_path:
        summary_items.append(Text.from_markup(f"  [dim]Output:[/dim] {out_path}"))

    # --- Mismatch table ---
    table_items: list[Table] = []
    if mismatches:
        summary_items.append(Text(""))  # spacer before table
        table = Table(title="Mismatches", show_header=True, header_style="bold")
        table.add_column("VA", style="cyan", no_wrap=True)
        table.add_column("Symbol", style="magenta")
        table.add_column("Status", style="bold")
        table.add_column("Reason")
        table.add_column("Detail")
        for m in mismatches:
            st = m.get("status", "")
            color = STATUS_COLORS.get(st, "red")
            st_str = f"[{color}]{st}[/{color}]" if st else "-"
            reason = m.get("reason", "")
            detail = m.get("detail") or "-"
            table.add_row(m.get("va", "-"), m.get("symbol", "-"), st_str, reason, detail)
        table_items.append(table)

    # --- Subtitle (verdict) ---
    if match:
        subtitle = "[bold green]✔ match[/bold green]"
    else:
        n = len(mismatches)
        subtitle = f"[bold red]✗ {n} mismatch{'es' if n != 1 else ''}[/bold red]"

    # --- Assemble panel ---
    all_content: list[Text | Table] = [*summary_items, *table_items]
    panel = Panel(
        Group(*all_content),
        title=title,
        subtitle=subtitle,
        border_style="blue",
    )
    console.print(panel)


def main_entry() -> None:
    """Run the Typer CLI application."""
    app()


if __name__ == "__main__":
    main_entry()
