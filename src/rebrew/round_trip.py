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

import typer
from rich.console import Console

from rebrew.binary_loader import BinaryInfo, load_binary, va_to_file_offset
from rebrew.cli import (
    EXIT_MISMATCH,
    EXIT_OK,
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
from rebrew.matcher.parsers import parse_obj_relocs_full, parse_obj_symbol_bytes
from rebrew.metadata import get_entry

console = Console(stderr=True)

app = typer.Typer(
    help="Splice every matched function back into the target PE and verify byte equality.",
    rich_markup_mode="rich",
)


@app.callback(invoke_without_command=True)
def main(
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
    out: Path | None = typer.Option(
        None, "--out", help="Override output PE path (default: <binary>.reasm next to target)"
    ),
    no_write: bool = typer.Option(
        False, "--no-write", help="Skip writing the reassembled PE; still emit the report"
    ),
    symbol_filter: str | None = typer.Option(
        None, "--filter", help="Only round-trip functions whose symbol contains this substring"
    ),
    target: str | None = TargetOption,
) -> None:
    cfg = require_config(target=target)
    raise typer.Exit(
        _run_round_trip(
            cfg, out=out, no_write=no_write, symbol_filter=symbol_filter, json_output=json_output
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
            cflags_str = getattr(ann, "cflags", "") or md.get("cflags", "") or ""
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


def _compile_and_extract(cfg: ProjectConfig, fn: _SpliceFn, work_dir: Path):
    """Compile fn.path inside ``work_dir`` and pull out (text, relocs, ok, detail).

    Returns ``(text_bytes, reloc_records, ok, detail)``. On compile failure ``ok`` is
    False and ``detail`` carries the compiler error; ``text`` is empty and ``relocs`` is [].
    """
    obj_path, err = compile_to_obj(cfg, fn.path, fn.cflags, work_dir)
    if obj_path is None:
        return b"", [], False, err or "compile failed"

    text, _reloc_offsets = parse_obj_symbol_bytes(obj_path, fn.symbol)
    if text is None:
        return b"", [], False, f"symbol {fn.symbol} not found in .obj"
    relocs = parse_obj_relocs_full(obj_path, fn.symbol)
    return bytes(text), relocs, True, ""


def _run_round_trip(
    cfg: ProjectConfig,
    *,
    out: Path | None,
    no_write: bool,
    symbol_filter: str | None,
    json_output: bool,
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

    mismatches: list[dict] = []
    with tempfile.TemporaryDirectory(prefix="rebrew-rt-") as td:
        work_dir = Path(td)
        for fn in splice_set:
            text, relocs, ok, detail = _compile_and_extract(cfg, fn, work_dir)
            if not ok:
                mismatches.append(_mismatch(fn, "compile_drift", detail))
                continue
            try:
                patched = apply_coff_relocations(
                    text,
                    relocs,
                    resolve_va,
                    image_base=cfg.image_base,
                    section_va=fn.va,
                )
            except UnresolvedSymbolError as exc:
                mismatches.append(_mismatch(fn, "unresolved_symbol", exc.symbol))
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
            reasm[offset:end] = patched[: fn.size]

    sha_original = hashlib.sha256(bytes(original)).hexdigest()
    sha_reasm = hashlib.sha256(bytes(reasm)).hexdigest()
    match = not mismatches and sha_original == sha_reasm

    out_path = out or cfg.target_binary.with_suffix(cfg.target_binary.suffix + ".reasm")
    if not no_write:
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_bytes(bytes(reasm))

    report = {
        "target": cfg.target_name,
        "binary": str(cfg.target_binary),
        "out": str(out_path) if not no_write else None,
        "sha256_original": sha_original,
        "sha256_reasm": sha_reasm,
        "match": match,
        "spliced": len(splice_set) - len(mismatches),
        "skipped_proven": len(proven_set),
        "skipped_other": other_count,
        "mismatches": mismatches,
    }
    if json_output:
        json_print(report)
    else:
        _render_rich(report)

    return EXIT_OK if match else EXIT_MISMATCH


def _mismatch(fn: _SpliceFn, reason: str, detail: str | None) -> dict:
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
    for path, anns in iter_annotations(
        iter_sources(cfg.reversed_dir, cfg),
        target=marker,
        metadata_dir=cfg.metadata_dir,
    ):
        annotated_dirs.add(path.parent)
        for ann in anns:
            if ann.module == marker and ann.name:
                funcs[ann.va] = ann.name

    data: dict[str, int] = {}
    for d in annotated_dirs:
        for (mod, va), meta in load_data_metadata(d).items():
            if mod == marker and meta.get("name"):
                data[meta["name"]] = va
    return funcs, data


def _render_rich(report: dict) -> None:
    """Compact Rich summary mirroring `rebrew verify --summary`."""
    if report["match"]:
        console.print(
            f"[bold green]✔[/] round-trip clean: "
            f"{report['spliced']} functions spliced, "
            f"{report['skipped_proven']} PROVEN skipped"
        )
        return
    console.print(f"[bold red]✗[/] {len(report['mismatches'])} unexpected mismatches")
    for m in report["mismatches"]:
        console.print(
            f"  [yellow]{m['symbol']}[/] @ {m['va']} → {m['reason']}"
            + (f" ({m['detail']})" if m.get("detail") else "")
        )


def main_entry() -> None:
    """Run the Typer CLI application."""
    app()


if __name__ == "__main__":
    main_entry()
