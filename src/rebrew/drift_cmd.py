"""``rebrew drift`` -- localise byte drift from branch targets, without disassembling.

Compiles one function, compares its branch targets against the reference's, and
reports the spans whose byte drift those targets measure.  See
:mod:`rebrew.drift` for the arithmetic and why backward jumps invert.

The command answers "where did the bytes go?" for a function that compiles to
roughly the right size but not the right bytes -- the case where a byte-level
diff is a wall of noise because one early size difference shifts everything
after it.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import typer
from rich.console import Console
from rich.table import Table

from rebrew.annotation import parse_c_file_multi, parse_source_metadata
from rebrew.binary_loader import extract_raw_bytes
from rebrew.cli import (
    EXIT_ERROR,
    TargetOption,
    error_exit,
    json_print,
    parse_va,
    require_config,
)
from rebrew.compile import compile_and_compare
from rebrew.compile_overrides import resolve_compile_overrides
from rebrew.drift import DerivedRegion, DriftWindow, derive_regions, drift_windows
from rebrew.sources import target_marker

console = Console(stderr=True)

# Module-form registration (empty ``attr`` in builtins.py) resolves BOTH a
# ``main`` callable and a module-level ``app``.  A module exposing only ``main``
# is silently mounted as an *unavailable stub*, which presents as a working
# command whose ``--help`` lists no options at all -- an easy failure to
# misread as a stale install rather than a missing declaration.
app = typer.Typer(
    help="Localise where compiled bytes drift from the reference, from branch targets.",
    rich_markup_mode="rich",
    epilog=(
        "[bold]Examples:[/bold]\n\n"
        "  rebrew drift src/f.c · · · · · · VA and size from the annotation header\n\n"
        "  rebrew drift --va 0x401000 --size 512 src/f.c · Explicit geometry\n\n"
        "  rebrew drift --json src/f.c · · · Machine-readable windows\n"
    ),
)


def _emit_text(windows: list[DriftWindow], derived: list[DerivedRegion]) -> None:
    if not windows:
        console.print(
            "[yellow]no aligned branch pairs with differing targets[/yellow] — "
            "every same-sized branch agrees on its target, so this function has "
            "no drift this method can measure."
        )
        return

    table = Table(title=f"{len(windows)} branch pair(s) measuring drift")
    table.add_column("at", justify="right")
    table.add_column("ref →", justify="right")
    table.add_column("ours →", justify="right")
    table.add_column("drift", justify="right")
    table.add_column("span")
    table.add_column("width", justify="right")
    for w in windows:
        table.add_row(
            f"+{w.jump:#06x}",
            f"{w.ref_target:#06x}",
            f"{w.our_target:#06x}",
            f"{w.drift:+d}",
            f"[{w.lo:#x}, {w.hi:#x})" + ("  (backward)" if w.backward else ""),
            str(w.width),
        )
    console.print(table)

    if derived:
        console.print(
            "\n[bold]derived by subtraction[/bold] (regions with no branch pair of their own):"
        )
        for d in derived:
            console.print(
                f"  [{d.outer.lo:#x}, {d.outer.hi:#x}) {d.outer.drift:+d} "
                f"minus inner [{d.inner.lo:#x}, {d.inner.hi:#x}) {d.inner.drift:+d}"
                f"  =>  [bold]{d.drift:+d}[/bold] outside the inner window"
            )

    console.print(
        "\n[dim]A positive drift means the compiled code is longer across that span; "
        "negative means shorter, which is evidence about register pressure rather "
        "than a defect to fix.[/dim]"
    )


@app.callback(invoke_without_command=True)
def main(
    source: str = typer.Argument(..., help="C source file containing the function."),
    va: str = typer.Option(
        None, "--va", help="Function VA (default: from the // FUNCTION: header)."
    ),
    size: int = typer.Option(None, "--size", help="Function size (default: from metadata)."),
    cflags: str = typer.Option(None, "--cflags", help="Override compiler flags."),
    toolchain: str = typer.Option(None, "--toolchain", help="Override toolchain profile."),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
    target: str | None = TargetOption,
) -> None:
    """Localise where a function's bytes drift from the reference, using branch targets.

    A jump whose encoding matches the reference but whose target differs measures
    the drift accumulated between it and its target.  Nested windows subtract, so
    regions with no branch pair of their own can still be bounded.
    """
    cfg = require_config(target=target, json_mode=json_output)

    src_path = Path(source)
    if not src_path.exists():
        error_exit(f"source not found: {source}", json_mode=json_output)

    # Resolve va/size/symbol from the file's annotations, the same source
    # `rebrew test` uses.  The symbol in particular must come from here rather
    # than from the filename: a __stdcall function decorates as ``_name@N``, so
    # a ``_`` + stem guess silently fails to extract and reports EXTRACT_ERROR.
    meta = parse_source_metadata(str(src_path))
    annos = parse_c_file_multi(
        src_path, target_name=target_marker(cfg), metadata_dir=cfg.metadata_dir
    )
    selected = None
    if va is not None:
        want = parse_va(va, json_mode=json_output)
        selected = next((a for a in annos if a.va == want), None)
    elif annos:
        selected = annos[0]

    va_int = selected.va if selected else (parse_va(va, json_mode=json_output) if va else None)
    if va_int is None:
        error_exit(
            "no VA: pass --va or give the file a `// FUNCTION:` header",
            json_mode=json_output,
        )

    size_val = size
    if size_val is None and selected is not None and selected.size > 0:
        size_val = selected.size
    # ``meta["SIZE"]`` is the first annotation only — a --va-selected sibling
    # with no SIZE must not borrow that span.
    if (
        size_val is None
        and "SIZE" in meta
        and (selected is None or not annos or selected is annos[0])
    ):
        try:
            size_val = int(meta["SIZE"])
        except ValueError:
            error_exit(f"invalid SIZE metadata: {meta['SIZE']!r}", json_mode=json_output)
    if size_val is None:
        error_exit("no size: pass --size or record SIZE metadata", json_mode=json_output)

    symbol = (selected.symbol if selected and selected.symbol else "") or (
        meta.get("SYMBOL", "") if selected is None or not annos or selected is annos[0] else ""
    )
    if not symbol:
        error_exit(
            f"no symbol for 0x{va_int:08x}: add a `// SYMBOL:` header or a "
            "`// FUNCTION:` header above the definition",
            json_mode=json_output,
        )
    if selected is not None:
        _ann_toolchain: str | None = selected.toolchain or None
        _ann_cflags: str | None = selected.cflags or None
        _mod = selected.module
    else:
        _ann_toolchain = meta.get("TOOLCHAIN")
        _ann_cflags = meta.get("CFLAGS")
        _mod = ""
    toolchain_name, cflags_str = resolve_compile_overrides(
        cfg,
        src_path.resolve().parent,
        toolchain or _ann_toolchain,
        cflags or _ann_cflags,
        _mod,
    )

    ref_code = extract_raw_bytes(cfg.target_binary, va_int, size_val)
    result = compile_and_compare(
        cfg,
        src_path,
        symbol,
        ref_code,
        cflags_str,
        section_va=va_int,
        toolchain=toolchain_name,
    )
    if result.obj_bytes is None:
        error_exit(
            f"compile/extract failed for {symbol}: {result.status}",
            json_mode=json_output,
            code=EXIT_ERROR,
        )

    import capstone

    md = capstone.Cs(cfg.capstone_arch, cfg.capstone_mode)
    windows = drift_windows(ref_code, result.obj_bytes, md)
    derived = derive_regions(windows)

    if json_output:
        payload: dict[str, Any] = {
            "source": str(src_path),
            "symbol": symbol,
            "va": f"0x{va_int:08x}",
            "size": size_val,
            "obj_size": len(result.obj_bytes),
            "status": result.status,
            "windows": [
                {
                    "lo": w.lo,
                    "hi": w.hi,
                    "width": w.width,
                    "drift": w.drift,
                    "jump": w.jump,
                    "ref_target": w.ref_target,
                    "our_target": w.our_target,
                    "backward": w.backward,
                }
                for w in windows
            ],
            "derived": [
                {
                    "outer": [d.outer.lo, d.outer.hi],
                    "outer_drift": d.outer.drift,
                    "inner": [d.inner.lo, d.inner.hi],
                    "inner_drift": d.inner.drift,
                    "drift": d.drift,
                }
                for d in derived
            ],
        }
        json_print(payload)
        return

    console.print(
        f"[bold]{symbol}[/bold] @ 0x{va_int:08x}  "
        f"size {size_val}, object {len(result.obj_bytes)} "
        f"({len(result.obj_bytes) - size_val:+d})  [{result.status}]\n"
    )
    _emit_text(windows, derived)


def main_entry() -> None:
    """Run the Typer CLI application."""
    _standalone = typer.Typer()
    _standalone.command()(main)
    _standalone()


if __name__ == "__main__":
    main_entry()
