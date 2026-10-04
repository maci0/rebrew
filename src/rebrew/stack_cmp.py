"""stack_cmp.py — the ``rebrew diagnose stack`` command.

Compiles the seed source and hands the target and compiled bytes to
:mod:`rebrew.stack_analysis`, which derives and diffs the frames.  This module
owns the CLI surface: argument parsing, the Rich output, and the exit code.
The frame analysis itself lives in the library so ``near_analysis`` can reach
it without importing a command.

Usage::

    rebrew diagnose stack src/game/my_func.c
    rebrew diagnose stack 0x10009310
    rebrew diagnose stack src/game/my_func.c --json
"""

from __future__ import annotations

from pathlib import Path

import typer

from rebrew.binary_loader import capstone_mode_for_arch
from rebrew.cli import (
    EXIT_ERROR,
    EXIT_MISMATCH,
    TargetOption,
    console,
    error_exit,
    json_print,
    require_config,
)
from rebrew.stack_analysis import analyze_frame, compare_frames


def run_stack_cmp(
    seed_c: str,
    json_output: bool,
    target: str | None = None,
) -> None:
    """Compile *seed_c* and compare its stack frame against the target."""
    cfg = require_config(target=target, json_mode=json_output)

    from rebrew.cli import resolve_source_arg

    va_arg = seed_c.strip().lower().startswith("0x")
    original_arg = seed_c
    seed_c = str(resolve_source_arg(cfg, seed_c))

    from rebrew.match_sweep import resolve_build_params

    symbol_arg = not va_arg and not Path(original_arg).exists()
    params = resolve_build_params(
        cfg,
        seed_c,
        None,
        None,
        None,
        original_arg if symbol_arg else None,
        original_arg if va_arg else None,
        None,
        False,  # ignore_lint
        json_output,
    )

    from rebrew.matcher import compiler as compile_seam

    res = compile_seam.build_candidate_obj_only(
        params.seed_src,
        params.cl,
        params.inc,
        params.cflags,
        params.symbol,
        env=params.msvc_env,
        cache=params.cc,
        extra_include_dirs=[str(params.seed_c.parent.resolve())],
        posix_style=bool(getattr(params.cfg, "posix_style", False)),
        profile=getattr(params.cfg, "compiler_profile", ""),
        cfg=params.cfg,
    )
    if not (res.ok and res.obj_bytes):
        error_exit(f"Build failed: {res.error_msg}", json_mode=json_output, code=EXIT_ERROR)

    obj_bytes = res.obj_bytes
    cs_mode = capstone_mode_for_arch(getattr(params.cfg, "arch", ""))
    target_frame = analyze_frame(params.target_bytes, params.va_int, cs_mode)
    compiled_frame = analyze_frame(obj_bytes, params.va_int, cs_mode)
    comparison = compare_frames(target_frame, compiled_frame)

    payload = {
        "va": f"0x{params.va_int:08x}",
        "symbol": params.symbol or "",
        "frame_match": comparison["frame_match"],
        "target": target_frame,
        "compiled": compiled_frame,
        "diffs": comparison["diffs"],
        "hints": comparison["hints"],
        "slots": comparison["slots"],
    }

    if json_output:
        json_print(payload)
    else:
        console.print(f"[bold]Stack frame 0x{params.va_int:08x}[/bold] ({params.symbol or '?'})")
        console.print(
            f"  target:   frame 0x{target_frame['frame_size']:x} · "
            f"{'ebp' if target_frame['frame_pointer'] else 'esp(/Oy)'} · "
            f"ret {target_frame['ret_popping']}"
        )
        console.print(
            f"  compiled: frame 0x{compiled_frame['frame_size']:x} · "
            f"{'ebp' if compiled_frame['frame_pointer'] else 'esp(/Oy)'} · "
            f"ret {compiled_frame['ret_popping']}"
        )
        if comparison["diffs"]:
            console.print("  [red]frame differs:[/red]")
            for d in comparison["diffs"]:
                console.print(f"    - {d}")
            for h in comparison["hints"]:
                console.print(f"  [yellow]hint:[/yellow] {h}")
        else:
            console.print("  [green]frames match[/green]")

    if not comparison["frame_match"]:
        raise typer.Exit(code=EXIT_MISMATCH)


_EPILOG = (
    "[bold]Examples:[/bold]\n\n"
    "  rebrew diagnose stack src/game/my_func.c · · · · Compare frame vs target\n\n"
    "  rebrew diagnose stack 0x10009310 · · · · · · · Resolve VA to its source\n\n"
    "  rebrew diagnose stack src/game/my_func.c --json · JSON output\n\n"
    "[bold]Exit codes:[/bold]\n\n"
    "  0   Stack frames match\n\n"
    "  1   Frame differs (size / frame pointer / ret-popping / slot layout)\n\n"
    "  2   Build failed (also a usage error: unknown flag, missing argument)\n\n"
    "[dim]130 = interrupted (Ctrl+C), 141 = stdout closed early (piped into head).[/dim]\n\n"
    "[dim]Derives the frame from disassembly on both sides (no PDB needed — "
    "works for MSVC 6.0 classic PDBs llvm-pdbutil cannot read).  A frame "
    "delta is a per-function flag symptom (/Oy, /O1 vs /O2, /Gs, calling "
    "convention).[/dim]"
)

app = typer.Typer(
    help="Compare the stack frame of a compiled function against the target binary.",
    rich_markup_mode="rich",
    epilog=_EPILOG,
)


@app.callback(invoke_without_command=True)
def main(
    seed_c: str = typer.Argument(
        ..., metavar="source", help="C source file, symbol name, or VA (hex)"
    ),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
    target: str | None = TargetOption,
) -> None:
    """Compile a seed source and compare its stack frame against the target function."""
    run_stack_cmp(seed_c, json_output, target)


def main_entry() -> None:
    """Run the Typer CLI application."""
    from rebrew.cli import run_standalone

    run_standalone(main)


if __name__ == "__main__":
    main_entry()
