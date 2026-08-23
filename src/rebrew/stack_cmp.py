"""stack_cmp.py — compare the stack frame of a compiled function against the target.

reccmp ``stackcmp`` adapted to rebrew's architecture.  reccmp reads
local-variable records from the recomp PDB (cvdump, VC7+ PDBs); rebrew
compiles per-function objects and has no recomp PDB in its pipeline, so the
frame is derived from **disassembly on both sides** — the target bytes and
the compiled ``.obj`` — which works for every toolchain including MSVC 6.0
(whose classic PDBs ``llvm-pdbutil`` cannot read anyway).

Compared:

- ``frame_size``   — max stack depth (ESP tracking across push/pop/sub/add/
  ``lea esp``/enter/pushad)
- ``frame_pointer`` — ebp-frame (``push ebp; mov ebp,esp``) vs esp-based
  (frame-pointer omission, ``/Oy``)
- ``ret_popping``  — ``__stdcall``/``__thiscall`` ``ret N`` vs ``__cdecl``
- ``slots``        — the set of ``[ebp±N]``/``[bp±N]`` displacements
  referenced (local-variable layout)

A frame delta is a classic per-function flag symptom — frame-pointer omission
(``/Oy``), missing/extra locals, ``/Gs`` stack probes, wrong calling
convention — the exact signal for tuning static-CRT / vendored-zlib LIBRARY
functions per-function (the reccmp <50% grind).

Usage::

    rebrew stack-cmp src/game/my_func.c
    rebrew stack-cmp 0x10009310
    rebrew stack-cmp src/game/my_func.c --json
"""

from __future__ import annotations

import functools
import re
from typing import Any

import capstone  # module-level: analyze_frame is a hot path (near-diag calls it per pair)
import typer
from rich.console import Console

from rebrew.analysis import capstone_mode_for_arch
from rebrew.cli import (
    EXIT_ERROR,
    EXIT_MISMATCH,
    TargetOption,
    error_exit,
    json_print,
    require_config,
)

console = Console(stderr=True)

_EBP_SLOT_RE = re.compile(r"\[(?:e?bp)\s*([+-])\s*(0x[0-9a-fA-F]+|\d+)\]")
_ESP_DELTA_RE = re.compile(r"\[e?sp\s*([+-])\s*(0x[0-9a-fA-F]+|\d+)\]")
_ENTER_SIZE_RE = re.compile(r"(0x[0-9a-fA-F]+|\d+)")


@functools.lru_cache(maxsize=8)
def _cs_detail_handle(arch: int, mode: int) -> capstone.Cs:
    """A cached detail capstone handle — constructing ``capstone.Cs`` per call
    was a measurable cost in the per-pair hot path (near-diag calls
    ``analyze_frame`` twice per classification)."""
    md = capstone.Cs(arch, mode)
    md.detail = True
    return md


def analyze_frame(code: bytes, va: int, cs_mode: int) -> dict[str, Any]:
    """Derive the stack frame of *code* from disassembly.

    Tracks ESP across explicit stack operations (push/pop/pushad/sub/add/
    ``lea esp``/enter) — ``call`` is deliberately not tracked because its
    return pops the pushed address, netting zero.  Returns:

    - ``frame_size``: max stack depth in bytes (0 when the function allocates
      nothing on the stack)
    - ``frame_pointer``: True when an ebp/bp frame is established
      (``push ebp; mov ebp, esp`` or ``enter N, 0``)
    - ``ret_popping``: the ``ret N`` argument-pop count (0 = plain ``ret``)
    - ``slots``: sorted distinct ``[ebp±N]``/``[bp±N]`` displacements
      (negative = local below the frame pointer)

    Robust to garbage/undecodable input (empty result, never raises).
    """
    word = 4 if cs_mode == capstone.CS_MODE_32 else 2
    md = _cs_detail_handle(capstone.CS_ARCH_X86, cs_mode)

    esp = 0
    min_esp = 0
    frame_pointer = False
    ret_popping = 0
    slots: set[int] = set()

    try:
        insns = list(md.disasm(code, va))
    except Exception:  # degenerate input yields an empty frame
        insns = []

    for idx, insn in enumerate(insns):
        mnem = insn.mnemonic
        op_str = insn.op_str

        if mnem in ("push", "pop"):
            esp += -word if mnem == "push" else word
        elif mnem in ("pushad", "pusha"):
            esp -= 8 * word
        elif mnem in ("popad", "popa"):
            esp += 8 * word
        elif mnem == "sub" and "sp" in op_str:
            for op in insn.operands:
                if op.type == capstone.x86.X86_OP_IMM:
                    esp -= op.imm
                    break
        elif mnem == "add" and "sp" in op_str:
            for op in insn.operands:
                if op.type == capstone.x86.X86_OP_IMM:
                    esp += op.imm
                    break
        elif mnem == "lea" and "sp" in op_str:
            # lea esp, [esp - N] — stack alignment / probing reset.  The
            # destination esp takes the pointer value, so [esp-N] lowers esp.
            m = _ESP_DELTA_RE.search(op_str)
            if m:
                delta = int(m.group(2), 16) if m.group(2).startswith("0x") else int(m.group(2))
                esp += -delta if m.group(1) == "-" else delta
        elif mnem == "enter":
            m = _ENTER_SIZE_RE.search(op_str)
            if m:
                size = int(m.group(1), 16) if m.group(1).startswith("0x") else int(m.group(1))
                esp -= word + size
            frame_pointer = True
        elif mnem == "ret" and op_str:
            ret_popping = int(op_str, 16) if op_str.startswith("0x") else int(op_str)

        # Frame pointer establishment: push ebp immediately followed by
        # mov ebp, esp (16-bit: push bp / mov bp, sp).
        if (
            not frame_pointer
            and mnem == "push"
            and "bp" in op_str
            and idx + 1 < len(insns)
            and insns[idx + 1].mnemonic == "mov"
            and insns[idx + 1].op_str.replace(" ", "").startswith(("ebp,esp", "bp,sp"))
        ):
            frame_pointer = True

        m = _EBP_SLOT_RE.search(op_str)
        if m:
            delta = int(m.group(2), 16) if m.group(2).startswith("0x") else int(m.group(2))
            if m.group(1) == "-":
                delta = -delta
            slots.add(delta)

        min_esp = min(min_esp, esp)

    return {
        "frame_size": -min_esp,
        "frame_pointer": frame_pointer,
        "ret_popping": ret_popping,
        "slots": sorted(slots),
    }


def compare_frames(target: dict[str, Any], compiled: dict[str, Any]) -> dict[str, Any]:
    """Compare two :func:`analyze_frame` results into a verdict + hints.

    Frame size / pointer / ret-popping are always compared; the ``[ebp±N]``
    slot layout only when BOTH sides use a frame pointer (an esp-based side
    has no comparable displacement set).  Hints are flag-focused — the
    actionable signal for per-function CFLAGS tuning.
    """
    diffs: list[str] = []
    hints: list[str] = []

    if target["frame_size"] != compiled["frame_size"]:
        diffs.append(
            f"frame size: target 0x{target['frame_size']:x} vs compiled "
            f"0x{compiled['frame_size']:x}"
        )
        hints.append(
            "local layout differs — /O1 vs /O2, a missing/extra local, or a "
            "/Gs stack probe; compare the [ebp±N] slots below"
        )
    if target["frame_pointer"] != compiled["frame_pointer"]:
        t_side = "ebp frame" if target["frame_pointer"] else "esp-based (/Oy)"
        c_side = "ebp frame" if compiled["frame_pointer"] else "esp-based (/Oy)"
        diffs.append(f"frame pointer: target {t_side} vs compiled {c_side}")
        hints.append("frame-pointer omission mismatch — /Oy on one side only")
    if target["ret_popping"] != compiled["ret_popping"]:
        diffs.append(
            f"ret-popping: target {target['ret_popping']} vs compiled {compiled['ret_popping']}"
        )
        hints.append(
            "calling-convention mismatch — __stdcall/__thiscall vs __cdecl "
            "(ret N pops N bytes of arguments)"
        )

    t_slots, c_slots = set(target["slots"]), set(compiled["slots"])
    if target["frame_pointer"] and compiled["frame_pointer"]:
        only_t = sorted(t_slots - c_slots)
        only_c = sorted(c_slots - t_slots)
        if only_t or only_c:
            diffs.append(
                f"stack slots: target-only {[hex(s) for s in only_t]}, "
                f"compiled-only {[hex(s) for s in only_c]}"
            )
            if not any("local layout" in h for h in hints):
                hints.append(
                    "different [ebp±N] slots — the C declares a different "
                    "local-variable layout than the original"
                )

    return {
        "frame_match": not diffs,
        "diffs": diffs,
        "hints": hints,
        "slots": {
            "target": target["slots"],
            "compiled": compiled["slots"],
        },
    }


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

    from rebrew.match import resolve_build_params

    params = resolve_build_params(
        cfg,
        seed_c,
        None,
        None,
        None,
        None,
        original_arg if va_arg else None,
        None,
        False,  # ignore_lint
        json_output,
    )

    from rebrew.matcher import build_candidate_obj_only

    res = build_candidate_obj_only(
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
    "  rebrew stack-cmp src/game/my_func.c · · · · Compare frame vs target\n\n"
    "  rebrew stack-cmp 0x10009310 · · · · · · · Resolve VA to its source\n\n"
    "  rebrew stack-cmp src/game/my_func.c --json · JSON output\n\n"
    "[bold]Exit codes:[/bold]\n\n"
    "  0   Stack frames match\n\n"
    "  1   Frame differs (size / frame pointer / ret-popping / slot layout)\n\n"
    "  2   Build failed\n\n"
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
    seed_c: str = typer.Argument(..., help="C source file, symbol name, or VA (hex)"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
    target: str | None = TargetOption,
) -> None:
    """Compile SEED_C and compare its stack frame against the target function."""
    run_stack_cmp(seed_c, json_output, target)


def main_entry() -> None:
    """Run the Typer CLI application."""
    app()


if __name__ == "__main__":
    main_entry()
