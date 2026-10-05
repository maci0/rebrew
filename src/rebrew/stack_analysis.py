"""stack_analysis.py — compare the stack frame of a compiled function against the target.

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

The library half of the ``rebrew diagnose stack`` command: deriving a frame from
disassembly and diffing two frames is pure analysis, with no Typer app and no
console output, so ``rebrew.near_analysis`` and the command both import it.
``rebrew.stack_cmp`` owns the CLI.
"""

from __future__ import annotations

import re
from typing import Any

import capstone  # module-level: analyze_frame is a hot path (near-diag calls it per pair)

from rebrew.analysis import capstone_handle
from rebrew.utils import parse_int_literal

_EBP_SLOT_RE = re.compile(r"\[(?:[er]?bp)\s*([+-])\s*(0x[0-9a-fA-F]+|\d+)\]")
_ESP_DELTA_RE = re.compile(r"\[(?:[er]?sp)\s*([+-])\s*(0x[0-9a-fA-F]+|\d+)\]")
_ENTER_SIZE_RE = re.compile(r"(0x[0-9a-fA-F]+|\d+)")


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
    word = {capstone.CS_MODE_64: 8, capstone.CS_MODE_32: 4}.get(cs_mode, 2)
    # Per-thread handle: near-diag runs analyze_frame from GA/match worker
    # threads, and a shared ``Cs`` races on its libcapstone handle.
    md = capstone_handle(capstone.CS_ARCH_X86, cs_mode, detail=True)

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
        elif mnem in ("sub", "add") and "sp" in op_str:
            # Only a register destination adjusts ESP — `sub dword ptr
            # [esp+4], 0x10` adjusts a stack slot, not the pointer, and
            # would poison frame_size if the first immediate were subtracted.
            if insn.operands and insn.operands[0].type == capstone.x86.X86_OP_REG:
                dst_name = insn.reg_name(insn.operands[0].reg) or ""
                if "sp" in dst_name:
                    for op in insn.operands:
                        if op.type == capstone.x86.X86_OP_IMM:
                            esp += -op.imm if mnem == "sub" else op.imm
                            break
        elif mnem == "lea" and "sp" in op_str:
            # lea esp, [esp - N] — stack alignment / probing reset.  The
            # destination must be ESP: `lea eax, [esp - 0x10]` only computes an
            # address and does NOT move the stack pointer.
            if (
                insn.operands
                and insn.operands[0].type == capstone.x86.X86_OP_REG
                and "sp" in (insn.reg_name(insn.operands[0].reg) or "")
            ):
                m = _ESP_DELTA_RE.search(op_str)
                if m:
                    delta = parse_int_literal(m.group(2))
                    esp += -delta if m.group(1) == "-" else delta
        elif mnem == "enter":
            m = _ENTER_SIZE_RE.search(op_str)
            if m:
                size = parse_int_literal(m.group(1))
                esp -= word + size
            frame_pointer = True
        elif mnem == "ret" and op_str:
            ret_popping = parse_int_literal(op_str)

        # Frame pointer establishment: push ebp immediately followed by
        # mov ebp, esp (16-bit: push bp / mov bp, sp).
        if (
            not frame_pointer
            and mnem == "push"
            and "bp" in op_str
            and idx + 1 < len(insns)
            and insns[idx + 1].mnemonic == "mov"
            and insns[idx + 1].op_str.replace(" ", "").startswith(("ebp,esp", "bp,sp", "rbp,rsp"))
        ):
            frame_pointer = True

        m = _EBP_SLOT_RE.search(op_str)
        if m:
            delta = parse_int_literal(m.group(2))
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
