"""stack_analysis.py — compare the stack frame of a compiled function against the target.

reccmp ``stackcmp`` adapted to rebrew's architecture.  reccmp reads
local-variable records from the recomp PDB (cvdump, VC7+ PDBs); rebrew
compiles per-function objects and has no recomp PDB in its pipeline, so the
frame is derived from **disassembly on both sides** — the target bytes and
the compiled ``.obj``, for x86 16/32/64-bit code including MSVC 6.0
(whose classic PDBs ``llvm-pdbutil`` cannot read anyway).

Compared:

- ``frame_size``   - peak tracked depth in linear disassembly (ESP across push/pop/sub/add/
  ``lea esp``/enter/pushad)
- ``frame_pointer`` — ebp-frame (``push ebp; mov ebp,esp``) vs esp-based
  (frame-pointer omission, ``/Oy``)
- ``ret_popping``  — ``__stdcall``/``__thiscall`` ``ret N`` vs ``__cdecl``
- ``slots``        — the set of ``[ebp±N]``/``[bp±N]`` displacements
  referenced (local-variable layout)

A frame delta suggests experiments with frame-pointer omission (``/Oy``),
locals, ``/Gs`` stack probes and calling convention when tuning library code.
Source and control-flow differences can also produce the same delta.

The library half of the ``rebrew diagnose stack`` command: deriving a frame from
disassembly and diffing two frames is pure analysis, with no Typer app and no
console output, so ``rebrew.near_analysis`` and the command both import it.
``rebrew.stack_cmp`` owns the CLI.
"""

from __future__ import annotations

lazy from typing import Any

lazy import capstone  # module-level: analyze_frame is a hot path (near-diag calls it per pair)

lazy from rebrew.analysis import capstone_handle


def analyze_frame(code: bytes, va: int, cs_mode: int) -> dict[str, Any]:
    """Derive the x86 stack frame of *code* from disassembly.

    Tracks ESP across explicit stack operations (push/pop/pushad/sub/add/
    ``lea esp``/enter) — ``call`` is deliberately not tracked because its
    return pops the pushed address, netting zero.  Returns:

    - ``frame_size``: peak tracked depth in linear disassembly, in bytes
      (0 when no stack allocation is tracked); this does not follow control flow
    - ``frame_pointer``: True when an ebp/bp frame is established
      (``push ebp; mov ebp, esp`` or ``enter N, 0``)
    - ``ret_popping``: the ``ret N`` argument-pop count (0 = plain ``ret``)
    - ``slots``: sorted distinct ``[ebp±N]``/``[bp±N]`` displacements
      (negative = local below the frame pointer)

    Robust to garbage/undecodable input (empty result, never raises).
    """
    from capstone.x86 import (
        X86_OP_IMM,
        X86_OP_MEM,
        X86_OP_REG,
        X86_REG_BP,
        X86_REG_EBP,
        X86_REG_ESP,
        X86_REG_RBP,
        X86_REG_RSP,
        X86_REG_SP,
    )

    sp_regs = {X86_REG_SP, X86_REG_ESP, X86_REG_RSP}
    bp_regs = {X86_REG_BP, X86_REG_EBP, X86_REG_RBP}
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
        ops = insn.operands
        stack_word = word
        if 0x66 in insn.prefix:
            stack_word = 4 if word == 2 else 2
        if word == 8 and insn.rex & 8:
            stack_word = 8

        if mnem in ("push", "pop"):
            esp += -stack_word if mnem == "push" else stack_word
        elif mnem in ("pushad", "pusha", "pushal", "pushaw"):
            esp -= 16 if mnem in ("pusha", "pushaw") else 32
        elif mnem in ("popad", "popa", "popal", "popaw"):
            esp += 16 if mnem in ("popa", "popaw") else 32
        elif (
            mnem in ("sub", "add")
            and len(ops) >= 2
            and ops[0].type == X86_OP_REG
            and ops[0].reg in sp_regs
        ):
            if ops[1].type == X86_OP_IMM:
                esp += -int(ops[1].imm) if mnem == "sub" else int(ops[1].imm)
        elif (
            mnem == "lea"
            and len(ops) >= 2
            and ops[0].type == X86_OP_REG
            and ops[0].reg in sp_regs
            and ops[1].type == X86_OP_MEM
            and ops[1].mem.base in sp_regs
        ):
            esp += int(ops[1].mem.disp)
        elif mnem == "enter" and len(ops) >= 2:
            size = int(ops[0].imm)
            nesting = int(ops[1].imm) & 31
            esp -= stack_word * (nesting + 1) + size
            frame_pointer = True
        elif mnem == "ret" and ops and ops[0].type == X86_OP_IMM:
            ret_popping = int(ops[0].imm)

        # Frame pointer establishment: push ebp immediately followed by
        # mov ebp, esp (16-bit: push bp / mov bp, sp).
        if (
            not frame_pointer
            and mnem == "push"
            and ops
            and ops[0].type == X86_OP_REG
            and ops[0].reg in bp_regs
            and idx + 1 < len(insns)
            and insns[idx + 1].mnemonic == "mov"
            and len(insns[idx + 1].operands) >= 2
            and insns[idx + 1].operands[0].type == X86_OP_REG
            and insns[idx + 1].operands[0].reg in bp_regs
            and insns[idx + 1].operands[1].type == X86_OP_REG
            and insns[idx + 1].operands[1].reg in sp_regs
        ):
            frame_pointer = True

        for op in ops:
            if op.type == X86_OP_MEM and op.mem.base in bp_regs and op.mem.disp != 0:
                slots.add(int(op.mem.disp))

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
    has no comparable displacement set). Hints suggest CFLAGS experiments;
    they do not establish the cause of a difference.
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
