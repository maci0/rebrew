"""gap_trace.py — where does a function lose (or gain) length vs the reference?

Aligns the two instruction streams and prints our offset minus the
reference's at the start of each equal block.  The running gap is the
instrument for a LENGTH hypothesis, which neither ``rebrew test`` nor
``rebrew near-diag`` can see: a function whose real COMDAT body is N bytes
short has its out-of-line jump table / case map N bytes early, moving every
4-byte relocated entry in it, while the object score stays flat.

Generalized from guild-rebrew's ``scripts/gaptrace.py`` (MSVC6/x86-32
campaign).  Arch-neutral: disassembly and reloc masking go through the
project's configured toolchain and format handlers.
"""

from __future__ import annotations

import difflib
from pathlib import Path
from typing import Any

import typer
from rich.console import Console

from rebrew.analysis import Insn, iter_instructions
from rebrew.binary_loader import load_binary
from rebrew.cli import (
    TargetOption,
    error_exit,
    json_print,
    require_config,
    select_annotation,
)
from rebrew.compile import compile_to_obj

console = Console(stderr=True)

app = typer.Typer(
    help="Trace length-gap drift between object and reference instruction streams.",
    rich_markup_mode="rich",
)

_BRANCHES = frozenset(
    {
        "call",
        "jmp",
        "jz",
        "jnz",
        "je",
        "jne",
        "jl",
        "jle",
        "jg",
        "jge",
        "jb",
        "jbe",
        "ja",
        "jae",
        "js",
        "jns",
        "jo",
        "jno",
        "jp",
        "jnp",
        "jcxz",
        "loop",
        "loope",
        "loopne",
    }
)


def reference_window(cfg: Any, va: int) -> int | None:
    """Bytes from *va* to the next known function VA (the real body).

    For a function with an out-of-line jump table or case map the real body
    is longer than the metadata ``size`` (code only).  Comparing only the
    metadata window decodes table bytes as phantom instructions.
    """
    from rebrew.asm import _next_function_va

    nxt = _next_function_va(cfg, va)
    return (nxt - va) if nxt else None


def _masked_key(raw: bytes, reloc: bool, mnemonic: str) -> bytes:
    """Instruction bytes with reloc slots and branch operands blanked."""
    if reloc:
        return b"\x00" * len(raw)
    if mnemonic in _BRANCHES:
        return raw[:1] + b"\x00" * (len(raw) - 1)
    return bytes(raw)


def trace_gaps(
    ref_insns: list[tuple[int, bytes, str, str]],
    obj_insns: list[tuple[int, bytes, str, str]],
) -> list[dict[str, Any]]:
    """Align two (offset, key, mnemonic, op_str) streams; return gap events."""
    sm = difflib.SequenceMatcher(
        a=[k for _, k, _, _ in ref_insns],
        b=[k for _, k, _, _ in obj_insns],
        autojunk=False,
    )
    events: list[dict[str, Any]] = []
    last_gap: int | None = None
    for tag, i1, i2, j1, j2 in sm.get_opcodes():
        if tag == "equal":
            gap = obj_insns[j1][0] - ref_insns[i1][0]
            if gap != last_gap:
                events.append(
                    {
                        "type": "gap",
                        "gap": gap,
                        "ref_off": ref_insns[i1][0],
                        "obj_off": obj_insns[j1][0],
                        "mnemonic": ref_insns[i1][2],
                        "op_str": ref_insns[i1][3],
                    }
                )
                last_gap = gap
        else:
            events.append(
                {
                    "type": tag,
                    "ref_range": [i1, i2],
                    "obj_range": [j1, j2],
                    "ref_off": ref_insns[i1][0] if i1 < len(ref_insns) else None,
                    "obj_off": obj_insns[j1][0] if j1 < len(obj_insns) else None,
                }
            )
    return events


def _seq(insns: list[Insn], va: int, reloc_offs: set[int]) -> list[tuple[int, bytes, str, str]]:
    return [
        (i.va - va, _masked_key(i.raw, (i.va - va) in reloc_offs, i.mnemonic), i.mnemonic, i.op_str)
        for i in insns
    ]


def _real_end(seq: list[tuple[int, bytes, str, str]]) -> str:
    if not seq:
        return "0"
    off, raw, _, _ = seq[-1]
    return hex(off + len(raw))


def _obj_text_sections(obj_path: str) -> list[tuple[bytes, set[int]]]:
    """(.text body, reloc-offset set) per section, via lief."""
    import lief

    out: list[tuple[bytes, set[int]]] = []
    binary = lief.parse(obj_path)
    if binary is None:
        return out
    for section in binary.sections:
        name = section.name
        name = name.decode("utf-8", errors="replace") if isinstance(name, bytes) else str(name)
        if not name.startswith(".text"):
            continue
        rels: set[int] = set()
        if hasattr(section, "relocations"):
            for r in section.relocations:
                for k in range(r.address, r.address + 4):
                    rels.add(k)
        out.append((bytes(section.content), rels))
    return out


@app.callback(invoke_without_command=True)
def main(
    source: str = typer.Argument(..., help="C source file (or VA/symbol) for the function"),
    va: str | None = typer.Option(None, "--va", help="Target VA in hex (default: from annotation)"),
    size: int | None = typer.Option(None, "--size", help="Window in bytes (default: real body)"),
    cflags: str | None = typer.Option(
        None, "--cflags", help="Compiler flags (default: from metadata)"
    ),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
    target: str | None = TargetOption,
) -> None:
    """Print the length-gap trace of SOURCE against the reference function."""
    cfg = require_config(target=target, json_mode=json_output)
    path, sel, va_int = select_annotation(cfg, source, va, json_mode=json_output)
    if va_int is None:
        error_exit("Need a VA (from the annotation or --va)", json_mode=json_output)

    real = reference_window(cfg, va_int)
    if size is None:
        if real is None:
            error_exit("Cannot derive window: no next function; pass --size", json_mode=json_output)
        size = real
    elif real and size != real:
        console.print(
            f"  NOTE: size {size} passed but the next function starts {real} bytes on "
            f"({real - size:+d}); the reference real body is {real}.  Omit size to use it."
        )

    info = load_binary(cfg.target_binary)
    ref_insns = iter_instructions(info, va_int, size)
    ref_seq = _seq(ref_insns, va_int, set())

    from rebrew.compile_overrides import resolve_compile_overrides

    # Same fallback chain as test/verify/near-diag so module presets and
    # library overrides cannot make gap-trace disagree with those tools.
    toolchain_name, cflags_str = resolve_compile_overrides(
        cfg,
        path.resolve().parent,
        sel.toolchain,
        cflags or sel.cflags or None,
        sel.module,
    )
    flags = cflags_str.split()
    workdir = Path(cfg.root) / ".rebrew" / "gaptrace"
    workdir.mkdir(parents=True, exist_ok=True)
    obj_path, err = compile_to_obj(
        cfg, path, flags, workdir, use_cache=False, toolchain=toolchain_name
    )
    if obj_path is None:
        error_exit(f"Compile failed: {err}", json_mode=json_output)

    from rebrew.analysis import _capstone

    md = _capstone(skipdata=True, info=info)
    obj_seq: list[tuple[int, bytes, str, str]] = []
    for body, rels in _obj_text_sections(obj_path):
        for insn in md.disasm(body, va_int):
            off = insn.address - va_int
            local_rels = {r - 0 for r in rels if 0 <= r - 0 < len(body)}
            obj_seq.append(
                (
                    off,
                    _masked_key(insn.bytes, off in local_rels, insn.mnemonic),
                    insn.mnemonic,
                    insn.op_str,
                )
            )
        break  # first .text section only; multi-function TUs need --symbol scoping later

    events = trace_gaps(ref_seq, obj_seq)
    payload = {
        "va": hex(va_int),
        "size": size,
        "reference_insns": len(ref_seq),
        "object_insns": len(obj_seq),
        "reference_code_end": _real_end(ref_seq),
        "object_code_end": _real_end(obj_seq),
        "events": events,
    }
    if json_output:
        json_print(payload)
        return
    console.print(
        f"  reference {len(ref_seq)} insns, ours {len(obj_seq)} "
        "(COUNTS INCLUDE TRAILING ALIGNMENT FILL -- do not use them for length);"
    )
    console.print(f"  real code ends:  reference {_real_end(ref_seq)}, ours {_real_end(obj_seq)}")
    for ev in events:
        if ev["type"] == "gap":
            console.print(
                f"  gap {ev['gap']:+3d}  from refoff {ev['ref_off']:#06x}  "
                f"(ouroff {ev['obj_off']:#06x})   {ev['mnemonic']} {ev['op_str']}"
            )
        else:
            console.print(
                f"    -- {ev['type']:7s} ref{ev['ref_range']} at {ev['ref_off']}  "
                f"built{ev['obj_range']} at {ev['obj_off']}"
            )


def main_entry() -> None:
    """Run the Typer CLI application."""
    app()


if __name__ == "__main__":
    main_entry()
