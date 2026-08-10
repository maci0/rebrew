"""rebrew discover-functions — robust function enumeration for a target binary.

Function discovery is the weak link in onboarding: rizin's ``aaa`` mis-merges
functions on some toolchains (the MinGW GCC family) and ``aap`` misses
frameless functions, and rizin sizes are frequently off by a few bytes.  This
command chains several strategies and merges the best result:

1. rizin ``aaa`` (full analysis)
2. rizin ``aa; aap`` (function-prelude analysis)
3. a capstone linear sweep over .text: function starts after padding runs,
   ``push ebp; mov ebp, esp`` prologues, and direct-call targets

Candidates are merged by VA (dropping any that land inside a larger span) and
each size is refined by disassembling to the first ``ret`` — the size that
actually matches what a compiler emits (the "rizin said 34, real size 36"
problem).

Usage::

    rebrew discover-functions original/game.exe
    rebrew discover-functions game.exe --output src/game/functions.txt
"""

from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import typer
from rich.console import Console

from rebrew.analysis import iter_instructions
from rebrew.binary_loader import load_binary
from rebrew.cli import EXIT_ERROR, json_print
from rebrew.utils import atomic_write_text

console = Console(stderr=True)

app = typer.Typer(help="Enumerate functions: rizin aaa/aap + capstone sweep, sizes validated.")


@dataclass
class Discovery:
    """A merged function-discovery result."""

    functions: list[tuple[int, int, str]] = field(default_factory=list)
    sources: dict[str, int] = field(default_factory=dict)  # strategy -> count


def _rizin_functions(binary: Path, cmds: list[str]) -> list[tuple[int, int, str]]:
    """Run rizin with *cmds* and parse ``afl`` output (3- or 4-column)."""
    try:
        r = subprocess.run(
            ["rizin", "-q", "-c", "; ".join(cmds) + "; afl", str(binary)],
            capture_output=True,
            text=True,
            timeout=300,
        )
    except (OSError, subprocess.TimeoutExpired):
        return []
    out: list[tuple[int, int, str]] = []
    for line in r.stdout.splitlines():
        p = line.split()
        if not p or not p[0].startswith("0x"):
            continue
        try:
            va = int(p[0], 16)
        except ValueError:
            continue
        if len(p) >= 4 and p[2].isdigit():
            size, name = int(p[2]), p[3]
        elif len(p) >= 3:
            size, name = int(p[1]), p[2]
        else:
            continue
        if name in ("->", "loc") or name.startswith("sub."):
            name = f"fcn.{va:08x}"
        out.append((va, size, name))
    return out


def _capstone_sweep(binary: Path) -> list[tuple[int, int, str]]:
    """Linear-sweep candidates from .text: post-padding starts, frame prologues, call targets."""
    info = load_binary(binary)
    text = next((s for s in info.sections.values() if s.name.lower() == ".text"), None)
    if text is None:
        return []
    data = info.data
    raw = data[text.file_offset : text.file_offset + text.size]
    va_base = text.va

    starts: set[int] = set()
    # 1. the .text base is always a candidate
    starts.add(va_base)
    # 2. bytes after padding runs (int3 / nop alignment)
    i = 0
    n = len(raw)
    while i < n - 1:
        b = raw[i]
        if b in (0xCC, 0x90):
            j = i
            while j < n and raw[j] in (0xCC, 0x90, 0x0F, 0x1F):
                j += 1
            # a padding run of >= 3 bytes: the byte after it starts a function
            if j - i >= 3 and j < n:
                # skip trailing 0f 1f 40 xx / 0f 1f 00 (multi-byte nops) precisely-ish:
                k = j
                starts.add(va_base + k)
            i = j
        else:
            i += 1
    # 3. `push ebp; mov ebp, esp` prologue
    for m in re.finditer(rb"\x55\x8b\xec", raw):
        starts.add(va_base + m.start())
    # 4. direct-call targets (e8 rel32) via capstone
    for insn in iter_instructions(info, text.va, text.size):
        if insn.mnemonic == "call" and insn.op_str.startswith("0x"):
            try:
                tgt = int(insn.op_str, 16)
            except ValueError:
                continue
            if text.va <= tgt < text.va + text.size:
                starts.add(tgt)

    funcs: list[tuple[int, int, str]] = []
    for va in sorted(starts):
        funcs.append((va, 0, f"fcn.{va:08x}"))
    return funcs


_PAD = {0xCC, 0x90}


def _is_padding(info: Any, va: int, end: int) -> bool:
    """True when [va, end) disassembles to nothing but padding bytes."""
    from rebrew.analysis import extract_bytes

    try:
        raw = extract_bytes(info, va, end - va)
    except Exception:
        return False
    i = 0
    while i < len(raw):
        b = raw[i]
        if b in _PAD:
            i += 1
            continue
        if b == 0x0F and i + 1 < len(raw) and raw[i + 1] == 0x1F:
            i += 1  # 0f 1f multi-byte nop — skip its leading byte; rest is operands (skip generously)
            i = min(len(raw), i + 5)
            continue
        return False
    return True


def _validate_and_refine(
    info: Any, funcs: list[tuple[int, int, str]]
) -> list[tuple[int, int, str]]:
    """Drop candidates that are inside another function's span; size = gap, trimmed of padding.

    A candidate is a *real* function start when the previous function's code
    reaches a ``ret`` followed by padding before the candidate.  If the code
    runs straight into the candidate with no ret+padding boundary, the
    candidate is a false positive (a call target inside the previous
    function).  Sizes are the gap to the next validated start, minus trailing
    padding — the size a compiler actually emits.
    """
    funcs = sorted(funcs, key=lambda f: f[0])
    out: list[tuple[int, int, str]] = []
    i = 0
    while i < len(funcs):
        va, _s, name = funcs[i]
        nxt = funcs[i + 1][0] if i + 1 < len(funcs) else None
        gap = (nxt - va) if nxt else None

        # find the first ret within the gap
        ret_end = None
        hit_nxt = False
        try:
            for insn in iter_instructions(info, va, gap or 0x400):
                if insn.mnemonic.startswith("ret"):
                    ret_end = insn.va + insn.size - va
                    break
                if gap is not None and nxt is not None and insn.va >= nxt:
                    hit_nxt = True
                    break
        except Exception:
            pass

        if hit_nxt:
            # code runs straight into the next candidate with no ret — that
            # candidate is a false positive inside this function: drop it.
            del funcs[i + 1]
            continue

        if ret_end is not None and gap is not None:
            tail = gap - ret_end
            size = (
                ret_end
                if tail > 0 and nxt is not None and _is_padding(info, va + ret_end, nxt)
                else gap
            )
        else:
            size = gap if gap is not None else (ret_end or 0)
        out.append((va, size, name))
        i += 1
    return out


def discover_functions(binary: Path, *, min_size: int = 8) -> Discovery:
    """Chain rizin + capstone strategies and merge into validated functions."""
    d = Discovery()

    aaa = _rizin_functions(binary, ["aaa"])
    d.sources["rizin aaa"] = len(aaa)
    aap = _rizin_functions(binary, ["aa", "aap"])
    d.sources["rizin aa;aap"] = len(aap)

    # Merge: prefer the strategy with more candidates; union them.
    merged: dict[int, tuple[int, str]] = {}
    for funcs, _src in ((aaa, "aaa"), (aap, "aap")):
        for va, size, name in funcs:
            cur = merged.get(va)
            if cur is None or size > cur[0]:
                merged[va] = (size, name)
    d.sources["merged-rizin"] = len(merged)

    # Add capstone sweep candidates not already present.
    try:
        sweep = _capstone_sweep(binary)
    except Exception:
        sweep = []
    for va, _size, name in sweep:
        if va not in merged:
            merged[va] = (0, name)
    d.sources["capstone sweep"] = len([va for va in merged if va in {x[0] for x in sweep}])

    # Validate: drop candidates that fall inside a larger span.
    ordered = sorted(merged.items())
    kept: dict[int, tuple[int, str]] = {}
    for i, (va, (size, name)) in enumerate(ordered):
        nxt_va = ordered[i + 1][0] if i + 1 < len(ordered) else None
        if nxt_va is not None and nxt_va - va <= 2:
            continue  # duplicate/adjacent junk
        kept[va] = (size, name)

    funcs = [(va, size, name) for va, (size, name) in sorted(kept.items())]

    # Refine sizes against the binary (first-ret).
    try:
        info = load_binary(binary)
        funcs = _validate_and_refine(info, funcs)
    except Exception:
        pass

    funcs = [f for f in funcs if f[1] >= min_size]
    d.functions = funcs
    return d


@app.callback(invoke_without_command=True)
def main(
    binary: str = typer.Argument(..., help="Path to the target binary."),
    output: str | None = typer.Option(
        None, "--output", "-o", help="Write functions.txt to this path (default: stdout)."
    ),
    min_size: int = typer.Option(8, "--min-size", help="Drop functions smaller than this."),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
) -> None:
    """Enumerate functions with chained strategies and validated sizes."""
    bin_path = Path(binary)
    if not bin_path.exists():
        msg = f"binary not found: {bin_path}"
        if json_output:
            json_print({"error": msg, "code": EXIT_ERROR})
        else:
            console.print(f"[red]Error:[/red] {msg}")
        raise typer.Exit(code=EXIT_ERROR)

    d = discover_functions(bin_path, min_size=min_size)
    text = "".join(f"0x{va:08x} {name} {size}\n" for va, size, name in d.functions)

    if output:
        Path(output).parent.mkdir(parents=True, exist_ok=True)
        atomic_write_text(Path(output), text)

    if json_output:
        json_print(
            {
                "binary": str(bin_path),
                "functions": len(d.functions),
                "sources": d.sources,
                "output": output,
                "sample": [
                    {"va": f"0x{va:08x}", "size": size, "name": name}
                    for va, size, name in d.functions[:10]
                ],
            }
        )
    else:
        console.print(f"[green]{len(d.functions)} functions[/green] from {d.sources}")
        if output:
            console.print(f"  wrote {output}")
        else:
            print(text, end="")


def main_entry() -> None:
    """Run the Typer CLI application."""
    app()


if __name__ == "__main__":
    main_entry()
