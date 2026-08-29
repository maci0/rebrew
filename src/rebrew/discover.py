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

import logging
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import typer
from rich.console import Console

from rebrew.analysis import iter_instructions
from rebrew.binary_loader import load_binary
from rebrew.cli import error_exit, json_print
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
    from rebrew.catalog import parse_rizin_afl

    try:
        r = subprocess.run(
            ["rizin", "-q", "-c", "; ".join(cmds) + "; afl", str(binary)],
            capture_output=True,
            text=True,
            timeout=300,
        )
    except (OSError, subprocess.TimeoutExpired):
        return []
    if r.returncode != 0:
        logging.debug("rizin %s failed (rc=%d): %s", cmds, r.returncode, r.stderr[:500])
        return []
    return parse_rizin_afl(r.stdout)


def _capstone_sweep(binary: Path) -> list[tuple[int, int, str]]:
    """Linear-sweep candidates from .text: post-padding starts, frame prologues, call targets."""
    try:
        info = load_binary(binary)
    except (OSError, ValueError):
        return []
    text = next((s for s in info.sections.values() if s.name.lower() == ".text"), None)
    if text is None:
        return []
    if text.size <= 0 or text.file_offset < 0:
        return []
    if text.file_offset + text.size > len(info.data):
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
            # a padding run of >= 3 bytes: the byte after it starts a function.
            # The inner loop stops at a multi-byte nop's MODRM byte
            # (0f 1f 40 xx / 0f 1f 00 / 0f 1f 44 xx xx) — skip the whole nop
            # so the start lands after it, not on the 0x40.
            if j - i >= 3 and j < n:
                if j + 1 < n and raw[j] == 0x0F and raw[j + 1] == 0x1F:
                    modrm = raw[j + 2] if j + 2 < n else 0
                    nop_len = {0x00: 3, 0x40: 4, 0x44: 5, 0x84: 7, 0xC0: 3, 0xC4: 4}.get(modrm, 3)
                    j = min(n, j + nop_len)
                starts.add(va_base + j)
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
        logging.debug("extract_bytes failed at 0x%x", va, exc_info=True)
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
            # Disassembly failure at this candidate: ret_end stays None, so the
            # size falls back to the raw gap. Log it — a mis-sized function in
            # the catalog is otherwise indistinguishable from a correct one.
            logging.debug(
                "instruction sweep failed at candidate 0x%x (size = raw gap)", va, exc_info=True
            )

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


def _mz_capstone_sweep(binary: Path) -> list[tuple[int, int, str]]:
    """Linear-sweep candidates for a plain DOS MZ executable.

    Rizin cannot analyze MZ; the code region (after the header + relocation
    table) is swept in 16-bit mode for the classic cdecl prologue
    ``push bp; mov bp,sp``, padding runs, the CS:IP entry point, and
    ``e8 rel16`` call targets inside the region.  VAs are linear
    ``segment*16+offset`` addresses (the DOS convention).
    """
    from rebrew.binary_loader import parse_mz_header

    h = parse_mz_header(binary)
    with open(binary, "rb") as f:
        f.seek(h["code_offset"])
        raw = f.read(h["code_size"])
    if not raw:
        return []
    # VAs are segment-relative linear addresses: the code region starts at
    # VA 0 and the header's code segment ``e_cs`` lands at ``e_cs*16``
    # (entry at ``e_cs*16 + e_ip``), consistent with load_binary's pseudo
    # .text section.  VA(F) = F - code_offset.
    va_base = h["va_base"]
    starts: set[int] = set()

    # 1. the code region base and the CS:IP entry are always candidates
    starts.add(va_base)
    entry = h["entry_va"]
    if va_base <= entry < va_base + len(raw):
        starts.add(entry)
    # 2. bytes after padding runs (nop alignment)
    i = 0
    n = len(raw)
    while i < n - 1:
        if raw[i] == 0x90:
            j = i
            while j < n and raw[j] in (0x90, 0xCC):
                j += 1
            if j - i >= 2 and j < n:
                starts.add(va_base + j)
            i = j
        else:
            i += 1
    # 3. `push bp; mov bp,sp` prologue (16-bit cdecl)
    for m in re.finditer(rb"\x55\x8b\xec", raw):
        starts.add(va_base + m.start())
    # 4. direct-call targets (e8 rel16) inside the region
    try:
        import capstone

        md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_16)
    except Exception:
        md = None
    if md is not None:
        for insn in md.disasm(raw, va_base):
            if insn.mnemonic == "call" and insn.op_str.startswith("0x"):
                try:
                    tgt = int(insn.op_str, 16)
                except ValueError:
                    continue
                if va_base <= tgt < va_base + n:
                    starts.add(tgt)

    # Sizes: extent up to the next candidate (linear-sweep convention);
    # the last candidate runs to the end of the code region.
    ordered = sorted(starts)
    region_end = va_base + n
    out: list[tuple[int, int, str]] = []
    for i, va in enumerate(ordered):
        end = ordered[i + 1] if i + 1 < len(ordered) else region_end
        out.append((va, max(0, end - va), f"fcn.{va:04x}"))
    return out


def discover_functions(binary: Path, *, min_size: int = 8) -> Discovery:
    """Chain rizin + capstone strategies and merge into validated functions.

    16-bit NE binaries short-circuit to the native NE loader's linear sweep
    — rizin cannot analyze NE, and its output is garbage file-offset
    "functions" (the 233-function false enumeration that once polluted the
    SkiFree intake).  Plain DOS MZ binaries short-circuit to the 16-bit
    capstone sweep (rizin cannot analyze MZ either).
    """
    from rebrew.binary_loader import is_mz, is_ne, load_binary

    if is_ne(binary):
        from rebrew.ne_loader import enumerate_ne_functions

        info = load_binary(binary)
        funcs = [(f.va, f.size, f.name) for f in enumerate_ne_functions(info) if f.size >= min_size]
        d = Discovery()
        d.functions = funcs
        d.sources = {"ne loader": len(funcs)}
        return d

    if is_mz(binary):
        # Sizes are unknown in a bare MZ sweep (no symbol table) — estimate
        # each candidate's extent as the gap to the next candidate so
        # --min-size is honored (a size-0 filter would drop everything).
        funcs = sorted(_mz_capstone_sweep(binary))
        sized: list[tuple[int, int, str]] = []
        for idx, (va, _size, name) in enumerate(funcs):
            nxt = funcs[idx + 1][0] if idx + 1 < len(funcs) else va + 0x100
            sized.append((va, max(1, nxt - va), name))
        d = Discovery()
        d.functions = [f for f in sized if f[1] >= min_size]
        d.sources = {"mz sweep": len(d.functions)}
        return d

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
    sweep: list[tuple[int, int, str]] = []
    try:
        sweep = _capstone_sweep(binary)
    except Exception as exc:
        # The capstone sweep is a fallback source; its absence must not be
        # silent — without it, rizin-derived sizes go unvalidated.
        logging.warning("capstone linear sweep failed (sizes unvalidated): %s", exc)
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
    except Exception as exc:
        # Unvalidated gap-based sizes are still emitted, but the user must
        # know the refine pass was skipped.
        logging.warning("size refine step failed (emitting unvalidated sizes): %s", exc)

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
        error_exit(msg, json_mode=json_output)

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
    """Run the Typer CLI application.

    The callback is registered as a plain command on a fresh app: the
    group-style ``invoke_without_command`` callback fails to parse
    positional-then-option invocations (``rebrew-<cmd> ARG --opt`` — click
    treats the positional as a command name), while the umbrella's command
    registration parses both orderings (cli-review F1).
    """
    _standalone = typer.Typer()
    _standalone.command()(main)
    _standalone()


if __name__ == "__main__":
    main_entry()
