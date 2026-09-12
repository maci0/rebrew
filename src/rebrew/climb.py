"""climb -- deterministic single-statement hill-climb over one function body.

``rebrew match`` searches with a genetic algorithm.  When a residual is statement
*order* rather than expression shape, the GA can stall: on
gm_CreateEntityFromParents (3689 B) it ran 100 generations without improving,
while this climb found five moves worth +21 matched bytes in one sweep.  The two
are complementary -- the GA explores expression and control-flow rewrites, the
climb exhausts the cheap adjacent relocations.

Each candidate is one adjacent swap of two top-level statements in the function
body, scored with the same compile->compare path as ``rebrew test``.  Candidates
are written to the source itself (the compile mounts the project root, so a copy
outside it would be invisible to the container) and the original text is
restored unless a move wins.  A hard kill can therefore leave an accepted
candidate in place -- two statements of the same function exchanged, still valid
C -- and ``git diff`` shows it.

A candidate is rejected when its object diverges further from the target's
length than the function already does (``_within_size_budget``).  Matched bytes
alone is not enough: ``total`` is ``max(target, object)``, so on a
size-mismatched function the search can raise its score by emitting more code.
On gm_CreateEntityFromParents (3689 B target, 3681 B object) that took the score
from ~583 to 861 matched bytes while growing the object to 3706 and ordering the
``slot[2] == 0x15 || 0x16`` test after the location block, against the target's
own order at 0x10018c49 / 0x10018c59.
"""

from __future__ import annotations

import difflib
import os
import re
import signal
from collections.abc import Callable
from pathlib import Path
from typing import Any

import typer
from rich.console import Console

from rebrew.annotation import parse_c_file_multi
from rebrew.binary_loader import extract_raw_bytes
from rebrew.cli import (
    TargetOption,
    error_exit,
    json_print,
    parse_va,
    require_config,
    resolve_compile_overrides,
)
from rebrew.coff_reloc import build_name_to_va
from rebrew.compile import compile_and_compare
from rebrew.config import ProjectConfig
from rebrew.sources import target_marker
from rebrew.utils import atomic_write_text, read_source_text

console = Console(stderr=True)

app = typer.Typer(
    help="Deterministic single-statement hill-climb for one function", rich_markup_mode="rich"
)

# ---------------------------------------------------------------------------
# statement chunking
# ---------------------------------------------------------------------------


def _code_lines(lines: list[str]) -> list[str]:
    """Per-line copy of *lines* with comments removed, preserving the line count.

    Tracks multi-line block comments and string/char literals across lines, so a
    ``{``/``}``/``;`` inside a comment or a literal never affects brace depth.
    A plain per-line strip corrupts real sources: ``"http://x"`` loses its code
    after ``//``, and braces inside a decompiler comment block are counted.
    """
    out: list[str] = []
    in_block = False
    quote: str | None = None
    for line in lines:
        buf: list[str] = []
        i = 0
        n = len(line)
        while i < n:
            ch = line[i]
            if in_block:
                end = line.find("*/", i)
                if end == -1:
                    break
                in_block = False
                i = end + 2
                continue
            if quote is not None:
                if ch == "\\" and i + 1 < n:
                    i += 2
                    continue
                if ch == quote or ch == "\n":
                    buf.append(ch)
                    quote = None
                i += 1
                continue
            if ch == "/" and i + 1 < n and line[i + 1] == "/":
                break
            if ch == "/" and i + 1 < n and line[i + 1] == "*":
                in_block = True
                i += 2
                continue
            if ch in "\"'":
                quote = ch
            buf.append(ch)
            i += 1
        out.append("".join(buf))
    return out


def _function_span(lines: list[str], symbol: str) -> tuple[int, int]:
    """Return the line indices of the definition of *symbol* and its closing brace.

    Raises:
        ValueError: when no definition or no matching closing brace is found.
    """
    name = symbol[1:] if symbol.startswith("_") else symbol
    # A __stdcall/__fastcall definition carries an "@<bytes>" decoration, which
    # the compiler adds and the source never writes: `_foo@8` defines `foo`.
    name = re.sub(r"@\d+$", "", name)
    head = re.compile(rf"^[\w\s\*]+?\b{re.escape(name)}\s*\(")
    code = _code_lines(lines)
    # A file may declare the symbol before defining it; a definition is the
    # match that does not end in ';'.  Taking the first match would climb the
    # prototype's neighbourhood -- file-scope structs included.
    start = next(
        (i for i, line in enumerate(code) if head.match(line) and not line.rstrip().endswith(";")),
        None,
    )
    if start is None:
        raise ValueError(f"definition of {name} not found in the source")
    depth = 0
    for i in range(start, len(code)):
        depth += code[i].count("{") - code[i].count("}")
        if i > start and depth == 0 and code[i].strip() == "}":
            return start, i
    raise ValueError(f"closing brace of {name} not found")


def _statements(lines: list[str], lo: int, hi: int) -> list[tuple[int, int]]:
    """Top-level statements in lines[lo:hi] as inclusive (first, last) index pairs.

    A statement ends where the brace depth returns to the function's own depth,
    so multi-line blocks move as a unit.  Trailing blank lines stay with the
    statement they follow.
    """
    code = _code_lines(lines)
    brace = next((i for i in range(lo, hi) if "{" in code[i]), None)
    if brace is None:
        raise ValueError("function body not found")
    depth = 1
    out: list[tuple[int, int]] = []
    first: int | None = None
    i = brace + 1
    while i < hi:
        stripped = code[i]
        if first is None:
            if stripped.strip() == "":
                i += 1
                continue
            first = i
        depth += stripped.count("{") - stripped.count("}")
        if depth == 1 and (stripped.rstrip().endswith(";") or stripped.rstrip().endswith("}")):
            last = i
            j = i + 1
            while j < hi and lines[j].strip() == "":
                last = j
                j += 1
            out.append((first, last))
            first = None
            i = last
        i += 1
    return out


# ---------------------------------------------------------------------------
# scoring
# ---------------------------------------------------------------------------


#: Address-sized hex (>= 6 digits) — an absolute address, never a constant the
#: source chose.  Same threshold ``scripts/seqdiff.py`` uses.
_ADDRESS_RE = re.compile(r"0x[0-9a-f]{6,}")

#: A bracketed short addend, the form an object carries for a relocation
#: against a global (the target side shows the resolved address).
_SHORT_ADDEND_RE = re.compile(r"\[0x[0-9a-f]{1,5}\]")


def _score(
    cfg: ProjectConfig,
    path: Path,
    symbol: str,
    target_bytes: bytes,
    cflags: str,
    name_to_va: dict[str, int],
    section_va: int,
    toolchain: str | None,
) -> tuple[float, int]:
    """Matched-byte count and object length for *path*, or ``(-1.0, 0)``.

    The arguments and the arithmetic mirror ``rebrew test`` exactly, including
    ``name_to_va``/``section_va`` (DIR32 absolute validation) and the
    match_percent -> match_count reconstruction.  Scoring a differently computed
    percentage once made a move look like an improvement while
    ``rebrew test`` reported one byte fewer.

    The object length comes back alongside the score because matched bytes
    alone is not a safe objective: ``total`` is ``max(target, object)``, so a
    candidate that emits more code can match more bytes while walking away from
    the target's length.  ``_within_size_budget`` is what refuses those.
    """
    result = compile_and_compare(
        cfg,
        path,
        symbol,
        target_bytes,
        cflags,
        name_to_va=name_to_va,
        section_va=section_va,
        toolchain=toolchain,
    )
    if result.obj_bytes is None:
        return -1.0, 0
    # The longer side is truncated before comparison, so ``obj_bytes`` is not
    # the object's real length on a size mismatch; ``full_obj_size`` is.  The
    # score's ``total`` keeps using the truncated bytes exactly as before, so
    # it still mirrors ``rebrew test``.
    obj_len = result.full_obj_size if result.full_obj_size is not None else len(result.obj_bytes)
    total = max(len(target_bytes), len(result.obj_bytes))
    if result.matched:
        return float(total), obj_len
    return float(round(result.match_percent / 100.0 * total)), obj_len


def _score_aligned(
    cfg: ProjectConfig,
    path: Path,
    symbol: str,
    target_bytes: bytes,
    cflags: str,
    name_to_va: dict[str, int],
    section_va: int,
    toolchain: str | None,
) -> tuple[float, int]:
    """Aligned instruction-pair count for *path*, or ``(-1.0, 0)``.

    The compile path is :func:`_score`'s; the comparison is the mnemonic
    alignment ``.scratch/ndiff.py`` reports as ``aligned`` instead of the
    positional byte count.  On a function whose byte stream is out of step with
    the target's the positional count rewards a candidate that merely shifts
    code into a better offset: measured on gm_AllocSpieler, ten accepted
    swaps raised it 859 -> 909 while the alignment fell 740 -> 728.

    It counts PAIRS, not bytes: scoring aligned bytes let one long instruction
    outweigh two short ones (1886 -> 2004 aligned bytes bought only 740 -> 743
    aligned instructions while the hunk count rose 177 -> 179).
    """
    result = compile_and_compare(
        cfg,
        path,
        symbol,
        target_bytes,
        cflags,
        name_to_va=name_to_va,
        section_va=section_va,
        toolchain=toolchain,
    )
    if result.obj_bytes is None:
        return -1.0, 0
    obj_len = result.full_obj_size if result.full_obj_size is not None else len(result.obj_bytes)
    from rebrew.near_diag import Insn, disasm_insns

    arch = getattr(cfg, "capstone_arch", "CS_ARCH_X86")
    mode = getattr(cfg, "capstone_mode", "CS_MODE_32")

    def text(insn: Insn) -> str:
        """Instruction text as the alignment compares it.

        Address-sized immediates fold to ``g``, and the operands an object
        carries for a relocation — a
        bare ``[0]`` or a short addend — fold onto ``g`` too, because the
        target side has the resolved address there.  ``scripts/seqdiff.py:norm``
        applies the same folds; without them the aligner paired 624 of the
        target's instructions where the sequence diff pairs 740.
        """
        text = _ADDRESS_RE.sub("g", f"{insn.mnemonic} {insn.op_str}")
        text = text.replace("[0]", "[g]")
        return _SHORT_ADDEND_RE.sub("[g]", text).strip()

    compiled = disasm_insns(result.obj_bytes, section_va, arch, mode)
    target = disasm_insns(target_bytes, section_va, arch, mode)
    # autojunk=False: difflib's default drops "popular" elements, which on a
    # 1000-instruction stream collapses the alignment (523 pairs against the
    # 740 the same streams pair with the heuristic off).
    aligner = difflib.SequenceMatcher(
        a=[text(i) for i in compiled], b=[text(i) for i in target], autojunk=False
    )
    return float(sum(block.size for block in aligner.get_matching_blocks())), obj_len


def _within_size_budget(matched: float, obj_len: int, target_len: int, budget: int) -> bool:
    """Whether a scored candidate may be kept.

    *matched* is negative when the candidate does not compile.  Otherwise the
    candidate must not diverge further from the target's length than the
    function already does (*budget*): the target's size is a hard fact, and a
    byte-exact result cannot come from an object of a different length.
    """
    if matched < 0.0:
        return False
    return abs(obj_len - target_len) <= budget


def _swap(lines: list[str], a: tuple[int, int], b: tuple[int, int]) -> list[str]:
    """Return *lines* with the two statement ranges exchanged."""
    a1, b1 = a
    b0, b2 = b
    return lines[:a1] + lines[b0 : b2 + 1] + lines[a1 : b1 + 1] + lines[b2 + 1 :]


def _install_restore_handler(path: Path, original: str, encoding: str) -> dict[int, Any]:
    """Put the source back if a signal ends the climb early.

    Scoring writes every candidate into the real source, so the file returns to
    *original* only on the normal and exception paths.  A SIGTERM -- a
    `timeout` wrapper, a supervisor killing the job -- runs neither, and leaves
    whichever candidate was last scored sitting in the tree.  Returns the
    previous handlers so the caller can restore them; the payload type is
    whatever ``signal.signal`` handed back, which has no useful common name.
    """
    previous: dict[int, Any] = {}

    def handler(signum: int, _frame: object) -> None:
        atomic_write_text(path, original, encoding=encoding)
        signal.signal(signum, previous.get(signum, signal.SIG_DFL))
        os.kill(os.getpid(), signum)

    for name in ("SIGTERM", "SIGINT", "SIGHUP"):
        number = getattr(signal, name, None)
        if number is not None:
            previous[number] = signal.signal(number, handler)
    return previous


def _remove_restore_handler(previous: dict[int, Any]) -> None:
    for number, handler in previous.items():
        signal.signal(number, handler)


def _climb(
    lines: list[str],
    chunks: list[tuple[int, int]],
    score_fn: Callable[[list[str]], float],
    passes: int,
    symbol: str,
    on_move: Callable[[dict[str, int | float]], None] | None = None,
) -> tuple[list[str], float, list[dict[str, int | float]]]:
    """Sweep adjacent statement swaps, keeping every move that scores higher.

    Returns the winning line list, its score and the accepted moves.  *score_fn*
    is called with a candidate and must return a higher-is-better number, which
    keeps the search testable without a compiler.  *on_move*, when given, is
    called with each accepted move so a long search can report progress.
    """
    best = score_fn(lines)
    moves: list[dict[str, int | float]] = []
    for sweep in range(passes):
        improved = 0
        for k in range(len(chunks) - 1):
            if k + 1 >= len(chunks):
                break
            candidate = _swap(lines, chunks[k], chunks[k + 1])
            score = score_fn(candidate)
            if score > best:
                best = score
                lines = candidate
                chunks = _statements(lines, *_function_span(lines, symbol))
                improved += 1
                move: dict[str, int | float] = {"pass": sweep, "index": k, "after": best}
                moves.append(move)
                if on_move is not None:
                    on_move(move)
        if improved == 0:
            break
    return lines, best, moves


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


@app.callback(invoke_without_command=True)
def main(
    source: str = typer.Argument(..., help="C source file containing the function"),
    va: str | None = typer.Option(None, "--va", help="VA in hex (e.g. 0x10018850)"),
    symbol: str | None = typer.Option(None, "--symbol", help="COFF symbol (e.g. _funcname)"),
    size: int | None = typer.Option(None, "--size", help="Size in bytes"),
    cflags: str | None = typer.Option(None, "--cflags", help="Compiler flags"),
    passes: int = typer.Option(1, "--passes", help="Sweeps of adjacent statement swaps"),
    objective: str = typer.Option(
        "positional",
        "--objective",
        help="Scoring: 'positional' matches bytes in place (test's count); "
        "'aligned' counts aligned instructions (near_diag), which is honest when "
        "the object's byte stream is out of step with the target's",
    ),
    dry_run: bool = typer.Option(False, "--dry-run", help="Preview changes without writing"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
    target: str | None = TargetOption,
) -> None:
    """Relocate one top-level statement at a time and keep every move that matches more bytes."""
    cfg = require_config(target=target)
    path = Path(source)
    if not path.is_file():
        error_exit(f"Source file not found: {source}", json_mode=json_output)
    if objective not in ("positional", "aligned"):
        error_exit(
            f"unknown --objective {objective!r} (use 'positional' or 'aligned')",
            json_mode=json_output,
        )
    scorer = _score_aligned if objective == "aligned" else _score

    anns = parse_c_file_multi(path, target_name=target_marker(cfg), metadata_dir=cfg.metadata_dir)
    if not anns:
        error_exit("No // FUNCTION annotation found in the source", json_mode=json_output)
    selected = anns[0]
    if va:
        want = parse_va(va, json_mode=json_output)
        selected = next((a for a in anns if a.va == want), selected)

    sym = symbol or selected.symbol
    size_val = size or selected.size
    va_int = parse_va(va, json_mode=json_output) if va else selected.va
    if not sym or va_int is None or not size_val:
        error_exit(
            "Need symbol, VA and SIZE (from the annotation or --symbol/--va/--size)",
            json_mode=json_output,
        )
    target_bytes = extract_raw_bytes(cfg.target_binary, va_int, size_val)
    toolchain_name, cflags_str = resolve_compile_overrides(
        cfg,
        path.resolve().parent,
        None,
        cflags or getattr(selected, "cflags", None),
        selected.module,
    )
    name_to_va = build_name_to_va(cfg)

    original, encoding = read_source_text(path)
    previous_handlers = _install_restore_handler(path, original, encoding)
    lines = original.splitlines(keepends=True)
    try:
        lo, hi = _function_span(lines, sym)
    except ValueError as exc:
        error_exit(str(exc), json_mode=json_output)
    chunks = _statements(lines, lo, hi)
    if len(chunks) < 2:
        error_exit("nothing to climb: fewer than two top-level statements", json_mode=json_output)

    def score_fn(candidate: list[str]) -> float:
        atomic_write_text(path, "".join(candidate), encoding=encoding)
        matched, obj_len = scorer(
            cfg, path, sym, target_bytes, cflags_str, name_to_va, va_int, toolchain_name
        )
        if not _within_size_budget(matched, obj_len, len(target_bytes), size_budget):
            return -1.0
        return matched

    def report(move: dict[str, int | float]) -> None:
        # stderr, so --json output on stdout stays parseable
        console.print(f"  pass {move['pass']} statement {move['index']}: {move['after']:.0f} bytes")

    try:
        baseline, baseline_obj = scorer(
            cfg, path, sym, target_bytes, cflags_str, name_to_va, va_int, toolchain_name
        )
        if baseline < 0:
            error_exit("baseline does not compile -- fix the function first", json_mode=json_output)
        size_budget = abs(baseline_obj - len(target_bytes))
        console.print(f"baseline {sym}: {baseline:.0f} matched bytes")
        lines, best, moves = _climb(lines, chunks, score_fn, passes, sym, on_move=report)
        applied = best > baseline and not dry_run
        atomic_write_text(path, "".join(lines) if applied else original, encoding=encoding)
    except BaseException:
        atomic_write_text(path, original, encoding=encoding)
        raise
    finally:
        _remove_restore_handler(previous_handlers)

    payload = {
        "source": str(path),
        "symbol": sym,
        "va": hex(va_int),
        "size": size_val,
        "statements": len(chunks),
        "baseline_matched": baseline,
        "best_matched": best,
        "applied": applied,
        "dry_run": dry_run,
        "moves": moves,
    }
    if json_output:
        json_print(payload)
        return
    console.print(
        f"{sym}: {baseline:.0f} -> [bold]{best:.0f}[/bold] matched bytes "
        f"({len(moves)} move(s){', dry run' if dry_run else ''})"
    )
    for move in moves:
        console.print(f"  pass {move['pass']} statement {move['index']}: {move['after']:.0f}")


def main_entry() -> None:
    """Run the Typer CLI application."""
    app()


if __name__ == "__main__":
    main_entry()
