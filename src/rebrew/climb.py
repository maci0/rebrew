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
"""

from __future__ import annotations

import re
from collections.abc import Callable
from pathlib import Path

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
from rebrew.compile import compile_and_compare
from rebrew.config import ProjectConfig
from rebrew.core import build_name_to_va
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


def _score(
    cfg: ProjectConfig,
    path: Path,
    symbol: str,
    target_bytes: bytes,
    cflags: str,
    name_to_va: dict[str, int],
    section_va: int,
    toolchain: str | None,
) -> float:
    """Matched-byte count for *path*, or -1.0 when it does not compile.

    The arguments and the arithmetic mirror ``rebrew test`` exactly, including
    ``name_to_va``/``section_va`` (DIR32 absolute validation) and the
    match_percent -> match_count reconstruction.  Scoring a differently computed
    percentage once made a move look like an improvement while
    ``rebrew test`` reported one byte fewer.
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
        return -1.0
    total = max(len(target_bytes), len(result.obj_bytes))
    if result.matched:
        return float(total)
    return float(round(result.match_percent / 100.0 * total))


def _swap(lines: list[str], a: tuple[int, int], b: tuple[int, int]) -> list[str]:
    """Return *lines* with the two statement ranges exchanged."""
    a1, b1 = a
    b0, b2 = b
    return lines[:a1] + lines[b0 : b2 + 1] + lines[a1 : b1 + 1] + lines[b2 + 1 :]


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
    dry_run: bool = typer.Option(False, "--dry-run", help="Preview changes without writing"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
    target: str | None = TargetOption,
) -> None:
    """Relocate one top-level statement at a time and keep every move that matches more bytes."""
    cfg = require_config(target=target)
    path = Path(source)
    if not path.is_file():
        error_exit(f"Source file not found: {source}", json_mode=json_output)

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
        return _score(cfg, path, sym, target_bytes, cflags_str, name_to_va, va_int, toolchain_name)

    def report(move: dict[str, int | float]) -> None:
        # stderr, so --json output on stdout stays parseable
        console.print(f"  pass {move['pass']} statement {move['index']}: {move['after']:.0f} bytes")

    try:
        baseline = score_fn(lines)
        if baseline < 0:
            error_exit("baseline does not compile -- fix the function first", json_mode=json_output)
        console.print(f"baseline {sym}: {baseline:.0f} matched bytes")
        lines, best, moves = _climb(lines, chunks, score_fn, passes, sym, on_move=report)
        applied = best > baseline and not dry_run
        atomic_write_text(path, "".join(lines) if applied else original, encoding=encoding)
    except BaseException:
        atomic_write_text(path, original, encoding=encoding)
        raise

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
