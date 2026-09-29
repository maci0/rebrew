"""qual_sweep.py — sweep declaration qualifiers/types for one function.

``rebrew climb`` moves whole statements.  Functions that converge there do
so because their residue is register *naming* rather than order: the target
keeps a loop counter in ``ebx`` where we keep it in ``edi``, the same
instruction kinds in the same sequence.  The allocator is driven by live
ranges, so the cheap way to perturb it without changing what the code does
is to change a local's qualifying type.

This runs that idea over every declaration in a function, one at a time,
keeping only moves that improve the score.  It complements the GA's random
``mut_toggle_volatile`` (``rebrew match``): this is the exhaustive,
deterministic, one-variable-at-a-time sweep for when the GA stalls on an
allocator wall.

Generalized from guild-rebrew's ``scripts/qualsweep.py`` (MSVC6/x86-32
campaign).  Scoring goes through ``rebrew.compile.compile_and_compare``
so flags, toolchain, and reloc masking resolve per project.
"""

from __future__ import annotations

import contextlib
import re
import tempfile
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import typer

from rebrew.cli import (
    TargetOption,
    console,
    error_exit,
    json_print,
    require_config,
    select_annotation,
)
from rebrew.climb import function_span as climb_function_span
from rebrew.compile import compile_and_compare
from rebrew.compile_overrides import resolve_compile_overrides
from rebrew.temp_dirs import sweep_stale_temp_dirs
from rebrew.utils import (
    SOURCE_BACKUP_DIRNAME,
    atomic_write_text,
    filename_component,
    interruptible_pool,
    read_source_text,
    source_backup,
    untrusted_ident,
)

app = typer.Typer(
    help="Sweep declaration qualifiers over one function, keeping winners.",
    rich_markup_mode="rich",
    epilog=(
        "[bold]Examples:[/bold]\n\n"
        "  rebrew qual-sweep src/f.c · · · · · · · · Try every qualifier set, keep winners\n\n"
        "  rebrew qual-sweep src/f.c --rounds 5 · · · Re-sweep until the result stops changing\n\n"
        "  rebrew qual-sweep src/f.c --dry-run · · · Report the winning declaration, write nothing\n\n"
        "  rebrew qual-sweep src/f.c --json · · · · · · Machine-readable winner table to stdout\n\n"
        "[bold]Exit codes:[/bold]\n\n"
        "  0   The sweep finished (report the winner on stderr)\n\n"
        "  2   Build or config error (also a usage error: unknown flag, missing argument)\n\n"
        "[dim]130 = interrupted (Ctrl+C), 141 = stdout closed early (piped into head).[/dim]"
    ),
)

#: (label, pattern, replacement) — each must keep the declaration legal and
#: the function semantically identical.
QUALIFIERS: list[tuple[str, str, str]] = [
    ("volatile", r"^(\s*)(?!(?:.*\bvolatile\b))", r"\1volatile "),
]


def _strip_literals(text: str) -> str:
    return re.sub(r'"(?:[^"\\]|\\.)*"', '""', text)


def variants(decl: str) -> list[tuple[str, str]]:
    """Candidate rewrites of one declaration, as (label, text)."""
    body = _strip_literals(decl).strip()
    out = []
    for label, pat, repl in QUALIFIERS:
        new = re.sub(pat, repl, decl, count=1, flags=re.M)
        if _strip_literals(new).strip() != body:
            out.append((label, new))
    return out


def function_span(lines: list[str], symbol: str) -> tuple[int, int]:
    """Half-open line range of *symbol*'s definition, closing brace included.

    Raises:
        ValueError: when no definition or no matching closing brace is found.
    """
    lo, last = climb_function_span(lines, symbol)
    return lo, last + 1


def _is_decl(unit: str) -> bool:
    s = _strip_literals(unit).strip()
    return bool(
        re.match(
            r"^(?:volatile\s+|const\s+|static\s+|register\s+)?(?:\w[\w\s\*]*?)\s+\w+\s*(?:\[[^\]]*\])?\s*(?:=[^;]*)?;",
            s,
        )
    )


@contextlib.contextmanager
def _restore_source_on_error(path: Path, original: str, encoding: str) -> Iterator[None]:
    """Restore *path* to *original* if the body unwinds.

    The sweep writes each round's best-so-far candidate straight to the
    project ``.c``, so a ``KeyboardInterrupt`` or a toolchain failure partway
    through would otherwise leave a partially swept declaration on disk with
    no record of how it got there.
    """
    try:
        yield
    except BaseException:
        atomic_write_text(path, original, encoding=encoding)
        raise


def score_fn(
    cfg: Any,
    path: Path,
    va: int,
    size: int,
    symbol: str,
    toolchain: str | None,
    cflags: str,
) -> tuple[float, int]:
    """(match_percent, obj_len) via the project's compile-and-compare path.

    *toolchain*/*cflags* are the function's resolved overrides
    (:func:`rebrew.compile_overrides.resolve_compile_overrides`), so the sweep
    scores with the compiler ``rebrew test``/``verify`` use.
    """
    from rebrew.binary_loader import extract_raw_bytes

    target_bytes = extract_raw_bytes(cfg.target_binary, va, size)
    res = compile_and_compare(cfg, path, symbol, target_bytes, cflags, toolchain=toolchain)
    obj_len = len(res.obj_bytes) if res.obj_bytes else -1
    if res.full_obj_size is not None:
        obj_len = res.full_obj_size
    return res.match_percent, obj_len


@app.callback(invoke_without_command=True)
def main(
    source: str = typer.Argument(..., help="C source file (or VA/symbol) for the function"),
    va: str | None = typer.Option(None, "--va", help="Target VA in hex (default: from annotation)"),
    symbol: str | None = typer.Option(
        None, "--symbol", help="COFF symbol (default: from annotation)"
    ),
    rounds: int = typer.Option(4, "--rounds", help="Sweep rounds (stops early on convergence)"),
    jobs: int = typer.Option(4, "--jobs", help="Parallel compile workers"),
    dry_run: bool = typer.Option(False, "--dry-run", help="Preview changes without writing"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
    target: str | None = TargetOption,
) -> None:
    """Sweep one qualifier at a time over every declaration; keep winners."""
    cfg = require_config(target=target, json_mode=json_output)
    path, sel, va_int = select_annotation(cfg, source, va, json_mode=json_output)
    sym = symbol or sel.symbol
    size = sel.size
    # The symbol is annotation text, not a vetted identifier: it names a
    # candidate file below and is a mkdtemp prefix, so it cannot go into a path
    # unsanitized.
    sym_file = filename_component(sym or "")
    if va_int is None or not sym or not size:
        error_exit(
            "Need symbol, VA and SIZE (from the annotation or --va/--symbol)", json_mode=json_output
        )

    original, encoding = read_source_text(path)
    lines = original.splitlines(keepends=True)
    try:
        lo, hi = function_span(lines, sym)
    except ValueError as exc:
        error_exit(str(exc), json_mode=json_output)
    head, body_lines, tail = lines[:lo], lines[lo:hi], lines[hi:]
    # Split the definition into units at the function body's top level
    # (brace depth 1): the signature through its `{`, each `;`-terminated
    # statement, each nested block through its `}`, then the closing brace.
    units: list[str] = []
    depth = 0
    cur: list[str] = []
    for ln in body_lines:
        cur.append(ln)
        prev = depth
        depth += ln.count("{") - ln.count("}")
        if depth == 1 and (prev != 1 or ";" in ln):
            units.append("".join(cur))
            cur = []
    if cur:
        units.append("".join(cur))
    decls = [k for k, u in enumerate(units) if _is_decl(u)]
    console.print(f"{untrusted_ident(sym)}: {len(units)} statements, {len(decls)} declarations")

    if dry_run:
        candidates = [
            (k, lab, _strip_literals(new).strip()) for k in decls for lab, new in variants(units[k])
        ]
        if json_output:
            json_print(
                {
                    "source": str(path),
                    "symbol": sym,
                    "va": hex(va_int),
                    "candidates": [
                        {"index": k, "qualifier": lab, "text": text} for k, lab, text in candidates
                    ],
                }
            )
            return
        for k, lab, text in candidates:
            console.print(f"  [{k:3d}] {lab}: {untrusted_ident(text[:70])}")
        return

    # Resolved from the real source dir: candidates compile from a scratch
    # dir whose walk-up would miss the function's rebrew-libraries.toml.
    toolchain, cflags = resolve_compile_overrides(
        cfg,
        path.resolve().parent,
        getattr(sel, "toolchain", None),
        getattr(sel, "cflags", None),
        getattr(sel, "module", ""),
    )
    base = score_fn(cfg, path, va_int, size, sym, toolchain, cflags)
    baseline = base
    console.print(f"baseline {base[0]} matched, object size {base[1]} vs target {size}")
    moves: list[dict[str, Any]] = []

    sweep_root = Path(cfg.root) / ".rebrew" / "qualsweep"
    sweep_root.mkdir(parents=True, exist_ok=True)
    # A hard-killed run strands its round dir here, and the compile-base sweep
    # never walks this tree, so the leftovers are reclaimed by age on the way in
    # instead of one dir per lost run.
    sweep_stale_temp_dirs(sweep_root, prefixes=(f"{sym_file}-",))
    # The restore below needs Python to run; a SIGKILL, an OOM kill, a power
    # cut, or a stopped container runs none of it and leaves the last
    # candidate scored in the file.  The pre-run bytes go to disk first.
    with (
        source_backup(
            path,
            original,
            encoding,
            Path(cfg.root) / ".rebrew" / SOURCE_BACKUP_DIRNAME,
            label=sym,
        ) as backup_path,
        _restore_source_on_error(path, original, encoding),
    ):
        if backup_path is not None:
            console.print(f"  [dim]pre-run copy: {untrusted_ident(backup_path)}[/dim]")
        else:
            console.print(
                "  [yellow]pre-run copy could not be written;"
                " an uncatchable kill loses the pre-run source[/yellow]"
            )
        for rnd in range(rounds):
            cands = [(k, lab, new) for k in decls for lab, new in variants(units[k])]

            def submit(
                c: tuple[int, str, str], _tmpdir: Path
            ) -> tuple[tuple[int, str, str], tuple[float, int]]:
                k, lab, new = c
                alt = units[:]
                alt[k] = new
                # Compile a copy: parallel candidates must not share one path.
                tmp = _tmpdir / f"{sym_file}_{k}_{lab}.c"
                tmp.write_text("".join(head) + "".join(alt) + "".join(tail), encoding=encoding)
                return (k, lab, new), score_fn(cfg, tmp, va_int, size, sym, toolchain, cflags)

            # Private dir per round: a concurrent sweep of the same symbol (another
            # target sharing this root) would otherwise overwrite a candidate
            # between its write and its compile, scoring the wrong source.
            # -j 0 (or negative) bypasses config's _positive_int validation, so
            # clamp before the pool: max_workers=0 raises ValueError.
            # The cleanup does not raise on a failed remove: the pool below
            # deliberately leaves its in-flight workers running when the round
            # is interrupted, so one of them can still be writing a candidate
            # as this dir goes away.  That raced the removal into an OSError
            # that replaced the Ctrl+C the user pressed; the round dir this
            # strands is reclaimed by the age sweep above on the next run.
            with (
                tempfile.TemporaryDirectory(
                    dir=sweep_root, prefix=f"{sym_file}-", ignore_cleanup_errors=True
                ) as rnd_dir,
                interruptible_pool(max(1, jobs)) as ex,
            ):
                # Drain every future, one at a time, in submission order: a
                # candidate that raises (a write error, an unexpected toolchain
                # failure) must not abort the round, and an undrained future is
                # reported as "never retrieved" at exit. Order matters because
                # the winner is picked with a strict `>`, so candidates tying on
                # score are separated by iteration order alone, and the winner's
                # declaration is written back into the .c. Submission order makes
                # that choice a function of the candidate list, not of how the
                # pool happened to schedule.
                futures = {ex.submit(submit, c, Path(rnd_dir)): c for c in cands}
                results = []
                for fut, cand in futures.items():
                    try:
                        results.append(fut.result())
                    except Exception as exc:
                        console.print(
                            f"  candidate {cand[0]} ({cand[1]}) failed, "
                            f"scoring it as no improvement: {untrusted_ident(exc)}"
                        )
                        results.append((cand, (0.0, 0)))

            best, best_c = base, None
            for (_k, _lab, _new), sc in results:
                if sc[0] > best[0] and sc[1] >= size:
                    best, best_c = sc, (_k, _lab, _new)
            if best_c is None:
                console.print(
                    f"round {rnd}: no improving qualifier among {len(cands)}; converged at {base[0]}"
                )
                break
            k, lab, new = best_c
            units[k] = new
            base = best
            atomic_write_text(
                path, "".join(head) + "".join(units) + "".join(tail), encoding=encoding
            )
            moves.append({"round": rnd, "index": k, "qualifier": lab, "matched": base[0]})
            console.print(f"round {rnd}: {lab} on [{k}] -> {base[0]} matched (object {base[1]})")

    payload = {
        "source": str(path),
        "symbol": sym,
        "va": hex(va_int),
        "baseline_matched": baseline[0],
        "best_matched": base[0],
        "moves": moves,
    }
    if json_output:
        json_print(payload)
        return
    console.print(
        f"{untrusted_ident(sym)}: final {base[0]} matched, object size {base[1]} "
        f"({len(moves)} move(s))"
    )


def main_entry() -> None:
    """Run the Typer CLI application."""
    from rebrew.cli import run_standalone

    run_standalone(main)


if __name__ == "__main__":
    main_entry()
