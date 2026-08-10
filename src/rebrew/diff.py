"""diff.py – Compile and diff a reversed function against the target binary.

Compiles the seed .c file with MSVC6 and shows a side-by-side byte diff
against the function at the annotated VA.  Optionally auto-writes BLOCKER/
BLOCKER_DELTA metadata based on structural analysis.

Usage:
    rebrew diff src/game/my_func.c
    rebrew diff src/game/my_func.c --mm
    rebrew diff src/game/my_func.c --fix-blocker
    rebrew diff src/game/my_func.c --json
"""

from __future__ import annotations

import csv
import sys
from pathlib import Path
from typing import Any

import typer
from rich.console import Console

from rebrew.cli import (
    EXIT_ERROR,
    EXIT_MISMATCH,
    TargetOption,
    error_exit,
    json_print,
    require_config,
)

console = Console(stderr=True)

# ---------------------------------------------------------------------------
# Shared: blocker classification (used by match.py)
# ---------------------------------------------------------------------------


def classify_blockers(diff_summary: dict[str, Any]) -> list[str]:
    """Auto-classify NEAR_MATCHING blockers from structural diffs.

    Looks for patterns in mismatched (** / RR) lines to identify systemic
    compiler differences like register allocation, loop rotation, etc.
    """
    blockers: set[str] = set()
    insns_raw = diff_summary.get("instructions", [])
    insns = insns_raw if isinstance(insns_raw, list) else []

    for row in insns:
        if not isinstance(row, dict):
            continue
        match_char = row.get("match")
        if match_char not in ("**", "RR"):
            continue

        t = row.get("target") or {}
        c = row.get("candidate") or {}
        t_asm = t.get("disasm", "")
        c_asm = c.get("disasm", "")

        # Register allocation
        if match_char == "RR":
            blockers.add("register allocation")
            continue

        t_parts = t_asm.split()
        c_parts = c_asm.split()
        t_mnem = t_parts[0] if t_parts else ""
        c_mnem = c_parts[0] if c_parts else ""

        # Loop rotation / jump conditions
        if (t_mnem.startswith("j") and c_mnem.startswith("j")) and t_mnem != c_mnem:
            if t_mnem != "jmp" and c_mnem != "jmp":
                blockers.add("jump condition swap")
            else:
                blockers.add("loop rotation / branch layout")

        if ("xor" in t_mnem and "mov" in c_mnem) or ("mov" in t_mnem and "xor" in c_mnem):
            blockers.add("zero-extend pattern (xor vs mov)")

        if t_mnem == "cmp" and c_mnem == "cmp" and t_asm != c_asm:
            blockers.add("comparison direction swap")

        if ("push" in t_mnem and "sub esp" in c_asm) or ("sub esp" in t_asm and "push" in c_mnem):
            blockers.add("stack frame choice (push vs sub esp)")

        if ("lea" in t_mnem and "mov" in c_mnem) or ("mov" in t_mnem and "lea" in c_mnem):
            blockers.add("instruction folding (lea vs mov)")

    return sorted(blockers)


def print_structural_similarity(sim: Any) -> None:
    verdict = "flag sweep MAY help" if sim.flag_sensitive else "flags unlikely to help"
    console.print(f"\nStructural similarity ({verdict}):")
    console.print(
        f"  Instructions: {sim.exact} exact, {sim.reloc_only} reloc, "
        f"{sim.register_only} register, {sim.structural} structural "
        f"(of {sim.total_insns} total)"
    )
    console.print(
        f"  Mnemonic match: {sim.mnemonic_match_ratio:.1%}  |  "
        f"Structural ratio: {sim.structural_ratio:.1%}"
    )


# ---------------------------------------------------------------------------
# Core diff logic (used by both diff.py CLI and match.py GA mode)
# ---------------------------------------------------------------------------


def _global_name_map(cfg: Any) -> dict[int, str]:
    """Build a VA → global-name map (inverse of build_name_to_va)."""
    from rebrew.core import build_name_to_va

    try:
        return {v: n for n, v in build_name_to_va(cfg).items() if v}
    except Exception:  # noqa: BLE001 — best-effort name resolution
        return {}


def _resolve_global_names(instructions: list[dict[str, Any]], cfg: Any) -> None:
    """Rewrite absolute addresses in the diff disasm to global names in place.

    ``mov eax, dword ptr [0x10034640]`` → ``mov eax, dword ptr [g_stat1]``
    when the data scan knows the global — makes diffs far more readable.
    """
    name_by_va = _global_name_map(cfg)
    if not name_by_va:
        return

    def _sub(disasm: str) -> str:
        import re

        def _rep(m: re.Match[str]) -> str:
            va = int(m.group(0), 16)
            return name_by_va.get(va, m.group(0))

        return re.sub(r"0x[0-9a-fA-F]+", _rep, disasm)

    for row in instructions:
        if not isinstance(row, dict):
            continue
        for side in ("target", "candidate"):
            obj = row.get(side)
            if isinstance(obj, dict) and obj.get("disasm"):
                obj["disasm"] = _sub(obj["disasm"])


def _missing_global_hints(instructions: list[dict[str, Any]]) -> list[dict[str, str]]:
    """Detect candidate references to absolute address 0 (unresolved globals).

    MSVC compiles a reference to an extern into a relocation (shown as
    ``[0]`` in the candidate disasm) — that is normal and masked by the
    reloc-aware comparison (``~~`` rows).  A ``[0]`` operand on a
    NON-reloc row means the address genuinely didn't resolve (missing
    definition), which source mutation cannot fix — the user must add a
    ``// GLOBAL:`` annotation (or extern) for the target address.
    """
    hints: list[dict[str, str]] = []
    for row in instructions:
        if not isinstance(row, dict):
            continue
        if row.get("match") in ("~~", "=="):
            continue  # reloc-masked extern or exact match — normal
        c_obj = row.get("candidate") or {}
        c_data = c_obj if isinstance(c_obj, dict) else {}
        c_disasm = c_data.get("disasm", "")
        if "[0]" not in c_disasm and " 0x0" not in c_disasm:
            continue
        t_obj = row.get("target") or {}
        t_data = t_obj if isinstance(t_obj, dict) else {}
        hints.append({"candidate": c_disasm, "target": t_data.get("disasm", "")})
    # Deduplicate by candidate disasm.
    seen: set[str] = set()
    out: list[dict[str, str]] = []
    for h in hints:
        if h["candidate"] in seen:
            continue
        seen.add(h["candidate"])
        out.append(h)
    return out


def run_diff(
    seed_c: str,
    mismatches_only: bool,
    register_aware: bool,
    csv_output: bool,
    fix_blocker: bool,
    json_output: bool,
    # resolved build params from match.resolve_build_params
    p: Any,
    *,
    dry_run: bool = False,
) -> None:
    """Compile seed and show byte diff vs target. Shared with match.py."""
    from rebrew.matcher import (
        build_candidate_obj_only,
        diff_functions,
        structural_similarity,
    )

    res = build_candidate_obj_only(
        p.seed_src,
        p.cl,
        p.inc,
        p.cflags,
        p.symbol,
        env=p.msvc_env,
        cache=p.cc,
        timeout=p.cfg.compile_timeout,
        extra_include_dirs=[str(p.seed_c.parent.resolve())],
        posix_style=getattr(p.cfg, "compiler_profile", "") in ("gcc", "gcc-pe", "clang"),
    )
    if not (res.ok and res.obj_bytes):
        error_exit(f"Build failed: {res.error_msg}", json_mode=json_output, code=EXIT_ERROR)

    obj_bytes = res.obj_bytes
    if len(obj_bytes) > len(p.target_bytes):
        obj_bytes = obj_bytes[: len(p.target_bytes)]

    summary = diff_functions(
        p.target_bytes,
        obj_bytes,
        res.reloc_offsets,
        mismatches_only=mismatches_only,
        register_aware=register_aware,
        as_dict=True,
    )
    if not json_output and not csv_output:
        diff_functions(
            p.target_bytes,
            obj_bytes,
            res.reloc_offsets,
            mismatches_only=mismatches_only,
            register_aware=register_aware,
        )

    if isinstance(summary, dict) and summary.get("instructions"):
        _resolve_global_names(summary["instructions"], p.cfg)
    missing_globals = _missing_global_hints(
        summary.get("instructions", []) if isinstance(summary, dict) else []
    )

    has_structural = False
    if summary:
        blockers = classify_blockers(summary)
        sim = structural_similarity(p.target_bytes, obj_bytes, res.reloc_offsets)

        # Short-candidate triage: target instructions with no compiled
        # counterpart are the not-yet-decompiled tail (SIZE_MISMATCH class).
        missing_tail: dict[str, Any] | None = None
        missing_rows = [
            i
            for i in (summary.get("instructions") or [])
            if i.get("match") == "**" and not (i.get("candidate") or {}).get("disasm")
        ]
        if missing_rows:
            missing_tail = {
                "count": len(missing_rows),
                "first": (missing_rows[0].get("target") or {}).get("disasm", ""),
                "last": (missing_rows[-1].get("target") or {}).get("disasm", ""),
            }

        if json_output:
            summary["structural_similarity"] = {
                "total_insns": sim.total_insns,
                "exact": sim.exact,
                "reloc_only": sim.reloc_only,
                "register_only": sim.register_only,
                "structural": sim.structural,
                "mnemonic_match_ratio": sim.mnemonic_match_ratio,
                "structural_ratio": sim.structural_ratio,
                "flag_sensitive": sim.flag_sensitive,
            }
            if missing_tail:
                summary["missing_tail"] = missing_tail
            if blockers:
                summary["blockers"] = blockers
            if missing_globals:
                summary["missing_globals"] = missing_globals
            json_print(summary)
        elif csv_output:
            writer = csv.writer(sys.stdout)
            writer.writerow(
                ["Index", "Match", "Target_Bytes", "Target_Disasm", "Cand_Bytes", "Cand_Disasm"]
            )
            instructions_obj = summary.get("instructions", [])
            instructions = instructions_obj if isinstance(instructions_obj, list) else []
            for row in instructions:
                if not isinstance(row, dict):
                    continue
                m_char = row.get("match") or ""
                if mismatches_only and m_char != "**":
                    continue
                t_obj = row.get("target") or {}
                c_obj = row.get("candidate") or {}
                t_data = t_obj if isinstance(t_obj, dict) else {}
                c_data = c_obj if isinstance(c_obj, dict) else {}
                writer.writerow(
                    [
                        row.get("index", ""),
                        m_char,
                        t_data.get("bytes", ""),
                        t_data.get("disasm", ""),
                        c_data.get("bytes", ""),
                        c_data.get("disasm", ""),
                    ]
                )
        else:
            if missing_globals:
                console.print(
                    f"\n[yellow]hint:[/yellow] {len(missing_globals)} unresolved global "
                    "reference(s) ([0] operand) — add a GLOBAL annotation for the "
                    "target address"
                )
            if blockers:
                console.print("\nAuto-classified blockers:")
                for b in blockers:
                    console.print(f"  - {b}")
            if missing_tail:
                console.print(
                    f"\n[yellow]{missing_tail['count']} target instruction(s) not yet "
                    f"decompiled[/yellow] — the C covers {len(obj_bytes)}/{len(p.target_bytes)} "
                    f"bytes; first missing: [bold]{missing_tail['first']}[/bold]"
                )
            print_structural_similarity(sim)

        if fix_blocker:
            from rebrew.annotation import parse_c_file
            from rebrew.metadata import remove_field, update_field

            seed_path = Path(p.seed_c)
            ann = parse_c_file(seed_path)
            metadata_dir = p.cfg.metadata_dir
            va = ann.va if ann else p.va_int
            module = ann.module if ann else ""

            if blockers:
                blocker_text = ", ".join(blockers)
                delta = sum(
                    1 for a, b in zip(p.target_bytes, obj_bytes, strict=False) if a != b
                ) + abs(len(p.target_bytes) - len(obj_bytes))
                if dry_run:
                    if not json_output:
                        console.print(f"  Would update BLOCKER: {blocker_text} ({delta}B delta)")
                else:
                    update_field(metadata_dir, va, "blocker", blocker_text, module=module)
                    if delta > 0:
                        update_field(metadata_dir, va, "blocker_delta", delta, module=module)
                    if not json_output:
                        console.print(f"  Updated BLOCKER: {blocker_text} ({delta}B delta)")
            else:
                if dry_run:
                    if not json_output:
                        console.print("  Would clear BLOCKER (no structural diffs)")
                else:
                    deleted_b = remove_field(metadata_dir, va, "blocker", module=module)
                    deleted_d = remove_field(metadata_dir, va, "blocker_delta", module=module)
                    if (deleted_b or deleted_d) and not json_output:
                        console.print("  Cleared BLOCKER (no structural diffs)")

        summary_obj = summary.get("summary", {})
        structural_obj = summary_obj.get("structural", 0) if isinstance(summary_obj, dict) else 0
        has_structural = isinstance(structural_obj, int | float) and structural_obj > 0

    if has_structural:
        raise typer.Exit(code=EXIT_MISMATCH)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

_EPILOG = (
    "[bold]Examples:[/bold]\n\n"
    "  rebrew diff src/game/my_func.c · · · · · · · · Show full byte diff\n\n"
    "  rebrew diff 0x10009310 · · · · · · · · · · · · Resolve VA to its source and diff\n\n"
    "  rebrew diff src/game/my_func.c --mm · · · · · · Show only structural mismatches (**)\n\n"
    "  rebrew diff src/game/my_func.c --rr · · · · · · Normalize register encodings (mark as RR)\n\n"
    "  rebrew diff src/game/my_func.c --fix-blocker · · Auto-write BLOCKER from diff analysis\n\n"
    "  rebrew diff src/game/my_func.c --format csv · · · CSV output\n\n"
    "  rebrew diff src/game/my_func.c --json · · · · · JSON structured diff\n\n"
    "[bold]Exit codes:[/bold]\n\n"
    "  0   No structural differences\n\n"
    "  1   Structural differences found (** lines)\n\n"
    "  2   Build failed\n\n"
    "[dim]Compiles source with MSVC6 (CFLAGS from metadata) and diffs against the target binary. "
    "Symbol, VA, and size are auto-detected from // FUNCTION markers and rebrew-function.toml metadata.[/dim]"
)

app = typer.Typer(
    help="Compile and diff a reversed function against the target binary.",
    rich_markup_mode="rich",
    epilog=_EPILOG,
)


@app.callback(invoke_without_command=True)
def main(
    seed_c: str = typer.Argument(..., help="C source file, symbol name, or VA (hex)"),
    mismatches_only: bool = typer.Option(
        False,
        "--mismatches-only",
        "-m",
        help="Show only structural diff (**) lines",
    ),
    register_aware: bool = typer.Option(
        False,
        "--register-aware",
        "-r",
        help="Normalize register encodings and mark differences as RR",
    ),
    fix_blocker: bool = typer.Option(
        False,
        "--fix-blocker",
        help="Auto-write BLOCKER/BLOCKER_DELTA metadata from diff classification",
    ),
    dry_run: bool = typer.Option(False, "--dry-run", help="Preview changes without writing"),
    fmt: str = typer.Option(
        "terminal",
        "--format",
        "-f",
        help="Output format: terminal, csv",
    ),
    ignore_lint: bool = typer.Option(
        False, "--ignore-lint", help="Continue even if source marker lint errors exist"
    ),
    watch: bool = typer.Option(
        False, "--watch", help="Watch the seed source and re-diff on every change"
    ),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
    target: str | None = TargetOption,
) -> None:
    """Compile a reversed function and show a byte diff against the target."""
    if fmt not in ("terminal", "csv"):
        error_exit("--format must be 'terminal' or 'csv'", json_mode=json_output)

    csv_output = fmt == "csv"

    cfg = require_config(target=target, json_mode=json_output)

    # Accept a hex VA or symbol name in addition to a .c path, like
    # `rebrew prove`/`rebrew test` (resolve_source_arg returns the argument
    # unchanged when nothing matches, so the original error path is kept).
    from rebrew.cli import resolve_source_arg

    va_arg = seed_c.strip().lower().startswith("0x")
    original_arg = seed_c
    seed_c = str(resolve_source_arg(cfg, seed_c))

    # Resolve build parameters via match module's shared resolver.  When the
    # argument was a bare VA, pass it through so resolve_build_params targets
    # THAT annotation in a multi-function file — previously it fell back to
    # the first annotation and diffed the wrong function (false match).
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
        ignore_lint,
        json_output,
    )

    if watch:
        from rebrew.utils import watch_files

        seed_path = Path(seed_c).resolve()
        # Keep the original positional (VA or symbol) for re-entry — seed_c is
        # now the resolved path, and passing it would drop the VA targeting and
        # re-diff the first annotation in a multi-function file.
        watch_arg = original_arg if va_arg else seed_c

        def _retest() -> None:
            # Re-run the full single-function diff path; --watch must not nest.
            main(
                seed_c=watch_arg,
                mismatches_only=mismatches_only,
                register_aware=register_aware,
                fix_blocker=fix_blocker,
                dry_run=dry_run,
                fmt=fmt,
                ignore_lint=ignore_lint,
                watch=False,
                json_output=json_output,
                target=target,
            )

        watch_files([seed_path], _retest)
        return

    run_diff(
        seed_c,
        mismatches_only,
        register_aware,
        csv_output,
        fix_blocker,
        json_output,
        params,
        dry_run=dry_run,
    )


def main_entry() -> None:
    """Run the Typer CLI application."""
    app()


if __name__ == "__main__":
    main_entry()
