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

from rebrew.cli import TargetOption, error_exit, json_print, require_config

console = Console(stderr=True)

# ---------------------------------------------------------------------------
# Shared: blocker classification (re-exported to match.py callers)
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

        t_obj = row.get("target") or {}
        c_obj = row.get("candidate") or {}
        t = t_obj if isinstance(t_obj, dict) else {}
        c = c_obj if isinstance(c_obj, dict) else {}
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

        # Zero-extend patterns
        if ("xor" in t_mnem and "mov" in c_mnem) or ("mov" in t_mnem and "xor" in c_mnem):
            blockers.add("zero-extend pattern (xor vs mov)")

        # Comparison direction swap
        if t_mnem == "cmp" and c_mnem == "cmp" and t_asm != c_asm:
            blockers.add("comparison direction swap")

        # Stack frame choice
        if ("push" in t_mnem and "sub esp" in c_asm) or ("sub esp" in t_asm and "push" in c_mnem):
            blockers.add("stack frame choice (push vs sub esp)")

        # Instruction folding (lea vs mov)
        if ("lea" in t_mnem and "mov" in c_mnem) or ("mov" in t_mnem and "lea" in c_mnem):
            blockers.add("instruction folding (lea vs mov)")

    return sorted(blockers)


def _print_structural_similarity(sim: Any) -> None:
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


def run_diff(
    seed_c: str,
    mismatches_only: bool,
    register_aware: bool,
    csv_output: bool,
    fix_blocker: bool,
    json_output: bool,
    # resolved build params from match._resolve_build_params
    p: Any,
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
    )
    if not (res.ok and res.obj_bytes):
        if json_output:
            error_exit(f"Build failed: {res.error_msg}", json_mode=True)
        console.print(f"Build failed: {res.error_msg}")
        raise typer.Exit(code=2)

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

    has_structural = False
    if summary:
        blockers = classify_blockers(summary)
        sim = structural_similarity(p.target_bytes, obj_bytes, res.reloc_offsets)

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
            if blockers:
                summary["blockers"] = blockers
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
            if blockers:
                console.print("\nAuto-classified blockers:")
                for b in blockers:
                    console.print(f"  - {b}")
            _print_structural_similarity(sim)

        if fix_blocker:
            from rebrew.annotation import parse_c_file
            from rebrew.metadata import remove_field, update_field

            seed_path = Path(p.seed_c)
            ann = parse_c_file(seed_path)
            metadata_dir = seed_path.parent
            va = ann.va if ann else p.va_int
            module = ann.module if ann else ""

            if blockers:
                blocker_text = ", ".join(blockers)
                delta = sum(
                    1 for a, b in zip(p.target_bytes, obj_bytes, strict=False) if a != b
                ) + abs(len(p.target_bytes) - len(obj_bytes))
                update_field(metadata_dir, va, "blocker", blocker_text, module=module)
                if delta > 0:
                    update_field(metadata_dir, va, "blocker_delta", delta, module=module)
                if not json_output:
                    console.print(f"  Updated BLOCKER: {blocker_text} ({delta}B delta)")
            else:
                deleted_b = remove_field(metadata_dir, va, "blocker", module=module)
                deleted_d = remove_field(metadata_dir, va, "blocker_delta", module=module)
                if (deleted_b or deleted_d) and not json_output:
                    console.print("  Cleared BLOCKER (no structural diffs)")

        summary_obj = summary.get("summary", {})
        structural_obj = summary_obj.get("structural", 0) if isinstance(summary_obj, dict) else 0
        has_structural = isinstance(structural_obj, int | float) and structural_obj > 0

    if has_structural:
        raise typer.Exit(code=1)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

_EPILOG = (
    "[bold]Examples:[/bold]\n\n"
    "  rebrew diff src/game/my_func.c · · · · · · · · Show full byte diff\n\n"
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
    seed_c: str = typer.Argument(..., help="Seed source file (.c)"),
    mismatches_only: bool = typer.Option(
        False,
        "--mismatches-only",
        "--mm",
        help="Show only structural diff (**) lines",
    ),
    register_aware: bool = typer.Option(
        False,
        "--register-aware",
        "--rr",
        help="Normalize register encodings and mark differences as RR",
    ),
    fix_blocker: bool = typer.Option(
        False,
        "--fix-blocker",
        help="Auto-write BLOCKER/BLOCKER_DELTA metadata from diff classification",
    ),
    fmt: str = typer.Option(
        "terminal",
        "--format",
        "-f",
        help="Output format: terminal, csv",
    ),
    force: bool = typer.Option(
        False, "--force", help="Continue even if source marker lint errors exist"
    ),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
    target: str | None = TargetOption,
) -> None:
    """Compile a reversed function and show a byte diff against the target."""
    if fmt not in ("terminal", "csv"):
        error_exit("--format must be 'terminal' or 'csv'", json_mode=json_output)

    csv_output = fmt == "csv"

    cfg = require_config(target=target, json_mode=json_output)

    # Resolve build parameters via match module's shared resolver
    from rebrew.match import resolve_build_params

    params = resolve_build_params(
        cfg, seed_c, None, None, None, None, None, None, force, json_output
    )

    run_diff(seed_c, mismatches_only, register_aware, csv_output, fix_blocker, json_output, params)


def main_entry() -> None:
    """Run the Typer CLI application."""
    app()


if __name__ == "__main__":
    main_entry()
