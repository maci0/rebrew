#!/usr/bin/env python3
"""Atomic promote: test a function and update its STATUS annotation.

Runs rebrew-test internally, then updates the STATUS and BLOCKER annotations
based on the result. Outputs structured JSON for agent consumption.

Usage:
    rebrew-promote src/server.dll/my_func.c
    rebrew-promote src/server.dll/my_func.c --json
"""

import json
import shutil
import sys
import tempfile
from pathlib import Path
from typing import Any

import typer

from rebrew.annotation import parse_c_file_multi
from rebrew.cli import TargetOption, get_config
from rebrew.matcher.parsers import parse_coff_symbol_bytes
from rebrew.test import (
    _build_result_dict,
    compile_obj,
    smart_reloc_compare,
    update_source_status,
)

_EPILOG = """\
[bold]Examples:[/bold]
  rebrew-promote src/game_dll/my_func.c             Test + update STATUS
  rebrew-promote src/game_dll/my_func.c --json       JSON output for agents
  rebrew-promote src/game_dll/my_func.c --dry-run    Show what would change

[bold]How it works:[/bold]
  1. Compiles the source file
  2. Compares compiled bytes against the target binary
  3. Updates STATUS to EXACT/RELOC/MATCHING based on result
  4. Removes BLOCKER annotation if the function matches (EXACT/RELOC)
  5. Reports the result as structured JSON

[dim]This is the atomic version of 'rebrew-test + manual STATUS edit'.
Safe for agent use — idempotent, validates before writing.[/dim]"""

app = typer.Typer(
    help="Test a function and atomically update its STATUS annotation.",
    rich_markup_mode="rich",
)


@app.command(epilog=_EPILOG)
def main(
    source: str = typer.Argument(help="C source file"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
    dry_run: bool = typer.Option(False, "--dry-run", help="Show what would change without writing"),
    target: str | None = TargetOption,
) -> None:
    """Test a function and atomically update its STATUS annotation."""
    cfg = get_config(target=target)
    source_path = Path(source)

    annotations = parse_c_file_multi(source_path)
    if not annotations:
        _error("No annotations found in source file", json_output, source=source)
        raise typer.Exit(code=1)

    # Use first annotation's cflags for compilation
    cflags_str = annotations[0].cflags or "/O2 /Gd"
    cflags_parts = cflags_str.split()

    results: list[dict[str, Any]] = []

    workdir = tempfile.mkdtemp(prefix="promote_")
    try:
        obj_path, err = compile_obj(cfg, source, cflags_parts, workdir)
        if obj_path is None:
            _error(f"Compile error: {err}", json_output, source=source)
            raise typer.Exit(code=1)

        for ann in annotations:
            sym = ann.symbol
            if not sym or not ann.size:
                results.append(
                    {
                        "va": f"0x{ann.va:08x}",
                        "symbol": sym or "",
                        "status": "SKIPPED",
                        "previous_status": ann.status,
                        "action": "none",
                        "reason": "missing SYMBOL or SIZE",
                    }
                )
                continue

            target_bytes = cfg.extract_dll_bytes(ann.va, ann.size)
            if not target_bytes:
                results.append(
                    {
                        "va": f"0x{ann.va:08x}",
                        "symbol": sym,
                        "status": "ERROR",
                        "previous_status": ann.status,
                        "action": "none",
                        "reason": f"Failed to extract target bytes at VA 0x{ann.va:08x}",
                    }
                )
                continue
            obj_bytes, coff_relocs = parse_coff_symbol_bytes(obj_path, sym)

            if obj_bytes is None:
                results.append(
                    {
                        "va": f"0x{ann.va:08x}",
                        "symbol": sym,
                        "status": "ERROR",
                        "previous_status": ann.status,
                        "action": "none",
                        "reason": f"Symbol '{sym}' not found in .obj",
                    }
                )
                continue

            if len(obj_bytes) > len(target_bytes):
                obj_bytes = obj_bytes[: len(target_bytes)]

            matched, match_count, total, relocs = smart_reloc_compare(
                obj_bytes, target_bytes, coff_relocs
            )

            if matched:
                new_status = "RELOC" if relocs else "EXACT"
            else:
                comparable = min(len(obj_bytes), len(target_bytes))
                new_status = (
                    "MATCHING"
                    if (comparable > 0 and match_count > comparable * 0.8)
                    else ann.status
                )

            action = "none"
            if new_status != ann.status:
                if not dry_run:
                    update_source_status(
                        source,
                        new_status,
                        blockers_to_remove=(new_status in ("EXACT", "RELOC")),
                        target_va=ann.va,
                    )
                action = "updated" if not dry_run else "would_update"

            result_dict = _build_result_dict(
                source,
                sym,
                f"0x{ann.va:08x}",
                ann.size,
                matched,
                match_count,
                total,
                relocs,
                obj_bytes,
                target_bytes,
            )
            result_dict["previous_status"] = ann.status
            result_dict["new_status"] = new_status
            result_dict["action"] = action
            results.append(result_dict)

    finally:
        shutil.rmtree(workdir, ignore_errors=True)

    if json_output:
        print(json.dumps({"source": source, "results": results}, indent=2))
    else:
        for r in results:
            sym = r.get("symbol", "?")
            status = r.get("new_status", r.get("status", "?"))
            prev = r.get("previous_status", "?")
            action = r.get("action", "none")
            if action in ("updated", "would_update"):
                verb = "Updated" if action == "updated" else "Would update"
                print(f"{sym}: {prev} -> {status} ({verb})", file=sys.stderr)
            elif r.get("status") == "SKIPPED":
                print(f"{sym}: SKIPPED ({r.get('reason', '')})", file=sys.stderr)
            elif r.get("status") == "ERROR":
                print(f"{sym}: ERROR ({r.get('reason', '')})", file=sys.stderr)
            else:
                print(f"{sym}: {status} (no change)", file=sys.stderr)

    # Exit 1 if any function has structural mismatches
    has_mismatches = any(
        r.get("status") == "MISMATCH" or r.get("new_status") not in ("EXACT", "RELOC")
        for r in results
        if r.get("status") != "SKIPPED" and r.get("status") != "ERROR"
    )
    if has_mismatches:
        raise typer.Exit(code=1)


def _error(msg: str, json_output: bool, source: str = "") -> None:
    """Print error in appropriate format."""
    if json_output:
        print(json.dumps({"source": source, "error": msg}, indent=2))
    else:
        print(f"ERROR: {msg}", file=sys.stderr)


def main_entry() -> None:
    app()


if __name__ == "__main__":
    main_entry()
