#!/usr/bin/env python3
"""verify.py - Traceability and verification tool for rebrew.

Analyzes src/*.c files, matches them against the target binary,
and reports status (EXACT, RELOC, MATCHING, etc.).
"""

import concurrent.futures
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import typer
from rich.console import Console
from rich.progress import BarColumn, MofNCompleteColumn, Progress, TextColumn
from rich.text import Text

from rebrew.catalog import (
    build_function_registry,
    parse_r2_functions,
    scan_reversed_dir,
)
from rebrew.cli import TargetOption, get_config

# ---------------------------------------------------------------------------
# Verification (--verify)
# ---------------------------------------------------------------------------


def verify_entry(entry: dict[str, Any], cfg: Any) -> tuple[bool, str]:
    """Compile a .c file and compare output bytes against DLL.

    Delegates to ``compile_and_compare`` for the compile→extract→compare flow.
    """
    from rebrew.compile import compile_and_compare

    cfile = cfg.reversed_dir / entry["filepath"]
    if not cfile.exists():
        return False, f"MISSING_FILE: {cfile}"

    if entry["va"] < 0x1000:
        return False, "INVALID_VA: VA too low"
    if entry["size"] <= 0:
        return False, "MISSING_SIZE: No SIZE annotation"

    cflags_str = entry["cflags"]
    cflags = cflags_str if cflags_str else "/O2"
    symbol = entry["symbol"] if entry["symbol"] else "_" + entry["name"]

    target_bytes = cfg.extract_dll_bytes(entry["va"], entry["size"])
    if not target_bytes:
        return False, "Cannot extract DLL bytes"

    matched, msg, _obj_bytes, _reloc_offsets = compile_and_compare(
        cfg,
        str(cfile),
        symbol,
        target_bytes,
        cflags,
    )
    return matched, msg


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


console = Console(stderr=True)
out_console = Console()

app = typer.Typer(
    help="Rebrew verification pipeline: compile each .c and verify bytes match.",
    rich_markup_mode="rich",
    epilog="""\
[bold]Examples:[/bold]
  rebrew-verify                             Verify all .c files (rich progress bar)
  rebrew-verify --json                      Emit structured JSON report to stdout
  rebrew-verify -o db/verify_results.json   Write JSON report to file
  rebrew-verify -j 8                        Use 8 parallel compile jobs
  rebrew-verify -t server.dll               Verify a specific target

[bold]How it works:[/bold]
  For each .c file in reversed_dir, compiles it, extracts the COFF symbol,
  and compares the output bytes against the original DLL. Reports EXACT,
  RELOC (match after relocation masking), MISMATCH, or COMPILE_ERROR.

[dim]Requires rebrew.toml with valid compiler and target binary paths.
Run 'rebrew-catalog' first to generate coverage data.[/dim]""",
)


@app.callback(invoke_without_command=True)
def main(
    root: Path = typer.Option(
        None,
        "--root",
        help="Project root directory (auto-detected from rebrew.toml if omitted)",
    ),
    target: str | None = TargetOption,
    jobs: int | None = typer.Option(
        None,
        "-j",
        "--jobs",
        help="Number of parallel compile jobs (default: from [project].jobs or 4)",
    ),
    output_json: bool = typer.Option(
        False, "--json", help="Emit structured JSON report instead of rich output"
    ),
    output_path: str | None = typer.Option(
        None, "--output", "-o", help="Write JSON report to file (default: db/verify_results.json)"
    ),
) -> None:
    """Rebrew verification pipeline: compile each .c and verify bytes match."""
    try:
        cfg = get_config(target=target)
    except (FileNotFoundError, KeyError) as exc:
        console.print(f"[red bold]ERROR:[/] {exc}")
        raise typer.Exit(code=1) from None
    bin_path = cfg.target_binary
    reversed_dir = cfg.reversed_dir
    if jobs is None:
        jobs = getattr(cfg, "default_jobs", 4)
    r2_path = reversed_dir / "r2_functions.txt"
    ghidra_json_path = reversed_dir / "ghidra_functions.json"

    console.print(f"Scanning {reversed_dir}...")
    entries = scan_reversed_dir(reversed_dir, cfg=cfg)
    r2_funcs = parse_r2_functions(r2_path)

    registry = build_function_registry(r2_funcs, cfg, ghidra_json_path)

    unique_vas = {e["va"] for e in entries}
    ghidra_count = sum(1 for r in registry.values() if "ghidra" in r["detected_by"])
    r2_count = sum(1 for r in registry.values() if "r2" in r["detected_by"])
    both_count = sum(
        1 for r in registry.values() if "ghidra" in r["detected_by"] and "r2" in r["detected_by"]
    )
    thunk_count = sum(1 for r in registry.values() if r["is_thunk"])
    console.print(
        f"Found {len(entries)} annotations ({len(unique_vas)} unique VAs) "
        f"from {len(registry)} total functions "
        f"(r2: {r2_count}, ghidra: {ghidra_count}, both: {both_count}, "
        f"thunks: {thunk_count})"
    )

    # Verify

    if not bin_path.exists():
        console.print(f"[red bold]ERROR:[/] {bin_path} not found")
        raise typer.Exit(code=1)

    # Deduplicate: only verify once per VA
    seen_vas: set[int] = set()
    unique_entries: list[dict[str, Any]] = []
    for entry in sorted(entries, key=lambda x: x["va"]):
        if entry["va"] not in seen_vas:
            seen_vas.add(entry["va"])
            unique_entries.append(entry)

    passed = 0
    failed = 0
    fail_details: list[tuple[dict[str, Any], str]] = []
    results: list[dict[str, Any]] = []  # per-function structured results
    total = len(unique_entries)
    effective_jobs = min(jobs, total) if total else 1

    def _verify(e: dict[str, Any]) -> tuple[dict[str, Any], bool, str]:
        return (e, *verify_entry(e, cfg))

    with Progress(
        TextColumn("[bold blue]Verifying"),
        BarColumn(),
        MofNCompleteColumn(),
        TextColumn("[dim]{task.description}"),
        console=console,
        disable=output_json,
    ) as progress:
        task = progress.add_task("functions", total=total)
        with concurrent.futures.ThreadPoolExecutor(max_workers=effective_jobs) as pool:
            futures = {pool.submit(_verify, e): e for e in unique_entries}
            for future in concurrent.futures.as_completed(futures):
                try:
                    entry, ok, msg = future.result()
                except Exception as exc:
                    entry = futures[future]
                    ok, msg = False, f"INTERNAL_ERROR: {exc}"
                name = entry["name"]
                progress.update(task, advance=1, description=name)

                # Classify result
                if ok:
                    passed += 1
                    status = "RELOC" if "RELOC" in msg else "EXACT"
                else:
                    failed += 1
                    fail_details.append((entry, msg))
                    if "MISMATCH" in msg:
                        status = "MISMATCH"
                    elif "COMPILE_ERROR" in msg:
                        status = "COMPILE_ERROR"
                    elif "MISSING_FILE" in msg:
                        status = "MISSING_FILE"
                    else:
                        status = "FAIL"

                results.append(
                    {
                        "va": f"0x{entry['va']:08x}",
                        "name": name,
                        "filepath": entry.get("filepath", ""),
                        "size": entry.get("size", 0),
                        "status": status,
                        "message": msg,
                        "passed": ok,
                    }
                )

    # Sort results by VA
    results.sort(key=lambda r: r["va"])

    # Build structured report
    timestamp = datetime.now(UTC).isoformat()
    report = {
        "timestamp": timestamp,
        "target": getattr(cfg, "target_name", ""),
        "binary": str(bin_path),
        "summary": {
            "total": total,
            "passed": passed,
            "failed": failed,
            "exact": sum(1 for r in results if r["status"] == "EXACT"),
            "reloc": sum(1 for r in results if r["status"] == "RELOC"),
            "mismatch": sum(1 for r in results if r["status"] == "MISMATCH"),
            "compile_error": sum(1 for r in results if r["status"] == "COMPILE_ERROR"),
            "missing_file": sum(1 for r in results if r["status"] == "MISSING_FILE"),
        },
        "results": results,
    }

    # JSON output mode
    if output_json or output_path:
        report_json = json.dumps(report, indent=2)

        if output_path:
            out_file = Path(output_path)
        else:
            out_file = cfg.root / "db" / "verify_results.json" if hasattr(cfg, "root") else None

        if out_file:
            out_file.parent.mkdir(parents=True, exist_ok=True)
            out_file.write_text(report_json, encoding="utf-8")
            if not output_json:
                console.print(f"Report written to {out_file}")

        if output_json:
            print(report_json)
            if failed > 0:
                raise typer.Exit(code=1)
            return

    # Print failures
    if fail_details:
        out_console.print()
        for entry, msg in sorted(fail_details, key=lambda x: x[0]["va"]):
            out_console.print(rf"  [red bold]\[FAIL][/] 0x{entry['va']:08X} {entry['name']}: {msg}")

    # Summary
    style = "green" if failed == 0 else "red"
    result_text = Text()
    result_text.append("\nVerification: ")
    result_text.append(f"{passed}/{total} passed", style=style)
    if failed:
        result_text.append(", ")
        result_text.append(f"{failed} failed", style="red")
    out_console.print(result_text)

    if failed > 0:
        raise typer.Exit(code=1)


def main_entry() -> None:
    app()


if __name__ == "__main__":
    main_entry()
