"""Atomic promote: test a function and update its STATUS annotation.

Runs rebrew test internally, then updates the STATUS and BLOCKER annotations
based on the result. Outputs structured JSON for agent consumption.

Usage:
    rebrew promote src/server.dll/my_func.c
    rebrew promote src/server.dll/my_func.c --json
"""

import tempfile
from pathlib import Path
from typing import Any

import typer
from rich.console import Console
from rich.progress import BarColumn, MofNCompleteColumn, Progress, TextColumn

from rebrew.annotation import parse_c_file_multi
from rebrew.cli import TargetOption, error_exit, get_config, iter_sources, json_print
from rebrew.config import ProjectConfig
from rebrew.matcher.parsers import parse_obj_symbol_bytes
from rebrew.test import (
    build_result_dict,
    compile_obj,
    smart_reloc_compare,
    update_source_status,
)

_EPILOG = """\
[bold]Examples:[/bold]

rebrew promote src/game_dll/my_func.c             Test + update STATUS

rebrew promote src/game_dll/my_func.c --json       JSON output for agents

rebrew promote src/game_dll/my_func.c --dry-run    Show what would change

rebrew promote --all                          Batch promote all promotable functions

rebrew promote --all --origin GAME            Only promote GAME functions

rebrew promote --all --dir src/server.dll     Restrict to subdirectory

rebrew promote --all --dry-run --json         Preview batch promotion as JSON

[bold]How it works:[/bold]

1. Compiles the source file

2. Compares compiled bytes against the target binary

3. Updates STATUS to EXACT/RELOC/MATCHING based on result

4. Removes BLOCKER annotation if the function matches (EXACT/RELOC)

5. Reports the result as structured JSON

[dim]This is the atomic version of 'rebrew test + manual STATUS edit'.
Safe for agent use — idempotent, validates before writing.[/dim]"""

app = typer.Typer(
    help="Test a function and atomically update its STATUS annotation.",
    rich_markup_mode="rich",
    epilog=_EPILOG,
)

console = Console(stderr=True)

_STATUS_RANK: dict[str, int] = {
    "EXACT": 0,
    "RELOC": 1,
    "MATCHING": 2,
    "STUB": 3,
    "": 4,
}


def _promote_file(
    source_path: Path,
    cfg: ProjectConfig,
    dry_run: bool,
    origin_filter: str | None = None,
) -> list[dict[str, Any]]:
    source = str(source_path)
    annotations = parse_c_file_multi(source_path, target_name=cfg.marker if cfg else None)
    if not annotations:
        return [
            {
                "source": source,
                "symbol": "",
                "status": "ERROR",
                "action": "none",
                "reason": "No annotations found in source file",
            }
        ]

    results: list[dict[str, Any]] = []
    selected_annotations = annotations
    if origin_filter:
        selected_annotations = [
            ann for ann in annotations if (ann.origin or "").upper() == origin_filter.upper()
        ]
        skipped_annotations = [
            ann for ann in annotations if (ann.origin or "").upper() != origin_filter.upper()
        ]
        for ann in skipped_annotations:
            results.append(
                {
                    "source": source,
                    "va": f"0x{ann.va:08x}",
                    "symbol": ann.symbol or "",
                    "status": "SKIPPED",
                    "previous_status": ann.status,
                    "action": "none",
                    "reason": f"origin '{ann.origin}' does not match filter '{origin_filter}'",
                }
            )

    if not selected_annotations:
        return results

    cflags_str = selected_annotations[0].cflags or "/O2 /Gd"
    cflags_parts = cflags_str.split()
    origin = selected_annotations[0].origin if selected_annotations else ""
    compile_cfg = cfg.for_origin(origin)

    with tempfile.TemporaryDirectory(prefix="promote_") as workdir:
        obj_path, err = compile_obj(compile_cfg, source, cflags_parts, workdir)
        if obj_path is None:
            return [
                *results,
                {
                    "source": source,
                    "symbol": "",
                    "status": "ERROR",
                    "action": "none",
                    "reason": f"Compile error: {err}",
                },
            ]

        for ann in selected_annotations:
            sym = ann.symbol
            if not sym or not ann.size:
                results.append(
                    {
                        "source": source,
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
                        "source": source,
                        "va": f"0x{ann.va:08x}",
                        "symbol": sym,
                        "status": "ERROR",
                        "previous_status": ann.status,
                        "action": "none",
                        "reason": f"Failed to extract target bytes at VA 0x{ann.va:08x}",
                    }
                )
                continue

            obj_bytes, coff_relocs = parse_obj_symbol_bytes(obj_path, sym)
            if obj_bytes is None:
                results.append(
                    {
                        "source": source,
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

            matched, match_count, total, relocs, _ = smart_reloc_compare(
                obj_bytes, target_bytes, coff_relocs
            )

            if matched:
                candidate_status = "RELOC" if relocs else "EXACT"
            else:
                comparable = min(len(obj_bytes), len(target_bytes))
                candidate_status = (
                    "MATCHING"
                    if (comparable > 0 and match_count > comparable * 0.8)
                    else ann.status
                )

            new_status = ann.status
            should_update = False
            if candidate_status in ("EXACT", "RELOC"):
                should_update = candidate_status != ann.status
                if should_update:
                    new_status = candidate_status
            elif _STATUS_RANK.get(candidate_status, 99) < _STATUS_RANK.get(ann.status, 99):
                should_update = True
                new_status = candidate_status

            action = "none"
            if should_update:
                if not dry_run:
                    update_source_status(
                        source_path,
                        new_status,
                        blockers_to_remove=(new_status in ("EXACT", "RELOC")),
                        target_va=ann.va,
                    )
                action = "updated" if not dry_run else "would_update"

            result_dict = build_result_dict(
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

    return results


@app.callback(invoke_without_command=True)
def main(
    source: str | None = typer.Argument(None, help="C source file (required in single-file mode)"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
    dry_run: bool = typer.Option(False, "--dry-run", help="Show what would change without writing"),
    batch_all: bool = typer.Option(False, "--all", help="Batch promote all promotable functions"),
    dir_filter: str | None = typer.Option(
        None, "--dir", help="Restrict batch to this subdirectory"
    ),
    origin_filter: str | None = typer.Option(
        None,
        "--origin",
        help="Filter by origin (GAME, MSVCRT, ZLIB)",
    ),
    target: str | None = TargetOption,
) -> None:
    """Test a function and atomically update its STATUS annotation."""
    cfg = get_config(target=target)
    if batch_all:
        scan_dir = Path(dir_filter) if dir_filter else cfg.reversed_dir
        if not scan_dir.exists() or not scan_dir.is_dir():
            error_exit(f"Scan directory not found: {scan_dir}", json_mode=json_output)

        source_files = iter_sources(scan_dir, cfg)
        results: list[dict[str, Any]] = []

        with Progress(
            TextColumn("[bold blue]Promoting"),
            BarColumn(),
            MofNCompleteColumn(),
            TextColumn("[dim]{task.description}"),
            console=console,
            disable=json_output,
        ) as progress:
            task = progress.add_task("files", total=len(source_files))
            for source_path in source_files:
                progress.update(task, description=source_path.name)
                try:
                    file_results = _promote_file(source_path, cfg, dry_run, origin_filter)
                except Exception as exc:
                    file_results = [
                        {
                            "source": str(source_path),
                            "symbol": "",
                            "status": "ERROR",
                            "action": "none",
                            "reason": f"INTERNAL_ERROR: {exc}",
                        }
                    ]
                results.extend(file_results)
                progress.update(task, advance=1)

        summary = {
            "promoted": sum(1 for r in results if r.get("action") in ("updated", "would_update")),
            "unchanged": sum(
                1
                for r in results
                if r.get("action") == "none" and r.get("status") not in ("SKIPPED", "ERROR")
            ),
            "errors": sum(1 for r in results if r.get("status") == "ERROR"),
            "skipped": sum(1 for r in results if r.get("status") == "SKIPPED"),
        }

        if json_output:
            json_print(
                {
                    "batch": True,
                    "directory": str(scan_dir),
                    "origin": origin_filter,
                    "summary": summary,
                    "results": results,
                }
            )
        else:
            console.print(
                "Promotion complete: "
                f"{summary['promoted']} promoted, "
                f"{summary['unchanged']} unchanged, "
                f"{summary['errors']} errors, "
                f"{summary['skipped']} skipped"
            )

        if summary["errors"] > 0:
            raise typer.Exit(code=1)
        return

    if source is None:
        error_exit("source argument required (or use --all for batch mode)", json_mode=json_output)

    source_path = Path(source)
    results = _promote_file(source_path, cfg, dry_run, origin_filter)

    if json_output:
        json_print({"source": source, "results": results})
    else:
        for r in results:
            sym = r.get("symbol", "?")
            status = r.get("new_status", r.get("status", "?"))
            prev = r.get("previous_status", "?")
            action = r.get("action", "none")
            if action in ("updated", "would_update"):
                verb = "Updated" if action == "updated" else "Would update"
                typer.echo(f"{sym}: {prev} -> {status} ({verb})", err=True)
            elif r.get("status") == "SKIPPED":
                typer.echo(f"{sym}: SKIPPED ({r.get('reason', '')})", err=True)
            elif r.get("status") == "ERROR":
                typer.echo(f"{sym}: ERROR ({r.get('reason', '')})", err=True)
            else:
                typer.echo(f"{sym}: {status} (no change)", err=True)

    has_errors = any(r.get("status") == "ERROR" for r in results)
    has_mismatches = any(
        r.get("status") == "MISMATCH" or r.get("new_status") not in ("EXACT", "RELOC")
        for r in results
        if r.get("status") != "SKIPPED" and r.get("status") != "ERROR"
    )
    if has_errors or has_mismatches:
        raise typer.Exit(code=1)


def main_entry() -> None:
    """Run the promote CLI app."""
    app()


if __name__ == "__main__":
    main_entry()
