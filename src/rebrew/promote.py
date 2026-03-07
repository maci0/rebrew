"""Atomic promote: test a function and update its STATUS annotation.

Runs rebrew test internally, then updates the STATUS and BLOCKER annotations
based on the result. Outputs structured JSON for agent consumption.

When a function body contains inline assembly (``__asm`` / ``__asm__`` blocks),
promote immediately sets STATUS back to STUB and writes a BLOCKER comment
explaining the reason, without attempting to compile-compare.

Usage:
    rebrew promote src/mygame/my_func.c
    rebrew promote src/mygame/my_func.c --json
"""

import re
import tempfile
from pathlib import Path
from typing import Any

import typer
from rich.console import Console
from rich.progress import BarColumn, MofNCompleteColumn, Progress, TextColumn

from rebrew.annotation import parse_c_file_multi, update_annotation_key
from rebrew.binary_loader import extract_raw_bytes
from rebrew.cli import (
    TargetOption,
    error_exit,
    iter_sources,
    json_print,
    require_config,
    target_marker,
)
from rebrew.config import ProjectConfig
from rebrew.core.matching import smart_reloc_compare
from rebrew.matcher.parsers import parse_obj_symbol_bytes
from rebrew.test import (
    _MARKER_RE,
    build_result_dict,
    compile_obj,
    update_source_status,
)

_EPILOG = """\
[bold]Examples:[/bold]

rebrew promote src/game_dll/my_func.c             Test + update STATUS

rebrew promote src/game_dll/my_func.c --json       JSON output for agents

rebrew promote src/game_dll/my_func.c --dry-run    Show what would change

rebrew promote --all                          Batch promote all promotable functions

rebrew promote --all --origin GAME            Only promote GAME functions

rebrew promote --all --dir src/mygame     Restrict to subdirectory

rebrew promote --all --dry-run --json         Preview batch promotion as JSON

[bold]How it works:[/bold]

1. Compiles the source file

2. Compares compiled bytes against the target binary

3. Updates STATUS to EXACT/RELOC/MATCHING based on result

4. Demotes to STUB if byte match falls below 75% threshold

5. On demotion, adds BLOCKER annotation with match ratio

6. Removes BLOCKER annotation if the function matches (EXACT/RELOC)

7. Reports the result as structured JSON

[dim]This is the atomic version of 'rebrew test + manual STATUS edit'.
Safe for agent use — idempotent, validates before writing.[/dim]"""

app = typer.Typer(
    help="Test a function and atomically update its STATUS annotation.",
    rich_markup_mode="rich",
    epilog=_EPILOG,
)

console = Console(stderr=True)

# Status rank: lower number = better match quality.
# Used for both promotion (STUB → EXACT) and demotion (EXACT → MATCHING)
# when a recompilation result differs from the annotated status.
_STATUS_RANK: dict[str, int] = {
    "EXACT": 0,
    "RELOC": 1,
    "MATCHING": 2,
    "STUB": 3,
    "": 4,
}

# Minimum byte-match ratio to classify a non-exact comparison as MATCHING.
#
# Size-aware: a single mismatching byte in a 4-byte stub would fail a flat 75%
# threshold — not a meaningful signal.  We clamp the threshold between a hard
# floor (50%) and the normal ceiling (75%), using an absolute slack budget so
# that tiny functions get more leniency while large ones converge to 75%.
_MATCHING_FLOOR = 0.75  # threshold ceiling / large-function target
_MATCHING_HARD_FLOOR = 0.50  # absolute minimum — even tiny stubs need ≥50%
_MATCHING_SLACK_BYTES = 4  # absolute byte tolerance granted to small functions

# Inline ASM detection: matches MSVC ``__asm {``, ``__asm keyword``,
# and GCC ``__asm__(``.  The pattern is intentionally broad — any use of
# inline assembly in the function body disqualifies byte-compare promotion.
_INLINE_ASM_RE = re.compile(r"\b(?:__asm__|__asm)\b")


def _function_body_has_inline_asm(
    source_text: str, ann_index: int, all_va_lines: list[int]
) -> bool:
    """Return True if the function at *ann_index* contains inline ASM.

    Extracts the per-function text slice from *source_text* by finding the
    line range between the marker for this annotation and the next one (or
    end of file).  Scans that slice for ``__asm`` / ``__asm__`` tokens.

    Args:
        source_text: Full source file text.
        all_va_lines: List of 0-based line indices where each annotation
            marker starts (one entry per annotation, same order as selected).
        ann_index: Index of the annotation to check within *all_va_lines*.

    """
    lines = source_text.splitlines(keepends=True)
    start = all_va_lines[ann_index]
    end = all_va_lines[ann_index + 1] if ann_index + 1 < len(all_va_lines) else len(lines)
    body = "".join(lines[start:end])
    return bool(_INLINE_ASM_RE.search(body))


def _matching_threshold(comparable: int) -> float:
    """Return the minimum match ratio required for MATCHING classification.

    Uses ``clamp(1 - SLACK/n, HARD_FLOOR, FLOOR)`` so the threshold is lenient
    for small functions and converges to the normal 75% for large ones.

    With FLOOR=0.75, HARD_FLOOR=0.50, SLACK=4:

    ======  ===========  =========
    Size    1 - 4/n      threshold
    ======  ===========  =========
     4 B    0.00          0.50  (hard floor)
     6 B    0.33          0.50  (hard floor)
     8 B    0.50          0.50
    12 B    0.67          0.67
    16 B    0.75          0.75  (converged)
    32 B+   >0.75 → cap  0.75
    ======  ===========  =========
    """
    if comparable <= 0:
        return _MATCHING_FLOOR
    raw = 1.0 - _MATCHING_SLACK_BYTES / comparable
    return max(_MATCHING_HARD_FLOOR, min(_MATCHING_FLOOR, raw))


def _promote_file(
    source_path: Path,
    cfg: ProjectConfig,
    dry_run: bool,
) -> list[dict[str, Any]]:
    source = str(source_path)
    annotations = parse_c_file_multi(source_path, target_name=target_marker(cfg))
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

    if not selected_annotations:
        return results

    cflags_str = selected_annotations[0].cflags or "/O2 /Gd"
    cflags_parts = cflags_str.split()

    # Build a list of marker-line indices (0-based) for the selected annotations
    # so we can slice per-function source bodies for inline ASM detection.
    source_text = source_path.read_text(encoding="utf-8", errors="replace")
    source_lines = source_text.splitlines(keepends=True)

    marker_line_map: dict[int, int] = {}  # va -> 0-based line index
    for li, line in enumerate(source_lines):
        m = _MARKER_RE.match(line)
        if m:
            try:
                va_found = int(m.group(2), 16)
                marker_line_map[va_found] = li
            except (IndexError, ValueError):
                pass

    # Ordered list of marker start lines for all selected annotations
    selected_marker_lines = [marker_line_map.get(ann.va, 0) for ann in selected_annotations]

    with tempfile.TemporaryDirectory(prefix="promote_") as workdir:
        obj_path, err = compile_obj(cfg, source, cflags_parts, workdir)
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

        for ann_idx, ann in enumerate(selected_annotations):
            sym = ann.symbol

            # --- Inline ASM check --------------------------------------------------
            # If the function body contains __asm / __asm__ we can't byte-compare it;
            # demote to STUB immediately and record a BLOCKER.
            if _function_body_has_inline_asm(source_text, ann_idx, selected_marker_lines):
                candidate_status = "STUB"
                is_asm_demotion = ann.status != "STUB"
                if not dry_run:
                    if is_asm_demotion:
                        update_source_status(
                            source_path,
                            "STUB",
                            blockers_to_remove=False,
                            target_va=ann.va,
                        )
                    update_annotation_key(
                        source_path,
                        ann.va,
                        "BLOCKER",
                        "contains inline assembly (__asm block) — cannot byte-compare",
                    )
                action = (
                    "demoted"
                    if is_asm_demotion and not dry_run
                    else ("would_demote" if is_asm_demotion and dry_run else "none")
                )
                results.append(
                    {
                        "source": source,
                        "va": f"0x{ann.va:08x}",
                        "symbol": sym or "",
                        "previous_status": ann.status,
                        "new_status": "STUB",
                        "action": action,
                        "reason": "inline assembly detected",
                    }
                )
                continue
            # -----------------------------------------------------------------------

            if not sym or not ann.size:
                results.append(
                    {
                        "source": source,
                        "va": f"0x{ann.va:08x}",
                        "symbol": sym or "",
                        "status": "SKIPPED",
                        "previous_status": ann.status,
                        "action": "none",
                        "reason": "missing symbol (no C function definition) or SIZE",
                    }
                )
                continue

            target_bytes = extract_raw_bytes(cfg.target_binary, ann.va, ann.size)
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
                if comparable > 0 and match_count > comparable * _matching_threshold(comparable):
                    candidate_status = "MATCHING"
                else:
                    # Below match threshold — demote to STUB.
                    # A function can't be MATCHING/EXACT/RELOC if the diff is too big.
                    candidate_status = "STUB"

            # Update whenever the measured status differs from the annotation.
            # This handles both promotion (STUB → EXACT) and demotion
            # (EXACT → STUB when code changes break a previously-matching function).
            new_status = ann.status
            should_update = candidate_status != ann.status
            if should_update:
                new_status = candidate_status

            is_demotion = should_update and _STATUS_RANK.get(new_status, 99) > _STATUS_RANK.get(
                ann.status, 99
            )

            action = "none"
            if should_update:
                if not dry_run:
                    update_source_status(
                        source_path,
                        new_status,
                        blockers_to_remove=(new_status in ("EXACT", "RELOC")),
                        target_va=ann.va,
                    )
                    # On demotion to STUB, add a BLOCKER explaining why
                    if is_demotion and new_status == "STUB":
                        ratio = f"{match_count}/{total}" if total > 0 else "unknown"
                        update_annotation_key(
                            source_path,
                            ann.va,
                            "BLOCKER",
                            f"auto-demoted: byte match {ratio} below threshold",
                        )
                    # Verify the status was actually written.
                    # Default to "updated"/"demoted" — only downgrade if re-parse
                    # explicitly shows the old status persists.
                    action = "demoted" if is_demotion else "updated"
                    verify_annos = parse_c_file_multi(
                        source_path,
                        target_name=target_marker(cfg),
                        sidecar_dir=source_path.parent,
                    )
                    for va_ann in verify_annos:
                        if va_ann.va == ann.va:
                            if va_ann.status != new_status:
                                action = "write_failed"
                            break
                else:
                    action = "would_demote" if is_demotion else "would_update"

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
    dry_run: bool = typer.Option(False, "--dry-run", "-n", help="Preview changes without writing"),
    batch_all: bool = typer.Option(False, "--all", help="Batch promote all promotable functions"),
    dir_filter: str | None = typer.Option(
        None, "--dir", help="Restrict batch to this subdirectory"
    ),
    target: str | None = TargetOption,
) -> None:
    """Test a function and atomically update its STATUS annotation."""
    cfg = require_config(target=target, json_mode=json_output)
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
                    file_results = _promote_file(source_path, cfg, dry_run)
                except (OSError, ValueError, RuntimeError) as exc:
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
            "demoted": sum(1 for r in results if r.get("action") in ("demoted", "would_demote")),
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
                    "summary": summary,
                    "results": results,
                }
            )
        else:
            console.print(
                "Promotion complete: "
                f"{summary['promoted']} promoted, "
                f"{summary['demoted']} demoted, "
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
    results = _promote_file(source_path, cfg, dry_run)

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
                console.print(f"[magenta]{sym}[/]: {prev} \u2192 [bold green]{status}[/] ({verb})")
            elif action in ("demoted", "would_demote"):
                verb = "Demoted" if action == "demoted" else "Would demote"
                console.print(f"[magenta]{sym}[/]: {prev} \u2192 [bold red]{status}[/] ({verb})")
            elif r.get("status") == "SKIPPED":
                console.print(f"[magenta]{sym}[/]: [yellow]SKIPPED[/] ({r.get('reason', '')})")
            elif r.get("status") == "ERROR":
                console.print(f"[magenta]{sym}[/]: [red]ERROR[/] ({r.get('reason', '')})")
            else:
                console.print(f"[magenta]{sym}[/]: {status} (no change)")

    has_errors = any(r.get("status") == "ERROR" for r in results)
    if has_errors:
        raise typer.Exit(code=1)


def main_entry() -> None:
    """Run the Typer CLI application."""
    app()


if __name__ == "__main__":
    main_entry()
