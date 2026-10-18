"""catalog/cli.py - CLI entry point for the catalog command.

Orchestrates annotation scanning, registry building, and output generation
(Ghidra label export, size fixing).

``run_catalog()`` holds the orchestration so it is callable in-process; the
Typer callback is a thin wrapper that resolves config, validates CLI-only
option combinations, and prints the result.  Scan/registry/grid data comes
from :func:`rebrew.catalog.pipeline.build_catalog_data`.

The catalog writes no coverage document itself: ``rebrew coverage export --output snapshots/`` calls
:func:`rebrew.catalog.pipeline.build_catalog_data` and renders
``snapshots/coverage-<target>.toml`` from the returned dict.
``--json`` emits a machine-readable summary to stdout, like all other tools.
"""

import json
import logging
from pathlib import Path
from typing import Any

import typer

from rebrew.catalog.grid import covered_bytes
from rebrew.catalog.pipeline import build_catalog_data
from rebrew.cli import (
    RootOption,
    TargetOption,
    confirm_abort,
    console,
    error_exit,
    json_print,
    require_config,
    run_standalone,
)
from rebrew.config import ProjectConfig
from rebrew.metadata.bindings import SourceBinding, read_source_bindings
from rebrew.utils import floor_pct, untrusted_ident

log = logging.getLogger(__name__)

app = typer.Typer(
    help="Validate source bindings and summarize function catalog and coverage data.",
    rich_markup_mode="rich",
    epilog=(
        "[bold]Examples:[/bold]\n\n"
        "  rebrew coverage catalog\n\n"
        "  rebrew coverage catalog --json\n\n"
        "  rebrew coverage catalog --target mygame\n\n"
        "[dim]Combines source bindings and dedicated function metadata with discovery inventory and binary evidence. Builds the function registry and .text coverage grid, then prints a summary. It does not write coverage documents; use rebrew coverage export --output snapshots/ for snapshots/coverage-<target>.toml. Explicit export/fix options write their requested artifacts.[/dim]\n\n"
    ),
)


def run_catalog(
    cfg: ProjectConfig,
    *,
    summary: bool = False,
    export_ghidra_labels: bool = False,
    fix_sizes: bool = False,
    json_output: bool = False,
) -> dict[str, Any]:
    """Parse annotations, build the catalog and coverage data, and write the artifacts.

    The same pipeline the ``rebrew coverage catalog`` callback runs: scan
    ``reversed_dir``, build the function registry, print the human summary,
    and write the requested artifacts (``ghidra_data_labels.json``,
    ``--fix-sizes`` metadata updates).  With every flag left false the
    default action set applies (summary), matching a bare
    ``rebrew coverage catalog`` invocation.

    Returns the object the CLI prints under ``--json``.

    Raises:
        ValueError: ``function_structure.json`` is corrupt.  The CLI turns
            this into ``error_exit``; an in-process caller gets the exception.
    """
    bin_path = cfg.target_binary
    reversed_dir = cfg.reversed_dir
    target = cfg.target_name

    if not any(
        [
            summary,
            export_ghidra_labels,
            fix_sizes,
            json_output,
        ]
    ):
        summary = True

    bundle = build_catalog_data(cfg, with_data=bool(export_ghidra_labels))
    entries = bundle["entries"]
    registry = bundle["registry"]
    text_size = bundle["text_size"]
    binary_missing = bundle["binary_missing"]
    both_count = bundle["counts"]["both"]
    thunk_count = bundle["counts"]["thunks"]

    by_va: dict[int, list[SourceBinding]] = {}
    if summary or json_output:
        for e in entries:
            by_va.setdefault(e["va"], []).append(e)

    covered = covered_bytes(
        by_va,
        {va: reg["canonical_size"] for va, reg in registry.items()},
        section=(getattr(cfg, "text_va", 0), text_size),
    )
    identified_pct = floor_pct(covered, text_size)

    if summary:
        from rebrew.status import collect_status

        # Progress is `rebrew status`'s: one computation, library code excluded.
        progress = collect_status(cfg)
        console.print()
        console.print("\n=== Progress (rebrew status) ===")
        console.print(
            f"Byte-matched: {progress.matched_functions}/{progress.total_functions} functions"
        )
        for st in sorted(progress.status_counts):
            console.print(f"  {untrusted_ident(st)}: {progress.status_counts[st]}")
        console.print(f"Library identified: {progress.library_identified}")
        from rebrew.present import ratio_bar

        if progress.total_text_bytes > 0:
            # Same figure, same words, as `rebrew status`. Identified below
            # counts every annotated function, stubs included. The code account
            # is matched functions, identified libraries, and alignment padding.
            from rebrew.status import CODE_ACCOUNT_CAPTION, code_account_headline

            accounted = progress.accounted_text_bytes
            console.print(
                code_account_headline(
                    progress.byte_coverage_pct, accounted, progress.total_text_bytes
                )
            )
            console.print(CODE_ACCOUNT_CAPTION)
            console.print(ratio_bar(accounted, progress.total_text_bytes))
        console.print(
            f"Identified spans: {identified_pct:.1f}% of .text ({covered}/{text_size} bytes) "
            "claimed by an annotated function, stubs and library code included"
        )
        if text_size:
            console.print(ratio_bar(covered, text_size))

        console.print()
        console.print("=== Tool Detection ===")
        console.print(
            f"  func list only: {sum(1 for r in registry.values() if r['detected_by'] == ['list'])}"
        )
        console.print(
            f"  Ghidra only:  {sum(1 for r in registry.values() if r['detected_by'] == ['ghidra'])}"
        )
        console.print(f"  Both tools:   {both_count}")
        console.print(f"  IAT thunks:   {thunk_count}")
        size_mismatches = sum(
            1
            for r in registry.values()
            if "ghidra" in r["size_by_tool"]
            and "list" in r["size_by_tool"]
            and r["size_by_tool"]["ghidra"] != r["size_by_tool"]["list"]
        )
        console.print(f"  Size disagree: {size_mismatches}")

    from rebrew.utils import atomic_write_text

    if export_ghidra_labels:
        data = bundle["data"]
        labels_path = reversed_dir / "ghidra_data_labels.json"
        text_sec = data.get("sections", {}).get(".text")
        if not text_sec or not text_sec.get("va"):
            # Sections are empty when the binary is missing or failed to load
            # (grid.py logs that).  Overwriting here would replace every
            # existing label with [], so an existing file is left alone.
            if labels_path.exists():
                log.warning(
                    "no .text section data for %s; keeping the existing %s",
                    bin_path,
                    labels_path,
                )
                text_sec = None
            else:
                text_sec = {"va": 0, "cells": []}
        if text_sec is not None:
            sec_va = text_sec.get("va", 0)
            labels = []
            for cell in text_sec.get("cells", []):
                if cell["state"] in ("data", "thunk"):
                    cell_va = sec_va + cell["start"]
                    labels.append(
                        {
                            "va": cell_va,
                            "size": cell["end"] - cell["start"],
                            "label": cell.get("label", f"switchdata_{cell_va:08x}"),
                        }
                    )
            atomic_write_text(labels_path, json.dumps(labels, indent=2) + "\n", encoding="utf-8")
            console.print(
                f"Wrote {untrusted_ident(labels_path)} ({len(labels)} labels)", style="dim"
            )

    if fix_sizes:
        from rebrew.config import target_module
        from rebrew.metadata.bindings import grow_function_extent
        from rebrew.sources import iter_sources
        from rebrew.utils import rel_display_path

        # The scan above already parsed every source file; keep only the
        # (file, VA) pairs that can actually change, so a file with nothing
        # stale is skipped instead of being parsed a second time.
        stale: set[str] = set()
        for e in entries:
            reg = registry.get(e["va"])
            if reg is None:
                continue
            if reg["canonical_size"] > 0 and reg["canonical_size"] > e["size"]:
                stale.add(e["filepath"])

        updated = 0
        skipped = 0
        for cfile in iter_sources(reversed_dir, cfg):
            if rel_display_path(cfile, reversed_dir) not in stale:
                continue
            parsed = read_source_bindings(
                cfile,
                target_name=target_module(cfg),
                metadata_dir=cfg.metadata_dir,
                project_root=getattr(cfg, "root", None),
            )
            for ann in parsed:
                va = ann.va
                if va not in registry:
                    continue
                canonical = registry[va]["canonical_size"]
                if canonical <= 0 or canonical <= ann.size:
                    continue
                reason = registry[va].get("size_reason", "")
                if grow_function_extent(
                    cfile,
                    canonical,
                    target_va=va,
                    metadata_dir=cfg.metadata_dir,
                    # A migrated .c has no marker line to resolve the module
                    # from, and the write target is the TOML either way.
                    module=ann.module,
                ):
                    diff = canonical - ann.size
                    display = rel_display_path(cfile, reversed_dir)
                    console.print(
                        f"  {untrusted_ident(display)}: SIZE {ann.size} → {canonical} "
                        f"(+{diff}B, {untrusted_ident(reason)})"
                    )
                    updated += 1
                else:
                    # Say which file: a bare "N skipped" reads as "nothing to
                    # do" when a run actually left a stale SIZE behind.
                    console.print(
                        f"  {untrusted_ident(rel_display_path(cfile, reversed_dir))}: "
                        f"SIZE not written (no module key, or metadata already at {canonical})"
                    )
                    skipped += 1
        console.print(f"[green]Updated {updated} SIZE annotations[/] ({skipped} skipped)")

    payload: dict[str, Any] = {
        "target": target,
        "annotations": len(entries),
        "unique_vas": len({e["va"] for e in entries}),
        "registry": len(registry),
        "identified_bytes": covered,
        "text_size": text_size,
        "identified_pct": identified_pct,
    }
    if binary_missing:
        payload["warning"] = f"target binary missing ({bin_path}) — text_size=0, identified is 0%"
    return payload


@app.callback(invoke_without_command=True)
def main(
    summary: bool = typer.Option(False, "--summary", help="Print summary table (stderr)"),
    export_ghidra: bool = typer.Option(
        False,
        "--export-ghidra",
        help="Print Ghidra function-list export instructions (mutually exclusive with --json)",
    ),
    export_ghidra_labels: bool = typer.Option(
        False,
        "--export-ghidra-labels",
        help="Generate ghidra_data_labels.json from detected tables",
    ),
    fix_sizes: bool = typer.Option(
        False,
        "--fix-sizes",
        help="Update stored SIZE to canonical sizes (requires --force with --json)",
    ),
    force: bool = typer.Option(False, "--force", help="Skip the --fix-sizes confirmation prompt"),
    root: Path | None = RootOption,
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
    target: str | None = TargetOption,
) -> None:
    """Validate source bindings and summarize function catalog and coverage data."""
    cfg = require_config(target=target, json_mode=json_output, root=root)

    if fix_sizes:
        if json_output and not force:
            error_exit(
                "--fix-sizes modifies metadata; pass --force to use it in --json mode",
                json_mode=True,
                kind="confirmation_required",
                hint="Pass --force to skip the prompt.",
            )
        if not force:
            # Prompt on stderr so a redirected stdout still shows the question.
            confirm_abort(
                "--fix-sizes will modify rebrew-functions.toml metadata files in-place. Continue?"
            )

    if export_ghidra:
        # --export-ghidra prints interactive instructions and emits NO JSON
        # document — combining it with --json would produce zero stdout,
        # breaking the JSON contract.  Refuse up front like
        # the --fix-sizes --json guard above.
        if json_output:
            error_exit(
                "--export-ghidra prints instructions and produces no data — "
                "it cannot be combined with --json",
                json_mode=True,
            )
        console.print(
            "To export Ghidra functions, run this in the MCP console:\n"
            f"  get-functions programPath=/{untrusted_ident(cfg.target_binary.name)} "
            "filterDefaultNames=false\n"
            f"Then save the output as {untrusted_ident(cfg.reversed_dir.name)}"
            "/function_structure.json with format:\n"
            '  [{"va": 0x10001000, "size": 302, "tool_name": "FUN_10001000"}, ...]\n'
            "\n"
            "To also export data labels (switch tables, etc.), search for non-function\n"
            f"labels in Ghidra and save as {untrusted_ident(cfg.reversed_dir.name)}"
            "/ghidra_data_labels.json:\n"
            '  [{"va": 0x10002E9C, "size": 20, "label": "switchdataD_10002e9c"}, ...]',
        )
        return

    try:
        payload = run_catalog(
            cfg,
            summary=summary,
            export_ghidra_labels=export_ghidra_labels,
            fix_sizes=fix_sizes,
            json_output=json_output,
        )
    except ValueError as exc:
        error_exit(str(exc), json_mode=json_output)

    if json_output:
        json_print(payload)


def main_entry() -> None:
    """Run the Typer CLI application."""
    run_standalone(main)


if __name__ == "__main__":
    main_entry()
