"""catalog/cli.py - CLI entry point for the catalog command.

Orchestrates annotation scanning, registry building, and output generation
(data.json, reccmp CSV, Ghidra label export, size fixing).

``run_catalog()`` holds the orchestration so it is callable in-process; the
Typer callback is a thin wrapper that resolves config, validates CLI-only
option combinations, and prints the result.  Scan/registry/grid data comes
from :func:`rebrew.catalog.pipeline.build_catalog_data`.

``--data-json`` writes ``db/data_<target>.json`` (feeds into ``rebrew build-db``).
``--json`` emits a machine-readable summary to stdout, like all other tools.
"""

import json
from pathlib import Path
from typing import Any

import typer

from rebrew.annotation import Annotation, parse_c_file_multi
from rebrew.catalog.export import generate_reccmp_csv
from rebrew.catalog.grid import covered_bytes
from rebrew.catalog.pipeline import build_catalog_data
from rebrew.cli import (
    TargetOption,
    console,
    error_exit,
    json_print,
    require_config,
    run_standalone,
)
from rebrew.config import ProjectConfig
from rebrew.utils import floor_pct

app = typer.Typer(
    help="Rebrew validation pipeline: parse annotations, generate catalog and coverage data.",
    rich_markup_mode="rich",
    epilog=(
        "[bold]Examples:[/bold]\n\n"
        "  rebrew catalog · · · · · · · · · · · · Validate and summarize (default)\n\n"
        "  rebrew catalog --data-json · · · · · · · Write db/data_<target>.json (feeds build-db)\n\n"
        "  rebrew catalog --json · · · · · · · · · Machine-readable summary to stdout\n\n"
        "  rebrew catalog -t mygame · · · · · · · · Catalog a specific target\n\n"
        "[bold]What it does:[/bold]\n\n"
        "  1. Scans reversed_dir for .c files with reccmp-style annotations\n\n"
        "  2. Cross-references with function_structure.json\n\n"
        "  3. Builds function registry merging all detection sources\n\n"
        "  4. Generates cell-level coverage data for the .text section\n\n"
        "  5. Outputs structured data\n\n"
        "[dim]Run 'rebrew catalog --data-json && rebrew build-db' to populate the "
        "recoverage SQLite database.[/dim]"
    ),
)


def run_catalog(
    cfg: ProjectConfig,
    *,
    gen_data_json: bool = False,
    csv: bool = False,
    summary: bool = False,
    export_ghidra_labels: bool = False,
    fix_sizes: bool = False,
    json_output: bool = False,
) -> dict[str, Any]:
    """Parse annotations, build the catalog and coverage data, and write the artifacts.

    The same pipeline the ``rebrew catalog`` callback runs: scan
    ``reversed_dir``, build the function registry, print the human summary,
    and write the requested artifacts (``db/data_<target>.json``,
    reccmp CSV, ``ghidra_data_labels.json``, ``--fix-sizes`` metadata updates).
    With every flag left false the default action set applies (data
    JSON + CSV + summary), matching a bare ``rebrew catalog`` invocation.

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
            gen_data_json,
            csv,
            summary,
            export_ghidra_labels,
            fix_sizes,
            json_output,
        ]
    ):
        gen_data_json = True
        csv = True
        summary = True

    bundle = build_catalog_data(cfg, with_data=bool(gen_data_json or export_ghidra_labels))
    entries = bundle["entries"]
    funcs = bundle["funcs"]
    registry = bundle["registry"]
    text_size = bundle["text_size"]
    binary_missing = bundle["binary_missing"]
    both_count = bundle["counts"]["both"]
    thunk_count = bundle["counts"]["thunks"]

    by_va: dict[int, list[Annotation]] = {}
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
            console.print(f"  {st}: {progress.status_counts[st]}")
        console.print(f"Library identified: {progress.library_identified}")
        console.print(
            f"Identified: {identified_pct:.1f}% of .text ({covered}/{text_size} bytes) "
            "claimed by an annotated function, stubs and library code included"
        )

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

    if gen_data_json or export_ghidra_labels:
        data = bundle["data"]
        if gen_data_json:
            coverage_dir = cfg.db_dir
            coverage_dir.mkdir(parents=True, exist_ok=True)
            json_path = coverage_dir / f"data_{target}.json"
            atomic_write_text(json_path, json.dumps(data, indent=2) + "\n", encoding="utf-8")
            console.print(f"Wrote {json_path}", style="dim")

        if export_ghidra_labels:
            text_sec = data.get("sections", {}).get(".text", {})
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
            labels_path = reversed_dir / "ghidra_data_labels.json"
            atomic_write_text(labels_path, json.dumps(labels, indent=2) + "\n", encoding="utf-8")
            console.print(f"Wrote {labels_path} ({len(labels)} labels)", style="dim")

    if csv:
        csv_text = generate_reccmp_csv(entries, funcs, registry, target, cfg)
        csv_path = cfg.db_dir / f"{target.lower()}_functions.csv"
        csv_path.parent.mkdir(parents=True, exist_ok=True)
        atomic_write_text(csv_path, csv_text, encoding="utf-8")
        console.print(f"Wrote {csv_path} ({len(csv_text.splitlines()) - 6} functions)", style="dim")

    if fix_sizes:
        from rebrew.annotation import update_size_annotation
        from rebrew.sources import iter_sources, target_marker

        updated = 0
        skipped = 0
        for cfile in iter_sources(reversed_dir, cfg):
            parsed = parse_c_file_multi(
                cfile,
                target_name=target_marker(cfg),
                metadata_dir=cfg.metadata_dir,
            )
            for ann in parsed:
                va = ann.va
                if va not in registry:
                    continue
                canonical = registry[va]["canonical_size"]
                if canonical <= 0 or canonical <= ann.size:
                    continue
                reason = registry[va].get("size_reason", "")
                if update_size_annotation(
                    cfile, canonical, target_va=va, metadata_dir=cfg.metadata_dir
                ):
                    diff = canonical - ann.size
                    from rebrew.utils import rel_display_path

                    display = rel_display_path(cfile, reversed_dir)
                    console.print(
                        f"  {display}: SIZE {ann.size} → {canonical} (+{diff}B, {reason})"
                    )
                    updated += 1
                else:
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
        "wrote_data_json": gen_data_json,
        "wrote_csv": csv,
    }
    if binary_missing:
        payload["warning"] = f"target binary missing ({bin_path}) — text_size=0, identified is 0%"
    return payload


@app.callback(invoke_without_command=True)
def main(
    gen_data_json: bool = typer.Option(False, "--data-json", help="Write db/data_<target>.json"),
    summary: bool = typer.Option(False, "--summary", help="Print summary table (stderr)"),
    csv: bool = typer.Option(
        False, "--csv", help="Generate reccmp-compatible CSV (written to db/<target>_functions.csv)"
    ),
    export_ghidra: bool = typer.Option(
        False, "--export-ghidra", help="Print instructions for exporting the Ghidra function list"
    ),
    export_ghidra_labels: bool = typer.Option(
        False,
        "--export-ghidra-labels",
        help="Generate ghidra_data_labels.json from detected tables",
    ),
    fix_sizes: bool = typer.Option(
        False,
        "--fix-sizes",
        help="Update SIZE in rebrew-functions.toml metadata to match canonical sizes",
    ),
    force: bool = typer.Option(False, "--force", help="Skip the --fix-sizes confirmation prompt"),
    root: Path | None = typer.Option(
        None,
        "--root",
        help="Project root directory (auto-detected from rebrew-project.toml if omitted)",
    ),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
    target: str | None = TargetOption,
) -> None:
    """Rebrew validation pipeline: parse annotations, generate catalog and coverage data."""
    cfg = require_config(target=target, json_mode=json_output, root=root)

    if fix_sizes:
        if json_output and not force:
            error_exit(
                "--fix-sizes modifies metadata; pass --force to use it in --json mode",
                json_mode=True,
            )
        if not force:
            # Prompt on stderr so a redirected stdout still shows the question.
            typer.confirm(
                "--fix-sizes will modify rebrew-functions.toml metadata files in-place. Continue?",
                abort=True,
                err=True,
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
            f"  get-functions programPath=/{cfg.target_binary.name} filterDefaultNames=false\n"
            f"Then save the output as {cfg.reversed_dir.name}/function_structure.json with format:\n"
            '  [{"va": 0x10001000, "size": 302, "tool_name": "FUN_10001000"}, ...]\n'
            "\n"
            "To also export data labels (switch tables, etc.), search for non-function\n"
            f"labels in Ghidra and save as {cfg.reversed_dir.name}/ghidra_data_labels.json:\n"
            '  [{"va": 0x10002E9C, "size": 20, "label": "switchdataD_10002e9c"}, ...]',
        )
        return

    try:
        payload = run_catalog(
            cfg,
            gen_data_json=gen_data_json,
            csv=csv,
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
