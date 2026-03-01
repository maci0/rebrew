"""catalog/cli.py - CLI entry point for the catalog command.

Orchestrates annotation scanning, registry building, and output generation
(CATALOG.md, data.json, reccmp CSV, Ghidra label export, size fixing).
"""

import json
from pathlib import Path

import typer

from rebrew.annotation import Annotation, parse_c_file_multi
from rebrew.catalog.export import generate_catalog, generate_reccmp_csv
from rebrew.catalog.grid import generate_data_json
from rebrew.catalog.loaders import parse_function_list, scan_reversed_dir
from rebrew.catalog.registry import build_function_registry
from rebrew.catalog.sections import get_text_section_size
from rebrew.cli import (
    TargetOption,
    get_config,
)

app = typer.Typer(
    help="Rebrew validation pipeline: parse annotations, generate catalog and coverage data.",
    rich_markup_mode="rich",
    epilog="""\
[bold]Examples:[/bold]

rebrew catalog                              Validate annotations (default)

rebrew catalog --json                       Generate db/data_<target>.json

rebrew catalog --catalog                    Generate CATALOG.md in reversed_dir

rebrew catalog --json --catalog             Generate both JSON and CATALOG.md

rebrew catalog -t server.dll                Catalog a specific target

[bold]What it does:[/bold]

1. Scans reversed_dir for .c files with reccmp-style annotations

2. Cross-references with ghidra_functions.json and function list

3. Builds function registry merging all detection sources

4. Generates cell-level coverage data for the .text section

5. Outputs structured JSON and/or CATALOG.md

[dim]The JSON output feeds into 'rebrew build-db' to create the SQLite database
used by the recoverage dashboard.[/dim]""",
)


@app.callback(invoke_without_command=True)
def main(
    gen_json: bool = typer.Option(False, "--json", help="Generate db/data.json"),
    catalog: bool = typer.Option(
        False, "--catalog", help="Generate CATALOG.md in reversed directory"
    ),
    summary: bool = typer.Option(False, "--summary", help="Print summary to stdout"),
    csv: bool = typer.Option(False, "--csv", help="Generate reccmp-compatible CSV"),
    export_ghidra: bool = typer.Option(False, "--export-ghidra", help="Cache Ghidra function list"),
    export_ghidra_labels: bool = typer.Option(
        False,
        "--export-ghidra-labels",
        help="Generate ghidra_data_labels.json from detected tables",
    ),
    fix_sizes: bool = typer.Option(
        False,
        "--fix-sizes",
        help="Update // SIZE: annotations in .c files to match canonical sizes",
    ),
    root: Path | None = typer.Option(
        None,
        help="Project root directory (auto-detected from rebrew-project.toml if omitted)",
    ),
    target: str | None = TargetOption,
) -> None:
    """Rebrew validation pipeline: parse annotations, generate catalog and coverage data."""
    cfg = None
    try:
        cfg = get_config(target=target)
        bin_path = cfg.target_binary
        reversed_dir = cfg.reversed_dir
        root = cfg.root
        target = cfg.target_name
    except (AttributeError, KeyError, FileNotFoundError):
        if root is None:
            root = Path.cwd().resolve()
        bin_path = root / "binary.dll"
        reversed_dir = root / "src"
        target = target or "default"

    func_list_path = cfg.function_list if cfg else (reversed_dir / "functions.txt")
    ghidra_json_path = reversed_dir / "ghidra_functions.json"

    if not any(
        [
            catalog,
            gen_json,
            csv,
            summary,
            export_ghidra,
            export_ghidra_labels,
            fix_sizes,
        ]
    ):
        catalog = True
        gen_json = True
        csv = True
        summary = True

    if export_ghidra:
        typer.echo(
            "To export Ghidra functions, run this in the MCP console:\n"
            f"  get-functions programPath=/{bin_path.name} filterDefaultNames=false\n"
            f"Then save the output as {reversed_dir.name}/ghidra_functions.json with format:\n"
            '  [{"va": 0x10001000, "size": 302, "ghidra_name": "FUN_10001000"}, ...]\n'
            "\n"
            "To also export data labels (switch tables, etc.), search for non-function\n"
            f"labels in Ghidra and save as {reversed_dir.name}/ghidra_data_labels.json:\n"
            '  [{"va": 0x10002E9C, "size": 20, "label": "switchdataD_10002e9c"}, ...]\n'
            f"(Legacy ghidra_switchdata.json format is still supported for compat.)",
            err=True,
        )
        return

    typer.echo(f"Scanning {reversed_dir}...", err=True)
    entries = scan_reversed_dir(reversed_dir, cfg=cfg)
    funcs = parse_function_list(func_list_path)

    text_size = get_text_section_size(bin_path) if bin_path and bin_path.exists() else 0x24000

    registry = build_function_registry(funcs, cfg, ghidra_json_path, bin_path)

    unique_vas = {e["va"] for e in entries}
    ghidra_count = sum(1 for r in registry.values() if "ghidra" in r["detected_by"])
    list_count = sum(1 for r in registry.values() if "list" in r["detected_by"])
    both_count = sum(
        1 for r in registry.values() if "ghidra" in r["detected_by"] and "list" in r["detected_by"]
    )
    thunk_count = sum(1 for r in registry.values() if r["is_thunk"])
    typer.echo(
        f"Found {len(entries)} annotations ({len(unique_vas)} unique VAs) "
        f"from {len(registry)} total functions "
        f"(list: {list_count}, ghidra: {ghidra_count}, both: {both_count}, "
        f"thunks: {thunk_count})",
        err=True,
    )

    if summary:
        by_va: dict[int, list[Annotation]] = {}
        for e in entries:
            by_va.setdefault(e["va"], []).append(e)

        fn_vas = {
            va
            for va, vas in by_va.items()
            if any(e["marker_type"] not in ("GLOBAL", "DATA") for e in vas)
        }

        exact = sum(1 for va in fn_vas if any(e["status"] == "EXACT" for e in by_va[va]))
        reloc = sum(
            1
            for va in fn_vas
            if any(e["status"] in ("RELOC", "MATCHING_RELOC") for e in by_va[va])
            and not any(e["status"] == "EXACT" for e in by_va[va])
        )
        matching = sum(
            1
            for va in fn_vas
            if any(e["status"] in ("MATCHING", "MATCHING_RELOC") for e in by_va[va])
            and not any(e["status"] in ("EXACT", "RELOC") for e in by_va[va])
        )
        stub = sum(
            1
            for va in fn_vas
            if any(e["status"] == "STUB" for e in by_va[va])
            and not any(
                e["status"] in ("EXACT", "RELOC", "MATCHING", "MATCHING_RELOC") for e in by_va[va]
            )
        )

        origin_counts: dict[str, int] = {}
        for va in fn_vas:
            origin = by_va[va][0]["origin"]
            origin_counts[origin] = origin_counts.get(origin, 0) + 1

        done = exact + reloc + matching
        print("\n=== Rebrew Status ===")
        print(f"Matched: {done}/{len(registry)} functions")
        print(f"  EXACT: {exact}")
        print(f"  RELOC: {reloc}")
        if matching:
            print(f"  MATCHING: {matching}")
        if stub:
            print(f"  STUB: {stub}")
        print("By origin:")
        for origin in sorted(origin_counts):
            print(f"  {origin}: {origin_counts[origin]}")

        covered = 0
        for va in fn_vas:
            if va in registry:
                covered += registry[va]["canonical_size"]
        pct = (covered / text_size * 100.0) if text_size else 0.0
        print(f"Coverage: {pct:.1f}% ({covered}/{text_size} bytes)")

        print("\n=== Tool Detection ===")
        print(
            f"  func list only: {sum(1 for r in registry.values() if r['detected_by'] == ['list'])}"
        )
        print(
            f"  Ghidra only:  {sum(1 for r in registry.values() if r['detected_by'] == ['ghidra'])}"
        )
        print(f"  Both tools:   {both_count}")
        print(f"  IAT thunks:   {thunk_count}")
        size_mismatches = sum(
            1
            for r in registry.values()
            if "ghidra" in r["size_by_tool"]
            and "list" in r["size_by_tool"]
            and r["size_by_tool"]["ghidra"] != r["size_by_tool"]["list"]
        )
        print(f"  Size disagree: {size_mismatches}")

    if catalog:
        catalog_text = generate_catalog(entries, funcs, text_size)
        catalog_path = reversed_dir / "CATALOG.md"
        catalog_path.parent.mkdir(parents=True, exist_ok=True)
        catalog_path.write_text(catalog_text, encoding="utf-8")
        typer.echo(f"Wrote {catalog_path}", err=True)

    if gen_json or export_ghidra_labels:
        data = generate_data_json(entries, funcs, text_size, bin_path, registry, reversed_dir, root)
        if gen_json:
            coverage_dir = root / "db"
            coverage_dir.mkdir(parents=True, exist_ok=True)
            json_path = coverage_dir / f"data_{target}.json"
            json_path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
            typer.echo(f"Wrote {json_path}", err=True)

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
            labels_path.write_text(json.dumps(labels, indent=2) + "\n", encoding="utf-8")
            typer.echo(f"Wrote {labels_path} ({len(labels)} labels)", err=True)

    if csv:
        csv_text = generate_reccmp_csv(entries, funcs, registry, target, cfg)
        csv_path = root / "db" / f"{target.lower()}_functions.csv"
        csv_path.parent.mkdir(parents=True, exist_ok=True)
        csv_path.write_text(csv_text, encoding="utf-8")
        typer.echo(f"Wrote {csv_path} ({len(csv_text.splitlines()) - 6} functions)", err=True)

    if fix_sizes:
        from rebrew.annotation import update_size_annotation
        from rebrew.cli import iter_sources

        updated = 0
        skipped = 0
        for cfile in iter_sources(reversed_dir, cfg):
            parsed = parse_c_file_multi(cfile, target_name=cfg.marker if cfg else None)
            for ann in parsed:
                va = ann.va
                if va not in registry:
                    continue
                canonical = registry[va]["canonical_size"]
                if canonical <= 0 or canonical <= ann.size:
                    continue
                reason = registry[va].get("size_reason", "")
                if update_size_annotation(cfile, canonical):
                    diff = canonical - ann.size
                    from rebrew.cli import rel_display_path

                    display = rel_display_path(cfile, reversed_dir)
                    print(f"  {display}: SIZE {ann.size} → {canonical} (+{diff}B, {reason})")
                    updated += 1
                else:
                    skipped += 1
        typer.echo(f"Updated {updated} SIZE annotations ({skipped} skipped)", err=True)


def main_entry() -> None:
    """Run the catalog Typer application entrypoint."""
    app()


if __name__ == "__main__":
    main_entry()
