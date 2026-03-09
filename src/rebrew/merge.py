"""merge.py - Merge single-function C files into one multi-function file.

Combines multiple annotated source files into a single compilation unit,
deduplicating preamble lines and sorting function blocks by virtual address.
"""

from pathlib import Path
from typing import Any

import typer
from rich.console import Console

from rebrew.annotation import NEW_FUNC_CAPTURE_RE, parse_c_file_multi, split_annotation_sections
from rebrew.cli import (
    TargetOption,
    error_exit,
    iter_sources,
    json_print,
    rel_display_path,
    require_config,
    source_glob,
    target_marker,
)
from rebrew.config import ProjectConfig
from rebrew.utils import atomic_write_text

console = Console(stderr=True)

app = typer.Typer(
    help="Merge single-function C files into one multi-function file.",
    rich_markup_mode="rich",
)


def _block_metadata(block: str) -> dict[str, Any] | None:
    """Extract marker module/VA from a function block."""
    for line in block.splitlines():
        marker = NEW_FUNC_CAPTURE_RE.match(line.strip())
        if marker:
            return {
                "module": marker.group("module"),
                "va": int(marker.group("va"), 16),
            }
    return None


def _merge_preambles(preambles: list[str]) -> str:
    """Merge preambles with exact-line dedup and collapsed blank lines."""
    seen: set[str] = set()
    merged_lines: list[str] = []

    for preamble in preambles:
        for line in preamble.splitlines():
            if line.strip() == "":
                if merged_lines and merged_lines[-1] != "":
                    merged_lines.append("")
                continue
            if line in seen:
                continue
            seen.add(line)
            merged_lines.append(line)

    while merged_lines and merged_lines[-1] == "":
        merged_lines.pop()

    if not merged_lines:
        return ""
    return "\n".join(merged_lines) + "\n\n"


def _collect_input_files(paths: list[str], cfg: ProjectConfig) -> list[Path]:
    """Resolve input arguments into unique source-file paths."""
    expected_ext = source_glob(cfg).removeprefix("*")
    files: list[Path] = []
    seen: set[Path] = set()

    for raw in paths:
        p = Path(raw)
        if p.is_dir():
            for src in iter_sources(p, cfg):
                if src not in seen:
                    seen.add(src)
                    files.append(src)
            continue

        if not p.exists() or not p.is_file():
            continue
        if p.suffix != expected_ext:
            continue
        if p not in seen:
            seen.add(p)
            files.append(p)

    return files


@app.callback(invoke_without_command=True)
def main(
    sources: list[str] | None = typer.Argument(None, help="Input source files (or directories)"),
    output: str = typer.Option(..., "--output", "-o", help="Output merged source file"),
    dry_run: bool = typer.Option(False, "--dry-run", help="Preview changes without writing"),
    force: bool = typer.Option(False, "--force", help="Overwrite output if it exists"),
    delete: bool = typer.Option(
        False, "--delete", help="Delete input files after successful merge"
    ),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
    target: str | None = TargetOption,
) -> None:
    """Merge multiple single-function files into one multi-function file."""
    if not sources:
        error_exit("Merge requires at least two source files", json_mode=json_output)

    cfg = require_config(target=target, json_mode=json_output)
    input_files = _collect_input_files(sources, cfg)
    if len(input_files) < 2:
        error_exit("Merge requires at least two source files", json_mode=json_output)

    output_path = Path(output)
    if output_path.exists() and not force:
        error_exit(f"Output file already exists: {output_path}", json_mode=json_output)

    preambles: list[str] = []
    blocks_with_va: list[tuple[int, str]] = []
    included_inputs: list[Path] = []

    for file_path in input_files:
        annotations = parse_c_file_multi(
            file_path, target_name=target_marker(cfg), metadata_dir=cfg.metadata_dir
        )
        if not annotations:
            continue

        try:
            text = file_path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            error_exit(f"Failed to read {file_path}: {exc}", json_mode=json_output)

        preamble, blocks = split_annotation_sections(text)
        preambles.append(preamble)
        included_inputs.append(file_path)

        for block in blocks:
            meta = _block_metadata(block)
            if meta is None:
                continue
            module = str(meta["module"])
            if cfg.marker and module.lower() != cfg.marker.lower():
                continue
            va = int(meta["va"])
            blocks_with_va.append((va, block.strip("\n")))

    if len(blocks_with_va) < 2:
        error_exit(
            f"Need at least two matching function blocks for target '{cfg.marker}'",
            json_mode=json_output,
        )

    merged_preamble = _merge_preambles(preambles)
    sorted_blocks = [block for _, block in sorted(blocks_with_va, key=lambda x: x[0])]
    merged_text = merged_preamble + "\n\n".join(sorted_blocks) + "\n"

    if not dry_run:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        atomic_write_text(output_path, merged_text, encoding="utf-8")
        if delete:
            for file_path in included_inputs:
                if file_path.resolve() == output_path.resolve():
                    continue
                file_path.unlink(missing_ok=True)

    payload = {
        "output": str(output_path),
        "count": len(sorted_blocks),
        "input_count": len(included_inputs),
        "dry_run": dry_run,
        "deleted": bool(delete and not dry_run),
        "inputs": [rel_display_path(p, cfg.reversed_dir) for p in included_inputs],
        "vas": [f"0x{va:08x}" for va, _ in sorted(blocks_with_va, key=lambda x: x[0])],
    }
    if json_output:
        json_print(payload)
        return

    console.print(
        f"Merged [bold]{len(sorted_blocks)}[/] functions from {len(included_inputs)} files "
        f"into {output_path.name}"
    )
    if delete and not dry_run:
        console.print("Deleted original input files after merge")


def main_entry() -> None:
    """Run the Typer CLI application."""
    app()


if __name__ == "__main__":
    main_entry()
