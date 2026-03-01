"""split.py - Split a multi-function C file into single-function files.

Reads a C translation unit containing multiple ``// FUNCTION:`` annotation
blocks and writes one output file per function, preserving the shared preamble
in every output file.
"""

from pathlib import Path
from typing import Any

import typer

from rebrew.annotation import NEW_FUNC_CAPTURE_RE, NEW_KV_RE, parse_c_file_multi
from rebrew.cli import (
    TargetOption,
    error_exit,
    get_config,
    iter_sources,
    json_print,
    rel_display_path,
    source_glob,
)
from rebrew.utils import atomic_write_text

app = typer.Typer(
    help="Split multi-function C files into single-function files.",
    rich_markup_mode="rich",
)


def _split_sections(text: str) -> tuple[str, list[str]]:
    """Return (preamble, blocks) split by ``// FUNCTION:`` marker lines."""
    lines = text.splitlines(keepends=True)
    marker_indexes: list[int] = []
    for idx, line in enumerate(lines):
        if NEW_FUNC_CAPTURE_RE.match(line.strip()):
            marker_indexes.append(idx)

    if not marker_indexes:
        return text, []

    preamble = "".join(lines[: marker_indexes[0]])
    blocks: list[str] = []
    for i, start in enumerate(marker_indexes):
        end = marker_indexes[i + 1] if i + 1 < len(marker_indexes) else len(lines)
        blocks.append("".join(lines[start:end]))

    return preamble, blocks


def _block_metadata(block: str) -> dict[str, Any] | None:
    """Extract marker metadata and first annotation key-values for one block."""
    lines = block.splitlines()
    marker_idx: int | None = None
    marker_match = None
    for idx, line in enumerate(lines):
        m = NEW_FUNC_CAPTURE_RE.match(line.strip())
        if m:
            marker_idx = idx
            marker_match = m
            break

    if marker_idx is None or marker_match is None:
        return None

    kv: dict[str, str] = {}
    for line in lines[marker_idx + 1 :]:
        stripped = line.strip()
        if not stripped:
            continue
        kv_match = NEW_KV_RE.match(stripped)
        if kv_match:
            kv[kv_match.group("key").upper()] = kv_match.group("value").strip()
            continue
        if stripped.startswith("//"):
            continue
        break

    return {
        "module": marker_match.group("module"),
        "va": int(marker_match.group("va"), 16),
        "symbol": kv.get("SYMBOL", ""),
    }


def _build_output_name(symbol: str, va: int, ext: str) -> str:
    """Generate output filename from SYMBOL or fallback VA."""
    stem = symbol.lstrip("_").strip()
    if not stem:
        stem = f"func_{va:08x}"
    return f"{stem}{ext}"


@app.callback(invoke_without_command=True)
def main(
    source: str | None = typer.Argument(None, help="Path to a multi-function source file"),
    output_dir: str | None = typer.Option(None, "--output-dir", help="Output directory"),
    dry_run: bool = typer.Option(False, "--dry-run", help="Preview files without writing"),
    force: bool = typer.Option(False, "--force", help="Overwrite existing output files"),
    json_output: bool = typer.Option(False, "--json", help="Output structured JSON"),
    target: str | None = TargetOption,
) -> None:
    """Split a multi-function C file into one file per function block."""
    if source is None:
        error_exit("Source file argument is required", json_mode=json_output)

    cfg = get_config(target=target)
    source_path = Path(source)
    if not source_path.exists() or not source_path.is_file():
        error_exit(f"Source file not found: {source_path}", json_mode=json_output)

    expected_ext = source_glob(cfg).removeprefix("*")
    if source_path.suffix != expected_ext:
        error_exit(
            f"Source must match configured extension '{expected_ext}': {source_path.name}",
            json_mode=json_output,
        )

    out_dir = Path(output_dir) if output_dir else source_path.parent
    out_dir = out_dir.resolve() if out_dir.exists() else out_dir

    try:
        text = source_path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        error_exit(f"Failed to read source: {exc}", json_mode=json_output)

    preamble, blocks = _split_sections(text)
    if len(blocks) < 2:
        error_exit(
            "Input must contain at least two function blocks to split", json_mode=json_output
        )

    entries = parse_c_file_multi(source_path, target_name=cfg.marker if cfg else None)
    if len(entries) < 2:
        error_exit(
            f"No splittable blocks found for target '{cfg.marker}'",
            json_mode=json_output,
        )

    existing_sources = set(iter_sources(out_dir, cfg)) if out_dir.exists() else set()
    planned: list[dict[str, str]] = []
    split_count = 0
    for block in blocks:
        meta = _block_metadata(block)
        if meta is None:
            continue
        module = str(meta["module"])
        if cfg.marker and module.lower() != cfg.marker.lower():
            continue

        va = int(meta["va"])
        symbol = str(meta["symbol"])
        out_name = _build_output_name(symbol, va, cfg.source_ext)
        out_path = out_dir / out_name

        if not force and (out_path.exists() or out_path in existing_sources):
            error_exit(f"Output file already exists: {out_path}", json_mode=json_output)

        planned.append(
            {
                "source": rel_display_path(source_path, cfg.reversed_dir),
                "va": f"0x{va:08x}",
                "symbol": symbol,
                "output": rel_display_path(out_path, out_dir),
            }
        )

        if not dry_run:
            out_dir.mkdir(parents=True, exist_ok=True)
            atomic_write_text(out_path, preamble + block, encoding="utf-8")
        split_count += 1

    if split_count < 2:
        error_exit(
            f"Need at least two matching blocks for target '{cfg.marker}' to split",
            json_mode=json_output,
        )

    if json_output:
        json_print(
            {
                "source": str(source_path),
                "output_dir": str(out_dir),
                "count": split_count,
                "dry_run": dry_run,
                "files": planned,
            }
        )
        return

    typer.echo(
        f"Split {split_count} functions from {source_path.name} into {split_count} files",
        err=True,
    )
    for item in planned:
        typer.echo(f"  {item['output']} <- {item['va']}", err=True)


def main_entry() -> None:
    """Package entry point for ``rebrew-split``."""
    app()
