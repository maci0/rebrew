"""split.py – Split a multi-function C file into single-function files.

Reads a C translation unit containing multiple ``// FUNCTION:`` annotation
blocks and writes one output file per function, preserving the shared preamble
in every output file.  With ``--va``, a single function can be extracted into
its own file while the block is removed from the original source.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import TypedDict

import typer
from rich.console import Console

from rebrew.annotation import (
    _C_FUNC_IDENT_RE,
    NEW_FUNC_CAPTURE_RE,
    NEW_KV_RE,
    parse_c_file_multi,
    split_annotation_sections,
)
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
from rebrew.utils import atomic_write_text

console = Console(stderr=True)

app = typer.Typer(
    help="Split multi-function C files into single-function files.",
    rich_markup_mode="rich",
)


class _BlockMeta(TypedDict):
    """Metadata extracted from a single ``// FUNCTION:`` annotation block."""

    module: str
    va: int
    symbol: str


def _block_metadata(block: str) -> _BlockMeta | None:
    """Extract marker metadata and first annotation key-values for one block.

    Returns ``None`` when the block contains no recognisable
    ``// FUNCTION: <MODULE> 0x<VA>`` marker.
    """
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
    c_func_name = ""
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
        # Try to extract function name from C definition (same regex as annotation.py).
        # Skip forward declarations (ending with ';').
        if not c_func_name:
            m4 = _C_FUNC_IDENT_RE.match(stripped)
            if m4 and not stripped.rstrip().endswith(";"):
                c_func_name = m4.group("name")
        break

    # Symbol is derived from C function definition name
    symbol = c_func_name

    return _BlockMeta(
        module=marker_match.group("module"),
        va=int(marker_match.group("va"), 16),
        symbol=symbol,
    )


def _build_output_name(symbol: str, va: int, ext: str) -> str:
    """Generate output filename from symbol or fallback VA."""
    stem = symbol.lstrip("_").strip()
    if not stem:
        stem = f"func_{va:08x}"
    return f"{stem}{ext}"


# Matches // CFLAGS: <flags> annotation lines.
_CFLAGS_RE = re.compile(r"^(\s*//\s*CFLAGS:\s*)(.*)$", re.MULTILINE)


def _inject_include_parent(block: str) -> str:
    """Add ``/I..`` to the ``// CFLAGS:`` annotation inside *block*.

    When a function is extracted into a subdirectory (e.g. ``command_c/``),
    the compiler's ``-I<source_parent>`` points to the subdirectory instead
    of the original parent.  Adding ``/I..`` tells ``compile.py`` to also
    search the parent of the subdirectory, restoring the original include
    resolution without touching the preamble (which must stay identical for
    clean ``rebrew merge`` round-trips).
    """
    m = _CFLAGS_RE.search(block)
    if m:
        existing = m.group(2).strip()
        if "/I.." not in existing:
            new_cflags = f"{existing} /I.."
            return block[: m.start(2)] + new_cflags + block[m.end(2) :]
    return block


@app.callback(invoke_without_command=True)
def main(
    source: str | None = typer.Argument(None, help="Path to a multi-function source file"),
    va: str | None = typer.Option(
        None, "--va", help="Extract a single function by VA (hex) into its own file"
    ),
    output_dir: str | None = typer.Option(None, "--output-dir", help="Output directory"),
    dry_run: bool = typer.Option(False, "--dry-run", help="Preview changes without writing"),
    force: bool = typer.Option(False, "--force", help="Overwrite existing output files"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
    target: str | None = TargetOption,
) -> None:
    """Split a multi-function C file into one file per function block.

    With --va, extract a single function into its own file (preamble included).
    Without --va, split ALL functions into individual files.
    """
    if source is None:
        error_exit("Source file argument is required", json_mode=json_output)

    cfg = require_config(target=target, json_mode=json_output)
    source_path = Path(source)
    if not source_path.exists() or not source_path.is_file():
        error_exit(f"Source file not found: {source_path}", json_mode=json_output)

    expected_ext = source_glob(cfg).removeprefix("*")
    if source_path.suffix != expected_ext:
        error_exit(
            f"Source must match configured extension '{expected_ext}': {source_path.name}",
            json_mode=json_output,
        )

    out_dir = Path(output_dir).resolve() if output_dir else source_path.parent.resolve()

    try:
        text = source_path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        error_exit(f"Failed to read source: {exc}", json_mode=json_output)

    preamble, blocks = split_annotation_sections(text)

    # --va mode: extract a single function block
    if va is not None:
        va_cleaned = va.removeprefix("0x").removeprefix("0X")
        try:
            target_va = int(va_cleaned, 16)
        except ValueError:
            error_exit(f"Invalid VA (must be hex): {va}", json_mode=json_output)
            return  # unreachable — makes type-checker happy

        matched_block: str | None = None
        matched_meta: _BlockMeta | None = None
        matched_idx: int | None = None
        for idx, block in enumerate(blocks):
            meta = _block_metadata(block)
            if meta is None:
                continue
            if cfg.marker and meta["module"].lower() != cfg.marker.lower():
                continue
            if int(meta["va"]) == target_va:
                matched_block = block
                matched_meta = meta
                matched_idx = idx
                break

        if matched_block is None or matched_meta is None or matched_idx is None:
            error_exit(
                f"No function block found for VA 0x{target_va:08x} in {source_path.name}",
                json_mode=json_output,
            )
            return  # unreachable — makes type-checker happy

        symbol = matched_meta["symbol"]
        out_name = _build_output_name(symbol, target_va, cfg.source_ext)
        # Default to a subdirectory named after the source file: sim.c -> sim_c/
        if output_dir is None:
            stem = source_path.stem + source_path.suffix.replace(".", "_")
            va_out_dir = source_path.parent / stem
        else:
            va_out_dir = Path(output_dir)
        out_path = va_out_dir / out_name

        if not force and out_path.exists():
            error_exit(f"Output file already exists: {out_path}", json_mode=json_output)

        result_info = {
            "source": rel_display_path(source_path, cfg.reversed_dir),
            "va": f"0x{target_va:08x}",
            "symbol": symbol,
            "output": rel_display_path(out_path, va_out_dir),
        }

        if not dry_run:
            va_out_dir.mkdir(parents=True, exist_ok=True)
            # Inject /I.. into CFLAGS so the compiler searches the original
            # parent directory for relative #include paths.
            adjusted_block = (
                _inject_include_parent(matched_block) if output_dir is None else matched_block
            )
            atomic_write_text(out_path, preamble + adjusted_block, encoding="utf-8")
            # Remove the extracted block from the source file (by index, not identity)
            remaining = [b for i, b in enumerate(blocks) if i != matched_idx]
            if remaining:
                atomic_write_text(source_path, preamble + "".join(remaining), encoding="utf-8")
            else:
                source_path.unlink()

        if json_output:
            json_print(
                {
                    "source": str(source_path),
                    "output_dir": str(va_out_dir),
                    "count": 1,
                    "dry_run": dry_run,
                    "files": [result_info],
                }
            )
        else:
            action = "Would extract" if dry_run else "Extracted"
            console.print(
                f"[bold green]{action}[/] 0x{target_va:08x} ({symbol or 'unnamed'}) → {out_path.name}"
            )
        return

    # Full split mode: split ALL functions into individual files
    if len(blocks) < 2:
        error_exit(
            "Input must contain at least two function blocks to split", json_mode=json_output
        )

    entries = parse_c_file_multi(
        source_path, target_name=target_marker(cfg), sidecar_dir=source_path.parent
    )
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
        if cfg.marker and meta["module"].lower() != cfg.marker.lower():
            continue

        block_va = meta["va"]
        symbol = meta["symbol"]
        out_name = _build_output_name(symbol, block_va, cfg.source_ext)
        out_path = out_dir / out_name

        if not force and (out_path.exists() or out_path in existing_sources):
            error_exit(f"Output file already exists: {out_path}", json_mode=json_output)

        planned.append(
            {
                "source": rel_display_path(source_path, cfg.reversed_dir),
                "va": f"0x{block_va:08x}",
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

    console.print(
        f"Split [bold]{split_count}[/] functions from {source_path.name} into {split_count} files"
    )
    for item in planned:
        console.print(f"  {item['output']} ← [cyan]{item['va']}[/]")


def main_entry() -> None:
    """Run the Typer CLI application."""
    app()


if __name__ == "__main__":
    main_entry()
