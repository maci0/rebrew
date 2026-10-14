"""Generate target-scoped linker anchors from source identities and explicit storage choices."""

from pathlib import Path
from typing import Any

import typer

from rebrew.c_parser import find_variable_roles
from rebrew.c_rename import ParsedSource, definitions
from rebrew.cli import EXIT_MISMATCH, TargetOption, console, error_exit, json_print, require_config
from rebrew.config import ProjectConfig
from rebrew.metadata.bindings import FUNCTION_KINDS, iter_source_bindings
from rebrew.sources import iter_sources, target_marker
from rebrew.utils import atomic_write_text, preset_module_key

app = typer.Typer(
    help="Generate VA-ordered native function anchors and explicitly selected data anchors.",
    epilog=(
        "Examples:\n\n  rebrew build anchors --target server.dll --output layout/game-includes.rsp\n\n"
        "  rebrew build anchors --data-source src/constants.c --data-prefix _ --symbol _mark --dry-run\n\n"
        "Data sources are explicit storage choices; declarations and static definitions are excluded."
    ),
)


def anchor_symbols(
    cfg: ProjectConfig, data_sources: list[Path], symbols: list[str], data_prefix: str
) -> dict[str, Any]:
    """Keep native function symbols verbatim, sorted by selected-target VA."""
    marker = target_marker(cfg)
    rows: dict[int, str] = {}
    for _path, annotations in iter_source_bindings(
        list(iter_sources(cfg)), target=marker, metadata_dir=cfg.metadata_dir
    ):
        for ann in annotations:
            if ann.kind not in FUNCTION_KINDS or ann.kind == "LIBRARY":
                continue
            if preset_module_key(ann.module) != preset_module_key(marker or ""):
                continue
            if not ann.symbol:
                raise ValueError(f"function 0x{ann.va:x} has no native symbol")
            if ann.va in rows and rows[ann.va] != ann.symbol:
                raise ValueError(f"conflicting symbols for 0x{ann.va:x}")
            rows[ann.va] = ann.symbol
    data: set[str] = set()
    for path in data_sources:
        path = path if path.is_absolute() else cfg.root / path
        source = path.read_text(encoding="utf-8", errors="surrogateescape")
        owners, _, _ = find_variable_roles(source)
        parsed = ParsedSource.parse(source)
        data.update(
            data_prefix + name
            for name in owners
            if any(d.kind == "variable" and not d.static for d in definitions(parsed, name))
        )
    ordered = list(dict.fromkeys([*(rows[va] for va in sorted(rows)), *sorted(data), *symbols]))
    for symbol in ordered:
        if not symbol or any(ch.isspace() or ch in '";\x00' for ch in symbol):
            raise ValueError(f"invalid linker symbol: {symbol!r}")
    return {
        "target": cfg.target_name,
        "functions": len(rows),
        "data": len(data),
        "symbols": ordered,
        "text": "".join(f"/INCLUDE:{symbol}\n" for symbol in ordered),
    }


@app.callback(invoke_without_command=True)
def main(
    output: Path | None = typer.Option(None, "--output", "-o", help="Response file to write"),
    data_sources: list[Path] | None = typer.Option(
        None, "--data-source", help="Anchor external definitions from this source (repeatable)"
    ),
    symbols: list[str] | None = typer.Option(
        None, "--symbol", help="Additional native linker symbol (repeatable)"
    ),
    data_prefix: str = typer.Option(
        "", help="Explicit native decoration prefix for selected data definitions"
    ),
    check: bool = typer.Option(False, "--check", help="Fail when the response file differs"),
    dry_run: bool = typer.Option(False, "--dry-run", help="Preview changes without writing"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
    target: str | None = TargetOption,
) -> None:
    """Preview or emit a response file without changing managed identities."""
    cfg = require_config(target=target, json_mode=json_output)
    if check and output is None:
        error_exit("--check requires --output", json_mode=json_output)
    try:
        report = anchor_symbols(cfg, data_sources or [], symbols or [], data_prefix)
        destination = output if output is None or output.is_absolute() else cfg.root / output
        drift = destination is not None and (
            not destination.is_file() or destination.read_text() != report["text"]
        )
        if destination is not None and not check and not dry_run:
            destination.parent.mkdir(parents=True, exist_ok=True)
            atomic_write_text(destination, report["text"])
    except (OSError, ValueError) as exc:
        error_exit(str(exc), json_mode=json_output)
    if json_output:
        json_print(
            {
                **report,
                "output": str(destination) if destination is not None else None,
                "drift": drift,
            }
        )
    else:
        console.print(report["text"], markup=False, end="")
    if check and drift:
        raise typer.Exit(EXIT_MISMATCH)


def main_entry() -> None:
    """Run the Typer CLI application."""
    from rebrew.cli import run_standalone

    run_standalone(main)


if __name__ == "__main__":
    main_entry()
