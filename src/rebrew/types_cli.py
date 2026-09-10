"""types_cli.py - `rebrew types` command: check structs, apply types to signatures."""

from pathlib import Path
from typing import Any

import typer
from rich.console import Console

from rebrew.cli import TargetOption, error_exit, json_print, require_config

console = Console(stderr=True)

app = typer.Typer(
    help="Check declared struct layouts; apply types to C signatures.",
    rich_markup_mode="rich",
)


def collect_evidence(files: list[Path]) -> dict[str, dict[int, int]]:
    """Map struct name → ``{offset: majority width}`` from decompiler evidence.

    Reads ``*.dec.c`` / decompiler-output files via
    ``struct_recover.parse_decomp_for_structs``; named-type evidence only
    (anonymous temporaries cannot validate a declaration).
    """
    from rebrew.struct_recover import _majority_width, parse_decomp_for_structs

    merged: dict[str, dict[int, dict[int, int]]] = {}
    for path in files:
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        try:
            result = parse_decomp_for_structs(text)
        except Exception:
            continue
        for name, ent in result.named.items():
            slots = merged.setdefault(name, {})
            for offset, widths in ent.offsets.items():
                slot = slots.setdefault(offset, {})
                for width, count in widths.items():
                    slot[width] = slot.get(width, 0) + count
    return {
        name: {off: _majority_width(widths) for off, widths in slots.items()}
        for name, slots in merged.items()
    }


@app.callback(invoke_without_command=True)
def main(
    ctx: typer.Context,
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
    target: str | None = TargetOption,
) -> None:
    """Check declared structs against decompiler offset evidence."""
    if ctx.invoked_subcommand is not None:
        return
    cfg = require_config(target=target, json_mode=json_output)
    from rebrew.sources import iter_sources
    from rebrew.types import check_struct, parse_structs

    declared: dict[str, Any] = {}
    for src in iter_sources(cfg.reversed_dir, cfg):
        try:
            text = src.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for name, struct in parse_structs(text).items():
            declared.setdefault(name, struct)
    dec_files = [p for p in cfg.reversed_dir.rglob("*.dec.c") if p.is_file() and not p.is_symlink()]
    evidence = collect_evidence(dec_files)
    findings: list[dict[str, Any]] = []
    for name, struct in sorted(declared.items()):
        ev = evidence.get(name)
        if not ev:
            continue
        for finding in check_struct(struct, ev):
            findings.append({"struct": name, **finding})
    if json_output:
        json_print({"structs": len(declared), "findings": findings})
        return
    console.print(f"structs: {len(declared)}  findings: {len(findings)}")
    for f in findings:
        console.print(
            f"  [yellow]{f['struct']}[/yellow] +{f['offset']:#x}: "
            f"evidenced width {f['evidenced_width']} ({f['issue']}"
            + (f" on {f['field']}" if f.get("field") else "")
            + ")"
        )


def main_entry() -> None:
    """Run the Typer CLI application."""
    app()


@app.command("apply-type")
def apply_type(
    target_ident: str = typer.Argument(..., help="File path, symbol, or hex VA"),
    param: int = typer.Option(..., "--param", help="0-based parameter index"),
    type_name: str = typer.Option(..., "--type", help="New parameter type spelling"),
    dry_run: bool = typer.Option(False, "--dry-run", help="Preview changes without writing"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
    target: str | None = TargetOption,
) -> None:
    """Rewrite one parameter's type in project C source (recovered types reach the compiler)."""
    from rebrew.cli import resolve_source_arg
    from rebrew.types import rewrite_param_type
    from rebrew.utils import read_source_text

    cfg = require_config(target=target, json_mode=json_output)
    resolved = resolve_source_arg(cfg, target_ident)
    source_path = Path(str(resolved))
    if not source_path.is_file():
        error_exit(f"Cannot resolve {target_ident!r} to a source file", json_mode=json_output)
    try:
        text, encoding = read_source_text(source_path)
    except OSError as exc:
        error_exit(f"Cannot read {source_path}: {exc}", json_mode=json_output)
    from rebrew.c_parser import iter_function_name_and_proto
    from rebrew.utils import atomic_write_text

    matches = [name for name, _proto in iter_function_name_and_proto(text) if name == target_ident]
    func_name = matches[0] if matches else ""
    if not func_name:
        func_name = _first_function_name(text)
    if not func_name:
        error_exit(f"No function definition in {source_path.name}", json_mode=json_output)
    rewritten = rewrite_param_type(text, func_name, param, type_name)
    if rewritten is None:
        error_exit(
            f"Cannot rewrite param {param} of {func_name} — function or index not found",
            json_mode=json_output,
        )
    if rewritten == text:
        error_exit("New type identical to current spelling — nothing to do", json_mode=json_output)
    if json_output:
        json_print(
            {
                "file": str(source_path),
                "function": func_name,
                "param": param,
                "type": type_name,
                "dry_run": dry_run,
            }
        )
        return
    if dry_run:
        console.print(
            f"  [dim]Would rewrite[/dim] {source_path.name} {func_name} param {param} → {type_name}"
        )
        return
    atomic_write_text(source_path, rewritten, encoding=encoding)
    console.print(
        f"[green]Rewrote:[/green] {source_path.name} {func_name} param {param} → {type_name}"
    )


def _first_function_name(text: str) -> str:
    from rebrew.c_parser import iter_function_name_and_proto

    names = [name for name, _proto in iter_function_name_and_proto(text)]
    return names[0] if names else ""


if __name__ == "__main__":
    main_entry()
