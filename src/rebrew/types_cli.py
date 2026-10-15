"""Manage type identities, check struct layouts and apply types to signatures."""

import logging
from pathlib import Path
from typing import Any

import typer

from rebrew.cli import SOURCE_HELP, TargetOption, console, error_exit, json_print, require_config

app = typer.Typer(
    help="Manage types, audit contracts, reconcile headers, and check layouts.",
    rich_markup_mode="rich",
    epilog=(
        "[bold]Examples:[/bold]\n\n"
        "  rebrew types check --json\n\n"
        "  rebrew types check --compile\n\n"
        "  rebrew types bind obj t.h T --size 4 --native-size 4 --evidence alloc\n\n"
        "  rebrew types apply src/f.c --param 2 --type MAT4 --dry-run\n\n"
        "[dim]check compares layouts with evidence. contracts audits declaration and definition contracts; reconcile previews one reviewed canonical header signature across every target. bind records a checked type identity; apply edits a parameter. Verify affected functions after source edits.[/dim]\n\n"
    ),
)


def collect_evidence(files: list[Path]) -> dict[str, dict[int, int]]:
    """Map struct name → ``{offset: majority width}`` from decompiler evidence.

    Reads ``*.dec.c`` / decompiler-output files via
    ``struct_recover.parse_decomp_for_structs``; named-type evidence only
    (anonymous temporaries cannot validate a declaration).
    """
    from rebrew.struct_recover import majority_width, parse_decomp_for_structs

    merged: dict[str, dict[int, dict[int, int]]] = {}
    for path in files:
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            # Unreadable evidence reads as "no struct evidence found".
            logging.getLogger(__name__).warning("skipping unreadable %s: %s", path, exc)
            continue
        try:
            result = parse_decomp_for_structs(text)
        except Exception as exc:
            logging.getLogger(__name__).debug("struct parse failed: %s", exc)
            continue
        for name, ent in result.named.items():
            slots = merged.setdefault(name, {})
            for offset, widths in ent.offsets.items():
                slot = slots.setdefault(offset, {})
                for width, count in widths.items():
                    slot[width] = slot.get(width, 0) + count
    return {
        name: {off: majority_width(widths) for off, widths in slots.items()}
        for name, slots in merged.items()
    }


@app.command(
    "check",
    epilog=(
        "[bold]Examples:[/bold]\n\n"
        "  rebrew types check --json\n\n"
        "Reports layout conflicts and stale type bindings. --compile repeats managed sizeof/offsetof checks."
    ),
)
def check(
    compile_layouts: bool = typer.Option(
        False, "--compile", help="Recompile managed sizeof/offsetof assertions"
    ),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
    target: str | None = TargetOption,
) -> None:
    """Check declared structs against decompiler offset evidence."""
    cfg = require_config(target=target, json_mode=json_output)
    from rebrew.sources import iter_sources
    from rebrew.type_metadata import check_types
    from rebrew.types import check_struct, parse_structs

    declared: dict[str, Any] = {}
    for src in iter_sources(cfg.reversed_dir, cfg):
        try:
            from rebrew.utils import read_source_text

            text = read_source_text(src)[0]
        except OSError as exc:
            logging.getLogger(__name__).warning("skipping unreadable source %s: %s", src, exc)
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
        for finding in check_struct(struct, ev, known_structs=declared):
            findings.append({"struct": name, **finding})
    if json_output:
        bindings = check_types(cfg, compile_layouts=compile_layouts)
        json_print({"structs": len(declared), "findings": findings, "type_findings": bindings})
        if bindings:
            raise typer.Exit(1)
        return
    console.print(f"structs: {len(declared)}  findings: {len(findings)}")
    for f in findings:
        console.print(
            f"  [yellow]{f['struct']}[/yellow] +{f['offset']:#x}: "
            f"evidenced width {f['evidenced_width']} ({f['issue']}"
            + (f" on {f['field']}" if f.get("field") else "")
            + ")"
        )
    bindings = check_types(cfg, compile_layouts=compile_layouts)
    for binding_finding in bindings:
        console.print(
            f"  [yellow]{binding_finding['id']}:{binding_finding['module']}[/yellow] {binding_finding['issue']}"
        )
    if bindings:
        raise typer.Exit(1)


@app.command(
    "bind",
    epilog=(
        "[bold]Examples:[/bold]\n\n"
        "  rebrew types bind obj t.h T --size 4 --native-size 4 --evidence alloc\n\n"
        "Identity has no VA. Instance addresses belong to function/data records. Rebind the same ID after reviewing stale evidence."
    ),
)
def bind(
    identity: str = typer.Argument(..., help="Stable type ID, independent of the C name"),
    file: Path = typer.Argument(..., help="Owning C source or header"),
    symbol: str = typer.Argument(..., help="C typedef or struct tag"),
    size: str = typer.Option(..., "--size", help="C sizeof in bytes (decimal or hex)"),
    native_size: str = typer.Option(..., "--native-size", help="Evidenced native extent in bytes"),
    evidence: str = typer.Option(
        ..., "--evidence", help="Native allocation/stride and instance evidence"
    ),
    extent: str = typer.Option(
        "allocation", "--extent", help="Native extent kind: allocation or stride"
    ),
    fields: list[str] = typer.Option(
        [], "--field", help="Compiler-check member=offset (repeatable; no bitfields)"
    ),
    cflags: str | None = typer.Option(
        None, "--cflags", help="Compile flags; defaults to target flags"
    ),
    dry_run: bool = typer.Option(False, "--dry-run", help="Preview changes without writing"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
    target: str | None = TargetOption,
) -> None:
    """Bind a type to a target layout after sizeof/offsetof compiler checks."""
    from rebrew.type_metadata import bind_type

    cfg = require_config(target=target, json_mode=json_output)
    try:
        offsets: dict[str, int] = {}
        for field in fields:
            name, offset = field.split("=", 1)
            if name in offsets:
                raise ValueError(f"duplicate member offset {name!r}")
            offsets[name] = int(offset, 0)
        report = bind_type(
            cfg,
            identity,
            file,
            symbol,
            int(size, 0),
            int(native_size, 0),
            extent,
            evidence,
            offsets,
            cflags=cflags,
            dry_run=dry_run,
        )
    except (OSError, ValueError) as exc:
        error_exit(str(exc), json_mode=json_output)
    if json_output:
        json_print(report)
    else:
        console.print(
            f"{'Would bind' if dry_run else 'Bound'} {identity}:{report['module']} → {report['file']}:{symbol}"
        )


def main_entry() -> None:
    """Run the Typer CLI application."""
    from rebrew.cli import run_cli

    run_cli(app)


@app.command(
    "apply",
    epilog=(
        "[bold]Examples:[/bold]\n\n"
        "  rebrew types apply 0x401000 --param 0 --type int --dry-run\n\n"
        "Preview the parameter type edit, then test affected functions."
    ),
)
def apply_type(
    target_ident: str = typer.Argument(..., metavar="source", help=SOURCE_HELP),
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
    # Re-applying the same type is a converged no-op, not an error.
    changed = rewritten != text
    if changed and not dry_run:
        atomic_write_text(source_path, rewritten, encoding=encoding)
    if json_output:
        json_print(
            {
                "file": str(source_path),
                "function": func_name,
                "param": param,
                "type": type_name,
                "changed": changed,
                "dry_run": dry_run,
            }
        )
        return
    where = f"{source_path.name} {func_name} param {param}"
    if not changed:
        console.print(f"  [dim]Unchanged:[/dim] {where} is already {type_name}")
    elif dry_run:
        console.print(f"  [dim]Would rewrite[/dim] {where} → {type_name}")
    else:
        console.print(f"[green]Rewrote:[/green] {where} → {type_name}")


def _first_function_name(text: str) -> str:
    from rebrew.c_parser import iter_function_name_and_proto

    names = [name for name, _proto in iter_function_name_and_proto(text)]
    return names[0] if names else ""


@app.command(
    "contracts",
    epilog="[bold]Examples:[/bold]\n\n  rebrew types contracts --name queue --all-targets --json",
)
def contracts_cmd(
    name: str | None = typer.Option(
        None, "--name", help="Audit one C name; defaults to every declaration"
    ),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
    target: str | None = TargetOption,
    all_targets: bool = typer.Option(
        False, "--all-targets", help="Audit every configured target independently"
    ),
) -> None:
    """Audit C declaration contracts separately from native byte matches."""
    from rebrew.cli import all_targets_run
    from rebrew.source_contracts import audit_contracts

    if all_targets_run(
        target=target,
        all_targets=all_targets,
        json_mode=json_output,
        run_one=lambda selected: contracts_cmd(
            name=name, json_output=json_output, target=selected, all_targets=False
        ),
    ):
        return
    cfg = require_config(target=target, json_mode=json_output)
    try:
        report = audit_contracts(cfg, name=name)
    except (OSError, ValueError) as exc:
        error_exit(str(exc), json_mode=json_output)
    if json_output:
        json_print(report)
    else:
        console.print(report)
    if report["unknown"] or any(f["severity"] == "error" for f in report["findings"]):
        raise typer.Exit(1)


@app.command(
    "reconcile",
    epilog="[bold]Examples:[/bold]\n\n  rebrew types reconcile queue api.h --prototype 'int queue(void)' --dry-run",
)
def reconcile_cmd(
    name: str = typer.Argument(..., help="C function name to reconcile across every target"),
    header: Path = typer.Argument(..., help="Existing canonical subsystem header"),
    prototype: str = typer.Option(..., "--prototype", help="Complete reviewed C prototype"),
    expected_digest: str | None = typer.Option(
        None, "--expected-digest", help="Require input digest from a reviewed preview"
    ),
    dry_run: bool = typer.Option(False, "--dry-run", help="Preview changes without writing"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
) -> None:
    """Reconcile one reviewed signature and enumerate all caller verification contexts."""
    from rebrew.config import load_config
    from rebrew.rename_ops import RenameError
    from rebrew.source_contracts import reconcile_contract
    from rebrew.workspace.config import read_config, targets_table

    cfg = require_config(json_mode=json_output)
    try:
        configs = [
            load_config(target=target_name, root=cfg.root)
            for target_name in targets_table(read_config(cfg.root))
        ]
        report = reconcile_contract(
            configs or [cfg],
            name,
            header,
            prototype,
            dry_run=dry_run,
            expected_digest=expected_digest,
        )
    except (OSError, ValueError, RenameError) as exc:
        error_exit(str(exc), json_mode=json_output)
    if json_output:
        json_print(report)
    else:
        console.print(report)


if __name__ == "__main__":
    main_entry()
