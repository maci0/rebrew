"""blocker.py – Programmatic BLOCKER management for rebrew-functions.toml.

Every BLOCKER/BLOCKER_DELTA write must go through the metadata store
(``rebrew.metadata.functions``) under ``metadata_write_lock`` + ``atomic_write_locked`` —
never by hand-editing the TOML.  This CLI is that gate.

Other writers exist: ``rebrew diff --fix-blocker``, ``rebrew diagnose near
--fix-blocker``, and ``rebrew source document-unmatched``.  This command covers the
ad-hoc case: a human documenting a STUB/NEAR_MATCHING function whose block
is not auto-classifiable (needs RE structs, SEH helper, reference-source
library, etc.).

Usage::

    rebrew blocker set 0x401000 "needs RE structs -- see struct_recover"
    rebrew blocker set src/client/foo.c "SEH helper -- not matchable from C"
    rebrew blocker clear src/client/foo.c
    rebrew blocker show 0x401000 --json
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import typer

from rebrew.cli import (
    SOURCE_HELP,
    TargetOption,
    console,
    error_exit,
    json_print,
    parse_va,
    require_config,
)
from rebrew.config import module_marker
from rebrew.metadata.bindings import min_valid_va_for

_EPILOG = (
    "[bold]Examples:[/bold]\n\n"
    '  rebrew blocker set 0x401000 "needs recovered structs"\n\n'
    "  rebrew blocker show src/game/foo.c --json\n\n"
    "  rebrew blocker clear src/game/foo.c\n\n"
    "[dim]BLOCKER and optional BLOCKER_DELTA are stored in rebrew-functions.toml through locked writers. For a blocker derived from byte differences, use rebrew diff --fix-blocker or rebrew diagnose near --fix-blocker.[/dim]\n\n"
)

app = typer.Typer(
    help="Record, inspect, and clear function blockers in dedicated metadata.",
    rich_markup_mode="rich",
    epilog=_EPILOG,
)


def resolve_function(
    cfg: Any,
    function: str,
    va_override: str | None,
    json_mode: bool,
) -> tuple[str, int]:
    """Resolve FUNCTION (+ optional --va) to (module, va_int).

    Accepts file path, hex VA (0x...), or symbol (file stem). Mirrors the
    VA selection in near_diag.main so multi-function files require
    disambiguation via --va instead of silently picking the first annotation.
    """
    from rebrew.cli import resolve_source_arg
    from rebrew.metadata.bindings import read_source_bindings
    from rebrew.sources import target_marker

    va_from_flag = va_override is not None
    va_int: int | None = parse_va(va_override, json_mode=json_mode) if va_override else None

    raw = function
    # Check if positional itself is a hex VA before resolving through sources.
    if va_int is None and re.match(r"^0[xX][0-9a-fA-F]+$", raw.strip()):
        va_int = parse_va(raw.strip(), json_mode=json_mode)
        # Bare VA without a file — module comes from config marker.
        module = module_marker(cfg)
        if not module:
            error_exit(
                "Cannot determine module for bare VA — pass a file path or set a marker",
                json_mode=json_mode,
            )
        # The floor is per-target: 16-bit targets address code from segment 0,
        # so VA 0 names a real function there.
        if va_int < min_valid_va_for(cfg):
            error_exit(f"VA must be at least 0x{min_valid_va_for(cfg):x}", json_mode=json_mode)
        return module, va_int

    resolved = str(resolve_source_arg(cfg, raw))
    source_path = Path(resolved).resolve()
    # If still not a file, treat as unresolved symbol/VA lookup failure.
    if not source_path.is_file():
        # Allow bare symbol that resolve_source_arg may have returned as Path
        # even when not found — try metadata lookup with cfg.marker?
        # Fail with actionable message instead of writing to wrong key.
        error_exit(
            f"Cannot resolve function {raw!r} to a source file or VA "
            "(pass a .c path, 0xVA, symbol, or use --va 0x... to disambiguate)",
            json_mode=json_mode,
        )

    annos = read_source_bindings(
        source_path, target_name=target_marker(cfg), metadata_dir=cfg.metadata_dir
    )
    if not annos:
        error_exit(f"No annotations found in {source_path.name}", json_mode=json_mode)

    if va_int is None:
        if len(annos) > 1:
            vas = ", ".join(f"0x{a.va:08x}" for a in annos)
            error_exit(
                f"{source_path.name} covers {len(annos)} functions ({vas}) — "
                "pass --va 0x… to pick one",
                json_mode=json_mode,
            )
        va_int = annos[0].va
        ann = annos[0]
    else:
        ann = annos[0]
        matched = False
        for cand in annos:
            if cand.va == va_int:
                ann = cand
                matched = True
                break
        if not matched and not va_from_flag:
            error_exit(
                f"No annotation for VA 0x{va_int:08x} in {source_path.name} — "
                "the file covers different functions (pass --va 0x… to override)",
                json_mode=json_mode,
            )
        # An explicit --va that matches no annotation falls through on
        # purpose: the file's compile settings still apply, but the VA is the
        # requested target (covers stub files whose annotation VA differs).

    if va_int is not None and va_int < min_valid_va_for(cfg):
        error_exit(f"VA must be at least 0x{min_valid_va_for(cfg):x}", json_mode=json_mode)

    if va_from_flag and va_int is not None:
        # Use the explicit VA as target; keep module from matched ann if any,
        # else from first annotation.
        return ann.module or module_marker(cfg), va_int

    return ann.module, int(ann.va)


@app.command(
    "set",
    epilog=(
        '[bold]Examples:[/bold]\n\n  rebrew blocker set 0x401000 "compiler mismatch" --dry-run\n\n'
    ),
)
def blocker_set(
    function: str = typer.Argument(..., help=SOURCE_HELP),
    blocker: str = typer.Argument(..., help="BLOCKER text to write"),
    delta: str | None = typer.Option(
        None, "--delta", help="BLOCKER_DELTA as integer (decimal or 0x hex)"
    ),
    va: str | None = typer.Option(
        None, "--va", help="Disambiguate VA in a multi-function file (hex)"
    ),
    dry_run: bool = typer.Option(False, "--dry-run", help="Preview changes without writing"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
    target_name: str | None = TargetOption,
) -> None:
    """Set BLOCKER (and optional BLOCKER_DELTA) for a function."""
    cfg = require_config(target=target_name, json_mode=json_output)
    if not blocker.strip():
        error_exit("BLOCKER text must be non-empty", json_mode=json_output)
    if len(blocker) > 2000:
        error_exit("BLOCKER text too long (max 2000 chars)", json_mode=json_output)
    if "\n" in blocker or "\r" in blocker:
        error_exit("BLOCKER text must be a single line", json_mode=json_output)
    delta_int: int | None = None
    if delta is not None:
        try:
            delta_int = int(delta.strip(), 0)
        except (ValueError, TypeError):
            error_exit(
                f"Invalid --delta value: {delta!r} (expected integer)", json_mode=json_output
            )
        # metadata.model.MetadataEntry.problems() flags blocker_delta < 0 as
        # invalid; todo consumes it as a byte delta, so a negative value
        # would render as "−5B diff — try flag sweep".
        if delta_int < 0:
            error_exit(f"Invalid --delta value: {delta!r} (must be >= 0)", json_mode=json_output)
    module, va_int = resolve_function(cfg, function, va, json_output)

    payload: dict[str, Any] = {
        "module": module,
        "va": f"0x{va_int:08x}",
        "blocker": blocker,
        "dry_run": dry_run,
    }
    if delta_int is not None:
        payload["blocker_delta"] = delta_int

    if dry_run:
        if json_output:
            payload["written"] = False
            json_print(payload)
        else:
            extra = f" + delta {delta_int}" if delta_int is not None else ""
            console.print(
                f"[dim]Would set BLOCKER for {module} 0x{va_int:08x}:[/dim] {blocker}{extra}"
            )
        return

    from rebrew.metadata.functions import set_fields

    fields: dict[str, object] = {"blocker": blocker}
    if delta_int is not None:
        fields["blocker_delta"] = delta_int
    set_fields(cfg.metadata_dir, va_int, fields, module=module, updated_by="blocker")

    if json_output:
        payload["written"] = True
        json_print(payload)
    else:
        msg = f"Set BLOCKER for {module} 0x{va_int:08x}"
        if delta_int is not None:
            msg += f" (delta {delta_int})"
        console.print(f"[green]{msg}[/green]")


@app.command(
    "clear",
    epilog=("[bold]Examples:[/bold]\n\n  rebrew blocker clear 0x401000 --dry-run\n\n"),
)
def blocker_clear(
    function: str = typer.Argument(..., help=SOURCE_HELP),
    va: str | None = typer.Option(
        None, "--va", help="Disambiguate VA in a multi-function file (hex)"
    ),
    dry_run: bool = typer.Option(False, "--dry-run", help="Preview changes without writing"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
    target_name: str | None = TargetOption,
) -> None:
    """Clear BLOCKER and BLOCKER_DELTA for a function."""
    cfg = require_config(target=target_name, json_mode=json_output)
    module, va_int = resolve_function(cfg, function, va, json_output)

    if dry_run:
        payload: dict[str, Any] = {
            "module": module,
            "va": f"0x{va_int:08x}",
            "dry_run": True,
            "cleared": False,
        }
        if json_output:
            json_print(payload)
        else:
            console.print(f"[dim]Would clear BLOCKER for {module} 0x{va_int:08x}[/dim]")
        return

    from rebrew.metadata.functions import remove_field

    cleared_b = remove_field(cfg.metadata_dir, va_int, "blocker", module=module)
    cleared_d = remove_field(cfg.metadata_dir, va_int, "blocker_delta", module=module)
    cleared = bool(cleared_b or cleared_d)

    if json_output:
        json_print(
            {"module": module, "va": f"0x{va_int:08x}", "cleared": cleared, "dry_run": False}
        )
    elif cleared:
        console.print(f"[green]Cleared BLOCKER for {module} 0x{va_int:08x}[/green]")
    else:
        console.print(f"[dim]No BLOCKER to clear for {module} 0x{va_int:08x}[/dim]")


@app.command(
    "show",
    epilog=("[bold]Examples:[/bold]\n\n  rebrew blocker show 0x401000 --json\n\n"),
)
def blocker_show(
    function: str = typer.Argument(..., help=SOURCE_HELP),
    va: str | None = typer.Option(
        None, "--va", help="Disambiguate VA in a multi-function file (hex)"
    ),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
    target_name: str | None = TargetOption,
) -> None:
    """Show BLOCKER metadata for a function."""
    cfg = require_config(target=target_name, json_mode=json_output)
    module, va_int = resolve_function(cfg, function, va, json_output)

    from rebrew.metadata.functions import get_entry

    entry = get_entry(cfg.metadata_dir, va_int, module)
    blocker_val = entry.get("blocker", "")
    delta_val = entry.get("blocker_delta", None)
    # Provenance is written by every gated writer; reporting it here is what
    # makes the pair answer a question instead of sitting in the TOML.
    updated_by = str(entry.get("updated_by") or "")
    updated_at = str(entry.get("updated_at") or "")

    if json_output:
        json_print(
            {
                "module": module,
                "va": f"0x{va_int:08x}",
                "blocker": blocker_val,
                "blocker_delta": delta_val,
                "updated_by": updated_by,
                "updated_at": updated_at,
            }
        )
        return

    if blocker_val:
        console.print(f"[bold]{module} 0x{va_int:08x}[/bold] BLOCKER: {blocker_val}")
        if delta_val is not None:
            console.print(f"  BLOCKER_DELTA: {delta_val}")
    else:
        console.print(f"[dim]No BLOCKER for {module} 0x{va_int:08x}[/dim]")
    if updated_by or updated_at:
        stamp = " ".join(part for part in (updated_by, updated_at) if part)
        console.print(f"  [dim]last write: {stamp}[/dim]")


def main_entry() -> None:
    """Run the Typer CLI application."""
    from rebrew.cli import run_cli

    run_cli(app)


if __name__ == "__main__":
    main_entry()
