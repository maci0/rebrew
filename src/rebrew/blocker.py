"""blocker.py – Programmatic BLOCKER management for rebrew-function.toml.

Every BLOCKER/BLOCKER_DELTA write must go through the metadata store
(``rebrew.metadata``) under ``metadata_write_lock`` + ``atomic_write_text`` —
never by hand-editing the TOML.  This CLI is that gate.

Other writers exist: ``rebrew diff --fix-blocker``, ``rebrew near-diag
--fix-blocker``, and ``rebrew document-unmatched``.  This command covers the
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
from rich.console import Console

from rebrew.cli import TargetOption, error_exit, json_print, parse_va, require_config

console = Console(stderr=True)

_EPILOG = (
    "[bold]Examples:[/bold]\n\n"
    '  rebrew blocker set 0x401000 "needs RE structs" · · · Set BLOCKER by VA\n\n'
    '  rebrew blocker set src/game/foo.c "SEH helper" · · Target by file\n\n'
    "  rebrew blocker clear src/game/foo.c · · · · · · · · Clear BLOCKER (+ delta)\n\n"
    "  rebrew blocker show 0x401000 --json · · · · · · · · Show BLOCKER metadata\n\n"
    "[dim]Writes go through rebrew.metadata (locked + atomic). "
    "Auto-classified blockers use `rebrew diff --fix-blocker` or "
    "`rebrew near-diag --fix-blocker` instead.[/dim]"
)

app = typer.Typer(
    help="Manage BLOCKER metadata in rebrew-function.toml (programmatic only).",
    rich_markup_mode="rich",
    epilog=_EPILOG,
)


def _resolve_target(
    cfg: Any,
    target: str,
    va_override: str | None,
    json_mode: bool,
) -> tuple[str, int]:
    """Resolve TARGET (+ optional --va) to (module, va_int).

    Accepts file path, hex VA (0x...), or symbol (file stem). Mirrors the
    VA selection in near_diag.main so multi-function files require
    disambiguation via --va instead of silently picking the first annotation.
    """
    from rebrew.annotation import parse_c_file_multi
    from rebrew.cli import resolve_source_arg
    from rebrew.sources import target_marker

    va_from_flag = va_override is not None
    va_int: int | None = parse_va(va_override, json_mode=json_mode) if va_override else None

    raw = target
    # Check if positional itself is a hex VA before resolving through sources.
    if va_int is None and re.match(r"^0[xX][0-9a-fA-F]+$", raw.strip()):
        va_int = parse_va(raw.strip(), json_mode=json_mode)
        # Bare VA without a file — module comes from config marker.
        module = getattr(cfg, "marker", "") or ""
        if not module:
            # Fall back to first marker-like config, or require --target that has one.
            error_exit(
                "Cannot determine module for bare VA — pass a file path or set a marker",
                json_mode=json_mode,
            )
        if va_int is not None:
            return module, va_int

    resolved = str(resolve_source_arg(cfg, raw))
    source_path = Path(resolved).resolve()
    # If still not a file, treat as unresolved symbol/VA lookup failure.
    if not source_path.is_file():
        # Allow bare symbol that resolve_source_arg may have returned as Path
        # even when not found — try metadata lookup with cfg.marker?
        # Fail with actionable message instead of writing to wrong key.
        error_exit(
            f"Cannot resolve target {raw!r} to a source file or VA "
            "(pass a .c path, 0xVA, symbol, or use --va 0x... to disambiguate)",
            json_mode=json_mode,
        )

    annos = parse_c_file_multi(
        source_path, target_name=target_marker(cfg), metadata_dir=cfg.metadata_dir
    )
    if not annos:
        error_exit(f"No annotations found in {source_path.name}", json_mode=json_mode)

    if va_int is None:
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
        if not matched and va_from_flag:
            # Explicit --va override: file's compile settings still intended,
            # but the VA itself is the requested target (covers stub files
            # where the annotation VA won't match the override).
            pass

    if va_from_flag and va_int is not None:
        # Use the explicit VA as target; keep module from matched ann if any,
        # else from first annotation.
        return ann.module or getattr(cfg, "marker", "") or "", va_int

    return ann.module, int(ann.va)


@app.command("set")
def blocker_set(
    target: str = typer.Argument(..., help="C source file, symbol, or hex VA (0x...)"),
    blocker: str = typer.Argument(..., help="BLOCKER text to write"),
    delta: str | None = typer.Option(
        None, "--delta", help="BLOCKER_DELTA as integer (decimal or 0x hex)"
    ),
    va: str | None = typer.Option(
        None, "--va", help="Disambiguate VA in a multi-function file (hex, e.g. 0x401000)"
    ),
    dry_run: bool = typer.Option(False, "--dry-run", help="Preview changes without writing"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
    target_name: str | None = TargetOption,
) -> None:
    """Set BLOCKER (and optional BLOCKER_DELTA) for a function."""
    cfg = require_config(target=target_name, json_mode=json_output)
    if not blocker.strip():
        error_exit("BLOCKER text must be non-empty", json_mode=json_output)
    delta_int: int | None = None
    if delta is not None:
        try:
            delta_int = int(delta.strip(), 0)
        except (ValueError, TypeError):
            error_exit(
                f"Invalid --delta value: {delta!r} (expected integer)", json_mode=json_output
            )
    module, va_int = _resolve_target(cfg, target, va, json_output)

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

    from rebrew.metadata import update_field

    update_field(cfg.metadata_dir, va_int, "blocker", blocker, module=module)
    if delta_int is not None:
        update_field(cfg.metadata_dir, va_int, "blocker_delta", delta_int, module=module)

    if json_output:
        payload["written"] = True
        json_print(payload)
    else:
        msg = f"Set BLOCKER for {module} 0x{va_int:08x}"
        if delta_int is not None:
            msg += f" (delta {delta_int})"
        console.print(f"[green]{msg}[/green]")


@app.command("clear")
def blocker_clear(
    target: str = typer.Argument(..., help="C source file, symbol, or hex VA (0x...)"),
    va: str | None = typer.Option(
        None, "--va", help="Disambiguate VA in a multi-function file (hex)"
    ),
    dry_run: bool = typer.Option(False, "--dry-run", help="Preview changes without writing"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
    target_name: str | None = TargetOption,
) -> None:
    """Clear BLOCKER and BLOCKER_DELTA for a function."""
    cfg = require_config(target=target_name, json_mode=json_output)
    module, va_int = _resolve_target(cfg, target, va, json_output)

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

    from rebrew.metadata import remove_field

    cleared_b = remove_field(cfg.metadata_dir, va_int, "blocker", module=module)
    cleared_d = remove_field(cfg.metadata_dir, va_int, "blocker_delta", module=module)
    cleared = bool(cleared_b or cleared_d)

    if json_output:
        json_print(
            {"module": module, "va": f"0x{va_int:08x}", "cleared": cleared, "dry_run": False}
        )
    else:
        if cleared:
            console.print(f"[green]Cleared BLOCKER for {module} 0x{va_int:08x}[/green]")
        else:
            console.print(f"[dim]No BLOCKER to clear for {module} 0x{va_int:08x}[/dim]")


@app.command("show")
def blocker_show(
    target: str = typer.Argument(..., help="C source file, symbol, or hex VA (0x...)"),
    va: str | None = typer.Option(
        None, "--va", help="Disambiguate VA in a multi-function file (hex)"
    ),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
    target_name: str | None = TargetOption,
) -> None:
    """Show BLOCKER metadata for a function."""
    cfg = require_config(target=target_name, json_mode=json_output)
    module, va_int = _resolve_target(cfg, target, va, json_output)

    from rebrew.metadata import get_entry

    entry = get_entry(cfg.metadata_dir, va_int, module)
    blocker_val = entry.get("blocker", "")
    delta_val = entry.get("blocker_delta", None)

    if json_output:
        json_print(
            {
                "module": module,
                "va": f"0x{va_int:08x}",
                "blocker": blocker_val,
                "blocker_delta": delta_val,
            }
        )
        return

    if blocker_val:
        console.print(f"[bold]{module} 0x{va_int:08x}[/bold] BLOCKER: {blocker_val}")
        if delta_val is not None:
            console.print(f"  BLOCKER_DELTA: {delta_val}")
    else:
        console.print(f"[dim]No BLOCKER for {module} 0x{va_int:08x}[/dim]")


def main_entry() -> None:
    """Run the Typer CLI application."""
    app()


if __name__ == "__main__":
    main_entry()
