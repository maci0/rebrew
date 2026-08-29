"""ghidra/cli.py — Sync rebrew annotations with Ghidra via the BinSync state dir.

Field-level sync (names, comments/notes, prototypes, structs, globals) is
**BinSync-primary** (metadata-review R1): ``rebrew sync --push --state-dir D``
exports the annotations to the shared state dir and ``--pull`` imports it
back; the BinSync Ghidra plugin (or a collaborator's tool) relays the state
to and from Ghidra.  Structural Ghidra operations BinSync cannot express stay
on ReVa MCP: ``--create-functions``, ``--bookmarks``, ``--pull-data``.

``--pull --create-functions`` chains the two: functions imported from the
state dir are created in Ghidra via MCP, so "add a function to the state →
it appears in Ghidra" works with no external plugin.
"""

import logging
from pathlib import Path
from typing import Any

import typer
from rich.console import Console

from rebrew.cli import TargetOption, error_exit, json_print, require_config
from rebrew.ghidra.commands import (
    build_bookmark_commands,
    build_new_function_commands,
    resolve_program_path,
    validate_program_path,
)
from rebrew.ghidra.commands import (
    pull_data as pull_data_cmd,
)
from rebrew.sources import iter_sources

console = Console(stderr=True)
log = logging.getLogger(__name__)

app = typer.Typer(
    help="Sync rebrew annotations with Ghidra (BinSync state dir + MCP structural ops).",
    rich_markup_mode="rich",
    epilog=(
        "[bold]Examples:[/bold]\n\n"
        "  rebrew sync --push --state-dir ./state · · · · · · Export to the BinSync state\n\n"
        "  rebrew sync --pull --state-dir ./state · · · · · · Import the state into rebrew\n\n"
        "  rebrew sync --pull --state-dir ./state --create-functions\n"
        "                                            · · · Import + create functions in Ghidra\n\n"
        "  rebrew sync --create-functions · · · · · · · · · Create missing functions (MCP)\n\n"
        "  rebrew sync --bookmarks · · · · · · · · · · · · · Set status bookmarks (MCP)\n\n"
        "  rebrew sync --pull-data · · · · · · · · · · · · · Pull data labels (MCP)\n\n"
        "[dim]Field sync (names/comments/prototypes/structs/globals) is BinSync-primary;\n"
        "the BinSync Ghidra plugin relays the state to Ghidra.  MCP remains for the\n"
        "structural ops (function creation, bookmarks, data pulls).[/dim]"
    ),
)


def _require_state_dir(state_dir: Path | None, json_output: bool) -> Path:
    if state_dir is None:
        error_exit(
            "--push/--pull require --state-dir <dir> (the BinSync state directory)",
            json_mode=json_output,
        )
    return state_dir


def _probe_program_path(cfg: Any, endpoint: str, program_path: str, json_output: bool) -> str:
    """Validate the MCP program path (best-effort) — refuse when MCP is down."""
    import httpx

    from rebrew.ghidra.client import init_mcp_session

    try:
        with httpx.Client(timeout=10.0) as probe_client:
            session = init_mcp_session(probe_client, endpoint)
            return validate_program_path(probe_client, endpoint, program_path, session)
    except (httpx.HTTPError, OSError, RuntimeError, ValueError) as exc:
        detail = str(exc).strip() or type(exc).__name__
        error_exit(
            f"MCP unreachable at {endpoint} ({detail}) — cannot apply Ghidra operations",
            json_mode=json_output,
        )


def _mcp_apply(ops: list[dict[str, Any]], endpoint: str, json_output: bool) -> None:
    """Apply *ops* via ReVa MCP and report (success, error) counts."""
    from rebrew.ghidra.client import apply_commands_via_mcp

    if not ops:
        if not json_output:
            console.print("[dim]No operations to apply.[/dim]")
        return
    ok, err = apply_commands_via_mcp(ops, endpoint)
    if json_output:
        json_print({"applied": ok, "errors": err, "operations": len(ops)})
        return
    console.print(f"[green]Applied {ok} operation(s)[/green]")
    if err:
        console.print(f"[red]{err} error(s)[/red]")


@app.callback(invoke_without_command=True)
def main(
    state_dir: Path | None = typer.Option(
        None, "--state-dir", help="BinSync state directory (for --push/--pull)"
    ),
    push: bool = typer.Option(False, "--push", help="Export annotations to the BinSync state dir"),
    pull: bool = typer.Option(False, "--pull", help="Import the BinSync state dir into rebrew"),
    create_functions: bool = typer.Option(
        False,
        "--create-functions",
        help="Create functions in Ghidra (MCP); with --pull, creates the imported VAs",
    ),
    bookmarks: bool = typer.Option(
        False, "--bookmarks", help="Set status bookmarks in Ghidra (MCP)"
    ),
    pull_data: bool = typer.Option(
        False, "--pull-data", help="Pull data labels from Ghidra into rebrew_globals.h (MCP)"
    ),
    summary: bool = typer.Option(False, "--summary", help="Preview the push without writing"),
    watch: bool = typer.Option(
        False, "--watch", help="Watch sources and re-push to the state dir on change"
    ),
    accept_binsync: bool = typer.Option(
        False, "--accept-binsync", help="Accept BinSync names on pull conflicts"
    ),
    accept_local: bool = typer.Option(
        False, "--accept-local", help="Keep local names on pull conflicts (records provenance)"
    ),
    create_missing: bool = typer.Option(
        False, "--create-missing", help="Create STUB files for BinSync functions not in the catalog"
    ),
    endpoint: str = typer.Option(
        "http://localhost:8080/mcp/message", "--endpoint", help="ReVa MCP endpoint URL"
    ),
    dry_run: bool = typer.Option(False, "--dry-run", help="Preview changes without writing"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
    target: str | None = TargetOption,
) -> None:
    """Sync annotations with Ghidra via the BinSync state dir (+ MCP structural ops)."""
    if not (push or pull or create_functions or bookmarks or pull_data or summary or watch):
        error_exit(
            "No action specified. Available: --push/--pull (with --state-dir), "
            "--create-functions, --bookmarks, --pull-data, --summary",
            json_mode=json_output,
        )
    if accept_binsync and accept_local:
        error_exit(
            "--accept-binsync and --accept-local are mutually exclusive", json_mode=json_output
        )
    if push and pull:
        error_exit("--push and --pull are mutually exclusive", json_mode=json_output)
    if watch and not (push and state_dir is not None):
        error_exit("--watch requires --push --state-dir <dir>", json_mode=json_output)

    cfg = require_config(target=target, json_mode=json_output)

    # --- BinSync field sync ---
    if push or summary:
        out = _require_state_dir(state_dir, json_output)
        from rebrew.binsync_export import _print_export_result, export_state

        preview = dry_run or summary
        result = export_state(cfg, out, dry_run=preview, json_output=json_output)
        _print_export_result(result, json_output=json_output, dry_run=preview)
        if watch and not dry_run:
            from rebrew.utils import watch_files

            watch_paths = list(iter_sources(cfg.reversed_dir, cfg)) + [
                cfg.metadata_dir / "rebrew-functions.toml"
            ]

            def _re_export() -> None:
                fresh = export_state(cfg, out, dry_run=False, json_output=False)
                _print_export_result(fresh, json_output=False, dry_run=False)

            watch_files(watch_paths, _re_export)
        return

    if pull:
        src = _require_state_dir(state_dir, json_output)
        from rebrew.binsync_import import _print_import_result, import_state

        result = import_state(
            cfg,
            src,
            dry_run=dry_run,
            json_output=json_output,
            accept_binsync=accept_binsync,
            accept_local=accept_local,
            create_missing=create_missing,
        )
        _print_import_result(result, json_output=json_output, dry_run=dry_run)
        if create_functions and not dry_run:
            from typing import cast

            touched = sorted(int(v) for v in cast(list[Any], result.get("touched_vas") or []))
            if touched:
                program_path = resolve_program_path(cfg)
                _probe_program_path(cfg, endpoint, program_path, json_output)
                ops = [
                    {
                        "tool": "create-function",
                        "args": {"programPath": program_path, "address": f"0x{va:08X}"},
                        "_meta": {"reason": "imported from BinSync state"},
                    }
                    for va in touched
                ]
                _mcp_apply(ops, endpoint, json_output)
            elif not json_output:
                console.print("[dim]Nothing imported — no functions to create.[/dim]")
        return

    # --- MCP structural ops ---
    program_path = resolve_program_path(cfg)
    _probe_program_path(cfg, endpoint, program_path, json_output)

    if create_functions:
        from rebrew.catalog import build_function_registry, parse_function_list
        from rebrew.config import FUNCTION_STRUCTURE_JSON

        funcs = (
            list(parse_function_list(cfg.function_list))
            if cfg.function_list and Path(cfg.function_list).exists()
            else []
        )
        registry = build_function_registry(
            funcs, cfg, cfg.reversed_dir / FUNCTION_STRUCTURE_JSON, cfg.target_binary
        )
        ops = build_new_function_commands(registry, program_path, iat_thunks=set(cfg.iat_thunks))
        _mcp_apply(ops, endpoint, json_output)
        return

    if bookmarks:
        from rebrew.catalog import scan_reversed_dir

        entries = [
            e if isinstance(e, dict) else e.to_dict()
            for e in scan_reversed_dir(cfg.reversed_dir, cfg=cfg)
        ]
        ops = build_bookmark_commands(entries, program_path)
        _mcp_apply(ops, endpoint, json_output)
        return

    if pull_data:
        pull_data_cmd(cfg, endpoint, program_path, dry_run)
        return


def main_entry() -> None:
    """Run the Typer CLI application."""
    app()


if __name__ == "__main__":
    main_entry()
