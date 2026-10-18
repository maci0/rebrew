"""ghidra/cli.py — Sync rebrew annotations with Ghidra via the BinSync state dir.

Field-level sync (names, comments/notes, prototypes, structs, globals) is
**BinSync-primary**: ``rebrew sync push --state-dir D``
exports the annotations to the shared state dir and ``sync pull`` imports it
back; the BinSync Ghidra plugin (or a collaborator's tool) relays the state
to and from Ghidra.  Structural Ghidra operations BinSync cannot express stay
on ReVa MCP: ``sync create-functions``, ``sync bookmarks``, ``sync pull-data``.

``sync pull --create-functions`` chains the two: functions imported from the
state dir are created in Ghidra via MCP, so "add a function to the state →
it appears in Ghidra" works with no external plugin.
"""

import contextlib
import io
import json
import logging
import sys
from pathlib import Path
from typing import Any, override

import typer

from rebrew.cli import (
    CREATE_MISSING_HELP,
    EXIT_ERROR,
    TargetOption,
    console,
    error_exit,
    json_print,
    require_config,
    run_cli,
)
from rebrew.config import ConfigError, inventory_path_for, validate_http_url
from rebrew.ghidra.client import DEFAULT_MCP_ENDPOINT
from rebrew.ghidra.commands import (
    build_bookmark_commands,
    build_new_function_commands,
    resolve_program_path,
    validate_program_path,
)
from rebrew.ghidra.commands import (
    pull_data as pull_data_cmd,
)

log = logging.getLogger(__name__)

app = typer.Typer(
    help="Exchange metadata with Ghidra through BinSync and perform structural operations.",
    rich_markup_mode="rich",
    epilog=(
        "[bold]Examples:[/bold]\n\n"
        "  rebrew sync summary --state-dir ./state\n\n"
        "  rebrew sync push --state-dir ./state\n\n"
        "  rebrew sync pull --state-dir ./state\n\n"
        "  rebrew sync create-functions --dry-run\n\n"
        "  rebrew sync bookmarks --dry-run\n\n"
        "[dim]push/pull exchange names, prototypes, comments, types, and globals through a local BinSync state directory. The BinSync Ghidra plugin relays that state. create-functions, bookmarks, and pull-data use the configured structural backend. Use rebrew binsync for Git-backed collaboration.[/dim]\n\n"
    ),
)


def _require_state_dir(state_dir: Path | None, json_output: bool) -> Path:
    if state_dir is None:
        error_exit(
            "This operation requires --state-dir <dir> or a configured binsync_state_dir",
            json_mode=json_output,
        )
    return state_dir


def _probe_program_path(endpoint: str, program_path: str, json_output: bool) -> str:
    """Validate the MCP program path (best-effort) — refuse when MCP is down."""
    import httpx

    from rebrew.ghidra.client import end_mcp_session, init_mcp_session

    try:
        with httpx.Client(timeout=10.0) as probe_client:
            session = init_mcp_session(probe_client, endpoint)
            try:
                return validate_program_path(probe_client, endpoint, program_path, session)
            finally:
                end_mcp_session(probe_client, endpoint, session)
    except (httpx.HTTPError, OSError, RuntimeError, ValueError) as exc:
        detail = str(exc).strip() or type(exc).__name__
        error_exit(
            f"MCP unreachable at {endpoint} ({detail}) — cannot apply Ghidra operations",
            json_mode=json_output,
        )


class _JsonCapture(io.StringIO):
    """Stdout stand-in that records one compact JSON document."""

    @override
    def isatty(self) -> bool:
        return False


def _load_captured_json(text: str) -> dict[str, Any]:
    stripped = text.strip()
    if not stripped:
        return {}
    payload = json.loads(stripped)
    if not isinstance(payload, dict):
        return {}
    return payload


def _mcp_apply(
    ops: list[dict[str, Any]],
    endpoint: str,
    program_path: str,
    json_output: bool,
    cfg: Any = None,
    *,
    report: bool = True,
) -> tuple[int, int]:
    """Apply *ops* and report (success, error) counts.

    ReVa MCP is the default transport; when the config names ``ghidra_backend
    = "cli"`` (or MCP is unreachable), the ghidra-cli binary backend applies
    the same structural ops — the no-MCP escape hatch for the ops that remain.

    A completed apply with ``errors > 0`` keeps the progress document and
    exits ``EXIT_ERROR``. ``report=False`` returns the counts so a caller can
    fold them into one document.
    """
    if not ops:
        if report:
            if json_output:
                json_print({"applied": 0, "errors": 0, "operations": 0})
            else:
                console.print("[dim]No operations to apply.[/dim]")
        return 0, 0

    def _report(ok: int, err: int) -> tuple[int, int]:
        if report:
            if json_output:
                json_print({"applied": ok, "errors": err, "operations": len(ops)})
            else:
                console.print(f"[green]Applied {ok} operation(s)[/green]")
                if err:
                    console.print(f"[red]{err} error(s)[/red]")
            if err:
                raise typer.Exit(code=EXIT_ERROR)
        return ok, err

    def _apply_cli() -> tuple[int, int]:
        from rebrew.ghidra.cli_backend import apply_commands_via_cli, resolve_ghidra_cli

        ghidra_cli = resolve_ghidra_cli(cfg) or "ghidra-cli"
        return apply_commands_via_cli(ops, program=program_path, ghidra_cli=ghidra_cli)

    if cfg is not None and getattr(cfg, "ghidra_backend", "reva") == "cli":
        return _report(*_apply_cli())

    from rebrew.ghidra.client import McpApplyAborted, McpError, apply_commands_via_mcp

    try:
        ok, err = apply_commands_via_mcp(ops, endpoint)
    except McpApplyAborted as exc:
        # The transport died after earlier ops landed (or the failed op may
        # have landed server-side): re-running the full list via the CLI
        # backend would duplicate them.  Error with the progress instead —
        # only a clean transport failure (nothing applied) falls back.
        detail = str(exc).strip() or type(exc).__name__
        error_exit(
            f"MCP apply aborted mid-loop ({detail}) — "
            f"{exc.applied} of {len(ops)} op(s) may have been applied; "
            "not re-applying via ghidra-cli to avoid duplicates. "
            "Re-run once Ghidra state is confirmed.",
            json_mode=json_output,
        )
    except (McpError, OSError) as exc:
        # Clean transport failure (init/session setup — nothing applied):
        # fall back to the ghidra-cli binary backend.  The transport that
        # actually applied the ops changed, so say so where the operator reads
        # the run: at debug level the fallback is invisible in a -v run.
        log.warning("MCP apply failed before any op landed (%s); falling back to ghidra-cli", exc)
        if not json_output:
            console.print(
                f"[yellow]warning:[/yellow] MCP unavailable ({exc}); "
                "applying via ghidra-cli instead"
            )
        return _report(*_apply_cli())
    return _report(ok, err)


def _preview_ops(ops: list[dict[str, Any]], json_output: bool) -> None:
    """Report the operations a dry run would apply, without touching Ghidra."""
    if json_output:
        json_print({"dry_run": True, "operations": len(ops)})
        return
    console.print(f"[dim]Would apply {len(ops)} operation(s).[/dim]")


def execute_sync(
    state_dir: Path | None = None,
    push: bool = False,
    pull: bool = False,
    create_functions: bool = False,
    bookmarks: bool = False,
    pull_data: bool = False,
    summary: bool = False,
    watch: bool = False,
    accept_binsync: bool = False,
    accept_local: bool = False,
    create_missing: bool = False,
    endpoint: str = DEFAULT_MCP_ENDPOINT,
    dry_run: bool = False,
    json_output: bool = False,
    target: str | None = None,
) -> None:
    """Sync annotations with Ghidra via the BinSync state dir (+ MCP structural ops)."""
    if not (push or pull or create_functions or bookmarks or pull_data or summary or watch):
        error_exit(
            "No operation specified. Use sync push/pull (with --state-dir), "
            "create-functions, bookmarks, pull-data, summary or watch",
            json_mode=json_output,
        )
    if accept_binsync and accept_local:
        error_exit(
            "--accept-binsync and --accept-local are mutually exclusive", json_mode=json_output
        )
    if push and pull:
        error_exit("sync push and sync pull are mutually exclusive", json_mode=json_output)
    if watch and json_output:
        error_exit(
            "sync watch does not support JSON output; omit -o json to monitor changes",
            json_mode=True,
        )
    if watch and not push:
        error_exit("watch requires an export operation", json_mode=json_output)

    try:
        endpoint = validate_http_url(endpoint, "--endpoint")
    except ConfigError as exc:
        error_exit(str(exc), json_mode=json_output)

    cfg = require_config(target=target, json_mode=json_output)

    # ``ghidra_backend = "cli"`` executes the structural ops through the
    # ghidra-cli subprocess, so probing MCP first would refuse the run the
    # config asks to make without MCP.  ``--pull-data`` is MCP-only either way.
    cli_backend = getattr(cfg, "ghidra_backend", "reva") == "cli"
    needs_mcp = pull_data or not cli_backend

    # --state-dir defaults to the configured binsync_state_dir (if any).
    if state_dir is None:
        configured = getattr(cfg, "binsync_state_dir", "") or ""
        if configured:
            state_dir = Path(configured).expanduser()

    # --- BinSync field sync ---
    if push or summary or pull:
        from rebrew.binsync.serial import require_declib

        require_declib(json_mode=json_output)
    if push or summary:
        out = _require_state_dir(state_dir, json_output)
        from rebrew.binsync.export import export_state, print_export_result

        preview = dry_run or summary
        result = export_state(cfg, out, dry_run=preview)
        print_export_result(result, json_output=json_output, dry_run=preview)
        if watch and not dry_run:
            from rebrew.binsync.state import sync_watch_paths
            from rebrew.utils import watch_files

            watch_paths = sync_watch_paths(cfg, out)

            def _re_export() -> None:
                fresh = export_state(cfg, out, dry_run=False)
                print_export_result(fresh, json_output=False, dry_run=False)

            watch_files(watch_paths, _re_export, path_provider=lambda: sync_watch_paths(cfg, out))
        return

    if pull:
        src = _require_state_dir(state_dir, json_output)
        from rebrew.binsync.importer import import_from_repo, print_import_result

        result = import_from_repo(
            cfg,
            src,
            user=None,
            dry_run=dry_run,
            json_output=json_output,
            accept_binsync=accept_binsync,
            accept_local=accept_local,
            create_missing=create_missing,
        )
        chain_json = bool(create_functions and json_output)
        import_doc: dict[str, Any] | None = None
        if chain_json:
            captured = _JsonCapture()
            try:
                with contextlib.redirect_stdout(captured):
                    print_import_result(result, json_output=True, dry_run=dry_run)
            except typer.Exit:
                text = captured.getvalue()
                if text:
                    sys.stdout.write(text if text.endswith("\n") else text + "\n")
                raise
            import_doc = _load_captured_json(captured.getvalue())
        else:
            print_import_result(result, json_output=json_output, dry_run=dry_run)
        if create_functions:
            from typing import cast

            touched = sorted(int(v) for v in cast(list[Any], result.get("touched_vas") or []))
            if touched:
                program_path = resolve_program_path(cfg)
                ops = [
                    {
                        "tool": "create-function",
                        "args": {"programPath": program_path, "address": f"0x{va:08X}"},
                    }
                    for va in touched
                ]
                if dry_run:
                    creation = {"dry_run": True, "operations": len(ops)}
                    if not chain_json:
                        _preview_ops(ops, json_output)
                else:
                    if needs_mcp:
                        program_path = _probe_program_path(endpoint, program_path, json_output)
                    ok, err = _mcp_apply(
                        ops,
                        endpoint,
                        program_path,
                        json_output,
                        cfg,
                        report=not chain_json,
                    )
                    creation = {"applied": ok, "errors": err, "operations": len(ops)}
            else:
                creation = (
                    {"dry_run": True, "operations": 0}
                    if dry_run
                    else {"applied": 0, "errors": 0, "operations": 0}
                )
                if not json_output:
                    console.print("[dim]Nothing imported. No functions to create.[/dim]")
            if chain_json and import_doc is not None:
                import_doc["create_functions"] = creation
                json_print(import_doc)
                if creation.get("errors"):
                    raise typer.Exit(code=EXIT_ERROR)
        return

    # --- MCP structural ops ---
    program_path = resolve_program_path(cfg)
    # A dry run only previews the ops: it must not POST them, and it must not
    # require Ghidra to be reachable.  Neither may the ghidra-cli backend,
    # which never speaks MCP.
    if not dry_run and needs_mcp:
        program_path = _probe_program_path(endpoint, program_path, json_output)

    # Both structural ops may be requested in one run; the ops are collected
    # so a dry run previews them together instead of printing twice.
    structural_ops: list[dict[str, Any]] = []

    if create_functions:
        from rebrew.catalog import build_function_registry, cached_function_list

        funcs = cached_function_list(cfg)
        registry = build_function_registry(
            funcs, cfg, inventory_path_for(cfg.reversed_dir, cfg), cfg.target_binary
        )
        structural_ops += build_new_function_commands(
            registry, program_path, iat_thunks=set(cfg.iat_thunks)
        )

    if bookmarks:
        from rebrew.catalog import scan_reversed_dir

        entries = [
            e if isinstance(e, dict) else e.to_dict()
            for e in scan_reversed_dir(cfg.reversed_dir, cfg=cfg)
        ]
        structural_ops += build_bookmark_commands(entries, program_path)

    if create_functions or bookmarks:
        if dry_run:
            _preview_ops(structural_ops, json_output)
        elif structural_ops:
            _mcp_apply(structural_ops, endpoint, program_path, json_output, cfg)
        elif json_output:
            json_print({"applied": 0, "errors": 0, "operations": 0})
        else:
            console.print("[dim]No operations to apply.[/dim]")

    if pull_data:
        pull_data_cmd(cfg, endpoint, program_path, dry_run, json_output=json_output)
        return


@app.command(
    "push",
    epilog=(
        "[bold]Examples:[/bold]\n\n"
        "  rebrew sync push --state-dir ./state --dry-run --json\n\n"
        "Export local fields without committing or publishing Git changes. Use rebrew binsync push for Git-backed collaboration."
    ),
)
def push(
    state_dir: Path | None = typer.Option(
        None, "--state-dir", help="BinSync state directory (default: configured binsync_state_dir)"
    ),
    dry_run: bool = typer.Option(False, "--dry-run", help="Preview changes without writing"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
    target: str | None = TargetOption,
) -> None:
    """Export fields to a local BinSync state directory."""
    execute_sync(
        state_dir=state_dir, dry_run=dry_run, json_output=json_output, target=target, push=True
    )


@app.command(
    "pull",
    epilog=(
        "[bold]Examples:[/bold]\n\n"
        "  rebrew sync pull --state-dir ./state --dry-run --json\n\n"
        "Import available local state without fetching Git. Add --create-functions to create accepted functions in Ghidra."
    ),
)
def pull(
    state_dir: Path | None = typer.Option(
        None, "--state-dir", help="BinSync state directory (default: configured binsync_state_dir)"
    ),
    accept_binsync: bool = typer.Option(
        False, "--accept-binsync", help="Accept BinSync names on pull conflicts"
    ),
    accept_local: bool = typer.Option(
        False, "--accept-local", help="Keep local names on pull conflicts (records provenance)"
    ),
    create_missing: bool = typer.Option(
        False,
        "--create-missing",
        help=CREATE_MISSING_HELP,
    ),
    create_functions: bool = typer.Option(
        False,
        "--create-functions",
        help="Create the imported functions in Ghidra through MCP",
    ),
    endpoint: str = typer.Option(DEFAULT_MCP_ENDPOINT, "--endpoint", help="ReVa MCP endpoint URL"),
    dry_run: bool = typer.Option(False, "--dry-run", help="Preview changes without writing"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
    target: str | None = TargetOption,
) -> None:
    """Import fields and optionally create the accepted functions."""
    execute_sync(
        state_dir=state_dir,
        accept_binsync=accept_binsync,
        accept_local=accept_local,
        create_missing=create_missing,
        create_functions=create_functions,
        endpoint=endpoint,
        dry_run=dry_run,
        json_output=json_output,
        target=target,
        pull=True,
    )


@app.command(
    "summary",
    epilog=(
        "[bold]Examples:[/bold]\n\n"
        "  rebrew sync summary --state-dir ./state --json\n\n"
        "Preview outgoing local fields without writing. Use rebrew binsync summary to preview both synchronization directions."
    ),
)
def summary(
    state_dir: Path | None = typer.Option(
        None, "--state-dir", help="BinSync state directory (default: configured binsync_state_dir)"
    ),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
    target: str | None = TargetOption,
) -> None:
    """Preview local field export without writing."""
    execute_sync(state_dir=state_dir, json_output=json_output, target=target, summary=True)


def _context_requests_json(ctx: typer.Context | None) -> bool:
    """True when a parent ``-o json`` / ``--output json`` selected JSON.

    Typer keeps that value on its own click context, not the standalone click
    stack, so the command context has to be passed in.
    """
    current: Any = ctx
    while current is not None:
        params = current.params or {}
        if "output_format" in params and params["output_format"] is not None:
            return str(params["output_format"]) == "json"
        current = current.parent
    return False


@app.command(
    "watch",
    epilog=(
        "[bold]Examples:[/bold]\n\n"
        "  rebrew sync watch --state-dir ./state\n\n"
        "Watch exports local field changes until interrupted. This continuous human-readable monitor does not support --json."
    ),
)
def watch(
    ctx: typer.Context,
    state_dir: Path | None = typer.Option(
        None, "--state-dir", help="BinSync state directory (default: configured binsync_state_dir)"
    ),
    target: str | None = TargetOption,
) -> None:
    """Watch sources and export changes until interrupted."""
    execute_sync(
        state_dir=state_dir,
        json_output=_context_requests_json(ctx),
        target=target,
        push=True,
        watch=True,
    )


@app.command(
    "create-functions",
    epilog=(
        "[bold]Examples:[/bold]\n\n"
        "  rebrew sync create-functions --dry-run --json\n\n"
        "Preview discovered functions missing from Ghidra before creating them through the configured structural backend."
    ),
)
def create_functions(
    endpoint: str = typer.Option(DEFAULT_MCP_ENDPOINT, "--endpoint", help="ReVa MCP endpoint URL"),
    dry_run: bool = typer.Option(False, "--dry-run", help="Preview changes without writing"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
    target: str | None = TargetOption,
) -> None:
    """Create missing functions through the configured structural backend."""
    execute_sync(
        endpoint=endpoint,
        dry_run=dry_run,
        json_output=json_output,
        target=target,
        create_functions=True,
    )


@app.command(
    "bookmarks",
    epilog=(
        "[bold]Examples:[/bold]\n\n"
        "  rebrew sync bookmarks --dry-run --json\n\n"
        "Preview status bookmarks before applying them through the configured structural backend."
    ),
)
def bookmarks(
    endpoint: str = typer.Option(DEFAULT_MCP_ENDPOINT, "--endpoint", help="ReVa MCP endpoint URL"),
    dry_run: bool = typer.Option(False, "--dry-run", help="Preview changes without writing"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
    target: str | None = TargetOption,
) -> None:
    """Apply status bookmarks through the structural backend."""
    execute_sync(
        endpoint=endpoint, dry_run=dry_run, json_output=json_output, target=target, bookmarks=True
    )


@app.command(
    "pull-data",
    epilog=(
        "[bold]Examples:[/bold]\n\n"
        "  rebrew sync pull-data --dry-run --json\n\n"
        "Fetch data labels through ReVa MCP and generate rebrew_globals.h. Use --dry-run to preview the header."
    ),
)
def pull_data(
    endpoint: str = typer.Option(DEFAULT_MCP_ENDPOINT, "--endpoint", help="ReVa MCP endpoint URL"),
    dry_run: bool = typer.Option(False, "--dry-run", help="Preview changes without writing"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
    target: str | None = TargetOption,
) -> None:
    """Import Ghidra data labels through MCP."""
    execute_sync(
        endpoint=endpoint, dry_run=dry_run, json_output=json_output, target=target, pull_data=True
    )


def main_entry() -> None:
    """Run the Typer CLI application."""
    run_cli(app)


if __name__ == "__main__":
    main_entry()
