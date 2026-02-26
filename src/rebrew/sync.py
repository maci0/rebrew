#!/usr/bin/env python3
"""Sync annotations between reversed source .c files and Ghidra.

Reads annotations from decomp C source files and generates Ghidra script
commands to rename functions, add comments, and set bookmarks via ReVa MCP.

Usage:
    rebrew-sync --export    Export annotations to ghidra_commands.json
    rebrew-sync --summary   Show what would be synced
    rebrew-sync --apply     Apply ghidra_commands.json to Ghidra via ReVa MCP

The exported JSON can be consumed by automation that calls ReVa MCP tools:
  - create-function: define functions at annotated VAs (before labeling)
  - create-label: rename functions at their VA
  - set-comment: add annotation metadata as plate comments
  - set-bookmark: bookmark matched functions for tracking
"""

import json
import re
import sys
import time
from typing import Any

import typer

from rebrew.catalog import (
    build_function_registry,
    parse_r2_functions,
    scan_reversed_dir,
)
from rebrew.cli import TargetOption, get_config

# Pattern matching generic auto-names that shouldn't overwrite Ghidra renames
_GENERIC_NAME_RE = re.compile(r"^(func_|FUN_)[0-9a-fA-F]+$")

# Status → bookmark category prefix for visual distinction
_STATUS_BOOKMARK_CATEGORY = {
    "EXACT": "rebrew/exact",
    "RELOC": "rebrew/reloc",
    "MATCHING": "rebrew/matching",
    "MATCHING_RELOC": "rebrew/matching",
    "STUB": "rebrew/stub",
}


def _is_generic_name(name: str) -> bool:
    """Return True if *name* is a default auto-generated name like func_10006c00."""
    return bool(_GENERIC_NAME_RE.match(name))


def build_sync_commands(
    entries: list[dict[str, Any]],
    program_path: str,
    *,
    skip_generic_labels: bool = True,
    create_functions: bool = False,
    iat_thunks: set[int] | None = None,
) -> list[dict[str, Any]]:
    by_va: dict[int, list[dict[str, Any]]] = {}
    for e in entries:
        by_va.setdefault(e["va"], []).append(e)

    commands: list[dict[str, Any]] = []
    skipped_labels = 0
    thunk_set = iat_thunks or set()

    # Phase 1: create-function for all annotated VAs (before labels/comments)
    if create_functions:
        for va in sorted(by_va.keys()):
            if va in thunk_set:
                continue
            va_hex = f"0x{va:08X}"
            commands.append(
                {
                    "tool": "create-function",
                    "args": {
                        "programPath": program_path,
                        "address": va_hex,
                    },
                }
            )

    # Phase 2: labels, comments, bookmarks
    for va in sorted(by_va.keys()):
        elist = by_va[va]
        primary = elist[0]
        va_hex = f"0x{va:08X}"
        name = primary["name"]
        status = primary["status"]

        # Only push labels that carry actual information
        if skip_generic_labels and _is_generic_name(name):
            skipped_labels += 1
        else:
            commands.append(
                {
                    "tool": "create-label",
                    "args": {
                        "programPath": program_path,
                        "addressOrSymbol": va_hex,
                        "labelName": name,
                    },
                }
            )

        comment_lines = [
            f"[rebrew] {primary['marker_type']}: {status}",
            f"Origin: {primary['origin']}",
            f"Size: {primary['size']}B",
            f"CFlags: {primary['cflags']}",
            f"Symbol: {primary['symbol']}",
            f"Files: {', '.join(e['filepath'] for e in elist)}",
        ]
        commands.append(
            {
                "tool": "set-comment",
                "args": {
                    "programPath": program_path,
                    "addressOrSymbol": va_hex,
                    "comment": "\n".join(comment_lines),
                    "commentType": "plate",
                },
            }
        )

        bm_category = _STATUS_BOOKMARK_CATEGORY.get(status, primary["origin"].lower())
        bm_comment = f"{name} - {status} ({primary['size']}B, {primary['cflags']})"
        commands.append(
            {
                "tool": "set-bookmark",
                "args": {
                    "programPath": program_path,
                    "addressOrSymbol": va_hex,
                    "type": "Analysis",
                    "category": bm_category,
                    "comment": bm_comment,
                },
            }
        )

    if skipped_labels > 0:
        print(f"  Skipped {skipped_labels} generic labels (func_XXXXXXXX)")

    return commands


def apply_commands_via_mcp(
    commands: list[dict[str, Any]],
    endpoint: str = "http://localhost:8080/mcp/message",
) -> tuple[int, int]:
    """Apply sync commands to Ghidra via ReVa MCP Streamable HTTP.

    Returns (success_count, error_count).
    """
    try:
        import httpx
    except ImportError:
        print(
            "ERROR: httpx is required for --apply. Install with: uv pip install httpx",
            file=sys.stderr,
        )
        raise typer.Exit(code=1)

    success = 0
    errors = 0
    total = len(commands)

    with httpx.Client(timeout=30.0) as client:
        # Initialize MCP session
        init_payload = {
            "jsonrpc": "2.0",
            "id": 0,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-03-26",
                "capabilities": {},
                "clientInfo": {"name": "rebrew-sync", "version": "1.0.0"},
            },
        }
        try:
            resp = client.post(
                endpoint,
                json=init_payload,
                headers={
                    "Accept": "application/json, text/event-stream",
                    "Content-Type": "application/json",
                },
            )
            resp.raise_for_status()
        except httpx.HTTPError as exc:
            print(f"ERROR: Failed to initialize MCP session: {exc}", file=sys.stderr)
            raise typer.Exit(code=1)

        # Extract session ID from response header
        session_id = resp.headers.get("mcp-session-id", "")
        if not session_id:
            # Try to parse from SSE response body
            body = resp.text
            # Some servers return session ID in the JSON response
            try:
                data = json.loads(body)
                session_id = data.get("sessionId", "")
            except ValueError:
                pass

        if not session_id:
            print("WARNING: No session ID received, proceeding without one")

        headers = {
            "Accept": "application/json, text/event-stream",
            "Content-Type": "application/json",
        }
        if session_id:
            headers["mcp-session-id"] = session_id

        # Send initialized notification
        client.post(
            endpoint,
            json={"jsonrpc": "2.0", "method": "notifications/initialized"},
            headers=headers,
        )

        # Apply each command
        current_phase = ""
        for i, cmd in enumerate(commands):
            # Show phase transitions
            tool = cmd["tool"]
            if tool != current_phase:
                if current_phase:
                    print()  # newline after previous phase progress
                phase_labels = {
                    "create-function": "Creating functions",
                    "create-label": "Setting labels",
                    "set-comment": "Adding comments",
                    "set-bookmark": "Adding bookmarks",
                }
                print(f"  {phase_labels.get(tool, tool)}...")
                current_phase = tool

            payload = {
                "jsonrpc": "2.0",
                "id": i + 1,
                "method": "tools/call",
                "params": {"name": cmd["tool"], "arguments": cmd["args"]},
            }

            try:
                resp = client.post(endpoint, json=payload, headers=headers)
                resp.raise_for_status()
                success += 1
            except httpx.HTTPError as exc:
                errors += 1
                va = cmd["args"].get("addressOrSymbol", cmd["args"].get("address", "?"))
                if errors <= 5:
                    print(f"  ERROR at {va} ({cmd['tool']}): {exc}")
                elif errors == 6:
                    print("  ... suppressing further errors")

            # Progress indicator
            if (i + 1) % 50 == 0 or i == total - 1:
                pct = (i + 1) * 100 // total
                print(f"  [{pct:3d}%] {i + 1}/{total} operations applied", end="\r")

            # Rate limiting — don't overwhelm the server
            if (i + 1) % 100 == 0:
                time.sleep(0.1)

    print()  # newline after progress
    return success, errors


def build_size_sync_commands(
    registry: dict[int, dict[str, Any]],
    program_path: str,
    iat_thunks: set[int] | None = None,
) -> list[dict[str, Any]]:
    """Generate commands to expand function boundaries in Ghidra where r2 > ghidra."""
    commands: list[dict[str, Any]] = []
    thunk_set = iat_thunks or set()

    for va, entry in sorted(registry.items()):
        if va in thunk_set:
            continue
        sizes = entry.get("size_by_tool", {})
        ghidra_size = sizes.get("ghidra", 0)
        canonical = entry.get("canonical_size", 0)
        if canonical <= 0 or ghidra_size <= 0:
            continue
        if canonical <= ghidra_size:
            continue

        va_hex = f"0x{va:08X}"
        # Re-create function at VA to trigger Ghidra re-analysis of boundaries
        commands.append(
            {
                "tool": "create-function",
                "args": {
                    "programPath": program_path,
                    "address": va_hex,
                },
                "_meta": {
                    "reason": entry.get("size_reason", ""),
                    "ghidra_size": ghidra_size,
                    "canonical_size": canonical,
                },
            }
        )

    return commands


def build_new_function_commands(
    registry: dict[int, dict[str, Any]],
    program_path: str,
    iat_thunks: set[int] | None = None,
) -> list[dict[str, Any]]:
    """Generate create-function commands for functions r2 found but Ghidra missed."""
    commands: list[dict[str, Any]] = []
    thunk_set = iat_thunks or set()

    for va, entry in sorted(registry.items()):
        if va in thunk_set:
            continue
        detected = entry.get("detected_by", [])
        if "r2" in detected and "ghidra" not in detected:
            canonical = entry.get("canonical_size", 0)
            if canonical <= 0:
                continue
            va_hex = f"0x{va:08X}"
            commands.append(
                {
                    "tool": "create-function",
                    "args": {
                        "programPath": program_path,
                        "address": va_hex,
                    },
                    "_meta": {
                        "reason": "r2 only (not in Ghidra)",
                        "r2_size": entry.get("size_by_tool", {}).get("r2", 0),
                    },
                }
            )

    return commands


app = typer.Typer(
    help="Sync annotations between decomp C files and Ghidra.",
    rich_markup_mode="rich",
    epilog="""\
[bold]Examples:[/bold]
  rebrew-sync --export                   Export annotations to ghidra_commands.json
  rebrew-sync --summary                  Show what would be synced (dry run)
  rebrew-sync --apply                    Apply ghidra_commands.json via ReVa MCP

[bold]Typical workflow:[/bold]
  1. rebrew-sync --summary               Preview changes
  2. rebrew-sync --export                Generate JSON command file
  3. rebrew-sync --apply                 Push to Ghidra via ReVa MCP

[bold]What it syncs:[/bold]
  Function renames, status comments, bookmarks, and origin labels
  from .c annotation headers to Ghidra via ReVa MCP tools.

[dim]The exported JSON uses ReVa MCP format: create-label, set-comment,
set-bookmark. Requires Ghidra + ReVa extension running.[/dim]""",
)


@app.callback(invoke_without_command=True)
def main(
    export: bool = typer.Option(False, help="Export Ghidra commands to ghidra_commands.json"),
    summary: bool = typer.Option(False, help="Show sync summary without exporting"),
    apply: bool = typer.Option(False, help="Apply ghidra_commands.json to Ghidra via ReVa MCP"),
    push: bool = typer.Option(False, help="Export and apply in one step"),
    create_functions: bool = typer.Option(
        True, help="Prepend create-function ops for all annotated VAs (skips IAT thunks)"
    ),
    skip_generic: bool = typer.Option(
        True, help="Skip pushing generic func_XXXXXXXX labels (default: True)"
    ),
    sync_sizes: bool = typer.Option(
        False, "--sync-sizes", help="Push corrected function sizes to Ghidra (expand boundaries)"
    ),
    sync_new_functions: bool = typer.Option(
        False,
        "--sync-new-functions",
        help="Create functions in Ghidra that r2 found but Ghidra missed",
    ),
    endpoint: str = typer.Option("http://localhost:8080/mcp/message", help="ReVa MCP endpoint URL"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
    target: str | None = TargetOption,
) -> None:
    """Sync annotation data between decomp C files and Ghidra."""
    if not (summary or export or apply or push or sync_sizes or sync_new_functions):
        print("No action specified. Use --summary, --export, --apply, or --push.")
        raise typer.Exit(code=1)

    cfg = get_config(target=target)
    reversed_dir = cfg.reversed_dir
    program_path = f"/{cfg.target_binary.name}"

    entries = scan_reversed_dir(reversed_dir, cfg=cfg)
    by_va: dict[int, list[dict[str, Any]]] = {}
    for e in entries:
        by_va.setdefault(e["va"], []).append(e)

    iat_thunk_set: set[int] = set(getattr(cfg, "iat_thunks", []))

    # Build commands once (reused by --summary, --export, --push)
    ops: list[dict[str, Any]] | None = None

    if summary or export or push:
        ops = build_sync_commands(
            entries,
            program_path,
            skip_generic_labels=skip_generic,
            create_functions=create_functions,
            iat_thunks=iat_thunk_set,
        )

    if summary:
        if ops is None:  # pragma: no cover — guarded by branch above
            raise typer.Exit(code=1)
        by_origin: dict[str, list[dict[str, Any]]] = {}
        for e in entries:
            by_origin.setdefault(e["origin"], []).append(e)

        create_fns = [o for o in ops if o["tool"] == "create-function"]
        labels = [o for o in ops if o["tool"] == "create-label"]
        comments = [o for o in ops if o["tool"] == "set-comment"]
        bookmarks = [o for o in ops if o["tool"] == "set-bookmark"]

        if json_output:
            print(
                json.dumps(
                    {
                        "entries": len(entries),
                        "unique_vas": len(by_va),
                        "by_origin": {k: len(v) for k, v in sorted(by_origin.items())},
                        "operations": {
                            "create_function": len(create_fns),
                            "create_label": len(labels),
                            "set_comment": len(comments),
                            "set_bookmark": len(bookmarks),
                            "total": len(ops),
                        },
                    },
                    indent=2,
                )
            )
        else:
            print(f"Annotations: {len(entries)} entries, {len(by_va)} unique VAs")
            for origin in sorted(by_origin):
                print(f"  {origin}: {len(by_origin[origin])}")
            print(f"If exported, would generate {len(ops)} operations:")
            if create_fns:
                print(f"  - Create {len(create_fns)} functions (create-function)")
            print(f"  - Set {len(labels)} labels (create-label)")
            print(f"  - Add {len(comments)} plate comments (set-comment)")
            print(f"  - Add {len(bookmarks)} bookmarks (set-bookmark)")
            print(f"  Total: {len(ops)} operations")

    if export or push:
        if ops is None:  # pragma: no cover — guarded by branch above
            raise typer.Exit(code=1)
        out_path = cfg.root / "ghidra_commands.json"
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(ops, f, indent=2)
        print(f"Exported {len(ops)} operations to {out_path}")

    if apply or push:
        cmds_path = cfg.root / "ghidra_commands.json"
        if not cmds_path.exists():
            print(f"ERROR: {cmds_path} not found. Run --export first.", file=sys.stderr)
            raise typer.Exit(code=1)
        try:
            with open(cmds_path, encoding="utf-8") as f:
                commands = json.load(f)
        except (json.JSONDecodeError, OSError) as exc:
            print(f"ERROR: Failed to read {cmds_path}: {exc}", file=sys.stderr)
            raise typer.Exit(code=1)
        print(f"Applying {len(commands)} operations to Ghidra via {endpoint}...")
        ok, errs = apply_commands_via_mcp(commands, endpoint=endpoint)
        print(f"Done: {ok} succeeded, {errs} failed")
        if errs > 0:
            raise typer.Exit(code=1)

    if sync_sizes or sync_new_functions:
        # Build registry to compare r2 vs ghidra sizes
        r2_path = reversed_dir / "r2_functions.txt"
        ghidra_json_path = reversed_dir / "ghidra_functions.json"
        bin_path = cfg.target_binary

        r2_funcs = parse_r2_functions(r2_path)
        registry = build_function_registry(r2_funcs, cfg, ghidra_json_path, bin_path)

        all_cmds: list[dict[str, Any]] = []

        if sync_sizes:
            size_cmds = build_size_sync_commands(registry, program_path, iat_thunk_set)
            print(f"Size sync: {len(size_cmds)} functions need boundary expansion")
            for cmd in size_cmds:
                meta = cmd.pop("_meta", {})
                print(
                    f"  {cmd['args']['address']}: "
                    f"{meta.get('ghidra_size', '?')} → {meta.get('canonical_size', '?')} "
                    f"({meta.get('reason', '')})"
                )
            all_cmds.extend(size_cmds)

        if sync_new_functions:
            new_cmds = build_new_function_commands(registry, program_path, iat_thunk_set)
            print(f"New functions: {len(new_cmds)} r2-only functions to create in Ghidra")
            for cmd in new_cmds:
                meta = cmd.pop("_meta", {})
                print(f"  {cmd['args']['address']}: r2 size {meta.get('r2_size', '?')}")
            all_cmds.extend(new_cmds)

        if all_cmds:
            out_path = cfg.root / "ghidra_size_commands.json"
            with open(out_path, "w", encoding="utf-8") as f:
                json.dump(all_cmds, f, indent=2)
            print(f"Exported {len(all_cmds)} operations to {out_path}")

            if push:
                print(f"Applying {len(all_cmds)} size operations via {endpoint}...")
                ok, errs = apply_commands_via_mcp(all_cmds, endpoint=endpoint)
                print(f"Done: {ok} succeeded, {errs} failed")
                if errs > 0:
                    raise typer.Exit(code=1)


def main_entry() -> None:
    app()


if __name__ == "__main__":
    main_entry()
