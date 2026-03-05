import contextlib
import json
from typing import Any

import httpx
import typer

from rebrew.catalog import (
    build_function_registry,
    parse_function_list,
    scan_reversed_dir,
)
from rebrew.cli import TargetOption, error_exit, iter_sources, json_print, require_config
from rebrew.config import FUNCTION_STRUCTURE_JSON
from rebrew.ghidra.client import (
    _fetch_all_functions,
    _init_mcp_session,
    apply_commands_via_mcp,
)
from rebrew.ghidra.commands import (
    _is_generic_name,
    _pull_comments,
    _pull_data,
    _pull_prototypes,
    _pull_structs,
    _resolve_program_path,
    _validate_program_path,
    build_new_function_commands,
    build_size_sync_commands,
    build_sync_commands,
    pull_ghidra_renames,
)

app = typer.Typer(
    help="Sync annotations between decomp C files and Ghidra.",
    rich_markup_mode="rich",
    epilog="""\
[bold]Examples:[/bold]

rebrew sync --summary                  Show what would be synced (dry run)

rebrew sync --push                     Export + apply labels/comments to Ghidra

rebrew sync --push --dry-run           Preview push without applying

rebrew sync --pull                     Fetch Ghidra renames/comments into local files

rebrew sync --pull --dry-run           Preview pull without modifying files

rebrew sync --pull --json              Pull with structured JSON output

rebrew sync --export                   Generate ghidra_commands.json only

rebrew sync --apply                    Apply ghidra_commands.json via ReVa MCP

[bold]Typical workflow:[/bold]

1. rebrew sync --pull --dry-run         Preview incoming changes from Ghidra

2. rebrew sync --pull                   Apply Ghidra renames/comments locally

3. rebrew sync --summary               Preview outgoing changes to Ghidra

4. rebrew sync --push                   Push annotations to Ghidra

[bold]What it syncs:[/bold]

[bold]Push →[/bold] labels, plate comments, pre-comments (NOTE), bookmarks,
struct definitions (/rebrew DTM category), function prototypes,
DATA/GLOBAL labels, function sizes, new functions

[bold]Pull ←[/bold] function renames, data label names, plate/pre comments (as NOTE)

[bold]Safety:[/bold]

- Generic names (FUN_/DAT_/func_/switchdata) are never overwritten

- Conflicts (both sides have meaningful names) are reported, not overwritten

- [rebrew] plate comments are never pulled back (our own metadata)

- Use --dry-run to preview any operation before applying

[dim]Requires Ghidra + ReVa extension running for MCP operations.
Falls back to local JSON caches (ghidra_functions.json, ghidra_data_labels.json) when offline.[/dim]""",
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
    sync_data: bool = typer.Option(
        True,
        "--sync-data/--no-sync-data",
        help="Also push // DATA: and // GLOBAL: labels and bookmarks to Ghidra",
    ),
    sync_structs: bool = typer.Option(
        True,
        "--sync-structs/--no-sync-structs",
        help="Parse local C files for structs and push to Ghidra Data Type Manager",
    ),
    sync_signatures: bool = typer.Option(
        True,
        "--sync-signatures/--no-sync-signatures",
        help="Parse local C files for function prototypes and apply to Ghidra",
    ),
    pull: bool = typer.Option(
        False, "--pull", help="Pull function names from Ghidra and update local files"
    ),
    accept_ghidra: bool = typer.Option(
        False,
        "--accept-ghidra",
        help="Accept Ghidra names for all conflicts (with cross-ref updates)",
    ),
    accept_local: bool = typer.Option(
        False, "--accept-local", help="Keep local names for all conflicts (adds // GHIDRA:)"
    ),
    filter_origin: str = typer.Option(
        None, "--origin", help="Only apply pull updates to this origin (e.g. MSVCRT)"
    ),
    pull_signatures: bool = typer.Option(
        False, "--pull-signatures", help="Pull function prototypes from Ghidra and update externs"
    ),
    pull_structs: bool = typer.Option(
        False, "--pull-structs", help="Pull struct definitions from Ghidra into types.h"
    ),
    pull_comments: bool = typer.Option(
        False, "--pull-comments", help="Pull Ghidra analysis comments into source files"
    ),
    pull_data: bool = typer.Option(
        False, "--pull-data", help="Pull data labels from Ghidra and generate rebrew_globals.h"
    ),
    refresh_cache: bool = typer.Option(
        False,
        "--refresh-cache",
        help="Fetch all functions from Ghidra MCP and write function_structure.json",
    ),
    dry_run: bool = typer.Option(
        False,
        "--dry-run",
        help="Preview changes without modifying files (works with --pull and --push)",
    ),
    endpoint: str = typer.Option("http://localhost:8080/mcp/message", help="ReVa MCP endpoint URL"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
    target: str | None = TargetOption,
) -> None:
    """Sync annotation data between decomp C files and Ghidra."""
    if not (
        summary
        or export
        or apply
        or push
        or pull
        or sync_sizes
        or sync_new_functions
        or pull_signatures
        or pull_structs
        or pull_comments
        or pull_data
        or refresh_cache
    ):
        error_exit(
            "No action specified. Use --summary, --export, --apply, --push, --pull, or --refresh-cache."
        )

    cfg = require_config(target=target)
    reversed_dir = cfg.reversed_dir
    program_path = _resolve_program_path(cfg)

    entries_raw = scan_reversed_dir(reversed_dir, cfg=cfg)
    entries: list[dict[str, Any]] = [e if isinstance(e, dict) else e.to_dict() for e in entries_raw]

    if (
        push
        or pull
        or pull_signatures
        or pull_structs
        or pull_comments
        or pull_data
        or apply
        or refresh_cache
    ):
        try:
            with httpx.Client(timeout=10.0) as probe_client:
                probe_session = _init_mcp_session(probe_client, endpoint)
                program_path = _validate_program_path(
                    probe_client,
                    endpoint,
                    program_path,
                    probe_session,
                )
        except (httpx.HTTPError, OSError, RuntimeError, ValueError):
            pass

    if pull or pull_signatures or pull_structs or pull_comments or pull_data:
        if pull:
            pull_result = pull_ghidra_renames(
                entries,
                cfg,
                endpoint,
                program_path,
                dry_run=dry_run,
                json_output=json_output,
                accept_ghidra=accept_ghidra,
                accept_local=accept_local,
                filter_origin=filter_origin,
            )
            if pull_result.conflicts > 0 and not dry_run:
                print(
                    "Conflicts detected during name pull. Continuing with other pull operations if any."
                )

        if pull_signatures or pull_structs or pull_comments or pull_data:
            if pull_signatures:
                _pull_prototypes(entries, cfg, endpoint, program_path, dry_run)
            if pull_structs:
                _pull_structs(cfg, endpoint, program_path, dry_run)
            if pull_comments:
                _pull_comments(entries, cfg, endpoint, program_path, dry_run)
            if pull_data:
                _pull_data(cfg, endpoint, program_path, dry_run)

        return

    by_va: dict[int, list[dict[str, Any]]] = {}
    for e in entries:
        by_va.setdefault(e["va"], []).append(e)

    iat_thunk_set: set[int] = set(cfg.iat_thunks)

    data_scan = None
    if sync_data and (summary or export or push):
        from rebrew.data import scan_data_annotations, scan_globals

        data_scan = scan_globals(reversed_dir, cfg=cfg)
        data_scan.data_annotations = scan_data_annotations(reversed_dir, cfg=cfg)

    structs: list[str] | None = None
    signatures: list[dict[str, str]] | None = None

    if sync_structs or sync_signatures:
        if sync_structs and (summary or export or push):
            from rebrew.struct_parser import extract_structs_from_file, extract_type_definitions

            struct_set: set[str] = set()

            for hfile in sorted(reversed_dir.rglob("*.h")):
                # Skip auto-generated Ghidra files (types.h from --pull-structs)
                # — they use Ghidra notation that CParser rejects on push.
                if hfile.name == "types.h":
                    continue
                for typedef_str in extract_type_definitions(hfile):
                    struct_set.add(typedef_str)

            for cfile in iter_sources(reversed_dir, cfg):
                for struct_str in extract_structs_from_file(cfile):
                    struct_set.add(struct_str)

            structs = list(struct_set)

        if sync_signatures and (summary or export or push):
            from rebrew.signature_parser import extract_function_signatures

            # Map from function name (symbol) to VA, ignoring generic names.
            # Symbols use cdecl convention with leading underscore (e.g.
            # _AcceptConnections) while the C parser yields the bare name
            # (AcceptConnections).  Index both the raw symbol and the
            # stripped version so either form matches.
            name_to_va: dict[str, str] = {}
            for e in entries:
                if e.get("marker_type") in ("DATA", "GLOBAL"):
                    continue
                name = e.get("symbol") or e.get("name")
                if name and not _is_generic_name(name):
                    va_hex = f"0x{e['va']:08X}"
                    name_to_va[name] = va_hex
                    if name.startswith("_"):
                        name_to_va[name[1:]] = va_hex

            signatures = []
            for cfile in iter_sources(reversed_dir, cfg):
                for func_name, sig_str in extract_function_signatures(cfile):
                    if func_name in name_to_va:
                        signatures.append(
                            {
                                "va_hex": name_to_va[func_name],
                                "signature": sig_str,
                            }
                        )

    # Build commands once (reused by --summary, --export, --push)
    ops: list[dict[str, Any]] | None = None

    if summary or export or push:
        ops = build_sync_commands(
            entries,
            program_path,
            skip_generic_labels=skip_generic,
            create_functions=create_functions,
            iat_thunks=iat_thunk_set,
            data_scan=data_scan,
            structs=structs,
            signatures=signatures,
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
        structs_op = [o for o in ops if o["tool"] == "parse-c-structure"]
        sigs_op = [o for o in ops if o["tool"] == "set-function-prototype"]

        if json_output:
            json_print(
                {
                    "entries": len(entries),
                    "unique_vas": len(by_va),
                    "by_origin": {k: len(v) for k, v in sorted(by_origin.items())},
                    "operations": {
                        "create_function": len(create_fns),
                        "create_label": len(labels),
                        "set_comment": len(comments),
                        "set_bookmark": len(bookmarks),
                        "parse_c_structure": len(structs_op),
                        "set_function_prototype": len(sigs_op),
                        "total": len(ops),
                    },
                }
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
            if structs_op:
                print(f"  - Push {len(structs_op)} struct definitions (parse-c-structure)")
            if sigs_op:
                print(f"  - Set {len(sigs_op)} function prototypes (set-function-prototype)")
            print(f"  Total: {len(ops)} operations")

    if export or push:
        if ops is None:  # pragma: no cover — guarded by branch above
            raise typer.Exit(code=1)
        out_path = cfg.root / "ghidra_commands.json"
        with out_path.open("w", encoding="utf-8") as f:
            json.dump(ops, f, indent=2)
        print(f"Exported {len(ops)} operations to {out_path}")

    if apply or push:
        if dry_run:
            if ops is not None:
                print(f"Dry run: would apply {len(ops)} operations to Ghidra via {endpoint}")
            return
        cmds_path = cfg.root / "ghidra_commands.json"
        if not cmds_path.exists():
            error_exit(f"{cmds_path} not found. Run --export first.")
        try:
            with cmds_path.open(encoding="utf-8") as f:
                commands = json.load(f)
        except (json.JSONDecodeError, OSError) as exc:
            error_exit(f"Failed to read {cmds_path}: {exc}")
        print(f"Applying {len(commands)} operations to Ghidra via {endpoint}...")
        ok, errs = apply_commands_via_mcp(commands, endpoint=endpoint)
        print(f"Done: {ok} succeeded, {errs} failed")
        if errs > 0:
            raise typer.Exit(code=1)

    if refresh_cache:
        _refresh_structure_cache(cfg, endpoint, program_path, dry_run, json_output)

    if sync_sizes or sync_new_functions:
        # Build registry to compare function list vs ghidra sizes
        func_list_path = cfg.function_list
        ghidra_json_path = reversed_dir / FUNCTION_STRUCTURE_JSON
        bin_path = cfg.target_binary

        funcs = parse_function_list(func_list_path)
        registry = build_function_registry(funcs, cfg, ghidra_json_path, bin_path)

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
            print(f"New functions: {len(new_cmds)} list-only functions to create in Ghidra")
            for cmd in new_cmds:
                meta = cmd.pop("_meta", {})
                print(f"  {cmd['args']['address']}: list size {meta.get('list_size', '?')}")
            all_cmds.extend(new_cmds)

        if all_cmds:
            out_path = cfg.root / "ghidra_size_commands.json"
            with out_path.open("w", encoding="utf-8") as f:
                json.dump(all_cmds, f, indent=2)
            print(f"Exported {len(all_cmds)} operations to {out_path}")

            if push:
                print(f"Applying {len(all_cmds)} size operations via {endpoint}...")
                ok, errs = apply_commands_via_mcp(all_cmds, endpoint=endpoint)
                print(f"Done: {ok} succeeded, {errs} failed")
                if errs > 0:
                    raise typer.Exit(code=1)


def _refresh_structure_cache(
    cfg: Any,
    endpoint: str,
    program_path: str,
    dry_run: bool,
    json_output: bool,
) -> None:
    """Fetch all functions from Ghidra MCP and write function_structure.json.

    Uses an atomic write pattern (tmp file + rename) to avoid corruption.
    """
    import os
    import tempfile

    reversed_dir = cfg.reversed_dir
    out_path = reversed_dir / FUNCTION_STRUCTURE_JSON

    try:
        with httpx.Client(timeout=30.0) as client:
            session_id = _init_mcp_session(client, endpoint)
            print(f"Fetching functions from Ghidra ({program_path})...")
            raw_funcs = _fetch_all_functions(client, endpoint, program_path, session_id)
    except (httpx.HTTPError, OSError) as exc:
        error_exit(f"Failed to fetch functions from Ghidra MCP: {exc}")

    if not raw_funcs:
        error_exit("No functions returned from Ghidra MCP. Is the program open?")

    # Normalize to tool-agnostic schema
    entries = []
    for f in raw_funcs:
        # Parse VA — Ghidra MCP may return hex strings like "0x10001000"
        raw_va = f.get("va", 0)
        va = int(raw_va, 0) if isinstance(raw_va, str) else int(raw_va)
        raw_size = f.get("size", 0)
        size = int(raw_size, 0) if isinstance(raw_size, str) else int(raw_size)

        entry: dict[str, Any] = {"va": va, "size": size}
        # Preserve tool-assigned name as optional hint
        tool_name = f.get("tool_name") or f.get("ghidra_name", "")
        if tool_name:
            entry["tool_name"] = tool_name
        entries.append(entry)

    print(f"  Fetched {len(entries)} functions")

    if json_output:
        json_print(entries)
        return

    if dry_run:
        print(f"  Would write {len(entries)} entries to {out_path}")
        return

    # Atomic write: write to tmp file in same directory, then rename
    reversed_dir.mkdir(parents=True, exist_ok=True)
    fd, tmp_path = tempfile.mkstemp(
        suffix=".tmp", prefix="function_structure_", dir=str(reversed_dir)
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as tmp_f:
            json.dump(entries, tmp_f, indent=2)
            tmp_f.write("\n")
        os.replace(tmp_path, str(out_path))
        print(f"  Wrote {out_path}")
    except BaseException:
        # Clean up tmp file on any error
        with contextlib.suppress(OSError):
            os.unlink(tmp_path)
        raise


def main_entry() -> None:
    """Run the Typer CLI application."""
    app()


if __name__ == "__main__":
    main_entry()
