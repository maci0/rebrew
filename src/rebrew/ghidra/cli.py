"""ghidra/cli.py — Sync rebrew annotations bidirectionally with Ghidra via ReVa MCP.

Supports push (export + apply labels/comments/structs to Ghidra), pull (import
Ghidra renames/comments into local C files), and bulk cache refresh.
All network operations use httpx against the ReVa MCP endpoint.
"""

import json
import logging
from pathlib import Path
from typing import Any

import httpx
import typer
from rich.console import Console

from rebrew.catalog import (
    build_function_registry,
    parse_function_list,
    scan_reversed_dir,
)
from rebrew.cli import (
    EXIT_MISMATCH,
    TargetOption,
    error_exit,
    iter_sources,
    json_print,
    require_config,
)
from rebrew.config import FUNCTION_STRUCTURE_JSON
from rebrew.ghidra.client import (
    apply_commands_via_mcp,
    fetch_all_functions,
    init_mcp_session,
)
from rebrew.ghidra.commands import (
    build_new_function_commands,
    build_size_sync_commands,
    build_sync_commands,
    is_generic_name,
    pull_ghidra_renames,
    resolve_program_path,
    validate_program_path,
)
from rebrew.ghidra.commands import (
    pull_comments as pull_comments_cmd,
)
from rebrew.ghidra.commands import (
    pull_data as pull_data_cmd,
)
from rebrew.ghidra.commands import (
    pull_datatypes as pull_datatypes_cmd,
)
from rebrew.ghidra.commands import (
    pull_prototypes as pull_prototypes_cmd,
)
from rebrew.ghidra.commands import (
    pull_structs as pull_structs_cmd,
)
from rebrew.utils import atomic_write_text

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Push dedup / idempotency tracking
# ---------------------------------------------------------------------------

_SYNC_STATE_FILE = "ghidra_sync_state.json"


def _op_hash(op: dict[str, Any]) -> str:
    """Deterministic content hash of one sync operation.

    JSON with sorted keys (recursive) so semantically identical operations
    hash the same regardless of dict ordering.  Any change to the operation
    (e.g. an edited comment) produces a new hash and is re-pushed.  Note:
    ``sort_keys`` normalizes ordering but not ``1`` vs ``1.0`` — no current
    operation carries floats, so that distinction is intentionally kept.
    """
    import hashlib

    return hashlib.sha256(
        json.dumps(op, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def _load_pushed_hashes(cfg: Any) -> set[str]:
    """Read the set of operation hashes already applied to Ghidra."""
    state_path = cfg.root / ".rebrew" / _SYNC_STATE_FILE
    try:
        data = json.loads(state_path.read_text(encoding="utf-8"))
        if isinstance(data, dict) and isinstance(data.get("pushed"), list):
            return {str(h) for h in data["pushed"]}
    except (OSError, json.JSONDecodeError):
        pass
    return set()


def _build_ops(
    entries: list[dict[str, Any]],
    cfg: Any,
    reversed_dir: Path,
    program_path: str,
    *,
    skip_generic: bool,
    create_functions: bool,
    sync_data: bool,
    sync_structs: bool,
    sync_signatures: bool,
) -> list[dict[str, Any]]:
    """Build the push operation list from already-scanned *entries*.

    Shared by the summary/export/push paths and watch-mode retests, so the
    input computation (IAT thunks, data scan, structs, signatures) lives in
    exactly one place.
    """
    iat_thunk_set: set[int] = set(cfg.iat_thunks)

    data_scan = None
    if sync_data:
        from rebrew.data import scan_data_annotations, scan_globals

        data_scan = scan_globals(reversed_dir, cfg=cfg)
        data_scan.data_annotations = scan_data_annotations(reversed_dir, cfg=cfg)

    structs: list[str] | None = None
    signatures: list[dict[str, str]] | None = None

    if sync_structs or sync_signatures:
        if sync_structs:
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

        if sync_signatures:
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
                if name and not is_generic_name(name):
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

    return build_sync_commands(
        entries,
        program_path,
        skip_generic_labels=skip_generic,
        create_functions=create_functions,
        iat_thunks=iat_thunk_set,
        data_scan=data_scan,
        structs=structs,
        signatures=signatures,
    )


def _export_apply_ops(
    cfg: Any,
    ops: list[dict[str, Any]] | None,
    endpoint: str,
    force: bool,
    dry_run: bool,
    json_output: bool,
    *,
    program_path: str = "",
    do_export: bool,
    do_apply: bool,
) -> None:
    """Export (dedup-filtered) ops to ghidra_commands.json and/or apply them.

    *ops* is only needed for the export half; --apply alone reads the file.
    *program_path* is the RESOLVED program path (not the raw toml value) —
    the cli backend needs it to target the right program.
    """
    if do_export and ops is not None:
        out_path = cfg.root / "ghidra_commands.json"
        # Idempotency: skip operations already applied to Ghidra (tracked in
        # .rebrew/ghidra_sync_state.json) unless --force re-pushes everything.
        pushed = set() if force else _load_pushed_hashes(cfg)
        dedup_skipped = 0
        if pushed:
            fresh: list[dict[str, Any]] = []
            for op in ops:
                if _op_hash(op) in pushed:
                    dedup_skipped += 1
                else:
                    fresh.append(op)
            ops = fresh
        atomic_write_text(out_path, json.dumps(ops, indent=2), encoding="utf-8")
        msg = f"Exported {len(ops)} operations to {out_path}"
        if dedup_skipped:
            msg += f" ({dedup_skipped} already applied, skipped)"
        console.print(msg)

    if do_apply:
        if dry_run:
            count = len(ops) if ops is not None else 0
            if json_output:
                json_print({"dry_run": True, "operations": count, "endpoint": endpoint})
            else:
                console.print(f"Dry run: would apply {count} operations to Ghidra via {endpoint}")
            return
        cmds_path = cfg.root / "ghidra_commands.json"
        if not cmds_path.exists():
            error_exit(f"{cmds_path} not found. Run --export first.", json_mode=json_output)
        try:
            with cmds_path.open(encoding="utf-8") as f:
                commands = json.load(f)
        except (json.JSONDecodeError, OSError) as exc:
            error_exit(f"Failed to read {cmds_path}: {exc}", json_mode=json_output)
        total_cmds = len(commands)
        console.print(f"Applying {total_cmds} operations to Ghidra via {endpoint}...")
        # Transport: ReVa MCP (default) or the ghidra-cli binary backend.
        backend = getattr(cfg, "ghidra_backend", "reva")
        if backend == "cli":
            from rebrew.ghidra.cli_backend import apply_commands_via_cli, resolve_ghidra_cli

            ok, errs = apply_commands_via_cli(
                commands,
                program=program_path,
                project=None,
                ghidra_cli=resolve_ghidra_cli(cfg) or "ghidra-cli",
            )
        else:
            ok, errs = apply_commands_via_mcp(commands, endpoint=endpoint)
        console.print(f"Applied {ok}/{total_cmds} operations successfully")
        if errs > 0:
            console.print(f"[red]{errs} operations failed[/red]")
            raise typer.Exit(code=EXIT_MISMATCH)
        # Record applied operations so the next --export skips them.  Always
        # record — --force bypasses the EXPORT filter (re-push everything),
        # not the APPLY recording; skipping it here would make the state
        # permanently lag reality.
        _record_pushed_hashes(cfg, {_op_hash(c) for c in commands})


def _record_pushed_hashes(cfg: Any, hashes: set[str]) -> None:
    """Merge *hashes* into the pushed-state file (create on first push).

    The read-merge-write is guarded by an exclusive lock so two concurrent
    pushes cannot lose each other's updates.
    """
    import fcntl

    state_path = cfg.root / ".rebrew" / _SYNC_STATE_FILE
    state_path.parent.mkdir(parents=True, exist_ok=True)
    lock_path = state_path.with_suffix(state_path.suffix + ".lock")
    with lock_path.open("w", encoding="utf-8") as lock_fh:
        fcntl.flock(lock_fh, fcntl.LOCK_EX)
        try:
            existing = _load_pushed_hashes(cfg)
            merged = existing | hashes
            atomic_write_text(
                state_path,
                json.dumps({"pushed": sorted(merged)}, indent=2),
                encoding="utf-8",
            )
        finally:
            fcntl.flock(lock_fh, fcntl.LOCK_UN)


console = Console(stderr=True)

app = typer.Typer(
    help="Sync annotations between decomp C files and Ghidra.",
    rich_markup_mode="rich",
    epilog=(
        "[bold]Examples:[/bold]\n\n"
        "  rebrew sync --summary · · · · · · Show what would be synced (dry run)\n\n"
        "  rebrew sync --push · · · · · · · · Export + apply labels/comments to Ghidra\n\n"
        "  rebrew sync --push --dry-run · · · Preview push without applying\n\n"
        "  rebrew sync --pull · · · · · · · · Fetch Ghidra renames/comments into local files\n\n"
        "  rebrew sync --pull --dry-run · · · Preview pull without modifying files\n\n"
        "  rebrew sync --pull --json · · · · · Pull with structured JSON output\n\n"
        "  rebrew sync --pull-structs · · · · · · Pull Ghidra structs into types.h\n\n"
        "  rebrew sync --pull-structs --types-out PATH · · Override output path\n\n"
        "  rebrew sync --pull-structs --by-module · · · · Split into types_<module>.h files\n\n"
        "  rebrew sync --pull-datatypes · · · · Pull enum/typedef inventory into enums_types.h\n\n"
        "  rebrew sync --export · · · · · · · Generate ghidra_commands.json only\n\n"
        "  rebrew sync --apply · · · · · · · · Apply ghidra_commands.json via ReVa MCP\n\n"
        "[bold]Typical workflow:[/bold]\n\n"
        "  1. rebrew sync --pull --dry-run · · Preview incoming changes from Ghidra\n\n"
        "  2. rebrew sync --pull · · · · · · · Apply Ghidra renames/comments locally\n\n"
        "  3. rebrew sync --summary · · · · · Preview outgoing changes to Ghidra\n\n"
        "  4. rebrew sync --push · · · · · · · Push annotations to Ghidra\n\n"
        "[bold]What it syncs:[/bold]\n\n"
        "  [bold]Push \u2192[/bold] labels, plate comments, pre-comments (NOTE), bookmarks, "
        "struct definitions (/rebrew DTM category), function prototypes, "
        "DATA/GLOBAL labels, function sizes, new functions\n\n"
        "  [bold]Pull \u2190[/bold] function renames, data label names, plate/pre comments (as NOTE)\n\n"
        "[bold]Safety:[/bold]\n\n"
        "  - Generic names (FUN_/DAT_/func_/switchdata) are never overwritten\n\n"
        "  - Conflicts (both sides have meaningful names) are reported, not overwritten\n\n"
        "  - [rebrew] plate comments are never pulled back (our own metadata)\n\n"
        "  - Use --dry-run to preview any operation before applying\n\n"
        "[dim]Requires Ghidra + ReVa extension running for MCP operations. "
        "Falls back to local JSON caches (function_structure.json, ghidra_data_labels.json) when offline.[/dim]"
    ),
)


@app.callback(invoke_without_command=True)
def main(
    export: bool = typer.Option(
        False, "--export", help="Export Ghidra commands to ghidra_commands.json"
    ),
    summary: bool = typer.Option(False, "--summary", help="Show sync summary without exporting"),
    apply: bool = typer.Option(
        False, "--apply", help="Apply ghidra_commands.json to Ghidra via ReVa MCP"
    ),
    push: bool = typer.Option(False, "--push", help="Export and apply in one step"),
    create_functions: bool = typer.Option(
        True,
        "--create-functions/--no-create-functions",
        help="Generate create-function operations for all annotated VAs (skips IAT thunks)",
    ),
    skip_generic: bool = typer.Option(
        True, "--skip-generic/--no-skip-generic", help="Skip pushing generic func_XXXXXXXX labels"
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
        False,
        "--accept-local",
        help="Keep local names for all conflicts (records GHIDRA in metadata)",
    ),
    filter_module: str = typer.Option(
        None, "--module", help="Only apply pull updates to this module (e.g. MSVCRT)"
    ),
    pull_signatures: bool = typer.Option(
        False, "--pull-signatures", help="Pull function prototypes from Ghidra and update externs"
    ),
    pull_structs: bool = typer.Option(
        False, "--pull-structs", help="Pull struct definitions from Ghidra into types.h"
    ),
    pull_datatypes: bool = typer.Option(
        False,
        "--pull-datatypes",
        help="Pull enum/typedef inventory from Ghidra into enums_types.h",
    ),
    types_out: Path | None = typer.Option(
        None,
        "--types-out",
        help="Override output path for --pull-structs (single-file mode; mutually exclusive with --by-module)",
        show_default=False,
    ),
    by_module: bool = typer.Option(
        False,
        "--by-module",
        help="Split --pull-structs output into per-module files (e.g. types_server.h, types_shared.h)",
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
        help="Preview changes without writing",
    ),
    endpoint: str = typer.Option(
        "http://localhost:8080/mcp/message", "--endpoint", help="ReVa MCP endpoint URL"
    ),
    force: bool = typer.Option(
        False,
        "--force",
        help="Re-export already-applied operations (only meaningful with --export/--push)",
    ),
    watch: bool = typer.Option(
        False, "--watch", help="Watch sources and re-push on every change (requires --push)"
    ),
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
        or pull_datatypes
        or pull_comments
        or pull_data
        or refresh_cache
    ):
        error_exit(
            "No action specified. Available actions:\n"
            "  Preview:  --summary\n"
            "  Export:   --export, --apply\n"
            "  Sync:    --push, --pull\n"
            "  Cache:   --refresh-cache",
            json_mode=json_output,
        )

    if types_out is not None and by_module:
        error_exit(
            "--types-out and --by-module are mutually exclusive: "
            "--types-out is single-file output; --by-module writes per-module files.",
            json_mode=json_output,
        )

    cfg = require_config(target=target, json_mode=json_output)
    reversed_dir = cfg.reversed_dir
    program_path = resolve_program_path(cfg)

    # Watch mode: live re-push on every source/metadata change.  Dedup
    # tracking (slice 177) makes each re-push incremental — only operations
    # whose content changed are re-applied.
    if watch:
        if not push:
            error_exit("--watch requires --push", json_mode=json_output)
        from rebrew.utils import watch_files

        watch_paths = list(iter_sources(reversed_dir, cfg)) + [cfg.root / "rebrew-function.toml"]

        def _retest() -> None:
            # Re-run the push path with a fresh scan (no recursive main() —
            # typer option defaults are OptionInfo objects, so an unforwarded
            # kwarg would silently corrupt the re-run).
            fresh_entries = [
                e if isinstance(e, dict) else e.to_dict()
                for e in scan_reversed_dir(reversed_dir, cfg=cfg)
            ]
            fresh_ops = _build_ops(
                fresh_entries,
                cfg,
                reversed_dir,
                program_path,
                skip_generic=skip_generic,
                create_functions=create_functions,
                sync_data=sync_data,
                sync_structs=sync_structs,
                sync_signatures=sync_signatures,
            )
            _export_apply_ops(
                cfg,
                fresh_ops,
                endpoint,
                force,
                dry_run,
                json_output,
                program_path=program_path,
                do_export=True,
                do_apply=True,
            )

        watch_files(watch_paths, _retest)
        return

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
                probe_session = init_mcp_session(probe_client, endpoint)
                program_path = validate_program_path(
                    probe_client,
                    endpoint,
                    program_path,
                    probe_session,
                )
        except (httpx.HTTPError, OSError, RuntimeError, ValueError) as exc:
            # Bare ConnectionError() has an empty str — include the type name.
            detail = str(exc).strip() or type(exc).__name__
            log.debug("MCP probe failed (will use cached data): %s", detail)

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
                filter_origin=filter_module,
            )
            if pull_result.conflicts > 0 and not dry_run:
                console.print(
                    "Conflicts detected during name pull. Continuing with other pull operations if any."
                )

        if pull_signatures or pull_structs or pull_datatypes or pull_comments or pull_data:
            if pull_signatures:
                pull_prototypes_cmd(entries, cfg, endpoint, program_path, dry_run)
            if pull_structs:
                pull_structs_cmd(
                    cfg,
                    endpoint,
                    program_path,
                    dry_run,
                    types_out=types_out,
                    by_module=by_module,
                )
            if pull_datatypes:
                pull_datatypes_cmd(
                    cfg,
                    endpoint,
                    program_path,
                    dry_run=dry_run,
                    types_out=types_out,
                )
            if pull_comments:
                pull_comments_cmd(entries, cfg, endpoint, program_path, dry_run)
            if pull_data:
                pull_data_cmd(cfg, endpoint, program_path, dry_run)

        return

    by_va: dict[int, list[dict[str, Any]]] = {}
    for e in entries:
        by_va.setdefault(e["va"], []).append(e)

    # Build commands once (reused by --summary, --export, --push).  The input
    # computation (IAT thunks, data scan, structs, signatures) lives in
    # _build_ops so watch-mode retests share it.
    ops: list[dict[str, Any]] | None = None
    if summary or export or push:
        ops = _build_ops(
            entries,
            cfg,
            reversed_dir,
            program_path,
            skip_generic=skip_generic,
            create_functions=create_functions,
            sync_data=sync_data,
            sync_structs=sync_structs,
            sync_signatures=sync_signatures,
        )

    if summary:
        assert ops is not None
        module_entries: dict[str, list[dict[str, Any]]] = {}
        for e in entries:
            module_entries.setdefault(e["module"], []).append(e)

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
                    "by_module": {k: len(v) for k, v in sorted(module_entries.items())},
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
            console.print(f"Annotations: {len(entries)} entries, {len(by_va)} unique VAs")
            for module in sorted(module_entries):
                console.print(f"  {module}: {len(module_entries[module])}")
            console.print(f"If exported, would generate {len(ops)} operations:")
            if create_fns:
                console.print(f"  - Create {len(create_fns)} functions (create-function)")
            console.print(f"  - Set {len(labels)} labels (create-label)")
            console.print(f"  - Add {len(comments)} plate comments (set-comment)")
            console.print(f"  - Add {len(bookmarks)} bookmarks (set-bookmark)")
            if structs_op:
                console.print(f"  - Push {len(structs_op)} struct definitions (parse-c-structure)")
            if sigs_op:
                console.print(
                    f"  - Set {len(sigs_op)} function prototypes (set-function-prototype)"
                )
            console.print(f"  Total: {len(ops)} operations")

    if export or push:
        _export_apply_ops(
            cfg,
            ops,
            endpoint,
            force,
            dry_run,
            json_output,
            program_path=program_path,
            do_export=True,
            do_apply=(push or apply),
        )
    elif apply:
        _export_apply_ops(
            cfg,
            None,
            endpoint,
            force,
            dry_run,
            json_output,
            program_path=program_path,
            do_export=False,
            do_apply=True,
        )

    if refresh_cache:
        functions = _refresh_structure_cache(cfg, endpoint, program_path, dry_run, json_output)
        data_labels = _refresh_data_labels_cache(cfg, endpoint, program_path, dry_run, json_output)
        if json_output:
            json_print(
                {
                    "functions": functions,
                    "data_labels": data_labels,
                    "function_count": len(functions),
                    "data_label_count": len(data_labels),
                }
            )

    if sync_sizes or sync_new_functions:
        # Build registry to compare function list vs ghidra sizes
        func_list_path = cfg.function_list
        ghidra_json_path = reversed_dir / FUNCTION_STRUCTURE_JSON
        bin_path = cfg.target_binary

        funcs = parse_function_list(func_list_path)
        registry = build_function_registry(funcs, cfg, ghidra_json_path, bin_path)

        all_cmds: list[dict[str, Any]] = []
        iat_thunk_set: set[int] = set(cfg.iat_thunks)

        if sync_sizes:
            size_cmds = build_size_sync_commands(registry, program_path, iat_thunk_set)
            console.print(f"Size sync: {len(size_cmds)} functions need boundary expansion")
            for cmd in size_cmds:
                meta = cmd.pop("_meta", {})
                console.print(
                    f"  {cmd['args']['address']}: "
                    f"{meta.get('ghidra_size', '?')} → {meta.get('canonical_size', '?')} "
                    f"({meta.get('reason', '')})"
                )
            all_cmds.extend(size_cmds)

        if sync_new_functions:
            new_cmds = build_new_function_commands(registry, program_path, iat_thunk_set)
            console.print(f"New functions: {len(new_cmds)} list-only functions to create in Ghidra")
            for cmd in new_cmds:
                meta = cmd.pop("_meta", {})
                console.print(f"  {cmd['args']['address']}: list size {meta.get('list_size', '?')}")
            all_cmds.extend(new_cmds)

        if all_cmds:
            out_path = cfg.root / "ghidra_size_commands.json"
            atomic_write_text(out_path, json.dumps(all_cmds, indent=2), encoding="utf-8")
            console.print(f"Exported {len(all_cmds)} operations to {out_path}")

            if push:
                total_size_cmds = len(all_cmds)
                console.print(f"Applying {total_size_cmds} size operations via {endpoint}...")
                backend = getattr(cfg, "ghidra_backend", "reva")
                if backend == "cli":
                    from rebrew.ghidra.cli_backend import apply_commands_via_cli, resolve_ghidra_cli

                    ok, errs = apply_commands_via_cli(
                        all_cmds,
                        program=program_path,
                        project=None,
                        ghidra_cli=resolve_ghidra_cli(cfg) or "ghidra-cli",
                    )
                else:
                    ok, errs = apply_commands_via_mcp(all_cmds, endpoint=endpoint)
                console.print(f"Applied {ok}/{total_size_cmds} operations successfully")
                if errs > 0:
                    console.print(f"[red]{errs} operations failed[/red]")
                    raise typer.Exit(code=EXIT_MISMATCH)


def _refresh_structure_cache(
    cfg: Any,
    endpoint: str,
    program_path: str,
    dry_run: bool,
    json_output: bool,
) -> list[dict[str, Any]]:
    """Fetch all functions from Ghidra MCP and write function_structure.json."""
    reversed_dir = cfg.reversed_dir
    out_path = reversed_dir / FUNCTION_STRUCTURE_JSON

    try:
        with httpx.Client(timeout=30.0) as client:
            session_id = init_mcp_session(client, endpoint)
            console.print(f"Fetching functions from Ghidra ({program_path})...")
            raw_funcs = fetch_all_functions(client, endpoint, program_path, session_id)
    except (httpx.HTTPError, OSError) as exc:
        error_exit(f"Failed to fetch functions from Ghidra MCP: {exc}", json_mode=json_output)

    if not raw_funcs:
        error_exit(
            "No functions returned from Ghidra MCP. Is the program open?", json_mode=json_output
        )

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

    console.print(f"  Fetched {len(entries)} functions")

    if json_output:
        return entries

    if dry_run:
        console.print(f"  Would write {len(entries)} entries to {out_path}")
        return entries

    reversed_dir.mkdir(parents=True, exist_ok=True)
    atomic_write_text(out_path, json.dumps(entries, indent=2) + "\n")
    console.print(f"  Wrote {out_path}")
    return entries


def _refresh_data_labels_cache(
    cfg: Any,
    endpoint: str,
    program_path: str,
    dry_run: bool,
    json_output: bool,
) -> list[Any]:
    """Fetch all data labels from Ghidra MCP and write ghidra_data_labels.json."""
    from rebrew.ghidra.client import fetch_all_symbols

    reversed_dir = cfg.reversed_dir
    out_path = reversed_dir / "ghidra_data_labels.json"

    try:
        with httpx.Client(timeout=30.0) as client:
            session_id = init_mcp_session(client, endpoint)
            console.print(f"Fetching data labels from Ghidra ({program_path})...")
            raw_syms = fetch_all_symbols(client, endpoint, program_path, session_id)
    except (httpx.HTTPError, OSError) as exc:
        error_exit(f"Failed to fetch data labels from Ghidra MCP: {exc}", json_mode=json_output)

    console.print(f"  Fetched {len(raw_syms)} symbols")

    if json_output:
        return raw_syms

    if dry_run:
        console.print(f"  Would write {len(raw_syms)} entries to {out_path}")
        return raw_syms

    reversed_dir.mkdir(parents=True, exist_ok=True)
    atomic_write_text(out_path, json.dumps(raw_syms, indent=2) + "\n")
    console.print(f"  Wrote {out_path}")
    return raw_syms


def main_entry() -> None:
    """Run the Typer CLI application."""
    app()


if __name__ == "__main__":
    main_entry()
