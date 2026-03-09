"""Module docstring."""

import json
import re
import time
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from rebrew.catalog.registry import RegistryEntry
import httpx
import typer
from rich.console import Console

from rebrew.annotation import Annotation, update_annotation_key
from rebrew.cli import error_exit, iter_sources, json_print
from rebrew.config import FUNCTION_STRUCTURE_JSON, ProjectConfig
from rebrew.ghidra.client import (
    _MCP_HEADERS,
    _MCP_REQUEST_TIMEOUT_S,
    _fetch_all_functions,
    _fetch_all_symbols,
    _fetch_mcp_tool,
    _fetch_mcp_tool_raw,
    _init_mcp_session,
)
from rebrew.ghidra.models import PullChange, PullResult
from rebrew.utils import atomic_write_text

console = Console(stderr=True)

# Pattern matching generic auto-names that shouldn't overwrite Ghidra renames
_GENERIC_NAME_RE = re.compile(r"^_?(func_|FUN_)[0-9a-fA-F]+(@\d+)?$")

# Status → bookmark category prefix for visual distinction
_STATUS_BOOKMARK_CATEGORY = {
    "EXACT": "rebrew/exact",
    "RELOC": "rebrew/reloc",
    "NEAR_MATCHING": "rebrew/matching",
    "STUB": "rebrew/stub",
}


def _is_generic_name(name: str) -> bool:
    """Return True if *name* is a default auto-generated name like func_10006c00."""
    return bool(_GENERIC_NAME_RE.match(name))


def _resolve_program_path(cfg: ProjectConfig) -> str:
    """Return the Ghidra program path from config or derive from binary name."""
    configured = getattr(cfg, "ghidra_program_path", "")
    if configured:
        return configured
    return f"/{cfg.target_binary.name}"


def _validate_program_path(
    client: httpx.Client,
    endpoint: str,
    program_path: str,
    session_id: str,
) -> str:
    """Best-effort validation of derived programPath against current Ghidra project."""
    try:
        result = _fetch_mcp_tool_raw(
            client,
            endpoint,
            "get-current-program",
            {},
            request_id=1,
            session_id=session_id,
        )
    except (OSError, ValueError, KeyError, TypeError, RuntimeError):
        return program_path

    if not isinstance(result, dict):
        return program_path

    ghidra_path = result.get("programPath")
    if not isinstance(ghidra_path, str) or not ghidra_path:
        return program_path

    if ghidra_path != program_path:
        typer.echo(
            f"Ghidra has '{ghidra_path}' open, but rebrew derived '{program_path}'. "
            f'Add ghidra_program_path = "{ghidra_path}" to [targets.X] in '
            "rebrew-project.toml to fix.",
            err=True,
        )
    return ghidra_path


def build_sync_commands(
    entries: list[dict[str, Any]],
    program_path: str,
    *,
    skip_generic_labels: bool = True,
    create_functions: bool = False,
    iat_thunks: set[int] | None = None,
    data_scan: Any = None,
    structs: list[str] | None = None,
    signatures: list[dict[str, str]] | None = None,
) -> list[dict[str, Any]]:
    """Build a list of ReVa MCP commands from annotation entries.

    If data_scan (ScanResult) is provided, also generates commands for globals.
    """
    by_va: dict[int, list[dict[str, Any]]] = {}
    for e in entries:
        # Separate functions from data annotations
        marker = e.get("marker_type", "FUNCTION")
        if marker in ("DATA", "GLOBAL"):
            continue
        by_va.setdefault(e["va"], []).append(e)

    commands: list[dict[str, Any]] = []
    skipped_labels = 0
    thunk_set = iat_thunks or set()

    # Phase 0: Push type definitions (typedefs + structs) BEFORE prototypes
    # so Ghidra's CParser can resolve custom types in function signatures.
    # Simple typedefs (no '{') are pushed first so structs can reference them.
    if structs:
        typedefs_first = sorted(structs, key=lambda s: ("{" in s, s))
        for struct_str in typedefs_first:
            bare = struct_str.strip().rstrip(";").strip()
            if bare.startswith("struct {") and bare.endswith("}"):
                continue
            commands.append(
                {
                    "tool": "parse-c-structure",
                    "args": {
                        "programPath": program_path,
                        "cDefinition": struct_str,
                        "category": "/rebrew",
                    },
                }
            )

    # Phase 1: create-function for all annotated VAs (before labels/comments)
    if create_functions:
        for va in sorted(by_va):
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

    # Phase 2: set-function-prototype for functions with parsed C signatures.
    # Must run BEFORE create-label — Ghidra's createLabel() produces a
    # secondary LABEL-type symbol that blocks function.setName() with a
    # DuplicateNameException.
    sig_vas: set[int] = set()
    if signatures:
        for sig_info in signatures:
            va_int = int(sig_info["va_hex"], 16)
            sig_vas.add(va_int)
            commands.append(
                {
                    "tool": "set-function-prototype",
                    "args": {
                        "programPath": program_path,
                        "location": sig_info["va_hex"],
                        "signature": sig_info["signature"],
                    },
                }
            )

    # Phase 3: labels, comments, bookmarks for functions
    for va in sorted(by_va):
        elist = by_va[va]
        primary = elist[0]
        va_hex = f"0x{va:08X}"
        name = primary.get("name") or primary.get("symbol") or f"func_{va:08x}"
        status = primary.get("status", "UNKNOWN")

        # Skip labels for VAs where set-function-prototype already set the name
        # (avoids creating secondary LABEL symbols that trigger DuplicateNameException).
        if va in sig_vas or skip_generic_labels and _is_generic_name(name):
            skipped_labels += 1
        else:
            commands.append(
                {
                    "tool": "create-label",
                    "args": {
                        "programPath": program_path,
                        "addressOrSymbol": va_hex,
                        "labelName": name,
                        "setAsPrimary": True,
                    },
                }
            )

        comment_lines = [
            f"[rebrew] {primary.get('marker_type', 'FUNCTION')}: {status}",
            f"Module: {primary.get('module', '')}",
            f"Size: {primary.get('size', 0)}B",
            f"CFlags: {primary.get('cflags', '')}",
            f"Symbol: {primary.get('symbol', '')}",
            f"Files: {', '.join(e.get('filepath', '') for e in elist)}",
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

        bm_category = _STATUS_BOOKMARK_CATEGORY.get(
            status, primary.get("module", "").lower() or "rebrew"
        )
        bm_comment = f"{name} - {status} ({primary.get('size', 0)}B, {primary.get('cflags', '')})"
        commands.append(
            {
                "tool": "set-bookmark",
                "args": {
                    "programPath": program_path,
                    "addressOrSymbol": va_hex,
                    "type": "Note",
                    "category": bm_category,
                    "comment": bm_comment,
                },
            }
        )

        # Push NOTE as a pre-comment (separate from plate metadata)
        note = primary.get("note", "")
        if note:
            commands.append(
                {
                    "tool": "set-comment",
                    "args": {
                        "programPath": program_path,
                        "addressOrSymbol": va_hex,
                        "comment": note,
                        "commentType": "pre",
                    },
                }
            )

    # Phase 4: Push Data / Globals
    if data_scan is not None:
        # Push variables identified by data_scan.globals
        for name, g_entry in sorted(data_scan.globals.items()):
            if not g_entry.va:
                continue
            va_hex = f"0x{g_entry.va:08X}"

            # Label
            if not skip_generic_labels or not _is_generic_name(name):
                commands.append(
                    {
                        "tool": "create-label",
                        "args": {
                            "programPath": program_path,
                            "addressOrSymbol": va_hex,
                            "labelName": name,
                            "setAsPrimary": True,
                        },
                    }
                )

            # Comment
            comment_lines = [
                "[rebrew] GLOBAL",
                f"Type: {g_entry.type_str}",
            ]
            if g_entry.section:
                comment_lines.append(f"Section: {g_entry.section}")
            if g_entry.declared_in:
                comment_lines.append(f"Files: {', '.join(g_entry.declared_in)}")

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

            # Bookmark
            commands.append(
                {
                    "tool": "set-bookmark",
                    "args": {
                        "programPath": program_path,
                        "addressOrSymbol": va_hex,
                        "type": "Note",
                        "category": "rebrew/data",
                        "comment": f"Global: {g_entry.type_str} {name}",
                    },
                }
            )

        # Push raw // DATA: annotations that might not be in globals (e.g. inline assemblies)
        for d_entry in data_scan.data_annotations:
            va_hex = d_entry["va"]
            name = d_entry["name"]

            # Label
            if not skip_generic_labels or not _is_generic_name(name):
                commands.append(
                    {
                        "tool": "create-label",
                        "args": {
                            "programPath": program_path,
                            "addressOrSymbol": va_hex,
                            "labelName": name,
                            "setAsPrimary": True,
                        },
                    }
                )

            # Comment
            comment_lines = [
                "[rebrew] DATA",
                f"Size: {d_entry['size']}B",
                f"Section: {d_entry['section']}",
                f"Module: {d_entry.get('module', '')}",
            ]
            if d_entry.get("note"):
                comment_lines.append(f"Note: {d_entry['note']}")
            comment_lines.append(f"File: {d_entry['filepath']}")

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

            commands.append(
                {
                    "tool": "set-bookmark",
                    "args": {
                        "programPath": program_path,
                        "addressOrSymbol": va_hex,
                        "type": "Note",
                        "category": "rebrew/data",
                        "comment": f"Data: {name} ({d_entry['size']}B)",
                    },
                }
            )

    if skipped_labels > 0:
        print(f"  Skipped {skipped_labels} generic labels (func_XXXXXXXX)")

    return commands


def _parse_va(va_raw: str | int | None) -> int | None:
    """Normalize a VA value (hex string or int) to int, or None if invalid."""
    if va_raw is None:
        return None
    if isinstance(va_raw, int):
        return va_raw
    if isinstance(va_raw, str) and va_raw.startswith("0x"):
        try:
            return int(va_raw, 16)
        except ValueError:
            return None
    try:
        return int(va_raw)
    except (ValueError, TypeError):
        return None


def _is_meaningful_name(name: str) -> bool:
    """Return True if a name carries real semantic information (not auto-generated)."""
    return bool(name) and not (
        _is_generic_name(name)
        or name.startswith("FUN_")
        or name.startswith("DAT_")
        or name.startswith("switchdata")
        or name.startswith("thunk_")
    )


def _ghidra_name_to_symbol(
    ghidra_name: str, entry: Annotation | dict[str, str], cfg: ProjectConfig | None = None
) -> str:
    """Convert a Ghidra function name to a C symbol name based on calling convention and config."""
    if not ghidra_name:
        return ""
    if ghidra_name.startswith("_"):
        return ghidra_name

    if cfg is not None and getattr(cfg, "symbol_prefix", None) == "_":
        return "_" + ghidra_name

    # Try attribute access first, then dict access
    symbol = getattr(entry, "symbol", None) if hasattr(entry, "symbol") else None
    if symbol is None and isinstance(entry, dict):
        symbol = entry.get("symbol")

    cflags = getattr(entry, "cflags", None) if hasattr(entry, "cflags") else None
    if cflags is None and isinstance(entry, dict):
        cflags = entry.get("cflags")

    if symbol and str(symbol).startswith("_") and not str(symbol).startswith("_thunk"):
        return "_" + ghidra_name

    if cflags and "/Gz" in str(cflags):
        return ghidra_name

    return "_" + ghidra_name


def pull_ghidra_renames(
    entries: list[dict[str, Any]],
    cfg: ProjectConfig,
    endpoint: str = "http://localhost:8080/mcp/message",
    program_path: str = "",
    dry_run: bool = False,
    json_output: bool = False,
    accept_ghidra: bool = False,
    accept_local: bool = False,
    filter_origin: str | None = None,
) -> PullResult:
    """Pull function and data names from Ghidra and update local .c files.

    When *dry_run* is True, reports what would change without modifying files.
    Returns a PullResult with all proposed/applied changes.
    """
    result = PullResult()

    if not dry_run:
        print("Fetching function, data, and comment lists from Ghidra via ReVa MCP...")
    functions: list[Any] = []
    data_labels: list[Any] = []
    plate_comments: list[Any] = []
    pre_comments: list[Any] = []

    with httpx.Client(timeout=30.0) as client:
        init_payload = {
            "jsonrpc": "2.0",
            "id": 0,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-03-26",
                "capabilities": {},
                "clientInfo": {"name": "rebrew sync", "version": "1.0.0"},
            },
        }
        session_id = ""
        try:
            init_resp = client.post(
                endpoint, json=init_payload, headers=_MCP_HEADERS, timeout=_MCP_REQUEST_TIMEOUT_S
            )
            session_id = init_resp.headers.get("Mcp-Session-Id", "")

            functions = _fetch_all_functions(client, endpoint, program_path, session_id)
            data_labels = _fetch_all_symbols(client, endpoint, program_path, session_id)
            plate_comments = _fetch_mcp_tool(
                client,
                endpoint,
                "get-comments",
                {"programPath": program_path, "commentTypes": ["plate"]},
                3,
                session_id=session_id,
            )
            pre_comments = _fetch_mcp_tool(
                client,
                endpoint,
                "get-comments",
                {"programPath": program_path, "commentTypes": ["pre"]},
                4,
                session_id=session_id,
            )
        except httpx.RequestError as e:
            typer.echo(f"Warning: Could not connect to ReVa MCP ({e}).", err=True)
            typer.echo("Falling back to local caches...", err=True)

    if not functions:
        ghidra_json_path = cfg.reversed_dir / FUNCTION_STRUCTURE_JSON
        if ghidra_json_path.exists():
            try:
                functions = json.loads(ghidra_json_path.read_text(encoding="utf-8"))
                if not dry_run:
                    print(f"Loaded {len(functions)} functions from {ghidra_json_path.name}")
            except (json.JSONDecodeError, OSError) as e:
                typer.echo(f"Error reading cache: {e}", err=True)
        else:
            typer.echo(
                f"Could not fetch functions from MCP and {ghidra_json_path.name} not found.",
                err=True,
            )

    if not data_labels:
        data_json_path = cfg.reversed_dir / "ghidra_data_labels.json"
        if data_json_path.exists():
            try:
                data_labels = json.loads(data_json_path.read_text(encoding="utf-8"))
                if not dry_run:
                    print(f"Loaded {len(data_labels)} data labels from {data_json_path.name}")
            except (json.JSONDecodeError, OSError):
                pass

    if not functions and not data_labels:
        return result

    ghidra_names_by_va: dict[int, str] = {}
    for f in functions:
        va = _parse_va(f.get("va") or f.get("address"))
        gname = f.get("tool_name") or f.get("ghidra_name") or f.get("name")
        if va is not None and gname:
            ghidra_names_by_va[va] = gname

    for d in data_labels:
        va = _parse_va(d.get("va") or d.get("address"))
        name = d.get("name") or d.get("label") or d.get("ghidra_name")
        if va is not None and name:
            ghidra_names_by_va[va] = name

    ghidra_comments_by_va: dict[int, str] = {}
    for c in plate_comments:
        va = _parse_va(c.get("address"))
        comment = c.get("comment")
        if va is not None and comment and not comment.startswith("[rebrew]"):
            ghidra_comments_by_va[va] = comment.strip()

    for c in pre_comments:
        va = _parse_va(c.get("address"))
        comment = c.get("comment")
        if va is not None and comment and not comment.startswith("[rebrew]"):
            ghidra_comments_by_va.setdefault(va, comment.strip())

    from rebrew.data import scan_data_annotations

    all_entries = list(entries)
    all_entries.extend(scan_data_annotations(cfg.reversed_dir, cfg=cfg))

    for entry in all_entries:
        va = _parse_va(entry.get("va"))
        if va is None:
            continue

        filepath = Path(entry.get("filepath", ""))
        if not filepath.exists() and not filepath.is_absolute():
            filepath = cfg.reversed_dir / filepath
        if not filepath.exists():
            continue
        # Guard against path traversal: resolved path must stay within reversed_dir
        try:
            filepath.resolve().relative_to(cfg.reversed_dir.resolve())
        except ValueError:
            continue

        ghidra_name = ghidra_names_by_va.get(va)
        if ghidra_name and _is_meaningful_name(ghidra_name):
            local_name = entry.get("symbol") or entry.get("name") or f"func_{va:08x}"
            ghidra_as_symbol = _ghidra_name_to_symbol(ghidra_name, entry, cfg)
            if local_name != ghidra_as_symbol:
                local_is_meaningful = _is_meaningful_name(local_name)
                skip_name_update = False

                if local_name.lstrip("_") == ghidra_name.lstrip("_"):
                    skip_name_update = True

                if filter_origin and entry.get("module") != filter_origin:
                    skip_name_update = True

                if (
                    not skip_name_update
                    and local_is_meaningful
                    and local_name.lstrip("_") != ghidra_name.lstrip("_")
                ):
                    if accept_ghidra:
                        pass  # proceed with updating to ghidra_name
                    elif accept_local:
                        if not dry_run:
                            update_annotation_key(
                                filepath, va, "GHIDRA", ghidra_name, metadata_dir=cfg.metadata_dir
                            )
                        change = PullChange(
                            va=va,
                            field="GHIDRA",
                            local_value=local_name,
                            ghidra_value=ghidra_name,
                            filepath=str(filepath.name),
                            action="update (keep local)",
                            reason="user chose --accept-local",
                        )
                        result.changes.append(change)
                        result.updated += 1
                        if not json_output:
                            print(
                                f"  Added GHIDRA: {ghidra_name} for 0x{va:08x} (kept {local_name})"
                            )
                        skip_name_update = True
                    else:
                        # Existing GHIDRA annotation?
                        existing_ghidra = entry.get("ghidra", "")
                        if existing_ghidra == ghidra_name:
                            skip_name_update = True  # we already tracked this conflict
                        else:
                            change = PullChange(
                                va=va,
                                field="NAME",
                                local_value=local_name,
                                ghidra_value=ghidra_name,
                                filepath=str(filepath.name),
                                action="conflict",
                                reason="both local and Ghidra have meaningful names",
                            )
                            result.changes.append(change)
                            result.conflicts += 1
                            if not json_output:
                                print(
                                    f"  CONFLICT 0x{va:08x}: local={local_name} vs ghidra={ghidra_name}"
                                )
                            skip_name_update = True

                if not skip_name_update:
                    if dry_run:
                        change = PullChange(
                            va=va,
                            field="NAME",
                            local_value=local_name,
                            ghidra_value=ghidra_name,
                            filepath=str(filepath.name),
                            action="update",
                        )
                        result.changes.append(change)
                        result.updated += 1
                        if not json_output:
                            print(f"  Would update 0x{va:08x}: {local_name} -> {ghidra_name}")
                    else:
                        if not json_output:
                            print(f"  Updating VA 0x{va:08x}: {local_name} -> {ghidra_name}")

                        if entry.get("marker_type", "FUNCTION") == "FUNCTION":
                            from rebrew.rename import rename_function_everywhere

                            old_name = entry.get("name", "")
                            old_sym = entry.get("symbol", "")
                            if not old_sym:
                                old_sym = old_name
                            target_func = ghidra_name.lstrip("_")
                            target_sym = ghidra_as_symbol

                            rename_function_everywhere(
                                cfg=cfg,
                                filepath=filepath,
                                va=va,
                                old_name=old_name,
                                old_sym=old_sym,
                                target_func=target_func,
                                target_sym=target_sym,
                                rename_file=True,
                                dry_run=dry_run,
                            )
                        else:
                            # DATA/GLOBAL entries — write name to rebrew-data.toml metadata
                            module = entry.get("module", "")
                            if module and not dry_run:
                                from rebrew.data_metadata import set_data_field

                                set_data_field(
                                    cfg.reversed_dir,
                                    va,
                                    "name",
                                    ghidra_name,
                                    module,
                                )

                        change = PullChange(
                            va=va,
                            field="NAME",
                            local_value=local_name,
                            ghidra_value=ghidra_name,
                            filepath=str(filepath.name),
                            action="update",
                        )
                        result.changes.append(change)
                        result.updated += 1

        ghidra_comment = ghidra_comments_by_va.get(va)
        if ghidra_comment:
            local_note = entry.get("note", "")
            if local_note != ghidra_comment:
                sanitized = ghidra_comment.replace("\n", " ")
                if dry_run:
                    change = PullChange(
                        va=va,
                        field="NOTE",
                        local_value=local_note,
                        ghidra_value=sanitized,
                        filepath=str(filepath.name),
                        action="update",
                    )
                    result.changes.append(change)
                    result.updated += 1
                    if not json_output:
                        print(f"  Would update NOTE at 0x{va:08x}")
                else:
                    marker_type = entry.get("marker_type", "FUNCTION")
                    if marker_type in ("DATA", "GLOBAL"):
                        # DATA/GLOBAL notes go to rebrew-data.toml metadata
                        module = entry.get("module", "")
                        if module:
                            from rebrew.data_metadata import set_data_field

                            set_data_field(cfg.metadata_dir, va, "note", sanitized, module)
                            change = PullChange(
                                va=va,
                                field="NOTE",
                                local_value=local_note,
                                ghidra_value=sanitized,
                                filepath=str(filepath.name),
                                action="update (data metadata)",
                            )
                            result.changes.append(change)
                            result.updated += 1
                            if not json_output:
                                print(f"  Updated NOTE in rebrew-data.toml at 0x{va:08x}")
                    elif update_annotation_key(
                        filepath, va, "NOTE", sanitized, metadata_dir=cfg.metadata_dir
                    ):
                        change = PullChange(
                            va=va,
                            field="NOTE",
                            local_value=local_note,
                            ghidra_value=sanitized,
                            filepath=str(filepath.name),
                            action="update",
                        )
                        result.changes.append(change)
                        result.updated += 1
                        if not json_output:
                            print(f"  Updated NOTE at 0x{va:08x}")

    if json_output:
        json_print(result.to_dict())
    elif result.updated == 0 and result.conflicts == 0:
        print("No new data to pull from Ghidra.")
    else:
        verb = "Would pull" if dry_run else "Successfully pulled"
        print(f"{verb} {result.updated} updates from Ghidra.")
        if result.conflicts > 0:
            print(
                f"  {result.conflicts} conflict(s) skipped "
                "(both sides have meaningful names — resolve manually)"
            )

    return result


def build_size_sync_commands(
    registry: dict[int, "RegistryEntry"],
    program_path: str,
    iat_thunks: set[int] | None = None,
) -> list[dict[str, Any]]:
    """Generate commands to expand function boundaries in Ghidra where list > ghidra."""
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
    registry: dict[int, "RegistryEntry"],
    program_path: str,
    iat_thunks: set[int] | None = None,
) -> list[dict[str, Any]]:
    """Generate create-function commands for functions list found but Ghidra missed."""
    commands: list[dict[str, Any]] = []
    thunk_set = iat_thunks or set()

    for va, entry in sorted(registry.items()):
        if va in thunk_set:
            continue
        detected = entry.get("detected_by", [])
        if "list" in detected and "ghidra" not in detected:
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
                        "reason": "list only (not in Ghidra)",
                        "list_size": entry.get("size_by_tool", {}).get("list", 0),
                    },
                }
            )

    return commands


def _pull_prototypes(
    entries: list[Any],
    cfg: ProjectConfig,
    endpoint: str,
    program_path: str,
    dry_run: bool,
    replace_externs: bool = False,
) -> None:
    """Pull function prototypes from Ghidra and update local files.

    When replace_externs is False (default), only writes // PROTOTYPE: annotations.
    When True, also replaces extern declarations across the project (WARNING: Ghidra
    types like uint/byte/undefined are not valid C89/MSVC6 — use with caution).
    """
    console.print("Pulling function prototypes from Ghidra...")

    with httpx.Client(timeout=30.0) as client:
        try:
            session_id = _init_mcp_session(client, endpoint)
        except httpx.RequestError as e:
            console.print(f"[red]Error connecting to MCP: {e}[/red]")
            return

        updated_count = 0

        # Paginate through all functions (default page size is 100)
        all_funcs: list[Any] = []
        start_index = 0
        page_size = 200
        request_id = 1
        while True:
            page = _fetch_mcp_tool_raw(
                client,
                endpoint,
                "get-functions",
                {
                    "programPath": program_path,
                    "filterDefaultNames": False,
                    "verbose": True,
                    "maxCount": page_size,
                    "startIndex": start_index,
                },
                request_id,
                session_id=session_id,
            )
            if not isinstance(page, list) or not page:
                break
            # First item is the header with pagination metadata
            header = (
                page[0] if page and isinstance(page[0], dict) and "totalCount" in page[0] else None
            )
            func_items = page[1:] if header else page
            all_funcs.extend(func_items)
            if header:
                total = header.get("totalCount", 0)
                next_idx = header.get("nextStartIndex", 0)
                if next_idx <= start_index or len(all_funcs) >= total:
                    break
                start_index = next_idx
                request_id += 1
            else:
                break

        console.print(f"  Fetched {len(all_funcs)} functions from Ghidra")

        ghidra_sigs: dict[int, str] = {}
        for f in all_funcs:
            va_str = f.get("address") or f.get("va")
            if va_str:
                try:
                    va = int(va_str, 16) if isinstance(va_str, str) else int(va_str)
                    if "signature" in f:
                        ghidra_sigs[va] = f["signature"]
                except ValueError:
                    pass

        for entry in entries:
            marker = entry.get("marker_type", "FUNCTION")
            if marker != "FUNCTION":
                continue
            va = entry.get("va")
            if not va:
                continue

            sig = ghidra_sigs.get(va)
            if not sig:
                # Fallback to get-decompilation if signature isn't in get-functions
                res = _fetch_mcp_tool_raw(
                    client,
                    endpoint,
                    "get-decompilation",
                    {
                        "programPath": program_path,
                        "functionNameOrAddress": f"0x{va:x}",
                        "signatureOnly": True,
                    },
                    va,
                    session_id=session_id,
                )
                if isinstance(res, str):
                    sig = res.strip()
                elif isinstance(res, dict) and "signature" in res:
                    sig = res["signature"]
                elif isinstance(res, dict) and "decompilation" in res:
                    sig = res["decompilation"]

            if sig:
                # Clean up the signature string
                sig = sig.replace("\n", " ").strip()
                if sig.endswith(";"):
                    sig = sig[:-1].strip()

                local_proto = entry.get("prototype", "")
                if local_proto != sig:
                    fp = cfg.reversed_dir / entry.get("filepath", "")
                    if not fp.exists():
                        continue

                    if not dry_run:
                        update_annotation_key(
                            fp, va, "PROTOTYPE", sig, metadata_dir=cfg.metadata_dir
                        )

                        if replace_externs:
                            # Replace externs across the project
                            # WARNING: Ghidra types (uint, byte, undefined) are not valid C89
                            sym = entry.get("symbol") or entry.get("name")
                            actual_name = sym.lstrip("_") if sym.startswith("_") else sym

                            # Build the new extern statement
                            extern_str = f"extern {sig};"

                            for src_file in iter_sources(cfg.reversed_dir, cfg):
                                try:
                                    content = src_file.read_text(encoding="utf-8")
                                    # Regex to match existing extern for this function
                                    # extern <type> <name>(...);
                                    pattern = (
                                        r"extern\s+[^;]+?\b"
                                        + re.escape(actual_name)
                                        + r"\s*\([^;]*\)\s*;"
                                    )
                                    new_content = re.sub(pattern, extern_str, content)
                                    if new_content != content:
                                        atomic_write_text(src_file, new_content, encoding="utf-8")
                                except OSError:
                                    pass

                    console.print(f"  [green]Updated prototype[/green] 0x{va:x}: {sig}")
                    updated_count += 1

        console.print(f"Successfully pulled {updated_count} prototypes.")


def _pull_structs(cfg: ProjectConfig, endpoint: str, program_path: str, dry_run: bool) -> None:
    """Pull struct definitions from Ghidra into types.h using list-structures + get-structure-info."""
    console.print("Pulling struct definitions from Ghidra...")

    with httpx.Client(timeout=30.0) as client:
        try:
            session_id = _init_mcp_session(client, endpoint)
        except httpx.RequestError as e:
            console.print(f"[red]Error connecting to MCP: {e}[/red]")
            return

        structs_list = _fetch_mcp_tool_raw(
            client,
            endpoint,
            "list-structures",
            {"programPath": program_path},
            1,
            session_id=session_id,
        )
        if not isinstance(structs_list, (list, dict)):
            console.print("[yellow]No structures found in Ghidra.[/yellow]")
            return

        struct_names: list[str] = []
        if isinstance(structs_list, list):
            for s in structs_list:
                name = s.get("name") if isinstance(s, dict) else str(s)
                if name:
                    struct_names.append(name)
        elif isinstance(structs_list, dict):
            structs_items = structs_list.get("structures") or structs_list.get("names") or []
            for name in structs_items:
                if isinstance(name, dict):
                    struct_names.append(name.get("name", ""))
                else:
                    struct_names.append(str(name))

        if not struct_names:
            text = str(structs_list)
            console.print(
                f"[yellow]list-structures returned data but no names extracted: {text[:200]}[/yellow]"
            )
            return

        header_lines = [
            "/* Auto-generated from Ghidra via rebrew sync --pull-structs */",
            f"/* {len(struct_names)} structures exported */",
            "",
            "#ifndef TYPES_H",
            "#define TYPES_H",
            "",
            "typedef unsigned char uint8_t;",
            "typedef unsigned short uint16_t;",
            "typedef unsigned int uint32_t;",
            "",
        ]

        exported = 0
        for i, name in enumerate(struct_names):
            if not name or name.startswith("_") and name.count("_") > 2:
                continue

            info = _fetch_mcp_tool_raw(
                client,
                endpoint,
                "get-structure-info",
                {"programPath": program_path, "structureName": name},
                100 + i,
                session_id=session_id,
            )
            if not info:
                continue

            c_def = None
            if isinstance(info, dict):
                c_def = (
                    info.get("cDefinition") or info.get("c_definition") or info.get("definition")
                )
                if not c_def:
                    fields = info.get("fields", [])
                    if fields:
                        size = info.get("size", "?")
                        header_lines.append(f"/* size: {size} */")
                        header_lines.append(f"typedef struct {name} {{")
                        for field_info in fields:
                            if isinstance(field_info, dict):
                                fname = field_info.get(
                                    "name", field_info.get("fieldName", "unknown")
                                )
                                ftype = field_info.get("dataType", field_info.get("type", "int"))
                                foffset = field_info.get("offset", "")
                                offset_comment = (
                                    f"  /* offset 0x{foffset:x} */"
                                    if isinstance(foffset, int)
                                    else ""
                                )
                                header_lines.append(f"    {ftype} {fname};{offset_comment}")
                            else:
                                header_lines.append(f"    /* {field_info} */")
                        header_lines.append(f"}} {name};")
                        header_lines.append("")
                        exported += 1
                        continue
            elif isinstance(info, str):
                c_def = info

            if c_def:
                header_lines.append(c_def.rstrip())
                header_lines.append("")
                exported += 1

        header_lines.append("#endif /* TYPES_H */")
        header_lines.append("")

        if exported > 0:
            out_file = cfg.reversed_dir / "types.h"
            header_text = "\n".join(header_lines)
            if not dry_run:
                out_file.write_text(header_text, encoding="utf-8")
            console.print(f"[green]Exported {exported} structures to {out_file}[/green]")
        else:
            console.print("[yellow]No exportable structures found.[/yellow]")


def _pull_comments(
    entries: list[Any], cfg: ProjectConfig, endpoint: str, program_path: str, dry_run: bool
) -> None:
    """Pull Ghidra analysis comments into source files."""
    console.print("Pulling comments from Ghidra...")

    # Determine address range from entries
    vas = [e.get("va") for e in entries if e.get("va")]
    if not vas:
        console.print("[yellow]No entries with VAs to pull comments for.[/yellow]")
        return
    min_va = min(vas)
    max_va = max(vas)
    # Extend range slightly to capture end-of-function comments
    addr_range = {"start": f"0x{min_va:x}", "end": f"0x{max_va + 0x10000:x}"}

    with httpx.Client(timeout=60.0) as client:
        try:
            session_id = _init_mcp_session(client, endpoint)
        except httpx.RequestError as e:
            console.print(f"[red]Error connecting to MCP: {e}[/red]")
            return

        result = _fetch_mcp_tool_raw(
            client,
            endpoint,
            "get-comments",
            {
                "programPath": program_path,
                "addressRange": addr_range,
                "commentTypes": ["eol", "pre", "post"],
            },
            1,
            session_id=session_id,
        )

        # Response is {"comments": [...]} dict or a list
        all_comments: list[Any] = []
        if isinstance(result, dict):
            all_comments = result.get("comments", [])
        elif isinstance(result, list):
            for item in result:
                if isinstance(item, dict) and "comments" in item:
                    all_comments.extend(item["comments"])
                elif isinstance(item, dict) and "address" in item:
                    all_comments.append(item)

        if not all_comments:
            console.print("[yellow]No comments found in Ghidra.[/yellow]")
            return

        # Group comments by VA, skip rebrew-generated ones
        comments_by_va: dict[int, list[str]] = {}
        for c in all_comments:
            va_raw = c.get("address")
            comment = c.get("comment", "")
            if not va_raw or not comment:
                continue
            if comment.startswith("[rebrew]"):
                continue
            try:
                va = int(va_raw, 16) if isinstance(va_raw, str) else int(va_raw)
                comments_by_va.setdefault(va, []).append(comment)
            except ValueError:
                pass

        # Build VA→entry lookup for matching comments to functions
        # A comment belongs to a function if its VA falls within [func_va, func_va + size)
        entry_ranges = []
        for entry in entries:
            va = entry.get("va")
            size = entry.get("size", 0)
            if va and size:
                entry_ranges.append((va, va + size, entry))
        entry_ranges.sort(key=lambda x: x[0])

        updated_count = 0
        matched_entries: dict[int, list[str]] = {}

        for comment_va, comment_list in comments_by_va.items():
            # Find which function this comment belongs to
            for start, end, entry in entry_ranges:
                if start <= comment_va < end:
                    entry_va = entry.get("va")
                    matched_entries.setdefault(entry_va, []).extend(comment_list)
                    break

        for entry_va, comment_list in matched_entries.items():
            entry = next((e for e in entries if e.get("va") == entry_va), None)
            if not entry:
                continue

            fp = cfg.reversed_dir / entry.get("filepath", "")
            if not fp.exists():
                continue

            combined_comments = " | ".join(c.replace("\n", " ") for c in comment_list if c)
            if not combined_comments:
                continue

            if not dry_run:
                update_annotation_key(
                    fp, entry_va, "ANALYSIS", combined_comments, metadata_dir=cfg.metadata_dir
                )
            console.print(
                f"  [green]Pulled comment[/green] for 0x{entry_va:x}: {combined_comments[:80]}..."
            )
            updated_count += 1

        console.print(f"Successfully pulled comments for {updated_count} functions.")


def _pull_data(
    cfg: ProjectConfig,
    endpoint: str,
    program_path: str,
    dry_run: bool,
) -> None:
    """Pull data labels from Ghidra and generate rebrew_globals.h.

    Fetches all non-function symbols from Ghidra via ReVa MCP (get-symbols),
    then queries data type info for each (get-data), and writes a header file
    with extern declarations.
    """
    try:
        httpx = __import__("httpx")
    except ImportError:
        error_exit("httpx is required for --pull-data. Install with: uv pip install httpx")

    def _canonical_section_name(section_name: str) -> str:
        name = section_name.lower()
        if ".data" in name:
            return ".data"
        if ".rdata" in name or "__const" in name:
            return ".rdata"
        if ".bss" in name or "zerofill" in name:
            return ".bss"
        return section_name

    def _find_section(va: int, sections: list[Any]) -> str:
        for section in sections:
            sec_va = int(getattr(section, "va", 0))
            sec_size = int(getattr(section, "size", 0))
            sec_raw_size = int(getattr(section, "raw_size", 0))
            span = max(sec_size, sec_raw_size)
            if span <= 0:
                continue
            if sec_va <= va < sec_va + span:
                return _canonical_section_name(str(getattr(section, "name", "")))
        return ""

    def _normalize_name(raw_name: str, fallback_addr: str) -> str:
        candidate = raw_name or f"g_{fallback_addr.lower().replace('0x', '')}"
        candidate = re.sub(r"[^A-Za-z0-9_]", "_", candidate)
        if not candidate:
            candidate = f"g_{fallback_addr.lower().replace('0x', '')}"
        if candidate[0].isdigit():
            candidate = f"g_{candidate}"
        return candidate

    _GHIDRA_TYPE_MAP: dict[str, str] = {
        "string": "char",
        "terminatedcstring": "char",
        "dword": "unsigned int",
        "byte": "unsigned char",
        "uchar": "unsigned char",
        "ushort": "unsigned short",
        "word": "unsigned short",
        "wchar16": "unsigned short",
        "unicode": "unsigned short",
        "sbyte": "signed char",
        "short": "short",
        "uint": "unsigned int",
        "ulong": "unsigned long",
        "long": "long",
        "longlong": "long long",
        "ulonglong": "unsigned long long",
        "float": "float",
        "double": "double",
        "bool": "int",
    }

    def _normalize_ghidra_type(dtype: str) -> str:
        """Map Ghidra-specific type names to valid C89 types."""
        lower = dtype.strip().lower()
        mapped = _GHIDRA_TYPE_MAP.get(lower)
        if mapped:
            return mapped
        return dtype.strip()

    def _build_extern_decl(data_type: str, symbol_name: str, length: int) -> tuple[str, str]:
        dtype = data_type.strip()
        lower = dtype.lower()

        if lower in {"pointer", "pointer32"}:
            return f"extern void* {symbol_name};", ""

        ptr_match = re.fullmatch(r"(.+?)\s*\*", dtype)
        if ptr_match:
            base = ptr_match.group(1).strip()
            base_lower = base.lower()
            if re.fullmatch(r"undefined(\d+)?", base_lower):
                return f"extern void* {symbol_name};", ""
            return f"extern {_normalize_ghidra_type(base)}* {symbol_name};", ""

        undef_match = re.fullmatch(r"undefined(\d+)?", lower)
        if undef_match:
            arr_len = max(length, int(undef_match.group(1) or "0"))
            if arr_len > 0:
                return f"extern unsigned char {symbol_name}[{arr_len}];", ""
            return f"extern unsigned char {symbol_name}[];", "unknown size"

        arr_match = re.fullmatch(r"(.+?)\[(.+)\]", dtype)
        if arr_match:
            base = _normalize_ghidra_type(arr_match.group(1).strip())
            dim = arr_match.group(2).strip()
            return f"extern {base} {symbol_name}[{dim}];", ""

        if dtype:
            c_type = _normalize_ghidra_type(dtype)
            is_string_type = lower in {"string", "terminatedcstring"}
            if is_string_type and length > 0:
                return f"extern {c_type} {symbol_name}[{length}];", ""
            elif is_string_type:
                return f"extern {c_type} {symbol_name}[];", ""
            return f"extern {c_type} {symbol_name};", ""

        if length > 0:
            return f"extern unsigned char {symbol_name}[{length}];", "unknown type"
        return f"extern unsigned char {symbol_name}[];", "unknown type/size"

    console.print("Pulling data labels from Ghidra...")

    sections: list[Any] = []
    try:
        from rebrew.binary_loader import load_binary

        binary_info = load_binary(cfg.target_binary, getattr(cfg, "format", "auto"))
        sections = list(binary_info.sections.values())
    except (ImportError, OSError, ValueError, AttributeError) as e:
        console.print(f"[yellow]Warning: Could not load binary sections: {e}[/yellow]")

    with httpx.Client(timeout=30.0) as client:
        try:
            session_id = _init_mcp_session(client, endpoint)
        except httpx.RequestError as e:
            console.print(f"[yellow]Warning: Could not connect to MCP endpoint: {e}[/yellow]")
            return

        try:
            count_result = _fetch_mcp_tool_raw(
                client,
                endpoint,
                "get-symbols-count",
                {
                    "programPath": program_path,
                    "filterDefaultNames": True,
                },
                1,
                session_id=session_id,
            )
        except httpx.RequestError as e:
            console.print(f"[yellow]Warning: Could not fetch symbols count: {e}[/yellow]")
            return

        total_count = 0
        if isinstance(count_result, dict):
            raw_count = count_result.get("count", 0)
            if isinstance(raw_count, int):
                total_count = raw_count

        page_size = 200
        request_id = 2
        all_symbols: list[dict[str, Any]] = []
        start = 0

        while True:
            try:
                page = _fetch_mcp_tool_raw(
                    client,
                    endpoint,
                    "get-symbols",
                    {
                        "programPath": program_path,
                        "startIndex": start,
                        "maxCount": page_size,
                        "filterDefaultNames": True,
                    },
                    request_id,
                    session_id=session_id,
                )
            except httpx.RequestError as e:
                console.print(f"[yellow]Warning: Could not fetch symbols page: {e}[/yellow]")
                return

            request_id += 1
            if not isinstance(page, list) or not page:
                break

            for sym in page:
                if isinstance(sym, dict):
                    all_symbols.append(sym)

            start += page_size
            if total_count > 0 and start >= total_count:
                break
            if len(page) < page_size:
                break

        data_symbols = [s for s in all_symbols if not s.get("isFunction", False)]
        if not data_symbols:
            console.print("[yellow]No non-function data symbols found in Ghidra.[/yellow]")
            return

        rows: list[dict[str, Any]] = []
        for sym in data_symbols:
            sym_addr = str(sym.get("address", "")).strip()
            if not sym_addr:
                continue

            try:
                data_info = _fetch_mcp_tool_raw(
                    client,
                    endpoint,
                    "get-data",
                    {
                        "programPath": program_path,
                        "addressOrSymbol": sym_addr,
                    },
                    request_id,
                    session_id=session_id,
                )
            except httpx.RequestError as e:
                console.print(f"[yellow]Warning: get-data failed at {sym_addr}: {e}[/yellow]")
                continue

            request_id += 1
            if not isinstance(data_info, dict):
                continue

            address = str(data_info.get("address") or sym_addr)
            va = _parse_va(address)
            if va is None:
                continue

            symbol_name = _normalize_name(
                str(data_info.get("symbolName") or sym.get("name") or ""),
                address,
            )

            length_raw = data_info.get("length", 0)
            length = int(length_raw) if isinstance(length_raw, int | float) else 0
            data_type = str(data_info.get("dataType") or "")
            decl, type_note = _build_extern_decl(data_type, symbol_name, length)
            section_name = _find_section(va, sections)

            note_parts = [f"0x{va:08X}", f"{length} bytes"]
            if type_note:
                note_parts.append(type_note)
            rows.append(
                {
                    "va": va,
                    "section": section_name,
                    "decl": decl,
                    "note": ", ".join(note_parts),
                }
            )

    if not rows:
        console.print("[yellow]No data declarations generated from Ghidra symbols.[/yellow]")
        return

    rows.sort(key=lambda x: int(x["va"]))

    seen_va: set[int] = set()
    deduped: list[dict[str, Any]] = []
    for row in rows:
        va = int(row["va"])
        if va in seen_va:
            continue
        seen_va.add(va)
        deduped.append(row)

    dup_count = len(rows) - len(deduped)
    if dup_count:
        console.print(f"  Deduplicated {dup_count} duplicate address(es)")
    rows = deduped

    grouped: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        sec = str(row.get("section") or "")
        grouped.setdefault(sec, []).append(row)

    out_file = cfg.reversed_dir / "rebrew_globals.h"
    generated = time.strftime("%Y-%m-%d %H:%M:%S")

    header_lines = [
        "/* Auto-generated by rebrew sync --pull-data. DO NOT EDIT.",
        " * Source: Ghidra via ReVa MCP",
        f" * Generated: {generated}",
        " */",
        "",
        "#ifndef REBREW_GLOBALS_H",
        "#define REBREW_GLOBALS_H",
        "",
    ]

    section_order = [".data", ".rdata", ".bss"]
    emitted_sections: set[str] = set()
    for section_name in section_order:
        items = grouped.get(section_name, [])
        if not items:
            continue
        header_lines.append(f"/* {section_name} section globals */")
        for row in items:
            header_lines.append(f"{row['decl']} /* {row['note']} */")
        header_lines.append("")
        emitted_sections.add(section_name)

    for section_name in sorted(grouped):
        if section_name in emitted_sections:
            continue
        items = grouped[section_name]
        label = section_name or "(unknown)"
        header_lines.append(f"/* {label} section globals */")
        for row in items:
            header_lines.append(f"{row['decl']} /* {row['note']} */")
        header_lines.append("")

    header_lines.append("#endif /* REBREW_GLOBALS_H */")
    header_lines.append("")
    header_text = "\n".join(header_lines)

    if dry_run:
        console.print(f"[yellow]Dry run: would write {out_file} with {len(rows)} globals[/yellow]")
        console.print(header_text)
        return

    out_file.write_text(header_text, encoding="utf-8")
    console.print(f"Pulled {len(rows)} data labels from Ghidra, wrote {out_file.name}")
