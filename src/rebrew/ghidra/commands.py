"""ReVa MCP command builder for Ghidra integration.

Constructs MCP commands and orchestrates Ghidra sync operations, including
command building for push operations and direct MCP communication for pull
operations.
"""

import json
import re
import time
from bisect import bisect_right
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from rebrew.catalog.registry import RegistryEntry
import httpx
from rich.console import Console

from rebrew.annotation import Annotation, update_annotation_key
from rebrew.cli import json_print
from rebrew.config import FUNCTION_STRUCTURE_JSON, ProjectConfig
from rebrew.ghidra.client import (
    fetch_all_functions,
    fetch_all_symbols,
    fetch_mcp_tool,
    fetch_mcp_tool_raw,
    init_mcp_session,
)
from rebrew.ghidra.models import PullChange, PullResult
from rebrew.rename_ops import rename_function_everywhere
from rebrew.sources import iter_sources
from rebrew.utils import atomic_write_text, read_source_text

console = Console(stderr=True)

# Pattern matching generic auto-names that shouldn't overwrite Ghidra renames
_GENERIC_NAME_RE = re.compile(r"^_?(func_|FUN_)[0-9a-fA-F]+(@\d+)?$")

# Matches non-identifier characters to remove from symbol names.
_NORMALIZE_NAME_RE = re.compile(r"[^A-Za-z0-9_]")

# Status → bookmark category prefix for visual distinction
_STATUS_BOOKMARK_CATEGORY = {
    "EXACT": "rebrew/exact",
    "RELOC": "rebrew/reloc",
    "NEAR_MATCHING": "rebrew/matching",
    "STUB": "rebrew/stub",
}


def is_generic_name(name: str) -> bool:
    """Return True if *name* is a default auto-generated name like func_10006c00."""
    return bool(_GENERIC_NAME_RE.match(name))


def _label_cmd(program_path: str, va_hex: str, name: str) -> dict[str, Any]:
    """Build a ``create-label`` MCP command."""
    return {
        "tool": "create-label",
        "args": {
            "programPath": program_path,
            "addressOrSymbol": va_hex,
            "labelName": name,
            "setAsPrimary": True,
        },
    }


def _comment_cmd(
    program_path: str, va_hex: str, comment: str, comment_type: str = "plate"
) -> dict[str, Any]:
    """Build a ``set-comment`` MCP command."""
    return {
        "tool": "set-comment",
        "args": {
            "programPath": program_path,
            "addressOrSymbol": va_hex,
            "comment": comment,
            "commentType": comment_type,
        },
    }


def _bookmark_cmd(program_path: str, va_hex: str, category: str, comment: str) -> dict[str, Any]:
    """Build a ``set-bookmark`` MCP command (always of Ghidra type ``Note``)."""
    return {
        "tool": "set-bookmark",
        "args": {
            "programPath": program_path,
            "addressOrSymbol": va_hex,
            "type": "Note",
            "category": category,
            "comment": comment,
        },
    }


def resolve_program_path(cfg: ProjectConfig) -> str:
    """Return the Ghidra program path from config or derive from binary name."""
    configured = getattr(cfg, "ghidra_program_path", "")
    if configured:
        return configured
    return f"/{cfg.target_binary.name}"


def validate_program_path(
    client: httpx.Client,
    endpoint: str,
    program_path: str,
    session_id: str,
) -> str:
    """Best-effort validation of derived programPath against current Ghidra project."""
    try:
        result = fetch_mcp_tool_raw(
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
        console.print(
            f"[yellow]warning:[/yellow] Ghidra has '{ghidra_path}' open, but rebrew derived '{program_path}'. "
            f'Add ghidra_program_path = "{ghidra_path}" to [targets.X] in '
            "rebrew-project.toml to fix."
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

    Generates commands for function labels, prototypes, comments, and optionally
    struct definitions.  If *data_scan* (ScanResult) is provided, also generates
    commands for globals.
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
    # Must run BEFORE create-label — setting the prototype also sets the name,
    # so a subsequent createLabel() would produce a secondary LABEL-type symbol
    # that triggers DuplicateNameException.
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
        if va in sig_vas or skip_generic_labels and is_generic_name(name):
            skipped_labels += 1
        else:
            commands.append(_label_cmd(program_path, va_hex, name))

        comment_lines = [
            f"[rebrew] {primary.get('marker_type', 'FUNCTION')}: {status}",
            f"Module: {primary.get('module', '')}",
            f"Size: {primary.get('size', 0)}B",
            f"CFlags: {primary.get('cflags', '')}",
            f"Symbol: {primary.get('symbol', '')}",
            f"Files: {', '.join(e.get('filepath', '') for e in elist)}",
        ]
        commands.append(_comment_cmd(program_path, va_hex, "\n".join(comment_lines)))

        bm_category = _STATUS_BOOKMARK_CATEGORY.get(
            status, primary.get("module", "").lower() or "rebrew"
        )
        bm_comment = f"{name} - {status} ({primary.get('size', 0)}B, {primary.get('cflags', '')})"
        commands.append(_bookmark_cmd(program_path, va_hex, bm_category, bm_comment))

        # Push NOTE as a pre-comment (separate from plate metadata)
        note = primary.get("note", "")
        if note:
            commands.append(_comment_cmd(program_path, va_hex, note, "pre"))

    # Phase 4: Push Data / Globals
    if data_scan is not None:
        # Push variables identified by data_scan.globals
        for name, g_entry in sorted(data_scan.globals.items()):
            if not g_entry.va:
                continue
            va_hex = f"0x{g_entry.va:08X}"

            # Label
            if not skip_generic_labels or not is_generic_name(name):
                commands.append(_label_cmd(program_path, va_hex, name))

            # Comment
            comment_lines = [
                "[rebrew] GLOBAL",
                f"Type: {g_entry.type_str}",
            ]
            if g_entry.section:
                comment_lines.append(f"Section: {g_entry.section}")
            if g_entry.declared_in:
                comment_lines.append(f"Files: {', '.join(g_entry.declared_in)}")

            commands.append(_comment_cmd(program_path, va_hex, "\n".join(comment_lines)))

            # Bookmark
            commands.append(
                _bookmark_cmd(
                    program_path, va_hex, "rebrew/data", f"Global: {g_entry.type_str} {name}"
                )
            )

        # Push raw // DATA: annotations that might not be in globals
        for d_entry in data_scan.data_annotations:
            va_hex = d_entry["va"]
            name = d_entry["name"]

            # Label
            if not skip_generic_labels or not is_generic_name(name):
                commands.append(_label_cmd(program_path, va_hex, name))

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

            commands.append(_comment_cmd(program_path, va_hex, "\n".join(comment_lines)))

            commands.append(
                _bookmark_cmd(
                    program_path, va_hex, "rebrew/data", f"Data: {name} ({d_entry['size']}B)"
                )
            )

    if skipped_labels > 0:
        console.print(f"  Skipped {skipped_labels} generic labels (func_XXXXXXXX)")

    return commands


def parse_ghidra_va(va_raw: str | int | None) -> int | None:
    """Normalize a VA from hex string, decimal string, or int to int.  Returns None if invalid."""
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


def is_meaningful_name(name: str) -> bool:
    """Return True if a name carries real semantic information (not auto-generated by Ghidra/r2)."""
    return bool(name) and not (
        is_generic_name(name) or name.startswith(("FUN_", "DAT_", "switchdata", "thunk_"))
    )


def ghidra_name_to_symbol(
    ghidra_name: str, entry: Annotation | dict[str, str], cfg: ProjectConfig | None = None
) -> str:
    """Convert a Ghidra function name to a C symbol name.

    Applies underscore prefix rules based on the config's symbol_prefix,
    the entry's existing symbol or calling convention (``/Gz`` = __stdcall).
    """
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
        transport = "ghidra-cli" if getattr(cfg, "ghidra_backend", "reva") == "cli" else "ReVa MCP"
        console.print(f"Fetching function, data, and comment lists from Ghidra via {transport}...")
    functions: list[Any] = []
    data_labels: list[Any] = []
    plate_comments: list[Any] = []
    pre_comments: list[Any] = []

    backend = getattr(cfg, "ghidra_backend", "reva")
    if backend == "cli":
        # ghidra-cli backend: one batched fetch instead of MCP calls.
        from rebrew.ghidra.cli_backend import fetch_pull_data_via_cli, resolve_ghidra_cli

        pull_data = fetch_pull_data_via_cli(
            program=program_path, ghidra_cli=resolve_ghidra_cli(cfg) or "ghidra-cli"
        )
        functions = pull_data["functions"]
        data_labels = pull_data["symbols"]
        plate_comments = pull_data["plate"]
        pre_comments = pull_data["pre"]

    if backend != "cli":
        with httpx.Client(timeout=30.0) as client:
            session_id = ""
            try:
                session_id = init_mcp_session(client, endpoint)

                functions = fetch_all_functions(client, endpoint, program_path, session_id)
                data_labels = fetch_all_symbols(client, endpoint, program_path, session_id)
                plate_comments = fetch_mcp_tool(
                    client,
                    endpoint,
                    "get-comments",
                    {"programPath": program_path, "commentTypes": ["plate"]},
                    3,
                    session_id=session_id,
                )
                pre_comments = fetch_mcp_tool(
                    client,
                    endpoint,
                    "get-comments",
                    {"programPath": program_path, "commentTypes": ["pre"]},
                    4,
                    session_id=session_id,
                )
            except httpx.RequestError as e:
                console.print(f"[yellow]warning:[/yellow] Could not connect to ReVa MCP ({e}).")
                console.print("Falling back to local caches...")

    if not functions:
        ghidra_json_path = cfg.reversed_dir / FUNCTION_STRUCTURE_JSON
        if ghidra_json_path.exists():
            try:
                functions = json.loads(ghidra_json_path.read_text(encoding="utf-8"))
                if not dry_run:
                    console.print(f"Loaded {len(functions)} functions from {ghidra_json_path.name}")
            except (json.JSONDecodeError, OSError) as e:
                console.print(f"[red bold]error:[/red bold] reading cache: {e}")
        else:
            console.print(
                f"[yellow]warning:[/yellow] Could not fetch functions and {ghidra_json_path.name} not found."
            )

    if not data_labels:
        data_json_path = cfg.reversed_dir / "ghidra_data_labels.json"
        if data_json_path.exists():
            try:
                data_labels = json.loads(data_json_path.read_text(encoding="utf-8"))
                if not dry_run:
                    console.print(
                        f"Loaded {len(data_labels)} data labels from {data_json_path.name}"
                    )
            except (json.JSONDecodeError, OSError) as e:
                console.print(f"[red bold]error:[/red bold] reading {data_json_path.name}: {e}")

    if not functions and not data_labels:
        return result

    ghidra_names_by_va: dict[int, str] = {}
    for f in functions:
        va = parse_ghidra_va(f.get("va") or f.get("address"))
        gname = f.get("tool_name") or f.get("ghidra_name") or f.get("name")
        if va is not None and gname:
            ghidra_names_by_va[va] = gname

    for d in data_labels:
        va = parse_ghidra_va(d.get("va") or d.get("address"))
        name = d.get("name") or d.get("label") or d.get("ghidra_name")
        if va is not None and name:
            ghidra_names_by_va[va] = name

    ghidra_comments_by_va: dict[int, str] = {}
    for c in plate_comments:
        va = parse_ghidra_va(c.get("address"))
        comment = c.get("comment")
        if va is not None and comment and not comment.startswith("[rebrew]"):
            ghidra_comments_by_va[va] = comment.strip()

    for c in pre_comments:
        va = parse_ghidra_va(c.get("address"))
        comment = c.get("comment")
        if va is not None and comment and not comment.startswith("[rebrew]"):
            ghidra_comments_by_va.setdefault(va, comment.strip())

    from rebrew.data import scan_data_annotations

    all_entries = list(entries)
    all_entries.extend(scan_data_annotations(cfg.reversed_dir, cfg=cfg))

    for entry in all_entries:
        va = parse_ghidra_va(entry.get("va"))
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
        if ghidra_name and is_meaningful_name(ghidra_name):
            local_name = entry.get("symbol") or entry.get("name") or f"func_{va:08x}"
            ghidra_as_symbol = ghidra_name_to_symbol(ghidra_name, entry, cfg)
            if local_name != ghidra_as_symbol:
                local_is_meaningful = is_meaningful_name(local_name)
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
                            console.print(
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
                                console.print(
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
                            console.print(
                                f"  Would update 0x{va:08x}: {local_name} -> {ghidra_name}"
                            )
                    else:
                        if not json_output:
                            console.print(
                                f"  Updating VA 0x{va:08x}: {local_name} -> {ghidra_name}"
                            )

                        if entry.get("marker_type", "FUNCTION") == "FUNCTION":
                            old_name = entry.get("name", "")
                            old_sym = entry.get("symbol", "")
                            if not old_sym:
                                old_sym = old_name
                            target_func = ghidra_name.lstrip("_")

                            rename_function_everywhere(
                                cfg=cfg,
                                filepath=filepath,
                                old_name=old_name,
                                old_sym=old_sym,
                                target_func=target_func,
                                rename_file=True,
                                dry_run=dry_run,
                            )
                        else:
                            # DATA/GLOBAL entries — write name to rebrew-data.toml metadata
                            module = entry.get("module", "")
                            if module and not dry_run:
                                from rebrew.data_metadata import set_data_field

                                set_data_field(
                                    cfg.metadata_dir,
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
                        console.print(f"  Would update NOTE at 0x{va:08x}")
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
                                console.print(f"  Updated NOTE in rebrew-data.toml at 0x{va:08x}")
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
                            console.print(f"  Updated NOTE at 0x{va:08x}")

    if json_output:
        json_print(result.to_dict())
    elif result.updated == 0 and result.conflicts == 0:
        console.print("No new data to pull from Ghidra.")
    else:
        verb = "Would pull" if dry_run else "Successfully pulled"
        console.print(f"{verb} {result.updated} updates from Ghidra.")
        if result.conflicts > 0:
            console.print(
                f"  {result.conflicts} conflict(s) skipped "
                "(both sides have meaningful names — resolve manually)"
            )

    return result


def build_size_sync_commands(
    registry: dict[int, "RegistryEntry"],
    program_path: str,
    iat_thunks: set[int] | None = None,
) -> list[dict[str, Any]]:
    """Generate commands to expand function boundaries where function list size exceeds Ghidra size."""
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
    """Generate create-function commands for functions in the list but not detected by Ghidra."""
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


def pull_prototypes(
    entries: list[Any],
    cfg: ProjectConfig,
    endpoint: str,
    program_path: str,
    dry_run: bool,
    replace_externs: bool = False,
) -> None:
    """Pull function prototypes from Ghidra and update local files.

    Args:
        entries: Annotation entries to match against Ghidra functions.
        cfg: Project configuration.
        endpoint: ReVa MCP endpoint URL.
        program_path: Ghidra program path for MCP requests.
        dry_run: If True, report changes without writing files.
        replace_externs: When False (default), only writes ``// PROTOTYPE:``
            annotations.  When True, also replaces extern declarations
            (WARNING: Ghidra types like uint/byte may not be valid C89/MSVC6).
    """
    console.print("Pulling function prototypes from Ghidra...")

    with httpx.Client(timeout=30.0) as client:
        try:
            session_id = init_mcp_session(client, endpoint)
        except httpx.RequestError as e:
            raise RuntimeError(f"Error connecting to MCP: {e}") from e

        updated_count = 0

        # Paginate through all functions
        all_funcs: list[Any] = []
        start_index = 0
        page_size = 200
        request_id = 1
        while True:
            page = fetch_mcp_tool_raw(
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
            # ReVa MCP may return pagination metadata as the first item
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
                res = fetch_mcp_tool_raw(
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
                            actual_name = sym.lstrip("_")

                            extern_str = f"extern {sig};"

                            for src_file in iter_sources(cfg.reversed_dir, cfg):
                                try:
                                    content, encoding = read_source_text(src_file)
                                    # Regex to match existing extern for this function
                                    # extern <type> <name>(...);
                                    pattern = (
                                        r"extern\s+[^;]+?\b"
                                        + re.escape(actual_name)
                                        + r"\s*\([^;]*\)\s*;"
                                    )
                                    new_content = re.sub(pattern, extern_str, content)
                                    if new_content != content:
                                        atomic_write_text(src_file, new_content, encoding=encoding)
                                except OSError as e:
                                    console.print(
                                        f"  [yellow]Warning:[/yellow] failed to replace extern "
                                        f"for 0x{va:x} in {src_file}: {e}"
                                    )

                    console.print(f"  [green]Updated prototype[/green] 0x{va:x}: {sig}")
                    updated_count += 1

        console.print(f"Successfully pulled {updated_count} prototypes.")


def pull_params(
    entries: list[Any],
    cfg: ProjectConfig,
    endpoint: str,
    program_path: str,
    dry_run: bool,
) -> int:
    """Pull Ghidra parameter names into unnamed parameters of local .c files.

    Uses the same get-decompilation signature source as pull_signatures:
    the decompiled prototype carries Ghidra's parameter names.  Merge-safe —
    a parameter that already has a local name is never overwritten, and any
    signature that is unsafe to rewrite (function-pointer params, arity
    mismatch) is skipped.  Returns the number of files rewritten.
    """
    from rebrew.ghidra.params import apply_param_names, param_names_from_proto

    console.print("Pulling parameter names from Ghidra...")
    with httpx.Client(timeout=30.0) as client:
        try:
            session_id = init_mcp_session(client, endpoint)
        except httpx.RequestError as e:
            raise RuntimeError(f"Error connecting to MCP: {e}") from e

        updated = 0
        for entry in entries:
            marker = entry.get("marker_type", "FUNCTION")
            if marker != "FUNCTION":
                continue
            va = entry.get("va")
            func_name = entry.get("name") or entry.get("symbol") or ""
            if not va or not func_name:
                continue
            filepath = entry.get("filepath")
            if not filepath:
                continue
            fp = cfg.reversed_dir / filepath
            if not fp.exists():
                continue

            try:
                content, encoding = read_source_text(fp)
            except OSError:
                continue

            res = fetch_mcp_tool_raw(
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
            else:
                continue
            sig = sig.replace("\n", " ").strip().rstrip(";").strip()

            names = param_names_from_proto(sig)
            if names is None:
                continue  # unsafe or unparseable — never guess
            rewritten = apply_param_names(content, func_name, names)
            if rewritten is None or rewritten == content:
                continue  # nothing to fill or arity mismatch

            if dry_run:
                console.print(f"  [dim]Would name params[/dim] 0x{va:x} {func_name}: {names}")
                updated += 1
                continue
            atomic_write_text(fp, rewritten, encoding=encoding)
            console.print(f"  [green]Named params[/green] 0x{va:x} {func_name}: {names}")
            updated += 1

        console.print(f"Successfully named params for {updated} function(s).")
        return updated


def _infer_struct_module(info: Any) -> str | None:
    """Infer a module name from Ghidra struct metadata.

    Returns the upper-cased module string (e.g. ``"SERVER"``) or ``None``
    when no module attribution can be determined.  The ``info`` dict may
    carry a ``category``, ``namespace``, or ``categoryPath`` field set by
    Ghidra / ReVa — the first path component is taken as the module.
    """
    if not isinstance(info, dict):
        return None
    raw: str | None = (
        info.get("namespace")
        or info.get("category")
        or info.get("categoryPath")
        or info.get("category_path")
    )
    if not raw:
        return None
    # Strip leading slashes and take the first path component.
    segment = raw.lstrip("/").split("/")[0].strip()
    if not segment:
        return None
    return segment.upper()


def _make_header_preamble(n_structs: int, guard: str) -> list[str]:
    """Return the standard header preamble lines for a types header."""
    return [
        "/* Auto-generated from Ghidra via rebrew sync --pull-structs */",
        f"/* {n_structs} structures exported */",
        "",
        f"#ifndef {guard}",
        f"#define {guard}",
        "",
        "typedef unsigned char uint8_t;",
        "typedef unsigned short uint16_t;",
        "typedef unsigned int uint32_t;",
        "",
    ]


def _append_struct_def(lines: list[str], name: str, info: Any) -> bool:
    """Append a C struct definition from *info* to *lines*.

    Returns ``True`` if a definition was appended, ``False`` if *info*
    carried no usable definition.
    """
    c_def: str | None = None
    if isinstance(info, dict):
        c_def = info.get("cDefinition") or info.get("c_definition") or info.get("definition")
        if not c_def:
            fields = info.get("fields", [])
            if fields:
                size = info.get("size", "?")
                lines.append(f"/* size: {size} */")
                lines.append(f"typedef struct {name} {{")
                for field_info in fields:
                    if isinstance(field_info, dict):
                        fname = field_info.get("name", field_info.get("fieldName", "unknown"))
                        ftype = field_info.get("dataType", field_info.get("type", "int"))
                        foffset = field_info.get("offset", "")
                        offset_comment = (
                            f"  /* offset 0x{foffset:x} */" if isinstance(foffset, int) else ""
                        )
                        lines.append(f"    {ftype} {fname};{offset_comment}")
                    else:
                        lines.append(f"    /* {field_info} */")
                lines.append(f"}} {name};")
                lines.append("")
                return True
    elif isinstance(info, str):
        c_def = info

    if c_def:
        lines.append(c_def.rstrip())
        lines.append("")
        return True
    return False


def pull_structs(
    cfg: ProjectConfig,
    endpoint: str,
    program_path: str,
    dry_run: bool,
    types_out: Path | None = None,
    by_module: bool = False,
) -> None:
    """Pull struct definitions from Ghidra into types.h (or per-module files).

    Fetches structure names via ``list-structures``, retrieves each definition
    via ``get-structure-info``, and writes a consolidated header file.

    :param cfg: Project configuration.
    :param endpoint: ReVa MCP endpoint URL.
    :param program_path: Ghidra program path.
    :param dry_run: When ``True``, print what would be written without writing.
    :param types_out: Override the output path (single-file mode only).
    :param by_module: Split output into one file per inferred origin module;
        structs with no module attribution go into ``types_shared.h``.
    """
    console.print("Pulling struct definitions from Ghidra...")

    with httpx.Client(timeout=30.0) as client:
        try:
            session_id = init_mcp_session(client, endpoint)
        except httpx.RequestError as e:
            raise RuntimeError(f"Error connecting to MCP: {e}") from e

        structs_list = fetch_mcp_tool_raw(
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

        # ------------------------------------------------------------------ #
        # Parse the struct name list from whatever shape Ghidra returns.      #
        # ------------------------------------------------------------------ #
        struct_entries: list[dict[str, Any]] = []
        if isinstance(structs_list, list):
            for s in structs_list:
                if isinstance(s, dict):
                    name = s.get("name", "")
                    namespace = s.get("namespace") or s.get("category") or s.get("categoryPath")
                    struct_entries.append({"name": name, "namespace": namespace})
                else:
                    struct_entries.append({"name": str(s), "namespace": None})
        elif isinstance(structs_list, dict):
            structs_items = structs_list.get("structures") or structs_list.get("names") or []
            for item in structs_items:
                if isinstance(item, dict):
                    name = item.get("name", "")
                    namespace = (
                        item.get("namespace") or item.get("category") or item.get("categoryPath")
                    )
                    struct_entries.append({"name": name, "namespace": namespace})
                else:
                    struct_entries.append({"name": str(item), "namespace": None})

        struct_entries = [e for e in struct_entries if e["name"]]

        if not struct_entries:
            text = str(structs_list)
            console.print(
                f"[yellow]list-structures returned data but no names extracted: {text[:200]}[/yellow]"
            )
            return

        # ------------------------------------------------------------------ #
        # Fetch individual struct info and collect definitions.               #
        # ------------------------------------------------------------------ #
        # module_defs: module_key -> list[str lines]
        # "shared" key is used for structs with no module attribution.
        module_defs: dict[str, list[str]] = {}
        single_lines: list[str] = []
        exported = 0

        for i, entry in enumerate(struct_entries):
            struct_name: str = entry["name"]
            if not struct_name or (struct_name.startswith("_") and struct_name.count("_") > 2):
                continue

            info = fetch_mcp_tool_raw(
                client,
                endpoint,
                "get-structure-info",
                {"programPath": program_path, "structureName": struct_name},
                100 + i,
                session_id=session_id,
            )
            if not info:
                continue

            # Infer module from the list entry first; fall back to info dict.
            module: str | None = None
            if entry.get("namespace"):
                raw_ns: str = str(entry["namespace"]).lstrip("/").split("/")[0].strip()
                if raw_ns:
                    module = raw_ns.upper()
            if module is None:
                module = _infer_struct_module(info)

            if by_module:
                bucket = module if module else "SHARED"
                buf = module_defs.setdefault(bucket, [])
                if _append_struct_def(buf, struct_name, info):
                    exported += 1
            else:
                if _append_struct_def(single_lines, struct_name, info):
                    exported += 1

        if exported == 0:
            console.print("[yellow]No exportable structures found.[/yellow]")
            return

        # ------------------------------------------------------------------ #
        # Write output files.                                                 #
        # ------------------------------------------------------------------ #
        if by_module:
            for bucket, defs in sorted(module_defs.items()):
                if not defs:
                    continue
                guard = f"TYPES_{bucket}_H"
                filename = f"types_{bucket.lower()}.h"
                out_file = cfg.reversed_dir / filename
                preamble = _make_header_preamble(len(defs), guard)
                text = "\n".join(preamble + defs + [f"#endif /* {guard} */", ""])
                if not dry_run:
                    atomic_write_text(out_file, text)
                console.print(f"[green]Exported {len(defs)} structures → {out_file}[/green]")
        else:
            out_file = types_out if types_out is not None else cfg.reversed_dir / "types.h"
            preamble = _make_header_preamble(exported, "TYPES_H")
            text = "\n".join(preamble + single_lines + ["#endif /* TYPES_H */", ""])
            if not dry_run:
                atomic_write_text(out_file, text)
            console.print(f"[green]Exported {exported} structures to {out_file}[/green]")


_DATATYPE_CATEGORIES = ("/Enum", "/TypeDef")
_DATATYPE_PAGE_SIZE = 500

#: Marker for the merge-safe user section in enums_types.h — everything from
#: this line to the #endif survives regeneration (manual definitions).
_USER_MARKER = "/* --- USER DEFINITIONS (kept on re-pull) --- */"


def pull_datatypes(
    cfg: ProjectConfig,
    endpoint: str,
    program_path: str,
    *,
    dry_run: bool = False,
    types_out: Path | None = None,
) -> None:
    """Pull the user-defined enum + typedef inventory from Ghidra into a header.

    Uses ReVa's ``get-data-types`` MCP tool with ``categoryPath="/Enum"`` and
    ``"/TypeDef"`` (an empty ``archiveName`` makes ReVa search every data type
    manager, including the target program's own, per DataTypeParserUtil).
    Pagination is followed via ``totalCount``/``returnedCount``.

    ReVa's MCP surface does not expose enum member values (the datatypes
    response carries name/displayName/categoryPath/size/alignment only), so
    this emits an honest manifest - name, size, category - rather than
    fabricated C definitions.  Define the enums in source and push them with
    ``rebrew sync --push`` when member values are needed in Ghidra.

    :param cfg: Project configuration (``cfg.reversed_dir`` is the default output dir).
    :param endpoint: ReVa MCP endpoint URL.
    :param program_path: Ghidra program path.
    :param dry_run: Print what would be written without writing.
    :param types_out: Override the output path (default ``<reversed_dir>/enums_types.h``).
    """
    console.print("Pulling enum/typedef inventory from Ghidra...")

    with httpx.Client(timeout=30.0) as client:
        try:
            session_id = init_mcp_session(client, endpoint)
        except httpx.RequestError as e:
            raise RuntimeError(f"Error connecting to MCP: {e}") from e

        # (kind, name, size, category)
        manifest: list[tuple[str, str, int, str]] = []

        for category in _DATATYPE_CATEGORIES:
            start_index = 0
            while True:
                result = fetch_mcp_tool_raw(
                    client,
                    endpoint,
                    "get-data-types",
                    {
                        "programPath": program_path,
                        "archiveName": "",
                        "categoryPath": category,
                        "includeSubcategories": True,
                        "startIndex": start_index,
                        "maxCount": _DATATYPE_PAGE_SIZE,
                    },
                    1,
                    session_id=session_id,
                )
                if not isinstance(result, dict):
                    break
                items = result.get("dataTypes")
                if not isinstance(items, list):
                    break
                for item in items:
                    if not isinstance(item, dict):
                        continue
                    name = item.get("name")
                    if not name:
                        continue
                    size = item.get("size")
                    size_int = int(size) if isinstance(size, int) else 0
                    cat = str(item.get("categoryPath") or category)
                    kind = "enum" if category == "/Enum" else "typedef"
                    manifest.append((kind, str(name), size_int, cat))
                total = result.get("totalCount")
                returned = result.get("returnedCount")
                if (
                    not isinstance(total, int)
                    or not isinstance(returned, int)
                    or returned <= 0
                    or start_index + returned >= total
                ):
                    break
                start_index += returned

        if not manifest:
            console.print("[yellow]No user-defined enums or typedefs found in Ghidra.[/yellow]")
            return

        lines: list[str] = []
        for kind, heading in (("enum", "Enums"), ("typedef", "Typedefs")):
            entries = [(n, s, c) for k, n, s, c in manifest if k == kind]
            if not entries:
                continue
            lines.append(f"/* {heading} ({len(entries)}) */")
            for name, size, cat in sorted(entries):
                lines.append(f"/* {name} - size {size} - {cat} */")
            lines.append("")

        preamble = _make_header_preamble(len(manifest), "REBREW_DATATYPES_H")
        note = (
            "/* ReVa's MCP protocol exposes enum/typedef names, sizes, and categories "
            "but not enum member values. Define enums in source and push with "
            "'rebrew sync --sync-structs' to create them in Ghidra. */"
        )

        # Merge-safe re-pull: a user section between the marker and #endif is
        # preserved verbatim across regenerations (manual definitions, notes).
        out_file = types_out if types_out is not None else cfg.reversed_dir / "enums_types.h"
        user_trailer = ""
        if out_file.exists():
            try:
                old_text = out_file.read_text(encoding="utf-8")
            except OSError:
                old_text = ""
            idx = old_text.find(_USER_MARKER)
            if idx >= 0:
                # Preserve everything from the marker up to (not including)
                # the closing #endif, so re-pulls never duplicate the guard.
                trailer = old_text[idx:]
                end_idx = trailer.find("#endif")
                if end_idx >= 0:
                    trailer = trailer[:end_idx]
                user_trailer = trailer
        if not user_trailer:
            user_trailer = (
                _USER_MARKER + "\n/* Manual definitions below survive re-pulls (merge-safe). */\n"
            )
        if not user_trailer.endswith("\n"):
            user_trailer += "\n"

        text = (
            "\n".join(preamble + [note, ""] + lines + [""])
            + user_trailer
            + "#endif /* REBREW_DATATYPES_H */\n"
        )

        if not dry_run:
            atomic_write_text(out_file, text)
        console.print(f"[green]Exported {len(manifest)} datatypes to {out_file}[/green]")


def pull_comments(
    entries: list[Any], cfg: ProjectConfig, endpoint: str, program_path: str, dry_run: bool
) -> None:
    """Pull Ghidra analysis comments into source files.

    Fetches comments in the VA range covered by *entries* and writes them
    as ``// ANALYSIS:`` annotations into the corresponding ``.c`` files.
    """
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
            session_id = init_mcp_session(client, endpoint)
        except httpx.RequestError as e:
            raise RuntimeError(f"Error connecting to MCP: {e}") from e

        result = fetch_mcp_tool_raw(
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
        entries_by_va: dict[int, Any] = {}
        for entry in entries:
            va = entry.get("va")
            size = entry.get("size", 0)
            if va and size:
                entry_ranges.append((va, va + size, entry))
                entries_by_va[va] = entry
        entry_ranges.sort(key=lambda x: x[0])
        range_starts = [start for start, _end, _entry in entry_ranges]

        updated_count = 0
        matched_entries: dict[int, list[str]] = {}

        for comment_va, comment_list in comments_by_va.items():
            # Find which function this comment belongs to
            range_index = bisect_right(range_starts, comment_va) - 1
            if range_index >= 0:
                start, end, entry = entry_ranges[range_index]
                if start <= comment_va < end:
                    entry_va = entry.get("va")
                    matched_entries.setdefault(entry_va, []).extend(comment_list)

        for entry_va, comment_list in matched_entries.items():
            entry = entries_by_va.get(entry_va)
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


def pull_data(
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
        candidate = _NORMALIZE_NAME_RE.sub("_", candidate)
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

        binary_info = load_binary(cfg.target_binary, getattr(cfg, "binary_format", "auto"))
        sections = list(binary_info.sections.values())
    except (ImportError, OSError, ValueError, AttributeError) as e:
        console.print(f"[yellow]warning:[/yellow] Could not load binary sections: {e}")

    with httpx.Client(timeout=30.0) as client:
        try:
            session_id = init_mcp_session(client, endpoint)
        except httpx.RequestError as e:
            console.print(f"[yellow]warning:[/yellow] Could not connect to MCP endpoint: {e}")
            return

        try:
            count_result = fetch_mcp_tool_raw(
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
            console.print(f"[yellow]warning:[/yellow] Could not fetch symbols count: {e}")
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
                page = fetch_mcp_tool_raw(
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
                console.print(f"[yellow]warning:[/yellow] Could not fetch symbols page: {e}")
                return

            request_id += 1
            if not isinstance(page, list) or not page:
                break

            all_symbols.extend(sym for sym in page if isinstance(sym, dict))

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
                data_info = fetch_mcp_tool_raw(
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
                console.print(f"[yellow]warning:[/yellow] get-data failed at {sym_addr}: {e}")
                continue

            request_id += 1
            if not isinstance(data_info, dict):
                continue

            address = str(data_info.get("address") or sym_addr)
            va = parse_ghidra_va(address)
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
        header_lines.extend(f"{row['decl']} /* {row['note']} */" for row in items)
        header_lines.append("")
        emitted_sections.add(section_name)

    for section_name in sorted(grouped):
        if section_name in emitted_sections:
            continue
        items = grouped[section_name]
        label = section_name or "(unknown)"
        header_lines.append(f"/* {label} section globals */")
        header_lines.extend(f"{row['decl']} /* {row['note']} */" for row in items)
        header_lines.append("")

    header_lines.append("#endif /* REBREW_GLOBALS_H */")
    header_lines.append("")
    header_text = "\n".join(header_lines)

    if dry_run:
        console.print(f"[yellow]Dry run: would write {out_file} with {len(rows)} globals[/yellow]")
        console.print(header_text)
        return

    atomic_write_text(out_file, header_text, encoding="utf-8")
    console.print(f"Pulled {len(rows)} data labels from Ghidra, wrote {out_file.name}")
