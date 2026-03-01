"""Sync annotations between reversed source .c files and Ghidra.

Reads annotations from decomp C source files and generates Ghidra script
commands to rename functions, add comments, and set bookmarks via ReVa MCP.
Also provides pull operations for fetching prototypes, structs, and comments
from Ghidra back into local source files.

Usage:
    rebrew sync --export    Export annotations to ghidra_commands.json
    rebrew sync --summary   Show what would be synced
    rebrew sync --apply     Apply ghidra_commands.json to Ghidra via ReVa MCP
    rebrew sync --pull      Pull function names from Ghidra
    rebrew sync --pull-signatures  Pull prototypes from Ghidra
    rebrew sync --pull-structs     Pull struct definitions into types.h
    rebrew sync --pull-comments    Pull analysis comments into source files

The exported JSON can be consumed by automation that calls ReVa MCP tools:
  - create-function: define functions at annotated VAs (before labeling)
  - create-label: rename functions at their VA
  - set-comment: add annotation metadata as plate comments
  - set-bookmark: bookmark matched functions for tracking
"""

import contextlib
import json
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import httpx
import typer
from rich.console import Console

from rebrew.annotation import update_annotation_key
from rebrew.catalog import (
    build_function_registry,
    parse_function_list,
    scan_reversed_dir,
)
from rebrew.cli import TargetOption, error_exit, get_config, iter_sources, json_print
from rebrew.config import ProjectConfig

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


def _resolve_program_path(cfg: ProjectConfig) -> str:
    """Return the Ghidra program path from config or derive from binary name."""
    configured = getattr(cfg, "ghidra_program_path", "")
    if configured:
        return configured
    return f"/{cfg.target_binary.name}"


def _validate_program_path(
    client: Any,
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

    # Phase 2: labels, comments, bookmarks for functions
    for va in sorted(by_va):
        elist = by_va[va]
        primary = elist[0]
        va_hex = f"0x{va:08X}"
        name = primary.get("name") or primary.get("symbol") or f"func_{va:08x}"
        status = primary.get("status", "UNKNOWN")

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
            f"[rebrew] {primary.get('marker_type', 'FUNCTION')}: {status}",
            f"Origin: {primary.get('origin', 'UNKNOWN')}",
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
            status, primary.get("origin", "UNKNOWN").lower()
        )
        bm_comment = f"{name} - {status} ({primary.get('size', 0)}B, {primary.get('cflags', '')})"
        commands.append(
            {
                "tool": "set-bookmark",
                "args": {
                    "programPath": program_path,
                    "address": va_hex,
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

    # Phase 3: Push Data / Globals
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
                        "address": va_hex,
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
                        },
                    }
                )

            # Comment
            comment_lines = [
                "[rebrew] DATA",
                f"Size: {d_entry['size']}B",
                f"Section: {d_entry['section']}",
                f"Origin: {d_entry['origin']}",
            ]
            if d_entry["note"]:
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
                        "address": va_hex,
                        "category": "rebrew/data",
                        "comment": f"Data: {name} ({d_entry['size']}B)",
                    },
                }
            )

    # Phase 4: Push Structs
    if structs:
        for struct_str in structs:
            commands.append(
                {
                    "tool": "parse-c-structure",
                    "args": {
                        "programPath": program_path,
                        "cCode": struct_str,
                        "categoryPath": "/rebrew",
                    },
                }
            )

    # Phase 5: Push Function Signatures
    if signatures:
        for sig_info in signatures:
            commands.append(
                {
                    "tool": "set-function-prototype",
                    "args": {
                        "programPath": program_path,
                        "addressOrSymbol": sig_info["va_hex"],
                        "prototype": sig_info["signature"],
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


def _parse_sse_response(text: str) -> Any:
    """Extract JSON-RPC result from an SSE (text/event-stream) response body."""
    for line in text.splitlines():
        if line.startswith("data: "):
            try:
                return json.loads(line[6:])
            except json.JSONDecodeError:
                continue
        elif line.startswith("data:"):
            try:
                return json.loads(line[5:])
            except json.JSONDecodeError:
                continue
    return None


_MCP_HEADERS = {
    "Content-Type": "application/json",
    "Accept": "application/json, text/event-stream",
}

console = Console()


def _fetch_mcp_tool(
    client: Any,
    endpoint: str,
    tool_name: str,
    arguments: dict[str, Any],
    request_id: int,
    session_id: str = "",
) -> list[Any]:
    """Call a ReVa MCP tool and return parsed JSON list from text content."""
    payload = {
        "jsonrpc": "2.0",
        "id": request_id,
        "method": "tools/call",
        "params": {"name": tool_name, "arguments": arguments},
    }
    headers = dict(_MCP_HEADERS)
    if session_id:
        headers["Mcp-Session-Id"] = session_id
    resp = client.post(endpoint, json=payload, headers=headers)
    if resp.status_code != 200:
        return []
    ct = resp.headers.get("content-type", "")
    if "text/event-stream" in ct:
        data = _parse_sse_response(resp.text)
    else:
        text = resp.text.strip()
        if not text:
            return []
        try:
            data = resp.json()
        except (ValueError, UnicodeDecodeError):
            return []
    if not data:
        return []
    if "result" in data and "content" in data["result"]:
        items = data["result"]["content"]
        text_items = [it for it in items if it.get("type") == "text"]
        if not text_items:
            return []
        # Multiple text items: each is a separate JSON object
        if len(text_items) > 1:
            objects = []
            for it in text_items:
                with contextlib.suppress(json.JSONDecodeError):
                    objects.append(json.loads(it["text"]))
            return objects
        # Single text item
        raw = text_items[0]["text"]
        try:
            parsed = json.loads(raw)
            if isinstance(parsed, list):
                return parsed
            return [parsed]
        except json.JSONDecodeError:
            pass
    return []


def _fetch_mcp_tool_raw(
    client: Any,
    endpoint: str,
    tool_name: str,
    arguments: dict[str, Any],
    request_id: int,
    session_id: str = "",
) -> Any:
    """Call a ReVa MCP tool and return parsed JSON result (raw, not list-wrapped).

    Unlike ``_fetch_mcp_tool`` which always returns ``list[Any]``, this returns
    the parsed value directly — dict, list, str, or None on failure.  Used by
    the extended pull operations (prototypes, structs, comments).
    """
    payload = {
        "jsonrpc": "2.0",
        "id": request_id,
        "method": "tools/call",
        "params": {"name": tool_name, "arguments": arguments},
    }
    headers = dict(_MCP_HEADERS)
    if session_id:
        headers["Mcp-Session-Id"] = session_id
    resp = client.post(endpoint, json=payload, headers=headers)
    if resp.status_code != 200:
        return None
    ct = resp.headers.get("content-type", "")
    if "text/event-stream" in ct:
        data = _parse_sse_response(resp.text)
    else:
        text = resp.text.strip()
        if not text:
            return None
        try:
            data = resp.json()
        except (json.JSONDecodeError, ValueError, UnicodeDecodeError):
            return None
    if not data:
        return None
    if "result" in data and "content" in data["result"]:
        items = data["result"]["content"]
        text_items = [it for it in items if it.get("type") == "text"]
        if not text_items:
            return None
        # Single text item: return parsed JSON directly
        if len(text_items) == 1:
            raw = text_items[0]["text"]
            try:
                return json.loads(raw)
            except json.JSONDecodeError:
                return raw
        # Multiple text items: parse each as JSON, collect into list
        objects = []
        for it in text_items:
            with contextlib.suppress(json.JSONDecodeError):
                objects.append(json.loads(it["text"]))
        return objects if objects else None
    return None


def _init_mcp_session(client: Any, endpoint: str) -> str:
    """Initialize an MCP session and return the session ID."""
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
    resp = client.post(endpoint, json=init_payload, headers=_MCP_HEADERS)
    return resp.headers.get("Mcp-Session-Id", "")


@dataclass
class PullChange:
    """A single proposed change from a pull operation."""

    va: int
    field: str
    local_value: str
    ghidra_value: str
    filepath: str
    action: str  # "update", "conflict", "skip"
    reason: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a plain dict for JSON output."""
        d: dict[str, Any] = {
            "va": f"0x{self.va:08x}",
            "field": self.field,
            "local": self.local_value,
            "ghidra": self.ghidra_value,
            "file": self.filepath,
            "action": self.action,
        }
        if self.reason:
            d["reason"] = self.reason
        return d


@dataclass
class PullResult:
    """Aggregated result of a pull operation."""

    changes: list[PullChange] = field(default_factory=list)
    updated: int = 0
    skipped: int = 0
    conflicts: int = 0

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a plain dict for JSON output."""
        return {
            "updated": self.updated,
            "skipped": self.skipped,
            "conflicts": self.conflicts,
            "changes": [c.to_dict() for c in self.changes],
        }


def _is_meaningful_name(name: str) -> bool:
    """Return True if a name carries real semantic information (not auto-generated)."""
    return bool(name) and not (
        _is_generic_name(name)
        or name.startswith("FUN_")
        or name.startswith("DAT_")
        or name.startswith("switchdata")
        or name.startswith("thunk_")
    )


def _ghidra_name_to_symbol(ghidra_name: str, entry: Any, cfg: ProjectConfig | None = None) -> str:
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
            init_resp = client.post(endpoint, json=init_payload, headers=_MCP_HEADERS)
            session_id = init_resp.headers.get("Mcp-Session-Id", "")

            functions = _fetch_mcp_tool(
                client,
                endpoint,
                "get-functions",
                {"programPath": program_path, "filterDefaultNames": False},
                1,
                session_id=session_id,
            )
            data_labels = _fetch_mcp_tool(
                client,
                endpoint,
                "get-labels",
                {"programPath": program_path, "filterDefaultNames": False},
                2,
                session_id=session_id,
            )
            plate_comments = _fetch_mcp_tool(
                client,
                endpoint,
                "get-comments",
                {"programPath": program_path, "commentType": "plate"},
                3,
                session_id=session_id,
            )
            pre_comments = _fetch_mcp_tool(
                client,
                endpoint,
                "get-comments",
                {"programPath": program_path, "commentType": "pre"},
                4,
                session_id=session_id,
            )
        except httpx.RequestError as e:
            typer.echo(f"Warning: Could not connect to ReVa MCP ({e}).", err=True)
            typer.echo("Falling back to local caches...", err=True)

    if not functions:
        ghidra_json_path = cfg.reversed_dir / "ghidra_functions.json"
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
        va = _parse_va(f.get("va"))
        gname = f.get("ghidra_name")
        if va is not None and gname:
            ghidra_names_by_va[va] = gname

    for d in data_labels:
        va = _parse_va(d.get("va"))
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
        va = _parse_va(entry["va"])
        if va is None:
            continue

        filepath = Path(entry["filepath"])
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

                if filter_origin and entry.get("origin") != filter_origin:
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
                            update_annotation_key(filepath, va, "GHIDRA", ghidra_name)
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
                                field="SYMBOL",
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
                            field="SYMBOL",
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
                            update_annotation_key(filepath, va, "SYMBOL", ghidra_name)

                        change = PullChange(
                            va=va,
                            field="SYMBOL",
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
                    if update_annotation_key(filepath, va, "NOTE", sanitized):
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


def apply_commands_via_mcp(
    commands: list[dict[str, Any]],
    endpoint: str = "http://localhost:8080/mcp/message",
) -> tuple[int, int]:
    """Apply sync commands to Ghidra via ReVa MCP Streamable HTTP.

    Returns (success_count, error_count).
    """
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
                "clientInfo": {"name": "rebrew sync", "version": "1.0.0"},
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
            error_exit(f"Failed to initialize MCP session: {exc}")

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
            typer.echo("WARNING: No session ID received, proceeding without one", err=True)

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
                    "parse-c-structure": "Pushing struct definitions",
                    "set-function-prototype": "Setting function prototypes",
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
                body = resp.text.strip()
                if not body:
                    success += 1
                    continue
                ct = resp.headers.get("content-type", "")
                if "text/event-stream" in ct:
                    data = _parse_sse_response(body)
                else:
                    try:
                        data = resp.json()
                    except (ValueError, UnicodeDecodeError):
                        success += 1
                        continue
                if not data:
                    success += 1
                    continue
                if "error" in data:
                    errors += 1
                    va = cmd["args"].get("addressOrSymbol", cmd["args"].get("address", "?"))
                    if errors <= 5:
                        print(f"  ERROR at {va} ({cmd['tool']}): {data['error']}")
                    elif errors == 6:
                        print("  ... suppressing further errors")
                else:
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
    registry: dict[int, dict[str, Any]],
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
                        update_annotation_key(fp, va, "PROTOTYPE", sig)

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
                                        src_file.write_text(new_content, encoding="utf-8")
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
            for name in structs_list.get("structures", structs_list.get("names", [])):
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
                update_annotation_key(fp, entry_va, "ANALYSIS", combined_comments)
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

    def _build_extern_decl(data_type: str, symbol_name: str, length: int) -> tuple[str, str]:
        dtype = data_type.strip()
        lower = dtype.lower()

        if lower in {"pointer", "pointer32"}:
            return f"extern void* {symbol_name};", ""

        undef_match = re.fullmatch(r"undefined(\d+)?", lower)
        if undef_match:
            arr_len = max(length, int(undef_match.group(1) or "0"))
            if arr_len > 0:
                return f"extern unsigned char {symbol_name}[{arr_len}];", ""
            return f"extern unsigned char {symbol_name}[];", "unknown size"

        arr_match = re.fullmatch(r"(.+?)\[(.+)\]", dtype)
        if arr_match:
            base = arr_match.group(1).strip()
            dim = arr_match.group(2).strip()
            return f"extern {base} {symbol_name}[{dim}];", ""

        if dtype:
            return f"extern {dtype} {symbol_name};", ""

        if length > 0:
            return f"extern unsigned char {symbol_name}[{length}];", "unknown type"
        return f"extern unsigned char {symbol_name}[];", "unknown type/size"

    console.print("Pulling data labels from Ghidra...")

    sections: list[Any] = []
    with contextlib.suppress(Exception):
        from rebrew.binary_loader import load_binary

        binary_info = load_binary(cfg.target_binary, getattr(cfg, "format", "auto"))
        sections = list(binary_info.sections.values())

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
    ):
        error_exit("No action specified. Use --summary, --export, --apply, --push, or --pull.")

    cfg = get_config(target=target)
    reversed_dir = cfg.reversed_dir
    program_path = _resolve_program_path(cfg)

    entries_raw = scan_reversed_dir(reversed_dir, cfg=cfg)
    entries: list[dict[str, Any]] = [e if isinstance(e, dict) else e.to_dict() for e in entries_raw]

    if push or pull or pull_signatures or pull_structs or pull_comments or pull_data or apply:
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
            from rebrew.struct_parser import extract_structs_from_file

            struct_set = set()
            for cfile in iter_sources(reversed_dir, cfg):
                for struct_str in extract_structs_from_file(cfile):
                    struct_set.add(struct_str)
            structs = list(struct_set)

        if sync_signatures and (summary or export or push):
            from rebrew.signature_parser import extract_function_signatures

            # Map from function name (symbol) to VA, ignoring generic names
            name_to_va = {}
            for e in entries:
                if e.get("marker_type", "FUNCTION") != "FUNCTION":
                    continue
                name = e.get("symbol") or e.get("name")
                if name and not _is_generic_name(name):
                    name_to_va[name] = f"0x{e['va']:08X}"

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

    if sync_sizes or sync_new_functions:
        # Build registry to compare function list vs ghidra sizes
        func_list_path = cfg.function_list
        ghidra_json_path = reversed_dir / "ghidra_functions.json"
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


def main_entry() -> None:
    """Package entry point for ``rebrew-sync``."""
    app()


if __name__ == "__main__":
    main_entry()
