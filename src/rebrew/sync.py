"""Sync annotations between reversed source .c files and Ghidra.

Reads annotations from decomp C source files and generates Ghidra script
commands to rename functions, add comments, and set bookmarks via ReVa MCP.

Usage:
    rebrew sync --export    Export annotations to ghidra_commands.json
    rebrew sync --summary   Show what would be synced
    rebrew sync --apply     Apply ghidra_commands.json to Ghidra via ReVa MCP

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
from dataclasses import dataclass, field
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


def _parse_va(va_raw: Any) -> int | None:
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


def _fetch_mcp_tool(
    client: Any,
    endpoint: str,
    tool_name: str,
    arguments: dict[str, Any],
    request_id: int,
) -> list[Any]:
    """Call a ReVa MCP tool and return parsed JSON list from text content."""
    payload = {
        "jsonrpc": "2.0",
        "id": request_id,
        "method": "tools/call",
        "params": {"name": tool_name, "arguments": arguments},
    }
    resp = client.post(endpoint, json=payload)
    if resp.status_code != 200:
        return []
    data = resp.json()
    if "result" in data and "content" in data["result"]:
        for item in data["result"]["content"]:
            if item.get("type") == "text":
                try:
                    return json.loads(item["text"])
                except json.JSONDecodeError:
                    pass
    return []


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
    )


def pull_ghidra_renames(
    entries: list[dict[str, Any]],
    cfg: Any,
    endpoint: str = "http://localhost:8080/mcp/message",
    program_path: str = "",
    dry_run: bool = False,
    json_output: bool = False,
) -> PullResult:
    """Pull function and data names from Ghidra and update local .c files.

    When *dry_run* is True, reports what would change without modifying files.
    Returns a PullResult with all proposed/applied changes.
    """
    result = PullResult()

    try:
        import httpx
    except ImportError:
        print(
            "ERROR: httpx is required for --pull. Install with: uv pip install httpx",
            file=sys.stderr,
        )
        raise typer.Exit(code=1)

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
        try:
            client.post(endpoint, json=init_payload)

            functions = _fetch_mcp_tool(
                client,
                endpoint,
                "get-functions",
                {"programPath": program_path, "filterDefaultNames": False},
                1,
            )
            data_labels = _fetch_mcp_tool(
                client,
                endpoint,
                "get-labels",
                {"programPath": program_path, "filterDefaultNames": False},
                2,
            )
            plate_comments = _fetch_mcp_tool(
                client,
                endpoint,
                "get-comments",
                {"programPath": program_path, "commentType": "plate"},
                3,
            )
            pre_comments = _fetch_mcp_tool(
                client,
                endpoint,
                "get-comments",
                {"programPath": program_path, "commentType": "pre"},
                4,
            )
        except httpx.RequestError as e:
            print(f"Warning: Could not connect to ReVa MCP ({e}).", file=sys.stderr)
            print("Falling back to local caches...", file=sys.stderr)

    if not functions:
        ghidra_json_path = cfg.reversed_dir / "ghidra_functions.json"
        if ghidra_json_path.exists():
            try:
                functions = json.loads(ghidra_json_path.read_text(encoding="utf-8"))
                if not dry_run:
                    print(f"Loaded {len(functions)} functions from {ghidra_json_path.name}")
            except (json.JSONDecodeError, OSError) as e:
                print(f"Error reading cache: {e}", file=sys.stderr)
        else:
            print(
                f"Could not fetch functions from MCP and {ghidra_json_path.name} not found.",
                file=sys.stderr,
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

    from pathlib import Path

    from rebrew.annotation import update_annotation_key
    from rebrew.data import scan_data_annotations

    all_entries = list(entries)
    all_entries.extend(scan_data_annotations(cfg.reversed_dir, cfg=cfg))

    for e in all_entries:
        va = _parse_va(e["va"])
        if va is None:
            continue

        filepath = Path(e["filepath"])
        if not filepath.exists() and not filepath.is_absolute():
            filepath = cfg.reversed_dir / filepath
        if not filepath.exists():
            continue

        ghidra_name = ghidra_names_by_va.get(va)
        if ghidra_name and _is_meaningful_name(ghidra_name):
            local_name = e.get("symbol") or e.get("name") or f"func_{va:08x}"
            if local_name != ghidra_name:
                local_is_meaningful = _is_meaningful_name(local_name)
                if local_is_meaningful and local_name.lstrip("_") != ghidra_name.lstrip("_"):
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
                        print(f"  CONFLICT 0x{va:08x}: local={local_name} vs ghidra={ghidra_name}")
                    continue

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
                    if update_annotation_key(filepath, va, "SYMBOL", ghidra_name):
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

                        if e.get("marker_type", "FUNCTION") == "FUNCTION":
                            old_stem = filepath.stem
                            if old_stem in (local_name, f"func_{va:08x}"):
                                new_filepath = filepath.with_name(f"{ghidra_name}{filepath.suffix}")
                                if not new_filepath.exists():
                                    filepath.rename(new_filepath)
                                    if not json_output:
                                        print(
                                            f"    Renamed: {old_stem}{filepath.suffix}"
                                            f" -> {new_filepath.name}"
                                        )

        ghidra_comment = ghidra_comments_by_va.get(va)
        if ghidra_comment:
            local_note = e.get("note", "")
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
        print(json.dumps(result.to_dict(), indent=2))
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
                data = resp.json()
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
    if not (summary or export or apply or push or pull or sync_sizes or sync_new_functions):
        print("No action specified. Use --summary, --export, --apply, --push, or --pull.")
        raise typer.Exit(code=1)

    cfg = get_config(target=target)
    reversed_dir = cfg.reversed_dir
    program_path = f"/{cfg.target_binary.name}"

    entries_raw = scan_reversed_dir(reversed_dir, cfg=cfg)
    entries: list[dict[str, Any]] = [e if isinstance(e, dict) else e.to_dict() for e in entries_raw]

    if pull:
        pull_result = pull_ghidra_renames(
            entries,
            cfg,
            endpoint,
            program_path,
            dry_run=dry_run,
            json_output=json_output,
        )
        if pull_result.conflicts > 0 and not dry_run:
            raise typer.Exit(code=1)
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
        from rebrew.cli import iter_sources

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
                            "parse_c_structure": len(structs_op),
                            "set_function_prototype": len(sigs_op),
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
            print(f"ERROR: {cmds_path} not found. Run --export first.", file=sys.stderr)
            raise typer.Exit(code=1)
        try:
            with cmds_path.open(encoding="utf-8") as f:
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
    app()


if __name__ == "__main__":
    main_entry()
