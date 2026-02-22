#!/usr/bin/env python3
"""ghidra_sync.py - Sync annotations between server_dll/*.c files and Ghidra.

This script reads annotations from decomp C source files and generates
Ghidra script commands to rename functions, add comments, and set bookmarks
in the Ghidra project via ReVa MCP tools.

Usage:
    uv run python ghidra_sync.py --export    Export annotations to ghidra_commands.json
    uv run python ghidra_sync.py --summary   Show what would be synced

The exported JSON can be consumed by automation that calls ReVa MCP tools:
  - create-label: rename functions at their VA
  - set-comment: add annotation metadata as plate comments
  - set-bookmark: bookmark matched functions for tracking
"""

import json
import sys
from pathlib import Path
from typing import Dict, List, Optional

import typer

from verify import parse_c_file, scan_reversed_dir


PROGRAM_PATH = "/server.dll"


def build_sync_commands(entries: List[dict]) -> List[dict]:
    by_va: Dict[int, List[dict]] = {}
    for e in entries:
        by_va.setdefault(e["va"], []).append(e)

    commands = []

    for va in sorted(by_va.keys()):
        elist = by_va[va]
        primary = elist[0]
        va_hex = f"0x{va:08X}"

        commands.append(
            {
                "tool": "create-label",
                "args": {
                    "programPath": PROGRAM_PATH,
                    "addressOrSymbol": va_hex,
                    "labelName": primary["name"],
                },
            }
        )

        comment_lines = [
            f"[rebrew] {primary['marker_type']}: {primary['status']}",
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
                    "programPath": PROGRAM_PATH,
                    "addressOrSymbol": va_hex,
                    "comment": "\n".join(comment_lines),
                    "commentType": "plate",
                },
            }
        )

        bm_category = primary["origin"].lower()
        bm_comment = (
            f"{primary['name']} - {primary['status']} "
            f"({primary['size']}B, {primary['cflags']})"
        )
        commands.append(
            {
                "tool": "set-bookmark",
                "args": {
                    "programPath": PROGRAM_PATH,
                    "addressOrSymbol": va_hex,
                    "type": "Analysis",
                    "category": bm_category,
                    "comment": bm_comment,
                },
            }
        )

    return commands


app = typer.Typer(help="Sync annotations between decomp C files and Ghidra.")


@app.command()
def main(
    export: bool = typer.Option(False, help="Export Ghidra commands to ghidra_commands.json"),
    summary: bool = typer.Option(False, help="Show sync summary without exporting"),
    root: Path = typer.Option(
        Path(__file__).resolve().parent.parent,
        help="Project root directory",
    ),
    target: Optional[str] = typer.Option(
        None, "--target", "-t",
        help="Target name from rebrew.toml (default: first target)",
    ),
):
    """Sync annotation data between decomp C files and Ghidra."""
    if not export and not summary:
        summary = True

    try:
        from rebrew.config import load_config
        _c = load_config(root, target=target)
        reversed_dir = _c.reversed_dir
    except Exception:
        reversed_dir = root / "src" / "server_dll"

    entries = scan_reversed_dir(reversed_dir)
    by_va: Dict[int, List[dict]] = {}
    for e in entries:
        by_va.setdefault(e["va"], []).append(e)

    if summary:
        print(f"Annotations: {len(entries)} entries, {len(by_va)} unique VAs")
        by_origin = {}
        for e in entries:
            by_origin.setdefault(e["origin"], []).append(e)
        for origin in sorted(by_origin):
            print(f"  {origin}: {len(by_origin[origin])}")

        ops = build_sync_commands(entries)
        labels = [o for o in ops if o["tool"] == "create-label"]
        comments = [o for o in ops if o["tool"] == "set-comment"]
        bookmarks = [o for o in ops if o["tool"] == "set-bookmark"]
        print(f"If exported, would generate {len(ops)} operations:")
        print(f"  - Set {len(labels)} labels (create-label)")
        print(f"  - Add {len(comments)} plate comments (set-comment)")
        print(f"  - Add {len(bookmarks)} bookmarks (set-bookmark)")
        print(f"  Total: {len(ops)} operations")

    if export:
        ops = build_sync_commands(entries)
        out_path = root / "ghidra_commands.json"
        with open(out_path, "w") as f:
            json.dump(ops, f, indent=2)
        print(f"Exported {len(ops)} operations to {out_path}")


if __name__ == "__main__":
    app()
