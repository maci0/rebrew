#!/usr/bin/env python3
"""Sync annotations between reversed source .c files and Ghidra.

Reads annotations from decomp C source files and generates Ghidra script
commands to rename functions, add comments, and set bookmarks via ReVa MCP.

Usage:
    rebrew-sync --export    Export annotations to ghidra_commands.json
    rebrew-sync --summary   Show what would be synced

The exported JSON can be consumed by automation that calls ReVa MCP tools:
  - create-label: rename functions at their VA
  - set-comment: add annotation metadata as plate comments
  - set-bookmark: bookmark matched functions for tracking
"""

import json

import typer

from rebrew.cli import TargetOption, get_config
from rebrew.verify import scan_reversed_dir


def build_sync_commands(entries: list[dict], program_path: str) -> list[dict]:
    by_va: dict[int, list[dict]] = {}
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
                    "programPath": program_path,
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
                    "programPath": program_path,
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
                    "programPath": program_path,
                    "addressOrSymbol": va_hex,
                    "type": "Analysis",
                    "category": bm_category,
                    "comment": bm_comment,
                },
            }
        )

    return commands


app = typer.Typer(help="Sync annotations between decomp C files and Ghidra.")


@app.callback(invoke_without_command=True)
def main(
    export: bool = typer.Option(False, help="Export Ghidra commands to ghidra_commands.json"),
    summary: bool = typer.Option(False, help="Show sync summary without exporting"),
    target: str | None = TargetOption,
):
    """Sync annotation data between decomp C files and Ghidra."""
    cfg = get_config(target=target)
    reversed_dir = cfg.reversed_dir
    program_path = f"/{cfg.target_binary.name}"

    entries = scan_reversed_dir(reversed_dir)
    by_va: dict[int, list[dict]] = {}
    for e in entries:
        by_va.setdefault(e["va"], []).append(e)

    if summary:
        print(f"Annotations: {len(entries)} entries, {len(by_va)} unique VAs")
        by_origin = {}
        for e in entries:
            by_origin.setdefault(e["origin"], []).append(e)
        for origin in sorted(by_origin):
            print(f"  {origin}: {len(by_origin[origin])}")

        ops = build_sync_commands(entries, program_path)
        labels = [o for o in ops if o["tool"] == "create-label"]
        comments = [o for o in ops if o["tool"] == "set-comment"]
        bookmarks = [o for o in ops if o["tool"] == "set-bookmark"]
        print(f"If exported, would generate {len(ops)} operations:")
        print(f"  - Set {len(labels)} labels (create-label)")
        print(f"  - Add {len(comments)} plate comments (set-comment)")
        print(f"  - Add {len(bookmarks)} bookmarks (set-bookmark)")
        print(f"  Total: {len(ops)} operations")

    if export:
        ops = build_sync_commands(entries, program_path)
        out_path = cfg.root / "ghidra_commands.json"
        with open(out_path, "w") as f:
            json.dump(ops, f, indent=2)
        print(f"Exported {len(ops)} operations to {out_path}")


def main_entry():
    app()

if __name__ == "__main__":
    main_entry()
