---
name: rebrew-sync
description: Synchronize function annotations between reversed source files and Ghidra via ReVa MCP, including export, apply, and push workflows.
license: MIT
---

# Rebrew Sync

This skill covers synchronizing annotations between reversed source files and Ghidra using the `rebrew-sync` tool and ReVa MCP.

## 1. Export Annotations

Generate a `ghidra_commands.json` file containing rename, comment, and bookmark commands:
- Run `uv run rebrew-sync --export`
- The exported JSON contains commands for each annotated function:
  - `create-label` — rename functions at their VA
  - `set-comment` — add annotation metadata as plate comments
  - `set-bookmark` — bookmark matched functions for tracking (categorized by status)

## 2. Review What Would Be Synced

Before applying, preview the sync operations:
- Run `uv run rebrew-sync --summary`
- Shows counts of labels, comments, and bookmarks that would be created/updated.

## 3. Apply to Ghidra

Push the exported commands to a running Ghidra instance via ReVa MCP:
- Run `uv run rebrew-sync --apply`
- Requires a running Ghidra instance with the ReVa MCP plugin.
- Commands are applied in order: labels first, then comments, then bookmarks.

## 4. Push (Export + Apply)

Shorthand to export and immediately apply:
- Run `uv run rebrew-sync --push`

## Bookmark Categories

Functions are bookmarked by status for easy filtering in Ghidra:
- `rebrew/exact` — byte-perfect matches
- `rebrew/reloc` — matches after relocation masking
- `rebrew/matching` — close matches with known blockers
- `rebrew/stub` — placeholder implementations

## 5. JSON Output

For machine-readable output of sync operations:
- Run `uv run rebrew-sync --summary --json` to get structured operation counts.
- Output includes entry counts, unique VAs, by-origin breakdown, and operation counts.

## Tips
- Generic auto-names (like `func_10006c00` or `FUN_10006c00`) are skipped by default to avoid overwriting manual Ghidra renames.
- Re-running sync is safe — it's idempotent.
- Use `--target <name>` to sync a specific target when the project has multiple binaries.
- After `rebrew promote` updates STATUS annotations, run `rebrew-sync --push` to push changes to Ghidra.
