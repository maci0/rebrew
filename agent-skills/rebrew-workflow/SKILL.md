---
name: rebrew-workflow
description: Standard workflow for reverse engineering functions using the rebrew compiler-in-the-loop toolchain. Use this when the user asks to reverse, match, or decompile a function.
license: MIT
---

# Rebrew Workflow

This skill outlines the standard operating procedure for reversing functions in the `rebrew` project.

## 1. Pick a Function
If the user hasn't specified a VA, use `rebrew-next` to find one.
- Run `uv run rebrew-next` to get an overview of the easiest functions to tackle.
- Run `uv run rebrew-next --stats` to see the current matching progress and unmatchable functions.
- Run `uv run rebrew-next --improving` to see functions that are currently MATCHING but can be improved, sorted by byte delta.
- Run `uv run rebrew-flirt --json` as a reconnaissance step to identify known library functions (MSVCRT, zlib, etc.) before picking a function — library matches can be fast wins.

## 2. Generate Skeleton
Generate a source file skeleton with annotations for your chosen VA.
- Run `uv run rebrew-skeleton 0x<VA>`
- Optionally add `--decomp` to fetch pseudo-C decompilation from supported backends (e.g. `r2dec`, `r2ghidra`).
  - Example: `uv run rebrew-skeleton 0x<VA> --decomp --decomp-backend r2dec`
- **Note**: The file extension for reversed source files is controlled by `source_ext` in `rebrew.toml` (default: `.c`). Tools auto-detect this — you don't need to specify it manually.

## 3. Review Disassembly
Understand the actual assembly of the original binary to guide your C implementation.
- Run `uv run rebrew-asm 0x<VA> 128` to dump 128 bytes of assembly at the given VA.
- For machine-readable output: `uv run rebrew-asm 0x<VA> 128 --json`

## 4. Implement and Test
Iteratively edit your source file and compile to compare bytecode against the exact bytes in the target binary.
- Run the test command printed by `rebrew-skeleton`, usually:
  - `uv run rebrew-test src/<target>/<filename>.c`
- For machine-readable results: `uv run rebrew-test src/<target>/<filename>.c --json`
- Adjust code, variables, and compiler flags (`// CFLAGS:`) in the source file until the output matches perfectly (EXACT/RELOC).

## 5. Global Data Analysis
If your function accesses global variables:
- Ensure they are annotated with `// GLOBAL:` (or `// DATA:` for standalone data files).
- Or use the `rebrew-data-analysis` skill to properly identify and structure them.

## 6. Batch GA for Near-Miss Functions
If there are many MATCHING functions with only a few differing bytes, use the batch GA to automatically resolve them:
- Run `uv run rebrew-ga --near-miss` to target all MATCHING functions with ≤10B byte delta.
- Use `--threshold N` to narrow the scope (e.g. `--threshold 5` for only ≤5B).
- Use `--dry-run` to preview which functions would be attempted.

## 7. Promote Matched Functions
When you achieve an EXACT or RELOC match, atomically update the STATUS annotation:
- Run `uv run rebrew promote src/<target>/<file>.c` to test + update STATUS in one step.
- Use `--dry-run` to preview what would change without modifying the file.
- For machine-readable output: `uv run rebrew promote --json src/<target>/<file>.c`
- Exit code 0 = all functions matched; exit code 1 = structural mismatches remain.

## 8. Cold-Start Triage
When beginning a new session, get a comprehensive overview:
- Run `uv run rebrew triage` for a human-readable summary combining coverage stats, near-miss functions, and recommendations.
- Run `uv run rebrew triage --json` for machine-readable output suitable for automated agents.
- Includes FLIRT library match count when signatures are available.

## 9. Autonomous Agent Mode
For fully automated batch reversing using a local LLM:
- Run `uv run rebrew-agent --dry-run` to preview the work queue.
- Run `uv run rebrew-agent --max-functions 10` to process up to 10 functions.
- Use `--git` to auto-create a branch and commit each successful promotion.
- The agent loads prior audit trail attempts to learn from past failures.
- Configure via `agent_local.yml` or CLI flags (`--api-base`, `--model`).

## Edge Cases
- **Unmatchable Functions**: Sometimes `rebrew-next` auto-filters thunks or stubs. You can see them with `uv run rebrew-next --unmatchable`.
- **Large Functions**: For massive functions, use `rebrew-ga` for automated parameter/type guesswork or break them down manually.
- **Dispatch Tables**: If you encounter function pointer arrays in `.data`/`.rdata`, use `uv run rebrew data --dispatch` to detect and resolve them.
