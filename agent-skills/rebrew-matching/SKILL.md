---
name: rebrew-matching
description: Use the GA matching engine, flag sweeping, and diff analysis to achieve byte-perfect matches against target binary functions.
license: MIT
---

# Rebrew Matching

This skill covers the GA-based binary matching engine and related tools for achieving byte-perfect (EXACT/RELOC) matches.

## 1. Diff Analysis (First Step)

Before running the GA, always start with a diff to understand the current state:
- Run `uv run rebrew-match --diff-only src/<target>/<file>.c` for a side-by-side disassembly diff.
- Use `--mm` (mismatches-only) to filter to structural differences (`**` lines only).
- For machine-readable diff: `uv run rebrew-match --diff-only --json src/<target>/<file>.c`

### Diff Markers
- `==` — identical bytes
- `~~` — relocation difference (acceptable, counts as RELOC match)
- `**` — structural difference (needs fixing)

## 2. Flag Sweep

If the code logic looks correct but bytes don't match, try different compiler flags:
- Run `uv run rebrew-match --flag-sweep-only src/<target>/<file>.c` to try all flag combinations.
- Use `--tier 1` (fast, common flags) through `--tier 3` (exhaustive).
- The sweep reports the best-scoring flag combination found.

## 3. GA Engine

For automated matching when manual tuning isn't enough:
- Run `uv run rebrew-match src/<target>/<file>.c --generations 200 --pop 64 -j 16`
- The GA mutates C source code (variable types, casts, loop structures, etc.) and scores each variant against the target bytes.
- Progress prints to stderr; final best source is written to the file.

### Key GA Options
- `--generations N` — number of GA generations (default: 100)
- `--pop N` — population size (default: 32)
- `-j N` — parallel compilation jobs (default: 8)
- `--seed N` — RNG seed for reproducibility

## 4. Batch GA

For bulk matching of STUB or near-miss functions:
- Run `uv run rebrew-ga --dry-run` to preview which STUBs would be attempted.
- Run `uv run rebrew-ga --generations 200` to run the GA on all STUBs.
- Run `uv run rebrew-ga --near-miss --threshold 5` to target MATCHING functions with ≤5B delta.

## 5. Scoring System

The GA uses a composite score (lower = better):

| Component | Weight | What it measures |
|-----------|--------|------------------|
| Length penalty | 3.0 | `abs(candidate_size - target_size)` |
| Weighted byte similarity | 1000.0 | Position-weighted, prologue 3x |
| Relocation-aware similarity | 500.0 | After masking relocatable fields |
| Mnemonic similarity | 200.0 | Via capstone disassembly |
| Prologue bonus | -100.0 | If first 20 bytes match |

## 6. Structured Blocker Tracking

When a function is MATCHING but not yet byte-perfect, track the blocker:
- Add `// BLOCKER: description of remaining mismatch` to the annotation.
- Add `// BLOCKER_DELTA: N` (byte count) for machine-readable near-miss tracking.
- These are used by `rebrew-next --improving` to sort MATCHING functions by how close they are.

## 7. Atomic Promotion

After achieving a match, use `rebrew promote` instead of manually editing STATUS:
- Run `uv run rebrew promote src/<target>/<file>.c` to test + update STATUS atomically.
- Use `--dry-run` to preview. Use `--json` for structured output.
- Automatically removes BLOCKER/BLOCKER_DELTA when promoting to EXACT/RELOC.

## Tips
- Start with `--diff-only` to understand the gap before running the GA.
- If the diff shows only relocation differences (`~~`), the function is already RELOC — use `rebrew promote` to update STATUS.
- Flag sweep is fast and often finds the right combination without needing the GA.
- For MSVC6 quirks, check `// CFLAGS:` annotation — common presets are `/O2 /Gd` (GAME) and `/O1 /Gd` (MSVCRT).
- Use `rebrew-ga --json` for machine-readable batch GA results.
