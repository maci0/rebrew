---
name: rebrew-matching
description: Performs byte-level binary matching using diff analysis, compiler flag sweeping, and the genetic algorithm engine. Use when a function needs flag tuning, structural diff analysis, or automated GA matching to achieve EXACT/RELOC status.
license: MIT
---

# Rebrew Matching

Deep dive into diff analysis, flag sweeping, and the GA engine.
For the overall reversing workflow, see the `rebrew-workflow` skill.

## 1. Diff Analysis (Always Start Here)

```bash
rebrew match --diff-only src/<target>/<file>.c --json        # structured diff
rebrew match --diff-only --mm src/<target>/<file>.c --json   # structural diffs only
```

### Diff Markers

- `==` identical bytes
- `~~` relocation difference (acceptable — counts as RELOC)
- `RR` register encoding difference (with `--rr` / `--register-aware`)
- `**` structural difference (needs fixing)

If the diff shows only `~~` lines, the function is already RELOC — promote it.
Use `--register-aware` to see if remaining `**` diffs are actually just unfixable register allocation differences.

### Auto-Classified Blockers

`rebrew match --diff-only` will auto-classify systemic compiler differences from `**` / `RR` lines (e.g. "register allocation", "loop rotation / branch layout", "stack frame choice"). Use this to determine if a function is genuinely improvable.

## 2. Flag Sweep

When code logic is correct but bytes diverge, try different compiler flags:

```bash
rebrew match --flag-sweep-only src/<target>/<file>.c              # default tier
rebrew match --flag-sweep-only --tier targeted src/<target>/<file>.c # codegen-altering flags
```

| Tier | Combinations | Use Case |
|------|-------------|----------|
| `quick` | ~192 | Fast iteration |
| `targeted` | ~6K | Codegen-altering flags only (`/Oy`, `/Op`) |
| `normal` | ~21K | Default sweep |
| `thorough` | ~1M | Deep search |
| `full` | ~8.3M | Exhaustive |

## 3. GA Engine

For automated matching when manual tuning is insufficient:

```bash
rebrew match src/<target>/<file>.c --generations 200 --pop-size 64 -j 16
```

- `--generations N` — GA generations (default: 100)
- `--pop-size N` — population size (default: 32)
- `-j N` — parallel compilation jobs (default: 4)
- `--seed N` — RNG seed for reproducibility
- `--out-dir DIR` — output directory for GA results (default: `output/ga_run`)
- `--force` — continue even if annotation linter finds errors

The GA mutates C source (variable types, casts, loop structures) and scores
each variant against the target bytes. Best source is written to the file.

## 4. Scoring (lower = better)

| Component | Weight | Measures |
|-----------|--------|----------|
| Length penalty | 3.0 | `abs(candidate_size - target_size)` |
| Weighted byte similarity | 1000.0 | Position-weighted, prologue 3x |
| Relocation-aware similarity | 500.0 | After masking relocatable fields |
| Mnemonic similarity | 200.0 | Via capstone disassembly |
| Prologue bonus | -100.0 | If first 20 bytes match |

## 5. Blocker Tracking

When a function is MATCHING but not byte-perfect, track the blocker in annotations:

```c
// BLOCKER: register allocation differs in loop body
// BLOCKER_DELTA: 3
```

Used by `rebrew next --improving` to sort by proximity to a match.

## Tips

- Always start with `--diff-only` before running the GA.
- Flag sweep is fast and often sufficient without the GA.
- Common CFLAGS presets: `/O2 /Gd` (GAME), `/O1 /Gd` (MSVCRT).
