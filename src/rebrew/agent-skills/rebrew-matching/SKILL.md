---
name: rebrew-matching
description: Performs byte-level binary matching using diff analysis, compiler flag sweeping, and the genetic algorithm engine. Use this skill when a function needs flag tuning, structural diff analysis, automated GA matching, or batch flag sweeping to achieve EXACT/RELOC status. Triggers on 'match', 'diff', 'flag sweep', 'GA', 'genetic algorithm', 'byte diff', 'MATCHING status', 'near-miss', 'BLOCKER', 'structural similarity', 'compiler flags', or 'CFLAGS'.
license: MIT
---

# Rebrew Matching

Deep dive into diff analysis, flag sweeping, and the GA engine.
For the overall reversing workflow, see the `rebrew-workflow` skill.

## 1. Diff Analysis (Always Start Here)

```bash
rebrew match --diff-only src/<target>/<file>.c --json        # structured diff
rebrew match --diff-only --mm src/<target>/<file>.c --json   # structural diffs only
rebrew match --diff-only src/<target>/<file>.c --diff-format csv # CSV format
```

### Diff Markers

- `==` identical bytes
- `~~` relocation difference (acceptable — counts as RELOC)
- `RR` register encoding difference (with `--rr` / `--register-aware`)
- `**` structural difference (needs fixing)
- `XX` invalid relocation difference (resolves to wrong target VA - counts as MISMATCH)

If the diff shows only `~~` lines, the function is already RELOC — promote it.

### How Relocations are Scored
Rebrew parses the COFF object's relocation and symbol tables. It resolves symbols (e.g. `g_var`) against the Data Catalog to find their intended absolute VAs, and checks if the hardcoded VA in the original binary matches.
- `~~` means the relocation points to the correct global variable.
- `XX` means the relocation points to the wrong global variable (the C code referenced `g_var1` instead of `g_var2`). This forces a `MISMATCH`.
Use `--register-aware` to see if remaining `**` diffs are actually just unfixable register allocation differences.

### Auto-Classified Blockers

`rebrew match --diff-only` auto-classifies systemic compiler differences from `**` / `RR` lines (e.g. "register allocation", "loop rotation / branch layout", "stack frame choice"). Use `--fix-blocker` to auto-write these as `// BLOCKER:` and `// BLOCKER_DELTA:` annotations:

```bash
rebrew match --diff-only --fix-blocker src/<target>/<file>.c       # auto-write BLOCKER annotations
rebrew match --diff-only --fix-blocker --json src/<target>/<file>.c # with JSON output
```

When no structural diffs remain, `--fix-blocker` clears existing BLOCKER/BLOCKER_DELTA annotations.

## 2. Flag Sweep

When code logic is correct but bytes diverge, try different compiler flags:

```bash
rebrew match --flag-sweep-only src/<target>/<file>.c              # default tier
rebrew match --flag-sweep-only --tier targeted src/<target>/<file>.c # codegen-altering flags
```

| Tier | Combinations | Use Case |
|------|-------------|----------|
| `quick` | ~192 | Fast iteration |
| `targeted` | ~1.1K | Codegen-altering flags only (`/Oy`, `/Op`) |
| `normal` | ~21K | Default sweep |
| `thorough` | ~1M | Deep search |
| `full` | ~8.3M | Exhaustive |


### Multiple Targets
If the file contains multiple `// FUNCTION:` blocks (e.g. for different targets like LEGO1 and BETA10), Rebrew commands will automatically use the active `--target` from `rebrew-project.toml` or the CLI and only diff/mutate against that specific target. Always preserve multi-target annotations.

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

## 5. Structural Similarity Metric

Both `--diff-only` and `--flag-sweep-only` output a structural similarity breakdown that distinguishes flag-fixable vs structural differences:

```
Structural similarity (flags unlikely to help):
  Instructions: 12 exact, 3 reloc, 2 register, 1 structural (of 18 total)
  Mnemonic match: 94.4%  |  Structural ratio: 5.6%
```

With `--json`, the diff output includes a `structural_similarity` object:
- `mnemonic_match_ratio`: how similar the mnemonic sequences are (1.0 = identical)
- `structural_ratio`: fraction of instructions with real structural diffs
- `flag_sensitive`: `true` when flag sweeping may help, `false` when diffs are structural

Use this to quickly rule out flag-based solutions before spending time on sweeps.

## 6. Blocker Tracking

When a function is MATCHING but not byte-perfect, track the blocker in annotations.
Use `--fix-blocker` to auto-generate these from diff classification, or write manually:

```c
// BLOCKER: register allocation, jump condition swap
// BLOCKER_DELTA: 3
```

Used by `rebrew next --improving` to sort by proximity to a match.
`rebrew promote` automatically removes BLOCKER/BLOCKER_DELTA on promotion to EXACT/RELOC.

## 7. Batch Flag Sweep

Sweep compiler flags across all MATCHING functions at once:

```bash
rebrew ga --flag-sweep                             # sweep all MATCHING functions
rebrew ga --flag-sweep --tier targeted             # use targeted tier (~1.1K combos)
rebrew ga --flag-sweep --fix-cflags                # auto-update CFLAGS on exact match
rebrew ga --flag-sweep --dry-run --json            # preview candidates as JSON
rebrew ga --flag-sweep --filter my_func            # only functions matching substring
rebrew ga --flag-sweep --min-size 20 --max-size 200  # filter by size
```

Functions are prioritized by byte delta (smallest first = closest to match).
Functions without a known delta are processed last.

| Tier | Combinations | Use Case |
|------|-------------|----------|
| `quick` | ~192 | Fast iteration (default) |
| `targeted` | ~1.1K | Codegen-altering flags only |
| `normal` | ~21K | Default sweep |
| `thorough` | ~1M | Deep search |
| `full` | ~8.3M | Exhaustive |

With `--fix-cflags`, the `// CFLAGS:` annotation is automatically updated when
the sweep finds an exact match (score < 0.1).

## Tips

- Always start with `--diff-only` before running the GA.
- Flag sweep is fast and often sufficient without the GA.
- Common CFLAGS presets: `/O2 /Gd` (GAME), `/O1 /Gd` (MSVCRT).
