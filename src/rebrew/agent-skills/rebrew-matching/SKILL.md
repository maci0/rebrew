---
name: rebrew-matching
description: Performs byte-level binary matching using diff analysis, compiler flag sweeping, and the genetic algorithm engine. Use this skill when a function needs structural diff analysis, GA matching, batch flag sweeping, or symbolic equivalence proving to achieve EXACT/RELOC/PROVEN status. Triggers on 'match', 'diff', 'flag sweep', 'GA', 'genetic algorithm', 'byte diff', 'MATCHING status', 'near-miss', 'BLOCKER', 'structural similarity', 'compiler flags', 'CFLAGS', 'prove', 'symbolic execution', 'angr', or 'semantic equivalence'.
license: MIT
---

# Rebrew Matching

Deep dive into diff analysis, flag sweeping, and the GA engine.
For the overall reversing workflow, see the `rebrew-workflow` skill.

## 1. Diff Analysis (Always Start Here)

```bash
rebrew diff src/<target>/<file>.c --json        # structured diff + structural similarity
rebrew diff src/<target>/<file>.c --mm --json   # structural diffs only (**)
rebrew diff src/<target>/<file>.c --format csv  # CSV for spreadsheet analysis
```

### Diff Markers

- `==` identical bytes
- `~~` relocation difference (acceptable — counts as RELOC)
- `RR` register encoding difference (with `--rr` / `--register-aware`)
- `**` structural difference (needs fixing)
- `XX` invalid relocation difference (wrong target VA — counts as MISMATCH)

If the diff shows only `~~` lines, the function is already RELOC — `rebrew test` will promote it.

### How Relocations are Scored
Rebrew parses the COFF object's relocation and symbol tables. It resolves symbols against
the Data Catalog to find their intended VAs.
- `~~` means the relocation points to the correct global variable.
- `XX` means it points to the wrong variable (forces MISMATCH).
Use `--rr` to see if remaining `**` diffs are register allocation differences.

### Auto-Classified Blockers

`rebrew diff` auto-classifies systemic compiler differences from `**` / `RR` lines
(e.g. "register allocation", "loop rotation / branch layout", "stack frame choice").
Use `--fix-blocker` to auto-write these to the `rebrew-functions.toml` sidecar:

```bash
rebrew diff --fix-blocker src/<target>/<file>.c       # auto-write BLOCKER to sidecar
rebrew diff --fix-blocker --json src/<target>/<file>.c # with JSON output
```

When no structural diffs remain, `--fix-blocker` clears existing BLOCKER/BLOCKER_DELTA.

## 2. Flag Sweep

> [!IMPORTANT]
> **Only run flag sweeps when the project's default flags are genuinely suspect for this function.**
> If the project has well-established global CFLAGS (e.g. `/O2 /Gd` for GAME origin), a per-function
> sweep rarely helps and wastes time. The GA is usually more effective for finding code transformations.
>
> **When to sweep**: the diff shows byte-level divergence with correct structure (no `**` lines),
> or you have reason to believe this function used non-standard optimization flags.

```bash
rebrew match --flag-sweep-only src/<target>/<file>.c --tier targeted    # ~1.1K combos
rebrew match --flag-sweep-only src/<target>/<file>.c                    # default tier (normal, ~21K)
```

| Tier | Combinations | Use Case |
|------|-------------|----------|
| `quick` | ~192 | Fast sanity check |
| `targeted` | ~1.1K | Codegen-altering flags only (`/Oy`, `/Op`) — try this first |
| `normal` | ~21K | Default sweep |
| `thorough` | ~1M | Deep search |
| `full` | ~8.3M | Exhaustive |

The structural similarity block in `rebrew diff --json` tells you if sweeping is likely to help:
- `flag_sensitive: true` → sweep may help
- `flag_sensitive: false` → diffs are structural; skip the sweep, go to GA or `rebrew prove`

## 3. GA Engine

For automated matching when manual tuning and diffs are insufficient:

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

`rebrew diff` outputs a structural similarity breakdown:

```
Structural similarity (flags unlikely to help):
  Instructions: 12 exact, 3 reloc, 2 register, 1 structural (of 18 total)
  Mnemonic match: 94.4%  |  Structural ratio: 5.6%
```

With `--json`, the output includes a `structural_similarity` object:
- `mnemonic_match_ratio`: how similar the mnemonic sequences are (1.0 = identical)
- `structural_ratio`: fraction of instructions with real structural diffs
- `flag_sensitive`: `true` when flag sweeping may help

Use this to quickly rule out flag-based solutions before spending time on sweeps.

## 6. Blocker Tracking

When a function is MATCHING but not byte-perfect, blockers live in the `rebrew-functions.toml` sidecar:

```toml
["SERVER.0x<VA>"]
blocker = "register allocation, jump condition swap"
blocker_delta = 3
```

Use `rebrew diff --fix-blocker` to auto-generate these from diff classification.

## 7. Batch Flag Sweep

> [!IMPORTANT]
> Same caveat as above: only run batch sweeps if there is genuine uncertainty about
> project flags. For established projects, prefer `rebrew ga` for batch near-miss functions.

```bash
rebrew ga --flag-sweep                             # sweep all MATCHING functions
rebrew ga --flag-sweep --tier targeted             # targeted tier (~1.1K combos)
rebrew ga --flag-sweep --fix-cflags                # auto-update CFLAGS on exact match
rebrew ga --flag-sweep --dry-run --json            # preview candidates as JSON
rebrew ga --flag-sweep --filter my_func            # only functions matching substring
rebrew ga --flag-sweep --min-size 20 --max-size 200  # filter by size
```

With `--fix-cflags`, the `CFLAGS` field is updated in the sidecar when the sweep finds
an exact match (score < 0.1).

## Tips

- Always start with `rebrew diff` before running the GA.
- For library-origin functions (MSVCRT, ZLIB), use `rebrew crt-match` to identify the reference source first.
- If `flag_sensitive: false`, skip the flag sweep and go straight to GA or `prove`.
- Common CFLAGS presets: `/O2 /Gd` (GAME), `/O1 /Gd` (MSVCRT).
- If a function remains MATCHING after GA and blockers are structural, use `rebrew prove`.

## 8. Symbolic Equivalence Proving

When stuck at MATCHING due to structural differences (register allocation, instruction reordering,
loop unrolling), use `rebrew prove` to mathematically prove semantic equivalence:

```bash
rebrew prove src/<target>/<file>.c --json               # prove and update STATUS → PROVEN
rebrew prove src/<target>/<file>.c --dry-run --json      # preview without updating
rebrew prove src/<target>/<file>.c --timeout 120 --json  # allow 2 min for complex funcs
rebrew prove my_func --json                              # find by symbol name
```

How it works:
1. Extracts target bytes from the DLL and compiles the C source to an .obj
2. Loads both byte blobs into angr's symbolic execution engine
3. Parses the C function definition for calling convention and argument setup
4. Hooks external call relocations with `ReturnUnconstrained`
5. Runs LoopSeer-bounded symbolic execution on both
6. Compares EAX via Z3 — if no input can distinguish them, PROVEN

Requirements:
- angr must be installed: `uv pip install -e ".[prove]"`
- Function must have STATUS: MATCHING or MATCHING_RELOC

Limitations:
- Floating-point heavy functions may not prove (Z3 struggles with x87/SSE)
- Complex loops may cause timeout (increase with `--timeout N`)
- Never produces false positives — if it can't prove, STATUS stays MATCHING
