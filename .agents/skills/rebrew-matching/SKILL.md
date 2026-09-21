---
name: rebrew-matching
description: >-
  Deep byte-level matching for functions already stuck at NEAR_MATCHING —
  structural diff, flag sweep, GA, climb/qual-sweep, or symbolic prove to reach
  EXACT/RELOC/PROVEN. Use after rebrew-workflow's test/diff loop stalls.
  Triggers on 'GA', 'genetic algorithm', 'flag sweep', 'near-diag', 'near-miss',
  'prove', 'angr', 'symbolic equivalence', 'NEAR_MATCHING', 'objdiff',
  'gap-trace', 'climb', 'qual-sweep', or 'rebrew match'. For first-pass
  test/verify/todo, use rebrew-workflow instead.
license: MIT
---

```mermaid
graph TD
    Diff[Diff analysis<br/>rebrew diff --json] --> FixBlocker[Classify blockers<br/>rebrew diff --fix-blocker]
    FixBlocker --> Sensitive{flag_sensitive?<br/>structural similarity}
    Sensitive -->|yes| Sweep[Flag sweep<br/>rebrew match --flag-sweep-only --tier &lt;tier&gt;]
    Sensitive -->|no| Ga[GA engine<br/>rebrew match]
    Sweep -->|EXACT / RELOC| RoundTrip[Round-trip validation<br/>rebrew round-trip --json]
    Sweep -->|still NEAR| Ga
    Ga -->|EXACT / RELOC| RoundTrip
    Ga -->|NEAR_MATCHING| Classify[Classify delta<br/>rebrew near-diag --json]
    Classify -->|register / equivalent| Edit[C-level tweaks<br/>edit .c source]
    Edit --> Diff
    Classify -->|structural| Prove[Prove equivalence<br/>rebrew prove --watch-va]
    Prove -->|PROVEN| RoundTrip
    Prove -->|not proven| Edit
```

# Rebrew Matching

Deep dive into diff analysis and the GA engine.
For the overall reversing workflow, see the `rebrew-workflow` skill.

## When NOT to use this skill

- Picking which function to work on → use `rebrew-workflow` (`rebrew todo`)
- Generating skeletons / editing source / verifying STATUS → use `rebrew-workflow`
- Fixing missing globals / `~~` diffs caused by BSS gaps → use `rebrew-data-analysis`

## 1. Diff Analysis (Always Start Here)

```bash
rebrew diff src/bench/<file>.c --json         # structured diff + structural similarity
rebrew diff src/bench/<file>.c -m --json      # mismatches only (** lines)
rebrew diff src/bench/<file>.c -r --json      # register-aware (mark RR encoding diffs)
rebrew diff src/bench/<file>.c --format csv   # CSV for spreadsheet analysis
rebrew diff 0x10009310 --json                    # resolve a VA directly (no .c path needed)
rebrew near-diag src/bench/<file>.c --json    # classify WHY it doesn't match (first-mismatch diagnosis)
rebrew gap-trace src/bench/<file>.c --json    # length-gap trace (short body? early table?) when scores stall flat
rebrew objdiff --output objdiff.json                # GUI diffing project (objdiff) from target objects
```

`rebrew objdiff` synthesizes one target COFF object per annotated source file
from the reference binary and writes an objdiff project config — open
`objdiff.json` in the objdiff GUI for instruction-level diffing of every
function at once (objdiff rebuilds base objects via `rebrew-objdiff-build`).

> **VA on a multi-function file**: `rebrew diff/match/prove/test 0x<va>` targets the
> annotation whose VA matches, NOT the first function in the file. When the
> resolved file covers a different function than the VA, the tool errors out
> instead of silently diffing the wrong bytes.

### Diff Markers

- `==` identical bytes
- `~~` relocation difference (acceptable — counts as RELOC)
- `RR` register encoding difference (only with `-r` / `--register-aware`)
- `**` structural difference (needs fixing)
- `XX` invalid relocation difference (wrong target VA — counts as MISMATCH)

If the diff shows only `~~` lines, the function is already RELOC — `rebrew test` will promote it.

Exit codes: `0` = no structural differences (EXACT/RELOC), `1` = structural `**` lines
found (fix them), `2` = build error. With `--json`, read `summary.exact / summary.reloc /
summary.reg / summary.structural` instead of parsing lines.

### How Relocations are Scored
Rebrew parses the COFF object's relocation and symbol tables. It resolves symbols against
the Data Catalog to find their intended VAs.
- `~~` means the relocation points to the correct global variable.
- `XX` means it points to the wrong variable (forces MISMATCH).
Use `-r` / `--register-aware` to see if remaining `**` diffs are register allocation differences.

### Auto-Classified Blockers

`rebrew diff` auto-classifies systemic compiler differences from `**` / `RR` lines
(e.g. "register allocation", "loop rotation / branch layout", "stack frame choice").
Use `--fix-blocker` to auto-write these to the `rebrew-functions.toml` metadata file:

```bash
rebrew diff --fix-blocker src/bench/<file>.c        # auto-write BLOCKER to metadata file
rebrew diff --fix-blocker --json src/bench/<file>.c # with JSON output
# Ad-hoc BLOCKERs that diff cannot classify (needs structs, SEH helper, etc.):
rebrew blocker set src/bench/<file>.c "needs RE structs -- see rebrew recover-structs"
rebrew blocker clear src/bench/<file>.c
```

When no structural diffs remain, `--fix-blocker` clears existing BLOCKER/BLOCKER_DELTA.
**Never hand-edit `rebrew-functions.toml` for BLOCKER — use `rebrew blocker set/clear` or the `--fix-blocker` writers.**

Use this to quickly rule out structural issues before running the GA.

## 2. GA Engine (Single File)

For automated matching when manual tuning and diffs are insufficient:

```bash
rebrew match src/bench/<file>.c --generations 200 --pop-size 64 -j 16
```

Key flags: `-g/--generations` (default 100), `-p/--pop-size` (64), `-j/--jobs`,
`--seed`, `--seed-file`, `--no-seeds`, `--mutation-focus register|equivalent|structural|auto`,
`--seed-solved/--no-seed-solved`, `--out-dir` (single-function only; default
`output/ga_runs`), `--compare-obj`, `--ignore-lint`, `--collect-pairs`.
Best source → `best.c` under `--out-dir` and back into the `.c` when it wins.
Exit: `0` match · `1` no match · `2` build/config error.

## 3. Flag Sweep

When diff shows `flag_sensitive: true`, try compiler flag combinations before
the GA. Default to `--flag-sweep-only` (targeted tier). Escalation tiers,
batch `--all` flags, and safety stops:
`references/flag-sweep.md`.

```bash
rebrew match src/bench/<file>.c --flag-sweep-only              # targeted (default)
rebrew match src/bench/<file>.c --flag-sweep-only --tier quick # first pass
```

Do **not** run `--tier thorough` / `--tier full` or long `--all` sweeps unless
the user asks. Hand-try `/O2` or `/O1` first; see `references/codegen-hints.md`.

## 4. Structural Similarity Metric

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

Use this to quickly rule out flag-based solutions before spending time on sweeps:
`flag_sensitive: false` means flag sweeping won't help — go straight to the GA or
`rebrew prove`. A high `mnemonic_match_ratio` with low `structural_ratio` means the
code is semantically close and C-level tweaks (or `rebrew near-diag`) may finish
the job.

When kinds match but residue remains (statement order / qualifiers), prefer these
over another GA pass:

```bash
rebrew climb src/bench/<file>.c --json                 # adjacent statement-order hill-climb
rebrew climb src/bench/<file>.c --objective aligned --json
rebrew qual-sweep src/bench/<file>.c --json            # declaration qualifier sweep
rebrew qual-sweep src/bench/<file>.c --dry-run --json
```

`climb` = adjacent statement swaps; `qual-sweep` = exhaustive per-declaration
qualifier variants. Batch flag/GA details: `references/flag-sweep.md`.

## 5. Blocker Tracking

When a function is NEAR_MATCHING but not byte-perfect, blockers live in the `rebrew-functions.toml` metadata file (managed programmatically — never hand-edit):

```toml
["SERVER.0x<VA>"]
blocker = "register allocation, jump condition swap"
blocker_delta = 3
```

Set them via `rebrew blocker set <file|0xVA> "<reason>" [--delta N]` (and `rebrew blocker clear` to remove).
Use `rebrew diff --fix-blocker` / `rebrew near-diag --fix-blocker` to auto-generate from classification.

## 6. Tips

- Always start with `rebrew diff` before running the GA.
- For library-origin functions (MSVCRT, ZLIB), use `rebrew crt-match` to identify the reference source first.
- Common CFLAGS presets: `/O2 /Gd` (GAME), `/O1 /Gd` (MSVCRT).
- If a function remains NEAR_MATCHING after GA and blockers are structural, use `rebrew prove`.
- While iterating on a single function, `--watch` (on `diff`, `prove`, or `match`) re-runs on every
  file save — faster than re-typing the command.
- Do not start long GA (`-g` large / `--all`) or thorough/full sweeps without user confirmation.

## 7. Symbolic Equivalence Proving

When stuck at NEAR_MATCHING (register alloc / reorder / loop layout), classify
then prove:

```bash
rebrew near-diag src/bench/<file>.c --json
rebrew near-diag --all --fix-blocker --json
rebrew prove src/bench/<file>.c --json
rebrew prove --all --json
```

Register-gap verdicts (`REGISTER (N% of delta)`) are prime PROVEN candidates —
run `rebrew prove --all` before more GA. Full flags, EDX/`--watch-va` gotchas,
and angr mechanics: `references/prove.md`. Requires `pip install 'rebrew[prove]'`.

## 8. End-to-End Round-Trip

After `rebrew verify` reports all EXACT/RELOC:

```bash
rebrew round-trip --json                     # full splice validation
rebrew round-trip --json --dry-run           # preview the splice set
rebrew round-trip --json --filter "MyClass::"  # scope to a symbol substring
rebrew round-trip --json --strict-catalog    # exit non-zero on unresolved catalog symbols
```

Writes `<binary>.reasm` next to the target. Inspect `spliced`, `mismatches`
(`compile_drift` / `catalog_resolution_drift`), `skipped_catalog`,
`skipped_proven`. Full splice/fallback rules live in the rebrew-workflow
skill (its round-trip reference). Use in CI alongside `verify --compare`.
