# Flag sweep and batch GA: details

Use when `rebrew diff --json` reports `flag_sensitive: true`, or for batch
NEAR_MATCHING sweeps. Start with `quick`/`targeted`; escalate only if needed.

## Safety

Use `--tier thorough`, `--tier full`, or multi-hour `match batch` GA/sweep batches
only within an explicitly authorized time/scope. Do not request it again
when the session already provides that authorization. Prefer `--dry-run` / `match history`
first. `thorough`/`full` product counts are huge; the engine stride-samples to a
~100k combo bound (see rebrew repo `docs/FLAG_SWEEP_TIERS.md`).

## Single-function sweep

```bash
rebrew match flags src/test/<file>.c # targeted tier (default)
rebrew match flags src/test/<file>.c --tier quick # first pass
rebrew match flags src/test/<file>.c --tier targeted
rebrew match flags src/test/<file>.c --tier normal
rebrew match flags src/test/<file>.c --tier thorough # requires authorized long-run scope
rebrew match flags src/test/<file>.c --tier full # requires authorized long-run scope
```

| Tier | Combinations (product) | When to use |
|------|-------------|-------------|
| `quick` | 192 | First pass on a new STUB |
| `targeted` | 1,152 | Default; when `quick` is close |
| `normal` | 5,376 | General-purpose |
| `thorough` | 258,048 | After `normal` still near: Authorized long run |
| `full` | 6,193,152 | Last resort: Authorized long run (engine auto-samples; no `--sample` flag) |

Axes are per-profile (MSVC `/` flags, Watcom `-os/-ot/…`, Borland `-O1/-O2`,
16-bit MSVC). Docker-only images: `rebrew toolchain pull <profile>`. Try `/O2`
or `/O1` by hand before a blind sweep; heuristics:
`references/codegen-hints.md`. Counts: rebrew repo `docs/FLAG_SWEEP_TIERS.md`.

## Batch matching (`match batch`)

```bash
rebrew match batch --algorithm flags # batch: all NEAR_MATCHING
rebrew match batch --algorithm flags --fix-cflags # auto-update CFLAGS on hit
rebrew match batch --algorithm flags-then-ga # sweep, then GA with best flags
rebrew match batch --algorithm flags-then-ga --skip-recent 24 # skip recent GA runs
rebrew match batch --near-miss
rebrew match batch --improve
rebrew match batch --threshold 8
rebrew match batch --max-stubs 10
rebrew match batch --min-size 32 --max-size 512
rebrew match batch --filter "MyClass::"
rebrew match batch --timeout-min 5
rebrew match batch --dry-run
rebrew match history --json
rebrew match solutions --best --json                       # best GA score per function from .rebrew/ga_runs.jsonl
rebrew match partitions --dry-run                         # TU-partition search (original was amalgamated)
```

Check `match history` before long batches; `--skip-recent N` resumes; `--seed-solved`
is on by default (`--no-seed-solved` to disable). Prefer `climb` / `qual-sweep`
(single-function, in SKILL.md §4) over another GA pass when `near-diag` says
order or qualifier residue.
