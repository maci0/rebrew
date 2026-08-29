# PRD 06 — Data Section Analysis

**Feature name:** Global Data Inventory & Relocation Hygiene
**One-line value:** Treat globals, dispatch tables, and BSS layout as
first-class artifacts so relocation byte diffs can be reasoned about
without leaving the rebrew toolchain.

## Problem It Solves

Once functions start referencing global variables, the byte-level matching
problem becomes a relocation problem:

- The same VA may be annotated with different types in different `.c`
  files; the linker doesn't catch it but it breaks reasoning.
- BSS layout is implicit — missing an extern declaration shifts every
  subsequent global, cascading mismatches across the project.
- Vtables and dispatch tables in `.rdata` look like noise in a hex dump
  until you know they're tables of function pointers.
- Header files describing globals must be hand-maintained, or generated
  from Ghidra, which is overkill when offline.

PRD 06 ships `rebrew data` for the data-section side of the workbench:
inventory, conflict detection, dispatch-table identification, BSS
verification, and `rebrew_globals.h` generation.

## Users

- **Solo reverser** chasing a `~~` (relocation diff) trail back to a
  missing global.
- **AI agent** (`rebrew-data-analysis` skill) auditing the data section
  for conflicts and generating type headers without touching Ghidra.
- **Team lead** wanting a section-by-section summary of how much data is
  annotated.

## Goals

- One command (`rebrew data`) with mode flags for the recurring data
  questions:
  - What globals do we know about?
  - Which globals have type conflicts across files?
  - Where are dispatch tables / vtables?
  - Where are the gaps in our BSS layout?
- Auto-fix mode for BSS gaps (`--fix-bss`) that generates a
  `bss_padding.c` with dummy arrays so the linker emits the correct
  layout.
- A `--gen-header` mode that builds `rebrew_globals.h` from local
  annotations without needing Ghidra.
- `.data` placement tooling (`--layout-audit`, `--fill-data`, `--own`,
  `--fix-ownership`, `--converge`) that converges the linked per-TU data
  layout onto the reference binary's bytes.

## Non-Goals

- `rebrew data` does not push to Ghidra; that's PRD 07.
- It does not infer types from byte patterns alone; type discovery is a
  human/agent task (the tool surfaces evidence).
- It does not rewrite the original `.c` source bodies (only generates
  helper files / headers).

## Functional Requirements

### Default mode

- Scans `reversed_dir` for `// GLOBAL:` and `// DATA:` markers plus
  matching `extern` declarations.
- Cross-references with the target binary's section table.
- Lists every global by VA, name, section (`.data`, `.rdata`, `.bss`),
  and type (per file).
- `--json` emits structured data.

### `--conflicts`

- Filters the inventory to globals whose declared type or array length
  disagrees across files.
- Used to bisect a relocation diff back to a wrong extern.

### `--summary`

- Section-level counts (number of globals, total bytes annotated, %
  coverage of each PE section).

### `--dispatch`

- Heuristically detects dispatch tables and vtables in `.data` / `.rdata`
  by looking for runs of plausible function-pointer-aligned values into
  the `.text` section.
- Lists the table VA, length, and named entries (when identifiable).
- Tunable via `--min-table-len` (default 3) and `--max-pointer-stride`
  (default 4 = contiguous); non-pointer slots within the stride are
  tolerated, so sparse tables still register.

### `--bss`

- Verifies BSS layout: walks the `.bss` section and reports gaps between
  known globals (missing externs).
- Detects "implicit" globals that shift subsequent variables.

### `--fix-bss`

- Generates `bss_padding.c` with `char gap_<VA>[N];` arrays (plus
  `// DATA:` markers) for each detected gap, headed by an auto-generated
  comment.
- Writes SIZE/SECTION/NOTE metadata back to `rebrew-data.toml` (the data
  metadata file at `cfg.metadata_dir`, distinct from the per-directory
  `rebrew-functions.toml` which tracks function status).
- Idempotent on re-run: previously generated declarations are merged with
  newly detected gaps instead of being deleted.

### `--gen-header`

- Builds `rebrew_globals.h` from `// GLOBAL:` / `// DATA:` annotations,
  grouped by section.
- Emits typed `extern` declarations (falling back to
  `unsigned char <name>[]` when no type is known).
- Writes to `{reversed_dir}/rebrew_globals.h` by default;
  `--gen-header-out` redirects it. Refuses to overwrite an existing file
  unless `--force` is passed; regeneration is idempotent (the write is
  skipped when only the timestamp would differ).
- Safe to invoke offline; `rebrew sync --pull-data` writes the same file
  with Ghidra-sourced types when available.

### `.data` placement family

These modes treat per-TU `.data`/`.bss` placement as a convergence
problem: the linked layout must reproduce the reference binary's byte
order across all translation units at once.

- `--annotate` inserts `// GLOBAL:` markers from `rebrew-data.toml` into
  the sources, above each symbol's first declaration (`--dry-run`
  previews; already-marked symbols are skipped).
- `--layout-audit` reports per-TU `.data`/`.bss` span/order feasibility —
  what blocks placement convergence (ORDER/SPAN violations, unowned and
  duplicate-owned symbols).
- `--fill-data` emits `_dpad_<addr>[N]` pads for uncovered `.data` byte
  runs (byte-exact from the reference in the raw region, zero-init for
  BSS); `--bss-only` skips the initialized region.
- `--own` materializes stub-file globals as real definitions in their
  owner TUs (original bytes from the reference); `--stub-file PATH`
  overrides the stub TU (default `src/link_stubs.c`).
- `--fix-ownership` re-partitions global definitions across TUs so each
  owns one contiguous address run (fixes `--layout-audit` SPAN/ORDER
  violations).
- `--converge` runs fixed-point `.data` placement: insert/adjust
  `_dlead_<tu>[N]` leading pads and re-measure; `--rounds N` iterates
  (rebuild per round).

## User Stories / Workflows

### Story 1 — Chasing a `~~` diff to a missing extern

1. `rebrew diff foo.c -m` shows two `~~` lines on a memory load.
2. `rebrew data --conflicts --json` reports that `_g_state` is `int` in
   `foo.c` but `struct State*` in `state.c`.
3. User fixes the type, reruns `rebrew test`, and the diff promotes to
   EXACT.

### Story 2 — Filling a BSS gap

1. `rebrew data --bss --json` reports a 24-byte gap between `_buffer`
   (0x10100000) and `_counter` (0x10100020).
2. `rebrew data --fix-bss` generates `bss_padding.c` with a 24-byte
   placeholder and updates metadata.
3. Subsequent verify runs see no further BSS-induced relocation noise.

### Story 3 — Generating a global header offline

1. The user is working without Ghidra. They run
   `rebrew data --gen-header`.
2. `src/<target>/rebrew_globals.h` is written with grouped extern
   declarations by section.
3. They `#include "rebrew_globals.h"` in functions that needed them.

### Story 4 — Finding a vtable

1. A function calls indirectly through a memory location near
   `0x10300100` in `.rdata`.
2. `rebrew data --dispatch --json` flags a 28-entry table starting at
   that VA with each entry pointing into `.text`.
3. User annotates the table and writes wrappers, unblocking 28 STUB
   functions at once.

## CLI Surface

```
rebrew data [OPTIONS]
      --conflicts
      --summary
      --dispatch
      --min-table-len INTEGER       (default: 3)
      --max-pointer-stride INTEGER  (default: 4)
      --bss
      --fix-bss
      --annotate
      --layout-audit
      --fill-data
      --bss-only
      --own
      --stub-file PATH
      --fix-ownership
      --converge
      --rounds N                    (default: 1)
      --gen-header
      --gen-header-out PATH         (default: {reversed_dir}/rebrew_globals.h)
      --force
      --dry-run
      --json
  -t, --target TEXT
```

(Modes can compose for `--summary` / `--conflicts` plus `--json`; modes
like `--bss --fix-bss` and `--gen-header` are write modes, previewable
with `--dry-run`.)

## Success Metrics

- After running `rebrew data --bss --fix-bss --gen-header`, no
  relocation-diff (`~~`) lines remain in `rebrew diff` runs that are
  attributable to missing/mistyped globals.
- `rebrew data --conflicts` returns an empty list on a clean project.
- `rebrew_globals.h` is deterministic across runs (no spurious
  reordering).
- `rebrew data --dispatch` recovers known vtables on the reference
  project with no false positives.

## Open Questions / Known Limitations

- Type inference is annotation-driven; if no file declares a type the
  tool can only report the byte range.
- `--fix-bss` adds opaque padding arrays; the user must later replace
  them with the real declarations.
- The dispatch-table heuristic (tunable via `--min-table-len` /
  `--max-pointer-stride`) tolerates non-pointer slots within the
  configured stride, but tables whose pointer runs are further apart
  than the stride may still be missed; 16-bit NE tables rely on far
  pointer (`seg:off`) decoding.
- `--gen-header` refuses to overwrite an existing `rebrew_globals.h`
  unless `--force` is passed (FIXED: was a silent overwrite); hand-edited
  files are otherwise preserved.
- Section detection comes from LIEF and covers single PE/ELF/NE (16-bit)
  targets; fat / Mach-O binaries are not yet covered.
- `rebrew data` does not handle data-flow analysis (e.g. which functions
  read which globals). That's left to Ghidra.
