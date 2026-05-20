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

### `--bss`

- Verifies BSS layout: walks the `.bss` section and reports gaps between
  known globals (missing externs).
- Detects "implicit" globals that shift subsequent variables.

### `--fix-bss`

- Generates `bss_padding.c` with `static char _pad_<VA>[N];` arrays for
  each detected gap.
- Writes SIZE/SECTION/NOTE metadata back to `rebrew-function.toml` (more
  precisely the per-directory data metadata file).
- Idempotent on re-run.

### `--gen-header`

- Builds `rebrew_globals.h` from `// GLOBAL:` / `// DATA:` annotations,
  grouped by section.
- Emits typed `extern` declarations.
- Safe to invoke offline; `rebrew sync --pull-data` will overwrite the
  same file with Ghidra-sourced types if/when available.

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
      --bss
      --fix-bss
      --gen-header
      --json
  -t, --target TEXT
```

(Modes can compose for `--summary` / `--conflicts` plus `--json`; modes
like `--bss --fix-bss` and `--gen-header` are write modes.)

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
- The dispatch-table heuristic uses runs of x86-aligned candidate
  pointers; tables containing non-pointer entries (mixed payloads) may
  be missed.
- `--gen-header` overwrites `rebrew_globals.h`; users editing that file
  by hand should rename it or block the path before running.
- Section detection comes from LIEF and assumes a single PE/ELF target;
  fat / Mach-O binaries are not yet covered.
- `rebrew data` does not handle data-flow analysis (e.g. which functions
  read which globals). That's left to Ghidra.
