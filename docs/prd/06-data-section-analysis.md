# PRD 06: Data Section Analysis

- **Status**: Shipped
- **Date**: 2026-05 (updated 2026-10)
- **Owner**: rebrew team

**Feature name:** Global Data Inventory & Relocation Hygiene
**One-line value:** Explain global references, storage ownership, dispatch tables,
and linked layout with the same target configuration as function matching.

## Problem and Users

Reversers need to distinguish a wrong declaration from a wrong data address,
complete storage extent, or misplaced linked object. Agents need reproducible
inventories and previews that preserve identity and provenance. Project leads
need section-level summaries without treating extern declarations as owners or
function matches as proof of data bytes.

## Data Model

`rebrew-data.toml` is a dedicated format-2 managed store. Qualified `MODULE.0xVA`
rows own identity (`file`, `name`, `kind`), type, extent, section, storage
relationships, and verification evidence. Use CLI commands or locked metadata
APIs; never hand-edit the store. Optional ADDRESS comments bind exactly the next
C declaration. No inline state, old blocks, or earlier data schemas are read.

One source definition or selected linked archive member owns an allocation.
Extern declarations and users are reported separately. An interior alias names
its backing allocation; a layout span or import slot is not another game global.
Uncertain ownership remains unresolved. Binary placement alone does not establish
whether data belongs to the game or runtime.

## Commands

| Command | Behavior |
|---|---|
| `rebrew data list` | Combine source declarations, metadata, sections, and raw-link map evidence; list globals and owners. `--conflicts` filters type conflicts; `--summary` prints section counts. |
| `rebrew data set` | Edit type, name, size, section, file, kind, note, storage kind, backing, or native link symbol through locked writers. Values use repeatable `0xVA=VALUE` options. |
| `rebrew data move OLD_VA NEW_VA` | Re-address one row, refusing an occupied destination; drops the verdict while retaining verification history. |
| `rebrew data mark-literals` | Record compiler literals supported by the link map. |
| `rebrew data dispatch` | Detect plausible function-pointer runs in data sections. `--min-table-len` and `--max-pointer-stride` tune table selection. |
| `rebrew data bss` | Report BSS extents and uncovered gaps. |
| `rebrew data fix-bss` | Generate `bss_padding.c` gap arrays with ADDRESS anchors and dedicated metadata; preserve earlier generated declarations. |
| `rebrew data header` | Generate typed extern declarations from known metadata/declarations without Ghidra. `--output` chooses a path; `--force` permits replacing an existing header. |
| `rebrew data annotate` | Record discovered globals in dedicated metadata; does not insert legacy source markers. |
| `rebrew data layout audit` | Report per-object span/order violations and unresolved or duplicate storage ownership. |
| `rebrew data layout fill` | Emit byte-exact initialized padding and zero-filled BSS padding for established gaps; `--bss-only` limits this to BSS. |
| `rebrew data layout own` | Materialize placeholder globals in their owning source files. `--stub-file` selects the placeholder source. |
| `rebrew data layout fix-ownership` | Move global definitions between source files so each owns a contiguous address run. |
| `rebrew data layout converge` | Insert or adjust leading data pads from measured linked placement. `--rounds` repeats measurement of the same build; rebuild between invocations to measure changed placement. |

Operations offer `--json` for structured output and `--target` for target
selection. Write operations offer `--dry-run`; preview ownership moves and
padding/header generation before accepting them. Read the operation's `-h` for
its exact options; flags belong after the selected subcommand.

Data inventory does not verify bytes. Rebuild after source/layout changes, then
use `rebrew verify --data --built PATH --raw-link` with an actual raw link.
Function matches do not establish data verdicts. BSS is virtual zero-filled
storage and is excluded from initialized-file byte accounting.

## Workflows

### Resolve a declaration conflict

1. Run `rebrew diff src/foo.c --mismatches-only` to locate the operand difference.
2. Run `rebrew data list --conflicts --json` and inspect canonical declarations.
3. Fix the owning subsystem header while preserving compiler-sensitive order.
4. Test affected functions, rebuild, and verify data against the raw link.

### Investigate a BSS gap

1. Run `rebrew data bss --json` and establish the complete extent and provenance.
2. Preview `rebrew data fix-bss --dry-run` or the appropriate layout operation.
3. Accept proven padding, rebuild, and compare placement; a gap alone is not a
   reason to invent another allocation or replacement runtime definition.

### Generate declarations offline

1. Preview `rebrew data header --dry-run`.
2. Reconcile generated declarations with game/runtime ownership boundaries.
3. Generate the header and verify functions affected by declaration changes.

### Decode a dispatch table

1. Run `rebrew data dispatch --json`.
2. Check pointer width, stride, entry count, full extent, and target evidence.
3. Record a backed storage identity and reuse its canonical declaration.

## Success Criteria and Limits

Inventories are deterministic and separate owners, declarations, and users.
Repeated generation preserves managed identity and avoids duplicate definitions.
Previews write nothing; errors name the invalid input. Unknown types and
ambiguous archive providers remain unresolved rather than guessed.

Dispatch detection is heuristic and can miss sparse or unusual tables. Type
inference still needs evidence. Padding records layout facts, not recovered
semantics. Placement convergence does not invoke the build. Header generation
refuses an existing file unless explicitly forced. Live Ghidra label imports use
`rebrew sync pull-data`; synchronization is specified in PRD 07.
