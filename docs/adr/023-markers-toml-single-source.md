# ADR-023: Markers: TOML single source (pure-C sources)

- **Status**: Accepted. Amends [ADR-012](012-metadata-store-tiers.md) (canonical tier: `.c`
  marker lines are no longer the identity source).
- **Date**: 2026-09

## Context

Rebrew's function annotations began as reccmp's inline marker format: every
`.c` file carries `// FUNCTION: MODULE 0xVA` blocks plus key-value comment
lines (`// SIZE:`, `// CFLAGS:`, historically `// STATUS:` and friends).
Rebrew already moved the volatile state (STATUS, BLOCKER, NOTE, GHIDRA, …)
into `rebrew-functions.toml` (ADR 012), but kept the identity fields
inline as the "reccmp contract" so reccmp's parser and a recomp build could
read the tree directly.

That dual layer has real costs:

- **Every `.c` file is parsed twice over**: `annotation.py` /
  `asm.py` maintain the marker block parser, the lint (W019) reconciles
  inline values against TOML overrides, and `--fix-sizes` rewrites C
  source to keep the two copies in step.
- **SIZE/CFLAGS live in two places** (inline contract + TOML override),
  so disagreement is a whole warning class and a sync tool.
- **The marker set is frozen at reccmp's grammar**: rebrew-specific
  markers (`VTABLE`, `STRING`) had to be rejected.
- **Exports shape the registry**: `data.json`, the reccmp CSV, and
  `objdiff.json` read the same registry but the inline marker is the
  de-facto input contract.

Community interop (LEGO-style projects, recomp builds reading the tree
directly) is the one thing the inline contract buys, and it can be had as
an *output* instead of an input constraint.

## Decision

**`rebrew-functions.toml` is the single source of truth for function
identity and state. A migrated `.c` file is pure C.**

- **Per-file, flag-free migration.** `parse_c_file_multi` /
  `parse_c_file_text` fall back to metadata-synthesized Annotations when a
  file carries no inline markers: any TOML entry tagged with a `file`
  field matching the source contributes its `symbol`, `name`,
  `marker_type`, and volatile fields. Files that still carry markers parse
  exactly as before, so a project migrates file-by-file (or never) and all
  consumers keep working.
- **`rebrew migrate-markers`** performs the move: it copies each
  function's `file` / `symbol` / `name` / `marker_type` into the TOML
  entry, strips the marker block (marker line, attached KV lines, bare
  name hints) from the `.c`, and is idempotent. `--dry-run` previews.
- **SIZE/CFLAGS are metadata-owned.** An unmigrated file may still carry
  `// SIZE:` / `// CFLAGS:`. The parser reads them. `rebrew lint --fix`
  moves an equal copy into the store and strips it. A disagreement warns
  and the store wins; the inline text is left for the author. W019 is
  moot on a marker-less file. `--fix-sizes` rewrites the store.
- **The marker set is unshackled.** `VTABLE` and `STRING` are now legal
  markers (`VALID_MARKERS`, parser regexes, lint E001/E015 exemptions on
  par with `GLOBAL`/`DATA`).
- **Interop as output.** *(Superseded; see the amendment at the end: the
  reccmp CSV, `data.json` and `objdiff.json` emitters are deleted, and a
  community recomp build reads the reccmp-compatible source tree.)*
- **Interop as output (original decision, kept for the record).** The reccmp CSV, `data.json`, and
  `objdiff.json` stay thin emitters over `build_function_registry`. A
  community recomp build that needs inline markers reads the reccmp CSV
  (`rebrew catalog --csv`) rather than reading the source tree as the
  contract. *(Superseded; see the amendment at the end: these emitters are
  deleted, so the command and file named here do not exist.)*

## Consequences

- New writers record `file` and a kind under `MODULE.0xVA` and emit pure C.
  Skeletons, library headers, import stubs, `asm --inline-c` (except
  `// SOURCE: naked`), intake stubs, BinSync stubs, data annotate, BSS
  gaps, layout comments, cross-import, and splat import do not write
  `// FUNCTION:`, `// LIBRARY:`, `// STUB:`, `// GLOBAL:`, `// DATA:`,
  `// VTABLE:`, or `// STRING:`. `rebrew source merge` and `rebrew source
  split` still rearrange a file that already carries those lines.
  `rebrew source migrate-markers` is how an unmigrated tree drops them.
- `rebrew source migrate-markers` moves data identity into `rebrew-data.toml`
  on the same pass as function identity. A data row gains `file` and
  `marker_type` (`GLOBAL`, `DATA`, `VTABLE`, or `STRING`), and gains `name`,
  `type`, `size`, and `section` when the row does not already hold them.
  The two stores stay separate: function STATUS and data STATUS are different
  vocabularies, and a global is not compiled. The parser still reads an
  unmigrated data marker. A file with no data-marker line is read from
  `rebrew-data.toml` rows whose `file` matches. A file that still has a
  data-marker line is read from that line.
- `file` matching is by metadata-root-relative path, stored display path,
  or bare filename; a moved metadata root keeps working through the
  trailing-suffix rule.
- Community round-trips (reccmp-based dashboards, PRs with markers)
  re-enter through the source tree or a re-annotated copy: inbound
  sources always re-verify through the pinned image anyway.  (The CSV
  half of this is amended above: there is no CSV export.)

*(Amended: the export half of this decision is superseded. `catalog/export.py`
is deleted, so `data.json`, the reccmp CSV and `rebrew catalog --csv` /
`--data-json` no longer exist; the registry feeds one writer,
`rebrew build-db` → `db/coverage-<target>.toml` (see
[COVERAGE_DOCUMENT.md](../COVERAGE_DOCUMENT.md)). The marker half stands: reccmp-compatible
inline markers remain the input contract, and community round-trips re-enter
through the source tree or a re-annotated copy.)*

*(Amended again: the marker-half sentence above no longer holds. Inline
`// FUNCTION:`, `// LIBRARY:`, `// STUB:`, `// GLOBAL:`, `// DATA:`,
`// VTABLE:`, and `// STRING:` lines, and co-read `// SIZE:` / `// CFLAGS:`,
are not the input contract. The parser still reads them, and `rebrew source
migrate-markers` moves them. New writers record `file` plus a kind under
`MODULE.0xVA` and emit pure C. A reccmp checkout of a migrated tree sees no
annotations. `SIZE` and `CFLAGS` are metadata-owned. `// SOURCE: naked` stays
file-borne. `rebrew source merge` and `rebrew source split` still rearrange
files that already carry inline markers.)*
