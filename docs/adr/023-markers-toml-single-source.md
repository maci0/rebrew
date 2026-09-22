# 023 — Markers: TOML single source (pure-C sources)

## Status

Accepted. Amends [ADR-012](012-metadata-store-tiers.md) (canonical tier: `.c`
marker lines are no longer the identity source).

## Context

Rebrew's function annotations began as reccmp's inline marker format: every
`.c` file carries `// FUNCTION: MODULE 0xVA` blocks plus key-value comment
lines (`// SIZE:`, `// CFLAGS:`, historically `// STATUS:` and friends).
Rebrew already moved the volatile state (STATUS, BLOCKER, NOTE, GHIDRA, …)
into `rebrew-functions.toml` (ADR 012), but kept the identity fields
inline as the "reccmp contract" so reccmp's parser and a recomp build could
read the tree directly.

That dual layer has real costs:

- **Every `.c` file is parsed twice over** — `annotation.py` /
  `asm.py` maintain the marker block parser, the lint (W019) reconciles
  inline values against TOML overrides, and `--fix-sizes` rewrites C
  source to keep the two copies in step.
- **SIZE/CFLAGS live in two places** (inline contract + TOML override),
  so disagreement is a whole warning class and a sync tool.
- **The marker set is frozen at reccmp's grammar** — rebrew-specific
  markers (`VTABLE`, `STRING`) had to be rejected.
- **Exports shape the registry**: `data.json`, the reccmp CSV, and
  `objdiff.json` read the same registry but the inline marker is the
  de-facto input contract.

Community interop (LEGO-style projects, recomp builds reading the tree
directly) is the one thing the inline contract buys — and it can be had as
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
- **SIZE/CFLAGS become single-source.** Once a file is migrated there is
  no inline value to co-read and no disagreement to warn about (W019 is
  moot on marker-less files); `--fix-sizes` has no source to rewrite.
- **The marker set is unshackled.** `VTABLE` and `STRING` are now legal
  markers (`VALID_MARKERS`, parser regexes, lint E001/E015 exemptions on
  par with `GLOBAL`/`DATA`).
- **Interop as output.** The reccmp CSV, `data.json`, and `objdiff.json`
  stay thin emitters over `build_function_registry`. A community recomp
  build that needs inline markers reads the reccmp CSV
  (`rebrew catalog --csv`) rather than reading the source tree as the contract.

## Consequences

- New projects may keep writing inline markers (skeletons, etc.) until
  migrated — the mixed tree is the steady state, not a bug.
- Tools that scan `.c` files for their own `// GLOBAL:` / `// DATA:`
  patterns (e.g. `rebrew data` global discovery) do not yet read migrated
  data entries from the TOML; migrating data-marker files is deferred
  until that path reads the TOML too.
- `file` matching is by metadata-root-relative path, stored display path,
  or bare filename; a moved metadata root keeps working through the
  trailing-suffix rule.
- Community round-trips (reccmp-based dashboards, PRs with markers)
  re-enter through the CSV/catalog or a re-annotated copy — inbound
  sources always re-verify through the pinned image anyway.
