# ADR-030: Address-only source bindings and dedicated metadata

- **Status**: Amended by [ADR-033](033-consolidated-source-evidence.md)
- **Date**: 2026-10

## Context

Inline identity blocks and partial metadata migration create two authorities for
source state. Keeping naked-reconstruction flags, structure hints and support
purposes in source perpetuates that ambiguity. The workbench already has locked
stores for identity, provenance and comparison evidence.

## Decision

All state lives in dedicated format-2 metadata stores. Optional ADDRESS comments
bind exactly the next C declaration, with one line per target. New source writers
include these anchors. Readers join syntax-bound addresses with canonical metadata;
metadata-only identities remain valid. Comments do not supply status, sizes, flags,
provenance, reconstruction kind, or support purposes.

Replace the annotation transport with SourceBinding and metadata classification
with `kind`. Provide `source register` for current address-bound declarations.
Remove block parsers, inline writers and marker migration entirely. Reject older
store formats; there is no compatibility or migration reader in the product.

## Consequences

This is a breaking API, CLI and data-format change. Existing projects must be
converted from reviewed exported evidence before use. Conversion is operational
work, not a retained parser. Preserve code, storage ownership, physical line
numbers where relevant, stored verification and external provenance. Registration
cannot earn a comparison verdict. Assembly evidence and target-scoped support
purposes belong in a separate `rebrew-source.toml` store (as amended by
[ADR-033](033-consolidated-source-evidence.md), they now live under `[source]`
in format-3 `rebrew-functions.toml`).

Supersedes the inline-input and incremental-migration decisions in ADR 023.
