# ADR-029: Managed type identities and target layout evidence

- **Status**: Accepted
- **Date**: 2026-10

## Context

A C type has no unique VA. Function/data address rows identify instances or
code, while BinSync struct artifacts are external interchange. Neither binds a
local C definition to a durable type identity with separate target layouts.
Raw preprocessor branches and partial accessed views cannot establish native
allocation extents.

## Decision

Use `rebrew-types.toml`, format 1, with `types.ID.MODULE` records. IDs are stable
across C name/file changes. The writer uses the existing locked atomic 0444
store contract. Store the definition file/name, C size, member offsets, native
size, allocation/stride extent kind, reviewed evidence and compile flags.
Target compiler C89 sizeof/offsetof assertions gate writes. Bind evidence to
the whole owning file, reached-header fingerprint, target compiler context and
native binary SHA-256. Check freshness in `types check` and lint W031.

## Consequences

Full byte extents can contain unknown byte regions; no original field semantics
are implied. A smaller C view remains distinct from a native allocation. No
type VA or byte-match verdict is invented. Renames/moves and conservative
whole-file/header invalidation require reviewing and rebinding the same ID.
Header fingerprints reuse verification's stat-based dependency guard, so a
fresh checkout or touched dependency can require rebinding. External BinSync
artifacts remain separate; this change does not synchronize or publish them.
