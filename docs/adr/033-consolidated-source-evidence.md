# ADR-033: Source evidence shares the function metadata store

- **Status**: Accepted
- **Date**: 2026-10

## Context

Original assembly receipts can describe inline helpers without native addresses.
Support translation units also need target-scoped purposes without invented VAs.
Their separate source store duplicates the function store's ownership, locking
and atomic publication boundary. Ordinary function/data comments already have
canonical fields and need no second copy.

## Decision

Use format 3 for `rebrew-functions.toml`, retaining its `MODULE.0xVA` rows and
adding `[source.definitions.FILE.SYMBOL.MODULE]` (`source_hash`, `evidence`) and
`[source.files.FILE.MODULE]` (`purpose`). Data remains format 2. Both source APIs
and function writers share the function-store lock and preserve each other's
sections, including full row replacements. Existing hashes retain their meaning;
mechanical renames refresh only receipts that were current beforehand.

Normal readers accept only the current canonical stores. Provide the explicit
`source consolidate` operation to preview format-2 function/source inputs and
apply with the reviewed input digest. Preserve every function field and source
receipt before removing the retired source store. A failed retirement restores
the original function document; interrupted identical publications can be retried.

## Consequences

Projects must migrate each metadata root before using version 5.0. Preview and
apply use the same schema validation; stale reviews cannot overwrite newer
inputs. Addressless helpers and file purposes remain explicit identities and
never become fabricated function rows or byte verdicts. Comments stay in their
existing source/function/data locations.

Amends ADR 030's separate source store, function format version and migration
policy; address-only C bindings and rejection of inline state remain unchanged.
