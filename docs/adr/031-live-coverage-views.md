# 031: Live coverage views and explicit portable exports

- **Status**: Accepted
- **Date**: 2026-10

## Context

Both dashboards consumed generated coverage TOMLs while notes and blockers already
came from canonical metadata. Projects carried `db_dir` despite having no database.
Normal viewing required a second generation step and could display stale state.
Historical transitions lived only in exports and could not simply be discarded.

## Decision

Normal dashboards derive an immutable view from canonical metadata, sources,
inventory, binary sections and link evidence through one shared Rebrew reader.
Views cache per project/target with input invalidation and coherent publication;
failed targets remain explicit beside healthy siblings. Reads never compile or
write project files. Grid coverage remains presentation data, separate from
status/todo byte denominators.

Remove project `db_dir` and directory resolution APIs. Portable coverage TOMLs
remain an explicit `coverage export --output <directory>` operation with explicit
offline serving. Recoverage uses `RECOVERAGE_SNAPSHOTS` only for this offline mode;
there is no legacy environment alias or metadata-format parser.

Comparison writers record status transitions in `status_history` atomically with
the earned verdict. The metadata owner supports strict, idempotent imports of
existing exported history without changing identity, STATUS, ordinary provenance
or verification. Previews write nothing. Export refuses to overwrite history that
has not been imported. Retiring exports preserves configured inventory files.

## Consequences

Local views follow canonical inputs without a generated store. Shared accounting
and normalization prevent the two dashboards from inventing separate answers.
Cold live reads do more analysis than parsing a prebuilt document, so dependency
tracking, caching and measured rejecting controls are part of the contract.

Offline exports remain useful for sharing and disconnected browsing, and are
read-only in Recoverage. Refresh generates no files; backup/restore operate only
on explicit portable exports. The coverage-tier part of ADR 012 is amended;
canonical address-only source ownership remains ADR 030.
