# ADR-035: Ordered metadata reads and durable replicated writes

- **Status**: Accepted. Amends [ADR-034](034-metadata-storage-backends.md) (adds ordered multi-backend reads and replicated writes beside the single-backend selection).
- **Date**: 2026-11-05

## Context

A project can use SQLite or PostgreSQL for reads while retaining TOML files and
other database replicas. A writer can fail after another destination commits.
Existing domain `updated_at` fields are optional, do not cover every store and
cannot describe deletions. Wall-clock ordering alone can discard independent
offline edits or prefer a machine with a fast clock.

## Decision

Extend the metadata storage boundary from ADR 034 with independent nonempty
`read_backends` and `write_backends` lists in project configuration. Readers use
configured order and fall back only on unavailability. Missing documents,
invalid data and unsupported schemas remain authoritative outcomes or errors.
A single `backend` selection remains available for single-backend projects.

Keep domain validation, provenance and verdict ownership unchanged. A routed
store implements the same document operations as the physical backends.
Staged mutations commit first to a local durable write-ahead journal, then to
each writer. Failed destinations remain queued and are reported. Ordinary
reads can overlay committed local operations on a lagging replica without
writing repairs; previews remain read-only.

Track each document's timestamp, causal revision clock and complete payload in
separate replication state. Preserve deletions as tombstones. Later causal
versions replace older ones; concurrent divergent versions and conflicting
unstamped copies require review. Revision clocks, rather than wall clocks,
establish whether one edit incorporated another. They apply to whole logical
documents, without merging rows or manufacturing verdicts.

Attempt catch-up on the next metadata write and through `metadata reconcile`.
The command validates domain documents and supports read-only preview. It does
not change configuration. Single-backend `metadata migrate` remains a separate
reviewed operation and is refused while routing multiple backends.

## Consequences

The journal and replica receipts are durable recovery inputs, not disposable
caches. TOML and SQLite backups include the local files. PostgreSQL database
backups still require the project's local recovery files alongside them.

Backends commit independently. A successful operation means its recovery
journal is durable; it does not mean every configured replica is current.
There is no background retry daemon, cross-system atomic commit, indexed
record query API or performance guarantee. Losing an unreplicated journal can
lose the newest operations. Independent edits are preserved as conflicts until
reviewed; reconciliation does not choose a winner from timestamps alone.
