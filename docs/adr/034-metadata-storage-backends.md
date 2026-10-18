# ADR-034: Managed metadata storage backends

- **Status**: Accepted
- **Date**: 2026-10-19

## Context

Managed metadata has five domain owners, while readers, file watchers and review
guards have also depended on physical TOML paths. Supporting another persistence
format requires those consumers to share a storage boundary without moving
schema validation, provenance or comparison verdict ownership into a backend.

## Decision

Use `metadata.storage.MetadataStore` for document reads, writes, discovery,
fingerprints, snapshots and transactions. Keep the existing function, data,
source-evidence, type and library APIs as domain owners. Project configuration
remains `rebrew-project.toml` and selects `[metadata].backend`; TOML is the default.
Optional factories register through `rebrew.metadata_backends`.

The TOML backend retains main files and ownership-preserving `.d/*.toml` fragments.
The experimental SQLite backend stores logical documents by project-relative
filename in `rebrew-metadata.sqlite3`. Documents use TOML encoding inside SQLite
to preserve the existing scalar types. This first backend provides transactional
persistence rather than a relational query API or a performance guarantee.

Writers take the project-config lock before selecting and locking storage.
SQLite uses a reentrant transaction across all logical stores in one database;
the database is mode 0444 at rest. Readers and previews never create storage.
Both backends retain domain validation and earned-STATUS rules.

`rebrew metadata migrate` previews and validates all documents, optionally checks
a reviewed input digest, copies and verifies the destination, then changes the
project selection. It retains the source. Destination-only documents are removed
so switching back cannot resurrect previously deleted settings. There is no
fallback to inactive metadata and no implicit import when configuration changes.

## Consequences

Existing TOML projects need no configuration change. SQLite is an explicit,
project-wide experiment; its database is durable project data and needs backups.
Migration to TOML provides a reviewable export and preserves existing fragment
ownership where records still exist. TOML replacements remain atomic per file,
with rollback on write failures, but are not crash-atomic across a collection.
A failed migration leaves the original backend selected; an inactive destination
may contain a partial export and can be replaced by a subsequent migration.
