# ADR-028: CLI domains and explicit operations

- **Status**: Accepted
- **Date**: 2026-10

## Context

The CLI had 103 root entries. Related operations were scattered, several commands
selected unrelated readers and writers through mode flags, and BinSync exposed
both grouped and flat paths for identical callbacks. Documentation and generated
build callers need one discoverable, accurate command surface.

## Decision

Keep the daily reversing workflow at the root. Compose specialized commands in
`source`, `binary`, `build`, `diagnose`, `coverage`, `similarity`, `export`, and
`dev`; extend the existing `match`, `types`, `library`, and `binsync` groups.
`builtins.DOMAIN_COMPONENTS` declares membership using the existing public
`CliComponent` and context activation mechanism. Third-party entry points retain
that same mechanism and collision policy; no second dispatcher or alias layer is
introduced. Domain contexts and scopes live as long as their apps.

Use explicit operations for match search, data inventory/writes/layout, Ghidra
sync, imports, PDB flag imports, orphan pruning, and CRT configuration.
Signature copying uses `library init-signatures`; optional runner installation
uses `toolchain install-wibo` so scanning and diagnosis remain read-only. Existing
implementation owners remain shared routines below the callbacks. Locked
metadata writers, byte-earned STATUS, synchronization baselines, and input
provenance remain the same. `sync pull --create-functions` remains an explicit
field-import/structural-operation chain.

Use `--decompiler` for provider selection, `--output/-o` for destination paths,
`--jobs/-j` for workers, and `--limit` for displayed/imported result caps. Document
file versus directory destinations and each zero value. Compiler-profile search
uses plural `--toolchains`/`--exclude-toolchains`; singular `--toolchain` selects
one profile. Executable inputs remain distinct from raw binary slices.

Build callers use `rebrew build driver <cl|link|lib> -- ARG...` and
`rebrew build objdiff-driver TARGET OBJECT`. CMake keeps the executable separate
from arguments; the forwarding boundary preserves caller argv unchanged.
This amends ADR 027's command paths, retaining its single-executable decision.

Every command and group has useful help examples, shared verbosity/version
options, and the common exit-code contract. Templates, canonical packaged skills,
current documentation, and sibling project guidance migrate with the commands.
The complete old-to-new mapping is in [CLI_MIGRATION.md](../CLI_MIGRATION.md).

## Consequences

These are breaking path and option changes, without compatibility aliases.
Consumers must refresh guidance and regenerate CMake/objdiff configurations;
CMake build directories must then be reconfigured. Recoverage continues to call
`catalog.cli.run_catalog` and `coverage_toml.write_coverage_toml` in process and to
read the same coverage document schema. Its CLI hints use `rebrew coverage build`.

The root is smaller and specialized operations require another command word.
Explicit callbacks add signatures but preserve distinct owners and make writes
visible. Tests traverse nested routes, enforce shared help contracts, validate
examples, and exercise generated build argv and the coverage-consumer contract.
