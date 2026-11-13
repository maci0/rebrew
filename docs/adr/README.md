# Architecture Decision Records (ADR)

Decision records for rebrew's architecture.  Each ADR captures a
significant design choice: the context that forced it, the decision
itself, and the consequences (including trade-offs accepted).

## Convention

- Records live in `docs/adr/` as `NNN-short-title.md`, numbered in the
  order they were written.
- Every ADR opens with `# ADR-NNN: Title`, then `- **Status**:` and
  `- **Date**:` (`YYYY-MM` or `YYYY-MM-DD`) lines, then three sections: **Context**,
  **Decision**, **Consequences**.
- Status values: `Accepted` (in force), `Amended by NNN` (partially
  superseded; read the citing ADR for the current shape), `Superseded by
  NNN`. A record whose decision is only partly implemented says so in its
  status line and names the open half. A decision still being made is an
  RFC, not a proposed ADR.
- Write a new ADR when a change is architectural: a new format/profile/
  backend, a behavioral contract change, or a deliberate trade-off that
  future readers must not silently undo.  Small fixes and polish do not
  need an ADR: the CHANGELOG covers those.

## Records

Records keep the command names, flags and module paths current when they were
written. ADR-028 renamed most commands; [CLI_MIGRATION.md](../CLI_MIGRATION.md)
maps old routes to new ones, and [CLI.md](../CLI.md) has current flags.

| ADR | Title |
| --- | --- |
| 001 | [Native 16-bit Windows NE parsing](001-native-ne-parsing.md) |
| 002 | [NE function enumeration: Borland markers vs MSVC-style segments](002-ne-function-enumeration.md) |
| 003 | [NE import parsing degrades to module list, never fabricates](003-ne-imports-degrade-to-modules.md) |
| 004 | [Intake re-discovery prunes only exact auto-stubs](004-intake-prunes-stale-stubs.md) *(amended by 030)* |
| 005 | [Toolchain detection: backend order + NE marker family + linker fallback](005-toolchain-detection.md) |
| 006 | [Standardized toolchain invocation (docker-first, host fallback)](006-toolchain-standardization.md) *(amended by 007, 008, 011, 016; see status lines)* |
| 007 | [Complete containerization + unified byte-reproducibility gate](007-complete-containerization-reproducibility.md) *(amended by 011, 016; see status lines)* |
| 008 | [Docker-only toolchain execution (no host wine/dosbox)](008-docker-only-execution.md) *(amended by 016, 032; see status lines)* |
| 009 | [Cross-target function import (`rebrew source import-related`)](009-cross-target-import.md) *(amended by 022, 024, 028)* |
| 010 | [Shared multi-version sources (`src/shared` + per-target defines)](010-shared-multi-version-sources.md) *(amended by 030: address anchors replaced the `// FUNCTION:` marker)* |
| 011 | [Toolchain build source moves to the sibling recompile-toolchains checkout](011-external-toolchains-checkout.md) |
| 012 | [Metadata store tiers: canonical vs derived vs cache](012-metadata-store-tiers.md) (see [METADATA.md](../METADATA.md)) *(amended by 023, 030, 031, 033, 034, 035)* |
| 013 | [Byte-level library detection against linked archives (`rebrew library match`)](013-lib-match.md) |
| 014 | [The CLI is a component graph (`rebrew.app.plugin` + `rebrew.app.builtins`)](014-component-composition.md) |
| 015 | [Compile backends: local docker images plus the recompile service](015-compile-backends.md) *(amended by 016)* |
| 016 | [Image-backed native compiler profiles (gcc-14.2.0, clang-18.1.8, mingw-16.2.0, watcom-2.0-win16)](016-image-backed-native-profiles.md) *(amended by 017)* |
| 017 | [Standardized toolchain profile names (`<image-family>-<version>`)](017-standardized-toolchain-names.md) *(`msvc-7.0` now builds VC 7.0 RTM like `msvc-7.0-rtm`; see [TOOLCHAIN.md](../TOOLCHAIN.md))* |
| 018 | [Single-file verify scope and baseline (`rebrew verify <file.c> --compare`)](018-single-file-verify.md) |
| 019 | [Todo blocked category (`rebrew todo -c blocked`)](019-todo-blocked.md) *(superseded by 025)* |
| 020 | [Init scaffolding skill (`rebrew-init`)](020-init-skill.md) |
| 021 | [Batch container compiles (`compile_batch_objs` / `precompile_batch`)](021-batch-compiles.md) |
| 022 | [Shared single-file imports (`source import-related --shared`)](022-shared-single-file-imports.md) *(amended by 030)* |
| 023 | [Markers: TOML single source](023-markers-toml-single-source.md) *(superseded by 030)* |
| 024 | [PROVEN is not matched and not sticky](024-proven-is-not-matched.md) |
| 025 | [Remove the todo blocked lens](025-remove-todo-blocked-lens.md) |
| 026 | [One installed CLI for routine commands](026-unified-cli-entry-point.md) *(amended by 027)* |
| 027 | [Build hooks under the umbrella CLI](027-build-hooks-under-umbrella.md) *(amended by 028)* |
| 028 | [CLI domains and explicit operations](028-cli-domains-and-explicit-operations.md) *(amended by 031)* |
| 029 | [Managed type identities and target layout evidence](029-managed-type-identities.md) |
| 030 | [Address-only source bindings and dedicated metadata](030-address-only-source.md) *(amended by 033)* |
| 031 | [Live coverage views and explicit portable exports](031-live-coverage-views.md) |
| 032 | [Explicit local execution and experimental rootless namespaces](032-experimental-unshare.md) |
| 033 | [Source evidence shares the function metadata store](033-consolidated-source-evidence.md) |
| 034 | [Managed metadata storage backends](034-metadata-storage-backends.md) *(amended by 035)* |
| 035 | [Ordered metadata reads and durable replicated writes](035-metadata-replication.md) |
