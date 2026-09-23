# Rebrew Documentation

## Guides

| Document | Description |
|----------|-------------|
| [GETTING_STARTED.md](GETTING_STARTED.md) | Start here (humans): the mental model, the 15-minute walkthrough, the core loop |
| [ONBOARDING.md](ONBOARDING.md) | First-run walkthrough: binary → intake → doctor → first match (incl. manual discovery) |
| [WORKFLOW.md](WORKFLOW.md) | Full iteration loop — test, diff, match, prove, verify; multi-binary; JSON / CI |
| [CODEGEN_PATTERNS.md](CODEGEN_PATTERNS.md) | MSVC6 codegen patterns table, SEH helpers, C89 rules, matching idioms |
| [FLIRT_SIGNATURES.md](FLIRT_SIGNATURES.md) | Obtaining, creating, and using FLIRT signatures for library identification |

## Reference

| Document | Description |
|----------|-------------|
| [CLI.md](CLI.md) | All CLI commands (umbrella `rebrew` + multi-command groups) — flags, examples, internal modules |
| [CONFIG.md](CONFIG.md) | `rebrew-project.toml` format, config loader, arch presets, compiler profiles |
| [ANNOTATIONS.md](ANNOTATIONS.md) | Source-file marker format (`// FUNCTION:` / `library_*.h`) and linter codes E000–E023 / W003–W029 |
| [METADATA_FORMAT.md](METADATA_FORMAT.md) | TOML metadata files (`rebrew-functions.toml`, `rebrew-data.toml`) — volatile fields, status lifecycle |
| [METADATA.md](METADATA.md) | The full store map — canonical vs derived vs cache tiers, who owns which fact, precedence rules |
| [MATCH_TYPES.md](MATCH_TYPES.md) | EXACT / RELOC / NEAR_MATCHING / PROVEN / SKIP — byte-level examples and relocation masking |
| [RECCMP_ADAPTATIONS.md](RECCMP_ADAPTATIONS.md) | reccmp-adapted modules: pinned diff, asm equivalences, vtordisp, float consts, demangle, cvdump PDB access |
| [GA_MUTATIONS.md](GA_MUTATIONS.md) | All 128 GA mutation operators — categories, rationale, discovery origins |
| [FLAG_SWEEP_TIERS.md](FLAG_SWEEP_TIERS.md) | MSVC6 flag-sweep tiers (quick/targeted/normal/thorough/full) — axes and combination counts |
| [DB_FORMAT.md](DB_FORMAT.md) | SQLite schema for `coverage.db`, JSON intermediate format, REST API |
| [NAME_NORMALIZATION.md](NAME_NORMALIZATION.md) | Cross-tool function name normalization (Ghidra/r2/IDA → canonical `func_` form) |
| [TOOLCHAIN.md](TOOLCHAIN.md) | The toolchain zoo — compilers (MSVC 1.52–7, Borland C++ 5.5, Open Watcom, Delphi 1.0), docker images, reproducible builds (`rebrew toolchain vendor`/`smoke`), external tools, Python deps |
| [SDK_MEDIA.md](SDK_MEDIA.md) | DirectX and Platform SDK media provenance: verified archive.org checksums, gaps, official and license-clean sources |
| [OMF_NOTES.md](OMF_NOTES.md) | OMF object format research (Watcom wcc386 32-bit + MSVC 1.52 16-bit dialects, reloc decoding) |
| [POSTLINK.md](POSTLINK.md) | `rebrew postlink`: post-link layout normalization of a built binary onto a reference, text-only layout package from `rebrew gen-layout` |
| [ARCHITECTURE.md](ARCHITECTURE.md) | Module map, data flow, metadata routing rules, architectural conventions |
| [CI.md](CI.md) | CI pipeline: lint/test/package/cli-contract jobs, gates, reproducibility |
| [DEVELOPMENT.md](DEVELOPMENT.md) | Developer workflow |
| [PERFORMANCE.md](PERFORMANCE.md) | Performance notes and hot paths |
| [STYLE.md](STYLE.md) | Documentation style: one-home-per-fact, slop checklist |
| [ADDING_A_COMMAND.md](ADDING_A_COMMAND.md) | Checklist for adding a `rebrew` command |
| [DEFENSIVE_PATTERNS.md](DEFENSIVE_PATTERNS.md) | Bug classes that bit this repo, as prevention rules |
| [THREAT_MODEL.md](THREAT_MODEL.md) | Trust boundaries, attacker-controlled inputs, and their mitigations |

## Integration

| Document | Description |
|----------|-------------|
| [BINSYNC_INTEGRATION.md](BINSYNC_INTEGRATION.md) | `rebrew binsync-init/export/import/diff/overlay`: declib-backed state bridge (names, prototypes, globals, structs, enums, typedefs, locals, comments) + `rebrew sync` feature matrix |
| [DECOMPME_COMPILERS.md](DECOMPME_COMPILERS.md) | decomp.me compiler fleet research + snippet-scrape guide |
| [JEV.md](JEV.md) | TypeSafe Jev (System One) research: typed decisions over rebrew JSON, not codegen |
| [ROADMAP.md](ROADMAP.md) | Multi-arch plan + consoles dossier appendix |
| [IDEAS-GUILD.md](IDEAS-GUILD.md) | Open feature ideas from the guild-rebrew byte-identical campaign, with evidence pointers |

## Ecosystem

| Document | Description |
|----------|-------------|
| [ECOSYSTEM.md](ECOSYSTEM.md) | Cross-repo architecture: how rebrew fits with rebrew-toolchains, resembl, recoverage, reportal, recompile, reagent, relumea, decompedia, recondb — mermaid diagrams |
| [architecture.drawio](architecture.drawio) | Same map in diagrams.net: ecosystem, compile loop, toolchains, FLIRT/resembl/GA, reverse data flows, config/store tiers, data/globals/layout, LLM training export, AI-decomp research |

## Project

| Document | Description |
|----------|-------------|
| [PRINCIPLES.md](PRINCIPLES.md) | Core architectural philosophy (idempotency, score monotonicity, snowball effect) |
| [adr/](adr/README.md) | Architecture decision records (settled decisions, Nygard format) |
| [prd/](prd/README.md) | Product requirements per subsystem |
| [codegen/](codegen/README.md) | Per-compiler-version codegen reference (prologues, registers, FPU, loops) |
