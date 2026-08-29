# Rebrew Documentation

## Guides

| Document | Description |
|----------|-------------|
| [QUICKSTART.md](QUICKSTART.md) | 5-step path from clone to first matched function |
| [WORKFLOW.md](WORKFLOW.md) | Full iteration loop — test, diff, match, prove, verify; multi-binary; JSON / CI |
| [CODEGEN_PATTERNS.md](CODEGEN_PATTERNS.md) | MSVC6 codegen patterns table, SEH helpers, C89 rules, matching idioms |
| [BOOTSTRAPPING.md](BOOTSTRAPPING.md) | Adding a new binary to a project from scratch (no prior RE work) |
| [FLIRT_SIGNATURES.md](FLIRT_SIGNATURES.md) | Obtaining, creating, and using FLIRT signatures for library identification |

## Reference

| Document | Description |
|----------|-------------|
| [CLI.md](CLI.md) | All CLI commands (umbrella `rebrew` + multi-command groups) — flags, examples, internal modules |
| [CONFIG.md](CONFIG.md) | `rebrew-project.toml` format, config loader, arch presets, compiler profiles |
| [ANNOTATIONS.md](ANNOTATIONS.md) | Source-file marker format (`// FUNCTION:` / `library_*.h`) and linter codes E000–E023 / W001–W028 |
| [METADATA_FORMAT.md](METADATA_FORMAT.md) | TOML metadata files (`rebrew-functions.toml`, `rebrew-data.toml`) — volatile fields, status lifecycle |
| [METADATA.md](METADATA.md) | The full store map — canonical vs derived vs cache tiers, who owns which fact, precedence rules |
| [MATCH_TYPES.md](MATCH_TYPES.md) | EXACT / RELOC / NEAR_MATCHING / PROVEN / SKIP — byte-level examples and relocation masking |
| [GA_MUTATIONS.md](GA_MUTATIONS.md) | All 119 GA mutation operators — categories, rationale, discovery origins |
| [FLAG_SWEEP_TIERS.md](FLAG_SWEEP_TIERS.md) | MSVC6 flag-sweep tiers (quick/targeted/normal/thorough/full) — axes and combination counts |
| [DB_FORMAT.md](DB_FORMAT.md) | SQLite schema for `coverage.db`, JSON intermediate format, REST API |
| [NAME_NORMALIZATION.md](NAME_NORMALIZATION.md) | Cross-tool function name normalization (Ghidra/r2/IDA → canonical `func_` form) |
| [TOOLCHAIN.md](TOOLCHAIN.md) | The toolchain zoo — compilers (MSVC 1.52–7, Borland C++ 5.5, Open Watcom, Delphi 1.0), docker images, reproducible builds (`rebrew toolchain vendor`/`smoke`), external tools, Python deps |
| [OMF_NOTES.md](OMF_NOTES.md) | OMF object format research (Watcom wcc386 32-bit + MSVC 1.52 16-bit dialects, reloc decoding) |
| [ARCHITECTURE.md](ARCHITECTURE.md) | Module map, data flow, metadata routing rules, architectural conventions |
| [CI.md](CI.md) | CI pipeline: lint/test/package/cli-contract jobs, gates, reproducibility |
| [DEVELOPMENT.md](DEVELOPMENT.md) | Developer workflow |
| [PERFORMANCE.md](PERFORMANCE.md) | Performance notes and hot paths |

## Integration

| Document | Description |
|----------|-------------|
| [GHIDRA_SYNC.md](GHIDRA_SYNC.md) | `rebrew sync` feature matrix and known issues (current state; see [prd/07](prd/07-ghidra-sync.md) for roadmap) |
| [BINSYNC_INTEGRATION.md](BINSYNC_INTEGRATION.md) | `rebrew binsync-export` / `rebrew binsync-import` bidirectional bridge (real types + struct fields, `--module`, `--git`, `--accept-binsync`; see [prd/09](prd/09-binsync-full.md) for full `libbs` PRD) |

## Ecosystem

| Document | Description |
|----------|-------------|
| [ECOSYSTEM.md](ECOSYSTEM.md) | Cross-repo architecture: how rebrew fits with rebrew-toolchains, resembl, recoverage, recompile, reagent, relumea, decompedia, recondb — mermaid diagrams |

## Project

| Document | Description |
|----------|-------------|
| [PRINCIPLES.md](PRINCIPLES.md) | Core architectural philosophy (idempotency, score monotonicity, snowball effect) |
| [USER_STORIES.md](USER_STORIES.md) | Personas, acceptance criteria, and mermaid workflow diagrams |
| [CAMPAIGNS.md](CAMPAIGNS.md) | Record of systematic `rebrew match` runs across the corpus |
| [GAP_ANALYSIS.md](GAP_ANALYSIS.md) | Known gaps / missing-feature analysis for the toolchain |
| [IDEAS.md](IDEAS.md) | Open improvement ideas and completed-work log |
| [ML_TRAINING.md](ML_TRAINING.md) | Aspirational: generating binary-source pair datasets and training ML models (not shipped) |
