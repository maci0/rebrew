# Rebrew Documentation

## Guides

| Document | Description |
|----------|-------------|
| [WORKFLOW.md](WORKFLOW.md) | Step-by-step reversing guide — pick a function, write C, test, iterate |
| [BOOTSTRAPPING.md](BOOTSTRAPPING.md) | Adding a new binary to a project from scratch |
| [FLIRT_SIGNATURES.md](FLIRT_SIGNATURES.md) | Obtaining, creating, and using FLIRT signatures for library identification |

## Reference

| Document | Description |
|----------|-------------|
| [CLI.md](CLI.md) | All 22 CLI tools — flags, examples, internal modules |
| [CONFIG.md](CONFIG.md) | `rebrew.toml` format, config loader, arch presets, compiler profiles |
| [ANNOTATIONS.md](ANNOTATIONS.md) | Annotation format (`// FUNCTION:`, `// STATUS:`), linter codes E001–E017 / W001–W015 |
| [MATCH_TYPES.md](MATCH_TYPES.md) | EXACT / RELOC / MATCHING explained with byte-level examples |
| [DB_FORMAT.md](DB_FORMAT.md) | SQLite schema for `coverage.db`, JSON intermediate format, REST API |
| [NAME_NORMALIZATION.md](NAME_NORMALIZATION.md) | Cross-tool function name normalization (Ghidra/r2/IDA → canonical `func_` form) |
| [TOOLCHAIN.md](TOOLCHAIN.md) | External tools (Ghidra, r2, MSVC6), Python dependencies |

## Integration

| Document | Description |
|----------|-------------|
| [GHIDRA_SYNC.md](GHIDRA_SYNC.md) | Ghidra ↔ Rebrew sync feature matrix and roadmap |

## Project

| Document | Description |
|----------|-------------|
| [DESIGN_PRINCIPLES.md](DESIGN_PRINCIPLES.md) | Core architectural philosophy (idempotency, score monotonicity, snowball effect) |
| [USER_STORIES.md](USER_STORIES.md) | Personas, acceptance criteria, and mermaid workflow diagrams |
| [IDEAS.md](IDEAS.md) | Prioritized improvement ideas |
