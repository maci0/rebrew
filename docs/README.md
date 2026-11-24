# Rebrew documentation

[Getting started](GETTING_STARTED.md) walks through a first byte match.
[Project setup](ONBOARDING.md) covers manual setup and first-run errors.
[Workflow](WORKFLOW.md) covers day-to-day matching, multiple targets, and CI.

## Commands and project configuration

- [CLI reference](CLI.md) · commands, flags, examples, and exit codes
- [CLI migration](CLI_MIGRATION.md) · routes renamed in the October 2026 reorganization
- [Configuration](CONFIG.md) · `rebrew-project.toml` and environment variables
- [Toolchains](TOOLCHAIN.md) · compiler profiles, image builds, and execution backends
- [SDK media](SDK_MEDIA.md) · provenance and checksums for DirectX and Platform SDK media
- [Xtensa](XTENSA.md) · ELF, XCC linking, and disassembly

## Matching, libraries, and binary layout

- [Match types](MATCH_TYPES.md) · byte verdicts, relocation masking, and proof results
- [Compiler code generation](codegen/README.md) · per-compiler instruction patterns and C idioms
- [MSVC 6 matching patterns](CODEGEN_PATTERNS.md) · C89, SEH, and byte-matching examples
- [GA mutations](GA_MUTATIONS.md) and [flag sweep tiers](FLAG_SWEEP_TIERS.md) · search operators and compiler option sets
- [FLIRT signatures](FLIRT_SIGNATURES.md) · obtain and generate signatures to identify library code
- [reccmp adaptations](RECCMP_ADAPTATIONS.md) · assembly comparison, vtables, and float constants
- [OMF object notes](OMF_NOTES.md) · 16-bit Microsoft and 32-bit Watcom object formats
- [Post-link layout](POSTLINK.md) · layout packages and normalization against a reference binary

## Metadata, coverage, and integrations

- [Metadata ownership](METADATA.md) · stores, precedence, provenance, and writers
- [Metadata formats](METADATA_FORMAT.md) · function and data TOML schemas
- [Source annotations](ANNOTATIONS.md) · address anchors, bindings, and lint diagnostics
- [Coverage documents](COVERAGE_DOCUMENT.md) and [dashboard API](dashboard-api.yaml) · portable snapshots and HTTP contract
- [Ghidra and BinSync](BINSYNC_INTEGRATION.md) · field exchange, state repositories, and structural operations
- [Name normalization](NAME_NORMALIZATION.md) · symbol names from Ghidra and rizin
- [Python API](PYTHON_API.md) · library imports, registries, errors, and service clients
- [Ecosystem](ECOSYSTEM.md) and [architecture diagrams](architecture.drawio) · Rebrew, Resembl, and third-party interfaces
- [Jobs service](../services/jobs/README.md) · experimental loopback service for queued operations
- [decomp.me compilers](DECOMPME_COMPILERS.md) · compiler inventory and snippet research

## Contributing

- [Contributor setup](../CONTRIBUTING.md) · prerequisites, tests, and releasing
- [Architecture](ARCHITECTURE.md) and [principles](PRINCIPLES.md) · module map, data flow, and invariants
- [Repository rules](../AGENTS.md), [development](DEVELOPMENT.md), [adding a command](ADDING_A_COMMAND.md), and [documentation style](STYLE.md)
- [CI](CI.md) · required checks and project verification
- [Cordis](CORDIS.md) and [tutorial](CORDIS_TUTORIAL.md) · component composition, provider replacement, and teardown
- [Security policy](../SECURITY.md), [threat model](THREAT_MODEL.md), and [defensive patterns](DEFENSIVE_PATTERNS.md)
- [Performance](PERFORMANCE.md) · measurement log and retained optimizations, with detailed reports for [ten hot paths](PERFORMANCE_TEN_HOTPATHS.md), [6.6.0](PERFORMANCE_6_6_0.md), and [6.7.0](PERFORMANCE_6_7_0.md)

## Decisions, proposals, and research

- [Architecture decisions](adr/README.md) and [product requirements](prd/README.md) · decisions, design scope, and implementation status
- [Roadmap](ROADMAP.md) and [Guild findings](IDEAS-GUILD.md) · proposals and campaign evidence
- [Project tooling](PROJECT_TOOLING.md) · migration ledger for Guild, Holidaydecomp, and test projects
- [Jev research](JEV.md) · typed decisions over Rebrew JSON
- [Changelog](../CHANGELOG.md) and [archive](archive/README.md) · releases, dated reviews, and completed plans
