# Rebrew Product Requirements Documents

This directory contains feature-level PRDs that describe what Rebrew does
today (not aspirational design docs). Each PRD captures:

- The product problem the feature solves
- Target users
- Goals / non-goals
- Functional requirements
- Concrete user workflows
- The actually-shipped CLI surface (verified via `--help`)
- Success metrics and known limitations

PRDs are organised by feature area:

| #  | PRD                                              | Scope |
| -- | ------------------------------------------------ | ----- |
| 01 | [Project Onboarding](01-project-onboarding.md)   | `init`, `intake`, `doctor`, `cfg`, multi-target setup |
| 02 | [Function Catalog](02-function-catalog.md)       | `catalog`, `extract`, `flirt`, `build-db`, `crt-match`, `lib-match` |
| 03 | [Skeleton & Iteration](03-skeleton-and-iteration.md) | `skeleton`, `test`, `diff`, `lint`, `migrate-markers`, `split`/`merge`/`rename`, `todo` |
| 04 | [Byte-Matching Engine](04-byte-matching-engine.md) | `match` (GA), flag sweeps, `prove` |
| 05 | [Verification & Progress](05-verification-and-progress.md) | `verify`, `status`, `graph`, `cache`, `round-trip` |
| 06 | [Data Section Analysis](06-data-section-analysis.md) | `data` (conflicts, dispatch, bss, gen-header) |
| 07 | [Ghidra Sync](07-ghidra-sync.md)                 | `sync` (BinSync state-dir field sync + ReVa MCP structural ops) |
| 08 | [Agent Skills](08-agent-skills.md)               | The six `agent-skills/*/SKILL.md` workflows |
| 09 | [Full BinSync Integration](09-binsync-full.md) | Bidirectional sync with declib, git-backed state, locals/enums/typedefs |

Each PRD carries its own `- **Status**:` line; PRD 09 is the only one not
`Shipped` (the umbrella and declib I/O ship, divergent git merge remains).

For source-side gaps discovered while validating these PRDs see
[`00-source-gap-report.md`](00-source-gap-report.md) — last audited
2026-08-22, re-audited 2026-09: 33 recorded gaps, all closed (30 fixed in
place, 3 resolved by the BinSync-primary rework).

## Coverage

The nine PRDs above cover the core reversing loop, not the whole CLI:
`rebrew --help` lists 101 top-level commands, and 64 of them are named in no
PRD in this directory (`toolchain`, `library`, `dashboard`, `diagnose`, the
`*-scan` family, and others) — counted by matching every
`rebrew <command>` mention in these files against the top-level command list.
A command absent from this directory is uncovered, not unplanned.
`docs/CLI.md` is the exhaustive command reference.
