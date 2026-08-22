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
| 01 | [Project Onboarding](01-project-onboarding.md)   | `init`, `doctor`, `cfg`, multi-target setup |
| 02 | [Function Catalog](02-function-catalog.md)       | `catalog`, `extract`, `flirt`, `build-db`, `crt-match` |
| 03 | [Skeleton & Iteration](03-skeleton-and-iteration.md) | `skeleton`, `test`, `diff`, `lint`, `split`/`merge`/`rename`, `todo` |
| 04 | [Byte-Matching Engine](04-byte-matching-engine.md) | `match` (GA), flag sweeps, `prove` |
| 05 | [Verification & Progress](05-verification-and-progress.md) | `verify`, `status`, `graph`, `cache`, `round-trip` |
| 06 | [Data Section Analysis](06-data-section-analysis.md) | `data` (conflicts, dispatch, bss, gen-header) |
| 07 | [Ghidra Sync](07-ghidra-sync.md)                 | `sync` (push, pull, structs, comments, data labels) |
| 08 | [Agent Skills](08-agent-skills.md)               | The five `agent-skills/*/SKILL.md` workflows |
| 09 | [Full BinSync Integration](09-binsync-full.md) *(umbrella future; flat `binsync-export`/`binsync-import`/`binsync-diff` ship today)* | Bidirectional sync with libbs, git-backed state, locals/enums/typedefs |

For source-side gaps discovered while validating these PRDs see
[`00-source-gap-report.md`](00-source-gap-report.md) — last audited
2026-08-22, every recorded gap is marked fixed with evidence.
