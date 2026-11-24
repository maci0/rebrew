# Rebrew Product Requirements Documents

These records describe subsystem requirements and their implementation
status. Use each PRD's status line to interpret examples and open items.
The PRDs cover the core reversing loop. PRD 09 is partial because divergent
Git merge remains open. For current commands and options, see the
[CLI reference](../CLI.md) or
`rebrew --help`.

| #  | PRD                                              | Scope |
| -- | ------------------------------------------------ | ----- |
| 01 | [Project Onboarding](01-project-onboarding.md)   | `init`, `intake`, `doctor`, `cfg`, multi-target setup |
| 02 | [Function Catalog](02-function-catalog.md)       | `coverage catalog/export`, `binary extract`, `library scan-signatures/crt-match/match` |
| 03 | [Skeleton & Iteration](03-skeleton-and-iteration.md) | `skeleton`, `test`, `diff`, `lint`, `source register`, `source split`/`merge`/`rename`, `todo` |
| 04 | [Byte-Matching Engine](04-byte-matching-engine.md) | `match` (GA), flag sweeps, `prove` |
| 05 | [Verification & Progress](05-verification-and-progress.md) | `verify`, `status`, `source graph`, `cache`, `build round-trip` |
| 06 | [Data Section Analysis](06-data-section-analysis.md) | `data list/dispatch/bss/header/layout` |
| 07 | [Ghidra Sync](07-ghidra-sync.md)                 | `sync` (BinSync state-dir field sync + ReVa MCP structural ops) |
| 08 | [Agent Skills](08-agent-skills.md)               | The six `agent-skills/*/SKILL.md` workflows |
| 09 | [Full BinSync Integration](09-binsync-full.md) | Bidirectional sync with declib, git-backed state, locals/enums/typedefs |

The [source-gap report](00-source-gap-report.md) records the August and
September 2026 audits that closed the 33 gaps observed at the time.
