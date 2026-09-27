# PRD 08 — Agent Skills

- **Status**: Shipped
- **Date**: 2026-05 (updated 2026-09)
- **Owner**: rebrew team

**Feature name:** Agent-Facing Workflow Skills
**One-line value:** Ship opinionated, task-scoped playbooks that let an
LLM agent drive Rebrew end-to-end without re-deriving "how to use the
tool" each turn.

## Problem It Solves

Rebrew exposes 25+ CLI tools and dozens of options. An agent that has to
discover the workflow on the fly:

- Burns context tokens reading help output.
- Picks suboptimal command orderings.
- Mixes up edges that humans tolerate but cause silent failures (e.g.
  forgetting `--json`, editing `rebrew-functions.toml` directly).

PRD 08 bundles six skill packs that load only when relevant (via
keyword triggers in their frontmatter) and provide focused command
recipes for each phase of a project.

## Users

- **AI agents** (Claude Code, Cursor, etc.) acting on a Rebrew project.
- **Human users** who want a quick crib sheet for a specific phase.
- **CI bots** dispatching agents to specific tasks (e.g. nightly intake,
  near-miss sweeps).

## Goals

- One SKILL.md per major workflow phase.
- Frontmatter description tuned for keyword routing (init, intake,
  matching, data-analysis, ghidra sync, day-to-day workflow).
- Each skill explicitly states when **not** to use it, pointing at the
  sibling skill instead.
- Machine-readable commands are documented with `--json` so the agent
  receives structured output it can parse without ambiguity. (Convention,
  not machine-checked: `tools/validate_skill_commands.py` skips `--json`,
  so a batch command example without it is not flagged.)

## Non-Goals

- Skills are not tutorials for humans (use `docs/WORKFLOW.md` and
  `docs/CLI.md` for that).
- Skills do not duplicate `--help` text; they reference commands and
  call out the relevant flags.
- Skills do not encode environment-specific paths; agents must read
  `rebrew-project.toml` for paths.

## Functional Requirements

### `rebrew-init` (bare-directory scaffolding)

Trigger keywords: `init`, `scaffold`, `new project`, `bare directory`,
`create project`, `initialize project`, `init project`, `project setup`,
`set up rebrew`, `rebrew init`, `guess-compiler`, `refresh-agents`.

Scope:

- Bare directory + binary → working scaffold (`rebrew init` flag
  selection, including `--guess-compiler` and when to override it).
- Target naming and `.agents/skills/` rendering check.
- `rebrew doctor` as the done-gate; handoff to `rebrew-intake`.

Excludes: in-project intake, day-to-day reversing, matching.
(See ADR-020.)

### `rebrew-workflow` (day-to-day reversing)

Trigger keywords: `reverse`, `decompile`, `skeleton`, `test function`,
`verify`, `lint`, `next function`, `workflow`, or any rebrew CLI not
covered elsewhere.

Scope:

- Picking a function via `rebrew status` and `rebrew todo`.
- Generating skeletons (`rebrew skeleton`).
- Test/diff/lint inner loop.
- Multi-target source-sharing notes.
- References to the annotation spec.

Excludes (route to other skills): intake, deep matching, data analysis,
Ghidra sync.

### `rebrew-intake` (binary onboarding)

Trigger keywords: `intake`, `onboard`, `onboard binary`, `new binary`,
`new target`, `import binary`, `binary recon`, `FLIRT scan`, `first triage`,
`catalog`, `build-db`, `detect-crt`, `gen-layout`.

Scope:

- `rebrew intake <binary>`: the one-shot onboarding command (init +
  enumerate + STUB document). It runs `rebrew init` in-process when no
  `rebrew-project.toml` exists, so it also covers the bare-directory case.
  It does not run FLIRT, catalog, or `build-db`; the skill's procedure
  continues from there. `rebrew-init` remains the path for teaching
  `rebrew init`, profile selection, and target naming.
- Multi-target file layout.
- Ordered intake procedure: doctor → FLIRT (`cfg detect-crt --write`,
  `rebrew flirt`) → `crt-match` → catalog → `build-db` → triage.
- Outputs and post-intake hand-off to other skills.

Excludes: day-to-day work, deep matching, individual function reversing.

### `rebrew-matching` (deep byte matching)

Trigger keywords: the shipped `description` frontmatter in
`src/rebrew/agent-skills/rebrew-matching/SKILL.md` (`stuck`, `almost
matches`, `byte match`, `flag tuning`, `flag sweep`, `GA`, `near-miss`,
`prove`, `angr`, `objdiff`, `gap-trace`, `climb`, `qual-sweep`, …). That
file is the single source of truth for the trigger list.

Scope:

- Diff analysis as the always-first step.
- Diff marker semantics (`==`, `~~`, `RR`, `**`, `XX`).
- Auto-classified blockers.
- GA engine usage (single-function and batch).
- Flag sweep tiers.
- `rebrew prove` workflow.

Excludes: picking what to match, skeleton/edit, global-data debugging.

### `rebrew-data-analysis` (globals & BSS)

Trigger keywords: `global`, `global variable`, `data section`, `BSS`,
`vtable`, `dispatch table`, `bss gap`, `bss padding`, `fix bss`,
`extern`, `missing extern`, `type conflict`.

Scope:

- `rebrew data` mode flags (`--conflicts`, `--summary`, `--dispatch`,
  `--bss`, `--fix-bss`, `--gen-header`).
- DATA / GLOBAL annotation format and where metadata lives
  (`rebrew-data.toml`).
- Relationship with `rebrew sync --pull-data`.

Excludes: function bodies, deep matching.

### `rebrew-ghidra-sync` (Ghidra ↔ rebrew)

Trigger keywords: `Ghidra`, `binsync`, `sync ghidra`, `binsync push`,
`binsync pull`, `state-dir`, `ReVa`, `rebrew sync`, `create-functions`,
`bookmarks`, `pull-data`.

> **Architecture note (2026-09):** field sync is BinSync-primary
> (`--push`/`--pull --state-dir`, `--accept-binsync` / `--accept-local`),
> while ReVa MCP handles structural operations (`--create-functions`,
> `--bookmarks`, `--pull-data`).

Scope:

- Program path validation (`ghidra_program_path` in config).
- Preview / inspect commands.
- Push and pull recipes with safety guarantees.
- Default ReVa MCP endpoint (`http://localhost:8080/mcp/message`); overrideable via
  `--endpoint URL`.

Excludes: source editing, picking functions, data analysis without Ghidra.

## User Stories / Workflows

### Story 1 — Agent routes correctly by keyword

1. User: "the FLIRT scan flagged a bunch of MSVCRT funcs, what now?"
2. Agent loads `rebrew-intake` (keyword "FLIRT scan") and follows the
   intake procedure that includes the CRT match step.

### Story 2 — Agent escalates to matching

1. User: "this function is NEAR_MATCHING with delta 6, can you finish it?"
2. Agent loads `rebrew-matching`, runs `rebrew diff`, classifies the
   blocker, then runs `rebrew match --flag-sweep-only`.

### Story 3 — Agent stays in scope

1. User in the middle of editing a function asks "what about the
   relocation on `_g_state`?"
2. The active skill is `rebrew-workflow`. It explicitly hands off to
   `rebrew-data-analysis` rather than answering inline with stale
   knowledge.

### Story 4 — Multi-skill sequence

1. Empty directory → `rebrew-init` scaffolds, then hands off.
2. Fresh project → `rebrew-intake` runs.
3. After intake completes, agent transitions to `rebrew-workflow` for
   day-to-day reversing.
4. When NEAR_MATCHING piles up, `rebrew-matching` is engaged.
5. Before merging, `rebrew-ghidra-sync` pushes new labels.

## Skill File Layout

Each skill lives at
`src/rebrew/agent-skills/<name>/SKILL.md` and follows this template:

```
---
name: <skill-name>
description: <one-paragraph summary with keyword triggers>
license: MIT
---

# <Skill Title>
<orientation paragraph>

## When NOT to use this skill
- … route to sibling skill X
- … route to sibling skill Y

## <Phase 1 heading>
<command block>
<notes>

## <Phase 2 heading>
…
```

Supporting documents live alongside, e.g.
`agent-skills/rebrew-workflow/references/annotation-format.md`.

`rebrew init` renders this tree into a project's `.agents/skills/` directory
(substituting `<target>`), so agents working in the project load them from
there; `src/rebrew/agent-skills/` remains the canonical, packaged tree.

## CLI Surface

```bash
rebrew skills list                # table of skill name + short description
rebrew skills list --json         # machine-readable list (name + description)
rebrew skills show <name>         # pretty-print the SKILL.md (Markdown render)
rebrew skills show <name> --json  # name/description/path + raw content
```

## Success Metrics

- An agent presented with a fresh project completes intake purely from
  `rebrew-intake` instructions.
- An agent never edits `rebrew-functions.toml` by hand because every
  skill emphasises `update_source_status` / the CLI tools.
- Skill files stay <250 lines so the agent always loads them in one
  fetch.
- A regression test asserts that example commands in each SKILL.md use real
  flags: `tools/validate_skill_commands.py` checks every `rebrew <subcommand>
  --flag` in the SKILL.md bash blocks and inline code spans (plus
  `references/*.md`) against live `--help` output, skipping
  `--help`/`--json`/`--target`/`--version` (`_SKIP_FLAGS`). It runs only
  under the suite (`tests/test_skill_commands_validate.py`); the
  `validate-skill-commands` pre-commit hook is registered with
  `stages: [manual]`, so it is not part of `pre-commit run --all-files`.
  `tests/test_skills_sync.py` pins the rendered `.agents/skills/` copy to
  `src/rebrew/agent-skills/`.

## Open Questions / Known Limitations

- Flag drift is auto-checked: `tools/validate_skill_commands.py` parses every
  `rebrew <subcommand>` line in the SKILL.md bash blocks, inline code spans,
  and `references/*.md`, then verifies each `--flag` against live `--help`.
  It runs in the suite; the pre-commit hook is `stages: [manual]` and nothing
  in CI or the Makefile invokes it. (Partly resolved — `--json`, `--target`,
  `--version`, and `--help` are skipped, so those four can still drift; so can
  frontmatter descriptions / trigger keywords, which are not validated against
  the CLI surface at all.)
- The `rebrew-ghidra-sync` skill and all CLI tools share a single canonical
  default endpoint of `http://localhost:8080/mcp/message`. (Resolved — was
  a dual-default between 8089 and 8080; see gap report for history.)
- `rebrew-init` ships bare-directory scaffolding for `rebrew init`
  (ADR-020). `rebrew intake` invokes the same init app in-process when no
  project exists, so a bare directory is covered by either skill; `rebrew-init`
  is the one that teaches `rebrew init` itself.
- `rebrew skills list` / `rebrew skills show` provide built-in discovery
  (`--json` for machine-readable output). (Resolved — was missing; agents no
  longer need to scan the directory.)
- Skills assume the agent has shell access to run rebrew CLI; pure
  text-only agents can read the skills but cannot execute commands.
