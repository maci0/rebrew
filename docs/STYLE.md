# Documentation style

How rebrew docs stay accurate without rotting. Adapted from the DeepSeek
Harness documentation standard (`docs/AGENTS.md` there); trimmed to what a
single-maintainer Python repo can enforce. The executable part is
`tests/test_docs_hygiene.py`: prose below it is guidance for reviewers.

## One home per fact

Each fact lives in exactly one document; everywhere else links there.

| Tier | Job | Does NOT belong there |
|---|---|---|
| `README.md` | What rebrew is + 5-minute install | Flag tables, procedures, rationale |
| `docs/GETTING_STARTED.md` | Human tutorial: mental model → first match | Exhaustive flags (→ CLI.md) |
| `docs/ONBOARDING.md` | First-run error catalog | Concepts (→ GETTING_STARTED.md) |
| `docs/CLI.md` | Per-command flags and examples | Design rationale (→ ADRs) |
| `docs/*.md` topical | One subject each (config, toolchain, metadata…) | Other subjects' facts |
| `docs/adr/` | Why a decision was made, what was given up | Current behavior narration |
| `CHANGELOG.md` | What changed per release | How-to (→ guides) |
| `src/rebrew/agent-skills/` | Agent workflows, not contracts | Runtime contracts (→ `docs/CLI.md`) |
| `src/rebrew/AGENTS.md.template` / `PRINCIPLES.md` | Packaged project rules | Contributor-only setup and copied flag catalogs |
| `docs/ROADMAP.md`, `docs/IDEAS-GUILD.md`, `docs/prd/` | Scoped proposals/requirements and dated evidence | Unlabeled proposed commands presented as shipped behavior |

When a review finds the same fact in two places, delete the copy that is
farther from the code and link the survivor. `test_docs_hygiene.py` already
pins the mechanical cases (lint codes ↔ ANNOTATIONS.md, commands ↔ CLI.md +
skills); prose duplication needs human eyes.

## The slop checklist

Hunt these in any doc review:

- **Duplicated rules**: search a distinctive phrase; keep one home, link rest.
- **History in current guides**: state current facts. No "previously…",
  "as of v2.x…", implementation-status annotations ("planned", "not yet").
  Historical PRDs and RFCs keep dated evidence and explicitly label proposed
  commands; they are not current command manuals.
- **Hand-restated catalogs**: flag lists, command lists, lint-code lists
  restated away from their owner. Link the owner.
- **Reasoning transcripts**: how the author derived the answer, rejected
  alternatives, test walkthroughs. Keep the resulting contract; delete path.
- **Paragraph walls**: one paragraph carrying several rules plus asides.
  Split it or demote detail to its home.
- **Emphasis inflation**: bold/CAPS/"critically" everywhere means nothing
  stands out. Reserve emphasis for the clause that changes behavior.
- **Spec-speak in shipped records**: ADRs describe what was decided, in past
  tense. No "should", no migration plans, no acceptance checklists.

## Writing rules

- **Document current state.** Examples use current flags; verify every
  command snippet with `rebrew <cmd> --help` before committing.
- **Name actors and facts.** "verify demotes the STATUS" beats "the status
  is demoted". Name the exact command, field, file, or behavior.
- **One term per concept.** STATUS, BLOCKER, CFLAGS, VA: same word
  everywhere. No synonym rotation.
- **Code terms exact.** Command names, flags, field names, file paths are
  quoted verbatim; never paraphrase them.
- **Terse like the codebase.** Short sentences, fragments OK for tables and
  lists. No pleasantries, no hedging, no filler.

## Maintain the generated surfaces

Edit packaged skills in `src/rebrew/agent-skills/`, the project agent template
in `src/rebrew/AGENTS.md.template`, and principles in `src/rebrew/PRINCIPLES.md`.
Run `make gen-skills`; copy packaged principles over root `PRINCIPLES.md`.
`docs/PRINCIPLES.md` remains a symlink. In generated projects,
`rebrew init --check` reports drift and `--refresh-agents` regenerates the scaffold.
Load skills by task and use references for detail; descriptions distinguish
capabilities rather than enumerate every possible trigger word. Existing user
authorization takes precedence over generic approval advice in skill text.

Validate changes with the existing gates:

```bash
make gen-skills-check
uv run --frozen python tools/validate_skill_commands.py --docs
uv run --frozen pytest -q tests/test_docs_hygiene.py tests/test_docs_links.py tests/test_env_docs.py tests/test_skills_sync.py tests/test_render_skills.py tests/test_skill_commands_validate.py tests/test_init.py
```

The command validator probes `--help` only; it does not execute examples. It
checks command/flag existence, not arguments, semantic claims, external links,
or correctness of a proof/build. Review those against code and focused tests.
Published changelog entries and historical ADRs remain dated records.
