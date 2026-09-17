# Documentation style

How rebrew docs stay accurate without rotting. Adapted from the DeepSeek
Harness documentation standard (`docs/AGENTS.md` there); trimmed to what a
single-maintainer Python repo can enforce. The executable part is
`tests/test_docs_hygiene.py` — prose below it is guidance for reviewers.

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
| `src/rebrew/agent-skills/` | Agent workflows, not contracts | Runtime contracts (→ docs/source) |

When a review finds the same fact in two places, delete the copy that is
farther from the code and link the survivor. `test_docs_hygiene.py` already
pins the mechanical cases (lint codes ↔ ANNOTATIONS.md, commands ↔ CLI.md +
skills); prose duplication needs human eyes.

## The slop checklist

Hunt these in any doc review:

- **Duplicated rules**: search a distinctive phrase; keep one home, link rest.
- **History outside CHANGELOG/ADRs**: state current facts. No "previously…",
  "as of v2.x…", implementation-status annotations ("planned", "not yet").
  Status rots; the tree carries it.
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
- **One term per concept.** STATUS, BLOCKER, CFLAGS, VA — same word
  everywhere. No synonym rotation.
- **Code terms exact.** Command names, flags, field names, file paths are
  quoted verbatim; never paraphrase them.
- **Terse like the codebase.** Short sentences, fragments OK for tables and
  lists. No pleasantries, no hedging, no filler.
