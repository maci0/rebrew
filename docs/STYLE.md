# Documentation style

Give each contract one reference. Use a guide to show the workflow, then link
to the reference for flags, schemas, or edge cases. The
[documentation index](README.md) helps readers find each topic.

## One home per fact

| Document | Purpose |
| --- | --- |
| [README](../README.md) | Explain Rebrew, install it, and start a project |
| [Getting started](GETTING_STARTED.md), [onboarding](ONBOARDING.md), [workflow](WORKFLOW.md) | First match, setup and troubleshooting, day-to-day reversing |
| [CLI](CLI.md), [configuration](CONFIG.md), and topical references | Current commands, defaults, formats, and integration contracts |
| [ADRs](adr/README.md) and [changelog](../CHANGELOG.md) | Record decisions and release changes |
| [PRDs](prd/README.md), [roadmap](ROADMAP.md), and [archive](archive/README.md) | Record requirements, proposals, and dated evidence with their status |
| [Packaged skills](../src/rebrew/agent-skills/) and [project rules template](../src/rebrew/AGENTS.md.template) | Guide project work using the same commands and contracts |

## Writing rules

- Lead with the task or contract. Give the reader the command, file, field,
  or result they need.
- Use exact spellings for command names, options, fields, and paths. Mark
  placeholders and show the prerequisites for runnable examples.
- Link to the reference instead of repeating a table of flags or lint codes.
  Keep a short explanation in a guide if the reader needs it for the next step.
- Keep published changelog entries and historical ADRs as dated records.
  Label proposed commands and historical examples where readers might try
  them against the current CLI.

## Maintain the generated surfaces

Edit skills in `src/rebrew/agent-skills/`, the project rule template in
`src/rebrew/AGENTS.md.template`, and principles in `src/rebrew/PRINCIPLES.md`.
Run `make gen-skills` after editing packaged skills. Copy modified principles
to root `PRINCIPLES.md`. `docs/PRINCIPLES.md` points to the packaged source. In a generated
project, `rebrew init --check` reports drift and `--refresh-agents` refreshes
the scaffold.

Validate references with the existing gates:

```bash
make gen-skills-check
uv run --frozen python tools/validate_skill_commands.py --docs
uv run --frozen pytest -q tests/test_docs_hygiene.py tests/test_docs_links.py tests/test_env_docs.py
uv run --frozen pytest -q tests/test_skills_sync.py tests/test_render_skills.py tests/test_skill_commands_validate.py tests/test_validate_skill_commands.py tests/test_init.py
```

The command validator checks command paths and registered flags through
`--help`. Verify argument values, write behavior, and result semantics against
implementation or focused tests.
