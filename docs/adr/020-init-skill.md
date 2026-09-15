# 020 — Init scaffolding skill

## Status

Accepted

## Context

The intake skill assumes an existing project (`rebrew init` appears inside
it as one step among many). Agents starting from a bare binary + empty
directory hand-roll the scaffold: `rebrew init` flags, `--guess-compiler`
vs explicit profile, skill rendering into `.agents/skills/`, first `doctor`
gate, then handoff to intake. The decisions (which profile, what target
name, when the scaffold is "done") are project-setup knowledge with no
dedicated skill.

## Decision

- New `rebrew-init` packaged skill: bare directory → working scaffold.
  Covers `rebrew init` flag selection (including `--guess-compiler` and
  when to override it), target naming, `.agents/skills/` rendering check,
  `doctor` as the done-gate, and handoff to `rebrew-intake`.
- The skill is prose + commands only (like the other five) — no code.
  Validated by `tools/validate_skill_commands.py` like the rest.

## Consequences

- Six packaged skills; `rebrew skills list` picks it up mechanically.
- Intake keeps its in-project scope; init owns the empty-directory case.
  Overlap is one handoff line in each direction.
