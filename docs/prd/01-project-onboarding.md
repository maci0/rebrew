# PRD 01 — Project Onboarding

**Feature name:** Project Onboarding
**One-line value:** Make standing up a new Rebrew project a single command, with safe
defaults for compiler, layout, and target binary, and provide diagnostics that prove
the toolchain works before the user attempts to match a single function.

## Problem It Solves

Binary-matching reversing requires a precise toolchain (period-correct MSVC, Wine or wibo,
include/lib paths, FLIRT signatures, a parsed function list). New users repeatedly fail
during their first hour because:

- They start with no `rebrew-project.toml` and have to author one by hand.
- They have multiple binaries (DLL + EXE) and the relationship between "target",
  "binary", and "module" is unclear.
- The MSVC6 + Wine combo silently misbehaves (missing `mspdb*.dll`, `tools/wibo` not
  executable, include path typos) and the failure surfaces deep inside a compile far
  from the cause.
- TOML edits get clobbered (formatting, comments, indentation) when scripted.

Project Onboarding solves all of this with `rebrew init`, `rebrew doctor`, and the
`rebrew cfg` family of read/write commands that round-trip TOML.

## Users

- **Solo reverser** spinning up a project for a game/utility binary.
- **AI agent** (e.g. the `rebrew-intake` skill) that must script project setup,
  edit `rebrew-project.toml` programmatically, and verify readiness.
- **CI/automation** that wants a single `rebrew doctor --json` exit code to gate
  matrix jobs.
- **Team lead** adding a second target (beta build, demo, expansion DLL) to an
  existing project.

## Goals

- One-command project bootstrap that creates a working directory layout
  (`original/`, `src/<target>/`, `bin/<target>/`) and a valid
  `rebrew-project.toml`.
- Compiler profile auto-selection (`msvc400`, `msvc420`, `msvc6`, `msvc7`,
  `gcc`, `clang`) with a single `--compiler` flag.
- Optional one-shot install of the `wibo` Wine alternative (`--install-wibo`).
- Doctor command that validates:
  - The configuration file parses.
  - The target binary exists and is the declared format/arch.
  - The compiler binary is on `PATH` or in a configured location.
  - Include and lib paths exist.
  - The function list (`functions.txt` / Ghidra JSON) is parseable.
  - `reversed_dir` exists.
- A scriptable `rebrew cfg` subcommand suite that reads and writes TOML safely
  (preserves comments + ordering via `tomlkit`) and exits cleanly when keys are
  missing.

## Non-Goals

- Onboarding is not responsible for **finding** the binary; the user must drop it
  into `original/<filename>` themselves.
- `rebrew init` does not download the MSVC toolchain (legal/licensing constraints).
  It only optionally fetches `wibo`.
- Doctor does not attempt to **fix** problems. It diagnoses and exits non-zero;
  fixes are left to the user / `rebrew cfg set ...`.
- No GUI; CLI only.

## Functional Requirements

### `rebrew init`

- Creates `rebrew-project.toml` in the current working directory.
- Creates `original/`, `src/<target>/`, and `bin/<target>/` subdirectories.
- Writes an `AGENTS.md` stub from the bundled template so AI agents have project
  context.
- Picks compiler defaults from one of the named profiles
  (`msvc400`, `msvc420`, `msvc6` default, `msvc7`, `gcc`, `clang`).
- Idempotent: re-running on an existing project must not corrupt
  `rebrew-project.toml`.
- `--install-wibo` downloads `tools/wibo` and marks it executable.
- `--json` emits a structured result of what was created.

### `rebrew doctor`

- Reads `rebrew-project.toml` from the current directory (auto-walks upward).
- For the chosen target (`--target`, defaulting to first listed) runs a checklist:
  config validity, target binary existence + format match, compiler path,
  include/lib paths, function list presence, reversed dir presence.
- Exits non-zero on any failure (CI gate).
- `--json` mode emits the full check list with per-check `status` + `message`.
- `--install-wibo` can be passed to fetch the runner if it's missing.

### `rebrew cfg`

- `list-targets` enumerates `[targets.*]` entries with binary + format.
- `show [KEY]` prints the parsed config, or one value if a dotted key is given.
- `raw [--format json|toml]` dumps the raw file untouched.
- `path` prints the absolute path to the discovered `rebrew-project.toml`.
- `add-target NAME --binary FILE` adds a new target stanza idempotently and
  auto-detects format/arch from the binary using LIEF.
- `remove-target NAME` removes the stanza idempotently.
- `set KEY VALUE` sets a scalar value via dotted path; respects scoping rules
  (e.g. `targets.<name>.binary`).
- `add-module TARGET MODULE` / `remove-module TARGET MODULE` manages origin
  module names (e.g. `GAME`, `MSVCRT`).
- `set-cflags TARGET MODULE "/O2 /GS-"` sets the per-module CFLAGS preset.
- `detect-crt` walks the project tree for MSVC source mirror directories and
  registers them.

## User Stories / Workflows

### Story 1 — Fresh project, one binary

1. User creates an empty directory, drops `mygame.exe` into a sibling
   `original/` folder.
2. Runs `rebrew init --target mygame --binary mygame.exe --install-wibo`.
3. `rebrew-project.toml`, `AGENTS.md`, `src/mygame/`, `bin/mygame/` appear.
4. User runs `rebrew doctor` and sees green checkmarks for compiler + binary.
5. They run `rebrew extract list` to find their first function to reverse.

### Story 2 — Adding a second target

1. User has a project with a `main` target (game DLL) and wants to add the EXE.
2. Runs `rebrew cfg add-target client --binary client.exe`.
3. `rebrew cfg show targets.client` confirms the new entry; format was
   auto-detected as PE/x86_32.
4. User runs `rebrew doctor --target client` to validate the toolchain.

### Story 3 — Tuning per-module CFLAGS

1. User notices their MSVCRT-origin functions need `/O1 /Gd` instead of `/O2`.
2. Runs `rebrew cfg set-cflags main MSVCRT "/O1 /Gd"`.
3. Re-running `rebrew verify` picks up the new CFLAGS from the config; no
   `.c` file edits needed.

### Story 4 — CI doctor gate

1. CI runs `rebrew doctor --target main --json` on each PR.
2. If any check fails, the job fails with the JSON report attached as an artifact.
3. The PR author can re-run locally to inspect the same JSON.

## CLI Surface

```
rebrew init [OPTIONS]
  -t, --target TEXT         Initial target name (default: main)
  -b, --binary TEXT         Binary filename (default: program.exe)
  -c, --compiler TEXT       Profile: msvc400 | msvc420 | msvc6 | msvc7 | gcc | clang
      --install-wibo        Download tools/wibo
      --json                Output result as JSON

rebrew doctor [OPTIONS]
      --install-wibo
  -t, --target TEXT
      --json

rebrew cfg list-targets [--json]
rebrew cfg show [KEY] [--json]
rebrew cfg raw [--format json|toml]
rebrew cfg path
rebrew cfg add-target NAME --binary FILE [--format auto] [--arch auto]
rebrew cfg remove-target NAME
rebrew cfg set KEY VALUE
rebrew cfg add-module TARGET MODULE
rebrew cfg remove-module TARGET MODULE
rebrew cfg set-cflags TARGET MODULE "FLAGS"
rebrew cfg detect-crt [--json]
```

All `cfg` write commands round-trip via `tomlkit` and preserve comments and
formatting.

## Success Metrics

- New user can produce a passing `rebrew doctor` exit code in under 5 minutes
  from a fresh checkout, given a valid binary + toolchain.
- Re-running `rebrew init` on an existing project never destroys configuration.
- `rebrew cfg` round-trip preserves comments and section ordering across a
  `raw` → external edit → `set` cycle.
- Adding a new target is one `cfg add-target` call away (no manual TOML edit).
- AI agents using the `rebrew-intake` skill can complete onboarding entirely via
  `--json` commands.

## Open Questions / Known Limitations

- `init` always seeds the same `AGENTS.md` template from `src/rebrew/AGENTS.md.template`;
  it cannot be customised per-project at creation time.
- `init --install-wibo` is the only auto-fetched toolchain piece; MSVC itself
  must be sourced separately (legal constraint).
- `doctor` does not check FLIRT signature availability or CRT source mirror
  health — those land in PRD 02 (Function Catalog) and the `cfg detect-crt`
  command.
- `cfg add-target` infers format/arch from the binary at the time of the call;
  if the binary is later replaced with a different arch, the stanza is stale
  (manual `cfg set` required).
- Multi-target projects share a single compiler profile by default; per-target
  compiler overrides require manual `cfg set` calls.
