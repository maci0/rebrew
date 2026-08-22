# PRD 01 — Project Onboarding

**Feature name:** Project Onboarding
**One-line value:** Make standing up a new Rebrew project a single command, with safe
defaults for compiler, layout, and target binary, and provide diagnostics that prove
the toolchain works before the user attempts to match a single function.

## Problem It Solves

Binary-matching reversing requires a precise toolchain (period-correct MSVC in a
docker image, include/lib paths, FLIRT signatures, a parsed function list). New
users repeatedly fail during their first hour because:

- They start with no `rebrew-project.toml` and have to author one by hand.
- They have multiple binaries (DLL + EXE) and the relationship between "target",
  "binary", and "module" is unclear.
- The period-correct toolchain is a docker image — every Windows/DOS compiler
  executes docker-only (wine runs inside the image; there is no host wine/wibo
  fallback) — and a missing image, a profile that contradicts the detected
  compiler family, or wrong flags surface deep inside a compile far from the
  cause.
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
  (`original/`, `src/<target>/`, `bin/<target>/`), an empty function list,
  metadata TOMLs, and a valid `rebrew-project.toml`.
- Compiler profile selection: `--compiler` picks the profile explicitly
  (default `msvc6`; full list via `rebrew toolchain list`), or `--guess-compiler`
  auto-selects from the target binary (diec → PDB → heuristics; prefers the
  16-bit profile for DOS/NE binaries).
- Doctor command that validates:
  - The configuration file parses.
  - The target binary exists, loads, and has a known format/arch.
  - The compiler is ready: the profile's docker image is built (execution is
    docker-only for Windows/DOS toolchains) or the native binary is on `PATH`.
  - Include and lib paths exist (docker-backed profiles get them from the image).
  - The function list (`functions.txt` / Ghidra JSON) is parseable and
    FUNCTION/STUB annotations are not stale.
  - `reversed_dir` exists, plus metadata TOMLs, FLIRT signatures, and Ghidra
    sync setup.
- A scriptable `rebrew cfg` subcommand suite that reads and writes TOML safely
  (preserves comments + ordering via `tomlkit`) and exits cleanly when keys are
  missing.

## Non-Goals

- Onboarding is not responsible for **finding** the binary; the user must drop it
  into `original/<filename>` themselves.
- `rebrew init` does not download or build the toolchain. Windows/DOS compilers
  run through docker images built from the sibling rebrew-toolchains checkout
  (`rebrew toolchain build <name>`); native compilers are PATH/vendored binaries.
  The legacy `--install-wibo` host runner is ignored for image-backed profiles.
- Doctor does not attempt to **fix** problems. It diagnoses and exits non-zero;
  fixes are left to the user / `rebrew cfg set ...`.
- No GUI; CLI only.

## Functional Requirements

### `rebrew init`

- Creates `rebrew-project.toml` in the current working directory; refuses to run
  when one already exists ("A rebrew-project.toml already exists").
- Creates `original/`, `src/<target>/`, and `bin/<target>/` subdirectories, an
  empty `src/<target>/functions.txt`, and `src/rebrew-function.toml` +
  `src/rebrew-data.toml` metadata files.
- Writes an `AGENTS.md` from the bundled template so AI agents have project
  context, copies the bundled `agent-skills/` into `.agents/skills/` (with
  `<target>` substituted), and copies `PRINCIPLES.md`.
- Picks the compiler profile from `--compiler` (default `msvc6`). Accepted
  profiles are the full toolchain list — MSVC 1.52–11.0 variants (`msvc6`,
  `msvc7`, `msvc600sp6`, ...), Borland/Turbo C (`borlandc55`, `tc16`, `tc20`),
  Open Watcom (`watcom`, `watcom16`), `gcc-pe`, `gcc`, `clang` (see
  `rebrew toolchain list`).
- When the binary is already in `original/`, auto-detects format/arch (PE/ELF/
  Mach-O/NE/MZ) and seeds CRT linkage + optimization flags from the toolchain
  fingerprint (MSVC profiles); warns on 16-bit/profile and compiler-family
  mismatches.
- Docker-backed profiles (all Windows/DOS toolchains) are written with an empty
  `command`/`runner` — the docker image drives compilation, so `--install-wibo`
  is ignored for them (wine runs inside the image).
- `--guess-compiler` auto-selects the profile from the target binary; the
  `--wizard/--no-wizard` TTY wizard prompts for anything not passed on the CLI
  (off under `--json`); `--install-completions` writes bash/zsh/fish completion
  scripts into `completions/`; `--link-tools-from PATH` symlinks the profile's
  vendored tree from a master toolchain directory.
- `--json` emits a structured result of what was created.

### `rebrew doctor`

- Reads `rebrew-project.toml` from the current directory (auto-walks upward).
- For the chosen target (`--target`, defaulting to the project default target)
  runs a checklist: config validity, target binary existence + loadability +
  known arch/format, toolchain alignment (detected family vs profile), CRT
  linkage + optimization fingerprint (MSVC), docker image presence for
  Windows/DOS profiles (the image IS the compiler), runner, include/lib paths,
  function list presence + annotation staleness, source files, bin dir,
  metadata TOMLs, FLIRT signatures, Ghidra sync setup, and optional prove tools.
- Exits non-zero on any failure (CI gate).
- `--json` mode emits the full check list with per-check `status` + `message`.
- `--install-wibo` fetches the legacy host runner if missing; it is a no-op for
  docker-backed profiles (the runner config is left untouched).

### `rebrew cfg`

- `list-targets` enumerates `[targets.*]` entries with binary + arch.
- `show [KEY]` prints the parsed config, or one value if a dotted key is given.
- `raw [--format json|toml]` dumps the raw file untouched.
- `path` prints the absolute path to the discovered `rebrew-project.toml`.
- `add-target NAME --binary FILE` adds a new target stanza idempotently and
  auto-detects format/arch from the binary using LIEF (`--arch`/`--format`
  override the detection; `--modules`, `--source-ext`, `--copy/--no-copy`; the
  command refuses a missing binary unless `--force` writes default values).
- `remove-target NAME` removes the stanza idempotently (`--force` skips the
  confirmation prompt; `src/`/`bin/` dirs are kept).
- `set KEY VALUE` sets a scalar value via dotted path; bare target-scoped keys
  (e.g. `binary`) route to the default target (`--dry-run` previews).
- `add-module MODULE` / `remove-module MODULE` manage origin module names for a
  target selected with `--target` (e.g. `GAME`, `MSVCRT`).
- `set-cflags MODULE FLAGS` sets the per-module CFLAGS preset; `--target`
  scopes it to that target's `[targets.<name>.compiler.cflags_presets]` (omitted
  → global `[compiler.cflags_presets]`).
- `set-compiler TARGET PROFILE` sets the per-target compiler profile
  (`targets.<name>.compiler` — the per-target override from the init template).
- `detect-crt [--write]` walks the project tree for MSVC CRT source mirror
  directories and registers them under the target's `crt_sources` when
  `--write` is passed.

## User Stories / Workflows

### Story 1 — Fresh project, one binary

1. User creates an empty directory, drops `mygame.exe` into a sibling
   `original/` folder.
2. Runs `rebrew init --target mygame --binary mygame.exe --guess-compiler`
   (or accepts the wizard's suggested profile), then builds the toolchain
   image with `rebrew toolchain build <profile>`.
3. `rebrew-project.toml`, `AGENTS.md`, `src/mygame/`, `bin/mygame/` appear.
4. User runs `rebrew doctor` and sees green checkmarks for compiler + binary.
5. They run `rebrew extract list` to find their first function to reverse.

### Story 2 — Adding a second target

1. User has a project with a `main` target (game DLL) and wants to add the EXE.
2. Runs `rebrew cfg add-target client --binary original/client.exe`.
3. `rebrew cfg show targets.client` confirms the new entry; format was
   auto-detected as PE/x86_32.
4. User runs `rebrew doctor --target client` to validate the toolchain.

### Story 3 — Tuning per-module CFLAGS

1. User notices their MSVCRT-origin functions need `/O1 /Gd` instead of `/O2`.
2. Runs `rebrew cfg set-cflags MSVCRT "/O1 /Gd" --target main`.
3. Re-running `rebrew verify` picks up the new CFLAGS from the config; no
   `.c` file edits needed.

### Story 4 — CI doctor gate

1. CI runs `rebrew doctor --target main --json` on each PR.
2. If any check fails, the job fails with the JSON report attached as an artifact.
3. The PR author can re-run locally to inspect the same JSON.

## CLI Surface

```
rebrew init [OPTIONS]
  -t, --target TEXT          Name of the initial target (default: main)
  -b, --binary TEXT          Binary filename; an 'original/' prefix is accepted (default: program.exe)
  -c, --compiler TEXT        Compiler profile to use (default: msvc6)
      --guess-compiler       Auto-select the profile from the target binary (diec → PDB → heuristics)
      --install-wibo         Download wibo runner to tools/wibo (legacy; ignored for image-backed profiles)
      --install-completions  Write bash/zsh/fish completion scripts into completions/
      --link-tools-from PATH Master toolchain directory to symlink tools/<profile> from
      --wizard/--no-wizard   Run the interactive onboarding wizard (TTY only, off under --json; default: wizard)
      --json                 Output results as JSON

rebrew doctor [OPTIONS]
      --install-wibo         Download wibo to tools/wibo if missing (legacy; no-op for docker-backed profiles)
  -t, --target TEXT          Target name from rebrew-project.toml (default: project default target)
      --json                 Output results as JSON

rebrew cfg list-targets [--json]
rebrew cfg show [KEY] [--target TARGET] [--json]
rebrew cfg raw [--format json|toml]
rebrew cfg path
rebrew cfg add-target NAME --binary FILE [--arch ARCH] [--format FORMAT] [--modules LIST] [--source-ext EXT] [--copy/--no-copy] [--force]
rebrew cfg remove-target NAME [--force]
rebrew cfg set KEY VALUE [--dry-run]
rebrew cfg add-module MODULE [--target TARGET] [--dry-run]
rebrew cfg remove-module MODULE [--target TARGET] [--force]
rebrew cfg set-cflags MODULE FLAGS [--target TARGET] [--dry-run]
rebrew cfg set-compiler TARGET PROFILE
rebrew cfg detect-crt [--write] [--target TARGET] [--json]
```

All `cfg` write commands round-trip via `tomlkit` and preserve comments and
formatting.

## Success Metrics

- New user can produce a passing `rebrew doctor` exit code in under 5 minutes
  from a fresh checkout, given a valid binary + toolchain.
- Re-running `rebrew init` on an existing project is refused — it never destroys
  configuration.
- `rebrew cfg` round-trip preserves comments and section ordering across a
  `raw` → external edit → `set` cycle.
- Adding a new target is one `cfg add-target` call away (no manual TOML edit).
- AI agents using the `rebrew-intake` skill can complete onboarding entirely via
  `--json` commands.

## Open Questions / Known Limitations

- `init` always seeds the same `AGENTS.md` template from `src/rebrew/AGENTS.md.template`;
  it cannot be customised per-project at creation time.
- Toolchain acquisition is now docker-image based: `rebrew toolchain build
  <profile>` builds the profile's image from the sibling rebrew-toolchains
  checkout. The legacy `--install-wibo` host runner is a no-op for image-backed
  profiles (kept for old host-runner configs).
- FIXED: `doctor` now checks FLIRT signature availability (parses every
  `.pat`/`.sig` in `flirt_sigs/`); CRT source mirror discovery lives in
  `cfg detect-crt --write`.
- `cfg add-target` infers format/arch from the binary at the time of the call;
  if the binary is later replaced with a different arch, the stanza is stale
  (manual `cfg set targets.<name>.format/arch`, or `--force` for a binary that
  is not yet present).
- FIXED: per-target compiler overrides are first-class now — `cfg set-compiler
  TARGET PROFILE` (or `cfg set targets.<name>.compiler.profile`) overrides the
  shared `[compiler]` section per target.
