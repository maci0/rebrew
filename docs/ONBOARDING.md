# Onboarding: your first rebrew project

The first-run companion to [Getting started](GETTING_STARTED.md): what
`init` and `intake` automate (including the init wizard), the health check,
the errors a new user can hit and what each one means, 16-bit targets, and
manual function discovery.  For the full command reference see [CLI.md](CLI.md); for toolchains
see [TOOLCHAIN.md](TOOLCHAIN.md).

## Prerequisites

Install rebrew and the host tools in
[Getting started: prerequisites](GETTING_STARTED.md#prerequisites).

## The 5-minute path

### 1. Initialize the project

```bash
rebrew init --target server --binary server.dll
```

Creates `rebrew-project.toml`, `original/`, `src/server/`, metadata files,
and prints the next steps.  If you have the binary handy, skip straight to
`rebrew intake`: it runs `init` for you. The examples use the binary stem
`server` as the target name, matching intake's default.

#### Interactive wizard

Bare `rebrew init` on a TTY runs an **onboarding wizard** (`--wizard` is the
default; `--no-wizard` or `--json` opts out).  It only asks about parameters
you did NOT pass on the command line: a fully flagged run
(`--target/--binary/--toolchain/--write-completions` all given) prompts
nothing.

1. **Binary**: scans `original/` first, then the current directory, for
   `*.exe`/`*.dll`/`*.sys`/`*.bin`/`*.com` and offers a numbered pick list
   (`m` lets you type a path/name manually).
2. **Detection → compiler profile**: the chosen binary is fingerprinted
   (format/arch + toolchain family) and the suggested profile becomes the
   default answer, visibly flagged (`detection suggests …`).  An unknown
   answer gets one reprompt, then falls back to the current value.
3. **Target name**: defaults to the binary stem (`mini_pe.exe` → `mini_pe`).
4. **Shell completions**: optional `completions/` scripts.
5. **Summary + confirm**: nothing is written before you answer "yes".
6. **Toolchain image**: after the project is written, the docker image
   state for the chosen profile is reported; a missing image prints the
   exact `rebrew toolchain build <profile>` command and offers to run it.

Piped/CI invocations (non-TTY stdin, `--json`) never prompt.

### 2. One-shot onboarding

```bash
rebrew intake original/server.dll          # auto-detects the compiler profile
rebrew intake original/server.dll --toolchain msvc-6.0   # or pin it explicitly
```

`intake` does the whole first pass automatically:

1. **detects the compiler profile** (diec → PDB → PE metadata → heuristics)
2. runs `rebrew init` (skipped if the project already exists; re-running
   intake is a safe re-discovery)
3. copies the binary to `original/`
4. **enumerates functions** via discoverer plugins → `src/server/function_structure.json`
5. **documents every function** as a STUB skeleton with a BLOCKER,
   so `rebrew status`/`rebrew todo` show the full reversing landscape

The summary names the detected profile, the function count and the next
command; [Getting started](GETTING_STARTED.md#2-onboard-it) shows a sample.

### 3. Health check

```bash
rebrew doctor            # green/red checklist with fixes for every failing item
rebrew doctor --json     # machine-readable
```

`doctor` validates the config, binary, toolchain (docker image or native
compiler), include/lib paths, function list, sources, metadata, and more.
Every `fail` line names its fix.  The common ones after a fresh intake:

- **`Compiler`/`Toolchain`/`Runner` fail**: the docker image isn't built:
  `rebrew toolchain build <profile>` or `rebrew toolchain pull <profile>`.
- **`Toolchain alignment` fail**: the detected compiler family doesn't match
  the configured profile: switch the profile (e.g. `rebrew cfg set
  compiler.profile msvc-6.0`) or document it as a blocker.
- **`Include path`/`Lib path`**: for docker-backed profiles these are
  provided *by the image* (it is built from the pinned source in the sibling
  `recompile-toolchains` checkout), so a dangling host path is informational,
  not a failure.  Every shipped profile is docker-backed; only a plugin
  toolchain registered without an image uses real host paths.

### 4. Status, library code, first match

Continue at [Getting started step 4](GETTING_STARTED.md#4-review-project-status):
`rebrew status` / `rebrew todo`, ruling out library code, then the
`test` / `diff` / `diagnose near` / `match` loop on the stubs intake wrote
(for example `src/server/fcn_00401000.c`). For statically linked MSVCRT,
`rebrew library crt-match --all --fix-source` also records the accepted CRT
source references in `rebrew-functions.toml`.

The agent skills in `.agents/skills/` (`rebrew-init`, `rebrew-intake`,
`rebrew-workflow`, `rebrew-matching`, `rebrew-data-analysis`,
`rebrew-ghidra-sync`) walk the same loop with step-by-step instructions for
AI agents.

## First-run errors and what they mean

| Error | Cause | Fix |
|-------|-------|-----|
| `binary not found: …` | typo'd path | pass the real path: `rebrew intake` copies it to `original/` |
| `no functions discovered` | no discoverer found functions (rizin missing, timed out, or couldn't analyze the binary) | `apt install rizin` or register another `rebrew.discoverers` plugin; re-run `rebrew intake` (the scaffold is kept) |
| `docker image rebrew/… not built` | image missing | `rebrew toolchain build <profile>` (or `rebrew toolchain pull <profile>`) |
| `Toolchain alignment` fail | detected family ≠ configured profile | `rebrew cfg set compiler.profile <detected>` |
| `Cannot extract DLL bytes` (verify) | binary changed since the annotation | re-run `rebrew intake` for re-discovery, or fix the stored/bound VA (the error names the VA when it is missing from the current function list) |
| `Failed to load: …` (doctor) | `format` doesn't match the binary | set `format = "pe"/"elf"/"macho"/"ne"` in `rebrew-project.toml` |
| `A rebrew-project.toml already exists` | `init` in an existing project | use `rebrew intake` instead: it re-runs init only when needed |

## 16-bit targets

For MZ (DOS) and NE (16-bit Windows) binaries `intake` sets `arch = "x86_16"`
automatically, and the profile must be one registered with `bits = 16` (for
example `msvc-1.52`, `msc-6.0`, `borland-3.1`, `watcom-2.0-win16`,
`delphi-1.0`, or a plugin that declares the same).  `rebrew verify` byte-compares only the
ones that emit a per-function object; `delphi-1.0` emits a linked NE and is
skipped.  `rebrew doctor` explains exactly which profile to configure.

## Manual discovery (without `intake`)

When onboarding by hand (or feeding a third-party tool's output), write
`src/<target>/function_structure.json` directly: `[{va, size, name}]` with
integer VAs:

```bash
# Ghidra: Auto-Analyze, export the function list, save as above.
# rizin headless (the packaged discoverer's executable):
rizin -q -c 'aaa; aflj' original/mygame.exe \
  | jq '[.[] | {va: .offset, size: .size, name: .name}]' \
  > src/mygame/function_structure.json
```

Then continue at step 3 (`rebrew doctor`).

## Next

- [CLI.md](CLI.md): every command
- [TOOLCHAIN.md](TOOLCHAIN.md): compilers, images, per-library overrides
- [ANNOTATIONS.md](ANNOTATIONS.md): function/data metadata, optional ADDRESS anchors, and lint diagnostics
- [CONFIG.md](CONFIG.md): `rebrew-project.toml` reference
- [ARCHITECTURE.md](ARCHITECTURE.md): how the pieces fit together
