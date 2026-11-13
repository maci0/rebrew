# Getting started: reversing your first binary with rebrew

This guide is for humans. It assumes you can read C and have poked at a
disassembler before, but have never used rebrew. You will scaffold a binary, inspect its work queue, and follow the loop toward
your first byte match. Matching time depends on the function and toolchain.

**What rebrew is, in one paragraph:** you write C; rebrew compiles it with
the *same compiler that built the original binary* (running inside a docker
image) and diffs your bytes against the target, byte for byte. A function is
done when your compiled output is identical to the original. Everything else
(the GA engine, flag sweeps, FLIRT scans, Ghidra sync) exists to close the
gap between "close" and "identical".

## The mental model (read this first)

Three ideas carry the whole tool:

1. **Status is earned, never claimed.** Every function has a STATUS
   (`STUB` → `NEAR_MATCHING` → `EXACT`/`RELOC`). You never set it by hand:
   `rebrew test` / `rebrew verify` compute it from a real byte comparison
   and write it for you. If you hand-edit a STATUS, the next verify demotes
   it back (a `verify --dry-run` shows the `would update STATUS → ...` line).
   Trust the ladder: it tells you exactly how done each function is.
2. **The compiler is the ground truth.** You are not writing "equivalent" C.
   You are writing the C that makes *that specific compiler version, with
   those specific flags,* emit *those exact bytes*. This is why rebrew runs
   each compiler version in its own docker image, and why `rebrew match flags` exists: half of matching is finding the flags.
3. **Pick a scoped action.** `rebrew todo` ranks unfinished work by affected
   byte extent, then estimated effort. Setup comes first. Choose an action
   you can complete; a small leaf function can still teach you the
   compiler's habits. See [queue ordering](CLI.md#rebrew-todo).

## Prerequisites

| You need | Why | Get it with |
|----------|-----|-------------|
| Linux x86_64 | all compiler images target it | n/a |
| Python 3.15+ and `uv` | runs rebrew | [uv installer](https://docs.astral.sh/uv/getting-started/installation/); `uv python install 3.15` |
| Rust (cargo + rustc) | installing rebrew builds the `python-flirt` binding from source; managed deployments can use the published native wheel instead ([README Development](../README.md#development)) | [rustup](https://rustup.rs) or your distro |
| Docker (default) or Podman | **every** shipped compiler runs inside an image: Windows tools use wine, 16-bit tools may use DOSBox, Linux toolchains run natively there. A host wine or wibo install is no fallback. Experimental unshare is a third backend; see [compile backends](TOOLCHAIN.md#compile-backends) | your distro's container runtime |
| rizin | the packaged function discoverer (`rebrew.discoverers`; capstone sweep / eh_frame / pdata are fallbacks, and other discoverers plug in without host edits) | `apt install rizin` / [rizin.re](https://rizin.re) |
| `diec` (optional) | stronger compiler detection in `rebrew doctor`/`intake` | Detect It Easy 4.0: `diec` on `PATH` (Arch: `detect-it-easy-bin`), or, in a rebrew source checkout, unpack [release 4.0.0](https://github.com/horsicq/DIE-engine/releases/tag/4.0.0) so `tools/diec/diec` and `tools/diec/lib/` exist (gitignored, not shipped) |
| ReconDB (optional) | signature sets for `rebrew library init-signatures --matched-only`, which copies the matching subset into the project's `flirt_sigs/`; `rebrew library scan-signatures` reads that project directory plus the ReconDB checkout when present. A rebrew source checkout finds a sibling `../recondb` (next to rebrew, not next to the project); a wheel install has no checkout, so set `REBREW_FLIRT_SIGS_DIR`. A relative value resolves against the working directory, so an absolute path is safest; a value that is not a directory fails `rebrew library scan-signatures` outright | `git clone https://github.com/relumea/recondb` next to your rebrew checkout, or anywhere plus `export REBREW_FLIRT_SIGS_DIR=/abs/path/to/recondb` |
| A binary | the thing you are reversing | yours |

Install rebrew itself:

```bash
uv tool install 'rebrew[prove] @ git+https://github.com/maci0/rebrew.git'
```

The `[prove]` extra is what installs angr; without it `rebrew prove` exits
with that install hint. Drop the extra if you never want symbolic proof.
In a rebrew checkout, use `make setup` instead (see
[CONTRIBUTING.md](../CONTRIBUTING.md#bootstrap-clean-clone)).

## Walkthrough

We will use a tiny demo binary. Substitute your own game `.exe`/`.dll`
whenever you are ready: the steps are identical.

### 1. Create a project directory and copy in the binary

```bash
mkdir ~/dedemo && cd ~/dedemo
cp /path/to/your-game.exe ./game.exe
```

(`rebrew intake` copies it into `original/` itself. Re-running `intake` on
the copy it already made skips the copy and re-runs discovery in place; it
does not demote functions you have already worked on, so a re-discovered
binary is safe to pass again.)

### 2. Onboard it

```bash
rebrew intake ./game.exe
```

This one command: detects the compiler (MSVC 8.0, say), scaffolds the
project, copies the binary, enumerates functions, and writes a STUB
skeleton plus a BLOCKER for each one. You will see something like:

```
Intake complete: game (msvc-8.0)
  detected family: msvc (MSVC 8.0)
  functions: 259, documented: 259
  toolchain: msvc-8.0 runs through docker image rebrew/msvc:8.0-win32 — run 'rebrew toolchain build msvc-8.0' if the image is missing
  next: rebrew doctor && rebrew status --json
  first run? see the rebrew repo's docs/ONBOARDING.md for the walkthrough
```

Two things to notice: the **detected profile** (`msvc-8.0`), that is the
compiler you must match against, and the **function count**. Every one of
those 259 is now a STUB waiting for you.

### 3. Check the project's health

```bash
rebrew doctor
```

A checklist with a fix for every red line. On a fresh intake the usual red
is **Toolchain**: the docker image isn't built yet. Fix it as instructed:

```bash
rebrew toolchain pull msvc-8.0    # prebuilt image
rebrew toolchain build msvc-8.0   # or build it from the recompile-toolchains checkout
```

(`build` needs the sibling **recompile-toolchains** checkout, or
`REBREW_TOOLCHAINS_DIR` pointing at it; `pull` is the download. Either way it
can take a few minutes. Reuse the image while the selected toolchain and image remain unchanged.) Re-run `rebrew doctor` until the board is green: a red
`Toolchain alignment` means the detected compiler and the configured
profile disagree, and everything downstream will silently compare against
the wrong codegen.

### 4. Review project status

```bash
rebrew status        # file agreement, accounted .text, stored data verdicts, and counts
rebrew todo          # what to do next, ranked by affected extent
```

These status percentages have different denominators;
[CLI accounting](CLI.md#rebrew-status) explains their byte buckets and library
contributions. Stored data verdicts are not a fresh build comparison.

`todo` is your work queue for the entire project. Its first unfinished
items affect the most bytes. For a first match, choose a small leaf function
whose disassembly you understand.

### 5. Rule out library code first

Before writing a line of C, check whether your function was even written by
the game authors. Statically linked CRT looks exactly like game code:

```bash
rebrew library init-signatures --matched-only   # fetch the signature set matching your CRT linkage
rebrew library scan-signatures                  # identify library functions
```

`rebrew library scan-signatures` only reports matches; it writes nothing. To actually annotate them
and drop them from your queue, run `rebrew library identify` (or settle them
by byte comparison against the archives you link with `rebrew library match
--lib <archive>`).

### 6. Match your first function

Pick a small item from `rebrew todo --json` and open the source file it identifies.
`intake` already documented its discovered functions, so edit that existing stub.
For an inventory function without source, generate a skeleton:

```bash
rebrew skeleton 0x00401000          # only if this VA has no source yet
```

Use the path the tool reports (for example `src/<target>/fcn_00401000.c`). The file is pure C: a best-guess signature and an empty body. The VA lives on the `MODULE.0xVA` row in `rebrew-functions.toml`. Now write the obvious implementation: the disassembly is a click
away:

```bash
rebrew binary asm show 0x00401000 # disassembly of the target
```

Then compile-and-compare:

```bash
rebrew test src/<target>/fcn_00401000.c
```

You will get one of three answers:

- **EXACT**: bytes identical. Done. Move to the next function.
- **NEAR_MATCHING (85%)**: close. Ask why:
  ```bash
  rebrew diff src/<target>/fcn_00401000.c        # side-by-side disassembly
  rebrew diagnose near src/<target>/fcn_00401000.c   # classifies the delta
  ```
  `rebrew diagnose near` tells you the *kind* of gap (register allocation, an
  equivalent instruction the compiler prefers, a flag variant) and
  suggests GA mutations. Fix the C, `rebrew test` again. This edit→test
  cycle is the core loop; each round takes seconds.
- **STUB / low %**: the control flow diverges. Read the disassembly more
  carefully; the skeleton's guess at the structure was wrong.

When the gap is a flag, not your code:

```bash
rebrew match flags src/<target>/fcn_00401000.c # try compiler flags
```

And when you are stuck on the last few bytes:

```bash
rebrew match run src/<target>/fcn_00401000.c # GA engine searches C variants
```

### 7. Verify the whole project

```bash
rebrew verify            # bulk: every function, STATUS auto-updated
rebrew verify --compare  # CI mode: fail on regressions vs the saved baseline
```

`verify --no-cache` rechecks every selected function, ignoring saved verdicts;
compiler objects may still be reused. Plain `verify` already covers every
function and rechecks only the ones whose inputs changed.

## The core loop (your daily driver)

```
rebrew todo → rebrew skeleton → edit C → rebrew test → rebrew diff → …
                                              ↑_______________|
```

- `todo` picks the function. `skeleton` scaffolds it. You write C.
- `test` grades it in seconds. `diff`/`diagnose near` explain the gap.
- `match run` searches C variants; `match flags` searches compiler flags.
- `verify` banks progress across the whole project.
- `status` shows the ladder filling up: `STUB → NEAR_MATCHING → EXACT`.

## Statuses, decoded

| You see | It means | You do |
|---------|----------|--------|
| `STUB` | skeleton, never implemented | write the function |
| `NEAR_MATCHING (85%)` | close: registers, scheduling, or flags | `diff`, `diagnose near`, tweak, re-`test` |
| `STUB` (under 60%) | structure diverges | re-read the disassembly |
| `EXACT` | byte-identical | next function |
| `RELOC` | identical except linker-filled addresses | next function (as done as EXACT) |
| `SIZE_MISMATCH` | compiles but wrong length | extra/missing code: compare sizes first |
| `COMPILE_ERROR` | doesn't compile | read the compiler output, fix C |
| `PROVEN` | semantically equal within the modeled proof, bytes differ (angr/Z3) | retain the proof as evidence; continue byte matching for EXACT/RELOC |

## When you are stuck

| Symptom | Likely cause | Command |
|---------|--------------|---------|
| Everything is `COMPILE_ERROR` | wrong toolchain image / profile | `rebrew doctor`, check Toolchain rows |
| Right logic, ~90%, won't close | wrong flags | `rebrew match flags <file>` |
| Right logic, small delta, won't close | compiler idiom (register pick, equivalent encoding) | `rebrew diagnose near`, then `rebrew match run` (GA) |
| Right logic, qualifier-shaped delta | declaration qualifiers perturb allocation | `rebrew match qualifiers` |
| Right logic, statement-order delta | adjacent statements swapped | `rebrew match climb` |
| Gap grows along the function | length drift (short COMDAT, early table) | `rebrew diagnose gap` |
| Function looks like gibberish | it's library code | `rebrew library scan-signatures`, `rebrew library crt-match --all` |
| `verify` disagrees with your edit | stale STATUS claim | let `verify` rewrite it; `verify --dry-run` shows the pending transition |
| BSS/layout bytes differ, code matches | data placement, not code | `rebrew data list`, `rebrew build check-data-placement` |

## What's next

- [ONBOARDING.md](ONBOARDING.md): the same path with every error message
  catalogued (when something breaks, look here first)
- [WORKFLOW.md](WORKFLOW.md): the full reversing loop in depth
- [CLI.md](CLI.md): every command with flags
- [TOOLCHAIN.md](TOOLCHAIN.md): compilers, images, per-library overrides
- [MATCH_TYPES.md](MATCH_TYPES.md): what each STATUS really proves
- `.agents/skills/` in your project: the same loop as step-by-step
  instructions, if you drive rebrew through an AI agent
