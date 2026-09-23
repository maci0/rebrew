# Getting started — reversing your first binary with rebrew

This guide is for humans. It assumes you can read C and have poked at a
disassembler before, but have never used rebrew. In ~15 minutes you will go
from a bare binary to your first byte-matched function, and understand the
loop you will repeat for the other 542.

**What rebrew is, in one paragraph:** you write C; rebrew compiles it with
the *same compiler that built the original binary* (running inside a docker
image) and diffs your bytes against the target, byte for byte. A function is
done when your compiled output is identical to the original. Everything else
— the GA engine, flag sweeps, FLIRT scans, Ghidra sync — exists to close the
gap between "close" and "identical".

## The mental model (read this first)

Three ideas carry the whole tool:

1. **Status is earned, never claimed.** Every function has a STATUS
   (`STUB` → `NEAR_MATCHING` → `EXACT`/`RELOC`). You never set it by hand —
   `rebrew test` / `rebrew verify` compute it from a real byte comparison
   and write it for you. If you hand-edit a STATUS, the next verify demotes
   it back with a `metadata:` warning. Trust the ladder: it tells you
   exactly how done each function is.
2. **The compiler is the ground truth.** You are not writing "equivalent" C.
   You are writing the C that makes *that specific compiler version, with
   those specific flags,* emit *those exact bytes*. This is why rebrew runs
   20+ compiler versions in docker images, and why `rebrew match
   --flag-sweep` exists: half of matching is finding the flags.
3. **Work smallest-first.** `rebrew todo` ranks functions by return on
   investment — tiny leaf functions first. A 20-byte function you match in
   ten minutes teaches you the compiler's habits; those habits compound
   across the whole binary.

## Prerequisites

| You need | Why | Get it with |
|----------|-----|-------------|
| Linux x86_64 | all compiler images target it | — |
| Python 3.13+ and `uv` | runs rebrew | [uv installer](https://docs.astral.sh/uv/getting-started/installation/); `uv python install 3.13` |
| docker | **every** compiler runs inside an image (wine/DOSBox live there; there is no host-wine path) | your distro's `docker` |
| rizin | the packaged function discoverer | `apt install rizin` |
| A binary | the thing you are reversing | yours |

Install rebrew itself:

```bash
uv tool install git+https://github.com/maci0/rebrew.git
```

## The 15-minute walkthrough

We will use a tiny demo binary. Substitute your own game `.exe`/`.dll`
whenever you are ready — the steps are identical.

### 1. Put the binary somewhere *outside* your project dir

```bash
mkdir ~/dedemo && cd ~/dedemo
cp /path/to/your-game.exe ./game.exe
```

(`rebrew intake` copies it into `original/` itself. Pointing it at a file
already inside `original/` errors out — a common first-run stumble.)

### 2. Onboard it

```bash
rebrew intake ./game.exe
```

This one command: detects the compiler (MSVC 8.0, say), scaffolds the
project, copies the binary, enumerates functions, and writes a `// STUB:`
skeleton for each one. You will see something like:

```
Intake complete: game (msvc-8.0)
  detected family: msvc (MSVC 8.0 (cl 14.00))
  functions: 259, documented: 259
  next: rebrew doctor && rebrew status --json
```

Two things to notice: the **detected profile** (`msvc-8.0`) — that is the
compiler you must match against — and the **function count**. Every one of
those 259 is now a STUB waiting for you.

### 3. Check the project's health

```bash
rebrew doctor
```

A checklist with a fix for every red line. On a fresh intake the usual red
is **Toolchain**: the docker image isn't built yet. Fix it as instructed:

```bash
rebrew toolchain build msvc-8.0
```

(This downloads/pins the exact compiler. It takes a few minutes once, then
never again.) Re-run `rebrew doctor` until the board is green — a red
`Toolchain alignment` means the detected compiler and the configured
profile disagree, and everything downstream will silently compare against
the wrong codegen.

### 4. See the landscape

```bash
rebrew status        # where you stand: counts per STATUS, per module
rebrew todo          # what to do next, ranked by ROI
```

`todo` is your work queue for the entire project. Start at the top: the
smallest, easiest functions. Do not start with the 2,685-byte monster —
start with the 40-byte leaf.

### 5. Rule out library code first

Before writing a line of C, check whether your function was even written by
the game authors. Statically linked CRT looks exactly like game code:

```bash
rebrew flirt --init-matched   # fetch the signature set matching your CRT linkage
rebrew flirt                  # identify library functions
```

Functions flagged as library (MSVCRT, zlib, …) get annotated as such and
leave your queue. On a typical game binary this removes a third of the
work before you start.

### 6. Match your first function

Pick the top item from `rebrew todo`. Say it is at `0x00401000`:

```bash
rebrew skeleton 0x00401000          # generate a stub with the right prototype
```

Open the generated `src/<target>/fcn_00401000.c`. It has a `// FUNCTION:`
marker (the VA — do not touch it), a best-guess signature, and an empty
body. Now write the obvious implementation — the disassembly is a click
away:

```bash
rebrew asm 0x00401000                # disassembly of the target
```

Then compile-and-compare:

```bash
rebrew test src/<target>/fcn_00401000.c
```

You will get one of three answers:

- **EXACT** — bytes identical. Done. Move to the next function. (This
  happens more often than you expect on small functions.)
- **NEAR_MATCHING (85%)** — close. Ask why:
  ```bash
  rebrew diff src/<target>/fcn_00401000.c        # side-by-side disassembly
  rebrew near-diag src/<target>/fcn_00401000.c   # classifies the delta
  ```
  `near-diag` tells you the *kind* of gap — register allocation, an
  equivalent instruction the compiler prefers, a flag variant — and
  suggests GA mutations. Fix the C, `rebrew test` again. This edit→test
  cycle is the core loop; each round takes seconds.
- **STUB / low %** — the control flow diverges. Read the disassembly more
  carefully; the skeleton's guess at the structure was wrong.

When the gap is a flag, not your code:

```bash
rebrew match src/<target>/fcn_00401000.c --flag-sweep-only   # try compiler flags
```

And when you are stuck on the last few bytes:

```bash
rebrew match src/<target>/fcn_00401000.c   # GA engine searches C variants
```

### 7. Verify the whole project

```bash
rebrew verify            # bulk: every function, STATUS auto-updated
rebrew verify --compare  # CI mode: fail on regressions vs last report
```

`verify --full` forces everything (cold: ~17s on 283 functions; warm:
~2s). Plain `verify` is incremental — only changed functions recompile.

## The core loop (your daily driver)

```
rebrew todo → rebrew skeleton → edit C → rebrew test → rebrew diff → …
                                              ↑_______________|
```

- `todo` picks the function. `skeleton` scaffolds it. You write C.
- `test` grades it in seconds. `diff`/`near-diag` explain the gap.
- `match`/`match --flag-sweep-only` close gaps you can't see.
- `verify` banks progress across the whole project.
- `status` shows the ladder filling up: `STUB → NEAR_MATCHING → EXACT`.

## Statuses, decoded

| You see | It means | You do |
|---------|----------|--------|
| `STUB` | skeleton, never implemented | write the function |
| `NEAR_MATCHING (85%)` | close — registers, scheduling, or flags | `diff`, `near-diag`, tweak, re-`test` |
| `NEAR_MATCHING (30%)` | structure diverges | re-read the disassembly |
| `EXACT` | byte-identical | next function |
| `RELOC` | identical except linker-filled addresses | next function (as done as EXACT) |
| `SIZE_MISMATCH` | compiles but wrong length | extra/missing code — compare sizes first |
| `COMPILE_ERROR` | doesn't compile | read the compiler output, fix C |
| `PROVEN` | semantically equal, bytes differ (angr/Z3) | accept via `rebrew prove`, move on |

## When you are stuck

| Symptom | Likely cause | Command |
|---------|--------------|---------|
| Everything is `COMPILE_ERROR` | wrong toolchain image / profile | `rebrew doctor`, check Toolchain rows |
| Right logic, ~90%, won't close | wrong flags | `rebrew match <file> --flag-sweep-only` |
| Right logic, small delta, won't close | compiler idiom (register pick, equivalent encoding) | `rebrew near-diag`, then `rebrew match` (GA) |
| Right logic, qualifier-shaped delta | declaration qualifiers perturb allocation | `rebrew qual-sweep` |
| Right logic, statement-order delta | adjacent statements swapped | `rebrew climb` |
| Gap grows along the function | length drift (short COMDAT, early table) | `rebrew gap-trace` |
| Function looks like gibberish | it's library code | `rebrew flirt`, `rebrew crt-match --all` |
| `verify` disagrees with your edit | stale STATUS claim | let `verify` rewrite it; read the `metadata:` warning |
| BSS/layout bytes differ, code matches | data placement, not code | `rebrew data`, `rebrew verify-placement` |

## What's next

- [ONBOARDING.md](ONBOARDING.md) — the same path with every error message
  catalogued (when something breaks, look here first)
- [WORKFLOW.md](WORKFLOW.md) — the full reversing loop in depth
- [CLI.md](CLI.md) — every command with flags
- [TOOLCHAIN.md](TOOLCHAIN.md) — compilers, images, per-library overrides
- [MATCH_TYPES.md](MATCH_TYPES.md) — what each STATUS really proves
- `.agents/skills/` in your project — the same loop as step-by-step
  instructions, if you drive rebrew through an AI agent
