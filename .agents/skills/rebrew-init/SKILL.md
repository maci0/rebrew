---
name: rebrew-init
description: >-
  Set up a new Rebrew project with rebrew init (scaffold, first setup, new
  project): choose target names and compiler profiles, and check scaffold
  drift. Trigger: "scaffold a new project", "new rebrew project", "rebrew
  init". Use rebrew-intake for one-shot binary onboarding and rebrew-workflow
  for an existing target.
license: MIT
---

# Rebrew Init

Scaffold a project and select its target and compiler profile. Use
`rebrew-intake` for automatic discovery and initial triage.

## Scaffold

Run from the project root directory:

```bash
mkdir -p original && cp <path-to-binary> original/
rebrew init --target <name> --binary <filename> --guess-compiler --no-wizard
```

Choose a bare binary stem as an explicit target (`server.dll` → `server`). A name becomes a path component, so no separators. Noninteractive `init` defaults to `main`; pass `--target`. The wizard suggests a normalized lowercase ASCII stem when possible; `intake` keeps the binary stem unchanged (`My-Game.dll` → `My-Game`). Use `--target` to match an existing configured target key. Paths are `layout/bench/`, `src/bench/`.

Starting from a splat YAML instead of a bare binary:
`rebrew source import-splat <config>` plans names, layout, and dedicated metadata, and writes
nothing until `--apply` (`--force` replaces conflicting metadata entries).

## Profile selection

`--guess-compiler` detects from the binary using DIE, PDB, PE metadata, and other
heuristics. Override with `--toolchain <profile>` when:

- The binary is a rebuild or repack whose headers lie (guess follows the
  headers, not the codegen).
- You already know the exact toolchain (matching SP-level profile matters:
  `msvc-6.0-sp6` vs `msvc-6.0` selects different compiler binaries, CRTs
  and headers, even where measured codegen is identical).
- 16-bit DOS/NE binaries where the heuristic picks the wrong family: use
  `watcom-2.0-win16` for Open Watcom 2.0 wcc, `msvc-1.52` for MSVC 1.52
  (16-bit DOSBox), `borland-3.1` for Turbo C++ 3.1. List shipped profiles
  with `rebrew toolchain list`.

```bash
rebrew init --target <name> --binary <filename> --toolchain <profile> --no-wizard
```

## Done-gate

```bash
rebrew doctor
```

Run it after scaffolding and address required failures relevant to the task.
Optional FLIRT, Ghidra, and BinSync warnings can be left for later. For a
missing compiler image, pull the profile or build it from the
recompile-toolchains checkout.

## Scaffold drift check

`rebrew init` renders AGENTS.md, PRINCIPLES.md, and `.agents/skills/` with any
`REBREW_SKILLS_DIR` overlay. `rebrew init --check` reports scaffold drift and
exits 1 when it finds differences. `rebrew init --refresh-agents` renders for
the configured default target and its compiler override. Keep local rules
below the project-rules marker in AGENTS.md.

## Global organization

Organize game and CRT extern declarations separately, with one canonical header
per subsystem and one CRT header. Headers do not allocate storage; definitions
belong to one source owner or linked stock library member. A section range is not
subsystem ownership. Preserve an existing curated split when refreshing scaffolds
or generating headers; use `rebrew-data-analysis` for consolidation.

## Handoff

Report the target name and profile. For discovery and initial triage, use
`rebrew-intake`.

Target namespaces use `[targets.<name>].module`. Source comments can anchor
addresses. Function and data kinds and state belong in metadata.
