# ADR-026: One installed CLI for routine commands

- **Status**: Accepted
- **Date**: 2026-10

## Context

All routine tools already mount under `rebrew` through the component graph
(ADR 014), but packaging also installed 68 duplicate `rebrew-*` executables.
They cluttered PATH and created a second registration list to maintain.

## Decision

Install `rebrew` as the only user CLI. Add commands through components rather
than `[project.scripts]`. Remove duplicate executable names without aliases.

Retain four executable hooks for callers outside Rebrew:

- `rebrew-cmake-cl`, `rebrew-cmake-link`, and `rebrew-cmake-lib` accept compiler,
  linker, and archiver arguments from generated CMake toolchains. Their executable
  names select the driver mode.
- `rebrew-objdiff-build` is the executable in generated objdiff `custom_make`
  configurations; objdiff appends its target/object arguments.

Module-level `main_entry()` functions may remain for `python -m` execution
and focused development checks. They are not installed executables.

## Consequences

People use `rebrew <command>` and discover tools through `rebrew --help`.
Reinstalling or upgrading removes the old scripts from the environment.
Existing CMake and objdiff configurations retain working build hooks.
The packaging test pins the five allowed entry points, so adding a routine
command cannot silently add another executable.
