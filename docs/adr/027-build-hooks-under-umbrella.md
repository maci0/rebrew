# ADR-027: Build hooks under the umbrella CLI

- **Status**: Amended by 028
- **Date**: 2026-10

## Context

ADR 026 retained four CMake/objdiff executables beside `rebrew`. Both callers
can supply subcommand arguments, so these executables and their PATH links
are unnecessary.

## Decision

Install only `rebrew`. Register `cmake-driver` and `objdiff-build` through the
same component graph as other commands. Remove the old executable hooks and
their entry functions without aliases.

CMake selects `rebrew cmake-driver <cl|link|lib> -- <arguments>`. The compiler
uses `CMAKE_C_COMPILER_ARG1`; a companion rule override adds the linker and
archiver subcommands after CMake initializes its MSVC rules. All three tools
use one resolved executable path. `REBREW_CMAKE_AR_COMMAND` supplies an
argument list for custom archive commands.

Objdiff uses `custom_make: rebrew` and `custom_args: [objdiff-build, <target>]`,
then appends the base object path as before.

## Consequences

Reinstalling Rebrew removes all separate hook executables. Existing projects
must regenerate their CMake toolchain and objdiff configuration, reconfigure
their build directory, and update custom archive commands. Keep the generated
rule override beside its toolchain file. The `--` delimiter protects compiler
arguments from Rebrew's global options. The packaging gate permits one script,
and integration tests exercise compile, link, and archive command generation.
