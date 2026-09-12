# ADR-013: Byte-level library detection against linked archives

- **Status**: Accepted
- **Date**: 2026-09

## Context

Reversed sources can contain functions that are really statically linked
library code (CRT, zlib, runtime). The linker supplies those bytes anyway, so
reversing them is wasted effort, yet the work gets committed, counted as
coverage, and "improved" for weeks before anyone notices. One MSVC6 project
carried all 68 of its reversed CRT functions this way.

The existing detectors do not settle the question:

- **`rebrew flirt`** matches short byte signatures against prebuilt `.pat`
  files. A signature set built from a different library build misses real
  matches, and short patterns cannot cover every function. Measured on that
  project: FLIRT identified 9 of the 68 CRT functions present; even after
  regenerating signatures from the exact `LIBCMT.LIB` it still found 9 of 68.
- **`rebrew crt-match`** compares against reference *source*, which exists
  only for the CRT/zlib families.
- **Name-based** checks are useless: a decompiler names library code
  `fcn_XXXX` like anything else.

What would have caught all 68 is a different comparison: take the whole
function body from the target and compare it, byte for byte, against the
library archive the project actually links. A `.lib`/`.a` member's code has
its relocation slots zero-filled, so "identical outside those slots" is
exactly what a linked-in object looks like.

## Decision

Add `rebrew lib-match`, a command that:

- takes one or more `--lib PATH` archives (`.lib`/`.a`),
- can instead (or additionally) take `--stock-lib NAME`, a stock archive the
  project toolchain ships. It is extracted from the profile's image into
  `.scratch/` on first use, and the cached copy is refused when its md5
  differs from the image's, so a hand-edited archive (objects stripped to
  make a link succeed) cannot quietly redefine what "library code" means.
  Both the image tag and the in-image `Lib` path come from the toolchain
  registry, so a service pack that moves its tree cannot leave the check
  pointing at a directory that does not exist,
- can index objects the build produces from a source-vendored subtree: a
  library vendored as source (built from a `references/` tree) never ships a
  `.LIB`, so its objects are read from the build database
  (`build/compile_commands.json`, `--compile-commands`) rather than a glob,
  which would also pick up stale objects,
- indexes every code symbol in them, **including COFF storage-class-3
  (static) symbols** — MSVC marks CRT helpers such as `_initterm` and
  `_parse_cmdline` static, so an external-symbol-only index reports them
  absent from the library, which is the wrong answer to "should I reverse
  this?",
- compares each reversed function's bytes (from the target binary) against
  every indexed body, treating the body's recorded relocation offsets as
  don't-care,
- requires each candidate to be at least half fixed bytes, so a body that is
  mostly relocation slots (a pointer table such as `__sys_errlist`) cannot
  trivially "match" anything,
- supports `--va` for a single-function verdict (for use before starting
  work), `--allow FILE` for VAs known to be library code but kept for link
  reasons, and `--json`. Exit status 0 = clean, 1 = a reversed function
  matches a library, 2 = config/library error, so it works as a pre-commit or
  CI gate.

The archive parsing reuses `gen_flirt_pat.parse_archive` /
`parse_coff_obj`; no third parser is introduced. Libraries are named
explicitly (`--lib`, `--stock-lib`, or the build database); there is no
implicit library auto-discovery.

## Consequences

- Reversed-library-code detection no longer depends on signature coverage or
  reference-source availability: if the archive is given, a matching function
  is found.
- `flirt` and `crt-match` remain useful for *naming* matches and
  `// SOURCE:` annotation; `lib-match` is the byte-level arbiter when a miss
  leaves the question open.
- The archive index cost is per-`.lib` load, amortised across all VAs in a
  scan; single-`--va` checks pay the same one-time index.
- `--lib`/`--stock-lib` are optional but at least one input is required: the
  command cannot guess which archives a project links, and it must not run
  silently with nothing to compare against.
- The toolchain image is the source of truth for a stock archive and for the
  `Lib` path that holds it; both derive from the registry rather than a
  hardcoded path, which is the failure this replaced.
- The static-symbol requirement is load-bearing: an index built only from the
  archive symbol index silently misses MSVC's static CRT helpers, which is
  the exact failure this command exists to prevent.
