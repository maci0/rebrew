# ADR-021: Batch container compiles

- **Status**: Accepted
- **Date**: 2026-09

## Context

Every `compile_to_obj` pays a full `docker run` (measured 2.0s for one
mingw file, of which the compile itself is ms). A 20-function verify pays
~40s of container startups; batching all 20 into one invocation measured
2.95s — a 13× win. The per-function model made sense when compiles were
rare (single `rebrew test`); `verify --all` on real projects compiles
hundreds.

## Decision

- `precompile_batch(cfg, entries, ...)` / `compile_batch_objs(...)`:
  group by (toolchain image, cflags), one `docker run` per group with N
  source files, default-named outputs collected per file. Grouping ignores
  `/I`; each group compiles with the union of its members' include dirs.
- Only `posix`/`msvc` arg styles batch. dos/borland/watcom profiles, the
  recompile backend, context-merged units, and groups of one compile
  individually.
  GCC: `gcc -O2 -c a.c b.c ...` in one workdir (objects land in the
  workdir root); MSVC: `cl /c a.c b.c ...` (same). Per-file `/Fo`/`-o` is
  dropped — outputs are renamed from defaults after the run.
- Cache hits are filtered BEFORE grouping (their files never enter a
  batch); cache writes happen per file after collection, under the same
  key a single-file compile uses, and only for members whose own include
  set equals the group union (otherwise the bytes were built with a wider
  search path than that key describes).
- Single-file callers keep `compile_to_obj` unchanged. No caller migration
  required; `run_verification` calls `precompile_batch` first, and entries
  it did not build compile individually in `verify_entry`.
- A group failure (nonzero exit) keeps the objects the run did emit and
  falls back to per-file compiles for the rest, to attribute the error:
  batch output interleaves stderr, so the failing file is identified by
  re-running individually (rare path, correctness over speed).

## Consequences

- `verify --all` wall time becomes ~compiles/groups + cache hits instead
  of ~compiles. Mixed-cflags projects degrade gracefully (one invocation
  per distinct flag set — usually 1-3).
- Docker is still one-shot per group (no daemon); the recompile service
  remains the persistent alternative.
- MSVC `/Fo` per-file naming is lost inside a batch — outputs are matched
  by stem (`foo.c` → `foo.obj`) in the workdir root. Sources whose stem
  (case-insensitive) appears more than once in a group stay out of the
  batch and compile individually.
