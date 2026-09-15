# 021 — Batch container compiles

## Status

Accepted

## Context

Every `compile_to_obj` pays a full `docker run` (measured 2.0s for one
mingw file, of which the compile itself is ms). A 20-function verify pays
~40s of container startups; batching all 20 into one invocation measured
2.95s — a 13× win. The per-function model made sense when compiles were
rare (single `rebrew test`); `verify --all` on real projects compiles
hundreds.

## Decision

- `compile_batch(cfg, [(source, cflags, toolchain, workdir)], ...)`:
  group by (toolchain image, cflags, include set), one `docker run` per
  group with N source files, default-named outputs collected per file.
  GCC: `gcc -O2 -c a.c b.c ...` in one workdir (objects land beside
  sources); MSVC: `cl /c a.c b.c ...` (same). Per-file `/Fo`/`-o` is
  dropped — outputs are renamed from defaults after the run.
- Cache hits are filtered BEFORE grouping (their files never enter a
  batch); cache writes happen per file after collection, same keys.
- Single-file callers keep `compile_to_obj` (thin wrapper over a 1-group
  batch). No caller migration required; `run_verification` switches to
  the batch entry when >1 file shares a group.
- A group failure (nonzero exit) falls back to per-file compiles to
  attribute the error — batch output interleaves stderr, so the failing
  file is identified by re-running individually (rare path, correctness
  over speed).

## Consequences

- `verify --all` wall time becomes ~compiles/groups + cache hits instead
  of ~compiles. Mixed-cflags projects degrade gracefully (one invocation
  per distinct flag set — usually 1-3).
- Docker is still one-shot per group (no daemon); the recompile service
  remains the persistent alternative.
- MSVC `/Fo` per-file naming is lost inside a batch — outputs are matched
  by stem (`foo.c` → `foo.obj`), so duplicate stems across directories
  must be disambiguated by copying into per-file subdirs (same as today).
