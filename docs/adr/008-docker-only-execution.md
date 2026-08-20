# ADR-008: Docker-only toolchain execution (no host wine/dosbox)

## Status

Accepted

## Context

The toolchain abstraction (ADR-006) standardized invocation as
`docker run <image> <compiler> <args>` with a **host-path fallback**: when
docker or the image was unavailable, rebrew exec'd the vendored binary
directly — `wine CL.EXE` for MSVC, `wibo` as a lighter alternative, the
DOSBox sandbox for the 16-bit compilers, plus host-side Xvfb/xvfb-run
headless glue.  The fallback kept several legacy code paths alive:

- `compile_to_obj` had a separate direct-wine branch (`resolve_cl_command`
  + `msvc_env_from_config` + `maybe_headless_wine`) for the default MSVC
  profiles, distinct from the toolchain-runner branch — two ways to reach
  the same compiler, with per-function toolchain overrides patching the
  wine env (`vendored_msvc_env`) so Wine loaded the right C1.DLL/C2.DLL.
- The GA/flag-sweep path duplicated that glue (`matcher/compiler.py` raw
  subprocess + `vendored_compiler_command`).
- Every environment quirk leaked host-side: wine prefixes, Xvfb, wibo
  downloads, DOSBox configs, uppercase FAT files — none of which matter
  once the runtime lives in the image.

Now that the complete MSVC 1.0–10.0 matrix ships as sha256-pinned images
(ADR-007), the fallback buys nothing: the images encapsulate wine and
DOSBox and are byte-reproducible.  The host paths are dead weight and a
correctness hazard (two codegen paths must agree, and the env-patching
is fragile).

## Decision

Execution is **docker-only for every Windows/DOS toolchain**:

- `run_toolchain` invokes the image and nothing else for wine/dosbox
  runtime specs; a missing image is a hard `ToolchainError` telling the
  user to `rebrew toolchain build <name>`.  Native-Linux toolchains
  without an image (gcc-pe, watcom16 `wcc`) still exec their vendored/PATH
  binary directly — they are not Windows binaries, no wine involved.
- `compile_to_obj` routes every registered profile through the runner;
  the direct-wine branch is gone.  Project include dirs are
  **same-path bind-mounted** into the container (`-v <dir>:<dir>` at the
  absolute host path) so `/I` flags work unchanged AND relative
  `#include "../../x.h"` paths resolve exactly as on the host (the old
  host-wine path relied on wine's Z: whole-filesystem mapping; a
  container-root mount would let `../..` escape to `/`).  The toolchain's
  own include tree is not mounted (the image carries its byte-identical
  copy).
- The per-function toolchain override (metadata `TOOLCHAIN`) selects the
  override's image instead of patching a wine env.
- Removed host-side helpers: `vendored_msvc_env`,
  `vendored_compiler_command`; the wine env/Xvfb/wibo plumbing is no
  longer on the compile path (wine runs headless inside the image).
- `rebrew doctor` checks image presence for docker-backed profiles and
  skips the wine/wibo runner checks for them.

## Consequences

Positive:

- One execution path for every Windows/DOS compiler; codegen can never
  silently come from a different compiler than configured (the env
  patching hazard is gone).
- No host wine prefix / Xvfb / wibo setup; compiles are headless by
  construction.
- The compile-cache key uses the image tag, stable across machines.

Negative / accepted:

- Compilation requires docker and the image; a fresh clone must
  `rebrew toolchain build <name>` (or pull) before the first compile —
  `doctor` reports this with the exact command.
- Docker adds per-invocation overhead vs a warm host wine; amortized by
  the compile cache (cache hits skip the subprocess entirely).
- Include trees are bind-mounted at their host paths, so compiles see
  the project's full include structure (relative `../..` includes work);
  the smoke gate covers the toolchain's own includes.
- The vendored trees are still required as the image build source (and
  for `rebrew toolchain vendor` reproducibility), so disk usage is
  unchanged.
