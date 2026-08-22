# ADR-011: Toolchain build source moves to the sibling rebrew-toolchains checkout

## Status

Accepted

## Date

2026-08

## Context

ADR-006 established in-repo `toolchain/<family>/<version>-<arch>/Dockerfile`
as the canonical build specs, with the 16-bit media tarballs and vendored
host trees committed next to them.  Three problems grew out of that:

1. **Repo weight and history**: the toolchain trees (MSVC 1.0–10.0,
   Borland, Watcom, Turbo C) and the 16-bit media tarballs are megabytes of
   binary content pinned inside rebrew's git history, where every future
   refactor pays for it.
2. **Blurred ownership**: the build files are consumed by `rebrew
   toolchain build`/`vendor`/`update`, but editing them means touching the
   rebrew repo — a contributor fixing a Dockerfile must wait on rebrew's
   review/release cycle, and rebrew CI cannot independently verify toolchain
   builds without coupling the two repos' histories.
3. **Distribution licensing**: shipping proprietary compiler media inside
   the rebrew git repo mixes the MIT codebase with redistribution-sensitive
   media; keeping them in a separate, separately-licensed checkout keeps the
   boundary explicit.

## Decision

The docker-image build source (Dockerfiles, wrapper scripts, the shared
`base/`, the 16-bit media tarballs) and the vendored host trees
(`<family>/<version>-<arch>/source`, assembled by `rebrew toolchain
vendor`) live in the standalone **rebrew-toolchains** checkout —
`github.com/maci0/rebrew-toolchains`, expected as a sibling directory,
overridable via `REBREW_TOOLCHAINS_DIR`.

- `rebrew.toolchain._toolchains_repo()` resolves the checkout; a missing
  checkout is a hard, actionable `ToolchainError` telling the user to clone
  it or set `REBREW_TOOLCHAINS_DIR` (`_require_toolchains_repo`, called
  only by commands that consume the build source — `toolchain
  build`/`vendor`/`update`).  Plain registry/status commands never touch
  the checkout.
- The rebrew repo keeps the `ToolchainSpec` registry, the docker/native
  runner, the byte-reproducibility smoke gate, and the tests that pin the
  external layout (every image-backed spec must have a **git-tracked**
  Dockerfile at `<family>/<ver>-<arch>/Dockerfile` in the checkout — the
  untracked-Dockerfile guard from ADR-007 — plus the Dockerfile-sanity
  checks).
- Byte-reproducibility invariants from ADR-007 are unchanged: images and
  vendored host trees are built from the same pinned, sha256-verified
  source; the smoke gate hashes them identically.

## Consequences

- **Positive**: rebrew's history stops carrying compiler trees and media;
  the toolchains checkout can version, review, and license itself
  independently; a Dockerfile fix no longer needs a rebrew PR.
- **Negative**: a fresh clone of rebrew alone cannot build images or vendor
  trees — the sibling checkout (or `REBREW_TOOLCHAINS_DIR`) is required,
  and `toolchain build`/`vendor`/`update` fail with the resolution error
  until it exists.  Cross-repo drift is possible; the smoke gate and the
  layout-pinning tests in `tests/test_toolchain.py` keep the contract
  enforced.  Execution remains docker-only for Windows/DOS toolchains
  (ADR-008); this ADR changes where the build source lives, not how
  toolchains run.
