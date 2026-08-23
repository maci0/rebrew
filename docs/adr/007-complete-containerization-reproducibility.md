# ADR-007: Complete containerization + unified byte-reproducibility gate

- **Status**: Accepted
- **Date**: 2026-08
- **Amended by**: [ADR-011](011-external-toolchains-checkout.md)
  (the build source this ADR described as in-repo — Dockerfiles, media
  tarballs, vendored trees — moved to the sibling rebrew-toolchains
  checkout; the pinned-source and smoke-gate invariants below are
  unchanged).

## Context

ADR-006 standardized docker-first toolchain invocation, but left gaps that
made the zoo not fully reproducible:

- **msvc420 / msvc5 / msvc400 were host-only** — the OmniBlade decomp.me
  mirror has no 4.0/4.2/5.0 tarballs, so they had no images and no smoke
  gate.  Their vendored trees existed but had **no pinned source**:
  `rebrew toolchain vendor` answered "no pinned source" on a fresh clone,
  so they were unreproducible by definition.
- **tc16 / tc20 images were built from UNTRACKED Dockerfiles** (and the
  tc `tc*-run.sh` wrappers + `tc20.tar.xz`/`tc31.tar.xz` tarballs were
  never committed): the images existed locally, but a fresh clone could
  neither `toolchain build` nor `toolchain vendor` them.
- The smoke gate ran only the docker path, so host-only toolchains had
  **no byte-reproducibility coverage** at all.

## Decision

Complete the ADR-006 model so every registry toolchain satisfies three
invariants:

1. **Pinned source, shared by image and host tree.**  Every vendored
   toolchain has a `ToolchainSource` (sha256-verified codeload/remote
   tarball, or a media tarball committed in the rebrew-toolchains
   checkout).  The docker image downloads the SAME pinned source
   (checksum verified inside the Dockerfile) and `rebrew toolchain vendor`
   assembles the host tree from it — so images and host trees are
   byte-identical **by construction**, not by accident.  msvc420/msvc5 pin
   the archaic-msvc codeload snapshots (verified byte-identical to the
   pre-existing committed trees); msvc400 pins itsmattkc/MSVC400.
2. **A docker image (or a documented exception).**  msvc400/msvc420/msvc5
   gained `rebrew/msvc:<ver>-win32` Dockerfiles (same `rebrew/base`
   pattern as msvc6: sha256-verified download, `cl` wrapper from
   `wrapper-common.sh`, OCI labels).  The only registry toolchain without
   an image is `gcc-pe`, deliberately: it is a PATH tool, not a vendored
   tree, so there is nothing to pin or reproduce.
3. **A smoke-gate slot.**  The gate now runs image-backed toolchains via
   docker AND host-only vendored trees via the uniform host runner (the
   runner wine-prefixes wine-runtime binaries — previously a latent bug:
   it exec'd Windows PEs directly).  COFF goldens are path-independent,
   so image and host runs hash identically; `toolchain smoke
   --print-goldens` regenerates the masked hashes when a pinned source
   changes.

Enforcement: a test asserts every image-backed spec's Dockerfile is
git-tracked in the rebrew-toolchains checkout (`git ls-files` against the
external repo) — an untracked Dockerfile is now a gate failure, closing
the tc16/tc20 class of regression (the guard moved with the build source
per ADR-011 and is no longer xfail).

## Consequences

- A fresh clone can rebuild or vendor EVERY toolchain from pinned,
  checksum-verified sources; the smoke gate proves byte reproducibility
  for every registry toolchain (image and host paths alike). *(Written
  when the registry held eleven toolchains; the MSVC matrix has since
  expanded to the full 1.0–11.0 set — all entries remain smoke-gated via
  `_SMOKE_GOLDEN`.)*
- The msvc line (4.0/4.2/5.0/6.0-sp3/sp6/7.0) is now a first-class,
  gated, roundtrip-tested set (compile → parse → compare → EXACT), with
  `--sweep-toolchain` covering the full range.
- The git-tracked Dockerfile guard is a hard, non-xfail test; the
  previously-uncommitted tc16/tc20 Dockerfiles and wrapper scripts are now
  committed in the rebrew-toolchains checkout (ADR-011) — the 16-bit media
  tarballs stay untracked by design, user-supplied next to their Dockerfile.
- Cost: larger image set to maintain (three new `rebrew/msvc` images),
  and the gate depends on codeload tarball stability — a repo rewrite
  changes the pinned sha256 and must be re-pinned deliberately (the
  `--print-goldens` path exists for exactly that).
