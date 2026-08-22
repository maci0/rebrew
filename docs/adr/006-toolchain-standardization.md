# ADR-006: Standardized toolchain invocation (docker-first, host fallback)

- **Status**: Accepted
- **Date**: 2026-08
- **Amended by**: [ADR-007](007-complete-containerization-reproducibility.md)
  (pinned-source unification), [ADR-008](008-docker-only-execution.md)
  (docker-only — the host fallback described below no longer exists for
  Windows/DOS toolchains), [ADR-011](011-external-toolchains-checkout.md)
  (build specs moved out of this repo to the sibling rebrew-toolchains
  checkout).  Read this ADR for the model's origin; 007/008/011 for its
  current shape.

## Context

rebrew's byte-matching needs the *actual* compiler that built a target.
Each toolchain brought its own runner glue: wine for MSVC, a DOSBox
sandbox for DCC (Delphi 1.0), native PATH for MinGW — plus finicky
installers (the Open Watcom self-extractor SIGFPEs on modern glibc; MSVC
1.52's CL is a Phar Lap TNT DOS-extender binary that wine cannot run).
Adding Watcom, MSVC 1.52, bcc32, and future compilers one glue-hack at a
time does not scale, and per-host installs are not reproducible.

## Decision

Standardize on the Godbolt/Compiler Explorer model: **one container image
per toolchain-version**, with the compiler behind a wrapper *inside* the
image so the host invocation is uniform (`docker run <image> <compiler>
<args>`).  The image encapsulates the runtime quirks (wine, DOSBox, the
finicky installer — build once, share).

- `rebrew.toolchain` holds a `ToolchainSpec` registry (`name`, image tag,
  host binary, image entry shim, flag style, object extension, vendored
  host path) and a runner that picks backend in order: **docker image
  present → vendored host path → PATH binary**.  *(The docker→host
  fallback was removed for every Windows/DOS toolchain by ADR-008 —
  execution is docker-only there; native-Linux specs like gcc-pe and
  watcom16 still exec their vendored/PATH binary directly.)*
- `rebrew toolchain list/status/pull/build/vendor/smoke` exposes the
  registry.
- `toolchain/<family>/<version>-<arch>/Dockerfile` are the
  canonical build specs (top-level dir = unversioned family — `msvc/`,
  `delphi/`, `watcom/` — so version and arch appear exactly once, in the
  subdir and image tag).  *(Moved with the build source to the sibling
  rebrew-toolchains checkout — ADR-011.)*  All images inherit the shared
  `rebrew/base` (pinned debian digest) and download pinned, sha256-verified
  sources (or extract committed media tarballs), so builds are
  reproducible from a clean checkout with only docker.
- The shared `rebrew.dosbox` runner (mount a sandbox as `C:`, run
  autoexec, read FAT-uppercased outputs) is reused by both 16-bit
  compilers (delphi16, msvc16).
- Toolchains through the abstraction (as of 2026-08): `watcom` (native
  Open Watcom 2.0), `msvc1.52` (DOSBox), `watcom16` (native wcc),
  `tc16` (Turbo C++ 3.1, DOSBox), `borlandc55` (bcc32, wine),
  `delphi16`, alongside the existing `msvc6`/`gcc-pe` — each with a
  vendored tree, docker image, and a slot in the byte-reproducibility
  smoke gate (6/6 images).  The model was subsequently completed — every
  registry toolchain now has a pinned source shared by image and host
  tree, and all eleven toolchains are smoke-gated (see
  [ADR-007](007-complete-containerization-reproducibility.md)).

## Consequences

- New compilers are added as a spec + a Dockerfile, not new runner glue.
- A toolchain can be shared/pinned via its image tag — reproducible
  matching across machines (the eventual goal for CI and the corpus).
- Host fallback keeps existing vendored toolchains working without docker.
  *(Superseded for Windows/DOS toolchains by ADR-008 — execution is
  docker-only there; the vendored trees remain as the image build source,
  see ADR-007/011.)*
- Watcom/32-bit OMF objects are converted to COFF via the vendored
  **objconv** and parsed by LIEF — 32-bit OMF byte matching is enabled.
  The vendored objconv carries the 16-bit OMF fix from the objconv fork
  (relocation methods + COMDAT→COFF sections, see the fork's
  PR-16BIT-OMF.md); 16-bit MSVC/Borland/Watcom objects parse via the
  custom `omf16` decoder (docs/OMF_NOTES.md has the mapped layout).
- Borland 16-bit (Turbo C++ 3.1) and 32-bit (bcc32) installs are both
  vendored in-repo (archive.org `turboc3.1_202112` / `BorlandC55` items).
