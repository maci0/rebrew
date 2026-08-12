# ADR-006: Standardized toolchain invocation (docker-first, host fallback)

- **Status**: Accepted
- **Date**: 2026-08

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
  present → vendored host path → PATH binary**.
- `rebrew toolchain list/status/pull/build/vendor/smoke` exposes the
  registry.
- `toolchain/<family>/<version>-<arch>/Dockerfile` are the
  canonical build specs (top-level dir = unversioned family — `msvc/`,
  `delphi/`, `watcom/` — so version and arch appear exactly once, in the
  subdir and image tag).  All images inherit the shared
  `rebrew/base` (pinned debian digest) and download pinned, sha256-verified
  sources (or extract committed in-repo tarballs), so builds are
  reproducible from a clean checkout with only docker.
- The shared `rebrew.dosbox` runner (mount a sandbox as `C:`, run
  autoexec, read FAT-uppercased outputs) is reused by both 16-bit
  compilers (delphi16, msvc16).
- First toolchains through the abstraction: `watcom` (native Open Watcom
  2.0), `msvc1.52` (DOSBox), alongside the existing `msvc6`/`gcc-pe`.

## Consequences

- New compilers are added as a spec + a Dockerfile, not new runner glue.
- A toolchain can be shared/pinned via its image tag — reproducible
  matching across machines (the eventual goal for CI and the corpus).
- Host fallback keeps existing vendored toolchains working without docker.
- Watcom/32-bit OMF objects are converted to COFF via the vendored
  **objconv** and parsed by LIEF — 32-bit OMF byte matching is enabled.
  objconv crashes on 16-bit OMF, so MSVC 1.52 matching still needs the
  custom 16-bit parser (docs/OMF_NOTES.md has the mapped layout).
- Borland C++ (bcc32) install extraction remains pending (16-bit Windows
  installer).
