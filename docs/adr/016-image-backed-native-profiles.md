# 016 — Image-backed native compiler profiles (gcc-14.2.0, clang-18.1.8, mingw-16.2.0, watcom-2.0-win16)

## Status

Accepted

## Context

ADR 015 kept `gcc-14.2.0`, `mingw-16.2.0`, `clang-18.1.8` and `watcom-2.0-win16` as native specs (PATH or
vendored binary, no image), and recorded the blockers for making them
image-backed:

- `rebrew-toolchains` had no build source for the replacement images and
  `sources.json` pinned no compiler media for them;
- the only MinGW image carried GCC 14 while the native `mingw-16.2.0` resolved
  GCC 16.2.0 on the host — silently a different code generator;
- byte-exact matching requires the author's exact compiler, so a profile's
  version must be pinned, not whatever the host happens to have;
- `watcom-2.0-win16` needed 16-bit media that is user-supplied and absent.

Those blockers are gone.  Pinned sources exist for all four families: GNU GCC
release tarballs, LLVM's official prebuilt x86_64 Linux releases, the
`niXman/mingw-builds-binaries` release assets, and the Open Watcom snapshot —
whose `binl/wcc` is the 16-bit compiler (`wcc386` is the 32-bit one), so no
separate media is needed.

## Decision

Every shipped compiler profile is image-backed:

| Profile | Image | Compiler (verified by running it) |
| --- | --- | --- |
| `gcc-14.2.0` | `rebrew/gcc:14.2.0-linux-x64` | GCC 14.2.0 (ELF/x86_64) |
| `gcc-12.3.0` | `rebrew/gcc:12.3.0-linux-x64` | GCC 12.3.0 (ELF/x86_64) |
| `clang-18.1.8` | `rebrew/clang:18.1.8-linux-x64` | Clang 18.1.8 (ELF/x86_64) |
| `clang-16.0.4` | `rebrew/clang:16.0.4-linux-x64` | Clang 16.0.4 (ELF/x86_64) |
| `mingw-16.2.0` | `rebrew/mingw:16.2.0-win32` | MinGW-w64 GCC 16.2.0 (PE/x86_32) |
| `mingw-14.2.0` | `rebrew/mingw:14.2.0-win32` | MinGW-w64 GCC 14.2.0 (PE/x86_32) |
| `watcom-2.0-win16` | `rebrew/watcom:2.0-win16` | Open Watcom 2.0 `wcc` (16-bit OMF) |

- The generic names keep the newest version (`gcc-14.2.0` → 14.2.0, `clang-18.1.8` →
  18.1.8, `mingw-16.2.0` → 16.2.0), so the default `mingw-16.2.0` still resolves the
  same compiler family and version the host PATH binary did; the versioned
  profiles select the older build.
- `clang-16.0.4` pins 16.0.4: it is the newest 16.x with a published x86_64 Linux
  asset (16.0.5 and 16.0.6 shipped aarch64 and powerpc64le only).
- The mingw-builds driver is a Windows PE binary (PE32 i386), so the `mingw-16.2.0`
  image wrapper dispatches through `rebrew_run` (wine) like the MSVC images;
  those specs carry `runtime = "wine"` and declare no `tool_root` (one gcc
  driver, no CL/LINK/LIB), so the CMake bridge refuses them with an
  actionable error rather than generating a broken toolchain file.
- The ELF profiles carry empty `includes`/`libs`: the C library and mingw
  headers ship inside the image, so no host `/usr/include` is bind-mounted
  over the container's tree.
- Both Watcom images pin the dated `2026-09-01-Build` Open Watcom snapshot.  The
  moving `Last-CI-build` tag the 32-bit image used to reference was republished,
  so its recorded sha256 stopped resolving upstream; a dated release asset
  stays valid.

## Consequences

- A compile needs no host gcc/clang/mingw.  The compiler version is pinned by
  the image tag, which is what byte-exact matching needs; a host toolchain
  upgrade can no longer change match results.
- All seven images are in the `rebrew toolchain smoke` gate (verified
  byte-reproducible objects across runs).
- `rebrew toolchain vendor` extracts the pinned source into the checkout
  (the mingw `.7z` archives via the new `7z-strip1` layout); the images
  build from the same pins recorded in `sources.json`.
- The image-less native branch in `toolchain.py`/`compile.py` stays for a
  plugin toolchain registered without an `image`; no shipped profile uses it.
- `watcom-2.0-win16`'s smoke golden changed with the snapshot (Open Watcom
  `2026-09-01` codegen); the 32-bit `watcom-2.0-win32` golden is untouched, and
  re-pinning that image to a dated release is a separate change.
