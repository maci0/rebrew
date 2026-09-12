# 017 — Standardized toolchain profile names

## Status

Accepted

## Context

Profile names had grown organically and encoded three different conventions at
once.  MSVC profiles used a compressed version with no separator (`msvc6`,
`msvc600sp6`), Borland/Turbo C used the vendor's product code (`tc20`, `tc16`,
`borlandc55`), and the MinGW GCC images were named after the object format
(`gcc-pe`, `gcc-pe14`) even though PE is the target, not the compiler.  The
image tag next to a profile already used a clean `<family>:<version>-<target>`
form, so a project's `profile = "msvc6"` and its image `rebrew/msvc:6.0-win32`
disagreed on how to spell the same thing, and `msvc7` (the 7.1 compiler carried
by the `7.0-win32` image) versus `msvc700` (7.0 RTM) was impossible to read off
the name.

## Decision

Every toolchain profile is named `"<image-family>-<version>"`, lowercase, with
version dots kept: `msvc-6.0`, `gcc-14.2.0`, `borland-5.5`.  The target suffix
is appended only when one family and version exist for more than one target;
Watcom 2.0 is the only such family, so the profiles are `watcom-2.0-win32` and
`watcom-2.0-win16`.  Service-pack and variant markers keep their existing
words: `msvc-6.0-sp1`, `msvc-7.0-rtm`, `msvc-6.0-sp5-pp`.

The `gcc-pe` image family is renamed `mingw`, matching what the image actually
holds.  The image repository becomes `rebrew/mingw:<version>-win32` and the
build directory `rebrew-toolchains/mingw/<version>-win32`.  The bad name is
removed from the image content too: the tree installs to `/opt/mingw-<version>`
and the entrypoint wrapper is `/usr/local/bin/mingw`, so both images are
rebuilt rather than retagged.

Old profile names are removed, not aliased: a project or plugin naming one of
them fails the same way any unknown profile does, with a warning and the
documented fallback.

## Consequences

- Profile, image and host directory now read consistently: `msvc-6.0` ->
  `rebrew/msvc:6.0-win32` -> `msvc/6.0-win32`.
- The 7.0 final (`msvc-7.0`, the `7.0-win32` image) and 7.0 RTM (`msvc-7.0-rtm`)
  are distinguishable without prose.
- **Breaking:** every existing `rebrew-project.toml` and toolchain override
  naming a profile must be updated.  The CHANGELOG carries the full mapping.
- Profile names appear in `rebrew-libraries.toml`, `TOOLCHAIN` metadata fields,
  entry-point registrations and `_IMAGE_ENTRYPOINTS`, so plugins and projects
  pinning those values must move with them.  Where a profile name is a TOML
  table header (the `REBREW_TOOLCHAIN_OVERLAY_DIR` files), a dotted name must
  be quoted: `["msvc-6.0"]`, not `[msvc-6.0]`.
- Both MinGW images are rebuilt (`docker build -t rebrew/mingw:16.2.0-win32
  mingw/16.2.0-win32`); the old `rebrew/gcc-pe:*` tags are removed, so no
  `gcc-pe` name survives in a tag, path or wrapper binary.
