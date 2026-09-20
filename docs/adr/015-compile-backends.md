# 015 — Compile backends: local docker images plus the recompile service

## Status

Amended by [016](016-image-backed-native-profiles.md) — the blockers recorded
below are resolved; every shipped profile is image-backed now.

## Context

The compile path had one backend, the local docker image for the profile's
toolchain. A second backend exists over HTTP, served by the sibling
`recompile` service with the same pinned images (`POST /api/v1/compile`
plus artifact download). At acceptance, a branch
(`fix/remote-compile-backend`) also made every toolchain image-backed and
deleted the host/native, wibo and headless paths — but that migration could
not land yet with the artifacts then at hand:

- `rebrew-toolchains` had no build source for the replacement images
  (`rebrew/gcc:pe-win32`, `rebrew/gcc:linux-x64`, `rebrew/clang:linux-x64`,
  `rebrew/watcom:2.0-win16`), and `sources.json` pinned no compiler media for
  them;
- the one local MinGW image, `rebrew/mingw:2.0`, contained GCC 14-win32
  while the native `mingw-16.2.0` resolved GCC 16.2.0 on the host;
- byte-exact matching requires the author's exact compiler
  (`docs/TOOLCHAIN.md`, MinGW GCC caveat), so pointing `mingw-16.2.0` at that
  image would have silently changed every match result;
- `watcom-2.0-win16` needed the 16-bit media, which was user-supplied and
  absent.

Those blockers were cleared in
[ADR-016](016-image-backed-native-profiles.md); the Decision below reflects
the backends that remain in force.

## Decision

Keep the local docker image as the default backend, and add the recompile
service as a second, opt-in backend.

- `rebrew.compile.recompile_url` selects it, from `REBREW_RECOMPILE_URL`
  (env wins) or `[compiler] recompile_url`.
- `rebrew.recompile_client` carries the transport: request caps mirrored
  from the service, artifact download, and a typed `RecompileError` for
  unreachable and non-2xx replies.
- The compile cache keys an object on the backend that produced it, so
  switching backends cannot serve the other's object.
- `recompile_emit_assembly` passes the service's opt-in training tap.

The image-backed migration for `gcc-14.2.0`, `mingw-16.2.0`,
`clang-18.1.8`, and `watcom-2.0-win16` landed in
[ADR-016](016-image-backed-native-profiles.md) — every shipped profile is
image-backed now.  An image-less native branch remains only for plugin
toolchains registered without an `image`.

## Consequences

- A compile runs locally (docker images) or against a shared recompile
  service without a project-config change, and a backend switch cannot
  serve the other's cached object.
- *(Historical — superseded by ADR-016:)* at acceptance, `gcc-14.2.0`,
  `mingw-16.2.0`, `clang-18.1.8` and `watcom-2.0-win16` were still native
  specs and the Decision deferred their images.  That migration landed;
  whether it also retires `match --link/--lib/--no-compare-obj` remains a
  separate product decision.  `wibo.py` / `headless.py` remain for doctor /
  init / plugin host paths, not as a shipped-profile compile backend.
