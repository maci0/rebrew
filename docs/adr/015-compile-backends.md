# 015 — Compile backends: local docker images plus the recompile service

## Status

Amended by [016](016-image-backed-native-profiles.md) — the blockers recorded
below are resolved; every shipped profile is image-backed now.

## Context

The compile path had one backend, the local docker image for the profile's
toolchain. A second backend exists over HTTP, served by the sibling
`recompile` service with the same pinned images (`POST /api/v1/compile`
plus artifact download). A branch (`fix/remote-compile-backend`) also made
every toolchain image-backed and deleted the host/native, wibo and
headless paths.

That deletion cannot land with the artifacts at hand:

- `rebrew-toolchains` has no build source for the replacement images
  (`rebrew/gcc:pe-win32`, `rebrew/gcc:linux-x64`, `rebrew/clang:linux-x64`,
  `rebrew/watcom:2.0-win16`), and `sources.json` pins no compiler media for
  them;
- the one local MinGW image, `rebrew/mingw:2.0`, contains GCC 14-win32
  while the native `mingw-16.2.0` resolves GCC 16.2.0 on this host;
- byte-exact matching requires the author's exact compiler
  (`docs/TOOLCHAIN.md`, MinGW GCC caveat), so pointing `mingw-16.2.0` at that
  image would silently change every match result;
- `watcom-2.0-win16` needs the 16-bit media, which is user-supplied and absent.

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

The native path stays.

Making `gcc-14.2.0`, `mingw-16.2.0`, `clang-18.1.8` and `watcom-2.0-win16` image-backed is deferred
until a pinned source with the author's exact compiler version exists for
each, recorded in `sources.json`, and the 16-bit Watcom media is available.

## Consequences

- A compile runs locally (docker images) or against a shared recompile
  service without a project-config change, and a backend switch cannot
  serve the other's cached object.
- `gcc-14.2.0`, `mingw-16.2.0`, `clang-18.1.8` and `watcom-2.0-win16` remain native specs; `command`,
  `runner`, `wibo.py` and `headless.py` stay in place.
- The all-image migration, when it lands, removes the native branch, the
  `command`/`runner` keys, `wibo.py` and `headless.py`. Whether it also
  retires `match --link/--lib/--no-compare-obj` is a separate product
  decision.
