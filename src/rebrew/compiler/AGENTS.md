# AGENTS.md: compiler/

Compile execution and the compile cache: resolve a toolchain profile, run its docker image (or the remote recompile service), key and store the result, and compare the extracted bytes against the target.

## Modules

| Module | Role |
|--------|------|
| `compile.py` | `compile_to_obj`, `compile_and_compare`, `CompareResult`, batch precompile, remote backend dispatch |
| `cache.py` | Compile cache keys and storage (`CACHE_SCHEMA_VERSION`, diskcache backend, `rebrew.cache_backends` plugins) |
| `context.py` | `CompileContext`: the declarations document a compile is pinned to |
| `overrides.py` | Effective `TOOLCHAIN` / `CFLAGS` per source (function → `rebrew-libraries.toml` → project) |
| `toolchain.py` | Toolchain registry, image id admission, `run_toolchain` (docker-only for shipped profiles) |
| `toolchain_spec.py` / `toolchain_data.py` | `ToolchainSpec` value types and the packaged profile table |
| `toolchain_paths.py` | Location of the sibling recompile-toolchains checkout (`REBREW_TOOLCHAINS_DIR`) |
| `recompile_client.py` | HTTP client for the remote recompile service |
| `msvc_env.py` / `headless.py` | Compiler environment and headless X for wine invocations |
| `temp_dirs.py` | Compile sandbox placement that survives a hard-killed run |
| `dosbox.py`, `msvc16.py`, `tc16.py`, `delphi16.py` | 16-bit DOSBox compile drivers |

Externals (the only packages this one may import): `coff_reloc`, `config`, `errors`, `flag_data`, `flags`, `formats.binary_loader`, `formats.binary_model`, `formats.ne_loader`, `matcher.parsers`, `metadata`, `registry`, `sources`, `utils`, `workspace`. `matcher.parsers` is a lazy import inside `compile.py`; the matcher package imports this one, not the reverse. `tools/check_layering.py` enforces `PACKAGE_EXTERNALS`; this line follows it.

## Contracts

- **Commands live outside.** `rebrew cache` (`cache_cli.py`) and `rebrew toolchain` (`toolchain_cli.py`) stay at the package root; nothing here builds a Typer app.
- **One admitted image id.** A local compile's cache key, `docker run`, and publish share one full `sha256:` + 64 hex image id (`toolchain.image_content_id`). A missing or malformed id still compiles against the tag but the cache is neither read nor written. Remote results are never cached: the service response carries no image id.
- **Compile runs never pull.** `run_toolchain` passes `--pull=never` and `--network=none`; a missing image is a local error, not a fetch. Build and pull stay explicit (`rebrew toolchain build` / `pull`).
- **Bump `CACHE_SCHEMA_VERSION` in `cache.py`** when what a compile result depends on changes, so an upgrade reads a cold cache instead of a wrong hit.
