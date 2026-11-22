# AGENTS.md: compiler/

Compile execution and the compile cache: resolve a toolchain profile, run its docker image (or the remote recompile service), key and store the result, and compare the extracted bytes against the target.

## Modules

| Module | Role |
|--------|------|
| `compile.py` | `compile_to_obj`, `compile_and_compare`, `CompareResult`, batch precompile, remote backend dispatch |
| `cache.py` | Compile cache keys and storage (`CACHE_SCHEMA_VERSION`, diskcache backend, `rebrew.cache_backends` plugins) |
| `context.py` | `CompileContext`: the declarations document a compile is pinned to |
| `preprocessed_context.py` | Opt-in, scoped pinned-MSVC preprocessing capture; unresolved inputs refuse |
| `overrides.py` | Effective `TOOLCHAIN` / `CFLAGS` per source (function → `rebrew-libraries.toml` → project) |
| `xtensa.py` | Core-aware XCC relocation/relaxation linking and verified native disassembly |
| `toolchain.py` | Toolchain registry, image id admission, `run_toolchain` (image-backed for shipped profiles) |
| `toolchain_spec.py` / `toolchain_data.py` | `ToolchainSpec` value types, the packaged profile table, and the source pins (`pinned_sources`) read from the vendored `toolchains.json` |
| `toolchain_paths.py` | Location of the sibling recompile-toolchains checkout (`REBREW_TOOLCHAINS_DIR`) |
| `unshare.py` / `unshare_runner.c` | Experimental rootless OCI-profile execution, immutable image export and disposable overlay cleanup |
| `recompile_client.py` | HTTP client for the remote recompile service |
| `msvc_env.py` / `headless.py` | Compiler environment and headless X for wine invocations |
| `temp_dirs.py` | Compile sandbox placement that survives a hard-killed run |
| `dosbox.py`, `msvc16.py`, `tc16.py`, `delphi16.py` | 16-bit DOSBox compile drivers |
| `image_headers.py` | Fresh image-bound MSVC header trees for read-only include reviews |

Externals (the only packages this one may import): `coff_reloc`, `config`, `errors`, `flag_data`, `flags`, `formats.binary_loader`, `formats.binary_model`, `formats.xtensa`, `formats.ne_loader`, `matcher.parsers`, `metadata.functions`, `registry`, `sources`, `telemetry`, `utils`, `workspace`. `matcher.parsers` is a lazy import inside `compile.py`; the matcher package imports this one, not the reverse. `tools/check_layering.py` enforces `PACKAGE_EXTERNALS`; this line follows it.

## Contracts

- **Commands live outside.** `rebrew cache` (`cache_cli.py`) and `rebrew toolchain` (`toolchain_cli.py`) stay at the package root; nothing here builds a Typer app.
- **One admitted image id.** A local compile's cache key, `docker run`, and publish share one full `sha256:` + 64 hex image id (`toolchain.image_content_id`). A missing or malformed id still compiles against the tag but the cache is neither read nor written. Remote results are never cached: the service response carries no image id.
- **Compile runs never pull.** `run_toolchain` passes `--pull=never` and `--network=none`; a missing image is a local error, not a fetch. Build and pull stay explicit (`rebrew toolchain build` / `pull`). Every `docker run` goes through `docker_hardening_args()` (`--cap-drop=ALL`, `--security-opt=no-new-privileges`, `--pids-limit=256`, `--memory=2g`, `--cpus=2`); `--read-only` stays off because images write a wineprefix under `/opt/wineprefix` and `$HOME` on every compile.
- **Remote compiles are counted per op call.** `_compile_via_recompile` appends each recompile call (verdict or not, and its wait) to the `RemoteCompiles` ledger of the dispatch op in flight (a context variable in process, `REBREW_REMOTE_COMPILES` in a child command) and sends that call's `Attribution`; the op sums the ledger into its `remote_compile` (`count` billed with a verdict, `billed_undelivered` billed without one, `unsettled` possibly billed with no settling answer; a call is in at most one). A compile outside an op records nothing.
- **One table reads recompile's answers.** `recompile_client._ANSWERS` classifies every status and code of the compile and artifact routes by recompile's client rules (what the key cost, the next step); `compile_source` follows it and nothing else, and `tests/test_recompile_client.py::TestClientRulesTable` iterates it. A new recompile code is a row there.
- **Only offered compilers run.** `compile_to_obj` refuses before anything runs (`CompilerNotOffered`, `compiler_not_offered`) a profile the registry withdrew (`ToolchainSpec.withdrawn`; `run_toolchain` refuses it too) or a profile the service's `GET /api/v1/compilers` lists as not installed (`remote_installed_compilers`, kept 30 s; a job asks the jobs owner's mediator, which forwards the listing cut to the job's compilers); a listing with no `admitted` row (recompile before 13), a 404 or an unreadable listing holds nothing back. Toolchain sweeps leave such profiles out of the search and its count (`match_sweep._installed_toolchains`).
- **Bump `CACHE_SCHEMA_VERSION` in `cache.py`** when what a compile result depends on changes, so an upgrade reads a cold cache instead of a wrong hit.
- **One include search order.** `local_include_order` gives every local compile, single-file (`compile_to_obj`) and batch (`precompile_batch`), the source's directory first, then the flags' include directories in order, then `[compiler] includes` (MSVC's `INCLUDE` position); `remote_include_bundle` ships the headers that order reaches and spells the directories relative to the source, and the compile cache key (`_cache_key_for`) and the verification fingerprint (`verify_hash.entry_headers_fp`) resolve headers in the same order. A change to one changes all of them, or they compile, hash or ship different headers.

- **Execution selection stays explicit.** `cfg.execution_backend` selects Docker,
  Podman or experimental unshare. Image admission, compile and timeout cleanup
  use the same frontend. Unshare requires a pinned image ID and supported
  MSVC/Wine profile; never fall back after setup failure. Every invocation owns
  its private overlay; PID-namespace teardown kills detached Wine descendants.
  Helper and profile content participate in object and verification cache keys.
- **Source pins are recompile-toolchains'.** `toolchains.json` is that repository's release manifest, vendored byte for byte and pinned by `TOOLCHAINS_MANIFEST_SHA256`; never edit it or keep a second copy of a pin here. Re-pin in recompile-toolchains, then re-vendor the release (docs/TOOLCHAIN.md). Nothing here edits a file in the recompile-toolchains checkout except the host trees `rebrew toolchain vendor` assembles.
