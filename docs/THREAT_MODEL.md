# Threat model — Rebrew

Living CISO-facing view of attack surface, trust boundaries, assets, and
mitigations. Point vulnerabilities and fixes belong to sec-review; this
document aims them.

| Field | Value |
| --- | --- |
| Last reviewed | 2026-09-25 |
| Scope | Python package `src/rebrew/` + CLI entry points in `pyproject.toml` |
| Owner / review cadence | Not designated in-repo |
| Disclosure | See repository root [`SECURITY.md`](../SECURITY.md) |

**What this is not:** rebrew is a local analyst workbench (CLI + optional
loopback dashboard). It is not a multi-tenant SaaS. Highest impact is
**local compromise of the analyst workstation**, **project data
exfiltration**, and **tampering of reversing artifacts** — not remote
unauthenticated RCE on a public service.

---

## Risk-ranked summary

| Rank | Risk | Boundary | Impact | Mitigations present | Gap |
| --- | --- | --- | --- | --- | --- |
| 1 | Hostile or compromised **compile path** (`rebrew` docker compile + **cmake bridge** + optional remote recompile) | Analyst → toolchain / recompile service | Arbitrary compile of attacker-influenced C; project root (and cmake wineprefix) bind-mounted into the container; remote sees full source when `REBREW_RECOMPILE_URL` or the project's `[compiler] recompile_url` is set | Docker-only shipped toolchains ([`compile.py`](../src/rebrew/compile.py), [`cmake_tc.py`](../src/rebrew/cmake_tc.py), ADR 008/015/016); `--network=none` + `--security-opt=no-new-privileges` on local container runs ([`toolchain.py`](../src/rebrew/toolchain.py) `run_toolchain`, [`cmake_tc.py`](../src/rebrew/cmake_tc.py)); `/I` outside project/workdir not bind-mounted ([`_docker_include_rewrite`](../src/rebrew/compile.py)); project root and `/I` mounts are `:ro` on the `run_toolchain` path; same-origin artifact URL + flag caps ([`recompile_client.py`](../src/rebrew/recompile_client.py)) | No authn to recompile; container escape / malicious image trust not modeled in-app; `run_toolchain` passes no `--user`, so a compile runs as the image's default user (root unless its Dockerfile sets `USER`); it can read the whole project root (mounted `:ro`) and write only the temp `/work` dir; the cmake bridge mounts the full project root and wineprefix **read-write** (as `--user uid:gid`, [`cmake_tc.py`](../src/rebrew/cmake_tc.py) `_docker_user_args`), so a hostile cmake-bridge image can rewrite the tree (`.git/hooks` included) |
| 2 | **Host-side execution driven by the project tree** (`rebrew calibrate-bss`, `rebrew link-sweep`; host analysis tools on target binaries; git on BinSync state) | Project files → host process | `calibrate-bss` and `link-sweep` run the argv read from `build/CMakeFiles/*/link.txt` directly on the host (`calibrate-bss` also its `--compile-cmd`, default `rebrew-cmake-cl`): a project tree shipping a crafted `link.txt` gets arbitrary command execution as the analyst, with no container | Both refuse `shell=True` (`shlex.split` only) and use unpredictable scratch paths: `calibrate-bss` `mkstemp` + 600 s / 300 s timeouts ([`calibrate_bss.py`](../src/rebrew/calibrate_bss.py)), `link-sweep` `mkdtemp` + 300 s process-group kill ([`link_sweep.py`](../src/rebrew/link_sweep.py)); analysis tools get argv lists, no shell ([`decompiler.py`](../src/rebrew/decompiler.py), [`discover.py`](../src/rebrew/discover.py)) | `link.txt` argv[0] is not checked against the cmake bridge scripts; rizin/r2, kuna, objconv, llvm-pdbutil, diec, objdump parse attacker binaries on the host unsandboxed; `git -C <state_dir>` honours that repo's `.git/config` |
| 3 | **Plugin / entry-point code load** (`rebrew.*` groups, cache backends, mutations, CLI plugins) | Build/install → runtime | Import-time code execution as the analyst user; an image-less toolchain (entry point or `REBREW_TOOLCHAIN_OVERLAY_DIR` TOML, `runtime` defaults to `"native"`) runs its `binary` on the host with the full parent environment | Duplicate name → `RegistryError` for identity-critical groups ([`registry.py`](../src/rebrew/registry.py)); optional groups warn-and-skip; overlay TOML rejects unknown fields ([`toolchain.py`](../src/rebrew/toolchain.py) `toolchain_from_toml`) | No signature/attestation of plugins; installing a malicious wheel is full compromise; a data-only overlay TOML is enough for host exec (`run_toolchain` native branch: `_resolve_binary` → `host_path` or `PATH`, `env = dict(os.environ)` so `REBREW_LLM_API_KEY` / `GH_TOKEN` reach the binary, no container) |
| 4 | **Environment / overlay redirection** (`REBREW_*`, `GH_TOKEN`/`GITHUB_TOKEN`) | Host env → process | Swap toolchains, skills, container runtime, FLIRT sigs dir, cmake wineprefix/profile, compiler runner, recompile URL, LLM endpoint | Documented in [`docs/CONFIG.md`](CONFIG.md); overlay conflict policy in [`toolchain.py`](../src/rebrew/toolchain.py) | Env is trusted; no integrity check on overlay dirs, `REBREW_TOOLCHAINS_DIR`, `REBREW_CONTAINER_RUNTIME`, `REBREW_FLIRT_SIGS_DIR`, `REBREW_WINEPREFIX`, or runner path |
| 5 | **Secrets in config or outbound HTTP** (`[llm] api_key`, LLM/decomp.me/recompile traffic) | Secrets → code / third party | API key leak via committed TOML; source/ASM sent to configured endpoints | Warn if `api_key` in TOML ([`config.py`](../src/rebrew/config.py)); prefer `REBREW_LLM_API_KEY`; key refused over plain `http` to a non-loopback host (`_key_safe_endpoint`); LLM response size/parse caps ([`llm_seed.py`](../src/rebrew/llm_seed.py)) | Key still readable from process env/TOML; no secret store; a project's `[llm] endpoint` wins over `REBREW_LLM_ENDPOINT` while an env `REBREW_LLM_API_KEY` wins over the TOML key, so a cloned project can aim the analyst's key at its own `https` host (`llm_config`); recompile traffic has no transport check (plain `http` accepted); decomp.me upload is intentional third-party share ([`decompme.py`](../src/rebrew/decompme.py)) |
| 6 | **Coverage dashboard HTTP** (`rebrew dashboard`) | Browser / LAN → app | Read of project coverage.db (function names, VAs, status); DNS-rebinding class reads | Default bind `127.0.0.1`; Host allow-list; read-only SQLite; GET/HEAD only; row `limit` cap; startup warning on non-loopback bind ([`dashboard.py`](../src/rebrew/dashboard.py)) | **No authentication**; `--host 0.0.0.0` exposes LAN; on wildcard bind the Host allow-list adds every address `getaddrinfo(gethostname())` returns (`_local_interface_ips`) |
| 7 | **Ghidra ReVa MCP / ghidra-cli** | App → local MCP or CLI bridge | Mutate Ghidra program state; read decompiler output | Default MCP endpoint loopback ([`ghidra/cli.py`](../src/rebrew/ghidra/cli.py), [`ghidra/client.py`](../src/rebrew/ghidra/client.py)); optional `ghidra_backend = "cli"` subprocess ([`ghidra/cli_backend.py`](../src/rebrew/ghidra/cli_backend.py)) | MCP client does not authenticate; trusts whatever answers the URL; ghidra-cli path trusts the local binary on `PATH` |
| 8 | **Supply-chain downloads** (wibo release asset; toolchain media/tarballs) | Build → runtime / host FS | Hostile binary or SDK archive landed under the project or media cache | Wibo: GitHub host allow-list + redirect check + release `digest` SHA-256 ([`wibo.py`](../src/rebrew/wibo.py)); toolchain: host-suffix allow-list + redirect check + pinned `sha256` ([`toolchain_cli.py`](../src/rebrew/toolchain_cli.py), [`toolchain_data.py`](../src/rebrew/toolchain_data.py)); vendor extract refuses path escape ([`_flatten_wrapper_dir`](../src/rebrew/toolchain_cli.py)) | Wibo trusts live GitHub release JSON for the digest (not an in-repo pin; wibo fetch does not use `GH_TOKEN`); `GH_TOKEN`/`GITHUB_TOKEN` only elevates GitHub API auth on toolchain pin-check/update paths |
| 9 | **Untrusted binary / signature / packer / prove parsers** | File → app | Parser DoS or native-lib memory safety issues (LIEF, python-flirt, LZEXE, optional angr) | 512 MiB binary size guard ([`binary_loader.py`](../src/rebrew/binary_loader.py)); LIEF preferred over hand parsers; prove is opt-in `[prove]` extra ([`prove.py`](../src/rebrew/prove.py)) | No sandbox around native parsers; FLIRT/LZEXE/prove inputs are attacker-controlled files; angr path exploration can amplify CPU/RAM |
| 10 | **Compile-cache store integrity** (diskcache + pluggable backends) | Local FS → app | Poisoned `.obj` bytes → wrong match verdicts; a custom `[cache] backend` could reintroduce unsafe deserialize | Packaged path: [`NoPickleDisk`](../src/rebrew/compile_cache.py) refuses pickle modes + `chmod 0o700` ([`compile_cache.py`](../src/rebrew/compile_cache.py) `CompileCache.__init__`, `OSError` suppressed); values are `.obj` / JSON bytes | Upstream GHSA-w8v5-vhqr-4h9v remains open on diskcache itself; shared/NFS homes weaken the mode bit; entry-point `rebrew.cache_backends` plugins are not forced through `NoPickleDisk` |

---

## 1. Attack surface inventory

### Entry points (code → model)

| Class | Concrete surface | File references |
| --- | --- | --- |
| CLI | Umbrella `rebrew` + console scripts, objdiff build shim `rebrew-objdiff-build`, AST security scanner `rebrew security-scan`, crypto scanner `rebrew crypto-scan`, build tree integrity check `rebrew build-check` | [`pyproject.toml`](../pyproject.toml) `[project.scripts]`; composition [`plugin.py`](../src/rebrew/plugin.py), [`builtins.py`](../src/rebrew/builtins.py), [`main.py`](../src/rebrew/main.py), [`objdiff_project.py`](../src/rebrew/objdiff_project.py), [`security_scan.py`](../src/rebrew/security_scan.py), [`crypto_scan.py`](../src/rebrew/crypto_scan.py), [`build_check.py`](../src/rebrew/build_check.py) |
| CMake bridge | `rebrew-cmake-{cl,link,lib}` (+ generated `cmake-toolchain` files) | [`cmake_tc.py`](../src/rebrew/cmake_tc.py) `tc_main` / `_docker_run`; scripts in [`pyproject.toml`](../pyproject.toml) |
| HTTP server (local) | `ThreadingHTTPServer` coverage dashboard | [`dashboard.py`](../src/rebrew/dashboard.py) |
| HTTP client | Recompile compile API; ReVa MCP (sync, data-label pull, decompiler, skeleton); LLM chat completions; decomp.me scratches; wibo GitHub release fetch; toolchain media/pin HTTP | [`recompile_client.py`](../src/rebrew/recompile_client.py), [`ghidra/client.py`](../src/rebrew/ghidra/client.py), [`ghidra/cli.py`](../src/rebrew/ghidra/cli.py), [`ghidra/commands.py`](../src/rebrew/ghidra/commands.py), [`decompiler.py`](../src/rebrew/decompiler.py), [`skeleton.py`](../src/rebrew/skeleton.py), [`llm_seed.py`](../src/rebrew/llm_seed.py), [`decompme.py`](../src/rebrew/decompme.py), [`wibo.py`](../src/rebrew/wibo.py), [`toolchain_cli.py`](../src/rebrew/toolchain_cli.py) |
| Git remote | `rebrew binsync pull` runs `git pull --ff-only` in the state dir by default (opt out with `--no-git`), then imports; `rebrew binsync push --git-push` pushes `binsync/__root__` and `HEAD` to `--remote` (default `origin`); 30 s timeout per git call | [`binsync/cli.py`](../src/rebrew/binsync/cli.py) `pull` / `push`, [`binsync/init.py`](../src/rebrew/binsync/init.py) `run_git` / `_GIT_TIMEOUT` |
| Container / subprocess | Docker/podman toolchain images (`REBREW_CONTAINER_RUNTIME`); image-less (native) plugin/overlay toolchain binaries run on the host by `run_toolchain` ([`toolchain.py`](../src/rebrew/toolchain.py)); cmake wineprefix containers; containerized libgrep (`gen_layout.py`) and stock lib extraction/assertion (`lib_match.py`); container cleanup on interrupt/timeout via `kill_container` ([`toolchain.py`](../src/rebrew/toolchain.py), [`cmake_tc.py`](../src/rebrew/cmake_tc.py), [`gen_layout.py`](../src/rebrew/gen_layout.py), [`lib_match.py`](../src/rebrew/lib_match.py)); optional host runner via `REBREW_COMPILER_RUNNER`; optional Xvfb for host-wine helpers (`REBREW_WINE_HEADLESS` / `REBREW_XVFB_DISPLAY`); ghidra-cli when `ghidra_backend = "cli"`; residual host DOSBox via library helpers (not the shipped `compile.py` path); `rebrew calibrate-bss` running the CMake `link.txt` argv and `--compile-cmd` on the host; `rebrew link-sweep` running the `link.txt` argv (or `--link-cmd`) once per candidate on the host; `rebrew gen-stubs --build-cmd` running an operator-supplied build argv on the host with `cwd` = project root; linked-exe GA mode running native compiler/linker on the host ([`match_ga.py`](../src/rebrew/match_ga.py), [`matcher/compiler.py`](../src/rebrew/matcher/compiler.py) `build_candidate`); host analysis tools on target binaries/objects/PDBs (rizin/r2, kuna, rizin `afl` discovery, objconv, llvm-pdbutil, diec, objdump, nasm); 5-second post-SIGKILL pipe drain timeout in `run_process_group` ([`utils.py`](../src/rebrew/utils.py)); `rebrew doctor` host-wine smoke of `cl.exe`; `git -C` on the BinSync state dir | [`calibrate_bss.py`](../src/rebrew/calibrate_bss.py) `find_link_cmd`, [`link_sweep.py`](../src/rebrew/link_sweep.py) `_discover_link_cmd`, [`gen_stubs.py`](../src/rebrew/gen_stubs.py), [`decompiler.py`](../src/rebrew/decompiler.py), [`discover.py`](../src/rebrew/discover.py), [`matcher/parsers.py`](../src/rebrew/matcher/parsers.py), [`pdb_info.py`](../src/rebrew/pdb_info.py), [`toolchain_detect.py`](../src/rebrew/toolchain_detect.py), [`data_layout.py`](../src/rebrew/data_layout.py), [`asm.py`](../src/rebrew/asm.py), [`doctor.py`](../src/rebrew/doctor.py), [`binsync/export.py`](../src/rebrew/binsync/export.py) / [`binsync/init.py`](../src/rebrew/binsync/init.py) / [`binsync/serial.py`](../src/rebrew/binsync/serial.py), [`compile.py`](../src/rebrew/compile.py), [`cmake_tc.py`](../src/rebrew/cmake_tc.py), [`utils.py`](../src/rebrew/utils.py) `container_runtime()` / `run_process_group()`, [`toolchain.py`](../src/rebrew/toolchain.py) `kill_container()`, [`gen_layout.py`](../src/rebrew/gen_layout.py), [`lib_match.py`](../src/rebrew/lib_match.py), [`matcher/compiler.py`](../src/rebrew/matcher/compiler.py), [`headless.py`](../src/rebrew/headless.py), [`ghidra/cli_backend.py`](../src/rebrew/ghidra/cli_backend.py), [`dosbox.py`](../src/rebrew/dosbox.py) + [`msvc16.py`](../src/rebrew/msvc16.py) / [`tc16.py`](../src/rebrew/tc16.py) / [`delphi16.py`](../src/rebrew/delphi16.py) |
| File parsers | PE/ELF/Mach-O/NE via LIEF + loaders; OMF16 archives/objects; COFF archives/objects (`.lib`/`.obj`); FLIRT `.sig` (`REBREW_FLIRT_SIGS_DIR`); LZEXE unpack; PDB; PE `.rsrc`; coverage SQLite; BinSync state TOML; CMake build files (`build.make`/`flags.make`); tree-sitter C AST; optional angr blobs via `rebrew prove` | [`binary_loader.py`](../src/rebrew/binary_loader.py), [`ne_loader.py`](../src/rebrew/ne_loader.py), [`omf16.py`](../src/rebrew/omf16.py), [`gen_flirt_pat.py`](../src/rebrew/gen_flirt_pat.py), [`lib_match.py`](../src/rebrew/lib_match.py), [`coff_reloc.py`](../src/rebrew/coff_reloc.py), [`flirt.py`](../src/rebrew/flirt.py), [`lzexe.py`](../src/rebrew/lzexe.py), [`pdb_info.py`](../src/rebrew/pdb_info.py), [`resource.py`](../src/rebrew/resource.py), [`binsync/`](../src/rebrew/binsync/), [`build_check.py`](../src/rebrew/build_check.py), [`c_parser.py`](../src/rebrew/c_parser.py), [`struct_parser.py`](../src/rebrew/struct_parser.py), [`security_scan.py`](../src/rebrew/security_scan.py), [`prove.py`](../src/rebrew/prove.py) |
| Config / env | `rebrew-project.toml`, `rebrew-functions.toml`, `REBREW_*` (incl. `REBREW_CONTAINER_RUNTIME`, `REBREW_TOOLCHAINS_DIR`, `REBREW_FLIRT_SIGS_DIR`, `REBREW_COMPILER_RUNNER`, `REBREW_TOOLCHAIN` / `REBREW_WINEPREFIX` for cmake, `REBREW_WINE_HEADLESS` / `REBREW_XVFB_DISPLAY`, `REBREW_RECOMPILE_URL`, `REBREW_LLM_*`, overlays), `GH_TOKEN`/`GITHUB_TOKEN`; `REBREW_RUNNER` is **in-image only** (not read by host Python) | [`config.py`](../src/rebrew/config.py), [`docs/CONFIG.md`](CONFIG.md), [`utils.py`](../src/rebrew/utils.py), [`flirt.py`](../src/rebrew/flirt.py), [`cmake_tc.py`](../src/rebrew/cmake_tc.py), [`toolchain_paths.py`](../src/rebrew/toolchain_paths.py), |
| Plugins | setuptools entry-point groups (`rebrew.toolchains`, `rebrew.mutations`, `rebrew.commands`, `rebrew.cache_backends`, …) + `REBREW_TOOLCHAIN_OVERLAY_DIR` / `REBREW_SKILLS_DIR` | [`registry.py`](../src/rebrew/registry.py), [`toolchain.py`](../src/rebrew/toolchain.py), [`skills.py`](../src/rebrew/skills.py), [`compile_cache.py`](../src/rebrew/compile_cache.py) |
| Skills render | `rebrew init` copies packaged + overlay `SKILL.md` trees into the project | [`init.py`](../src/rebrew/init.py) (symlink refusal), [`skills.py`](../src/rebrew/skills.py) |
| Caches / derived | `.rebrew/compile_cache/` (bytes via `NoPickleDisk`), verify cache JSON with strict hash check & forced-include dir fingerprints, `ga_runs.jsonl`, `coverage.db`, cmake wineprefix under `XDG_CACHE_HOME` / `REBREW_WINEPREFIX` | [`compile_cache.py`](../src/rebrew/compile_cache.py), [`verify_cache.py`](../src/rebrew/verify_cache.py), [`verify_hash.py`](../src/rebrew/verify_hash.py), [`residue.py`](../src/rebrew/residue.py), [`catalog/loaders.py`](../src/rebrew/catalog/loaders.py), [`matcher/solutions.py`](../src/rebrew/matcher/solutions.py), [`build_db.py`](../src/rebrew/build_db.py), [`cmake_tc.py`](../src/rebrew/cmake_tc.py) `_wineprefix` |

**Not present:** authenticated multi-user API, message queues, webhooks, scheduled jobs, or tenant isolation. No inbound network listener except the optional dashboard.

### Inputs often treated as trusted

- Project `.c` / headers and `#include` paths (feed the compiler container / cmake bridge).
- Configured MCP / LLM / recompile URLs (operator-chosen or shipped in a cloned project's `rebrew-project.toml`; TOML and `REBREW_RECOMPILE_URL` / `REBREW_LLM_ENDPOINT` values alike are shape-checked by [`validate_http_url`](../src/rebrew/config.py) via [`compile.py`](../src/rebrew/compile.py) and [`llm_seed.py`](../src/rebrew/llm_seed.py) `llm_config`, not pinned or authenticated).
- Installed entry-point packages and overlay directories (`REBREW_TOOLCHAIN_OVERLAY_DIR`, `REBREW_SKILLS_DIR`).
- `REBREW_CONTAINER_RUNTIME` (defaults to `docker`), `REBREW_TOOLCHAINS_DIR`, and `REBREW_FLIRT_SIGS_DIR` (redirect toolchain checkout / signature corpus) ([`utils.py`](../src/rebrew/utils.py), [`toolchain_paths.py`](../src/rebrew/toolchain_paths.py), [`flirt.py`](../src/rebrew/flirt.py)).
- `REBREW_TOOLCHAIN` / `REBREW_WINEPREFIX` for cmake bridge image selection and prefix location ([`cmake_tc.py`](../src/rebrew/cmake_tc.py)).
- `REBREW_COMPILER_RUNNER`, `REBREW_WINE_HEADLESS`, `REBREW_XVFB_DISPLAY` for host PE runner / headless wine helpers ([`matcher/compiler.py`](../src/rebrew/matcher/compiler.py), [`headless.py`](../src/rebrew/headless.py), [`compile.py`](../src/rebrew/compile.py)).
- BinSync state directory contents on `pull` / import ([`binsync/importer.py`](../src/rebrew/binsync/importer.py)), including whatever `rebrew binsync pull` just fast-forwarded from the state repo's configured upstream ([`binsync/cli.py`](../src/rebrew/binsync/cli.py)).
- GitHub release JSON for wibo (digest + `browser_download_url` before allow-list) ([`wibo.py`](../src/rebrew/wibo.py)).
- In-repo toolchain `SOURCES` URLs once the operator accepts a pin rewrite ([`toolchain_data.py`](../src/rebrew/toolchain_data.py)).
- Host DOSBox + vendored 16-bit trees when library helpers (`msvc16` / `tc16` / `delphi16`) are invoked outside the docker compile path ([`dosbox.py`](../src/rebrew/dosbox.py)).
- - Optional angr / Z3 stack when `[prove]` is installed ([`prove.py`](../src/rebrew/prove.py)).
- Community skill markdown under `REBREW_SKILLS_DIR` (copied into the project on `rebrew init`; content is trusted for agent consumption) ([`init.py`](../src/rebrew/init.py), [`skills.py`](../src/rebrew/skills.py)).

---

## 2. Trust boundaries and data flow

| Boundary | What crosses | Authn / validation point |
| --- | --- | --- |
| **Analyst → CLI** | argv, cwd, project files | Typer parsing only; no auth (single-user local tool) |
| **CLI → docker toolchain** | Source copy into a temp workdir (`writable_temp_dir`, mounted read-write at `/work`); project-root and in-tree `/I` dirs bind-mounted read-only; flags | Image must exist ([`compile.py`](../src/rebrew/compile.py)); include rewrite + out-of-tree `/I` not mounted ([`_docker_include_rewrite`](../src/rebrew/compile.py)); extra mounts `:ro` ([`toolchain.py`](../src/rebrew/toolchain.py) `run_toolchain`); `--network=none` + `no-new-privileges`, no `--user` ([`toolchain.py`](../src/rebrew/toolchain.py) `run_toolchain`); runtime binary from `REBREW_CONTAINER_RUNTIME` ([`utils.py`](../src/rebrew/utils.py)) |
| **CLI → cmake bridge containers** | Full project-root mount + wineprefix mount; CMake argv rewritten to wine paths | Profile from `REBREW_TOOLCHAIN` / `/REBREW_TOOLCHAIN:` / project TOML ([`cmake_tc.py`](../src/rebrew/cmake_tc.py)); `--network=none` + `no-new-privileges` + `--user uid:gid`; prefix via `REBREW_WINEPREFIX` or XDG cache; **no** `/I` allow-list filter (entire root is mounted) |
| **CLI → recompile service** | Source, flags, compiler id over HTTP | Same-origin artifact fetch; flag count/length caps ([`recompile_client.py`](../src/rebrew/recompile_client.py)); URL shape via [`validate_http_url`](../src/rebrew/config.py) on `REBREW_RECOMPILE_URL` (wins when set, even empty) or `[compiler] recompile_url` ([`compile.py`](../src/rebrew/compile.py) `recompile_url`); **no client auth**; plain `http` accepted; no local container (so no `--network=none`) |
| **CLI → LLM** | Truncated/sanitized C + Bearer API key | Prompt injection protection (fence neutralization, chat control token stripping, delimiter masking, count clamp 1..8) + tree-sitter AST gate (rejects compiler extensions `__declspec`/`__attribute__` in body, preprocessor directives, inline asm) + body caps ([`llm_seed.py`](../src/rebrew/llm_seed.py)); endpoint shape via [`validate_http_url`](../src/rebrew/config.py) (`[llm] endpoint` TOML wins over `REBREW_LLM_ENDPOINT`; `REBREW_LLM_API_KEY` wins over TOML when set); a key paired with plain `http` to a non-loopback host is refused before any request (`llm_config` / `_key_safe_endpoint`) |
| **CLI → ReVa MCP** | JSON-RPC tool calls (sync, decompile, skeleton) | Loopback default; **no auth header** ([`ghidra/client.py`](../src/rebrew/ghidra/client.py), [`skeleton.py`](../src/rebrew/skeleton.py), [`decompiler.py`](../src/rebrew/decompiler.py)); pagination soft-capped at `MAX_MCP_PAGES` |
| **CLI → ghidra-cli** | Subprocess argv applying sync ops | Selected when `ghidra_backend = "cli"` ([`ghidra/cli_backend.py`](../src/rebrew/ghidra/cli_backend.py)); trusts `ghidra-cli` on `PATH` |
| **CLI → decomp.me** | Function object + C + context; server returns `slug` + `claim_token` | Operator-initiated upload; `--api` base (default `https://decomp.me`) shape-checked by [`validate_http_url`](../src/rebrew/config.py); reply `slug` / `claim_token` must be URL-safe tokens before they are spliced into the printed claim URL ([`decompme.py`](../src/rebrew/decompme.py) `upload_scratch`, `scratch_url`); the claim URL (token included) goes to stdout / `--json` and so to shell logs |
| **CLI → GitHub (wibo / toolchain media)** | Release JSON + asset bytes; pinned tarball URLs | Wibo host allow-list + SHA-256 ([`wibo.py`](../src/rebrew/wibo.py)); toolchain host-suffix allow-list + pin verify + zip-slip flatten guard ([`toolchain_cli.py`](../src/rebrew/toolchain_cli.py)); optional `GH_TOKEN`/`GITHUB_TOKEN` for toolchain GitHub API only |
| **CLI ↔ BinSync git remote** | State TOML fetched by `git pull --ff-only`, then imported; exported state pushed on `--git-push` | Remote URL, transport, and credentials come from the state repo's `.git/config` and the user's git config, not rebrew; no signature check on pulled commits; conflict flags on import ([`binsync/cli.py`](../src/rebrew/binsync/cli.py), [`binsync/importer.py`](../src/rebrew/binsync/importer.py)) |
| **Browser → dashboard** | HTTP GET APIs over coverage.db | Host header allow-list; RO SQLite ([`dashboard.py`](../src/rebrew/dashboard.py)); **no session auth** |
| **Install → runtime** | Entry points / overlays / cache backends; image-less toolchain specs executed on the host | Conflict policy ([`registry.py`](../src/rebrew/registry.py)); no code signing; native `run_toolchain` branch has no container or env scrub ([`toolchain.py`](../src/rebrew/toolchain.py)); packaged compile cache uses `NoPickleDisk` ([`compile_cache.py`](../src/rebrew/compile_cache.py)) |
| **Skills overlay → project** | `SKILL.md` trees from `REBREW_SKILLS_DIR` | Symlink / path-escape refusal on copy ([`init.py`](../src/rebrew/init.py)); skill **content** is not sandboxed |
| **Build → runtime** | Toolchain Dockerfiles / SOURCES pins → images and media caches | Sha256 pins in [`toolchain_data.py`](../src/rebrew/toolchain_data.py); image must exist at compile ([`compile.py`](../src/rebrew/compile.py)) |
| **Secrets → code** | `REBREW_LLM_API_KEY`, optional TOML `api_key`, GitHub tokens | Warn on committed key ([`config.py`](../src/rebrew/config.py)); not scrubbed from process memory |
| **Shared FS → metadata** | BinSync / `rebrew-functions.toml` | Lock + mode `0444` via `atomic_write_locked` ([`utils.py`](../src/rebrew/utils.py)); conflict flags on import |
| **Shared FS → compile cache & verify cache** | `.rebrew/compile_cache/` and verify cache entries | Packaged compile cache: `NoPickleDisk` + dir `0o700` ([`compile_cache.py`](../src/rebrew/compile_cache.py)); plugin backends choose their own store; verify cache: strict hash matching, forced-include directory fingerprints, and isolated catalog copies ([`verify_hash.py`](../src/rebrew/verify_hash.py), [`verify_cache.py`](../src/rebrew/verify_cache.py), [`catalog/loaders.py`](../src/rebrew/catalog/loaders.py)) |

**Privilege transitions:** ordinary user process → container runtime (`REBREW_CONTAINER_RUNTIME` / docker.sock / podman) is the main elevation (compile and cmake bridge); MCP or ghidra-cli mutations elevate influence inside Ghidra; metadata writers chmod through the 0444 lock; downloaded wibo is marked owner-read+exec only (`stat.S_IRUSR | stat.S_IXUSR` in [`wibo.py`](../src/rebrew/wibo.py)); optional Xvfb/`xvfb-run` for host-wine helpers ([`headless.py`](../src/rebrew/headless.py), [`maybe_headless_wine`](../src/rebrew/compile.py)); host DOSBox library helpers elevate only insofar as the local `dosbox` binary and staged trees allow.

---

## 3. Assets and impact

| Asset | Why it matters | Where it lives |
| --- | --- | --- |
| Target binaries + reconstructed C | IP / game reverse engineering work product | Project tree (`src/`, binaries under config paths) |
| Match metadata (STATUS, CFLAGS, blockers, VAs) | Integrity of the matching pipeline | `rebrew-functions.toml`, `rebrew-data.toml` (tool-locked) |
| Coverage / catalog DBs | Progress and function inventory (names, VAs) | `coverage.db`, catalog JSON ([`build_db.py`](../src/rebrew/build_db.py)) |
| LLM / GitHub credentials | Account abuse, billed API use | Env / optional TOML |
| Toolchain images + overlays | Byte-reproducibility and supply chain | Docker images; `REBREW_TOOLCHAINS_DIR` / overlay dir |
| Wibo / toolchain media caches | Executable PE loader and SDK archives on disk | `tools/wibo` ([`wibo.py`](../src/rebrew/wibo.py)); media from [`toolchain_cli.py`](../src/rebrew/toolchain_cli.py) |
| CMake wineprefix | Persistent wine state bind-mounted into cmake builds | `REBREW_WINEPREFIX` or `XDG_CACHE_HOME/rebrew-*-wineprefix` ([`cmake_tc.py`](../src/rebrew/cmake_tc.py)) |
| Ghidra program state | Shared reversing annotations | Via MCP / BinSync / ghidra-cli |
| Compile cache | Integrity of cached `.obj` (bytes store; packaged path refuses pickle) | `.rebrew/compile_cache/` |
| Analyst host | Container mounts + plugins can reach host FS | Workstation running rebrew |

Concrete blast radius of a dashboard leak: function names, virtual addresses, match status, and globals for configured targets — enough to map the binary’s reversing progress, not usually the full source tree.

---

## 4. Threats per boundary (STRIDE, concrete)

### Analyst / CLI → toolchain, cmake bridge & recompile

- **S** Spoofed recompile base URL via `REBREW_RECOMPILE_URL` or `[compiler] recompile_url` → source sent to attacker.
- **T** Tampered docker image tag / overlay toolchain / `REBREW_TOOLCHAIN` → wrong bytes, false EXACT/RELOC.
- **I** Information disclosure: remote compile + optional `emit_assembly` training tap ([`recompile_client.py`](../src/rebrew/recompile_client.py) module doc); cmake wineprefix on shared FS.
- **D** Unbounded project/compile jobs (GA/verify/cmake builds) → CPU/disk DoS on analyst machine; service-side caps only mirrored for flags.
- **E** Compiling C inside a container with broad bind mounts → write/read of mounted host paths if the image or compiler is hostile. Local runs use `--network=none` (egress blocked) and `no-new-privileges`, but `run_toolchain` sets no `--user`: the compiler runs as the image's default user (root in most images). It can read the whole project root (mounted `:ro`) and write only the temp `/work` dir, whose outputs rebrew reads back as the compiled object. The cmake bridge mounts the project root and wineprefix read-write, so a hostile cmake image can rewrite or plant files in the project tree ([`cmake_tc.py`](../src/rebrew/cmake_tc.py)). That is **not** a claim of container escape resistance.
- **D/E** Orphan container accumulation: when the docker CLI is killed or interrupted, dockerd keeps the attached container running. Mitigated by explicit container naming and `kill_container` on timeout and `BaseException` (Ctrl+C) across toolchain runs, cmake wineprefix setup, layout symbol extraction, and stock lib verification ([`toolchain.py`](../src/rebrew/toolchain.py), [`cmake_tc.py`](../src/rebrew/cmake_tc.py), [`gen_layout.py`](../src/rebrew/gen_layout.py), [`lib_match.py`](../src/rebrew/lib_match.py)). Leaked inherited pipe fds blocking `communicate()` after process group `SIGKILL` are bounded by a 5-second drain timeout ([`utils.py`](../src/rebrew/utils.py) `run_process_group`).

### Browser → dashboard

- **S/I** DNS rebinding / wrong Host → mitigated by allow-list; residual risk if wildcard bind + hostname in allow-list.
- **I** Unauthenticated read of coverage APIs when bound beyond loopback.
- **D** Large `limit` (capped at 5000) still amplifies DB read cost.

### App → MCP / LLM / decomp.me / ghidra-cli

- **S** Anything listening on the configured MCP/LLM URL is trusted (sync CLI, skeleton, and decompiler backends share the client).
- **T** MCP apply path mutates Ghidra ([`apply_commands_via_mcp`](../src/rebrew/ghidra/client.py)); ghidra-cli apply is the same ops via subprocess ([`ghidra/cli_backend.py`](../src/rebrew/ghidra/cli_backend.py)).
- **I** LLM and decomp.me receive function source/ASM.
- **D** MCP list pagination can walk up to `MAX_MCP_PAGES` (100_000) before stopping ([`ghidra/client.py`](../src/rebrew/ghidra/client.py)).
- **E** LLM seeds only enter GA after tree-sitter checks — not shell execution — but still compile in the toolchain path.
- **S/T** Prompt injection via reversed C snippets: adversarial source containing chat-template control tokens (`<|im_start|>`, `<|system|>`, etc.), delimiter keywords (`END_C_SOURCE`), or fake markdown fences attempting to hijack LLM completions; mitigated by prompt fence neutralization, delimiter keyword masking to `C_DATA`, stripping control tokens, and clamping request counts to 1..8 ([`llm_seed.py`](../src/rebrew/llm_seed.py)). Returned code is parsed via tree-sitter to reject compiler extensions (`__declspec`, `__attribute__`) altering codegen/sections, preprocessor directives, and inline assembly before entering the compile/GA pipeline.

### CLI → GitHub (wibo / toolchain media)

- **S/T** Compromised GitHub release metadata or CDN → wrong wibo bytes; mitigated by host allow-list + digest check, but digest itself comes from the same release JSON ([`wibo.py`](../src/rebrew/wibo.py)). Wibo does not send `GH_TOKEN`.
- **T** Drifted or replaced toolchain tarball fails pin check unless operator re-pins ([`toolchain_cli.py`](../src/rebrew/toolchain_cli.py)); hostile archive members that escape the extract dir are refused at flatten ([`_flatten_wrapper_dir`](../src/rebrew/toolchain_cli.py)).
- **I** `GH_TOKEN`/`GITHUB_TOKEN` sent as GitHub API auth when set on toolchain pin-check/update only ([`toolchain_cli.py`](../src/rebrew/toolchain_cli.py) `_github_auth_headers`).

### Install / env → runtime

- **E** Malicious `rebrew.mutations` / `rebrew.commands` / cache backend entry point → code exec on use/import ([`registry.py`](../src/rebrew/registry.py)).
- **E/I** A TOML file under `REBREW_TOOLCHAIN_OVERLAY_DIR` (no Python needed) that omits `image` registers a native toolchain; selecting it (profile, per-function `TOOLCHAIN`) runs its `binary` on the host via [`run_toolchain`](../src/rebrew/toolchain.py) with a copy of the full process environment, outside the docker-only guarantee.
- **T** `REBREW_COMPILER_RUNNER` prepends an alternate runner ([`matcher/compiler.py`](../src/rebrew/matcher/compiler.py)); `REBREW_CONTAINER_RUNTIME` swaps docker/podman binary ([`utils.py`](../src/rebrew/utils.py)); `REBREW_FLIRT_SIGS_DIR` / `REBREW_TOOLCHAINS_DIR` redirect corpora and Dockerfiles ([`flirt.py`](../src/rebrew/flirt.py), [`toolchain_paths.py`](../src/rebrew/toolchain_paths.py)); `REBREW_WINEPREFIX` relocates cmake's bind-mounted prefix ([`cmake_tc.py`](../src/rebrew/cmake_tc.py)).
- **T** `REBREW_SKILLS_DIR` supplies agent skill markdown copied on `rebrew init` ([`skills.py`](../src/rebrew/skills.py), [`init.py`](../src/rebrew/init.py)); symlink escape is refused, content is not attested.
- **E** Calling [`msvc16`](../src/rebrew/msvc16.py) / [`tc16`](../src/rebrew/tc16.py) / [`delphi16`](../src/rebrew/delphi16.py) on the host runs local DOSBox against staged trees ([`dosbox.py`](../src/rebrew/dosbox.py)) — orthogonal to the docker-only shipped `compile.py` path. Host-wine helpers may spawn Xvfb ([`headless.py`](../src/rebrew/headless.py)).

### Project tree → host process

- **E** [`calibrate_bss.find_link_cmd`](../src/rebrew/calibrate_bss.py) reads the first `build/CMakeFiles/*/link.txt` under the project root and executes its argv on the host (only `/out:` and `/pdb:` are rewritten). A cloned project that ships a `build/` tree turns `rebrew calibrate-bss` into arbitrary host command execution; the docker-only guarantee does not apply.
- **E** [`link_sweep._discover_link_cmd`](../src/rebrew/link_sweep.py) reads the same `build/CMakeFiles/*/link.txt` (relative to cwd) and `rebrew link-sweep` executes it on the host once per link-option candidate: same host-exec class as `calibrate-bss`. The file text is also used as a `str.format` template, so stray braces abort the sweep.
- **E** `rebrew gen-stubs --build-cmd` executes an operator-supplied build command on the host with `cwd` = project root ([`gen_stubs.py`](../src/rebrew/gen_stubs.py)).
- **E** Linked-exe GA mode ([`match_ga.py`](../src/rebrew/match_ga.py)) runs native (image-less) toolchains on the host via `build_candidate` ([`matcher/compiler.py`](../src/rebrew/matcher/compiler.py)) with full process environment and no container.
- **T** Stale or manipulated `build/` makefiles (`build.make`, `flags.make`) silently changing compiler flags or objects; checked and verified by `rebrew build-check` ([`build_check.py`](../src/rebrew/build_check.py)).
- **E** `rebrew-objdiff-build` custom_make shim invoked by the objdiff GUI rebuilds base objects via `compile_to_obj` ([`objdiff_project.py`](../src/rebrew/objdiff_project.py)).
- **E/D** Host analysis tools parse attacker-supplied binaries outside any container: rizin/r2 `aaa` and kuna ([`decompiler.py`](../src/rebrew/decompiler.py)), rizin `afl` ([`discover.py`](../src/rebrew/discover.py)), objconv ([`matcher/parsers.py`](../src/rebrew/matcher/parsers.py)), llvm-pdbutil ([`pdb_info.py`](../src/rebrew/pdb_info.py), [`toolchain_detect.py`](../src/rebrew/toolchain_detect.py)), diec ([`toolchain_detect.py`](../src/rebrew/toolchain_detect.py)), objdump ([`data_layout.py`](../src/rebrew/data_layout.py)). A parser bug in any of them runs as the analyst.
- **I** A project's `rebrew-project.toml` chooses outbound endpoints. `[compiler] recompile_url` applies whenever `REBREW_RECOMPILE_URL` is absent from the environment, so every compile in that project posts source to the named host ([`compile.py`](../src/rebrew/compile.py) `recompile_url`). `[llm] endpoint` takes precedence over `REBREW_LLM_ENDPOINT`, and an exported `REBREW_LLM_API_KEY` beats the TOML key, so `match --seed-llm` sends the analyst's key as a Bearer header to the project's chosen `https` host ([`llm_seed.py`](../src/rebrew/llm_seed.py) `llm_config`). The URL is shape-checked, never pinned.
- **E** `git -C <state_dir>` ([`binsync/export.py`](../src/rebrew/binsync/export.py), [`binsync/init.py`](../src/rebrew/binsync/init.py), [`doctor.py`](../src/rebrew/doctor.py)) honours the state repo's own `.git/config` (e.g. `core.fsmonitor`, hooks). A state dir copied wholesale from an untrusted source, rather than cloned, can execute commands on commit.

### CLI ↔ BinSync git remote

- **S/T** Anyone with push access to the state repo's upstream controls what `rebrew binsync pull` imports: the pull runs unless `--no-git` is passed, and commits are not signature-checked ([`binsync/cli.py`](../src/rebrew/binsync/cli.py) `pull`). Tampered names, types, or comments land in project metadata subject only to import conflict handling ([`binsync/importer.py`](../src/rebrew/binsync/importer.py)).
- **I** `push --git-push` publishes exported state (function names, VAs, types, comments) to whatever `--remote` resolves to.
- **R** Attribution rests on git author fields, which `rebrew binsync init` fills from the user name with a synthetic `<name>@binsync.local` email when unset ([`binsync/init.py`](../src/rebrew/binsync/init.py)).

### File → parsers

- **D/T** Crafted PE/ELF/NE/LZEXE/FLIRT/`.rsrc` inputs against native parsers ([`binary_loader.py`](../src/rebrew/binary_loader.py), [`lzexe.py`](../src/rebrew/lzexe.py), [`flirt.py`](../src/rebrew/flirt.py), [`resource.py`](../src/rebrew/resource.py)).
- **D/T** Crafted OMF16 archives/objects or COFF archives/objects (`.lib`/`.obj`) parsed by native loaders and python-flirt ([`omf16.py`](../src/rebrew/omf16.py), [`gen_flirt_pat.py`](../src/rebrew/gen_flirt_pat.py), [`lib_match.py`](../src/rebrew/lib_match.py), [`coff_reloc.py`](../src/rebrew/coff_reloc.py)).
- **D** `rebrew prove` path exploration against crafted blobs ([`prove.py`](../src/rebrew/prove.py); optional `[prove]` / angr).
- **D** `winepath` is bounded by `_WINEPATH_TIMEOUT_S`.

### Local multi-user FS

- **T** Writable compile-cache dir → plant wrong `.obj` bytes (match false positive/negative); packaged readers refuse pickle modes via [`NoPickleDisk`](../src/rebrew/compile_cache.py) so this is **not** pickle-gadget RCE on the default backend.
- **E** A malicious `rebrew.cache_backends` plugin can bypass `NoPickleDisk` entirely ([`compile_cache.py`](../src/rebrew/compile_cache.py) `_discover_cache_backends`).
- **E** World-writable cache dir still lets another local user replace value files / SQLite (partially mitigated by `0o700`).
- **T** Verification cache collision / poisoning: mitigated by strict hash matching in [`verify_hash.py`](../src/rebrew/verify_hash.py) and directory fingerprint fallback for forced includes ([`compile_cache.py`](../src/rebrew/compile_cache.py), [`residue.py`](../src/rebrew/residue.py)). In-memory mutation of cached catalog entries is prevented by returning isolated copies ([`catalog/loaders.py`](../src/rebrew/catalog/loaders.py)).

**History signal (recur class):** dependency and cache hardening already landed (`NoPickleDisk` + diskcache mode bits, httpx/idna pins, gitpython floor for `[prove]`, recompile same-origin artifact URLs, dashboard Host checks, wibo download host allow-list) — see [`CHANGELOG.md`](../CHANGELOG.md) and [`pyproject.toml`](../pyproject.toml) dependency comments. Expect regression pressure on cache deserialize paths, HTTP clients, Host/SSRF checks, and download URL allow-lists.

---

## 5. Mitigations mapping

| Control | Threats covered | Evidence |
| --- | --- | --- |
| Docker-only shipped toolchains | Host wine/DOSBox RCE class on the main compile path; non-reproducible compilers | [`compile.py`](../src/rebrew/compile.py), ADR 008/016 |
| Container `--network=none` + `--security-opt=no-new-privileges` (every `run` of a toolchain image: compile, link, cmake, smoke, layout grep, lib hash/copy) | Malicious image egress during compile; setuid escalation inside the image | [`toolchain.py`](../src/rebrew/toolchain.py) `run_toolchain`; [`compile.py`](../src/rebrew/compile.py) link container; [`cmake_tc.py`](../src/rebrew/cmake_tc.py); [`toolchain_cli.py`](../src/rebrew/toolchain_cli.py); [`gen_layout.py`](../src/rebrew/gen_layout.py); [`lib_match.py`](../src/rebrew/lib_match.py) |
| Container kill on timeout / interrupt (compile, cmake prefix setup, libgrep, lib extraction/assertion) | Lingering or orphaned containers running under dockerd after SIGINT or timeout | `kill_container` in [`toolchain.py`](../src/rebrew/toolchain.py), [`cmake_tc.py`](../src/rebrew/cmake_tc.py), [`gen_layout.py`](../src/rebrew/gen_layout.py), [`lib_match.py`](../src/rebrew/lib_match.py) |
| Process-group kill drain timeout (5 s) | `communicate()` blocking indefinitely on inherited pipe fds after SIGKILL | `run_process_group` in [`utils.py`](../src/rebrew/utils.py) |
| `calibrate-bss` / `link-sweep` argv-only exec + unpredictable scratch path | Shell metacharacters in `link.txt`; local-user symlink/swap of the scratch DLL | `shlex.split` without `shell=True`; `tempfile.mkstemp` in [`calibrate_bss.py`](../src/rebrew/calibrate_bss.py), `tempfile.mkdtemp` + `run_process_group` in [`link_sweep.py`](../src/rebrew/link_sweep.py) (neither restricts which program `link.txt` names) |
| Project root + `/I` mounts `:ro` in compile containers | Hostile compiler or output-path flag rewriting the project tree (`.git/hooks`, sources) | `:ro` suffix on `mounts` in [`toolchain.py`](../src/rebrew/toolchain.py) `run_toolchain`; only the temp `/work` dir is writable (not the cmake bridge, which mounts read-write) |
| Out-of-tree `/I` not bind-mounted | Hostile `CFLAGS: /I/home/...` exfil via compiler container | [`_docker_include_rewrite`](../src/rebrew/compile.py) (rebrew compile path only; cmake mounts full project root) |
| Recompile same-origin artifact URL | SSRF via malicious `artifact_url` | [`recompile_client.py`](../src/rebrew/recompile_client.py) `_same_origin_artifact_url` |
| Flag count/length caps (client) | Oversized remote compile requests | `_MAX_FLAGS` / `_MAX_FLAG_LEN` in [`recompile_client.py`](../src/rebrew/recompile_client.py) |
| TOML HTTP URL shape check | Garbage / non-http URL knobs reaching clients | [`validate_http_url`](../src/rebrew/config.py) for `recompile_url` / `llm.endpoint` |
| Wibo download host allow-list + redirect check + SHA-256 | SSRF via poisoned `browser_download_url`; silent binary swap | `_trusted_wibo_download_url` / `_get_with_trusted_redirects` / digest check in [`wibo.py`](../src/rebrew/wibo.py) |
| Toolchain download host-suffix allow-list + sha256 pins | SSRF via CDN redirect; tampered SDK/media tarball at build | `_trusted_toolchain_download_url` / `SOURCES` verify in [`toolchain_cli.py`](../src/rebrew/toolchain_cli.py); pins in [`toolchain_data.py`](../src/rebrew/toolchain_data.py) |
| Vendor extract path-escape refusal | Zip-slip after a compromised pin | `_flatten_wrapper_dir` in [`toolchain_cli.py`](../src/rebrew/toolchain_cli.py) |
| Dashboard Host allow-list + RO DB + GET-only | CSRF-ish cross-site reads / writes | [`dashboard.py`](../src/rebrew/dashboard.py) |
| Dashboard default `127.0.0.1` | Accidental LAN exposure | `--host` default in [`dashboard.py`](../src/rebrew/dashboard.py) |
| List `limit` max 5000 | Unbounded list DoS | `_MAX_LIMIT` in [`dashboard.py`](../src/rebrew/dashboard.py) |
| Binary size 512 MiB | Trivial memory DoS via huge files | `_MAX_BINARY_SIZE` in [`binary_loader.py`](../src/rebrew/binary_loader.py) |
| Compile cache `NoPickleDisk` | Pickle-gadget RCE via poisoned diskcache entry (GHSA-w8v5-vhqr-4h9v) on packaged backends | [`NoPickleDisk`](../src/rebrew/compile_cache.py) |
| Compile cache dir `0o700` | Cross-user plant of value files / SQLite DB | [`compile_cache.py`](../src/rebrew/compile_cache.py) `CompileCache.__init__` (a failed `chmod` is suppressed, so the store opens with whatever mode the dir already had) |
| Verify cache strict hash matching & forced-include dir fingerprints | Stale cache hits, false matches from collision, or forced-include header drift | [`verify_hash.py`](../src/rebrew/verify_hash.py), [`verify_cache.py`](../src/rebrew/verify_cache.py), [`residue.py`](../src/rebrew/residue.py) |
| Catalog function list copy isolation | In-memory mutation by caller corrupting cached catalog data | [`catalog/loaders.py`](../src/rebrew/catalog/loaders.py) |
| Skills copy refuses symlinks | Overlay skill tree escapes project via symlink during `rebrew init` | [`init.py`](../src/rebrew/init.py) regular-file / non-symlink walk |
| LLM fence sanitize + control token stripping + delimiter masking + request count clamp (1..8) | Prompt injection: switching roles via `<|im_start|>`, terminating prompt fence via `END_C_SOURCE`, or requesting unbounded completions | `_sanitize_source`, `build_prompt` in [`llm_seed.py`](../src/rebrew/llm_seed.py) |
| LLM output seed AST validation | Model-generated `__declspec` / `__attribute__` faking matches, preprocessor directives, or inline assembly | `valid_c_source` in [`llm_seed.py`](../src/rebrew/llm_seed.py) |
| Warn on TOML-embedded LLM API key | Accidental secret commit | [`config.py`](../src/rebrew/config.py) |
| LLM key needs `https` (or loopback `http`) | Bearer key sent in cleartext over the network | `_key_safe_endpoint` in [`llm_seed.py`](../src/rebrew/llm_seed.py) `llm_config` |
| decomp.me reply token check | Hostile `--api` server splicing path/query text into the printed claim URL | `slug` / `claim_token` shape check in [`decompme.py`](../src/rebrew/decompme.py) `upload_scratch` |
| Dashboard non-loopback bind warning | Silent LAN exposure of the unauthenticated API | startup `console.print` in [`dashboard.py`](../src/rebrew/dashboard.py) `main` |
| Build tree drift check (`rebrew build-check`) | Hand-edited `build.make` / `flags.make` altering compile flags or stale object lists without updating source | [`build_check.py`](../src/rebrew/build_check.py) |
| Static unsafe C call scanner (`rebrew security-scan`) | Accidental or malicious introduction of unbounded string copies, format string bugs, command injection | [`security_scan.py`](../src/rebrew/security_scan.py) |
| Metadata `0444` + lock writes | Casual hand-edit / races on STATUS store | [`utils.py`](../src/rebrew/utils.py) `atomic_write_locked` |
| Registry duplicate-name errors | Silent plugin clobber of toolchains/commands | [`registry.py`](../src/rebrew/registry.py) |

### Unmitigated / weak (ranked)

1. `rebrew calibrate-bss` and `rebrew link-sweep` execute whatever program the project's `build/CMakeFiles/*/link.txt` names on the host ([`calibrate_bss.py`](../src/rebrew/calibrate_bss.py), [`link_sweep.py`](../src/rebrew/link_sweep.py)); `rebrew gen-stubs --build-cmd` executes an operator-supplied build command on the host ([`gen_stubs.py`](../src/rebrew/gen_stubs.py)); linked-exe GA runs native compilers on the host ([`match_ga.py`](../src/rebrew/match_ga.py), [`matcher/compiler.py`](../src/rebrew/matcher/compiler.py)); host analysis tools parse target binaries unsandboxed.
2. No authentication on dashboard or MCP client.
3. No attestation of toolchain images, overlays, or entry-point plugins (including `rebrew.cache_backends`); an image-less overlay toolchain executes on the host with the full environment ([`toolchain.py`](../src/rebrew/toolchain.py) `run_toolchain`).
4. The cmake bridge bind-mounts the full project root and wineprefix read-write with no `/I` allow-list filtering; the `run_toolchain` compile path mounts the root `:ro` but passes no `--user` (image default user, usually root) and can read everything under the root.
5. Remote endpoints fully trusted once set (URL shape only), including when the project TOML rather than the operator sets them: `[llm] endpoint` overrides the env endpoint and receives the env API key; recompile and MCP accept plain `http` to any host, so source crosses the network in cleartext (only the LLM key path demands `https` off loopback).
6. Wibo digest comes from live GitHub release JSON (not an in-repo pin); wibo fetch ignores `GH_TOKEN`.
7. Packaged compile-cache pickle RCE is mitigated in-code (`NoPickleDisk`); residual gaps are value-file integrity on shared FS and any plugin backend that does not refuse pickle.
8. Residual host DOSBox library path (`msvc16`/`tc16`/`delphi16`) and linked-exe GA (`match_ga.py` / `build_candidate`) are outside the docker-only compile guarantee.
9. Optional `rebrew prove` / angr has no resource sandbox beyond CLI loop/timeout knobs.
10. `REBREW_SKILLS_DIR` skill **content** is trusted after path-escape refusal — hostile markdown can still steer agents.
11. `rebrew binsync pull` imports whatever the state repo's upstream serves, with no commit-signature check ([`binsync/cli.py`](../src/rebrew/binsync/cli.py)).

**Single points of failure:** (a) trust in the local Python environment + entry points; (b) trust in the container runtime and image contents; (c) Host allow-list as the sole dashboard browser control; (d) GitHub as the sole publisher of wibo release digests.

**Doc vs code:** This model does not claim mitigations the code lacks. Older prose that implied host wine fallback on the shipped compile path is obsolete (docker-only shipped profiles; see ADR 008/016, not this model). Optional `rebrew init` wibo download remains a separate supply-chain path ([`wibo.py`](../src/rebrew/wibo.py)), not a compile-host fallback. Host DOSBox helpers remain outside the compile path. `rebrew calibrate-bss` and `rebrew link-sweep` are shipped CLI commands that run the CMake link command (and, for `calibrate-bss`, the stub compile) on the host, not through `compile.py`'s container; `rebrew gen-stubs --build-cmd` and native-profile linked-exe GA likewise execute on the host. Docker-only covers shipped (packaged) profiles; an image-less toolchain registered by an entry point or overlay TOML runs natively on the host ([`toolchain.py`](../src/rebrew/toolchain.py) `run_toolchain`). `--network=none` blocks egress during local container compiles; it is **not** a hardened sandbox against a hostile project tree or malicious image ([`SECURITY.md`](../SECURITY.md)). Do **not** read the open upstream diskcache advisory as “rebrew still unpickles cache entries”: the packaged backends refuse pickle modes.

---

## 6. Abuse cases (hostile but local operator)

Scenarios assume the operator can run CLI commands; there is no separate auth layer.

| Scenario | Enabling path |
| --- | --- |
| Exfiltrate function ASM/C to a third party | `rebrew decompme` ([`decompme.py`](../src/rebrew/decompme.py)); or set `REBREW_RECOMPILE_URL` / LLM endpoint |
| Exhaust CPU/disk with GA / verify / flag sweep / prove | `rebrew match`, `rebrew verify`, `rebrew prove`, compile cache growth ([`match.py`](../src/rebrew/match.py), [`prove.py`](../src/rebrew/prove.py), [`compile_cache.py`](../src/rebrew/compile_cache.py)) |
| Overwrite project metadata from untrusted BinSync state | Push to the shared state repo; a collaborator's default `rebrew binsync pull` fast-forwards and imports it, `--accept-binsync` resolves every conflict in the pusher's favour ([`binsync/cli.py`](../src/rebrew/binsync/cli.py), [`binsync/importer.py`](../src/rebrew/binsync/importer.py)) |
| Bind dashboard on all interfaces and scrape coverage | `rebrew dashboard --host 0.0.0.0` ([`dashboard.py`](../src/rebrew/dashboard.py)) — **no auth to bypass** |
| Redirect compiles through attacker runner or container binary | `REBREW_COMPILER_RUNNER` ([`matcher/compiler.py`](../src/rebrew/matcher/compiler.py)); `REBREW_CONTAINER_RUNTIME` ([`utils.py`](../src/rebrew/utils.py)) |
| Redirect cmake builds via profile or wineprefix | `REBREW_TOOLCHAIN` / `/REBREW_TOOLCHAIN:` and `REBREW_WINEPREFIX` ([`cmake_tc.py`](../src/rebrew/cmake_tc.py)) — full project root remains mounted |
| Land a PE loader via init download | `rebrew init` optional wibo fetch ([`init.py`](../src/rebrew/init.py) → [`wibo.py`](../src/rebrew/wibo.py)) — integrity depends on GitHub release digest |
| Re-pin toolchain media to attacker-chosen archive | `rebrew toolchain update --apply` rewrites `SOURCES` / Dockerfile sha; refused unless rebrew runs from an editable checkout (`SOURCE_CHECKOUT`), so wheel installs in site-packages are not mutated ([`toolchain_cli.py`](../src/rebrew/toolchain_cli.py) `update_cmd`) |
| Land hostile agent skills via overlay | `REBREW_SKILLS_DIR` + `rebrew init` ([`skills.py`](../src/rebrew/skills.py), [`init.py`](../src/rebrew/init.py)) — path escape blocked; markdown content is not |
| Run host DOSBox against staged 16-bit trees | Library helpers [`msvc16.compile_c`](../src/rebrew/msvc16.py) / [`tc16`](../src/rebrew/tc16.py) / [`delphi16`](../src/rebrew/delphi16.py) via [`dosbox.run_dosbox`](../src/rebrew/dosbox.py) (not the shipped docker compile path) |
| Run an arbitrary host command from a shared project | Commit `build/CMakeFiles/x/link.txt` naming any program; a collaborator's `rebrew calibrate-bss` or `rebrew link-sweep` executes it on the host ([`calibrate_bss.py`](../src/rebrew/calibrate_bss.py) `find_link_cmd`, [`link_sweep.py`](../src/rebrew/link_sweep.py) `_discover_link_cmd`) |
| Harvest a collaborator's LLM key or source | Ship `rebrew-project.toml` with `[llm] endpoint` (or `[compiler] recompile_url`) set to an attacker host; a collaborator with `REBREW_LLM_API_KEY` exported who runs `rebrew match --seed-llm` (or any compile, when `REBREW_RECOMPILE_URL` is unset) sends the key or the source there ([`llm_seed.py`](../src/rebrew/llm_seed.py) `llm_config`, [`compile.py`](../src/rebrew/compile.py) `recompile_url`) |
| Run an arbitrary host binary as a "compiler" | Drop a TOML toolchain without `image` into `REBREW_TOOLCHAIN_OVERLAY_DIR` and select it as the profile or a function's `TOOLCHAIN`; `run_toolchain` executes it with the analyst's environment ([`toolchain.py`](../src/rebrew/toolchain.py)) |
| Supply an arbitrary build command during stub generation | `rebrew gen-stubs --build-cmd "<cmd>"` executes the command directly on the host with `cwd` = project root ([`gen_stubs.py`](../src/rebrew/gen_stubs.py)) |
| Hijack LLM completions via control tokens in reversed C | Neutralized: `_sanitize_source` strips chat-template control tokens (`<|...|>`), masks `END_C_SOURCE` to `C_DATA`, and clamps request count ([`llm_seed.py`](../src/rebrew/llm_seed.py)) |
| Fake a match via model-generated compiler extensions | Neutralized: `valid_c_source` tree-sitter AST validation rejects `__declspec` / `__attribute__` in function body, preprocessors, and inline asm before compilation ([`llm_seed.py`](../src/rebrew/llm_seed.py)) |
| Manipulate `build/` makefiles to alter flags or mask residue | Flagged: `rebrew build-check` compares `build.make` against CMake `flags.make` custom comments and verifies source file existence ([`build_check.py`](../src/rebrew/build_check.py)) |

Client-side enforcement: N/A for core CLI. Dashboard UI filters are convenience only; API query params are server-parsed with caps.

---

## 7. Document quality / maintenance

- Keep this file aligned with code: every entry point and mitigation above carries a path for re-verification.
- Prefer updating the risk table when adding listeners, HTTP clients, or new secret knobs.
- Do not record CVE lists here (deps-review) or PII mappings (privacy-review).

---

## 8. Response readiness (notes only)

- **Disclosure contact:** [`SECURITY.md`](../SECURITY.md) (author email from package metadata). No separate security@ mailbox or bug-bounty program is defined in-repo.
- **Supported versions:** package is Beta ([`pyproject.toml`](../pyproject.toml) classifiers); no LTS matrix published.
- **Vuln → fix path:** not documented beyond normal PR/commit workflow on `main`. No security-incident runbook in-repo.
- **Audit trail:** CLI tools log to stderr/rich; no security-event audit log for dashboard access, MCP mutations, or remote compile submissions (o11y-review owns log structure). Investigate via shell history, `.rebrew/` artifacts, and VCS.
