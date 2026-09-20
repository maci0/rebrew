# Threat model — Rebrew

Living CISO-facing view of attack surface, trust boundaries, assets, and
mitigations. Point vulnerabilities and fixes belong to sec-review; this
document aims them.

| Field | Value |
| --- | --- |
| Last reviewed | 2026-09-21 |
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
| 1 | Hostile or compromised **compile path** (`rebrew` docker compile + **cmake bridge** + optional remote recompile) | Analyst → toolchain / recompile service | Arbitrary compile of attacker-influenced C; project root (and cmake wineprefix) bind-mounted into the container; remote sees full source when `REBREW_RECOMPILE_URL` is set | Docker-only shipped toolchains ([`compile.py`](../src/rebrew/compile.py), [`cmake_tc.py`](../src/rebrew/cmake_tc.py), ADR 008/015/016); `--network=none` on local container runs ([`toolchain.py`](../src/rebrew/toolchain.py) `run_toolchain`, [`cmake_tc.py`](../src/rebrew/cmake_tc.py)); `/I` outside project/workdir not bind-mounted ([`_docker_include_rewrite`](../src/rebrew/compile.py)); same-origin artifact URL + flag caps ([`recompile_client.py`](../src/rebrew/recompile_client.py)) | No authn to recompile; container escape / malicious image trust not modeled in-app; project-root same-path mount (and cmake's full-root + wineprefix mounts) still expands blast radius |
| 2 | **Plugin / entry-point code load** (`rebrew.*` groups, cache backends, mutations, CLI plugins) | Build/install → runtime | Import-time code execution as the analyst user | Duplicate name → `RegistryError` for identity-critical groups ([`registry.py`](../src/rebrew/registry.py)); optional groups warn-and-skip | No signature/attestation of plugins; installing a malicious wheel is full compromise |
| 3 | **Environment / overlay redirection** (`REBREW_*`, `GH_TOKEN`/`GITHUB_TOKEN`) | Host env → process | Swap toolchains, skills, container runtime, FLIRT sigs dir, cmake wineprefix/profile, compiler runner, recompile URL, LLM endpoint | Documented in [`docs/CONFIG.md`](CONFIG.md); overlay conflict policy in [`toolchain.py`](../src/rebrew/toolchain.py) | Env is trusted; no integrity check on overlay dirs, `REBREW_TOOLCHAINS_DIR`, `REBREW_CONTAINER_RUNTIME`, `REBREW_FLIRT_SIGS_DIR`, `REBREW_WINEPREFIX`, or runner path |
| 4 | **Secrets in config or outbound HTTP** (`[llm] api_key`, LLM/decomp.me/recompile traffic) | Secrets → code / third party | API key leak via committed TOML; source/ASM sent to configured endpoints | Warn if `api_key` in TOML ([`config.py`](../src/rebrew/config.py)); prefer `REBREW_LLM_API_KEY`; LLM response size/parse caps ([`llm_seed.py`](../src/rebrew/llm_seed.py)) | Key still readable from process env/TOML; no secret store; decomp.me upload is intentional third-party share ([`decompme.py`](../src/rebrew/decompme.py)) |
| 5 | **Coverage dashboard HTTP** (`rebrew dashboard`) | Browser / LAN → app | Read of project coverage.db (function names, VAs, status); DNS-rebinding class reads | Default bind `127.0.0.1`; Host allow-list; read-only SQLite; GET/HEAD only; row `limit` cap ([`dashboard.py`](../src/rebrew/dashboard.py)) | **No authentication**; `--host 0.0.0.0` exposes LAN; Host allow-list includes machine hostname addresses on wildcard bind |
| 6 | **Ghidra ReVa MCP / ghidra-cli** | App → local MCP or CLI bridge | Mutate Ghidra program state; read decompiler output | Default MCP endpoint loopback ([`ghidra/cli.py`](../src/rebrew/ghidra/cli.py), [`ghidra/client.py`](../src/rebrew/ghidra/client.py)); optional `ghidra_backend = "cli"` subprocess ([`ghidra/cli_backend.py`](../src/rebrew/ghidra/cli_backend.py)) | MCP client does not authenticate; trusts whatever answers the URL; ghidra-cli path trusts the local binary on `PATH` |
| 7 | **Supply-chain downloads** (wibo release asset; toolchain media/tarballs) | Build → runtime / host FS | Hostile binary or SDK archive landed under the project or media cache | Wibo: GitHub host allow-list + redirect check + release `digest` SHA-256 ([`wibo.py`](../src/rebrew/wibo.py)); toolchain: host-suffix allow-list + redirect check + pinned `sha256` ([`toolchain_cli.py`](../src/rebrew/toolchain_cli.py), [`toolchain_data.py`](../src/rebrew/toolchain_data.py)); vendor extract refuses path escape ([`_flatten_wrapper_dir`](../src/rebrew/toolchain_cli.py)) | Wibo trusts live GitHub release JSON for the digest (not an in-repo pin; wibo fetch does not use `GH_TOKEN`); `GH_TOKEN`/`GITHUB_TOKEN` only elevates GitHub API auth on toolchain pin-check/update paths |
| 8 | **Untrusted binary / signature / packer / prove parsers** | File → app | Parser DoS or native-lib memory safety issues (LIEF, python-flirt, LZEXE, optional angr) | 512 MiB binary size guard ([`binary_loader.py`](../src/rebrew/binary_loader.py)); LIEF preferred over hand parsers; prove is opt-in `[prove]` extra ([`prove.py`](../src/rebrew/prove.py)) | No sandbox around native parsers; FLIRT/LZEXE/prove inputs are attacker-controlled files; angr path exploration can amplify CPU/RAM |
| 9 | **Compile cache pickle store** (diskcache) | Local FS → app | Pickle gadget RCE if another local user writes the cache | `chmod 0o700` on cache dir ([`compile_cache.py`](../src/rebrew/compile_cache.py), [`matcher/core.py`](../src/rebrew/matcher/core.py)); values expected to be `.obj` bytes | Upstream diskcache unsafe-pickle advisory remains; shared/NFS home dirs weaken the mode bit |

---

## 1. Attack surface inventory

### Entry points (code → model)

| Class | Concrete surface | File references |
| --- | --- | --- |
| CLI | Umbrella `rebrew` + many `rebrew-*` console scripts | [`pyproject.toml`](../pyproject.toml) `[project.scripts]`; composition [`plugin.py`](../src/rebrew/plugin.py), [`builtins.py`](../src/rebrew/builtins.py), [`main.py`](../src/rebrew/main.py) |
| CMake bridge | `rebrew-cmake-{cl,link,lib}` (+ generated `cmake-toolchain` files) | [`cmake_tc.py`](../src/rebrew/cmake_tc.py) `tc_main` / `_docker_run`; scripts in [`pyproject.toml`](../pyproject.toml) |
| HTTP server (local) | `ThreadingHTTPServer` coverage dashboard | [`dashboard.py`](../src/rebrew/dashboard.py) |
| HTTP client | Recompile compile API; ReVa MCP (sync, decompiler, skeleton); LLM chat completions; decomp.me scratches; wibo GitHub release fetch; toolchain media/pin HTTP | [`recompile_client.py`](../src/rebrew/recompile_client.py), [`ghidra/client.py`](../src/rebrew/ghidra/client.py), [`ghidra/cli.py`](../src/rebrew/ghidra/cli.py), [`decompiler.py`](../src/rebrew/decompiler.py), [`skeleton.py`](../src/rebrew/skeleton.py), [`llm_seed.py`](../src/rebrew/llm_seed.py), [`decompme.py`](../src/rebrew/decompme.py), [`wibo.py`](../src/rebrew/wibo.py), [`toolchain_cli.py`](../src/rebrew/toolchain_cli.py) |
| Container / subprocess | Docker/podman toolchain images (`REBREW_CONTAINER_RUNTIME`); cmake wineprefix containers; optional host runner via `REBREW_COMPILER_RUNNER`; optional Xvfb for host-wine helpers (`REBREW_WINE_HEADLESS` / `REBREW_XVFB_DISPLAY`); ghidra-cli when `ghidra_backend = "cli"`; residual host DOSBox via library helpers (not the shipped `compile.py` path) | [`compile.py`](../src/rebrew/compile.py), [`cmake_tc.py`](../src/rebrew/cmake_tc.py), [`utils.py`](../src/rebrew/utils.py) `container_runtime()`, [`matcher/compiler.py`](../src/rebrew/matcher/compiler.py), [`headless.py`](../src/rebrew/headless.py), [`ghidra/cli_backend.py`](../src/rebrew/ghidra/cli_backend.py), [`dosbox.py`](../src/rebrew/dosbox.py) + [`msvc16.py`](../src/rebrew/msvc16.py) / [`tc16.py`](../src/rebrew/tc16.py) / [`delphi16.py`](../src/rebrew/delphi16.py) |
| File parsers | PE/ELF/Mach-O/NE via LIEF + loaders; FLIRT `.sig` (`REBREW_FLIRT_SIGS_DIR`); LZEXE unpack; PDB; PE `.rsrc`; coverage SQLite; BinSync state TOML; optional angr blobs via `rebrew prove` | [`binary_loader.py`](../src/rebrew/binary_loader.py), [`flirt.py`](../src/rebrew/flirt.py), [`lzexe.py`](../src/rebrew/lzexe.py), [`pdb_info.py`](../src/rebrew/pdb_info.py), [`resource.py`](../src/rebrew/resource.py), [`binsync/`](../src/rebrew/binsync/), [`prove.py`](../src/rebrew/prove.py) |
| Config / env | `rebrew-project.toml`, `rebrew-functions.toml`, `REBREW_*` (incl. `REBREW_CONTAINER_RUNTIME`, `REBREW_TOOLCHAINS_DIR`, `REBREW_FLIRT_SIGS_DIR`, `REBREW_COMPILER_RUNNER`, `REBREW_TOOLCHAIN` / `REBREW_WINEPREFIX` for cmake, `REBREW_WINE_HEADLESS` / `REBREW_XVFB_DISPLAY`, `REBREW_RECOMPILE_URL`, `REBREW_LLM_*`, overlays), `GH_TOKEN`/`GITHUB_TOKEN`; `REBREW_RUNNER` is **in-image only** (not read by host Python) | [`config.py`](../src/rebrew/config.py), [`docs/CONFIG.md`](CONFIG.md), [`utils.py`](../src/rebrew/utils.py), [`flirt.py`](../src/rebrew/flirt.py), [`cmake_tc.py`](../src/rebrew/cmake_tc.py), [`toolchain_paths.py`](../src/rebrew/toolchain_paths.py) |
| Plugins | setuptools entry-point groups + `REBREW_TOOLCHAIN_OVERLAY_DIR` / `REBREW_SKILLS_DIR` | [`registry.py`](../src/rebrew/registry.py), [`toolchain.py`](../src/rebrew/toolchain.py), [`skills.py`](../src/rebrew/skills.py) |
| Caches / derived | `.rebrew/compile_cache/`, verify cache JSON, `ga_runs.jsonl`, `coverage.db`, cmake wineprefix under `XDG_CACHE_HOME` / `REBREW_WINEPREFIX` | [`compile_cache.py`](../src/rebrew/compile_cache.py), [`verify_cache.py`](../src/rebrew/verify_cache.py), [`matcher/solutions.py`](../src/rebrew/matcher/solutions.py), [`build_db.py`](../src/rebrew/build_db.py), [`cmake_tc.py`](../src/rebrew/cmake_tc.py) `_wineprefix` |

**Not present:** authenticated multi-user API, message queues, webhooks, scheduled jobs, or tenant isolation. No inbound network listener except the optional dashboard.

### Inputs often treated as trusted

- Project `.c` / headers and `#include` paths (feed the compiler container / cmake bridge).
- Configured MCP / LLM / recompile URLs (operator-chosen; shape-checked by [`validate_http_url`](../src/rebrew/config.py) for TOML knobs, not pinned or authenticated).
- Installed entry-point packages and overlay directories (`REBREW_TOOLCHAIN_OVERLAY_DIR`, `REBREW_SKILLS_DIR`).
- `REBREW_CONTAINER_RUNTIME` (defaults to `docker`), `REBREW_TOOLCHAINS_DIR`, and `REBREW_FLIRT_SIGS_DIR` (redirect toolchain checkout / signature corpus) ([`utils.py`](../src/rebrew/utils.py), [`toolchain_paths.py`](../src/rebrew/toolchain_paths.py), [`flirt.py`](../src/rebrew/flirt.py)).
- `REBREW_TOOLCHAIN` / `REBREW_WINEPREFIX` for cmake bridge image selection and prefix location ([`cmake_tc.py`](../src/rebrew/cmake_tc.py)).
- BinSync state directory contents on `pull` / import ([`binsync/importer.py`](../src/rebrew/binsync/importer.py)).
- GitHub release JSON for wibo (digest + `browser_download_url` before allow-list) ([`wibo.py`](../src/rebrew/wibo.py)).
- In-repo toolchain `SOURCES` URLs once the operator accepts a pin rewrite ([`toolchain_data.py`](../src/rebrew/toolchain_data.py)).
- Host DOSBox + vendored 16-bit trees when library helpers (`msvc16` / `tc16` / `delphi16`) are invoked outside the docker compile path ([`dosbox.py`](../src/rebrew/dosbox.py)).
- Optional angr / Z3 stack when `[prove]` is installed ([`prove.py`](../src/rebrew/prove.py)).

---

## 2. Trust boundaries and data flow

| Boundary | What crosses | Authn / validation point |
| --- | --- | --- |
| **Analyst → CLI** | argv, cwd, project files | Typer parsing only; no auth (single-user local tool) |
| **CLI → docker toolchain** | Source copy into workdir; project-root and in-tree `/I` dirs bind-mounted; flags | Image must exist ([`compile.py`](../src/rebrew/compile.py)); include rewrite + out-of-tree `/I` not mounted ([`_docker_include_rewrite`](../src/rebrew/compile.py)); `--network=none` ([`toolchain.py`](../src/rebrew/toolchain.py) `run_toolchain`); runtime binary from `REBREW_CONTAINER_RUNTIME` ([`utils.py`](../src/rebrew/utils.py)) |
| **CLI → cmake bridge containers** | Full project-root mount + wineprefix mount; CMake argv rewritten to wine paths | Profile from `REBREW_TOOLCHAIN` / `/REBREW_TOOLCHAIN:` / project TOML ([`cmake_tc.py`](../src/rebrew/cmake_tc.py)); `--network=none`; prefix via `REBREW_WINEPREFIX` or XDG cache; **no** `/I` allow-list filter (entire root is mounted) |
| **CLI → recompile service** | Source, flags, compiler id over HTTP | Same-origin artifact fetch; flag count/length caps ([`recompile_client.py`](../src/rebrew/recompile_client.py)); TOML URL shape via [`validate_http_url`](../src/rebrew/config.py); **no client auth**; no local container (so no `--network=none`) |
| **CLI → LLM** | Truncated/sanitized C + Bearer API key | Fence neutralization + tree-sitter seed gate + body caps ([`llm_seed.py`](../src/rebrew/llm_seed.py)); endpoint shape via [`validate_http_url`](../src/rebrew/config.py); TLS depends on endpoint URL |
| **CLI → ReVa MCP** | JSON-RPC tool calls (sync, decompile, skeleton) | Loopback default; **no auth header** ([`ghidra/client.py`](../src/rebrew/ghidra/client.py), [`skeleton.py`](../src/rebrew/skeleton.py), [`decompiler.py`](../src/rebrew/decompiler.py)); pagination soft-capped at `MAX_MCP_PAGES` |
| **CLI → ghidra-cli** | Subprocess argv applying sync ops | Selected when `ghidra_backend = "cli"` ([`ghidra/cli_backend.py`](../src/rebrew/ghidra/cli_backend.py)); trusts `ghidra-cli` on `PATH` |
| **CLI → decomp.me** | Function object + C + context | Operator-initiated upload ([`decompme.py`](../src/rebrew/decompme.py)) |
| **CLI → GitHub (wibo / toolchain media)** | Release JSON + asset bytes; pinned tarball URLs | Wibo host allow-list + SHA-256 ([`wibo.py`](../src/rebrew/wibo.py)); toolchain host-suffix allow-list + pin verify + zip-slip flatten guard ([`toolchain_cli.py`](../src/rebrew/toolchain_cli.py)); optional `GH_TOKEN`/`GITHUB_TOKEN` for toolchain GitHub API only |
| **Browser → dashboard** | HTTP GET APIs over coverage.db | Host header allow-list; RO SQLite ([`dashboard.py`](../src/rebrew/dashboard.py)); **no session auth** |
| **Install → runtime** | Entry points / overlays | Conflict policy ([`registry.py`](../src/rebrew/registry.py)); no code signing |
| **Build → runtime** | Toolchain Dockerfiles / SOURCES pins → images and media caches | Sha256 pins in [`toolchain_data.py`](../src/rebrew/toolchain_data.py); image must exist at compile ([`compile.py`](../src/rebrew/compile.py)) |
| **Secrets → code** | `REBREW_LLM_API_KEY`, optional TOML `api_key`, GitHub tokens | Warn on committed key ([`config.py`](../src/rebrew/config.py)); not scrubbed from process memory |
| **Shared FS → metadata** | BinSync / `rebrew-functions.toml` | Lock + mode `0444` via `atomic_write_locked` ([`utils.py`](../src/rebrew/utils.py)); conflict flags on import |

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
| Compile cache | Integrity of cached `.obj` (pickle store) | `.rebrew/compile_cache/` |
| Analyst host | Container mounts + plugins can reach host FS | Workstation running rebrew |

Concrete blast radius of a dashboard leak: function names, virtual addresses, match status, and globals for configured targets — enough to map the binary’s reversing progress, not usually the full source tree.

---

## 4. Threats per boundary (STRIDE, concrete)

### Analyst / CLI → toolchain, cmake bridge & recompile

- **S** Spoofed recompile base URL via `REBREW_RECOMPILE_URL` or `[compiler] recompile_url` → source sent to attacker.
- **T** Tampered docker image tag / overlay toolchain / `REBREW_TOOLCHAIN` → wrong bytes, false EXACT/RELOC.
- **I** Information disclosure: remote compile + optional `emit_assembly` training tap ([`recompile_client.py`](../src/rebrew/recompile_client.py) module doc); cmake wineprefix on shared FS.
- **D** Unbounded project/compile jobs (GA/verify/cmake builds) → CPU/disk DoS on analyst machine; service-side caps only mirrored for flags.
- **E** Compiling C inside a container with broad bind mounts → write/read of mounted host paths if the image or compiler is hostile. Local runs use `--network=none` (egress blocked); that is **not** a claim of container escape resistance.

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

### CLI → GitHub (wibo / toolchain media)

- **S/T** Compromised GitHub release metadata or CDN → wrong wibo bytes; mitigated by host allow-list + digest check, but digest itself comes from the same release JSON ([`wibo.py`](../src/rebrew/wibo.py)). Wibo does not send `GH_TOKEN`.
- **T** Drifted or replaced toolchain tarball fails pin check unless operator re-pins ([`toolchain_cli.py`](../src/rebrew/toolchain_cli.py)); hostile archive members that escape the extract dir are refused at flatten ([`_flatten_wrapper_dir`](../src/rebrew/toolchain_cli.py)).
- **I** `GH_TOKEN`/`GITHUB_TOKEN` sent as GitHub API auth when set on toolchain pin-check/update only ([`toolchain_cli.py`](../src/rebrew/toolchain_cli.py) `_github_auth_headers`).

### Install / env → runtime

- **E** Malicious `rebrew.mutations` / `rebrew.commands` / cache backend entry point → code exec on use/import ([`registry.py`](../src/rebrew/registry.py)).
- **T** `REBREW_COMPILER_RUNNER` prepends an alternate runner ([`matcher/compiler.py`](../src/rebrew/matcher/compiler.py)); `REBREW_CONTAINER_RUNTIME` swaps docker/podman binary ([`utils.py`](../src/rebrew/utils.py)); `REBREW_FLIRT_SIGS_DIR` / `REBREW_TOOLCHAINS_DIR` redirect corpora and Dockerfiles ([`flirt.py`](../src/rebrew/flirt.py), [`toolchain_paths.py`](../src/rebrew/toolchain_paths.py)); `REBREW_WINEPREFIX` relocates cmake's bind-mounted prefix ([`cmake_tc.py`](../src/rebrew/cmake_tc.py)).
- **E** Calling [`msvc16`](../src/rebrew/msvc16.py) / [`tc16`](../src/rebrew/tc16.py) / [`delphi16`](../src/rebrew/delphi16.py) on the host runs local DOSBox against staged trees ([`dosbox.py`](../src/rebrew/dosbox.py)) — orthogonal to the docker-only shipped `compile.py` path. Host-wine helpers may spawn Xvfb ([`headless.py`](../src/rebrew/headless.py)).

### File → parsers

- **D/T** Crafted PE/ELF/NE/LZEXE/FLIRT/`.rsrc` inputs against native parsers ([`binary_loader.py`](../src/rebrew/binary_loader.py), [`lzexe.py`](../src/rebrew/lzexe.py), [`flirt.py`](../src/rebrew/flirt.py), [`resource.py`](../src/rebrew/resource.py)).
- **D** `rebrew prove` path exploration against crafted blobs ([`prove.py`](../src/rebrew/prove.py); optional `[prove]` / angr).

### Local multi-user FS

- **E** World-writable compile cache → pickle on read (partially mitigated by `0o700`).

**History signal (recur class):** dependency and cache hardening already landed (diskcache mode bits, httpx/idna pins, gitpython floor for `[prove]`, recompile same-origin artifact URLs, dashboard Host checks, wibo download host allow-list) — see [`CHANGELOG.md`](../CHANGELOG.md) and [`pyproject.toml`](../pyproject.toml) dependency comments. Expect regression pressure on pickle caches, HTTP clients, Host/SSRF checks, and download URL allow-lists.

---

## 5. Mitigations mapping

| Control | Threats covered | Evidence |
| --- | --- | --- |
| Docker-only shipped toolchains | Host wine/DOSBox RCE class on the main compile path; non-reproducible compilers | [`compile.py`](../src/rebrew/compile.py), ADR 008/016 |
| Container `--network=none` (local compile / cmake / smoke) | Malicious image egress during compile | [`toolchain.py`](../src/rebrew/toolchain.py) `run_toolchain`; [`cmake_tc.py`](../src/rebrew/cmake_tc.py); [`toolchain_cli.py`](../src/rebrew/toolchain_cli.py) |
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
| Compile cache dir `0o700` | Cross-user pickle plant | [`compile_cache.py`](../src/rebrew/compile_cache.py), [`matcher/core.py`](../src/rebrew/matcher/core.py) |
| LLM fence sanitize + tree-sitter seed gate + size caps | Prompt breakout → arbitrary seed text; huge responses; `#include` / multi-def ride-alongs | [`llm_seed.py`](../src/rebrew/llm_seed.py) |
| Warn on TOML-embedded LLM API key | Accidental secret commit | [`config.py`](../src/rebrew/config.py) |
| Metadata `0444` + lock writes | Casual hand-edit / races on STATUS store | [`utils.py`](../src/rebrew/utils.py) `atomic_write_locked` |
| Registry duplicate-name errors | Silent plugin clobber of toolchains/commands | [`registry.py`](../src/rebrew/registry.py) |

### Unmitigated / weak (ranked)

1. No authentication on dashboard or MCP client.
2. No attestation of toolchain images, overlays, or entry-point plugins.
3. Broad project-root bind mounts during compile; cmake additionally mounts the wineprefix and does not apply `/I` allow-list filtering.
4. Operator-configured remote endpoints fully trusted once set (URL shape only).
5. Wibo digest comes from live GitHub release JSON (not an in-repo pin); wibo fetch ignores `GH_TOKEN`.
6. diskcache pickle advisory (operational mitigation only).
7. Residual host DOSBox library path (`msvc16`/`tc16`/`delphi16`) is outside the docker-only compile guarantee.
8. Optional `rebrew prove` / angr has no resource sandbox beyond CLI loop/timeout knobs.

**Single points of failure:** (a) trust in the local Python environment + entry points; (b) trust in the container runtime and image contents; (c) Host allow-list as the sole dashboard browser control; (d) GitHub as the sole publisher of wibo release digests.

**Doc vs code:** This model does not claim mitigations the code lacks. Older prose that implied host wine fallback on the shipped compile path is obsolete (docker-only shipped profiles) — see ADR 008/016, not this model. Optional `rebrew init` wibo download remains a separate supply-chain path ([`wibo.py`](../src/rebrew/wibo.py)), not a compile-host fallback. Host DOSBox helpers remain for library/test use and must not be read as a restored compile fallback. `--network=none` blocks egress during local container compiles; it is **not** a hardened sandbox against a hostile project tree or malicious image ([`SECURITY.md`](../SECURITY.md)).

---

## 6. Abuse cases (hostile but local operator)

Scenarios assume the operator can run CLI commands; there is no separate auth layer.

| Scenario | Enabling path |
| --- | --- |
| Exfiltrate function ASM/C to a third party | `rebrew decompme` ([`decompme.py`](../src/rebrew/decompme.py)); or set `REBREW_RECOMPILE_URL` / LLM endpoint |
| Exhaust CPU/disk with GA / verify / flag sweep / prove | `rebrew match`, `rebrew verify`, `rebrew prove`, compile cache growth ([`match.py`](../src/rebrew/match.py), [`prove.py`](../src/rebrew/prove.py), [`compile_cache.py`](../src/rebrew/compile_cache.py)) |
| Overwrite project metadata from untrusted BinSync state | `rebrew binsync` pull/import with accept flags ([`binsync/importer.py`](../src/rebrew/binsync/importer.py)) |
| Bind dashboard on all interfaces and scrape coverage | `rebrew dashboard --host 0.0.0.0` ([`dashboard.py`](../src/rebrew/dashboard.py)) — **no auth to bypass** |
| Redirect compiles through attacker runner or container binary | `REBREW_COMPILER_RUNNER` ([`matcher/compiler.py`](../src/rebrew/matcher/compiler.py)); `REBREW_CONTAINER_RUNTIME` ([`utils.py`](../src/rebrew/utils.py)) |
| Redirect cmake builds via profile or wineprefix | `REBREW_TOOLCHAIN` / `/REBREW_TOOLCHAIN:` and `REBREW_WINEPREFIX` ([`cmake_tc.py`](../src/rebrew/cmake_tc.py)) — full project root remains mounted |
| Land a PE loader via init download | `rebrew init` optional wibo fetch ([`init.py`](../src/rebrew/init.py) → [`wibo.py`](../src/rebrew/wibo.py)) — integrity depends on GitHub release digest |
| Re-pin toolchain media to attacker-chosen archive | `rebrew toolchain` pin-update paths that rewrite `SOURCES` / Dockerfile sha ([`toolchain_cli.py`](../src/rebrew/toolchain_cli.py)) |
| Run host DOSBox against staged 16-bit trees | Library helpers [`msvc16.compile_c`](../src/rebrew/msvc16.py) / [`tc16`](../src/rebrew/tc16.py) / [`delphi16`](../src/rebrew/delphi16.py) via [`dosbox.run_dosbox`](../src/rebrew/dosbox.py) (not the shipped docker compile path) |

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
