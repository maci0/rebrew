# Security Policy

## Supported versions

Rebrew is published as **Beta** (`Development Status :: 4 - Beta` in
[`pyproject.toml`](pyproject.toml)). There is no separate LTS track in this
repository: security fixes land on the default branch (`main`) and in the
next release cut from that branch. Older tags are not guaranteed to receive
backports.

## Reporting a vulnerability

Email the package author listed in [`pyproject.toml`](pyproject.toml):

**Marcel W. Wysocki** — `maci.stgn@gmail.com`

Please include enough detail to reproduce the issue (affected command or
module path, rebrew version or commit, and whether a local project or
dependency is required). Do not open a public GitHub issue for unfixed
vulnerabilities.

This repository does not define an SLA, bug bounty, or encrypted-reporting
channel. Acknowledgement and fix timing depend on maintainer availability.

## Security model (summary)

Rebrew is a **local** compiler-in-the-loop reversing workbench (CLI). It is
not a multi-tenant network service. The living attack-surface and trust-boundary
document is:

- [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md)

Operators should treat project source, configured HTTP endpoints
(recompile, LLM, ReVa MCP, decomp.me), GitHub release and toolchain-media
downloads (wibo, SDK tarballs), docker/podman images (`REBREW_CONTAINER_RUNTIME`),
cmake bridge wineprefix / profile pins (`REBREW_WINEPREFIX`, `REBREW_TOOLCHAIN`),
`REBREW_SKILLS_DIR` overlays, BinSync state-repo git remotes (`rebrew binsync pull`
fast-forwards and imports by default), and installed Python entry-point plugins
(including `rebrew.cache_backends`) as part of the trust boundary.

The packaged compile-cache backends refuse pickle deserialize
(`NoPickleDisk` in `src/rebrew/compile_cache.py`); that does not attest
plugin cache backends or remove the open upstream diskcache advisory.

## Claims this policy does **not** make

- No claim of authentication or authorization on `rebrew dashboard` (default
  bind is loopback; binding to non-loopback addresses exposes a read-only
  HTTP API without credentials).
- No claim that docker toolchain or cmake-bridge execution is a hardened
  sandbox against a hostile project tree or malicious image. Local container
  runs use `--network=none` (no egress) and `no-new-privileges`; that does
  not imply escape resistance. The compile path passes no `--user`, so the
  compiler runs as the image's default user; it mounts the project root
  read-only but can read all of it. The cmake bridge mounts the project root
  and wineprefix read-write.
- No claim that "docker-only" covers toolchains registered by an entry point
  or a `REBREW_TOOLCHAIN_OVERLAY_DIR` TOML file: a spec without `image` runs
  its `binary` on the host with the full process environment
  (`run_toolchain` in `src/rebrew/toolchain.py`).
- No claim that optional wibo / toolchain-media downloads are attested beyond
  the in-code host allow-list and hash checks described in
  [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md). Wibo integrity uses the live
  GitHub release `digest`; it does not consume `GH_TOKEN`/`GITHUB_TOKEN`
  (those tokens are used only by toolchain pin-check/update HTTP to GitHub).
- No claim that dependency CVEs are absent; pin rationale lives in
  `pyproject.toml` comments and the changelog. In particular, diskcache's
  open pickle advisory is mitigated for packaged backends by `NoPickleDisk`,
  not by claiming the upstream advisory is fixed.
- No claim that library helpers which invoke host DOSBox
  (`rebrew.msvc16` / `tc16` / `delphi16`) or host wine (`rebrew.pdb_cvdump`
  runs `cvdump.exe` from `REBREW_CVDUMP` or `PATH`) are covered by the
  docker-only compile guarantee on the shipped CLI compile path.
- No claim that every shipped CLI command stays inside a container.
  `rebrew calibrate-bss` executes the link command read from the project's
  `build/CMakeFiles/*/link.txt` and its `--compile-cmd` on the host,
  `rebrew link-sweep` executes that same `link.txt` command on the host,
  `rebrew gen-stubs --build-cmd` executes an operator-supplied build command on the host,
  linked-exe GA (`match_ga.py` / `build_candidate`) runs native toolchains on the host, and
  analysis helpers run host rizin/r2, kuna, objconv, llvm-pdbutil, diec, and
  objdump against target binaries. Treat a project tree from an untrusted
  source as able to run code on the host through these paths.
- No claim that the project tree cannot redirect outbound traffic. A
  project's `[compiler] recompile_url` applies unless `REBREW_RECOMPILE_URL`
  is set, and its `[llm] endpoint` overrides `REBREW_LLM_ENDPOINT` while an
  exported `REBREW_LLM_API_KEY` is still sent to it (`llm_config` in
  `src/rebrew/llm_seed.py`).
