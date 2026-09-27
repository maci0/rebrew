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
(including `rebrew.cache_backends`) as part of the trust boundary. On a
multi-user host the headless X display is one too: rebrew's `Xvfb` carries a
per-run MIT-MAGICK cookie and an unauthenticated Xvfb already on the box is
never adopted, so wine's windows are not readable by another local user
(`src/rebrew/headless.py`).

CI is a boundary of its own: `pull_request` (never `pull_request_target`),
workflow `permissions: contents: read`, no `id-token`, `secrets.GITHUB_TOKEN`
mapped only onto the resembl clone step, `persist-credentials: false`, and
every third-party Action pinned by commit SHA. `.github/workflows/toolchain-sync.yml`
runs nightly and reports toolchain pin drift without applying it. There is no
publish step and no artifact signing in this repository.

The packaged compile-cache backends refuse pickle deserialize
(`NoPickleDisk` in `src/rebrew/compile_cache.py`); that does not attest
plugin cache backends or remove the open upstream diskcache advisory.

## Claims this policy does **not** make

- No claim of authentication or authorization on `rebrew dashboard` (default
  bind is loopback; binding to non-loopback addresses exposes a read-only
  HTTP API without credentials). The only gate on those routes is the Host
  allow-list; there is no rate limit and no connection cap, and
  `GET /api/health` reports the absolute `coverage.db` path and the
  configured target count to any client that clears it.
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
  [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md). Wibo asset bytes are
  allow-listed, redirect-checked per hop, and checked against the release
  `digest`; the release-metadata GET that supplies that digest is pinned to
  `api.github.com` per hop (`wibo.py` `_trusted_wibo_metadata_url` /
  `_read_release_metadata`, which uses `follow_redirects=False`). None of that
  is content attestation: the digest is whatever the current GitHub release
  publishes. Wibo does not consume `GH_TOKEN`/`GITHUB_TOKEN`
  (those tokens are used only by toolchain pin-check/update HTTP to GitHub).
- No claim that dependency CVEs are absent; pin rationale lives in
  `pyproject.toml` comments and the changelog. In particular, diskcache's
  open pickle advisory is mitigated for packaged backends by `NoPickleDisk`,
  not by claiming the upstream advisory is fixed.
- No claim that library helpers which invoke host DOSBox
  (`rebrew.msvc16` / `tc16` / `delphi16` via `rebrew.dosbox`) are covered by
  the docker-only compile guarantee on the shipped CLI compile path.
  There is no `pdb_cvdump` module and no `REBREW_CVDUMP` setting. PDB reads
  on the shipped path run host `llvm-pdbutil`
  (`rebrew.pdb_info` / `rebrew.toolchain_detect`), not wine `cvdump.exe`.
- No claim that every shipped CLI command stays inside a container.
  `rebrew calibrate-bss` executes the link command read from the project's
  `build/CMakeFiles/*/link.txt` and its `--compile-cmd` on the host,
  `rebrew link-sweep` executes that same `link.txt` command on the host,
  `rebrew gen-stubs --build-cmd` executes an operator-supplied build command on the host,
  and analysis helpers run host rizin/r2, kuna, objconv, llvm-pdbutil, diec,
  objdump, and nasm against target binaries. Linked-exe GA
  (`match_ga.py` `_compile_source` / `matcher/compiler.py` `build_candidate`)
  runs that host compiler only when the profile has no docker image; a
  profile whose spec has an image raises instead of starting host wine.
  `rebrew doctor` smoke-runs host wine or wibo plus `CL.EXE` only on that
  same image-less path (`check_compiler`); a docker-backed profile returns
  before the smoke. Treat a project tree from an untrusted source as able
  to run code on the host through the paths that do execute.
- No claim that `REBREW_CONTAINER_RUNTIME` is restricted to a container
  runtime rebrew trusts. `container_runtime` (`src/rebrew/utils.py`) rejects
  characters outside `^[a-zA-Z0-9_\-\./]+$` and, for a value with no path
  separator, any name outside `docker` / `podman` / `nerdctl`. That is a typo
  guard: a value containing `/` is spawned as a path to the binary, so the
  knob remains a full redirection of every container run.
- No claim that the project tree cannot redirect outbound traffic. A
  project's `[compiler] recompile_url` applies unless `REBREW_RECOMPILE_URL`
  is set, and its `[llm] endpoint` overrides `REBREW_LLM_ENDPOINT`, so a
  cloned project chooses where the function **source** is sent
  (`recompile_url` in `src/rebrew/compile.py`, `llm_config` in
  `src/rebrew/llm_seed.py`). The one thing the project cannot take is the
  operator's **environment** key: `llm_config` refuses to send
  `REBREW_LLM_API_KEY` to a non-loopback `[llm].endpoint` unless
  `REBREW_LLM_ALLOW_PROJECT_ENDPOINT=1` is set
  (`_project_endpoint_allowed` in `src/rebrew/llm_seed.py`). That gate reads
  the key's provenance, so a key committed in the project TOML still travels
  to that project's own endpoint, and `[compiler] recompile_url` is not gated
  at all.
