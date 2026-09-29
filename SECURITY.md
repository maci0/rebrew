# Security Policy

## Supported versions

Rebrew is published as **Beta** (`Development Status :: 4 - Beta` in
[`pyproject.toml`](pyproject.toml)). There is no separate LTS track in this
repository: security fixes land on the default branch (`main`) and in the
next release cut from that branch. Older tags are not guaranteed to receive
backports.

## Reporting a vulnerability

Email the package author listed in [`pyproject.toml`](pyproject.toml):

**Marcel W. Wysocki**: `maci.stgn@gmail.com`

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
fast-forwards and imports by default), a foreign splat project handed to
`rebrew import-splat` (its `splat.yaml` and `symbol_addrs` files are written into
the local project as metadata, source markers, and `library_<module>.h` names;
the command is a dry run unless `--write` is passed), and installed Python
entry-point plugins
(including `rebrew.cache_backends`) as part of the trust boundary. So are the
host-tool knobs outside the `REBREW_` namespace: `KUNA_SPECS` (else the first
pypcode spec dir under `UV_TOOL_DIR` / `XDG_DATA_HOME` / `LOCALAPPDATA`) is the
SLEIGH language definition the native `kuna` binary parses, `XDG_CACHE_HOME` is
the sandbox base whose `rebrew`-prefixed directories older than a day are
deleted by `sweep_stale_temp_dirs` on the next compile
(`src/rebrew/temp_dirs.py`), and `XAUTHORITY` names the X cookie file rebrew
adopts for host-wine helpers and re-exports to wine children, accepted as any
file the analyst can read (`_local_cookie` in `src/rebrew/headless.py`), so the
headless-display access decision is taken from the process environment. On a
multi-user host the headless X display is one too: the `Xvfb` rebrew
**starts** carries a per-run MIT-MAGICK cookie, so its windows are not
readable by another local user (`src/rebrew/headless.py`). Adopting an
Xvfb already on the box is weaker than that: `_adopt` uses the candidate
server's own `-auth` cookie when it advertises one and the operator's
`XAUTHORITY` otherwise, so a server started without `-auth` is adopted and
its windows are readable by any local user. The display's pid is also
resolved through the world-writable `/tmp/.X11-unix` directory.

CI is a boundary of its own: `pull_request` (never `pull_request_target`),
workflow `permissions: contents: read`, no `id-token`, `persist-credentials: false`,
and every third-party Action pinned by commit SHA. `secrets.GITHUB_TOKEN` is
never workflow-level `env`: in `ci.yml` it reaches only the resembl clone
step through the composite action's `github-token` input, and in
`.github/workflows/toolchain-sync.yml` it reaches the resembl clone step and
the nightly `check-updates` run. That workflow runs nightly and reports
toolchain pin drift without applying it. There is no publish step and no
artifact signing in this repository.

The packaged compile-cache backends refuse pickle deserialize
(`NoPickleDisk` in `src/rebrew/compile_cache.py`); that does not attest
plugin cache backends or remove the open upstream diskcache advisory.

## Claims this policy does **not** make

- No claim of authentication or authorization on `rebrew dashboard` (default
  bind is loopback; binding to non-loopback addresses exposes a read-only
  HTTP API without credentials). The only gate on those routes is the Host
  allow-list; there is no rate limit, and the 64-connection cap
  (`_MAX_ACTIVE_CONNECTIONS` in `src/rebrew/dashboard.py`) is an availability
  bound an allow-listed client can fill. `GET /api/health` reports the
  configured target count to any client that clears it, and the absolute
  coverage-directory path only when the bind is `127.0.0.1` / `localhost` /
  `::1`; a non-loopback `--host` drops that field (`expose_paths` in
  `src/rebrew/dashboard.py`). The flag is decided by the `--host` string, not
  by the address the socket bound, so a `localhost` that resolves off-box
  would still serve the path.
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
- No claim that a cloned project's metadata can make rebrew read or
  write outside the project, and no claim that a command other than the
  validator enforces it. The `file` identity field is a path, and one
  validator owns it: `contained_path` (`src/rebrew/sources.py`) resolves the
  value under `source_roots` (`reversed_dir`, then `shared_dir`, with the
  project `root` as the outer bound, since a shared-tree source is recorded
  `../`-prefixed relative to `reversed_dir`) and refuses an empty, absolute,
  or escaping value. Every read and write join calls it, including
  `rebrew verify` (`verify.py` `verify_entry`, where a refused entry is
  recorded `MISSING_FILE`), that module's cache-validity read and deferred
  STATUS pass, the batch compile (`compile.py` `precompile_batch`), the
  blocker clear in `rebrew test`, the `rebrew-objdiff-build` shim
  (`objdiff_project.py`), `rebrew merge-sweep`, and every read and write in
  `rebrew cross-import` (`cross_import.py` `import_function`,
  `import_shared_function`, `promote_to_shared`); `rebrew rename`
  (`rename.py`, `rename_ops.py`) and the verify cache's patch refresh
  (`verify_cache.py`) keep their own resolve-and-compare. What this does
  **not** claim: it is a shared function, not a type, so a new join that
  skips it is unchecked, and `merge_sweep` keeps a second rule for an older
  absolute value that tests containment against the project `root` only.
  It says nothing about a project running host commands, which
  [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) §4 covers separately.
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
- No claim that a recompile endpoint only receives the source. The object it
  returns is written to the compile workdir and published into the local
  compile cache (`publish_obj_cache` in `src/rebrew/compile.py`), keyed on
  source, flags, and `recompile:<url>/<spec.name>`, and later runs are served
  those bytes instead of compiling. A hostile endpoint, or a MITM on the plain
  `http` leg the URL check still allows, therefore plants bytes that persist
  across runs, carry no provenance marker, are never expired, and are handed
  to LIEF's COFF parser (or host `objconv` on an OMF profile) on every replay.
  The response body has no size cap; the cache `size_limit` is the only
  bound, and that too is project-supplied: the 500 MiB default
  (`_DEFAULT_SIZE_LIMIT` in `src/rebrew/compile_cache.py`) is replaced by
  `[cache] size_limit_mib` from `rebrew-project.toml` with no upper clamp
  (`cache_size_limit` in `src/rebrew/config.py`).
  Changing the endpoint or toolchain starts from a cache miss, and
  `rebrew cache clear` drops the entries a same-endpoint change leaves in
  place.
- No claim that a decomp.me upload is revocable. `POST /api/scratch` has no
  idempotency key and mints a public scratch, whose slug and `claim_token`
  exist only in the reply. A read timeout or dropped connection can therefore
  hide a create the service already committed, leaving the uploaded function
  source, ASM, and context in a public scratch that neither the analyst nor
  `rebrew` can claim or delete. `rebrew decompme` no longer re-POSTs after a
  post-send transport failure (`_never_delivered` in
  `src/rebrew/decompme.py`), so a single run does not mint a second orphan,
  but a hand-run retry still does, and the existing orphan is not discoverable
  from the CLI.
