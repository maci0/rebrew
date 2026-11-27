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

Rebrew runs locally and processes project code, native binaries, and compiler
and decompiler inputs. It has three HTTP listeners. `rebrew ops serve` gates
operations, health, and metrics with a bearer token. The experimental jobs
service requires a bearer token for jobs and binds only to loopback. Its
liveness routes are public within that boundary. The coverage dashboard
defaults to loopback and serves coverage to any client that can reach it.
See the [threat model](docs/THREAT_MODEL.md#1-attack-surface-inventory)
for listeners, trusted inputs, and mitigations.

Use trusted backup and restore paths. A TOML restore replaces the live project
configuration and can change metadata and service settings for later runs.
Restore checks file digests against the bundle's manifest and preserves the
old store as `.before-restore`. The recovery guide lists which files the bundle
covers and what to back up separately. For PostgreSQL, use the database's
backup tools. See [backup and restore](docs/METADATA.md#backup-and-restore).

Operators control these trust boundaries.

- **Inputs and tools.** Rebrew trusts project source, configured HTTP services, release
  and toolchain-media downloads, container images, Wine prefix and compiler
  profile settings, skill overlays, and installed Python entry-point plugins.
  `KUNA_SPECS` selects the language definitions parsed by native `kuna`.
- **Imports.** `rebrew binsync pull` may fetch and import state. `validate_remote`
  in `binsync/git.py` rejects spaces, control characters, `..`, a leading `-` or
  `+`, and command transports such as `ext::` and `fd::`.
  `rebrew source import-splat` previews the foreign config and symbols by default.
  `--apply` writes metadata, source markers, and library headers.
- **Scratch directories.** `sweep_stale_temp_dirs` removes directories whose
  names match registered scratch prefixes under the cache base selected by
  `XDG_CACHE_HOME`. Project sweeps in `.rebrew/climb` and `.rebrew/qualsweep`
  derive a confined prefix from the function's symbol. Eligibility uses
  the newest subtree mtime, a 24-hour age threshold, and a one-hour
  clock-step allowance.
- **Headless X displays.** Rebrew starts Xvfb with a private
  MIT-MAGIC-COOKIE-1 file. It discovers candidate servers through
  `/proc/*/cmdline`. For an existing server without `-auth`, it may adopt a
  readable `XAUTHORITY` from the environment and pass it to later child
  processes. It does not verify access by opening an X connection, so treat
  an adopted display as unauthenticated on a multi-user host.

CI is a boundary of its own: `pull_request` (never `pull_request_target`),
workflow `permissions: contents: read`, `persist-credentials: false`,
and every third-party Action pinned by commit SHA. The one exception is the
`package` job in `ci.yml`, which carries per-job `attestations: write` and
`id-token: write` grants so its `actions/attest-build-provenance` step
records SLSA build provenance for the wheel, sdist and SBOM in Sigstore's
transparency log (`.github/workflows/ci.yml` `package:` job,
`tests/test_ci_pins.py` `test_package_job_attests_build_provenance`). Every
other job in both workflows stays on `contents: read` with no write grant. `secrets.GITHUB_TOKEN` is
never workflow-level `env`: in `ci.yml` it reaches only the resembl clone
step through the composite action's `github-token` input, and in
`.github/workflows/toolchain-sync.yml` it reaches the resembl clone step and
the nightly `check-updates` run. That workflow runs nightly and reports
toolchain pin drift without applying it. There is no publish step in this
repository: release files are attached to a GitHub release by hand from a
`dist/` the package job verified, so a release is not attributable to a
workflow run, and there is no package-index upload. CI signing is limited to the SLSA
build-provenance attestation for the `package` job's wheel, sdist and SBOM
(`dist/rebrew.cdx.json`) subjects: it records what the package job built, under the workflow's
Sigstore identity, and is not a signature over the manually attached release
files.

The packaged compile-cache backends refuse pickle deserialize
(`NoPickleDisk` in `src/rebrew/compiler/cache.py`); that does not attest
plugin cache backends or remove the open upstream diskcache advisory.

## Claims this policy does **not** make

- No claim of authentication or authorization on `rebrew coverage serve` (default
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
  runs share `docker_hardening_args()` in
  `src/rebrew/compiler/toolchain.py`: `--network=none` (no egress),
  `--cap-drop=ALL`, `--security-opt=no-new-privileges`,
  `--pids-limit=256`, `--memory=2g`, `--cpus=2`, plus `--pull=never`
  where the call site passes `pull=True` (the cmake bridge passes
  `pull=False`). `--read-only` is deliberately absent: toolchain images
  write a wineprefix under `/opt/wineprefix` and `$HOME` on every
  compile. None of that implies escape resistance. The compile path
  passes no `--user`, so the compiler runs as the image's default user;
  it mounts the project root read-only but can read all of it. The cmake
  bridge mounts the project root and wineprefix read-write.
- No claim that "docker-only" covers toolchains registered by an entry point
  or a `REBREW_TOOLCHAIN_OVERLAY_DIR` TOML file: a spec without `image` runs
  its `binary` on the host with the full process environment
  (`run_toolchain` in `src/rebrew/compiler/toolchain.py`).
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
  (`rebrew.compiler.msvc16` / `tc16` via `rebrew.compiler.dosbox`) are covered by
  the docker-only compile guarantee on the shipped CLI compile path.
  There is no `pdb_cvdump` module and no `REBREW_CVDUMP` setting. PDB reads
  on the shipped path run host `llvm-pdbutil`
  (`rebrew.pdb_info` / `rebrew.toolchain_detect`), not wine `cvdump.exe`.
- No claim that every shipped CLI command stays inside a container.
  `rebrew build calibrate-bss` executes the link command read from the project's
  `build/CMakeFiles/*/link.txt` and its `--compile-cmd` on the host,
  `rebrew build sweep-link-flags` executes that same `link.txt` command on the host,
  `rebrew build symbol-stubs --build-cmd` executes an operator-supplied build command on the host,
  `rebrew build check --objects` runs host `make -q -f <build.make>` in the
  build directory, and analysis helpers run host rizin/r2, kuna, objconv,
  llvm-pdbutil, diec, objdump, and nasm against target binaries. Linked-exe GA
  (`match_ga.py` `_compile_source` / `matcher/compiler.py` `build_candidate`)
  runs that host compiler only when the profile has no docker image; a
  profile whose spec has an image raises instead of starting host wine.
  `rebrew doctor` smoke-runs host wine or wibo plus `CL.EXE` only on that
  same image-less path (`check_compiler`); a docker-backed profile returns
  before the smoke. Treat a project tree from an untrusted source as able
  to run code on the host through the paths that do execute.
  Query mode still evaluates makefiles. The preflight rejects recognized
  executing forms and computed include names. Use `--objects` only with trusted
  build files. See the [host build boundary](docs/THREAT_MODEL.md#project-tree--host-process).
- No claim that reading a project's build files stays inside the project
  directory, except the cmake bridge's `@rsp` rewrite. That rewrite reads
  response files on the host and stages the copy in a temporary directory
  inside the read-write project root, but each `@` path must resolve to a
  regular file inside the project (`rebrew-project.toml` root): an absolute
  or `..` path outside it, a symlink (even to an in-project target), a
  directory, device or fifo, or a file over 8 MiB (`_MAX_RESPONSE_BYTES`)
  is refused before it is copied (`src/rebrew/cmake_tc.py`
  `_response_source` / `_rewrite_response_files`, called from `_docker_run`
  and `_unshare_run`). The bound is the project root, not a narrower build
  directory, so a regular file already inside the tree can still be read
  and rewritten into that staging directory.
- No claim that a cloned project's metadata can make rebrew read or
  write outside the project, and no claim that one validator covers every
  join of the `file` field. Two checks exist, and neither runs everywhere.
  `validate_identity_file` (`src/rebrew/metadata/source_schema.py`) rejects
  a value that starts with `/`, carries a drive letter, or contains a `..`
  part. It runs when a row is written and when either compiled-source
  binder reads one (`function_providers.py` `bind_compiled_source`,
  `_bind_compiled_row`), not on every read of a hand-edited store;
  `rebrew lint` W034 reports the rows it would refuse. `contained_path`
  (`src/rebrew/sources.py`) resolves a value under `source_roots` (`reversed_dir`, then `shared_dir`,
  with the project `root` as the outer bound, since a shared-tree source is
  recorded `../`-prefixed relative to `reversed_dir`) and refuses an empty
  value, one `Path.is_absolute()` accepts, or one that resolves outside
  every root. `rebrew verify` (`verify.py` `verify_entry`, where a refused
  entry is recorded `MISSING_FILE`), that module's cache-validity read and
  deferred STATUS pass, the batch compile (`compiler/compile.py`
  `precompile_batch`), the `rebrew build objdiff-driver` command
  (`objdiff_project.py`), `rebrew match partitions`, every read and write in
  `rebrew source import-related` (`cross_import.py` `import_function`,
  `import_shared_function`, `promote_to_shared`), and `rename.py`
  `_row_source` all resolve through it. `rebrew test` does not join `file`.
  The compiled-source fast path (`_bind_compiled_row`) does not resolve
  the joined path or make the `is_relative_to(root)` check that
  `bind_compiled_source` makes: after `validate_identity_file`, it trusts a
  base lexically inside the project and falls back to
  `bind_compiled_source` when the source or a parent directory is a
  symlink. `contained_path`'s absolute test does not see an `X:` drive
  spelling on POSIX, and `join_under` (`src/rebrew/utils.py`) returns one
  unchanged on every host; `validate_identity_file` refuses that spelling
  before either binder joins it. `rename_ops.py` `_Project` joins
  `reversed_dir / filepath` with no check of its own; that `filepath` comes
  from `bind_compiled_source`, already bounded by the project root. The
  verify cache's patch refresh (`verify_cache.py`
  `patch_verify_cache_entries`) resolves a cache entry's `filepath` and
  skips the hash refresh when it lands outside `reversed_dir`.
  BinSync overlay uses `contained_path` for source reads and
  signature/comment targets; prototype imports update the actual C signature
  through the AST and the importer's source-tree check. A corrupt BinSync
  state file is never silently treated as missing or empty: `load_artifact`
  / `load_many` in `binsync/serial.py` raise `ValueError` on
  unreadable/unparseable input (a missing file still returns `None` / `[]`),
  so export/import/pull fail closed instead of proceeding with empty state.
  What this does **not** claim: the shared validator's outer bound is the
  project `root`, so project-internal paths such as `.git/hooks/`,
  `rebrew-project.toml`, or `.rebrew/` can pass that validator. It says
  nothing about a project running host commands, which
  [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) §5 covers separately.
- No claim that `REBREW_CONTAINER_RUNTIME` is restricted to a container
  runtime rebrew trusts. `container_runtime` (`src/rebrew/utils.py`) rejects
  characters outside `^[a-zA-Z0-9_\-\./]+$`, any name outside
  `docker` / `podman` / `nerdctl` when the value carries no path separator,
  and any relative path (a value containing `/` must start with `/`, so
  `./evil` resolving against the project cwd is refused). That is a typo
  guard: an absolute path is spawned as the binary, so
  `REBREW_CONTAINER_RUNTIME=/tmp/evil` remains a full redirection of every
  container run.
- No claim that the project tree cannot redirect outbound traffic. A
  project's `[compiler] recompile_url` applies unless `REBREW_RECOMPILE_URL`
  is set, and its `[llm] endpoint` overrides `REBREW_LLM_ENDPOINT`, so a
  cloned project chooses where the function **source** is sent
  (`recompile_url` in `src/rebrew/compiler/compile.py`, `llm_config` in
  `src/rebrew/llm_seed.py`). The one thing the project cannot take is the
  operator's **environment** key: `llm_config` refuses to send
  `REBREW_LLM_API_KEY` to a non-loopback `[llm].endpoint` unless
  `REBREW_LLM_ALLOW_PROJECT_ENDPOINT=1` is set
  (`_project_endpoint_allowed` in `src/rebrew/llm_seed.py`). That gate reads
  the key's provenance, so a key committed in the project TOML still travels
  to that project's own endpoint, and `[compiler] recompile_url` is not gated
  at all. `REBREW_RECOMPILE_API_KEY` comes from the environment and goes to
  the configured service and its same-origin artifact endpoint. It requires
  HTTPS or the explicitly configured in-cluster HTTP host. Direct compile
  calls generate a fresh idempotency key. Eligible retries within the call
  reuse it after an ambiguous outcome. Managed jobs persist their own
  attempt keys for recovery. See [remote compile](docs/TOOLCHAIN.md#compile-backends)
  and the [jobs service](services/jobs/README.md).
- No claim that a recompile endpoint only receives the source. The object it
  returns is written to the compile workdir and parsed for that run (LIEF's
  COFF parser, or host `objconv` on an OMF profile). It is not published into
  the compile cache: the service response has no image id, so a later run
  compiles again instead of replaying those bytes (`_cache_key_for` in
  `src/rebrew/compiler/compile.py`). The artifact body is capped at 32 MiB
  (`_MAX_ARTIFACT_BYTES` in `src/rebrew/compiler/recompile_client.py`,
  declared-length and buffered-length checked before the object is written to
  disk and parsed, after the GET has buffered the body, so memory is not
  bounded). The compile
  cache `size_limit` still bounds locally compiled objects only, and that
  limit is project-supplied: the 500 MiB default (`_DEFAULT_SIZE_LIMIT` in
  `src/rebrew/compiler/cache.py`) is replaced by `[cache] size_limit_mib` from
  `rebrew-project.toml` with no upper clamp (`cache_size_limit` in
  `src/rebrew/config.py`).
- No claim that a decomp.me upload is revocable, or that it leaves the host
  over TLS. `POST /api/scratch` has no
  idempotency key and mints a public scratch, whose slug and `claim_token`
  exist only in the reply. A read timeout or dropped connection can therefore
  hide a create the service already committed, leaving the uploaded function
  source, ASM, and context in a public scratch that neither the analyst nor
  `rebrew` can claim or delete. `rebrew export decompme` does not re-POST after a
  post-send transport failure (`_never_delivered` in
  `src/rebrew/decompme.py`), so a single run does not mint a second orphan,
  but a hand-run retry still does, and the existing orphan is not discoverable
  from the CLI. `validate_http_url` admits plain `http` to any host, so a
  non-TLS `--api` sends the function source, its object, and the returned
  `claim_token` in cleartext.
- No claim that a decomp.me or other outbound URL is pinned in transport.
  The wibo asset and metadata fetches, the toolchain media download, and the
  `GH_TOKEN`-bearing GitHub commit lookup pass `trust_env=False`, so their
  httpx calls ignore `HTTPS_PROXY`, `SSL_CERT_FILE`, and
  `REQUESTS_CA_BUNDLE`. The recompile, decomp.me, MCP and LLM clients also pass
  `trust_env=False` on their own clients (`compiler/compile.py`
  `_shared_recompile_client`,
  `compiler/recompile_client.py`, `decompiler.py`, `skeleton.py`,
  `ghidra/client.py`, `ghidra/cli.py`, `ghidra/commands.py`), so ambient `*_proxy` is ignored there too; ops
  `_download` follows the worker's IP-pinning policy below. The OTLP span exporter
  (`src/rebrew/telemetry.py`) is not an httpx client: its `urllib.request`
  POST goes through an opener built with `ProxyHandler({})`, so ambient
  `*_proxy` variables cannot reroute it either; `REBREW_OTLP_ENDPOINT`
  admits plain `http`, so a non-loopback collector still receives spans
  (trace/span ids, op names, status codes; no source or credentials) in
  cleartext, and the endpoint is operator env, not project configuration.
  The wibo asset is capped at
  64 MiB (`_MAX_WIBO_DOWNLOAD_BYTES` in `src/rebrew/wibo.py`), its release
  digest is shape-validated before the GET (exactly 64 hex, lowercased,
  else refused, `src/rebrew/wibo.py`), the
  release-metadata JSON at 1 MiB (`_MAX_WIBO_METADATA_BYTES` in
  `src/rebrew/wibo.py`, declared length checked, then a running cap while
  the body streams in, before `json` parsing), and the toolchain media at 2 GiB
  (`_MAX_PINNED_DOWNLOAD_BYTES` in `src/rebrew/toolchain_cli.py`), and the
  GitHub commit lookup reply (`_live_commit_sha`, the bare sha requested as
  `application/vnd.github.sha`) at 1 MiB (`_MAX_LIVE_SHA_BYTES` in
  `src/rebrew/toolchain_cli.py`, declared length checked, then a running
  cap while the body streams in; anything but 40 lowercase hex is refused). These caps
  apply while the body streams in (`read_capped_body` in
  `src/rebrew/utils.py`), so they bound memory during the download.
- No claim that the ops worker's presigned-URL download is SSRF-proof.
  `_download` in `src/rebrew/ops.py` refuses a `url` that is not https, a
  hostless URL, or a URL carrying userinfo (`parts.username or
  parts.password`), and refuses a `url` host that resolves to a
  non-public address: `_check_download_host` resolves the hostname and
  refuses any non-`is_global` address (IP literals checked the same way)
  and any resolution failure. The refusal is bypassed only by the operator
  env `REBREW_OPS_ALLOW_PRIVATE_DOWNLOAD=1`, parsed strictly by
  `parse_env_bool` (`src/rebrew/config.py` `ALLOW_PRIVATE_DOWNLOAD_ENV`)
  and validated at startup by `env_knob_errors`, so `0`/`false`/`no`/`off`
  keep the refusal and a typo is a `ConfigError` rather than a silent
  bypass; the opt-in is worker env, never request data, so a bearer holder
  cannot grant it. `_check_download_host` returns the validated public
  address and `_download` pins it for the fetch (IP literal, original
  `Host` header and `sni_hostname` so TLS verifies against the DNS name),
  so a DNS name that flips from public to private between the check and
  the `httpx` GET cannot reach a private host. The DNS resolution itself
  is bounded to 10 s (`DNS_TIMEOUT_SECONDS`, a daemon thread in
  `_check_download_host`) so a hung resolver cannot pin a worker slot; a
  proxy resolving the name itself is not a bypass, because
  `_download` passes `trust_env=False` (ambient `*_proxy` ignored) while
  re-applying an operator-pinned `SSL_CERT_FILE`/`SSL_CERT_DIR`
  explicitly via `verify=`.

## Hardened behavior

These are checked behaviors, not guarantees beyond their stated scope.

- **PostgreSQL schema validation.** `PgsqlStore._present` checks the exact
  columns, primary key, and both CHECK constraints. It caches successful
  checks per connection and revalidates on a fresh connection. An advisory
  lock serializes first-use DDL. Queries have a 30-second statement timeout
  and diagnostics are redacted.
- **Host header folding.** Both sides of the Host allow-list comparison are
  folded through `fold_host` (`src/rebrew/utils.py`), which runs
  `strip_bidi_format` after NFC normalization and before casefold/IDNA, so a
  spelling variant does not bypass the allow-list. Ops error/reply text is
  bidi-stripped the same way (`error_body` and `_bounded` in
  `src/rebrew/ops.py`).
- **OTLP endpoint validation at startup.** `OTLP_ENDPOINT_ENV` in
  `src/rebrew/config.py` is `validate_http_url`-checked in
  `_env_knob_parsers` / `env_knob_errors` (reported by `rebrew cfg
  effective`), and `src/rebrew/telemetry.py` `ENDPOINT_ENV` aliases that
  single source. The endpoint still admits plain `http` (above).
- **Splat path containment.** `splat_config._rel` resolves paths against the
  operator's base and refuses input paths outside it, including paths
  that escape through a symlink. `--apply` enables writes to the project.
- **`rebrew build check --objects` include probe.** The probe refuses when
  `build.make` or any file it includes carries make function expansion:
  `_MAKE_INCLUDE_RE` in `src/rebrew/build_check.py` matches `-s?include`
  (including `sinclude`), and `_probe_expansion` recurses the include graph,
  depth-capped at 32 with cycle tracking, refusing a computed (`$`-bearing)
  include name outright. A makefile naming its own programs without function
  expansion remains the disclosed residual; see `docs/THREAT_MODEL.md` §5.
- **No `PATH` lookup for native toolchain binaries.** Image-less
  (plugin/overlay) toolchains resolve vendored-only: `compiler/toolchain.py`
  `_resolve_binary` has no `shutil.which` fallback, and a binary name
  containing a path separator or NUL is rejected, so a hostile project cannot
  plant `cl` on `PATH` to hijack the lookup.
- **Strict JSON and integer parsing.** `json_print` (`src/rebrew/cli.py`)
  passes `allow_nan=False` on both tty and pipe paths, so `NaN`/`Infinity`
  cannot emit non-strict JSON. `utils.parse_int_literal` treats `010` as
  decimal ten by default.
  `utils.parse_c_integer_literal` follows C syntax and reads it as octal eight.
- **Ops download client lifetime.** `_download` closes its `httpx.Client`
  through a context manager.
