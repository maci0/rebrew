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

Rebrew is a local compiler-in-the-loop reversing workbench (CLI). It is not a multi-tenant network service. Two bearer-token network listeners exist, both plain HTTP: rebrew ops serve (workspace-confined write ops plus bearer-gated GET/HEAD `/health` and `/metrics` aggregates, `src/rebrew/ops.py` `_not_post` / `OpsServer.metrics_snapshot`; a browser-origin POST with a non-empty `Origin`/`Referer` is refused 403 `cross-origin` before the bearer check, and `/metrics` carries bounded per-op RED counters) and the Go jobs owner `rebrew-jobs` (`services/jobs/`, loopback `127.0.0.1:8089` by default, unauthenticated `GET/HEAD /healthz`+`/health` returning only `{"status":"ok"}`), `REBREW_JOBS_ADDR` to override only to another loopback address (non-loopback is refused at startup, `isLoopbackAddr` in `services/jobs/cmd/rebrew-jobs/main.go`), `REBREW_WORKSPACE`/`REBREW_JOB_DIR`/`REBREW_JOB_TOKEN` required (token at least 32 bytes, checked at startup, `services/jobs/cmd/rebrew-jobs/main.go`); `REBREW_MANAGED_RECOMPILE_URL`, when set, additionally requires a valid https-or-loopback upstream (`validateManagedUpstream`) plus `REBREW_MANAGED_COMPILE_LIMIT`/`REBREW_MANAGED_COMPILERS` with a non-blank list); the coverage dashboard is loopback by default and unauthenticated. The living attack-surface and trust-boundary
document is:

- [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md)

Operators should also treat operator-supplied backup/restore paths as trusted: `rebrew match solutions --backup <dir>` / `--restore <file>` copies `.rebrew/ga_runs.jsonl` off-tree (`src/rebrew/matcher/solutions.py` `backup_ga_runs` / `restore_ga_runs`), and the SQLite metadata backup/restore (`src/rebrew/metadata/sqlite.py`) and `rebrew metadata migrate` destination snapshot (`src/rebrew/metadata_transfer.py`) handle `rebrew-metadata.sqlite3` the same way.

The default TOML backup (`backup_metadata_toml` / `restore_metadata_toml` in `src/rebrew/metadata/sqlite.py`, walked recursively by `toml_store_trees` so a nested `metadata_dir` is covered and nested projects are skipped) additionally copies and installs the project `rebrew-project.toml`, so a TOML restore also overwrites the live project config (preserved as `.before-restore`) and can re-point `metadata_dir`, endpoints, and compiler settings for the next run; a config-only bundle is refused.

The same TOML/SQLite bundle also carries `.rebrew/decompme-uploads.json` when present (`_UPLOADS_REL` in `extra_durable_sources`, `src/rebrew/metadata/sqlite.py`; the decomp.me claim-token ledger, whose loss re-uploads already-claimed scratches inside the 90-day dedup window) and the `pgsql-before-transfer` snapshots (`.rebrew/pgsql-before-transfer/**/*.toml`, `_PGSQL_SNAPSHOT_DIR_REL`, the only copy of a destination a `metadata migrate pgsql` replaced), plus `.rebrew/extern-names.json` (`_EXTERN_NAMES_REL`), `.rebrew/name_to_va_cache.json` (`_NAME_TO_VA_CACHE_REL`), `.rebrew/verify_cache.json` (`_VERIFY_JSON_REL`), the BinSync state dir, and the target binary named by `rebrew-project.toml` (`_target_binary_relpaths`), a non-regenerable verification input (absolute and `..` entries are skipped). A complete recovery set also needs source backups, SQLite projects need a separate config copy, and excluded binary or BinSync paths need separate backups; see [backup and recovery](docs/METADATA.md#backup-and-restore).

Every `rebrew metadata backup` bundle carries a manifest (`rebrew-backup.manifest.json`, size+sha256 per file, `metadata/sqlite.py` `_write_backup_manifest`), and restore verifies it with `verify_backup_manifest` before installing anything, refusing a bundle with a missing/corrupt manifest or any missing/mismatched file.

The PostgreSQL metadata backend (dsn+project in project TOML, `src/rebrew/metadata/pgsql.py`) has no rebrew-side backup: `rebrew metadata backup`/`restore` reject it and require `pg_dump`/`pg_restore` (`src/rebrew/metadata_cli.py`; see `docs/METADATA.md` PostgreSQL backup and restore; `src/rebrew/doctor.py` `check_backup_readiness` warns).

Restores validate the payload and preserve the live store as `.before-restore` before replacing it, but nothing confines a backup destination or a restore source to the project: a restore file a hostile project planted is installed as the live store.

Operators should treat project source, configured HTTP endpoints
(recompile, LLM, ReVa MCP, decomp.me), GitHub release and toolchain-media
downloads (wibo, SDK tarballs), docker/podman images (`REBREW_CONTAINER_RUNTIME`),
cmake bridge wineprefix / profile pins (`REBREW_WINEPREFIX`, `REBREW_TOOLCHAIN`),
`REBREW_SKILLS_DIR` overlays, BinSync state-repo git remotes (`rebrew binsync pull` fast-forwards and imports by default; remote validated by `validate_remote()` in `binsync/git.py`: spaces/control chars, `..`, leading `-`/`+`, any `<transport>::` command transport such as `ext::`/`fd::` refused, blocking git option injection and command-transport execution), a foreign splat project handed to
`rebrew source import-splat` (its `splat.yaml` and `symbol_addrs` files are written into
the local project as metadata, source markers, and `library_<module>.h` names;
the command is a dry run unless `--apply` is passed), and installed Python
entry-point plugins
(including `rebrew.cache_backends`) as part of the trust boundary. So are the
host-tool knobs outside the `REBREW_` namespace: `KUNA_SPECS` names the
SLEIGH language definitions the native `kuna` binary parses in place of its
own, `XDG_CACHE_HOME` is
the sandbox base whose `rebrew`-prefixed directories older than a day are
deleted by `sweep_stale_temp_dirs` on the next compile
(`src/rebrew/compiler/temp_dirs.py`). That sweep is not confined to the cache base: it
also deletes, by the same age rule, directories under the project at
`.rebrew/climb` and `.rebrew/qualsweep`, where the prefix it matches is
declared by the caller and derived from the function's symbol name
(`src/rebrew/climb.py` `:911`, `src/rebrew/qual_sweep.py` `:294`), so a
symbol name in shipped metadata decides what a later run may remove from
those two rebrew-owned scratch directories, and nothing else. And
`XAUTHORITY` names the X cookie file rebrew
adopts for host-wine helpers and re-exports to wine children, accepted as any
file the analyst can read (`_local_cookie` in `src/rebrew/compiler/headless.py`), so the
headless-display access decision for adopted servers is taken from the process environment. On a multi-user host the headless X display is a boundary, and on **both**
of its paths the access control holds only for a server rebrew starts. The `Xvfb` rebrew starts is
handed an `-auth` file holding a real MIT-MAGIC-COOKIE-1 xauth record
(`_xauth_record` via `_new_cookie` in `src/rebrew/compiler/headless.py`), so the started
display refuses clients without the cookie; adopting an Xvfb already on the box is
still unauthenticated, because `_adopt` falls back to the operator's
`XAUTHORITY` when the candidate server advertises no `-auth`
cookie of its own. Nothing in the module opens an X connection to verify.
Treat an adopted display as unauthenticated, and note that
`XAUTHORITY` is written into `os.environ`, so every later child process
inherits it. The display's pid is resolved through `/proc/*/cmdline` on
the process name `Xvfb`, which is world-readable.

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
  (`rebrew.compiler.msvc16` / `tc16` / `delphi16` via `rebrew.compiler.dosbox`) are covered by
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
  `make -q` suppresses makefile recipes, not `$(shell …)` / `$(info …)`
  expansion while the file is read, so the `build.make` CMake generates for a
  cloned project is host-executable too.
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
  write outside the project, and no claim that a command other than the
  validator enforces it. The `file` identity field is a path, and one
  validator owns it on the compile/verify/rename/cross-import path:
  `contained_path` (`src/rebrew/sources.py`) resolves the
  value under `source_roots` (`reversed_dir`, then `shared_dir`, with the
  project `root` as the outer bound, since a shared-tree source is recorded
  `../`-prefixed relative to `reversed_dir`) and refuses an empty, absolute,
  or escaping value. `rebrew verify` (`verify.py` `verify_entry`, where a
  refused entry is recorded `MISSING_FILE`), that module's cache-validity
  read and deferred STATUS pass, the batch compile (`compiler/compile.py`
  `precompile_batch`), the blocker clear in `rebrew test`, the
  `rebrew build objdiff-driver` command (`objdiff_project.py`), `rebrew match partitions`,
  and every read and write in `rebrew source import-related` (`cross_import.py`
  `import_function`, `import_shared_function`, `promote_to_shared`) all
  resolve through it; `rebrew source rename` (`rename.py`, `rename_ops.py`) and
  the verify cache's patch refresh (`verify_cache.py`) keep their own
  resolve-and-compare. BinSync overlay also uses
  `contained_path` for source reads and signature/comment targets; prototype
  imports update the actual C signature through the AST and the importer's
  source-tree check. A corrupt BinSync state file is never silently treated
  as missing or empty: `load_artifact` / `load_many` in `binsync/serial.py`
  raise `ValueError` on unreadable/unparseable input (a missing file still
  returns `None` / `[]`), so export/import/pull fail closed instead of
  proceeding with empty state. What this does **not** claim: the shared validator's outer
  bound is the project `root`, so project-internal paths such as `.git/hooks/`,
  `rebrew-project.toml`, or `.rebrew/` can pass that validator. It says nothing
  about a project running host commands, which
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
  at all. The recompile bearer key, when set, is the one exception on that
  path: `REBREW_RECOMPILE_API_KEY` is read from the environment only (never
  from the project tree), `compile_source` in
  `src/rebrew/compiler/recompile_client.py` refuses it unless the service
  URL is `https` with no credentials/query/fragment, sends it only to the
  configured service and its same-origin artifact endpoint, and every
  compile POST carries a deterministic `Idempotency-Key` so retries and
  restarts dedup server-side instead of re-billing.
- No claim that a recompile endpoint only receives the source. The object it
  returns is written to the compile workdir and parsed for that run (LIEF's
  COFF parser, or host `objconv` on an OMF profile). It is not published into
  the compile cache: the service response has no image id, so a later run
  compiles again instead of replaying those bytes (`_cache_key_for` in
  `src/rebrew/compiler/compile.py`). The artifact body is capped at 30 MiB
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
  `_shared_recompile_client`/`_job_recompile_client`,
  `compiler/recompile_client.py`, `decompiler.py`, `skeleton.py`,
  `ghidra/client.py`, `ghidra/cli.py`, `ghidra/commands.py`), so ambient `*_proxy` is ignored there too; ops
  `_download` also passes `trust_env=False` (proxy env ignored) with
  `SSL_CERT_FILE`/`SSL_CERT_DIR` re-applied explicitly, so an
  operator-pinned CA bundle is not silently dropped. The OTLP span exporter
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
  `src/rebrew/utils.py`), so they bound memory too. The 30 MiB recompile
  artifact cap is checked after a buffered GET has received the whole body,
  so it refuses an oversized artifact but does not bound the memory spent
  receiving it.
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
- No claim that PostgreSQL schema-shape validation is re-run on every store
  operation. `PgsqlStore._present` (`src/rebrew/metadata/pgsql.py`) caches the
  four-catalog-query verdict per connection id, and first-use DDL
  (`pg_advisory_xact_lock` + `_DDL`, then dropping the cached `False` verdict)
  makes the transaction that creates the table see it; the advisory lock
  serializes DDL so the verdict cannot go stale mid-transaction, and a fresh
  connection re-validates. The cache does not change the schema pin itself
  (exact column list + PK/CHECK, `statement_timeout 30s`, redacted diagnostics).

## Hardened behavior

These are checked behaviors, not guarantees beyond their stated scope.

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
- **Splat path containment.** `splat_config._rel` (`splat_config.py:517-531`)
  resolves every `splat.yaml` path against the operator's base and raises
  `ValueError` on any that escape it (`is_relative_to`), so an absolute,
  `../..`, or backslash-separated entry is refused before any read or
  `shutil.copy2` into the project; `--apply` remains the only write opt-in.
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
  cannot emit non-strict JSON. Integer parsing goes through
  `utils.parse_int_literal` / `parse_c_integer_literal` (`src/rebrew/utils.py`):
  a `0x` prefix selects base 16, otherwise decimal (`010` is ten), ASCII digits
  only, across the binsync/catalog/prove/report/residue/switch call sites.
- **Ops download client lifetime.** `_download` (`src/rebrew/ops.py`) closes
  its `httpx.Client` through a context manager
  (`with httpx.Client(...) as _http: _http.stream(...)`); the SSRF pinning,
  `trust_env=False`, and `verify=` behavior above are unchanged.
