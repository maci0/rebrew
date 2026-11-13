# Local job owner (candidate)

This experimental owner starts `rebrew match run <seed> --json` from a private
copy of one configured workspace. Admission copies and hashes a bounded
regular-file tree, retains a sealed original, and launches from a separate
working copy. The caller must submit `workspace_sha256`, a lowercase full-tree
digest of the intended workspace, with each admission. Use
`rebrew-jobs workspace-digest PATH` to compute a pin before submitting it; a
missing or mismatched pin is refused before dispatch. Symlinks and non-regular
files are refused. Admission accepts `generations` from 1 to 10,000 and
`population` from 2 to 4,096; omitted values retain the CLI defaults of 100
and 64. Both are retained as part of the original request and checked on
replay. The owner retains up to 4 MiB of combined stdout and stderr with byte
count, truncation status and a digest, and publishes coalesced progress
snapshots over an authenticated loopback API. It does not replace the
existing Rebrew CLI or library.

The optional Docker provider requires a pinned image ID, a read-only original
mount, a separate working mount, no network, no daemon socket, read-only root,
dropped capabilities and bounded resources. It retains the exact container ID
before start and reports completion only after inspecting that same container's
exit and isolation. After a lost response, reconciliation may prove stop while
marking output incomplete. Once stop is proven, the complete result workspace
is copied, sealed and hashed before capacity is released. A changed retained
result refuses recovery. An optional owner-mediated Unix socket lets a
no-network job request pinned, budgeted managed compiles without exposing the
caller credential to the container. The owner retains each original request
and idempotency key before dispatch; ambiguous outcomes require an explicit
reconciliation with the original caller credential. The worker's capability
permits only its job's compile requests and returned artifact paths.

This is not ready for deployment. A file-by-file copy is not an atomic filesystem
snapshot, and same-user code can change the sealed original. The digest pins
the copied bytes but its creation still requires a trusted, quiescent source;
stronger custody is needed against same-user mutation. The direct local-process
provider cannot prove the whole process tree or a daemon-launched container
stopped, so its CLI exit remains uncertain and fences new jobs. A live owner's
queued job can be cancelled as never started. Docker cancellation is recorded
only after the exact container's stop or never-started state is inspected;
unresolved remote compiles also keep capacity fenced.

An isolated Platform and experimental Go Recompile pair passed a real compile
and artifact download, a lost-response recovery with one recorded usage unit,
and a bounded MinGW matching run. The matching run completed with `exact=false`;
it did not prove an exact byte match. The canonical Python Recompile pairing,
distributed execution, tenant authorization and independent settlement
verification remain unqualified. The loopback token authorizes one local owner;
it is not a tenant authorization boundary.

From the repo root, `make jobs-check` runs the CI jobs-service gate (gofmt, vet,
builds, `go test -race`) and `make jobs-build` builds `rebrew-jobs`. To qualify the isolated Docker
provider against a locally available image containing `/opt/venv/bin/rebrew`,
set `REBREW_TEST_DOCKER_IMAGE` to its full `sha256:` image ID. The executable
requires `REBREW_WORKSPACE`, `REBREW_JOB_DIR`, and a `REBREW_JOB_TOKEN` of at
least 32 bytes. Set `REBREW_BINARY` to an absolute CLI path for the direct
provider, or set `REBREW_DOCKER_BINARY` and `REBREW_JOB_DOCKER_IMAGE` for the
Docker candidate. It listens on `127.0.0.1:8089`; `REBREW_JOBS_ADDR` may move it to another
loopback address only (non-loopback is refused at startup). The job directory must be
private and outside the workspace. A single local owner holds an exclusive
filesystem lock. Reconnect to `/jobs/{id}/events` for retained state snapshots;
`/jobs/{id}/output` returns currently retained partial output. Output is not an
independently settled result.

To enable the candidate managed path, configure `REBREW_MANAGED_RECOMPILE_URL`,
`REBREW_MANAGED_COMPILE_LIMIT` (1..1000) and the comma-separated compiler IDs in
`REBREW_MANAGED_COMPILERS`. Include the scoped caller credential in the
`X-Rebrew-Compile-Credential` header on admission as the raw scoped API key,
in addition to the local job API token. The credential is held in owner memory,
never passed to the job.
List recovery identifiers with `GET /jobs/{id}/compile-intents`. Reconcile an
unresolved retained intent with `POST /jobs/{id}/compile-reconcile`, a JSON
body containing `intent`, and the same credential; afterward reconcile the
exact container stop. A changed
caller credential or managed configuration refuses recovery.

The experimental `catalog` kind admits `{"key":"…","kind":"catalog","workspace_sha256":"…"}` and executes the fixed command `rebrew coverage catalog --json` against the retained workspace. The project root must contain `rebrew-project.toml`; seed, match tuning and compile credentials are rejected. The existing output combines stdout and stderr and may be truncated, so it is not a standalone JSON response. Catalog is a report, not a durable corpus index; importing or exporting external state is not implemented by this kind.
