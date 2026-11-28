# Local jobs service

The experimental jobs service runs matching or catalog jobs in a private
copy of one workspace. It serves an authenticated loopback API.

## Setup

From the repo root, `make jobs-check` runs the CI jobs-service gate (gofmt, vet,
builds, `go test -race`) and `make jobs-build` builds `rebrew-jobs`. To qualify the isolated Docker
provider against a locally available image containing `/opt/venv/bin/rebrew`,
set `REBREW_TEST_DOCKER_IMAGE` to its full `sha256:` image ID. The executable
requires `REBREW_WORKSPACE`, `REBREW_JOB_DIR`, and a `REBREW_JOB_TOKEN` of at
least 32 bytes. Set `REBREW_BINARY` to an absolute CLI path for the direct
provider, or set `REBREW_DOCKER_BINARY` and `REBREW_JOB_DOCKER_IMAGE` for the
Docker provider. It listens on `127.0.0.1:8089`; `REBREW_JOBS_ADDR` may move it to another
loopback address only (non-loopback is refused at startup). The job directory must be private and outside the workspace.

The service creates a missing job directory. On Unix, the owner verifies
private mode bits and locks the directory for exclusive use. On Windows,
the caller must ensure single-process ownership and private access.

## Admission and results

For matching, the owner starts `rebrew match run <seed> --json` from a private
copy of one configured workspace. Admission copies and hashes a bounded
regular-file tree, retains a sealed original, and launches from a separate
working copy. The caller must submit `workspace_sha256`, a lowercase full-tree
digest of the intended workspace, with each admission. Use
`rebrew-jobs workspace-digest PATH` to compute a pin before submitting it; a
missing or mismatched pin is refused before dispatch. Symlinks and non-regular
files are refused. Admission accepts `generations` from 1 to 10,000 and
`population` from 2 to 4,096; omitted values retain the CLI defaults of 100
and 64. Both are retained as part of the original request and checked on
replay, together with the selected provider and pinned image. The owner retains
up to 4 MiB of combined stdout and stderr with byte
count, truncation status and a digest, and publishes coalesced progress
snapshots over an authenticated loopback API. It does not replace the
existing Rebrew CLI or library.

The tree limit is 10,000 non-root entries and 256 MiB of file contents.
An admission interrupted before its receipt is durable can be
retried under the same key; custody is discarded only when the compile ledger
proves no attempt was sent. Reconnect to `/jobs/{id}/events` for retained state snapshots;
`/jobs/{id}/output` returns currently retained partial output. Output is not an
independently settled result.

The experimental `catalog` kind admits `{"key":"…","kind":"catalog","workspace_sha256":"…"}` and executes the fixed command `rebrew coverage catalog --json` against the retained workspace. The project root must contain `rebrew-project.toml`; seed, match tuning and compile credentials are rejected. The existing output combines stdout and stderr and may be truncated, so it is not a standalone JSON response. Catalog is a report, not a durable corpus index; importing or exporting external state is not implemented by this kind.

## Docker execution and recovery

The optional Docker provider requires a pinned image ID, a read-only original
mount, a separate working mount, no network, no daemon socket, read-only root,
dropped capabilities and bounded resources. It retains the exact container ID
before start and reports completion only after inspecting that same container's
exit and isolation. After a lost response, reconciliation may prove stop while
marking output incomplete. Once stop is proven, the complete result workspace
is copied, sealed and hashed before capacity is released. A changed retained
result refuses recovery. A container still running at the 10-minute run
timeout, or when the owner closes, is killed and then inspected. Once a stop
proof is durable, the owner removes the container and the `<id>.workspace`
working copy; `<id>.original`, `<id>.result` and `<id>.output` stay.

A job that fails before its container or process starts (a changed retained
original, existing workspace custody, a failed or timed-out `docker create`)
is retained as `failed` with `never_started` and releases capacity and its
compile mediator. After a failed create the owner removes any container left
under the fixed name `rebrew-job-<id>`; that container was never started.

## Managed compiles

Managed compiles require the Docker provider. Configure `REBREW_MANAGED_RECOMPILE_URL`,
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

The limit applies to each job.

An owner-mediated Unix socket lets a
no-network job request pinned, budgeted managed compiles without exposing the
caller credential to the container. The owner retains each compile intent's
request and the Idempotency-Key of its current attempt before dispatch, and
counts each intent once against the budget; a spent budget answers 403. A
fresh refusal that proves no compile ran (a 4xx such as a 429 throttle, or a
200 whose `error_code` is `capacity`, `timeout`, `runner_unavailable`,
`publish_failed` or `provenance_unavailable`) reaches the worker with its
status and `Retry-After` (and recompile's error `code`, which the mediator
relays). It is not kept as the intent's result, so the next attempt draws a
new key.
Only `admission_abandoned` and `admission_expired` prove that a key billed
nothing and can never yield a result, so they settle even an unresolved
attempt. A refusal that may follow a billed compile, or asks for the same key,
keeps it for the intent's next attempt, also on its first exchange: a 401, 403,
408 or 425, `admission_conflict`, `admission_unrecoverable`,
`retained_output_unavailable`, `result_unavailable`, `artifact_expired`,
`workbench_plan_required` or `account_under_review`. An ambiguous outcome (no
answer, a 5xx, a reply that is unreadable or over 16 MiB) also keeps the key:
the worker's retry resends it, which recompile answers without compiling or
billing twice. One intent's state never holds back another's. After the job
stops, an intent still unresolved fences its capacity until an explicit
reconciliation with the original caller credential resends that key. The
worker's capability permits only its job's compile requests, their returned
artifact paths, and
`GET /api/v1/features`, which the owner answers from the upstream without its
credential so the worker can check for include bundles before it sends one, and
`GET /api/v1/compilers`, answered the same way but cut to the rows of the job's
own compilers, so the worker sends none the upstream's deployment has not
installed (`execution_status`); a compile request's `includes` and `source_dir`
pass through unchanged. The
`X-Relumea-Attribution` header of the request that creates an intent is
retained with it and sent on every attempt, a reconciliation's included; one
that is not rebrew's attribution object (exactly `org`, `project`, `user` and
`job`, each 1 to 128 printable ASCII characters) answers 400 before anything
is sent.

## Deployment limits

This service is experimental. A file-by-file copy is not an atomic filesystem
snapshot, and same-user code can change the sealed original. The digest pins
the copied bytes but its creation still requires a trusted, quiescent source;
stronger custody is needed against same-user mutation. The direct local-process
provider cannot prove the whole process tree or a daemon-launched container
stopped, so its CLI exit remains uncertain and fences new jobs. A live owner's
queued job can be cancelled as never started. Cancelling a running or
`uncertain` Docker job kills its exact container. Docker cancellation is recorded
only after the exact container's stop or never-started state is inspected;
unresolved remote compiles also keep capacity fenced.

An isolated Platform and experimental Go Recompile pair passed a real compile
and artifact download, a lost-response recovery with one recorded usage unit,
and a bounded MinGW matching run. The matching run completed with `exact=false`;
it did not prove an exact byte match. The canonical Python Recompile pairing,
distributed execution, tenant authorization and independent settlement
verification remain unqualified. The loopback token authorizes one local owner;
it is not a tenant authorization boundary.
