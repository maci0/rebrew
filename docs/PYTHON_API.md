# Rebrew Python API

Install as a dependency (`uv add git+https://github.com/maci0/rebrew.git` or
`pip install` from the same URL). Import submodules directly. The same entry
points are also attributes of the package (`from rebrew import load_config`),
loaded on first use, and a star-import binds them along with `__version__`:

```python
from rebrew.config import load_config
from rebrew.compiler.compile import compile_and_compare
from rebrew.errors import RebrewError
from rebrew.sources import iter_sources
from rebrew.compiler.toolchain import TOOLCHAINS, get_toolchain
from rebrew.compiler.toolchain import ToolchainError

cfg = load_config()  # walks up for rebrew-project.toml
for path in iter_sources(cfg):  # a bare path works too: iter_sources("src/game")
    print(path)

try:
    get_toolchain(cfg.compiler_profile)  # e.g. "msvc-6.0"
except ToolchainError as exc:
    # Branch on exc.kind / exc.name / exc.retryable, not message substrings.
    raise

# The legal profile names are the registry, not a hardcoded list. TOOLCHAINS
# maps name -> ToolchainSpec, so a consumer can enumerate and inspect them
# with attributes rather than parsing `rebrew toolchain list` output:
for name, spec in sorted(TOOLCHAINS.items()):
    print(name, spec.family, spec.bits, spec.obj_ext, spec.image)

# `spec.withdrawn` is why a profile is not offered ("" when it is): a consumer
# listing the registry shows it as not offered and never runs it.  rebrew
# refuses a compile of one with `rebrew.compiler.toolchain.CompilerNotOffered`
# (`error_code` "compiler_withdrawn"; `rebrew.errors` exports the class).

# `list_toolchains()` is the other view of the same registry snapshot, one
# dict per profile, with `origin` (packaged vs plugin) and the docker-present
# flag on each row. Reach for it when you want those alongside the spec.
# `rebrew toolchain list --json` prints `{"toolchains": list_toolchains(), "docker_available": <bool>}`:
# the rows verbatim, wrapped in the envelope, so a consumer reads
# `payload["toolchains"]` rather than parsing the table out of a list.

# Byte-level matching uses the same entry as the CLI:
#   from rebrew.compiler.compile import CompareResult, CompareStatus, compile_and_compare
#   result = compile_and_compare(cfg, source_path, symbol, target_bytes, cflags)
#   result.matched / result.status / result.match_percent / result.message
#   `status` is a `CompareStatus` ("EXACT" / "RELOC" / "NEAR_MATCHING" /
#   "COMPILE_ERROR" / ...), so an annotation on it type-checks.
```

Remote compile transport, registry plugins, workspace helpers, and the GA
matcher follow the same pattern (`rebrew.compiler.recompile_client`, `rebrew.registry`,
`rebrew.app.plugin`, `rebrew.workspace`, `rebrew.matcher`). Component declarations,
scoped contexts, and teardown are documented in the [Cordis guide](CORDIS.md);
the [tutorial](CORDIS_TUTORIAL.md) exercises provider replacement with the public API.

Every error class is importable from `rebrew.errors`, whichever submodule
defines it. Catch the
specific type (`ConfigError`, `RecompileError`, `McpError`, `ToolchainError`,
`RegistryError`, ...) when the recovery differs per failure, and `RebrewError`
when it does not:

```python
try:
    result = compile_and_compare(cfg, source_path, symbol, target_bytes, cflags)
except RebrewError as exc:
    if exc.retryable:
        ...  # transient docker/daemon blip or transport hiccup
    raise

# The compile service gave no compiler verdict.
if result.status == "NOT_RUN" and result.error is not None:
    if result.error.retryable:
        ...  # retry according to the caller's schedule
    else:
        ...  # report result.error.kind or ask for another profile
# COMPILE_ERROR without a structured error means the compiler rejected the source.
```

Persisting that result keeps the decision: `CompareResult.to_dict()` writes
`error` through `RebrewError.to_dict()`, and `CompareResult.from_dict()`
reads it back as the same exception class, so `result.error.retryable` and
`result.error.kind` still work on a result loaded from JSON. `RebrewError`
gains the same `to_dict()` / `from_dict()` pair for any other error you store.

Every public rebrew error type inherits `RebrewError`. Many also inherit a
built-in exception such as `RuntimeError`, `ValueError`, `FileNotFoundError`,
or `KeyError`; some, including `OpsError` and `WorkspaceConfigError`, inherit
only `RebrewError`. The structured fields `kind`, `name`, `status_code` and
`group` are declared on that base too, so one `except RebrewError` can read
them without `getattr`; a field the arriving error does not fill is `None`,
and a serialized error leaves it out.

The clients that talk to a service take the HTTP client as an argument, so
your tests never need a live one. `HttpClient` (from `rebrew.compiler.recompile_client`
or `rebrew.decompme`) is the two-method shape those clients call: `.post` and
`.get`. The two protocols differ in signature: `recompile_client` takes
typed `json`/`headers`/`follow_redirects` keywords while `decompme` takes
`**kwargs`, so a stand-in for one does not fit the other unless it matches
that signature. What it returns is a reply, and that is typed too:
`HttpResponse` names the members each transport reads.
`rebrew.compiler.recompile_client` needs `status_code`, `text`, `json()`,
`content` (the artifact bytes) and `headers` (the Content-Length bound);
`rebrew.decompme` needs `status_code`, `text`, `json()` and `close()`,
because the module-level `httpx.post` / `httpx.get` reply owns a connection.
It does not require `content` or `headers`. An `httpx.Response` satisfies both,
and a stand-in missing a required member is a type error rather than a wrong
value at the far end:

```python
from rebrew.compiler.recompile_client import compile_source


class _Reply:
    """Satisfies rebrew.compiler.recompile_client.HttpResponse."""

    def __init__(self, status_code, *, json_body=None, content=b"", text="", headers=None):
        self.status_code = status_code
        self._json = json_body
        self.content = content
        self.text = text
        self.headers = {} if headers is None else headers

    def json(self):
        if self._json is None:
            raise ValueError("not json")
        return self._json


class FakeService:
    def post(self, url, **kwargs):
        return _Reply(200, json_body={"status": "ok", "artifact_url": "/api/v1/artifacts/1.obj"})

    def get(self, url, **kwargs):
        return _Reply(200, content=b"\x90" * 8)


result = compile_source(
    "http://localhost:8080",  # base URL
    "msvc-6.0",  # compiler
    "int f(void) { return 0; }",  # source
    ["/O2"],  # flags: a str is split on whitespace
    client=FakeService(),
)
print(result.ok, result.obj_bytes, result.log, result.compiler_version)

# No client means rebrew creates and closes one httpx.Client per attempt.
# `retries=N` re-attempts failures the answer table marks retryable, with
# exponential backoff and at least a reply's `Retry-After`; `retries=0` still
# allows capacity/throttle waits until `deadline=`, or 300 seconds without one.
# `RecompileError.kind` is "network" / "http" / "validation" / "protocol" /
# "service" / "deadline" (not sent: no time before the deadline), and
# `status_code` is set for the "http" ones. `gate=ServiceGate(n)` bounds
# concurrent attempts and applies a shared `Retry-After` hold-off.
# A failed compile reply is read by its `error_code`:
# "toolchain_failure" is `result.ok == False` with the compiler log; the
# service's own failures raise kind "service" carrying that `error_code`
# (retryable for capacity, runner_unavailable and publish_failed; timeout and
# provenance_unavailable are final). A reply without a known `error_code` is
# "protocol", resent under the same key like a lost reply.
# An HTTP refusal carries the body's `code` in `error_code` (recompile 11
# answers `{"detail", "code"}`); a code saying the key can never yield a result
# and billed nothing in every recompile release (`admission_abandoned`,
# `admission_expired`) is retried
# under a new key. `RecompileError.cost` is what the call's last key cost:
# "billed" (billed and no verdict reached the call: the download failed after
# ok, or billed_not_delivered, retained_output_unavailable, artifact_expired),
# "unknown" (it may have been billed and no answer said), or "free".
# Every `RecompileError` is no verdict on the source (`compile_and_compare`
# reads it as NOT_RUN); the toolchain's verdict is `result.ok == False`.
# `result.to_dict()` / `RecompileResult.from_dict()` store the verdict (not
# the object bytes) the way `CompareResult` does.
#
# `includes={"inc/a.h": text, ...}` and `source_dir="src"` send an include
# bundle: the service writes the headers at those paths and compiles the
# source in `source_dir`. Before the first POST the client reads the
# service's `GET /api/v1/features` (a stand-in answers it on `.get` too) and
# raises kind "validation" unless it lists "include-bundles";
# `accepts_include_bundles(base_url, client=...)` asks the same question.
#
# `installed_compilers(base_url, client=...)` reads `GET /api/v1/compilers`:
# the ids whose `execution_status` is "admitted", or None when no row is
# (recompile before 13) or the route answers 404. `compile_source` does not
# read it; a compiler the deployment has not installed is refused by the
# service, HTTP 400 with `error_code` "compiler_not_installed", unbilled.
#
# `rebrew.decompme`'s `upload_scratch` also accepts `client=` and `retries=N`,
# with the same backoff helper (`retry_backoff_delay` in `rebrew.utils`).
# Its retry policy is narrower: connect-stage failures and HTTP
# 408/425/429/503 can retry; read timeouts and HTTP 500/502/504 do not,
# because a public scratch may already have been created.
# Its `payload` is what `build_scratch_payload` returns (a `data` form mapping
# and a `files` multipart mapping); both keys are checked before
# the request is built, so a payload you assembled wrongly arrives as
# `kind="validation"`, not as a network failure a retry could chase.
```

The ReVa MCP client (`rebrew.ghidra`, the transport for
`rebrew sync create-functions`, `bookmarks`, and `pull-data`) injects
`McpHttpClient` instead: `post` and `delete`, because it
opens a session and terminates it on every exit path. Both take a `url` plus
`**kwargs` (the JSON-RPC `json=` body, the `headers` session id, the per-call
`timeout`), so a stand-in carrying those two methods satisfies it. The reply is
typed as `McpResponse` and has to carry `status_code`, `headers`, `text`,
`json()` and `raise_for_status()`. That is the `FakeService` above with `delete`
added, over a `_Reply` that also carries `headers` and `raise_for_status()`.
`close()` is absent from both the `recompile_client` and MCP reply protocols
(probed via `close_response`), so a stand-in holding no connection to release
is still a valid answer; only the `decompme` protocol requires `close()`.

An engine that serves retained requests beside rebrew (recoverage's coverage
ops) stages each request's snapshot as rebrew's own retained ops do, with these
three names from the op worker `rebrew.ops`, and serves its ops over HTTP with a
fourth, `OpsServer`; the rest of that module is the worker's own:

```python
from rebrew.config import load_config
from rebrew.errors import OpsError
from rebrew.ops import RetainedFile, WorkerConfig, retained_target_snapshot

config = WorkerConfig(filestore=filestore, workspace=workspace)
files = [RetainedFile(path=e.path, digest=e.digest, size=e.size, key=e.key, url=e.url) for e in manifest]
try:
    with retained_target_snapshot(config, files, target, sha256, binary_key, binary_url) as root:
        cfg = load_config(root, target=target)
except OpsError as exc:
    ...  # exc.code, exc.status: the refusal to answer
```

Each `RetainedFile` names its bytes by exactly one of a filestore `key` and a
presigned `url`. The snapshot is staged under `<workspace>/.scratch` and
removed when the block ends. Staging refuses a manifest over the readset
bounds, a repeated or non-portable path, bytes that do not match, a
`rebrew-project.toml` rebrew cannot load, config paths that leave the snapshot
(so a caller need not run `confined_snapshot_config` again), metadata that is
not one local backend, and a snapshot without its inventory and function
metadata; a block that ends without an exception is refused when it changed
the binary or a staged file.

`OpsServer(address, config, token, concurrency, allowed_hosts, *, ops=..., answer=...)`
is rebrew's op server (a `ThreadingHTTPServer`: bearer *token*, Host allow-list,
*concurrency* slots, `/health` and `/metrics`, progress streams, cancellation when
the caller leaves). *answer* answers every `POST /<name>`: called with *config*,
the name and the body, it returns `(status, reply bytes)`. *ops* is the names it
serves: they bound the per-op metrics (`op="/<name>"`, any other name
`/unknown`) and the server span names. An authenticated `GET` or `HEAD` on
`/health` and `/metrics` returns 200; other methods on those paths return 405.
A non-POST request to a served op returns 405 `Allow: POST`; any other path
returns 404 `unknown-op`. Both default to
rebrew's own op table and dispatcher:

```python
from rebrew.ops import OpsServer, WorkerConfig

def answer(config: WorkerConfig, name: str, body: bytes) -> tuple[int, bytes]:
    ...  # the engine's dispatcher: 404 for a name it does not serve

server = OpsServer(("127.0.0.1", 0), WorkerConfig(filestore, workspace), token, 4,
                   ops=ENGINE_OPS, answer=answer)
signal.signal(signal.SIGTERM, lambda _signum, _frame: server.request_stop())
try:
    server.serve_forever()
finally:
    server.server_close()
    left = server.drain(30)  # the calls still in flight after 30 s; 0 once all answered
```

The graceful stop is these two calls and nothing else of the server's state.
`request_stop()` refuses every new call 503 `worker-busy` and ends
`serve_forever()` from its own thread, so it is safe in a signal handler; a second
call changes nothing. `drain(timeout)` refuses new calls the same way, waits up to
*timeout* seconds for the calls in flight to answer, and returns how many are
still in flight. `rebrew ops serve` stops this way.

An engine exports its server's spans with `rebrew.telemetry.configure(endpoint,
service, version)`: it starts posting finished spans to the OTLP/HTTP collector at
*endpoint* (`<endpoint>/v1/traces`) under the service name and version, raises
`ValueError` for an endpoint that is not an `http(s)` URL with a host and without
credentials, and returns the shutdown to call when the server stops. Without it
the server's spans still continue the caller's `traceparent`, and nothing is
exported. These are the only telemetry names an engine uses.

The Python import surface is not frozen and has no deprecation window, so pin
the minor version if you import rebrew as a library. The full compatibility
policy is in [CONTRIBUTING.md](../CONTRIBUTING.md#versioning-and-releases).
