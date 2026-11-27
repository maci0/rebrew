# Rebrew Python API

Install as a dependency (`uv add git+https://github.com/maci0/rebrew.git` or
`pip install` from the same URL). Import from the owning submodule.
Selected entry points, such as `load_config`, are also available from
`rebrew` and load on first use.

## Configuration, toolchains, and byte comparison

```python
from rebrew.config import load_config
from rebrew.compiler.compile import compile_and_compare
from rebrew.errors import RebrewError
from rebrew.source.discovery import iter_sources
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

for name, spec in sorted(TOOLCHAINS.items()):
    print(name, spec.family, spec.bits, spec.obj_ext, spec.image)
```

`TOOLCHAINS` maps profile names to `ToolchainSpec` objects. A nonempty
`spec.withdrawn` explains why compiling with that profile raises
`CompilerNotOffered` with `error_code="compiler_withdrawn"`.

`list_toolchains()` returns one dictionary per profile, including `origin`.
Each row repeats the same Docker availability flag under `docker`.
`rebrew toolchain list --json` returns this shape:
`{"toolchains": list_toolchains(), "docker_available": <bool>}`.

`compile_and_compare(cfg, source_path, symbol, target_bytes, cflags)` returns
a `CompareResult` with `matched`, `status` (`CompareStatus`), `match_percent`,
and `message`.

Remote compile transport, registry plugins, workspace helpers, and the GA
matcher follow the same pattern (`rebrew.compiler.recompile_client`, `rebrew.registry`,
`rebrew.app.plugin`, `rebrew.workspace`, `rebrew.matcher`). Component declarations,
scoped contexts, and teardown are documented in the [Cordis guide](CORDIS.md);
the [tutorial](CORDIS_TUTORIAL.md) exercises provider replacement with the public API.

## Errors and retry decisions

Every error class is importable from `rebrew.errors`. Catch the specific
type (`ConfigError`, `RecompileError`, `McpError`, `ToolchainError`,
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
# For COMPILE_ERROR without a structured error, read result.message.
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

## HTTP clients and test doubles

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
    "https://recompile.example.invalid",  # base URL
    "msvc-6.0",  # compiler
    "int f(void) { return 0; }",  # source
    ["/O2"],  # flags: a str is split on whitespace
    client=FakeService(),
)
print(result.ok, result.obj_bytes, result.log, result.compiler_version)
```

`compile_source` creates and closes a client per attempt when no client is
supplied. A shared `ServiceGate(n)` bounds concurrency and applies the
service's `Retry-After` hold-off. Capacity, runner-unavailable, and throttle waits are bounded
by `deadline`, or 300 seconds without one. The `retries` count applies to
other retryable failures. See [remote compile behavior](TOOLCHAIN.md#compile-backends).

A toolchain failure returns `result.ok == False` with the compiler log.
A service or transport failure raises `RecompileError` without a byte
verdict. `compile_and_compare` maps that outcome to `NOT_RUN`. Read
`kind`, `status_code` (HTTP errors), `error_code`, `retry_after`, and
`cost` (`free`, `billed`, or `unknown`) for retry and billing decisions.
`result.to_dict()` and `RecompileResult.from_dict()` preserve the verdict
without the object bytes.

Passing `includes` or `source_dir` requires the service to advertise
`include-bundles` at `GET /api/v1/features`. A test client must provide
that response too. `accepts_include_bundles()` checks the same capability.
`installed_compilers()` reads the admitted compiler IDs from
`GET /api/v1/compilers` and returns `None` for an unsupported listing.
The compiler itself can still be refused with `compiler_not_installed`.

`rebrew.decompme.upload_scratch` accepts a test client and a retry count.
Build its `data` and `files` mappings with `build_scratch_payload`.
Invalid mappings fail validation before a request. Connect-stage errors
and HTTP 408, 425, 429, or 503 may retry. Read timeouts and HTTP 500,
502, or 504 are final because the first request may have created a scratch.

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

## Retained snapshots and worker servers

An engine that serves retained requests beside rebrew (recoverage's coverage
ops) stages each request's snapshot as rebrew's own retained ops do, with these
helpers from `rebrew.ops`. This fragment takes the filestore, workspace, and
manifest from the caller.

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

`OpsServer(address, config, token, concurrency, allowed_hosts=frozenset(), *, ops=..., answer=...)`
is rebrew's op server (a `ThreadingHTTPServer`: bearer *token*, Host allow-list,
*concurrency* slots, `/health` and `/metrics`, progress streams, cancellation when
the caller leaves). *answer* answers every `POST /<name>`: called with *config*,
the name and the body, it returns `(status, reply bytes)`. *ops* is the names it
serves: they bound the per-op metrics (`op="/<name>"`, any other name
`/unknown`) and the server span names. `ops` and `answer` default to Rebrew's
op table and dispatcher. An authenticated `GET` or `HEAD` on
`/health` and `/metrics` returns 200; other methods on those paths return 405.
A non-POST request to a served op returns 405 `Allow: POST`; any other path
returns 404 `unknown-op`. This fragment uses the caller's token,
workspace, filestore, operation table, and dispatcher.

```python
import signal

from rebrew.ops import OpsServer, WorkerConfig

config = WorkerConfig(filestore=filestore, workspace=workspace)
server = OpsServer(("127.0.0.1", 0), config, token, 4, ops=ENGINE_OPS, answer=engine_dispatcher)
signal.signal(signal.SIGTERM, lambda _signum, _frame: server.request_stop())
try:
    server.serve_forever()
finally:
    server.server_close()
    left = server.drain(30)  # the calls still in flight after 30 s; 0 once all answered
```

Use `request_stop()` and `drain()` for graceful shutdown.
`request_stop()` refuses new operation admissions with 503 `worker-busy` and ends
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
