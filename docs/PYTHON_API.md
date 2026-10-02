# Rebrew Python API

Install as a dependency (`uv add git+https://github.com/maci0/rebrew.git` or
`pip install` from the same URL). Import submodules directly. The same entry
points are also attributes of the package (`from rebrew import load_config`),
loaded on first use, and a star-import binds them along with `__version__`:

```python
from rebrew.config import load_config
from rebrew.compile import compile_and_compare
from rebrew.errors import RebrewError
from rebrew.sources import iter_sources
from rebrew.toolchain import ToolchainError, get_toolchain

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
from rebrew.toolchain import TOOLCHAINS, get_toolchain

for name, spec in sorted(TOOLCHAINS.items()):
    print(name, spec.family, spec.bits, spec.obj_ext, spec.image)

# `list_toolchains()` is the other view of the same table, one dict per
# profile, with `origin` and the docker-present flag on each row. Reach for it
# when you want those alongside the spec. `rebrew toolchain list --json`
# prints `{"toolchains": list_toolchains(), "docker_available": <bool>}`:
# the rows verbatim, wrapped in the envelope, so a consumer reads
# `payload["toolchains"]` rather than parsing the table out of a list.

# Byte-level matching uses the same entry as the CLI:
#   from rebrew.compile import CompareResult, CompareStatus, compile_and_compare
#   result = compile_and_compare(cfg, source_path, symbol, target_bytes, cflags)
#   result.matched / result.status / result.match_percent / result.message
#   `status` is a `CompareStatus` ("EXACT" / "RELOC" / "NEAR_MATCHING" /
#   "COMPILE_ERROR" / ...), so an annotation on it type-checks.
```

Remote compile transport, registry plugins, workspace helpers, and the GA
matcher follow the same pattern (`rebrew.recompile_client`, `rebrew.registry`,
`rebrew.plugin`, `rebrew.workspace`, `rebrew.matcher`). Every error class is
importable from `rebrew.errors`, whichever submodule defines it. Catch the
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

# A remote recompile failure does not raise: it is a COMPILE_ERROR result
# with the structured error attached, so the retry decision survives the
# compile boundary.
if result.status == "COMPILE_ERROR" and result.error is not None:
    if result.error.retryable:
        ...  # compile service unreachable / 503 - retry later
    else:
        ...  # the service rejected the request; rebrewing the C will not help
```

Persisting that result keeps the decision: `CompareResult.to_dict()` writes
`error` through `RebrewError.to_dict()`, and `CompareResult.from_dict()`
reads it back as the same exception class, so `result.error.retryable` and
`result.error.kind` still work on a result loaded from JSON. `RebrewError`
gains the same `to_dict()` / `from_dict()` pair for any other error you store.

Every rebrew error type inherits `RebrewError` alongside its original
`RuntimeError`/`ValueError` base, so a new error type in a later release lands
in that handler instead of escaping it. The structured fields `kind`, `name`,
`status_code` and `group` are declared on that base too, so one `except
RebrewError` can read them without `getattr`; a field the arriving error does
not fill is `None`, and a serialized error leaves it out.

The clients that talk to a service take the HTTP client as an argument, so
your tests never need a live one. `HttpClient` (from `rebrew.recompile_client`
or `rebrew.decompme`) is the two-method shape those clients call: `.post` and
`.get`. A stand-in that takes `**kwargs` satisfies both, so one fake covers
both of them. What it returns is a reply, and that is typed too: `HttpResponse`
names the members each transport reads. `rebrew.recompile_client` needs
`status_code`, `text`, `json()` and `content` (the artifact bytes);
`rebrew.decompme` needs the same minus `content` plus `close()`, because the
module-level `httpx.post` / `httpx.get` reply owns a connection. An
`httpx.Response` satisfies both, and a stand-in missing a member is a type
error rather than a wrong value at the far end:

```python
from rebrew.recompile_client import compile_source


class _Reply:
    """Satisfies rebrew.recompile_client.HttpResponse."""

    def __init__(self, status_code, *, json_body=None, content=b"", text=""):
        self.status_code = status_code
        self._json = json_body
        self.content = content
        self.text = text

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
result.ok / result.obj_bytes / result.log / result.compiler_version

# No client means rebrew builds an httpx.Client(timeout=...) for the call and
# closes it after. `retries=N` re-attempts a retryable RecompileError with
# exponential backoff; `RecompileError.kind` is "network" / "http" /
# "validation" / "protocol" and `status_code` is set for the "http" ones.
# `result.to_dict()` / `RecompileResult.from_dict()` store the verdict (not
# the object bytes) the way `CompareResult` does.
#
# `rebrew.decompme`'s `upload_scratch` is the same shape: `client=` injects a
# stand-in, and `retries=N` re-attempts a retryable `DecompmeError` on the
# same backoff (`retry_backoff_delay` in `rebrew.utils`) and the same
# transient status set, so both service clients recover from a blip the
# same way. Its `payload` is what `build_scratch_payload` returns (a `data`
# form mapping and a `files` multipart mapping); both keys are checked before
# the request is built, so a payload you assembled wrongly arrives as
# `kind="validation"`, not as a network failure a retry could chase.
```

The ReVa MCP client (`rebrew.ghidra`, the transport behind
`rebrew sync`) injects `McpHttpClient` instead: `post` and `delete`, because it
opens a session and terminates it on every exit path. Both take a `url` plus
`**kwargs` (the JSON-RPC `json=` body, the `headers` session id, the per-call
`timeout`), so a stand-in carrying those two methods satisfies it. The reply is
typed as `McpResponse` and has to carry `status_code`, `headers`, `text`,
`json()` and `raise_for_status()`. That is the `FakeService` above with `delete`
added, over a `_Reply` that also carries `headers` and `raise_for_status()`.
`close()` is optional on both reply protocols, so a stand-in holding no
connection to release is still a valid answer.

The CLI commands, flags, and the `rebrew-project.toml` schema are frozen for
the 2.x line. The Python import surface and the dashboard `/api/*` JSON are
not: a removal, move, or signature change there ships in a minor release with
a `**Breaking:**` entry in the changelog, and there is no deprecation window,
so pin the minor version if you import rebrew as a library. See
[CONTRIBUTING.md](../CONTRIBUTING.md#versioning-and-releases).
