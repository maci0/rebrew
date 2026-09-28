# AGENTS.md: ghidra/

Sync rebrew annotations with Ghidra. Field-level sync (names, comments, prototypes, structs, globals) is BinSync-primary and lives in `rebrew.binsync`; the ReVa MCP surface here covers the structural ops BinSync cannot express: function creation, bookmarks, and data pulls.

## Modules

| Module | Role |
|--------|------|
| `models.py` | `JsonRpcResponse`, `McpToolResult` — the wire shapes |
| `client.py` | ReVa MCP HTTP client: session init, JSON-RPC tool invocation, `McpError` / `McpApplyAborted` |
| `commands.py` | MCP command builders (`build_new_function_commands`, `build_bookmark_commands`) + apply orchestration |
| `cli_backend.py` | `ghidra-cli` subprocess backend, the alternative transport to MCP |
| `cli.py` | the single `rebrew sync` command (`--push` / `--pull` / `--create-functions` / `--bookmarks` / `--pull-data`) |

Externals (the only packages this one may import): `binary_loader`, `binsync.export`, `binsync.importer`, `catalog`, `cli`, `config`, `errors`, `sources`, `utils`. The `binsync.*` imports are the read side of the sync; a field write still goes out through `rebrew.binsync`.

## Public surface

`__init__.py` resolves names lazily via `__getattr__` and does not cache: an in-tree caller that needs `DEFAULT_MCP_ENDPOINT` alone does not load the MCP client, the command builders, or the `ghidra-cli` backend, and a stand-in swapped onto `rebrew.ghidra.client` is seen through the facade. `DEFAULT_MCP_ENDPOINT` and `MCP_REQUEST_TIMEOUT_S` are the single homes of the ReVa MCP default URL and request budget; a `--endpoint` option in another module names them instead of repeating the literal. Reach for the package (`rebrew.ghidra`), never `rebrew.ghidra.client` / `.commands` directly — a `skeleton` / `decompiler` caller that needs the module unloaded imports the package by name and reads the attribute off it, so the deferral survives the boundary.

## Contracts

- **Two transports, one command list.** `commands.py` builds the operation list; `client.py` (MCP) or `cli_backend.py` (`ghidra-cli`) executes it. Adding an op means adding a builder, not a transport branch.
- **`cli.py` is the only Typer surface here.** Library modules stay transport-free so a host other than the CLI can drive the sync.
- **`models.py` holds the wire types.** A response field is added there, never re-declared at the call site.
- **`client=` is typed `McpHttpClient`,** a `runtime_checkable` Protocol (`post` / `delete`, replies carrying `status_code`, `headers`, `text`, `json()`, `raise_for_status()`). A new HTTP call in this package takes the protocol, not `httpx.Client`, so a consumer's stand-in stays type-checked and needs no live Ghidra.
