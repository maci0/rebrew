# Configuration Reference

All tools read project settings from **`rebrew-project.toml`** via the config loader. This eliminates hardcoded paths and makes the toolchain portable to different targets.

> **Core Principle: Idempotency** — Every rebrew tool can be run repeatedly with the same result. No destructive side effects — safe to retry, re-run, or chain in scripts and AI agent loops.

## `rebrew-project.toml` (Project Root)

Multiple targets are supported in `rebrew-project.toml`.
Tools use `[project].default_target` unless `--target <name>` is passed.

```toml
[project]
default_target = "target_name"           # Default target when --target is not passed

[targets.target_name]
binary = "original/target.dll"          # Target binary (relative to project root)
format = "pe"                            # Binary format: pe, elf, macho, ne, mz
arch = "x86_32"                          # Architecture: x86_16, x86_32, x86_64, arm32, arm64
# marker = "TARGET_NAME"                 # Defaults to target key uppercased (see below)
reversed_dir = "src/target_name"         # Where reversed .c files live
# inventory_file = "db/inventory-target.json"  # Function-inventory override
# (default: reversed_dir/function_structure.json). Set it when several
# targets share one source tree so each keeps its own VA/size inventory.
bin_dir = "bin/target_name"
# source_ext = ".c"                      # Source file extension (default: ".c")
# ghidra_program_path = ""               # Ghidra program path for ReVa MCP sync
# origins = ["GAME", "ZLIB"]             # Recorded by `rebrew cfg add-target`; informational
# only — module filters come from the annotations themselves
# library_modules = ["MSVCRT", "ZLIB"]   # Modules that should use LIBRARY markers

# Add more targets as needed:
# [targets.client_exe]
# binary = "original/Client/client.exe"
# ...

[compiler]
profile = "msvc-6.0"                        # Compiler profile (see `rebrew toolchain list`)
command = ""                             # Empty for docker-backed profiles — the image IS the
                                         # compiler; only native profiles set a real command
includes = "toolchain/msvc/6.0-win32/source/VC98/Include"
libs = "toolchain/msvc/6.0-win32/source/VC98/Lib"
```

## What the Config Loader Provides

| Attribute | Source | Description |
|-----------|--------|-------------|
| `target_name` | Key under `[targets]` | Active target name (e.g. `"game_dll"`) |
| `all_targets` | All keys under `[targets]` | List of all available target names |
| `project_name` | `[project].name` | Project name (informational; defaults to `""`) |
| `marker` | `[targets.<name>].marker` | Module identifier for source markers (default: target name uppercased, non-alphanumeric characters stripped) |
| `target_binary` | `[targets.<name>].binary` | Resolved path to the target executable/DLL |
| `default_jobs` | `[project].jobs` | Default parallelism for batch commands |
| `db_dir` | `[project].db_dir` | Coverage JSON, SQLite DB, CSV directory (verify reports are no longer written here by default — the `--compare` baseline lives in `.rebrew/`) |
| `output_dir` | `[project].output_dir` | Default output directory for generated artifacts |
| `image_base` | Auto-detected from PE | `0x10000000` for example DLL |
| `text_va` | Auto-detected from PE | `.text` section virtual address |
| `reversed_dir` | `[targets.<name>].reversed_dir` | Where `.c` files are stored |
| `inventory_file` | `[targets.<name>].inventory_file` | Function-inventory path override, relative to project root (default: `reversed_dir/function_structure.json`); per-target inventories for one shared source tree |
| `shared_dir` | `[project].shared_dir` | Project-level shared-sources root (`src/shared` by default); sources here are scanned for every target and may carry one `// FUNCTION: <target> <va>` marker per target. Empty value disables shared sources. When the whole tree is the source root (`reversed_dir` is `src` itself), the TOMLs may live inside it |
| `metadata_dir` | Derived: parent of `reversed_dir`, falling back to `reversed_dir` itself when it holds `rebrew-functions.toml` and the parent does not | Canonical home of `rebrew-functions.toml` / `rebrew-data.toml`; callers must pass it explicitly (no walk-up) |
| `capstone_arch` / `capstone_mode` | Derived from `arch` | Capstone disassembly constants |
| `padding_bytes` | Derived from `arch` | `(0xCC, 0x90)` for x86_32/x86_64 (see Architecture Presets) |
| `symbol_prefix` | Derived from `arch` | `_` for x86_16/x86_32, empty for x86_64/arm |
| `external_libs` | `[targets.<name>].external_libs` | External `.lib` code — `module = "link-spec"` table (e.g. `LIBCMT = "LIBCMT.lib"`, `D3DX8 = "references/dxsdk8/lib/d3dx8.lib"`, `MSVCRT = ""` for identified-only).  The one flag for "not our work": rows attributed to these modules leave the progress accounting, `rebrew lib-match` ingests the archives by default, and `rebrew cmake-sources` emits the non-empty specs as `REBREW_EXTERNAL_LIBS` for `target_link_libraries` — config order is link order (static archives last) |
| `crt_sources` | `[targets.<name>].crt_sources` | Maps origin names to reference source directories for CRT cross-matching |
| `library_modules` | `[targets.<name>].library_modules` | Module names that use `LIBRARY` markers |
| `source_ext` | `[targets.<name>].source_ext` | Source extension used when discovering and creating files |
| `ghidra_program_path` | `[targets.<name>].ghidra_program_path` | ReVa MCP program path override |
| `compiler_profile` | `[compiler].profile` | Selects the toolchain's docker image and flag-sweep axes |
| `compiler_includes` | `[compiler].includes` | Resolved path to include dir |

## Architecture Presets

| Arch | Capstone | Pointer Size | Padding | Symbol Prefix |
|------|----------|-------------|---------|---------------|
| `x86_16` | `CS_ARCH_X86, CS_MODE_16` | 2 | `0x90, 0x00` | `_` |
| `x86_32` | `CS_ARCH_X86, CS_MODE_32` | 4 | `0xCC, 0x90` | `_` |
| `x86_64` | `CS_ARCH_X86, CS_MODE_64` | 8 | `0xCC, 0x90` | (empty) |
| `arm32` | `CS_ARCH_ARM, CS_MODE_ARM` | 4 | `0x00` | (empty) |
| `arm64` | `CS_ARCH_ARM64, CS_MODE_ARM` | 8 | `0x00` | (empty) |

`x86_16` targets are 16-bit binaries — Windows 3.x NE executables (Borland Delphi 1.0 /
MSVC 16-bit) or plain DOS MZ; `rebrew intake` sets `format = "ne"` (or `"mz"`) +
`arch = "x86_16"` automatically.  See `docs/TOOLCHAIN.md` for the NE support matrix.

## Target Marker (`marker`)

The `marker` field identifies which target a source file's markers belong to. It appears as the module name in marker headers:

```c
// FUNCTION: SERVER 0x10008880    ← "SERVER" is the marker
```

When a project has multiple targets (e.g. `server.dll` and `client.exe`), the same `.c` file may contain markers for both targets. Tools use `marker` to filter markers to the active target — only markers matching `cfg.marker` are processed.

By default, `marker` is the target key uppercased — so `[targets.server_dll]` gets marker `SERVER_DLL`. Override it when the marker prefix differs from the target key:

```toml
[targets.server_dll]
binary = "original/Server/server.dll"
marker = "SERVER"                        # override: "SERVER" instead of default "SERVER_DLL"

[targets.client_exe]
binary = "original/Client/client.exe"
marker = "CLIENT"                        # override: "CLIENT" instead of default "CLIENT_EXE"
```

A multi-target source file might look like:

```c
// FUNCTION: SERVER 0x10008880

// FUNCTION: CLIENT 0x00401000

void __cdecl MyFunc(void) { ... }
```

The shared `rebrew-functions.toml` holds the metadata (STATUS, SIZE, CFLAGS, …)
under module-prefixed keys (`SERVER.0x…`, `CLIENT.0x…`) for the corresponding VA —
one TOML per metadata root, not one per target.

Running `rebrew test --target server_dll` processes only the `SERVER` marker block. Running `rebrew test --target client_exe` processes only the `CLIENT` block.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `marker` | `string` | target key uppercased, non-alphanumeric characters stripped (e.g. `server.dll` → `SERVERDLL`) | Module identifier used in `// FUNCTION:`, `// LIBRARY:`, `// STUB:` markers |

The lint tool (`rebrew lint`) validates that each marker's module matches the configured marker (error E012) — except stacked blocks naming another known project target, which is the `src/shared` pattern (ADR-010), not a mismatch. Each stacked block answers to its own target's CFLAGS defaults (W018).

`src/shared` files are scanned for every target; `rebrew doctor` warns on multi-target projects when the shared dir is missing or `shared_dir` is disabled. `rebrew cross-import --shared` stacks the destination marker onto the shared file in place (verified before STATUS promotion) instead of copying per-target duplicates.

Progress commands (`status`, `todo`) scope to the active target's own module: in a shared tree every target scans every file, so unscoped counts credit one binary with another target's rows (library headers land in every target's map). Rows whose module matches the target marker count; module-less legacy rows are kept; navigation maps stay unfiltered. Divergent twins that cannot share one file sit side by side as `GOLDTL.<name>.c` / `GOLD.<name>.c` (module-first, like metadata keys).

## Compiler Profiles

| Profile | Flag Source | Obj Format | Symbol Naming |
|---------|-------------|------------|---------------|
| `msvc-6.0` | 13 axes from decomp.me (excludes 7.x-only `/fp:*`, `/GS-`) | COFF | `_func` |
| `msvc-7.0` | 15 axes from decomp.me (full set, incl. `/fp:*`, `/GS-`) | COFF | `_func` |
| `gcc-14.2.0` | posix axes (`GCC_FLAGS` + `GCC_SWEEP_TIERS`) | ELF | `func` |
| `clang-18.1.8` | posix axes (same GCC set) | ELF/Mach-O | `func` |

Other profiles carry their own axis sets (`msvc-1.52` 16-bit, `watcom-2.0-win32`/`watcom-2.0-win16`,
`borland-3.1`/`borland-2.0`/`borland-5.5`); the remaining MSVC variants fall back to the
`msvc-6.0` axis set.

Flag axes are synced from [decomp.me](https://github.com/decompme/decomp.me) via `tools/sync_decomp_flags.py`.
Sweep tiers: `quick` (~192), `targeted` (~1.2K), `normal` (~5.4K), `thorough` (~258K), `full` (~6.2M).

## Compiler Configuration

### Merge Hierarchy

Compiler settings are resolved in layers. Each layer overrides the previous:

1. **Built-in defaults** — empty host `command` for docker-backed profiles (the docker image is the compiler; `wine CL.EXE` is only a legacy fallback for hand-written configs), `/nologo /c /MT` base flags, 60s timeout
2. **`[compiler]`** — Global settings shared across all targets
3. **`[targets.<name>.compiler]`** — Per-target overrides (partial — only keys present override)
4. **Nearest `rebrew-libraries.toml`** — Per-library toolchain/flags overrides (walk-up from the source dir; presets fill missing fields)
5. **`rebrew-functions.toml` metadata** — Per-function TOOLCHAIN/CFLAGS override in the function's entry (highest priority)

```toml
# Global defaults — all targets inherit these
[compiler]
profile = "msvc-6.0"                 # selects the docker image (rebrew/msvc:6.0-win32)
command = ""                      # empty for docker-backed profiles; the image IS the compiler
includes = "toolchain/msvc/6.0-win32/source/VC98/Include"
libs = "toolchain/msvc/6.0-win32/source/VC98/Lib"
cflags = "/O2 /Gd"
base_cflags = "/nologo /c /MT"
timeout = 60

# Per-target override — only the profile differs, everything else inherited
[targets."client.exe".compiler]
profile = "msvc-7.0"
```

### Compiler Keys

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `profile` | `string` | `"msvc-6.0"` | Selects the toolchain's docker image and the flag-sweep axes for `rebrew match` |
| `command` | `string` | `"wine CL.EXE"` | Host compiler invocation (resolved relative to project root). **Empty for docker-backed profiles** — the image IS the compiler (that is what `rebrew init` writes for every shipped profile); only a plugin toolchain registered without an image sets a real command. The `wine CL.EXE` fallback default is inert under docker-only execution |
| `includes` | `string` | `"toolchain/msvc/6.0-win32/source/VC98/Include"` | Path to compiler include directory. For `msvc-6.0`/`msvc-7.0` the default resolves the best layout actually present (full master, then the vendored compile-only mirrors `toolchain/msvc/6.0-sp6-win32`/`toolchain/msvc/6.0-sp3-win32`/`toolchain/msvc/7.0-win32`) — see `rebrew init` output and docs/TOOLCHAIN.md. Empty is valid ("no extra dir"; e.g. `mingw-16.2.0` ships its own headers) |
| `libs` | `string` | `"toolchain/msvc/6.0-win32/source/VC98/Lib"` | Path to compiler lib directory (empty is valid — the compile-only mirrors ship no `Lib/`) |
| `cflags` | `string` | `""` | Default compiler flags |
| `base_cflags` | `string` | `"/nologo /c /MT"` | Always-on flags prepended to every compile. Posix-style profiles (`gcc-14.2.0`, `mingw-16.2.0`, `clang-18.1.8`, `watcom-2.0-win32`, `watcom-2.0-win16`, `borland-5.5`, `borland-3.1`, `borland-2.0`) default to `""` — the MSVC glue would break them |
| `runner` | `string` | `""` | Win32 PE runner (`wine`, `wibo`, or empty). Auto-detected from `command` if not set explicitly. Under docker-only execution the runner is empty for image-backed profiles; `rebrew init --install-wibo` writes `tools/wibo` only for native (non-image) profiles — it is ignored for docker-backed ones. A relative runner path resolves against the project root and needs a `command` without the runner prefix |
| `recompile_url` | `string` | `""` | Base URL of the recompile compile service (e.g. `http://localhost:8000`). When set (or `REBREW_RECOMPILE_URL`), every compile routes through `POST /api/v1/compile` instead of local docker images: the same pinned images, plus the opt-in training tap |
| `recompile_emit_assembly` | `bool` | `false` | Pass `emit_assembly=true` on remote compiles (the training-data tap). Off by default; the GA `--collect-pairs` path enables it per run |
| `timeout` | `integer` | `60` | Compile subprocess timeout in seconds |

Per-target compiler settings (`rebrew cfg set-compiler <target> <profile>`) are
the supported way to vary the toolchain; `[compiler.profiles.*]` is not
recognized (the loader warns about it as an unrecognized key).

### Origin-Based Flag Presets (`cflags_presets`)

Named flag presets for projects that track common per-origin compiler flags.
`rebrew cfg set-cflags` edits these tables, but per-function `CFLAGS` metadata is
still the value consumed by compile/test operations.

```toml
[compiler.cflags_presets]
GAME = "/O2 /Gd"
MSVCRT = "/O1"
ZLIB = "/O2"

[targets."server.dll".compiler.cflags_presets]
ZLIB = "/O3"
```

Per-target presets (`rebrew cfg set-cflags MODULE FLAGS --target <name>`, stored
under the target's `[compiler]` sub-table) override global presets for the same
origin key. A legacy top-level `[targets.<name>.cflags_presets]` table is still
honoured but warns at load — move it to `[targets.<name>.compiler.cflags_presets]`.
Every preset collection must be a TOML table with string values; malformed tables
or entries fail at load with the offending field path. An empty table adds no
overrides, and an empty string remains a valid preset value.

### Per-Target Compiler Overrides

When different targets need different compilers (e.g. one DLL was built with MSVC6 and another with MSVC 7.0):

```toml
[targets."server.dll"]
binary = "original/Server/server.dll"

[targets."server.dll".compiler]
profile = "msvc-6.0"

[targets."client.exe"]
binary = "original/Client/client.exe"

[targets."client.exe".compiler]
profile = "msvc-7.0"
```

Only the keys you specify in the per-target `[compiler]` section override the global `[compiler]`. Unspecified keys fall back to the global defaults.

## Compile Cache Backend

The compile-cache **store** is a pluggable component: `[cache] backend` in
`rebrew-project.toml` selects which registered backend `get_compile_cache()`
opens.  The default is the packaged `diskcache` backend (SQLite +
filesystem at `{project_root}/.rebrew/compile_cache/`); a plugin registers a
new backend through the `rebrew.cache_backends` entry-point group (a factory
`(cache_dir: Path, size_limit: int) -> CacheBackend` — the directory doubles
as the per-project namespace even for remote/shared stores).

```toml
[cache]
backend = "diskcache"   # or any registered rebrew.cache_backends member
```

The **keying** is deliberately NOT pluggable: what makes a cache hit valid
(source/flags/toolchain/include digests) is shared semantics every backend
must respect — a backend stores and retrieves bytes; it never reinterprets
the keys.  `rebrew cache stats` / `clear` operate on the configured backend.
An unknown `backend` name is a `ValueError` at config load (and again where
the cache is opened, for programmatic callers that skip the loader).

## Environment Variables

Project settings live in ``rebrew-project.toml``. Environment variables are
namespaced ``REBREW_*`` and act as per-run overrides or secret carriers —
they do **not** all share one global precedence over the TOML.

**Per-setting precedence (when both TOML and env apply):**

| Setting | Winner |
|---------|--------|
| `[compiler] recompile_url` / `REBREW_RECOMPILE_URL` | env **when the variable is present** (even if empty — empty forces local docker for the run); else TOML |
| `[llm] endpoint` / `REBREW_LLM_ENDPOINT` | TOML, then env |
| `[llm] api_key` / `REBREW_LLM_API_KEY` | env **when present** (even if empty — clears a committed TOML key for the run); else TOML — prefer the env var; do not commit keys |
| `[llm] model` / `REBREW_LLM_MODEL` | TOML, then env (default `gpt-4o-mini-2024-07-18`; `latest`/`auto`/`default` fall back to it) |

Unset vs empty: for the two env-wins settings above, an unset variable falls through to TOML; an empty value is intentional and overrides TOML. `rebrew cfg set` refuses non-empty secret keys (they would appear in argv/history); clear with `rebrew cfg set llm.api_key ''` or set `REBREW_LLM_API_KEY`.

Within a project file, compiler settings still merge as: built-in defaults →
`[compiler]` → `[targets.<name>.compiler]` → library/metadata overrides
(see Compiler Configuration above). CLI flags that mirror a setting are owned
by the CLI layer and win for that invocation.

### Runtime / secrets

- `REBREW_LLM_ENDPOINT` / `REBREW_LLM_API_KEY` / `REBREW_LLM_MODEL` — LLM
  seeding endpoint, key, and model pin (`rebrew match --seed-llm`). Required
  for LLM seeding when `[llm]` is unset. The key is sent only as a `Bearer`
  header to the configured endpoint, never logged. Prefer these env vars over
  `[llm] api_key` in TOML. Endpoint must be an `http(s)` URL with a host.
- `REBREW_LLM_MAX_REQUESTS` — process-wide ceiling on LLM HTTP calls
  (default `32`). Stops `--watch` / batch seeding from burning a paid
  endpoint. `0` disables further calls for the process. A set-but-non-integer
  or negative value is a `ValueError` (not silently reset to the default).
  Values above `10000` clamp to `10000` with a warning.
- `REBREW_RECOMPILE_URL` — base URL of the recompile compile service
  (e.g. `http://localhost:8000`). Same effect as `[compiler] recompile_url`;
  when the variable is present it wins (empty forces local docker for the
  run). When set to a non-empty URL, every compile routes through the
  service instead of local docker images. Must be an `http(s)` URL with a
  host (invalid values fail at load / resolve time).

### Paths / overlays

- `REBREW_TOOLCHAINS_DIR` — path to the sibling `rebrew-toolchains` checkout
  (Dockerfiles / wrappers). Default: sibling of this install.
- `REBREW_TOOLCHAIN_OVERLAY_DIR` — directory of extra toolchain TOML overlays
  (plugin-style profiles without editing host source).
- `REBREW_FLIRT_SIGS_DIR` — path to the `rebrew-flirt-sigs` checkout.
- `REBREW_SKILLS_DIR` — user/community Agent Skills directory (overrides
  packaged skills of the same name).
- `REBREW_CONTAINER_RUNTIME` — container CLI (`docker` default, or `podman`).

### Host-wine / cmake (dormant under docker-only profiles)

- `REBREW_WINE_HEADLESS` — set to `0` to disable headless wine (run bare
  wine, e.g. if you genuinely want the window).  Default: wine compiles
  against a persistent `Xvfb` virtual display whenever the `Xvfb` binary
  is on PATH.
- `REBREW_XVFB_DISPLAY` — display (e.g. `:99`) of the virtual X server
  headless wine uses.  Set by rebrew itself on first use; override to pin
  a specific display (it must host a live Xvfb).
- `REBREW_WINEPREFIX` — Wine prefix for cmake toolchain bridge scripts.
- `REBREW_TOOLCHAIN` — cmake bridge pin for the active profile name.
- `REBREW_COMPILER_RUNNER` — host PE runner path/name (set by `msvc_env`).
- `REBREW_RUNNER` — PE runner **inside** docker toolchain images
  (`wine` default, `wibo` opt-in).  Not read by the host Python process.

### Other

- `REBREW_PROJECTS_ROOT` — root directory scanned by `tools/audit_projects.py`
  (default: parent of this install).
- `_REBREW_COMPLETE` — shell-completion mode marker (probed during `rebrew init` shell-completion scaffolding; there is no `rebrew completion` command).
- `GH_TOKEN` / `GITHUB_TOKEN` — optional GitHub auth for `rebrew toolchain`
  downloads that need a token (not a rebrew-prefixed name; standard gh env).

## Lint style (`[project.lint]`)

Optional style rules consumed by `rebrew lint` (W024–W027).  All default to
off (`none` / `200`).  Unknown keys warn at load; unknown enum values warn
and fall back to `none` (a typo must not silently disable the rule).

```toml
[project.lint]
naming_convention = "snake_case"   # snake_case | camelCase | none
brace_style = "same_line"          # same_line | new_line | none
indent_style = "spaces"            # spaces | tabs | none
max_line_length = 200
```

## Validation

The config loader fail-fasts on missing/invalid structure:
- No `[targets]`, missing `default_target`, unknown target name, or missing/empty `binary`.
- Non-string or empty `project.default_target`.
- Explicitly empty required path fields (`reversed_dir`, `bin_dir`,
  `db_dir`, `output_dir`) or an empty `compiler.command` on a native (non-image)
  profile (these otherwise resolve to the project root or fail only when a compiler
  subprocess is launched). `includes`/`libs` may be empty — that means "no extra
  dir" (e.g. `mingw-16.2.0` ships its own headers).
- Empty or unregistered `[cache].backend` (must name a `rebrew.cache_backends` member).

It emits warnings (and applies safe defaults) if:
- Unrecognized keys are found in top-level, project, global compiler, target,
  per-target compiler, `[llm]`, `[cache]`, or `[project.lint]` tables (likely typos).
- `[llm].api_key` is set in the TOML (prefer `REBREW_LLM_API_KEY`) or is set
  without an endpoint.
- A legacy `[targets.<name>.cflags_presets]` table is present (wrong place —
  still honoured; move to `[targets.<name>.compiler.cflags_presets]`).
- `format` is not one of `pe`, `elf`, `macho`, `ne`, `mz` (falls back to `pe` — never stores the bad value).
- `arch` is not one of the known presets (falls back to `x86_32`).
- `profile` is not a known compiler profile (falls back to `msvc-6.0`).
- `[project.lint]` enum fields are not in their known set (falls back to `none`).
- String/bool fields have non-string/non-bool types (e.g. `recompile_emit_assembly = "false"`
  would otherwise become `True` via Python `bool()`).
- The target binary is missing — `image_base`/`text_va` auto-detection is skipped
  (warning emitted at load time).

`[compiler] recompile_url`, `[llm] endpoint`, and the matching
`REBREW_RECOMPILE_URL` / `REBREW_LLM_ENDPOINT` env values share URL validation:
non-empty values must use `http(s)`, have a hostname, and use a numeric port in
1–65535 if specified. Malformed IPv6 addresses, embedded whitespace, and control
characters are rejected. Surrounding whitespace is trimmed; empty values remain
unset. TOML values are validated at load; environment values are validated when
resolved, before any HTTP request. `REBREW_LLM_MAX_REQUESTS`, when set, must be
a non-negative integer (validated when LLM config is resolved).

`cflags` are user-facing defaults (e.g. `/O2 /Gd`). `base_cflags` are always-on
flags prepended by the compile helpers (default `/nologo /c /MT`) and must not be
passed as `--cflags` overrides.

For a full toolchain health check, run `rebrew doctor`.

## Which Tools Use What Config

All tools read from `rebrew-project.toml`. Key tools and the config values they use:

| Tool | Config Values Used |
|------|--------------------|
| `verify.py` | `image_base`, `text_va`, `target_binary`, `reversed_dir`, `db_dir` (`text_raw_offset` lives on `binary_loader.BinaryInfo`, not the config) |
| `test.py` | `target_binary`, `text_va`, compiler paths |
| `match.py` | `reversed_dir`, `target_binary`, `compiler.includes`, `compiler.command` |
| `ghidra/cli.py` | `reversed_dir` |
| `todo.py` | `reversed_dir`, `target_binary` |
| `skeleton.py` | `reversed_dir` |
| `extract.py` | `reversed_dir`, `target_binary` |
| `asm.py` | `target_binary`, `capstone_arch`, `capstone_mode` |
| `annotation.py` | Canonical source marker parser — used by verify, extract, sync, match |
| `binary_loader.py` | LIEF-based binary loading — used by extract, flirt |
| `matcher/scoring.py` | `capstone_arch`, `capstone_mode` |
| `matcher/compiler.py` | `compiler_profile` (drives flag axes) |
| `matcher/parsers.py` | `padding_bytes` |
| `catalog/` | `image_base`, `text_va`, `db_dir` |
| `data.py` | `reversed_dir`, `target_binary`, `image_base` |
| `depgraph.py` | `reversed_dir` |
| `lint.py` | `reversed_dir`, module name |
| `init.py` | All target config (scaffolding) |
| `rename.py` | `reversed_dir` |
| `doctor.py` | `target_binary`, `reversed_dir`, `bin_dir`, compiler paths, `arch`, `binary_format` |
| `flirt.py` | `target_binary`, `root` |
| `crt_match.py` | `crt_sources`, `reversed_dir`, `target_binary` |
| `build_db.py` | `project_root`, `db_dir` |
| `cache_cli.py` | `project_root` (cache directory location) |
| `cfg.py` | `rebrew-project.toml` (tomlkit read/write) |
| `split.py` | `marker`, `source_ext`, `reversed_dir` |
| `merge.py` | `marker`, `source_ext`, `reversed_dir` |
| `binsync/export.py` | `reversed_dir` |

## Config Editor (`rebrew cfg`)

Programmatically read and write `rebrew-project.toml` using `tomlkit` for format-preserving
edits (comments and ordering are retained). All mutating commands are idempotent —
running the same command twice produces the same result with no errors.

Dotted key paths use greedy longest-match resolution so TOML keys that contain dots
(like target names `server.dll`) are handled correctly — e.g. `targets.server.dll.arch`
resolves through the `server.dll` key.

| Subcommand | Description | Example |
|------------|-------------|---------|
| `list-targets` | List all defined targets | `rebrew cfg list-targets` |
| `show [KEY]` | Print config or a dot-separated key | `rebrew cfg show compiler.cflags` |
| `set KEY VALUE` | Set a scalar config key (refuses non-empty secret keys such as `llm.api_key` — use `REBREW_LLM_API_KEY`; URL fields are validated) | `rebrew cfg set compiler.cflags "/O1"` |
| `raw` | Dump entire config as JSON (default) or TOML (`--format toml`) | `rebrew cfg raw` |
| `path` | Print absolute path to `rebrew-project.toml` | `rebrew cfg path` |
| `add-target NAME` | Add a target section + create dirs | `rebrew cfg add-target client.exe -b original/client.exe` |
| `remove-target NAME` | Remove a target section | `rebrew cfg remove-target old_target` |
| `set-cflags ORIGIN FLAGS` | Set cflags preset for an origin | `rebrew cfg set-cflags ZLIB "/O3" -t server.dll` |
| `set-compiler TARGET PROFILE` | Set compiler profile for a target | `rebrew cfg set-compiler client.exe msvc-7.0` |
| `add-module MODULE` | Add a module to a target's origins list | `rebrew cfg add-module ZLIB -t server.dll` |
| `remove-module MODULE` | Remove a module from a target's origins list | `rebrew cfg remove-module ZLIB -t server.dll` |
| `detect-crt` | Auto-detect MSVC CRT source directories | `rebrew cfg detect-crt --write` |

```bash
# Example workflow: add a second binary and configure it
rebrew cfg add-target client.exe --binary original/Client/client.exe --arch x86_32
rebrew cfg set-cflags GAME "/O2 /Gd" --target client.exe
rebrew cfg show targets.client.exe

# Read/write through dotted target names
rebrew cfg show targets.server.dll.arch         # read value through dotted key
rebrew cfg set targets.server.dll.arch x86_64   # set value through dotted key

# Auto-detect CRT source directories from MSVC tools
rebrew cfg detect-crt                           # preview detected paths
rebrew cfg detect-crt --write                   # write into rebrew-project.toml

# Dump config for scripting
rebrew cfg raw                                  # JSON output
rebrew cfg raw --format toml                    # TOML output
rebrew cfg path                                 # print path to config file
```

## Compiler profiles from `rebrew init`

`rebrew init --toolchain <profile>` supports the full toolchain matrix (run
`rebrew toolchain list` for the exact names): every MSVC variant — 4.0/4.2/5.0
(and sp1–sp3), 6.0 (and sp1–sp6), 7.0–11.0 (rtm/sp variants), 2.0/4.1, and the
16-bit 1.0 (`msvc-1.0`)/1.5 (`msvc-1.5`)/1.52 (`msvc-1.52`) — plus borland-5.5,
borland-3.1/borland-2.0, watcom-2.0-win32/watcom-2.0-win16, delphi-1.0,
gcc-14.2.0/gcc-12.3.0/mingw-16.2.0/mingw-14.2.0 and
clang-18.1.8/clang-16.0.4.  Every profile gets an empty `command`/`runner` in the
generated config (the docker image is the compiler); only a plugin toolchain
registered without an image keeps a real host command.  The target
`arch` follows the profile (`msvc-1.52` → `x86_16`); if a binary is already in
`original/`, `format`/`arch` are auto-detected from it instead.
