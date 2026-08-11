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
format = "pe"                            # Binary format: pe, elf, macho, ne
arch = "x86_32"                          # Architecture: x86_16, x86_32, x86_64, arm32, arm64
# marker = "TARGET_NAME"                 # Defaults to target key uppercased (see below)
reversed_dir = "src/target_name"         # Where reversed .c files live
function_list = "src/target_name/functions.txt"
bin_dir = "bin/target_name"
# source_ext = ".c"                      # Source file extension (default: ".c")
# ghidra_program_path = ""               # Ghidra program path for ReVa MCP sync
# origins = ["GAME", "ZLIB"]             # Origin list for annotation filtering
# library_modules = ["MSVCRT", "ZLIB"]   # Modules that should use LIBRARY markers

# Add more targets as needed:
# [targets.client_exe]
# binary = "original/Client/client.exe"
# ...

[compiler]
profile = "msvc6"                        # Compiler profile: msvc6, gcc, clang
command = "wine tools/MSVC600/VC98/Bin/CL.EXE"
includes = "tools/MSVC600/VC98/Include"
libs = "tools/MSVC600/VC98/Lib"
```

## What the Config Loader Provides

| Attribute | Source | Description |
|-----------|--------|-------------|
| `target_name` | Key under `[targets]` | Active target name (e.g. `"game_dll"`) |
| `all_targets` | All keys under `[targets]` | List of all available target names |
| `marker` | `[targets.<name>].marker` | Module identifier for source markers (default: target name uppercased) |
| `target_binary` | `[targets.<name>].binary` | Resolved path to the target executable/DLL |
| `default_jobs` | `[project].jobs` | Default parallelism for batch commands |
| `db_dir` | `[project].db_dir` | Coverage JSON, SQLite DB, CSV, and verify report directory |
| `output_dir` | `[project].output_dir` | Default output directory for generated artifacts |
| `image_base` | Auto-detected from PE | `0x10000000` for example DLL |
| `text_va` | Auto-detected from PE | `.text` section virtual address |
| `text_raw_offset` | Auto-detected from PE | `.text` section raw file offset |
| `reversed_dir` | `[targets.<name>].reversed_dir` | Where `.c` files are stored |
| `metadata_dir` | Derived: parent of `reversed_dir` | Canonical home of `rebrew-function.toml` / `rebrew-data.toml`; callers must pass it explicitly (no walk-up) |
| `capstone_arch` / `capstone_mode` | Derived from `arch` | Capstone disassembly constants |
| `padding_bytes` | Derived from `arch` | `(0xCC, 0x90)` for x86 |
| `symbol_prefix` | Derived from compiler profile | `_` for MSVC, empty for GCC |
| `crt_sources` | `[targets.<name>].crt_sources` | Maps origin names to reference source directories for CRT cross-matching |
| `library_modules` | `[targets.<name>].library_modules` | Module names that use `LIBRARY` markers |
| `source_ext` | `[targets.<name>].source_ext` | Source extension used when discovering and creating files |
| `ghidra_program_path` | `[targets.<name>].ghidra_program_path` | ReVa MCP program path override |
| `compiler_profile` | `[compiler].profile` | Drives flag sweep axes |
| `compiler_includes` | `[compiler].includes` | Resolved path to include dir |

## Architecture Presets

| Arch | Capstone | Pointer Size | Padding | Symbol Prefix |
|------|----------|-------------|---------|---------------|
| `x86_16` | `CS_ARCH_X86, CS_MODE_16` | 2 | `0x90, 0x00` | `_` |
| `x86_32` | `CS_ARCH_X86, CS_MODE_32` | 4 | `0xCC, 0x90` | `_` |
| `x86_64` | `CS_ARCH_X86, CS_MODE_64` | 8 | `0xCC, 0x90` | (empty) |
| `arm32` | `CS_ARCH_ARM, CS_MODE_ARM` | 4 | `0x00` | (empty) |
| `arm64` | `CS_ARCH_ARM64, CS_MODE_ARM` | 8 | `0x00` | (empty) |

`x86_16` targets are 16-bit Windows 3.x NE executables (Borland Delphi 1.0 /
MSVC 16-bit); `rebrew intake` sets `format = "ne"` + `arch = "x86_16"`
automatically.  See `docs/TOOLCHAIN.md` for the NE support matrix.

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

Each target's `rebrew-function.toml` metadata holds the metadata (STATUS, SIZE, CFLAGS) for the
corresponding VA.

Running `rebrew test --target server_dll` processes only the `SERVER` marker block. Running `rebrew test --target client_exe` processes only the `CLIENT` block.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `marker` | `string` | target key uppercased | Module identifier used in `// FUNCTION:`, `// LIBRARY:`, `// STUB:` markers |

The lint tool (`rebrew lint`) validates that each marker's module matches the configured marker (error E012).

## Compiler Profiles

| Profile | Flag Source | Obj Format | Symbol Naming |
|---------|-------------|------------|---------------|
| `msvc6` | 11 axes from decomp.me (excludes 7.x-only `/fp:*`, `/GS-`) | COFF | `_func` |
| `msvc` / `msvc7` | 13 axes from decomp.me (full set) | COFF | `_func` |
| `gcc` | `-O0..3`, `-fomit-frame-pointer`, `-mtune=*` | ELF | `func` |
| `clang` | Same as GCC | ELF/Mach-O | `func` |

Flag axes are synced from [decomp.me](https://github.com/decompme/decomp.me) via `tools/sync_decomp_flags.py`.
Sweep tiers: `quick` (~192), `targeted` (~1.1K), `normal` (~5.4K), `thorough` (~258K), `full` (~6.2M).

## Compiler Configuration

### Merge Hierarchy

Compiler settings are resolved in layers. Each layer overrides the previous:

1. **Built-in defaults** — `wine CL.EXE`, `/nologo /c /MT`, 60s timeout
2. **`[compiler]`** — Global settings shared across all targets
3. **`[targets.<name>.compiler]`** — Per-target overrides (partial — only keys present override)
4. **`rebrew-function.toml` metadata** — Per-function CFLAGS override in the function's entry (highest priority for cflags)

```toml
# Global defaults — all targets inherit these
[compiler]
profile = "msvc6"
runner = "wine"
command = "wine tools/MSVC600/VC98/Bin/CL.EXE"
includes = "tools/MSVC600/VC98/Include"
libs = "tools/MSVC600/VC98/Lib"
cflags = "/O2 /Gd"
base_cflags = "/nologo /c /MT"
timeout = 60

# Per-target override — only command differs, everything else inherited
[targets."client.exe".compiler]
command = "wine tools/MSVC7/Bin/CL.EXE"
includes = "tools/MSVC7/Include"
libs = "tools/MSVC7/Lib"
```

### Compiler Keys

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `profile` | `string` | `"msvc6"` | Selects flag sweep axes for `rebrew match` |
| `command` | `string` | `"wine CL.EXE"` | Compiler invocation (resolved relative to project root) |
| `includes` | `string` | `"tools/MSVC600/VC98/Include"` | Path to compiler include directory |
| `libs` | `string` | `"tools/MSVC600/VC98/Lib"` | Path to compiler lib directory |
| `cflags` | `string` | `""` | Default compiler flags |
| `base_cflags` | `string` | `"/nologo /c /MT"` | Always-on flags prepended to every compile |
| `runner` | `string` | `""` | Win32 PE runner (`wine`, `wibo`, or empty for native). Auto-detected from `command` if not set explicitly. |
| `timeout` | `integer` | `60` | Compile subprocess timeout in seconds |

### Custom Compiler Profiles

Define alternative compiler profiles under `[compiler.profiles.<name>]`. Each profile is a full set of compiler keys that can be selected at runtime.

```toml
[compiler]
profile = "msvc6"
command = "wine tools/MSVC600/VC98/Bin/CL.EXE"
includes = "tools/MSVC600/VC98/Include"
libs = "tools/MSVC600/VC98/Lib"
cflags = "/O2 /Gd"

[compiler.profiles.clang]
command = "clang"
includes = "/usr/include"
libs = "/usr/lib"
cflags = "-O2"

[compiler.profiles.gcc-pe]
command = "i686-w64-mingw32-gcc"
includes = ""
libs = ""
cflags = "-O2 -march=pentium4"

[compiler.profiles.msvc7]
command = "wine tools/MSVC7/Bin/CL.EXE"
includes = "tools/MSVC7/Include"
libs = "tools/MSVC7/Lib"
cflags = "/O2 /Gd"
```

Profiles are stored in `cfg.compiler_profiles` as a `dict[str, dict[str, str]]` for tools that need to switch compilers programmatically.

### Origin-Based Flag Presets (`cflags_presets`)

Named flag presets for projects that track common per-origin compiler flags.
`rebrew cfg set-cflags` edits these tables, but per-function `CFLAGS` metadata is
still the value consumed by compile/test operations.

```toml
[compiler.cflags_presets]
GAME = "/O2 /Gd"
MSVCRT = "/O1"
ZLIB = "/O2"

[targets."server.dll".cflags_presets]
ZLIB = "/O3"
```

Per-target presets override global presets for the same origin key.

### Per-Target Compiler Overrides

When different targets need different compilers (e.g. one DLL was built with MSVC6 and another with MSVC7):

```toml
[targets."server.dll"]
binary = "original/Server/server.dll"

[targets."server.dll".compiler]
profile = "msvc6"
command = "wine tools/MSVC600/VC98/Bin/CL.EXE"
includes = "tools/MSVC600/VC98/Include"

[targets."client.exe"]
binary = "original/Client/client.exe"

[targets."client.exe".compiler]
profile = "msvc7"
command = "wine tools/MSVC7/Bin/CL.EXE"
includes = "tools/MSVC7/Include"
```

Only the keys you specify in the per-target `[compiler]` section override the global `[compiler]`. Unspecified keys fall back to the global defaults.

## Environment Variables

Configuration precedence is: CLI flags > per-function metadata > `rebrew-project.toml` > environment variables > defaults.

- `REBREW_COMPLETE` — shell-completion mode marker (used by `rebrew` completion).
- `REBREW_GLOBALS_H` — path to an additional `globals.h`-style header loaded by
  the C parser (for decomp projects that keep globals in an external header).
- `REBREW_LLM_ENDPOINT` / `REBREW_LLM_API_KEY` — LLM seeding endpoint + key
  (`rebrew match --llm-seed`). The `[llm]` config keys (`llm_endpoint`,
  `llm_api_key`) win over these env vars; both fall back to env when unset.
  The key is sent only as a `Bearer` header to the configured endpoint, never
  logged. Prefer the env vars over committing the key to
  `rebrew-project.toml`.

## Validation

The config loader fail-fasts on missing/invalid structure:
- No `[targets]`, missing `default_target`, unknown target name, or missing/empty `binary`.
- Non-string or empty `project.default_target`.
- Explicitly empty path fields or `compiler.command` (these otherwise resolve to the project
  root or fail only when a compiler subprocess is launched).

It emits warnings (and applies safe defaults) if:
- Unrecognized keys are found in top-level, project, global compiler, target, or per-target
  compiler tables (likely typos).
- `format` is not `pe`, `elf`, or `macho` (falls back to `pe` — never stores the bad value).
- `arch` is not one of the known presets (falls back to `x86_32`).
- `profile` is not a known compiler profile (falls back to `msvc6`).
- String fields (`cflags`, `base_cflags`, `marker`, …) have non-string types.
- The target binary is missing — `image_base`/`text_va` auto-detection is skipped
  (warning emitted at load time).

`cflags` are user-facing defaults (e.g. `/O2 /Gd`). `base_cflags` are always-on
flags prepended by the compile helpers (default `/nologo /c /MT`) and must not be
passed as `--cflags` overrides.

For a full toolchain health check, run `rebrew doctor`.

## Which Tools Use What Config

All tools read from `rebrew-project.toml`. Key tools and the config values they use:

| Tool | Config Values Used |
|------|--------------------|
| `verify.py` | `image_base`, `text_va`, `text_raw_offset`, `target_binary`, `reversed_dir`, `db_dir` |
| `test.py` | `target_binary`, `text_va`, `text_raw_offset`, compiler paths |
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
| `doctor.py` | `target_binary`, `reversed_dir`, `bin_dir`, `function_list`, compiler paths, `arch`, `binary_format` |
| `flirt.py` | `target_binary`, `root` |
| `crt_match.py` | `crt_sources`, `reversed_dir`, `target_binary` |
| `build_db.py` | `project_root`, `db_dir` |
| `cache_cli.py` | `project_root` (cache directory location) |
| `cfg.py` | `rebrew-project.toml` (tomlkit read/write) |
| `split.py` | `marker`, `source_ext`, `reversed_dir` |
| `merge.py` | `marker`, `source_ext`, `reversed_dir` |
| `binsync_export.py` | `reversed_dir` |

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
| `set KEY VALUE` | Set a scalar config key | `rebrew cfg set compiler.cflags "/O1"` |
| `raw` | Dump entire config as JSON (default) or TOML (`--format toml`) | `rebrew cfg raw` |
| `path` | Print absolute path to `rebrew-project.toml` | `rebrew cfg path` |
| `add-target NAME` | Add a target section + create dirs | `rebrew cfg add-target client.exe -b original/client.exe` |
| `remove-target NAME` | Remove a target section | `rebrew cfg remove-target old_target` |
| `set-cflags ORIGIN FLAGS` | Set cflags preset for an origin | `rebrew cfg set-cflags ZLIB "/O3" -t server.dll` |
| `set-compiler TARGET PROFILE` | Set compiler profile for a target | `rebrew cfg set-compiler client.exe msvc7` |
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
