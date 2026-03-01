# Configuration Reference

All tools read project settings from **`rebrew-project.toml`** via the config loader. This eliminates hardcoded paths and makes the toolchain portable to different targets.

> **Core Principle: Idempotency** — Every rebrew tool can be run repeatedly with the same result. No destructive side effects — safe to retry, re-run, or chain in scripts and AI agent loops.

## `rebrew-project.toml` (Project Root)

Multiple targets are supported in `rebrew-project.toml`.
Tools default to the first target unless `--target <name>` is passed.

```toml
[targets.target_name]
binary = "original/target.dll"          # Target binary (relative to project root)
format = "pe"                            # Binary format: pe, elf, macho
arch = "x86_32"                          # Architecture: x86_32, x86_64, arm32, arm64
# marker = "TARGET_NAME"                 # Defaults to target key uppercased (see below)
reversed_dir = "src/target_name"         # Where reversed .c files live
function_list = "src/target_name/functions.txt"
bin_dir = "bin/target_name"

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
| `marker` | `[targets.<name>].marker` | Module identifier for annotations (default: target name uppercased) |
| `target_binary` | `[targets.<name>].binary` | Resolved path to the target executable/DLL |
| `image_base` | Auto-detected from PE | `0x10000000` for example DLL |
| `text_va` | Auto-detected from PE | `.text` section virtual address |
| `text_raw_offset` | Auto-detected from PE | `.text` section raw file offset |
| `reversed_dir` | `[targets.<name>].reversed_dir` | Where `.c` files are stored |
| `capstone_arch` / `capstone_mode` | Derived from `arch` | Capstone disassembly constants |
| `padding_bytes` | Derived from `arch` | `(0xCC, 0x90)` for x86 |
| `symbol_prefix` | Derived from compiler profile | `_` for MSVC, empty for GCC |
| `compiler_profile` | `[compiler].profile` | Drives flag sweep axes |
| `compiler_includes` | `[compiler].includes` | Resolved path to include dir |

## Architecture Presets

| Arch | Capstone | Pointer Size | Padding | Symbol Prefix |
|------|----------|-------------|---------|---------------|
| `x86_32` | `CS_ARCH_X86, CS_MODE_32` | 4 | `0xCC, 0x90` | `_` |
| `x86_64` | `CS_ARCH_X86, CS_MODE_64` | 8 | `0xCC, 0x90` | (empty) |
| `arm32` | `CS_ARCH_ARM, CS_MODE_ARM` | 4 | `0x00` | (empty) |
| `arm64` | `CS_ARCH_ARM64, CS_MODE_ARM` | 8 | `0x00` | (empty) |

## Target Marker (`marker`)

The `marker` field identifies which target a source file's annotations belong to. It appears as the module name in annotation headers:

```c
// FUNCTION: SERVER 0x10008880    ← "SERVER" is the marker
// STATUS: EXACT
// ORIGIN: GAME
```

When a project has multiple targets (e.g. `server.dll` and `client.exe`), the same `.c` file may contain annotations for both targets. Tools use `marker` to filter annotations to the active target — only annotations matching `cfg.marker` are processed.

By default, `marker` is the target key uppercased — so `[targets.server_dll]` gets marker `SERVER_DLL`. Override it when the annotation prefix differs from the target key:

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
// STATUS: EXACT
// ORIGIN: GAME
// SIZE: 42
// CFLAGS: /O2 /Gd
// SYMBOL: _MyFunc

// FUNCTION: CLIENT 0x00401000
// STATUS: STUB
// ORIGIN: GAME
// SIZE: 42
// CFLAGS: /O2 /Gd
// SYMBOL: _MyFunc

void __cdecl MyFunc(void) { ... }
```

Running `rebrew test --target server_dll` processes only the `SERVER` annotation block. Running `rebrew test --target client_exe` processes only the `CLIENT` block.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `marker` | `string` | target key uppercased | Module identifier used in `// FUNCTION:`, `// LIBRARY:`, `// STUB:` annotations |

The lint tool (`rebrew lint`) validates that each annotation's module matches the configured marker (error E012).

## Compiler Profiles

| Profile | Flag Source | Obj Format | Symbol Naming |
|---------|-------------|------------|---------------|
| `msvc6` | 11 axes from decomp.me (excludes 7.x-only `/fp:*`, `/GS-`) | COFF | `_func` |
| `msvc` / `msvc7` | 13 axes from decomp.me (full set) | COFF | `_func` |
| `gcc` | `-O0..3`, `-fomit-frame-pointer`, `-mtune=*` | ELF | `func` |
| `clang` | Same as GCC | ELF/Mach-O | `func` |

Flag axes are synced from [decomp.me](https://github.com/decompme/decomp.me) via `tools/sync_decomp_flags.py`.
Sweep tiers: `quick` (~192), `targeted` (~1.1K), `normal` (~21K), `thorough` (~1M), `full` (~8.3M).

## Compiler Configuration

### Merge Hierarchy

Compiler settings are resolved in layers. Each layer overrides the previous:

1. **Built-in defaults** — `wine CL.EXE`, `/nologo /c /MT`, 60s timeout
2. **`[compiler]`** — Global settings shared across all targets
3. **`[targets.<name>.compiler]`** — Per-target overrides (partial — only keys present override)
4. **Source annotations** — `// CFLAGS: /O2 /Gd` in individual `.c` files (highest priority)

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

[compiler.profiles.msvc7]
command = "wine tools/MSVC7/Bin/CL.EXE"
includes = "tools/MSVC7/Include"
libs = "tools/MSVC7/Lib"
cflags = "/O2 /Gd"
```

Profiles are stored in `cfg.compiler_profiles` as a `dict[str, dict[str, str]]` for tools that need to switch compilers programmatically.

### Per-Origin Compiler Overrides (`compiler.origins`)

Different parts of a binary may have been compiled by different teams or with different compiler versions. `compiler.origins` lets you override **any compiler key** per origin.

```toml
[compiler.origins.ZLIB]
command = "wine tools/MSVC7/Bin/CL.EXE"    # different compiler version
includes = "references/zlib"                 # zlib-specific headers
cflags = "/O3"                               # different optimization
profile = "msvc7"                            # different flag sweep profile

[compiler.origins.MSVCRT]
cflags = "/O1"
base_cflags = "/nologo /c /MD"              # different runtime linkage
```

Per-target origin overrides are also supported and merge on top of global origins:

```toml
[targets."server.dll".compiler.origins.ZLIB]
cflags = "/O2"    # this target's ZLIB uses /O2, not the global /O3
```

**Merge hierarchy** (each layer overrides the previous):

1. `[compiler]` — Global defaults
2. `[targets.<name>.compiler]` — Per-target overrides
3. `[compiler.origins.<ORIGIN>]` — Global per-origin overrides
4. `[targets.<name>.compiler.origins.<ORIGIN>]` — Per-target per-origin (most specific config)
5. `// CFLAGS:` annotation — Per-file (cflags only, highest priority)

Supported keys in `[compiler.origins.<ORIGIN>]`: `command`, `runner`, `includes`, `libs`, `cflags`, `base_cflags`, `profile`, `timeout`.

Tools use `cfg.for_origin(origin)` to get a config with all origin overrides applied. `cfg.resolve_origin_cflags(origin)` returns the effective default cflags for skeleton generation and lint validation.

### Origin-Based Flag Presets (`cflags_presets`)

A simpler shorthand for the common case where only cflags differ per origin. Used by `rebrew skeleton` (generates `// CFLAGS:` annotations), `rebrew next` (recommends flags), and `rebrew lint` (validates annotations).

```toml
[compiler.cflags_presets]
GAME = "/O2 /Gd"
MSVCRT = "/O1"
ZLIB = "/O2"

[targets."server.dll".cflags_presets]
ZLIB = "/O3"
```

If both `compiler.origins.ZLIB.cflags` and `cflags_presets.ZLIB` are set, `origins` takes priority. Per-target presets override global presets for the same origin key.

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

## Validation

The config loader will emit warnings if:
- Unrecognized keys are found in `rebrew-project.toml` (likely typos).
- `format` is not `pe`, `elf`, or `macho`.
- `arch` is not one of the known presets (falls back to `x86_32`).
- `profile` is not a known compiler profile.

For a full toolchain health check, run `rebrew doctor`.

## Which Tools Use What Config

All 24 tools read from `rebrew-project.toml`. Each uses `try/except` with hardcoded fallbacks:

| Tool | Config Values Used |
|------|--------------------|
| `verify.py` | `image_base`, `text_va`, `text_raw_offset`, `target_binary`, `reversed_dir` |
| `test.py` | `target_binary`, `text_va`, `text_raw_offset`, compiler paths |
| `nasm.py` | `target_binary`, `reversed_dir` (uses `cfg.extract_dll_bytes()`) |
| `ga.py` | `reversed_dir`, `target_binary`, `compiler_includes` |
| `sync.py` | `reversed_dir` |
| `next.py` | `reversed_dir` |
| `skeleton.py` | `reversed_dir` |
| `extract.py` | `reversed_dir`, `target_binary` |
| `asm.py` | `target_binary`, `capstone_arch`, `capstone_mode` |
| `annotation.py` | Canonical annotation parser — used by verify, extract, sync, ga, nasm |
| `binary_loader.py` | LIEF-based binary loading — used by extract, flirt |
| `matcher/scoring.py` | `capstone_arch`, `capstone_mode` |
| `matcher/compiler.py` | `compiler_profile` (drives flag axes) |
| `matcher/parsers.py` | `padding_bytes` |
| `catalog/` | `image_base`, `text_va` (via verify.py) |
| `status.py` | `reversed_dir`, `text_va` |
| `data.py` | `reversed_dir`, `target_binary`, `image_base` |
| `depgraph.py` | `reversed_dir` |
| `lint.py` | `reversed_dir`, module name |
| `init.py` | All target config (scaffolding) |
| `rename.py` | `reversed_dir` |
| `promote.py` | `marker`, `extract_dll_bytes()`, `for_origin()` |
| `triage.py` | `reversed_dir`, `target_binary`, `iat_thunks`, `root` |
| `doctor.py` | `target_binary`, `reversed_dir`, `bin_dir`, `function_list`, compiler paths, `arch`, `binary_format` |
| `flirt.py` | `target_binary`, `root` |
| `build_db.py` | `project_root` (via CLI arg, reads `data_*.json` from `db/`) |
| `cfg.py` | `rebrew-project.toml` (tomlkit read/write) |

## Config Editor (`rebrew cfg`)

Programmatically read and write `rebrew-project.toml` using `tomlkit` for format-preserving
edits (comments and ordering are retained). All mutating commands are idempotent —
running the same command twice produces the same result with no errors.

| Subcommand | Description | Example |
|------------|-------------|---------|
| `list-targets` | List all defined targets | `rebrew cfg list-targets` |
| `show [KEY]` | Print config or a dot-separated key | `rebrew cfg show compiler.cflags` |
| `add-target NAME` | Add a target section + create dirs | `rebrew cfg add-target client.exe -b original/client.exe` |
| `remove-target NAME` | Remove a target section | `rebrew cfg remove-target old_target` |
| `set KEY VALUE` | Set a scalar config key | `rebrew cfg set compiler.cflags "/O1"` |
| `add-origin ORIGIN` | Append origin to targets list | `rebrew cfg add-origin ZLIB -t server.dll` |
| `remove-origin ORIGIN` | Remove origin from targets list | `rebrew cfg remove-origin ZLIB -t server.dll` |
| `set-cflags ORIGIN FLAGS` | Set cflags preset for an origin | `rebrew cfg set-cflags ZLIB "/O3" -t server.dll` |

```bash
# Example workflow: add a second binary and configure it
rebrew cfg add-target client.exe --binary original/Client/client.exe --arch x86_32
rebrew cfg add-origin ZLIB --target client.exe
rebrew cfg set-cflags GAME "/O2 /Gd" --target client.exe
rebrew cfg show targets.client.exe
```
