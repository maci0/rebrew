# Configuration Reference

All tools read project settings from **`rebrew.toml`** via the config loader. This eliminates hardcoded paths and makes the toolchain portable to different targets.

> **Core Principle: Idempotency** — Every rebrew tool can be run repeatedly with the same result. No destructive side effects — safe to retry, re-run, or chain in scripts and AI agent loops.

## `rebrew.toml` (Project Root)

Multiple targets are supported in `rebrew.toml`.
Tools default to the first target unless `--target <name>` is passed.

```toml
[targets.target_name]
binary = "original/target.dll"          # Target binary (relative to project root)
format = "pe"                            # Binary format: pe, elf, macho
arch = "x86_32"                          # Architecture: x86_32, x86_64, arm32, arm64
reversed_dir = "src/target_name"         # Where reversed .c files live
function_list = "src/target_name/r2_functions.txt"
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

## Compiler Profiles

| Profile | Flag Source | Obj Format | Symbol Naming |
|---------|-------------|------------|---------------|
| `msvc6` | 11 axes from decomp.me (excludes 7.x-only `/fp:*`, `/GS-`) | COFF | `_func` |
| `msvc` / `msvc7` | 13 axes from decomp.me (full set) | COFF | `_func` |
| `gcc` | `-O0..3`, `-fomit-frame-pointer`, `-mtune=*` | ELF | `func` |
| `clang` | Same as GCC | ELF/Mach-O | `func` |

Flag axes are synced from [decomp.me](https://github.com/decompme/decomp.me) via `tools/sync_decomp_flags.py`.
Sweep tiers: `quick` (~192), `normal` (~21K), `thorough` (~1M), `full` (~8.3M).

## Which Tools Use What Config

All 22 tools read from `rebrew.toml`. Each uses `try/except` with hardcoded fallbacks:

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

## Config Editor (`rebrew cfg`)

Programmatically read and write `rebrew.toml` using `tomlkit` for format-preserving
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
