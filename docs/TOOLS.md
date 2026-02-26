# Reverse Engineering Tools Inventory

Tools available for the rebrew reverse engineering project.

---

## Configuration System

All tools read project settings from **`rebrew.toml`** via the config loader. This eliminates hardcoded paths and makes the toolchain portable to different targets.

> **Core Principle: Idempotency** — Every rebrew tool can be run repeatedly with the same result. No destructive side effects — safe to retry, re-run, or chain in scripts and AI agent loops.

### `rebrew.toml` (Project Root)

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

### What the config loader provides

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

### Architecture presets

| Arch | Capstone | Pointer Size | Padding | Symbol Prefix |
|------|----------|-------------|---------|---------------|
| `x86_32` | `CS_ARCH_X86, CS_MODE_32` | 4 | `0xCC, 0x90` | `_` |
| `x86_64` | `CS_ARCH_X86, CS_MODE_64` | 8 | `0xCC, 0x90` | (empty) |
| `arm32` | `CS_ARCH_ARM, CS_MODE_ARM` | 4 | `0x00` | (empty) |
| `arm64` | `CS_ARCH_ARM64, CS_MODE_ARM` | 8 | `0x00` | (empty) |

### Compiler profiles

| Profile | Flag Source | Obj Format | Symbol Naming |
|---------|-------------|------------|---------------|
| `msvc6` | 11 axes from decomp.me (excludes 7.x-only `/fp:*`, `/GS-`) | COFF | `_func` |
| `msvc` / `msvc7` | 13 axes from decomp.me (full set) | COFF | `_func` |
| `gcc` | `-O0..3`, `-fomit-frame-pointer`, `-mtune=*` | ELF | `func` |
| `clang` | Same as GCC | ELF/Mach-O | `func` |

Flag axes are synced from [decomp.me](https://github.com/decompme/decomp.me) via `tools/sync_decomp_flags.py`.
Sweep tiers: `quick` (~192), `normal` (~21K), `thorough` (~1M), `full` (~8.3M).

### Tools using config

All 21 tools read from `rebrew.toml`. Each uses `try/except` with hardcoded fallbacks:

| Tool | Config Values Used |
|------|--------------------|
| `verify.py` | `image_base`, `text_va`, `text_raw_offset`, `target_binary`, `reversed_dir` |
| `test.py` | `target_binary`, `text_va`, `text_raw_offset`, compiler paths |
| `nasm.py` | `target_binary`, `reversed_dir` (uses `cfg.extract_dll_bytes()`) |
| `ga.py` | `reversed_dir`, `target_binary`, `compiler_includes` |
| `sync.py` | `reversed_dir` |
| `next.py` | `reversed_dir` |
| `skeleton.py` | `reversed_dir` |
| `batch.py` | `reversed_dir`, `target_binary` |
| `asm.py` | `target_binary`, `capstone_arch`, `capstone_mode` |
| `annotation.py` | Canonical annotation parser — used by verify, batch, sync, ga, nasm |
| `binary_loader.py` | LIEF-based binary loading — used by batch, flirt |
| `matcher/scoring.py` | `capstone_arch`, `capstone_mode` |
| `matcher/compiler.py` | `compiler_profile` (drives flag axes) |
| `matcher/parsers.py` | `padding_bytes` |
| `catalog.py` | `image_base`, `text_va` (via verify.py) |
| `status.py` | `reversed_dir`, `text_va` |
| `data.py` | `reversed_dir`, `target_binary`, `image_base` |
| `depgraph.py` | `reversed_dir` |
| `lint.py` | `reversed_dir`, module name |
| `init.py` | All target config (scaffolding) |

## Disassemblers & Decompilers

### Ghidra 11.4 (Primary)

- **Package**: `ghidra-git-bin 11.4-7` (AUR)
- **Integration**: Connected via ReVa MCP (Model Context Protocol)
- **Program**: `/target.dll` loaded in project
- **Functions found**: 496 (97 user-named, 399 default `FUN_` names)
- **Capabilities used**:
  - Decompilation (`get-decompilation`)
  - Cross-references (`find-cross-references`)
  - Memory reads (`read-memory`)
  - String search (`search-strings-regex`, `get-strings-by-similarity`)
  - Labels and comments (`create-label`, `set-comment`, `set-bookmark`)
  - Structure editing (`parse-c-structure`, `modify-structure-from-c`)
  - Data flow tracing (`trace-data-flow-backward`, `trace-data-flow-forward`)
  - Import/export analysis (`list-imports`, `list-exports`, `find-import-references`)
  - Call graph analysis (`get-call-graph`, `get-call-tree`)
  - Vtable analysis (`analyze-vtable`)

### Binary Ninja Free 5.2

- **Package**: Installed at `/opt/binaryninja-free/`
- **Version**: 5.2.8722 free
- **Status**: Installed, not yet integrated into pipeline
- **Capabilities**:
  - Disassembly, IL lifting (LLIL/MLIL/HLIL)
  - **MSVC signature database**: `signatures/windows-x86/msvcrt_windows-x86.sig` (can auto-identify CRT functions)
  - **Windows x86 type libraries**: Full set of `.bntl` files for Win32 API (kernel32, ws2_32, user32, etc.)
  - Ghidra decompiler plugin (`plugins/libghidra.so`) for Ghidra-compatible decompilation
  - Built-in YASM assembler
- **Potential use**:
  - Cross-validation of function boundaries (third opinion vs Ghidra/r2)
  - MSVC CRT signature matching to auto-identify library functions
  - HLIL output as alternative decompilation reference
- **Notes**: No Python API available in free version; GUI-only analysis. Headless scripting requires commercial license.

### IDA Free 9.2.0

- **Package**: `ida-free 9.2.0-1` (AUR)
- **Location**: `/opt/ida-free/`
- **Status**: Installed but not currently integrated into pipeline
- **Capabilities**: Disassembly, decompilation (limited in free version), FLIRT signatures
- **Potential use**: Cross-validation of function boundaries, FLIRT-based CRT identification
- **Notes**: Headless mode available via `idat` binary; could be integrated for automated analysis

### radare2 5.9.8

- **Package**: `radare2 5.9.8-1.1` (community)
- **Binary**: `/usr/bin/r2`
- **Functions found**: 471 (from prior `aaa` analysis)
- **Data files**:
  - `src/target_name/r2_functions.txt` — Human-readable function list (VA, size, name)
  - `src/target_name/r2_functions.json` — Full r2 analysis output with metadata (offset, size, name, ninstrs, calltype, signature, etc.)
- **Known issues**:
  - 2 bogus size entries: `0x1000ad40` (1,106,626B — actually 600B) and `0x10018200` (16,941,438B — actually 123B)
  - r2 names use `fcn.XXXXXXXX` and `sub.DLL_funcname` conventions
- **Capabilities**: Disassembly, basic decompilation (via r2dec/r2ghidra plugins if installed), scripting via r2pipe

---

## Binary Analysis Tools

### DUMPBIN.EXE (MSVC6)

- **Location**: `tools/MSVC600/VC98/Bin/DUMPBIN.EXE`
- **Execution**: Via Wine (`wine tools/MSVC600/VC98/Bin/DUMPBIN.EXE`)
- **Version**: 6.00.8447
- **Capabilities**:
  - `/EXPORTS` — List exported functions (example.dll exports: `Init`, `Exit`)
  - `/IMPORTS` — List imported DLLs and functions
  - `/HEADERS` — PE headers, section table
  - `/RELOCATIONS` — Base relocation entries
  - `/DISASM` — Disassembly
  - `/SYMBOLS` — COFF symbol table (if present)
  - `/RAWDATA` — Raw section data dumps
  - `/DEPENDENTS` — DLL dependency tree

```bash
# Examples
wine tools/MSVC600/VC98/Bin/DUMPBIN.EXE /EXPORTS target.dll
wine tools/MSVC600/VC98/Bin/DUMPBIN.EXE /IMPORTS target.dll
wine tools/MSVC600/VC98/Bin/DUMPBIN.EXE /HEADERS target.dll
wine tools/MSVC600/VC98/Bin/DUMPBIN.EXE /DISASM /RAWDATA:1 some_file.obj
```

### objconv 2.56

- **Package**: `objconv 2.56-1` (AUR)
- **Binary**: `/usr/bin/objconv`
- **Capabilities**:
  - COFF/PE/ELF/OMF format conversion
  - comp.id extraction (verify compiler version: `000A2636` = MSVC6)
  - Disassembly output
  - Symbol table dump

```bash
# Verify compiler ID in .obj
objconv -fasm file.obj /dev/null 2>&1 | grep "comp.id"
```

### objdump (GNU Binutils 2.46)

- **Package**: System binutils
- **Binary**: `/usr/bin/objdump`
- **Capabilities**:
  - `-t` — Symbol table (empty for stripped PE like target.dll)
  - `-x` — All headers including export table
  - `-d` — Disassembly
  - `-r` — Relocation entries
  - `-s` — Full section contents
  - Useful for analyzing `.obj` files produced by our MSVC6 compilations

```bash
# Dump export table
objdump -x target.dll | grep -A30 "Export Table"
# Disassemble an obj
objdump -d -M intel candidate.obj
```

### llvm-objdump

- **Binary**: `/usr/bin/llvm-objdump`
- **Capabilities**: Same as GNU objdump but with LLVM backend; sometimes gives better PE parsing

### yara 4.5.5

- **Package**: `yara 4.5.5-1.1`
- **Binary**: `/usr/bin/yara`
- **Capabilities**:
  - Signature-based binary pattern matching
  - Can write rules to identify compiler patterns, CRT signatures, library code
  - Useful for bulk identification of library functions

```bash
# Example: find functions with specific prologue
echo 'rule msvc6_stdcall { strings: $a = { 55 8B EC 83 EC } condition: $a }' > /tmp/test.yar
yara /tmp/test.yar target.dll
```

---

## MSVC6 Toolchain

All run under Wine from `tools/MSVC600/VC98/Bin/`:

| Tool | Purpose |
|------|---------|
| `CL.EXE` | C/C++ compiler (our primary compilation tool) |
| `LINK.EXE` | Linker |
| `LIB.EXE` | Library manager (extract .obj from .lib archives) |
| `DUMPBIN.EXE` | Binary dumper (see above) |
| `EDITBIN.EXE` | Binary editor (modify PE headers, base addresses) |
| `MKTYPLIB.EXE` | Type library compiler |

---

## Python Libraries

### Installed (Available for Scripts)

| Library | Version | Source | Use in Project |
|---------|---------|--------|----------------|
| **capstone** | 5.0.7 | `python-capstone` (pacman) | x86 disassembly in matcher scoring |
| **pefile** | 2024.8.26 | `python-pefile` (pacman) | PE parsing in matcher |
| **pygad** | 3.3.1 | `pip install pygad` | Genetic algorithm library for converged engine |
| **pycparser** | 3.0 | `pip install pycparser` | C AST parser for AST-aware mutations |
| **pyelftools** | 0.32 | `python-pyelftools` (pacman) | ELF parsing (not needed for PE32 but available) |
| **pycryptodome** | 3.23.0 | `python-pycryptodome` (pacman) | Crypto primitives |
| **numpy** | 2.4.2 | `python-numpy` (pacman) | Numeric computation |
| **matplotlib** | 3.10.8 | `python-matplotlib` (pacman) | Plotting / visualization |
| **pillow** | 12.1.1 | `python-pillow` (pacman) | Image processing |
| **pyyaml** | 6.0.3 | `python-yaml` (pacman) | YAML parsing |
| **requests** | 2.32.5 | `python-requests` (pacman) | HTTP client |
| **prettytable** | 3.17.0 | `python-prettytable` (pacman) | Table formatting |
| **psutil** | 7.2.2 | `python-psutil` (pacman) | Process utilities |
| **selenium** | 4.40.0 | `python-selenium` (pacman) | Browser automation |

### Not Installed (Could Be Added)

| Library | Purpose | Install |
|---------|---------|---------|
| **r2pipe** | Programmatic radare2 access from Python | `pip install r2pipe` |
| **lief** | 0.16+ | `uv pip install lief` | PE/ELF/Mach-O parsing — **core dependency**, used by `matcher/parsers.py`, `binary_loader.py`, and `test.py` for COFF symbol extraction |
| **angr** | Symbolic execution, CFG recovery | `pip install angr` (heavy) |
| **frida** | Dynamic instrumentation | `pip install frida-tools` |
| **keystone** | Assembler engine (x86 → bytes) | `pip install keystone-engine` |
| **unicorn** | CPU emulation | `pip install unicorn` |
| **ropper** | ROP gadget finder | `pip install ropper` |
| **yara-python** | YARA rules from Python | `pip install yara-python` |
| **rzpipe** | Programmatic rizin access | `pip install rzpipe` |

---

## Function Discovery Comparison

| Source | Functions | Exports | Notes |
|--------|-----------|---------|-------|
| **Ghidra** | 496 | 2 | Most accurate sizes; includes thunks; connected via MCP |
| **radare2** | 471 | 2 | 2 bogus sizes, 10 IAT thunks, 21 tiny wrappers |
| **Binary Ninja** | TBD | 2 | Not yet analyzed; has MSVC sig matching |
| **IDA Free** | TBD | 2 | Not yet analyzed; has FLIRT signatures |
| **DUMPBIN** | — | 2 | `Init` @ 0x10009320, `Exit` @ 0x10009350 |
| **objdump** | 0 | 2 | No COFF symbols (PE is stripped) |

### Known Discrepancies

| Issue | Details |
|-------|---------|
| Ghidra has 25 more functions than r2 | Ghidra may detect functions r2 missed, or split functions differently |
| r2 bogus sizes | `0x1000ad40`: r2=1,106,626B vs Ghidra=600B; `0x10018200`: r2=16,941,438B vs Ghidra=123B |
| 1-byte "functions" | `0x10006f30` and `0x10016670` are 1B each — likely `ret` stubs or alignment, seen by both tools |
| IAT thunks | 7× WS2_32.dll + 1× KERNEL32.dll `jmp [IAT]` stubs at 6B each — not reversible C code |

### Cross-Tool Tracking

The `catalog.py` pipeline tracks which tools detected each function via the `detected_by` field in `db/data.json`. Each function entry includes:

```json
{
  "detected_by": ["ghidra", "r2"],
  "size_by_tool": {"ghidra": 302, "r2": 302},
  "ghidra_name": "FUN_10001000",
  "r2_name": "fcn.10001000",
  "is_thunk": false
}
```

The `ghidra_functions.json` file is generated by `catalog.py --export-ghidra` and caches the Ghidra function list for offline cross-referencing.

### Pipeline Scripts

All scripts live under `tools/` and are installed as CLI entry points via `pyproject.toml`.
Tools use **typer** for rich CLI help with colors, auto-completion, `--target` support,
and detailed usage examples via `rich_markup_mode="rich"` with epilog text.
Run any tool with `--help` to see usage examples and context.

**Entry points** (invoke with `uv run rebrew-<name>` or after `uv sync`):

| Entry Point | Script | Description |
|-------------|--------|-------------|
| `rebrew` | `main.py` | Unified CLI entry point for all subcommands |
| `rebrew-init` | `init.py` | Scaffold a new project directory and `rebrew.toml` |
| `rebrew-test` | `test.py` | Quick compile-and-compare (single or multi-function files); `--json` structured output |
| `rebrew-asm` | `asm.py` | Dump disassembly from target binary at a VA; `--json` structured output |
| `rebrew-next` | `next.py` | Prioritize uncovered functions by difficulty; auto-filters unmatchable; `--json` for all modes |
| `rebrew-skeleton` | `skeleton.py` | Generate annotated `.c` skeleton from VA (with `--decomp` and `--append` for multi-function files) |
| `rebrew-catalog` | `catalog.py` | Parse annotations, generate catalog + coverage JSON |
| `rebrew-sync` | `sync.py` | Sync annotations to Ghidra via ReVa MCP (`--push`, `--apply`, `--export`, `--summary`) |
| `rebrew-lint` | `lint.py` | Lint annotation standards in decomp C files |
| `rebrew-batch` | `batch.py` | Batch extract and disassemble functions from binary |
| `rebrew-match` | `match.py` / `matcher/` | GA matching engine (diff with `--mm`, flag-sweep with `--tier`, GA); `--diff-only --json` structured diff |
| `rebrew-ga` | `ga.py` | Batch GA runner for STUB functions and near-miss MATCHING functions |
| `rebrew-verify` | `verify.py` | Compile all `.c` files and verify byte match against DLL; `--json` structured reports |
| `rebrew-build-db` | `build_db.py` | Build SQLite `db/coverage.db` from `data_*.json` ([schema docs](DB_FORMAT.md)); stamps `db_version`, stores `detected_by`/`size_by_tool`/`textOffset` per function, `origin`/`size` per global |
| `rebrew-cfg` | `cfg.py` | Read and edit `rebrew.toml` programmatically (idempotent) |
| `rebrew-nasm` | `nasm.py` | NASM assembly extraction |
| `rebrew-flirt` | `flirt.py` | FLIRT signature scanning |
| `rebrew-status` | `status.py` | Project reversing status overview (per-target breakdowns) |
| `rebrew-data` | `data.py` | Global data scanner for .data/.rdata/.bss; `--bss` layout verification; `--dispatch` vtable detection; `// DATA:` annotations |
| `rebrew-graph` | `depgraph.py` | Function dependency graph (mermaid, DOT, summary) |


All typer-based tools support `--target / -t` to select a target from `rebrew.toml` and
read defaults (binary path, reversed_dir, compiler settings) from the project config.

```bash
# Examples
rebrew-asm 0x100011f0 64               # Disassemble 64 bytes at VA
rebrew-asm 0x100011f0 --target server.dll  # Use alternate target from config
rebrew-lint --fix                       # Auto-fix old annotations
rebrew-skeleton 0x10003da0 --decomp     # Skeleton with inline decompilation
rebrew-skeleton 0x10003da0 --decomp --decomp-backend r2dec  # Use r2dec backend
rebrew-skeleton 0x10003da0 --append crt_env.c               # Append to multi-function file
rebrew-next --stats                     # Show progress statistics
rebrew-next --improving                 # List MATCHING functions sorted by byte delta
rebrew-next --unmatchable               # Show auto-detected unmatchable functions
rebrew-catalog --summary --csv          # Generate catalog + CSV
rebrew-status                           # Show reversing progress overview
rebrew-status --json                    # Machine-readable JSON output
rebrew-verify                           # Compile and verify all reversed functions
rebrew-verify --json                    # Structured JSON report to stdout
rebrew-verify -o db/verify_results.json # Write report to file
rebrew-data                             # Inventory globals in .data/.rdata/.bss
rebrew-data --conflicts                 # Show only type-conflict globals
rebrew-data --bss                       # Verify .bss layout and detect gaps
rebrew-data --bss --json                # BSS layout report as JSON
rebrew-data --dispatch                  # Detect dispatch tables / vtables in .data/.rdata
rebrew-data --dispatch --json           # Dispatch tables as JSON
rebrew-test src/target_name/my_func.c --json   # JSON test result
rebrew-next --stats --json                     # JSON progress stats
rebrew-next --json                             # JSON recommendations
rebrew-match --diff-only --json src/target_name/my_func.c  # JSON diff
rebrew-asm 0x10003ca0 --size 77 --json         # JSON disassembly
rebrew-ga                               # Batch GA on all STUB functions
rebrew-ga --near-miss                   # Batch GA on MATCHING functions with ≤10B delta
rebrew-ga --near-miss --threshold 5     # Only attempt functions with ≤5B delta
rebrew-ga --dry-run                     # List candidates without running GA
rebrew-graph                            # Mermaid call graph from extern decls
rebrew-graph --format dot --origin GAME  # DOT graph filtered to GAME origin
rebrew-graph --focus FuncName --depth 2  # Neighbourhood of a function
```

#### Config Editor (`rebrew-cfg`)

Programmatically read and write `rebrew.toml` using `tomlkit` for format-preserving
edits (comments and ordering are retained). All mutating commands are idempotent —
running the same command twice produces the same result with no errors.

| Subcommand | Description | Example |
|------------|-------------|---------|
| `list-targets` | List all defined targets | `rebrew-cfg list-targets` |
| `show [KEY]` | Print config or a dot-separated key | `rebrew-cfg show compiler.cflags` |
| `add-target NAME` | Add a target section + create dirs | `rebrew-cfg add-target client.exe -b original/client.exe` |
| `remove-target NAME` | Remove a target section | `rebrew-cfg remove-target old_target` |
| `set KEY VALUE` | Set a scalar config key | `rebrew-cfg set compiler.cflags "/O1"` |
| `add-origin ORIGIN` | Append origin to targets list | `rebrew-cfg add-origin ZLIB -t server.dll` |
| `remove-origin ORIGIN` | Remove origin from targets list | `rebrew-cfg remove-origin ZLIB -t server.dll` |
| `set-cflags ORIGIN FLAGS` | Set cflags preset for an origin | `rebrew-cfg set-cflags ZLIB "/O3" -t server.dll` |

```bash
# Example workflow: add a second binary and configure it
rebrew-cfg add-target client.exe --binary original/Client/client.exe --arch x86_32
rebrew-cfg add-origin ZLIB --target client.exe
rebrew-cfg set-cflags GAME "/O2 /Gd" --target client.exe
rebrew-cfg show targets.client.exe
```

#### Internal Matcher Modules

| Script | Purpose |
|--------|---------|
| `matcher/scoring.py` | Multi-metric fitness scoring (byte, reloc, mnemonic) |
| `matcher/compiler.py` | Compilation backend + `flag_sweep(tier=)` + `generate_flag_combinations(tier=)` |
| `matcher/flags.py` | `FlagSet`/`Checkbox` primitives (compatible with decomp.me) |
| `matcher/flag_data.py` | Auto-generated MSVC flags + sweep tiers (from `tools/sync_decomp_flags.py`) |
| `matcher/parsers.py` | COFF `.obj` and PE byte extraction (LIEF-based) |
| `matcher/mutator.py` | 40+ C mutation operators for GA |
| `matcher/core.py` | SQLite `BuildCache` + GA checkpointing |

#### Annotation & Sync

| Script | Purpose | Usage |
|--------|---------|-------|
| `annotation.py` | Canonical annotation parser (parse_c_file, parse_c_file_multi, normalize_status, etc.) | Imported by verify, batch, sync, ga, nasm |
| `lint.py` | Annotation linter (E001-E014 / W001-W015) | `rebrew-lint` |
| `lint.py --fix` | Auto-migrate old annotations to reccmp-style | `rebrew-lint --fix` |
| `sync.py` | Sync annotations to Ghidra via ReVa MCP; skips generic `func_` labels by default | `rebrew-sync --push` (export + apply), `--export`, `--apply`, `--summary` |

#### Library Identification

| Script | Purpose | Usage |
|--------|---------|-------|
| `flirt.py` | FLIRT signature matching (no IDA required) | `rebrew-flirt [sig_dir]` |
| `gen_flirt_pat.py` | Generate `.pat` files from COFF `.lib` archives | `uv run python tools/gen_flirt_pat.py LIBCMT.LIB -o out.pat` |

#### Utilities & Experimental

| Script | Purpose | Usage |
|--------|---------|-------|
| `extract_target.py` | Compile C, extract function bytes via MAP file | `uv run python tools/extract_target.py --cl ... --symbol _add` |
| `train_mutation_model.py` | Train mutation guidance model from GA data | `uv run python tools/train_mutation_model.py data.jsonl` |
| `batch_test.sh` | Batch test all reversed functions | `./tools/batch_test.sh` |

---

## Usage Recommendations

### For Function Identification
1. Start with **Ghidra** decompilation (best quality, connected via MCP)
2. Cross-reference with **r2** names for alternative analysis perspective
3. Use **DUMPBIN /IMPORTS** to identify library boundaries
4. Use **yara** rules for bulk pattern identification of CRT/zlib functions

### For Byte Comparison
1. **rebrew-match** `--diff-only` mode for side-by-side disassembly (add `--mm` to show only `**` lines)
2. **objconv** to verify comp.id on compiled .obj files
3. **DUMPBIN /DISASM** for quick .obj inspection

### For Compiler Flag Analysis
1. **rebrew-match** `--flag-sweep-only --tier normal` for flag sweep (~21K combos)
2. Use `--tier quick` for fast iteration (192 combos) or `--tier thorough` for deep search (~1M)
3. **objconv** comp.id verification to confirm same compiler
4. Re-sync flags from decomp.me: `python tools/sync_decomp_flags.py`

### For Structure Recovery
1. **Ghidra** structure editor via MCP (`parse-c-structure`, `get-structure-info`)
2. **DUMPBIN /RAWDATA** for raw data inspection at specific offsets
