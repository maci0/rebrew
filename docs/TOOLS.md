# Reverse Engineering Tools Inventory

Tools available for the rebrew reverse engineering project.

---

## Configuration System

All tools read project settings from **`rebrew.toml`** via the **`tools/config.py`** loader. This eliminates hardcoded paths and makes the toolchain portable to different targets.

### `rebrew.toml` (Project Root)

Multiple targets are supported in `rebrew.toml`.
Tools default to the first target unless `--target <name>` is passed.

```toml
[targets.server_dll]
binary = "original/Server/server.dll"   # Target binary (relative to project root)
format = "pe"                            # Binary format: pe, elf, macho
arch = "x86_32"                          # Architecture: x86_32, x86_64, arm32, arm64
reversed_dir = "src/server_dll"          # Where reversed .c files live
function_list = "src/server_dll/r2_functions.txt"
bin_dir = "bin/server_dll"

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
| `target_name` | Key under `[targets]` | Active target name (e.g. `"server_dll"`) |
| `all_targets` | All keys under `[targets]` | List of all available target names |
| `target_binary` | `[targets.<name>].binary` | Resolved path to the target executable/DLL |
| `image_base` | Auto-detected from PE | `0x10000000` for server.dll |
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

| Profile | Flag Axes | Obj Format | Symbol Naming |
|---------|-----------|------------|---------------|
| `msvc6` | `/O1..Od`, `/Oy`, `/G5..6`, `/Gd..Gz`, `/Gy`, `/Oi` | COFF | `_func` |
| `gcc` | `-O0..3`, `-fomit-frame-pointer`, `-mtune=*` | ELF | `func` |
| `clang` | Same as GCC | ELF/Mach-O | `func` |

### Tools using config

All 14 tools read from `rebrew.toml`. Each uses `try/except` with hardcoded fallbacks:

| Tool | Config Values Used |
|------|--------------------|
| `verify.py` | `image_base`, `text_va`, `text_raw_offset`, `target_binary`, `reversed_dir` |
| `test_func.py` | `target_binary`, `text_va`, `text_raw_offset`, compiler paths |
| `nasm_extract.py` | `target_binary`, `text_va`, `text_raw_offset`, `reversed_dir` |
| `ga_batch.py` | `reversed_dir`, `target_binary`, `compiler_includes` |
| `ghidra_sync.py` | `reversed_dir` |
| `lint_annotations.py` | `reversed_dir` |
| `next_work.py` | `reversed_dir` |
| `gen_skeleton.py` | `reversed_dir` |
| `batch_extract.py` | `reversed_dir`, `target_binary` |
| `dump_asm.py` | `target_binary`, `capstone_arch`, `capstone_mode` |
| `matcher/scoring.py` | `capstone_arch`, `capstone_mode` |
| `matcher/compiler.py` | `compiler_profile` (drives flag axes) |
| `matcher/parsers.py` | `padding_bytes` |
| `catalog.py` | `image_base`, `text_va` (via verify.py) |

## Disassemblers & Decompilers

### Ghidra 11.4 (Primary)

- **Package**: `ghidra-git-bin 11.4-7` (AUR)
- **Integration**: Connected via ReVa MCP (Model Context Protocol)
- **Program**: `/server.dll` loaded in project
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
  - `src/server_dll/r2_functions.txt` — Human-readable function list (VA, size, name)
  - `src/server_dll/r2_functions.json` — Full r2 analysis output with metadata (offset, size, name, ninstrs, calltype, signature, etc.)
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
  - `/EXPORTS` — List exported functions (server.dll exports: `Init`, `Exit`)
  - `/IMPORTS` — List imported DLLs and functions
  - `/HEADERS` — PE headers, section table
  - `/RELOCATIONS` — Base relocation entries
  - `/DISASM` — Disassembly
  - `/SYMBOLS` — COFF symbol table (if present)
  - `/RAWDATA` — Raw section data dumps
  - `/DEPENDENTS` — DLL dependency tree

```bash
# Examples
wine tools/MSVC600/VC98/Bin/DUMPBIN.EXE /EXPORTS server.dll
wine tools/MSVC600/VC98/Bin/DUMPBIN.EXE /IMPORTS server.dll
wine tools/MSVC600/VC98/Bin/DUMPBIN.EXE /HEADERS server.dll
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
  - `-t` — Symbol table (empty for stripped PE like server.dll)
  - `-x` — All headers including export table
  - `-d` — Disassembly
  - `-r` — Relocation entries
  - `-s` — Full section contents
  - Useful for analyzing `.obj` files produced by our MSVC6 compilations

```bash
# Dump export table
objdump -x server.dll | grep -A30 "Export Table"
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
yara /tmp/test.yar server.dll
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
| **capstone** | 5.0.7 | `python-capstone` (pacman) | x86 disassembly in matcher.py scoring |
| **pefile** | 2024.8.26 | `python-pefile` (pacman) | PE parsing in matcher.py |
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
| **lief** | Modern PE/ELF/MachO parsing (richer than pefile) | `pip install lief` |
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

The `catalog.py` pipeline tracks which tools detected each function via the `detected_by` field in `recoverage/data.json`. Each function entry includes:

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
Tools use **typer** for rich CLI help with colors, auto-completion, and `--target` support.

**Entry points** (invoke with `uv run rebrew-<name>` or after `uv sync`):

| Entry Point | Script | Description |
|-------------|--------|-------------|
| `rebrew-test` | `test_func.py` | Quick compile-and-compare for a single function |
| `rebrew-asm` | `dump_asm.py` | Dump disassembly from target binary at a VA |
| `rebrew-next` | `next_work.py` | Prioritize uncovered functions by difficulty |
| `rebrew-skeleton` | `gen_skeleton.py` | Generate annotated `.c` skeleton from VA |
| `rebrew-catalog` | `catalog.py` | Parse annotations, generate catalog + coverage JSON |
| `rebrew-sync` | `ghidra_sync.py` | Sync annotation data with Ghidra |
| `rebrew-lint` | `lint_annotations.py` | Lint annotation standards in decomp C files |
| `rebrew-batch` | `batch_extract.py` | Batch extract and disassemble functions from DLL |
| `rebrew-match` | `matcher.py` | Unified GA engine (diff, flag-sweep, batch GA) |
| `rebrew-ga` | `ga_batch.py` | Batch GA runner for STUB functions |
| `rebrew-verify` | `verify.py` | Compile all `.c` files and verify byte match against DLL |

All typer-based tools support `--target / -t` to select a target from `rebrew.toml` and
read defaults (binary path, reversed_dir, compiler settings) from the project config.

```bash
# Examples
rebrew-asm 0x100011f0 64               # Disassemble 64 bytes at VA
rebrew-asm 0x100011f0 --target client   # Use alternate target from config
rebrew-lint --fix                       # Auto-fix old annotations
rebrew-next --stats                     # Show progress statistics
rebrew-catalog --summary --csv          # Generate catalog + CSV
```

#### Internal Matcher Modules

| Script | Purpose |
|--------|---------|
| `matcher/scoring.py` | Multi-metric fitness scoring (byte, reloc, mnemonic) |
| `matcher/compiler.py` | Compilation backend + flag sweep (Wine/MSVC6, GCC) |
| `matcher/parsers.py` | COFF `.obj` and PE byte extraction |
| `matcher/mutator.py` | 40+ C mutation operators for GA |
| `matcher/core.py` | SQLite `BuildCache` + GA checkpointing |

#### Annotation & Sync

| Script | Purpose | Usage |
|--------|---------|-------|
| `lint_annotations.py` | Annotation linter (E001-E010 / W001-W007) | `rebrew-lint` |
| `lint_annotations.py --fix` | Auto-migrate old annotations to reccmp-style | `rebrew-lint --fix` |
| `ghidra_sync.py` | Export annotations as Ghidra commands | `rebrew-sync --export` |

#### Library Identification

| Script | Purpose | Usage |
|--------|---------|-------|
| `identify_libs.py` | FLIRT signature matching (no IDA required) | `uv run python tools/identify_libs.py flirt_sigs/` |
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
1. **matcher.py** `--diff-only` mode for side-by-side disassembly
2. **objconv** to verify comp.id on compiled .obj files
3. **DUMPBIN /DISASM** for quick .obj inspection

### For Compiler Flag Analysis
1. **matcher.py** `--flag-sweep-only` for exhaustive flag combination testing
2. **objconv** comp.id verification to confirm same compiler

### For Structure Recovery
1. **Ghidra** structure editor via MCP (`parse-c-structure`, `get-structure-info`)
2. **DUMPBIN /RAWDATA** for raw data inspection at specific offsets
