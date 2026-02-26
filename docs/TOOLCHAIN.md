# Toolchain & Environment

External tools that rebrew integrates with or builds on top of.

---

## MSVC6 Toolchain (Compile Backend)

All run under Wine from `tools/MSVC600/VC98/Bin/`:

| Tool | Purpose |
|------|---------|
| `CL.EXE` | C/C++ compiler (primary compilation tool) |
| `LINK.EXE` | Linker |
| `LIB.EXE` | Library manager (extract .obj from .lib archives) |
| `DUMPBIN.EXE` | Binary dumper (see below) |
| `EDITBIN.EXE` | Binary editor (modify PE headers, base addresses) |

---

## Disassemblers & Decompilers

### Ghidra (Primary)

Connected via ReVa MCP (Model Context Protocol). Rebrew uses the following MCP tools:

| Capability | MCP Tool |
|------------|----------|
| Decompilation | `get-decompilation` |
| Cross-references | `find-cross-references` |
| Memory reads | `read-memory` |
| String search | `search-strings-regex`, `get-strings-by-similarity` |
| Labels and comments | `create-label`, `set-comment`, `set-bookmark` |
| Structure editing | `parse-c-structure`, `modify-structure-from-c` |
| Data flow | `trace-data-flow-backward`, `trace-data-flow-forward` |
| Imports/exports | `list-imports`, `list-exports`, `find-import-references` |
| Call graph | `get-call-graph`, `get-call-tree` |
| Vtable analysis | `analyze-vtable` |

See [GHIDRA_SYNC.md](GHIDRA_SYNC.md) for the sync feature matrix and roadmap.

### radare2

Used for function boundary detection and as an alternative analysis perspective.

**Data files consumed by rebrew:**
- `r2_functions.txt` — Human-readable function list (VA, size, name)
- `r2_functions.json` — Full r2 analysis output with metadata
- `ghidra_functions.json` — Ghidra function list (consumed by `rebrew-skeleton`, `rebrew-next`)

**Known issues:**
- r2 occasionally reports bogus sizes for some functions
- r2 names use `fcn.XXXXXXXX` and `sub.DLL_funcname` conventions

### IDA / Binary Ninja

Not integrated into the pipeline. Potential uses:
- Cross-validation of function boundaries (third opinion vs Ghidra/r2)
- MSVC CRT signature matching (Binary Ninja has built-in MSVC sigs)
- FLIRT-based CRT identification (IDA)

---

## Binary Analysis Tools

### DUMPBIN.EXE (MSVC6)

Part of the MSVC6 toolchain. Run via Wine:

```bash
wine tools/MSVC600/VC98/Bin/DUMPBIN.EXE /EXPORTS target.dll
wine tools/MSVC600/VC98/Bin/DUMPBIN.EXE /IMPORTS target.dll
wine tools/MSVC600/VC98/Bin/DUMPBIN.EXE /HEADERS target.dll
wine tools/MSVC600/VC98/Bin/DUMPBIN.EXE /DISASM /RAWDATA:1 some_file.obj
```

### objconv

COFF/PE/ELF/OMF format conversion and comp.id extraction (verify compiler version):

```bash
objconv -fasm file.obj /dev/null 2>&1 | grep "comp.id"
```

### objdump (GNU Binutils)

```bash
objdump -x target.dll | grep -A30 "Export Table"   # Dump export table
objdump -d -M intel candidate.obj                   # Disassemble an obj
```

### yara

Signature-based binary pattern matching for bulk identification:

```bash
echo 'rule msvc6_stdcall { strings: $a = { 55 8B EC 83 EC } condition: $a }' > /tmp/test.yar
yara /tmp/test.yar target.dll
```

---

## Python Libraries

### Core Dependencies

| Library | Use in Project |
|---------|----------------|
| **capstone** | x86 disassembly in matcher scoring |
| **lief** | PE/ELF/Mach-O parsing — core dependency for `binary_loader.py`, `matcher/parsers.py`, `test.py` |
| **pycparser** | C AST parser for AST-aware GA mutations |
| **numpy** | Numeric computation |
| **typer** | CLI framework with rich help |
| **rich** | Terminal formatting |

### Available (not core)

| Library | Use in Project |
|---------|----------------|
| **pyelftools** | ELF parsing (not needed for PE32) |
| **matplotlib** | Plotting / visualization |
| **pyyaml** | YAML parsing (for reccmp-project.yml) |

### Not Installed (could be added)

| Library | Purpose |
|---------|---------|
| **r2pipe** | Programmatic radare2 access from Python |
| **angr** | Symbolic execution, CFG recovery |
| **keystone** | Assembler engine (x86 -> bytes) |
| **unicorn** | CPU emulation |

---

## Function Discovery

Multiple tools detect functions independently. Ghidra typically finds the most (most
accurate sizes, includes thunks), while r2 occasionally reports bogus sizes. The catalog
pipeline tracks which tools detected each function via the `detected_by` field.

### Common Discrepancies

| Issue | Details |
|-------|---------|
| Tool count mismatch | Ghidra typically finds more functions than r2 (missed functions or different splitting) |
| 1-byte "functions" | Likely `ret` stubs or alignment — seen by both tools |
| IAT thunks | 6-byte `jmp [IAT]` stubs — not reversible C code |
| Size disagreements | Tools may report different function sizes; `canonical_size` picks the best |

See [NAME_NORMALIZATION.md](NAME_NORMALIZATION.md) for how tool-specific names
are normalized.

---

## Usage Recommendations

### For Function Identification
1. Start with **Ghidra** decompilation (best quality, connected via MCP)
2. Cross-reference with **r2** names for alternative analysis perspective
3. Use **DUMPBIN /IMPORTS** to identify library boundaries
4. Use **yara** rules for bulk pattern identification of CRT/zlib functions

### For Byte Comparison
1. `rebrew-match --diff-only` for side-by-side disassembly (add `--mm` for structural diffs only)
2. **objconv** to verify comp.id on compiled .obj files
3. **DUMPBIN /DISASM** for quick .obj inspection

### For Compiler Flag Analysis
1. `rebrew-match --flag-sweep-only --tier normal` (~21K combos)
2. Use `--tier quick` for fast iteration (192) or `--tier thorough` for deep search (~1M)
3. **objconv** comp.id verification to confirm same compiler
4. Re-sync flags from decomp.me: `python tools/sync_decomp_flags.py`

### For Structure Recovery
1. **Ghidra** structure editor via MCP (`parse-c-structure`, `get-structure-info`)
2. **DUMPBIN /RAWDATA** for raw data inspection at specific offsets
