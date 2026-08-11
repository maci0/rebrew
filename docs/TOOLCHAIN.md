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

## MinGW GCC (gcc-pe profile, for PE/x86_32 targets)

Some PE/x86_32 binaries are built with MinGW GCC instead of MSVC (identifiable
by a `.buildid` section, GNU-style multi-byte `0f 1f` nops, and a call-based
stack probe `mov eax, N; call ___chkstk_ms`).  For these, use the `gcc-pe`
compiler profile:

```toml
[compiler]
profile = "gcc-pe"
command = "i686-w64-mingw32-gcc"
includes = ""            # mingw ships its own headers
libs = ""
cflags = "-O2 -march=pentium4"
base_cflags = ""         # -c is added by rebrew for posix-style profiles
```

`rebrew init --compiler gcc-pe` creates this configuration.  The compile
pipeline is profile-aware: `-I/-c/-o` flag style, no Wine runner, and PATH
resolution of the bare toolchain name.

**Caveat — codegen-version sensitivity:** byte-exact matching requires the
author's *exact* GCC version.  Modern GCC (e.g. 16.x) differs from older GCC
(4.x–7.x) in argument passing (accumulate-outgoing-args), stack probing
(chkstk convention), and scheduling, so old MinGW-built binaries usually
match only *structurally* (use `rebrew diff` structural ratio) — document the
semantic decomp and blocker the byte delta rather than forcing a pass.

**Analysis note:** rizin's `aaa` mis-merges functions on this toolchain —
use `aa; aap` (function-prelude analysis) for the function list.  Ghidra
headless gives correct boundaries but is slow on loaded machines.

---

## Delphi 1.0 (16-bit NE compile backend — future matching)

The vendored `tools/DELPHI10` toolchain (DCC.EXE, DOS DPMI app run under
DOSBox headless) compiles 16-bit Windows 3.x NE executables; the
`rebrew.delphi16.compile_ne` wrapper makes it invocable from Python and
parses the output with the native NE loader.  Byte matching is not yet
wired (ADR-001) — see `tools/DELPHI10/README.md` for the recipe and the
RTM.EXE / non-tmpfs requirements, and the NE section below for the
analysis-side support matrix.

---

## Toolchain standardization (docker-first)

`rebrew toolchain` (see [CLI.md](CLI.md)) manages compiler toolchains
through a uniform abstraction (`rebrew.toolchain`), modeled on Godbolt's
Compiler Explorer convention: **one container image per toolchain-version**,
with the compiler behind a wrapper inside the image, so the host invocation
is always `docker run <image> <compiler> <args>`.  The runner falls back to
a vendored host path (`tools/…`) or PATH binary when docker or the image is
unavailable — the same profile works either way.

Current toolchains (`rebrew toolchain list`): `msvc6` (wine), `delphi16`
(DOSBox), `gcc-pe` (native MinGW), `watcom` (native Open Watcom 2.0 —
installed at `tools/WATCOM`), `msvc1.52` (16-bit, DOSBox via
`rebrew.msvc16`).  Dockerfiles live in `toolchain-images/<name>/Dockerfile`.

Notes:

- **Watcom** (`wcc386`) emits **OMF** objects — converted to COFF via the
  vendored **objconv** (tools/objconv) and parsed by LIEF transparently;
  32-bit OMF byte-matching is enabled.  objconv crashes on 16-bit OMF, so
  MSVC 1.52 matching still needs the custom 16-bit parser — see
  [OMF_NOTES.md](OMF_NOTES.md).
- **MSVC 1.52** (`tools/MSVC152`, from archive.org `en_vc152_202512`) is a
  Phar Lap TNT DOS-extender binary — runs headless under DOSBox via the
  shared `rebrew.dosbox` runner; produces 16-bit OMF objects.
- **Borland C++ (bcc32)**: installer CD obtained (`turbo-c-v-4.5`); the
  16-bit Windows SETUP.EXE needs a Windows 3.x environment — install
  extraction pending.
- **Symantec C++ / Zortech C++ / Intel C++**: detected (family hints) but
  no byte-matching profile.

### Toolchain Detection (doctor alignment check)

`rebrew doctor` runs a "Toolchain alignment" check that guesses what
actually built the target and warns when the configured `[compiler] profile`
cannot byte-match it.  Detection is layered, best-first:

1. **Detect It Easy** (`diec -j --heuristicscan`) — the strongest signatures
   for MSVC (per-version, e.g. `12.00.9782` = MSVC 6.0), Borland/Delphi,
   linkers.  Used when `diec` is on PATH or vendored at `tools/diec/diec`
   (fetch the Linux `die_3.10_Ubuntu_24.04_amd64.deb` from the
   horsicq/Detect-It-Easy "Beta" release, `ar x` + `tar -xf` it, and vendor
   the matching `libQt5Core`/`libQt5Script`/`libicu74` `.so` files into
   `tools/diec/lib/` — the `.so`-only pair from a single distro release
   works; mixing distros aborts the QtScript engine).
2. **PDB** (`llvm-pdbutil`) — when a sibling `.pdb` exists: the `S_COMPILE3`
   record carries the compiler version and, for MSVC PDBs, the exact
   compiler flags (auto-surfaced in the doctor report).  A `.zig-cache`
   module path identifies Zig builds.
3. **Structural heuristics** — `.buildid` section, GNU `0f 1f` nops vs
   MSVC alignment nops / int3 padding, imports, Delphi RTL strings, and
   GCC-arg-passing era (pre-8 push style vs modern accumulate style).

The check fails when the detected family has no compatible profile
(Delphi: document blockers) and passes with a warning for families that may
only match structurally (Zig under `gcc-pe`).  See
`src/rebrew/toolchain_detect.py` and `profile_matches_detection`.

### Archived MSVC Toolchains (additional MSVC versions)

The most complete collection is the **`archaic-msvc`** GitHub org — one repo
per compiler version, from VC 2.0 through VC 10.0 (every VC 6.0 SP level,
VC 5.0 + SPs, VC 7.0/7.1, VC 8.0/9.0/10.0).  Download via codeload tarball:

```bash
cd tools
for r in MSVC420 MSVC500; do   # repo names are lowercase: msvc420 msvc500 ...
  curl -L -o $r.tar.gz "https://codeload.github.com/archaic-msvc/${r,,}/tar.gz/refs/heads/master"
  mkdir -p $r && tar xzf $r.tar.gz --strip-components=1 -C $r
done
```

### 16-bit Windows NE Binaries (native parsing + disassembly; matching future work)

`rebrew` primarily targets 32-bit PE/ELF/Mach-O with MSVC6/MinGW, but
**16-bit Windows 3.x NE executables** (MZ stub + `NE` header — e.g. 1990s
DOS/Windows games and Borland Delphi 1.0 apps) are now parsed natively:

1. **NE parsing — DONE** (`src/rebrew/ne_loader.py`): MZ `e_lfanew` → NE
   header (segment table with sector math, resident name table = exports,
   module reference + imported names = Win16 imports).  Segments become
   `BinaryInfo` sections with synthetic flat VAs `(segment << 16 | offset)`,
   so `load_binary`, `extract_raw_bytes`, `rebrew strings`, and `rebrew
   analyze` work on NE targets.  A capstone-based probe classifies code vs
   data segments: Borland segments carry a `[index\x00][name-string][content]`
   marker (detected conditionally — MSVC 16-bit segments start directly with
   code and the probe does not skip bytes for them).  `is_ne` reads the
   signature at `e_lfanew` (Borland puts it at 0x40; the MSVC 16-bit linker
   places it at 0x400, past a fixed stub read).
2. **16-bit disassembly — DONE**: the `x86_16` arch preset (`CS_MODE_16`,
   2-byte pointers) makes `asm`, `similar`, and `cu_map` disassemble
   segmented x86-16 (far calls, segment registers).
3. **Function enumeration — DONE**: `rebrew.ne_loader.enumerate_ne_functions`
   runs a 16-bit linear sweep (`push bp` / `enter` prologs, `ret`/`retf`
   epilogs) that handles both conventions — Borland (skip marker+name) and
   MSVC (code from offset 0, with the segment entry forced as a function
   start since MSVC entry code opens `push ds/pop ax/nop/inc bp`).
   holiday.exe (Borland) → 1783 functions; ski16.exe, the original 1991
   16-bit SkiFree (MSVC) → 137.
4. **Strings — DONE for Delphi**: NE targets scan data segments and recognize
   Pascal (length-prefixed) strings in addition to ASCII/UTF-16 runs.
5. **Toolchain detection — DONE**: `detect_toolchain` identifies NE targets
   by their segment markers — Borland markers → `delphi` (high confidence),
   markerless segments with content → `msvc` (16-bit MSVC-style) — falling
   back to RTL string evidence when segments are absent.
6. **16-bit compile profile / byte matching — FUTURE WORK**: a genuine 16-bit
   compiler (Borland Turbo C 2.0, Microsoft C 7.0 / Visual C++ 1.5) under
   Wine producing 16-bit OMF objects, plus segment-relative reloc handling in
   `smart_reloc_compare`.  NOTE: the vendored `tools/MSVC420` is the *32-bit*
   VC 4.2 compiler (i386 COFF output) — NOT suitable for 16-bit matching.

The workflow for a 16-bit target is: `rebrew intake <ne.exe>` (enumerates +
documents every function as a STUB blocker — Delphi functions are marked
audit-only in `rebrew todo -c documented`), `rebrew analyze <ne.exe>` for the
intelligence dossier (format, toolchain family, imports, strings),
`rebrew asm <va>` for disassembly.  `rebrew verify` short-circuits 16-bit
targets with a notice (no 16-bit compile profile — see item 6).

**Delphi 1.0 toolchain (vendored, verified working):** for 16-bit *Delphi*
targets (e.g. `holiday.exe`, a Delphi 1.0 VCL app), `tools/DELPHI10/` now
ships the exact command-line toolchain — `DCC.EXE` (Delphi Compiler 8.0,
Sep 1995), `DELPHI.DSL` (compiler symbol table), the `CMDLINE.PAK` tools,
and the RTL/VCL units (`UNITS.PAK` + `LIB.PAK`).  It compiles real 16-bit
NE 6.01 GUI executables; the working recipe and the reverse-engineered
**Quantum archive format** (`tools/DELPHI10/pak_extract.py`) are documented
in `tools/DELPHI10/README.md`.  Matching 16-bit output is still future work
(above).

Layout: `bin/cl.exe` + `include/` + `lib/` (case varies by version).  The
`msvc420` profile is backed by this source; `msvc5` (VC 5.0, 11.00.7022) is
validated against real Microsoft VC5.0 product binaries (e.g. `BIND.EXE`).

decomp.me also maintains win32 compiler data (`github.com/decompme/compilers`,
`platforms/win32/`); its toolchains are published by
`github.com/OmniBlade/decomp.me/releases/download/msvcwin9x/` (a subset —
msvc6.0/6.3/6.4/6.5/6.5pp/6.6/7.0 only, no Lib dir):

| Version | File | CL version | Notes |
|---------|------|------------|-------|
| msvc6.0 | `msvc6.0.tar.gz` (6.2 MB) | 12.00.x | same SP line as the local master |
| msvc6.3 | `msvc6.3.tar.gz` (6.6 MB) | 12.00.8168 | **SP3 — codegen differs from SP6** |
| msvc6.6 | `msvc6.6.tar.gz` (6.6 MB) | 12.00.8804 | **SP6 — same compiler as the local master** |
| msvc7.0 | `msvc7.0.tar.gz` (33 MB) | 13.10.3077 | **VC7 — enables the `msvc7` profile** |
| msvc4.x/7.1/8.0 | not published | — | document + skip |

Layout notes (differ from the local `tools/MSVC600/VC98/...`):

- msvc6.3/6.6: `Bin/CL.EXE`, `Include/`, **no `Lib/`** (compile-only; link with
  a full toolchain's Lib, e.g. the master's).
- msvc7.0: `Bin/cl.exe` (lowercase!), `Include/`, `MFC/`, **no `Lib/`**.
  Case matters on Linux — point `[compiler] command` at the lowercase file.

Fetch + extract (kept out of git — `tools/` is ignored; ~75 MB total):

```bash
cd tools
for v in msvc6.3 msvc6.6 msvc7.0; do
  curl -L -o $v.tar.gz https://github.com/OmniBlade/decomp.me/releases/download/msvcwin9x/$v.tar.gz
  mkdir -p $v && tar xzf $v.tar.gz -C $v
done
```

`rebrew init --compiler msvc6.3|msvc6.6` sets up the profiles; each is proven by
`tests/test_toolchain_roundtrip.py` (compile → compare → EXACT; skipped when the
tarballs are absent).  Round-trip validation: compile a snippet with the
toolchain, link against a full toolchain's Lib, intake the result, and
`rebrew test` the source — the profile is correct when it classifies EXACT.
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

See [GHIDRA_SYNC.md](GHIDRA_SYNC.md) for the sync feature matrix and known issues.

### radare2 / rizin

Used for decompilation backends (r2ghidra, r2dec) and as an alternative analysis
perspective. Rebrew auto-detects whichever is installed (`rz` preferred over `r2`).

**Data files consumed by rebrew:**
- `functions.txt` — Human-readable function list (VA, size, name) — tool-agnostic format
- `function_structure.json` — Ghidra function list (consumed by `rebrew skeleton`, `rebrew todo`)

**Known issues:**
- r2/rz occasionally report bogus sizes for some functions
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
| **diskcache** | Persistent caching for GA compilation results (`matcher/core.py`) |
| **httpx** | HTTP client for Ghidra/ReVa MCP communication (`ghidra/cli.py`, `skeleton.py`, `decompiler.py`) |
| **lief** | PE/ELF/Mach-O parsing — core dependency for `binary_loader.py`, `matcher/parsers.py`, `test.py` |
| **numpy** | Numeric computation |
| **python-flirt** | FLIRT signature matching for library identification (`flirt.py`) |
| **rich** | Terminal formatting |
| **tomlkit** | Comment-preserving TOML editing (`cfg.py`) |
| **tree-sitter** | C source AST parsing for signature and struct extraction |
| **tree-sitter-c** | Tree-sitter C language grammar (used with `tree-sitter`) |
| **typer** | CLI framework with rich help |

### Available (not core)

| Library | Use in Project |
|---------|----------------|
| **pyelftools** | ELF parsing (not needed for PE32) |
| **matplotlib** | Plotting / visualization |

### Optional Dependencies

| Library | Purpose | Install |
|---------|---------|--------|
| **angr** | Symbolic execution + Z3 for `rebrew prove` | `uv sync --all-extras` |

### Not Installed (could be added)

| Library | Purpose |
|---------|---------|
| **r2pipe** | Programmatic radare2 access from Python |
| **keystone** | Assembler engine (x86 → bytes) |
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
1. `rebrew diff` for side-by-side disassembly (add `--mismatches-only` for structural diffs only)
2. **objconv** to verify comp.id on compiled .obj files
3. **DUMPBIN /DISASM** for quick .obj inspection

### For Compiler Flag Analysis
1. `rebrew match --flag-sweep-only --tier normal` (~5.4K combos)
2. Use `--tier quick` for fast iteration (192) or `--tier thorough` for deep search (~258K)
3. **objconv** comp.id verification to confirm same compiler
4. Re-sync flags from decomp.me: `python tools/sync_decomp_flags.py`

### For Structure Recovery
1. **Ghidra** structure editor via MCP (`parse-c-structure`, `get-structure-info`)
2. **DUMPBIN /RAWDATA** for raw data inspection at specific offsets
