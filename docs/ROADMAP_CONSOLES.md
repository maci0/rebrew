# Rebrew for Consoles — 5th Gen Onwards

> **Status:** Research / proposal — 2026-08-11
> **Scope:** PlayStation (PS1), Nintendo 64, GameCube, Sega Saturn, Dreamcast
>            (with notes on PS2 / PS2-era spillover)
> **Why this document:**  These consoles are *all* C/C++ targets with
> deterministic cross-compilers — exactly the problem Rebrew solves for
> PC (MSVC6 / MinGW).  This doc maps how the current engine transfers,
> what breaks, and a phased plan to get there.

---

## 1. Executive Summary

| Question | Answer |
|----------|--------|
| **Are these consoles C/C++?** | Yes — every 5th-gen-onward console shipped a C (and later C++) SDK. Studios used vendor compilers, not hand-written ASM, for >90% of game code. |
| **Does Rebrew's model apply?** | Directly.  The loop `C source → cross-compile → obj bytes → reloc-aware compare → STATUS` is compiler-agnostic.  What changes is the *backend*: CPU arch, binary container, object format, flag set, and relocation model. |
| **Closest win** | **N64 (IDO) and GameCube (CodeWarrior)** — both already have decomp.me-grade toolchains, deterministic codegen, and active matching decomp communities to borrow flag definitions from. |
| **Hardest** | **Saturn SH-2 dual-CPU** (shared-memory synchronization) and **PS1 Psy-Q** (obsolete proprietary toolchain that is hard to source legally). |
| **Recommended order** | MIPS family first (PS1 + N64 + PS2 share MIPS), then PowerPC (GC), then SuperH (Saturn → Dreamcast). |

**One-line pitch:**  Rebrew already knows how to do byte-exact C matching for x86 PE.  Consoles replace `CL.EXE + COFF + PE` with `ccpsx/ido/mwcc/sh-elf-gcc + ELF/COFF + PS-EXE/ROM/DOL` — the rest (catalog, scoring, GA, todo, verify, round-trip) transfers.

---

## 2. Why Rebrew Transfers

Rebrew's value is not "MSVC6" — it is the *compiler-in-the-loop workbench*:

| Rebrew capability | Console use |
|-------------------|-------------|
| **Function catalog + coverage grid** (`catalog/`, `build_db`, `status`, `todo`) | ROMs/DOLs have no PDB — catalog is the only source of truth. Overlay-aware catalog is needed (N64, Saturn, PS2). |
| **Skeleton generation** (`skeleton.py` — decompile → typed C stub) | Console SDKs have rich headers (libultra, libgcm, SGL, Katana) — skeleton + `library_*.h` works identically. |
| **Byte-exact compare** (`compile.py` → `core/matching.py::smart_reloc_compare`) | Console compiles are *more* deterministic than MSVC6 (no incremental link). Matching is the whole goal of N64/GC decomp. |
| **Diff + structural similarity** (`diff.py`, `similar.py`, `near_diag.py`, `scoring.py`) | Identical — swap Capstone arch/mode. Mnemonic similarity is arch-independent. |
| **GA code mutations** (`matcher/mutator.py` 120+) | Most mutations are C-level (loop form, const folding, type punning) and transfer as-is. ~15% are x86 codegen idioms and need arch notes. |
| **Flag sweep** (`matcher/compiler.py` + `flag_data.py`) | Console compilers have *smaller* flag spaces than MSVC — often just `-O0..2` + a few codegen toggles. Sweeps are cheaper. |
| **FLIRT / CRT matching** (`flirt.py`, `crt_match.py`) | Every console SDK shipped as a static lib (libultra, libgcm, SGL, Katana) — FLIRT-identifiable. Already the primary way console decomps filter SDK code. |
| **Prove / symbolic** (`prove.py` via angr) | Capstone + VEX lifts MIPS/PPC/SH/ARM — angr already handles them. |
| **Round-trip** (`round_trip.py` — splice matched funcs back into binary) | Console equivalent = rebuild ROM/DOL/EXE with matched objects and verify ISO hash. Same principle, different linker script. |
| **Ghidra sync** (`ghidra/`) | Ghidra has first-class MIPS/PPC/SH/ARM processors; ReVa MCP works for any ISA. |

**Net:** ~70% of the codebase is ISA/format-agnostic.  The remaining ~30% is concentrated in four seams: arch presets, binary loader, toolchain detection, and object parsers.

---

## 3. Per-Console Research Dossier

### 3.1 PlayStation 1 (PS1) — MIPS R3000 (MIPS-I), 33.8 MHz

| Field | Detail |
|-------|--------|
| **CPU** | MIPS R3000A (Sony CXD8530) — MIPS-I ISA, little-endian, no FPU interlocks (load-delay slot), 32-bit. |
| **SDK** | **Psy-Q SDK** (SN Systems, later Sony) — `CCPSX` compiler (proprietary MIPS C compiler, GCC-derived optimizer), `CCPSX` + `ASMPSX` + `LINKER` (`psylink`). Versions Psy-Q 3.2–4.7 dominate commercial games (1995-2000). |
| **Language** | C89 (libs in C, some inline ASM for GTE / MDEC / CD-ROM). C++ rare. |
| **SDK libs** | `LIBGTE`, `LIBGPU`, `LIBSPU`, `LIBCD`, `LIBMCRD`, `LIBDS`, `LIBCARD` — all static `.LIB` (Psy-Q link format), FLIRT-signaturable. |
| **Binary format** | **PS-X EXE** —  `0x80010000`-based flat executable (`"PS-X EXE"` magic, 2KB header + code at `0x80010000`, not ELF). Shipped inside ISO9660 (`SYSTEM.CNF` → `cdrom:\SLUS_XXX.X;1`). |
| **Object format** | Psy-Q object: proprietary `LINK` format (not ELF, not COFF — SN `PSYOBJ`). Second-phase toolchain uses standard ELF via `psx-gcc` (homebrew). Commercial = PSYOBJ; modern matching decomp uses `maspsx` (assembler that preserves Psy-Q codegen) + GCC cross. |
| **Decomp precedents** | Very active: `psxdecomp`, Crash Bandicoot, Spyro, FF7, Tomb Raider — most use Ghidra + `maspsx`/`gcc-mipsel` to match. `decomp.me` has `ps1`/`psyq` compilers. Matching is hard because Psy-Q is unobtainable legally in pure form; community uses `maspsx` + GCC as proxy. |
| **Rebrew fit** | `PS-X EXE` loader + MIPS little-endian disasm is the only new primitive. Object parsing is the bottleneck (PSYOBJ). Pragmatic path: match via `mipsel-linux-gnu-gcc` + `maspsx` for ASM stubs, document PSYOBJ as future work. |

### 3.2 Nintendo 64 — MIPS R4300i (MIPS-III, 64-bit, used as 32-bit), 93.75 MHz

| Field | Detail |
|-------|--------|
| **CPU** | MIPS R4300i — MIPS-III, big-endian (N64 is BE!), 32-bit mode (64-bit regs available but games use 32-bit ABI `o32`). |
| **SDK** | **N64 SDK `libultra`** + **SGI IDO / MIPSPro** toolchain (IRIX). Canonical versions: **IDO 5.3** (early, 1996-98), **IDO 7.1 / MIPSPro 7.1** (late, 1998-2002), plus **EGCS 1.x / GCC 2.7-2.95** for third parties (Rare used GCC). |
| **Language** | C (C89, `ultra64` headers), C++ late (Factor 5, Rare). |
| **SDK libs** | `libultra` (`os*`, `vi*`, `pi*`, `si*`), `libgultra`/`libgL`, `libaudio`. Overlays are `libultra` objects linked per-level. |
| **Binary format** | **N64 ROM** — big-endian, 64-byte header (PI BSB / IPL3 bootcode at `0x0000`), then monolithic ROM. Not ELF/PE — parsed via build linker script. The community uses `splat` / `splat64` YAML to split ROM into sections + overlays (each overlay is a relocatable code segment loaded to RAM at runtime). Compression common (Yaz0/MIO0). |
| **Object format** | **ELF o32** (MIPS ELF). IDO emits `mips` ELF with `mdebug` + IDO-specific relocs. LIEF already parses MIPS ELF — half the work is done. |
| **Decomp precedents** | Gold standard: SM64, OOT, MM, Perfect Dark, Paper Mario — all **IDO matching decomp** with `decomp.me` `ido5.3` / `ido7.1` compilers. `splat` is the intake tool, `asm-processor`/`mips-dis` for matching. Flag space tiny (`-O1`/`-O2`/`-g` + `-non_shared`/`-G0`/`-mgpopt`). |
| **Rebrew fit** | Highest synergy: ELF objects (LIEF works), LIEF + Capstone already handle `CS_ARCH_MIPS, CS_MODE_MIPS32+R6 / CS_MODE_BIG_ENDIAN`. Biggest addition: **ROM + overlay loader** + **splat YAML import** as an alternative catalog source (equal to `function_structure.json`). Flag sweep is 2-3 axes, trivial. |

### 3.3 Nintendo GameCube — PowerPC Gekko (750CXe), 485 MHz

| Field | Detail |
|-------|--------|
| **CPU** | PowerPC 750 "Gekko" — 32-bit PPC (based on 750CXe/CX), big-endian, paired singles (PS) SIMD extensions, 32 GPRs + FPRs. |
| **SDK** | **Dolphin SDK / GCN SDK + Metrowerks CodeWarrior** — `mwcceppc.exe` (Win32) compiler versions **GC 1.x / 2.0 / 2.5 / 2.6 / 2.7** dominate (2001-06). Each version has distinct codegen (inlining heuristics, `__va_arg` layout, float scheduling). Early SDK used `gcc ppc-eabi`. |
| **Language** | C++ (heavy — full STL-free C++ with vtables, RTTI disabled, `__declspec` class layouts), C for drivers. |
| **SDK libs** | `libdolphin.a` (`GX`, `VI`, `PAD`, `OS`, `AR`, `DSP`, `DVD`), `libogc` (homebrew), `REL` (relocatable modules loaded at runtime — REL relocation format is custom). |
| **Binary format** | **DOL** (GameCube executable — 18 text+data segments, BSS, entry point, load addresses) + **REL** (relocatable modules, used for almost everything beyond the DOL). Shipped inside **GCM ISO** (GC disc format, FST filesystem). DOL = flat; REL = has custom PPC reloc table. |
| **Object format** | CodeWarrior object = **ELF** (PowerPC, big-endian, DWARF) — LIEF-parseable. `mwcc` can also emit `SOM` on older hosts. Modern matching decomp drives `mwcceppc.exe` under Wine (same runner pattern as `CL.EXE` under Wine today). |
| **Decomp precedents** | Very active: `doldecomp` (Melee, Sunshine, Wind Waker, TTYD, F-Zero GX), `decomp.me` `mwcc_247_92` etc., `cw` Docker images that bundle every CodeWarrior version. `decomp.me/mwcc` flag axes are already curated (opt level, inline, scheduling, interproc). DOL matching is the canonical example of Rebrew's problem on a different ISA. |
| **Rebrew fit** | Second-best after N64. DOL/REL loader + PPC BE disasm + Wine-wrapped `mwcceppc.exe`. Vtable/dispatch analysis (`rebrew data --dispatch`) directly relevant — GC games are C++ vtable-heavy. |

### 3.4 Sega Saturn — Dual Hitachi SH-2 (SH7604), 28.6 MHz ×2

| Field | Detail |
|-------|--------|
| **CPU** | 2× Hitachi SH-2 (SuperH SH7604) — 32-bit RISC, **big-endian**, 16-bit fixed-width + 32-bit ops, 16 GPRs, very small register file, split master/slave with shared RAM + SCU synchronization. Optional 68000 + SH-1 for CD block, VDP1/VDP2, SCSP. |
| **SDK** | **SGL** (Sega Graphics Library) + **SBL** (Saturn Basic Library) + **Hitachi SH C Compiler** (`shc`/`shcpp`, later Renesas `SHC 7.x`). GCC `sh-elf-gcc` used by homebrew and some third parties (Traveller's Tales). C usually, C++ rare. |
| **Language** | C (SH C), assembly for VDP/SCU sync loops. |
| **SDK libs** | `libsgl.a`, `libsbl.a`, `libgte` equivalents (`libsn`, `libper`, `libscl`, `libcd`). Dual-CPU coordination via `SBL` message passing. |
| **Binary format** | **ISO9660 + `0WLDEXE.BIN` / `1ST_READ.BIN`-style flat binary** loaded to `0x06004000` (work RAM High). Format varies by publisher: often a flat binary or **COFF/ELF** that the IPL copies. Some use **Sega's COFF** (Hitachi SH COFF, distinct from MS COFF). The Saturn IP boot record + security ring is out of scope (extract after ISO parse). |
| **Object format** | Hitachi SHC object = **SH COFF** (Microsoft-like COFF with SH relocs, type `0x014C`-family distinct). GCC SH = **ELF sh**. Community `saturn-sdk-gcc` ships modern `sh-elf-gcc`. |
| **Decomp precedents** | Small but growing: `saturn decomp` (VF2, Nights, Panzer Dragoon), `Jo Engine` (homebrew SDK), Ghidra SH-2 processor + `saturn_tool` for ISO split. SH-2's 16-bit encoding makes recompilation matching unusually sensitive (small flag changes flip delay-slot / literal-pool placement). |
| **Rebrew fit** | Medium difficulty. Single biggest blocker: **dual-CPU catalog** (two SH-2s share one address space but have distinct entry points; a flat `functions.txt` hides the CPU affinity). Architecture + SHC toolchain are niche — GCC SH ELF is the pragmatic first profile (`sh-elf-gcc -m2 -mb`), Hitachi SHC second (Wine-wrapped `shc.exe`). Capstone `CS_ARCH_SH` + `CS_MODE_SH2` / `CS_MODE_BIG_ENDIAN` covers disasm. LIEF parses SH ELF; SH COFF needs a new parser. |

### 3.5 Sega Dreamcast — Hitachi SH-4 (SH7750) + ARM7, 200 MHz

| Field | Detail |
|-------|--------|
| **CPU** | Hitachi SH-4 (SH7750) — 32-bit SuperH, superset of SH-2, **little-endian** on Dreamcast (Katana), 200 MHz, FPU + 128-bit FPU vector, 5-stage pipeline. Co-CPU: **ARM7DI** (AICA sound, 45 MHz, little-endian, `armv4t`). GPU: PowerVR2 (PVR, not CPU). |
| **SDK** | **Katana SDK** (Sega, official) — **Hitachi SH C/C++ Compiler** (`shc` 5.x/6.x, `shcpp`) + **KallistiOS** (homebrew, `sh-elf-gcc` + `arm-eabi-gcc`). Katana also bundles Microsoft VC for tools and `sh-elf-ld` for final link. GCC SH-4 used by open toolchains; Katana's compiler is Wine-runnable. |
| **Language** | C (C89/C99 late), C++ common (Dreamcast era games are C++: Sonic Adventure, Shenmue, Crazy Taxi). |
| **SDK libs** | `libkatana.a` (`kamui` graphics, `aica` sound, `gd` disc, `pvr` 3D), `libdream.a` (KallistiOS). SH-4 FPU intrinsics matter (`fmac`, `fipr`). |
| **Binary format** | **`IP.BIN` (boot, 16 sectors) + `1ST_READ.BIN` (main executable, scrambled)** — `1ST_READ.BIN` is a **SH-4 ELF** (little-endian) scrambled by `scramble.exe` (byte interleave) after link; descrambled = plain ELF (LIEF-parseable). Entrypoint `0x8c010000` (P2 cached RAM). ARM7 binary is a separate raw blob loaded to AICA RAM. Shipped inside GD-ROM / ISO (`IP.BIN` + `1ST_READ.BIN` + assets). |
| **Object format** | **ELF sh** (little-endian). Same as Saturn GCC path — LIEF already handles it. Hitachi SHC may emit COFF; descrambled ELF is the canonical artifact. |
| **Decomp precedents** | Active but fragmented: `dreamcast decomp` (Sonic Adventure, Shenmue splits), `KallistiOS` + `dc-tool` for ELF extraction, `ghidra-dreamcast-loader` (descramble + load). SH-4 decomp leans heavily on Ghidra's SH-4 processor + `sh4-dis`. Matching decomp pattern mirrors GC: `sh-elf-gcc` with `-m4-single -ml -m4-nofpu` flag sensitivity. |
| **Rebrew fit** | High (shared with Saturn SH path). Discriminated by **SH-4 LE vs SH-2 BE** + FPU codegen. Simplification: use KallistoS `sh-elf-gcc` ELF (LIEF works) and treat Hitachi SHC as an optional Wine profile (same pattern as `mwcceppc`). Dreamcast's descramble step parallels Rebrew's "header parity" — `round-trip --fix-headers` analogue is `descramble → patch → rescramble → GD-ROM rebuild`. |

### 3.6 Spillover: PlayStation 2, Xbox, PSP (6th gen, same pattern)

| Target | CPU | Compiler | Binary container | Notes |
|--------|-----|----------|------------------|-------|
| **PS2** | MIPS R5900 (EE, MIPS-III + 107 new EE opcodes + VU0/VU1) | `ee-gcc` 2.9/3.2 (Sony SN toolchain), `ee-g++` | **ELF** (EE ELF, `0x00100000`, little-endian; `IOP` is MIPS-I EL ELF) — LIEF parses directly | PS2 decomp is the natural sequel to PS1/N64 MIPS work; `ee-gcc` flag space tiny. |
| **Xbox** | x86 Pentium III (Coppermine) | MSVC 6/7 (same as Rebrew today!) | **XBE** (Xbox Executable — PE-derived, `XBEH` instead of `MZ`) | Trivial port — add XBE loader (LIEF already handles XBE as PE variant). |
| **PSP** | MIPS R4000 (Allegrex, VFPU) | `psp-gcc` 4.x | **ELF/PRX** (PRX = relocatable PSP ELF with `~PSP` magic) | Same MIPS EL family as PS1/PS2. |

These are listed for prioritization: PS2 and Xbox are *strictly* cheaper than Saturn because the ISA/format/toolchain already overlap with shipped Rebrew paths.

---

## 4. The Common Platform Trait (Why One Engine Covers Them All)

Every console from the 5th gen onward converged on the same build model:

```
C/C++ source  ──►  cross-compiler (host = x86 Win32 IRIX)  ──►  ELF/COFF obj
                                                            ─┬─► static libs (SDK)
                                                             └─► linker script
                                                                  ──► flat ROM / DOL / PS-EXE / BIN
```

*Deterministic codegen* — no PGO/LTCG on these compilers, no ASLR, no CFG obfuscation.
*Flags matter* — `-O2` vs `-O1`, `-G0` vs `-G8`, `-inline off` vs `auto`, `-m4-single`, etc., produce predictable byte deltas — exactly what `flag_sweep` and `near_diag` exploit.
*C89/C++98* — no `std::` heavy lifting; SDK headers are C and compile under any host compiler for skeleton generation.
*Static linking* — the final ROM is a concatenation of objects; FLIRT SDK signatures cleanly separate game code from library code.

This is why console matching communities ended up recreating Rebrew's loop with shell scripts + `splat` + `decomp.me`.  Rebrew's job is to make that loop first-class and *portable across ISAs*.

---

## 5. What Breaks Today (Gap Inventory)

Grouped by the four seams that need work.  Ordered by dependency (1 → 4).

### 5.1 Architecture Presets & Disassembly (`config.py`, `scoring.py`, `asm.py`)

| Gap | Current | Needed |
|-----|---------|--------|
| **No console arch presets** | `_ARCH_PRESETS` has `x86_16/32/64`, `arm32/64` only. | Add `mips`, `mipsel`, `mips64`, `ppc`/`ppc_gekko`, `sh2`, `sh2eb`, `sh4`, `sh4le`, `arm7`, `armv4t`, `allegrex`, `r5900`. Each needs `capstone_arch/mode`, `pointer_size` (4 always for these consoles), `padding_bytes` (mostly `0x00`), `symbol_prefix` (``). Capstone mappings: `CS_ARCH_MIPS + CS_MODE_MIPS32+CS_MODE_LITTLE_ENDIAN/BIG_ENDIAN`, `CS_ARCH_PPC+CS_MODE_32`, `CS_ARCH_SH+CS_MODE_SH2/SH4+CS_MODE_BIG_ENDIAN`, `CS_ARCH_ARM+CS_MODE_ARM`. |
| **Endian-aware scoring** | `scoring.py`'s `_zero_reloc_fields` is hard-coded x86-32 (`call rel32`, `mov abs32`, `ModR/M`). | Dispatch per ISA: MIPS (zero `jal` target + `lui`/`addiu` hi/lo pairs), PPC (zero `bl`/`lis`/`addi` immediates), SH (zero `mov.l` literal-pool + `bsr`/`bra` disp). Or switch heuristic reloc masking to explicit `reloc_offsets` (already supported) once obj parsers supply typed relocs — heuristic is only a fallback. |
| **Register masking** | `_mask_registers_x86_32` masks `ModR/M`. | Extend or generalize: MIPS/PPC/SH register fields are simpler. `near_diag`'s `RR` class should become ISA-aware. |
| **Instruction-level diff** | `diff_functions` assumes 32→32 diff. | Works once capstone produces correct mnems; only the reloc/register heuristics are ISA-specific. |

### 5.2 Binary Loader & Format Detection (`binary_loader.py`, `catalog/`, `analysis.py`)

| Gap | Current | Needed |
|-----|---------|--------|
| **Only PE/ELF/Mach-O/NE** | `load_binary` + `detect_format_and_arch` handle LIEF's three formats + NE. | New `format` values: `psexe`, `n64rom` (z64), `dol`, `rel`, `xbe`, `gdrom`, `prx`, `saturnbin` (flat), `elf-sh` already covered. Each adds a `_load_XXX` path. |
| **LIEF limitations** | LIEF cannot parse PS-EXE, N64 ROM, DOL, REL, XBE, Saturn COFF, Katana scramble. | Custom section builders: synthesize `BinaryInfo` + `SectionInfo` from parsed headers (PS-EXE header → one `.text`; DOL header → 18 segment Sections; N64 ROM → `.text` + overlay Sections from `splat` YAML). Rom/EXE/REL data stays `info.data`; VA math is header-derived. |
| **No overlay model** | `function_structure.json` is flat. | Overlay-aware catalog: `src/{target}/overlays/{overlay}/functions.txt` or `{va,size,overlay}`. `catalog` should produce `overlay_*.json` and `build_db` should carry `overlay` column. Saturn (two CPUs) and N64 (many overlays) need this; GC RELs are the same problem. |
| **Section names not portable** | Saturn `_TEXT` vs `CODE` vs `.text`. | Normalize section-name checks (already partly handled for Watcom `_TEXT`). |
| **No ISO/GCM/GD-ROM filesystem walk** | Expected input is the inner binary, not the disc image. | `rebrew intake` should accept a disc image path, detect filesystem (ISO9660/FST/GD), and prompt/extract the inner `1ST_READ.BIN` / `SLUS_*` / `*.dol`. Do not embed a full ISO parser — shell out to `7z`/`gditools`/`ndstool` or document manual extraction and detect common containers. |

### 5.3 Toolchain Detection & Compiler Profiles (`toolchain_detect.py`, `config.py`, `matcher/compiler.py`, `flag_data.py`)

| Gap | Current | Needed |
|-----|---------|--------|
| **Heuristics are PE/MZ-only** | `detect_toolchain` looks for `.buildid`, `msvcrt.dll`, Borland sections, MSVC nops, GNU ld signals. | Add console heuristics: PS-EXE magic / `Sony Computer Entertainment` strings / `libgte` markers; N64 `81000000` IPL3 + `libultra` symbols; DOL `00 00 00` entry-at-0 + `Metrowerks` string; SH `SH2`/`SH4` machine type in ELF `e_machine` (`0x2A`/`0x2C`) + `Hitachi`/`Renesas` strings. |
| **Only five real profiles** | `msvc400..7`, `gcc`, `gcc-pe`, `clang`, `watcom(draft)`. | Add `psyq` (proxy: `mipsel-elf-gcc` + `maspsx`), `ido53`, `ido71`, `egcs`, `cw_gc` (CodeWarrior GC 1.0–2.7 aliases), `sh-elf-gcc` (`sh2`/`sh4` variants), `shc` (Hitachi), `ee-gcc`, `xbe` (msvc6 alias), `psp-gcc`. Each maps to a `FlagSet`/`Checkbox` list in `flag_data.py` (sync from `decompme/compilers` repo + community flag docs). |
| **Flag sync is decomp.me-only** | `tools/sync_decomp_flags.py` pulls from `messi/decomp.me`. | Console flag sets already live in `decomp.me` (`platforms/mwcc`, `platforms/ido`, `platforms/ps1`). Extend sync to pull `mwcc`/`ido` axes. Watcom `wcc386` already under research (`docs/OMF_NOTES.md`). |
| **No overlay linker scripts** | Round-trip assumes PE header patching. | Console round-trip is `ld -T script.ld` with overlay ldscripts (N64) / DOL params / scramble step. `round_trip.py` needs a linker-script mode (emit `*.ld`, invoke `ld.lld`/`sh-elf-ld`, then ROM/DOL builder). |
| **Wine runner pattern is Windows-only** | MSVC6 runs as `wine CL.EXE`; `wcc386` same. | Console toolchains are *also* Windows IRIX-hosted cross compilers (`mwcceppc.exe`, `ccpsx.exe`, `shc.exe`, IDO `cc` on IRIX). Same Wine/wibo pattern works for CodeWarrior + PsyQ + SHC. IDO needs IRIX emulation (or Docker `ido-static-recomp` which ships Linux-native recompiled IDO binaries — preferred). |
| **No legal toolchain vendoring story** | `tools/MSVC600/` is vendored. | Console SDKs are proprietary (Sony/Nintendo/Sega). Cannot vendor. Pattern: `tools/` is `.gitignore`'d; `rebrew doctor --install-toolchain <profile>` docs the fetch (user-owned SDK dump) and `toolchain_detect` verifies presence. Ship *open* GCC cross toolchains (`mips-elf-gcc`, `powerpc-eabi-gcc`, `sh-elf-gcc`) by default; treat proprietary IDO/CW/PsyQ as optional overlays. |

### 5.4 Object Parsers & Relocation Model (`matcher/parsers.py`, `core/matching.py`)

| Gap | Current | Needed |
|-----|---------|--------|
| **Only COFF/ELF/Mach-O** | `parsers.py` handles COFF, ELF, Mach-O via LIEF. Watcom OMF already needs a custom parser (`docs/OMF_NOTES.md`). | Console objects are mostly **ELF** (IDO, GCC, CodeWarrior, sh-elf-gcc, ee-gcc) — so *most consoles already work* for the compile side. The gap is **Psy-Q PSYOBJ** (custom) and **Hitachi SH COFF** (variant). Both are small parsers (record framing like OMF). Prioritize ELF consoles first to defer this work. |
| **Relocation types are PE-centric** | `smart_reloc_compare` understands `IMAGE_REL_I386_DIR32/REL32` and ELF `R_386_*`. | Add MIPS (`R_MIPS_26`, `R_MIPS_HI16/LO16`), PPC (`R_PPC_ADDR32`, `R_PPC_REL24`), SH (`R_SH_DIR32`, `R_SH_REL32`, literal-pool `R_SH_CODE`); reuse the typed `CoffRelocRecord`-style path extended to `RelocRecord` (type + addend). For ELF, LIEF already exposes typed relocs — just extend the dispatch. |
| **Pointer size = 4 assumption is fine** | Console pointers are all 32-bit (even N64 uses 32-bit ABI). | Keep pointer_size 4 for every console preset (N64 is MIPS64 hardware but o32 ABI). No change. |
| **Mutator ISA assumptions** | ~15/120 mutations emit or pattern-match x86 codegen idioms (`_asm { int 3 }`, `__try/__except`, `rep movs`, `fs:[0]`). | Tag mutations with `arch` applicability (e.g. `x86_only`, `generic`). Console matching doesn't need these filtered immediately — just disable `x86_only` when arch ≠ x86. Generic C mutations (loop form, const shape, branch order) transfer directly. |

---

## 5.5 Alignment with Adopted ADRs & Existing Docs

This section is the delta after re-reading all six ADRs and the
`ARCHITECTURE` / `TOOLCHAIN` / `CONFIG` / `WORKFLOW` / `ANNOTATIONS` /
`DB_FORMAT` / `GAP_ANALYSIS` / `CODEGEN_PATTERNS` / `OMF_NOTES` docs.
It is not a rewrite — it patches the gap inventory (§5) and the phases
(§6) so every new console feature follows the patterns the project has
already committed to.

### 5.5.1 ADR map — what each decision means for consoles

| ADR | Decision (1 line) | Console implication |
|-----|-------------------|---------------------|
| **001** Native NE parsing | Non-LIEF formats via a **native loader** (`ne_loader.py`) + **synthetic flat VAs** `(segment<<16\|off)` so every downstream tool works without special-casing. | PS-EXE / N64 ROM / DOL / REL / `1ST_READ.BIN` follow the **same seam**: a dedicated loader module (`rebrew/psexe_loader.py`, `n64rom_loader.py`, `dol_loader.py`, …) that synthesizes `BinaryInfo`/`SectionInfo`. Do **not** bloat `binary_loader.py` with inline parsers — import like `ne_loader`. BE headers must not use LE unpacks (new failure mode vs LE-only NE). |
| **002** Borland vs MSVC enumeration | Enumeration must **probe conditionally** (marker vs markerless); forcing one convention corrupts the other. | MIPS / PPC / SH enumeration (overlays, RELs, delay slots) will have the same two-convention problem. E.g. `splat` overlays vs flat ROM; SH BE vs LE literal pools; DOL's 18 segments vs REL's custom reloc table. Build a `probe_is_code(info, offset, arch)` gate and test both fixtures (one BE ROM + one LE ELF) before claiming coverage. The forced-start trick for markerless segments (ADR-002) is the model for "entry VA lives outside the sweep" on Saturn. |
| **003** Imports degrade to module list | Never fabricate per-API imports when the table is misplaced — **keep the module set, drop the detail**. | Disc-image extraction (ISO9660 → PS-EXE, GCM FST → DOL, GD-ROM → `1ST_READ.BIN`) must obey the same rule: when the FST/ISO directory is unreadable, report the container + module-level records (the disc is a `GCM` containing *a* DOL) and mark per-file VAs as missing — do not synthesize. The sanity gate `count ∈ 1..0x1000` has a console analogue: clamp overlay count / REL count / DOL segment count before synthesis. |
| **004** Intake prunes only exact auto-stubs | Stale re-discovery is cleaned by **exact regex match** on `// STUB: … 0xVA`; edited files never touched; metadata for pruned VA deleted via `delete_metadata_entry`. | Overlays + RELs make this overlay-aware: a VA may exist in *one* overlay's `functions.txt` but not another's. Prune key becomes `(overlay, VA)` — do not delete a file that is still live in another overlay. Migration: `function_structure.json` → per-overlay `functions_{overlay}.txt` keeps the safety regex unchanged. |
| **005** Toolchain detection order | **DIE → PDB (`S_COMPILE3`) → heuristics**; string evidence outranks marker; linker version is the fallback version hint. | Console detection extends the chain with an **ELF-header backend** in the PDB slot: `e_machine` (`EM_MIPS`/`EM_PPC`/`EM_SH`) + `e_flags` (MIPS ISA level, SH2 vs SH4) is as strong as `S_COMPILE3`. Order becomes **DIE → ELF header (e_machine/e_flags) → strings (.buildid/GNU nops analogue: `Metrowerks`, `libultra`, `SEGASATURN`, `SEGAKATANA`) → codegen probe (SH FPU `fmac`, MIPS `jal` delay-slot count).** N64 `IPL3` magic + PS-EXE magic + DOL text/data offset table are the DIE-class "magic" signals. |
| **006** Docker-first toolchains | One **container image per toolchain-version** (Godbolt model) with a wrapper inside; host falls back to vendored `tools/` or PATH binary; `rebrew.toolchain.ToolchainSpec` registry + `rebrew toolchain list/status/pull`. Shared `rebrew.dosbox` for 16-bit. | IDO, CodeWarrior `mwcceppc`, Hitachi `shc`, Psy-Q `ccpsx` are **not** new glue — they are new `ToolchainSpec` entries + `toolchain-images/<name>/Dockerfile`s. IDO is the IRIX→Linux-static-recomp analogue of DOSBox: prefer community `ghcr.io/decompme/ido-static-recomp` (Linux-native) over inventing an IRIX emulator. This replaces the roadmap's earlier ad-hoc "Docker or Wine" prose with the codified `docker image present → vendored → PATH` preference already tested for `watcom`/`msvc1.52`/`delphi16`. |

### 5.5.2 Doc touchpoints — where existing docs constrain the plan

| Doc | What it already says | Patch for consoles |
|-----|---------------------|---------------------|
| `ARCHITECTURE.md` | Data flow `BIN → load_binary (LIEF) → BinaryInfo → catalog/CMP/diff`; module map lists every package. | Keep the shape: console loaders still produce `BinaryInfo`. Add rows to the module map (`rebrew/psexe_loader.py`, `n64rom_loader.py`, `dol_loader.py`, `gdrom_loader.py`) and a one-line note that `format != elf/pe/macho/ne` flows through a native loader (ADR-001 pattern), not LIEF. |
| `TOOLCHAIN.md` | Toolchain standardization (ADR-006), MSVC archived toolchains, 16-bit NE support matrix (DONE/FUTURE), DIE/PDB/heuristics chain. | Append a **Consoles support matrix** mirroring the NE matrix (6 rows: PS-EXE parsing — TODO, N64 ROM — TODO, DOL/REL — TODO, Saturn flat — TODO, SH ELF — DONE via LIEF, Dreamcast descramble — TODO). Add sub-section "IDO / CodeWarrior / SHC — vendor fetch" that mirrors the `archaic-msvc` codeload recipe: `docker pull` for IDO-static-recomp + `WATCOM`-style vendored path for `mwcceppc.exe` / `shc.exe` (user-owned SDK dump, `.gitignore`d). |
| `CONFIG.md` | `format ∈ {pe,elf,macho,ne}`, `arch ∈ {x86_16,x86_32,x86_64,arm32,arm64}`, preset table, profile table (`msvc6/7`, `gcc`, `clang`, `watcom`), validation fallbacks (unknown → warn + fallback). | Extend `_KNOWN_FORMATS` and `_ARCH_PRESETS` in place (warn+fallback for unknown stays). Proposed arch names to reserve: `mips` (BE), `mipsel` (LE), `mips64`, `ppc`/`ppc_gekko`, `sh2`, `sh2eb`, `sh4`, `sh4le`, `arm7`/`armv4t`, `allegrex`, `r5900`. Section 5.1's preset list is the source of truth — keep Capstone strings as `CS_ARCH_MIPS + MIPS32(R6) + LE/BE` etc. so validation messaging stays 1:1 with `detect_format_and_arch`. |
| `WORKFLOW.md` | Canonical iteration loop `todo→skeleton→decomp→write→test→diff→match→prove→verify`; JSON purity; multi-binary `shared/` wrapper pattern. | Console projects reuse the loop unchanged. Add a sibling **`CODEGEN_PATTERNS` per ISA** (not one mega-doc): `docs/CODEGEN_PATTERNS_MIPS.md`, `CODEGEN_PATTERNS_PPC.md`, `CODEGEN_PATTERNS_SH.md` — each seeded from community flag docs + `decomp.me` axes. `CODEGEN_PATTERNS.md` itself gets an index paragraph linking to them. |
| `ANNOTATIONS.md` + `METADATA_FORMAT.md` | `// FUNCTION: MODULE 0xVA` marker + `rebrew-function.toml` keyed by `MODULE.VA`; library `library_*.h` alternative; lint E013 duplicate-VA across targets. | Overlays need `(overlay, VA)` scoping: extend `rebrew-function.toml` section to `"MODULE.OVERLAY.0xVA"` or add `overlay = "boot"` field inside the entry (prefer the latter — avoids key-syntax churn, keeps `target_marker()` intact). Library headers already handle shared overlays (`library_libultra.h`). Call out E013 interaction: same VA in two overlays is not a duplicate — mark per-target, not cross-overlay. |
| `DB_FORMAT.md` | `coverage.db` schema `v4` (`functions` PK `(target,va)`; `sections`/`cells`/`globals`/`metadata`/`verify_results`/`history`); `build_db.py --force` on `db_version` mismatch. | Overlay-aware is a **schema migration** (`db_version 5`): `functions` gains `overlay TEXT` (nullable, included in PK or as part of composite key), `sections` gains `overlay`, `cells` include overlay segment. Migration is `DROP+rebuild` via `--force` (existing convention) — no incremental ALTER. Document in `DB_FORMAT.md` §Version History. |
| `GAP_ANALYSIS.md` | Fresh audit categories IMPLEMENT/RECORD/DONE. | Console support is not yet a tracked gap — add an entry `F5 — No console format/arch/toolchain` (RECORD → IMPLEMENT per phase, or new section "Console gap family") so the living audit reflects the roadmap and CI parity (`test_recoverage_contract.py`) gets a console follow-up. |
| `OMF_NOTES.md` | Empirical OMF record framing research (Watcom) with sample bytes + "next steps" — the pattern for non-LIEF formats. | Use the **same research-note template** for each console container: one committed tiny fixture per format (real PS-EXE header bytes, real DOL header, one `z64` header + splat YAML snippet, one SH ELF LE/BE pair, one descrambled GD blob) + a `docs/{PSEXE,N64ROM,DOL,REL,GDROM}_NOTES.md` per format when it graduates from TODO. Do not speculate record tables — ship fixtures first. |
| `AGENTS.md` + `pyproject.toml` | Build/test/lint conventions; `capstone>=5.0.8`, `lief<1`, `tree-sitter`. | No new dep for Phase 0 (capstone already covers MIPS/PPC/SH/ARM). Phase 1+ should not add `pyelftools`/`r2pipe` — LIEF + Capstone + `shlex`-dispatched flag axes cover console objects. If ISO9660/FST parsing needs a dep, prefer shelling out to `7z` (already on most hosts) over vendoring `pycdlib` — see §5.2. |
| `IDEAS.md` | Completed vs Open vs Observations buckets. | On merge, move the 7 brainstorm items from §8 that are accepted (overlay editing, GP-relative, vtable triage) into `IDEAS.md` Open with `needs: Phase {N}` tags, so they appear in the normal triage flow rather than living only in the roadmap. |

### 5.5.3 Cross-cutting invariants to preserve

- **Config-driven + idempotent + no aliases** (`AGENTS.md` / `ARCHITECTURE.md` rules) — console arch/format/profile additions must not introduce per-ISA config dialects or compat shims.
- **Metadata routing** — `STATUS`/`CFLAGS`/`BLOCKER` stay in `rebrew-function.toml` (never inline). Console `overlay` is metadata too — keep it alongside, not in the marker line.
- **Synthetic VA discipline** — console VAs must be stable across re-loads (ROM base + file offset, DOL segment base, `segment<<16|offset` for SATURN SH) so `BinaryInfo.va` round-trips and `extract_bytes_at_va` stays canonical.
- **Disc-image honesty** — rebrew's contract is to compare **function bytes**, not disc images. Disc extraction is a convenience on top of the inner binary — the comparison target remains `1ST_READ.BIN`/`*.dol`/decompressed ROM bytes, and `round-trip` verifies those bytes before any re-packaging step.

---

## 6. Roadmap — Phased

Each phase is shippable independently and ordered by (decreasing payoff) / (increasing effort + legal risk).

### Phase 0 — Foundation: decouple the x86 assumption (1–2 weeks)

> Makes every later phase a *plugin*, not a rewrite. Follows ADR-001/005/006
> seams so nothing in Phase 1+ re-invents them.

- [ ] **0.1 Arch preset registry** (`config.py` `_ARCH_PRESETS`, ADR-001/ CONFIG.md pattern): add console arches as above, with correct `capstone_arch/mode`, `pointer_size=4`, `padding_bytes=[0x00]`, empty prefix. `capstone` 5.x already exposes `CS_ARCH_MIPS/PPC/SH/ARM` — no new dep. Keep unknown-arch warn+fallback (CONFIG.md invariant).
- [ ] **0.2 ISA-dispatched reloc heuristics** (`matcher/scoring.py`, ADR-005 analogue): extract `_zero_reloc_fields_x86_32` → `_zero_reloc_fields(isa)` dispatch; add MIPS/PPC/SH stubs that at minimum zero `jal`/`bl`/`bsr` targets (prove with tiny obj fixtures). Improve over time — typed relocs already bypass this, so scope is "fallback only".
- [ ] **0.3 Mutator tagging**: add `arch` tag, mark x86-only mutations, filter in GA when `cfg.arch` != x86.
- [ ] **0.4 `format` registry + `supported_formats`** (`config.py:697`, `binary_loader.py`, ADR-001 `is_ne` pattern): expand `_KNOWN_FORMATS` and `load_binary`'s `fmt` param to include `psexe/n64rom/dol/rel/xbe/prx/saturnbin`; add string `is_*` helpers alongside `is_ne`. **Do not** inline container parsers — each format gets a native loader module (`rebrew/psexe_loader.py`, `n64rom_loader.py`, `dol_loader.py`, `gdrom_loader.py`) that synthesizes `BinaryInfo`/`SectionInfo` with stable synthetic VAs (ADR-001), imported by `binary_loader.py` like `ne_loader` (ARCHITECTURE.md seam).
- [ ] **0.5 Toolchain spec stubs** (`rebrew/toolchain.py`, ADR-006): reserve `ToolchainSpec` entries + `toolchain-images/<name>/Dockerfile` placeholders for `ido53/71`, `cw_gc`, `sh-elf-gcc`, `psyq` (proxy), `ee-gcc` so every later phase is "fill the Dockerfile + flag axes" rather than new runner glue. Host fallback (`vendored → PATH`) keeps GCC cross toolchains working without docker.
- [ ] **0.6 Documentation + fixtures-per-format policy** (`docs/CONFIG.md`, `docs/TOOLCHAIN.md`, `AGENTS.md`, `docs/OMF_NOTES.md` template): update arch/profile tables; record the "one tiny hex fixture + one NOTES.md per container" rule (OMF_NOTES.md pattern, see §5.5.2) so reviewers expect `docs/{PSEXE,N64ROM,DOL,REL,GDROM}_NOTES.md` on promotion. Unit-test the registry + capstone mode construction (no binary fixture needed yet).

**Deliverable:** `rebrew cfg add-target` + `rebrew asm --target` work for console arches; disassembly is correct, comparison falls back to explicit relocs; every later container/toolchain has a home per ADR-001/006.

### Phase 1 — MIPS Family: PS1 + N64 (+ PS2) (3–5 weeks)

> One ISA, three containers.  ELF path already works — container is the novelty.

#### 1A. N64 — the beachhead (ship first)

- [ ] **ROM loader** (`rebrew/n64rom_loader.py::_load_n64rom`, ADR-001 native-loader pattern): parse N64 header (PI BSB, checksum, IPL3 offset), synthesize `BinaryInfo` (`format="n64rom"`, one `.text` Section for the decompressed body; handle `z64` byte-swapped ROM via magic `0x80371240` / `0x37804012` / `0x40123780`). Commit a tiny `z64` header fixture + `docs/N64ROM_NOTES.md` (OMF_NOTES.md template). BE unpacks — not LE (risk §9).
- [ ] **`splat` YAML intake** (`rebrew intake --splat splat.yaml` or auto-detect `splat.yaml`, ADR-002/004 implications): import overlay list as multiple `BinaryInfo` views or as `data_{target}.json` overlays. Store per-overlay `function_structure.json` or `overlay` column. `catalog` + `build_db` become overlay-aware (`db_version 5` migration — see §5.5.2 notes on DB_FORMAT.md/ANNOTATIONS.md: `overlay` field in `rebrew-function.toml`, not in the marker line; E013 is per-overlay). Pruning key is `(overlay, VA)` per ADR-004.
- [ ] **Compiler profiles** `ido53` / `ido71` / `egcs` (`rebrew/toolchain.py` ToolchainSpec + `toolchain-images/ido*/Dockerfile`, ADR-006): flag axes are tiny — `-O0..2` × `-G 0..128` × `-non_shared`/`-call_shared` × `-mgpopt`/`-mno-gpopt` × `-xgot`/`-mips2` vs `-mips3`. Sync from `decomp.me/platforms/mwcc` and `ehranchov/ido-static-recomp` docs. Provide Docker-based IDO (`ghcr.io/decompme/ido-static-recomp`) + host-native `mips-linux-gnu-gcc` fallback (ToolchainSpec host-fallback seam).
- [ ] **Heuristics** (`toolchain_detect.py`, ADR-005 ELF-header slot): N64 header + `ultra64` / `libultra` strings + ELF `e_flags` (MIPS ISA level) → `ido`/`egcs`. N64 header magic is the DIE-class signal (see §5.5.1).
- [ ] **FLIRT** for `libultra`: generate PAT from open `libultra` source (n64decomp/libultra) and ship.
- [ ] **E2E proof target**: SM64 or a minimal IPL3+binary homebrew ROM — demonstrate `intake → skeleton → compile with ido7.1 via Docker → test → verify` for 3 functions. Requires `docs/CODEGEN_PATTERNS_MIPS.md` stub.

**ADR at ship:** `ADR-00N: Overlay-aware catalog + native N64 ROM loader` (DB_FORMAT + ANNOTATIONS migration + `n64rom_loader` synthetic-VA contract + `function_structure.json` per-overlay).

#### 1B. PS1 (leverage the MIPS work)

- [ ] **PS-X EXE loader** (`rebrew/psexe_loader.py::_load_psexe`, ADR-001): `"PS-X EXE"` magic at `0x00`, `pc0/gp0/text_addr/stack` header → single `.text` Section at `0x80010000`, raw offset `0x800`. Handle both raw PS-EXE and ISO9660-wrapped (detect ISO magic `CD001` and extract `SYSTEM.CNF` default EXE path). ADR-003 degrade rule: unreadable ISO dir → keep container record, drop per-file VAs. Tiny PS-EXE fixture + `docs/PSEXE_NOTES.md`.
- [ ] **PS1 profile** `psyq` (`rebrew/toolchain.py`, ADR-006; `gcc-pe`-style posix profile, `mipsel-elf-gcc` command, empty includes/libs): proxy for Psy-Q; add `maspsx` wrapper for ASM-matching stubs (document as `--maspsx` option in `compile.py`). Flag axes: `-O0..2` × `-G0..8` × `-mgpopt` × `-fno-delayed-branch` etc. (GCC MIPS).
- [ ] **Heuristics**: `PS-X EXE` magic + Sony copyright string + `libgte` imports (ADR-005 DIE-class magic).
- [ ] **PSYOBJ deferment**: document as future work — SN PSYOBJ is the "fabulated imports" class (ADR-003): never reconstruct from incomplete record tables. Do not block ELF path (homebrew/modern decomp already uses GCC EL ELF + `maspsx`). Reuse OMF_NOTES.md framing when PSYOBJ is revisited.

#### 1C. PS2 (free with the above)

- [ ] **EE ELF** already loads via `load_binary` (ELF MIPS EL). Add `r5900`/`allegrex` arch presets and `ee-gcc` profile (toolchain `mips64r5900el-ps2-elf-gcc`). PS2's `IOP` (`mipsel` EL) reuses `mipsel`. No new loader.

### Phase 2 — GameCube: PowerPC Gekko (3–4 weeks, overlaps Phase 1)

> The community with the most deterministic matching pipeline after N64.  Tooling already ships via Docker + Wine.

- [ ] **DOL loader** (`rebrew/dol_loader.py::_load_dol`, ADR-001): parse GC DOL header (18 offsets/sizes + BSS + entry), synthesize 18 Sections (`sec00..sec17`), `text_va` = `text0_va`, BSS as zero-filled virtual Section. Big-endian. Fixture + `docs/DOL_NOTES.md`.
- [ ] **REL loader** (`rebrew/rel_loader.py::_load_rel`, ADR-001): parse REL header + relocation section (REL's custom `R_PPC_*` relocs), produce flat Sections + relocate virtual addrs. RELs are loaded as additional `BinaryInfo` views (one per REL, keyed by module ID). `catalog` enumerates DOL + each REL. ADR-003 clamp: REL count + segment count sanity-gated.
- [ ] **GCM/FST detection**: detect GCM magic (`\xC2\x33\x9F\x3D` at `0x1C`), extract DOL path from FST offset (`0x0420`), handle `boot.bin`/`bi2.bin`/`appldr.bin` skipping. ADR-003 degrade: unreadable FST → module-level `GCM contains DOL` record.
- [ ] **Compiler profile** `cw_gc` (`rebrew/toolchain.py` ToolchainSpec, ADR-006): map `cw_*` versions to sub-profiles (`cw1.0`, `cw2.5`, `cw2.6`, `cw2.7`); each ships as a Wine runner `wine mwcceppc.exe` (same pattern as MSVC6/`msvc1.52`). Add Wine env setup mirroring `msvc_env_from_config`. Provide GCC PPC fallback (`powerpc-eabi-gcc -meabi -msdata=eabi`) for users without CodeWarrior.
- [ ] **Flag axes** (`flag_data.py`): sync from `decomp.me/mwcc` — `-O0..4` (`-opt level`), `-inline off/auto`, `-schedule on/off`, `-sym on/off`, `-ipa file`. Small axes (≈200–2k combos).
- [ ] **Heuristics**: DOL magic + `Metrowerks` / `Dolphin` strings + `.init`/`.text` section naming (ADR-005 string backend; ELF header not applicable to DOL).
- [ ] **C++ dispatch**: extend `data.py --dispatch` for PPC vtables (32-bit `lis`/`addi` hi/lo pairs already detected) + `analyze`'s vtable detection.
- [ ] **E2E target**: a DOL from the `doldecomp` corpus (Melee, SMS) — DOL load → catalog → skeleton → `mwcceppc` via Wine → verify. Requires `docs/CODEGEN_PATTERNS_PPC.md` stub.

**ADRs at ship:** `ADR-00O: DOL + REL native loaders` (synthetic VA contract + overlay extension of 00N), `ADR-00P: Docker-first CodeWarrior toolchain` (ToolchainSpec + image tag).

### Phase 3 — SuperH: Saturn SH-2 → Dreamcast SH-4 (4–6 weeks)

> Shared SuperH ISA work.  Saturn is harder (dual-CPU + big-endian); Dreamcast is easier (EL ELF + modern GCC already works).  Do Saturn's loader first, Dreamcast free-rides.

- [ ] **SH ELF loader** (already half-done — LIEF; ADR-005 ELF-header backend): LIEF already parses SH ELF LE (`e_machine=0x2A`) and BE; add SH-2 vs SH-4 detection via `e_flags` + codegen probe (SH-4 `fmac`/`fipr`/`fsca` insns). Figure out whether LIEF wants a custom `_load_sh_elf` or the generic ELF path suffices (validate with real Saturn `0WLDEXE.BIN` descrambled ELFs). BE/LE fixture pair required (risk §9).
- [ ] **Saturn flat binary + ISO9660 loader** (`rebrew/saturn_loader.py::_load_saturnbin`, ADR-001/003): detect ISO9660 (`CD001`) with Saturn `SEGASATURN` security header at `0x0000`; extract first-executable from IP (`SEGA SEGASATURN` at `0x0100`, first file at `0x06004000`). Flat binary → single Section. Synthetic VA stability matters here — keep `0x06004000` base (invariant §5.5.3).
- [ ] **SH COFF parser** (Hitachi `shc` output): extend `matcher/parsers.py` with a SH COFF path (shares OMF record-framing research but simpler — Hitachi COFF is MS-like with `0x01A8` machine type). Needed only for Hitachi `shc` users; GCC SH path uses ELF and doesn't need it. Gate behind `docs/SHCOFF_NOTES.md` + fixture, like Watcom OMF.
- [ ] **Dreamcast descramble + IP.BIN loader** (`rebrew/gdrom_loader.py::_load_gdrom`, ADR-001): detect `SEGA SEGAKATANA` at `0x0000` of `IP.BIN`, handle `1ST_READ.BIN` scramble detection (descramble = de-interleave) and synthesize ELF `BinaryInfo` from_descrambled. Reuse SH ELF parse for the payload.
- [ ] **Compiler profiles** `sh-elf-gcc` (`sh2eb`/`sh4le` variants), `shc` (`shc.exe` via Wine) — `rebrew/toolchain.py` + `toolchain-images/sh*/Dockerfile`, ADR-006. Flags: `-m2`/`-m4-single`/`-m4` × `-ml`/`-mb` × `-O0..2` × FPU flags (`-m4-nofpu` etc.). Small.
- [ ] **Heuristics**: `e_machine == EM_SH` + `SEGA` IP marker + `Kamui`/`AICA` strings (DC); `libsc` / `Sega Graphics` strings (Saturn). ADR-005: ELF-header family + string backend.
- [ ] **Dual-CPU catalog (Saturn)**: mark functions with CPU affinity (`cpu: master/slave/unknown`) via section range (low work RAM vs high work RAM) or a sidecar map (`saturn_cpu_map.json` from community). `todo`/`status` filter by CPU. Store as metadata field on the function entry (same mechanism as overlay) — keeps E013 clean.
- [ ] **E2E targets**: Dreamcast `1ST_READ.BIN` (homebrew ELF via `sh-elf-gcc`) first; Saturn `Jo Engine` demo second. Requires `docs/CODEGEN_PATTERNS_SH.md`.

**ADRs at ship:** `ADR-00Q: SuperH loaders + SH COFF parser seam` (native BE/LE loaders + OMF-notes-style fixtures), `ADR-00R: Saturn dual-CPU metadata` (if `cpu` field escapes prototype).

### Phase 4 — Shared Hardening & Cross-Cutting (2–3 weeks, interleaved)

> Work that benefits *every* target, console and PC alike. Much of this
> was implicit before — ADRs now make the contract explicit.

- [ ] **MIPS/PPC/SH reloc typing** (`core/matching.py`, `matcher/parsers.py`): extend typed relocs beyond `IMAGE_REL_I386_*` to MIPS/PPC/SH ELF reloc numbers (already available from LIEF — just add to the dispatch). Needs `docs/CODEGEN_PATTERNS_{MIPS,PPC,SH}.md` so `BLOCKER` wording stays consistent.
- [ ] **Endian-aware extract & LIEF fallbacks**: every `extract_bytes_at_va` should handle BE/LE correctly (it already does — bytes are bytes; only disasm cares). Add BE/LE-aware integer decodes where the loader derives VAs from BE headers (risk §9 — gate with header fixtures per §5.5.2).
- [ ] **Overlay-aware `intake` / `catalog` / `build_db` / `status`** (DB_FORMAT.md migration): migrate from single `target_binary` to `target.binaries[]` (retrocompatible — keep `binary = ` as sugar for single-binary projects). Formalizes §5.5.2 `db_version 5` / ANNOTATIONS.md `overlay` field scope. DOL+REL, N64 overlays, Saturn dual-CPU map naturally. `GAP_ANALYSIS.md` entry should flip to IMPLEMENT here.
- [ ] **Disc-image-aware `doctor` + `intake`** (ADR-003 degrade rule): `doctor` detects disc images (`ISO9660` / `GCM` / `GD-ROM`) and names the inner binary; `intake` accepts disc image and extracts (via `7z` if present, else error with instructions). Unreadable FST/ISO dir → module-level record only.
- [ ] **FLIRT signature packs per console**: ship or document `.sig` for `libultra`, `libdolphin`, `libsgl`, `libkatana`; add `flirt --pack n64|gc|ps1|saturn|dc` to fetch. `identify-library` already aggregates FLIRT+imports+CRT.
- [ ] **SDK header packs** (`rebrew cfg detect-sdk`): like `detect_crt_sources`, detect vendored `include/` trees for `ultra64`, `dolphin`, `katana`, `sgl` (user-provided SDK dumps).
- [ ] **`round-trip` for ROM/DOL**: add `--format dol|n64rom|psexe` that rebuilds with `ld.lld` + board linker script + (de)scramble step, then verifies header + segment checksums (N64 checksum, DOL BSS, PS1 stack). Invariant §5.5.3: verify **function bytes first**, re-packaging second (round-trip contract, not disc-image equivalence).
- [ ] **Ghidra processor selection**: `ghidra/client.py` already passes VA; ensure console `arch` selects the correct Ghidra processor (MIPS:le:32, MIPS:be:32, ppc:BE:32, SuperH:*/SH2/SH4, ARM:LE:32:ARM).
- [ ] **GAP_ANALYSIS + IDEAS housekeeping**: flip console gap family to IMPLEMENT and move the accepted §8 brainstorm items (overlay editing, GP-relative, vtable triage) into `IDEAS.md` Open with `needs: Phase {N}` tags (see §5.5.2).

### Phase 5 — Reach / Convergence (optional, 2–4 weeks)

> Nice-to-haves that become cheap once Phases 0–4 exist.

- Xbox XBE (trivial — add `xbe` loader, LIEF treats it as PE variant; MSVC profiles already exist).
- PSP PRX / PSVita ELF (MIPS Allegrex).
- PS2 VU microcode (VU0/VU1 COP2/VCmd) — not C; document as ASM-only blocker (like SEH helpers today).
- Automatic `splat` ↔ Rebrew two-way sync (edit YAML from Rebrew, re-split ROM).
- Consensus decomp helpers: auto-detect `-G` gp register value from ROM (N64), auto-detect `__gp` for PS1.
- Cross-project `solutions_db` for `cw_gc`/`ido71` — sharing winning cflags across functions already works once the profile exists.

---

## 7. How Rebrew Would Be Used (Console Workflows)

### 7.1 The solo reverser (one ROM, no prior RE)

```bash
# 1. Onboard — handles disc images, detects N64 ROM + overlays + toolchain
rebrew intake original/baserom.z64          # → uses splat.yaml if present
rebrew doctor                                # → "detected IDO 7.1, profile ido71 fits"
rebrew cfg set-cflags default "-O2 -G 8"    # per-overlay presets later
rebrew analyze --output report.md            # toolchain, strings, SDK libs, FLIRT

# 2. Triage
rebrew todo -c start-function                # actionable funcs, filtered (skip SDK)
rebrew similar 0x80001234 --limit 5          # find similar funcs to batch

# 3. Skeleton → edit → match
rebrew skeleton 0x80001234
$EDITOR src/Target/func_80001234.c
rebrew test src/Target/func_80001234.c       # ido7.1 compile + compare (Docker IDO or GCC)
rebrew diff 0x80001234                        # mnemonic diff (MIPS BE, Capstone)
rebrew match src/Target/func_80001234.c      # GA + flag sweep (small console flag space)
rebrew asm 0x80001234 --size --imports        # inspect target bytes

# 4. Global data
rebrew data --scan --dispatch --gen-header    # vtable / overlay tables, rebrew_globals.h

# 5. Verify & rebuild
rebrew verify --parallel 8                   # incremental, cached
rebrew round-trip --format n64rom --overlay boot --fix-headers
```

### 7.2 The platform chameleon (multi-target project)

```toml
[targets.ps1_game]
binary = "original/SLUS_001.00"   # ISO9660 auto-extracted
arch   = "mipsel"
format = "psexe"
[targets.ps1_game.compiler]
profile = "psyq"                  # mipsel-elf-gcc + maspsx

[targets.n64_game]
binary = "original/baserom.z64"
arch   = "mips"
format = "n64rom"
[targets.n64_game.compiler]
profile = "ido71"                 # Docker ido-static-recomp
```

`rebrew todo --target ps1_game`, `--target n64_game`, shared `skeleton.py` + Ghidra sync per target.

### 7.3 The library cartographer

```bash
# Build FLIRT signatures from SDK .a/.lib once, then every project benefits
rebrew gen-flirt-pat sdk/libultra/libultra.a --out sigs/libultra.pat
rebrew gen-flirt-pat sdk/libdolphin.a --out sigs/libdolphin.pat
rebrew flirt sigs/                           # → auto-labels SDK functions as library_*.h
rebrew identify-library --all --fix-source   # merges FLIRT + imports + toolchain signals
```

### 7.4 The CI/verify bot

```bash
rebrew verify --json --all > verify.json
rebrew verify --compare                       # regression check
rebrew build-db                               # update coverage.db (now overlay-aware)
rebrew report --serve                         # PR artifact
```

---

## 8. Brainstorm — Extra Console-Useful Features

Ideas beyond "port the existing engine" — native console strengths that would be *new* capabilities in Rebrew.

### 8.1 Overlay/REL-Aware Editing
- `rebrew split` / `merge` already exist — extend to overlay boundaries (one file per overlay, like N64's `src/boot`, `src/ovl_Boss`). `cu_map` should infer CU boundaries *per overlay* (linker script = authoritative partition).

### 8.2 Literal-Pool & GP-Relative Tracking
- N64/PS1/PS2 MIPS use `$gp` to reach small data (`.sdata`/`.sbss`); SH literal pools do similar. `rebrew data` could track `gp`-relative globals and emit `__gp`-anchored `extern`s so C re-declarations produce `gp`-relative `lw` instead of `lui`/`addiu` pairs — a frequent mismatch source. This is console-specific codegen, and Rebrew could *generate* it rather than require hand-tuning.

### 8.3 C++ Demangle & Vtable-First Triage
- GC/DC are C++ heavy. `rebrew todo --c++` that ranks functions by `is_vtable_entry`, `is_pure_virtual`, or `has_vtable_cross_ref` would let reversers knock out class hierarchies bottom-up. Ghidra's `analyze-vtable` MCP tool already feeds this; expose it in `todo`/`depgraph`.

### 8.4 Match-Seeding Across Ports
- Many games shipped on multiple consoles with shared C sources (e.g. Tony Hawk PS1↔N64, Crazy Taxi DC↔PS2). Add `rebrew match --seed-project ../ps1-port` that seeds cflags/mutations from the port where a function was already matched. `solutions_db` already supports cross-project seeding.

### 8.5 Asset/Filesystem diff helper
- PS1/GC/Saturn/DC assets live alongside code in the same disc image. A lightweight `rebrew resource --diff-iso` that `diff`s extracted filesystems (FST vs ISO9660 vs GD) after a source rebuild would close the `round-trip` loop at the disc-image level (not just the inner executable).

### 8.6 ARM7/AICA world for Dreamcast
- The ARM7 blob is a separable target (`arch=arm7`, `arm-eabi-gcc`). It is tiny but has its own catalog. Treating it as a second target in the same project (like `server.dll`+`client.exe` today) requires no new code — just config docs + a loader.

### 8.7 `decomp.me` / `splat` import
- One-shot `rebrew intake --decomp-me <scratch_id>` or `rebrew intake --splat splat.yaml` that auto-fills `rebrew-project.toml` from existing decomp.me / splat metadata, so porting an in-progress community decomp into Rebrew is minutes not hours.

---

## 9. Risks & Open Questions

| Risk | Mitigation |
|------|------------|
| **Proprietary SDK/toolchain legality** (IDO, CodeWarrior, Psy-Q, SHC) cannot be vendored. | Ship only open GCC cross toolchains; treat proprietary compilers as user-owned add-ons. Document fetch-and-verify steps (like `wibo.py` for `wibo` already). Provide Docker images (community's `ido-static-recomp`, `cw` Docker) as the recommended IDO/CW path — no licensing friction. |
| **PSYOBJ parser is a project unto itself** — SN object format is undocumented and variant-heavy. | Defer PSYOBJ; PS1 users can match via `mipsel-elf-gcc` + `maspsx` (established community workaround). PSYOBJ parser, if built, reuses the OMF record-framing skill from `docs/OMF_NOTES.md`. |
| **N64 overlay linking is complex** — one ROM = many linker scripts; naïve flat rebuild produces a corrupt ROM. | Lean on `splat` as source of truth: re-import `splat.yaml` on `round-trip` and delegate link to `splat`'s generated ldscripts rather than re-inventing them. |
| **Capstone version drift for SuperH** — Capstone's SH support is younger than MIPS/PPC. | Pin `capstone>=5.0.8` already handles SH; add a `tests/fixtures/sh2-encode` round-trip test early to pin correct `CS_MODE_SH2/SH4` selection. |
| **Big-endian header parsing bugs** — DOL / N64 ROM / SH BE headers are all BE; loader must not use LE unpacks. | Add per-format header fixtures and `test_binary_loader_*` tests that assert `va`/`file_offset` for each segment against a hex dump before any scoring work. |
| **Dual-CPU Saturn: which CPU owns the function?** | Treat CPU affinity as ornament (like `BLOCKER` today) and filter on it — don't impose a two-catalog requirement until a Saturn project demonstrates the need. Simplest: one catalog with `cpu` tag. |
| **Flag-space curation churn** — IDO vs CW vs sh-gcc flag semantics shift per minor version. | Sync from `decomp.me` platforms (already curated) and tag profiles with compiler version (`ido71`, `cw2.7`) instead of trying to make one profile fit all. |
| **Community fragmentation** — GC uses `doldecomp`, N64 uses `splat`, PS1 uses `psxdecomp` — each has its own YAML/catalog conventions. | Rebrew as *complement*, not replacement: import their catalogs, export `rebrew_globals.h`/`types.h` they understand, and provide the missing workbench (STATUS/verify/match) on top. |

---

## 10. Appendix: Quick-Reference Tables

### A. ISA at a glance

| Console | ISA family | Arch preset (proposed) | Capstone | Endian | ptr | Notable |
|---------|-----------|------------------------|----------|--------|-----|---------|
| PS1 | MIPS-I (R3000) | `mipsel` | `MIPS + MIPS32 + LE` | LE | 4 | Delay slot |
| N64 | MIPS-III (R4300) | `mips` | `MIPS + MIPS32R6 (BE)` | BE | 4 | o32 ABI, `$gp` |
| GC | PowerPC 750 | `ppc_gekko` | `PPC + MODE_32` | BE | 4 | Paired singles |
| Saturn | SuperH SH-2 | `sh2` | `SH + SH2 + BE` | BE | 4 | 16-bit enc. |
| DC | SuperH SH-4 (+ ARM7) | `sh4` / `arm7` | `SH+SH4+LE` / `ARM+ARM` | LE | 4 | FPU vec |
| PS2 | MIPS R5900 | `r5900` | `MIPS+MIPS32+LE` | LE | 4 | COP2 VIF/VU |
| Xbox | x86 PIII | `x86_32` | `X86+32` | LE | 4 | Already ships |
| PSP | MIPS Allegrex | `allegrex` | `MIPS+MIPS32+LE` | LE | 4 | VFPU |

### B. Binary-container at a glance

| Console | Container(s) | Detected by | Loader synthesis | Round-trip check |
|---------|--------------|-------------|------------------|------------------|
| PS1 | PS-X EXE (inside ISO9660) | `PS-X EXE` magic + `CD001` | 1 Section `@0x80010000`, off `0x800` | `SYSTEM.CNF` entry + EXE header |
| N64 | ROM (`z64` BE) | `0x80371240` / IPL3 | 1 outer + overlay Sections from `splat.yaml` | N64 checksum (`CRC1/CRC2`) |
| GC | DOL + REL (inside GCM) | DOL text/data off table + GCM magic | 18 Sections + per-REL Sections | DOL BSS + FST + `bi2.bin` |
| Saturn | Flat bin (inside ISO9660 `SEGASATURN`) | `SEGA SEGASATURN` IP | 1 Section `@0x06004000` | IP + first-executable CRC |
| DC | `IP.BIN` + `1ST_READ.BIN` (scrambled ELF) | `SEGA SEGAKATANA` | Descrambled ELF via existing ELF path | Scramble parity + `IP.BIN` |
| PS2 | ELF (EE) + IOP ELF | ELF `e_machine=0x08` | LIEF ELF | ELF entry |
| Xbox | XBE | `XBEH` magic | LIEF PE-variant | PE headers (already LIEF) |

### C. Compiler → Rebrew profile mapping

| Compiler family | Versions seen | Rebrew profile(s) | Runner | Object | Notes |
|-----------------|---------------|-------------------|--------|--------|-------|
| Psy-Q `CCPSX` | 3.2–4.7 | `psyq` (proxy: `mipsel-elf-gcc`) | `ccpsx.exe` (Wine, optional) | PSYOBJ / ELF (GCC) | `maspsx` for ASM stubs |
| IDO / MIPSPro | 5.3, 7.1, 7.30 | `ido53`, `ido71` | Docker `ido-static-recomp` (Linux) | ELF | Flag space tiny |
| EGCS / GCC MIPS | 2.7, 2.95, 4.x | `gcc` (`-march=mips2/3`) | native `mips-elf-gcc` | ELF | Rare third parties |
| CodeWarrior PPC | 1.0–2.7 | `cw_gc` (`cw1.0..cw2.7`) | `mwcceppc.exe` via Wine | ELF | decomp.me axes exist |
| Hitachi SHC | 5.0, 6.x, 7.x | `shc` | `shc.exe` via Wine | SH COFF | Optional after GCC |
| GCC SH | 2.95..13 | `sh-elf-gcc` (`sh2`/`sh4` subs) | native `sh-elf-gcc` | ELF | Primary for Sega |
| EE-GCC | 2.9, 3.2 | `ee-gcc` | native `mips64r5900el-elf-gcc` | ELF | PS2 |
| MSVC XBE | 6, 7 | `msvc6`/`msvc7` | `wine CL.EXE` | COFF | Already ships |
| ARM GCC | 4.x..13 | `gcc` (`-march=armv4t`) | native `arm-none-eabi-gcc` | ELF | DC ARM7, GBA-adj. |

### D. Effort envelope (engineering estimate)

| Phase | Scope | Est. | Dependencies | Can ship alone |
|-------|-------|------|--------------|----------------|
| **0 Foundation** | Arch registry + ISA dispatch + `format` | 1–2 w | None | **Yes** |
| **1A N64** | ROM loader + splat + IDO/GCC profiles | 2–3 w | 0 | **Yes** |
| **1B PS1** | PS-EXE loader + PsyQ/GCC profile | 1 w | 0, 1A | **Yes** |
| **1C PS2** | Presets only (ELF already works) | 2 d | 1A | **Yes** |
| **2 GC** | DOL/REL loaders + CW profile | 3–4 w | 0 | **Yes** |
| **3 Saturn/DC SH** | Saturn bin + SH COFF + DC descramble | 4–6 w | 0 (SH ISA) | **Yes** |
| **4 Hardening** | Overlays, reloc typing, disc-aware intake, FLIRT packs | 2–3 w | 1A, 2, 3 | **Yes** |
| **5 Reach** | XBE/PSP/VU/asset diff/decomp.me import | 2–4 w | prior | **Yes** |

*All phases overlap; wall-clock with one engineer ≈ 3–4 months to "usable for PS1+N64+GC".*

---

## 11. Sources & Prior Art

- **Rebrew own research**: `docs/TOOLCHAIN.md` (x86 profile caveat, NE loader pattern), `docs/OMF_NOTES.md` (binary container parser pattern to reuse for PSYOBJ/DOL/ROM), `docs/CODEGEN_PATTERNS.md` / `docs/GA_MUTATIONS.md` (what transfers), `src/rebrew/binary_loader.py` / `config.py` (seams to extend).
- **Console tooling canon**: `splat`/`splat64` (N64 ROM → splat.yaml), `doldecomp`/`dtk` (GC DOL/REL), `ndstool`/`gdit` (disc images), `maspsx` (Psy-Q ASM proxy), `psxdecomp`, `ghidra-dreamcast-loader`, `ido-static-recomp` (Linux-native IDO), `KallistiOS` (Dreamcast GCC), `Jo Engine` (Saturn), LIEF (ELF/PE/COFF), Capstone (ISA).
- **Compiler corpora**: `decomp.me` compiler repo (`platforms/win32`, `platforms/mwcc`, `platforms/ido`, `platforms/ps1`), `archaic-msvc` (MSVC model to mirror for SDK vendors), `OmniBlade/decomp.me` releases.
- **Decomp communities**: SM64/OOT (N64), doldecomp Melee/SMS/WW (GC), PS1/PS2 matching discords, Dreamcast `dcdecomp`, Saturn `saturndecomp` — all converge on the same byte-match loop documented above.
- **IDs & standards**: Hitachi SH COFF `e_machine` values (`0x2A` sh), MIPS ELF `e_flags` ISA levels, N64 IPL3 header layout, GC DOL spec (`yagcd`), Dreamcast GD-ROM scramble (`scramble.exe` algorithm), PS-X EXE header (`EXEC`).

> Capstone and LIEF capabilities verified against their current docs; toolchain version strings (Psy-Q 3.2–4.7, IDO 5.3/7.1, CodeWarrior 1.0–2.7, SHC 5–7) are community-consensus ranges from decomp project READMEs.

---

## 12. Decision Proposal

1. Approve **Phase 0** immediately — zero risk, unblocks all console work, and improves the x86/ARM path (ISA-dispatched heuristics).
2. Green-light **1A N64** as the pilot (lowest risk, highest community leverage, most reusable for PS1/PS2) with a single E2E ROM as the exit criterion.
3. Queue **2 GC** in parallel with **1B PS1** — both exercise MIPS vs PPC independently.
4. Defer **PSYOBJ and SH COFF custom parsers** until a real project requires them — ELF/GCC paths unblock 80% of current open-source decomp efforts.
5. Record as ADRs: `ADR-XXX: Overlay-aware catalog`, `ADR-YYY: Disc-image intake`, `ADR-ZZZ: Console arch presets` when each ships.

*This doc is the backlog; each phase gets its own `docs/prd/` and ADR as it becomes active work.*
