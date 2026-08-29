# Multi-Arch Roadmap

Goal: make rebrew able to onboard, annotate, and **byte-match** binaries of
other architectures besides x86 — starting with **MIPS 32-bit** (N64/PS1) as the
first-class proof target, with PPC/ARM as the follow-on set.

Status: RFC — phased roadmap. Phases ship independently with green CI; Phase 0
and 1 together form the "MIPS works" milestone.

## Current state (grounded audit)

### Already arch-agnostic (no work needed)

- Byte-compare loop: `test.py` / `verify.py` / `diff.py` / `compile.py` compare
  bytes, not instructions — architecture-independent.
- GA core: `matcher/scoring.py` takes `cs_arch`/`cs_mode`/`pointer_size` params;
  `mutator.py` is tree-sitter C, arch-neutral.
- Coverage/reporting: `catalog`, `report`, `status`, `build_db`, `dashboard`,
  decomp.dev report, objdiff bridge, `symbol_addrs`, `context` — all VAs/sizes/
  bytes only.
- `cfg_ged.py` (CFG structural), `prove.py` (angr supports MIPS/PPC/ARM).
- `binary_loader` format detection (PE/ELF/Mach-O via LIEF), `toolchain.py`
  native-spec pattern (`gcc-pe`, `watcom16`).

### Arch-specific surfaces (the work list)

| Surface | Where | What's hardcoded |
|---|---|---|
| Arch presets | `config.py::_ARCH_PRESETS` | x86_16/32/64, arm32/arm64; **no MIPS/PPC/SuperH** |
| Arch detection | `binary_loader._ELF/_PE/_MACHO_MACHINE_TO_ARCH` | x86/arm only; ELF EM_MIPS=8, EM_PPC=20, EM_SH=42 missing |
| Function extent walker | `binary_loader.function_extent_from_disasm` | `CS_ARCH_X86` + `ret/jmp/int3` terminators |
| Reloc masking | `core/matching.py::smart_reloc_compare` | COFF `IMAGE_REL_I386_DIR32/REL32` constants |
| Object reloc parsing | `matcher/parsers.py` | verify ELF-MIPS/PPC reloc extraction (COFF-centric) |
| Function discovery | `discover.py::_capstone_sweep` | `e8 rel32` call targets, `CC/90` padding, `ret` ends |
| Stack frames | `stack_cmp.py` | esp/ebp frame analysis (x86-32) |
| Jump tables | `catalog/registry.py::is_jump_table` | `0x90/0xCC` prefix + `8BFF` check (x86) |
| Flags | `matcher/flag_data.py` | GCC family exists; no MIPS/PPC axes (`-mabi`, `-march`) |
| Toolchain specs | `toolchain.py::ToolchainSpec` | `bits` field only; add `arch` for alignment/detection |
| Import/PE lane | `round_trip`, `gen_layout`, `postlink`, `link_sweep`, `imports.py`, `pe_headers.py` | PE-specific — N/A for ELF targets (gate or ELF equivalents later) |
| Known arches | `doctor.py::_KNOWN_ARCHES` | extend alongside presets |

## Phase 0 — Arch plumbing foundation

Small, behavior-neutral; unblocks every later phase. Exit: full suite green,
**zero change to x86 behavior**.

1. `config.py`: add `mips32` (CS_ARCH_MIPS + CS_MODE_MIPS32, ptr 4, padding
   `[0x00]`), `mips64`, `ppc32` (CS_ARCH_PPC + CS_MODE_32), `ppc64`, `sh2`
   presets.
2. `binary_loader`: extend the three machine→arch maps (ELF: MIPS=8, PPC=20,
   SH=42; PE: THUMB/ARMNT as available).
3. `binary_loader.function_extent_from_disasm`: replace the x86 terminator list
   with a per-arch table driven by the loaded `BinaryInfo` arch:
   - x86: `ret/retf/iret/iretd/int3`, `jmp`
   - MIPS: `jr $ra` / `jr $t9` (tail), `j`/`jal` NOT terminators, padding `0x00`
   - PPC: `blr`, `bctr`/`b` (tail), padding `0x60 00 00 00` nop
   - ARM: `bx lr`, `mov pc,lr`
4. `core/matching.py`: refactor the reloc-type constants into a per-arch table
   (COFF-i386 keeps `DIR32/REL32`; add ELF-MIPS `R_MIPS_26/LO16/HI16/REL32`,
   ELF-PPC `R_PPC_ADDR32/REL24`). The masking *algorithm* (validate → mask) is
   unchanged; only the type constants + address extraction vary. **Highest-risk
   change** — keep the existing x86 tests as a regression net.
5. `discover.py`: arch-aware sweep (terminators/padding from a table; call-target
   extraction per arch: `jal` for MIPS, `bl` for PPC vs `e8 rel32` for x86).
6. `asm.py` (the one `CS_ARCH_X86` hardcode outside the presets path) cleanup.
7. `doctor.py::_KNOWN_ARCHES` + `catalog/registry.is_jump_table` arch gate (x86
   pattern only for x86; MIPS variant lands in Phase 1).
8. Tests: extent walker on synthetic MIPS/PPC bytes; `detect_format_and_arch` on
   tiny MIPS/PPC ELF fixtures; reloc masking with MIPS reloc records; the full
   existing suite stays green.

## Phase 1 — MIPS 32-bit first-class target (proof of pipeline)

Delivers: *a MIPS ELF binary can be onboarded, annotated, and matched with
`gcc-mips`* — the end-to-end milestone that validates the whole arch layer.

1. Toolchain spec `gcc-mips` (native Linux cross compiler,
   `mipsel-linux-gnu-gcc` for PS1 / `mips-linux-gnu-gcc` BE for N64; per-target
   `arch`/endianness in the spec) — copy the `gcc-pe` native-spec pattern;
   `bits=32`, `arch=mips32`.
2. `flag_data.py`: MIPS GCC flag family (minimal posix axes: `-march`, `-mabi`,
   `-O2` etc.) registered like `GCC_FLAGS`; sweep tiers.
3. `matcher/parsers.py`: MIPS ELF object + reloc support (R_MIPS_26/JUMP26/
   LO16/HI16) feeding the Phase-0 reloc table.
4. `stack_cmp.py`: minimal MIPS frame analyzer (sp/fp/ra slots) or explicit
   "N/A on this arch" gate — default: gate.
5. `catalog/registry.py::is_jump_table`: MIPS variant (word-pointer tables).
6. **End-to-end fixture**: compile a small C sample with `gcc-mips` into an ELF,
   `rebrew init` it, run discover → skeleton → `rebrew test`/`verify` → EXACT on
   a matching function and NEAR_MATCHING on a perturbed one. Checked into
   `tests/fixtures/` so CI exercises the whole pipeline without a target binary.
7. Ecosystem integrations: decomp.dev report (arch-agnostic ✓), objdiff target
   synthesis (`write_coff_object(machine=...)` — `0x0166` MIPS, or emit ELF since
   objdiff reads ELF natively), `symbol-addrs`, `context` — all already work;
   only the objdiff machine constant needs a MIPS value.

Caveat (same as `gcc-pe`, documented in AGENTS.md): `gcc-mips` gives
**structural** matches; byte-exact matching for console titles needs the original
compiler → Phase 2.

## Phase 2 — Console-era toolchains + ecosystem interop

Byte-exact for N64/PS1/GC requires the actual compilers:

1. **IDO (SGI) reimplementation** (MIPS, N64) and **MWCC PPC** (GC/Wii) via the
   rebrew-toolchains image pattern (`rebrew/ido:7.1`, `rebrew/mwcc:...`) — wine/
   wibo under the image, same as MSVC. Vendored trees in
   `<family>/<version>-<arch>/source`.
2. ~~**m2c as a decompiler backend**~~ *(DONE)*: m2c is MIPS/PPC-native; the `m2c`
   backend is registered in the decompiler registry (`rebrew skeleton
   --decomp-backend m2c`), feeding it the `rebrew context` output (`--context
   ctx.c`) — the m2c `--valid-syntax`/`--stack-structs` workflow is available
   for MIPS/ARM/SH targets.  PPC is still blocked: capstone 5 has no working
   PPC engine to feed m2c (word-scan extent only), so `fetch_m2c` returns None
   for PPC until a capstone ≥6 or rizin-based disassembler lands.
3. **FLIRT for console libs**: ~~`gen_flirt_pat` gains ELF archive support~~ *(DONE)* —
   ``rebrew gen-flirt-pat`` now dispatches on member magic (COFF ``.lib`` vs ELF
   ``.a``); ELF objects use exact symbol sizes and MIPS fixups mask the whole
   instruction word.  Remaining: signature DBs for libultra / PSX libc / DOL
   runtime and `identify_library` presets (e.g. `n64-libultra`, `psx-libc`).
4. `imports.py`/`asm --imports`: ELF import reading (`.dynsym`/PLT) for MIPS/PPC
   — the current import path is PE/IAT-centric.

## Phase 3 — Broadening + ELF link lane

1. Adopt PPC32, ARM32, SuperH targets as demand arrives (presets, terminators,
   reloc tables, flag axes all parameterized by Phase 0/1 — additive only).
2. **ELF link lane**: `gen_layout`/`round_trip`/`postlink` ELF equivalents
   (linker script from target ELF, `.data` placement, byte-identity re-link
   check) — only when a rebrew project links a full ELF rather than comparing
   objects.
3. Multi-arch fixture matrix in CI (one fixture per arch with a matching +
   non-matching function pair).

## Cross-cutting decisions / risks

- **Reloc-masking refactor (Phase 0 #4) is the risky one** — it's the core of
  RELOC matching. Mitigation: keep COFF-i386 constants byte-identical, add new
  arch entries alongside, lean on the existing test suite + new MIPS reloc tests.
- **Byte-exact requires the original compiler** — structural-only matches with
  cross gcc are the honest default until Phase 2 images land; document per-target
  in AGENTS.md like the gcc-pe caveat.
- **16-bit DOS lane (OMF16/NE/MZ) stays separate** — the arch work targets
  ELF/COFF 32/64-bit; do not entangle the 16-bit paths.
- **Naming**: new presets follow `mips32`/`ppc32` convention; `cfg.arch` is the
  single source of truth feeding capstone + extent + reloc + discovery tables.
