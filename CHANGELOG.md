## [Unreleased]
### Fixed
- **`rebrew-cmake-*` only translated paths under `/home`, `/tmp`,
  `/gamatcher`** — `_rewrite_args` (`cmake_tc.py`) decided which argv
  tokens were absolute host paths by matching a hardcoded prefix list, so
  a project checked out anywhere else (e.g. `/srv/decomp`) got raw
  POSIX paths handed to CL.EXE/LINK.EXE, which parse them as options.
  The prefixes are replaced by `_is_host_path`, a structural probe (a
  second slash marks a path; MSVC flags are single-segment), so any
  absolute project location converts to wine `Z:\` form.  `make
  release-check` dropped the bash-only `set -o pipefail` (the recipe has
  no pipelines; `/bin/sh` is dash on stock Debian).
### Added
- **Codegen corpus round 24 — guild Findings 46-50 primitives
  (probe27)** — `docs/codegen/corpus.json` grows 12852 → **13127
  records** (probe27 adds 275: 10 MSVC versions × /O2+/O1, 7 SPs,
  bcc32/Watcom/GCC/Zig, and the 16-bit set).  Added to RULES.md:
  - **F25 refined (F46)** — same-constant fail paths MERGE into one
    shared `xor eax,eax; ret` tail in every version (distinct
    constants inline, same constants merge — the doc's Finding 46
    reference shape IS the MSVC default).
  - **C32 VERIFIED** — the byte-slot or (`or ch,0x10` for `|= 0x1000`)
    is a **5.0/6.0-only trait** (the doc's `or dh,0x10` form); 2.0/4.1
    immediate `0d`, 7.0/7.1 `81 c9`, 8.0+ memory `81 08` — extends
    F15's AH-slot family to the memory-store context.
  - **E23 VERIFIED** — callee-saves push at ENTRY + fail-path pop in
    every version (no deferral past guards in the simple shape — the
    F48 region-split is context-specific); fill-loop counters stay
    KEPT (countdown) in every version (the F49/F50 elimination is
    also context-specific; 8.0/9.0 add-over-inc + sub-over-dec).
  - `corpus-matrix.json` index 460 → **469 functions**; idiom sweep
    validates (`fail_epi` guild 6×, `callee_defer` 1-4×, `fill_iv` 2×,
    `or_100000` 2×; exact `or_1000`/`fill_nested` negatives recorded).
    Docs: RULES.md (+2 rows + F25 refinement), DECOMP_IDIOMS.md (+4
    idioms), 17 per-toolchain files, README.  See the round-24 spec
    `.cache/goal_probe27.md`.
- **Codegen corpus round 23 — guild Finding 45 early-return placement
  (probe26)** — `docs/codegen/corpus.json` grows 12715 → **12852
  records** (probe26 adds 137: 10 MSVC versions × /O2+/O1, 7 SPs,
  bcc32/Watcom/GCC/Zig, and the 16-bit set).  Added to RULES.md:
  - **F25 VERIFIED** — early-return blocks stay INLINE right after
    their conditional checks in EVERY version (`test; jne +6; mov
    reg,-3; ret` — the `jne` skips the block) — **the doc's Finding 45
    tail-grouping claim is corrected: it is a register-pressure context
    artifact, not general MSVC behavior**; the shared `-1` epilogue is
    `or eax,-1` from 5.0 (2.0/4.1 `mov eax,-1`, the B5 trait); 11.0
    materializes negative constants via `lea eax,[reg-N]`.
  - The pop-edi scheduling and out-param order fixed points recorded
    as D with reasons.
  - `corpus-matrix.json` index 456 → **460 functions**; idiom sweep
    validates (`er1` guild 2× + CLIPBRD 1×, `er2`/`er4` guild 14-19× +
    server.dll 4× — the inline early-return placement is the default
    shape in the wild; exact `er3` negative recorded).  Docs: RULES.md
    (+1 row), DECOMP_IDIOMS.md (+2 idioms), 17 per-toolchain files,
    README.  See the round-23 spec `.cache/goal_probe26.md`.
- **Codegen corpus round 22 — guild Finding 44 primitives (probe25)** —
  `docs/codegen/corpus.json` grows 12408 → **12715 records** (probe25
  adds 307: 10 MSVC versions × /O2+/O1, 7 SPs, bcc32/Watcom/GCC/Zig,
  and the 16-bit set).  The four probe-able primitives from Finding 44
  were compiled through every toolchain and added to
  `docs/codegen/RULES.md`:
  - **C30 VERIFIED** — ternary nonnegative clamp `(x<=0)?0:x`:
    branchless `setle cl; neg ecx; and eax,ecx` in 5.0–7.1/9.0/10.0
    (the doc's setle/dec/and form), branchy `test; jg; xor` in 2.0/4.1,
    `setle; sub ecx,1` in 8.0 (sub-over-dec), `cmovle` in 11.0;
    `clamp_lt0` uses `sets` in 10.0 (sign-flag preference).
  - **C31 VERIFIED** — ×589 multiply: 2.0/4.1 four-lea chain,
    5.0/6.0 five-instruction lea chain, **7.0+ single `imul
    0x24d`** — the lea-vs-imul split fingerprints the era for
    non-power constants.
  - **E21 VERIFIED** — byte-arg push forms: **2.0–6.0 push the raw
    byte (`mov al,[mem]; push eax` — refutes the doc's "no C shape
    produces the raw push" claim, which only holds under register
    pressure)**; 7.0/7.1 `xor;mov cl` zero-extend; 8.0+ `movzx`;
    7.0+ tail-call the wrapper.
  - **E22 VERIFIED** — byte+dword sum loads the byte FIRST in every
    version (the doc's dword-first is a register-pressure artifact).
  - `corpus-matrix.json` index 447 → **456 functions**; idiom sweep
    validates (`clamp_*` guild 1× + sndrec32 1×, `mul589` lea-chain
    guild 2×, `sum_load` guild 11-18× + server.dll 1×; exact
    `bpush3`/`imul`-589 negatives recorded).  Docs: RULES.md (+4
    rows), DECOMP_IDIOMS.md (+4 idioms), 17 per-toolchain files,
    README.  See the round-22 spec `.cache/goal_probe25.md`.
- **Codegen corpus round 21 — guild Findings 37-43 primitives (probe24)** —
  `docs/codegen/corpus.json` grows 11897 → **12408 records** (probe24
  adds 511: 10 MSVC versions × /O2+/O1, 7 SPs, bcc32/Watcom/GCC/Zig,
  and the 16-bit set).  The eight probe-able primitives the new
  findings expose were compiled through every toolchain and added to
  `docs/codegen/RULES.md`:
  - **C29 VERIFIED** — WORD (unsigned short) zero-extension, the 16-bit
    twin of C4: `xor reg,reg; mov reg_low16,[mem]` in 4.1–6.0 (the doc's
    MSVC6 form, confirmed in the guild binary 2×), `and eax,0xffff` in
    2.0, `movzx` from 7.0; word params `and reg,0xffff` 2.0–6.0,
    `movzx` 7.0+; /O1 movzx everywhere.
  - **F24 VERIFIED** — size-dispatch `switch{1,2,4}` compiles to a
    **dec-chain, never a jump table**: `dec; jz; dec; jz; sub 2; jz` in
    5.0–7.1/10.0/11.0, `sub reg,1`-chain in 8.0/9.0 (the B10
    sub-over-dec trait), `cmp`-chain in 2.0/4.1 — extends F11.
  - **F23 VERIFIED** — word compare eras: raw word load + 16-bit
    `cmp ax,imm` 2.0–7.1; `movzx` + `cmp ax` 8.0+.
  - **E18/E19/E20 VERIFIED** — in-place memory and (`and word
    [mem],reg`) uniform in EVERY version (the doc's size2 form);
    byte or-mask memory-operand from 8.0 (5.0–7.1 byte-register
    round-trip is the odd era out); the simple field-store folds to
    `mov [reg+0x14],eax` in every version (the reference's desired
    form IS the default — the Finding 7 split needs the resolve-call
    context).
  - **D9 VERIFIED** — in-place float add eras: `fld [x]; fadd [y];
    fstp [x]` 5.0–10.0 (y-first 2.0/4.1/5.0), SSE `movsd; addsd;
    movsd` in 11.0.
  - **C27 extended** — lea+disp chain: 6.0–10.0 fold the displacement
    into the lea (`8d 44 40 24`), 2.0/4.1/5.0/11.0 keep the disp in
    the load.
  - `corpus-matrix.json` index 432 → **447 functions**; idiom sweep
    validates (`wze`/`wze2` guild 2× — the MSVC6 word zero-extend is
    real in the wild, `wze3` 5-6×, `wcmp` 2×+server.dll 1×,
    `fadd_ip2` 1-4×; exact `sz_disp`/`wand`/`bmask3` negatives
    recorded).  Docs: RULES.md (+8 rows), DECOMP_IDIOMS.md (+7 idioms),
    17 per-toolchain files, README.  See the round-21 spec
    `.cache/goal_probe24.md`.
- **Codegen corpus round 20 — guild Findings 23-36 (probe23)** —
  `docs/codegen/corpus.json` grows 11182 → **11897 records** (probe23
  adds 715: 10 MSVC versions × /O2+/O1, 7 SPs, bcc32/Watcom/GCC/Zig,
  and the 16-bit set).  The ten probe-able shapes from the guild doc's
  new Findings 23-36 were compiled through every toolchain and added to
  `docs/codegen/RULES.md`:
  - **C27 VERIFIED** — index-form lea family: `p[i*7]` → `lea reg,[reg*8];
    sub` (×8−1) everywhere **except 7.0/7.1 (`imul reg,reg,7`)**, a new
    7.x fingerprint; `p[i*24]` → `lea*3`+`shl` (6.0–9.0), `add`+×8-SIB
    (10.0/11.0); /O1 `imul` byte-offset (2.0/8.0/11.0).
  - **C28 VERIFIED** — division magic constants: signed `/60` =
    `0x88888889`+`sar 5`, unsigned `/24` = `0xaaaaaaab`+`shr 4`; real
    `idiv` in 2.0/4.1 and at /O1 everywhere.
  - **E15/E16/E17 VERIFIED** — SIB index-addressing from 7.0 (`cmp word
    [base+idx*2],0`; 2.0–6.0 pointer induction); dead arg-slot reuse is
    a **5.0/6.0 era marker** (`lea eax,[esp+8]`, no frame); base+offset
    folding from 5.0 (2.0/4.1 materialize the `add`).
  - **F19 VERIFIED** — branchless if-conversion of constant returns
    (`dec al;neg al;sbb eax,eax;and al,0xfc` in 5.0/6.0; 7.0+ `sete`+lea;
    11.0 `cmov`); **the `r=8; if (x==1) r=0xc; return r;` lever preserves
    the branch in 2.0–10.0** — the steering recipe.
  - **F21/F22 VERIFIED** — byte-compare temp lever (direct → memory
    operand compare from 8.0, named temp → register compare); FPU clamp
    compare forms (`fcomp` 5.0–7.1 / `fcomip` 8.0–10.0 / SSE `comisd`
    11.0).
  - **Verified-negatives** — zero-push hoist (every version `push 0`),
    the FPU re-compare fold (folded everywhere), the separate
    lea-then-load (SIB folded everywhere), the simple-shape SIB
    counter-as-base role, and the do-while rotation of the simple scan
    shape — all recorded with reasons (F27/F30/F35/F29/F23 contexts).
  - `corpus-matrix.json` index 411 → **432 functions**; idiom sweep
    validates the new signatures (`argslot` guild 1-3×, `idx7` 9-21×,
    `udiv24` magic 5-7× + server.dll 2×, `scan_rot` 29-53×; exact
    `ifconv1`/`div60`/`bytecmp`/`addfold`/`sib_scan`/`fpu_clamp`
    negatives recorded).  Docs: RULES.md (+9 rows), DECOMP_IDIOMS.md
    (+6 idioms), 17 per-toolchain files, README.  See the round-20 spec
    `.cache/goal_probe23.md`.
- **Codegen corpus round 19 — guild-rule verification (probe22)** —
  `docs/codegen/corpus.json` grows 10073 → **11182 records** (probe22
  adds 885: 10 MSVC versions × /O2+/O1, 7 SPs, bcc32/Watcom/GCC/Zig,
  and the 16-bit set now folded — `tc31`/`watcom16`/`msvc152` records
  for probes 17–22 were previously dropped by the classifier and are
  retroactively recovered).  The eight probe-able guild-rebrew
  allocator rules were compiled through every toolchain and promoted in
  `docs/codegen/RULES.md`:
  - **C24 VERIFIED** — `(x != c) ? -1 : 0` fuses to
    `sub al,N; neg al; sbb eax,eax; and; add` byte-exact in **5.0/6.0/
    8.0**; `-(x != c)` emits `cmp; setne; neg` (7B larger) — the doc's
    lever confirmed.
  - **F15 VERIFIED** — `*player |= 0x3000` → `or ch,0x30` (5.0/6.0);
    the `*player` flag shape emits `test ah,0x60` + `or ah,0x8` in
    5.0/6.0; 8.0+ switch to dword/memory forms; MinGW GCC emits the
    same AH-slot family (`or ah,0x30`).
  - **F17 VERIFIED** — byte-LIVE switch → and-mask preamble
    (`mov al,[eax]; and eax,0xff; add eax,-3; cmp eax,0x66; ja; jmp`)
    in 5.0/6.0; byte-DEAD → the 4B `xor; mov reg_low` form; 7.0+
    `movzx`-based.
  - **C23/C25 partial** — the C23 liveness forms (param and-form,
    dead xor-form, live and-form, equal-arm fold lever) verified per
    version (2.0/4.1 always mask, 5.0/6.0 the split, 7.0+ movzx);
    C25's signed/unsigned split (`jge` vs `jae`) verified in every
    version, the hoisted `or reg,0xff` materialization is **VC 5.0-only**.
  - **F12/F13/E11 verified-negatives** — the named-vs-direct register
    role lever and the array-index scalarization do not fire on the
    simplified shapes (full guild contexts required); the opaque-dest
    memset alignment prelude does not reproduce in ANY version (simple
    `rep stosd`+tail 2.0–7.1, libcall 8.0+).
  - **New E14** — constant-36B memset style: `rep stosd` 2.0–6.0,
    unrolled dword stores 7.0–10.0 (+GS cookie 10.0), SSE `movq` 11.0;
    **J1 addition** — VC 7.0 SP1 emits `rep stosd` where RTM unrolls
    (only probe22 SP delta).  `corpus-matrix.json` index 386 → **411
    functions**; idiom sweep validates the new signatures against the
    win2k/guild binaries (`ah_hi` guild 1×, `clear_fresh` server.dll
    5×, `uc_add` and-form guild 29–53×; fused-`negidm2`/`test ah,0x60`
    byte-exact negatives recorded).  Docs: RULES.md (8 rows promoted),
    DECOMP_IDIOMS.md (+5 guild-rule idioms), 17 per-toolchain files,
    README.  See `docs/codegen/` and the round-19 spec
    `.cache/goal_probe22.md`.
- **Toolchain containers run with `--network=none`** — every docker `run`
  of a toolchain image (compile runner, CMake cl/link/lib bridge, wineboot
  init, `toolchain smoke`, linked-compare link, import-symbol grep) now
  blocks egress: compilation is strictly local (source in, object out) and
  a toolchain image has no reason to touch the network during a build.
### Fixed
- **`rebrew data --own`/`--fix-ownership` materialized wrong float
  globals** — `_scalar_literal` (`data_layout.py`) routed the Windows
  typedefs `FLOAT`/`DOUBLE` to the integer-literal branch, so e.g. the 4
  bytes of `123.0f` were emitted as `FLOAT g = 0x42f60000;`, which C
  implicitly converts to `1123483648.0` (silently corrupting the stored
  value).  Float/double detection is now case-insensitive and emits a
  decimal literal that round-trips to the exact original bits.
  Non-finite bytes (NaN/Inf) previously rendered as `nanf`/`inff`
  (invalid C89, breaking the generated TU); they now return no literal,
  so `--own` reports the symbol as skipped instead of writing a
  definition that cannot compile, and array materialization raises a
  clear `ValueError` instead of silently zeroing the element.

## [0.5.0] - 2026-08-23
### Added
- **`// SOURCE: naked` honest-status split** (ct-recomp's NAKED_REQUIRED vs
  PURE_C_EXACT distinction, generalized) — `rebrew asm --inline-c` skeletons
  now carry a `// SOURCE: naked` marker, and `rebrew status`/`rebrew todo`
  treat naked reconstructions as **byte-covered but not decompiled**:
  - `rebrew status` reports `decompiled_pct` (matched minus naked) and a
    `naked_matched`/`naked_bytes` bucket ("N naked reconstructions, XB
    byte-exact but not decompiled — implement the C bodies"); JSON gains
    `decompiled_pct` + `naked_matched`.
  - `rebrew todo` keeps naked-marked matched functions actionable as
    `naked-reconstruction` items ("implement the real C body") instead of
    silently counting them as finished work.
  - `naming.load_data` surfaces the file-level `source` field; lint W019 and
    status's migration scan exempt the file-borne `// SOURCE: naked` marker
    (same convention as the `// CFLAGS: /DREBREW_ALLOW_NAKED` naked-guard).
- **`rebrew asm --format nasm --all --inline-c`** — batch naked-skeleton
  generation for the whole binary (`--batch-stubs` restricts to unmatched
  functions): every function gets a compileable, iterable fenced skeleton in
  `output/naked/`, giving the whole-binary byte-coverage baseline.
- **`rebrew test --linked`** — the linker-resolved single-function oracle
  (dll-rebuild's "padded link shell"): compile the function inside a
  `#pragma data_seg(".text$A")` pad + `#pragma code_seg(".text$B")` shell so
  its code lands at the exact .text offset it occupies in the target, LINK a
  real DLL at the target's image base (`/DLL /NOENTRY /OPT:NOREF /OPT:NOICF`,
  LINK.EXE runs inside the toolchain image via the shared wrapper), and
  compare the bytes RAW — no relocation masking.  rel32 displacements are
  linker-resolved and in-.text jump tables land in the window, so a match is
  byte-identical output, not RELOC-level.  Requires a VA and a docker MSVC
  toolchain; sources with externals (imports, cross-TU calls) fail the link
  by design (`compile_and_compare_linked` in `rebrew.compile`).
- **`rebrew asm --format nasm --inline-c` now emits an exact-bytes naked C
  skeleton** — the intermediate for functions without a C implementation.
  The target bytes are emitted verbatim (`__asm _emit 0xNN` on MSVC,
  `__asm__(".byte ...")` on GCC — raw bytes, so no assembler-encoding risk
  and no MASM syntax dependency) behind the `REBREW_ALLOW_NAKED` fence with
  a plain-C fallback, plus `// FUNCTION`/`// SIZE`/symbol so the file is
  self-contained for `rebrew test func.c --cflags /DREBREW_ALLOW_NAKED` —
  compileable and iterable one function at a time through the normal
  compile→compare loop; `rebrew round-trip --allow-naked` splices the naked
  branch.  (Previously the inline-C output used NASM mnemonics, which MSVC's
  inline assembler rejects — `dword [x]` vs `dword ptr [x]` — and whose
  encodings were unverified.)
- **`#pragma auto_inline` GA mutations** (`mut_add_auto_inline_pragma` /
  `mut_remove_auto_inline_pragma`) — `auto_inline(off)` stops MSVC from
  inlining helper stubs defined in the same TU into the target function, the
  classic DllMain/entry-point lever; the pragma stays with the function body
  across preamble/body splits like the other function-level pragmas.
- **near-diag `encoding` delta class** — same instruction, same registers,
  different opcode bytes (e.g. `mov reg,reg` as `89 /r` vs `8b /r`) is now
  classified as its own category with an ENCODING-ONLY verdict ("byte-identity
  needs the original compiler version, or `rebrew prove`"), instead of being
  mislabeled as register-allocation churn.  Encoding deltas riding along with
  register churn stay under the EFFECTIVE verdict.
- **`.data` placement tooling** (`rebrew.data_layout` + `rebrew data
  --layout-audit` / `--fill-data`) — the per-TU span/order audit and the
  `_dpad_` pad emission (byte-exact raw region + BSS sizing), generalized
  from the project's audit_layout/fill_data scripts with the geometry read
  from the layout metadata; verify-placement now shares the same model.
- **`rebrew data --annotate`** — insert `// GLOBAL:` markers from the data
  metadata into the sources (generalized from the project's
  annotate_globals.py; `--dry-run` previews, skips already-marked decls).
- **FLIRT sigs moved to a sibling checkout** (`rebrew-flirt-sigs`, like
  rebrew-toolchains; `REBREW_FLIRT_SIGS_DIR` overrides) — `rebrew flirt`
  merges the project's `flirt_sigs/` (project-specific, wins on conflicts)
  with the checkout's standard library sigs; the project no longer vendors
  the .pat/.sig files.
- **Byte-identity link tools** — `rebrew order-sources` (order sources by
  first-function VA for a position-aligned .text), `rebrew calibrate-bss`
  (empirically size a BSS tail pad so the raw link's .data VirtualSize
  matches the reference), `rebrew gen-link-stubs` (BSS placeholder TU from
  the data metadata), `rebrew verify-placement` (post-edit .data symbol VA
  check), and `rebrew gen-layout --data-gap <raw-size>` (emit
  `crt_region/data_restore.c` with the reference's raw .data tail).  All
  generalized from the server.dll project's scripts; `gen-layout` now
  resolves the import `@N` suffixes from the toolchain image's own Lib dir
  when no host MSVC tree exists.
- **Whole-binary build tooling folded in from project scripts** — six
  workflows that lived as ad-hoc project scripts are now rebrew commands:
  - `rebrew gen-stubs` — a stub TU for the linker's unresolved external
    symbols (LNK2001/2019): parses a build/log/stdin, derives types from the
    sources' `extern` decls, filters CRT library symbols (functions CSV),
    with `--specials <toml>`/`--footer <file>` for project policy (forwarding
    stubs, BSS arrays, tail pad, `_fltused`-style markers) and
    `--exclude-file`/`--cmake-stub-var` build integration.
  - `rebrew data --own` — materialize stub-file globals as real definitions
    in their owner TUs with the reference's original bytes (scalars and
    NUL-terminated/gap-sized arrays); `--fix-ownership` re-partitions global
    definitions across TUs to fix layout-audit SPAN/ORDER violations;
    `--converge` is the fixed-point `.data` placement loop
    (`_dlead_<tu>[N]` leading pads, re-measure per round).  All reuse the
    `data_layout` model (link order, ownership, pad emission) with PE-derived
    geometry instead of per-project hardcoded offsets.
  - `rebrew inline-strings` — materialize `s_<hint>_<0xADDR>` string-literal
    globals: rewrite C-level uses to literals (comments/`__asm` masked) and
    define the remaining asm-referenced strings in their owning TU.
  - `rebrew merge --consolidate` — hoist unique includes/externs/typedefs/
    `#pragma intrinsic` to the top of a merged multi-function TU, resolving
    conflicting extern signatures by specificity.
- **CMake toolchain bridge** (`rebrew.cmake_tc` + `rebrew cmake-toolchain`) —
  the `rebrew-cmake-{cl,link,lib}` console scripts run a docker toolchain
  image's tools (CL.EXE/LINK.EXE/LIB.EXE via wine inside the image) from any
  project's CMake build, with the same guarantees as the compile pipeline
  (same-path-mounted project root, shared flock-initialized wineprefix,
  self-contained INCLUDE/LIB).  `rebrew cmake-toolchain --toolchain msvc6`
  writes the CMake toolchain file; `ToolchainSpec` gained `tool_root`
  (container dir holding the tools).
- **Metadata store tiers documented (ADR-012 + `docs/METADATA.md`)** — the
  full store map (canonical vs derived vs cache, who owns which fact,
  precedence rules) now has a written contract.  Replaces the implicit
  "why are there so many files?" with one reference page.  A second sweep
  added the layout/PE-header family: `layout/<target>/` (text-only
  `layout.txt` + `*.hex` package), `[targets.<t>.layout]` / `[link]`
  config blocks, `<target>.def`, `crt_region/*.c`, `src/link_stubs.c`,
  `flirt_sigs/*.pat`, `.rebrew/ghidra_sync_state.json`, and the
  VCS-intended vs gitignored build-output split.  A third sweep (after the
  data-placement tooling landed) added `src/<target>/bss_padding.c`
  (`rebrew data --fix-bss`), `src/<target>/rebrew_globals.h`
  (`rebrew data --gen-header`), the `--fill-data` `_dpad_<addr>[N]` pads,
  and the rebrew-flirt-sigs sibling checkout as a read-only input source.
- **Shared metadata loader + write lock** (`rebrew.utils.load_metadata_doc`,
  `metadata_write_lock`) — `rebrew-function.toml`, `rebrew-data.toml`, and
  the library store now load through one tomllib-based, mtime-cached loader
  and serialize writes through one thread + flock mechanism (the data store
  previously had no write lock and used a different parser).
- **`TOOLCHAIN` is now a declared metadata field** (`METADATA_FIELDS` +
  canonical order) — it was live in the code but missing from the routing
  table, so writes bypassed the field gate.  Empty-module metadata writes
  now raise instead of silently writing a `0xVA` key the loader drops.
- **BinSync import writes STATUS via `update_source_status`** — created
  stubs carry only the marker line; STATUS/SIZE/NOTE land in
  `rebrew-function.toml` instead of deprecated inline `// STATUS:` forms
  (lint W019 no longer flags fresh BinSync stubs).
- **Dead/duplicate parsing removed** — `catalog.loaders.load_all_sources_parallel`
  (dead and broken), a second rizin `afl` parser (discover/intake now share
  `parse_rizin_afl`), `round_trip._list_names` (uses `cached_function_list`),
  and verify's double functions.txt parse (single `cached_function_list` call).
- **Doc drift fixes** — `docs/DB_FORMAT.md` `db_version` 4→5 and the
  JSON keying (hex VA, not name); lint code ranges in `docs/CLI.md` /
  `docs/ANNOTATIONS.md` (E000–E023 / W001–W028).
- **Text-only layout package** (`rebrew.layout_meta`, `gen-layout`,
  `postlink`) — the post-link fixers now reconstruct the reference from a
  committed text package (`layout/<target>/`: structured `layout.txt` +
  hex dumps of the opaque linker-stamped regions + sparse `.text` operand/
  call maps) instead of a binary snapshot (`layout/<target>.zip` with raw
  section blobs).  Zero binary bytes at rest; the original DLL is not needed
  at build time.  `gen-layout` emits the package + the extended
  `[targets.<t>.layout]` toml (image base, section raw pointers, reference
  IAT-slot VAs per import, export stamp); `postlink --layout` consumes it.

### Fixed
- **Single HTTP client** — `rebrew toolchain check-updates` used
  `urllib.request` (API call + release download) while every other network
  path in the package uses httpx; both spots now go through httpx (with
  `raise_for_status()` preserving urlopen's raise-on-non-2xx behavior).
  One TLS/proxy code path instead of two (deps-review).
- **Machine-independent `similarity` extra** — the optional `resembl`
  dependency was pinned to an absolute `file:///home/...` URL, breaking
  resolution on any other checkout.  It now declares a plain name resolved
  via `[tool.uv.sources]` (`path = "../resembl"`, relative to this
  pyproject.toml), matching the sibling-checkout convention used by
  rebrew-toolchains/rebrew-flirt-sigs; re-locking resolves byte-identically
  on this machine (deps-review).
- **`rebrew lint` W019 / `rebrew status` inline-metadata mismatch** — the
  two tools disagreed (status warned "N file(s) contain inline
  STATUS/CFLAGS/SIZE comments" while lint reported clean, so the hint was a
  dead end).  Two fixes: lint's header parser no longer treats a bare
  name-hint comment line (``// FuncName``) after a marker as "code", so
  following ``// SIZE:``/``// CFLAGS:``/``// BLOCKER:`` keys attach to the
  block and W019/``--fix`` can finally see them; and status now counts
  exactly what ``rebrew lint --fix`` migrates — inline keys in marker
  blocks not already backed by the metadata store — instead of any inline
  key anywhere.  Markerless ``// CFLAGS: /DREBREW_ALLOW_NAKED`` naked-guard
  markers (documented in E023) and metadata-backed stale duplicates no
  longer nag.  status count now equals lint's W019 count.
- **`rebrew doctor` / `rebrew lint` boundary** — the annotation-staleness
  check moved from `rebrew doctor` to `rebrew lint` (W028): doctor is
  environment health only, corpus-content checks belong to lint.  The
  Delphi 1.0 toolchain row no longer appears on 32-bit targets where it
  structurally cannot apply (16-bit-only checks now show only for x86_16).
- **`rebrew lint` W022 exemption for `.data` globals** — a file-scope zero
  initializer (`= 0` / `= {0}`) whose global is annotated
  `section = ".data"` (with a `name`) in `rebrew-data.toml` no longer warns:
  the original binary stored that zero-init data in `.data`, so dropping the
  initializer would shrink the rebuilt section and break byte identity.
  Unknown names and `.bss`-annotated globals still warn.
- **`rebrew lint` W028 mtime-aware fix message** — stale FUNCTION/STUB
  markers no longer always prescribe "re-run `rebrew intake`" on the
  assumption that the binary changed.  The check (moved from `rebrew
  doctor`; see the boundary entry above) compares the target binary's mtime
  against the function list's: a newer binary gets the
  intake/discover-refresh advice, while a list that is as new as the binary
  gets "the binary did not change — re-annotate the markers / regenerate the
  list if it came from a different binary (e.g. a rebuilt artifact)".
  Indeterminate mtimes (missing file) fall back to a cause-neutral message.

### Added
- **Interactive `rebrew init` onboarding wizard** — bare `rebrew init` on a
  TTY now walks through picking the binary (auto-scans `original/`, then the
  cwd root, for `*.exe`/`*.dll`/`*.sys`/`*.bin`/`*.com`, with a manual-entry
  option), the compiler profile (toolchain detection on the chosen binary
  suggests one, visibly flagged when it differs from the default; unknown
  answers get one reprompt then fall back), the target name (defaults to the
  binary stem), and a summary/confirm step that writes nothing when
  declined.  Afterwards the chosen profile's docker image state is reported
  (missing image → exact `rebrew toolchain build <profile>` hint plus an
  optional immediate build), and the next-steps block points at
  `rebrew doctor` + `rebrew intake`.  Automation is untouched: `--no-wizard`,
  `--json`, non-TTY stdin, and direct Python calls all keep the previous
  flow byte-identical, explicit CLI flags suppress their prompts
  (click parameter-source based), and a fully flagged run prompts zero
  times.  New `--wizard/--no-wizard` flag.  Covered by
  `tests/test_init_wizard.py` (gating, end-to-end prompt drives, abort,
  fully-flagged zero-prompt runs, mocked image build).
- **Ecosystem documentation** — new `docs/ECOSYSTEM.md` maps how rebrew fits
  with the sibling repos (rebrew-toolchains, resembl, recoverage, recompile,
  reagent, relumea, decompedia, recondb) via mermaid diagrams, dependency
  layering, and the workspace layout; linked from `ARCHITECTURE.md` and the
  docs index.
- **wine is the default runtime for docker toolchains** — the images already
  ran wine (`REBREW_RUNNER` defaults to wine), but rebrew steered users
  toward wibo (faster, but fails on some tools).  Now: `rebrew doctor
  --install-wibo` downloads wibo but leaves a docker-backed project's
  `runner` config untouched (the image runs wine; the config runner is
  obsolete for it), and `rebrew doctor`'s Runner check reports a present
  wibo binary as an informational note instead of recommending the switch.
  Documented in ONBOARDING.md + TOOLCHAIN.md.
- **Onboarding overhaul** — a fresh `rebrew init` → `rebrew intake` journey
  now ends with a zero-fail `rebrew doctor` (toolchain-independent checks)
  and actionable terminal messages:
  - `rebrew doctor`'s `Include path`/`Lib path` checks are docker-aware: a
    docker-backed profile gets its includes/libs from the image (built from
    the vendored toolchain), so a fresh intake's dangling host path is no
    longer a spurious fail — it reports the image and suggests
    `rebrew toolchain build <profile>` when it is missing.  Native profiles
    (gcc-pe) still require real host paths.
  - `rebrew intake`'s toolchain line for docker-backed profiles says the
    image is the toolchain (with the build command) instead of
    "symlink tools/ yourself".
  - `rebrew init`'s "Next steps" and `rebrew intake`'s summary point at the
    new **docs/ONBOARDING.md** first-run walkthrough (also linked from
    CLI.md's workflow intro): prerequisites, the 5-minute path, and a table
    of every first-run error with its fix.
  - New `tests/test_onboarding.py` runs the real intake journey on the
    `mini_pe.exe` fixture (rizin stubbed for determinism) and pins the
    contract: populated `functions.txt`, documented skeletons with valid
    markers, doctor clean on all toolchain-independent checks, idempotent
    re-run, and the ONBOARDING.md links.
- **`rebrew cross-import`** — import functions already matched in another
  target of the same project (binary versions with the same code at
  different VAs, or a DLL+EXE pair sharing code).  Structural matching from
  target bytes (no compile needed; source side = the other target's
  EXACT/RELOC/PROVEN functions), `--min-score`/`--min-gap` thresholding
  (default 95: identical code scores 100, structural siblings with a shared
  prologue score high 80s–low 90s), then compile + verify against the
  destination before STATUS promotion — a wrong match fails verification
  and stays untouched.  `--dry-run`/`--json`/`--va`/`--limit`.  See
  ADR-009.
- **Shared multi-version sources** — `[project] shared_dir` (default
  `src/shared`, empty disables): a project-level source root scanned for
  every target, so one `.c` serves multiple binaries.  Shared files can
  carry one `// FUNCTION: <target> <va>` marker per target (the same
  function at a different VA per version) with per-target STATUS in
  `rebrew-function.toml`, and `[targets.<name>] defines` add per-target
  compile-time defines (`/DV2`/`-DV2`) for `#ifdef` version deltas —
  the isledecomp/LEGO Island multi-version model.  A defines edit
  invalidates the target's verify cache.  See ADR-010.
- **Codegen fingerprint catalog for toolchain detection** — a new
  per-compiler-version reference in `docs/codegen/` (one file per
  compiler major version — MSVC 1.x/2.0/4.x/5.0/6.0/7.0/7.1/8.0/9.0/10.0/
  11.0, MinGW GCC, Open Watcom, Turbo C, Borland C++ 5.5, Delphi, Zig)
  documenting minute byte-level codegen patterns, cross-version deltas
  and verified "100% unique" markers, plus new detectors in
  `toolchain_detect.py`: VC 7.0+ `lea esp,[esp]` loop-alignment nops,
  rep movs/stos string-op inlining, magic-number division, SSE2 vs x87
  FPU, GCC `rep ret`, stack-probe symbol names (`__chkstk`,
  `___chkstk_ms`, `__aNchkstk`, `__CHK`, security cookie), frame-pointer
  prologue counting, and a 16-bit MZ entry-code disassembly scan.  All
  patterns verified by compiling one probe source through the MSVC 2.0–
  11.0 (incl. 4.0/4.2), MSVC 1.52, Turbo C 2.0/3.1, Borland C++ 5.5,
  Open Watcom 2.0 and MinGW GCC 16.1 toolchains.  `docs/CODEGEN_REFERENCE.md`
  is now a pointer into `docs/codegen/`.
- **Probe-verified unique codegen markers per toolchain** — five probe
  sources (division tables, copies, 64-bit, long double, rotates,
  cmov/SSE2, switches, FP constants/conversions, multiply chains,
  memcmp, struct returns, tail calls, sqrt/fdiv, bit idioms,
  `__fastcall`) compiled through every toolchain + two Pascal probes
  through Delphi 1.0's `DCC.EXE`, first-time probes of MSVC 1.0/1.5
  and Watcom 16-bit `wcc`, and the **first-ever service-pack codegen
  sweep**.  Highlights: the only verified SP-level codegen difference
  (VC 7.0 SP1's FP-equality `fucompp` → `fcomp [mem]`; 7.1/8.0/10.0
  SP1 and VC 6.0 SP1–SP6 verified identical); MSVC tail calls and
  `strcmp` tail-`jmp` from VC 7.0; `fsqrt` inlined in VC 2.0–7.1 vs
  `jmp __CIsqrt` from 8.0; reciprocal-`fmul` vs real `fdiv` for `a/5`
  (8.0+); `cvttsd2si` and SSE `movq`/`xorps` in VC 11; per-toolchain
  64-bit helper names and FP-conversion idioms (`__ftol`/`__CHP`/
  `fnstcw` dance); TC 2.0 vs 3.1 far/near long-mul helpers; Delphi
  `case` compare-chains and `rol`-based set membership; **SEH prologue
  ladder** (`push -1` 2.0–7.1 vs `push -2` 8.0+, `fs:[0]`-first in
  2.0/4.x); inline 64-bit multiply-high from VC 6.0; **FP-loop x87
  accumulation** (`fldz` init from 8.0, ×4 unrolling from 7.0,
  memory-accumulator in 2.0/4.x); indirect tail-calls from VC 7.0;
  volatile reads verified identical across all versions; **combined
  divmod from VC 7.0** (one `div` for `x/N + x%N`); the stack-probe
  threshold verified uniform at 4096 across all versions; 64-bit
  compares direct-memory from VC 7.0; `/O2` verified to already imply
  `/Oi`; a **corpus-validation sweep of all 51 marker byte-sequences**
  against the VC5/VC6/MinGW binaries (strong hits for `f3 a6`, `d9
  fa`, `dc 0d`, `0f 1f`, `0f a5 c2`, `83 e4 f8`; context-dependence
  notes for common instructions; two downgrade notes from VC6 hits);
  and the **expanded VC 7.0 SP1 finding — EIGHTEEN differing
  functions** (FP-equality structural, FP-libcall marshalling, FP
  loops + char-array + stack-probe functions in register
  allocation/layout, plus probe14's `_s64_ret` stack-offset shift —
  the 18th function surfaced by the mechanical corpus sweep).  Full
  table in `docs/codegen/README.md`.
- **Probe11 flag matrix** — `/G6` never enables `cmov` in VC 6.0
  (min/max/clamp stay branches; `/G5` vs `/G6` differ only in
  scheduling); VC 7.0 `/G5`≡`/G6` and 7.1 `/G5`≡`/G7`;
  `/arch:SSE2` on VC 8.0–10.0 produces the SSE `movq`/`pxor`/
  `comisd` forms (the VC 11.0-default markers now carry the flag
  caveat); `/fp:fast` ≡ default on the probe2 FP set; Delphi probe
  #3 (set/record copy via `rep movsw`).
- **Probe12 inlining + 16-bit switch** — static-helper inlining is an
  era marker: VC 7.0+ inlines small static helpers called once/twice/
  in a loop at /O2 and /O1 (11–12B callers) while VC 2.0–6.0 keep the
  call (30–34B) at both levels; VC 7.0/7.1/8.0/10.0 SP1s are identical
  to their RTMs on this feature.  New 16-bit discriminator: MSVC 1.52
  dispatches 8-case switches via `add ax,ax; xchg bx,ax` (`03 c0 93`)
  + `dw` table where TC 2.0/3.1 and Watcom 16-bit use `shl bx,1`
  scaling (`d1 e3`).  Probe3 leftovers analyzed: Delphi `pchar_len`
  walks a PChar via `les di` + `cmp byte ptr es:[di],0` with an
  offset-only `inc word ptr [bp+4]` (no segment carry), and Delphi
  `longmul` delegates 32-bit multiply to the RTL with a single
  `lcall` (`@LDmul`, register-pair operands) instead of inlining.
  Watcom 16-bit division verified as real `div`/`idiv` with **no
  reciprocal-magic even for constant divisors** (mirrors 32-bit
  wcc386); bcc32 5.5 verified NOT to inline the probe12 static
  helpers at -O1 or -O2 (4 `call`s at both levels), same as MSVC
  2.0–6.0; GCC inlines them unconditionally (not a discriminator).
- **Probe13 string intrinsics + char/bitfield/struct-return map** —
  five new dimensions swept across every MSVC version at /O2 and /O1
  plus bcc32/Watcom/GCC and the 16-bit set.  **strlen intrinsic**:
  `repne scasb` (`f2 ae`) in VC 2.0–6.0 /O2, manual scan loop in
  7.0+ (bcc32/Watcom/GCC libcall strlen — the forms are MSVC-only).
  **memcmp(8B)**: `repe cmpsb` (`f3 a6`) in 2.0–7.1 /O2, dword-compare
  loop in 8.0+ (three distinct register allocations: 8.0 ESI-counter,
  9.0/10.0 decrement-pair, 11.0 2-dword + byte tail).  **char
  zero-extension**: `xor; mov al` in 2.0/4.x (shared with bcc32),
  `and eax,0xff` (`25 ff 00 00 00`) in 5.0/6.0 — unique — and
  `movzx` in 7.0+ (shared with GCC/Watcom); every version uses movzx
  at /O1.  **VC 8.0 `add eax,1` (`83 c0 01`) over `inc eax`** in
  strlen and `g_val+1` (family-level; GCC shares the encoding).
  **signed-char compare against the zero register in memory**
  (`33 c0 38 44 24 04 0f 9c c0`) from 8.0+.  **New Watcom markers**:
  default-unsigned `char` (`char < 0` folds to `xor eax,eax; ret` in
  wcc386 AND wcc16 — every other toolchain is signed) and 8-byte
  struct returns via a `movsd` pair (`a5 a5`).  Delphi 1.0
  packed-record fields load as individual bytes (`es:[di+N]` +
  `xor ah,ah`) and `Char < #0` stays a runtime compare (not folded,
  unlike Watcom).  SP spot-check: 7.0/7.1/8.0/10.0 SP1 and VC 6.0
  SP1–SP6 are all byte-identical to their RTMs on every probe13
  function, and VC 5.0 SP1–SP3 match the 5.0 RTM as well.  Zig 0.16
  re-verified: no zig-vs-gcc byte marker in the probe13 set.
- **Probe14 statement-level idioms + corpus validation + SP closure**
  — six statement dimensions swept across every MSVC version at /O2
  and /O1 plus bcc32/Watcom/GCC/Zig and the 16-bit set.  New unique
  markers: **64-byte memcpy = `rep movsd` (`b9 10 00 00 00 f3 a5`) in
  every MSVC version** (GCC register-blocks, bcc32/Watcom libcall,
  Zig `movups`-pairs); **bcc32's memory-form `inc dword ptr [g]`
  (`ff 05`)** (everyone else round-trips EAX); **MSVC 5.0/6.0 64-bit
  shifts = `mov ecx,N; jmp __allshl/__allshr` tail-call** (7.0+ inline
  `shld`/`shrd` — shared with GCC/bcc32/Zig; Watcom `__I8LS` takes
  the count in EBX); **2.0/4.x + 1.52 zero-compare `cmp [mem],1;
  sbb; neg`** (5.0–7.1 load+test, 8.0+ memory compare against the
  zero register).  Family-level: VC 8.0's `add eax,1`/`sub eax,1`
  (`83 c0 01`/`83 e8 01`) confirmed a THIRD time on `g_inc`/`g_dec`
  (GCC shares); VC 10.0/11.0 inline 64-bit ×const via `shld`
  decomposition (5.0–9.0 call `__allmul`); VC 11.0 `cmov` ternaries
  (Zig/LLVM shares — downgraded); 11.0 keeps the EAX round-trip at
  /O1 where 4.1–10.0 use `ff 05` memory-inc.  **Corpus validation**
  (rebrew-projects win2k + skifree16/32 binaries): `f2 ae` strlen
  marker hits in 13 binaries, `f3 a6` in 12, `25 ff 00 00 00` in 6
  — the round-11 markers are real in the wild; `83 c0 01` correctly
  absent (VC8-only trait); no Watcom-built corpus binary for the
  unsigned-char fold (stands on the probe).  **SP closure**: VC 6.0
  SP2/SP4/SP5, VC 7.0/7.1/8.0/10.0 SP1 and VC 5.0 SP1–SP3 at /O1 all
  byte-identical to their RTMs on probe14; the VC 9.0 SP1 comparison
  remains blocked — see the Probe15 entry below.
- **Probe15 function boundaries + corpus round 3** — six
  function-boundary dimensions swept across every
  MSVC version at /O2 and /O1 plus bcc32/Watcom/GCC/Zig and the
  16-bit set.  New unique marker: **the `/GS` cookie-mix prologue
  (`a1 <cookie> 33 c4 89 44 24 40` — mov eax,[cookie]; xor eax,esp;
  store) in VC 8.0+** — the only probed toolchain with stack cookies
  (GCC/Zig/bcc32/Watcom emit none).  Family-level maps: signed setcc
  eras (2.0/4.x branch+`mov eax,1`; 5.0–7.1 register compare;
  8.0+ memory compare — shared with GCC/Zig); **wide-literal folding
  from 7.0** (`L"AB"[0]+L"AB"[1]` → `mov eax,0x83`; 2.0–6.0/bcc32/
  Watcom/TC load from memory; shared with GCC/Zig); address-form
  census (5.0 lea-scale, 6.0–9.0 `shl`+scale-1, 10.0/11.0
  `add reg,reg`+scale-8); stdcall reverse-arg-order in 5.0–9.0
  (2.0/4.1 + 11.0 direct; Zig also reverses); **VC 8.0's add-over-inc
  confirmed a FIFTH time** (`w_ge`, `/GS` copy loop); bcc32's
  setcc+`and eax,1` tail.  **CORRECTION — the "VC 9.0 SP1 unblock"
  is retracted**: a staged `sched.dll` from the XP SP1 SDK cross-tools
  made the SP1 cl.exe run, but the objects it emits are **IA64
  machine-type** (COFF 0x200, IA64 bundles — surfaced by the corpus
  generator, whose SP1 objects parse to zero x86 symbols).  The
  earlier "byte-identical to the 9.0 RTM on 54 functions" comparison
  was against empty parses and is withdrawn.  The 9.0 SP1 `/O1`/`/O2`
  comparison remains BLOCKED until a genuine VS2008-SP1 x86
  `sched.dll` is available; the verified SP record is: 5.0 SP1–SP3,
  6.0 SP1–SP6, 7.1 SP1, 8.0 SP1 and 10.0 SP1 identical to their
  RTMs on probes 13–15, 9.0 SP1 unverified, and VC 7.0 SP1's known
  17 functions differing (18 with probe14's `_s64_ret` — see the
  corpus entry below).  **Corpus round 3** (rebrew-projects + guild): the
  cmp-1 zero-compare marker correctly absent from VC5/6 binaries;
  `ff 05` present in VC5/6/guild (context-dependent — the bcc32 claim
  now carries the caveat); the exact constant-size 64B `rep movsd`
  form absent (real memcpys use variable sizes); no VC8+ corpus
  binary exists to hit the `/GS` marker (stands on the probe).
- **Probe16 64-bit division + C++ mode + 16-bit depth** — the last
  two never-probed dimensions, swept across MSVC 5.0–11.0 at /O2 and
  /O1 plus bcc32/GCC/Zig (C and C++).  **64-bit division**: 5.0–10.0
  call the helper with a register-load + 4-push staging (`8b 44 24
  10 … 51 52 50 e8`; uniform across `__alldiv`/`__aulldiv`/
  `__allrem`/`__aullrem`); **VC 11.0 is the only version using the
  4× memory-push form (`ff 74 24 10` ×4) at /O2** — the
  push-from-memory trait in its third dimension (every version uses
  the memory-push at /O1).  GCC stages `__divdi3` args on a stack
  frame; bcc32 uses `__lldiv`/`__llmod`; Watcom `__I8D`.  **C++
  mode**: `new`/`delete` are call+ret in 5.0/6.0 and **tail-jumps
  from 7.0**; VC 11.0 adds the **checked array-size multiply** for
  `new int[n]` (`mov edx,4; mul edx; seto cl; neg ecx; or ecx,eax`);
  vtable dispatch is uniform `mov eax,[ecx]; call [eax]` (GCC adds a
  null-vtable check; bcc32 pushes register-loaded args; Watcom's
  wpp386 rejected the probe — recorded).  **16-bit depth**: MSVC
  1.0/1.5/1.52 byte-identical on the probe13 set; TC 2.0 verified
  against 3.1 — `mul dx` vs `imul dx` for char*7, memory-held vs
  register-held loop pointers, and a TC 2.0 preprocessor quirk (no
  `defined()` in `#if` — probe14/15 uncompileable on TC 2.0).
  probe16 SP spot-check: 7.0/7.1/8.0/10.0 SP1 all byte-identical to
  their RTMs (9.0 SP1 remains blocked — see the Probe15 correction
  above).  Corpus round 4 (probe15
  markers): the `/GS` cookie stays absent (no VC8+ corpus binary —
  stands on the probe); the MSVC wide-compare `66 3b 4c 24` hits
  guild (5× per binary, confirming guild is MSVC-family) and several
  win2k binaries; the exact 8.0+ setcc memory-compare form is
  correctly absent from the VC5/6 corpus (era boundary validated).
- **The massive codegen pattern corpus** — `docs/codegen/corpus.json`
  now holds **8315 machine-readable records** (grew from 7892 with probe17) (one per toolchain,
  version, SP, flags, probe, function, with size + bytes), generated
  from every probe 1-16 object via `.cache/fp_probe/
  gen_codegen_corpus.py` and schema-validated by
  `validate_corpus.py` (JSON parses, all fields present, coverage
  spot-checked — CORPUS VALID).  The mechanical sweep
  (`sweep_corpus.py`) confirmed every hand-documented per-toolchain
  marker and surfaced no new cross-toolchain-unique ones; its **SP
  equivalence check compared 1957 SP rows against their RTMs — 1939
  identical, 18 mismatches, ALL VC 7.0 SP1**, including **probe14's
  `_s64_ret` (64-byte struct return, stack-offset shift) — the 18th
  SP1-differing function, missed by the hand-analysis and now
  documented (msvc-7.md, the "17 functions" count corrected to 18
  everywhere).  The corpus also exposed that the staged-sched.dll VC
  9.0 SP1 objects are **IA64 machine-type** — the round-14/15 "9.0
  SP1 byte-identical" claim is retracted (see msvc-9.md); the 9.0
  SP1 comparison remains blocked.  Corpus pointer added to all 17
  per-toolchain files; README gained a corpus section with query
  examples.
- **Probe17 conventions + allocator behaviors + fingerprint layer** —
  the documented rules from RULES.md verified by compilation.  **A2
  corrected**: 16-bit Watcom `__fastcall` = `ax,dx,bx` (3 register
  args, 4th on the stack) — Agner Fog table 5's "ax,dx,bx,cx (4
  regs)" claim is NOT reproduced by Open Watcom 2.0 (may be
  commercial-10.x-specific); TC 2.0/3.1 and 16-bit MSVC 1.5x lack
  `__fastcall` entirely.  **A5 verified in every version**: varargs
  float→double via `fld; sub esp,8; fstp qword [esp]` (`dd 1c 24`)
  for 2.0–10.0, SSE `movss; cvtss2sd; movsd` in 11.0, `fld; sub
  sp,8; fstp qword` in watcom16.  **A8 verified**: Watcom16 struct
  returns use PSI (`lea si,[bp-6]` + `movsw`, ptr in SI), TC 3.1
  passes the far stack pointer (I); 32-bit 2.0–6.0 stack-passed, 7.0+
  inlined sret, 11.0 SSE `movq`.  **B5 `-1`-store 3-era split**:
  2.0/4.x immediate `c7 05 ... ff ff ff ff`; 5.0–10.0 register `or
  eax,-1` (`83 c8 ff`) + `a3`; 11.0 immediate + dead `or eax,-1`.
  **B7**: address-taken params push ESI only in 5.0–8.0 but FOUR
  callee-saves (ebx/ebp/esi/edi) in 9.0/10.0.  B3's live-range flip
  does NOT trigger with the simplified probe in any version (the
  guild doc's fuller dispatch shape is required — recorded
  negative); B4's `dl`/`bl` form needs `char` flags (partial).
  **Behavioral fingerprint layer**: `corpus-behavior.json` now carries
  per-record register/zeroing/moffs/push signals; the fingerprint
  sweep found **`a3`/`a1` moffs usage doubles from VC 8.0** (15–16
  hits in 2.0–7.1 vs 24–25 in 8.0–11.0).  Corpus grew to **8315
  records** (CORPUS VALID).  **MSC 5.1 + Watcom 10.5a downloaded**
  from decomp.me releases and unpacked (CL.EXE/wcc.exe present);
  MSC 5.1's CL runs under the image's DOSBox but produced no object
  in the staged compile — recorded as a documented partial blocker
  pending a dedicated image; the fastcall/struct-return conventions
  were verified with the existing Open Watcom 2.0 instead.  RULES.md
  A2/A5/A8/B2-B7/B11 updated with the verified matrix; all 17
  per-toolchain files gained probe17 records.
- **Probe19/20 decomp-project idioms + the DECOMP_IDIOMS cheat-sheet**
  — 30 game/engine idiom shapes (PRNG/LCGs, fixed-point mul/div/lerp,
  trig tables, sign/clamp/bounds, hex classifier, djb2 hash, atoi,
  string walks, linked-list/ring/pool walks, command dispatch, va_list)
  compiled through every MSVC version + SPs + all other toolchains and
  folded into the corpus (**9670 records, CORPUS VALID**).  New
  per-version idiom fingerprints: **LCG multipliers = `imul imm32`
  from VC 7.0, shl/add decomposition in 2.0-6.0**; **`%360` magic
  arrives at 8.0** (2.0-7.1 real `idiv`); **djb2 *33 = `imul eax,eax,
  0x21` in 7.0/7.1 only**; **the sign idiom switches setl→sets
  (`0f 98`) at 10.0**; **the hex classifier moves to lea-adjusted
  range checks at 8.0+**; **the dense small-int switch
  (`83 f8 N; ja; ff 24 85`) is uniform across ALL versions**;
  **VC 8.0's add-over-inc confirmed 3 more times** (ring_next,
  skip_ws, str_cat — 7 total).  **`docs/codegen/DECOMP_IDIOMS.md`**
  is the decomp-facing cheat-sheet: each idiom's C shape, per-version
  signature bytes, and disassembly look-for.  **Corpus validation**
  (26 binaries): `array2d`, `lerp`, `bit_pack`, `ll_walk`,
  `in_bounds`, `dist_sq`, `cmd_dispatch`, `sign`, `skip_ws` appear in
  the wild (guild 33-49× for the 2D-index and lerp shapes); the LCG/
  fixed-point/atoi signatures are absent from these binaries
  (recorded negatives).  RULES.md gained idiom rows C19-C22, F11-F12,
  E9; all 17 per-toolchain files point at the cheat-sheet.
- **Probe21 decomp idioms + version-matrix index + toolchain retries**
  — batch 3 (round-half-up, 4x4 transforms, AABB checks, centering,
  8/16-case dispatch, function-pointer tables, distance compares,
  byte-swap/endian fixups, array-update loops, tolower chars)
  compiled through every toolchain and folded into the corpus
  (**10073 records, CORPUS VALID**).  New era markers: the
  **lea-adjusted range check is an 8.0+ trait** (hex_nibble +
  ci_char); **`sar reg,1` = `c1 f8 01` (3B) in 2.0/4.x vs `d1 f8`
  (2B) from 5.0**; **function-pointer dispatch `ff 14 8a` (5.0-7.1)
  vs load+`call eax` (8.0+)**; **bswap16's three eras** (byte-moves →
  movzx → shift/mask); **VC 11.0 unrolls array-update loops ×4**;
  **VC 8.0's add/sub-over-inc confirmed an 8th time** (update_objs
  loop decrement); 8/16-case jump tables uniform across all versions.
  **`corpus-matrix.json`** — the precomputed per-function version
  byte-group index (386 functions) — makes matrix/diff/unique O(1).
  **Toolchain retries (one focused pass each)**: MSC 5.1's CL.EXE
  runs under the image's DOSBox but produces no object/error output
  for any compile (bundled HELLO.OBJ was a false positive; line
  endings, single-shot, and ERROUT routing ruled out) — documented
  blocker; Watcom 10.5a's `binnt/wcc.exe` is a PE32 launcher
  requiring a `binw/wcc.exe` the package lacks — documented blocker
  (compiler absent).  TC 2.0 compiled probe18 (guard-free); probes
  17/19/20 fail on the documented `defined()` preprocessor quirk.
- **Corpus coverage + usability** — the corpus now carries **Delphi 1.0
  records** (NE user-code segments from probe1/2/3/13, function
  boundaries inferred at ret/retf — 6 records, probe13 split into 3
  functions) and **raw-code records** for OMF dialects that resist
  symbol listing (4 `code_raw` records incl. the bcc32 C++ object;
  recovered watcom objects).  A **query CLI** (`corpus_query.py`:
  `info`, `matrix <func>`, `unique <ver>`, `diff <v1> <v2>`,
  `look <hex>`) makes the corpus directly queryable — `matrix
  lcg_next` prints the per-version byte groups, `diff 7.1 8.0` lists
  the 141 functions that changed, `look ff 24 85` finds the 50
  jump-table records.  The matrix query **caught and corrected a
  DECOMP_IDIOMS.md error**: the LCG imul-vs-decompose split is
  **69069-specific** (2.0-6.0 decompose it; ×1103515245 and ×1664525
  are uniform `imul` in every version).  Corpus at **9670 records**,
  CORPUS VALID.
- **GA pragma mutations** — five new operators in `matcher/mutator.py`
  (114 → 119) that explore codegen levers compiler flags cannot reach:
  `mut_add/remove_optimize_pragma` wrap the function in
  `#pragma optimize("X", on|off)` … `("", on)` (X ∈ `""`/`"y"`/`"g"`/`"s"`/
  `"t"` — `("", off)` forces the classic unoptimized full-stack-frame
  layout), `mut_add/remove_intrinsic_pragma` toggle `#pragma intrinsic` for
  the string/memory CRT functions (memcpy → rep movs etc. under /Oi), and
  `mut_toggle_check_stack_pragma` suppresses /Gs stack probes.  Function-
  level pragmas now stay with the function body across preamble/body
  splits so removals are complete.  Researched in
  `docs/GA_MUTATIONS.md` §20 (MSVC 6.0 semantics + the deliberately
  not-mutated set: pack, auto_inline, code_seg, function).
- **Fenced naked reconstruction for round-trip verification** — sources
  generated from raw asm (`rebrew asm`) and thiscall stubs on compilers
  without a native `__thiscall` (MSVC 5.0) now emit their
  `__declspec(naked)` + inline-asm body behind `#ifdef REBREW_ALLOW_NAKED`
  (`__attribute__((naked))` for gcc/clang), with an idiomatic-C `#else`
  fallback so the comparison build always compiles.  New `rebrew round-trip
  --allow-naked` is the only switch that defines the macro (MSVC `/D` or
  posix `-D` per toolchain), so the naked branch reproduces exact bytes for
  byte-identity verification while `test`/`verify`/`match` never see it;
  naked remains a non-mutation (round-trip-only capability, never a GA
  operator).
- **Stale-annotation audit in `rebrew doctor`** — new `Annotation staleness`
  check cross-references every `// FUNCTION:`/`// STUB:` marker against the
  target's current `functions.txt` (the list `rebrew intake`/`discover`
  write).  A marker whose VA no longer has a function there ("dangling",
  function removed), or that now points *inside* another function's span
  ("moved/merged"), is reported with file:line, a sample list, and the
  fix (re-run `rebrew intake`, then re-annotate).  `LIBRARY` markers are
  excluded (they may legitimately point at import stubs the function-list
  parser filters out) and so are `DATA`/`GLOBAL` (not code); a missing or
  empty function list skips the check.  Warn-level: a changed binary is a
  workflow state, not a broken environment.
### Added
- **DecBench/Kuna adoption** — three new capabilities researched from
  Noelo-Lab's [decbench](https://github.com/Noelo-Lab/decbench) and
  [kuna](https://github.com/Noelo-Lab/kuna):
  - **`rebrew fix`** — compilability fixup for raw decompiler output
    (DecBench's fairness principle): token sanitization (Ghidra/IDA
    pseudo-types like `undefined4`, qualified symbols like
    `GLIBC_2.2.5::stderr`) plus diagnostic-driven injection of missing
    typedefs/prototypes, never redefining what the source declared.  Lets
    rebrew byte-match decompiler output, not just hand-written C.
  - **CFG structural similarity** (`rebrew.cfg_ged`) — a DecBench-GED-inspired
    control-flow score over capstone basic-block graphs (greedy block
    matching + edge Jaccard), surfaced as the `cfg` field in
    `rebrew near-diag --json`.
  - **Kuna backend + seeding** — `rebrew decompiler` gained a `kuna` backend
    (the agent-first Ghidra-port decompiler); `rebrew match --kuna-seed`
    decompiles the target function with Kuna, fixup's it, and injects it
    into the GA's initial population (with `--dry-run` preview).
  - **Symptom index** — `rebrew near-diag --catalog` prints the generated
    delta-category → suggestion → GA-mutations index (Kuna's options.md
    pattern), also committed as `docs/NEAR_DIAG_CATALOG.md`.
  - **Struct recovery surfaces unnamed-pointer evidence** — `rebrew
    recover-structs` no longer drops pointer accesses when the decompiler
    fails to type them (Kuna's `int a0` / `short *a0` params, Ghidra's
    `undefined4 *this`).  Cast-derefs capture the variable, offsets accept
    hex or decimal, and Kuna's array-index form (`*(int *)&a0[10]` → byte
    offset = index × element width) is parsed; the evidence is grouped by
    variable name into **anonymous candidates** with a synthesized layout
    (`--apply` never writes them — they need a user-chosen name first).
    Meaningful var names (`pPlayer`) get a type name with the Hungarian
    prefix stripped; compiler temps (`v1`, `local_8`) are dropped; offsets
    ≥ the target's image base (absolute addresses folded into
    `var + 0xADDR`) are filtered.  Verified against guild-rebrew's
    command handlers: 68 functions decompiled → one `a0` candidate shared
    by 48 functions with a consistent 0x3…0x3F layout.
  - **`rebrew decompile --named`** — the "feed the recovered structs back
    in" loop (`rebrew.name_decomp`): a naming pass over decompiler output
    that types anonymous pointer variables with the project's declared
    structs (from sources + `library_*.h`).  Rewrites the signature
    (`int a1` → `command_s *a1`), cast-derefs (`*(int *)(a1 + 0x10)` →
    `a1->field_10`), Kuna array-index forms (`&a0[10]` → `a0->field_14`),
    bare address arithmetic (`sub(a0 + 0x10)` → `sub(&a0->field_10)`), and
    `vN = aN;` aliases.  Matching is conservative (≥1 exact non-padding
    field hit, all offsets within span; misaligned reads into `gap_*`
    padding left alone; named cast types untouched; image-base addresses
    never rewritten).  Verified on guild's real kuna output for
    `sub_1000d350`: `command_s *a1` with every member access rewritten.


- **Hot-path optimizations (profile-driven)** — the GA scoring loop is
  **3.6x faster**: `_normalize_and_mnems_x86_32` now uses a non-detail
  disassembly with raw-byte reloc zeroing (legacy prefixes skipped; the
  rare SIB/disp32 fallback re-disassembles just that instruction), and
  `_zero_reloc_fields` skips sub-5-byte instructions.  Metadata reads use
  tomllib instead of tomlkit (**~23x** on `load_metadata`); `near-diag`
  classification is **~4.7x** faster via module-level imports + cached
  capstone handles.  Behavior is byte-identical, pinned by a parity
  regression test.  `tools/bench_hotpaths.py` reproduces the numbers
  (`--compare` shows the speedups vs recorded baselines).
- **Hot-path pass 2 (project-scale)** — the benchmark now covers
  whole-tree parsing, per-function diffing, registry/status aggregation and
  cache paths (`tools/bench_hotpaths.py --compare`).  Whole-tree annotation
  parse + metadata merge is **~1.8x faster** (metadata loaded once per file
  instead of per function), the incremental verify cache-hit check **~1.4x**,
  and `diff_functions`/`structural_similarity` **~1.3x** (a `summary_only`
  fast path with in-pass mnemonic collection, non-detail no-reloc
  normalization, and an in-place register mask).  The register-aware diff's
  remaining cost is the register mask's ModR/M detail dependency — a safe
  ceiling, documented.  Test suite now 57s wall.
- **Test-suite wall time 149s -> ~59s** — `tools/validate_skill_commands.py`
  runs its `--help` probes in parallel (16s -> 3.2s) with a session-cached
  validator test; `tools/check_idempotency.py` runs its read-only command
  pairs in parallel (19.5s -> 4.3s).  The remaining floor is docker
  compiles (out of scope).
- **`rebrew verify` EXTRACT_ERROR now names stale annotations** — when
  byte extraction fails and the annotation VA is not a function in the
  current function list, the error says so ("stale annotation? re-run
  `rebrew intake` or edit the marker VA") instead of a bare "Cannot
  extract DLL bytes" that blames binary tooling.
- **`rebrew verify --nolib`** — exclude LIBRARY-marked functions from
  verification entirely (not compiled, not counted, `summary.library_excluded`
  reports how many), the reccmp `--nolib` equivalent: the summary + CI gate
  reflect game code only, so statically-linked CRT / vendored zlib sources
  no longer drag the SERVER gate.  Fenced naked functions that fail to
  byte-match now get an explanatory note instead of a bare mismatch — the
  comparison build compiles the `#else` fallback, so byte-identity needs a
  `REBREW_ALLOW_NAKED` build (`round-trip --allow-naked`, or
  `-DREBREW_ALLOW_NAKED=1` for the reccmp recomp binary).
- **`rebrew round-trip --allow-naked` reports `fenced_naked`** — the JSON
  report lists the exact functions that require the define for byte-identity
  (`count` + `vas`), the checklist for a reccmp build matrix (a recomp
  binary built without the define shows those functions at ~0%).
- **`EFFECTIVE` verdict in `rebrew near-diag`** — reccmp's 100% effective
  match: when the ENTIRE byte delta is register allocation (same
  instructions, different registers), the verdict names it (not
  byte-identical — `rebrew prove` for PROVEN, or register-nudging C tweaks
  for byte-identity) and lists the register-oriented GA mutations.  A
  register-dominant verdict with real structural churn stays `REGISTER`.
- **`rebrew verify` reports effective matches** — the per-function diff now
  classifies register-encoding differences separately (`register_aware`
  x86-32), and a NEAR_MATCHING whose entire delta is register allocation
  gets an "effective match" note in its message (reccmp-parity naming) so
  the cause is visible instead of a bare byte diff.
- **`rebrew verify-exports`** — new tool (reccmp `verexp` equivalent):
  compare the export *names* of the project target vs a recompiled binary;
  reports missing/added, exits `EXIT_MISMATCH` when the sets differ.
- **`rebrew stack-cmp`** — new tool (reccmp `stackcmp` adapted, no PDB
  needed): compiles the function and compares its stack frame against the
  target — frame size (ESP tracking), ebp-vs-esp (`/Oy` frame-pointer
  omission), `ret N` popping (calling convention), and `[ebp±N]` slot
  layout — with flag-focused hints.  A frame delta is the per-function
  CFLAGS signal for tuning static-CRT / vendored-zlib LIBRARY functions.
  `rebrew near-diag --json` now carries the same comparison as a `frame`
  field on every classified pair.
- **recoverage integration** — `verify_results` rows now carry `reg_delta`
  (register-encoding-only diff count) and `effective_match` (true when the
  entire delta is register allocation — reccmp's 100% effective-match
  class), surfaced through the `rebrew verify` JSON report and the
  `db/coverage.db` `verify_results` table (`rebrew build-db`, schema
  version 4 → 5).  `diff_lines` semantics clarified: it counts *structural*
  diffs only since the register-aware diff (`RR` class) was wired into
  `rebrew verify`.  `tests/test_recoverage_contract.py` pins the two new
  columns.
- **`rebrew binary-similarity`** — new tool: whole-binary structural
  similarity vs another binary (the per-binary analog of the per-function
  diff metrics).  Best-matches every function of the current target against
  another binary's function list via the shared structural signature
  (mnemonic-histogram cosine + call/branch agreement, vectorised N×M), then
  aggregates into a byte-weighted `overall` similarity, mean/median,
  threshold buckets with byte shares, and the lowest-scoring functions —
  the version deltas.  `--other-list` (functions.txt format) or
  `--other-target` for a configured target.
- **GA works without docker (native toolchains)** — `base_cflags` now
  defaults per compiler profile: posix profiles (gcc-pe/mingw, watcom,
  tc16/20, borland) get `""` instead of the MSVC `/nologo /c /MT` glue
  that broke every compile for hand-written tomls, and the matcher's raw
  subprocess path no longer emits a bare `-I`/`/I` for empty include
  dirs.  The GA's per-run build cache key now covers per-target `defines`.
  `rebrew match --flag-sweep-only` / `--all --flag-sweep` refuse loudly on
  posix profiles (the sweep explores MSVC flag combos; previously every
  combo failed silently under gcc and only the empty-combo "matched").
### Changed
- **Lint default line length 100 → 200** — `rebrew lint`'s
  `lint_max_line_length` default was too aggressive for generated/decompiled
  C; projects can still override via `[project.lint] max_line_length`.
### Fixed
- **`cross-import` no longer clobbers unrelated destination files** —
  importing to a filename that already annotates a different VA is refused
  (`TARGET_CONFLICT`) instead of silently deleting that function's source;
  the destination's own annotation file (same VA) is still overwritten.
  Imported copies of shared multi-version sources now carry only the
  destination's marker (stacked markers from other targets are collapsed),
  and the stacked-marker name fallback no longer misnames bodyless
  LIBRARY/STUB blocks.
- **`iter_sources` no longer leaks shared sources into scans of unrelated
  directories** (shared files belong to the target's `reversed_dir` scan
  only), and `_parse_defines` rejects non-string entries (no more garbage
  `-DNone` flags).
- **Agent docs drift** — `.agents/skills/` re-rendered from the canonical
  `src/rebrew/agent-skills/` (it had fallen behind on the watcom16/tc16/
  borlandc55 sweep tiers, the vendored `source/` toolchain paths, and the
  `src/<target>` placeholders), guarded by a new `tests/test_skills_sync.py`.
  Root `AGENTS.md` tree updated for the modules it was missing
  (`postlink.py`, `struct_recover.py`, `ne_loader.py`, `headless.py`,
  `tc16.py`, `lzexe*.py`, `cross_import.py`, `document_unmatched.py`,
  `binsync_diff.py`/`binsync_import.py`, `library.py`), the duplicated
  `decompiler.py` entry collapsed, and `matcher/AGENTS.md`'s mutation count
  fixed (119).  `rebrew init`'s generated-domain wording now says docker,
  not host Wine, for MSVC toolchains; the `rebrew init --help` profile list
  and README's compiler-profiles paragraph were also rewritten for the
  docker-only registry ("via Wine (or wibo)" is gone everywhere; remaining
  Wine mentions are either the wine-in-image runtime or roadmap documents).
  API-attribution fixes in `AGENTS.md` and `verify.py`'s docstring:
  `verify_entry` lives in `rebrew.verify` (not `rebrew.compile`), and
  `rebrew verify` promotes STATUS via `update_statuses_batch`, not
  `update_source_status` (that is `rebrew test`'s writer).
- **Compile sandboxes no longer leak into `~`** — `rebrew toolchain smoke`
  and `rebrew toolchain update` created a `writable_temp_dir` sandbox per
  run and never removed it, so `~/rebrew_smoke_*/` accumulated (with the
  pinned `t.c` inside).  Both now clean up in `finally`; `compile.py`'s
  cleanup retries across the docker mount-unmount race (a busy mountpoint
  previously left an empty `~/rebrew_cmp_*/` shell), and
  `writable_temp_dir` now creates home sandboxes under
  `~/.cache/rebrew/tmp` instead of directly in the home directory so even
  hard-killed runs never clutter `~` again.

## [0.4.0] - 2026-08-21
- **`rebrew recover-structs`** — recover struct definitions from
  decompiler output: aggregate member-access offsets (`->field_N`,
  `*(T *)(p + 0xN)`) per named pointer type, synthesize `typedef struct
  ..._s { ... } name;` definitions with gap padding, merge against the
  project's existing structs, and `--apply` the new ones.  Backend-pluggable
  (kuna/r2ghidra/r2dec/ghidra) — the "recover more structs" workflow for
  guild-style projects once a decompiler backend is installed.
- **`rebrew decompiler` tool probe now finds `rizin`** — the upstream binary
  name was invisible to the r2ghidra/r2dec backends.

### Changed
- **Docs/housekeeping release — no user-facing code changes.**  The audit
  work below is recorded with per-item references in the dated
  `docs/GOAL_PROGRESS.md` entries (2026-08-21).
- **Gap-inventory re-audit**: all 35 gaps in `docs/prd/00-source-gap-report.md`
  and the GOAL_PROGRESS open list verified fixed against current code; a
  fresh per-module review sweep (all 44 CLI commands `--help`, JSON error
  paths, error patterns, idempotency contract, adversarially probed
  `canonicalize_cflags`) found no new defects.
- **Stale docs corrected**: `docs/IDEAS.md` — shipped ideas #23 (LLM seed),
  #24 (ghidra-cli backend), #25 (prove memory watch) moved from "Open
  Ideas" to Completed; JSON-purity contract 16 → 17 commands.
  `matcher/AGENTS.md` + `docs/GA_MUTATIONS.md` — mutation operator count
  121 → 114.  `AGENTS.md` — test count ~3460 → ~4620.
- **Format normalization**: 8 files reflowed by `ruff format` (mechanical;
  no behavior change).
### Fixed
- **Stale "Open Ideas" in `docs/IDEAS.md`** — three shipped features were
  still listed as open, which misled readers hunting for work items.

- **Compile-cache key v5: per-source header dependencies instead of
  whole-directory fingerprints** (`compile_cache.py`).  The key now resolves
  each translation unit's transitive `#include` closure against the source
  dir + `/I` dirs and fingerprints each *reached* header individually, so
  editing a header invalidates exactly the entries that reach it — an edit
  to an unrelated header in the same include dir is now a cache hit.  CRTs
  inside the immutable toolchain image are untracked (pinned by the image
  digest in the key); non-literal `#include MACRO` / `/FI` force-includes
  fall back to conservative directory fingerprints.  The verify cache
  applies the same per-source dependency fingerprint per entry, replacing
  the global `headers_hash` gate that re-verified the whole project on any
  header change.
- **Flag canonicalization in the cache key** (observational equivalence):
  `canonicalize_cflags()` reduces a flag list to its compilation-equivalent
  canonical form using the synced decomp.me flag definitions — identical
  flags are deduped, last-wins option groups collapse to their final value
  (`/O1 /O2` ≡ `/O2`), and flags across distinct options commute
  (`/O2 /Gd` ≡ `/Gd /O2`).  Order-sensitive input (`/I` search order, `/D`
  redefinitions, unknown flags) keeps its order, so genuinely different
  compilations still get distinct keys.
- **`rebrew toolchain` image swap is transactional** (backup→swap→rollback):
  `build` and `pull` run through `swap_toolchain_image()`, which records the
  current image id, verifies the tag resolves after the operation, and
  re-tags the previous image on failure — a failed build/pull never leaves a
  half-registered toolchain.  `toolchain update --apply` restores the
  previous source pin if the re-vendor/rebuild fails, so the pin never stays
  ahead of the image.
- **Verify cache classifies resolved-config changes** (per-entry
  `(toolchain, cflags)`): entries now store the resolved toolchain override
  (previously only cflags, so a `rebrew-library.toml` `TOOLCHAIN` edit
  served stale results), and the cflags comparison uses the canonicalized
  equivalence class — an order-only flag change is a hit, a material change
  invalidates exactly the affected functions.
### Added
- **`MutationLog` / `mutate_chain` in `matcher/mutator.py`**: revertible-
  effect tracking for GA mutations (Cordis-paper §3.1) — every applied
  mutation records its inverse, `undo_all()` restores the original source
  byte-identically LIFO, each inverse fires at most once, and `mutate_chain`
  supports a step-boundary guard.
- **`tests/test_property_library.py`**: order-independence properties of the
  library-config merge (preset merge is a fixed point, TOML field-order
  permutations resolve identically, nearest-ancestor-wins is independent of
  file creation order, and interleaved reconfiguration converges to the same
  resolution).
### Fixed
- **Toolchain docker build source moved to the standalone
  `rebrew-toolchains` repo** (github.com/maci0/rebrew-toolchains): rebrew no
  longer vendors Dockerfiles, wrappers, the shared `base` image, or the
  16-bit media tarballs in-repo.  `rebrew toolchain build`/`vendor`/`update`
  and the 16-bit host paths (`rebrew.tc16`/`msvc16`/`delphi16`) now resolve
  the build source via `rebrew.toolchain._toolchains_repo()` — the sibling
  `../rebrew-toolchains` checkout by default, overridable via
  `REBREW_TOOLCHAINS_DIR` (a missing checkout is an actionable error
  pointing at `git clone https://github.com/maci0/rebrew-toolchains
  ../rebrew-toolchains`).  `_SOURCES` `in_repo` tarball paths are now
  relative to that checkout; the legacy `tools/<name>` toolchain symlinks
  and their `ensure_compat_links` recreator were removed.
### Added
- **Code similarity score in `rebrew verify`** ("Sim %"): each verified
  function now carries a 0–100 structural similarity score between its
  compiled bytes and the target, computed via the sibling `resembl`
  project's dependency-light scoring core (`resembl.scoring` — importable
  without its sqlmodel/sqlalchemy DB stack).  Robust to register allocation
  and immediate-value differences that byte-match is blind to.  Optional:
  install the new `[similarity]` extra (`uv pip install -e .[similarity]`);
  without it the column stays `None`.  Surfaced in the `--summary` table,
  the failure-detail lines, the JSON report, cached results, and persisted to
  `coverage.db`'s `verify_results.similarity` so the `recoverage` dashboard
  can display it.
### Fixed
- **`rebrew rename` rejected the documented source-path forms**: entries
  store filepath relative to `reversed_dir` while `require_config` resolves
  `reversed_dir` absolute, so only the basename/VA/symbol matched.  All four
  forms now resolve (project-relative, reversed-dir-relative, absolute, VA).
- **`error_exit` defaulted to exit 1 (`EXIT_MISMATCH`) instead of 2
  (`EXIT_ERROR`)**: every generic error (missing binary, bad VA, missing
  state dir, config errors) reported as a "mismatch", so a CI script could
  read a broken environment as an unmatched function.  The default is now
  `EXIT_ERROR`; mismatch exits stay explicit (`code=1`).
- **`rebrew match --sweep-toolchain` ran the raw subprocess path with an
  empty `cl_cmd`** (docker-native configs) — it tried to exec the flags as a
  command and ignored the swept profile.  It now routes through each
  profile's docker image (`toolchain=profile`) and enumerates the registry
  profiles; new `--sweep-only` / `--sweep-exclude` filters narrow the sweep
  (e.g. `--sweep-exclude 2.0,4.0` for a Y2K binary).

- **VC 6.0 SP1/SP2/SP4 toolchains** (`msvc600sp1`, `msvc600sp2`,
  `msvc600sp4`): SP1/SP2 share the byte-identical 12.00.8168 driver with
  `msvc6` (SP1-3 changed no compiler/headers); SP4 carries the 12.00.8804
  driver (verified byte-identical to the official SP4 CD).  Sources
  published to **`archaic-toolchains`** (`msvc600_sp1` — a documented
  reconstruction, since the standalone SP1 payload is not preserved
  publicly; `msvc600_sp2` — RTM + the full official SP2 payload from the
  MSDN Disc 18; `msvc600_sp4` — SP4 headers/libs + the decomp.me `msvc6.4`
  Bin).  Smoke-gated (SP1/SP2 golden == msvc6's; SP4 distinct).
- **VC 2008 SP1 toolchain** (`msvc900sp1`, cl.exe 15.00.30729.01): closes
  the "VC 2008 SP1 compiler has no public tarball" gap via
  `archaic-toolchains/msvc900_sp1` (msvc900 base + the SP1 compiler from
  the official VS2008 SP1 DVD patch).  `rebrew toolchain detect` now
  maps Rich-header build 30729 to it.
- **VC 11.0 / VS 2012 toolchain** (`msvc1100`, cl.exe 17.00.50522.1) from
  `archaic-msvc/msvc1100`; detection maps linker 11.0 / build 50522 to it.
- `rebrew toolchain detect` / init / doctor profile sets updated for all of
  the above (config `_KNOWN_PROFILES`, `utils._MSVC_LAYOUTS`, init presets,
  `_PROFILE_COMPAT`, `_RICH_BUILD_PROFILES`, `_LINKER_ERA_PROFILES`).

### Fixed
- **docker-only compile broke project-relative includes** (C1083 on
  `#include "../../Units/..."` — the flat /work source copy + /incN
  mounts lost the original tree).  `compile_to_obj` now same-path
  bind-mounts the project root and every absolute include dir at its
  host path (`-v <dir>:<dir>`), so relative includes resolve exactly as
  under the old host-wine Z: mapping.

### Fixed
- **`rebrew diff` / GA flag-sweep on relative-include functions**
  (COMPILE_ERROR C1083): `build_candidate_obj_only` dropped
  `extra_include_dirs` on the docker path — the temp source copy lost the
  original source's parent, so `#include ../..` could not resolve.
  `compile_to_obj` now accepts `extra_include_dirs` and same-path mounts
  them into the container (verified: guild-rebrew ServerMainThread diffs).

### Changed
- **`rebrew init` writes docker-native configs**: image-backed profiles
  (all MSVC/Borland/Watcom/16-bit) now get an empty `compiler.command` /
  `runner` — the docker image is the compiler, and the stale
  `command = "wine toolchain/..."` line confused doctor/verify.  The
  config loader accepts an empty command for image-backed profiles
  (native profiles like gcc-pe still require one) and
  `resolve_cl_command` returns [] instead of a phantom CL.EXE path.

### Fixed
- **Compile cache served stale objects after `rebrew toolchain update`**:
  the cache keyed on the image tag, but `update --apply` rebuilds the
  image under the same tag.  The key now includes the image content id
  (docker image inspect, cached per process), so a re-pinned/rebuild
  invalidates cached objects.
- **`rebrew toolchain smoke` / `update` used /tmp/rebrew-smoke**: the
  system temp dir can be docker-invisible (sandboxed environments), so
  the smoke gate failed there.  Both now use the real-disk
  writable_temp_dir fallback; smoke passes under sandboxed homes.

### Added
- **Per-version toolchain detection** (`rebrew toolchain detect`): the
  detector now pins the exact MSVC version from PE metadata — the Rich
  header (compiler front/back-end build) + optional-header linker version
  -> e.g. 12.00.9782 = msvc600sp6 (the VC 6.0 SP builds are distinct C1
  builds: 8168 RTM / 8447 SP3 / 8966 SP5 / 9782 SP6; VC 2.0-4.2 have no
  Rich header and are named by the linker version 2.50/3.0/3.10/4.20),
  with the msvcpX.dll import as a secondary binder.  `suggested_profiles`
  picks the version-exact rebrew profile (init --guess-compiler / intake
  / doctor now suggest e.g. msvc600sp6 instead of msvc6 for an SP6
  binary), and `profile_matches_detection` flags a configured profile that
  is a different compiler build before the first compile.  Fixed a
  pre-existing `_is_16bit_target` bug that classified every PE as 16-bit.

### Added
- **Per-library toolchain/flags overrides** (`rebrew-library.toml` at a
  library root, managed by `rebrew library set/show/rm`): the right
  abstraction for "some parts of the codebase were built with other
  flags" — a source subtree declares its compiler (`toolchain`) and
  flags (`cflags`) once, and every function under it compiles with that
  docker image + flags (resolve_compile_overrides: per-function metadata
  > per-library walk-up > project default).  Known-library presets fill
  missing fields from what rebrew knows the shipped runtimes were built
  with (`msvcrt-static` = MSVC static CRT /MT /O2 /Gd, `msvcrt-dynamic`
  /MD, `msvc16-runtime`, `borland-runtime`, `watcom-runtime`).  Wired
  into verify / test / match / prove so a library compiles consistently
  everywhere.

### Changed
- **Docker-only toolchain execution** (ADR-008): the host never calls
  CL.EXE / DCC.EXE / TCC.EXE / bcc32.exe directly anymore — every
  Windows/DOS toolchain (all 20 MSVC 1.0-10.0 profiles, Borland, Watcom,
  the 16-bit DOS compilers) compiles ONLY through its docker image, with
  the runtime (wine / DOSBox) encapsulated in the image.  The vendored
  trees remain as the byte-identical build source for the images but are
  never exec'd; `run_toolchain`, `compile_to_obj`, the GA/flag-sweep path
  and doctor all route through the image and error clearly when it is
  missing (`rebrew toolchain build <name>`).  Host wine/wibo/Xvfb glue
  (`vendored_msvc_env`, `vendored_compiler_command`) is removed;
  native-Linux compilers (gcc-pe, watcom16 wcc) still exec directly.
  `compile_to_obj` same-path bind-mounts project include dirs into the
  container (at their absolute host paths) so /I flags and relative
  `#include "../.."` paths keep working.

### Added
- **Complete MSVC 1.0–10.0 toolchain matrix** (docs/TOOLCHAIN.md): 20 wine/
  DOSBox profiles — every version and every preserved service pack — each
  packaged as a sha256-pinned docker image `rebrew/msvc:<version>-<arch>`
  plus a vendored host tree, config/init/detect profile, tools/ compat link
  and a smoke-gate golden.  Sources pinned from **archaic-msvc** wherever the
  compiler exists (2.0, 4.1, 5.0+SP1-3, 6.0 base+SP5/SP6, 7.0 RTM+SP1, 7.1+
  SP1, 8.0+SP1, 9.0, 10.0+SP1 — re-pinned 6.0/6.0-SP6/legacy-7.0 from
  decomp.me to archaic-msvc, codegen-verified byte-identical); the 16-bit
  line comes from the original Microsoft media (archive.org `en_vc152` for
  1.5, the WinWorld 3.5" floppy set for 1.0 — both committed in-repo as
  tar.xz; the existing 1.52 stays).  Provenance + per-source checksums
  documented; official-release-only policy.
- **MSVC 6.0 SP5/SP6 mspdb60.dll relocation**: the archaic full-product
  trees stash the PDB server DLL under `Common/MSDev98/Bin` while CL
  12.00.8804 imports it in-dir — both the Dockerfiles and
  `rebrew toolchain vendor` relocate it, so /c compiles work.
- **VC 1.5 (msvc15) + VC 1.0 (msvc10) profiles**: 16-bit DOSBox compilers
  via the generalized `rebrew.msvc16` (version=1.5-win16 / 1.0-win16);
  both produce parseable 16-bit OMF (verified end-to-end; the 1.0 tree was
  assembled from the WinWorld 3.5" floppy set — SZDD payload, Phar Lap TNT
  driver).
- **Smoke-gate goldens** for all 19 new image-backed toolchains (28/29
  image toolchains verified byte-reproducible; tc20's mismatch is a
  pre-existing path-embedding artifact of non-smoke workdirs).
- **`--sweep-toolchain`** now enumerates the full vendored 2.0–10.0 line
  (was 4.0–7.0).
- `_vendored_binary` resolves nested product layouts (VC98/Bin, Vc7/bin,
  VC/bin) — the wrapped MSVC 6 master's host binary now resolves too.

### Added
- **Toolchain source sync** (`rebrew toolchain check-updates` /
  `rebrew toolchain update <name> [--apply]`): every GitHub-codeload pin
  (archaic-msvc, archaic-toolchains, itsmattkc) now records the branch commit
  it was pinned from; the checker compares the live commit sha via the GitHub
  API (no download) and reports upstream drift before a build fails.
  `update --apply` re-pins (sha256 + commit in `_SOURCES` and the
  Dockerfile), re-vendors the host tree, rebuilds the docker image and
  regenerates the smoke golden (verified stable across two compiles).  The
  Open Watcom `Last-CI-build` snapshot (a moving release tag) is
  re-downloaded + re-hashed; decomp.me/archive.org assets and in-repo
  tarballs are immutable.  First catch: watcom's snapshot had drifted and is
  re-pinned (99e494d9; codegen unchanged — golden stays 44a6354f).
  Nightly drift check added as `.github/workflows/toolchain-sync.yml`.

### Fixed
- **Rich-header build is the MODE, not the max**: a binary compiled with
  VC6 RTM but linked with a newer linker carried Rich entries
  [8168, 8168, 9782]; the max picked 9782 (msvc600sp6) instead of the
  C1/C2 pair's 8168 (msvc6).  `_rich_compiler_build` now takes the most
  common build across entries.
- **`/I ../Units` (space-separated) compiled the wrong dir**: shlex split
  it into `["/I", "../Units"]` and the bare `/I` alone was rewritten to
  `/I<src_parent>` while `../Units` became a stray positional.  The two
  tokens now merge and resolve as one include flag; a bare `/I` with no
  path (trailing or flag-adjacent) passes through untouched.
- **compile_to_obj distinguished unknown vs imageless toolchains** in the
  per-function TOOLCHAIN error; **`rebrew library set` fails fast on an
  unknown toolchain** (like --preset already did) instead of writing an
  override that only errors at compile time; **init template comments**
  updated to the docker-only reality (no stale wine command example /
  '--profile (future)' note); test_msvc6_resolves_available_toolchain now
  asserts the docker-native contract instead of matching the stale
  comment.

### Fixed
- **`rebrew diff` / GA / near-diag / prove / `test --multi` / round-trip
  compiled from a docker-invisible temp dir** under sandboxed homes: the
  bind-mounted `/work` silently lost the source and the image wrapper
  died with `no readable source file in: <flags>`.  All six docker
  compile sandboxes now use `writable_temp_dir` (workspace `.cache`
  fallback) with explicit cleanup — `rebrew diff` and the GA flag
  sweep work end-to-end again (verified on a real MSVC 6.0 PE).
- **`rebrew analyze` printed double `0x0x` VAs**: the strings /
  near-miss / library dossiers already format `va` as `0x…` strings
  and the terminal prints prepended another `0x`.
- **Per-version detection suggests the new VC6 SP1/SP2/SP4 profiles**:
  those service packs kept the RTM C1 build (8168) / SP4 shared 8966
  with SP5, so every profile carrying a build can byte-match; the
  version-exact tests now assert membership instead of exact tuples.

### Changed
- **Canonical `source/` layout for every vendored toolchain tree**: each
  `toolchain/<family>/<version>-<arch>/` folder now has the same shape —
  `Dockerfile` + wrappers/tarballs + the actual toolchain nested one level
  under `source/`.  Previously flat trees (VC6 sp3/sp6, VC7.0, 2.0/4.x/5.x,
  Borland, Watcom, Delphi) sat at the folder root while the master trees
  wrapped in `VC98/`/`Common7/Vc7/`/`Microsoft SDKs/VC/`.  `rebrew toolchain
  vendor` extracts into `source/`, `_vendored_binary`/`_vendored_include`
  and the 16-bit finders resolve it, the MSVC layout table + init defaults
  follow, and a per-tree `.dockerignore` keeps the extracted trees out of
  the docker build context (builds only need Dockerfile + wrappers).
- **Legacy `msvc6.3`/`msvc6.4`/`msvc6.5`/`msvc6.6` names removed**: no
  backward-compat aliases for old toolchain names — `rebrew init -c
  msvc6.3` now rejects with the real profile list, and the detection
  compat table only admits registry profiles.

### Changed
- **16-bit toolchain images download from the `archaic-toolchains`
  preservation repos**: the six 16-bit Dockerfiles (msvc1.52/1.5/1.0,
  tc16, tc20, delphi16) no longer COPY an in-repo tar.xz — each curls the
  pinned, sha256-verified codeload tarball of its matching
  archaic-toolchains repo (`msvc152`/`msvc15`/`msvc10`/`tc31`/`tc20`/
  `delphi10`) at build time, like the 32-bit images already did.  The
  extraction content is byte-identical to the old tarballs (verified:
  rebuilt msvc1.52/tc16/delphi16 pass the smoke gate; tc20's mismatch is
  the documented pre-existing golden artifact).  Build context no longer
  needs the tarballs (`.dockerignore` drops `*.tar.xz`).  The standalone
  [maci0/rebrew-toolchains](https://github.com/maci0/rebrew-toolchains)
  repo is synced and builds from scratch with only docker.
## [0.2.0] - 2026-08-18  comment.

## [0.2.0] - 2026-08-18
### Fixed
- **MZ code offset ignored the reloc-table position** (functionality-review
  HIGH): `parse_mz_header` computed `code_offset = cparhdr*16 + crlc*4`,
  but the MZ loader maps the file from `cparhdr*16` onward as the image —
  when the relocation table fits inside the header (the usual case, incl.
  the tc16 fixture and every LZEXE-unpacked file), the first `crlc*4`
  bytes of code were skipped and EVERY function VA shifted (the Keen 6
  demo's functions sat 0x2358 bytes off; the entry at VA 0 pointed 4 bytes
  into the startup).  `code_offset = max(cparhdr*16, lfarlc + crlc*4)`
  now.  Fixture VAs re-calibrated (`add` 0x28d → 0x291, `main` 0x29a →
  0x29e); the Keen demo re-discovers **690 functions** (was 572 — the
  previously-skipped code region is now addressed, and VA 0 is the real
  entry).
- **`match --all` stub collector used a hardcoded 0x1000 VA floor**
  (functionality-review HIGH): `_parse_annotations` silently dropped every
  16-bit DOS function from the `match --all` / `find_*` collections.  The
  parse/find helpers now take `min_va` and the batch collectors pass
  `min_valid_va_for(cfg)`.
- **tc20 missing from the flag-sweep plumbing** (functionality-review):
  `_FLAGS_MAP` and the sweep-tier branch covered tc16/borlandc55 only — a
  tc20 flag sweep generated MSVC flags (`/Od /Gd /MT ...`) that TCC 2.0
  rejects, so every combo failed.  tc20 now uses `BORLAND_FLAGS` /
  `BORLAND_SWEEP_TIERS`.
- **doctor's 16-bit profile set lacked tc20**: a tc20 project got a
  spurious "configure a 16-bit compiler profile" warning and no toolchain
  diagnosis.  `_16BIT` and the toolchain-backed tuple now include tc20.
- **intake did not link the Borland/Watcom 16-bit toolchains**: a DOS MZ
  intake (tc16/tc20/watcom16) printed "toolchain not found — symlink
  tools/ yourself" instead of linking the vendored tree.  The toolchain
  link map now covers them.
- **`rebrew report` dropped every 16-bit function**: the HTML report's
  hardcoded `MIN_VALID_VA` floor hid all MZ functions (and its docstring
  claimed status.py had the same floor — it doesn't).  Now arch-aware.
- **LZEXE v0.90 reloc-table truncation detected**: `_reloc_table90` now
  raises on EOF before the final segment group (mirroring v0.91), plus
  unit tests for the v0.90 decode/truncation paths (the v0.90 path had
  zero test coverage).
- **`rebrew unpack-lzexe` probed the file twice**: `lzexe_version` ran
  once in the CLI and again inside the unpack; the CLI now derives the
  version from a single `unpack_lzexe` result (also makes the error
  handling single-path).
- **`_parse_annotations`** (match.py) hardcoded VA floor fixed — see above.
### Added
- **PKLITE packer detection**: `rebrew toolchain detect` now reports
  `packed: pklite` for PKWARE-compressed DOS executables (the stub carries
  its banner near the header) with a "no built-in unpacker; find an
  unpacked copy" evidence line — so a packed binary's family is not trusted
  blindly from stub/compressed strings.  New fixture
  `tests/fixtures/tc16_hello_pklite.exe` (packed with the original PKLITE
  1.03 under DOSBox).  The intake skill documents the PKLITE vs LZEXE
  handling.
- **`tc20` joins the toolchain smoke gate — 7/7 images byte-reproducible**:
  a `rebrew/borland:2.0-win16` docker image (Dockerfile + DOSBox `tcc`
  wrapper mirroring the 3.1 image, built from the committed `tc20.tar.xz`)
  now gives Turbo C 2.0 a fully containerized path alongside the host
  DOSBox fallback, and the smoke gate covers it (its COMENT run-timestamp
  ticks + record checksum at offsets 44-49/57-58 are masked — computed by
  diffing consecutive compiles).  `rebrew toolchain smoke` → `Smoke: 7
  toolchains byte-reproducible`.
### Fixed
- **LZEXE unpacker hardened against corrupt files** (error-review): header
  geometry (param-block offset, stream offset) is bounds-checked before
  reads; `struct.error`/`IndexError` from corrupted-but-stub-intact files
  are converted to a clean `NotLzexeError`; match distances exceeding the
  output (negative back-references) raise instead of wrapping to garbage;
  the v0.90/0.91 relocation tables require their terminator (a truncated
  table previously returned a partial reloc list silently); the CLI error
  names the input file.  `lzexe_version` now reads only the header + stub
  region instead of the whole file (no more full read of 100 MB targets
  just to reject them).
- **OMF→COFF temp file leak**: `parse_obj_symbol_and_relocs` used
  `NamedTemporaryFile(delete=False)` and never unlinked — every 16-bit
  compile that fell through to the objconv path leaked a `/tmp/*.coff`.
  The conversion now runs inside a `TemporaryDirectory`.
- **`/* */` annotation markers honored in more paths** (error-review):
  `split_annotation_sections` only admitted `//` lines, so C89-style
  16-bit sources (tc20/msvc1.52/watcom16 skeletons) split into 0 blocks
  (merge/split would drop their annotations); and the KV regex captured a
  trailing `*/` into values (`/* SIZE: 64 */` → `int("64 */")` crashed to
  `size = 0`).  Both fixed.
- **`rebrew intake` stubs now profile-aware**: document-unmatched wrote
  `// STUB:` markers unconditionally — for C89-strict 16-bit profiles
  (Turbo C 2.0 rejects `//`) every intake-generated stub failed to
  compile.  The stub template (and the stale-stub prune regex) now emit
  /match the `/* STUB: ... */` form for those profiles.
- **MZ file size undercounted for exact-512-multiple files**: `cblp == 0`
  means the last page is exactly 512 bytes (per the MZ spec), but the
  `(cp-1)*512 + cblp` formula yielded `cp*512 - 512` — an empty code
  region for such files.  Now `cp*512` when `cblp == 0`.
- **GA compiles bypassed the toolchain routing**: `BinaryMatchingGA`'s
  `_compile_source` called `build_candidate_obj_only` without `profile`/
  `cfg`, so the toolchain-backed routing (fixed earlier for the flag-sweep
  path) never activated inside the GA — every GA compile on a 16-bit
  project tried to run the DOS compiler natively ("Permission denied:
  .../TCC.EXE").  The GA constructor now accepts `profile`/`cfg` and
  forwards them; both construction sites pass them from the config.  A
  smoke GA run on the Keen 6 demo function now compiles through DOSBox
  end-to-end (the 16-bit GA loop: compile → parse → score → mutate).
- **`rebrew intake` mislabeled MZ binaries as PE**: the one-shot onboarding
  only patched the config's format/arch for NE binaries — an MZ target got
  `format = "pe"` (only the arch came out right from the profile default).
  Intake now sets `format = "mz"` + `arch = "x86_16"` for plain DOS MZ
  binaries, matching init.
- **`toolchain detect` left the arch empty for die-detected MZ binaries**:
  the MZ branch only ran when the family was unknown — a diec/PDB-detected
  DOS binary (e.g. the unpacked Keen 6: `borlandc` via diec) returned with
  `arch: ""`, mislabeling 16-bit code.  The MZ branch now applies to every
  MZ executable (arch `x86_16` unconditionally; family from strings only
  when no stronger backend named it, and `detected_by` is preserved).
- **`profile_matches_detection` used a stale `_BITNESS_16 = {msvc1.52}`**:
  the arch-alignment check only treated msvc1.52 as 16-bit-capable (so
  tc16/tc20/watcom16 projects falsely failed doctor on 16-bit targets) and
  mislabeled MZ as "NE".  The set is now `{msvc1.52, tc16, tc20,
  watcom16}` with corrected wording, and the converse check (16-bit profile
  on a 32/64-bit binary) uses the same set.  The tc16 fixture's alignment
  test was updated: `borlandc55` (32-bit bcc32) now correctly rejects a
  16-bit binary, and the fixture's arch assertion locks in `x86_16`.
- **`rebrew diff` / GA compiled DOS sources via the raw subprocess path**:
  `build_candidate_obj_only` routed toolchain-backed profiles through
  `compile_to_obj` only for `("watcom", "msvc1.52")` — `tc16`/`tc20`/
  `watcom16`/`borlandc55` fell through to the raw subprocess path and tried
  to execute the DOS compiler binary natively ("Permission denied:
  .../TCC.EXE").  The profile tuple now matches compile.py's routing, so
  `rebrew diff` and the GA/flag-sweep compile path reach DOSBox for 16-bit
  projects.
- **`rebrew diff` disassembled DOS code as 32-bit**: `diff_functions` /
  `structural_similarity` calls from the diff command (and the GA fitness +
  flag-sweep scoring) used the 32-bit default mode — a 16-bit function's
  byte diff rendered `4a` as `dec edx` instead of `dec dx`.  The diff
  command now derives the mode from the target arch (`_cs_mode_for_cfg`),
  and `BinaryMatchingGA` gained a `cs_mode` parameter (wired from the
  config at both construction sites) so structural scoring disassembles
  16-bit targets in 16-bit mode.
- **`rebrew verify` batch and naming rejected 16-bit VAs**: the batch
  verify path had its own hardcoded `MIN_VALID_VA` floor (every MZ function
  reported `INVALID_VA: VA too low`), and `naming.load_data`/`existing_vas`
  silently SKIPPED all low-VA entries (16-bit projects appeared empty to
  todo/similar).  Both now use the arch-aware
  `min_valid_va_for(cfg)` (0 for x86_16).  Surfaced by running
  `rebrew verify` on the Keen 6 demo project.
- **`function_extent_from_disasm` disassembled DOS code as 32-bit**:
  hardcoded `CS_MODE_32` mis-decoded 16-bit MZ/NE instructions and hit a
  bogus early `ret`, truncating every DOS function's extent to ~20 bytes
  (breaking extent-based tooling — `rebrew describe`, skeleton convention
  inference, size validation — on all 16-bit targets).  The mode now
  follows the binary format (`mz`/`ne` → 16-bit); the Keen 6 demo's
  `fcn_042e` extent went from 24 to the correct 38.
- **16-bit DOS VAs are valid below 0x1000**: the annotation/lint "VA
  suspicious (below 0x1000)" check assumed PE-era image bases and flagged
  every MZ binary function (VA 0x42e, the code region base).  New
  `rebrew.cli.min_valid_va_for(cfg)` returns 0 for `x86_16` targets; wired
  into `Annotation.validate(min_va=...)`, `rebrew test`, `rebrew match`,
  and lint's E002.  Surfaced by running `rebrew test` on a real Keen 6
  demo function.
- **`extract_function_name_and_proto` misparsed `void far *pascal f(...)`**:
  tree-sitter marks the non-C89 keywords `far`/`pascal` as ERROR nodes, and
  the declarator walk recursed into them, returning "pascal" as the
  function name (breaking symbol resolution → "Symbol '_pascal' not
  found").  The pointer-declarator walk now prioritizes the nested
  `function_declarator` (the real name) before falling back.
- **Borland pascal OMF symbols resolve by the C-level name**: a `pascal`
  function compiles to an UPPERCASE no-underscore symbol (`FCN_042E`);
  `_match_symbol` now tries `name.strip("_").upper()` in addition to the
  cdecl `_name`/`name`/`name_` dialects, so `rebrew test` finds the
  compiled function without renaming.
### Added
- **16-bit calling-convention skeleton stubs**: `calling_convention_at`
  now infers conventions for `x86_16` targets too (16-bit disassembly; the
  `ret` vs `ret N` epilogue rule is word-size independent), and skeleton
  generation emits real stubs for DOS functions — `int pascal f(a1, a2)`
  for the Borland 16-bit profiles (tc16/tc20/borlandc55), `__stdcall` for
  MSVC/Watcom 16-bit — instead of the generic `int f(void)`.  The Keen 6
  demo's `fcn_042e` (`ret 4`) now skeletons as `int pascal fcn_042e(int
  a1, int a2)`.  `_ret_arg_count` gained a word-size parameter (2 for
  16-bit).
- **`rebrew unpack-lzexe` — LZEXE 0.90/0.91 unpacker**: restores DOS
  executables packed with Fabrice Bellard's LZEXE compressor (many 1990s
  games shipped packed; the visible code is only a decompressor stub, so
  discovery/detection see nothing until the image is restored).  The
  format is documented only by its own stub — it was reverse-engineered
  from the decompressor disassembly of a real packed game (Commander Keen
  6 demo) and validated byte-for-byte against the classic `unlzexe`
  reference implementation on both the canonical and the patched 0.91 stub
  variants.  Rebuilds the original MZ: decompressed image, reconstructed
  header (cblp/cp/crlc/cparhdr/minalloc/maxalloc/ss/sp/ip/cs), and the
  relocation table re-encoded as standard MZ entries.  `rebrew toolchain
  detect` reports `packed: lzexe 0.91` and points at the command.  New
  fixture `tests/fixtures/tc16_hello_lzexe.exe` (packed with the original
  LZEXE.EXE under DOSBox) locks the round-trip: image and relocation
  entries equal the pre-pack original.
- **`tc20` profile — Turbo C 2.0 (16-bit DOS)**: the 1988/89-era Borland
  compiler (the classic DOS-game compiler generation, and the one diec
  reports as "Borland C/C++ 1991" for binaries like Commander Keen 6) is
  now in the zoo (`toolchain/borland/2.0-win16`, assembled from the
  archive.org `turboc20` floppy images: TCC.EXE 2.0 + TLINK/CPP + runtime
  libs + headers).  `rebrew.tc16.compile_c` gained a `version` parameter
  ("3.1" default, "2.0"), the profile routes through `compile_to_obj`, and
  simple functions compile byte-identically to TCC 3.1.  `init --compiler
  tc20` works; `toolchain detect`/`doctor` accept the profile via
  `_PROFILE_COMPAT`.
- **C89-strict skeleton markers**: Turbo C 2.0 rejects `//` comments
  ("Declaration syntax error" — verified), so skeletons for the C89-strict
  16-bit profiles (`tc20`, `msvc1.52`, `watcom16`) now emit
  `/* FUNCTION: MODULE 0xVA */` markers, and the annotation parser
  (`NEW_FUNC_RE`, `NEW_FUNC_CAPTURE_RE`, `NEW_KV_RE`, `is_comment`
  pre-filter) accepts both comment styles.  `tc20` was also missing from
  the skeleton `__cdecl` strip-list (TCC 2.0 would choke on `__cdecl`).
  Round-trip: tc20 skeleton → parse → TC 2.0 compile works end-to-end.
- **`rebrew.tc16` workdir reuse is version-safe**: reusing a sandbox
  staged for a different TCC version silently kept the old toolchain's
  symlinks; stale links are now replaced when the target tree differs.
- **`tc16` joins the smoke gate**: the Turbo C++ 3.1 image is now part of
  `rebrew toolchain smoke` (6/6 images byte-reproducible).  TCC's objects
  embed a per-run sub-second timestamp in two Borland COMENT records, so
  the smoke mask now supports a list of ranges (the ticks bytes + record
  checksums are zeroed before hashing); determinism verified across
  consecutive runs.
- **`tc16` profile — Turbo C++ 3.1 (16-bit DOS)**: the classic DOS-game
  compiler is now in the zoo (`toolchain/borland/3.1-win16`, vendored
  in-repo from the archive.org `turboc3.1_202112` item).  `TCC.EXE` runs
  headless under DOSBox via the new `rebrew.tc16` module (mirroring
  `rebrew.msvc16`), `compile_to_obj` routes the profile through it, and the
  Borland 16-bit OMF parses via `rebrew.matcher.omf16` (verified:
  cdecl prologue/epilogue extracted).  Image `rebrew/borland:3.1-win16`
  with a `tcc` DOSBox wrapper.
### Added
- **`rebrew init --guess-compiler`**: auto-selects the compiler profile
  from the target binary (diec → PDB → heuristics, reusing the detector
  `_PROFILE_COMPAT` mapping), preferring the 16-bit profile for DOS/NE
  binaries — verified: a Turbo C++ 3.1-built DOS MZ exe guesses `tc16`, a
  MSVC 16-bit NE binary guesses `msvc1.52`.  Errors loudly when the binary
  is missing or the family has no matchable profile.
### Added
- **DOS MZ function discovery**: `rebrew discover-functions` (and intake)
  can now enumerate plain DOS MZ executables — rizin cannot analyze them
  (0 functions), so a 16-bit capstone linear sweep over the code region
  (after the MZ header + relocation table) finds the CS:IP entry, cdecl
  prologues (`push bp; mov bp,sp`), padding runs, and `e8 rel16` call
  targets.  `binary_loader` gains `is_mz`/`parse_mz_header`.  Verified on
  the TCC-built `tc16_hello.exe` fixture (44 candidates incl. the entry).
### Fixed
- **MZ header parse read `e_ss` as the code segment**: `parse_mz_header`
  read the entry CS from offset 0x0E — that is `e_ss` (the stack segment),
  not `e_cs` (0x16).  Any DOS program with separate code and data segments
  (SS != CS) got a wrong entry VA and a shifted address space; the TCC
  fixture only worked because tiny-model SS == 0.  The entry VA is now
  `e_cs*16 + e_ip`, and the whole MZ VA scheme is corrected to the
  segment-relative convention `VA(F) = F - code_offset` (the file IS the
  load image minus the header), so the header's segments land at their
  real linear addresses (`e_cs*16`, `e_ss*16`).  Fixture VAs rebased
  (`add` 0x10cd → 0x28d) with tests updated.  Found by real-game
  validation: Commander Keen 6 demo.
- **MZ string-based compiler detection**: `load_binary` succeeding for MZ
  made `toolchain detect` fall through the unparseable/NE family-assignment
  branches, leaving LZEXE-packed and plain DOS binaries at `unknown`
  despite clear Borland/Watcom runtime strings.  An MZ branch now assigns
  the family from string evidence (mirroring the NE branch), so a packed
  or plain DOS game detects as `borlandc`/`watcom`/`delphi` instead of
  `unknown`.
- **init mislabeled MZ/16-bit profiles**: `init` wrote `format = "pe"`
  for MZ binaries (format detection covered PE/ELF/Mach-O/NE but not MZ —
  `"mz"` is now a known format) and the profile-mismatch warning called
  any 16-bit binary "NE" and treated only `msvc1.52` as 16-bit.  It now
  derives the 16-bit profile set from `COMPILER_DEFAULTS` (msvc1.52/tc16/
  watcom16) and says "16-bit binary (mz/x86_16)".
- **`_omf_to_coff` resolved the wrong vendored objconv path**: `parents[2]`
  from `src/rebrew/matcher/parsers.py` is the repo `src/` dir, so the
  pinned 16-bit-OMF-capable objconv at `tools/objconv/` was never found
  and every OMF parse silently used whatever `objconv` was on PATH (stock
  2.56, which rejects 16-bit data relocations with `Error 2316`).  The
  vendored path now uses `parents[3]` (repo root); the fork build converts
  TCC 3.1 OMF with `disp16` data relocations cleanly.
- **16-bit intra-binary call relocations mask in the MZ path**: `main`
  from the TCC-built fixture (a cdecl call to `add`, `e8 rel16`) matches
  **RELOC 20/20** through the CLI — the compiled call slot is correctly
  relocation-masked against the binary's target address.  Locked in by an
  end-to-end test (second fixture function matched, this one
  reloc-bearing).
- **`rebrew doctor` handles 16-bit profiles correctly**: the Compiler
  check only warned for `msvc1.52` on 16-bit targets — a tc16/watcom16
  project got a stale "set msvc1.52" warning.  It now accepts all three
  16-bit-capable profiles, and for 32-bit profiles on 16-bit targets
  suggests the right profile via the shared detector (`suggest_profile` —
  a Borland MZ binary suggests `tc16`).  Intake skill documents the DOS
  MZ flow.
- **DOS match loop locked end-to-end**: the MZ fixture's `add` (extracted
  at its discovered VA 0x10cd via the MZ loader) is now asserted to equal
  the tc16-compiled code and match EXACT — plus the CLI workflow verified:
  `rebrew test` promotes STATUS to EXACT in the metadata and
  `rebrew verify` (cached and `--full`) re-derives 1/1.  The complete
  DOS-game reversing loop (init → discover → source → test → promote →
  verify) is proven and CI-locked.
- **omf16 drops the TCC/wcc16 LEDATA checksum byte**: Borland/Open Watcom
  16-bit objects end their 0xA0 code records with an OMF checksum byte
  (whole record incl. type+length ≡ 0 mod 256) that the parser included in
  the code slice — a spurious trailing byte that broke byte-matching.
  Detection is by the record sum, so MSVC 1.52 objects (no checksum) are
  unaffected.  This unlocked the first real DOS-game match: `rebrew test`
  on `add` from the TCC-built `tc16_hello.exe` returns **EXACT 13/13**
  through the full pipeline (init `--guess-compiler` → discover → source →
  tc16 compile → byte-compare); wcc16 objects parse clean too (11-byte
  `add` + rel16 slot).  Regression test added.
- **DOS MZ binaries now flow through the whole pipeline**: `load_binary`
  parses plain MZ executables (pseudo `.text` section, VAs as linear
  `segment*16+offset` addresses from the CS entry base) so
  `va_to_file_offset`/`extract_raw_bytes` work for DOS targets; the
  discovery sweep uses the same VA convention and computes sizes from
  candidate spacing (was 0, blocking skeleton).  Skeleton generation is
  profile-aware: non-MSVC profiles emit `int f(void)` instead of
  `__cdecl` (a syntax error in TCC 3.1 — "Declaration syntax error").
  Verified end-to-end on the TCC-built `tc16_hello.exe`: init
  (`--guess-compiler` → tc16) → discover (43 sized candidates incl. the
  CS:IP entry) → skeleton (`int main(void)`) → `rebrew test` (compiles via
  tc16, compares against the MZ target bytes).
- **Roadmap/ADR/OMF docs reconciled with the shipped zoo**: the consoles
  roadmap's "only five real profiles" row now reflects the 15-profile zoo;
  ADR-006's status section lists the toolchains actually through the
  abstraction (incl. tc16/borlandc55/watcom16) and drops the stale
  "bcc32 extraction pending" note; OMF_NOTES's "objconv crashes on 16-bit"
  caveat now documents the vendored fixed build + the fall-through path.
- **Agent skills updated for the 16-bit zoo**: `rebrew-matching` documents
  the tc16/borlandc55/watcom16 flag-sweep axes; `rebrew-intake` now
  recommends `--guess-compiler`, and its NE section reflects that MSVC-style
  NE byte-matches via `msvc1.52` and plain-DOS Borland targets via `tc16`
  (only Borland *Delphi* NE remains unmatchable, ADR-001).  All skills
  re-validated with `agentskills validate`.
- **`rebrew intake` now suggests the right profile for Borland binaries**:
  intake's hand-rolled family→profile mapping was inconsistent with the
  detector — a Borland DOS binary fell through to `msvc6`.  Family→profile
  selection is now unified in `rebrew.toolchain_detect.suggest_profile`
  (the single source of truth shared by init's `--guess-compiler`, intake,
  and doctor), so intake suggests `tc16` for Borland DOS and `msvc1.52`
  for MSVC 16-bit NE binaries.  Locked in by intake regression tests.
- **Flag sweeps use the right dialect for the new profiles**: the GA flag
  sweep fell back to msvc6's `/`-style flags for any profile outside the
  map — `tc16`/`borlandc55` would have fed `/O2` to TCC/bcc32.  Added a
  shared `BORLAND_FLAGS` set (`-O1`/`-O2`/`-Od`, `-K`, `-Z` — verified
  against the real compilers) with `BORLAND_SWEEP_TIERS`, and wired
  `watcom16` to the existing wcc flag family.  Locked in by sweep tests.
- **`rebrew init --compiler tc16` works**: `tc16` was missing from
  `COMPILER_DEFAULTS` (init rejected it as an unknown profile).  It now
  generates the full toolchain-backed config (command/includes/libs under
  `toolchain/borland/3.1-win16`) that loads without an unknown-profile
  fallback — locked in by an init regression test (profile-set assertions
  updated to 15 profiles).
- **`tc16` validated on a real artifact**: a Turbo C++ 3.1 + TLINK-built
  DOS executable (compiled under DOSBox with the vendored toolchain) now
  has a committed test fixture (`tests/fixtures/tc16_hello.exe`) and a
  detector regression test — diec identifies it as Borland C/C++ 1991 /
  TLINK 5.0, the detector maps it to the `borlandc` family, and the
  `tc16`/`borlandc55` profiles align (msvc6 correctly rejected with a
  "tc16 would fit" hint).  The whole build→detect→align loop for a new
  DOS-game target is now proven.
- **16-bit native profiles verified end-to-end**: `tc16` and `watcom16`
  now have proven full matching loops — `compile_and_compare` returns
  EXACT (TCC) / RELOC 100% (wcc, the chkstk rel16 slot masks) against
  their own compiled objects, closing the long-standing "compile works,
  matching unverified" note for watcom16.  Locked in by a roundtrip
  regression test.
- **`rebrew doctor` knows the new toolchain-backed profiles**: the
  Toolchain check now covers `watcom16`, `tc16` and `borlandc55` (was
  only `watcom`/`msvc1.52`) — it reports the vendored-binary/image
  resolution instead of the misleading "binary not in PATH" for these
  profiles.
- **Host and image DOSBox drivers are now byte-identical**: the host
  `rebrew.dosbox` and the toolchain-image `wrapper-common.sh`
  (`rebrew_dosbox_run`) generate the same DOSBox config — extracted into
  `_build_dosbox_conf` and enforced by `TestDosboxDriverSync`, so a
  headless/driver fix in one can no longer drift from the other (the
  docker-less fallback and the containerized path stay in lockstep).
- **`borlandc55` profile compiles again**: bcc32 was missing from
  `posix_style` and fell into the MSVC env path (msvc_env_from_config on a
  bcc32 command) — and even with the flag fix, the generic posix `-o obj`
  invocation misparses `obj` as an input file in Borland's flag dialect
  (`-o` is compile-only).  It now routes through the toolchain runner with
  bcc32 flags (`-c`, object follows the source stem).  Also added `tc16`
  to `posix_style` and all three new profiles (`watcom16`, `borlandc55`,
  `tc16`) to `_KNOWN_PROFILES` — a tc16/borlandc55 project no longer
  silently falls back to msvc6 on config load.
- **Detector profile alignment**: `borlandc` family now maps to
  `{tc16, borlandc55}` and `watcom` to `{watcom, watcom16}` — `rebrew
  doctor` no longer flags Borland/Watcom binaries as unmatchable (the
  "no profile can byte-match these yet" docstring was outdated).
- **DOSBox runs fully headless**: both the host runner (`rebrew.dosbox`,
  used by msvc16/delphi16/tc16) and the container wrapper
  (`wrapper-common.sh` → `rebrew_dosbox_run`) now set
  `SDL_AUDIODRIVER=dummy` alongside the existing
  `SDL_VIDEODRIVER=dummy` — a compile never pops a window (verified with
  `DISPLAY` unset) and never touches audio (the ALSA chatter in logs is
  gone).  Locked in by regression tests.
- **Failed objconv conversions raise loudly**: `_omf_to_coff` now requires a
  non-empty output file and a clean objconv exit — the caller pre-creates
  the output tempfile, so the old `exists()` check never fired and a failed
  conversion (objconv aborts before writing on errors) left an empty file
  that LIEF silently parsed as `None` (a phantom failed match instead of a
  readable error).
- **16-bit MSVC OMF dialects parse end-to-end**: `parse_obj_symbol_and_relocs`
  now falls through to the objconv→COFF path when the minimal `omf16`
  decoder cannot extract code (the `/O1` and far-code COMDAT models), instead
  of returning `None` outright; and `_omf_to_coff` prefers the vendored
  (pinned) objconv over a PATH binary.  The vendored `tools/objconv/objconv`
  should be the fixed build from the objconv fork (16-bit OMF relocation +
  COMDAT support); the stock build errors on 16-bit input.  The O1/far
  fixtures themselves parse via `omf16` with their real symbols (`_callg`,
  `_f` — far `lcall` model with rel16/disp16 slots), now covered by tests.
- **`watcom16` profile compiles through the toolchain runner**: the 16-bit
  `wcc` profile fell into the generic MSVC flag path (`/nologo /c` glue →
  E1139/E1073) and was absent from `posix_style`, so a watcom16 project
  could not compile at all.  It now routes through `rebrew.toolchain`
  with the wcc flag shape (`-fo=`/`-I`/`-zq`, no `-c` — wcc16 rejects it),
  and its OMF objects parse via the omf16 decoder — verified end-to-end
  (wcc → OMF → `parse_obj_symbol_and_relocs` yields code + rel16 slots).
- **Persisted machine statuses now validate**: `rebrew test` / `rebrew verify`
  pass `CompareResult.status` straight to `update_source_status`, which can
  persist `SIZE_MISMATCH`, `COMPILE_ERROR`, `EXTRACT_ERROR`, `MISSING_SIZE`
  and `MISSING_FILE` — but `KNOWN_STATUSES` (the gate used by
  `MetadataEntry.apply` and lint) only knew the six user classifications, so
  the validation layer contradicted the canonical writer (bench's stored
  `SIZE_MISMATCH` flagged invalid).  `KNOWN_STATUSES` now covers the full
  persistable vocabulary.
- **Legacy projects resolve the restructured toolchains again**: the
  gitignored `tools/<name>` compat symlinks were hand-made and missing
  `MSVC600`/`MSVC7` — 22 projects (win2k-*, skifree16/32) referencing
  `tools/MSVC600/VC98/...` silently broke after the `tools/` → `toolchain/`
  restructure.  `rebrew toolchain vendor` now (re)creates the full alias set
  (`MSVC600`, `MSVC7`, `msvc6.3`, …) after every successful vendor, so fresh
  clones get them automatically; the aliases are also covered by
  `.gitignore` so they cannot drift back in.  `resolve_msvc_toolchain` now
  prefers project-provisioned layouts (linked toolchain dirs) over the
  rebrew install's own vendored tree, so `--link-tools-from` projects keep
  the layout they actually linked instead of silently switching to the
  install's master.
- **`vendor msvc6` produced an unusable flat tree**: the OmniBlade
  decomp.me tarball is flat (Bin/Include/MFC/ATL at top level), but the
  canonical master layout and every legacy reference expect the classic
  `VC98/` wrapper.  `ToolchainSource.vc98_wrap` (msvc6 only) makes both
  `vendor` and the Dockerfile wrap the tree in `VC98/`, so host trees and
  containers stay byte-identical (smoke re-verified).  The mirror ships no
  `Lib` tree — `doctor` warns, which is expected for compile-only `/c`
  builds.
- **Dependency floors raised to close advisories (deps-review F1)**:
  `typer>=0.10` (the 0.9 floor admitted a version the CLI cannot start on —
  `rich_markup_mode` requires 0.10), `pytest>=9.0.3` (CVE-2025-71176
  `tmpdir`), and a declared `click>=8.3.3` (direct import in `init.py` shell
  completion; 8.3.3 fixes CVE-2025-6143/6144).  `uv audit` went from 35
  vulnerable packages to 2 (diskcache has no fixed release; its cache only
  stores compiled `.obj` bytes, documented in `pyproject.toml`).
- **`prove` extra now declares its own imports**: `claripy` (imported by
  `prove.py`/`doctor.py`) and `gitpython>=3.1.58` (angr's transitive dep with
  RCE-class advisories fixed in 3.1.58) — `uv pip install -e ".[prove]"` no
  longer relies on luck to pull them (deps-review F3).
- **`skills-ref` pre-commit hook fixed from a silent no-op**: the hook
  checked for a nonexistent `skills-ref` command and exited 0, so a broken
  SKILL.md passed CI.  The package's real binary is `agentskills`; the hook
  now runs `uv run agentskills validate` (infra-review F6).
- **CI drops the dead "Install wibo" step**: it swallowed download failures
  with `set +e` and no test consumed the binary (no wine on the ubuntu
  runner, vendored MSVC is gitignored).  The lint job now gates on
  `uv audit --locked` (exits 1 on vulnerable packages; diskcache's
  unfixed advisory is ignored only while no fix exists) (infra-review F5).
- **Pre-commit hygiene hooks added**: `end-of-file-fixer`,
  `check-merge-conflict`, `check-yaml`, `check-toml`, and
  `mixed-line-ending` (LF) — trailing-newline/conflict-marker/YAML/TOML
  breakage no longer lands silently (infra-review F6).
- **`prove` tests skip when angr is absent**: the CLI-status-guard and
  Win32-SimProcedure tests hard-failed with `ModuleNotFoundError` when the
  optional `prove` extra wasn't installed; they now honor the same
  `skipif(not has_angr)` guard as the rest of `test_prove.py`.
- **mypy is clean on 105 files (was 78 errors)**: the session's new code
  carried real type errors — `init.py` reused the `detected` variable for a
  `ToolchainInfo` after a tuple (renamed to `tc`), `binsync_export.py` typed
  `cfg` as `object` instead of `ProjectConfig` (4 signatures now typed) and
  shadowed the `warnings` module with a local list (renamed `warnings_list`),
  `verify.py` returned `Any` from a `bool`-typed helper, `compile.py` rebound
  `env` to `dict[str, str] | None`, and `binsync_diff.py`/`binsync_export.py`
  carried stale `# type: ignore` comments.  The remaining 35 prove.py errors
  were environmental — they vanish with angr installed.
- **CI lint job installs extras**: `uv sync --frozen --all-extras` — mypy
  only type-checks prove.py correctly with angr present (phantom
  unused-ignore / Any-subclass errors otherwise).  The lint mypy gate was
  red on every recent run for this reason.
- **CI audit gate corrected**: `uv audit --fail-on` doesn't exist in the
  pinned uv (0.12.2) — `uv audit` already exits 1 on vulnerable packages.
  The gate is now `uv audit --locked --ignore-until-fixed
  GHSA-w8v5-vhqr-4h9v`: diskcache's unsafe-pickle advisory is ignored only
  while unfixed, so a fixed release flips CI red.
- **CI test job installs nasm**: the NASM round-trip verification
  (`disassemble_to_nasm` stats) hard-failed with `nasm_ok == 0` — ubuntu
  runners don't ship nasm.
- **Toolchain-dependent tests skip without the vendored toolchains**
  (CI: `tools/` is gitignored): `test_msvc16.TestCompileC` skips without
  `tools/MSVC152`, `test_delphi16` without `tools/DELPHI10`,
  `test_doctor_compiler.test_watcom_vendored_passes` without
  `tools/WATCOM`; the GA msvc152 routing test now mocks
  `parse_obj_symbol_bytes` instead of relying on a vendored objconv; the
  doctor `--json` purity case accepts exit 1 (a failing check keeps stdout
  pure JSON).
- **CI pins the uv installer to the local version** (build-review): the
  workflow pinned uv 0.12.2 while the local toolchain runs 0.12.3 —
  against the pin's own "bump deliberately when upgrading" comment.  Now
  0.12.3.
- **CI gates wheel reproducibility** (build-review): the package job builds
  the wheel a second time with `--no-cache` into a fresh out-dir under the
  same `SOURCE_DATE_EPOCH` and fails if the sha256 differs.  The sdist stays
  excluded — setuptools (≤83) does not honor `SOURCE_DATE_EPOCH` for sdist
  tar entry mtimes / gzip header (verified: content identical, metadata
  varies); this is the documented Makefile limitation, and wheels are the
  reproducibility contract.
- **sdist no longer ships tests/** (pkg-review): setuptools' default sdist
  filelist pulled in all 185 test files (tests/ was the only dev tree that
  leaked).  A `MANIFEST.in` prunes `tests/`, `docs/`, `tools/`,
  `toolchain-images/` and excludes `*.py[cod]`/`__pycache__`; the wheel is
  unaffected (contents come from package-data, still byte-reproducible at
  the same `SOURCE_DATE_EPOCH`), and the pruned sdist still builds a
  complete wheel with `agent-skills` intact.
- **Release preflight gate** (release-review): `make release-check` verifies
  the CONTRIBUTING.md contract before tagging — `__version__` bumped past the
  last tag, clean tree, and a dated `[<version>]` changelog section — so a
  release cannot be tagged out of sync with the version or the notes.
- **Silent best-effort failures now log at debug** (o11y-review): 15
  swallowed `except Exception` sites in `binsync_diff.py` /
  `binsync_import.py` (both gained a module logger), `binary_loader.py` and
  `discover.py` now emit `logger.debug(..., exc_info=True)` with the VA
  context — `rebrew -v -v binsync-import …` shows *why* an entry was
  skipped instead of silently counting it.  The remaining silent fallbacks
  in the recon primitives (`analyze.py`, `asm.py`) are documented
  best-effort paths and are left untouched.  No sensitive data (LLM API
  keys, tokens) is ever logged.
- **Cross-process metadata lock regression test** (concurrency-review): the
  flock sidecar guarantee (error-review F6) was validated manually but never
  committed.  `test_metadata.py::TestCrossProcessMetadataLock` now spawns 4
  real processes × 20 unique STATUS promotions each and asserts all 80
  survive — an interleaved read-modify-write without the flock loses keys.
- **`lint --fix` outside a project warns instead of silently no-oping**
  (functionality-review): without a `rebrew-project.toml` the migration has
  nowhere to write, so `--fix` did nothing with zero explanation — a user
  outside the project dir saw no effect and no message.  It now prints
  `--fix needs a rebrew-project.toml — no config loaded, nothing migrated`
  and leaves the inline keys untouched (regression test added).
- **`init`/config resolve the MSVC toolchain layout instead of assuming the
  master** (error-review): `rebrew init --compiler msvc6|msvc7` and the
  config layer's default includes/libs pointed at `tools/MSVC600/VC98` /
  `tools/MSVC7`, which do not exist on machines that only vendor the
  compile-only mirrors (`tools/msvc6.6` / `msvc6.3` / `msvc7.0`) — a fresh
  project's first compile failed with wine `failed to open tools/MSVC600/...`
  (exit 53).  `rebrew init` now writes the best layout actually present
  (master → newest mirror → older mirror) and the config fallback resolves
  the same; verified end-to-end (the resolved `msvc6.6` and `msvc7.0`
  toolchains compile C → .obj).
- **`init --link-tools-from` accepts the compile-only mirrors** (error-review):
  the linker only looked for the master-named dir (`MSVC600` / `MSVC7`) and
  hard-failed on machines that only vendor `msvc6.3`/`msvc6.6`/`msvc7.0` —
  it now tries the mirrors in the same order as the config resolution and
  links whichever exists (regression test: mirror-only master dir).
- **`init` warns on compiler-family mismatch** (the detector's family now
  feeds init): a high-confidence detection that contradicts the chosen
  profile (e.g. a MinGW/Zig-built DLL initialized with `msvc6`) can never
  byte-match — init prints a warning naming the detected family and the
  counterpart profile (`--compiler gcc-pe`) instead of failing at the first
  verify.  `unknown`/low-confidence detections stay silent.
- **doctor/analyze show the detection backend by its real name**
  (error-review): the toolchain-alignment message leaked the internal
  backend id (`detected mingw … via die`); it now renders `via Detect It
  Easy (diec)` / `via PDB` / `via codegen heuristics` via a shared
  `backend_display_name` helper (unit-tested).
- **Toolchain-layout code deduplicated** (minimalism-review): the
  `--link-tools-from` candidate list in `init.py` duplicated the mirror
  table in `utils.py` (drift risk) — it is now derived from the same
  `_MSVC_LAYOUTS` source, and the unused `resolve_msvc6_toolchain`
  back-compat wrapper was deleted (no callers; the project forbids shims).
- **Grid-cell generation extracted + property-tested** (fuzz-review): the
  coverage-cell walk inside `generate_data_json` is now a pure
  `_build_cells` helper, with hypothesis tests asserting the invariants over
  random segment layouts — cells tile the section exactly (contiguous,
  gap-free, no overrun), `span == ceil(bytes / unit)` never exceeds the row
  width, and per-segment state is preserved.
- **Module boundary fixed** (arch-review): `init.py` reached into
  `utils._MSVC_LAYOUTS` (private data) to derive link candidates —
  replaced by a public `utils.toolchain_link_candidates(profile)` helper,
  which also removed the module-level derived dict.  `utils` stays a pure
  leaf module (no rebrew imports).
- **Toolchain directory naming made platform-explicit**: the vendored
  `tools/` subdirs were a mix of `MSVC152` (reads as "MSVC 152"),
  `MSVC420`/`MSVC500`, `DELPHI10`, `WATCOM` (uppercase, no version dots) and
  `msvc6.3`/`msvc6.6`/`msvc7.0` (lowercase) — none conveying that these are
  **Windows-targeting** toolchains run under Wine/DOSBox on Linux.  Renamed
  to a `compiler-version-target` scheme: `msvc-1.52-win16`, `msvc-4.2-win32`,
  `msvc-5.0-win32`, `msvc-6.0-win32` (master), `msvc-6.0-sp3-win32`,
  `msvc-6.0-sp6-win32`, `msvc-7.0-win32`, `delphi-1.0-win16`,
  `watcom-win32` — the same naming the OmniBlade mirror tarballs already
  use.  Every code/test/doc reference updated (~520), the CLI profile
  identifiers (`--compiler msvc6.3|msvc6.6`) are unchanged, and legacy dir
  names remain as symlinks so existing projects keep working (verified:
  mspaint corpus still verifies 251/251 through the `MSVC500` symlink).
- **Toolchain image folders aligned to the documented
  `<family>/<version>-<arch>` layout**: `toolchain-images/` used
  `msvc/6.0-linux-x64`-style names (the image *platform*), which said
  nothing about the compiled target and disagreed with the `tools/` scheme.
  Renamed to the layout docs/TOOLCHAIN.md already prescribed —
  `msvc/6.0-win32`, `msvc/1.52-win16`, `delphi/1.0-win16`,
  `watcom/2.0-win32` — and the image tags (`rebrew/msvc:6.0-win32`, …) and
  Dockerfile build/invoke comments updated (29 references).
- **Toolchains moved from `tools/` into a `toolchain/` folder structured like
  the docker images**: `toolchain/<family>/<version>-<arch>/` (e.g.
  `toolchain/msvc/6.0-sp6-win32/`, `toolchain/delphi/1.0-win16/`), with each
  dir's `Dockerfile` living alongside the toolchain it packages.  This is
  now the **default** — `rebrew init`, the config fallbacks, the GA
  toolchain sweep, the CRT-source detection and `--link-tools-from` all
  resolve `toolchain/…` paths (verified: fresh init writes
  `wine toolchain/msvc/6.0-sp6-win32/Bin/CL.EXE`; `docker build
  toolchain/msvc/6.0-win32` produces `rebrew/msvc:6.0-win32` which compiles
  C end-to-end).  `tools/` keeps the Linux-native helpers (diec, objconv,
  wibo) plus old-name symlinks so existing projects keep working (mspaint
  corpus still verifies 251/251).  `toolchain-images/` is gone (content
  merged into `toolchain/`).
- **Shared toolchain base image + common wrappers**: all toolchain
  Dockerfiles now inherit `FROM rebrew/base:1.0` (`toolchain/base/` — OS +
  wine + wine32 + dosbox + download tooling + common env), built
  automatically as a dependency by `rebrew toolchain build`.  The
  entrypoint wrappers (`cl`, `cl16`, `dcc`) share
  `toolchain/base/wrapper-common.sh` (`rebrew_pick_source` handles
  MSVC-style flags-first argv; `rebrew_dosbox_run` / `rebrew_copy_back`
  are one implementation instead of per-toolchain copies).  The vendored
  compiler trees sit at the top level of each
  `toolchain/<family>/<version>-<arch>/` dir so host and image share one
  layout.  Verified: all four images (`rebrew/msvc:6.0-win32`,
  `rebrew/msvc:1.52-win16`, `rebrew/delphi:1.0-win16`,
  `rebrew/watcom:2.0-win32`) compile C end-to-end from the base.
- **`recompile/` service skeleton** (recompile.online): a FastAPI
  compiler-as-a-service package that dispatches each compile into the
  matching toolchain container — `GET /api/v1/compilers` (catalog derived
  from the rebrew toolchain registry), `POST /api/v1/compile`
  (`{compiler, source, flags}` → status/artifact URL/compiler version/log,
  executed via `docker run` against the pinned image), and
  `GET /api/v1/artifacts/{id}` (path-traversal guarded).  Verified
  end-to-end: the API compiled C with `msvc6` (i386 COFF object served
  back) and `watcom`; unit tests cover the catalog, image resolution and
  the 400/404 error paths (no docker needed).
- **Toolchain zoo additions**: `borlandc55` (Borland C++ 5.5 free
  command-line tools — bcc32 under wine, OMF objects that parse via
  objconv; image `rebrew/borland:5.5-win32`) and `watcom16` (Open Watcom
  `wcc`, 16-bit DOS, native) — the detector's `borlandc`/`watcom` families
  now have profiles to byte-match with, and `rebrew init` warns on family
  mismatch with the correct counterpart.
- **Toolchain images are deterministic and self-contained**: every
  Dockerfile builds from a clean checkout with only docker — the base pins
  the debian digest, msvc6/watcom/borland downloads verify sha256 (the
  moving watcom tag is pinned by checksum), and msvc1.52 + delphi use
  committed in-repo tarballs (the archive.org en_vc152 RAR SFX extracts
  corrupt files under both 7z and unar; the Delphi RTL units have no
  public tarball).  7z extraction tolerates warning exits but verifies the
  compiler binary, so a bad extraction fails loudly.  All five images
  verified building + compiling.
- **`functions.similarity` documented as reserved**: the column was
  documented as a structural-similarity score but no catalog producer ever
  emitted it (it needs both target AND recompiled bytes, which only
  `rebrew match`/`diff` have) — every row was NULL and the doc's example
  showed a misleading `1.0` (db-review F14).  The doc now states it is
  reserved/always-NULL until a producer exists; recoverage displays it only
  when non-null, so no consumer is affected.
- **`history` table is retention-capped**: status-change rows were appended
  on every rebuild and never pruned — a long-lived project that regenerates
  often accumulated rows forever (db-review F7).  Only the newest 10,000
  rows per target now survive each rebuild (the dashboard pages the newest
  100, max 5000), bounding growth while preserving full history depth.
- **Removed the redundant `cells` index**: the `UNIQUE (target,
  section_name, start)` constraint already served the `(target,
  section_name)` prefix used by `section_cell_stats` and per-section
  queries — a separate `idx_cells_section` was paid for on every cell
  insert and never the only usable index (db-review F6).  Stale copies
  from older builds are dropped.
- **Unknown cell states warn instead of vanishing**: an out-of-set
  `cells.state` (a typo in hand-edited JSON) fell into the
  `section_cell_stats.other_count` bucket with no signal (db-review F4).
  `_normalize_cell_row` now logs a warning naming the state and the known
  set; the value is preserved so the count still reconciles.
- **Dashboard "coverage" now means matched bytes**: the headline `coverage_pct`
  summed EVERY function's size regardless of status — an all-STUB binary
  reported ~100% "coverage" (db-review F1).  It now uses matched bytes
  (EXACT/RELOC/PROVEN sizes) / text size, with a separate `identified_pct`
  ("fully documented", incl. stubs) stored alongside in `function_stats`.
  DB_FORMAT.md documents both definitions.
- **`verify_results` no longer dropped on full rebuild**: `rebrew build-db`
  wiped the table on every full rebuild (contradicting DB_FORMAT's "never
  dropped" promise), then re-imported only the last-verified target's rows —
  in multi-target projects every other target's verification history was
  silently lost (db-review F3).  The per-target `INSERT OR REPLACE` + prune
  now keeps it current without the drop.
- **`verify_results` prune no longer wipes on unparseable reports**: when a
  report's `va` values failed to parse, the prune built `va NOT IN ()` —
  which SQLite treats as vacuously TRUE, deleting the target's entire
  history (db-review F5).  The prune now guards on the parsed VAs.
- **`verify_results.diff_lines` is now populated**: the column was documented
  and recoverage-consumed but no producer ever emitted it — every row was
  NULL (db-review F2).  `rebrew verify` now computes the differing-
  disassembly-line count for unmatched functions (best-effort; matched
  functions skip the disassembly diff entirely, leaving NULL = 0 diffs).
- **`section_cell_stats` gained an `other_count` catch-all**: cells in
  states outside the counted buckets (compile_error, missing_*, skip,
  unknown) fell into no column, so `total_cells` never equaled the sum of
  the counted columns and per-section stats silently undercounted
  (db-review F4).
- **`rebrew` umbrella detects `--json` by exact token, not substring**: the
  uncaught-exception handler scanned `"--json" in sys.argv`, so any
  argument containing the literal (a file named `x--json.c`, or
  `--cflags "--json"`) switched the error envelope to JSON mode without
  the user passing `--json` (cli-review F11).  `_json_requested` now
  matches the exact `--json`/`--json=true` tokens.
- **`rebrew catalog --export-ghidra --json` is refused**: the export path
  prints interactive instructions and emits no JSON document — combining
  it with `--json` produced zero stdout, breaking the JSON contract
  (cli-review F9).  The combination now errors up front, like the existing
  `--fix-sizes --json` guard.
- **Malformed `[link]` version strings warn instead of silently no-op**: a
  typo'd `linker_version`/`os_version`/`subsystem_version` (e.g. `"5"` or
  `"abc"`) was swallowed by `except ValueError: pass` — `--fix-headers`
  skipped the field while the parity report showed an unexplained mismatch.
  A shared parser now warns on the malformed value (config-review F7).
- **GA run output honors `[project].output_dir`**: `rebrew match`'s GA
  checkpoints/resume paths hardcoded `output/ga_runs` while `rebrew report`
  used the config value — the same documented option behaved differently
  per tool.  All three sites now route through a shared helper honoring
  `cfg.output_dir` (default `output`, so existing projects are unchanged).
- **Reserved/no-op config keys warn at load**: `[compiler.profiles]` is
  documented as runtime-selectable but no tool consumes it, and
  `game_range_end` is a documented legacy no-op — both silently did
  nothing.  They now emit a load-time warning so a user configuring them
  sees the no-op instead of believing it works (config-review F5).
- **`cflags = ""` means "no default flags"**: an explicitly-empty
  `[compiler].cflags` silently compiled with the hardcoded `/O2 /Gd`
  fallback, indistinguishable from an absent key.  A presence flag
  (`cflags_explicit`) now distinguishes the two — the `/O2 /Gd` fallback
  applies only when the key is absent (config-review F5).
- **Verify cache invalidates on config-level CFLAGS changes**: the cache
  entry stored only the metadata CFLAGS, so a `rebrew cfg set-cflags` or
  `[compiler].cflags` edit changed the effective flags (via the config
  fallback chain) without changing the cache key or entry guard — stale
  EXACT/RELOC kept being served while `rebrew test --all` recompiled and
  demoted.  Entries now store the RESOLVED effective flags and the hit
  check compares the freshly-resolved value; the `_compiler_config_hash`
  comment claiming "verify never reads them" was false and is corrected.
- **`rebrew cfg set-compiler` writes the `profile` key**: it previously
  wrote only command/includes/libs, so the target's profile stayed at the
  default (msvc6) — compiling with a gcc command but MSVC-style `/I /Fo`
  routing, and never engaging the posix/toolchain branches
  (config-review F1).
- **`[llm]` config section is now parsed**: documented in CONFIG.md but
  never in the known top-level keys — a `[llm]` table warned
  "unrecognized" and `cfg.llm_endpoint` was always "" (only the env-var
  fallback worked), while `match --llm-seed`'s error message pointed users
  at the dead `[llm] endpoint` key.  The table now populates
  `cfg.llm_endpoint`/`cfg.llm_api_key`.
- **`compile_to_obj` routes POSIX flags through `cfg.posix_style`**: the
  local profile tuple duplicated the config property's "single source of
  truth" — adding a POSIX profile to one list but not the other silently
  switched flag routing and broke compiles.
- **Grid status counters count PROVEN as matched**: `count_statuses` had no
  PROVEN group, so a PROVEN annotation fell into no bucket and
  exact+reloc+near+stub could undercount `totalFunctions` — the catalog's
  "Matched: N/M" line lied for proven-but-not-byte-equal functions.
  PROVEN now ranks with RELOC, matching `_STATUS_RANK` everywhere else.
- **`_compile_cflags` no longer silently drops a `/c`-less base**: a
  `base_cflags` without `/c` (e.g. a bare `/MT`) was discarded in the glue
  branch — the same silent flag-loss class the function was consolidated to
  prevent.  It is now preserved alongside the `/nologo /c` glue (caught by
  the new unit tests for all five branches).
- **`rebrew catalog` no longer fabricates coverage from a missing binary**:
  a missing target binary fell back to a hardcoded `0x24000` (92160B)
  section, and coverage was reported against that made-up denominator —
  indistinguishable from a real measurement and ingested as truth by
  build-db/dashboards (code-review F9).  The size is now 0 (coverage 0%)
  with a warning on stderr and a `warning` field in the JSON payload.
- **`catalog --summary` help matches behavior**: it claimed "Print summary
  to stdout" but every summary line goes to stderr (the console).  Help
  text corrected.
- **Batch match runs honor the documented exit contract**: `rebrew match
  --all` / `--all-targets` always exited 0 even when every stub failed —
  a false green for CI gates against the epilog's "1 = no match found".
  Both batch paths now exit `EXIT_MISMATCH` when any stub failed (mirroring
  `rebrew test --all`); dry-run is unaffected.
- **`rebrew test <multi-function.c>` honors the exit contract**: the
  multi-annotation path printed results and always exited 0, so a file of
  all-STUB functions reported success.  It now exits 1 when any function is
  unmatched and 2 on tooling (EXTRACT_ERROR) failures, matching the
  single-function and `--all` paths.
- **`--dry-run --llm-seed` no longer runs the full GA**: when no LLM
  endpoint is configured, the warning printed and control fell through to
  `ga.run()` — hours of Wine compiles despite `--dry-run`'s "preview, no
  write" promise.  It now returns after the warning.
- **`--tier bogus` errors in every mode**: tier was only validated in sweep
  paths, so `rebrew match f.c --tier nonsense` silently succeeded in plain
  GA mode.  Now validated unconditionally at invocation time.
- **Usage errors exit 2 (EXIT_ERROR), not 1**: bad `--format` values
  (diff/asm), `--decomp-body` without `--decomp`, `--watch`+`--all`, and
  missing-source errors reported exit 1 = "needs code work" — violating
  cli.py's documented rule ("a bad argument is a usage error — exit 2") and
  typer's own convention.  All now exit 2.
- **`rebrew skeleton --append` refusal exits non-zero**: appending a VA
  already in the file printed a hint and exited 0 (success) with nothing
  appended — a false signal for automation.  It now errors via `error_exit`.
- **`rebrew verify` writes the default report in plain mode**: `--output`
  help promises "default: project db_dir/verify_results.json", but plain
  `rebrew verify` wrote nothing — so a first `--compare` run had no
  baseline and silently became one.  The report (already assembled) is now
  written in plain mode too.
- **`rebrew diff --fix-blocker --json` writes the blocker once**: the
  terminal-only write ran after the JSON branch had already written it —
  redoing metadata I/O and printing status chatter against the JSON
  contract.  Guarded with `not json_output`.
- **`rebrew diff` help no longer advertises nonexistent `--mm`/`--rr`**:
  the epilog and docstring examples used flags that don't exist (the real
  ones are `-m/--mismatches-only` and `-r/--register-aware`) — copying the
  documented example failed with "No such option".
- **Calling-convention inference uses the LAST jump**: `calling_convention`
  picked the first `jmp` for ret-less functions — the extent-padded window
  can bleed into the next function, and a jmp-table dispatcher followed by
  the next function's code produced several jmps with no ret.  The terminal
  jump is now used (matching the `rets[-1]` logic), so skeleton signatures
  no longer mis-derive from a mid-body switch dispatch.
- **`--sweep-toolchain` now validates reloc targets**: the per-toolchain
  match passed `name_to_va` via a `getattr(p, "name_to_va", None)` that
  never existed — every sweep ran with reloc validation disabled, so a
  wrong-callee source could tag "EXACT" (the same false-match class the GA
  and flag-sweep paths now guard against).  The catalog map and IAT region
  are computed once and threaded in.
- **`rebrew skeleton --append` now emits convention-aware stubs**: append
  mode (the common multi-function path) silently degraded to
  `int __cdecl f(void)` — the thiscall/stdcall stub work was
  single-file-only.  `generate_annotation_block` now computes and forwards
  the convention stub like `generate_skeleton` does.
- **`rebrew describe` convention inference is extent-based**: the dossier
  disassembled a flat 64-byte window — the exact bug skeleton.py already
  diagnosed (longer functions truncated mid-code → "unknown" → wrong
  cdecl default).  A shared `asm.calling_convention_at` helper (extent-
  derived window) now serves both.
- **verify's "once per process" logic hash actually caches**: the
  `lru_cache` decorated a nested `_hash()` re-created on every call, so the
  full-package source hash was recomputed on every verify run despite the
  docstring claim.  The decorator now sits on the outer function.
- **`rebrew data --fix-bss` is idempotent on re-run**: the generated
  `bss_padding.c`'s own `// DATA:` annotations close the gaps they fill, so
  a second run's gap scan reported fewer gaps — regenerating from scratch
  deleted the first run's arrays while `rebrew-data.toml` still claimed
  coverage (idempotency-review F4).  Existing auto-generated declarations
  are now merged with new gaps, and the file is written BEFORE its metadata
  so a crash between the two can never leave metadata claiming coverage the
  source does not declare.
- **`rebrew catalog` refreshes its own `function_structure.json`**: the
  compatibility export was written once (`not exists()` guard) and never
  refreshed, so re-discovery left a stale structure cache diverging from
  the freshly-written data JSON.  Catalog-generated entries are now stamped
  `_generated_by: "rebrew catalog"` and refreshed on re-run, while a REAL
  Ghidra export (no marker) is never overwritten.
- **`verify --watch` picks up files created during the session**: the
  watched set was captured once at startup, so a `.c` generated mid-session
  (e.g. `rebrew skeleton` for a newly discovered function) was never
  covered.  `watch_files` gains an optional `path_provider` that re-resolves
  the set every poll; verify passes one.
- **GA / flag-sweep "matches" are now validated like test/verify before
  promoting**: both the batch flag sweep and the GA splice promoted
  EXACT/RELOC on the reloc-masked score alone (`score_candidate` masks
  every reloc slot, so a candidate differing only in a call/mov
  displacement scored 0.0 without checking the reloc TARGET against the
  catalog).  A wrong-callee source could be promoted and immediately
  demoted by the next test/verify.  Each match is now confirmed with an
  authoritative `compile_and_compare` (with `name_to_va` + `section_va`)
  before STATUS is touched; unconfirmed sweeps report the flag and skip
  promotion.
- **`rebrew match` STATUS promotions now sync the verify cache**: the GA
  splice (STUB → RELOC) and batch flag-sweep EXACT promotion previously
  left `.rebrew/verify_cache.json` holding the stale pre-match entry, so
  `rebrew status`/`todo` contradicted the fresh metadata until the next
  full verify.  Both now call the shared `patch_verify_cache_entries`
  (identity-checked + cross-process locked), the same helper `rebrew test`
  uses — one implementation behind every promotion site.
- **`rebrew verify` labels pre-compile failures correctly**: an `INVALID_VA`
  (below the valid floor) was reported as COMPILE_ERROR — a bogus "compile
  error" in the summary that tripped the CI gate as if the source failed
  to build.  It now has its own `INVALID_VA` status (ranked with the
  MISSING_* annotation problems), and "Cannot extract DLL bytes" is
  `EXTRACT_ERROR` (the stage label compile.py already uses), so neither
  blames the `.c` file.
- **`rebrew skeleton --decomp-body` without `--decomp` is rejected**: the
  flag was accepted-but-inert, silently producing a plain stub.  It now
  fails with "requires --decomp" and writes nothing.
- **Legacy-encoded `.c` sources compile again**: sources are read with
  `decode("utf-8", errors="surrogateescape")` (lossless for cp1252/
  shift_jis bytes), but the compile-cache key re-encoded with strict
  `utf-8` — raising `UnicodeEncodeError` for any non-UTF-8 source, which
  `compile_and_compare` mislabeled as COMPILE_ERROR.  Every legacy-encoded
  file was permanently untestable and `verify` demoted its STATUS.  The
  digest now round-trips with `errors="surrogateescape"`.
- **`rebrew intake` on an existing project no longer resets the corpus**:
  re-discovery called `classify_all` with every function, writing
  STUB + auto-blocker for each — silently demoting EXACT/RELOC/
  NEAR_MATCHING back to STUB and clobbering user-written BLOCKERs
  (the `size` write already had a "never clobber" guard; status/blocker
  did not).  Non-STUB entries are now skipped and user blockers survive.
- **`rebrew test file.c --va X` promotes under the right module**: with
  `--symbol` given, the VA-based annotation selection was skipped entirely,
  so SIZE/CFLAGS/STATUS were written under the FIRST annotation's module —
  a phantom `(first_module, X)` key while the real entry stayed stale in
  multi-module files.  VA selection now happens unconditionally.
- **`rebrew split` (full mode) validates all outputs before writing any**:
  the interleaved check-then-write aborted mid-batch on the first existing
  output, leaving earlier blocks written — and every re-run then failed on
  block 1's now-existing file, so the split could never complete without
  `--force`.  Two-phase: every conflict is reported up front, nothing is
  written on any conflict (rename.py's pattern).
- **verify-cache patching is identity-checked and locked**: `rebrew test`
  patched `.rebrew/verify_cache.json` by VA only — in a multi-target
  project, `test -t CLIENT` could patch entries a `verify -t SERVER` wrote
  (and the next SERVER verify would serve CLIENT's status).  The patch now
  verifies the cache's target + compiler identity, and both the patch and
  `verify`'s save run under a shared cross-process lock (mirroring
  metadata.py's flock discipline).
- **`rebrew switch` stops at non-image table entries**: the case walk now
  halts at the first dispatch-table entry that is not a code address in the
  image, even when a bounds check suggests more — a misread/over-estimated
  `cmp reg, N` previously dragged garbage into the case list (observed on
  the mspaint corpus: a table with 7 real cases but a `cmp 0xb` bound).
- **`rebrew skeleton` warns on merged discovery entries**: a `functions.txt`
  entry that spans several functions (multiple ret-terminated epilogues
  within the declared size — e.g. the mspaint corpus's 53B entry covering
  three tiny functions) is flagged with "spans multiple functions — split
  into per-function files", so the user doesn't treat a merged region as
  one decomp target.  Single functions (including early-return bodies) are
  unaffected.
- **GA STATUS promotion runs only after the source write succeeds**: in
  `update_stub_to_matched` the `update_source_status(…, "RELOC")` call ran
  BEFORE `atomic_write_text` — a failed write (disk full, read-only dir)
  left `rebrew-function.toml` claiming RELOC on a `.c` whose body was still
  a stub, a false green until the next verify self-healed.  The promotion
  now happens after the write, matching the function's documented contract.
- **`rebrew verify` no longer counts tooling crashes as code regressions**:
  a worker exception now gets its own `INTERNAL_ERROR` status — excluded
  from the `--compare` regression/improvement classification and from the
  code-failure list, so a transient crash on a previously-EXACT function
  can never fail the CI gate as a false code regression.  The count is
  still surfaced in the run report.
- **`rebrew test` (multi-function) labels post-compile failures
  EXTRACT_ERROR instead of crashing the batch**: a LIEF raise on a
  malformed `.obj`, or a VA yielding no target bytes, previously aborted
  the whole file with a traceback (no JSON, wrong exit).  Each symbol now
  records an `EXTRACT_ERROR` row and the batch continues, mirroring
  `compile_and_compare`'s stage labeling.
- **`rebrew test` metadata writes are no longer silent**: the SIZE/CFLAGS
  persistence sites used `contextlib.suppress(Exception)` — a failed write
  (read-only metadata, corrupt TOML) was invisible while downstream
  `rebrew diff`/`verify` later failed with no link to the cause.  They now
  log a warning naming the VA and the consequence, matching `verify`'s
  metadata-write handling.
- **`iat_slot_vas` failures are surfaced**: the LIEF IAT scan swallowed
  every exception and returned `set()` — indistinguishable from "no IAT",
  which silently disabled IAT reloc masking and demoted true RELOC matches.
  A raised failure now logs a warning.
- **`rebrew verify` cache invalidation now covers the whole package**: the
  verify-cache logic hash was a hand-maintained list of six modules that had
  already drifted (reloc validation, IAT masking, flags, compiler env are
  all result-affecting but unlisted).  It now hashes the entire `rebrew`
  package source, so a fix to any comparison-affecting module invalidates
  caches written by the pre-fix build.
- **Batch GA degradations are visible**: flag-sweep failure (falling back to
  stub cflags), solution-list load failure (disabling `--seed-from-solved`),
  and per-stub seed lookup failure were logged at DEBUG — invisible in the
  headline `rebrew match --all` workflow.  All three now log at WARNING, so
  a run that was not sweep/seed-informed says so.
- **`build_name_to_va` scan failures are surfaced**: the global/function
  catalog scan returned `{}` on any failure — indistinguishable from
  "nothing to validate", so verify/test silently skipped reloc validation
  and wrong-callee calls could pass as RELOC.  The failure now logs a
  warning naming the cause.
- **`rebrew analyze` no longer aborts the whole dossier on an import record
  without `iat_va`**: the entry list did an unguarded `rec['iat_va']` —
  a KeyError/TypeError there escaped the per-section guards and the caller
  reported "Analyze failed", violating the module's contract that one
  broken backend never aborts the others.  The field now defaults to 0.
- **`rebrew verify` uses bounded pool submission**: it previously submitted
  every entry to the ThreadPoolExecutor up front — the exact pattern
  flag_sweep was deliberately changed away from (compiler.py).  It now
  submits `jobs` at a time and refills as each completes, so memory stays
  proportional to the worker count, not the corpus size (thousands of
  futures on large batches).  A regression test covers batches larger than
  the worker count.
- **`load_ga_runs` keeps only the newest `limit` records**: the GA-run log
  reader held the entire (unbounded, append-only) history in memory before
  trimming to `limit` — `--ga-history` and batch `--skip-recent` read it
  every run.  A bounded deque (applied after target filtering, so "limit"
  still means "up to limit records for this target") bounds memory without
  changing results.
- **`rebrew describe` scans `.text` once instead of twice**: the dossier
  ran `scan_references` for callers/globals/imports and then `string_refs`
  re-ran the same full-section disassembly for the strings section.  The
  string refs are now filtered from the already-computed reference pass
  (identical output, verified by an equivalence test) — a per-dossier
  full-`.text` disassembly saved on every `describe`/`analyze --function`
  call.

- **Tail-calling functions no longer misclassified as pure thunks**: a
  function whose jmp-terminated disassembly has a real body (>2 insns) is
  now classified `tail call` — a forwarding function — instead of
  `tail-call thunk` (the "implement as a naked asm tail-jump" note was
  wrong for it).  `rebrew skeleton` resolves the jmp target's decorated
  name (`name@N`, via the function lookup) to emit the correct
  `int __stdcall f(int a1, ...)` signature with a "N stack arg(s)
  forwarded" note; unresolved targets get a plain signature + guidance.
  Pure 1-2 insn thunks (`jmp [IAT]`, `mov ecx,imm; jmp`, `push; jmp`)
  keep the thunk classification.
- **Toolchain round-trip tests run ~14x faster with wibo**: the suite's
  compile tests hardcoded `wine`; they now prefer wibo when available
  (headless, no wine boot — the round-trip suite dropped 23.3 s → 1.6 s)
  and fall back to wine.  CI installs wibo best-effort before the test
  job, so the recommended runner is exercised in CI and the suite stays
  fast there.  `tools/wibo` is now gitignored.
- **Fresh skeletons classify as STUB, not a bare SIZE_MISMATCH**: a minimal
  candidate body (the skeleton's default `return 0`, ~3-8 bytes) against a
  much larger target is an unimplemented stub — `rebrew test` now reports
  STUB with a message naming both sizes ("the skeleton default was never
  implemented") instead of a confusing SIZE_MISMATCH.  Genuinely tiny
  functions byte-match (EXACT/RELOC) and never hit this path; near-size
  mismatches still report SIZE_MISMATCH.  `classify_compare_result` gained
  a `full_target_size` kwarg (the caller truncates the longer side before
  classifying, so the original lengths must be threaded explicitly).
- **`rebrew skeleton` warns on stale sizes**: the generated file's size (and
  the `--size N` in the suggested test command) comes from the Ghidra cache
  / function registry, which can hold a stale `functions.txt` entry.  When
  the disassembly extent runs past the resolved size, skeleton now warns
  with the real extent and points at `rebrew asm --size <extent>` /
  `rebrew test --fix-size` — previously the first `rebrew test` failed with
  SIZE_MISMATCH on a truncated size and the user had to rediscover the
  discrepancy by hand.  JSON output gains a `size_warning` field — in
  single-VA mode and per item in `--batch` mode (with a console warning
  line per stale function).
- **GA/flag-sweep never accepted RELOC matches**: `score_candidate`'s byte
  score counted relocation bytes as raw mismatches, so a candidate whose
  only diffs were at reloc sites (linker-determined call displacements)
  sat at a fitness floor of ~N×1000 and the `exact: score < 0.1` gate
  never fired — the GA kept mutating a byte-perfect candidate and flag /
  toolchain sweeps reported no match for RELOC-able functions.  The reloc
  mask now applies to the byte score too; a reloc-only match scores ~0 and
  is accepted.  Real mismatches outside reloc sites still count.
- **`rebrew asm` detects stale function-list sizes**: a size that truncates
  the function mid-code (stale `functions.txt` entry) now warns and extends
  the dump to the disassembly extent — previously the dump silently ended
  mid-instruction, which also broke the calling-convention inference
  (truncated window → "unknown" → wrong skeleton signature).  An explicit
  `--size` is honored (warn-only); the JSON report gains a `stale_size`
  field (`requested_size` keeps the pre-extension value).  x86-32 only —
  the extent walker is an x86 disassembler.
- **`rebrew skeleton` convention stub no longer truncates long functions**:
  the calling-convention window was a flat 48 bytes, so a function whose
  real body extended past it got the wrong default (`__cdecl` instead of a
  thiscall/stdcall shape — e.g. an MFC `ret 0x10` method with a 100+ byte
  body was emitted as `int __cdecl f(void)`).  The window is now the
  disassembly extent: exact when it terminated on a `ret`, padded past a
  mid-function branch-merge `jmp` (small ≤16 B jmp regions stay exact —
  they are real tail-call thunks).  `function_extent_from_disasm` gained a
  non-breaking `with_kind=True` returning `(extent, "ret"|"jmp")`.
- **Relative runner paths now anchor to the project root**: the config
  shape `rebrew init --install-wibo` writes (`runner = "tools/wibo"`,
  command without the runner prefix) previously broke under the temp
  compile workdir with "No such file or directory: 'tools/wibo'".  Both
  the `rebrew compile` path and the GA/flag-sweep path (via
  `REBREW_COMPILER_RUNNER`) resolve relative runner paths against the
  project root now, and `WINEDEBUG` is set by runner basename
  (`tools/wibo` is still wibo).
- **`rebrew doctor` false "CL.EXE not found"**: the Compiler check now
  honors the install-tools fallback used by `resolve_cl_command`, so
  projects without a local `tools/` symlink (fresh `rebrew init`, no
  `--link-tools-from`) report the compiler as reachable instead of a FAIL
  that contradicts working compiles.
- **`rebrew skeleton` emits calling-convention-aware stubs**: the generated
  skeleton now matches the target's convention instead of always being
  `int __cdecl f(void)` — `int __fastcall f(void *self)` for thiscall with
  no stack args, a `__declspec(naked)` template (with `ret N`) for
  thiscall-with-stack-args on MSVC 5.0 (no `__thiscall` keyword), and
  `int __stdcall f(int a1, ...)` for stdcall with N args.  Thunks get a
  note pointing at the naked tail-jump.  For MFC-heavy binaries (most
  functions are thiscall) this removes the per-function signature rewrite.
- **`rebrew asm` calling-convention inference**: both the hex dump and
  `--json` now report the function's calling convention (cdecl / stdcall /
  thiscall / thiscall-with-no-stack-args / ctor thunk / EH-guard thunk),
  derived from the epilogue (`ret` vs `ret N`) and this-pointer usage (ECX
  dereferenced or saved to a callee-saved register without a prior memory
  load).  This is the per-function answer that decides the C signature —
  `__stdcall`, `__fastcall` this-emulation, or naked asm for
  thiscall-with-stack-args on MSVC 5.0 — before writing any code; it was
  previously re-derived by hand from every function's epilogue.
- **MSVC optimization-level fingerprint**: `detect_toolchain` now inspects
  .text for wrapper-call codegen and reports the optimization level the
  binary was built with — `/O2` (load-first `mov eax,[esp+4]; push eax` +
  `add esp,N`) vs `/O1` (push-[mem] `push dword [esp+4]` + `pop ecx`), or
  `mixed` when both styles appear (per-file /O overrides, common in MS
  products).  `/O1` vs `/O2` change wrapper codegen, so the wrong level
  silently breaks byte-matching at every wrapper call site.  Surfaced in
  `rebrew analyze`, seeded into `rebrew init`'s compiler cflags, and
  checked by a new `rebrew doctor` Optimization-level check (warns on
  mismatch, suggests per-function flag sweeps for mixed builds).
- **`rebrew test --fix-size`**: corrects a stale SIZE annotation when ALL
  common bytes match — writes the compiled size into `rebrew-function.toml`
  and reclassifies as EXACT/RELOC (with promotion) in one command, instead
  of surfacing a `SIZE_MISMATCH` the user must resolve by hand.  Works in
  both the single-function and multi-function paths; `--dry-run` previews;
  file-scoped (batch repair stays `rebrew verify --fix-sizes`).  `CompareResult`
  gains `full_obj_size`/`full_obj_bytes` so the SIZE_MISMATCH path reports
  the real compiled length in JSON/display instead of the common-prefix
  slice, and the SIZE_MISMATCH hint now points at `--fix-size`.  The fix is
  gated on an evidence check: when the compiled function is longer than the
  annotated slice the binary is re-extracted at the compiled size and the
  newly visible bytes must match; when it is shorter the excess annotated
  bytes must be padding — a false fix (partial decompilation matched only
  over the prefix) would otherwise write a size that hides unreproduced
  code.  When those checks refuse (a discovery boundary merged the NEXT
  function into the annotation, so the excess bytes are real code), the
  gate falls back to the disassembly extent — the authoritative function
  end via `binary_loader.function_extent_from_disasm` — and fixes only if
  it agrees with the compiled size.  This automates the merged-boundary
  thunks (e.g. `mov ecx,X; jmp Y` ctor stubs) that previously needed a
  hand-supplied `--size`.
- **watcom is POSIX-style**: `ProjectConfig.posix_style` now includes
  watcom (wcc386 takes `-I`/`-fo=`/`-zq`).  Previously the flag routing
  treated it as MSVC-style and prepended `/nologo /c` glue — wcc386 then
  failed with "E1139: more than one file to compile" in `rebrew diff`
  (which also wasn't passing profile/cfg to the toolchain-backed compile
  runner).  diff/match/compile now route watcom through the shared
  `compile_to_obj` runner; verified test/diff/GA-sweep on a watcom
  project.
- **verify: 16-bit NE targets with the msvc1.52 profile now run the full
  pipeline** — the old gate short-circuited every NE target with a stale
  "16-bit matching is future work (ADR-001)" notice, silently hiding the
  DOSBox compile + omf16 object pipeline.  The skip now fires only when
  no 16-bit profile (`msvc1.52`) is configured, with a message naming the
  required profile.  Verified on the skifree16 NE project: 137 functions
  compile through DOSBox with 0 COMPILE_ERROR (was: skipped entirely).
- **IAT/jmp-stub reloc masking**: `build_iat_region` now also includes
  the configured `iat_thunks` (jmp-stub trampolines, `ff 25 <addr>` in
  `.text`) — functions calling *through* a stub dereference the stub
  address, not the IAT slot, so those DIR32 values must be masked too.
  `smart_reloc_compare` masks any DIR32 whose target lands in the merged
  region even when the catalog symbol maps elsewhere.
- **IAT-aware reloc masking**: `smart_reloc_compare` accepts an
  `iat_region` (the PE import-address slots, via new `build_iat_region`)
  and masks DIR32 relocs whose target value lands there even when the
  catalog maps the symbol to a different VA — swapped ordinal import
  names (e.g. WS2_32 WSAStartup/WSACleanup) no longer demote a RELOC
  match into a byte mismatch.  Fixes the guild-rebrew CreateListenSocket
  regression (NEAR_MATCHING → RELOC, 411/419 → 419/419).
- **Toolchain standardization (docker-first)**: `rebrew.toolchain` — a
  uniform spec registry + runner modeled on Godbolt's Compiler Explorer
  (one image per toolchain-version, wrapper inside the image, uniform
  `docker run <image> <compiler> <args>`; host-path/PATH fallback when
  docker or the image is unavailable), the `rebrew toolchain` CLI
  (`list`/`status`/`pull`), and `toolchain-images/<name>/Dockerfile` build
  specs.
- **Open Watcom profile**: Open Watcom 2.0 installed at `tools/WATCOM`
  (native Linux `wcc386`, verified compiling; emits OMF objects — the OMF
  parser is the documented enabling follow-up in `docs/OMF_NOTES.md` with
  the empirically-mapped record layout).
- **MSVC 1.52 (16-bit) profile**: `tools/MSVC152` (archive.org
  `en_vc152_202512`) + `rebrew.msvc16.compile_c` — the Phar Lap TNT
  CL.EXE runs headless under DOSBox via the new shared `rebrew.dosbox`
  runner (refactored out of `delphi16`), producing 16-bit OMF objects.
- **Detection hints**: Symantec C++ / Zortech C++ / Intel C++ families
  identified from runtime strings (dossier + blocker wording); Watcom
  family now aligns with the `watcom` profile in doctor; `msvc1.52` joins
  the msvc-compatible profile set.
- **Watcom flag sweep**: `generate_flag_combinations` supports the watcom
  profile (wcc386 `-`-style flags: opt/codegen/pack/flat axes) — the GA's
  `--flag-sweep` works for watcom projects.
- **doctor toolchain check**: generic `check_toolchain_backed` reports how
  the watcom/msvc1.52 toolchains resolve (vendored binary / pulled image)
  with a `rebrew toolchain pull` fix — no more misleading "not in PATH"
  for vendored compilers.
- **msvc1.52 compile-loop prefers the docker image** (cl16 wrapper) when
  pulled, falling back to the host DOSBox sandbox; FAT-uppercased .OBJ
  handled in compile_to_obj.
- **16-bit OMF parser** (`rebrew.matcher.omf16`): MSVC 1.52's OMF dialect
  (objconv crashes on it) decodes code from `0xA0` records + publics from
  MODEND — `parse_obj_symbol_and_relocs` extracts 16-bit function bytes
  (relocs `{}` pending 0x8C/0xB2 fixup decoding).
- **Symbol lookup across compiler conventions**: `parse_obj_symbol_and_relocs`
  tries `_name` / `name_` / `name` variants — the annotation layer derives
  MSVC-style leading-underscore symbols, but wcc386 emits trailing
  underscores (`callg_`); validated end-to-end with a watcom `rebrew test`.
- **Watcom usable in the compile loop**: `rebrew compile` routes the
  `watcom` profile through the toolchain runner (wcc386 `-fo=`/`-I` shape,
  docker image or vendored binary) and `msvc1.52` through
  `rebrew.msvc16` — `rebrew test`/`verify` now work for those targets.
- **Docker-first toolchain verified**: `rebrew/watcom:latest` image built
  from `toolchain-images/watcom/Dockerfile` (snapshot tarball — the
  installer SIGFPE workaround); `run_toolchain` compiles through it with
  byte-identical results to the host path (same reloc offsets).  Image
  entrypoint convention documented (`image_binary=None` = ENTRYPOINT is
  the compiler).
- **OMF support via objconv**: vendored `tools/objconv` (Agner Fog's
  object-file converter) converts OMF→COFF, so `parse_obj_symbol_and_relocs`
  now handles **Open Watcom 32-bit OMF** objects transparently (reloc
  offsets verified on the e8/a1 slots of a real wcc386 object).  objconv
  crashes on 16-bit OMF — MSVC 1.52 matching still needs the custom 16-bit
  parser (docs/OMF_NOTES.md).
- **ADR documentation**: architectural decisions now recorded in
  `docs/adr/` (Nygard format) — native NE parsing, NE function-enumeration
  conventions, the import-degradation policy, intake stale-stub pruning,
  and toolchain-detection ordering; the convention itself is in
  `AGENTS.md` so it stays maintained.
- **16-bit Windows NE support** — `holiday.exe` (Borland Delphi 1.0,
  NE 6.01) can now be onboarded and analyzed end-to-end:
  - `rebrew.ne_loader`: NE header/segment-table/resident-name/module-table
    parsing; segments map to `BinaryInfo` sections with synthetic flat VAs
    (`segment << 16 | offset`); a capstone probe classifies code vs data
    segments (Borland marks all segments identically).
  - `load_binary` parses NE natively (the old "16-bit not supported"
    rejection is gone); `x86_16` arch preset (CS_MODE_16) drives asm/similar/
    cu_map.
  - `enumerate_ne_functions`: Delphi 1.0 linear sweep (push bp / enter
    prologs, ret/retf epilogs) — 646 functions on holiday.exe.  `rebrew
    intake` uses it for NE targets instead of rizin.
  - `iter_strings`: NE targets scan data segments and recognize Pascal
    (length-prefixed) strings — holiday.exe yields 3739 strings (German UI).
  - `rebrew analyze` reports NE imports as module blocks and the toolchain
    family (delphi).
- `rebrew intake` fixes: skips `rebrew init` when the project already exists
  (idempotent re-runs), and `classify_all` batches its metadata writes
  (set_fields_batch + update_statuses_batch) — a 646-function intake dropped
  from ~5 minutes (timeout) to 3 seconds.
- `rebrew verify --fix-sizes` now backfills **missing** annotation SIZEs,
  not just stale ones: intake/documented stubs without a SIZE (which
  `rebrew test` refused with "Invalid SIZE: 0" and verify reported as
  MISSING_SIZE forever) get the binary-derived canonical size written into
  metadata.  Reported separately as `missing_sizes` in the JSON report.
- `rebrew intake` / `rebrew document-unmatched` record the
  disassembly-derived SIZE in metadata when documenting stubs, so newly
  documented functions are testable out of the box.
- `rebrew todo` no longer surfaces a MISSING_SIZE stub's vacuous 0-byte
  delta as a fake "0B diff" fix-delta quick-win — it classifies as
  missing-annotation with the `rebrew verify --fix-sizes` self-heal
  command.  IAT thunks / Delphi stubs (blocker-marked documented
  non-targets) move to a new audit-only `documented` category, hidden from
  the actionable list but visible via `rebrew todo -c documented` and
  counted in coverage stats / JSON.
- `rebrew analyze <binary>` now works **standalone outside a project** —
  the binary argument becomes required when no `rebrew-project.toml` is
  found. Project-scoped sections (FLIRT sigs, library headers, near-match
  metadata) degrade to `null`/`[]` instead of aborting, so the dossier is
  usable as the first intelligence step on an unknown binary (the use
  case it was built for). Clear error when neither a project nor a binary
  is given.
- `rebrew document-unmatched` — standalone version of intake's
  document-unmatched step: writes a STUB `.c` + BLOCKER/STATUS=STUB
  metadata for every function in the function list that isn't already
  documented (skips VAs with a `fcn_<va>.c` file or a FUNCTION/STUB
  marker; idempotent; `--dry-run`/`--json`).  Replaces the per-project
  classify scripts (bench/cpubench/makehm/openmiles) for re-discovery
  workflows.  The shared writers (`classify_all`/`blocker_reason`) were
  promoted to public in `rebrew.intake`.
- Vendored the Borland **Delphi 1.0 16-bit command-line toolchain**
  (`tools/DELPHI10/`, exact compiler family for 16-bit Delphi apps like
  `holiday.exe`): the `CMDLINE.PAK` tools plus the compiler symbol table
  `DELPHI.DSL` (required — without it DCC reports a phantom
  "SYSTEM.DCU not found" even though no such file ships anywhere in the
  product; System/WinTypes/WinProcs resolve from the built-in symbol
  table). Proven working: `DCC.EXE hello.dpr` compiles a real 16-bit NE
  6.01 Windows 3.10 GUI executable that runs under wine.
- `tools/DELPHI10/pak_extract.py` — a from-scratch, stdlib-only decoder
  for the **Quantum archive format** (David Stafford / Cinematronics
  1993-95; also a Microsoft CAB method) reverse-engineered from the
  Delphi 1.0 floppies: arithmetic-coded LZ77, 9 adaptive models, 2^10-2^21
  window, split-archive support (`.CA1`+`.CA2` concatenation). Validated
  byte-for-byte against the original Quantum GUI output (16/16 files) and
  the independent `unquantum` reimplementation.
- `rebrew match`'s no-match exit now guides the user to `rebrew prove`
  (register/structural gaps are often PROVEN-able) and
  `rebrew near-diag --fix-blocker` (classify + document) instead of
  exiting silently.
- smygb fully resolved: `prove --loop-bound 50` promoted the last
  NEAR_MATCHING (0x00401410, a loop 'no terminal states' failure) —
  the project now has ZERO NEAR_MATCHING functions (EXACT 17 / RELOC
  26 / PROVEN 7). The prove guidance documents the loop-bound retry.
- 16-bit Windows NE executables are detected explicitly
  (`binary_loader.is_ne`) and rejected with a clear format-specific message
  instead of a misleading "Failed to parse PE". The path to full 16-bit
  support (NE parser, x86-16 disasm, MSVC420 compile profile) is documented
  in docs/TOOLCHAIN.md.
- `rebrew near-diag`'s register verdict suggestion now leads with
  `rebrew prove` (register gaps are usually PROVEN-able without byte
  changes — validated on the corpus: 9 NEAR_MATCHING promoted to PROVEN).
- `rebrew near-diag` mutation guidance now includes a significant secondary
  category's operators (>=15% of the delta, e.g. the register component
  under a STRUCTURAL verdict) — the dominant-only list missed the register
  fix entirely for mixed deltas.
- `rebrew diff` reports a **missing_tail** summary when the compiled
  candidate is shorter than the target: how many target instructions are
  not yet decompiled + the first/last missing instruction (JSON
  `missing_tail`, terminal hint) — turns SIZE_MISMATCH triage into an
  actionable "write these next" list.
- `rebrew analyze` dossier gains a **NEAR_MATCHING (blocked)** section —
  every NEAR_MATCHING function with its blocker guidance (verdict + GA
  mutation operators) in JSON, Markdown, and terminal output.
- `rebrew report` function table gains a **Blocker** column — near-diag /
  diff-written blockers (with their GA mutation suggestions) now appear in
  the static HTML index page, making the project's documentation carry the
  same guidance as `rebrew todo`.
- `rebrew match --mutation-focus register|equivalent|structural|auto` — bias
  GA mutation selection toward a near-diag category: the category's suggested
  operators (from `rebrew.near_diag._MUTATION_SUGGESTIONS`) get 6x selection
  weight. `auto` derives the category from the function's BLOCKER metadata
  (single-function mode). Closes the classify → focus → GA loop: near-diag
  writes the blocker, todo surfaces the mutations, match acts on them.
- `rebrew todo` exposes the GA mutation operators suggested by a
  near-diag-written blocker as a structured `mutations` field (JSON output)
  and a `[try: ...]` terminal hint — an agent working from `todo --json`
  sees the next GA operators without re-running near-diag.
- `rebrew near-diag --fix-blocker` now writes the top GA mutation operators
  into the `BLOCKER` metadata (before the suggestion prose) — a reader
  acting on the blocker sees the actionable next step without re-running
  near-diag. The suggestion's first sentence survives when the 200-char
  metadata budget allows.
- `rebrew near-diag --all [--fix-blocker]` — classify (and optionally
  auto-document as `BLOCKER` metadata) every `NEAR_MATCHING` function in the
  project in one batch run; per-function compile/extract failures are recorded
  and the batch continues (mirrors `rebrew prove --all`).
- `rebrew discover-functions <binary>` — chained function enumeration: rizin
  `aaa` → `aa; aap` → a capstone linear sweep (post-padding starts, `push ebp;
  mov ebp, esp` prologues, direct-call targets), merged with boundary
  validation (interior candidates dropped) and gap-based sizes trimmed of
  padding — fixing both rizin's garbled `aaa` merges and its short sizes
  (e.g. 34 → real 36).
- `rebrew lint` W020 is now status-aware: an asm-dump body (`__asm`/`__emit`)
  with a non-stub `STATUS` claim (EXACT/RELOC/...) escalates to "cannot be a
  byte-match — fix the STATUS or mark BLOCKER", telling documented STUB
  placeholders apart from claimed matches at a glance.
- `rebrew analyze` dossier gains a **library** section — which VAs are
  library glue (via the identify-library backends), in JSON + Markdown.
- `rebrew prove --all --max-delta N` — bound the batch to near-misses whose
  recorded byte delta is ≤ N, focusing Z3 time on the closest matches.
- `rebrew match --all-targets` splits `--jobs` across targets (parallel
  targets, per-target determinism preserved) when there is more than one
  target and jobs to share.
- `tools/verify_baseline.py` — committed-baseline regression gate
  (`--snapshot` / `--check`) over `db/verify_results.json`; exits 1 when
  byte-matched drops below the committed baseline.
- `docs/CAMPAIGNS.md` — record of bounded corpus matching campaigns
  (first entry: smygb pipeline smoke: skeleton → single GA → batch
  `--resume`; library pass wrote 28 entries across 6 module headers).
- Property tests for the new parsers: `apply_param_names`/`param_names_from_proto`
  arity/named-preservation invariants and `_module_from_sig_file` attribution.
- `rebrew near-diag --fix-blocker` — writes the verdict as `BLOCKER` metadata
  (skipped on a match), closing the classify → document loop.  Live-verified
  on smygb 0x401370 (register-gap blocker auto-written).
- `rebrew near-diag`'s register-category suggestions now include
  `mut_hoist_repeated_deref` (the kept-live-local operator).
- GA mutation `mut_hoist_repeated_deref` — hoists a repeated absolute-pointer
  deref (`*(T*)0xADDR` used N times) into a kept-live local.  Campaign-driven:
  the register-only NEAR_MATCHING gap on smygb 0x401370 (100% mnemonic match,
  21 register diffs) needs exactly this shape; documented in
  `docs/GA_MUTATIONS.md`.
- `rebrew skeleton --decomp-body` — writes the decompiled C as the function
  BODY (renamed to the marker's function) instead of a comment block, giving
  the GA a real seed when a decompiler backend is available.
- decomp.me flag DB re-synced (`tools/sync_decomp_flags.py`): no semantic
  changes since the last sync; all vendored toolchains still pass
  `tests/test_toolchain_roundtrip.py` byte-exact.
- `rebrew near-diag` now suggests the specific `mut_*` GA operators most
  likely to fix each blocker category (register/equivalent/structural) —
  advisory mapping surfaced in terminal + JSON `mutations`, documented and
  enforced (every category has operators, every operator exists).
- `rebrew sync --pull-params` — pulls Ghidra parameter names (via
  `get-decompilation`) into unnamed parameters of local `.c` files,
  merge-safe: named params never overwritten, arity mismatch / function-
  pointer params skipped.  Local names already flow back via
  `set-function-prototype` (push covered by existing tests).
- `tools/corpus_sweep.py` — run doctor/analyze/identify-library/status across
  every `*-rebrew` project; documented SKIPPED/BLOCKED projects (per AGENTS.md)
  are honored.  Corpus run found + fixed: `msvc5` missing from the
  profile-compat table (bind doctor failure) and hgb's undocumented Delphi
  blocker.
- `rebrew identify-library --build-sigs [--lib-dir]` — generates
  `flirt_sigs/<lib>_vc6.pat` from the toolchain's `.lib` files (case-insensitive
  `.LIB` glob; one corrupt lib never aborts the batch).  Measured on smygb:
  262 sig files, identification yield **6 → 28 (4.7×)**.
- Per-sig-file module attribution for FLIRT hits (`msvcrt_vc6.pat` → MSVCRT,
  `zlib_vc6.pat` → ZLIB) plus a zlib name-prefix fallback (`deflate`,
  `inflate`, `crc32`, ...).
- `rebrew solutions [--symbol S] [--min-size N] [--max-size N] [--best]` —
  query the GA solutions database; `--best` shows the best-known GA outcome
  per function from the run history.
- `rebrew match --llm-seed --dry-run` — previews the exact LLM prompt and the
  validated-seed count without running the GA (`--dry-run` single-function is
  now allowed only with `--llm-seed`).
- `rebrew match --all --resume` — per-function GA checkpoints (`GACheckpoint`
  in matcher/core.py, written every generation to `output/ga_runs/.../
  checkpoints/`); interrupted batches continue from the checkpointed
  generation, rejected when source/params changed (args_hash).
- Corpus-driven fixes (found running the new tools on the smygb corpus
  project): `rebrew analyze` crashed on real binaries with dispatch tables
  (`DispatchTable` fields renamed) — now emits `entries`/`resolved`/`section`
  and is regression-tested; `rebrew identify-library` labeled DirectX imports
  as MSVCRT — import-stub modules now come from the import table's DLL
  (DDRAW → DDRAW, KERNEL32 → KERNEL32) with the name heuristic as fallback.
- Docs-hygiene meta-tests (`tests/test_docs_hygiene.py`): every lint code
  emitted by `lint.py` must be documented in `docs/ANNOTATIONS.md`, and every
  registered CLI command must have a `docs/CLI.md` section — drift is caught
  in CI.  Fixed the gaps it found (CLI.md gained `asm`/`imports`/`resource`/
  `status` sections) and refreshed `docs/IDEAS.md` (done items marked,
  completed backlog appended).
- Recoverage schema-parity contract test (`tests/test_recoverage_contract.py`):
  runs the real `catalog --data-json` → `build-db` pipeline on the fixture
  binary and asserts the SQLite schema has every table/column the recoverage
  dashboard queries (cells `label`/`parent_function`, `verify_results`,
  `section_cell_stats` view) — a rebrew change that would break the dashboard
  is caught in rebrew's own suite.
- GA scoring fast paths in `score_candidate` (behavior-identical): identical
  bytes skip candidate disassembly entirely; mnemonic-equality (the GA's
  common immediates-only-differ case) skips `SequenceMatcher`'s setup.  Measured
  1.76× faster on a realistic 5000-candidate mix; documented in
  `docs/PERFORMANCE.md` along with what was tried and rejected.
- Idempotency sweep extended: `tools/check_idempotency.py` now covers all 16
  offline `--json`/`--dry-run` commands (mirroring `tests/test_json_purity.py`),
  gains a `--fixture-dir` mode that assembles the checked-in fixture project,
  and runs as a CI step after the test suite.  (The CI test matrix already
  exercised 3.12/3.13/3.14.)
- `rebrew analyze --output report.md` — writes the dossier as a Markdown
  report; `--function 0xVA` drills into one function (callers, callees,
  strings, globals, imports via `describe`); `--output` + `--json` is an
  explicit error.
- Ghidra sync enum support: `struct_parser.extract_enums_from_file()` pulls
  `enum`/`typedef enum` definitions, `rebrew sync --sync-structs` pushes them
  through Ghidra's `parse-c-structure` CParser, and `--pull-datatypes` re-pull
  is now **merge-safe** (a user section between the marker and `#endif`
  survives regeneration) and byte-identical on re-pull.
- `rebrew identify-library` — combined library-identification pass: runs
  CRT source matching (strongest, with SOURCE metadata for ≥0.85 confidence),
  FLIRT signature scanning (ambiguous matches never guessed), and IAT
  import-stub detection, merges by VA with provenance ranking, and writes new
  `// LIBRARY:` entries to `library_<module>.h`.  Idempotent — VAs already
  annotated anywhere are skipped.  Also extracted a shared
  `flirt.match_text()` scan helper (used by `flirt`, `analyze`,
  `identify-library`).
- `rebrew match --all --seed-solutions <path>` — cross-project solutions
  seeding: merges another project's `.rebrew/solutions.json` (deduped by
  target+symbol, local wins) so same-size functions start from proven
  cflags when the source file doesn't resolve locally, and from the source
  file when it does.  Batch JSON reports `seeded_cflags`.
- Property-based round-trip tests for the typed metadata facade
  (`tests/test_metadata_model.py`): any valid field set survives
  `MetadataEntry.apply → load` exactly, and every known STATUS round-trips
  through the promotion gate — the "impossible by construction" proof for the
  field-routing bug class (add-module tomlkit persistence, lint `--fix` STATUS).
- `rebrew analyze [BINARY]` — one-shot intelligence dossier: binary layout
  and sections, layered toolchain detection (DIE → PDB → heuristics), string
  census with cross-reference counts, import table + IAT stubs, a
  code-reference profile, reversed-function coverage, dispatch-table
  detection, and FLIRT library identification (when the project has
  `flirt_sigs/`).  Every section is best-effort — a missing PDB, diec, or
  sigs dir skips only that part; `--json` stays pure JSON.
- `rebrew status` now surfaces the **effective status** overlay explicitly:
  terminal output reports how many functions the verify cache overrode and
  how many are stuck on `MISSING_SIZE` (set SIZE via metadata, re-verify);
  JSON gains `verify_cache: {overrides, missing_size}`.  The overlay rule
  (PROVEN wins, STUB is sticky, everything else follows the cache) is
  documented in `docs/ANNOTATIONS.md`.
- `rebrew init` ergonomics: `--binary original/bench.exe` no longer produces
  `original/original/bench.exe` (a leading `original/` prefix — either slash
  direction — is stripped), and the new `--link-tools-from <dir>` symlinks the
  profile's vendored toolchain (`tools/MSVC600`, `tools/msvc6.3`, ...) from a
  master toolchain directory in one step.
- `rebrew doctor` now knows how to fetch every profile toolchain: the
  missing-`CL.EXE` fix hints carry the decomp.me mirror URLs for
  msvc6.3/6.6/7.0, the archaic-msvc codeload URL for MSVC500, and the
  OmniBlade wcc tarball for Watcom.
- Toolchain detection now recognizes **Watcom C/C++** (`_TEXT`/`_DATA`/`_BSS`
  sections, runtime strings) and **Borland C/C++** (`CODE`/`DATA`/`BSS` +
  CW32/CC32/BORLNDMM runtime imports or Borland strings, without Delphi RTL
  markers) — DIE name mapping, version hints, and structural heuristics all
  extended.  `rebrew doctor` flags these families as blocker-documentation
  cases (no matching profile yet).
- Property tests for the catalog/grid edge-case parsers
  (`tests/test_property_parsers.py`): `_lookup_section`/`_build_section_index`
  and `_find_ghidra_data_label`/`_build_label_index` verified against a
  linear-scan reference over random non-overlapping sections/labels,
  `count_statuses` priority invariants, and `generate_data_json`
  reorder-invariance (shuffling the entries/funcs input must not change the
  coverage grid) — the last running end-to-end against the fixture PE.
- `tests/test_json_purity.py` — pins the ``--json`` stdout contract across
  the offline CLI surface (status/strings/imports/asm/describe/xrefs/verify/
  todo/lint/data/doctor/cache/cfg/flirt): stdout is exactly one JSON document,
  progress chatter ("Scanning...", LIEF logs, warnings) stays on stderr.
  Runs against the checked-in fixtures — no wine or toolchain needed (15 tests).
- Checked-in binary fixtures (`tests/fixtures/`, rebuilt by
  `tools/gen_fixtures.py`): a tiny synthetic COFF `.obj` (two functions,
  DIR32 + REL32 relocs), a matching PE and ELF32, and a `.lib` archive.  A
  freshness test regenerates them in-memory and asserts byte-identity, so the
  parse/compare/reloc paths — and the `gen_flirt_pat` → `flirt` pipeline —
  run end-to-end in CI without wine or a vendored toolchain (16 new tests).
- `rebrew match --sweep-toolchain` — compile the function with each vendored
  MSVC toolchain (point-version SPs) and report which byte-matches best,
  answering "which MSVC build produced this function" in one run.
- `rebrew pdb-info <binary>` — extract compiler version (S_COMPILE3 frontend/
  backend), the exact compiler flags (auto-writable to `[compiler] cflags` via
  `--write-cflags`), a Zig marker, and best-effort function names from a
  sibling PDB.  Gracefully reports unsupported formats (classic VC2–6 PDBs,
  llvm-pdbutil's VC7 crash) instead of failing.
- `rebrew intake <binary>` — one-shot binary onboarding: toolchain detection
  → init with a matching profile → copy binary → symlink vendored toolchain →
  rizin functions.txt (`aaa`/`aap` fallback) → document every function with a
  STUB .c + metadata blocker.  Produces a lint-clean project ready for the
  per-function decomp loop (consolidates the per-project classify scripts).
- `msvc5` compiler profile (VC 5.0) backed by the archaic-msvc toolchain
  (`tools/MSVC500`), validated byte-exact against a real Microsoft VC5.0
  binary (BIND.EXE table-walker → EXACT).
- `msvc420` profile now has a toolchain (archaic-msvc `tools/MSVC420`);
  both added to `tests/test_toolchain_roundtrip.py` (5/5 EXACT).
- `msvc6.3` and `msvc6.6` compiler profiles (decomp.me SP3/SP6 point-version
  toolchains — codegen differs across MSVC 6.x SP levels), and the `msvc7`
  profile now has a real toolchain (decomp.me `msvc7.0`).  Each is proven by
  `tests/test_toolchain_roundtrip.py` (compile → compare → EXACT).
- Config: an *explicitly empty* `compiler.includes`/`libs` is now allowed for
  any profile (decomp.me MSVC tarballs ship Bin+Include but no Lib); a missing
  key still falls back to the conventional default path.
- Toolchain detection (`rebrew doctor` "Toolchain alignment" check) —
  layered DIE (`diec`) / PDB (`llvm-pdbutil`) / structural-heuristics
  detection of the target's compiler family + version + (PDB) flags, with a
  fail/warn when the configured `[compiler] profile` cannot byte-match the
  detected family (e.g. Delphi binaries, Zig under gcc-pe).
- `gcc-pe` compiler profile — MinGW GCC (i686-w64-mingw32) for non-MSV C
  PE/x86_32 targets: POSIX-style flag routing (`-I`/`-c`/`-o`) in the
  compile/diff/match paths, PATH resolution of bare toolchain names, empty
  `includes`/`libs` allowed.  `rebrew init --compiler gcc-pe` sets it up.
- `rebrew cfg set <target-scoped-key>` now routes bare keys (e.g. `binary`,
  `marker`) to `[targets.<default>]` instead of silently writing a top-level
  key the config reader ignores.

- **16-bit NE support for MSVC-built targets** (the original 1991 SkiFree):
  `is_ne` read only the first 0x104 bytes, but the MSVC 16-bit linker places
  the NE header at `e_lfanew` = 0x400 (Borland uses 0x40) — NE binaries were
  silently misdetected as PE and enumerated by rizin into garbage.  `is_ne`
  now seeks to `e_lfanew`; `probe_is_code` skips the Borland `[index\x00]`
  marker only when it is actually present; `enumerate_ne_functions` treats a
  markerless segment's start as a function boundary (MSVC 16-bit entry code
  opens `push ds/pop ax/nop/inc bp`, not `push bp`), recovering the entry
  function (ski16.exe: 137 funcs vs 233 garbage; holiday.exe unchanged at
  1783).
- `rebrew intake` re-discovery (project already exists) now prunes
  auto-generated STUB files + metadata for functions absent from the new
  function list — a changed enumeration (rizin update, NE fix) previously
  left orphaned stubs that inflated `rebrew status` totals (233 stale stubs
  on the SkiFree NE re-onboarding).  Only exact auto-stub content is pruned;
  edited/renamed sources and progressed metadata are never touched.
- **NE import parsing no longer fabricates garbage**: the classic Win16
  import table does not exist in many binaries (MSVC-built NEs like the
  1991 SkiFree place the non-resident name table right after the entry
  table, and Borland binaries differ too) — the old parse read those bytes
  as counts and emitted tens of thousands of fake ordinal imports (holiday:
  WAVEMIX "18443 imports").  `parse_imports` now sanity-gates the count and
  validates by-name offsets, degrading to the module list only (KERNEL/GDI/
  USER on ski16), and `rebrew imports` reports module-level NE records so
  the DLL set stays visible.  Per-API Win16 imports (entry-table entries)
  remain future work.
- `rebrew intake` writes `format = "ne"` for 16-bit NE targets (was `"pe"`,
  cosmetic since `load_binary` auto-detects, but misleading in the config);
  `load_config` accepts `format = "ne"` without the unknown-format fallback
  warning, and `load_binary` reports "Not a 16-bit Windows NE executable"
  for `fmt="ne"` on a non-NE file instead of a generic format error.
- `rebrew verify` short-circuits 16-bit NE targets with a clear notice
  (no compile profile exists yet — ADR-001) instead of running every stub
  through the compile loop into COMPILE_ERROR rows.
- `rebrew data --dispatch` scans MSVC-style NE data segments from offset 0
  (the Borland `[index\x00]` skip is now conditional on the marker being
  present) — VMT/dispatch detection on the 1991 SkiFree was misaligned by
  2 bytes.
- `rebrew rename` accepts zero-padded hex VA identifiers (functions.txt
  writes `0x000100a0`; the strict string match rejected them while every
  other VA-taking tool accepts both forms).
- `rebrew discover-functions` routes 16-bit NE binaries through the native
  NE loader's linear sweep instead of rizin (whose NE output is garbage
  file-offset "functions" — the source of the original SkiFree 233-func
  false enumeration).
- `rebrew doctor` no longer fails 16-bit NE projects: the compiler + include
  checks downgrade to warnings for `x86_16` targets (no compile profile —
  ADR-001), and the toolchain-alignment check warns instead of failing for
  Delphi-family targets (documented-blocker, analysis-only).  Both NE corpus
  targets now report "Project looks healthy!".
- Property-based test for `bytes_to_pat_line` (hypothesis): lead masking,
  CRC-window truncation before the first tail relocation, size field, and
  determinism hold for arbitrary code bytes + reloc offsets.
- **`rebrew.delphi16.compile_ne`** — the ADR-001 16-bit compile foundation:
  a self-contained DOSBox sandbox (compiler trio + `RTM.EXE` + RTL units +
  staged `DCC.CFG`) compiles a `.dpr` headless and parses the resulting NE
  with the native loader.  Hard-won requirements documented: `RTM.EXE`
  (DPMI runtime — DCC silently fails without it) and a non-tmpfs mounted
  drive (DOSBox 0.74-3's shell breaks on tmpfs).  `hello.dpr` →
  `HELLO.EXE` → 15 functions enumerated.
- Property test for inline annotation update/remove symmetry: for arbitrary
  file-owned keys and printable values, `update_annotation_key` followed by
  `remove_annotation_key` restores the source file byte-for-byte.
- `rebrew analyze` `functions.total`/`total_bytes` were 0 for projects
  without a Ghidra export — the dossier now falls back to the project's
  own `functions.txt` via the canonical `parse_function_list`.
- `detect_toolchain` identifies 16-bit NE targets from their segment
  markers (Borland `[index\x00]` → `delphi`, markerless segments → `msvc`
  16-bit) and falls back to the Microsoft Linker version when diec misses
  the compiler record (explorer.exe on Win2K SP4 → "MSVC 5.0 (linker
  5.12.9049)").
- `rebrew verify --fix-sizes`: auto-corrects stale annotation SIZE from the
  binary-derived canonical size for every reported divergence (stale sizes
  cause false SIZE_MISMATCH / truncated byte extraction). `--dry-run`
  previews; JSON gains `sizes_fixed`. Validated on smygb: 3 stale sizes
  corrected (190→331, 235→217, 141→277), re-verify reports zero
  divergences. Extracted to `_apply_size_fixes` + unit-tested (writes,
  dry-run no-op, module fallback).
- Complete the standalone console scripts: every command module with a
  `main_entry()` now gets a `[project.scripts]` entry (43 total), making
  the documented "works both as rebrew-<cmd> and as a flat subcommand"
  pattern true for all 43 commands. Discovered via a clean-venv wheel
  smoke test: `rebrew-discover` / `rebrew-pdb-info` crashed with
  "Could not get a command for this Typer instance" because their
  `main()` lacked `@app.callback(invoke_without_command=True)` (the
  umbrella registration had masked the gap). Decorators added; a docs-
  hygiene test now guards that every scripted module wires a callback or
  subcommands.
- `rebrew prove` now persists a failed proof's Z3 counterexample as a
  metadata NOTE (`prove: Z3 found ... EAX=0 vs 4`) so the concrete
  register difference surfaces in `status`/`todo`/`describe` instead of
  being lost after the terminal output. Never clobbers a reverser's own
  note; timeout/path-explosion messages carry no note.
- `rebrew prove` CLI status-guard tests were **vacuous** — the
  source-first invocation made typer reject the call as "No such
  command", so every test passed regardless of the gate. Rewritten with
  options-first invocation + `chdir` + a real PE fixture: EXACT/STUB
  rejections and the SIZE_MISMATCH acceptance are now genuinely asserted.
- `rebrew prove` now accepts **SIZE_MISMATCH** functions (single + `--all`):
  a compiled size that differs structurally is exactly the "bytes differ
  but semantically equivalent" case the PROVEN status exists for, and the
  proof itself is what makes the promotion sound. Validated on smygb: both
  remaining SIZE_MISMATCH functions proved equivalent and promoted to
  PROVEN — the project now has ZERO SIZE_MISMATCH / ZERO NEAR_MATCHING
  (EXACT 17 / RELOC 26 / PROVEN 9 / STUB 103; coverage 87.1% -> 90.6%).
- `parse_function_list` (functions.txt reader, used by verify/todo/status/
  describe/document-unmatched) crashed with `UnicodeDecodeError` on
  legacy-encoded files — same bug class as the read_source_text fix (50/150
  fuzz inputs). Now reads via the tolerant `read_source_text`; 0/150 crash.
- `rebrew skeleton --append` read the target `.c` with a strict UTF-8 read
  and wrote back UTF-8 — a legacy-encoded source crashed the append and
  would have been re-encoded. Now reads with the tolerant reader and
  writes back in the file's own encoding (round-trip preserved).
- `rebrew.utils.read_source_text`: the CP1252 "universal fallback" was
  wrong — Windows-1252 has undefined bytes (0x81/0x8D/0x8F/0x90/0x9D), so
  reading a legacy-encoded source containing one crashed the core text
  reader (annotation parsing, lint, metadata) with `UnicodeDecodeError`.
  Found by fuzzing the annotation parser: 176/200 non-UTF-8 inputs
  crashed; now decode uses `errors="replace"` (those bytes are
  unrepresentable anyway) and 0/200 crash. Round-trip byte-for-byte
  behavior for all *defined* cp1252/Shift-JIS bytes is unchanged.
- `tools/DELPHI10/pak_extract.py` (Quantum archive decoder): hardened
  against malformed/truncated archives — header and name-table reads are
  now bounds-checked and raise a clean `ValueError` instead of crashing
  with `IndexError`/`struct.error` (fuzz regression: 67/200 header
  mutations crashed before; 0/200 after). Vendored the MIT reference
  archives as fixtures and pinned validity + no-crash contracts in
  `tests/test_pak_extract.py`.
- `rebrew prove`: end-to-end semantic-equivalence tests on synthetic
  x86-32 blobs (angr blob backend, no compiler/binary needed) — pins the
  core verdicts: equivalent implementations prove True (different
  encodings, register tricks, identity), differing constants prove False
  with Z3 finding the EAX difference.
- JSON-purity regression coverage extended to the session-era commands:
  `pdb-info`, `analyze --function`, `similar`, `identify-library --dry-run`,
  `discover-functions`, `binsync-export --dry-run`, `report`,
  `gen-flirt-pat` — every `--json` invocation (success AND error paths)
  must emit exactly one JSON document on stdout.
- `rebrew gen-flirt-pat` / `identify-library --build-sigs` emitted a
  **malformed .pat line for nameless COFF symbols** (empty/public names) —
  the line's trailing name field was empty, so signature parsers rejected
  the whole file as "corrupt" (212 of 262 generated sigs in the smygb
  project were affected). Nameless symbols are now skipped; the smygb sigs
  were regenerated and `rebrew analyze` reports zero corrupt-sig warnings.
- `rebrew pdb-info --help` rendered "into  cflags" — the `[compiler]`
  in the help text was consumed as rich markup and vanished.
- `rebrew intake` option order — `--json` is now declared before
  `--target` (last two options), matching the project's CLI convention.
- `rebrew diff` / `rebrew match` / `rebrew prove` invoked with a VA whose
  resolved source file does not annotate that VA now error
  ("No annotation for VA ... — the resolved file covers different functions")
  instead of silently falling back to the first annotation and diffing the
  wrong function against the requested address.  An explicit `--symbol` is a
  deliberate override and remains allowed.
- Toolchain detection now identifies 16-bit NE Delphi binaries from
  their embedded strings (full-file byte scan, beyond the 256-string cap) —
  holiday.exe (Borland Delphi 1.0, Windows 3.1) is reported `delphi` by
  doctor's alignment check instead of "unknown", matching the hgb case.
- `load_binary` robustness pinned: 7 curated garbage-byte cases +
  a 100-example hypothesis probe confirm arbitrary/truncated binary input
  never crashes — always a clean ValueError/FileNotFoundError or a usable
  BinaryInfo (LIEF's partial-header leniency is asserted usable).
- `docs/CONFIG.md` now documents the environment variables
  (`REBREW_LLM_ENDPOINT`, `REBREW_LLM_API_KEY`, `REBREW_GLOBALS_H`) and
  the config>env>default precedence — the LLM-seeding env vars were
  undocumented.
- Metadata writers are now fully serialised by the module lock —
  `set_field`/`update_field`/`remove_field`/`save_metadata` did unlocked
  read-modify-writes (only `update_source_status` locked), a latent
  lost-update race under concurrent workers. All writers lock now; two
  concurrency tests pin the behavior.
- CI test job now runs `tools/gen_fixtures.py --check` — a fixture-
  generator change without regenerating the checked-in fixtures now fails
  CI instead of passing silently.
- `test_docs_hygiene` command-coverage regex now matches commands
  registered as multi-line tuples — `analyze` + 15 others slipped past the
  "every command documented" check; their `docs/CLI.md` sections added
  (analyze, describe, discover-functions, gen-flirt-pat, identify-library,
  intake, pdb-info, report, strings, xrefs, dashboard).
- `rebrew test <file.c> --va 0xHEX` on a multi-function file now selects the
  annotation AT that VA (symbol + fallback size) — it used to derive the
  symbol from the file's FIRST annotation and silently test the wrong
  function at the requested address (e.g. `_exit_handler@12` instead of
  `_CreateListenSocket`).  Same VA-picks-its-function rule as
  `diff`/`prove`/`near-diag`; an explicit `--va` that matches no annotation
  still falls back to the first annotation as a user override.
- `rebrew near-diag` masks only relocation sites that survive the same
  DIR32/REL32 address validation as `rebrew test`/`rebrew verify` — invalid
  relocs (wrong call target / global address) now surface as real structural
  bytes instead of being hidden behind "RELOC-level". The RELOC verdict's
  suggestion is honest about leftover real bytes: it says
  "NEAR_MATCHING-level, not RELOC" when the canonical status would be
  NEAR_MATCHING (e.g. `_CreateListenSocket` in guild was reported RELOC-100%
  but `rebrew test` classifies it NEAR_MATCHING with 8 real bytes).
- The Annotation-level marker-consistency check (annotation.py `validate`)
  had the same FUNCTION+STUB bug as lint's E015 — a STUB-status function may
  keep its FUNCTION marker; only library-module mismatches warn.  Both checks
  now agree (4 regression tests).
- `params.py` deduplicated: the named-param detection rule is one shared
  `_param_name` helper (minimalism review).
- **E015 lint rule**: the marker-consistency check fired on every
  FUNCTION-marker + STUB-status file (the documented convention — status
  lives in rebrew-function.toml).  It now only fires on library-module
  marker mismatches, its actual intent.  smygb lint went from **144 errors →
  0**.  `tools/corpus_sweep.py` now includes `lint --json` so this class of
  drift is caught project-wide.
- `rebrew init` now emits profile-appropriate `base_cflags` (empty for
  gcc-pe/gcc/clang) — a fresh gcc-pe project no longer compiles with MSVC
  `/nologo /c /MT` flags (which mingw rejects).
- `posix_style` is now threaded through the GA / flag-sweep paths
  (`flag_sweep`, `BinaryMatchingGA`, match's sweep sim) — `rebrew match`
  on gcc-pe profiles emits `-I/-o/-c` instead of `/I//Fo//c`.
- New `ProjectConfig.posix_style` property — single source of truth for
  POSIX-vs-MSVC flag routing (replaces the 6x duplicated predicate).
- Toolchain detection: profile-compat table covers msvc6.3/6.6; codegen-era
  scan slices `.text` instead of the whole file; MSVC version hints
  corrected (13.10=7.1, 14.00=8.0); dead msvcp glob + unused lists removed.
- `rebrew cfg set` routes the remaining target-scoped keys
  (`ghidra_program_path`, `r2_bogus_vas`, `iat_thunks`, ...).
- `msvc7` init preset pointed at `Bin/CL.EXE`; the decomp.me VC7 tarball ships
  `Bin/cl.exe` (lowercase) — the preset now matches.
- `should_promote_status` and the `rebrew status`/`todo` verify-cache overlay
  no longer demote documented STUBs to `MISSING_SIZE` — a blocker-documented
  stub keeps its classification after `rebrew verify`.
- `rebrew diff --dry-run` — preview `--fix-blocker` metadata writes without
  touching `rebrew-function.toml`.
- `rebrew extract batch --dry-run` — preview which `.bin` files would be
  written (JSON: `DRY_RUN` status, plus a `failed` count in the summary).
- `rebrew cfg set` / `add-module` / `set-cflags` gained `--dry-run` with
  future-tense previews (no in-memory mutation).
- `rebrew cfg set-cflags --target` now actually takes effect — per-target
  presets are written under the target's `compiler` sub-table, where the
  loader reads them (previously a silent no-op).
- `recoverage check --json` and `recoverage stats --json` — machine-readable
  verdicts/output.
- Per-module CFLAGS presets (`cflags_presets`) are now consumed as the
  CFLAGS fallback across match/diff/verify/test/prove/near_diag
  (`rebrew.cli.resolve_cflags`).
- `rebrew sync --refresh-cache --json` now actually writes the cache (the
  flag previously made it a silent no-op).
- `rebrew init --install-wibo` writes a working config (wine prefix dropped
  from the command).
- `rebrew data --gen-header` / catalog warn on globals whose VA falls
  outside every PE section.
### Added
- **`rebrew asm --hints` flags the equality-boolean idiom**: `cmp reg,1;
  sbb reg,reg` (+ optional `inc`) is MSVC's `!x`/`x==0` lowering, which
  plain C under MSVC5 compiles to a different epilogue (`neg/sbb/neg/dec` /
  `setcc`) — the hint advises writing it in naked asm (a repeated mismatch
  in the mspaint corpus).
- **GA can now fix wrong constants**: new `mut_tweak_integer_literal`
  mutation operator adjusts numeric literals (field offsets, sizes, magic
  numbers) by small ±deltas, preserving hex/decimal radix.  Previously the
  GA had no way to change a literal — a function whose only defect was an
  off-by-N offset plateaued at its seed score forever (a broken field
  offset stuck at 5000 for 960 evals).  With the operator the same search
  converges to `exact: True`.
- **`rebrew describe` reports the function pattern + calling convention**:
  the dossier gains `pattern` (import thunk / EH-ctor / switch dispatch /
  IAT forwarder — the skip-vs-decompile decision from `rebrew asm --hints`
  at function level) and `convention` (rebrew asm's inference) fields, so a
  single `rebrew describe <va>` call shows the recognizer's verdict plus
  the callers/callees/strings/imports.  JSON contract updated.
- **`rebrew asm --hints` flags esp-relative disp8 in naked asm**: MASM
  folds `lea/cmp/mov [esp+X]` operands into short-form encodings that
  don't match MSVC's `8d 44 24 XX` disp8 forms — the hint warns to force
  the exact bytes with `_emit` (a recurring naked-asm mismatch).
- **`rebrew asm --hints` flags EH-ctor prologs**: a `call` preceded by
  `mov eax, imm32` (the compiler-generated `__eh_ctor` registration
  pattern — 58 functions in the mspaint corpus) is annotated as not
  C-reproducible, so the user skips/documents instead of decompiling.
- **`rebrew asm --hints` flags IAT forwarding stubs**: a call through an
  IAT slot preceded by ≥3 reversed `mov reg,[esp+X]; push reg` pairs is an
  N-arg forwarder to an imported (usually stdcall) function.  The hint
  names the forwarder and the lesson from matching one byte-for-byte: the
  forwarder itself is cdecl (plain `ret`) while the callee cleans — declare
  a `__stdcall` function pointer for the call or MSVC emits a spurious
  `add esp,N`.  (The backward scan is immune to the asm `--hints` lookbehind
  prefix, which previously broke the pattern.)
- **`rebrew skeleton --batch --skip-fragments`**: excludes discovery
  entries whose first bytes match none of the common function-start
  prefixes — data regions and misaligned fragments (a bad function-list
  boundary) that are not decompilable code.  Opt-in because the heuristic
  can misflag an unusual real function; on the mspaint corpus it filters
  the known data entries (e.g. 0x1001794) while leaving real functions
  untouched.  ~10% of discovery entries in that corpus are non-code.
- **`rebrew asm --hints` flags byte-compressed switches**: a two-level
  dispatch (index fetched from a byte table before the indirect jmp —
  MSVC's sparse-switch form) is annotated with a warning that a plain C
  switch often does not reproduce the lowering (the compiler may pick a
  direct table instead) plus the `rebrew switch <va>` decode command — so
  the user knows up front not to chase the structure difference.
- **`rebrew switch --all` — recon pass**: scans every function-list entry
  and reports the ones containing jump-table dispatches (dispatch/case
  counts + the exact decode command per function).  On the mspaint corpus
  it surfaces 28 switch-dispatch functions in one command.  Also fixes a
  `0x0x` double-prefix in the console VA display.
- **`rebrew asm --hints` flags switch dispatches**: an indirect jump-table
  dispatch (`jmp dword ptr [reg*4 + 0x...]`) is now annotated with
  `switch dispatch (jump table) — decode the case table with
  rebrew switch <va>` — the recon hint surfaces where the user already
  looks, and points at the new decoder.
- **`rebrew switch <VA>` — jump-table switch decoder**: locates the
  bounds-checked indirect dispatch (`jmp dword ptr [edx*4 + table]`) in a
  function, reads the dispatch table from the binary, and prints the case
  table (index → handler VA → known function name).  The entry count comes
  from the preceding `cmp reg, N` bounds check when found (any register —
  MSVC copies the index into the scaled register between the cmp and the
  jmp), else from walking the table until a non-image entry (capped at
  256).  This is the "jump-table switch" category of functions that manual
  decompilation has to untangle by hand — the structure is now visible
  before writing any C.  `--json` for machine-readable case tables.
- **`rebrew doctor` Runner advisory**: when the project runs `wine` but a
  wibo binary is already available (PATH or `tools/wibo`), the Runner check
  warns with the exact config switch (`runner = "tools/wibo"` + strip the
  `wine ` prefix) — wibo is a headless PE loader with no X dependency, so
  compiles get faster and fully headless.
- **Headless wine by default**: every `wine` compiler invocation (compile
  and link, both the `rebrew compile` path and the GA flag-sweep path)
  runs against a **persistent `Xvfb` virtual display** — spawned once per
  process and reused across the whole verify/GA batch, with live Xvfb
  servers from earlier runs reused rather than re-spawned.  No more
  virtual-desktop window popping on each compile, and bare wine now works
  under CI with no `DISPLAY`.  The per-invocation `xvfb-run` wrapper costs
  ~3 s per compile, so a persistent server is the difference between a
  4 s cold compile and ~0.5 s (the toolchain round-trip suite halved:
  48 s → 23 s).  Opt out per-run with `REBREW_WINE_HEADLESS=0`;
  falls back to `xvfb-run` then bare wine when no Xvfb binary exists.
  `rebrew doctor` notes the headless setup (or points at wibo) for wine
  runners.

### Changed
- **Breaking (JSON):** `rebrew imports --json` now emits stub VAs as hex
  strings (`{"va": "0x...", "name": ...}` list) and `iat_va` as hex, matching
  every other rebrew JSON (previously stringified decimal dict keys).
- **Breaking (CLI):** `rebrew verify --compare` no longer advances the
  baseline report on a failing (regressed) run, and a failed gate run no
  longer writes the verify cache — the CI gate can no longer self-heal.
- Verify cache now invalidates on annotation SIZE changes (metadata-only
  `catalog --fix-sizes`), external `-I` header edits, and
  `compiler.runner`-only config edits.
- `rebrew verify` PROVEN overlay no longer masks real regressions
  (COMPILE_ERROR / EXTRACT_ERROR / MISSING_FILE surface as failures).
- Bad-VA arguments to `rebrew diff`/`match`/`asm`/`similar` now produce
  accurate errors instead of misleading symbol errors or silent empty output.
- `rebrew sync --dry-run` no longer writes `ghidra_commands.json`.
- `rebrew build-db` never deletes a locked/valid database; schema-less
  debris files auto-rebuild; infrastructure errors exit 2 (EXIT_ERROR).
- Main-command catch-all exits cleanly (no traceback, JSON envelope when
  `--json`) with EXIT_ERROR.
- `rebrew cfg` write commands surface OSError/tomlkit parse errors as clean
  messages.
- `rebrew extract batch` continues past a per-function disassembly error
  instead of aborting the batch.
- `rebrew asm --size` beyond the image warns and reports `truncated`.
- `rebrew flirt --va` bypasses the scan size gate so short functions are
  actually probed.
- CFLAGS resolution unified across tools (per-function → preset →
  `[compiler].cflags` → `/O2 /Gd`).
- `rebrew diff 0x<VA> --watch` lost VA targeting on re-entry (diffed the
  wrong function in multi-function files).
- `rebrew verify` PROVEN overlay masked regressions in proven functions.
- angr's import-time unicorn ERROR leaked to stderr on every `todo`/`doctor`
  run (and prove's status-guard failures).
- `rebrew sync --push --dry-run` wrote the export artifact.
- Coverage DB: failed builds left an empty DB that wedged later builds;
  full rebuilds left orphan `verify_results` rows and a dead v3 index.
- Coverage DB schema gate now verifies query-critical columns, not just
  object names.
- Default `marker` for dotted target names (e.g. `server.dll`) no longer
  produces a marker that matches no annotation module.
- Source filenames starting with `@`/`-` are prefixed `./` before CL.EXE
  (MSVC response-file/option confusion).
- Recovered `cu_map`'s orphaned standalone CLI surface (reachable only via
  `rebrew graph --cu-map`).

### Performance
- **`score_candidate` GA hot loop ~3x faster**: mnemonic extraction now uses
  capstone's `disasm_lite` (tuple-returning, no per-instruction ctypes
  objects) instead of `disasm` — identical output, ~2.7x cheaper disassembly.
  With the explicit-reloc GA path (precomputed target + reloc mask) a 60-insn
  candidate scores in ~47µs instead of ~143µs.
- **`iat_slot_vas` memoized per binary path**: `compile_and_compare` calls
  it once per function even on compile-cache hits, so a full verify/test
  batch re-parsed the same immutable PE N times (0.05–0.3s each).  Now
  scanned once per resolved path (bounded dict + lock, mirroring the
  `load_binary` cache).
- **GA source-digest memoization actually works**: `_source_digest` was
  documented as lru_cached but had no decorator — every flag-sweep combo
  and GA candidate re-ran a full SHA-256 of the source (perf-review F3:
  1-8s per 258k-combo sweep).  The `@lru_cache` the docstring promised is
  now applied; the GA loop's per-candidate re-hash for log lines now reuses
  the same memoized digest.
- **GA fitness memoization fixed**: `BuildResult.fitness` was populated
  after the disk-cache `put()`, so every `cache.get()` returned a fresh
  unpickled object whose fitness was `None` — the warm-scoring fast path
  could never fire, even for elites persisting across generations.  A
  process-local `{src_hash: fitness}` dict now makes it real (no extra disk
  write); a fresh-pickle result with the same hash skips re-scoring.
- **Batch GA flushes solutions once**: `_save_solution` per matched stub
  re-read and rewrote the whole solutions file per match (O(matches × file
  size)); the batch driver now collects `SolutionEntry`s across stubs and
  calls `save_solutions` once, mirroring the batch flag-sweep path.

- GA/flag-sweep hot path: `score_candidate`'s no-reloc fallback now
  disassembles the candidate ONCE (merged normalization + mnemonic
  extraction, `_normalize_and_mnems_x86_32`) and threads the target's
  mnemonics from the same pass — 4 disassemblies per call down to 2
  (~1.14x on reloc-less candidates; byte-identical scores, verified
  against the precomputed hot path).
- **GA fitness memo checked BEFORE the compile pool**: `_run_inner`
  consulted the disk BuildCache first, then the process-local memo — every
  elite/unchanged source still paid a sqlite read + unpickle per
  generation.  The memo is now consulted while building the futures dict,
  so fully-memoized generations skip `_compile_source` entirely
  (regression test: a whole-population memo hit makes zero compile
  submissions).  The memo key also switched from the truncated `[:8]` hex
  (32 bits — ~10 expected collision pairs at 300k unique sources) to the
  full SHA-256 digest; log lines still show the short form.
- **Reloc-mask construction vectorized in `score_candidate`**: the
  per-offset Python loop that slice-stamped `reloc_mask[start:end] = True`
  became one index-array build (`offsets[:, None] + arange(4)` with
  bounds masking); `reloc_score` now reuses the already-computed
  `byte_diff` instead of re-running `diff_mask & ~reloc_mask`.  5000-case
  fuzz + 300 end-to-end trials confirm byte-identical scores.
- **`_validate_dir32` catalog scan → set membership**: the smart-reloc
  comparator validated each DIR32 slot with a linear `any(...)` scan over
  every catalog VA — O(relocs × catalog) per function.  The caller now
  builds a `set` of catalog VAs once per compare and the validation is an
  algebraic `in` check; typed-reloc and dict branches share the one set.
- **OMF format detection no longer double-reads the object**:
  `parse_obj_symbol_and_relocs` opened the file to detect the format, then
  read it again for the OMF path.  A new data-based
  `_detect_obj_format_data` detects from the already-loaded bytes (the
  file-based wrapper delegates to it), removing one open+read per compiled
  candidate on the compile hot path.
- **`precompute_target` disassembles the target once, not twice**: the GA
  init path normalized with a `detail=True` pass and then re-disassembled
  the same bytes via `disasm_lite` for the mnemonic list.  It now
  delegates to `_normalize_and_mnems_x86_32` (the merged pass), halving
  the per-stub target disassembly in batch GA runs (byte-identical
  normalization + mnemonic list, verified across 300 trials).
- **`mutate_code` weight-list construction cached**: the GA passes the
  same `mutation_weights` dict for every call, but the 114-entry
  per-mutation weight list (a dict lookup per mutation function) was
  rebuilt on every call.  A `lru_cache` keyed on the sorted mapping turns
  it into a cache hit (~58x on the construction itself; semantics
  identical, unknown names still default to weight 1.0 and an all-zero
  mapping still falls back to uniform selection).
- **`compile_to_obj` skips the workdir source copy on cache hits**: the
  copy exists only for the compiler subprocess (Wine path mapping), but it
  was made before the cache lookup and the freshly-copied file was then
  read back to compute the cache key — one write + one read per warm
  compile.  The key is now hashed from the original source (copy2 is
  byte-identical) and the copy happens only on the miss path; regression
  test asserts a cache-hit workdir contains no source file.
- **Reloc-less `diff_functions` disassembles each buffer once, not twice**:
  the old path disassembled plain for the row diff, then
  `_normalize_reloc_x86_32` re-disassembled with `detail=True` for
  normalization.  The reloc-less branch now uses one detail pass per
  buffer for both (detail mode produces identical rows — verified —
  and the normalization is the same `_zero_reloc_fields` logic inline).
  Diff match markers byte-identical to the old path across 250 fuzz
  trials.
- **Smoke gate now covers the host-only toolchains**: `rebrew toolchain
  smoke` previously ran only the docker-image toolchains (7), silently
  skipping the vendored host trees without images — msvc420/msvc5 (wine)
  and watcom16 (native wcc) had NO byte-reproducibility gate, so a wine
  update or vendored-tree drift went unnoticed.  Host-only specs are now
  compiled in the same fixed-workdir/fixed-mtime contract via the uniform
  host runner and verified against golden hashes (msvc420/msvc5 mask the
  COFF TimeDateStamp like msvc6; watcom16 embeds no timestamp).  Gate is
  now 10/10 byte-reproducible.
- **`run_toolchain` host fallback wine-prefixes wine-runtime specs**: the
  host backend exec'd the vendored binary directly, so a wine-runtime spec
  without an image (exactly msvc420/msvc5) could never run — Linux
  EACCES on a Windows PE.  `wine` is now prepended for `runtime="wine"`
  specs; native specs unchanged (regression test asserts the
  `["wine", CL.EXE, ...]` command shape).
- **msvc400/msvc420/msvc5 pinned sources + msvc400 registry entry**: the
  three old-MSV C trees were vendored (and now smoke-gated) but had no
  `ToolchainSource`, so `rebrew toolchain vendor` said "no pinned source"
  and a fresh clone could not reproduce them.  Sources pinned with
  sha256-verified codeload tarballs (archaic-msvc/msvc420, msvc500 —
  verified byte-identical to the committed trees; itsmattkc/MSVC400),
  and the vendored `toolchain vendor` tar extraction auto-detects
  compression now (gzip codeload tarballs vs the watcom xz snapshot —
  `tar xJf` hardcoded xz).  `msvc400` also joins the TOOLCHAINS registry
  (config/init/detector already knew it — the toolchain CLI was the only
  surface missing it), the `tools/MSVC400` compat symlink alias is wired,
  and doctor's download hints for 4.0/4.2/5.0 now point at the pinned
  sources.
- **`msvc400` vendored + smoke-gated (11/11)**: the 4.0 tree is now
  committed alongside 4.2/5.0 (reproducible via the pinned source) and
  joins the smoke gate — its masked COFF object is byte-identical to
  msvc420's (same compiler lineage, cross-validating both goldens).
- **`toolchain vendor` guard case-insensitive**: the post-extraction probe
  built `host/Bin/cl` case-sensitively and rejected MSVC 4.0's all-caps
  `BIN/CL.EXE` layout (the 4.2/5.0 trees are lowercase, so it never
  tripped before).  The probe now reuses a new `_vendored_binary` helper
  (case-insensitive on subdir AND filename, extracted from
  `_resolve_binary`'s host logic) against the actual extracted dir — the
  spec's `host_path` is captured at import time and can predate the
  extraction.
- **`--sweep-toolchain` covers the full 4.0→7.0 line**: the sweep's MSVC
  version list gained the now-vendored 4.0 (uppercase BIN/INCLUDE layout
  — the sweep path is case-sensitive, so it had to be spelled exactly).
  The detector can suggest any of these profiles, so the sweep can now
  answer "which MSVC built this function" for every vendored version.
- **wine stderr filter strips libEGL/DRI3 display noise**: headless Xvfb
  compiles emit `libEGL warning: DRI3 error...` / `Ensure your X server
  supports DRI3...` lines with no `[hex]:` prefix, so the noise patterns
  missed them and a failed wine-runtime compile (e.g. MSVC 4.0/5.0 under
  Xvfb) reported only display chatter, drowning the real compiler error.
  `libEGL warning:`/`libGL warning:`/`MESA:` lines are now stripped
  (verified: the sample noise collapses to just the C2143 error).
- **Integration-validated the old-MSV C profiles through the full
  pipeline**: `compile_to_obj` with real configs for msvc400/msvc420/msvc5
  (vendored trees, wine runner, msvc-style flags) produces real .obj
  files end-to-end — the smoke gate covers the raw compilers; this
  confirms the config → resolve_cl_command → wine → CL.EXE glue too.
- **Old-MSV C line containerized** (`rebrew/msvc:4.0-win32`,
  `rebrew/msvc:4.2-win32`, `rebrew/msvc:5.0-win32`): the three were the
  last wine-runtime toolchains without docker images (their mirror
  tarballs were only pinned for the host tree in the previous session).
  New Dockerfiles follow the shared rebrew/base pattern (sha256-verified
  download inside the image, `cl` wrapper from wrapper-common.sh,
  OCI labels) with the same pinned sources as `rebrew toolchain vendor`,
  so images and host trees stay byte-identical; the smoke gate's COFF
  goldens carry over unchanged (path-independent objects — the images
  pass 11/11 via the docker path).  `spec.family` for these now derives
  `msvc` from the image repo, which also fixes `toolchain build`'s
  directory resolution (`toolchain/msvc/4.2-win32`, not the wrong
  `toolchain/msvc420/...`).  Host fallback remains for image-less
  environments.
- **`rebrew/base` Dockerfile fixed — `toolchain build` broken for every
  image since the OCI-label commit**: adding the LABEL block to
  `toolchain/base/Dockerfile` accidentally deleted the leading
  `RUN dpkg --add-architecture i386` line, leaving a lone
  `&& apt-get update` (a Dockerfile parse error).  `toolchain build`
  rebuilds base first for every image, so ALL image builds via the CLI
  failed (direct `docker build` worked only because the old
  `rebrew/base:1.0` image was already present).  The RUN line is
  restored and a CI-safe static test now pins the structure (no lone
  `&&` without a preceding `RUN` in any tracked Dockerfile), so the same
  class of edit regression is caught in CI without docker.
- **`init --guess-compiler` failure message is actionable**: an
  unrecognizable binary (detector family unknown) now tells the user to
  pass `--compiler <profile>` explicitly instead of a bare "cannot
  guess".  (Workflow validation: `doctor` on a real msvc420 project is
  all-clear — compiler reachable under headless wine, include/lib
  resolve; `init --guess-compiler` on a real DOS binary bootstraps a
  correct tc16 project with MZ/x86_16 config.)
- **Dependency audit (deps-review)**: `pygments` removed from the main
  dependencies — declared but never imported anywhere in src/tools/tests
  (rich's `Syntax` highlighting is unused; pygments remains in the lock
  as rich's transitive optional).  The `idna>=3.15` pin is documented as
  a no-direct-import transitive security floor (Unicode-property DoS in
  idna <3.15, forced through httpx's tree) — previously an unexplained
  zero-import pin that looked like a removal candidate.
- **Roundtrip suite covers the full MSVC line incl. 4.0**:
  `msvc-4.0-win32` joins the compile → extract → compare → EXACT
  roundtrip (its all-caps `BIN`/`INCLUDE` layout was missing from the
  config candidate lists, and the `msvc-4.0-win32` compat alias — the
  lowercase form every other version has — was absent, only `MSVC400`
  existed).  All 6 roundtrip toolchains (6.3/6.6/7.0/4.2/5.0/4.0) now
  prove byte-exact through the full pipeline.
- **New guard: every image-backed toolchain's Dockerfile must be
  git-tracked** — five images (msvc400/msvc420/msvc5 + tc16/tc20) are
  built from UNTRACKED Dockerfiles/tarballs, so a fresh clone cannot
  rebuild them at all (the smoke goldens and vendor sources all reference
  these files; only the local working tree has them).  The guard runs
  `git ls-files` against the image registry and asserts each Dockerfile
  is committed.  It currently **xfails (documented)** because those five
  files await the session commit; it goes green the moment
  `toolchain/msvc/{4.0,4.2,5.0}-win32/Dockerfile`,
  `toolchain/borland/{2.0,3.1}-win16/{Dockerfile,tc*-run.sh,*.tar.xz}`
  land in git.
- **`toolchain smoke --print-goldens`** — regeneration path for the
  golden table: recomputes each toolchain's masked sha256 WITHOUT
  comparing, so bumping a pinned source (new tarball/snapshot) is a
  mechanical two-step (run, verify stable across a second run, paste into
  `_SMOKE_GOLDEN`) instead of hand-deriving hashes.  Full-table
  cross-check: all 11 stored goldens recompute to MATCH (zero drift).
  Unit test pins the masked-hash output shape.
- **`toolchain pull` failure suggests `toolchain build`**: rebrew images
  are BUILT from pinned sources, not pushed to a registry — pulling an
  absent image returned a raw "pull access denied" dead end.  The error
  now says to run `rebrew toolchain build <name>` (regression test).
  TOOLCHAIN.md's smoke section documents `--print-goldens` and the
  11/11 image+host gating.
- **Flag-sweep fallback pinned for the expanded MSVC line**: verified
  msvc400/msvc420/msvc5/6.3/6.6/7 all share the msvc6 flag set in
  `generate_flag_combinations` (correct — they're MSVC-style; the tier
  routing also correctly stays on the MSVC tiers).  New regression test
  pins the equivalence so a future profile-specific flag set cannot
  silently diverge the sweep for these profiles.
- **tc16/tc20 docker wrappers embed the TCC log in the error**: the old
  message was "TCC produced no object (see /work/tcout.txt)" — a
  container-internal path the user cannot read (compile_to_obj's temp
  workdir is cleaned up before the error is seen).  The wrapper now
  embeds the compiler log in the error itself (matching the host
  `tc16.py` behavior), so a bad stub reports the actual TCC diagnostic
  (e.g. "Declaration syntax error") through `rebrew test --json`.
  Surfaced while validating the 16-bit DOSBox workflow end-to-end
  (init → discover → skeleton → test → SIZE_MISMATCH on the fixture).
- **ADR-007 records the completed containerization contract**: every
  registry toolchain now satisfies three invariants — a pinned source
  shared by image AND host tree (byte-identical by construction), a
  docker image (gcc-pe the documented exception), and a smoke-gate slot
  (image path or uniform host-runner path).  The git-tracked-Dockerfile
  guard enforces the tc16/tc20 class of regression; ADR-006's stale
  "6/6 images" line now points at ADR-007.

## [0.1.0] - 2026-08-08

First tagged release.  Rebrew is a compiler-in-the-loop decompilation
workbench: it compiles your C source with MSVC6 (under Wine/wibo), byte-compares
against the target binary, and drives the match loop with a GA engine,
symbolic proving, and a coverage database.

### Added

- **Matching**: `rebrew match` GA engine with flag sweeps (`--flag-sweep-only`,
  tiers quick/targeted/normal/thorough/full), solved-cflag seeding
  (`--seed-from-solved`), batch resume (`--skip-recent`, `--ga-history`,
  `--sweep-then-ga`), and `output/ga_runs` result storage.
- **Proving**: `rebrew prove` symbolic equivalence via angr — EDX/64-bit return
  checking (`--check-edx`), memory side-effect comparison (`--watch-va`), slice
  proving (`--start-offset/--end-offset`), and batch `--all` mode.
- **Round-trip**: `rebrew round-trip` splices every EXACT/RELOC function's
  compiled bytes back into a copy of the target PE and SHA-256 verifies the
  result.  Resolves MSVC `$SG<N>`/`??_C@` string constants by content, decodes
  Ghidra VA-encoded auto-names (`_g_1003546c`), maps `$L<N>`/`$cleanup_loop$<N>`
  jump tables from the .obj layout, and binds string literals that are strict
  prefixes of the target's copy.  Wrong fallbacks surface as
  `catalog_resolution_drift`, never silent corruption.
- **Similarity & triage**: `rebrew similar` (structurally similar functions),
  `rebrew near-diag` (structured diff diagnosis), `rebrew imports` (IAT
  introspection), `rebrew todo` (ROI-ranked action list).
- **Dashboard**: `rebrew dashboard` — read-only web dashboard over the
  coverage database (paired with the `recoverage` project).
- **Agent skills**: `rebrew skills` bundles five workflow skills
  (intake, workflow, matching, data-analysis, ghidra-sync) for AI agents.
- **Verification**: `rebrew verify --compare` detects regressions against the
  last saved report; `rebrew verify -o db/verify_results.json` feeds the
  coverage database (`build-db` imports it into the `verify_results` table).
- **Ghidra sync**: ReVa MCP sync plus a new `ghidra_backend = "cli"` backend;
  pull signatures/structs/datatypes/comments/data, size sync, bookmark sync.
- **Data analysis**: `rebrew data --dispatch`, `--bss`, `--fix-bss`,
  `--gen-header`, and configurable dispatch thresholds.
- **Catalog**: `rebrew catalog --data-json`, `--export-ghidra-labels`,
  `--fix-sizes`, `--csv`, CATALOG.md generation; `rebrew build-db` produces a
  versioned SQLite coverage DB (schema v4) with cell-level per-byte states.
- **Watch mode**: `--watch` on test/verify/diff/match/prove re-runs on source
  change.
- `rebrew doctor` extended with optional-tool (angr/claripy), FLIRT-signature,
  and Ghidra-sync health checks; `rebrew doctor --install-wibo` bootstraps the
  lightweight Wine replacement.
- **Metadata**: volatile per-function fields (STATUS, SIZE, CFLAGS, BLOCKER,
  NOTE, GHIDRA, …) live in `rebrew-function.toml`; per-directory data metadata
  in `rebrew-data.toml`; both under `cfg.metadata_dir`.  `rebrew lint --fix`
  migrates inline leftovers.
- **Property/fuzz tests**: hypothesis-based tests across parsers and the COFF
  .obj extraction helpers; the suite runs 3460 tests / 0 skipped with
  `uv sync --all-extras` (angr included).

### Changed

- **Breaking:** `coverage.db` schema is version `"4"` (normalized,
  range-checked cell rows; `cells` → `sections` foreign key with cascade
  delete).  `rebrew build-db` refuses to write into a version `"3"` database;
  rebuild it with `rebrew build-db --force`.  See `docs/DB_FORMAT.md`.
- **Breaking:** volatile annotation fields migrated out of `.c` headers into
  `rebrew-function.toml`; inline `// STATUS:` / `// SIZE:` are deprecated
  (lint W019) and no longer authoritative.
- angr is installed by the documented dev install (`uv sync --all-extras`);
  `rebrew prove` tests run for real instead of skipping.
- Ghidra MCP failure warnings name the failing endpoint and the fix.
- `rebrew catalog --fix-sizes` and `rebrew data --fix-bss` write metadata to
  `cfg.metadata_dir` (previously the source directory — fixes were silently
  lost).
- `rebrew build-db` emits `paths.sourceRoot` and imports the last
  `verify_results.json`; CATALOG.md coverage is computed from the real .text
  size.

### Fixed

- Round-trip oversize check now requires exact compiled size (a longer compile
  is no longer silently truncated); string search bounded by raw section
  extent.
- Negative section offsets (annotated VAs outside the binary) no longer abort
  the whole `build-db` rebuild (CHECK-constraint violation); grid skips them,
  build-db clamps defensively.
- `remove_annotation_key` no longer reports a write when nothing was removed;
  same-value writes are no-ops.
- 30 mypy errors in `rebrew prove` under real angr types; `SimState` typing,
  `self.addr` narrowing.
- Config load warns when the target binary is missing (image_base
  auto-detection skipped) instead of silently zeroing the layout.
- Ghidra auto-names with 9+ trailing hex digits are no longer mis-decoded as
  VAs.
