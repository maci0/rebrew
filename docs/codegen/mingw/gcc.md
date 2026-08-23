# MinGW GCC — codegen patterns

MinGW GCC targeting PE/x86_32 (`i686-w64-mingw32-gcc`).  Byte-exact
matching requires the author's *exact* GCC version — modern GCC (16.x)
and old GCC (4.x–7.x) differ in argument passing, stack probing and
scheduling, so old MinGW-built binaries usually match only
structurally.  Verified with **GCC 16.1** at `/O1`/`/O2`.

**Profiles:** `gcc-pe`.

## Prologue & frame pointer

- /O1: frame-based for complex functions; /O2: `push ebp; mov ebp,esp`
  omitted for leaves.  Not a reliable discriminator (unlike Borland's
  always-on frame).

## Argument passing — the era fingerprint

- **Modern GCC (≥ ~8)**: args stored with `mov dword ptr [esp+N],
  imm` / reloaded from `[esp+N]` (accumulate-outgoing-args); **old
  GCC**: `push`es args right-to-left.  rebrew's `_gcc_era_hint`
  counts `c7 04 24`/`89 04 24` (modern) vs `6a` push-immediates
  (old) to name the era.

## Register conventions

- Callee-saved `ebx/esi/edi/ebp` (x86-32 standard); `eax/ecx/edx`
  scratch.  No PIC register games on PE.

## Integer division

- **Magic constants, same values as MSVC 5.0+**: `x/3u` →
  `mov eax,0xAAAAAAAB; mul …; shr edx,1` — the constants are
  mathematically forced and shared with MSVC; only the surrounding
  schedule differs (GCC's `mul edi`/`imul` operand order and shift
  placement).  Magic presence is *not* a family discriminator.

## 64-bit arithmetic — inlined (the GCC marker)

- **64-bit multiply is INLINED** — `i64mul`: `imul`/`imul` + `mul` +
  `add` (`0f af … 0f af … f7 e2 … 01 d9`) — no helper call.  MSVC
  (`__allmul`), Borland (`__llmul`) and Watcom (`__I8M`) all call a
  helper.
- **64-bit shifts use `shld`** — `i64shl`: `shld edx,eax,cl` (`0f a5
  c2`) + `shl eax,cl` + `test cl,0x20` (`f6 c1 20`) — vs helper calls
  elsewhere.
- **64-bit division calls `__divdi3`/`__udivdi3`** (libgcc) — the
  `___divdi3` symbol in the object; distinct from `__alldiv` (MSVC),
  `__lldiv` (Borland), `__I8D` (Watcom).

## FPU

- x87 by default on x86-32 (`fld`/`fadd`, `.rdata` constants); SSE2
  (`addsd` etc.) with `-msse2`/`-march=…` (cpubench, a `-O2
  -march=pentium4` MinGW build, shows 348 SSE2 FP ops).
- **`long double` is 80-bit** — `ldadd`: `fld tbyte ptr [esp+4]`
  (`db 6c 24 04`) + `faddp st1,st0` (`de c1`) — shared with Borland
  (bcc32/TC), distinct from MSVC/Watcom (long double == double,
  `fld qword`).
- **cmov at default flags** — the i686 default target lets GCC emit
  `cmovs`/`cmovl`/`cmovg` (`0f 48/4c/4f`) for `mabs`/`mmin`/`mmax`
  with no `-march` flag — MSVC only emits cmov from VC 11.0.
- **`fnstcw; or ah,0xc; fldcw` FP-truncation dance** — `(int)a` /
  `(unsigned)a` compile to the control-word round-trip
  (`fnstcw [esp]; or ah,0xc; fldcw [esp]` then `fistp`, CW restored
  after) — GCC does the truncation dance inline where every other
  toolchain calls `__ftol` (MSVC/Borland), `__CHP` (Watcom) or uses
  `cvttsd2si` (VC 11.0).  Verified in probe4 (`d2i`/`d2u`).
- **`fdivr` for `a/5.0`** — `a/5.0` compiles to `fld [const];
  fdivr [a]` (the reverse divide) where MSVC 8.0+ uses `fdiv` and
  MSVC 2.0–7.1/Watcom/bcc32 use reciprocal-`fmul`.  Verified in
  probe5 (`fdiv5`).
- **8-byte stack alignment in FP functions** — `and esp,0xfffffff8`
  (`83 e4 f8`) appears in GCC's FP-heavy functions (verified `d2i`);
  **caveat: VC 11.0 aligns too** (SSE2 requires it — probe5 `sq`),
  so the marker is "GCC + VC 11.0, never VC 2.0–10.0", not
  GCC-only.

## Padding & nops — the unique markers

- **GNU multi-byte nops `0f 1f 00` / `0f 1f 40 00`** — unique to
  GCC/Zig among this set; the primary MinGW detector (plus the
  `.buildid` section from GNU ld).
- **`rep ret` (`f3 c3`)** — GCC's return-after-branch idiom.
  Verified present in real MinGW binaries (cpubench, test_sse2: 1
  each), absent in MSVC binaries (win2k-*, rt63, tcmd: 0).  A weak
  MinGW signal when `.buildid` is missing.
- **`8d 74 26 00` (`lea esi,[esi]`) 3-byte nop** — GCC uses the SAME
  bytes as MSVC 6.0's 3-byte nop.  Never count it as MSVC-exclusive
  evidence.
- **CS-prefixed 8-byte nop `2e 8d b4 26 00 00 00 00`** — GCC 16 pads
  with the `2e`-prefixed form at /O2//O3 (MSVC's 8-byte nop is the
  unprefixed `8d b4 26 00 00 00 00`).  Verified in the probe3 O2/O3
  objects.

## String ops

- Does **not** `rep stosd` the memset-shaped loop in the probe (GCC
  16.1 calls memset or emits plain stores) where every MSVC version
  inlines `f3 ab`.  GCC *can* emit `rep movs` for memcpy under some
  `-mstringop` settings — presence is weak evidence either way.
- Fixed-size memcpy: GCC unrolls 128-byte copies as a loop of mov
  pairs (`8b 41 78 89 42 78 …` with `83 f8 78`) — MSVC uses
  `rep movsd` for the same size.

## Stack probes

- **`___chkstk_ms`** (call-based, size in EAX) for big frames — the
  symbol distinguishes it from MSVC's `__chkstk` in objects and
  unstripped binaries.

## Loops / Switch

- `dec/jnz` loops with `0f 1f` alignment; jump tables via `.rodata`
  — no distinctive single-version marker verified.

## 100% unique to this version (family level)

- **`0f 1f` GNU nops** and **`rep ret` (`f3 c3`)** — verified absent
  in every MSVC/Borland/Watcom object and binary tested.
- **Inline 64-bit mul** and **`shld`-based 64-bit shifts** — verified
  in probe3 (`i64mul`/`i64shl`); every other toolchain calls a helper
  (`__allmul`/`__llmul`/`__I8M`).  The division helper is
  **`___divdi3`** (libgcc).
- **`cmov` at default flags** (no `-march`) — verified `mabs`/`mmax`/
  `mmin` at /O2; MSVC only from VC 11.0.
- **80-bit `long double`** (`fld tbyte`, `db`) — shared with Borland;
  the MSVC/Watcom `fld qword` side is the discriminator.
- **CS-prefixed 8-byte nop** (`2e 8d b4 26 …`) at /O2//O3.
- Not unique per GCC *version*: GCC 16.1's own output is what was
  verified; the era split (pre-8 push vs 8+ `[esp]` args) is the only
  verified version-level discriminator, and it separates eras, not
  exact versions.  **An older MinGW GCC was not obtainable in this
  environment** (only 16.1 is installed; no older i686-w64-mingw32
  package available offline) — the pre-8 era claims rest on the
  documented push-arg convention, not on a controlled compile.
  Exact-GCC-version matching is not achievable by codegen
  fingerprinting alone (documented in TOOLCHAIN.md).

## Version deltas (era scale)

- Pre-8 vs 8+: push-arg → `[esp]`-store arg passing; chkstk
  convention changes; scheduling.  **Verified gap:** no older GCC was
  available to reproduce the pre-8 side (see above).  Old MinGW
  binaries match only structurally — document the semantic decomp and
  blocker the byte delta.

## Probe12: static-helper inlining — verified negative (not a discriminator)

GCC inlines the probe12 static helpers at -O1 and -O2 — the callers
are bare 11–12B bodies with no `call` (`f1` at both levels is
`mov edx,[esp+4]; lea eax,[edx*8]; sub eax,edx; add eax,2; ret`) — so
the MSVC 7.0+ inlining marker does not separate GCC from anything;
inlining is unconditional.  Verified in a probe12 re-run with native
`i686-w64-mingw32-gcc` (`out12_gcc/probe12_{O1,O2}.obj`).

## Probe13: string intrinsics — verified negatives

- **strlen/memcmp/strcmp are NOT inlined** — all four probe13
  functions emit a tail-call or stack-arg call to the libc entry
  (`e9 00 00 00 00` PLT form) at -O1/-O2; the MSVC `repne scasb` /
  `repe cmpsb` intrinsic forms have no GCC counterpart here.
- **signed `char`** — `c_cmp` (`a < 0`) shifts the sign bit
  (`0f b6 44 24 04 c0 e8 07`), unlike Watcom's unsigned fold.
- **`unsigned char` sums use `movzx`** (shared with MSVC 7.0+ and
  Watcom); **8-byte structs return in EAX:EDX** (shared with MSVC
  5.0+); **`g_val+1` uses `83 c0 01`** (shares VC 8.0's
  add-over-inc encoding).  Zig `cc` output (probe13 re-run, zig
  0.16) shares every one of these family shapes — no new
  zig-vs-gcc byte marker.

## Probe14: statement idioms — verified negatives

- **64-byte memcpy is a register-block copy** (`8b 0a 89 08 …` —
  8-dword mov/store pairs), NOT `rep movsd` — the MSVC rep-movs form
  has no GCC counterpart; Zig (LLVM) inlines the same copy as
  `movups`-pair SSE loads/stores.
- **64-bit shifts inline `shld`/`shrd`** (`0f a4 c2 04 c1 e0 04`) —
  byte-identical to MSVC 7.0+ and bcc32 (shared trait, not a
  discriminator); Watcom alone calls `__I8LS`.
- **`g_counter++` round-trips EAX with `83 c0 01`** — shares VC 8.0's
  add-over-inc encoding (and the memory-inc form is bcc32-exclusive).
- **zero-compare** — `a == 0` = load + `test` + `setz` (like MSVC
  5.0–7.1); the ternary `a ? 7 : 13` uses the sbb trick
  (`83 7c 24 04 01 19 c0 83 e0 06 83 c0 07`) — compare-against-1
  shared with MSVC 2.0/4.x's style, but `sbb eax,eax` (`19 c0`) vs
  MSVC's `1b c0`.

## Probe15: function boundaries — verified negatives

- **NO stack cookies** — the buffer-copy function opens
  `push ebx; xor eax,eax; sub esp,0x40` with no cookie load/xor; the
  MSVC 8.0+ `/GS` cookie-mix (`33 c4`) has no GCC counterpart.
- **wide-literal sums ARE folded** — `L"AB"[0] + L"AB"[1]` compiles
  to `mov eax,0x83` like MSVC 7.0+ (and Zig/LLVM); only
  2.0–6.0/bcc32/Watcom load from memory.
- **setcc compares the second operand in memory** — `a < b` =
  `cmp eax,[esp+4]` after loading b (`39 44 24 04`), sharing the
  8.0+ memory-compare form (MSVC: `cmp ecx,[esp+8]`).
- **stdcall args load in REVERSE order** — `mov eax,[esp+8]; add
  eax,[esp+4]` — shared with MSVC 5.0–9.0 and Zig.

## Probe16: 64-bit division + C++ — verified negatives

- **64-bit division stages the operands on a stack frame for
  `__divdi3`** — `push ebp; mov ebp,esp; sub esp,0x10; mov eax,
  [ebp+0x10]; mov edx,[ebp+0x14]; mov [esp+8],…` — NOT the MSVC
  `__alldiv` register-load + 4-push form; the frame-staged libcall
  has no MSVC counterpart here.
- **C++ `delete` tail-jumps** (`jmp` to the deallocator) — shared
  with MSVC 7.0+; vtable dispatch includes a null-vtable check
  (`cmp eax,0; je`) absent from MSVC's bare `mov eax,[ecx]; call
  [eax]`.

- **Corpus pointer** — machine-checked in `corpus.json` (7892 records; the mechanical sweep confirmed this file's records and surfaced no un-documented markers here).

## Probe17: conventions + allocator behaviors

- **Probe17 verified-negative**: the probe17 convention/allocator markers are MSVC-internal (register forms, zero-register anchoring); GCC's behavior follows the shared conventions — no new GCC marker; corpus pointer.

- **Decomp idioms** — the probe19-25 game-idiom signatures for this toolchain are in [DECOMP_IDIOMS.md](../DECOMP_IDIOMS.md) and the corpus (`probe19`-`probe25` records).

## Probe22: guild-rule verification (round 19)

- **Probe22 (MinGW GCC)**: GCC emits the AH-slot ops for `*player` flags (`or ah,0x30` = `80 cc 30` — family trait, not MSVC-exclusive); C24 negation uses `cmovne` (`0f 45 c2`); the 36B memset is not inline (libcall staging).  See RULES.md F15/C24.


## Probe23: Findings 23-36 shapes (round 20)

- **Probe23 (MinGW GCC)**: idx via `lea`-family with GCC's register order; division via libgcc calls at -O2 for /60? (recorded in corpus); the SIB/if-conversion forms differ from MSVC.  See RULES.md C27/F19.


## Probe24: Findings 37-43 primitives (round 21)

- **Probe24 (MinGW GCC)**: word zero-extend via `movzx`-family; size-dispatch as compare chain; in-place and via memory operand — LLVM/GCC traits recorded in the corpus.  See RULES.md C29/F24.


## Probe25: Finding 44 primitives (round 22)

- **Probe25 (MinGW GCC)**: clamp via cmov-family; ×589 via `imul`-or-lea per GCC version — recorded in the corpus.  See RULES.md C30/C31.


## Verification

Probe `/O1`/`/O2`/`/O3` via native `i686-w64-mingw32-gcc` 16.1
(`gccpe_{O1,O2,O3}.o`; O2 ≡ O3, O1 differs only in scheduling);
probe3 (`out3/gccpe_O2.o`) for the i64/`shld`/`__divdi3`/`fld tbyte`/
cmov/`2e`-nop findings; corpus: cpubench, test_sse2 (MinGW 16 —
`0f 1f`=278/308, `f3 c3`=1, SSE2 FP, magic division present).
