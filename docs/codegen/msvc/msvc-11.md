# MSVC 11.0 — codegen patterns

MSVC 11.0 (VS 2012, CL 17.00.50522).  The newest preserved MSVC; the
first to emit **SSE2 FP instructions** in the probe — the only verified
codegen marker unique to a single 32-bit MSVC version.

**Profiles:** `msvc1100` — Rich build 50522; linker 11.0.

## Prologue & frame pointer

- `/O2`: no frame pointer for simple functions; `bsum` (unrolled)
  pushes all four callee-saved registers (`push ebp; push esi; push
  edi; push ebx`).
- `/O1`: some functions keep `push ebp; mov ebp,esp` (4 frame
  prologues in the /O1 probe) — the highest /O1 frame count of any
  MSVC version probed (VC 6.0–10.0 /O1: 1–2).

## FPU / SSE — the 11.0 change

- **SSE2 FP ops appear**: `addsd`/`mulsd`/`divsd` (`f2 0f 58/59/5e`)
  and `addss` (`f3 0f 58`) verified in the /O1 and /O2 probes (1–2
  occurrences each).  Every earlier MSVC version (2.0–10.0) is pure
  x87 — zero `f2 0f 5x` in the census.
- x87 is *not* gone: `fldz` (`d9 ee`) and `fld` still appear alongside
  — VS 2012 defaults x86 to `/arch:SSE2` but keeps x87 for parts of
  the FP schedule.  "SSE2 FP ops present" is the marker, not "pure
  SSE2".

## /GS security cookie

- Same as [msvc-9.md](msvc-9.md): cookie prologue/epilogue in
  `bigstack` (72B).

## Loops

- Same unrolling as 9.0/10.0 (`bsum` 78B); loop-align `lea esp,[esp]`
  (`8d 64 24 00`) at the peeled loop head (3 at /O2) and `lea
  ebx,[ebx]` in `bigstack`.

## Integer division / String ops / Switch

- Magic + post-shift division; `rep stosd`/`rep movsd`; dense jump
  tables — all unchanged.

## Stack probes

- `mov eax,<size>; call __chkstk` — unchanged, see
  [msvc-6.md](msvc-6.md).

## Optimization fingerprints

- /O1 keeps frame pointers more often (see above); /O2 unrolls.

## 100% unique to this version

- **`cmov` for min/max/clamp** — `imax`/`imin` compile to
  `cmp dword ptr [esp+4],eax; cmovg/cmovl eax,[esp+4]` (`39 44 24 04 0f
  4f 44 24 04` / `0f 4c`) and `clamp`'s upper bound to `cmp eax,ecx;
  cmovg eax,ecx` (`0f 4f c1`).  **No version before 11.0 emits a
  conditional move** for these (2.0–10.0 all use branches) — verified
  in probe2.  The only VC 11.0-unique marker among the line.
- **SSE `movq` for 16/32-byte memcpy** — `memcpy(d,s,16)`/`(,32)`
  compile to `movq xmm0,[s]` (`f3 0f 7e`) + `movq [d],xmm0` (`66 0f
  d6`) pairs by default from VC 11.0; VC 2.0–10.0 use integer mov
  pairs (16 B) / `rep movsd` (32 B).  Verified in probe3 (`c16`/
  `c32`).  **Caveat: VC 8.0–10.0 produce the same SSE forms under
  `/arch:SSE2`** (probe11) — the marker is "11.0 by default", not
  11.0-only.
- **`xorps`+`movq` 16-byte memset** — `memset(d,0,16)` →
  `xorps xmm0,xmm0` (`0f 57 c0`) + 2× `movq` (`66 0f d6`); 2.0–10.0
  use 4× `mov dword` pairs.  Verified in probe3 (`z16`); same
  `/arch:SSE2` caveat as the movq copies.
- **128-byte memset → libcall** — `memset(d,0,128)` becomes a call to
  the CRT (`push 0x80; push 0; push [esp+0xc]; call memset; add
  esp,0xc` — `68 80 00 00 00 6a 00 ff 74 24 0c e8`); 2.0–10.0 inline
  `rep stosd`.  Verified in probe3 (`z128`).
- **64-bit helper args pushed from memory** — `i64mul`/`i64div` push
  the four dwords straight from the stack (`ff 74 24 10` ×4) before
  `call __allmul`/`__alldiv`; VC 4.1–10.0 load them into registers
  first.  Verified in probe3.
- **`cvttsd2si` inline for FP→int** — `(int)a` compiles to
  `cvttsd2si eax,[esp+4]` (`f2 0f 2c 44 24 04`, float: `f3 0f 2c`);
  VC 2.0–10.0 emit `fld; jmp __ftol` (a tail-jump to the helper).
  Verified in probe4 (`d2i`/`f2i`) at both /O1 and /O2.  Caveat: GCC
  with SSE2 also emits `cvttsd2si` — the marker is 11.0-unique among
  the MSVC line, not vs GCC.
- **SSE2 FP handoff** — `a+1.0` compiles to `movsd xmm0,[esp+4]; addsd
  xmm0,[const]; movsd [esp+4],xmm0; fld [esp+4]; ret` — the FP result
  is computed in SSE2, then handed to x87 for the return value.  The
  `f2 0f 10/58/11` + `dd 44 24` handoff shape is verified 11.0-only
  (2.0–10.0 compute purely in x87).
- SSE2 FP ops by default (addsd/mulsd/subsd/divsd, `f2 0f 5x`) — as in
  probe1; shared with any `/arch:SSE2` build of an older version, so
  "unique at default flags", not absolute.

## Version deltas

- From VC 10.0: SSE2 FP ops + the SSE2→x87 handoff; `cmov` for
  min/max/clamp; memory-operand `imul` in div magic (10.0+); cdq-abs
  (10.0+); /O1 frame-pointer frequency rises; `bsum` grows 74B → 78B
  (extra `lea esp,[esp]`).

## Probe12: static-helper inlining — verified positive

Small static helpers inline at /O2 and /O1 (11–12B callers), matching
the VC 7.0+ era marker.  Verified in probe12 (`f1`/`f2`/`fl`).

## Probe13: string intrinsics + promotion — verified

- **strlen manual scan loop** at /O2 (`8d 50 01 8a 08 40 84 c9 75 f9
  2b c2`), the 7.0+ form.
- **memcmp(8B) = 2-dword compare + byte tail** at /O2 (`be 04 00 00
  00` counter; `3a 02` / `8a 41 01 3a 42 01` byte tail) — the 11.0
  form of the 8.0+ dword-loop family.
- **signed-char compare against the zero register in memory**
  (`33 c0 38 44 24 04 0f 9c c0`) — 8.0+ form.

## Probe14: statement idioms — verified

- **ternary `a ? 7 : 13` uses `cmov`** (`83 7c 24 04 00 b8 0d 00 00
  00 b9 07 00 00 00 0f 45 c1`, /O1: push/pop constants + `0f 45 c1`)
  — extends the VC 11.0 cmov trait to ternaries; note Zig (LLVM)
  also emits `cmov` (`0f 44 c1`) for the same expression, so this is
  an 11.0+LLVM trait, not MSVC-exclusive.
- **64-bit `× 7` inlines a `shld`-based decomposition** (`0f a4 c2 03
  c1 e0 03 2b 44 24 04 1b 54 24 08`) — VC 10.0/11.0 both inline;
  5.0–9.0 call `__allmul`.
- **`g_counter++` round-trips EAX even at /O1** (`a1 … 40 … a3`) —
  11.0 is the ONLY version that keeps the EAX round-trip at /O1
  (4.1–10.0 use the memory-form `inc dword ptr [g]` — `ff 05` — at
  /O1; 2.0 also round-trips).
- **zero-compare** — memory compare against the zero register
  (`33 c0 39 44 24 04 0f 94 c0`), the 8.0+ form.
- **64-byte memcpy = `rep movsd`** — shared by every MSVC version.

## Probe15: /GS + setcc + address forms — verified

- **`/GS` cookie prologue** — `sub esp,0x44; mov eax,[__security_cookie];
  xor eax,esp; mov [esp+0x40],eax` (`a1 <abs> 33 c4 89 44 24 40`),
  the 8.0+ cookie-mix form.
- **signed setcc compares in memory** — `cmp ecx,[esp+8]; setl al`,
  the 8.0+ form (shared with GCC/Zig).
- **address form** — `p[i*4+3]` = `add ecx,ecx` + `mov eax,
  [eax+ecx*8+0xc]` — the 10.0/11.0 add-self + scale-8 decomposition.
- **stdcall args load in DIRECT order** — 11.0 returns to `mov eax,
  [esp+4]; add eax,[esp+8]` (2.0/4.1 form) after 5.0–9.0's reverse
  order (Zig/LLVM also reverses).
- **`wchar >= 0x100`** = `mov eax,0x100; cmp ax,[esp+4]` (9.0+ loads
  the constant first, vs 2.0–8.0's memory-immediate `66 81 7c 24 04`).

## Probe16: 64-bit division + C++ — verified

- **64-bit division = 4× MEMORY-push helper call at /O2** — `push
  dword ptr [esp+0x10]` ×4 + call (`ff 74 24 10 ff 74 24 10 ff 74
  24 10 ff 74 24 10 e8`) — VC 11.0 is the ONLY version using the
  memory-push form at /O2 (5.0–10.0 register-load + 4-push; every
  version uses the memory-push at /O1).  The 11.0 push-from-memory
  trait, now in its third dimension (i64 div, vtable args).
- **C++ `new int[n]` adds a CHECKED array-size multiply** — `mov
  edx,4; mul edx; seto cl; neg ecx; or ecx,eax` (the overflow-guard
  before the `operator new[]` call); `new int`/`delete` stay
  tail-jumps; vtable args are pushed from memory (`push dword ptr
  [esp+8]`).

- **Corpus pointer** — machine-checked in `corpus.json` (7892 records; the mechanical sweep confirmed this file's records and surfaced no un-documented markers here).

## Probe17: conventions + allocator behaviors

- **Probe17 allocator/conventions**: varargs float→double via SSE (`movss; cvtss2sd; movsd [esp]`); `-1` stores emit the immediate form PLUS a dead `or eax,-1`; 12-byte sret built with SSE `movq`.  See RULES.md A5/A8/B5.

- **Decomp idioms** — the probe19-28 game-idiom signatures for this toolchain are in [DECOMP_IDIOMS.md](../DECOMP_IDIOMS.md) and the corpus (`probe19`-`probe28` records).

## Probe22: guild-rule verification (round 19)

- **Probe22 (11.0)**: C24 `sete`+`neg` with `push`-immediate constant staging; F15 pure dword forms (`f7 c1` test); 36B memset via SSE `movq` pairs; opaque memset libcall with memory-push args (`ff 74 24 …`).  See RULES.md C24/F15/E11/E14.


## Probe23: Findings 23-36 shapes (round 20)

- **Probe23 (11.0)**: branchless if-conversion becomes `cmov` (`0f 44 c1` — the r= form too); FPU clamp via SSE `comisd`; idx via lea×8−1/×8-SIB; division magic `imul [mem]` + memory-push staging.  See RULES.md F19/F22/C27.


## Probe24: Findings 37-43 primitives (round 21)

- **Probe24 (11.0)**: in-place double add via SSE (`movsd; addsd; movsd`); word zero-extend movzx; size-dispatch dec-chain; in-place word and.  See RULES.md D9/C29/F24.


## Probe25: Finding 44 primitives (round 22)

- **Probe25 (11.0)**: clamp becomes `cmovle`/`cmovns`; ×589 imul; byte-arg movzx + memory-push args.  See RULES.md C30/C31.


## Probe26: Finding 45 early-return placement (round 23)

- **Probe26 (11.0)**: inline early returns; negative constants via `lea eax,[reg-N]` (`8d 41 fd`); cmov-era tails.  See RULES.md F25.


## Probe27: Findings 46-50 primitives (round 24)

- **Probe27 (11.0)**: memory-operand or; `cmov`-era guard tails; frame-based prologues.  See RULES.md C32.


## Probe28: decompedia/CODEGEN_PATTERNS claims (round 25)

- **Probe28 (11.0)**: FP const via SSE (`movsd; addsd; movsd`); short return `mov eax`; memory compares.  See RULES.md D10/C34.


## Verification

Probe `/O1`/`/O2` via `rebrew/msvc:11.0-win32` (`msvc1100_{O1,O2}.obj`);
probe2 (`msvc1100_O2.obj` — `cmov` in `imax/imin/clamp`, SSE2 `addsd`
handoff in `fadd1`) and probe3 (`msvc1100.obj` — `movq` copies,
`xorps` memset, z128 libcall, push-memory i64 args) diffed against
10.0; probe4 (`msvc1100_{O1,O2}.obj` — `cvttsd2si`, the struct-return
verified negative) at both opt levels; smoke `msvc1100/t.obj`.  Census:
`f2 0f 58`=1, `f2 0f 59`=1, `f3 0f
58`=1 at /O2 — vs 0 for every other MSVC object.
## Probe29: round-29 era markers (11.0)

- **11.0 is the SSE2 boundary on the new shapes — every FP shape flips
  to SSE**: `(int)d` → `cvttsd2si eax,[esp+4]` (`f2 0f 2c`, D12);
  `d<0.0` → `xorps; comisd; seta` (`0f 57 c0 33 c0 66 0f 2f 44 24 04
  0f 97 c0`, D14); `-d` → `movsd; xorpd [sign-const]; movsd` (D15);
  `d*2.0` → `mulsd [const]` (D16); min/max → **`cmovl`/`cmovg` — the
  only version with conditional moves** (`0f 4c`/`0f 4f`, C39).
  Integer side: `div7_` `mul dword [esp+4]` from memory (C37);
  `udiv7_` lea-tail; `mod10_` stages via esi (`56 8b 74 24 08`);
  `s16_ret` register staging; `cvt_i2d` stays x87 roundtrip
  (`fild; fstp; fld` — D13).  See RULES.md.
## Probe30: round-30 era markers (11.0)

- **11.0**: magic-division staging via esi (`56 8b 74 24 08`, C43);
  `(double)i64` x87 roundtrip `fild; fstp; fld` (H5); `a*5` inline
  shld (H6); `tern_nest` **cmov** (C46); 64-bit add memory-operand.
  See RULES.md.
