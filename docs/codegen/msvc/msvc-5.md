# MSVC 5.0 — codegen patterns

MSVC 5.0 (1997, CL 11.00.7022; SP1–SP3 ship the same CL.EXE).  The
**magic-number division era begins here** — and the magic tail still lacks
the post-shift VC 7.0+ adds.

**Profiles:** `msvc5`, `msvc500sp1`, `msvc500sp2`, `msvc500sp3` — linker
5.0/5.10/5.12.  VC 5.0-era linkers write a Rich header with C1 build 0
(the Win2K binaries — linker 5.12 — show `C1/C2 build 0`), so the Rich
header does not pin the exact compiler here; the linker version (5.x)
does.  VC 2.0–4.2 linkers write no Rich header at all.

## Prologue & frame pointer

- `/O2`: no frame pointer, args `[esp+4]`+ — same as 2.0/4.x.
- Unoptimized: `55 8b ec` (smoke `msvc500sp*/t.obj`).

## Argument passing

- Direct `[esp+N]` loads (identical shape to 2.0/4.x for the probe).

## Register conventions

- Callee-saved `ebx/esi/edi`; **constant caching**: a loop-invariant
  small constant is hoisted into a callee-saved register and stored via
  it (`mov ebx,imm32` then `mov [mem],ebx`) — the pre-6.0 fingerprint
  (validated on the Europa 1400 server, whose player-init loop caches
  1000 in `ebx`; see [TOOLCHAIN.md](../../TOOLCHAIN.md)).  VC 6.0 folds the
  constant into immediate stores instead.
- Zero-tests now use `test reg,reg` (`85 d2`) — the `cmp reg,zeroreg`
  idiom of 2.0/4.x is gone.
- Unsigned char sum: `mov dl,[mem]; add eax,edx` (the `mov dl` + `add`
  pattern VC 5.0/6.0 share) — VC 7.0+ switches to `movzx`.

## Integer division

- **Magic constants** (first appearance): `x/3u` →
  `mov eax,0xAAAAAAAB` (`b8 ab aa aa aa`) · `mul dword ptr [esp+4]`
  (`f7 64 24 04`) · **`mov eax,edx`** — the high half is taken directly,
  **no post-shift**.
- Full verified constant set: `x/3u` → `0xAAAAAAAB`, `x/7u` →
  `0x24924925`, `x/10u` → `0xCCCCCCCD`, `x/100u` → `0x51EB851F`, signed
  `x/7` → `0x92492493`, signed `x/10` → `0x66666667`.  Signed tails use
  `sar edx,N` + `shr eax,31` correction.
- `mov eax,edx` (no shift) is the **VC 5.0/6.0 marker** — VC 7.0+ emits
  `shr edx,N` before taking the result.

## FPU / SSE

- Pure x87, `.rdata` constants — **but with a 5.0-only encoding**: FP
  constant adds use `fsub`/`fsubr` with **negated** constants.  `a+1.0`
  → `fld [esp+4]; fsub qword [−1.0]` (`dc 25`); `a*3.0+2.0` → `fmul
  [−3.0]` (`dc 0d`) + `fsubr [+2.0]` (`dc 2d`).  The .rdata table holds
  `−1.0, 1.0, 2.0, 0.5, −3.0` — VC 6.0+ stores the positive constants
  and emits `fadd` (`dc 05`)/`fmul` (`dc 0d`) instead.  (VC 2.0/4.x use
  `fld1` (`d9 e8`) for `+1.0`; VC 6.0+ use `fadd [const]`.)

## Loops / String ops / Padding / Switch

- `dec/jnz` loops, no intra-body alignment nops (probe: zero
  `8d 64 24 00`), `rep stosd` inlining (`p[i]=0x3e8` → `mov eax,0x3e8;
  f3 ab`), dense jump tables — all as in [msvc-2.md](msvc-2.md)/
  [msvc-6.md](msvc-6.md).
- `bigstack` loop identical to VC 2.0's (`88 04 04; 40; 3d 70 17 00 00;
  7c f4`) — no /GS, no unrolling.

## Stack probes

- `mov eax,<size>; call __chkstk` — identical to
  [msvc-2.md](msvc-2.md)/[msvc-6.md](msvc-6.md).

## Optimization fingerprints

- Same /O2 load-first vs /O1 push-[mem] wrapper styles.

## 100% unique to this version

- **FP constant adds via `fsub`/`fsubr` with NEGATED `.rdata` constants** —
  verified, and the only 5.0-vs-6.0 codegen difference found: `a+1.0` →
  `fld [esp+4]; fsub qword [−1.0]` (`dc 25`), `a*3.0+2.0` → `fmul [−3.0];
  fsubr [+2.0]` (`dc 0d`/`dc 2d`), with −1.0/−3.0 in .rdata.  VC 6.0+
  emits `fadd`/`fmul` with positive constants; VC 2.0/4.x use `fld1`.
  Caveat: `dc 25` alone is not a marker (plain `fsub m64` occurs in any
  compiler's subtraction) — the marker is the fsub-after-fld encoding of
  an *add* plus the negated constant table.
- **Shared with VC 6.0 (era markers, not 5.0-only):** the unsigned-div
  magic tail `mov eax,edx; shr eax,N` (`8b c2 c1 e8 N`, or `d1 e8` for
  shift 1) — VC 7.0+ emits `shr edx,N; mov eax,edx` (`c1 ea N 8b c2`);
  and the signed-div sign-fix via the ECX round-trip `mov ecx,eax; shr
  ecx,31; add eax,ecx` (`8b c8 c1 e9 1f 03 c1`) — VC 7.0+ uses `sar
  edx,N` first.  Verified across 20 unsigned and 13 signed divisors
  (probe2 + the probe3 13-divisor table), incl. every VC 6.0 SP level.
- **`shl eax,1` for `x*10`** — `x*10` → `lea eax,[eax+eax*4]; shl
  eax,1` (`8d 04 80 d1 e0`) in VC 5.0–7.1; VC 2.0/4.x and 8.0+ (and
  GCC) use `add eax,eax` (`03 c0`) instead.  Verified in probe4
  (`m10`).  Shared by 5.0–7.1, not 5.0/6.0-only.
- **`repe cmpsd` for fixed-size memcmp** — `memcmp(a,b,8/16/32)`
  compiles to `repe cmpsd` (`f3 a6`) + sbb adjustment in VC 2.0–7.1
  (confirmed in the real VC 6.0 binary rt63: 1 hit); VC 8.0+ unroll
  the dword compares, and GCC/Watcom/Borland call `memcmp`.  Shared
  by 2.0–7.1.
- The pre-6.0 constant-hoist signal marks the 4.x/5.0 era (not 5.0
  alone).  Distinguish 5.0 from 6.0 via the FP encoding above, the
  linker (5.x) or the Rich header (VC 6.0+ has one, C1 builds
  8168…9782).

## Version deltas

- From VC 4.x: magic division replaces real `div`; `xor edx,edx` replaces
  `sub edx,edx`; `test reg,reg` replaces `cmp reg,zeroreg`; constant
  caching into callee-saved registers.
- To VC 6.0: nothing verified in codegen — the two are the same optimizer
  for the probe.  (VC 6.0's identity is the Rich header + linker 6.0.)

## Probe12: static-helper inlining — verified negative

Small static helpers called once/twice/in a loop are NOT inlined: VC
5.0 keeps the `call` at both /O2 and /O1 (30–34B callers), unlike VC
7.0+ which inline them (11–12B).  Verified in probe12
(`f1`/`f2`/`fl`); keeping the call is itself the 2.0–6.0 era marker.

## Probe13: string intrinsics + promotion — verified

- **strlen is `repne scasb` (`f2 ae`)** with ECX=−1 at /O2 (2.0–6.0
  form; bcc32/Watcom/GCC libcall strlen).
- **memcmp(8B) is `repe cmpsb` (`f3 a6`) + sbb idiom** at /O2 (the
  2.0–7.1 form).
- **`unsigned char` sums zero-extend via `and eax,0xff`
  (`25 ff 00 00 00` / `81 e1 ff 00 00 00`)** at /O2 — the 5.0/6.0
  form, unique among the probed toolchains (2.0/4.x: xor+mov, 7.0+:
  movzx); /O1 uses movzx like everything else.
- **SP spot-check** — VC 5.0 SP1–SP3 byte-identical to the 5.0 RTM
  on every probe13 function.

## Probe14: 64-bit helpers + statement idioms — verified

- **64-bit shifts call the helper** — `i64 << 4` compiles to
  `mov ecx,4; jmp __allshl` (`b9 04 00 00 00 e9`, /O1: `6a 04 59 e9`)
  and `>> 4` to `jmp __allshr` — the 5.0/6.0 tail-call form, unique
  among the probed toolchains (7.0+ inline `shld`/`shrd` — shared
  with GCC/bcc32/Zig; Watcom's `__I8LS` takes the count in EBX).
- **64-bit `× 7` calls `__allmul`** (`6a 00 6a 07 50 51 e8`) — the
  5.0–9.0 form; 10.0/11.0 inline a `shld`-based decomposition.
- **64-byte memcpy = `rep movsd`** (`b9 10 00 00 00 f3 a5`) — shared
  by every MSVC version; no other probed toolchain uses rep-movs here.
- **zero-compare era** — `a == 0` = load + `test` + `setz` at /O2
  (5.0–7.1 form; 8.0+ compares in memory against the zero register).
- **SP spot-check** — 5.0 SP1–SP3 also byte-identical at /O1 on the
  probe14 set.

## Probe15: setcc + address forms — verified

- **setcc loads BOTH operands** — `a < b` = `mov ecx,[esp+4]; mov
  edx,[esp+8]; xor eax,eax; cmp ecx,edx; setl al` — the 5.0–7.1
  register-form (8.0+ compare the second operand in memory).
- **address form** — `p[i*4+3]` = `lea ecx,[eax*4]` + `mov eax,
  [edx+ecx*4+0xc]` — the 5.0 lea-scale form (6.0–9.0 use
  `shl eax,4` + scale-1; 10.0/11.0 `add reg,reg` + scale-8).
- **stdcall args load in REVERSE order** — `std_add` = `mov eax,
  [esp+8]; mov ecx,[esp+4]; add eax,ecx` — the 5.0–9.0 form
  (2.0/4.1 and 11.0 use direct order; Zig/LLVM also reverses).

## Probe16: 64-bit division + C++ — verified

- **64-bit division calls the helper with a register-load + 4-push**
  — `i64 / i64` = `mov eax,[esp+0x10]; mov ecx,[esp+0xc]; mov
  edx,[esp+8]; push eax; mov eax,[esp+8]; push ecx; push edx; push
  eax; call __alldiv` (the divisor and dividend staged hi-first) —
  the 5.0–10.0 form, identical across div/udiv/rem/urem (the target
  differs: `__alldiv`/`__aulldiv`/`__allrem`/`__aullrem`).  At /O1
  every version (including 5.0) uses the compact 4× memory-push
  (`ff 74 24 10` ×4) instead.
- **C++ `new` = call + `add esp,4`** — `new int[n]` = `lea ecx,
  [eax*4]; push ecx; call <operator new>; add esp,4`; `new int` =
  `push 4; call; add esp,4`; `delete` = call + `add esp,4`/`pop ecx`
  (the 5.0/6.0 call+ret form; 7.0+ tail-jumps).

- **Corpus pointer** — machine-checked in `corpus.json` (7892 records; the mechanical sweep confirmed this file's records and surfaced no un-documented markers here).

## Probe17: conventions + allocator behaviors

- **Probe17 allocator/conventions**: `-1` stores use the REGISTER form `or eax,-1` (`83 c8 ff`) + `a3` store (5.0–10.0 era); varargs float→double via `fld; sub esp,8; fstp qword [esp]` (`dd 1c 24`).  See RULES.md A5/B5.

- **Decomp idioms** — the probe19-28 game-idiom signatures for this toolchain are in [DECOMP_IDIOMS.md](../DECOMP_IDIOMS.md) and the corpus (`probe19`-`probe28` records).

## Probe22: guild-rule verification (round 19)

- **Probe22 (5.0)**: C23 and/xor liveness split begins here (`and eax,0xff` live, `xor;mov` dead); C24 fused negation byte-exact (`sub al,0xe; neg al; sbb eax,eax`); C25 `or dl,0xff` hoisted materialization (5.0-only); F17 live-switch and-mask preamble.  See RULES.md C23-C25/F17.


## Probe23: Findings 23-36 shapes (round 20)

- **Probe23 (5.0)**: idx7 = `mov; shl 3; sub` (mov-based ×8−1); `idx24` double-scales (`lea*3; shl 3` + ×4 SIB); division magic begins (0x88888889/0xaaaaaaab); **arg-slot reuse begins (no frame)**; branchless if-conversion = the `dec/neg/sbb/and al,0xfc` marker form.  See RULES.md C27/C28/E16/F19.


## Probe24: Findings 37-43 primitives (round 21)

- **Probe24 (5.0)**: word zero-extend `xor;mov ax` + param `and eax,0xffff`; size-dispatch dec-chain begins (`48 74`); in-place `and word [mem]`; field-store fold.  See RULES.md C29/F24/E18/E20.


## Probe25: Finding 44 primitives (round 22)

- **Probe25 (5.0)**: **branchless clamp begins (`setle cl; neg ecx; and`)**; ×589 five-instruction lea chain; raw byte push.  See RULES.md C30/C31/E21.


## Probe26: Finding 45 early-return placement (round 23)

- **Probe26 (5.0)**: inline early returns; the -1 tail becomes `or eax,-1` (B5).  See RULES.md F25/B5.


## Probe27: Findings 46-50 primitives (round 24)

- **Probe27 (5.0)**: **byte-slot or begins (`or ch,0x10` for |=0x1000)**; shared fail epilogue; entry-push callee-saves.  See RULES.md C32/F25.


## Probe28: decompedia/CODEGEN_PATTERNS claims (round 25)

- **Probe28 (5.0)**: **the FP-const quirk — `a+1.0` → `fsub qword [−1.0]` (`dc 25`) with negated const in .rdata (5.0-only)**; setne+neg -1 compare; setcc cmp encodings.  See RULES.md D10/F25/C33.


## Verification

Probe at `/O1`/`/O2` via `rebrew/msvc:5.0-win32`
(`msvc500_{O1,O2}.obj`); probe2 (`msvc500_O2.obj` — division tails, FP
constants) disassembled and diffed against every other version; smoke
`msvc500sp1/sp2/sp3/t.obj`; corpus:
win2k-* binaries (linker 5.12, VC 5.0 — `rep movs/stos` counts, frame
prologues, magic `0x66666667`/`0xCCCCCCCD` hits).
## Probe29: round-29 era markers (5.0)

- **5.0/6.0 open the branchy-abs era**: `abs_i` `test eax,eax; jns;
  neg eax` (`85 c0 7d 02 f7 d8` — 5.0 through 9.0, C38); `sat_add`
  `mov`+`and 0xff` pair (`25 ff 00 00 00 81 e1 ff 00 00 00`, C40);
  `%10` still real idiv (C35/C36); `fpcmp_lt0` the const-based
  `fcomp [−0.0]` + `test ah,1` form (`dc 1d … f6 c4 01`, D14); the
  5.0/6.0 magic-division tail (`mul; mov edx,eax; add eax,ecx; sar
  eax,2`, C37); `d*2.0` folds to `fadd st0,st0` (`dc c0`, D16);
  `s8_ret` returns in `eax:edx` (`8d 50 01 c3` — the 5.0+ ABI, G7);
  `bitf_get` `xor; mov al`.  See RULES.md.
## Probe30: round-30 era markers (5.0)

- **5.0/6.0 open the magic-division era on the new divisors**: `/3 /5
  /6 /9` → magic from 5.0 (`0x55555556`/`0x66666667`/`0xAAAAAAAB`/
  `0x38E38E39`) with the 5.0/6.0 mul-then-sar-eax tail (C42); `%7
  %360 %1000` STILL real idiv (the % boundary is 8.0, C43); strlen
  still `repne scasb` (E26); `mul11/13/100` lea-chains (C44);
  `mul17_` shl4-add; `(double)i64` direct `fild qword [esp+4]` (H5);
  `a*5` __allmul (H6); thiscall 5.0/6.0 register-pair member-body
  (I9).  See RULES.md.
