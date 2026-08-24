# MSVC 6.0 — codegen patterns

MSVC 6.0 (1998, CL 12.00).  The most-used Windows-era compiler for
matching; codegen-identical to VC 5.0 for the probe, with the SP levels
indistinguishable by code shape.

**Profiles:** `msvc6` + `msvc600sp1..sp6`.  Rich-header C1 builds:
**8168 (RTM–SP3), 8447 (SP3), 8966 (SP4/SP5), 9782 (SP6)** — the exact
build is the only reliable SP discriminator (see below).  Linker 6.0.

## Prologue & frame pointer

- `/O1`/`/O2`: no frame pointer — args `[esp+4]`+; `push ebp; mov
  ebp,esp` (`55 8b ec`) appears only unoptimized or with `/Oy-`
  (smoke `msvc6/t.obj` is unoptimized and framed).
- `bigstack` (6 KB frame): `mov eax,0x1770; call __chkstk; …; add
  esp,0x1770; ret` — no /GS cookie (VS2005 /GS arrives in VC 8.0).

## Argument passing

- Direct `[esp+N]` loads; wrapper calls: /O2 `mov eax,[esp+4]; push eax`
  (`8b 44 24 04 50`) + `add esp,N`; /O1 `push dword [esp+4]`
  (`ff 74 24 04`) + `pop ecx`.  The two are mutually exclusive per
  function — mixed presence means a per-file mixed /O build.

## Register conventions

- Callee-saved `ebx/esi/edi`; **no constant caching**: VC 6.0 folds a
  loop-invariant constant into immediate stores (`mov [mem],imm32`,
  `c7`) where 4.x/5.0 hoist it into a callee-saved register (the
  pre-6.0 fingerprint is absent in 6.0).
- Unsigned char sum: `mov dl,[mem]` + `add eax,edx` (same as 5.0).

## Integer division

- **Magic constants, `mov eax,edx` tail (no post-shift)** — identical to
  VC 5.0: `x/3u` → `mov eax,0xAAAAAAAB; mul [esp+4]; mov eax,edx`.
  Full constant set and signed tails as in [msvc-5.md](msvc-5.md).
- The no-shift tail is the 5.0/6.0 marker; VC 7.0+ adds `shr edx,N`.

## FPU / SSE

- Pure x87; `.rdata` FP constants (`fmul dword ptr [const]` for
  `*3.0f`); `fadd(double)` = `fld qword [esp+4]; fadd qword [esp+0xc]`.

## Loops

- `dec/jnz` induction; `p[i]=0x3e8` → `mov eax,0x3e8; rep stosd` (`f3
  ab`) — memset inlining.  No intra-body alignment nops (probe: zero
  `8d 64 24 00`), no unrolling (VC 9.0 unrolls the same loop).

## String ops

- `rep stosd`/`rep movsd` inlining confirmed across the probe and real
  VC 6.0 binaries (rt63: 22 rep string ops, 16 `rep movsd`).

## Padding & nops

- MSVC6 nop ladder: `90` (1B), `8b ff` `mov edi,edi` (2B), `8d 74 26 00`
  `lea esi,[esi]` (3B), `8d 74 20 00`/…, `8d a4 24 00 00 00 00` (7B) —
  inter-function/link-time padding.  `cc cc` int3 runs are MSVC-style
  filler (rt63: 34 int3 runs).
- `8b ff` as 2-byte padding is *not* a version marker: linked VC 6.0
  binaries show ~10/15KB of `.text` (rt63: 11, tcmd: 12), VC 5.0
  binaries show 0 — observed, but not proven unique to 6.0 (VC 7.0+
  also emits it).

## Stack probes

- `mov eax,<size>; call __chkstk` — same as every 32-bit MSVC version.
  Detect via the `b8 imm32 e8` shape in stripped binaries; the
  `__chkstk` symbol survives in objects.

## Switch dispatch

- Dense-range jump table: `mov eax,[esp+4]; dec eax; cmp eax,4; …
  jmp dword ptr [eax*4]` — same as all versions.

## Optimization fingerprints

- /O2 load-first vs /O1 push-[mem] wrapper styles (see Argument passing);
  the rebrew detector scores these to suggest the opt level.

## 100% unique to this version

- **None proven per version.**  Codegen is identical to VC 5.0 for the
  probe **except** the FP constant encoding: VC 6.0 emits `fadd`/`fmul`
  with positive `.rdata` constants where 5.0 uses the fsub-negation
  trick (so the FP encoding *separates* 5.0 from 6.0 — see
  [msvc-5.md](msvc-5.md)).
- **Shared with VC 5.0 (era markers):** the unsigned-div magic tail
  `mov eax,edx; shr eax,N` (`8b c2 c1 e8 N`) and the signed-div ECX
  round-trip (`8b c8 c1 e9 1f 03 c1`) — VC 7.0+ emits `shr edx,N; mov
  eax,edx` (`c1 ea N 8b c2`) / `sar edx,N` first.  Verified across
  20 unsigned and 13 signed divisors (probe2 + probe3 table), incl.
  every VC 6.0 SP level.
- **`shl eax,1` for `x*10`** and **`repe cmpsd` memcmp** — shared
  5.0–7.1 / 2.0–7.1 era markers, see
  [msvc-5.md](msvc-5.md).
- **TWO divisions for `x/N + x%N`** — VC 2.0–6.0 emit separate
  divisions for the quotient and remainder (VC 7.0+ shares one — see
  [msvc-7.md](msvc-7.md)).  Verified in probe9 (`dm3`/`udm3`).
- **Bitfield get/set: 5.0/6.0 share a 67B packing form** (VC 2.0/4.1
  a 77B form, 7.0+ the movzx-based 60B-and-smaller forms) — the
  bitfield code shrinks monotonically across versions (77→55B);
  version-ladder evidence, not a single byte marker.
- **SEH frame `push -1`** — `__try/__except` functions open the SEH
  frame with `push -1` (`6a ff`) in VC 2.0–7.1 (VC 8.0+ uses
  `push -2`); VC 5.0–7.1 load `fs:[0]` after the frame (VC 2.0/4.x
  load it first).  Verified in probe7 (`seh1`).
- **inline 64-bit multiply-high** — `(a*b)>>32` compiles to
  `mul [mem]; mov eax,edx` (`f7 64 24 08 8b c2`) inline from VC 6.0
  on; VC 4.1/5.0 do `mul` then tail-jump to the shift helper.
  Verified in probe7 (`mulhi`).
- **SP levels are codegen-identical:** every probe2–probe5 function
  produces byte-identical output across SP1–SP6 at **both /O1 and
  /O2** (the smoke `_add` is identical too) — the SPs differ in the
  compiler binary (C1 build), not in the tested code shape.  Treat
  the Rich-header C1 build as the only reliable SP fingerprint;
  complex-function optimizer differences between SPs are possible but
  not reproduced.
- What IS unique to the 6.0 family vs 7.0+: no `lea esp,[esp]`
  loop-alignment nops, the no-shift division tails, no `mov
  edi,edi`-heavy padding.  Identity must come from the Rich header (C1
  builds 8168/8447/8966/9782) + linker 6.0.

## Version deltas

- From VC 5.0: nothing verified in codegen (identical optimizer output).
- To VC 7.0: `lea esp,[esp]` loop-alignment nops appear; division tails
  gain `shr edx,N`; `movzx` replaces `mov dl;add` for unsigned char
  sums; linked binaries show `mov edi,edi` padding.

## Probe12: static-helper inlining — verified negative

Small static helpers called once/twice/in a loop are NOT inlined: VC
6.0 keeps the `call` at both /O2 and /O1 (30–34B callers), unlike VC
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
- **SP spot-check** — VC 6.0 SP2/SP4/SP5 byte-identical to the 6.0
  RTM on every probe14 function (SP1/SP3/SP6 already verified on
  probe13).

## Probe15: setcc + address forms — verified

- **setcc loads BOTH operands** — `a < b` = `mov ecx,[esp+4]; mov
  edx,[esp+8]; xor eax,eax; cmp ecx,edx; setl al` — the 5.0–7.1
  register-form (8.0+ compare the second operand in memory).
- **address form** — `p[i*4+3]` = `shl eax,4` + `mov eax,
  [eax+ecx+0xc]` — the 6.0–9.0 shl + scale-1 form (5.0: lea-scale;
  10.0/11.0: `add reg,reg` + scale-8).
- **stdcall args load in REVERSE order** — the 5.0–9.0 form
  (2.0/4.1 and 11.0 use direct order; Zig/LLVM also reverses).
- **SP spot-check** — 6.0 SP1/SP3/SP6 byte-identical to the 6.0 RTM
  on the probe15 set.

## Probe16: 64-bit division + C++ — verified

- **64-bit division = register-load + 4-push helper call** (`8b 44 24
  10 8b 4c 24 0c 8b 54 24 08 50 8b 44 24 08 51 52 50 e8`) — the
  5.0–10.0 form, uniform across div/udiv/rem/urem (target differs:
  `__alldiv`/`__aulldiv`/`__allrem`/`__aullrem`); /O1 uses the
  compact 4× memory-push in every version.
- **C++ `new`/`delete` = call + `add esp,4`/`pop ecx`** — the
  5.0/6.0 call+ret form (7.0+ tail-jumps).

- **Corpus pointer** — machine-checked in `corpus.json` (7892 records; the mechanical sweep confirmed this file's records and surfaced no un-documented markers here).

## Probe17: conventions + allocator behaviors

- **Probe17 allocator/conventions**: `-1` stores use the REGISTER form `or eax,-1` + `a3` (5.0–10.0 era); zero register kept in EAX (`alloc_zero`: `a3` moffs stores).  The guild-rebrew live-range flip (B3) does NOT trigger with the simplified probe.  See RULES.md B2/B3/B5.

- **Decomp idioms** — the probe19-28 game-idiom signatures for this toolchain are in [DECOMP_IDIOMS.md](../DECOMP_IDIOMS.md) and the corpus (`probe19`-`probe28` records).

## Probe22: guild-rule verification (round 19)

- **Probe22 (6.0)**: the guild-doc rules verify in full here — C24 fused negation, F17 byte-live switch preamble, F15 `or ch,0x30`/`test ah,0x60` AH-slot ops, E11 opaque-memset negative (simple rep-stosd form), F13 no-scalarization negative.  See RULES.md C24/F15/F16/F17/E11.


## Probe23: Findings 23-36 shapes (round 20)

- **Probe23 (6.0)**: idx24 `lea*3; shl 5`; `/60`/`/24` magic; `argslot` reuses the dead arg2 slot (`lea eax,[esp+8]`, no frame); `addfold` folds all offsets; if-conversion sbb-trick; FPU clamp `fcomp [a4]`+`test ah,1`.  See RULES.md C27/C28/E16/E17/F19/F22.


## Probe24: Findings 37-43 primitives (round 21)

- **Probe24 (6.0)**: word zero-extend `xor;mov ax` (the guild doc's exact form); size-dispatch dec-chain; in-place memory and; lea+disp folded into the lea (`8d 44 40 24`); byte or-mask register round-trip; field-store fold.  See RULES.md C29/F24/E18/E19/E20.


## Probe25: Finding 44 primitives (round 22)

- **Probe25 (6.0)**: branchless clamp (the doc's setle/dec/and form); ×589 five-lea chain; byte-arg raw push (`mov al,[mem]; push eax` — refutes the doc's unreproducibility claim for the simple shape); byte-first sum load.  See RULES.md C30/C31/E21/E22.


## Probe26: Finding 45 early-return placement (round 23)

- **Probe26 (6.0)**: inline early-return blocks after each check (`test; jne +6; mov -3; ret`) — the default placement; `or eax,-1` shared tail.  See RULES.md F25.


## Probe27: Findings 46-50 primitives (round 24)

- **Probe27 (6.0)**: byte-slot or `or ch,0x10` (the doc's `or dh,0x10` form); same-constant fail paths merge to one `xor eax,eax; ret` tail (the doc's F46 reference shape); callee-save at entry.  See RULES.md C32/F25/E23.


## Probe28: decompedia/CODEGEN_PATTERNS claims (round 25)

- **Probe28 (6.0)**: FP const `fadd qword [+1.0]` (`dc 05`); `<=0` test+setle 2B vs `<1` cmp+setl 3B; `x==-1` setne+neg; short return `mov ax`.  See RULES.md D10/C33/C34.



## Probe26-r: msvc6.5pp (fleet-gap round)

- **msvc6.5pp** (decomp.me id, VC 6.0 SP5 + Processor Pack) = cl **12.00.8804**: `/O2` and `/O2 /G6` codegen byte-identical to stock SP5 on the probe shapes; `/arch:SSE` is REJECTED (D4002 unknown option) — the Processor Pack changes CPU detection/runtime, not default instruction selection.  Verified-negative: no new corpus rows (extends J2).

## Verification

Probe `/O1`/`/O2` via `rebrew/msvc:6.0-win32` (`msvc600_{O1,O2}.obj`);
probe2 at `/O2` across **all six SP images** (`out2/msvc600sp{1..6}_O2.obj`)
— every probe2 function byte-identical across SP1–SP6; smoke `msvc6/t.obj`
+ `msvc600sp3/sp5/sp6/t.obj` (identical `_add`);
corpus: rt63, rt7, skifree32, tcmd (VC 6.0) — rep string ops, frame
prologues, `mov edi,edi` counts, magic constants, `/O1`-style wrappers
in explorer-adjacent builds.
## Probe29: round-29 era markers (6.0)

- **6.0 stays in the 5.0/6.0 pair for the new shapes**: branchy abs,
  `and 0xff`-pair sat_add, real `%10` idiv, const-based fpcmp
  (`dc 1d … f6 c4 01`), 5.0-form magic tails, `fadd st0,st0` ×2,
  eax:edx struct returns, `xor; mov al` bitfield loads.  `fastcall4_`
  gets the `lea eax,[ecx+edx]`-first folding (6.0-7.1 form, A11).
  SPs sp1-sp6 verified byte-identical on all 42 probe29 shapes
  (SP-equivalence scan, 3777 rows).  See RULES.md C35-C40/D14/D16/G7.
## Probe30: round-30 era markers (6.0)

- **6.0 stays in the 5.0/6.0 pair**: magic /3 /5 /6 /9 with the
  5.0/6.0 tail, real-idiv %7/%360/%1000, repne-scasb strlen,
  lea-chain muls, direct fild i64→d, __allmul ×5, register-pair
  thiscall body.  SPs sp1-sp6 verified byte-identical on all 53
  probe30 shapes (SP-equivalence scan, 4466 rows).  See RULES.md.
