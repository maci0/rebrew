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

## Verification

Probe `/O1`/`/O2` via `rebrew/msvc:6.0-win32` (`msvc600_{O1,O2}.obj`);
probe2 at `/O2` across **all six SP images** (`out2/msvc600sp{1..6}_O2.obj`)
— every probe2 function byte-identical across SP1–SP6; smoke `msvc6/t.obj`
+ `msvc600sp3/sp5/sp6/t.obj` (identical `_add`);
corpus: rt63, rt7, skifree32, tcmd (VC 6.0) — rep string ops, frame
prologues, `mov edi,edi` counts, magic constants, `/O1`-style wrappers
in explorer-adjacent builds.
