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
  1000 in `ebx`; see [TOOLCHAIN.md](../TOOLCHAIN.md)).  VC 6.0 folds the
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

## Verification

Probe at `/O1`/`/O2` via `rebrew/msvc:5.0-win32`
(`msvc500_{O1,O2}.obj`); probe2 (`msvc500_O2.obj` — division tails, FP
constants) disassembled and diffed against every other version; smoke
`msvc500sp1/sp2/sp3/t.obj`; corpus:
win2k-* binaries (linker 5.12, VC 5.0 — `rep movs/stos` counts, frame
prologues, magic `0x66666667`/`0xCCCCCCCD` hits).
