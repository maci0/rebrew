# MSVC 8.0 — codegen patterns

MSVC 8.0 (VS 2005, CL 14.00.50727; SP1 = 14.00.50727.762).  **/GS
security cookies become default-on for buffer functions** — the big
codegen change of this version.

**Profiles:** `msvc800`, `msvc800sp1` — Rich builds 50727; linker 8.0.

## Prologue & frame pointer

- `/O2`: no frame pointer; args `[esp+4]`+.

## /GS security cookie

- Verified in `bigstack` (6 KB char buffer): prologue
  `mov eax,[__security_cookie]` (`a1 00 00 00 00`) · `xor eax,esp`
  (`33 c4`) · `mov [esp+0x1770],eax` (`89 84 24 70 17 00 00`) — the
  frame grows 4 bytes for the cookie slot; epilogue reloads it, `xor
  ecx,esp` (`33 cc`), `call __security_check_cookie`.
- The `__security_cookie` / `__security_check_cookie` symbols survive in
  objects and unstripped binaries.  VC 7.x emits no cookie — /GS on a
  buffer function is the 8.0+ marker.

## Register conventions

- `movzx` char loads; magic + post-shift division — all as in
  [msvc-7.md](msvc-7.md) (`0xAAAAAAAB; mul; shr edx,1`).

## Integer division

- Magic + post-shift — unchanged from
  [msvc-7.md](msvc-7.md) (`0xAAAAAAAB; mul [esp+4]; shr edx,1; mov
  eax,edx`).

## FPU / SSE

- Pure x87 — SSE2 default arrives in VC 11.0.

## Loops

- Loop-alignment nops inside bodies: `bigstack` uses **`lea ebx,[ebx]`
  (`8d 9b 00 00 00 00`)** — the nop register differs from 7.0/7.1's
  `lea esp,[esp]` (8.0's census still shows 2× `8d 64 24 00` in other
  functions).  The lea-based intra-body alignment nop is the 7.0+
  marker; the specific register varies by version and function and is
  not a reliable version discriminator on its own.
- No loop unrolling in the probe (`bsum` still 33B-style; VC 9.0
  unrolls).

## String ops / Padding / Switch

- `rep stosd`/`rep movsd` inlining; `90`/`8b ff`/`8d 74 26 00`
  inter-function pads; dense jump tables — all unchanged.

## Stack probes

- `mov eax,<size>; call __chkstk` — unchanged, see
  [msvc-6.md](msvc-6.md).

## Optimization fingerprints

- Same wrapper styles; /GS adds the cookie prologue/epilogue on top.

## 100% unique to this version

- **`rol` for rotates** — `x<<n | x>>(32-n)` compiles to a single
  `rol eax,cl` (`d3 c0`) from VC 8.0 on; VC 2.0–7.1 emit the shift pair
  (`d3 e8; d3 e2`).  Verified: probe2 `rotl` is byte-identical in
  8.0/9.0/10.0/11.0 (`8b 44 24 04 8b 4c 24 08 d3 c0 c3`), the shift-pair
  form in every earlier version.  Unique to 8.0+ among the line (an era
  marker, not 8.0-only).
- **Inline 2^52-bias FP→unsigned** — `(unsigned)a` compiles to the
  x87 bias trick (`fistp qword [esp]; mov ax,[esp+0xc]; or ax,0xC0000;
  … fistp`) from VC 8.0 on (`0d 00 0c 00 00` = `or eax,0xC0000`); VC
  2.0–7.1 call the FP-conversion helper.  Verified in probe4
  (`d2u`/`f2u`).
- **`sqrt` stops being inlined** — `sqrt(a)` compiles to a bare
  `jmp __CIsqrt` (`e9` reloc) from VC 8.0 on; VC 2.0–7.1 inline
  `fld; fsqrt` (`d9 fa`).  Verified in probe5 (`sq`).
- **real `fdiv` for `a/5.0`** — `a/5.0` compiles to `fdiv qword
  [const]` (`dc 35`) from VC 8.0 on; VC 2.0–7.1 (and Watcom, bcc32)
  use reciprocal-`fmul` (`dc 0d`); GCC uses `fdivr`.  Verified in
  probe5 (`fdiv5`).
- /GS is shared by 8.0–11.0; the rest is inherited from 7.x.  No
  verified marker separates 8.0 from 9.0/10.0 — the probe objects are
  near-identical (519B vs 551B at /O2; same nops, cookie, division
  tails).  **Service pack:** 8.0 SP1 is codegen-identical to 8.0 RTM
  (probes 1–5, /O1 and /O2).  Identity via Rich build 50727 +
  linker 8.0.

## Version deltas

- From VC 7.1: /GS default-on (the defining change); loop-align nop
  register shifts esp→ebx in `bigstack` (observed, not proven uniform).
- To VC 9.0: loop unrolling appears (`bsum` 33B → 74B).

## Verification

Probe `/O1`/`/O2` via `rebrew/msvc:8.0-win32` (`msvc800_{O1,O2}.obj`);
smoke `msvc800/t.obj`, `msvc800sp1/t.obj`.  `/GS` cookie pattern
reproduced in `bigstack` at /O2.
