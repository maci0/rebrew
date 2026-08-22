# MSVC 10.0 — codegen patterns

MSVC 10.0 (VS 2010, CL 16.00.30319; SP1 = 16.00.40219).  Codegen-wise a
clone of VC 9.0 in the probe.

**Profiles:** `msvc1000`, `msvc1000sp1` — Rich builds 30319, 40219;
linker 10.0.

## Prologue & frame pointer

- `/O2`: no frame pointer for simple functions; `ebp` as scratch in the
  unrolled `bsum` (as in 9.0).

## /GS security cookie

- Same pattern as [msvc-8.md](msvc-8.md)/[msvc-9.md](msvc-9.md):
  `a1 [cookie]; 33 c4; mov [esp+N],eax` prologue + `33 cc; call
  __security_check_cookie` epilogue (verified in `bigstack`, 72B).

## Loops

- Same unrolling as 9.0 (`bsum` 74B-style, `lea ebx,[ebx]` alignment);
  census identical to 9.0: `lea esp,[esp]`=2, `movsx`=2, `movzx`=5.

## Integer division

- Magic + post-shift division — unchanged from
  [msvc-9.md](msvc-9.md) (`0xAAAAAAAB; mul; shr edx,1`).

## FPU / SSE

- Pure x87 — unchanged from [msvc-9.md](msvc-9.md); SSE2 arrives in
  VC 11.0.

## String ops / Padding / Switch

- `rep stosd`/`rep movsd`; dense jump tables — as in
  [msvc-9.md](msvc-9.md).

## Stack probes

- `mov eax,<size>; call __chkstk` — unchanged, see
  [msvc-6.md](msvc-6.md).

## 100% unique to this version

- **Memory-operand `imul` in signed-div magic** — `x/3`, `x/12`, `x/100`
  compile to `imul dword ptr [esp+4]` (`f7 6c 24 04`) with the magic
  constant loaded straight into EAX; VC 5.0–9.0 load the divisor into a
  register first (`mov ecx,[esp+4]; imul ecx`).  Verified in probe2:
  10.0 and 11.0 share the memory-imul form, 5.0–9.0 the register form.
- **`iabs` via cdq** — `x<0?-x:x` compiles to `cdq; xor eax,edx; sub
  eax,edx` (`99 33 c2 2b c2`) in 10.0+ (and, historically, 2.0/4.x);
  VC 5.0–9.0 emit `test eax,eax; jns; neg eax` (`85 c0 7d 02 f7 d8`).
  Verified in probe2: 10.0 and 11.0 share the cdq form.
- **`jns` for the `x<0` test** in clamps — `79` where 5.0–9.0 emit
  `jge` (`7d`); observed in `clamp` (10.0/11.0) — micro-scheduling, not
  claimed as a strong standalone marker.
- **Service pack:** 10.0 SP1 is codegen-identical to 10.0 RTM (probes
  1–5, /O1 and /O2).  `fcmp2` keeps the `fucompp` style shared with
  7.0 RTM/7.1 — the FP-equality style is not a 10.0 marker.
- The 10.0 probe otherwise matches 9.0's codegen (same sizes, census,
  unrolling).  Identity via Rich build 30319/40219 + linker 10.0.

## Version deltas

- From VC 9.0: nothing verified in codegen.
- To VC 11.0: SSE2 FP ops appear (addsd/mulsd/divsd/addss alongside
  x87).

## Probe12: static-helper inlining — verified positive

Small static helpers inline at /O2 and /O1 (11–12B callers), matching
the VC 7.0+ era marker; 10.0 SP1 is identical to RTM on this feature
(SP spot-check).  Verified in probe12 (`f1`/`f2`/`fl`).

## Probe13: string intrinsics + promotion — verified

- **strlen manual scan loop** at /O2 (`8d 50 01 8a 08 40 84 c9 75 f9
  2b c2`), the 7.0+ form.
- **memcmp(8B) dword-compare loop** with `83 e8 04`/`83 c1 04`/
  `83 c2 04` decrement+advance at /O2 — the 9.0/10.0 pair (8.0 uses
  an ESI counter, 11.0 a 2-dword + byte-tail form).
- **signed-char compare against the zero register in memory**
  (`33 c0 38 44 24 04 0f 9c c0`) — 8.0+ form.

## Verification

Probe `/O1`/`/O2` via `rebrew/msvc:10.0-win32`
(`msvc1000_{O1,O2}.obj`); probe2 (`msvc1000_O2.obj` — memory-imul div
magic, cdq-abs, `jns` clamp) diffed against 9.0 and 11.0; smoke
`msvc1000/t.obj`, `msvc1000sp1/t.obj`.
