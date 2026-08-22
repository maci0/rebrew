# MSVC 9.0 — codegen patterns

MSVC 9.0 (VS 2008, CL 15.00.21022; SP1 = 15.00.30729).  First version to
**unroll small loops** in the probe; /GS unchanged.

**Profiles:** `msvc900`, `msvc900sp1` — Rich builds 21022, 30729; linker
9.0.

## Prologue & frame pointer

- `/O2`: no frame pointer for simple functions; **`bsum` (unrolled)
  pushes `ebp` as an extra register** (`55` in `push ebp; push esi;
  push edi` — ebp is used as a free temp while the frame stays
  esp-based).  /O1 keeps `55 8b ec` frames for some functions.

## /GS security cookie

- Same as [msvc-8.md](msvc-8.md): `a1 [cookie]; 33 c4 xor eax,esp;
  mov [esp+0x1770],eax` prologue + `33 cc; call __security_check_cookie`
  epilogue, frame +4 bytes (verified in `bigstack`, 72B vs 39B in 6.0).

## Loops

- **Loop unrolling**: `bsum` (unsigned char sum over `len`) becomes a
  peeled 2-iteration loop — `cmp edi,2; jl <epilogue>; dec edi; …`
  (74B vs 33B in VC 6.0).  `bigstack`'s 6000-iteration loop stays
  rolled but gains the `lea ebx,[ebx]` alignment nop at the head.
- Loop-align nops: `lea ebx,[ebx]` (`8d 9b 00 00 00 00`) in
  `bigstack`; census also shows 2× `8d 64 24 00` (`lea esp,[esp]`) in
  the same object — both forms coexist.

## Register conventions

- `movzx` char loads; unrolled loops use `ebp` as a scratch register
  (saved/restored like the callee-saved set).

## Integer division / String ops / Padding / Switch

- Magic + post-shift division, `rep stosd`/`rep movsd` inlining,
  dense jump tables — all as in [msvc-8.md](msvc-8.md).

## FPU / SSE

- Pure x87 — unchanged from [msvc-8.md](msvc-8.md).

## Stack probes

- `mov eax,<size>; call __chkstk` — unchanged, see
  [msvc-6.md](msvc-6.md).

## Optimization fingerprints

- Same wrapper styles; the unrolling is /O2-only in the probe.

## 100% unique to this version

- **None proven per version.**  Loop unrolling of the probe's shapes is
  verified in 9.0, 10.0 and 11.0 (all three `bsum`s 74–78B; `dot`
  unrolled ×4 in 9.0+); `rol` for rotates is shared with 8.0+; /GS and
  nops are shared with 8.0+.  No verified byte marker separates 9.0
  from 8.0 or 10.0 (census counts identical: `lea esp,[esp]`=2,
  `movsx`=2, `movzx`=5, same magic set).  Identity via Rich build
  21022/30729 + linker 9.0.
- **Service pack:** 9.0 SP1 is codegen-identical to 9.0 RTM at `/Od`
  (probe5).  The `/O1`/`/O2` comparison is **blocked**: the SP1
  compiler needs `sched.dll` (C1350 "error loading dll"), and the DLL
  was never vendored into any image — verified absent from the 9.0
  RTM, 9.0 SP1, 10.0, 10.0 SP1 and 11.0 images (a packaging defect,
  not a compiler behavior).  A workaround by staging `sched.dll` from
  another image is not possible — no image has it.

## Version deltas

- From VC 8.0: loop unrolling (the visible change); nop register ebx in
  `bigstack` (already observed in 8.0).
- To VC 10.0: nothing verified in codegen (identical census).

## Probe12: static-helper inlining — verified positive

Small static helpers inline at /O2 and /O1 (11–12B callers), matching
the VC 7.0+ era marker.  Verified in probe12 (`f1`/`f2`/`fl`).

## Probe13: string intrinsics + promotion — verified

- **strlen manual scan loop** at /O2 (`8d 50 01 8a 08 40 84 c9 75 f9
  2b c2`), the 7.0+ form.
- **memcmp(8B) dword-compare loop** with `83 e8 04`/`83 c1 04`/
  `83 c2 04` decrement+advance at /O2 — the 9.0/10.0 pair (8.0 uses
  an ESI counter, 11.0 a 2-dword + byte-tail form).
- **signed-char compare against the zero register in memory**
  (`33 c0 38 44 24 04 0f 9c c0`) — 8.0+ form.

## Probe15: function boundaries + the 9.0 SP1 unblock — verified

- **`/GS` cookie prologue** — `sub esp,0x44; mov eax,[__security_cookie];
  xor eax,esp; mov [esp+0x40],eax` (`a1 <abs> 33 c4 89 44 24 40`) —
  the 8.0+ cookie-mix form, MSVC-unique among the probed toolchains
  (GCC/Zig/bcc32/Watcom emit no cookies).
- **signed setcc** — `a < b` = `cmp ecx,[esp+8]` against MEMORY
  (`8b 4c 24 04 33 c0 3b 4c 24 08 0f 9c c0`), the 8.0+ form
  (5.0–7.1 load both operands; 2.0/4.x use branch + `mov eax,1`).
- **VC 9.0 SP1 UNBLOCKED** — the previously-recorded sched.dll blocker
  is resolved: the x86 `sched.dll` from the XP SP1 SDK cross-tools
  (win2k-revival/downloads) is interface-compatible with the SP1
  cl.exe.  With it mounted next to cl.exe, VC 9.0 SP1 compiled
  probe13/14/15 at /O2 and /O1 and is **byte-identical to the 9.0 RTM
  on every one of the 54 probe functions** — the SP record is now
  complete: every MSVC SP probed is identical to its RTM except VC
  7.0 SP1's known 17 functions.

## Verification

Probe `/O1`/`/O2` via `rebrew/msvc:9.0-win32` (`msvc900_{O1,O2}.obj`);
smoke `msvc900/t.obj`.  `/GS` + unrolling reproduced at /O2.
