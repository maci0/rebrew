# MSVC 7.1 — codegen patterns

MSVC 7.1 (VS .NET 2003, CL 13.10.3077; SP1 = 13.10.6030).  The last pure
x87 MSVC of the .NET era; codegen-identical to 7.0 for the probe.

**Profiles:** `msvc7`, `msvc710`, `msvc710sp1` — Rich builds 3077
(RTM), 6030 (SP1); linker 7.10.

## Prologue & frame pointer

- `/O2`: no frame pointer; args `[esp+4]`+.  Unoptimized: `55 8b ec`
  (smoke `msvc710/t.obj`).

## Argument passing

- Direct `[esp+N]` loads; /O1//O2 wrapper styles unchanged.

## Register conventions

- Same as 7.0: `movzx` for unsigned char (`movzx edi,[ecx+esi]`),
  `ebx/esi/edi` callee-saved.

## Integer division

- Magic + post-shift (`shr edx,N`) — identical to 7.0
  (`0xAAAAAAAB; mul; shr edx,1; mov eax,edx`).

## FPU / SSE

- Pure x87; `.rdata` constants; unchanged.

## Loops

- `lea esp,[esp]` (`8d 64 24 00`) loop-alignment nops — verified in
  `bigstack`/`csum` (3 at /O2), same as 7.0.
- `strcmp_like`/`sw` show `mov edi,edi` (`8b ff`) used as 2-byte
  alignment padding inside code (`000e: 8b ff` before the loop) — the
  hotpatch-era 2-byte nop.  Observed; also present as padding in VC 6.0
  linked binaries, so not a version-exclusive marker.

## String ops

- `rep stosd`/`rep movsd` unchanged.

## Padding & nops

- Same ladder as 7.0 (`90`/`8b ff`/`8d 74 26 00`/`8d a4 24`) + the
  intra-body `8d 64 24 00`.

## Stack probes / Switch dispatch

- `mov eax,<size>; call __chkstk`; dense jump tables — unchanged.

## Optimization fingerprints

- Same wrapper styles; loop heads aligned with `8d 64 24 00`.

## 100% unique to this version

- **None proven.**  7.1 is codegen-indistinguishable from 7.0 for
  probes 1–5 (same object sizes: 473B /O2; same nops, tails,
  wrappers; `fcmp2` keeps the `fucompp` style — see
  [msvc-7.md](msvc-7.md) for the 7.0-SP1 flip).  Identity via Rich
  build (3077/6030) + linker 7.10.
- **Service pack:** 7.1 SP1 is codegen-identical to 7.1 RTM (probes
  1–5, /O1 and /O2).

## Version deltas

- From VC 7.0: nothing verified in codegen.
- To VC 8.0: /GS security cookies arrive (default-on for buffer
  functions); `lea esp,[esp]` counts drop slightly in the probe (8.0:
  2 vs 7.x: 3).

## Probe12: static-helper inlining — verified positive

Small static helpers inline at /O2 and /O1 (11–12B callers) — VC 7.1
shares VC 7.0's inlining marker; 7.1 SP1 is identical to RTM on this
feature (SP spot-check).  Verified in probe12 (`f1`/`f2`/`fl`).

## Verification

Probe `/O1`/`/O2` via `rebrew/msvc:7.1-win32` (`msvc710_{O1,O2}.obj`);
smoke `msvc710/t.obj`, `msvc710sp1/t.obj`, `msvc7/t.obj` (all
unoptimized `_add`, byte-identical).
