# MSVC 4.x — codegen patterns

MSVC 4.0 / 4.1 / 4.2 (1995–1996, CL 10.00/10.10/10.20).  The last
real-`div` era; codegen-identical to VC 2.0 for the probe.

**Profiles:** `msvc400` (4.0, linker 3.0), `msvc410` (4.1, linker 3.10),
`msvc420` (4.2, linker 4.20).  No Rich header — the linker version names
the version.

## Prologue & frame pointer

- `/O2`: no frame pointer; args `[esp+4]`+ (identical to VC 2.0).
- Unoptimized: `55 8b ec` frame (smoke `msvc410/t.obj`).

## Argument passing

- Direct `[esp+N]` loads; `_many` loads all args from the stack and adds —
  same shape as VC 2.0.

## Register conventions

- Same as VC 2.0: `ebx/esi/edi` callee-saved, `push esi/push edi` saves.
- Same `cmp reg,zeroreg` zero-test idiom as 2.0 (e.g. `cmp edx,eax` with
  `eax=0`).

## Integer division

- **Real `div`/`idiv` with `sub edx,edx` (`2b d2`) zero-extend** —
  identical to VC 2.0 (`mov ecx,3; mov eax,[esp+4]; sub edx,edx; div
  ecx`).  Signed: `cdq; idiv ecx`.
- The `sub edx,edx` marker is shared with VC 2.0 (see
  [msvc-2.md](msvc-2.md)); 5.0+ uses `xor edx,edx`.

## FPU / SSE

- Pure x87 (`fld`/`fadd`); FP constants from `.rdata` via `fmul` —
  identical to 2.0.

## Loops / String ops / Padding / Switch

All identical to [msvc-2.md](msvc-2.md): `dec/jnz` loops with no
alignment nops, `rep stosd` inlining, `movsx`/`movzx` char ops,
dense jump tables.

## Stack probes

- `mov eax,<size>; call __chkstk` — identical to
  [msvc-2.md](msvc-2.md)/[msvc-6.md](msvc-6.md).

## Optimization fingerprints (/O1 vs /O2)

- Same load-first (/O2) vs push-[mem] (/O1) wrapper styles as all MSVC.

## 100% unique to this version

- **None proven per minor.**  The 4.0/4.1/4.2 probe objects are
  byte-for-byte identical to each other **and** to VC 2.0's for every
  probe function (object sizes match exactly: 4469/4758 bytes).  Shared
  markers with 2.0: `sub edx,edx` div-zero, real `div`, `cmp
  reg,zeroreg`, `fld1` for FP `+1.0`, and the 3-byte shift-by-1
  encoding (`c1 e8 01`/`c1 f8 01` — see [msvc-2.md](msvc-2.md)).
  **No-op stack pair after `fild`** — `(double)x` emits `fild
  [esp+4]` followed by `sub esp,4; add esp,4` (`83 ec 04 83 c4 04`,
  a no-op pair) in VC 2.0/4.x — absent in every later version.
  Verified in probe4 (`i2d`/`i2f`).  **SEH `fs:[0]` load before the
  frame** — `__try/__except` functions load `mov eax,fs:[0]`
  (`64 a1 00 00 00 00`) BEFORE `push ebp; mov ebp,esp` in VC 2.0/4.x
  (5.0+ loads it after the frame).  Verified in probe7 (`seh1`).
  No verified codegen separates
  4.x from 2.0, or one 4.x minor from another — use the linker
  version (3.0 / 3.10 / 4.20) or PE-era metadata.

## Version deltas

- From VC 2.0: nothing verified in codegen — the compiler line is the
  same optimizer.  (The runtime/CRT changed — crtdll.dll — but that is a
  linking signal, not codegen.)
- To VC 5.0: the big jump — magic-number division arrives, `sub edx,edx`
  becomes `xor edx,edx`, `cmp reg,zeroreg` becomes `test reg,reg`, and
  constant-caching hoists loop-invariant values into `ebx/ebp/esi/edi`.

## Probe12: static-helper inlining — verified negative

Small static helpers called once/twice/in a loop are NOT inlined: VC
4.x keeps the `call` at both /O2 and /O1 (30–34B callers), unlike VC
7.0+ which inline them (11–12B).  Verified in probe12
(`f1`/`f2`/`fl`); keeping the call is itself the 2.0–6.0 era marker.

## Probe13: string intrinsics + promotion — verified

- **strlen is `repne scasb` (`f2 ae`)** with ECX=−1 at /O2 — the
  2.0–6.0 form; bcc32/Watcom/GCC libcall strlen instead.
- **memcmp(8B) is `repe cmpsb` (`f3 a6`) + sbb idiom** at /O2 — the
  2.0–7.1 form.
- **`unsigned char` sums use `xor eax,eax; mov al`** (2.0/4.x form;
  shared with bcc32) at /O2; every version uses `movzx` at /O1.
- **8-byte struct returns round-trip the stack** (`83 ec 08` + field
  copies + reload) — 2.0/4.x; 5.0+ return in EAX:EDX.

## Verification

Probe compiled with `rebrew/msvc:4.0-win32`, `4.1-win32`, `4.2-win32` at
`/O1` and `/O2` (`probe_4.0.obj`, `probe_4.1.obj`/`msvc410_O2.obj`,
`probe_4.2.obj`); smoke `msvc410/t.obj`.  Object sizes and disassembly
confirmed identical across the three minors and vs VC 2.0.
