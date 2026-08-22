# MSVC 2.0 — codegen patterns

First 32-bit MSVC (1994, "Microsoft C/C++ 9.00").  The 32-bit cdecl/COFF
line starts here; everything VC 2.0–11.0 shares is listed once in this
file and referenced from the later ones.

**Profiles:** `msvc200` — image `rebrew/msvc:2.0-win32`, linker 2.50,
no Rich header (early linkers write none).

## Prologue & frame pointer

- `/O2`: **no frame pointer** — args at `[esp+4]`/`[esp+8]`, e.g.
  `mov eax, dword ptr [esp+4]` (`8b 44 24 04`).
- Unoptimized: `push ebp; mov ebp,esp` (`55 8b ec`), args at `[ebp+8]`
  (smoke object `.cache/smoke/msvc200/t.obj`: `55 8b ec 8b 45 08 03 45 0c
  5d c3`).

## Argument passing

- Direct `[esp+N]` loads, no intermediate pushes for own args.
- `many(a,b,c,d)`: loads all four from `[esp+4..10]` and adds — no
  spill/reload; `mov ecx,[esp+0x10]; mov eax,[esp+4]; add ecx,[esp+0xc]…`.

## Register conventions

- Callee-saved: `ebx/esi/edi` (saved with `push` when used — `bsum` pushes
  `esi, edi`).
- Loop indices live in any free register (`eax` in bigstack, `esi` in
  bsum).
- **Micro-detail:** zero-tests compare against a zeroed register instead
  of `test reg,reg` — `bsum` uses `xor eax,eax … cmp edx,eax` (`3b d0`)
  where VC 5.0+ emits `test edx,edx` (`85 d2`).

## Integer division

- **Real `div`/`idiv`** — no magic constants: `x/3u` →
  `mov ecx,3` (`b9 03 00 00 00`) · `mov eax,[esp+4]` · **`sub edx,edx`
  (`2b d2`)** · `div ecx` (`f7 f1`).  Signed: `cdq` (`99`) + `idiv ecx`.
- **`sub edx,edx` to zero the dividend's high half is the VC 2.0/4.x
  marker** — VC 5.0+ (and every other compiler probed) uses
  `xor edx,edx` (`33 d2`).  Unique to the real-div era within this set.

## FPU / SSE

- Pure x87: `fadd(double)` → `fld qword [esp+0xc]` (`dd 44 24 0c`);
  `fadd qword [esp+4]` (`dc 44 24 04`); `ret`.
- **`a+1.0` uses `fld1` (`d9 e8`)** then `fadd qword [esp+4]` — the
  VC 2.0/4.x encoding (VC 5.0: fsub-negation; VC 6.0+: `fadd [const]`).
- `a/10.0` compiles to a multiply by the reciprocal stored in `.rdata`:
  `fld qword [esp+4]; fmul qword [const]` — never `fdiv` and never
  `fld1`-based constant synthesis.

## Loops

- `dec`/`jnz`-style induction (`inc eax; cmp eax,0x1770; jl`) — no `loop`
  instruction, no alignment nops inside bodies (nothing to align to).

## String ops

- `p[i]=0x3e8` (memset-shaped) → `mov eax,0x3e8; rep stosd` (`f3 ab`) —
  MSVC string-op inlining already present in 2.0.
- Signed char scan: `movsx` (`0f be`); unsigned char sum: `movzx`
  (`0f b6`) — VC 2.0 uses `movzx edi, byte ptr [ecx+esi]`.

## Padding & nops

- Inter-section/COMDAT `90` pads and `cc` — no multi-byte alignment nops
  in code (probe: zero `8d 64 24 00`, zero `8d 74 26 00`, zero `8d a4 24`).

## Stack probes

- Frames > 4 KB: `mov eax,<size>` (`b8 70 17 00 00` for 6000) + `call
  __chkstk`.  The `__chkstk` symbol appears in objects; stripped PEs lose
  it (detect the `b8 imm32 e8` prologue shape instead).

## Switch dispatch

- Jump table: `dec eax; cmp eax,4; … jmp dword ptr [eax*4]` — dense-range
  table, same shape as every later MSVC.

## Optimization fingerprints (/O1 vs /O2)

- /O2 wrapper calls load-first (`mov eax,[esp+4]; push eax; call; add
  esp,4`); /O1 pushes memory operands directly (`push dword [esp+4]`).
  Same two mutually-exclusive styles as all later versions.

## 100% unique to this version

- **None proven per minor.**  VC 2.0 and 4.x share every verified marker:
  the `sub edx,edx` div-zero (`2b d2`), real `div`, `cmp reg,zeroreg`
  zero-tests, `fld1` for FP `+1.0` (`a+1.0` → `d9 e8; fadd qword
  [esp+4]`), the **3-byte shift-by-1 encoding** — `x/2u` →
  `shr eax,1` as `c1 e8 01` and `x/2` → `sar eax,1` as `c1 f8 01`
  (VC 5.0+ use the 2-byte `d1 e8`/`d1 f8`) — verified in probe3
  (`u2`/`s2`) — and the **no-op `sub esp,4; add esp,4` pair after
  `fild`** in `(double)x` (`83 ec 04 83 c4 04`, verified in probe4
  `i2d`/`i2f`).  **SEH `fs:[0]` load before the frame** —
  `__try/__except` loads `mov eax,fs:[0]` (`64 a1 00 00 00 00`)
  before `push ebp; mov ebp,esp` (verified in probe7 `seh1`; shared
  with 4.x).  No verified codegen separates 2.0 from 4.x, or one
  4.x minor from another — use the linker version (2.50 → VC 2.0,
  3.0/3.10/4.20 → 4.x).

## Version deltas (vs nothing — first 32-bit)

- From the 16-bit line (VC 1.x): 32-bit registers/stack, COFF objects,
  `[esp+N]`/`[ebp+N]` args instead of `[bp+N]`; no `leave` epilogues, no
  `fwait`-interspersed FPU.
- To VC 4.x: nothing codegen-visible in the probe (identical objects).
- To VC 5.0: real `div` → magic constants; `sub edx,edx` → `xor edx,edx`;
  `cmp reg,zeroreg` → `test reg,reg`.

## Probe12: static-helper inlining — verified negative

Small static helpers called once/twice/in a loop are NOT inlined: VC
2.0 keeps the `call` at both /O2 and /O1 (30–34B callers), unlike VC
7.0+ which inline them (11–12B).  Verified in probe12
(`f1`/`f2`/`fl`); keeping the call is itself the 2.0–6.0 era marker.

## Verification

Probe compiled with `rebrew/msvc:2.0-win32` at `/O1` and `/O2`
(`.cache/fp_probe/out/msvc200_{O1,O2}.obj`), disassembled via objconv and
capstone; smoke object `.cache/smoke/msvc200/t.obj` (unoptimized `add`).
All patterns above reproduced from those objects.
