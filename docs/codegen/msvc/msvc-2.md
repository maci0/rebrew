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

## Probe13: string intrinsics + promotion — verified

- **strlen is `repne scasb` (`f2 ae`)** with ECX=−1 at /O2 — the
  2.0–6.0 form; bcc32/Watcom/GCC libcall strlen instead.
- **memcmp(8B) is `repe cmpsb` (`f3 a6`) + sbb idiom** at /O2 — the
  2.0–7.1 form.
- **`unsigned char` sums use `xor eax,eax; mov al`** (2.0/4.x form;
  shared with bcc32) at /O2; every version uses `movzx` at /O1.
- **8-byte struct returns round-trip the stack** (`83 ec 08` + field
  copies + reload) — 2.0/4.x; 5.0+ return in EAX:EDX.

## Probe14: zero-compare + 64-bit — verified

- **`a == 0` uses `cmp dword ptr [esp+4],1; sbb eax,eax; neg eax`
  (`83 7c 24 04 01 1b c0 f7 d8`)** — the compare-against-1 idiom,
  unique to the 2.0/4.x era among the probed toolchains (5.0–7.1:
  load+`test`; 8.0+: memory compare against the zero register).
- **64-byte struct returns round-trip the stack** (`83 ec 40` + field
  stores) — the 2.0/4.x form of the large-struct return.
- `g_counter++` round-trips EAX (`a1 … 40 … a3`) at /O2 — same as
  5.0–11.0 except 8.0's `add eax,1` variant.

## Probe15: setcc + stdcall — verified

- **setcc uses branch + `mov eax,1`** — `a < b` = `cmp [esp+8],[esp+4]`
  load + `b8 01 00 00 00` + `jle`-branch — the 2.0/4.x branch-form
  (5.0+ use `setcc`).
- **shift counts load as BYTES** — `a << b` loads b via `mov cl,
  [esp+8]` (`8a 4c 24 08`) where 5.0+ load the full dword.
- **stdcall args load in DIRECT order** — `std_add` = `mov eax,
  [esp+4]; add eax,[esp+8]` (2.0/4.1 form; 5.0–9.0 reverse the order;
  11.0 returns to direct).

## Probe16: 64-bit division — verified

- **VC 2.0/4.x have no 64-bit integer type** — the probe16 i64
  functions are absent from their objects (documented negative; the
  type arrives in 5.0).

- **Corpus pointer** — machine-checked in `corpus.json` (7892 records; the mechanical sweep confirmed this file's records and surfaced no un-documented markers here).

## Probe17: conventions + allocator behaviors

- **Probe17 allocator/conventions**: `-1` stores use the IMMEDIATE `c7 05 <addr> ff ff ff ff` form (2.0/4.x era; 5.0–10.0 use `or eax,-1` + `a3`); no zero register is materialized (`cmp [mem],0` memory-immediate compares).  Varargs float→double promotion verified (`fld; sub esp,8; fstp qword [esp]`).  See RULES.md A5/B5.

- **Decomp idioms** — the probe19/20 game-idiom signatures for this toolchain are in [DECOMP_IDIOMS.md](DECOMP_IDIOMS.md) and the corpus (`probe19`/`probe20` records).

## Verification

Probe compiled with `rebrew/msvc:2.0-win32` at `/O1` and `/O2`
(`.cache/fp_probe/out/msvc200_{O1,O2}.obj`), disassembled via objconv and
capstone; smoke object `.cache/smoke/msvc200/t.obj` (unoptimized `add`).
All patterns above reproduced from those objects.
