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

- **Probe17 allocator/conventions**: `-1` stores use the IMMEDIATE `c7 05 <addr> ff ff ff ff` form (2.0/4.x era); no zero register materialized.  Varargs float→double promotion verified.  See RULES.md A5/B5.

- **Decomp idioms** — the probe19-28 game-idiom signatures for this toolchain are in [DECOMP_IDIOMS.md](../DECOMP_IDIOMS.md) and the corpus (`probe19`-`probe28` records).

## Probe22: guild-rule verification (round 19)

- **Probe22 (4.x-era)**: mirrors 2.0's C23 mask-always + C24 sbb decomposition; `byte_dead2` is the only xor-extend `movzx`-style form (`33 c0; mov cl,[eax]`).  See RULES.md C23/C24.


## Probe23: Findings 23-36 shapes (round 20)

- **Probe23 (4.x-era)**: mirrors 2.0 (real idiv, shl+lea idx, materialized add); `argslot` allocates `sub esp,4`.  See RULES.md C28/E16/E17.


## Probe24: Findings 37-43 primitives (round 21)

- **Probe24 (4.x-era)**: word zero-extend `xor;mov ax` begins (4.1); size-dispatch cmp-chain; in-place and.  See RULES.md C29/F24.


## Probe25: Finding 44 primitives (round 22)

- **Probe25 (4.x-era)**: mirrors 2.0 (branchy clamp, 4-lea ×589, raw byte push).  See RULES.md C30/C31.


## Probe26: Finding 45 early-return placement (round 23)

- **Probe26 (4.x-era)**: inline early returns; `mov eax,-1` tail.  See RULES.md F25.


## Probe27: Findings 46-50 primitives (round 24)

- **Probe27 (4.x-era)**: mirrors 2.0 (shared fail tail, entry push, immediate or).  See RULES.md F25/C32.


## Probe28: decompedia/CODEGEN_PATTERNS claims (round 25)

- **Probe28 (4.x-era)**: mirrors 2.0 (fld1, inc/sbb, branchy cmp, mov ax).  See RULES.md D10/F25.


## Verification

Probe compiled with `rebrew/msvc:4.0-win32`, `4.1-win32`, `4.2-win32` at
`/O1` and `/O2` (`probe_4.0.obj`, `probe_4.1.obj`/`msvc410_O2.obj`,
`probe_4.2.obj`); smoke `msvc410/t.obj`.  Object sizes and disassembly
confirmed identical across the three minors and vs VC 2.0.
## Probe29: round-29 era markers (4.1)

- **4.1 vs 2.0 within the shared pre-5.0 line**: `bitf_get` uses
  `xor eax,eax; mov al,[mem]` (`33 c0 8b 4c 24 04 8a 41 01` — 2.0
  masks instead); `min_ii`/`max_ii` load the FIRST arg first (2.0
  loads the second); `fastcall4_` shuffles the stack args via esi
  (`8b 44 24 08 56 … 5e`, A11); the sparse switch normalizes with
  `sub eax,min` + a small `movzx`-indexed table (shared 2.0).  Shares
  the 2.0 cdq-abs, fild-dance cvt_i2d, hidden-pointer s8_ret and real
  `%10` idiv.  See RULES.md C35-C40/D12/D13/G7/A11.
## Probe30: round-30 era markers (4.1)

- **4.1 mirrors 2.0** on the new shapes (real-idiv %, lea-chain mul,
  repne-scasb strlen, fild-stack i64→d, __allmul ×5) with the 4.1
  register-order variants.  See RULES.md C42-C46/E26-E28.
