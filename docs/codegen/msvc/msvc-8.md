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
- **SEH frame `push -2`** — `__try/__except` functions open the SEH
  frame with `push -2` (`6a fe`, the new handler marker) from VC 8.0
  on, interleaved with the /GS cookie; VC 2.0–7.1 use `push -1`
  (`6a ff`).  Verified in probe7 (`seh1`).
- **`fldz` FP-loop accumulator init** — FP accumulation loops seed
  the accumulator with `fldz` (`d9 ee`) from VC 8.0 on; VC 2.0–7.1
  load 0.0 from `.rdata`.  Verified in probe8 (`fs1`/`fs2`/`fs3`).
- **`/arch:SSE2` switches copies and compares to SSE** — with
  `/arch:SSE2`, VC 8.0/9.0 emit `movq xmm0,[s]; movq [d],xmm0`
  (`f3 0f 7e`/`66 0f d6`) for 16-byte copies, `pxor xmm0,xmm0` for
  16-byte memset, and `movsd; comisd; jbe` (`66 0f 2f`) for FP
  compares — the same SSE forms VC 11.0 produces by default (see
  [msvc-11.md](msvc-11.md)).  Verified in probe11 (`mc16`/`ms16`/
  `fcmp`).  Basic x87 FP adds are NOT affected (fadd1 stays x87).
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

## Probe12: static-helper inlining — verified positive

Small static helpers inline at /O2 and /O1 (11–12B callers), matching
the VC 7.0+ era marker.  Verified in probe12 (`f1`/`f2`/`fl`).

## Probe13: string intrinsics + encoding quirks — verified

- **strlen manual loop with `add eax,1` (`83 c0 01`)** where 7.x and
  9.0–11.0 use `inc eax` (`40`) — VC 8.0's `add`-over-`inc` encoding
  preference, seen in strlen AND `g_val+1`; family-level only (GCC
  also emits `83 c0 01` for `g_val+1`).
- **memcmp(8B) switches to a dword-compare loop** (ESI=8 counter) at
  /O2 — the `repe cmpsb` rep-string form ends at 7.1.
- **signed-char compare against the zero register in memory**
  (`33 c0 38 44 24 04 0f 9c c0`) — the 8.0+ form; 5.0–7.1 load the
  byte and `test` it, 2.0/4.x `cmp byte ptr [esp+4],0`.

## Probe14: statement idioms — verified

- **`g_counter++` / `g_counter--` use `add eax,1` / `sub eax,1`
  (`83 c0 01` / `83 e8 01`)** where every other version (2.0–7.1,
  9.0–11.0) uses `inc`/`dec` (`40`/`48`) — a third independent
  confirmation of VC 8.0's add-over-inc encoding (probe13: strlen +
  `g_val+1`; probe14: `g_inc`/`g_dec`).  Family-level: GCC emits
  `83 c0 01` too.
- **zero-compare** — `a == 0` = `cmp dword ptr [esp+4],eax` against
  the zero register (`33 c0 39 44 24 04 0f 94 c0`), the 8.0+ form
  (5.0–7.1: load+`test`; 2.0/4.x: `cmp [mem],1; sbb; neg`).
- **64-byte memcpy = `rep movsd`** — shared by every MSVC version.

## Probe15: /GS cookies + setcc — verified

- **`/GS` cookie prologue** — the buffer function opens
  `sub esp,0x44; mov eax,[__security_cookie]; xor eax,esp; mov
  [esp+0x40],eax` (`a1 <abs> 33 c4 89 44 24 40`) — the verified
  cookie-mix form, MSVC-unique among the probed toolchains (no other
  emits stack cookies).  The 8.0 copy loop also shows the `add eax,1`
  (`83 c0 01`) encoding — a FIFTH independent confirmation of the
  add-over-inc trait.
- **signed setcc compares in memory** — `a < b` = `cmp ecx,[esp+8]`
  (`8b 4c 24 04 33 c0 3b 4c 24 08 0f 9c c0`) — the 8.0+ form
  (5.0–7.1 load both; shared memory-form with GCC/Zig).
- **`wchar >= 0x100`** = `cmp word ptr [esp+4],0x100` + `sbb` +
  `add eax,1` (`66 81 7c 24 04 00 01 1b c0 83 c0 01`) — memory-
  immediate compare with the add-over-inc tail (2.0–7.1 use `inc
  eax`; 9.0+ load the constant into EAX first).

## Probe16: 64-bit division — verified

- **64-bit division = register-load + 4-push helper call** — the
  5.0–10.0 form (8.0: `8b 44 24 10 8b 4c 24 0c 8b 54 24 08 50 8b 44
  24 08 51 52 50 e8`); /O1 uses the compact 4× memory-push in every
  version.

- **Corpus pointer** — machine-checked in `corpus.json` (7892 records; the mechanical sweep confirmed this file's records and surfaced no un-documented markers here).

## Probe17: conventions + allocator behaviors

- **Probe17 allocator/conventions**: `-1` register form; zero in EAX; moffs (`a1`/`a3`) usage doubles from 8.0 across the corpus (fingerprint B11).  See RULES.md B5/B11.

## Verification

Probe `/O1`/`/O2` via `rebrew/msvc:8.0-win32` (`msvc800_{O1,O2}.obj`);
smoke `msvc800/t.obj`, `msvc800sp1/t.obj`.  `/GS` cookie pattern
reproduced in `bigstack` at /O2.
