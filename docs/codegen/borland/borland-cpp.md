# Borland C++ 5.5 (bcc32) — codegen patterns

Borland C++ 5.5 (1999) — the free 32-bit Windows command-line tools
(`bcc32`, wine/wibo).  Emits OMF objects.  Verified with **`-O1`**.

**Profiles:** `borlandc55` — image `rebrew/borland:5.5-win32`.

## Prologue & frame pointer — the Borland signature

- **Frame pointer in EVERY function, even at `-O1`**: `push ebp; mov
  ebp,esp` (`55 8b ec`), args at `[ebp+8]`/`[ebp+0xc]` — verified 18
  frame prologues in the probe.  MSVC `/O2` and Watcom omit the
  frame; this always-on frame is the Borland codegen signature
  (shared with the 16-bit Turbo line; bcc32 has no frame-pointer-
  omission flag like MSVC's `/Oy`).

## Argument passing

- Frame-based `[ebp+N]` loads for own args; call sites push args
  right-to-left (cdecl).  No `[esp+N]`-addressed wrappers in the
  probe (unlike MSVC's /O1//O2 wrapper styles — bcc32's /O1 probe
  shows none of the `ff 74 24 04`/`8b 44 24 04 50` wrapper shapes).

## Integer division

- **Real `div`/`idiv` for EVERY small-constant divisor, at both `-O1`
  and `-O2`** — verified across 13 unsigned and 13 signed divisors
  (2/3/5/6/7/9/10/11/13/25/100/1000/100000 and the big constants):
  `x/3u` → `mov ecx,3; xor edx,edx; div ecx`; signed → `cdq; idiv ecx`.
  **bcc32 emits NO magic constants at all** (an earlier census hit for
  `0xCCCCCCCD` in `/10u` was a false positive — the real disassembly is
  `mov ecx,10; div ecx`).  Real-division-for-all-constants is the
  bcc32 signature vs MSVC 5.0+/GCC (which use magic).

## Register conventions

- Callee-saved `ebx/esi/edi`; `movsx`/`movzx` for char ops; `[ebp+8]`
  args.

## 64-bit arithmetic

- **Helper calls with Borland's own names**: `call __llmul`
  (`_i64mul`), `call __lldiv`, `call __llshl` — vs MSVC's
  `__allmul`/`__alldiv`/`__allshl`, Watcom's `__I8M`/`__I8D`/`__I8LS`
  and GCC's inline mul + `__divdi3`.  The `__ll*` symbol is a clean
  Borland marker in objects and unstripped binaries.

## FPU

- x87, frame-addressed (`fld qword [ebp+8]; fadd [ebp+0x10]`); FP
  constants from `.rdata`.  **`long double` is 80-bit** (`fld tbyte
  ptr [ebp+8]`) — shared with GCC/TC, distinct from MSVC/Watcom
  (which treat long double as double).

## String ops / Loops / Padding

- No `rep stosd` memset inlining in the probe (unlike MSVC); no
  multi-byte GNU nops; no MSVC-style `8d 74 26 00`/`8d 64 24 00`
  alignment nops observed.

## Stack probes

- Not triggered by the probe (no >4 KB frame); no `__chkstk`-style
  symbol observed in the object.  Unverified beyond that.

## 100% unique to this version

- **Real `div`/`idiv` for every small-constant divisor at every opt
  level** — verified `-O1` and `-O2`, 13+ divisors each (MSVC 5.0+
  and GCC use magic for the same code; MSVC 2.0/4.x, Watcom and TC
  also use real div, so this is family-shared with the real-div
  camp but a clean discriminator vs the magic camp).
- **`__llmul`/`__lldiv`/`__llshl` helper symbols** — verified in the
  probe3 object; unique among the tested toolchains.
- Frame-pointer-always is shared with Turbo C 2.0/3.1 (family trait).
  No other 32-bit Borland C++ (4.5/5.0) was probed.

## Version deltas

- Not verified vs other bcc32 versions (4.5/5.0 floppies exist but
  were not compiled for this reference).

## Probe12: static-helper inlining — verified negative

bcc32 5.5 does NOT inline the probe12 static helpers: the -O1 object
keeps 4 `call`s in 119B of code, the -O2 object 4 `call`s in 128B —
the same keep-the-call behavior as MSVC 2.0–6.0.  Verified in a
probe12 re-run via `rebrew/borland:5.5-win32` (`out12/bcc55*`).

## Probe13: string intrinsics + bitfields — verified negatives

- **strlen/memcmp/strcmp are libcalls** (stack-arg `e8` calls), never
  inlined — the MSVC `repne scasb`/`repe cmpsb` intrinsic forms have
  no bcc32 counterpart.
- **bitfield loads via non-movzx byte/word loads** — `bf_get` reads
  fields with `8a 50 01` (mov dl,[eax+1]) and `66 8b 40 02` (mov
  ax,[eax+2]) — the 8a/66-8b forms, distinct from MSVC/GCC `movzx`
  and Watcom's shift/mask.
- **`unsigned char` sums use `xor eax,eax; mov al`** — shared with
  MSVC 2.0/4.x (vs 5.0/6.0 `and eax,0xff`, 7.0+ `movzx`).
- **8-byte struct returns round-trip the stack** (`83 c4 f8` + field
  stores) — bcc32's own encoding of the 2.0/4.x-style round-trip.
- `char` is signed (`c_cmp`: `cmp byte ptr [ebp+8],0; jge`).

## Probe14: statement idioms — verified

- **`g_counter++` increments the global IN MEMORY** — `inc dword ptr
  [g]` (`ff 05 00 00 00`) at -O2 — the ONLY probed 32-bit toolchain
  that does so (MSVC/GCC/Watcom/Zig round-trip through EAX).
- **64-bit `× 7` calls `__llmul`** (`6a 00 6a 07 8b 45 08 8b 55 0c
  e8`) — the Borland helper (MSVC 5.0–9.0 uses `__allmul`); 64-bit
  shifts inline `shld` like MSVC 7.0+/GCC.
- **64-byte memcpy is a libcall** (`6a 40 … e8`) — never `rep
  movsd`.
- **zero-compare** — `cmp dword ptr [ebp+8],0` + `setz` + `and
  eax,1` (immediate compare, distinct from MSVC's zero-register
  form).

## Probe15: function boundaries — verified

- **setcc = compare + `setcc` + `and eax,1`** — `a < b` = `mov
  eax,[ebp+8]; cmp eax,[ebp+0xc]; setl al; and eax,1` — the
  `0f 9c c0 83 e0 01` tail (distinct from MSVC/GCC's `setcc` +
  movzx/zero-extend forms).
- **wide compare via memory-immediate** — `wchar >= 0x100` = `cmp
  word ptr [ebp+8],0x100` + `setae` + `and eax,1` (the `66 81 7d 08`
  form, shared with MSVC 2.0–8.0's `66 81 7c 24 04`).
- **wide-literal sums load from memory** — `L"AB"` = `movzx`-word
  loads + add — NOT folded (MSVC 7.0+/GCC/Zig fold).
- **no stack cookies** — the buffer-copy function opens a plain
  frame; no `/GS`-style cookie (MSVC 8.0+ unique).

## Probe16: 64-bit division + C++ — verified

- **64-bit division calls `__lldiv`/`__llmod`** — the Borland helper
  pair (vs MSVC `__alldiv`/`__allrem`); probe16 compiles cleanly at
  -O2.
- **C++ mode compiles cleanly** — the probe16.cpp class + vtable +
  `new`/`delete` build succeeds; the visible vtable dispatch pushes
  register-loaded args (ebp-frame), a similar shape to MSVC 5.0/6.0
  (the C++ OMF object resists symbol extraction via the standard
  path — recorded).

- **Corpus pointer** — machine-checked in `corpus.json` (7892 records; the mechanical sweep confirmed this file's records and surfaced no un-documented markers here).

## Probe17: conventions + allocator behaviors

- **Probe17 verified-negative**: the convention markers (A5 promotion, register forms) hold for bcc32's shared conventions — no new bcc32 marker; corpus pointer.

- **Decomp idioms** — the probe19-28 game-idiom signatures for this toolchain are in [DECOMP_IDIOMS.md](../DECOMP_IDIOMS.md) and the corpus (`probe19`-`probe28` records).

## Probe22: guild-rule verification (round 19)

- **Probe22 (bcc32)**: compiles the string.h shapes (its wrapper sets INCLUDE); object folded (raw fallback — OMF resists symbol listing).  See RULES.md J3/E8.


## Probe23: Findings 23-36 shapes (round 20)

- **Probe23 (bcc32)**: compiled; object folded (raw fallback).  See RULES.md E8.


## Probe24: Findings 37-43 primitives (round 21)

- **Probe24 (bcc32)**: compiled; object folded (raw fallback).  See RULES.md E8.


## Probe25: Finding 44 primitives (round 22)

- **Probe25 (bcc32)**: compiled; object folded (raw fallback).  See RULES.md E8.


## Probe26: Finding 45 early-return placement (round 23)

- **Probe26 (bcc32)**: compiled; object folded (raw fallback).  See RULES.md E8.


## Probe27: Findings 46-50 primitives (round 24)

- **Probe27 (bcc32)**: compiled; object folded (raw fallback).  See RULES.md E8.


## Probe28: decompedia/CODEGEN_PATTERNS claims (round 25)

- **Probe28 (bcc32)**: compiled; object folded (raw fallback).  See RULES.md E8.


## Verification

Probe `-O1` and `-O2` via `rebrew/borland:5.5-win32` (`probe.obj`,
`out3/bcc55/probe3.obj`, `out3/bcc55o2/probe3.obj`); disassembly via
objconv.  Division: real `div`/`idiv` in every function of both opt
levels; `__llmul`/`__lldiv`/`__llshl` calls in the 64-bit functions;
`fld tbyte` in `ldadd`; 18× `55 8b ec` frames.
