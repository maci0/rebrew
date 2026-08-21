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

## Verification

Probe `-O1` and `-O2` via `rebrew/borland:5.5-win32` (`probe.obj`,
`out3/bcc55/probe3.obj`, `out3/bcc55o2/probe3.obj`); disassembly via
objconv.  Division: real `div`/`idiv` in every function of both opt
levels; `__llmul`/`__lldiv`/`__llshl` calls in the 64-bit functions;
`fld tbyte` in `ldadd`; 18× `55 8b ec` frames.
