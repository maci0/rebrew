# Turbo C / Turbo C++ — codegen patterns

Turbo C 2.0 (1988) and Turbo C++ 3.1 (1992) — 16-bit DOS compilers
(`TCC.EXE` under DOSBox); the classic DOS-game compilers.

**Profiles:** `tc16` (3.1), `tc20` (2.0) — images
`rebrew/borland:{3.1,2.0}-win16` (tcc wrapper).

**Toolchain caveat:** the tc20 image's wrapper runs `TCC.EXE` without
`PATH=C:\BIN`, so the preprocessor `CPP.EXE` is never found and **any
source containing `#` fails** ("Illegal character '#'") — a packaging
bug in the rebrew-toolchains wrapper, not the compiler.  Probe3 for
tc20 was compiled from a pre-resolved `#`-free source variant; real
tc20 use needs the wrapper fixed first.

## Prologue & frame pointer

- **Frame pointer ALWAYS**: `push bp` (`55`) `mov bp,sp` (`8b ec`) at
  every function, args at `[bp+4h]` (`8b 46 04`) — the shared
  Borland-16-bit style (also bcc32's 32-bit style).

## Epilogue

- **`pop bp; ret`** — never `leave` (`c9`).  Verified: zero `leave`s
  in both probes, 25 in the MSVC 1.52 probe.  The `leave` *absence*
  is the Borland-16-bit half of the discriminator (the positive half
  is MSVC's `leave`).

## Register conventions

- 16-bit registers; **divisor loaded into BX** for division:
  `mov ax,[bp+4]; mov bx,3; xor dx,dx; div bx` — identical register
  choice to MSVC 1.52 (also `div bx`), so register choice does NOT
  separate the two 16-bit lines.
- `si/di` for pointer temps (`mov si,[bp+4]` in `csum`), `xor di,di`
  counters.

## Integer division

- Real `div`/`idiv` (`div bx`, divisor in BX); signed `cwd; idiv bx`.
  No magic constants.

## FPU

- x87 with **`fwait` (`9b`) before each FPU op** (`fwait; fld qword
  [bp+4]; fwait; fadd …`) — shared with MSVC 1.52 (both 8087-era);
  not a discriminator between the 16-bit lines.

## Loops / Switch

- `dec`/`jnz`-style loops at `-O1` — **no `loop` instruction in the
  probe** (the `loop`-mnemonic heuristic is NOT reliable for TCC at
  -O1).  Jump tables emitted as `dw` word arrays.

## Stack probes

- None observed for the probe's 6 KB frame (`sub sp,6000` style
  allocation; no `__CHK`/`__chkstk` call).  Not further verified.

## Memory model / OMF

- Borland-dialect 16-bit OMF; `DGROUP _DATA/_BSS`; `FIDRQQ` FPU init
  extern.  Objects parse via rebrew's OMF path.

## 100% unique to this version

- **None proven per minor**, but the two ARE codegen-distinguishable
  (probe3, same `#`-free source at default flags — earlier probe1
  finding of "identical" was limited to its simpler function set):
  - **Register strategy** — TC 3.1 loads operands into `si`/`di` and
    pushes both for simple functions (`mmax`/`mmin`: `push si; push
    di; mov si,[bp+4]; mov di,[bp+6]`); TC 2.0 uses the memory
    operands directly (`cmp ax,[bp+6]`).
  - **Test idiom** — TC 2.0 tests with a memory-immediate compare
    `cmp word ptr [bp+4],0` (`83 7e 04 00`); TC 3.1 loads then
    `or si,si` (`0b f6`).
  - **Jump tables** — TC 2.0 emits `mov bx,ax; shl bx,1; jmp word
    ptr cs:[table+bx]` with the table as `dw` entries and separate
    case bodies; TC 3.1 folds the `mov bx` away and packs the cases
    tighter (verified in `sws`: 25 vs 18 instructions).
  - **32-bit division** (`unsigned`/`long` in 16-bit mode) — both call
    library helpers, but with different argument setup and helper
    names (TC 3.1: `call N_LUDIV@`/`N_LDIV@` with the dividend pushed
    from `[bp+4]`; TC 2.0: `mov dx,1; mov ax,<seg>; push dx` style).
  These are function-shape differences, not standalone byte markers —
  treat them as "verified TC 2.0 vs 3.1 discriminators when the same
  function shape is present", not as raw-byte signatures.
- **32-bit `long` multiply helper: far vs near** — `long` (32-bit) `*`
  in 16-bit mode calls a library helper: TC 2.0 emits
  `call far ptr LXMUL@`, TC 3.1 emits `call N_LXMUL@` (near) with a
  different argument-setup order.  Verified in probe6 (`lmul`).  The
  `LXMUL@` vs `N_LXMUL@` symbol is a clean 2.0-vs-3.1 marker.  (32-bit
  `long` add/sub are inlined by both as `add; adc` — identical.)
  MSVC 1.52 calls its own long-op helpers (push-args + call) instead
  of inlining.
- The frame-pointer-always + `pop bp; ret` (no `leave`) combination
  is Borland-16-bit-unique vs MSVC 1.5x within this set (see
  [msvc-1.md](../msvc/msvc-1.md) for the other half).

## Version deltas

- 2.0 → 3.1: the register-strategy / test-idiom / jump-table / div-
  helper differences above (probe3-verified).  Probe1's simpler set
  showed no difference — the two share the base 16-bit idioms
  (frame, `div bx`, `fwait` FPU).

## Verification

Probes via `rebrew/borland:{3.1,2.0}-win16` — probe1 (`-O1`:
`probe.OBJ`, `tc20/probe.OBJ`) and probe3 (default flags, `#`-free
source: `out3/tc31/probe3_notc.OBJ`, `out3/tc20/probe3_notc.OBJ`; TC
3.1 also at `-O2`), disassembled with objconv and diffed
instruction-by-instruction; census compared against the MSVC 1.52
probe (`leave` counts: 0 vs 25).
