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
- **`-1` (8086) vs `-2` (80286) codegen: byte-identical** — verified
  negative on the probe3 function set (Turbo C++ 3.1's 8086/80286
  instruction-selection flags change nothing for the tested code).
- The frame-pointer-always + `pop bp; ret` (no `leave`) combination
  is Borland-16-bit-unique vs MSVC 1.5x within this set (see
  [msvc-1.md](../msvc/msvc-1.md) for the other half).

## Version deltas

- 2.0 → 3.1: the register-strategy / test-idiom / jump-table / div-
  helper differences above (probe3-verified).  Probe1's simpler set
  showed no difference — the two share the base 16-bit idioms
  (frame, `div bx`, `fwait` FPU).

## Probe12: 16-bit switch — verified

Probe12 (`sw8`) re-confirms the jump-table form for TC 3.1: `shl bx,1`
(`d1 e3`) + `jmp word ptr cs:[table+bx]`, in the position where MSVC
1.52 emits `add ax,ax; xchg bx,ax` instead.  The `shl`-scaling idiom
is the TC/Watcom-16 family trait; the `xchg bx,ax` idiom is
MSVC-1.5x-specific (see README).

## Probe13: 16-bit char/bitfield forms — verified (TC 3.1)

- **`char * 7` = `cwde` + `imul dx`** — `mov al,[bp+4]; cwde; mov
  dx,7; imul dx` (the 16-bit `imul dx`), vs Watcom16's `shl ax,3;
  sub ax,dx` and MSVC 1.52's plain word ops.
- **zero-extension via `mov ah,0` / `mov dh,0`** — no `movzx` on the
  8086 line (`uc_add`: `mov al,[bp+4]; mov ah,0; mov dl,[bp+6]; mov
  dh,0; add ax,dx`).
- **byte-in-memory compares** — `c_cmp` = `cmp byte ptr [bp+4],0;
  jge` (signed), `uc_cmp` = `cmp byte ptr [bp+4],0xc8; jbe`
  (unsigned) — char is SIGNED (unlike Watcom16's fold).
- **bitfield set = byte RMW** — `bf_set` clears/ors fields with
  `and byte ptr [si],0xf8; or byte ptr [si],al` (byte-level
  read-modify-write).

## Probe14: statement idioms — verified (TC 3.1)

- **`g += 7` adds in memory** — `add word ptr [g],7; mov ax,[g]`
  (memory-operand add), the 16-bit analog of bcc32's memory-inc
  form; MSVC 1.52 round-trips AX.
- **`a == 0` compares against 0 with branches** — `cmp word ptr
  [bp+4],0; jne; mov ax,1; jmp; xor ax,ax` (vs MSVC 1.52's
  compare-against-1 + sbb idiom).
- **ternary `a ? 7 : 13` uses branches** — `cmp [bp+4],0; je; mov
  ax,7; jmp; mov ax,0xd` (no cmov/sbb trick).
- **64-byte memcpy is a libcall** — `mov ax,0x40; push ax; push
  [bp+6]; push [bp+4]; call` (3-arg near call).

## Probe15: 16-bit compares + address forms — verified (TC 3.1)

- **setcc compares the second operand in memory + branches** —
  `a < b` = `mov ax,[bp+4]; cmp ax,[bp+6]; jge; mov ax,1` (signed
  `jge`, unsigned `jae`, wide-eq `jne`) — the branch form.
- **wide-literal sums load from memory** — `L"AB"` = `mov si,0; mov
  ax,[si]; add ax,[si+2]` (reloc'd absolute) — NOT folded.
- **16-bit address form** — `p[i*4+3]` = `shl ax,1; shl ax,1; add
  ax,3; shl ax,1` — the shl-chain + add + shl (no lea-scale).
- **no stack cookies** — plain frame + `sub sp,0x40` + `push si/di`.

## Probe16: TC 2.0 depth — verified

- **TC 2.0 `char * 7` = `cwde` + UNSIGNED `mul dx`** where TC 3.1
  uses `imul dx` — a verified 2.0-vs-3.1 discriminator for the same
  source (`mov al,[bp+4]; cwde; mov dx,7; mul dx` vs `imul dx`).
- **TC 2.0 keeps the loop pointer IN MEMORY** — `str_len_manual`
  increments `word ptr [bp+4]` (the pointer on the stack) where TC
  3.1 holds it in SI (`inc si`) — memory-held vs register-held
  induction.
- **TC 2.0 preprocessor quirk: no `defined()` in `#if`** — `#if
  defined(...)` fails with "Illegal character '#'" / "Expression
  syntax" (numeric `#if 1` works); probe13 (guard-free) compiles but
  probe14/15 (`#if defined(...)` guards) do not — the probe13 idiom
  set is the TC 2.0 comparison surface.

- **Corpus pointer** — machine-checked in `corpus.json` (7892 records; the mechanical sweep confirmed this file's records and surfaced no un-documented markers here).

## Verification

Probes via `rebrew/borland:{3.1,2.0}-win16` — probe1 (`-O1`:
`probe.OBJ`, `tc20/probe.OBJ`) and probe3 (default flags, `#`-free
source: `out3/tc31/probe3_notc.OBJ`, `out3/tc20/probe3_notc.OBJ`; TC
3.1 also at `-O2`), disassembled with objconv and diffed
instruction-by-instruction; census compared against the MSVC 1.52
probe (`leave` counts: 0 vs 25).
