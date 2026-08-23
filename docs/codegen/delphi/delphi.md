# Delphi 1.0 — codegen patterns

Borland Delphi 1.0 (1995, `DCC.EXE`) — 16-bit Windows 3.x Pascal
compiler producing genuine NE 6.01 executables.  The toolchain has no
matchable profile (Delphi codegen cannot be reproduced from C for byte
matching — documented blocker), but the codegen itself is now **probe-
verified**: a Pascal probe (`probe.dpr`: `add`, `div3`, `fmul`, `fadd1`,
`loopy`, referenced from the program body so the linker retains them)
compiled with `DCC.EXE` through `rebrew/delphi:1.0-win16` and the NE
output disassembled.  Findings below are from that object unless marked.

**Profiles:** `delphi16` — image `rebrew/delphi:1.0-win16` (DCC
wrapper, DOSBox).

## Prologue & frame pointer — the stack-check call

Every function opens `push bp; mov bp,sp` (`55 89 e5`), then emits a
**stack-check far call**: `mov ax,<frame size>` (`b8 08 00`) + `lcall
<rtl>` (`9a ff ff 00 00`) — the Borland 16-bit stack-probe idiom via the
RTL (the size is the local frame the check must cover).  Locals then
allocate with `sub sp,N` (`83 ec 08`).  Args sit at `[bp+4]`/`[bp+6]`
(Integer is 16-bit in Delphi 1.0) — same frame shape as the 16-bit C
compilers.

## Epilogue — `leave; ret N`

Functions end **`leave` (`c9`) + `ret N` with callee stack cleanup**
(`c2 04 00` for two Integer args, `c2 02 00` for one, `c2 08 00` for a
Double).  Verified in every probe function — the near `ret N` callee-
cleanup is the distinctive Delphi trait (Watcom also cleans in the
callee, but with `ret N` *near* only for FP args; Delphi does it for
plain Integer args too).  RTL functions use far `retf`/`retf N` (`ca`).

## Integer division

- Real 16-bit `idiv`: `div3` → `mov ax,[bp+4]` · `cdq` (`99`) ·
  `mov cx,3` · `idiv cx` (`f7 f9`) — divisor in CX, real division,
  no magic constants (16-bit).

## FPU

- x87 with **`wait` (`9b`) before each FPU op** (`wait; fld qword
  [bp+0xc]; wait; fmul qword [bp+4]; wait; fstp qword [bp-8]`) — the
  same fwait-interspersed style as the 16-bit C compilers.
- Double args at `[bp+4]`/`[bp+0xc]`; results round-trip through a
  local temp slot (`fstp [bp-8]` then reload) — the Pascal result
  idiom.

## Result passing

- Function results go through a local temp slot: `add` does
  `mov [bp-2],ax; mov ax,[bp-2]` before `leave; ret 4` — the compiler
  materializes the result variable, reloads it, and returns in AX.
  `LongInt` (32-bit) results return in `dx:ax`.

## case / set / for / LongInt (probe2.dpr)

- **`case` = a linear compare chain, NOT a jump table** — `casesel`
  compiles to `cmp ax,N; jne next; mov [bp-2],result; jmp end` per
  case (verified for a 4-case statement).  Delphi 1.0 does not emit
  jump tables for `case` in the probe.
- **set membership `x in s`** — `setop` compiles to the classic
  Pascal set test: `mov cl,[bp+4]` (the element) · `cmp cl,0x10`
  (bound check vs the set range) · `jae` (out of range → false) ·
  `mov ax,1; rol ax,cl` (`d3 c0` — **the 16-bit `rol`**) · `test
  [bp+6],ax` (the set bitmask word) · `jne` → true.  The
  `rol`-based set bit is verified; TC/MSVC16 never emitted `rol` in
  any probe.
- **set/record copy via `rep movsw`** (probe3.dpr) — `setadd`'s
  4-byte `Set of 0..31` argument copy emits `cld` (`fc`) · `les di`
  · `lds si` · `mov cx,4` · `rep movsw` (`f3 a5`) — the Borland
  Pascal bulk-copy idiom for set/record values.
- **`for` loop** — `loopy2` (`for i := n downto 1`) keeps the
  counter in memory (`mov [bp-4],ax; dec word ptr [bp-4]; cmp word
  ptr [bp-4],1; jne`) — no register-held induction.
- **`LongInt` arithmetic** — `longadd` loads `ax:[bp+8]`/`dx:[bp+0xa]`
  and does `add ax,[bp+4]; adc dx,[bp+6]` — the 32-bit-in-16-bit
  `adc` idiom, result in `dx:ax`, `ret 8` (callee cleanup).

## probe3 leftovers: PChar walk and LongInt multiply

- **`pchar_len` (PChar walk)** — `les di,[bp+4]` · `cmp byte ptr
  es:[di],0` · `je` exit · `inc word ptr [bp+4]` (increments only the
  OFFSET word, no segment carry) · `jmp` loop; the char is tested via
  ES:DI, the counter in `[bp-4]`.  Ends `leave; ret 4`.  Verified in
  probe3.dpr (`probe3.EXE` seg0 @ 0x81).
- **`longmul` (LongInt multiply)** — a single **far call to the RTL
  helper**: `lcall 0,0xffff` (the `@LDmul` runtime entry), operands in
  register pairs `ax:dx` (a) and `cx:bx` (b), 32-bit result back in
  `ax:dx`, `leave; ret 8`.  NOT inlined — Delphi 1.0 delegates
  32×32→64 multiply to the RTL (contrast: `longadd` above is inlined
  as `add; adc`).  Verified in probe3.dpr (`probe3.EXE` seg0 @ 0xb6).

## RTL / startup (segment 1)

- The RTL contains the classic Borland 16-bit library code: memory
  manager walks, `int 0x21` DOS calls, string helpers using real
  **`loop`/`loope`** instructions (`e2 f4` at 0x5c9, `e1 f7` at 0x654)
  and `lodsb`/`scasb` string ops — `loop`-family usage is verified in
  Delphi RTL (and was NOT found in the TC probe bodies at -O1).

## Stack probes

- The **stack-check far call in the prologue** IS Delphi's stack
  mechanism: every function opens `mov ax,<frame size>` (`b8 08 00`)
  + `lcall <rtl>` (`9a ff ff 00 00`) — the Borland 16-bit probe via
  the RTL, sized to the local frame.  Distinct from Watcom's
  `push N; call __CHK`, MSVC 1.5x's `mov ax,N; call __aNchkstk`
  (near call) and MinGW's `___chkstk_ms`.

## 100% unique to this version

- **Stack-check far call in the prologue** — `b8 <size>; 9a` (`mov ax,
  N; lcall`) in EVERY user function — verified in all five probe
  functions.  Distinct from Watcom's `push N; call __CHK` and MSVC
  1.5x's `mov ax,N; call __aNchkstk` (near call, no lcall).
- **`leave; ret N` callee cleanup for Integer args** — verified
  (`c9 c2 04 00` / `c9 c2 02 00`).  Among the 16-bit compilers here,
  only Delphi cleans Integer-arg stacks in the callee with `ret N`
  (TC 2.0/3.1 and MSVC 1.5x use plain `ret` for cdecl-like calls;
  MSVC 1.5x uses `leave` but plain `ret`).
- `fwait` FPU style is shared with TC/MSVC16 — NOT a marker.

## Version deltas

- Not applicable (single preserved version; Delphi 2+ is 32-bit and
  out of scope).

## probe13.dpr: packed records + Char — verified

- **packed-record fields = individual byte loads** — `bf_get` reads
  `p^.c`/`p^.b`/`p^.a` as `mov al, byte ptr es:[di+2]` /
  `es:[di+1]` / `es:[di]` with `xor ah,ah` zero-extension, then adds
  — no masking, no shifts (no range-checking codegen by default).
  Verified in probe13.dpr (`probe13.EXE` seg0 @ 0x2).
- **`Char < #0` is NOT constant-folded** — `c_cmp` keeps a runtime
  `cmp byte ptr [bp+4],0` (result 0/1 via the Pascal if/else shape),
  even though Char is unsigned — contrast with Watcom, which folds
  `char < 0` to 0 for its default-unsigned char.

## Probe14: statement idioms — not applicable (Pascal)

- probe14 is a C-statement probe; the Pascal equivalents of its
  dimensions were covered in probe2/3 (case chains, set membership,
  for-loop induction) and probe13.dpr (packed records, Char
  compare).  No new Delphi marker in this dimension — verified
  negative.

## Probe15: function boundaries — not applicable (Pascal)

- probe15's C-boundary dimensions (setcc census, wide-char literals,
  stdcall cleanup) have Pascal counterparts covered in probe2/3
  (`case` chains, `LongInt` results in dx:ax, `ret N` cleanup
  already documented) — no new marker; verified negative.

## Probe16: 64-bit division + C++ — not applicable (Pascal)

- Delphi 1.0 has no 64-bit integer type and no C++ mode; the probe16
  dimensions have no Pascal counterpart — verified negative.

- **Corpus pointer** — machine-checked in `corpus.json` (7892 records; the mechanical sweep confirmed this file's records and surfaced no un-documented markers here).

## Probe17: conventions + allocator behaviors

- **Probe17 verified-negative**: the C-convention triggers (fastcall, varargs) have no Delphi 1.0 Pascal counterpart — no new marker; corpus pointer.

- **Decomp idioms** — the probe19-22 game-idiom signatures for this toolchain are in [DECOMP_IDIOMS.md](../DECOMP_IDIOMS.md) and the corpus (`probe19`-`probe22` records).

## Probe22: guild-rule verification (round 19)

- **Probe22**: not applicable (Pascal — no probe22 source).


## Verification

Pascal probe `probe.dpr` compiled via `rebrew/delphi:1.0-win16`
(`probe.EXE`, NE 6.01, 3 segments: 330B code + 1740B RTL + 168B data),
disassembled with capstone (16-bit) through `rebrew.binary_loader`.
The five user functions were located by their `push bp; mov bp,sp`
prologues without the RTL's `push ds`; `begin..end` references retain
them (unreferenced functions are dead-stripped by the linker).
