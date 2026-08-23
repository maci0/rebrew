# MSVC 1.x (16-bit) — codegen patterns

MSVC 1.0 / 1.5 / 1.52 (1992–1995, Windows 3.x / DOS).  16-bit
compilers; `CL.EXE` is a Phar Lap TNT DOS-extender binary run under
DOSBox.  Emits 16-bit OMF objects.

**Profiles:** `msvc1.52`, `msvc15`, `msvc10` — images
`rebrew/msvc:{1.52,1.5,1.0}-win16` (cl16 wrapper).

## Prologue & frame pointer

- **Frame pointer ALWAYS**: `push bp` (`55`) `mov bp,sp` (`8b ec`) at
  every function (verified 18× in the probe).
- Args at `[bp+4h]`/`[bp+6h]`: `mov ax, word ptr [bp+4h]`
  (`8b 46 04`).

## Epilogue — the `leave` marker

- **Ends with `leave` (`c9`) then `ret` (`c3`)** — verified 25× in the
  probe.  Turbo C 2.0/3.1 (the only other 16-bit C compiler in this
  set) never emits `leave` — it uses `pop bp; ret`.  This cleanly
  separates MSVC 16-bit from Borland 16-bit codegen.

## Register conventions

- 16-bit registers: `ax/bx/cx/dx`, `si/di` for pointer-ish temps,
  `bp` frame.
- Register saves: `push si` / `push di` after the frame setup
  (verified in the fixtures `tg_msvc16.obj`: `push bp; mov bp,sp; mov
  ax,0; call __aNchkstk; push si; push di`).
- `leave` restores `sp`/`bp` in one instruction — no `pop bp`.

## Integer division

- **Real `div`/`idiv`, divisor in BX**: `x/3u` → `mov ax,[bp+4]`
  (`8b 46 04`) · `mov bx,3` (`bb 03 00`) · `xor dx,dx` (`33 d2`) ·
  `div bx` (`f7 f3`).  Signed: `cwd` (`99`) + `idiv bx`.
- No magic constants (16-bit divide stays a real division).

## FPU

- x87 with **`fwait` (`9b`) interspersed before each FPU op**
  (`fwait; fld qword [bp+4]; fwait; fadd …`) — shared with Borland
  TCC (both target the 8087); not a discriminator between the two
  16-bit lines.
- **`long double` is 80-bit** — `fld tbyte` (`db 6e`, 4× in the
  probe3 object) — shared with the other 16-bit compilers (TC 2.0/3.1
  also emit `fld tbyte`), distinct from 32-bit MSVC (long double ==
  double, `fld qword`).

## Memory model

- **Far model** (large): `retf` (`cb`) and far calls `lcall`
  (`9a 00 00 00 00`); near model: `ret` (`c3`).  Verified in the
  fixtures: `tg_msvc16_far.obj` = `mov ax,[0]; retf` +
  `lcall 0,0; add ax,[0]; retf`.
- DGROUP segments `_DATA`, `CONST`, `_BSS` (MSVC dialect OMF).

## Stack probes

- **`__aNchkstk` with the size in AX**: `mov ax,<size>; call
  __aNchkstk` — the 16-bit analog of 32-bit `__chkstk` (EAX) and
  MinGW's `___chkstk_ms`.  The `__aNchkstk` symbol appears in OMF
  fixtures (`tg_msvc16.obj`) and objects.

## Loops / String ops / Switch

- `dec`/`jnz`-style induction; `cmp; je` chains; data tables via
  `dw`.  No `loop` instruction in the probe (same as TCC at -O1 — not
  a discriminator).

## 100% unique to this version

- **`leave` (`c9`) epilogues among the 16-bit compilers in this set.**
  Verified: 25 `leave`s in the MSVC 1.52 probe, 0 in the TC 2.0 and
  TC 3.1 probes (which use `pop bp; ret`).  Caveat: any 16-bit
  compiler *outside* this set could also use `leave` — "unique among
  rebrew's 16-bit toolchains".
- **`enter` (`c8`) frame setup** — MSVC 1.52 emits `enter N,0` for
  some functions (verified 1× in the probe3 object: `c8 02 00 00`);
  TC 2.0/3.1 (0×) and Delphi use `push bp; mov bp,sp` instead.
  Unique among the 16-bit compilers here.
- **switch dispatch via `xchg bx,ax` (`03 c0 93`)** — MSVC 1.52
  dispatches 8-case `switch` statements with `dec ax; cmp ax,7; ja;
  add ax,ax; xchg bx,ax; jmp word ptr cs:[table+bx]` + `dw` entries;
  TC 2.0/3.1 use `shl bx,1` (`e3`) in the same position instead.
  Verified in probe12 (`sw8`); the MSVC 1.0/1.5 line dispatches the
  same way (1.52 == 1.5 line for probe4).
- `__aNchkstk` stack-probe symbol is unique among the probed
  toolchains (32-bit MSVC uses `__chkstk`, MinGW `___chkstk_ms`,
  Watcom `__CHK`).

## Version deltas (1.0 vs 1.5 vs 1.52)

- **Verified identical for probe4** (the first time 1.0/1.5 were
  probed): all three produced the same 36 code records with identical
  counts (`enter`=2 — the struct-return functions use `enter 8,0` —
  `leave`=38).  The three are the same compiler line; no verified
  codegen separates them.  (The earlier "1.0/1.5 assumed same line"
  note is now probe-confirmed.)

## Probe13: 16-bit bitfields and char promotion — verified

- **Bitfield access via full-word loads + masks** — `bf_set` loads the
  field word (`mov dx,[bx]`), masks with `and ax,0xf8` / `and cx,7`,
  extracts the 8-bit field via `mov cl,ch; sub ch,ch` (high-byte load
  + self-subtract zero-extend), and `shr al,3` for the 5-bit field.
  Verified in probe13.
- **`char + char` = plain 16-bit word add** — `c_add` compiles to
  `mov ax,[bp+6]; add ax,[bp+4]; leave; ret` — NO sign-extension (a
  char fits a word in 16-bit); the second arg is loaded first, the
  same reverse-order quirk as 32-bit VC 2.0/4.x.

## Probe14: zero-compare idiom — verified

- **`a == 0` compiles to `cmp word ptr [bp+4],1; sbb ax,ax; neg ax`**
  — the compare-against-1 + sbb/neg idiom, the same family trait as
  32-bit VC 2.0/4.x (probe14 `zc_reg`; also `cmp word ptr [bp+4],1;
  sbb ax,ax; and ax,6; add ax,7` for `a ? 7 : 13`).

## Probe15: 16-bit compares — verified

- **signed/unsigned/wide compares use branch + `mov ax,1`** — `a < b`
  (signed) = `mov ax,[bp+4]; cmp word ptr [bp+6],ax; jle; mov ax,1`
  (the second operand compared in memory, branch form — the same
  branch-style as 32-bit VC 2.0/4.x setcc).  `u_lt` uses `jbe`,
  `w_eq` uses `jne`.

## Probe16: 16-bit depth — verified

- **The 1.x line is byte-identical on the probe13 idiom set** — MSVC
  1.0, 1.5 and 1.52 produce identical objects for every probe13
  function (`c_add`/`uc_add`/`c_mul`/`bf_get`/`str_len_manual`/
  `s8_make`), extending the earlier probe4 identicality note to the
  full round-11 idiom set.  No codegen separates 1.0/1.5/1.52.

- **Corpus pointer** — machine-checked in `corpus.json` (7892 records; the mechanical sweep confirmed this file's records and surfaced no un-documented markers here).

## Probe17: conventions + allocator behaviors

- **Probe17 conventions**: 16-bit struct-return (A8) — MSVC 1.52's `s12_caller`/`s12_make` decode partially in the /O1 object (recorded partial); `__fastcall` is absent from the 1.5x keyword set (same as TC).  See RULES.md A8.

- **Decomp idioms** — the probe19/20 game-idiom signatures for this toolchain are in [DECOMP_IDIOMS.md](DECOMP_IDIOMS.md) and the corpus (`probe19`/`probe20` records).

## Verification

Probe `/O1` via `rebrew/msvc:1.52-win16` (`out16/probe.OBJ` and the
probe3 `out16b/probe3.OBJ` — `enter`, `fld tbyte`, real `div`,
`leave; ret` — disassembled with capstone through
`rebrew.matcher.omf16`); fixtures `tests/fixtures/tg_msvc16.obj`,
`tg_msvc16_o1.obj`, `tg_msvc16_far.obj` (near/far models,
`__aNchkstk`).
