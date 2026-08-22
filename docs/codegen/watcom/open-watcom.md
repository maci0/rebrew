# Open Watcom — codegen patterns

Open Watcom 2.0 (and the commercial Watcom C/C++ line): `wcc` (16-bit
DOS) and `wcc386` (32-bit).  The only family here with native Linux
binaries.  Verified with **wcc386 `-otexan`** and the `tg_watcom.o`
fixture.

**Profiles:** `watcom` (wcc386, 32-bit), `watcom16` (wcc, 16-bit DOS).

## Prologue & frame pointer

- **No frame pointer in leaf functions** — the prologue is the
  register-save block, no `push ebp`.
- **Saves caller-saved registers in the prologue** — the unique
  Watcom trait: whatever the body clobbers gets pushed up front,
  including **`push ecx; push edx` (`51 52`)** and `push ebx` (`53`)
  — MSVC/Borland/GCC never save ECX/EDX (caller-saved in their
  ABIs).  `div` helper: `push ecx; push edx; mov ecx,3; xor edx,edx;
  div ecx; pop edx; pop ecx`.

## Argument passing & register convention

- **Register convention**: the first args arrive in `eax/edx` (and
  `ebx/ecx`), not on the stack — `loop_const_store` starts
  `push ebx; push ecx; mov ebx,eax; mov ecx,edx`.
- **`ret N` callee cleanup for FP-arg functions** — the unique
  Watcom trait: `double fdiv(double)` ends `ret 8` (`c2 08 00`),
  `float fmul3(float)` ends `ret 4` (`c2 04 00`) — the callee pops
  its own args, where MSVC cdecl emits plain `ret` and leaves cleanup
  to the caller.

## Integer division

- **Real `div`/`idiv` even at `-otexan`** — `push ecx; push edx; mov
  ecx,3; xor edx,edx; div ecx` for `x/3u`.  Verified across the full
  13-divisor probe3 table (`u2`…`u100000`, `s2`…`s100000`, big
  constants) — **no magic constants at any tested optimization
  level**.

## 64-bit arithmetic

- **Watcom's own helpers via tail-jump/call**: `i64mul_` →
  `jmp __I8M`, `i64div_` → `jmp __I8D`, `i64shl_` → `call __I8LS` —
  vs MSVC's `__allmul`/`__alldiv`/`__allshl`, Borland's
  `__llmul`/`__lldiv`/`__llshl`, GCC's inline mul + `__divdi3`.
  The `__I8*` symbol is a clean Watcom marker.

## FPU

- x87; FP constants from `CONST`/`CONST2` (`fmul dword ptr [?_019]`);
  `a/10.0` → `fmul` by the reciprocal constant (like MSVC).
- **`long double` is 64-bit** — `ldadd` loads `fld qword ptr [esp+4]`
  and cleans `ret 16` (2×8-byte args) — shared with MSVC, distinct
  from GCC/Borland's 80-bit `fld tbyte`.

## Stack probes

- **`__CHK` with the amount pushed on the stack**: `push 4; call
  __CHK` (fixture `tg_watcom.o`) — distinct from MSVC `__chkstk`
  (size in EAX), MinGW `___chkstk_ms`, MSVC16 `__aNchkstk` (size in
  AX).  The `__CHK` symbol appears in Watcom OMF.
- Large frames may skip the probe entirely (`sub esp,6000` directly
  in the probe's `bigstack`).

## Padding

- **`ALIGN 8` between functions** — Watcom aligns function
  boundaries to 8 bytes.

## 16-bit `wcc`

- Same convention traits at 16-bit width (register args in
  `ax/dx/bx/cx`, `ret N` cleanup, `__CHK` probing); 8086 instruction
  set; OMF objects.  Probe12 (native `wcc` 2.0) verified two 16-bit
  specifics:
  - **Switch dispatch** — an 8-case `switch` compiles to `cmp ax,7;
    ja; mov bx,ax; shl bx,1; jmp word ptr cs:[bx]` + `dw` entries —
    the `shl bx,1` (`d1 e3`) scaling, shared with TC (MSVC 1.52 alone
    uses `add ax,ax; xchg bx,ax`).  Verified in `sw16`.
  - **Division** — real `xor dx,dx; div bx` (unsigned) / `cdq; idiv
    bx` (signed), and **no reciprocal-magic for constant divisors**
    (`a/7` loads `mov bx,7; cdq; idiv bx`) — mirroring the 32-bit
    wcc386 no-magic behavior.  Verified in `div16`.

## 100% unique to this version (family level)

- **`ret N` callee cleanup** (`c2 04 00`/`c2 08 00`) — verified:
  no other compiler in this set cleans FP args in the callee.
- **`push ecx; push edx` prologue saves** (`51 52`) — verified:
  absent in every MSVC/Borland/GCC object probed.
- **`__CHK` stack probe** — verified in the OMF fixture.
- **`__I8M`/`__I8D`/`__I8LS` 64-bit helpers** — verified in probe3.
- **`__CHP` FP-conversion helper** — `(int)a` compiles to `fld; call
  __CHP; add esp,4` — the x87 "change precision" helper; distinct
  from `__ftol` (MSVC+Borland), the `fnstcw` dance (GCC) and
  `cvttsd2si` (VC 11.0).  Verified in probe4 (`d2i_`).
- **`-otexan` ≡ `-oneatx`** (verified negative: identical probe3
  output under both optimization strategies).
- **16-bit `wcc` probed** (first data): `u3_` → `push bx; push dx;
  div bx; ret` — the register-save-before-div pattern (saving the
  clobbered caller-saved regs) at 16-bit width, same family trait as
  wcc386's `push ecx; push edx`; real division, no magic constants.
- Not unique per Open Watcom *minor* (1.0 vs 2.0): only 2.0 was
  probed; the commercial-line output was not reproduced.

## Version deltas

- Not verified: no controlled compile of Open Watcom 1.0 or the
  commercial 9.x/10.x/11.x line for this reference; family traits
  above are 2.0-verified.

## Probe12: 16-bit switch — verified

The 16-bit `wcc` dispatches the 8-case probe12 `sw8` switch via
`cmp ax,7; ja; mov bx,ax; shl bx,1; jmp word ptr cs:[bx]` + `dw`
entries — the `shl bx,1` (`d1 e3`) scaling, same family trait as TC
(not MSVC 1.52's `add ax,ax; xchg bx,ax`).  Verified in probe12
(`out12/watcom16/sw16.obj`, native `wcc`).

## Verification

Probe via `rebrew/watcom:2.0-win32` (wcc386 entrypoint) `-fo=` `-zq`
`-otexan` / `-oneatx` (`watcom_O1.o`, `out3/watcomotexan.o`,
`out3/watcomoneatx.o` — byte-identical); probe3 (`out3/watcomotexan.o`)
for the 13-divisor table, `__I8*` helpers and `ldadd`; probe4
(`out4/watcom.o`) for the `__CHP` FP-conversion helper; **16-bit `wcc`
probed via the image's `/opt/watcom/binl/wcc`** (`out4/wcc16_p3.o` —
`push bx; push dx; div bx` saves); fixture `tests/fixtures/tg_watcom.o`
(`push 4; call __CHK`).  Disassembly via
objconv (OMF-386).
