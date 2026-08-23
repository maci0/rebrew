# MSVC 7.0 — codegen patterns

MSVC 7.0 (VS .NET 2002, CL 13.00.9466).  The first compiler to emit
**`lea esp,[esp]` loop-alignment nops inside function bodies**, and the
first to post-shift division magic.

**Profiles:** `msvc700`, `msvc700sp1` — Rich builds 9466 (RTM), 9955
(SP1); linker 7.0.

## Prologue & frame pointer

- `/O2`: no frame pointer, args `[esp+4]`+ — as before.
- Unoptimized: `55 8b ec`.

## Argument passing

- Direct `[esp+N]` loads; same /O1//O2 wrapper styles as 6.0.

## Register conventions

- Callee-saved `ebx/esi/edi`.
- **Unsigned char sum switches to `movzx`**: `movzx edi, byte ptr
  [ecx+esi]` (`0f b6 3c 31`) where VC 5.0/6.0 emit `mov dl,[mem]; add
  eax,edx`.  Verified in `bsum` (32B vs 33B in 6.0).

## Integer division

- **Magic + post-shift**: `x/3u` → `mov eax,0xAAAAAAAB; mul [esp+4];
  shr edx,1; mov eax,edx`.  `x/10u` → `shr edx,3`, `x/100u` → `shr
  edx,5`.  The `shr edx,N` tail is the **7.0+ marker** (5.0/6.0 take
  `mov eax,edx` directly).

## FPU / SSE

- Pure x87 (`fld`/`fadd`, `.rdata` constants) — SSE2 default arrives in
  VC 11.0.

## Loops

- **`lea esp,[esp]` (`8d 64 24 00`) as loop-alignment nop inside
  function bodies** — verified in `bigstack` and `csum` (2–3 per
  optimized probe function).  Zero occurrences in VC 2.0–6.0 probes;
  this is the clean "VC 7.0+ codegen" marker (the 7.0 probe's nop
  register is `esp`; VC 9.0 uses `lea ebx,[ebx]` in places — the
  alignment-nop *register* varies by version).
- `dec/jnz` induction, `rep stosd` memset inlining — unchanged.

## String ops

- `rep stosd`/`rep movsd` inlining unchanged.

## Padding & nops

- Adds the intra-body `8d 64 24 00`; still uses `90`/`8b ff`/`8d 74 26
  00`-style inter-function padding.  `mov edi,edi` (`8b ff`) as a 2-byte
  pad appears in 7.0+ objects too — not a 7.0-exclusive marker.

## Stack probes

- `mov eax,<size>; call __chkstk` — unchanged.

## Switch dispatch

- Dense jump table, unchanged.

## Optimization fingerprints

- Same wrapper styles.  `csum` (char scan) shows the loop head aligned
  with `8d 64 24 00` at /O2.

## 100% unique to this version

- **None proven per minor** (7.0 vs 7.1 remain codegen-indistinguishable
  in probe1 and probe2 — same object sizes, same nops, same tails).
- **Shared with 7.1+ (era markers, first appearance in 7.0):**
  - `lea esp,[esp]` (`8d 64 24 00`) loop-alignment nops inside function
    bodies — zero in every VC ≤6.0 probe;
  - the division tails: unsigned `shr edx,N; mov eax,edx` (`c1 ea N 8b
    c2`) and signed `sar edx,N; mov eax,edx; shr eax,31; add eax,edx`
    (`c1 fa N 8b c2 c1 e8 1f 03 c2`) — 5.0/6.0 shift the *low* register
    instead (see [msvc-5.md](msvc-5.md));
  - `movzx` for unsigned char loads (5.0/6.0 use `mov dl;add`).
  - **`imul` for constant multiply** — `x*100` → `imul eax,eax,100`
    (`6b c0 64`) and `x*1000` → `imul eax,eax,1000` (`69 c0 e8 03 00
    00`) — VC 5.0/6.0 build these from `lea`×5 chains, VC 2.0/4.x use
    a different lea order.  Verified in probe4 (`m100`/`m1000`).
  - **strcmp → tail `jmp strcmp`** — `strcmp(a,b)` compiles to a bare
    `jmp strcmp` (`e9` reloc) from VC 7.0 on; VC 2.0–6.0 push the args
    and `call` + clean up.  Verified in probe4 (`strc`).
  - **tail call `jmp g`** — `return g(x)` compiles to a bare `jmp g`
    (`e9` reloc) from VC 7.0 on (VC 2.0–6.0: `call g; add esp,4; ret`;
    bcc32 also does not tail-call; GCC and Watcom do).  Verified in
    probe5 (`tc`).
  - **`__fastcall` register fusion** — `__fastcall` args `ecx`/`edx`
    fuse via `lea eax,[ecx+edx]` (`8d 04 11`) from VC 7.0 on (VC
    2.0–6.0: `mov eax,[esp+4]` first).  Verified in probe5 (`fc1`).
  - **FP-loop unrolling ×4** — FP accumulation loops peel 4 iterations
    (`cmp esi,4; jl`) from VC 7.0 on; VC 5.0/6.0 keep the tight x87
    loop in st0, VC 2.0/4.x keep the accumulator in memory.  Verified
    in probe8 (`fs1`/`fs2`).
  - **combined divmod** — `x/N + x%N` compiles to a SINGLE division
    (`idiv ecx; add eax,edx` / `div` + remainder arithmetic) from VC
    7.0 on; VC 2.0–6.0 emit TWO separate divisions.  Verified in
    probe9 (`dm3`/`udm3`); the magic-based forms of 8.0+ derive the
    remainder from the quotient.
  - **64-bit compares: direct memory operands** — `__int64` `<`/`==`/
    `!=`/`>=` compare the high and low dwords directly against
    memory (`3b 44 24 10 … 3b 4c 24 0c`, 31B) from VC 7.0 on; VC
    5.0/6.0 load both operands into registers first (35B); VC 4.1
    uses `39 44`-forms.  Verified in probe10 (`i64lt/eq/ne/ge`).
  - **FP libcall args: `fstp`-temp vs `push`-pair** — `floor(a)`/
    `ceil(a)` pass the double via `fld; fstp [esp]` in 7.0 RTM and via
    `push`-pair in 7.0 SP1 (marshalling change).
  - **indirect tail call `jmp [mem]`** — `(*fp)(x)` compiles to a
    bare `jmp [fp]` from VC 7.0 on (VC 2.0–6.0: `call [fp]; add
    esp,4; ret`).  Verified in probe8 (`indirect`).
  - **static-helper inlining at /O2** — small static helpers called
    once/twice/in a loop are inlined from VC 7.0 on (11–12B callers);
    VC 2.0–6.0 keep the call at both /O2 and /O1.  Verified in probe12
    (`f1`/`f2`/`fl`).
  - (Not unique: `imul eax,eax,7` for `x*7` — Watcom shares it; the
    `/O1` `lea eax,[eax+eax*2]` for `x*3` — GCC shares it.)
  Distinguish 7.0 from 7.1 via Rich build (9466/9955 = 7.0, 3077/6030
  = 7.1) and linker (7.0 vs 7.10).

## Service packs (probed for the first time)

- **VC 7.0 SP1 is the ONLY service pack with verified codegen
  differences — spanning TEN probe functions (EIGHTEEN functions
  total).**  (a) The `==`/`!=` FP
  family is structurally different: `fcmp2` (`a==b`), `fc5`
  (`a!=0.0`), `fc8` (`a!=b`), `fc9` (`a==0.0`) all switch from the
  two-load `fucompp` (`da e9`) to the single memory-operand
  `fcomp [mem]` (`dc 5c 24 0c`, 2 bytes shorter).  (b) The FP-loop
  functions `fs1`/`fs2`/`fs3`/`ff1` and the char-array `cb16` differ
  in register allocation (edx↔ecx swaps, same sizes) — scheduling
  fixes, not structural.  (c) The stack-probe functions
  `sp1024`…`sp8192` differ in scheduling/layout.  (d) The FP-libcall
  marshalling `fl`/`cl` and the probe10 64-bit `_cl`/`_fl` differ.
  (e) **probe14's `_s64_ret` (64-byte struct return) differs in stack
  offsets (`[esp+0x48]` vs `[esp+0x50]`, same size) — discovered by
  the mechanical corpus sweep, missed by the hand-analysis.**  The
  relational compares and everything else
  are unchanged.  Verified in probes 5/7/8 at both /O1 and /O2;
  the 18th function (`_s64_ret`) verified mechanically over the
  corpus (docs/codegen/corpus.json).
  The fucompp style is shared by 7.1 (RTM+SP1) and 10.0 (RTM+SP1);
  the fcomp style by 2.0–6.0, 8.0 and 9.0 — so the RTM↔SP1 flip is a
  genuine SP-level fingerprint: `da e9` = 7.0 RTM, `dc 5c 24 0c` =
  7.0 SP1.

## Version deltas

- From VC 6.0: `lea esp,[esp]` loop-alignment nops appear; division
  magic gains `shr edx,N`; unsigned char loads use `movzx`; `rep
  stosd`/wrappers unchanged.
- To VC 7.1: nothing verified in codegen.

## Probe13: string intrinsics — verified

- **strlen is inlined as a manual scan loop** at /O2 — `lea edx,[eax+1];
  mov cl,[eax]; inc eax; test cl,cl; jnz; sub eax,edx`
  (`8d 50 01 8a 08 40 84 c9 75 f9 2b c2`) — the 7.0+ form; the
  `repne scasb` intrinsic ends at 6.0.
- **memcmp(8B) keeps `repe cmpsb` (`f3 a6`)** at /O2 — 7.0/7.1 are
  the LAST versions with the rep-string form (8.0+ switch to a
  dword-compare loop).

## Probe14: statement idioms — verified

- **64-bit shifts inline `shld`/`shrd`** — `i64 << 4` = `shld
  edx,eax,4; shl eax,4` (`0f a4 c2 04 c1 e0 04`) — from 7.0 on
  (shared with GCC/bcc32/Zig; the 5.0/6.0 `jmp __allshl` tail-call
  is MSVC-unique to them).
- **64-byte memcpy = `rep movsd`** (`b9 10 00 00 00 f3 a5`), shared
  by every MSVC version.
- **zero-compare era** — `a == 0` = load + `test` + `setz` at /O2
  (5.0–7.1 form; 8.0+ compares in memory against the zero register).
- **`g_counter++`** round-trips EAX at /O2 (`a1 … 40 … a3`).

## Probe15: setcc + wide literals — verified

- **setcc loads BOTH operands** — `a < b` = register-form `cmp
  ecx,edx; setl al` (the 5.0–7.1 form; 8.0+ compare in memory).
- **wide-literal sums are CONSTANT-FOLDED from 7.0** — `L"AB"[0] +
  L"AB"[1]` compiles to `mov eax,0x83` (`b8 83 00 00 00`); VC 2.0–6.0
  (and bcc32/Watcom/TC) load the literal from memory.  Shared with
  GCC/Zig — family-level era marker.
- **stdcall args load in REVERSE order** — the 5.0–9.0 form.

## Probe16: 64-bit division + C++ — verified

- **64-bit division = register-load + 4-push helper call** — the
  5.0–10.0 form (`8b 44 24 10 … 51 52 50 e8`); /O1 uses the compact
  4× memory-push in every version.
- **C++ `new`/`delete` TAIL-JUMP from 7.0** — `new int` = `push 4;
  jmp <operator new>`-style and `delete` = `jmp <operator delete>`
  (the compiler reuses the incoming stack slot; 5.0/6.0 call + ret
  instead).  Vtable dispatch is uniform `mov eax,[ecx]; call [eax]`.

- **Corpus pointer** — machine-checked in `corpus.json` (7892 records; the mechanical sweep confirmed this file's records and surfaced no un-documented markers here).

## Probe17: conventions + allocator behaviors

- **Probe17 allocator/conventions**: `-1` register form (`83 c8 ff` + `a3`); zero in EAX; 7.0+ inline the 12-byte sret construction (direct register stores).  See RULES.md A8/B5.

- **Decomp idioms** — the probe19-22 game-idiom signatures for this toolchain are in [DECOMP_IDIOMS.md](../DECOMP_IDIOMS.md) and the corpus (`probe19`-`probe22` records).

## Probe22: guild-rule verification (round 19)

- **Probe22 (7.0)**: zero-extend becomes `movzx` in every form; C24 uses `sete`+`neg` (register compare); constant-memset 36B unrolls to dword stores — and **7.0 SP1 still emits `rep stosd`** (a J1 SP-difference).  See RULES.md C23/C24/E14/J1.


## Verification

Probe `/O1`/`/O2` via `rebrew/msvc:7.0-win32` (`msvc700_{O1,O2}.obj`);
smoke `msvc700/t.obj` and `msvc700sp1/t.obj`.  Census: `lea esp,[esp]`
= 3 at /O2 (0 for every VC ≤6.0 probe), `8b ff` = 2 (operand noise —
see [msvc-6.md](msvc-6.md) for the padding caveat).
