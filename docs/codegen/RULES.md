# Codegen Rules Catalog

Categorized reference of **codegen rules** — behavior-level statements
about how each toolchain/version generates code.  Complements the
[uniqueness table](README.md) (byte markers), the per-toolchain files
(verified records), and [corpus.json](corpus.json) (machine-readable
bytes).  Where a rule is empirically verified, its probe and corpus
records are cited; where it is documented from an external source, the
source is cited and the verification status is marked.

## Status legend

- **V** — verified by rebrew probes (probe N, corpus records).
- **D** — documented, external source cited; not yet probe-verified here.
- **V+D** — both.
- **P** — partial / single-case verified, general rule not proven.

Sources: [Agner Fog, calling conventions manual](https://www.agner.org/optimize/calling_conventions.pdf)
(AF), [decomp.me compiler fleet](https://github.com/decompme/compilers)
(DM), [guild-rebrew msvc6-allocator.md](../../../guild-rebrew/docs/msvc6-allocator.md)
(GD), decomp.me's per-compiler practice docs (DP).

---

## A. Calling conventions & parameter passing

| ID | Rule | Scope | Status |
|----|------|-------|--------|
| A1 | 32-bit cdecl: args on stack, pushed right-to-left, caller cleans (`add esp,N`); callee-clean `ret N` for `__stdcall` | all 32-bit toolchains | V (probe16 `std_add`/`std_many`) |
| A2 | 16-bit `fastcall` register parameters: Microsoft `ax,dx,bx`; Borland `ax,dx,bx`; **Watcom `ax,dx,bx` (3 regs, 4th arg on the stack)** — AF table 5's "ax,dx,bx,cx (4 regs)" is NOT reproduced by Open Watcom 2.0 `wcc` (may be commercial-10.x-specific); TC 2.0/3.1 and 16-bit MSVC 1.5x LACK the `__fastcall` keyword entirely | 16-bit MSVC/TC/Watcom | V (probe17; AF claim corrected) |
| A3 | 32-bit `__fastcall` register args `ecx,edx` (Microsoft-compatible); Borland/Watcom same for 2-arg | 32-bit toolchains | V (probe5 `fc1`-`fc3`) |
| A4 | Arg-load order in function bodies varies by version: VC 2.0/4.x load the SECOND arg first (`mov eax,[esp+8]; ...`) for 2-arg cdecl; 5.0–9.0 reverse for `__stdcall`; 2.0/4.1 + 11.0 direct | MSVC | V (probe13 `c_add`, probe15 `std_add`) |
| A5 | Varargs: `float` params promoted to `double` — verified in EVERY MSVC version: `fld [f]; sub esp,8; fstp qword [esp]` (`dd 1c 24`) for 2.0–10.0, **VC 11.0 uses SSE `movss; cvtss2sd; movsd [esp]`**; watcom16 also `fld; sub sp,8; fstp qword` | all C compilers | V (probe17 `va_promote`) |
| A6 | 8-byte (16-bit) / 16-byte (32-bit) struct returns in registers: `dx:ax` (16-bit), `edx:eax` (32-bit) from VC 5.0+ | MSVC 5.0+, GCC, Zig | V (probe13 `s8_make`) |
| A7 | Hidden-pointer struct returns: VC 2.0/4.x and bcc32 round-trip the struct through the stack; Watcom copies via `movsd` pairs | MSVC 2.0/4.x, bcc32, Watcom | V (probe13) |
| A8 | Struct-return pointer placement (AF table 7): **Watcom16 = PSI** (`lea si,[bp-6]` + `movsw` copy to the sret pointer in SI); **TC 3.1 = I** (far pointer pushed on the stack); 32-bit MSVC 2.0–6.0 pass the pointer on the stack, **7.0+ inline the sret construction** (direct register stores, SSE `movq` in 11.0) | 16-bit MSVC/TC/Watcom + 32-bit MSVC | V+D (probe17; AF table 7 confirmed for Watcom PSI + TC I) |
| A9 | Symbol decoration: `_func` cdecl, `_func@N` stdcall (32-bit); Borland C++ objects resist standard symbol extraction (mangled OMF) | MSVC, bcc32 | V (probe16 bcc55 object) |
| A10 | Name mangling schemes differ per compiler family: **Microsoft `?name@@Y...` verified** against the probe16 C++ objects (`??2@YAPAXI@Z` operator new, `??3@YAXPAX@Z` operator delete — matches AF §8.1); Borland `@name$q...` and Watcom schemes remain documented-only (their C++ OMF objects resist symbol extraction) | C++ mode | V+D (probe16 objects + AF §8) |

## B. Register allocation & assignment

| ID | Rule | Scope | Status |
|----|------|-------|--------|
| B1 | Register classes: 32-bit scratch `eax,ecx,edx`, callee-save `ebx,esi,edi,ebp`; 16-bit scratch `ax,bx,cx,dx,es`, callee-save `si,di,bp,ds` | all | V + D (AF table 4) |
| B2 | The "zero register": MSVC materializes `0` once and reuses it for compares/stores; anchored to EAX when the early `return 0` reuses it (`a3` moffs stores prove EAX residency).  **Per-version matrix (probe17 `alloc_zero`)**: VC 2.0/4.x materialize NO zero register (memory-immediate `cmp [mem],0`); VC 5.0–11.0 keep the zero in EAX with `a3` stores | MSVC | V+D (GD finding 1 + probe17 matrix) |
| B3 | **Live-range-across-loop flip**: one extra post-loop literal `return 0` with no intervening call makes MSVC merge return tails → callee-save pushed at entry, zero parked in ESI (`89 35` stores), far `je`.  **Per-version matrix (probe17 `alloc_flip`)**: the SIMPLIFIED trigger does NOT flip in any version (zero stays in EAX 5.0–11.0; 2.0/4.x use memory-immediate) — the guild doc's fuller dispatch shape is required to reproduce the flip; recorded negative for the simplified shape | VC 6.0 (full shape) | V+D (GD finding 2; simplified-trigger negative) |
| B4 | Flag variables assigned by dispatch order: first-tested flag → `dl`, second → `bl` (VC 6.0).  **Probe17 `alloc_flags`**: with `int` flags the dispatch-order structure is uniform across versions (all use mov-const flags); the `dl`/`bl` byte-flag form requires `char` flags — partial | VC 6.0 | P (GD finding 3; char-flag form not reproduced) |
| B5 | `-1` stores: **per-version split (probe17 `alloc_m1`)** — VC 2.0/4.x use the immediate `c7 05 ... ffffffff` (10B); **VC 5.0–10.0 use the register form `or eax,-1` (`83 c8 ff`) + `a3` store** when a volatile register is free; VC 11.0 emits the immediate store plus a dead `or eax,-1` | MSVC | V (probe17; extends GD finding 4) |
| B6 | Callee-save `esi` push/pop placement tracks the register's live range (pushed where first used, not necessarily at entry) | VC 6.0 | V+D (GD finding 5); probe17 `alloc_esi` trigger did not force a callee-save (negative) |
| B7 | An address-taken parameter kills the callee-save base register: **probe17 `alloc_addr` matrix** — VC 5.0–8.0 push ESI only; **VC 9.0/10.0 push ebx/ebp/esi/edi (four callee-saves)**; 16-bit Watcom parks the pointer in SI | MSVC/Watcom16 | V (probe17; extends GD finding 7) |
| B8 | Zeroing idiom: VC 2.0/4.x use `mov reg,0`; VC 5.0+ use `xor reg,reg` (mechanically re-derived from the corpus) | MSVC | V (corpus sweep) |
| B9 | Constant caching: VC 4.x/5.0 hoist loop-invariant constants into callee-saved registers; VC 6.0 does NOT (immediate stores stay in the loop) | MSVC 4.x–6.0 | V+D (GD baseline + probe docs) |
| B10 | VC 8.0 prefers `add reg,1`/`sub reg,1` (`83 c0 01`/`83 e8 01`) over `inc`/`dec` (`40`/`48`) — confirmed in strlen, `g_val+1`, `g_inc`/`g_dec`, `w_ge`, `/GS` copy loop (5 independent hits) | VC 8.0 | V (probe13/14/15); GCC shares the encoding (family-level) |
| B11 | **`a3`/`a1` moffs usage doubles from VC 8.0** — 15–16 moffs hits per version in 2.0–7.1 vs 24–25 in 8.0–11.0 across the whole corpus; the 8.0+ memory-centric codegen (memory compares, memory pushes) extends to EAX-absolute addressing | MSVC | V (corpus fingerprint sweep) |
| B12 | Dead-param-slot reuse: values hoisted into registers early leave their param slots dead; MSVC reuses them for spills — the wrong variable choice shifts every `[esp+N]` offset | VC 6.0 | D (GD `plt_SetPlantMap`, `amt_SwapOfficeHolders`) |
| B13 | Register-role lever (F12): whether a memory value lands in eax or ecx can depend on naming it as a local (distinct IR node at the assignment) vs reading memory directly (anonymous CSE'd load created at first use).  Steering: if a register role won't budge, delete the local / write the memory operand directly.  Allocator internals (reversed from c2.dll): priority = use_weight×loop_weight (6/use default), class-0xd nodes pinned to the priority-list tail, ascending list consumed head-first, equal-priority inserts before the equal group.  **probe22 `named_flags`/`direct_flags` verified-NEGATIVE for the simplified shape**: both land the flags in EAX (5.0/6.0), the role flip needs the fuller lb_SendLobbyConfig register-pressure shape; both shapes DO emit the AH-relative flag ops (`test ah,0x60` + `or ah,0x8`) — see F15 | VC 6.0 | V+D (GD finding 12; probe22 simplified negative) |
| B14 | Transient-register alternation (F20): consecutive global decrements alternate edx/ecx, the first transient reusing the just-freed block register — unsteerable (~185/188 match) | VC 6.0 | D (GD finding 20) |
| B15 | Callee-saved pair order (F16): which callee-save holds the arg vs the loop counter (edi vs esi) is an allocator liveness decision; unsteerable from C | VC 6.0 | D (GD finding 16) |

## C. Integer & arithmetic codegen

| ID | Rule | Scope | Status |
|----|------|-------|--------|
| C1 | Division: real `div`/`idiv` for 2.0/4.x and 5.0+ mixed; magic-number reciprocal division from VC 5.0 for constant divisors; VC 5.0+ `xor edx,edx` (was `sub edx,edx`), `test` (was `cmp reg,0`) | MSVC | V (probe2/3) |
| C2 | Watcom 16-bit: real `div`/`idiv`, no reciprocal magic even for constant divisors (mirrors 32-bit wcc386) | Watcom 16-bit | V (probe12 `div16`) |
| C3 | Combined divmod `x/N + x%N` → one `div` from VC 7.0 (2.0–6.0: two divisions) | MSVC | V (probe9) |
| C4 | `char` zero-extension eras: VC 2.0/4.x `xor; mov al`; VC 5.0/6.0 `and reg,0xff` (`25 ff 00 00 00`); VC 7.0+ `movzx`; all versions `movzx` at /O1 | MSVC | V (probe13) |
| C5 | Signed-char compare eras: 2.0/4.x `cmp byte [mem],0` + branch; 5.0–7.1 load+`test`; 8.0+ compare in memory against the zero register (`38 44 24 04`) | MSVC | V (probe13) |
| C6 | `char` signedness: MSVC/GCC/bcc32/TC treat `char` signed; **Watcom (wcc386 + wcc16) treats it unsigned** (`char < 0` constant-folds to 0) | Watcom vs others | V (probe13) |
| C7 | `x*7` forms: `imul eax,eax,7` (`6b c0 07`) shared by VC 7.0/7.1 and Watcom; `lea [ecx*8]` by VC 6.0/8.0+; shl/sub by 2.0–5.0 and GCC | MSVC/Watcom | V (probe13) |
| C8 | Address-form census for `p[i*4+3]`: 5.0 `lea [eax*4]`+scale-4; 6.0–9.0 `shl eax,4`+scale-1; **10.0/11.0 `add reg,reg` + scale-8 addressing** | MSVC | V (probe15) |
| C9 | Wide-literal sums (`L"AB"[0]+L"AB"[1]`) constant-folded from VC 7.0 and in GCC/Zig; 2.0–6.0/bcc32/Watcom/TC load from memory | MSVC/GCC/Zig | V (probe15) |
| C10 | 64-bit shifts: helper tail-call `mov ecx,N; jmp __allshl/__allshr` in VC 5.0/6.0 (count in ECX); inline `shld`/`shrd` from 7.0 (shared GCC/bcc32/Zig); Watcom `__I8LS` takes the count in EBX | MSVC/Watcom | V (probe14) |
| C11 | 64-bit multiply-by-const: `__allmul` call in VC 5.0–9.0; inline `shld`-decomposition in 10.0/11.0; bcc32 `__llmul`; GCC inline; Watcom `__I8M` | all | V (probe14/16) |
| C12 | 64-bit division: `__alldiv`/`__aulldiv`/`__allrem`/`__aullrem` with register-load + 4-push in VC 5.0–10.0; **VC 11.0 pushes all four dwords from memory (`ff 74 24 10` ×4) at /O2**; every version uses memory-push at /O1; GCC stages `__divdi3` args on a stack frame | MSVC/GCC | V (probe16) |
| C13 | 64-bit abs: branchless `cdq/xor/sub` (`99 33 c2 2b ca 1b c2`) from VC 10.0 | MSVC | V (probe14) |
| C14 | Ternary `a ? 7 : 13`: `cmov` in VC 11.0 AND Zig/LLVM (`0f 45 c1` / `0f 44 c1`); sbb-trick in GCC and VC 2.0/4.x; branches in bcc32/Watcom/TC | all | V (probe14/15) |
| C15 | `cmp [mem],1; sbb; neg` zero-compare idiom unique to VC 2.0/4.x (32-bit) + MSVC 1.52 (16-bit) — corpus-validated absent from VC5/6 binaries | MSVC | V (probe14 + corpus round 3) |
| C16 | 16-bit `char*7`: TC 2.0 `cwde; mul dx` (unsigned) vs TC 3.1 `cwde; imul dx`; Watcom16 `shl ax,3; sub ax,dx`; MSVC 1.52 plain word ops | 16-bit | V (probe13/16 depth) |
| C19 | LCG multipliers: `imul reg,reg,imm32` (`69 c0`) from VC 7.0; VC 2.0-6.0 decompose the constant into shl/add chains (verified for 1103515245, 1664525, 69069) — the imul-vs-decompose split fingerprints the version | MSVC | V (probe19/20) |
| C20 | `%360` (and similar medium constants): real `idiv` in VC 2.0-7.1 (`b9 68 01 00 00 99 f7 f9`), reciprocal-magic from VC 8.0 | MSVC | V (probe19 `wrap_div`) |
| C21 | `h*33` (djb2): `imul eax,eax,0x21` (`6b c0 21`) in VC 7.0/7.1 only; shl-5+add everywhere else | MSVC | V (probe19 `str_hash`) |
| C22 | Sign idiom `(x>0)-(x<0)`: `setg`+`setl`+`sub` in 5.0-9.0; **`setg`+`sets` (`0f 98`) from 10.0** (sign-flag preference); branches in 2.0/4.x | MSVC | V (probe19 `sign`, `in_bounds`) |
| C17 | Byte-register pairing via named byte vars: the guild doc's `or edx,-1` + `dl` form requires a BYTE-field shape.  **probe18 negative for the int-compare shape**: ALL MSVC versions emit `81 7c 24 04 ff 00 00 00` (cmp dword imm) + `c7 05` immediate `-1` store for BOTH the named-byte-var and literal forms — and the `c7 05` immediate is itself the B5 "no volatile free" behavior (the compare consumed the registers) | VC 6.0 (byte-field shape) | V+D (probe18 negative + GD) |
| C18 | Char-param partial-register loads: MSVC6 may load `mov bl, byte ptr [esp+8]` (8-bit) or `mov ebx, dword ptr [esp+8]` (32-bit) depending on how the value is used; when it feeds an FPU conversion the reference reloads the param slot (`mov eax,[esp+8]; and eax,0xff; mov [esp+8],eax; fild`) | VC 6.0 | D (GD `gm_RandomStatModifier`; ~12 formulations could not steer it) |
| C23 | unsigned-char zero-extension — the LIVENESS rule (resolves the and-idiom): byte PARAM (garbage high bits) → always `and eax,0xff` (the 5.0/6.0 marker, probe13 `uc_add`); pointer-deref byte DEAD after → `xor reg,reg; mov reg_low,[mem]`; pointer-deref byte LIVE after → `mov reg_low,[mem]; mov reg2,reg; and reg2,0xff`.  Lever: `(cond ? CONST : CONST)` with EQUAL constant arms folds (kills liveness → xor-form); variable/pointer arms don't fold (byte stays live → and-form).  **probe22 verified per version**: 2.0/4.1 always mask (`and eax,0xff`) or xor-extend (no era split); 5.0/6.0 = the and/xor split driven by liveness (fold_dead → xor-form, fold_live/byte_live → and-form); 7.0+ all `movzx` | VC 6.0 | V+D (probe13 C4 + GD deep-dive + probe22 matrix) |
| C24 | `-(x != c)` negation idiom: fused `sub al,N; neg al; sbb eax,eax; and; add` vs MSVC6's alternative `cmp; setne; neg` (7B larger) — context/register-role driven.  **probe22 verified the LEVER**: the ternary `(x != c) ? -1 : 0` (or `== c ? 0 : -1`) compiles to the fused sub/neg/sbb form — byte-exact in **5.0/6.0/8.0** (`8a 44 24 04 2c 0e f6 d8 1b c0`…); the `-(x != c)` unary form emits `cmp; setne; neg` in 5.0–7.1; 2.0/4.1 decompose via `sub al,N; cmp al,1; sbb eax,eax; inc`; 7.0/7.1/9.0+ use `sete`+`neg` (register or memory compare) | VC 6.0 | V (probe22 `negidm1`/`negidm2`/`negidm3` matrix; GD deep-dive confirmed) |
| C25 | Signed `-1` byte compares (F17): `== -1` on `char*` → `or reg,0xff` hoisted before the length check; `== 0xff` on `unsigned char*` → `mov reg,0xff` after the check.  **probe22 partial**: the signed/unsigned split is verified in EVERY version (the `p[-1] < 0x40` bound compiles `jge` signed vs `jae` unsigned); the hoisted `or reg,0xff` materialization reproduces in **VC 5.0 only** (`80 ca ff` before the length check) — 6.0–11.0 compare the immediate (`cmp al,0xff`) instead; the two-separate-if shape reproduces 7.0/7.1's redundant `cmp cl,cl` re-compare at /O1 | VC 6.0 | V+D (probe22 partial; GD finding 17) |
| C26 | Byte-param local vs global load form (F18): passing a GLOBAL to an `unsigned char` param → byte load `mov cl,[mem]`; a LOCAL → full-register push.  A reference loading the full dword implies the param was `int` | VC 6.0 | D (GD finding 18) |
| C27 | Index-form lea family (F23): `p[i*3]` → `lea reg,[reg+reg*2]`; `p[i*5]` → `lea reg,[reg+reg*4]`; `p[i*7]` → `lea reg,[reg*8]; sub reg,reg` (×8−1) in ALL versions **except 7.0/7.1 which emit `imul reg,reg,7`** (`6b c0 07`); `p[i*12]`/`p[i*24]` → `lea reg,[reg*3]` + `shl` (6.0–9.0), + `add` + ×8-SIB (10.0/11.0), or `shl`+`lea*3` (2.0/4.1); **at /O1 2.0/8.0/11.0 use `imul reg,reg,<byte-offset>`** (`6b c9 30` for ×48).  **lea+disp chain (F40, probe24 `idx_chain`)**: `p[i*3+0x24]` → 6.0–10.0 fold the displacement INTO the lea (`8d 44 40 24` + SIB), 2.0/4.1/5.0/11.0 keep the lea bare and put the disp in the load (`8b 84 8a 90 00 00 00`) | MSVC | V (probe23 `idx3`–`idx24`, probe24 `idx_chain`) |
| C28 | Division-magic constants (F28): signed `/60` → `0x88888889` `imul` + `sar 5` (5.0+); unsigned `/24` → `0xaaaaaaab` `mul` + `shr 4`; signed `/24` = same magic + sign-correction — the constants fingerprint the divisor.  **Real `idiv` in 2.0/4.1 AND at /O1 in every version** (the /O1 `push N; pop ecx; idiv ecx` staging) | MSVC | V (probe23 `div60`/`div24`/`udiv24`; extends C20) |
| C29 | WORD (unsigned short) zero-extension — the 16-bit twin of C4 (F38/F42/F43): pointer-deref word loads → **2.0 `and eax,0xffff`** (`66 8b 00 25 ff ff 00 00`), **4.1–6.0 `xor reg,reg; mov reg_low16,[mem]`** (`33 c0 66 8b 01` — the doc's MSVC6 form), **7.0+ `movzx reg,word ptr [mem]`** (`0f b7 00`); word PARAMS → `and reg,0xffff` in 2.0–6.0, `movzx` from 7.0; the `(uint)(ushort)` cast → `and eax,0xffff` 2.0–6.0, memory-`movzx` 7.0+; **at /O1 every version uses `movzx`** | MSVC | V (probe24 `wze`/`wze_add`/`wze3`; GD findings 38/42/43) |
| C30 | Ternary nonnegative clamp (F44): `(x <= 0) ? 0 : x` → **branchy `test; jg; xor` in 2.0/4.1**, **branchless `setle cl; neg ecx; and eax,ecx` in 5.0–7.1/9.0/10.0** (the doc's setle/dec/and form — the "dec" is the `neg`), **`setle cl; sub ecx,1; and` in 8.0** (`83 e9 01` — the B10 sub-over-dec), **`cmovle` in 11.0**; `(x < 0) ? 0 : x` uses `setl`/`cmovl`, and **10.0 uses `sets` (`0f 98`)** for it — the sign-flag preference again | MSVC | V (probe25 `clamp_le0`/`clamp_lt0`/`clamp_gt0`; GD finding 44) |
| C31 | ×589 multiply decomposition (F44): `x * 589` → **2.0/4.1 four-lea chain** (9x→73x→147x→589x), **5.0/6.0 five-instruction lea chain** (`lea*3; shl 4; add; lea*3; lea×4+x`), **7.0+ single `imul eax,eax,0x24d`** (`69 c0 4d 02 00 00`) — the lea-chain-vs-imul split fingerprints the era for non-power constants (extends C19) | MSVC | V (probe25 `mul589`/`mul589u`; GD finding 44) |

## D. Floating point

| ID | Rule | Scope | Status |
|----|------|-------|--------|
| D1 | FP equality: `fucompp` (`da e9`) two-load style vs `fcomp [mem]` single memory operand — the VC 7.0 RTM↔SP1 fingerprint | VC 7.0/7.1/10.0 | V (probe5/7) |
| D2 | x87 constants: `fldz` init from VC 8.0; reciprocal-`fmul` vs real `fdiv` for `a/5.0` (8.0+); `fld tbyte` 80-bit long double in 16-bit MSVC/TC/bcc32/GCC vs `fld qword` in 32-bit MSVC/Watcom | all | V (probe4/5/8) |
| D3 | `sqrt`: inlined in VC 2.0–7.1, `jmp __CIsqrt` from 8.0; `fld; fsqrt` in MinGW | MSVC/GCC | V (probe5) |
| D4 | FP-libcall marshalling differs between VC 7.0 RTM and SP1 (`fstp [esp]` vs `push`-pair) | VC 7.0 | V (probe8) |
| D5 | SSE2 FP ops (`addsd`/`mulsd`/`divsd`, `cvttsd2si`, `ucomisd`) from VC 11.0 default; `/arch:SSE2` on 8.0–10.0 produces them | MSVC | V (probe5/11) |
| D6 | x87 `wait` (`9b`) interspersed before FPU ops in all 16-bit compilers + Delphi | 16-bit | V (probe3) |
| D7 | `fwait`-free, `fld`-temp result round-trips: Pascal result idiom in Delphi (`fstp [bp-8]` then reload) | Delphi | V (probe3.dpr) |
| D8 | FPU compare flag tests: **probe18 verified** — `fcomp [const]` + `fnstsw` (`df e0`) + `test ah,1` (`f6 c4 01`, C0-only) is the EXACT form in VC 5.0–10.0 (`d9 44 24 04 dc 1d … df e0 f6 c4 01`); VC 2.0/4.x compare the float's BITS as a dword immediate + branch (`81 7c 24 04 <100.0f bits>`); VC 11.0 uses SSE `comiss` (`0f 2f`) + `setae` | VC 5.0–10.0 | V (probe18 `fpu_ge_const`) |
| D9 | In-place float add (F40): `*x += *y` (double) → `fld [x]; fadd [y]; fstp [x]` in 5.0–10.0 (operand load order varies: 2.0/4.1/5.0 load y first, 6.0+ x first); **11.0 SSE `movsd; addsd; movsd`** (`f2 0f 10/58/11`); float form `fld [x]; fadd [y]; fstp [x]` with the `fadd` memory-operand in 2.0/4.1/8.0–10.0 vs register pair in 6.0/7.0/7.1 | MSVC | V (probe24 `fadd_ip`/`fadd_ip2`; GD finding 40) |

## E. Memory & string operations

| ID | Rule | Scope | Status |
|----|------|-------|--------|
| E1 | `strlen` intrinsic: `repne scasb` (`f2 ae`) in VC 2.0–6.0 /O2; manual scan loop from 7.0; bcc32/Watcom/GCC libcall (never inlined); VC 8.0's loop uses `add eax,1` | MSVC | V (probe13 + corpus) |
| E2 | `memcmp(8)`: `repe cmpsb` (`f3 a6`) in VC 2.0–7.1 /O2; dword-compare loop from 8.0 (8.0 ESI-counter / 9.0–10.0 decrement-pair / 11.0 2-dword + byte tail); others libcall | MSVC | V (probe13 + corpus) |
| E3 | 64-byte `memcpy`: `rep movsd` (`f3 a5`) in EVERY MSVC version; GCC register-blocks; bcc32/Watcom libcall; Zig `movups`-pair SSE | all | V (probe14 + corpus) |
| E4 | Small copies: 16B `movq`-pairs / `rep movsd` from VC 8.0; 8B EAX:EDX returns; Watcom `a5 a5` movsd-pair struct copy | MSVC/Watcom | V (probe13/14) |
| E5 | `g_counter++`: bcc32 memory-form `inc dword ptr [g]` (`ff 05`) at -O2; MSVC/GCC/Watcom/Zig round-trip EAX; 4.1–10.0 use `ff 05` at /O1 but 2.0 and 11.0 round-trip even at /O1; 16-bit TC/Watcom add in memory | all | V (probe14 + corpus) |
| E6 | Wide-char compare: 16-bit memory compare `66 3b 4c 24` (MSVC/bcc32); memory-immediate `66 81 7c 24 04` (MSVC 2.0–8.0 + GCC + bcc32); register `66 39 d0` (Watcom) | all | V (probe15 + corpus round 4) |
| E7 | rep-movsd src register role: the memcpy src lands in ESI (consumed by the rep, then reloaded for the following call arg); alternate allocations keep it in EDX and pre-push — allocation-coupled, ~4 formulations could not steer it | VC 6.0 | D (GD `ProcessSendData`) |
| E8 | Aligned-memset prelude: **probe18 verified-negative across ALL versions** — no MSVC version emits the dest-alignment prelude; VC 2.0–7.1 inline the 1008-byte constant memset as `rep stosd` (`b9 fc 00 00 00 f3 ab`), **VC 8.0+ LIBCALL memset** (`68 f0 03 00 00 … e8` — a constant-memset inlining boundary), bcc32/Watcom/GCC/Zig libcall | VC 6.0 | V+D (probe18 all-version negative + GD; new 8.0+ libcall boundary) |
| E11 | The aligned-memset prelude is SHAPE-dependent (refines E8): it appears for OPAQUE dest+size pairs (fresh malloc result, potentially large size — F19/InitPacketPool) and NOT for the constant-0x3f0 shape we probed (all versions plain dword+tail).  **probe22 extended the negative to every opaque shape**: runtime size (`clear_opaque`), large constant 0x4000 (`clear_const`), fresh-allocation dest (`clear_fresh`) — NO version emits the alignment prelude; the inline-vs-libcall boundary holds (2.0–7.1 inline `rep stosd`+`rep stosb` tail, **8.0+ libcall** for the opaque shapes too, 11.0 memory-push args).  The E8 negative stands; the prelude is real only in the exact allocator context (register-reuse scheduling) | VC 6.0 | V+D (probe18 E8 negative + probe22 all-shape negative + GD finding 19) |
| E14 | Constant-size memset inlining style (36B shape): **2.0–6.0 `mov ecx,9; rep stosd`**; **7.0–10.0 unrolled dword stores** (`mov [esp+N],0` ×9, +GS cookie from 10.0); **11.0 SSE `movq` pairs** (`66 0f d6`); at /O1 every version calls the memset libc — and **7.0 SP1 still uses rep stosd where 7.0 RTM unrolls** (a J1 addition) | MSVC | V (probe22 `arr_counter`/`struct_counter`) |
| E15 | SIB index-addressing era (F29): word-compare scan loops use `[base+idx*2]` index addressing **from 7.0** (`66 83 3c 41 00`); 2.0–6.0 use pointer induction (`add reg,2` + `cmp word [reg],0`) instead — no SIB at all.  The doc's counter-as-base role (`[cnt+arr]`) appears in NO version; 7.0+ put the array as base with the counter scaled | MSVC | V (probe23 `sib_scan`/`sib_store`) |
| E16 | Dead arg-slot reuse (F26): an output local whose live range fits the dead arg2 slot lands **in the slot without a frame in 5.0/6.0** (`lea eax,[esp+8]`, no `sub esp`); 7.0+ allocate via `push ecx` (1 dword) or `sub esp` (2.0/4.1); at /O1 ebp frames take over — a 5.0/6.0 era marker | MSVC | V (probe23 `argslot`) |
| E17 | Base+offset folding (F36): `base + 0x18` then `[0]/[4]/[6]` accesses fold the constant into every load offset **from 5.0** (`0f be 41 1e` etc.); 2.0/4.1 materialize the `add reg,0x18` for at least one access | MSVC | V (probe23 `addfold`) |
| E18 | In-place memory and (F39): `*p &= m` on a 16-bit value emits the memory-operand `and word ptr [mem],reg` (`66 21 08`) in EVERY version — the size2 in-place form is uniform (load/and/store round-trip appears in no version) | MSVC | V (probe24 `wand`/`wand2`; GD finding 39) |
| E19 | Byte memory ops (F39): `*p |= ~mask` byte-store form: **8.0+ emit memory-operand `or byte [mem],reg`** (`08 08`); 5.0–7.1 round-trip through a byte register (`mov dl,[p]; or dl,cl; mov [p],dl`); 2.0/4.1 memory-operand too — the 5.0–7.1 register round-trip is the odd era out | MSVC | V (probe24 `bmask3`; extends F21) |
| E20 | Simple field-store fold (F37/F39): `*(int*)(base+0x14) = v` folds to `mov [reg+0x14],eax` in EVERY version — the reference's desired form IS the default; the Finding 7 hoisted-lea split needs the address-taken-param + resolve-call context | MSVC | V (probe24 `fstore`; GD findings 37/39 context) |
| E21 | Byte-arg push forms (F44): a memory-source `unsigned char` argument → **2.0–6.0 raw byte `mov al,[mem]; push eax` (NO extension — refutes the doc's "no C shape produces the raw push")**; **7.0/7.1 `xor reg,reg; mov reg_low` zero-extend**; **8.0+ `movzx`**; param-slot byte args push the raw dword slot in 2.0–6.0; 7.0+ tail-jump the callee (`e9 rel32`) when the call is the last statement | MSVC | V (probe25 `bpush`/`bpush2`/`bpush3`; GD finding 44 claim corrected) |
| E22 | Byte+dword sum load order (F44): `*(uchar*)(r+0xc) + *(int*)(a+0x13)` loads the BYTE first in every version (5.0/6.0 `xor eax,eax; mov al,[..]; mov edx,[..]; add`, 7.0+ `movzx` + memory-add) — the doc's dword-first is a register-pressure context artifact, not a general rule | MSVC | V (probe25 `sum_load`; GD finding 44 context) |
| E9 | Trig-table index `(angle>>8)&0xff`: byte-load of the high byte in 5.0/6.0 (`8a 44 24 05`), `shr+movzx` in 7.x, `sar+and` in 9.0/10.0, ECX-based in 11.0 | MSVC | V (probe19 `trig_lookup`) |
| E10 | lea-adjusted range checks (`8d 48 d0`-style) are an 8.0+ trait — verified in the hex classifier AND the tolower char test (2.0-7.1 use compare-immediate + add) | MSVC | V (probe19 `hex_nibble`, probe21 `ci_char`) |
| E11 | `sar reg,1` encoding: `c1 f8 01` (3B) in VC 2.0/4.x vs `d1 f8` (2B) from 5.0 | MSVC | V (probe21 `center`) |
| E12 | Function-pointer-table dispatch: `ff 14 8a` (direct `call [table+reg*4]`) in 5.0-7.1 vs `8b 04 8a; ff d0` (load + `call eax`) from 8.0 | MSVC | V (probe21 `fptable`) |
| E13 | Byte-swap eras: byte-move forms 2.0-6.0, `movzx`-based 7.0/7.1/8.0, shift/mask 9.0+ | MSVC | V (probe21 `bswap16`) |

## F. Control flow & switches

| ID | Rule | Scope | Status |
|----|------|-------|--------|
| F1 | Switch dispatch: MSVC 1.52 `add ax,ax; xchg bx,ax` (`03 c0 93`) + `dw` table; TC 2.0/3.1 and Watcom 16-bit `shl bx,1` (`d1 e3`) | 16-bit | V (probe12) |
| F2 | `case` in Delphi 1.0 = linear compare chain, never a jump table | Delphi | V (probe2.dpr) |
| F3 | `set` membership in Delphi = `mov ax,1; rol ax,cl; test [mem],ax` (`d3 c0`) — 16-bit `rol` never emitted by TC/MSVC16 | Delphi | V (probe2.dpr) |
| F4 | SEH prologue ladder: `push -1` in 2.0–7.1 vs `push -2` from 8.0; `fs:[0]`-first in 2.0/4.x | MSVC | V (probe7) |
| F5 | Boolean `&&`/`||`: 2.0/4.x AND 8.0+ compare args in memory (`83 7c 24 04 00`); 5.0–7.1 load + `test` | MSVC | V (probe14) |
| F6 | Setcc eras: 2.0/4.x branch + `mov eax,1`; 5.0–7.1 register compare; 8.0+ memory-operand compare (shared GCC/Zig); bcc32 `setcc` + `and eax,1` | all | V (probe15) |
| F7 | do-while vs while: **probe18 verified-negative for the simple shape** — NO MSVC version peels a plain `do-while` (2.0–6.0: do-while 4B smaller, no entry test; 7.0+: equal sizes); the guild doc's peel required the mid-loop-return query shape (`ahm_QueryEntityBuildingType`), not reproduced by the generic trigger | VC 6.0 (query shape) | V+D (probe18 negative + GD) |
| F8 | Loop-shape recipes (MSVC6 table scans): counter init BEFORE the base computation; found-return recomputed from the counter (not the induction pointer); increments in the for-clause (`inc ecx` before `add eax,0x80`); `for (i=N; i!=0; idx=(idx+1)&mask)` → `dec; inc; and; test; jne` | VC 6.0 | D (GD `gm_FindSlotById`, `ahm_InitRandomEntity`) |
| F9 | Induction-base folding: **probe18 negative for the simple loop** — MSVC strength-reduces the recompute form (both recompute and increment sources compile to the increment shape); the guild doc's fold distinction requires the larger `struct zone_record` scan | VC 6.0 (scan shape) | V+D (probe18 negative + GD) |
| F10 | Epilogue merging: MSVC6 tail-merges error epilogues into one shared xor block; a reference that INLINES each error epilogue (no xor when eax is already 0 from the test) cannot be reproduced by the merged form — source-shape-sensitive | VC 6.0 | D (GD `amt_SwapOfficeHolders`) |
| F11 | Dense small-int switch: `cmp eax,N; ja; jmp [eax*4+table]` (`ff 24 85`) — UNIFORM across ALL MSVC versions (2.0-11.0); a reliable "MSVC switch" look-for | MSVC | V (probe20 `cmd_dispatch`) |
| F13 | Dense switch jump table uniform at scale — 8- and 16-case switches use `83 f8 N; ja; ff 24 85` in ALL versions (extends F11) | MSVC | V (probe21 `sw8`/`sw16`) |
| F14 | VC 11.0 unrolls array-update loops ×4 (`83 fa 04 72 … lea`-based); VC 8.0/9.0 decrement the counter with `83 ea 01` (sub-over-dec) | MSVC | V (probe21 `update_objs`; 8.0 trait 8th confirmation) |
| F12 | Hex-nibble classifier: compare-immediate+add in 5.0-7.1; **lea-adjusted range checks (`8d 48 d0`) from 8.0** | MSVC | V (probe19 `hex_nibble`) |
| F15 | AH-relative masks (F14): `test ah,0x60` / `or ah,0x30` require the constant `(value << 8)` — the compiler commits the value to the AH byte-slot and won't mix AL/AH ops on one value.  **probe22 verified**: `*player |= 0x3000` → `or ch,0x30` (`80 cd 30`) in 5.0/6.0 and the `*player` flag shape emits `test ah,0x60` + `or ah,0x8` (`80 cc 08`) in 5.0/6.0; at /O1 2.0/4.1 use `or ah,0x30` (register) and 5.0–7.1 `or byte ptr [eax+1],0x30` (memory AH-slot); **8.0+ switch to dword/memory forms** (`test eax,imm` / `or dword ptr [mem],imm`).  The boolean-return shape (`(x & 0x6000) != 0`) booleanizes via neg/sbb instead of `test ah` — the AH form needs the branch/store context.  Cross-toolchain: MinGW GCC also emits `or ah,0x30` (`80 cc 30`) for the same shape (family-level trait, not MSVC-exclusive) | VC 6.0 | V (probe22 `ah_or_hi`, `named_flags`/`direct_flags`; GD finding 14) |
| F16 | Struct-fields beat array-index scalarization (F13): `list[++list[0]]` counter gets scalarized (the zeroed array shrinks); a struct FIELD is never scalarized; statement order drives load placement.  **probe22 verified-NEGATIVE for the simplified shape**: no version scalarizes the standalone `int list[9]` + `list[++list[0]]` (the zeroed 36B stays 9 dwords, identical to the struct form); the struct-vs-array delta is only the store offset (`[esp+idx*4+8]` vs `[esp+idx*4+0xc]`) — the doc's scalarization needs the full lb_ExPlayerlist loop context.  The per-version memset style (E14) is the real fingerprint here | VC 6.0 | V+D (probe22 simplified negative + GD finding 13) |
| F17 | Byte-index switch preamble: the reference's `mov dl,[eax]; mov ecx,edx; and ecx,0xff; add ecx,-3; cmp ecx,0x66; ja; jmp [ecx*4+table]` (10B, keeps the byte in dl) vs MSVC6's 4B `xor ecx,ecx; mov cl,[eax]` — the liveness of the switch byte (later `cmp dl,N`) drives it.  **probe22 verified**: the byte-LIVE switch (a case re-reads `*p`) emits the and-mask preamble `mov al,[eax]; and eax,0xff; add eax,-3; cmp eax,0x66; ja; jmp [eax*4+tbl]` in **5.0/6.0** (register roles aside, the form matches the reference); the byte-DEAD switch emits the 4B `xor;mov reg_low` form in 5.0/6.0; 2.0/4.1 use the xor-extend + sbb-era forms; 7.0+ `movzx`-based preambles | VC 6.0 | V (probe22 `f17_switch`/`f17_switch_dead`; GD GetCommandPayloadSize) |
| F18 | `?:` flag chain split (F21): a `seta`-chain can split around an interleaved store in one sibling function and not another — no flag or C shape reproduces both | VC 6.0 | D (GD finding 21) |
| F19 | Branchless if-conversion of constant returns (F32): `if (x==1) return 0xc; return 8;` → **branchless** `dec al; neg al; sbb eax,eax; and al,0xfc; add eax,0xc` in **5.0/6.0** (2.0/4.1: `dec al; cmp al,1; sbb; shl`-variant; 7.0/7.1: `cmp; sete; lea [reg*4+8]`; 8.0+: memory compare + `sete` + lea; 11.0: `cmov`).  **The steering lever: `r = 8; if (x == 1) r = 0xc; return r;` preserves the branch in 2.0–10.0** (`cmp; mov eax,8; jne; mov eax,0xc`), 11.0 converts it to `cmov` — write the assignment form to keep the reference's branchy code | MSVC | V (probe23 `ifconv1`/`ifconv2`; GD finding 32) |
| F20 | Zero-push hoist (F27): `f(a, b, 0, c)` emits `push 0` (`6a 00`) in EVERY version — **no version hoists `xor eax,eax; push eax`** (verified-negative for the reference's hoisted-zero; that behavior is context-driven by the table computation consuming the zero register) | MSVC | V+D (probe23 `zeropush` negative + GD finding 27) |
| F21 | Byte-compare memory vs register (F31): a direct `*p != 6` scan uses MEMORY-operand compares (`cmp byte [eax],6`) from 8.0 (5.0–7.1 mix memory + `cmp al,6`); declaring a named `t` temp forces REGISTER compares (`cmp al,6` + `inc`) in every version — the temp lever changes the compare form observably | MSVC | V (probe23 `bytecmp1`/`bytecmp2`; GD finding 31) |
| F22 | FPU clamp compare forms (F35): the double-sided clamp `if (f<a4){if(f<=cc)f=cc;}else f=a4;` emits **one `fcomp [a4]` + `fnstsw`/`test ah,1` in 5.0–7.1**, **`fcomip` (`d8 d1`) + `test ah,5` in 8.0–10.0**, **SSE `comisd` (`66 0f 2f`) in 11.0**, integer round-trip in 2.0/4.1; the redundant re-compare is FOLDED in every version (verified-negative for the reference's second `fcom [a4]`) | MSVC | V (probe23 `fpu_clamp`; GD finding 35 verified-negative) |
| F23 | WORD compare eras (F42): `*cmd == 0x2a \|\| *cmd == 0x116` → **2.0–7.1 raw word load + 16-bit compares** (`66 8b 00 66 3d 2a 00 … 66 3d 16 01`); **8.0+ `movzx` + `cmp ax,imm`** (9.0+ `cmp ax,reg` for the second); the word-compare chain form fingerprints the era | MSVC | V (probe24 `wcmp`; GD finding 42) |
| F24 | Size-dispatch dec-chain (F39): `switch (size) {1,2,4}` → **a compare/dec chain, NEVER a jump table**: 5.0–7.1/10.0/11.0 `dec reg; jz; dec reg; jz; sub reg,2; jz` (`48 74`), **8.0/9.0 `sub reg,1`-chain** (`83 e8 01` — the B10 sub-over-dec trait), 2.0/4.1 `cmp reg,1/2/4`-chain — extends F11 (small-int switches aren't always jump tables) | MSVC | V (probe24 `sz_disp`; GD finding 39) |
| F25 | Early-return block placement (F45): `if (a) return -3; if (b) return -6; …` keeps the early-return blocks **INLINE right after their conditional checks in EVERY version** (`test; jne +6; mov reg,-3; ret` — the `jne` skips the 6-byte block) — the doc's Finding 45 tail-grouping is a register-pressure context artifact, not general MSVC behavior.  The shared-epilogue `-1` tail materializes `or eax,-1` (`83 c8 ff`) from 5.0 (2.0/4.1 `mov eax,-1` — the B5 trait); 11.0 materializes the -3 constant via `lea eax,[reg-3]` | MSVC | V (probe26 `er1`–`er4`; GD finding 45 claim corrected) |

## G. Frames, prologues, epilogues, stack

| ID | Rule | Scope | Status |
|----|------|-------|--------|
| G1 | `/GS` cookie-mix prologue `a1 <cookie> 33 c4 89 44 24 40` (`mov eax,[cookie]; xor eax,esp; store`) from VC 8.0 — the only probed toolchain with stack cookies | MSVC 8.0+ | V (probe15) |
| G2 | Stack-probe threshold uniform at 4096 (`/Gs` default) across all MSVC versions; probe symbols `__chkstk` (32-bit) / `__aNchkstk` (16-bit) / `___chkstk_ms` (MinGW) / `__CHK` (Watcom) | all | V (probe9) |
| G3 | Frame-prologue nops: `mov edi,edi` hotpatch (VC 6.0); `lea esp,[esp]` loop-align (7.0+); `lea ebx,[ebx]` (9.0+); `0f 1f` GNU nops (GCC/Zig); `2e` nops (8.0+ era) | MSVC/GCC/Zig | V (probes) |
| G4 | Epilogue forms at /O1: `leave` (`c9`) in 16-bit MSVC 1.x (25× in probe, 0 in TC); `enter` (`c8`) frames in MSVC 1.52; `mov esp,ebp; pop ebp` in others | 16-bit | V (probe3) |
| G5 | Stack-frame alignment: `and esp,-16` in GCC + VC 11.0 (SSE2); never VC 2.0–10.0 | MSVC/GCC | V (probe4/5) |
| G6 | 16-bit stack check: `mov ax,<size>; call __aNchkstk` (MSVC 1.5x); `mov ax,<size>; lcall` RTL probe (Delphi); `__CHK` with amount pushed (Watcom) | 16-bit | V (probes) |

## H. 64-bit support

| ID | Rule | Scope | Status |
|----|------|-------|--------|
| H1 | No 64-bit integer type before VC 5.0 (2.0/4.x objects lack i64 functions) | MSVC | V (probe14/16) |
| H2 | 64-bit compare forms: direct-memory from VC 7.0 (`3b 44 24 10 ...`); 5.0/6.0 load both registers; 4.1 `39 44`-forms | MSVC | V (probe10) |
| H3 | 64-bit multiply-high inlined from VC 6.0 (`mul [mem]; mov eax,edx`); `__allmul` call before | MSVC | V (probe) |
| H4 | Helper symbol families: MSVC `__all*`; Borland `__ll*`; Watcom `__I8*`; GCC inline + `__divdi3` | all | V (probes) |

## I. Object model (C++)

| ID | Rule | Scope | Status |
|----|------|-------|--------|
| I1 | `new`/`delete`: call + ret in VC 5.0/6.0; **tail-jump from VC 7.0** (`jmp <operator new/delete>`); GCC also tail-jumps delete | MSVC/GCC | V (probe16) |
| I2 | `new int[n]` checked array-size multiply (`mov edx,4; mul edx; seto cl; neg ecx; or ecx,eax`) in VC 11.0; GCC uses a threshold compare (`cmp eax,0x1fffffff`) | MSVC/GCC | V (probe16) |
| I3 | Vtable dispatch uniform `mov eax,[ecx]; call [eax]` in MSVC; GCC adds a null-vtable check; bcc32 pushes register-loaded args | MSVC/GCC/bcc32 | V (probe16) |
| I4 | Watcom `wpp386` rejects the probe16 class+`new` syntax under the image's flags | Watcom | V (probe16 negative) |

## J. Toolchain identity & packaging

| ID | Rule | Scope | Status |
|----|------|-------|--------|
| J1 | SP codegen equivalence: VC 5.0 SP1–SP3, 6.0 SP1–SP6, 7.1 SP1, 8.0 SP1, 10.0 SP1 are byte-identical to their RTMs on every probe (machine-verified over 1957 corpus SP rows); **VC 7.0 SP1 differs on 18 functions** (FP equality, FP loops, char array, stack probes, marshalling, `_s64_ret`) — probe22 adds the constant-memset shapes (`arr_counter`/`struct_counter`: SP1 `rep stosd` vs RTM unrolled stores); **VC 9.0 SP1 unverified/blocked** (its cl.exe requires a sched.dll no image ships) | MSVC SPs | V (corpus sweep) |
| J2 | decomp.me treats MSVC 6.3–6.6 as separate compiler IDs — the split is CRT/header-driven, not codegen (consistent with our SP1–6 codegen-identical finding) | MSVC 6.0 SP line | V+D (DM + corpus) |
| J3 | Zig vs MinGW GCC: no byte-level codegen fingerprint separates them (LLVM-family traits only: `movups` copies, `cmov` ternaries, frame prologues) | Zig/GCC | V (probe13–16) |
| J4 | Corpus-exposed flaw: the staged-`sched.dll` VC 9.0 SP1 objects are IA64 machine-type — a compiler-workaround output must be machine-checked before trust | methodology | V (corpus) |
| J5 | TC 2.0 preprocessor: no `defined()` support in `#if` (numeric `#if` works) — probe14/15 uncompileable on TC 2.0 | TC 2.0 | V (probe16 depth) |

---


## K. Layout & linking (source-file level)

| ID | Rule | Scope | Status |
|----|------|-------|--------|
| K1 | COMDAT VA-contiguity (F15): each `.c`'s functions link as a contiguous VA run (0x10-padded), so VA-adjacent functions must stay in one file; uncovered holes need naked `_emit` placeholders in VA order; duplicate `// FUNCTION:` coverage breaks the layout silently | VC 6.0 linking | D (GD finding 15) |

## How to add a rule

1. Prefer **V**: write the trigger probe, compile through the toolchains, verify against every other toolchain's objects, record the corpus rows.
2. **D** rules come from the cited sources (AF manual, DM fleet, GD doc) and must state their verification status honestly.
3. Each rule maps to corpus records — query them via `corpus.json` (see the README corpus section for the query idiom).
4. Categorize into the table whose dimension matches; add new categories only when the existing ones genuinely don't fit.
