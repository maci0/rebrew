# Codegen Patterns — per-compiler-version reference

One file per compiler major version, documenting **minute byte-level codegen
details**: prologues, register conventions, integer division, FPU, loops,
string ops, padding, stack probes — how adjacent major versions differ, and
which fingerprints are (verified) 100% unique to a version.

This folder supersedes the single-doc `docs/CODEGEN_REFERENCE.md` (now a
pointer).  Cross-references: [TOOLCHAIN.md](../TOOLCHAIN.md) (profiles and
detection), [CODEGEN_PATTERNS.md](../CODEGEN_PATTERNS.md) (MSVC6 C-source
rules for byte matching).

## Index

One folder per compiler class; one file per version inside.

| File | Compiler | rebrew profiles |
|---|---|---|
| [msvc/msvc-1.md](msvc/msvc-1.md) | MSVC 1.0 / 1.5 / 1.52 (16-bit, Windows 3.x) | `msvc1.52`, `msvc15`, `msvc10` |
| [msvc/msvc-2.md](msvc/msvc-2.md) | MSVC 2.0 (first 32-bit) | `msvc200` |
| [msvc/msvc-4.md](msvc/msvc-4.md) | MSVC 4.0 / 4.1 / 4.2 | `msvc400`, `msvc410`, `msvc420` |
| [msvc/msvc-5.md](msvc/msvc-5.md) | MSVC 5.0 (SP1–SP3) | `msvc5`, `msvc500sp1..sp3` |
| [msvc/msvc-6.md](msvc/msvc-6.md) | MSVC 6.0 (RTM + SP1–SP6) | `msvc6`, `msvc600sp1..sp6` |
| [msvc/msvc-7.md](msvc/msvc-7.md) | MSVC 7.0 (.NET 2002) | `msvc700`, `msvc700sp1` |
| [msvc/msvc-7-1.md](msvc/msvc-7-1.md) | MSVC 7.1 (.NET 2003) | `msvc7`, `msvc710`, `msvc710sp1` |
| [msvc/msvc-8.md](msvc/msvc-8.md) | MSVC 8.0 (VS 2005) | `msvc800`, `msvc800sp1` |
| [msvc/msvc-9.md](msvc/msvc-9.md) | MSVC 9.0 (VS 2008) | `msvc900`, `msvc900sp1` |
| [msvc/msvc-10.md](msvc/msvc-10.md) | MSVC 10.0 (VS 2010) | `msvc1000`, `msvc1000sp1` |
| [msvc/msvc-11.md](msvc/msvc-11.md) | MSVC 11.0 (VS 2012) | `msvc1100` |
| [mingw/gcc.md](mingw/gcc.md) | MinGW GCC (PE/x86_32, by era) | `gcc-pe` |
| [watcom/open-watcom.md](watcom/open-watcom.md) | Open Watcom wcc (16-bit) / wcc386 (32-bit) | `watcom`, `watcom16` |
| [borland/turbo-c.md](borland/turbo-c.md) | Turbo C 2.0 / Turbo C++ 3.1 (16-bit DOS) | `tc16`, `tc20` |
| [borland/borland-cpp.md](borland/borland-cpp.md) | Borland C++ 5.5 `bcc32` (32-bit) | `borlandc55` |
| [delphi/delphi.md](delphi/delphi.md) | Delphi 1.0 (16-bit NE Pascal) | `delphi16` |
| [zig/zig.md](zig/zig.md) | Zig (`zig cc` → MinGW-w64) | `gcc-pe` (structural) |

Cross-cutting references: the **[rules catalog](RULES.md)** categorizes
behavior-level codegen rules, and the **[decomp idiom cheat-sheet](DECOMP_IDIOMS.md)**
maps the 30 probe19/20 game idioms to their per-version signatures and
disassembly look-fors (calling conventions, register allocation,
arithmetic, FP, memory ops, control flow, frames, 64-bit, C++, toolchain
identity) across all toolchains with verification status; the
**[uniqueness table](#uniqueness-table)** lists byte markers; and
**[corpus.json](corpus.json)** holds the machine-readable per-function
bytes (see below).

## Shared file template

Every file follows the same sections: **Identity** (CL.EXE / Rich-header C1
builds / linker versions / profiles) · **Prologue & frame pointer** ·
**Argument passing** · **Register conventions** · **Integer division** ·
**FPU / SSE** · **Loops** · **String ops** · **Padding & nops** · **Stack
probes** · **Switch dispatch** · **Optimization fingerprints** (/O1 vs /O2)
· **100% unique to this version** · **Version deltas** (vs the previous
major) · **Verification** (which toolchain output verified the patterns).

## Fingerprint catalog

The dimensions a codegen fingerprint lives on:

| # | Dimension | What differs |
|---|-----------|--------------|
| 1 | Argument passing | push-then-call vs `[esp+N]` stores vs `[ebp+N]` frame loads |
| 2 | Prologue / frame | `push ebp; mov ebp,esp` always (Borland) vs never at /O2 (MSVC) vs register saves first (Watcom) |
| 3 | Integer division | real `div`/`idiv` vs magic-constant multiply; the exact magic values and the post-shift tail |
| 4 | FPU | x87 (`fld`/`fadd`) vs SSE2 (`addsd`) vs `fwait`-interspersed 16-bit |
| 5 | Stack probes | `__chkstk` (eax=size) vs `___chkstk_ms` vs `__aNchkstk` (ax=size) vs `__CHK` (amount on stack) |
| 6 | Padding / nops | `0f 1f` GNU vs `8d 74 26 00`/`8d a4 24` MSVC6 vs `8d 64 24 00` VC7+ vs `90` vs `cc cc` |
| 7 | String ops | `rep movs/stos` inlining (MSVC) vs libcall memset (GCC) |
| 8 | Register conventions | callee-saved set, which register holds the divisor, `sub edx,edx` vs `xor edx,edx` |
| 9 | Loops | `dec/jnz` vs `loop` vs alignment-nop loop heads |
| 10 | Hotpatch / GS | `mov edi,edi` padding, `__security_check_cookie` (VC 8.0+) |

## Uniqueness table

Markers claimed as **100% unique to a version** (within the toolchain set on
this site — "unique among the compilers rebrew/decomp.me can build", not
"unique in all of computing").  Verified = reproduced from real toolchain
output (probe #2 adds the 64-bit/FP/rotate/divisor set; probe #3 adds a
13-divisor table, fixed-size memcpy/memset, long double, 64-bit arithmetic
and switch shapes — see the methodology); the byte patterns must not appear
in any other file's *normal patterns* section (grep-checked).  Unproven
claims are explicitly downgraded in the per-version files.

| Unique marker | Bytes | Claimed by | Verified |
|---|---|---|---|
| `sub edx,edx` div zero-extend | `2b d2` | MSVC 2.0 & 4.x (real-div era) | ✓ probe |
| `fld1` for FP `+1.0` | `d9 e8` before `fadd [esp+4]` | MSVC 2.0 & 4.x | ✓ probe2 (`fadd1`) |
| **3-byte shift-by-1 encoding** | `c1 e8 01` / `c1 f8 01` | **MSVC 2.0 & 4.x** (5.0+ use 2-byte `d1 e8`/`d1 f8`) | ✓ probe3 (`u2`/`s2`) |
| **FP adds via `fsub` with negated `.rdata` constants** | `dc 25` after `fld`; `-1.0`/`-3.0` in .rdata | **MSVC 5.0 only** | ✓ probe2 + .rdata dump |
| Magic division WITHOUT post-shift (`mov eax,edx` tail) | `8b c2 c1 e8 N` | MSVC 5.0 & 6.0 | ✓ probe2+3, 20 divisors |
| Signed-div sign-fix via ECX round-trip | `8b c8 c1 e9 1f 03 c1` | MSVC 5.0 & 6.0 | ✓ probe2+3, 13 divisors |
| Magic division WITH post-shift (`shr edx,N` tail) | `c1 ea N 8b c2` | MSVC 7.0+ | ✓ probe2+3 |
| **`rol` for rotate (`x<<n \| x>>(32-n)`)** | `d3 c0` | **MSVC 8.0+** (shift pairs in 2.0–7.1) | ✓ probe2 (`rotl`) |
| **Memory-operand `imul dword ptr [esp+4]` in signed-div magic** | `f7 6c 24 04` | **MSVC 10.0+** (register-load in 5.0–9.0) | ✓ probe2+3, 13 divisors |
| **`iabs` via cdq** (`x<0?-x:x`) | `99 33 c2 2b c2` | **MSVC 10.0+** (test/jns/neg in 5.0–9.0) | ✓ probe2 (`iabs`) |
| **`cmov` for min/max/clamp** | `0f 4f` / `0f 4c` | **MSVC 11.0 only** (branches in 2.0–10.0) | ✓ probe2 (`imax/imin/clamp`) |
| SSE2 FP ops by default | `f2 0f 58/59/5c/5e` | MSVC 11.0 | ✓ probe1+2 (all earlier MSVC pure x87) |
| SSE2 `movsd/addsd` handoff for FP returns | `f2 0f 10 … f2 0f 58 … dd 44 24` | MSVC 11.0 | ✓ probe2 (`fadd1`) |
| **SSE `movq` for 16/32-byte memcpy** | `f3 0f 7e` / `66 0f d6` | **MSVC 11.0 by default; VC 8.0–10.0 with `/arch:SSE2`** (mov pairs / rep movsd otherwise) | ✓ probe3/11 (`c16`/`c32`) |
| **`xorps`+`movq` 16-byte memset** | `0f 57 c0` + `66 0f d6` | **MSVC 11.0 by default; VC 8.0–10.0 with `/arch:SSE2`** (4× mov pairs otherwise) | ✓ probe3/11 (`z16`) |
| **128-byte memset → libcall** | `68 80 00 00 00 6a 00 ff 74 24 0c e8` | **MSVC 11.0** (rep stosd in 2.0–10.0) | ✓ probe3 (`z128`) |
| **64-bit helper args pushed from memory** | `ff 74 24 10` ×4 | **MSVC 11.0** (register loads in 4.1–10.0) | ✓ probe3 (`i64mul`/`i64div`) |
| **`cvttsd2si` inline double→int** | `f2 0f 2c 44 24 04` | **MSVC 11.0** (2.0–10.0: `fld; jmp __ftol`; caveat: GCC with SSE2 also uses it) | ✓ probe4 (`d2i`/`f2i`) |
| **2^52-bias inline double→unsigned** | `0d 00 0c 00 00` (or eax,0xC0000) | **MSVC 8.0+** (2.0–7.1: helper call) | ✓ probe4 (`d2u`/`f2u`) |
| **`repe cmpsd` fixed-size memcmp** | `f3 a6` | **MSVC 2.0–7.1** (8.0+ unroll; GCC/Watcom/Borland call memcmp) | ✓ probe4 (`mc8/16/32`) + corpus rt63 |
| **`imul` for x*100 / x*1000** | `6b c0 64` / `69 c0 e8 03 00 00` | **MSVC 7.0+** (5.0/6.0 use lea chains) | ✓ probe4 (`m100`/`m1000`) |
| **`shl eax,1` for x*10** | `8d 04 80 d1 e0` | **MSVC 5.0–7.1** (2.0/4.x + 8.0+ and GCC use `add eax,eax`) | ✓ probe4 (`m10`) |
| **strcmp → tail `jmp strcmp`** | `e9` (reloc) | **MSVC 7.0+** (2.0–6.0: call + cleanup) | ✓ probe4 (`strc`) |
| **tail call `jmp g`** (`return g(x)`) | `e9` (reloc) | **MSVC 7.0+** (2.0–6.0 and bcc32: call + cleanup; GCC/Watcom also tail-call) | ✓ probe5 (`tc`) |
| **inline `fsqrt`** | `d9 fa` | **MSVC 2.0–7.1** (8.0–10.0: `jmp __CIsqrt`; 11.0: SSE2 call; GCC inlines with a NaN check) | ✓ probe5 (`sq`) |
| **reciprocal-`fmul` for `a/5.0`** | `dc 0d` | **MSVC 2.0–7.1** + Watcom + bcc32 | ✓ probe5 (`fdiv5`) |
| **real `fdiv` for `a/5.0`** | `dc 35` | **MSVC 8.0–10.0** (GCC uses `fdivr`) | ✓ probe5 (`fdiv5`) |
| **`fucompp` FP equality** | `da e9` | VC 7.0 RTM, 7.1, 10.0 (SP1: `fcomp [mem]` `dc 5c 24 0c`) | ✓ probe5 (`fcmp2`) + probe7 (`fc5`/`fc8`/`fc9`) |
| **SEH frame `push -1`** (`__try/__except`) | `6a ff` after `push ebp` | **MSVC 2.0–7.1** (8.0+ uses `push -2` `6a fe`) | ✓ probe7 (`seh1`) |
| **SEH `fs:[0]` load BEFORE the frame** | `64 a1 00 00 00 00 55 8b ec` | **MSVC 2.0 & 4.x** (5.0+ loads it after `push ebp`) | ✓ probe7 (`seh1`) |
| **SEH frame `push -2`** (new handler) | `6a fe` | **MSVC 8.0+** (with /GS cookie interleave) | ✓ probe7 (`seh1`) |
| **inline 64-bit multiply-high** | `f7 64 24 08 8b c2` (`mul [mem]; mov eax,edx`) | **MSVC 6.0+** (4.1/5.0: `mul` + `jmp` to the shift helper) | ✓ probe7 (`mulhi`) |
| **`fldz` FP-loop accumulator init** | `d9 ee` | **MSVC 8.0+** (2.0–7.1 load 0.0 from `.rdata`) | ✓ probe8 (`fs1/fs2/fs3`) |
| **FP-loop unrolling ×4** | `cmp esi,4; jl` peel | **MSVC 7.0+** (5.0/6.0: tight x87 loop in st0; 2.0/4.x: memory accumulator) | ✓ probe8 (`fs1/fs2`) |
| **indirect tail call `jmp [mem]`** | `ff 25` / `ff 20` (reloc) | **MSVC 7.0+** (2.0–6.0: `call [mem]; add esp,4; ret`) | ✓ probe8 (`indirect`) |
| **volatile reads** | `mov eax,[0]` | identical in ALL versions (verified negative) | ✓ probe8 (`vread`) |
| **combined divmod** (`x/N + x%N` → one `div`) | `99 … f7 f9 … 03 c2` | **MSVC 7.0+** (2.0–6.0 do TWO divisions) | ✓ probe9 (`dm3`/`udm3`) |
| **stack-probe threshold** | `b8 <size> e8` | **uniform 4096 bytes across ALL versions** (`/Gs` default; verified negative) | ✓ probe9 (`sp1024…8192`) |
| **64-bit compares: direct-memory form** | `3b 44 24 10 … 3b 4c 24 0c` | **MSVC 7.0+** (5.0/6.0 load operands into registers first — 35B; 4.1 uses `39 44`-forms) | ✓ probe10 (`i64lt/eq/ne/ge`) |
| **static-helper inlining at /O2** | (no `call` in the caller) | **MSVC 7.0+** (2.0–6.0 keep the call at /O2 and /O1; 7.0+ inline to 11–12B) | ✓ probe12 (`f1`/`f2`/`fl`) |
| **16-bit switch via `xchg bx,ax`** | `03 c0 93` (`add ax,ax; xchg bx,ax`) | **MSVC 1.5x (16-bit)** (TC 2.0/3.1 and Watcom 16-bit scale via `shl bx,1` — `d1 e3`) | ✓ probe12 (`sw8`) |
| **strlen intrinsic: `repne scasb`** | `f2 ae` (ECX=−1 init) | **MSVC 2.0–6.0 /O2** (7.0+ inline a manual scan loop `8d 50 01 8a 08 84 c9 75 f9 2b c2`; bcc32/Watcom/GCC libcall strlen) | ✓ probe13 (`str_len_lib`) |
| **memcmp 8B intrinsic: `repe cmpsb`** | `f3 a6` | **MSVC 2.0–7.1 /O2** (8.0+ use a dword-compare loop; bcc32/Watcom/GCC libcall memcmp) | ✓ probe13 (`mem_cmp8_lib`) |
| **`and eax,0xff` zero-extension** | `25 ff 00 00 00` / `81 e1 ff 00 00 00` | **MSVC 5.0/6.0 /O2** (2.0/4.x: `xor eax,eax; mov al` — shared with bcc32; 7.0+: `movzx` — shared with GCC/Watcom) | ✓ probe13 (`uc_add`) |
| **default-unsigned `char`** | `char < 0` → `31 c0 c3` (folded to 0) | **Open Watcom** (wcc386 + wcc16; MSVC/GCC/bcc32/TC use signed char) | ✓ probe13 (`c_cmp`) |
| **8-byte struct return via `movsd` pair** | `a5 a5` | **Open Watcom** (MSVC 5.0+ return in EAX:EDX; bcc32 and MSVC 2.0/4.x round-trip the stack) | ✓ probe13 (`s8_make`) |
| **64-byte memcpy = `rep movsd`** | `b9 10 00 00 00 f3 a5` | **MSVC, ALL versions** (GCC register-blocks the copy; bcc32/Watcom libcall; Zig LLVM uses `movups`-pair SSE copies) | ✓ probe14 (`cpy64_lib`) |
| **memory-form `inc dword ptr [g]`** | `ff 05` | **bcc32 at -O2** (MSVC/GCC/Watcom/Zig round-trip through EAX: `a1 … 40 … a3` in the same probe functions; context-dependent — VC5/6 also emit `ff 05` for memory counters in other shapes) | ✓ probe14 (`g_inc`) |
| **64-bit shift helper tail-call** | `b9 <n> 00 00 00 e9` (`mov ecx,N; jmp __allshl/__allshr`) | **MSVC 5.0/6.0** (7.0+ inline `shld`/`shrd` — shared with GCC/bcc32/Zig; Watcom `__I8LS` uses an EBX count) | ✓ probe14 (`i64_shl`/`i64_shr`) |
| **zero-compare: `cmp [mem],1; sbb; neg`** | `83 7c 24 04 01 1b c0 f7 d8` | **MSVC 2.0/4.x + 1.52 (16-bit)** (5.0–7.1: load+`test`; 8.0+: memory compare against the zero register) | ✓ probe14 (`zc_reg`) |
| **`/GS` cookie-mix prologue** | `a1 <cookie> 33 c4 89 44 24 40` (`mov eax,[cookie]; xor eax,esp; store`) | **MSVC 8.0+** — the only probed toolchain with stack cookies (GCC/Zig/bcc32/Watcom emit none) | ✓ probe15 (`pro_gs`) |
| **SSE2 `ucomisd` FP compare** | `66 0f 2f` + `0f 97 c0` | MSVC 11.0 | ✓ probe5 (`fcmp1-4`) |
| **`__fastcall` register fusion `lea eax,[ecx+edx]`** | `8d 04 11` | **MSVC 7.0+** (2.0–6.0: `mov eax,[esp+4]` first) | ✓ probe5 (`fc1`) |
| **`fdivr` for `a/5.0`** | `dc 35`-reverse (`fdivr m64`) | MinGW GCC | ✓ probe5 (`fdiv5`) |
| **8-byte stack alignment in FP functions** | `83 e4 f8` | GCC + MSVC 11.0 (SSE2); never VC 2.0–10.0 | ✓ probe4 (`d2i`) + probe5 (`sq`) |
| **TC 3.1 near long-mul helper** | `call N_LXMUL@` | TC 3.1 (TC 2.0: far `call far ptr LXMUL@`) | ✓ probe6 (`lmul`) |
| **Delphi set-membership `rol`** | `d3 c0` + `85 46` | Delphi 1.0 (`x in s` → `mov ax,1; rol ax,cl; test [mem],ax`) | ✓ probe2.dpr (`setop`) |
| **Delphi `case` = compare chain** | `3d … 75 …` | Delphi 1.0 (no jump table) | ✓ probe2.dpr (`casesel`) |
| **Delphi set/record copy via `rep movsw`** | `fc … c5 76 … b9 04 00 f3 a5` | Delphi 1.0 (`cld; lds si; les di; mov cx,N; rep movsw`) | ✓ probe3.dpr (`setadd`) |
| **no-op `sub esp,4; add esp,4` after `fild`** | `83 ec 04 83 c4 04` | **MSVC 2.0 & 4.x** | ✓ probe4 (`i2d`/`i2f`) |
| `leave` epilogues (16-bit) | `c9` | MSVC 1.x (16-bit) | ✓ probe msvc1.52 (TC 2.0/3.1 never) |
| **`enter` frame setup** | `c8` | **MSVC 1.5x (16-bit)** (TC/Delphi use `push bp;mov bp,sp`) | ✓ probe3 (`c8 02 00 00`) |
| **80-bit `long double`** | `db 6e` (`fld tbyte`) | MSVC 1.5x, TC, bcc32, GCC (32-bit MSVC/Watcom: `fld qword`) | ✓ probe3 (`ldadd`) |
| `ret N` callee cleanup for FP args | `c2 04 00` / `c2 08 00` | Open Watcom wcc386 | ✓ probe |
| Saves caller-saved ECX/EDX in prologue | `51 52` | Open Watcom | ✓ probe (MSVC never) |
| `__CHK` stack probe symbol | `__CHK` | Open Watcom | ✓ OMF fixtures |
| **64-bit helpers `__I8M`/`__I8D`/`__I8LS`** | symbols | Open Watcom | ✓ probe3 (`jmp __I8M`) |
| **`fld qword` for long double** (ld == double) | `dd 44 24` in `ldadd` | MSVC + Watcom only (GCC/Borland use 80-bit `fld tbyte` `db`) | ✓ probe3 (`ldadd`) |
| **`fnstcw; or ah,0xc; fldcw` FP-truncation dance** | `d9 3c 24 … 80 cc … d9 2c 24` | **MinGW GCC** (others call `__ftol`/`__CHP` or `cvttsd2si`) | ✓ probe4 (`d2i`/`d2u`) |
| **`__CHP` FP-conversion helper** | symbol | **Open Watcom** (vs `__ftol` shared by MSVC+Borland) | ✓ probe4 (`d2i_`) |
| GNU `0f 1f` multi-byte nops | `0f 1f` | MinGW GCC / Zig | ✓ probe + corpus |
| `rep ret` return-after-branch | `f3 c3` | MinGW GCC | ✓ corpus (absent in MSVC) |
| **inline 64-bit mul** (no helper call) | `0f af … 0f af … f7 e2` | MinGW GCC | ✓ probe3 (`i64mul`) |
| **`shld`-based 64-bit shifts** | `0f a5 c2` | MinGW GCC | ✓ probe3 (`i64shl`) |
| **`__divdi3` 64-bit division helper** | symbol | MinGW GCC (libgcc) | ✓ probe3 (`i64div`/`u64div`) |
| **cmov at default flags** | `0f 48/4c/4f` | MinGW GCC (i686 default) | ✓ probe3 (`mabs`/`mmax`/`mmin`) |
| **CS-prefixed 8-byte nop** | `2e 8d b4 26 00 00 00 00` | MinGW GCC | ✓ probe3 (O2/O3 padding) |
| **real `div` for every small-constant divisor at all opt levels** | `f7 f1` / `f7 f9` | Borland bcc32 (no magic constants at -O1/-O2) | ✓ probe3 (13+ divisors) |
| **64-bit helpers `__llmul`/`__lldiv`/`__llshl`** | symbols | Borland bcc32 | ✓ probe3 |
| Frame pointer in every function at -O1 | `55 8b ec` | Borland (bcc32 + TCC) | ✓ probe (MSVC /O2, Watcom omit) |
| **Delphi stack-check far call in prologue** | `b8 <size>; 9a` (`lcall`) | Delphi 1.0 (DCC) | ✓ probe3 (dpr) |
| **`leave; ret N` callee-cleanup epilogue** | `c9 c2 N N` | Delphi 1.0 (DCC) | ✓ probe3 (dpr) |

**Service-pack verdicts** (probe5+7+8+9+10 sweeps — the SP1 images probed
for the first time): **VC 7.0 SP1 is the only SP with verified codegen
differences — now SEVENTEEN probe functions.**  (a) 4 structural: the
`==`/`!=` FP family (`fcmp2`/`fc5`/`fc8`/`fc9`) switch from the
two-load `fucompp` (`da e9`) to `fcomp [mem]` (`dc 5c 24 0c`, 2 bytes
shorter).  (b) 2 marshalling: `fl`/`cl` (floor/ceil) pass the FP
libcall argument via `fstp`-temp in RTM vs `push`-pair in SP1.  (c) 11
scheduling/layout: the FP loops `fs1`/`fs2`/`fs3`/`ff1`, the char-array
`cb16`, and all six stack-probe functions `sp1024…sp8192` differ in
register allocation and stack layout (±2 bytes).  The relational
compares, the 64-bit compares and everything else are unchanged.  The
fucompp style is shared by 7.0 RTM, 7.1 (RTM+SP1) and 10.0 (RTM+SP1);
the fcomp style by 2.0–6.0, 8.0 and 9.0.  VC 7.1 SP1, 8.0 SP1, 10.0
SP1: codegen-identical to their RTMs (probes 1–10).  VC 9.0 SP1:
identical to RTM at `/Od`; the `/O1`/`/O2` comparison is **blocked** —
the compiler needs `sched.dll` (C1350) which no image ships (verified
absent from 9.0 RTM, 9.0 SP1, 10.0, 10.0 SP1, 11.0 — the DLL was never
vendored).  VC 6.0 SP1–SP6: codegen-identical to RTM at both `/O1` and
`/O2` (probes 1–10).  VC 5.0 SP1–SP3 ship the same CL.EXE (no distinct
builds to compare).

**Corpus validation** (probe10 round) — every byte-level marker in this
table was scanned against the corpus binaries' `.text`
(win2k-*/bind = VC 5.0, rt63/rt7/skifree32/tcmd = VC 6.0,
cpubench/test_sse2 = MinGW GCC 16).  Strongly confirmed (corpus hits in
the claimed versions): `f3 a6` repe-cmpsd (rt63/rt7/tcmd), `d9 fa`
fsqrt, `dc 0d` reciprocal-fmul, `d9 e8` fld1, `c1 e8 01` 3-byte shift,
`2b d2` div-zero, `0f 1f`/`0f a5 c2`/`83 e4 f8`/`0f 4f`/`0f 4c`/`d9 ee`/
`0f 57 c0`/`f3 0f 7e`/`66 0f d6` in the MinGW binaries.  Markers whose
raw bytes are **context-dependent** (they appear in binaries of versions
outside the claim because the instruction is common — the marker is the
*sequence*, not the bytes): `ff 74 24 10` (push [esp+0x10]), `ff 25`/
`ff 20` (jmp [mem] — IAT jumps), `6a ff`/`6a fe` (push ±1 — SEH frame
vs plain constants), `51 52` (push ecx;push edx), `c2 04 00`/`c2 08 00`
(ret N — stdcall cleanup), `8d 04 11` (lea [ecx+edx]), `6b c0 64`
(imul eax,100).  Two claims get **downgrade notes** from corpus hits in
VC 6.0 binaries: the `cdq`-abs idiom (`99 33 c2 2b c2`, skifree32=1)
and `imul eax,100` (`6b c0 64`, tcmd=1) — both exist in pre-10.0 code
in *some* context, so the marker is the probe *function's* form, not
the raw idiom.

**Proven *non*-markers** (verified negative results, incl. the probe11
flag matrix): **VC 6.0 never emits `cmov` — even under `/G6`** (PPro
target; `imax/imin/clamp/iabs` stay branches; `/G5` vs `/G6` differ
only in instruction scheduling — 7 functions, register-order and
epilogue `pop` placement); VC 7.0 `/G5`≡`/G6` and 7.1 `/G5`≡`/G7`
(identical); `/fp:fast` ≡ default on the probe2 FP set (no contraction
opportunities); the `/arch:SSE2` FP-comparison form (`comisd`) and the
SSE `movq`/`pxor` copy forms are produced by VC 8.0–10.0 under
`/arch:SSE2` — so the VC 11.0-default markers carry the flag caveat
(see the table). the VC 6.0 SP levels
(SP1–SP6) are codegen-identical for every probe3 function — only the
Rich-header C1 build separates them; VC 4.0/4.1/4.2 are codegen-identical
to each other and to VC 2.0; **MSVC 1.0/1.5/1.52 are codegen-identical
for probe4** (probed for the first time); 64-bit mul/div/shift are a
helper call in **every** MSVC version — never inlined (and the helper
*name* is the toolchain marker: `__allmul`/`__alldiv`/`__allshl` MSVC,
`__llmul`/`__lldiv`/`__llshl` Borland, `__I8M`/`__I8D`/`__I8LS` Watcom,
`__divdi3`/`__udivdi3` GCC, inline for GCC mul/shift); no MSVC version
emits `cmov` before VC 11.0 (GCC does at default flags); `memcpy` of
2–16 B inlines as mov pairs and 32–64 B as `rep movsd` in MSVC 2.0–10.0;
**VC 11.0 does NOT return 16-byte structs in XMM0** (builds them in the
hidden return buffer — probe4 `s16b`); **no toolchain emits `fldpi`/
`fldl2e`** for FP constants (all load from `.rdata`); **`bsf`/`bsr` are
never synthesized** from bit-scan loops; the `imul eax,7` for x*7 is
shared by VC 7.0/7.1 and Watcom (not unique — downgraded); the `lea
eax,[eax+eax*2]` for x*3 at /O1 is shared with GCC (not unique);
`__ftol` is shared by MSVC and Borland; Watcom `-otexan` ≡ `-oneatx`
(identical probe3 output); Watcom's 16-bit `wcc` and Turbo C 2.0
cannot compile `#`-preprocessed sources in the current toolchain images
(TC 2.0's wrapper never finds `CPP.EXE` — see
[turbo-c.md](borland/turbo-c.md)).

Explicitly **not** unique (verified or observed): `mov edi,edi` (`8b ff`)
appears as padding in linked VC6+ binaries and as operand noise elsewhere —
not a version marker; `8d 74 26 00` is used by both MSVC6 and GCC as a
3-byte nop; division magic constants are shared between MSVC 5.0+ and GCC
(the surrounding sequence discriminates); `fwait` appears in 16-bit MSVC,
Borland AND Delphi FPU code; the FP-constant *opcode* mix (`fadd` vs `fsub`)
is unique to VC 5.0 but `dc 25` alone is not (plain `fsub m64` appears in
any compiler's subtraction).  The `rol` opcode (`d3 c0`) is shared by
the MSVC 8.0+ rotate idiom and Delphi 1.0's set-membership bit — the
*context* discriminates (32-bit `rol eax,cl` as a shift-pair
replacement vs 16-bit `rol ax,cl` in `x in s`), so neither is a
standalone raw-byte marker.

## Machine-readable corpus — `corpus.json`

[`corpus.json`](corpus.json) is the machine-readable codegen corpus:
**15745 records**, one per (toolchain, version, SP, flags, probe,
function) with `{toolchain, version, sp, flags, probe, function,
size, bytes}` — generated from every probe 1-29 object + the commercial Watcom 10.x line (all 13 MSVC
versions 1.0-11.0 at /O2 and /O1 + all SP images, bcc32, Watcom
32/16, TC 2.0/3.1, MinGW GCC, Zig, the 16-bit MSVC set).  Query
examples:

```python
import json
d = json.load(open("docs/codegen/corpus.json"))
# every version's strlen bytes
[r["version"] + " " + r["bytes"] for r in d["records"]
 if r["function"] == "_str_len_lib" and r["flags"].startswith("/O2")]
```

The generator (`gen_codegen_corpus.py`), schema validator
(`validate_corpus.py`), mechanical sweep (`sweep_corpus.py`) and the
**query CLI** (`corpus_query.py` — `info` / `matrix <func>` /
`unique <ver>` / `diff <v1> <v2>` / `look <hex>`) live in the
gitignored `.cache/fp_probe/` harness.  `matrix`/`diff`/`unique` read
the precomputed **`corpus-matrix.json`** index (532 functions × their
per-version byte groups) for O(1) lookups.  `matrix lcg_next` prints the
per-version byte groups for a function; `look ff 24 85` finds every
record containing a byte pattern.  The corpus also carries Delphi 1.0
records (NE user-code segments, function boundaries inferred at
`ret`/`retf`) and raw-code records for OMF dialects that resist symbol
listing (e.g. the bcc32 C++ object).  Sweep results: the
per-toolchain uniqueness confirmed every hand-documented marker and
surfaced no new cross-toolchain-unique ones; the **SP equivalence is
machine-verified over 2697 SP rows (matching each SP against its RTM
twin by toolchain/version/flags/probe/function)** — the known VC 7.0
SP1 delta set (18 functions incl. probe14's `_s64_ret`) now extends
with probe22's `_arr_counter`/`_struct_counter` (7.0 SP1 emits
`rep stosd` where RTM unrolls the 36B memset — the only probe22 SP
delta; 6.0 SP1–SP6, 7.1 SP1, 8.0 SP1, 10.0 SP1 are byte-identical on
all 26 probe22 functions).  The corpus also surfaced that the
VC 9.0 SP1 "workaround" objects are IA64-typed (see msvc-9.md) —
the 9.0 SP1 comparison remains blocked.

## Verification methodology

Every byte pattern in this folder comes from compiling eleven C89
probes (division, copies, 64-bit, long double, rotates, cmov/SSE2,
switches, FP constants/conversions, multiply chains, memcmp, struct
returns, tail calls, sqrt/fdiv, bit idioms, __fastcall, 16-bit long
arithmetic, SEH, FP loops, bitfields, divmod, stack probes, 64-bit
compares, floor/ceil/fmod, strchr/memchr) plus three Pascal probes
through Delphi 1.0's `DCC.EXE`, and flag-matrix passes (/G5-/G7,
/arch:SSE2/IA32, /fp:fast) — compiled through every toolchain and
disassembling the objects.  Turbo C 2.0 is compiled from a
pre-resolved `#`-free variant (its image's wrapper cannot run the
preprocessor):

| Toolchain | Image / binary | Flags |
|-----------|----------------|-------|
| MSVC 2.0 – 11.0 | `rebrew/msvc:{2.0,4.0,4.1,4.2,5.0,6.0,7.0,7.1,8.0,9.0,10.0,11.0}-win32` | `/O1`, `/O2` |
| MSVC 6.0 SP1–SP6 | `rebrew/msvc:6.0-sp{1..6}-win32` | `/O2` (probe2 SP matrix) |
| MSVC 1.52 | `rebrew/msvc:1.52-win16` (cl16 wrapper) | `/O1` |
| Turbo C 2.0 / 3.1 | `rebrew/borland:{2.0,3.1}-win16` (tcc wrapper) | `-O1` |
| Borland C++ 5.5 | `rebrew/borland:5.5-win32` (bcc32) | `-O1` |
| Open Watcom 2.0 | `rebrew/watcom:2.0-win32` (wcc386 entrypoint) | `-otexan` |
| MinGW GCC 16.1 | `i686-w64-mingw32-gcc` (native) | `-O1`, `-O2` |

Secondary sources: the smoke objects in `.cache/smoke/<profile>/t.obj`
(one trivial `add` per profile, incl. every VC 6.0 SP level), the 16-bit
fixtures `tests/fixtures/tg_msvc16*.obj` / `tg_watcom.o`, and the real
corpus binaries in `../*-rebrew` (win2k-* = VC 5.0, rt63/rt7/skifree32/tcmd
= VC 6.0, cpubench/test_sse2 = MinGW GCC 16).  Disassembly via
`tools/objconv/objconv -fasm` (COFF32 + OMF) and capstone through
`rebrew.matcher.parsers.parse_obj_symbol_bytes`.

**Legend** — a pattern is `✓ verified` when reproduced from the outputs
above; `observed` when seen in a corpus binary but not reproduced from a
controlled compile; `not proven unique` when it also appears (or could
appear) in another compiler's output.  Per-version files cite which source
verified each claim.
