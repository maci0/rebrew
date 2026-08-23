# Decomp Project Idioms — codegen cheat-sheet

For each idiom a decomp project actually matches (probes 19-20): the C
shape, the per-version signature (VC 6.0 /O2 unless noted), and what
to look for in the disassembly.  The machine-readable bytes are in
[corpus.json](corpus.json) (probes 19-20); verified across MSVC
2.0-11.0 at /O2 and /O1 + SPs plus bcc32/Watcom/GCC/Zig and the
16-bit set.  "Version-agnostic" = the idiom cannot fingerprint the
version (useful: it means the shape is reliable regardless of MSVC
era).

## PRNG / LCG

| Idiom | C shape | VC 6.0 /O2 signature | Look for |
|---|---|---|---|
| LCG `*1103515245+12345` | `*s = *s * 1103515245u + 12345u` | `69 c0 6d 4e c6 41 05 39 30 00 00` (`imul eax,eax,0x41c64e6d` + `add eax,0x3039`) | `imul reg,reg,imm32` — **UNIFORM across ALL versions** (matrix-verified); the multiplier in the imm32 is itself the fingerprint |
| LCG `*1664525+1013904223` | `*s = *s * 1664525u + 1013904223u` | `69 c0 0d 66 19 00` + `05 5f f3 6e 3c` (imul + add imm32) | `imul` uniform across ALL versions |
| LCG `*69069+1` | `*s = *s * 69069u + 1u` | `69 c0 cd 0d 01 00` (imul 0x10dcd) | **the only LCG multiplier that decomposes**: VC 2.0-6.0 emit shl/add chains (`8d 04 80 c1 e0 08 2b c1 …`), 7.0+ `imul` — the imul-vs-decompose split is a version fingerprint FOR THIS CONSTANT |

## Fixed-point math

| Idiom | C shape | VC 6.0 /O2 signature | Look for |
|---|---|---|---|
| Fixed multiply `(a*b)>>16` | `(int)(((i64)a * b) >> 16)` | `f7 6c 24 08 b1 10 e9` (imul full product + `mov cl,16` + helper tail) | 5.0-9.0 call a shift helper after `imul edx:eax`; **10.0+ inline `shrd eax,edx,16; sar edx,16` (`0f ac d0 10 c1 fa 10`)** — the inline-vs-helper boundary at 10.0 |
| Fixed divide `(a<<16)/b` | `(int)(((i64)a << 16) / b)` | `99 … 0f a4 ce 10 … e8` (cdq + `shld` + helper call) | `shld` inline shift from 7.0, then a `__alldiv`-family call; no version inlines the division itself |
| Lerp `a+((b-a)*t>>8)` | `a + ((b - a) * t >> 8)` | `2b c1 0f af 44 24 0c c1 f8 08 03 c1` | `sub` + `imul` + `sar 8` + `add` — **uniform across 5.0-11.0** (version-agnostic; common in the wild, guild 33-49×) |

## Tables & indexing

| Idiom | C shape | VC 6.0 /O2 signature | Look for |
|---|---|---|---|
| Trig table `table[(angle>>8)&0xff]` | `table[(angle >> 8) & 0xff]` | `8a 44 24 05 8b 04 81` (byte load of the shifted-out bits + indexed load) | 5.0/6.0 load the byte directly; **7.0/7.1 `shr eax,8; movzx`**; 9.0/10.0 `sar + and`; 11.0 ECX-based — per-version fingerprint |
| 2D index `m[r*16+c]` | `m[r * 16 + c]` | `8b 44 24 08 8b 4c 24 04 c1 e0 04 03 c1 8b 04 88` | `shl`+`add`+indexed load — uniform; **very common in the wild** (guild 33-49×) |
| Clamped table `table[clamp(a,0,31)]` | `if (a<0)a=0; if (a>31)a=31;` | clamp chains (see clamps) | clamp structure first, then the index |

## Control idioms

| Idiom | C shape | VC 6.0 /O2 signature | Look for |
|---|---|---|---|
| Sign `(x>0)-(x<0)` | `(x > 0) - (x < 0)` | `85 c0 0f 9f c1 33 d2 85 c0 0f 9c c2 2b ca` | `setg` + `setl` + `sub` in 5.0-9.0; **10.0+ use `setg` + `sets` (`0f 98`)** — the setl→sets switch at 10.0 fingerprints the version |
| Bounds check `i>=0 && i<n` | `i >= 0 && i < n` | `85 c0 7c 0c 3b 44 24 08 7d 06` | `test`+`jl`+`cmp`+`jge`; **10.0+ use `js` (`78`) for the i>=0 test** — same sign-flag preference as sign() |
| 4-case switch | `switch(id){case 0..3}` | `83 f8 03 77 … ff 24 85 …` | **`cmp eax,N; ja; jmp [eax*4+table]` (`ff 24 85`) — the MSVC dense jump table, uniform across ALL versions** — a reliable "this is MSVC" look-for |
| Hex nibble | the `'0'-'9','a'-'f','A'-'F'` chain | `83 f8 30 7c 09 83 f8 39 7f 04 83 c0 d0 …` | 5.0-7.1 compare-immediate + `add`-adjust; **8.0+ use `lea`-adjusted compares (`8d 48 d0`)** — the 8.0 lea-range-check fingerprint |

## String idioms

| Idiom | C shape | VC 6.0 /O2 signature | Look for |
|---|---|---|---|
| djb2 hash `h*33+c` | `h = h * 33 + c` | `c1 e6 05 03 f0 03 f1` (shl 5 + add + add) | 2.0-6.0 and 8.0+ shl/add; **7.0/7.1 use `imul eax,eax,0x21` (`6b c0 21`)** — the 7.x imul-by-33 fingerprint |
| atoi `v*10+c-'0'` | the digit loop | `8d 04 80 42 … 8d 44 41 d0` (lea ×5 + lea ×2 + lea -48) | `lea [eax+eax*4]` + `lea [ecx+edx*2-48]`-style — version-scheduled but recognizable |
| Whitespace skip | `while (*s==' '||*s=='\t') s++;` | `8a 08 80 f9 20 74 05 80 f9 09 75 03 40 eb f1` | byte compares + `inc eax` loop; **8.0 uses `add eax,1` (`83 c0 01`)** |
| String append | the strlen+copy tail | `80 38 00 … 8a 48 01 40 84 c9 …` | the double-walk loop; 8.0 `add-over-inc` in both increments; 7.0+ `lea esp,[esp]` loop-align |

## Data-structure walks

| Idiom | C shape | VC 6.0 /O2 signature | Look for |
|---|---|---|---|
| Linked-list walk | `while (h){n++; h=h->next;}` | `85 c9 74 07 8b 09 40 85 c9 75 f9` | `test` + `mov ecx,[ecx]` + `inc` — uniform 5.0+ (2.0/4.x `cmp`-based); common in the wild (guild 6-12×) |
| Ring next `(i+1)%size` | `(i + 1) % size` | `40 99 f7 7c 24 08` (inc + cdq + idiv [size]) | variable divisor → real `idiv` in every version (no magic); 8.0 uses `add eax,1` |
| Pool alloc (freelist pop) | `n=p->free; if(n) p->free=n->next;` | `8b 01 85 c0 74 04 8b 10 89 11` | load head + null-test + `mov [ecx],edx` — uniform 2.0-10.0 |

## Rounding & transforms (probe21)

| Idiom | C shape | VC 6.0 /O2 signature | Look for |
|---|---|---|---|
| Round-half-up `(x+0x8000)>>16` | `(x + 0x8000) >> 16` | `8b 44 24 04 05 00 00 80 00 c1 f8 10` | `add reg,0x8000` + `sar 16` — uniform 2.0-8.0 (version-agnostic) |
| Centering `(w-h)>>1` | `(w - h) >> 1` | `8b 44 24 04 2b 44 24 08 d1 f8` | **VC 2.0/4.x encode `sar eax,1` as `c1 f8 01` (3B), 5.0+ as `d1 f8` (2B)** — an era encoding marker |
| 4x4 transform `m[0]*x+m[4]*y+m[8]*z+m[12]` | the multiply-add chain | `8b 41 10 0f af 44 24 0c 8b 51 20 0f af 54 24 10 …` | four `imul` + `add` in per-version order — the chain itself is the look-for |
| AABB overlap `a.x < b.x+b.w && …` | the comparison chain | `8b 02 8b 52 08 03 d0 3b ca …` | add-then-compare pair per axis; 11.0 uses memory-operand compares |

## Dispatch at scale (probe21)

| Idiom | C shape | VC 6.0 /O2 signature | Look for |
|---|---|---|---|
| 8/16-case switch | `switch(id){case 0..7/15}` | `83 f8 07 … ff 24 85` (8-case) / `83 f8 0f 77 67 ff 24 85` (16-case) | **jump table uniform across ALL versions** (confirms the 4-case finding at scale) |
| Function-pointer table | `tbl[id](x)` | `8b 44 24 0c 8b 4c 24 08 8b 54 24 04 50 ff 14 8a` | **5.0-7.1 call the table directly `ff 14 8a`; 8.0+ load `8b 04 8a; ff d0`** — a dispatch-form era marker |

## Byte ops & loops (probe21)

| Idiom | C shape | VC 6.0 /O2 signature | Look for |
|---|---|---|---|
| Byte swap `(v>>8)\|(v<<8)` | the 16-bit swap | `33 c9 8a e8 8a cc …` | 2.0-6.0 byte-move forms; **7.0/7.1/8.0 `movzx`-based (`0f b6 cc`); 9.0+ shift/mask (`c1 f8 08 25 ff 00 00 00 …`)** — three eras |
| Endian fixup (32-bit) | the 4-byte swap | `8a 6c 24 06 … c1 e0 10 …` | byte loads + shift/or per version — recognizable |
| Array update `xs[i]+=vx[i]` | the update loop | `8b 34 01 01 30 83 c0 04 4a 75 f5` | **VC 8.0/9.0 decrement with `83 ea 01` (sub-over-dec); VC 11.0 UNROLLS ×4** (`83 fa 04 72 … lea`-based) |
| tolower char `c>='A'&&c<='Z'` | the range test | `83 f8 41 7c 08 83 f8 5a 7f 03 83 c0 20` | 2.0-7.1 compare-immediate + add; **8.0+ lea-adjusted (`8d 48 bf`)** — same trait as hex_nibble |

## Guild-doc rules (probe22)

| Idiom | C shape | VC 6.0 /O2 signature | Look for |
|---|---|---|---|
| Fused compare-and-negate `(x!=c)?-1:0` | `((x != c) ? -1 : 0) & mask + base` | `8a 44 24 04 2c 0e f6 d8 1b c0 83 e0 7c 83 c0 11` (`sub al,0xe; neg al; sbb eax,eax; and; add`) | **5.0/6.0/8.0 fuse to sub/neg/sbb**; the `-(x!=c)` unary form emits `cmp;setne;neg` (7B larger) — write the ternary to steer.  Guild GetCommandPayloadSize case-0x20 pattern |
| Byte-live switch preamble | `switch (*p)` with a case re-reading `*p` | `8b 44 24 04 8a 00 25 ff 00 00 00 83 c0 fd 83 f8 66 77 … ff 24 85` (`mov al,[eax]; and eax,0xff; add eax,-3; cmp eax,0x66; ja; jmp tbl`) | the and-mask preamble (10B, byte kept live) vs the dead form `xor reg,reg; mov reg_low,[mem]` (4B) — **liveness of the switch byte selects the form** in 5.0/6.0; equal-const-arm ternaries fold and kill liveness, pointer-arm ternaries don't |
| AH-slot flag ops | `if ((*player & 0x6000)) …; *player \|= 0x800;` | `8b 44 24 04 8b 00 f6 c4 60 74 03 80 cc 08 89 01` (`mov eax,[eax]; test ah,0x60; jz; or ah,0x8; mov [eax],eax`) | `test ah,imm` / `or ah,imm` / `or ch,imm` byte-slot ops on `*player` flags — **5.0/6.0 marker** (8.0+ use dword `test eax,imm`); constants must be `(value << 8)`; MinGW GCC emits the same family (`or ah,0x30`) |
| Signed -1 byte compare | `== -1` vs `== 0xff` on `char*`/`unsigned char*` | VC 5.0: `80 ca ff` (`or dl,0xff` hoisted before the length check); 6.0–11.0 `cmp al,0xff` immediates | signed vs unsigned bound compares split `jge`/`jae` in EVERY version; the hoisted `or reg,0xff` constant materialization is a **VC 5.0-only** marker |
| Fresh-alloc clear | `p = alloc(n); memset(p, 0, n);` | `56 8b 74 24 08 57 56 e8 … 8b d0 8b ce 33 c0 8b fa c1 e9 02 f3 ab …` (call + inline rep stosd) | inline-clear-after-alloc in 2.0–7.1; **8.0+ two libcalls**; present in the wild (guild 2–5×, server.dll 5×, pinball 2×) |

## Findings 23-36 shapes (probe23)

| Idiom | C shape | VC 6.0 /O2 signature | Look for |
|---|---|---|---|
| Index-lea `p[i*7]` | `p[i * 7]` | `8b 44 24 08 8b 54 24 04 8d 0c c5 00 00 00 00 2b c8 8b 04 8a` (`lea ecx,[eax*8]; sub ecx,eax`) | **×8−1 lea decomposition in all versions except 7.0/7.1 (`imul ecx,eax,7` `6b c0 07`)** — the imul-by-7 marks a 7.0/7.1 build |
| Index-lea `p[i*24]` | `p[i * 24]` | `8b 44 24 08 8b 4c 24 04 8d 04 40 c1 e0 05 8b 04 08` (`lea eax,[eax+eax*2]; shl eax,5`) | lea*3 + shl5 (6.0-9.0); 10.0/11.0 use lea*3+`add`+×8-SIB; 5.0 double-scales (`lea*3; shl 3` + ×4 SIB); **/O1 2.0/8.0/11.0 use `imul reg,reg,<byte offset>`** |
| Division `/60` magic | `x / 60` | `b8 89 88 88 88 f7 e9 03 d1 c1 fa 05` (mov 0x88888889; imul; add; sar 5) | `0x88888889` = signed /60 (5.0+); `/24` unsigned = `0xaaaaaaab` `mul`+`shr 4` — **the magic constant fingerprints the divisor**; real `idiv` in 2.0/4.1 and at /O1 |
| Branchless if-conversion | `if (x==1) return 0xc; return 8;` | `8a 44 24 04 fe c8 f6 d8 1b c0 24 fc 83 c0 0c` (`dec al; neg al; sbb eax,eax; and al,0xfc; add eax,0xc`) | **5.0/6.0 turn constant-return ifs into the sbb trick**; 7.0+ `sete`+`lea`; 11.0 `cmov`.  **Steering: `r=8; if (x==1) r=0xc; return r;` keeps the branch** (2.0-10.0) |
| Arg-slot reuse | an out-local fitting the dead arg2 slot | `56 8b 74 24 08 8d 44 24 08 50 56 e8 …` (`lea eax,[esp+8]` for `&out`, no `sub esp`) | **5.0/6.0 reuse the dead param slot (no frame)**; 7.0+ `push ecx` frame; a `sub esp,8` frame in the reference suggests a different compiler/context |
| Byte-compare scan | `while (*p != 6) p++;` | 8.0: `80 38 06 74 0f … 83 c0 01 80 38 06 75 f8` (memory compare + add-over-inc) | memory-operand `cmp byte [mem],N` loops from 8.0; a named `t` temp switches to register compares (`cmp al,6`) — both forms appear in the wild (guild 29-53×) |

## Findings 37-43 primitives (probe24)

| Idiom | C shape | VC 6.0 /O2 signature | Look for |
|---|---|---|---|
| Word zero-extend `*p` (ushort) | `return *p;` on `unsigned short*` | `8b 4c 24 04 33 c0 66 8b 01` (`xor eax,eax; mov ax,[ecx]`) | **4.1–6.0 the `xor;mov r16` form; 7.0+ `movzx` (`0f b7 00`); 2.0 `and eax,0xffff`** — the 16-bit twin of the C4 char eras; the doc's MSVC6 form is in the guild binary (2×) |
| Word param mask | `unsigned short a + b` | `8b 44 24 04 8b 4c 24 08 25 ff ff 00 00 81 e1 ff ff 00 00 03 c1` | `and reg,0xffff` pairs in 2.0–6.0; `movzx` pair from 7.0 |
| Size dispatch `switch(size){1,2,4}` | the 3-way size copy | `8b 44 24 0c 48 74 31 48 74 1a 83 e8 02 74 03 33 c0 …` (`dec; jz; dec; jz; sub 2; jz`) | **dec-chain, never a jump table** — 5.0–7.1/10.0/11.0 `48 74`; 8.0/9.0 `83 e8 01` sub-chain; 2.0/4.1 `cmp`-chain |
| In-place memory and | `*p &= m;` (short) | `8b 44 24 04 66 8b 4c 24 08 66 21 08` (`and word ptr [eax],ax`) | **memory-operand `and word [mem],reg` in EVERY version** — the size2 in-place form is uniform |
| Word compare chain | `*cmd == 0x2a \|\| *cmd == 0x116` | `8b 44 24 04 66 8b 00 66 3d 2a 00 74 09 66 3d 16 01 74 03 …` | 2.0–7.1 raw word load + 16-bit `cmp ax,imm`; **8.0+ `movzx` + `cmp ax`** |
| Byte or-mask store | `*p \|= ~base[0x20];` | 8.0: `8a 48 20 8b 44 24 04 f6 d1 08 08 0f be 00` (memory-operand `or byte [eax],cl`) | **8.0+ memory-operand byte or; 5.0–7.1 byte-register round-trip** (`mov dl,[p]; or dl,cl; mov [p],dl`) |
| In-place double add | `*x += *y;` | `8b 44 24 04 8b 4c 24 08 dd 00 dc 01 dd 18` (`fld [x]; fadd [y]; fstp [x]`) | 5.0–10.0 fld/fadd/fstp (load order varies by era); **11.0 SSE `movsd; addsd; movsd`** |

## Finding 44 primitives (probe25)

| Idiom | C shape | VC 6.0 /O2 signature | Look for |
|---|---|---|---|
| Nonnegative clamp `(x<=0)?0:x` | the ternary clamp | `8b 44 24 04 33 c9 85 c0 0f 9e c1 49 23 c1` (`test; setle cl; neg ecx; and eax,ecx`) | **branchless in 5.0-7.1/9.0/10.0; 2.0/4.1 branchy (`test; jg; xor`); 8.0 `setle; sub ecx,1`; 11.0 `cmovle`** — clamps are everywhere (guild 1×, sndrec32 1×) |
| ×589 multiply | `x * 589` | `8b 4c 24 04 8d 04 49 c1 e0 04 03 c1 8d 04 40 8d 04 81` (5-instruction lea chain) | **2.0/4.1 four-lea chain; 5.0/6.0 five-instruction lea chain; 7.0+ single `imul eax,eax,0x24d`** — the imul-vs-lea-chain split fingerprints the era |
| Byte-arg raw push | `callee(v, s->a, s->b)` with `unsigned char b` | `8b 44 24 04 8a 48 04 8b 10 8b 44 24 08 51 52 50 …` (`mov al,[ecx+4]; push eax` — raw, no extension) | **2.0–6.0 push the raw byte slot; 7.0/7.1 zero-extend (`xor;mov cl`); 8.0+ `movzx`** — the doc's "raw push is unreproducible" claim only holds under register pressure |
| Byte+dword sum | `*(uchar*)(r+0xc) + *(int*)(a+0x13)` | `8b 4c 24 04 8b 54 24 08 33 c0 8a 41 0c 8b 4a 4c 03 c1` (byte loaded first) | the byte loads FIRST in every version (movzx + memory-add from 7.0) |

## Finding 45 primitives (probe26)

| Idiom | C shape | VC 6.0 /O2 signature | Look for |
|---|---|---|---|
| Inline early-return blocks | `if (a) return -3; if (b) return -6; …` | `8b 4c 24 04 85 c9 75 06 b8 fd ff ff ff c3 8b 44 24 08 85 c0 75 06 b8 fa ff ff ff c3 03 c1` (`test; jne +6; mov eax,-3; ret` ×2) | **every MSVC version inlines the early-return block right after its check** (`jne` skips it) — the guild doc's Finding 45 tail-grouping is a register-pressure artifact; this is the default shape in the wild (guild 2-19×, server.dll 4×) |
| Shared -1 epilogue | `… return -1;` tail | `83 c8 ff` (`or eax,-1`) | the B5 register form from 5.0 (2.0/4.1 `mov eax,-1`); 11.0 materializes small negative constants via `lea eax,[reg-N]` |

## Findings 46-50 primitives (probe27)

| Idiom | C shape | VC 6.0 /O2 signature | Look for |
|---|---|---|---|
| Shared fail epilogue | `if (a<0\|\|a>100) return 0; if (b==0) return 0; …` | `85 c0 7c 1c 83 f8 64 7f 17 … 33 c0 c3` (all fail checks jump FORWARD to one `xor eax,eax; ret`) | **same-constant fail paths merge into one tail in EVERY version** — distinct constants inline (F25), same constants merge; the reference's Finding 46 shape IS the MSVC default (guild 6×) |
| Callee-save entry push | guards + callee-save use after | `56 8b 74 24 08 33 c0 85 f6 7d 05 83 c8 ff 5e c3 …` (`push esi` at entry; fail paths `mov eax,-1; pop esi; ret`) | **push at entry + fail-path pop in every version** — no deferral past guards in the simple shape (the doc's F48 region-split is context-specific) |
| Fill-loop counter | `for (i=0;i<n;i++) p[i]=f();` | `57 … 56 … 6a 40 e8 … 89 06 83 c6 04 4f 75 eb` (running pointer + `dec edi; jne` countdown) | **counter KEPT (countdown) in every version** — the F49/F50 elimination needs the nested 768x768 context; 8.0/9.0 add-over-inc + sub-over-dec on the pair |
| Byte-slot or `\|=0x1000` | `*p \|= 0x1000;` | `8b 44 24 04 8b 08 80 cd 10 89 08` (`or ch,0x10`) | **5.0/6.0-only byte-slot or** (the doc's `or dh,0x10`); 2.0/4.1 `or eax,0x1000` imm; 7.0/7.1 `or ecx,imm`; 8.0+ memory `or dword [mem],imm` |

## Decompedia / CODEGEN_PATTERNS claims (probe28)

| Idiom | C shape | VC 6.0 /O2 signature | Look for |
|---|---|---|---|
| FP-const add | `a + 1.0` | `dd 44 24 04 dc 05 00 00 00 00` (`fld [a]; fadd qword [+1.0]`) | **VC 5.0 is the odd one out: `fsub qword [−1.0]` (`dc 25`) with the NEGATED constant in .rdata** — a 5.0-only marker; 2.0/4.x `fld1`+fadd; 6.0-10.0 fadd; 11.0 SSE |
| `<= 0` vs `< 1` | `x <= 0` vs `x < 1` | `85 c9 0f 9e c0` (test; setle, 2B test) vs `83 f9 01 0f 9c c0` (cmp 1; setl, 3B cmp) | **5.0-7.1: the exact-constant form is 1 byte shorter** — steerable from C (write `<= 0`, not `< 1`) |
| Return-width | `short f() { return 5; }` | 2.0-8.0: `66 b8 05 00` (`mov ax,5`, 4B); 9.0+: `b8 05 00 00 00` (`mov eax,5`, 5B) | **short-return width changes at 9.0** (char returns `mov al,N` in every version) |
| `x == -1` compare | `if (x==-1) return -1;` | `83 f9 ff 0f 95 c0 48` (`cmp; setne al; neg eax`) | **5.0-11.0 setne+neg (both the if-form and `(x!=-1)-1`)**; 2.0/4.1 inc/sbb family — the CODEGEN_PATTERNS "inc/neg/sbb 7B" claim only holds for 2.0/4.1-era shapes |

## Verified negatives (in these binaries)

The exact VC 6.0 /O2 signatures for `atoi_like`, `checksum`, `clamp8`,
`clip_rect`, `fixed_div`, `fixed_mul`, `hex_nibble`, the three LCGs,
`pool_alloc`, `ring_next` and `str_cat` do **not** appear in the
rebrew-projects win2k set or guild's server.dll (either the idiom is
unused there or the surrounding context changes the bytes) — recorded
as corpus validation negatives, not claims of absence elsewhere.

## Validation summary (idiom_sweep.py, VC 6.0 /O2 signatures × 26 binaries)

- Present in the wild: `array2d` (guild 33-49×/EXE, 8 win2k binaries),
  `lerp` (33-49×, 8 win2k), `bit_pack` (34-41×, 5 win2k),
  `ll_walk` (6-12× guild), `in_bounds` (5-6× guild), `dist_sq`
  (2-12× guild, pinball), `cmd_dispatch` (pinball 4×), `sign`
  (guild 1×, sndrec32), `skip_ws` (mspaint 1×).
- Context note: short signatures (`array2d`/`lerp` share a common
  `8b 44 24 08 8b 4c 24 04` prefix) inflate hit counts — treat hits as
  "the shape class appears", not exact-function matches.
- Probe21 additions: `center` (guild 29-53×/EXE + 8 win2k), `fptable`
  (guild 34-41× + 5 win2k), `aabb_x` (guild 5-7× + 4 win2k),
  `bswap16`/`endian32` (guild 4-5×) all appear in the wild — the
  centering, function-pointer-table, AABB and endian idioms are real
  decomp targets.
- Probe22 additions: `ah_hi` (the `*player & 0x6000` shape, guild 1×),
  `clear_fresh` (fresh-alloc inline clear — guild 2-5× + server.dll 5× +
  pinball 2×), `clear_opaque` (inline rep-stosd memset, guild 1×),
  `byte_dead`/`byte_live2`/`fold_dead`/`f17_switch_dead` (the xor-form
  zero-extend byte loads, guild 1-2×) and `negidm1` (the setne-neg
  form, guild 1×) all hit; the `uc_add` and-form (`and eax,0xff`) is the
  single most common guild marker (29-53×).  **Negatives**: the exact
  fused `negidm2` bytes, the `test ah,0x60` flag-preamble, the
  wide-range live `f17_switch` and the an1/an2 length-check shapes do
  not appear byte-exact in the scanned set (the guild originals use the
  register-role variants the doc describes) — recorded as validation
  negatives, not absence claims.
- Probe23 additions: `argslot` (the 5.0/6.0 dead-arg-slot reuse, guild
  1-3×), `idx7` (the lea-×8−1 index form, guild 9-21×), `idx3/5/12/24`
  + `lea_load` (guild 33-49× — shared prefix with the array2d/lerp
  family, counts inflated), `scan_rot` (byte-scan loop, guild 29-53×),
  `udiv24` (the `0xaaaaaaab` /24 magic — guild 5-7× + server.dll 2×)
  and `zeropush` (guild 34-41×) all hit.  **Negatives**: `ifconv1`
  (the sbb-trick exact bytes), `div60`, `bytecmp1/2`, `addfold`,
  `sib_scan` and `fpu_clamp` do not appear byte-exact — the guild
  originals' register dances differ from the probe forms; recorded as
  validation negatives.
- Probe24 additions: `wze`/`wze2` (the **5.0/6.0 `xor;mov ax` word
  zero-extend — the doc's MSVC6 form is in the guild binary, 2×**),
  `wze3` (`and eax,0xffff` cast, guild 5-6×), `wcmp` (word compare
  chain, guild 2× + server.dll 1×), `fadd_ip2` (float add, guild
  1-4×) all hit; the `bmask1/2`, `fadd_ip`, `fstore`, `idx_chain` and
  `wze_add` signatures share the common `8b 44 24 04`-family prefix
  (counts inflated, 29-53×).  **Negatives**: `sz_disp` (the dec-chain
  exact bytes), `wand`, `bmask3` and the field-store fold do not appear
  byte-exact in the scanned set — recorded as validation negatives.
- Probe27 additions: `fail_epi` (the shared fail epilogue — guild 6×/5×),
  `callee_defer` (entry-push + fail-pop — guild 1-4× + explorer 1× +
  winmine 1×), `fill_iv` (countdown fill loop — TL 1× + np_recompiled
  1×) and `or_100000` (mspaint 1× + wordpad 1×) all hit.  **Negatives**:
  `or_1000` (the 5.0/6.0 byte-slot or) and `fill_nested` do not appear
  byte-exact in the scanned set — recorded as validation negatives.
- Probe28 additions (decompedia DP + CODEGEN_PATTERNS sources): `cmp_ge1`/
  `cmp_lt1` (guild 6-8× + server.dll 1× + pinball 2×), `cmp_gt0`/
  `cmp_le0` (guild 6-12×), `m1idiom`/`m1alt` (the setne+neg -1 compare —
  guild 6-8× + server.dll 1×), `fp4` (float const form — guild 3×),
  `ret_int` (guild 8×) and `rot3`/`rot16` (shift-pair — TL 3×) all
  hit.  **Negatives**: `fp1`/`fp2`/`fp3` (the fadd/fsub const forms —
  the rel32 const address differs per binary, so byte-exact misses)
  and `ret_char`/`ret_short` are not byte-exact in the scanned set —
  recorded as validation negatives.
- Probe26 additions: `er1` (the inline early-return signature — guild
  2× + CLIPBRD 1×), `er2`/`er4` (guild 14-19× + server.dll 4×) all
  hit — the inline early-return placement is the default shape in the
  wild.  **Negative**: `er3` (the `jns`-based variant) does not appear
  byte-exact — recorded as a validation negative.
- Probe25 additions: `clamp_le0`/`clamp_lt0`/`clamp_gt0` (the branchless
  setle clamp — guild 1× + sndrec32 1×), `mul589`/`mul589u` (the
  5.0/6.0 lea-chain form — guild 2×), `sum_load` (byte-first sum —
  guild 11-18× + server.dll 1×) and `bpush`/`bpush2` (34-41×, shared
  prefix inflated) all hit.  **Negatives**: `bpush3` (the memory-source
  raw-byte push exact bytes) and the 7.0+ `imul` ×589 form do not
  appear byte-exact in the scanned set — recorded as validation
  negatives.
