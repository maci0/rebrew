# Function Status Reference

All function statuses are stored in the `rebrew-function.toml` metadata, keyed by hex VA.
The `.c` file contains only the stable `// FUNCTION: MODULE 0xVA` marker line.

## Status Overview

```
UNDOCUMENTED  →  STUB  →  NEAR_MATCHING  →  RELOC  →  EXACT
                                  ↓
                               PROVEN (from NEAR_MATCHING via rebrew prove)
                               SKIP   (parallel track — intentionally unmatchable)
```

| Status | Byte match | Set by | Counts in coverage |
|--------|-----------|--------|-------------------|
| `UNDOCUMENTED` | — | Automatic (no .c file) | ❌ No |
| `STUB` | <60% | `rebrew test` (demotion) | ❌ No |
| `NEAR_MATCHING` | ≥60% | `rebrew test` | ⚠️ Partial |
| `RELOC` | 100% (masked) | `rebrew test` | ✅ Yes |
| `EXACT` | 100% (raw) | `rebrew test` | ✅ Yes |
| `PROVEN` | Semantic | `rebrew prove` | ✅ Yes |
| `SKIP` | N/A | Manual (metadata) | ✅ Yes (excluded) |

---

## UNDOCUMENTED

Function exists in `function_structure.json` but no `.c` file has been created yet.
This is the implicit starting state — rebrew tracks it from the function list, not the
metadata. Tools like `rebrew todo` surface these as action items.

```bash
rebrew todo --json          # find next UNDOCUMENTED function to start
rebrew skeleton 0x10008880  # generate .c skeleton → transitions to STUB
```

No metadata entry exists yet. Coverage dashboard shows these as "untouched".

---

## STUB

A `.c` file exists but the implementation is a placeholder — either empty, contains
`TODO`, or compiles to something radically different from the target (< 60% byte match,
or wrong size).

Also assigned automatically by `rebrew test` when a previously-matching function
regresses below the 60% match threshold (demotion).

```toml
["SERVER.0x10008880"]
status = "STUB"
size = 163
blocker = "needs complete rewrite from scratch, 199B target vs 163B compiled"
```

Common causes: LLM-generated skeleton that doesn't match, missing CRT internals,
wrong calling convention, completely wrong algorithm structure.

---

## NEAR_MATCHING

The compiled output is ≥ 60% byte-similar to the target but has structural differences
that persist after relocation masking — different register allocation, different loop
structure, different branch ordering.

`rebrew match --fix-blocker` auto-classifies the difference type and writes it to the metadata:

```toml
["SERVER.0x10008880"]
status = "NEAR_MATCHING"
size = 130
blocker = "register allocation (esi/edi swap)"
blocker_delta = 7
```

Common blockers: register allocation, loop peeling, branch inversion, code block
reordering, stack frame choice, operand swaps, small byte deltas.

**Next steps**: Iterate code structure, or run `rebrew match` (GA engine) to explore
permutations. For near-miss cases (small delta), try `rebrew match --all --near-miss`.
Strong candidates for `rebrew prove` when the delta is very small.

---

## RELOC

Identical after masking relocatable bytes (`call rel32`, `jmp rel32`, `mov eax,[abs32]`,
etc.). The function's logic, register allocation, and control flow are all correct.
Only call targets and global addresses differ, which is expected — the linker patches
these at link time.

```
Target:  50 e8 f0 83 00 00 8b f8 83 c4 04 a1 80 58 03 10
Output:  50 e8 00 00 00 00 8b f8 83 c4 04 a1 00 00 00 00
         == ~~ ~~ ~~ ~~ ~~ == == == == == ~~ ~~ ~~ ~~ ~~
```

This is the **typical best result** for functions that call other functions or reference
globals. Counts as complete in the project coverage metrics.

```toml
["SERVER.0x10008880"]
status = "RELOC"
size = 42
```

---

## EXACT

Byte-for-byte identical. Every single byte in the compiled `.obj` matches the target
bytes extracted from the DLL.

```
Target:  53 8b 5c 24 08 56 57 8b 43 10 50 e8 f0 83 00 00
Output:  53 8b 5c 24 08 56 57 8b 43 10 50 e8 f0 83 00 00
         == == == == == == == == == == == == == == == ==
```

Rare in practice for functions with external calls (since call offsets are
linker-dependent). Common for leaf functions with no calls or global refs.

```toml
["SERVER.0x10008880"]
status = "EXACT"
size = 31
```

---

## PROVEN

Semantically equivalent — mathematically verified by `rebrew prove` via angr
symbolic execution + Z3 constraint solving. The compiled bytes differ structurally
(different register allocation, instruction reordering, loop unrolling), but for **all
possible inputs**, the return value and observable side-effects are identical.

Used when a function is stuck on NEAR_MATCHING due to compiler jitter that can't be
resolved by flag sweeps or code restructuring.

```toml
["SERVER.0x10008880"]
status = "PROVEN"
size = 142
```

```bash
rebrew prove src/target/calculate_physics.c   # runs angr + Z3, ~15-60s
```

Counts as complete. Holds the same weight as EXACT or RELOC in coverage metrics.

---

## SKIP

Intentionally excluded from matching. Used for functions that are known to be
unmatchable or irrelevant to the decompilation effort:

| Reason | Examples |
|--------|---------|
| IAT thunks | `jmp [__imp_GetProcAddress]` — compiler-generated, no source |
| SEH helpers | `__except_handler3`, `__local_unwind2` — MSVC runtime internals |
| ASM builtins | `_memcpy_rep`, `_strlen_sse2` — hand-written assembly |
| Import stubs | Trampolines to DLL imports with no game logic |
| Padding / alignment | Dead bytes between functions, never executed |
| Linker-generated | `__security_cookie_check`, `__SEH_prolog` |

```toml
["SERVER.0x10001234"]
status = "SKIP"
skip_reason = "IAT thunk — jmp [__imp_CreateFileA]"
```

SKIP functions are excluded from the "unmatched" count in coverage metrics — they
are treated as intentionally resolved, not as open work items.

```bash
rebrew todo --json    # surface likely SKIP candidates
```

---

## How rebrew test Classifies Results

```mermaid
flowchart TD
    A[Compile C to .obj] --> B[Extract obj bytes]
    B --> C[Extract target bytes from DLL]
    C --> D{target == output?}
    D -- Yes --> E[EXACT]
    D -- No --> F[Mask relocation bytes]
    F --> G{masked target == masked output?}
    G -- Yes --> H[RELOC]
    G -- No --> I[Compute similarity score]
    I --> J{score >= 60%?}
    J -- Yes --> K[NEAR_MATCHING]
    J -- No --> L[STUB demotion]
```

```text
1. Compile .c file to .obj with MSVC6 under Wine
2. Extract symbol bytes from .obj (COFF parser)
3. Extract target bytes from DLL at the given VA
4. Compare:
   a. target_bytes == output_bytes               → EXACT
   b. masked_target == masked_output             → RELOC
   c. similarity >= 60%                          → NEAR_MATCHING
   d. similarity < 60% or wrong size             → STUB (demotion)
```

## Relocation Masking Details

The normalizer (`_normalize_reloc_x86_32`) walks the x86 instruction stream and zeros
out bytes that are expected to differ between compilations:

| Pattern | Opcode | Bytes zeroed | Why |
|---------|--------|-------------|-----|
| `call rel32` | `E8` | bytes 1-4 | Call target is a relative offset from current IP |
| `jmp rel32` | `E9` | bytes 1-4 | Jump target is a relative offset |
| `mov eax, [moffs32]` | `A1` | bytes 1-4 | Absolute address of a global variable |
| `cmp [abs32], imm8` | `83 3D` | bytes 2-5 | Address of global in comparison |
| Conditional jumps near | `0F 8x` | bytes 2-5 | 32-bit relative offsets in Jcc instructions |
| `push imm32` | `68` | bytes 1-4 | Only when value looks like an address (> 0x10000000) |
| `mov reg, imm32` | `B8`-`BF` | bytes 1-4 | Only when value looks like an address |
| `mov reg, [abs32]` | `8B 0D/15/1D/25/2D/35/3D` | bytes 2-5 | Global variable loads |
| `mov [abs32], reg` | `89 0D/15/1D/25/2D/35/3D` | bytes 2-5 | Global variable stores |

After masking, if the bytes are identical, the code is structurally the same — only the
linker-dependent addresses differ. This is the RELOC match.

---

## Observed NEAR_MATCHING Patterns

Patterns and insights from hands-on RE work — not actionable tool ideas, but reference
knowledge about what actually blocks byte-level matching in practice.

### Close NEAR_MATCHING analysis (0-3B delta)

GA mutations (100 gen, pop 30) consistently fail to improve close NEAR_MATCHING functions. All blockers are compiler-internal decisions that C source mutations cannot influence.

Common uncontrollable blocker categories:
1. **Register allocation** — ebx vs edi, eax vs ecx swaps (most common)
2. **Loop rotation** — compiler peels first iteration or uses jge+jmp vs jl
3. **Instruction folding** — lea+mov to single mov with SIB, saves 2B
4. **Zero-extend patterns** — xor+mov dl vs bare mov dl for byte params
5. **Stack frame choice** — push ecx vs sub esp,8 for locals
6. **Comparison direction swap** — cmp eax,ecx/jae vs cmp ecx,eax/jbe

### Register allocation as systemic ceiling

Register allocation is the primary systemic blocker for ALL remaining GAME functions. With `/O2 /Gd` (frame pointer omission), the compiler may use ebp as a callee-save register, but only if there's enough register pressure. If C source doesn't create enough demand, the compiler won't allocate ebp, producing fewer push/pop instructions and different register assignments throughout.

### Dependency chains limit matchable scope

Dependency chains make many CRT functions permanently unreachable:
- `memmove` (hand-written ASM) blocks `fread`, `fwrite`
- SEH functions block `_stricmp`, `_strnicmp`
- `strcat` (hand-written ASM) blocks downstream functions
- `FreeHeapBlockWithRuntimeLock` (SEH) blocks ~33 other functions

These form a "dependency ceiling" that limits what can be matched regardless of tooling.

### STUB conversion notes

- Remaining GAME STUBs range from 355B to 6000B+. Even small ones (under 400B) face register pressure challenges with `/O2 /Gd`.
- MSVCRT STUBs range from 11B to 1825B. Many small ones (85-200B) may be achievable using reference CRT source.
- Verifying string literals via hex dump is critical — Ghidra often gets string references wrong.
- Dead assignments in STUBs are common — Ghidra generates reads for values the target code never uses.
- Entity records are 65 bytes — MSVC6 decomposes `*65` as `shl eax, 6; add eax, base; add eax, index`.
- CRT `_mbctype` access: `_mbctype[(unsigned char)c + 1] & 4` compiles to `test byte ptr [reg + 0x11766321], 4` — the +1 offset is baked into the immediate address.
