# Rebrew Tooling Improvement Ideas

Ideas collected during hands-on workflow testing, prioritized by impact.

---

## Prioritized Ideas

| # | Idea | Impact | Effort | Priority |
|---|------|--------|--------|----------|
| 1 | [CRT source cross-reference tool](#1-crt-source-cross-reference-tool) | High | Medium | **P0** |
| 2 | [Register-aware diff mode](#2-register-aware-diff-mode) | High | Medium | **P1** |
| 3 | [Auto-classify MATCHING blockers](#3-auto-classify-matching-blockers) | High | Medium | **P1** |
| 4 | [Verify summary with STATUS breakdown](#4-verify-summary-with-status-breakdown) | High | Low | **P1** |
| 5 | [GA code layout mutations](#5-ga-code-layout-mutations) | Medium | High | **P2** |
| 6 | [Fix diff relocation marking](#6-fix-diff-relocation-marking) | Medium | Low | **P2** |
| 7 | [Batch flag sweep mode](#7-batch-flag-sweep-mode) | Medium | Medium | **P2** |
| 8 | [Auto-detect ASM-origin CRT functions](#8-auto-detect-asm-origin-crt-functions) | Medium | Low | **P2** |
| 9 | [Structural similarity metric](#9-structural-similarity-metric) | Low | Medium | **P3** |
| 10 | [Targeted flag sweep tier](#10-targeted-flag-sweep-tier) | Low | Low | **P3** |
| 11 | [Similarity-based prioritization in rebrew-next](#11-similarity-based-prioritization-in-rebrew-next) | Low | Medium | **P3** |
| 12 | [Callee-save register injection](#12-callee-save-register-injection) | High | High | **P3** |

---

## Idea Details

### 1. CRT source cross-reference tool

**Pain**: Identifying which CRT source file a function came from requires manual search through `tools/MSVC600/VC98/CRT/SRC/`. Many MSVCRT STUBs (85-200B) are verbatim copies of reference source.

**Proposed**: `rebrew-crt-match 0xVA` — given a VA, search the MSVC6 CRT source for likely matches based on function size, call graph, and string references. Rank candidates by similarity. A bulk mode could auto-match against all known CRT implementations.

**Impact**: Automating the lookup saves significant manual research time on ~100 MSVCRT-origin functions.

### 2. Register-aware diff mode

**Pain**: Register allocation is the dominant systemic blocker for all remaining GAME functions. MSVC6's register allocator assigns callee-save registers differently, and no C source transformation or GA mutation can fix this. The current diff conflates register encoding differences with real structural differences.

**Proposed**: A diff mode that ignores register encoding (treating `[edx+0xc]` the same as `[ecx+0xc]`) to show "semantic" structural diffs separate from register allocation diffs.

**Impact**: Helps identify which remaining diffs are actually fixable from C source vs permanently stuck on register allocation.

### 3. Auto-classify MATCHING blockers

**Pain**: Categorizing blockers manually is tedious. Common categories include: register allocation (ebx/edi swaps), loop rotation, instruction folding (lea+mov to single mov with SIB), zero-extend patterns (xor+mov dl vs bare mov dl), stack frame choice (push ecx vs sub esp,8), and comparison direction swaps.

**Proposed**: `rebrew-blocker-report` — reads diffs and auto-tags the blocker type per function. Batch-identifies which functions are genuinely improvable vs permanently stuck.

**Impact**: Enables data-driven decisions about where to spend effort.

### 4. Verify summary with STATUS breakdown

**Pain**: `rebrew-verify` output doesn't show STATUS per function or byte match percentages, making progress tracking difficult at a glance.

**Proposed**: `rebrew-verify --summary` showing a table with EXACT/RELOC/MATCHING (by delta range: 0B, 1-5B, 6-20B, 21+B)/STUB counts, plus byte match percentage per function (e.g., "MATCHING 274/297B (92%)").

**Impact**: Single-command progress overview.

### 5. GA code layout mutations

**Pain**: GA mutations focus on C source mutations, but most close MATCHING blockers are register allocation issues that C changes can't fix. The mutations that actually affect codegen are structural.

**Proposed**: A "code layout" mutation type that tries different if/else orderings, goto vs inline returns, nested vs flat conditionals, and do-while vs while loops.

**Impact**: Targets the mutations that actually affect codegen structure.

### 6. Fix diff relocation marking

**Pain**: The diff tool marks some relocation-only differences as `**` (structural) when the only difference is an immediate address value (e.g., `lea ecx, [eax*4 + 0x100358a0]` vs `lea ecx, [eax*4]`). These should be marked `~~` instead.

**Proposed**: Improve the relocation normalizer to handle SIB+disp32 addressing modes and other indirect address patterns.

**Impact**: Reduces noise in diff output, fewer false "structural" differences.

### 7. Batch flag sweep mode

**Pain**: Running `rebrew-match --flag-sweep-only` on all MATCHING functions sequentially is slow. The GA is CPU-intensive but embarrassingly parallel.

**Proposed**: A batch flag sweep mode that parallelizes across functions with priority queuing (smallest delta first).

**Impact**: Faster turnaround on systematic flag exploration.

### 8. Auto-detect ASM-origin CRT functions

**Pain**: Many CRT STUB functions use hand-written assembly (`strpbrk`, `strcspn`, `strlen` use BTS/BT, `repne scasb`, etc.) that C can never produce. Time is wasted attempting to match these.

**Proposed**: Auto-detect and mark as `ASM_ORIGIN` based on instruction pattern analysis. Note: `rebrew-next` already filters IAT thunks, single-byte stubs, and SEH handlers — this extends that to ASM-origin CRT.

**Impact**: Prevents wasted effort on inherently unmatchable functions.

### 9. Structural similarity metric

**Pain**: Flag sweep shows identical scores across all combinations for most functions, suggesting differences are structural rather than flag-related, but there's no metric to confirm this.

**Proposed**: Add a "structural similarity" metric alongside the score to distinguish when flags won't help vs when they might.

**Impact**: Saves time by quickly ruling out flag-based solutions.

### 10. Targeted flag sweep tier

**Pain**: The "quick" tier (192 combos) is fast but never finds anything different from default flags.

**Proposed**: A "targeted" tier that only varies flags known to affect codegen structure (`/Oy`, `/Op`, frame pointer flags).

**Impact**: More focused flag exploration between "quick" and "normal" tiers.

### 11. Similarity-based prioritization in rebrew-next

**Pain**: Functions that share code patterns with already-matched functions would be easier to reverse, but `rebrew-next` doesn't account for this.

**Proposed**: Prioritize by similarity to already-matched functions (shared call targets, similar size/structure).

**Impact**: Better work ordering for snowball effect.

### 12. Callee-save register injection

**Pain**: The target binary often pushes 4 callee-saves (ebx, ebp, esi, edi) and uses ebp=0 throughout the function. The compiler never generates this pattern because it doesn't see enough register pressure.

**Proposed**: Inject specific callee-save register patterns (e.g., force ebp allocation via inline assembly prologue/epilogue) to match the target's register usage.

**Impact**: Could unlock many MATCHING to RELOC transitions, but highly experimental.

---

## Observations (Reference Knowledge)

Patterns and insights from RE work — not actionable tool ideas, but useful context.

### Close MATCHING analysis (0-3B delta)

GA mutations (100 gen, pop 30) consistently fail to improve close MATCHING functions. Tested on multiple functions (69-74B range). All blockers are compiler-internal decisions that C source mutations cannot influence.

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
