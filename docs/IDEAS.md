# Rebrew Tooling Improvement Ideas

Ideas collected during hands-on workflow testing, prioritized by impact.

---

## Prioritized Ideas

| # | Idea | Impact | Effort | Priority |
|---|------|--------|--------|----------|
| 1 | [CRT source cross-reference tool](#1-crt-source-cross-reference-tool) | High | Medium | **P0** |
| 5 | [GA code layout mutations](#5-ga-code-layout-mutations) | Medium | High | **P2** |
| 7 | [Batch flag sweep mode](#7-batch-flag-sweep-mode) | Medium | Medium | **P2** |
| 11 | [Similarity-based prioritization in rebrew next](#11-similarity-based-prioritization-in-rebrew-next) | Low | Medium | **P3** |
| 12 | [Callee-save register injection](#12-callee-save-register-injection) | High | High | **P3** |
| 13 | [Data Sync and XREF Pipeline](#13-data-sync-and-xref-pipeline) | High | Medium | **P1** |
| 14 | [Relocation Target Validation](#14-relocation-target-validation) | High | High | **P1** |
| 16 | [Incremental verify](#16-incremental-verify) | Medium | Medium | **P2** |
| 17 | [rebrew doctor](#17-rebrew-doctor) | Medium | Low | ~~**P2**~~ **DONE** |
| 18 | [Config validation layer](#18-config-validation-layer) | Medium | Low | ~~**P2**~~ **DONE** |
| 19 | [Annotation round-trip fidelity tests](#19-annotation-round-trip-fidelity-tests) | Medium | Low | ~~**P2**~~ **DONE** |
| 20 | [Diff export formats](#20-diff-export-formats) | Low | Low | ~~**P3**~~ **DONE** |

---

## Idea Details

### 1. CRT source cross-reference tool

**Pain**: Identifying which CRT source file a function came from requires manual search through `tools/MSVC600/VC98/CRT/SRC/`. Many MSVCRT STUBs (85-200B) are verbatim copies of reference source.

**Proposed**: `rebrew-crt-match 0xVA` — given a VA, search the MSVC6 CRT source for likely matches based on function size, call graph, and string references. Rank candidates by similarity. A bulk mode could auto-match against all known CRT implementations.

**Impact**: Automating the lookup saves significant manual research time on ~100 MSVCRT-origin functions.

### 5. GA code layout mutations

**Pain**: GA mutations focus on C source mutations, but most close MATCHING blockers are register allocation issues that C changes can't fix. The mutations that actually affect codegen are structural.

**Proposed**: A "code layout" mutation type that tries different if/else orderings, goto vs inline returns, nested vs flat conditionals, and do-while vs while loops.

**Impact**: Targets the mutations that actually affect codegen structure.

### 7. Batch flag sweep mode

**Pain**: Running `rebrew match --flag-sweep-only` on all MATCHING functions sequentially is slow. The GA is CPU-intensive but embarrassingly parallel.

**Proposed**: A batch flag sweep mode that parallelizes across functions with priority queuing (smallest delta first).

**Impact**: Faster turnaround on systematic flag exploration.

### 11. Similarity-based prioritization in rebrew next

**Pain**: Functions that share code patterns with already-matched functions would be easier to reverse, but `rebrew next` doesn't account for this.

**Proposed**: Prioritize by similarity to already-matched functions (shared call targets, similar size/structure).

**Impact**: Better work ordering for snowball effect.

### 12. Callee-save register injection

**Pain**: The target binary often pushes 4 callee-saves (ebx, ebp, esi, edi) and uses ebp=0 throughout the function. The compiler never generates this pattern because it doesn't see enough register pressure.

**Proposed**: Inject specific callee-save register patterns (e.g., force ebp allocation via inline assembly prologue/epilogue) to match the target's register usage.

**Impact**: Could unlock many MATCHING to RELOC transitions, but highly experimental.

### 13. Data Sync and XREF Pipeline

**Pain**: Global variables (`.data`, `.rdata`, `.bss`) are defined manually in Ghidra and must be re-typed manually in Rebrew as `extern` with `// GLOBAL:` or `// DATA:` annotations. `rebrew skeleton` gives an empty file, requiring manual inspection of Ghidra to find which globals the function references.

**Proposed**:
1. **Data Pull**: `rebrew sync --pull-data` queries ReVa MCP for all labeled data and auto-generates a master `rebrew_globals.h`.
2. **Data Push**: `rebrew sync --push` handles `// DATA:` markers, pushing label and size to Ghidra.
3. **XREF Injection**: `rebrew skeleton 0xVA` queries Ghidra for data XREFs and auto-injects `extern` declarations for every global the function touches.

**Impact**: Eliminates manual synchronization of the data section. Massively speeds up skeleton implementation by providing immediate context (especially string literals from `.rdata`).

### 14. Relocation Target Validation

**Pain**: Currently, `score_candidate` (and the diff tool) zeroes out relocation fields in both the target and the compiled `.obj` (e.g. `mov eax, [0x10025000]` becomes `A1 00 00 00 00`). If a candidate references `g_var1` instead of `g_var2`, Rebrew incorrectly reports a `RELOC MATCH`.

**Proposed**: Parse the COFF relocation and symbol tables from the `.obj`. For every relocation, resolve the symbol name to its target VA using the Rebrew data catalog. Compare that resolved VA against the hardcoded absolute address in the target binary. If they mismatch, mark as `XX` (wrong reference) instead of `~~` (acceptable relocation).

**Impact**: Guarantees that a `RELOC MATCH` is perfectly accurate in logic AND data references. Eliminates silent bugs where the game compiles but crashes due to wrong global access.

### 16. Incremental verify

**Pain**: `rebrew verify` recompiles every reversed function from scratch on every run. For projects with 200+ functions, a full verify takes minutes. During active development, you only changed one or two files — recompiling everything else is wasted work.

**Proposed**: Track file modification times (or content hashes) in a lightweight cache file (e.g. `.rebrew/verify_cache.json`). On subsequent runs, only recompile files whose source or config changed since the last verify. A `--full` flag forces a clean rebuild. The cache is invalidated when `rebrew.toml` compiler settings change.

**Impact**: Cuts typical verify iteration time from minutes to seconds during active development.

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

### 21. Surgical Semantic Equivalence with `angr`

**Pain**: `MATCHING` functions that are functionally identical but structurally different (due to register allocation, instruction folding, etc.) cannot reach `EXACT`/`RELOC` status through byte diffing alone. This leaves them permanently stuck as "almost complete".

**Proposed**: `rebrew prove <target_ident>` — a tool that compiles the target `.c` to a `.obj`, extracts the raw bytes of both the `.obj` function and the target executable function, loads them both via `angr.Project` (using the CLE blob backend), stubs external calls with symbolic procedures, and runs symbolic execution to the end of the function. It then uses the Z3 constraint solver to mathematically prove that the final symbolic state of the return registers and memory are logically equivalent. If proven, updates annotation to `STATUS: PROVEN`.

**Impact**: Closes the final 1% gap on complex functions where the modern compiler refuses to generate byte-for-byte identical code to the original legacy compiler, providing mathematical certainty without resorting to inline assembly hacks.
