# Rebrew Tooling Improvement Ideas

Ideas collected during hands-on workflow testing, sorted by impact-to-effort ratio.

---

## Completed

| # | Idea | Notes |
|---|------|-------|
| 15 | Compile result cache | `compile_cache.py` — SHA-256 hash-based `.obj` caching via `diskcache`. CLI: `rebrew cache stats/clear`. 23 tests. |
| 17 | Match regression detection | `rebrew verify --diff` — compares verify results against last saved report. Exit code 1 on regressions. |
| 18 | Batch promote | `rebrew promote --all` — discovers and promotes all promotable functions in one pass. Supports `--origin`, `--dry-run`. |
| 1 | CRT source cross-reference tool | `rebrew crt-match` — indexes CRT source directories, matches by name with confidence tiers, auto-writes `// SOURCE:`. 19 tests. |
| 2 | Data Sync and XREF Pipeline | `rebrew sync --pull-data` — fetches data labels from Ghidra, generates `rebrew_globals.h`. 11 tests. |
| 16 | Auto-download wibo | `wibo.py` — `download_wibo()`, `find_wibo()`, `ensure_wibo()`. CLI: `rebrew doctor --install-wibo`. 15 tests. |
| 3 | Incremental verify | `rebrew verify` uses `.rebrew/verify_cache.json`, `--full` forces rebuild. |
| 6 | XREF context in skeleton | `rebrew skeleton --xrefs` — fetches cross-references via MCP, decompiles callers. 9 tests. |
| 7 | Ghidra decompilation backend | `fetch_ghidra()` in `decompiler.py` via ReVa MCP `get-decompilation`. 12 tests. |
| 9 | Validate programPath | `ghidra_program_path` config + `_resolve_program_path()` in `sync.py`. |
| 12 | Auto-BLOCKER classification | `rebrew match --diff-only --fix-blocker` — `classify_blockers()` auto-writes annotations. 20 tests. |
| 13 | Multi-function file splitting | `rebrew split` + `rebrew merge` — split/merge with preamble preservation. 20 tests. |
| 14 | Semantic equivalence with angr | `rebrew prove` — symbolic execution + Z3 constraint solving. Optional dep. |
| — | Coverage dashboard | Sibling project `recoverage` — consumes `data_{target}.json`. |
| — | CRT auto-detection | `rebrew cfg detect-crt` — scans `tools/` for known MSVC CRT source dirs. `detect_crt_sources()` in `config.py`. |
| — | Dotted key resolution | `rebrew cfg show/set/get` — greedy longest-match resolution for TOML keys containing dots. |

---

## Open Ideas

### ~~4. GA code layout mutations~~ ✅

> **Status: Done.** 16 new structural mutations added to `mutator.py` in two batches. Batch 1: `flatten_nested_if`, `extract_else_body`, `for_to_while`/`while_to_for`, `if_to_ternary`/`ternary_to_if`, `hoist_return`/`sink_return`. Batch 2: `swap_adjacent_stmts`, `guard_clause`, `invert_loop_direction`, `compound_assign_toggle`, `demorgan`, `postpre_increment`, `xor_zero_toggle`, `negate_condition`. Total mutations: 67.

### ~~19. Cross-function solution transfer~~ ✅

> **Status: Done.** Solution database added in `solutions.py`. GA auto-saves solution fingerprints (cflags, origin, size) on exact match to `.rebrew/solutions.json`. New GA runs auto-seed from similar solved functions. CLI: `rebrew match --all --no-solved` to disable, `rebrew match --extra-seed FILE --no-seed`.

### 20. Test watch mode

**Pain**: During active development, the edit → run `rebrew test` → check output loop is manual. A watch mode would automatically recompile and diff on file save.

**Proposed**: `rebrew test --watch src/target/func.c` — monitors the file and re-runs on save.

**Impact**: Medium quality-of-life improvement. Straightforward with `watchdog` or inotify.

### 21. Binary similarity search

**Pain**: Finding functions with similar byte patterns across the binary requires manual analysis. Structurally similar functions likely share the same optimization approach.

**Proposed**: Given a solved function, find other functions in the binary with similar byte patterns, call structure, or control flow. Useful for prioritizing which STUBs to tackle next.

**Impact**: Medium — helps with prioritization but `rebrew next` already does some of this.

---

## Observations (Reference Knowledge)

Patterns and insights from RE work — not actionable tool ideas, but useful context.

### Close MATCHING analysis (0-3B delta)

GA mutations (100 gen, pop 30) consistently fail to improve close MATCHING functions. All blockers are compiler-internal decisions that C source mutations cannot influence.

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
