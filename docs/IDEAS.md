# Rebrew Tooling Improvement Ideas

Ideas collected during hands-on workflow testing, sorted by impact-to-effort ratio.

---

## Prioritized Ideas

| # | Idea | Impact | Effort | Priority | Status |
|---|------|--------|--------|----------|--------|
| 15 | [Compile result cache (test/verify)](#15-compile-result-cache) | **Critical** | Medium | **P0** | **Done** |
| 17 | [Match regression detection](#17-match-regression-detection) | High | Low | **P0** | **Done** |
| 18 | [Batch promote](#18-batch-promote) | High | Low | **P0** | **Done** |
| 1 | [CRT source cross-reference tool](#1-crt-source-cross-reference-tool) | High | Medium | **P1** | **Done** |
| 2 | [Data Sync and XREF Pipeline](#2-data-sync-and-xref-pipeline) | High | Medium | **P1** | **Done** |
| 16 | [Auto-download wibo](#16-auto-download-wibo) | Medium | Low | **P1** | **Done** |
| 3 | [Incremental verify](#3-incremental-verify) | Medium | Medium | **P2** | **Done** |
| 6 | [XREF context in skeleton generation](#6-xref-context-in-skeleton-generation) | Medium | Low | **P2** | **Done** |
| 7 | [Ghidra decompilation backend for skeleton](#7-ghidra-decompilation-backend-for-skeleton) | Medium | Low | **P2** | **Done** |
| 9 | [Validate programPath against Ghidra project](#9-validate-programpath-against-ghidra-project) | Medium | Low | **P2** | **Done** |
| 20 | [Test watch mode](#20-test-watch-mode) | Medium | Medium | **P2** | — |
| 4 | [GA code layout mutations](#4-ga-code-layout-mutations) | Medium | High | **P2** | Partial |
| 5 | [Incremental / dirty-only Ghidra sync](#5-incremental--dirty-only-ghidra-sync) | Medium | Medium | **P2** | — |
| 8 | [Sync deduplication / idempotency tracking](#8-sync-deduplication--idempotency-tracking) | Medium | Medium | **P2** | — |
| 13 | [Multi-function file splitting tool](#13-multi-function-file-splitting-tool) | Low | Low | **P3** | **Done** |
| 21 | [Binary similarity search](#21-binary-similarity-search) | Medium | High | **P3** | — |
| 19 | [Cross-function solution transfer](#19-cross-function-solution-transfer) | High | High | **P3** | — |
| 10 | [Callee-save register injection](#10-callee-save-register-injection) | High | High | **P3** | — |
| 11 | [Watch mode for live Ghidra sync](#11-watch-mode-for-live-ghidra-sync) | Low | High | **P4** | — |
| 14 | [Surgical Semantic Equivalence with angr](#14-surgical-semantic-equivalence-with-angr) | Medium | High | **P4** | — |

### Done

| # | Idea | Notes |
|---|------|-------|
| 7 | Ghidra decompilation backend for skeleton | `fetch_ghidra()` in decompiler.py calls ReVa MCP `get-decompilation`. 12 tests in `test_decompiler.py::TestGhidraBackend` |
| 12 | Auto-BLOCKER classification from diffs | `classify_blockers()` in match.py + `--fix-blocker` auto-writes BLOCKER/BLOCKER_DELTA annotations. 20 tests in `test_match_fix_blocker.py` |
| 13 | Multi-function file splitting tool | Implemented as `rebrew split` (split.py) and `rebrew merge` (merge.py). Split breaks multi-function files into individual files preserving shared preamble. Merge combines files with preamble deduplication and VA-sorted blocks. 20 tests in test_split.py and test_merge.py. |
| 1 | CRT source cross-reference tool | `rebrew crt-match` indexes configured reference source directories, matches by function name with confidence scoring, detects ASM-only CRT functions, auto-writes `// SOURCE:` annotations. 19 tests in `test_crt_match.py`. |
| — | Coverage dashboard (HTML) | Implemented as sibling project `recoverage` — consumes `data_{target}.json` |

---

## Idea Details

### 1. CRT source cross-reference tool

> **Status: Done.** Implemented as `rebrew crt-match` in `crt_match.py`. Indexes configured CRT source directories (`crt_sources` in rebrew-project.toml), matches binary functions by name with confidence tiers (0.95 exact, 0.90 normalized, 0.85 filename-based), detects 35+ known MSVC6 ASM-only functions, and auto-writes `// SOURCE:` annotations via `--fix-source`. Supports `--all`, `--origin` filter, `--index`, and `--json`. 19 tests in `test_crt_match.py`.

**Pain**: Identifying which CRT source file a function came from requires manual search through `tools/MSVC600/VC98/CRT/SRC/`. Many MSVCRT STUBs (85-200B) are verbatim copies of reference source.

**Proposed**: `rebrew-crt-match 0xVA` — given a VA, search the MSVC6 CRT source for likely matches based on function size, call graph, and string references. Rank candidates by similarity. A bulk mode could auto-match against all known CRT implementations.

**Impact**: Automating the lookup saves significant manual research time on ~100 MSVCRT-origin functions.

### 2. Data Sync and XREF Pipeline ✅

> **Status: Done.** `rebrew sync --pull-data` implemented in `sync.py`. Fetches data labels from Ghidra via `get-symbols` + `get-data` MCP tools, generates `rebrew_globals.h` with extern declarations grouped by section. 11 tests in `test_sync_pull_data.py`. Data push via `--push` was already implemented (Phase 3 of `build_sync_commands`).

**Pain**: Global variables (`.data`, `.rdata`, `.bss`) are defined manually in Ghidra and must be re-typed manually in Rebrew as `extern` with `// GLOBAL:` or `// DATA:` annotations. `rebrew skeleton` gives an empty file, requiring manual inspection of Ghidra to find which globals the function references.

**Implemented**:
1. **Data Pull**: `rebrew sync --pull-data` queries ReVa MCP for all non-function symbols via paginated `get-symbols`, queries `get-data` for each to get type info, and generates `rebrew_globals.h` with extern declarations. Type mapping handles int/pointer/undefined/array/float types. Globals grouped by PE section.
2. **Data Push**: `rebrew sync --push` handles `// DATA:` and `// GLOBAL:` markers (pre-existing).
3. **XREF Injection**: See #6 — `rebrew skeleton --xrefs` fetches cross-references from Ghidra.

**Impact**: Eliminates manual synchronization of the data section. Massively speeds up skeleton implementation by providing immediate context (especially string literals from `.rdata`).

### 3. Incremental verify

> **Status: Done.** `rebrew verify` now uses `.rebrew/verify_cache.json` to skip unchanged
> files, supports `--full` to force a full rebuild, and auto-invalidates cache when compiler
> settings or source content changes. Covered by `test_verify_incremental.py`.

**Pain**: `rebrew verify` recompiles every reversed function from scratch on every run. For projects with 200+ functions, a full verify takes minutes. During active development, you only changed one or two files — recompiling everything else is wasted work.

**Proposed**: Track file modification times (or content hashes) in a lightweight cache file (e.g. `.rebrew/verify_cache.json`). On subsequent runs, only recompile files whose source or config changed since the last verify. A `--full` flag forces a clean rebuild. The cache is invalidated when `rebrew-project.toml` compiler settings change.

**Impact**: Cuts typical verify iteration time from minutes to seconds during active development.

### 4. GA code layout mutations

**Pain**: GA mutations focus on C source mutations, but most close MATCHING blockers are register allocation issues that C changes can't fix. The mutations that actually affect codegen are structural.

**Proposed**: A "code layout" mutation type that tries different if/else orderings, goto vs inline returns, nested vs flat conditionals, and do-while vs while loops.

**Impact**: Targets the mutations that actually affect codegen structure.

### 5. Incremental / dirty-only Ghidra sync

**Pain**: `rebrew sync --export` regenerates all operations every time. Applying hundreds of MCP calls takes time.

**Proposed**:
- Track a sync state file (e.g. `ghidra_sync_state.json`) with timestamps or hashes
- Only emit operations for files that changed since the last sync
- Add a `--force` flag to override and re-sync everything

**Impact**: Cuts sync time from minutes to seconds for small changes.

### 6. XREF context in skeleton generation ✅

> **Status: Done.** `rebrew skeleton --xrefs` implemented in `skeleton.py`. Fetches cross-references via `find-cross-references` MCP tool, decompiles top callers via `get-decompilation`, and embeds formatted context as C block comments in the skeleton. Works with single-VA, batch, and append modes. 9 tests in `test_skeleton_xrefs.py`.

**Pain**: When reversing a function, the developer must manually look up callers and callees in Ghidra. This context is critical for understanding parameter types and data flow.

**Implemented**: `rebrew skeleton 0x10006c00 --xrefs` (with `--endpoint` for MCP URL):
- Calls `find-cross-references` via ReVa MCP to get incoming callers and data references
- Calls `get-decompilation` on the top N callers (default 5, configurable)
- Embeds caller context as a `/* === Cross-references === */` C block comment before the function body
- Supports both call and data references
- Gracefully degrades when MCP is unavailable (returns None, prints warning)

**Impact**: Saves a round-trip to Ghidra for every new function, providing immediate calling context.

### 7. Ghidra decompilation backend for skeleton ✅

> **Status: Done.** `fetch_ghidra()` in `decompiler.py` connects to a running Ghidra instance via ReVa MCP `get-decompilation` tool. Uses `httpx.Client` and the existing `_fetch_mcp_tool_raw`/`_init_mcp_session` helpers from `sync.py`. The `endpoint` parameter threads through `fetch_decompilation()` to all 3 skeleton.py call sites (batch, append, single-VA). Tests in `test_decompiler.py::TestGhidraBackend`.

**Pain**: `rebrew skeleton --decomp` currently uses radare2 backends (`r2ghidra`, `r2dec`), which produce lower quality output than Ghidra's decompiler.

**Proposed**: Add a `--decomp-backend ghidra` option that calls ReVa's `get-decompilation`:

```bash
rebrew skeleton 0x10006c00 --decomp --decomp-backend ghidra
```

**Impact**: Significantly better decompilation quality for initial skeleton generation.

### 8. Sync deduplication / idempotency tracking

**Pain**: Running `--export` + `--apply` twice re-applies all operations. While ReVa probably handles this idempotently, it wastes time and network round-trips.

**Proposed**: Track what has already been pushed in a sync state file. Skip operations whose source data hasn't changed since the last successful push.

**Impact**: Pairs with incremental sync (#5) to make repeated syncs near-instant.

### 9. Validate programPath against Ghidra project

> **Status: Done.** Added `ghidra_program_path` target config override, centralized
> path resolution in `sync.py::_resolve_program_path()`, best-effort runtime
> validation against ReVa `get-current-program`, and wired this through
> `sync.py`, `skeleton.py`, and the Ghidra decompiler path plumbing.

**Pain**: The `program_path` is derived from `cfg.target_binary.name` which gives `/server.dll`. But Ghidra may have imported the binary under a different path (e.g. `/Server/server.dll` or just `server.dll` without leading slash).

**Proposed**:
1. Query ReVa for `get-current-program` to validate the path
2. Or make the program path configurable in `rebrew-project.toml` (e.g. `ghidra_program_path`)

**Impact**: Prevents silent sync failures when Ghidra's program path doesn't match the derived one.

### 10. Callee-save register injection

**Pain**: The target binary often pushes 4 callee-saves (ebx, ebp, esi, edi) and uses ebp=0 throughout the function. The compiler never generates this pattern because it doesn't see enough register pressure.

**Proposed**: Inject specific callee-save register patterns (e.g., force ebp allocation via inline assembly prologue/epilogue) to match the target's register usage.

**Impact**: Could unlock many MATCHING to RELOC transitions, but highly experimental.

### 11. Watch mode for live Ghidra sync

**Pain**: Developers must manually run `rebrew sync --push` after every file change. This interrupts the edit-test-sync cycle.

**Proposed**: `rebrew sync --watch` monitors `.c` file changes and automatically pushes updates to Ghidra in near-real-time:

```bash
rebrew sync --watch
# Watching src/server.dll/*.c for changes...
# [12:30:01] func_10006c00.c changed → pushed label + comment
# [12:30:45] zlib_adler32.c status MATCHING→RELOC → updated bookmark
```

Uses `watchdog` or `inotify` to detect file saves and push only the changed annotations.

**Impact**: Nice quality-of-life improvement, but high effort and low urgency.

### 12. Auto-BLOCKER classification from diffs ✅

> **Status: Done.** `rebrew match --diff-only --fix-blocker` auto-writes `// BLOCKER:` and `// BLOCKER_DELTA:` annotations from `classify_blockers()` output. Uses `update_annotation_key()`/`remove_annotation_key()` from `annotation.py`. Clears BLOCKER when no structural diffs remain. 20 tests in `test_match_fix_blocker.py`.

**Pain**: After `rebrew match --diff-only` shows structural diffs (`**` markers), the developer must manually classify the blocker type (register allocation, loop rotation, etc.) and write a `// BLOCKER:` annotation.

**Impact**: Saves manual annotation work and ensures BLOCKER annotations are always up to date.

### 13. Multi-function file splitting tool

> **Status: Done.** Implemented as `rebrew split` (split.py) and `rebrew merge` (merge.py). Split breaks multi-function files into individual files preserving shared preamble. Merge combines files with preamble deduplication and VA-sorted blocks. 20 tests in test_split.py and test_merge.py.

**Pain**: Some multi-function files grow unwieldy or contain functions that would be better tracked individually (different CFLAGS, different origins). Splitting them requires manually duplicating headers and moving code.

**Proposed**: `rebrew split src/target/multi.c` — splits a multi-function file into individual files, preserving all annotations and generating correct filenames from `SYMBOL` annotations.

**Impact**: Small quality-of-life improvement for codebase organization.

### 14. Surgical Semantic Equivalence with angr

**Pain**: `MATCHING` functions that are functionally identical but structurally different (due to register allocation, instruction folding, etc.) cannot reach `EXACT`/`RELOC` status through byte diffing alone. This leaves them permanently stuck as "almost complete".

**Proposed**: `rebrew prove <target_ident>` — a tool that compiles the target `.c` to a `.obj`, extracts the raw bytes of both the `.obj` function and the target executable function, loads them both via `angr.Project` (using the CLE blob backend), stubs external calls with symbolic procedures, and runs symbolic execution to the end of the function. It then uses the Z3 constraint solver to mathematically prove that the final symbolic state of the return registers and memory are logically equivalent. If proven, updates annotation to `STATUS: PROVEN`.

See [ANGR_PROPOSAL.md](ANGR_PROPOSAL.md) for the full technical proposal.

**Impact**: Closes the final 1% gap on complex functions where the modern compiler refuses to generate byte-for-byte identical code to the original legacy compiler, providing mathematical certainty without resorting to inline assembly hacks.

### 15. Compile result cache ✅

> **Status: Done.** Implemented in `compile_cache.py`, integrated into `compile.py`, `matcher/compiler.py`, `match.py`, and `ga.py`. CLI via `rebrew cache stats` / `rebrew cache clear`. 23 tests in `test_compile_cache.py`.

**Pain**: Every Wine/wibo invocation takes 200-500ms of startup overhead. During `rebrew ga` (100 generations × 30 population × N functions) and `rebrew match --flag-sweep` (192-8.3M flag combinations), the same `(source + flags)` combination is frequently compiled multiple times — identical source with identical flags producing identical `.obj` output. This is pure waste.

**Implemented**: Hash-based `.obj` caching via `diskcache` (SQLite-backed, thread-safe) that skips the Wine/wibo subprocess entirely on cache hit.

- **Cache key**: SHA-256 of `(CACHE_SCHEMA_VERSION, source_content, source_filename, source_ext, ordered_cflags, ordered_include_dirs, toolchain_id)`. Flag order is preserved (matters for `/I` search paths, `/D` redefinitions).
- **Cache location**: `{project_root}/.rebrew/compile_cache/` (gitignored), managed by `diskcache.Cache`.
- **Integration points**: `compile_to_obj()` in `compile.py` and `build_candidate_obj_only()` in `matcher/compiler.py` — the two hot paths where all compilation funnels through. `match.py` and `ga.py` create and pass cache instances.
- **Cache hit**: Read `.obj` bytes from cache, write to workdir, skip subprocess entirely.
- **Cache miss**: Compile normally, store `.obj` bytes after successful compile.
- **Only successes cached**: Failed compiles are never cached (transient errors).
- **Size management**: LRU eviction at 500MB default via `diskcache.Cache(size_limit=...)`.
- **CLI**: `rebrew cache stats` (entry count, disk usage) and `rebrew cache clear` (purge all entries).

**Impact**: The single biggest performance win for GA and flag sweep. For a typical `--flag-sweep --tier targeted` run (1,152 combos × N functions), cache hits on unchanged functions eliminate ~90% of Wine invocations on subsequent runs. GA benefits when mutations produce previously-seen source text.

### 16. Auto-download wibo ✅

> **Status: Done.** Implemented in `wibo.py` with `download_wibo()`, `find_wibo()`, `ensure_wibo()`. Integrated into `doctor.py` (`check_runner()` + `--install-wibo` flag). Platform detection for Linux x86_64/i686 and macOS. SHA256 verification from GitHub API `digest` field. 15 tests in `test_wibo.py`.

**Pain**: [wibo](https://github.com/decompals/wibo) is a lightweight Win32 PE loader that's 5-10x faster than Wine for running MSVC `CL.EXE`. It's a single static binary with no dependencies. But setting it up requires manually downloading the release, placing it on `PATH`, and marking it executable. This friction means most users stick with Wine.

**Implemented**:
- `wibo.py` module: `download_wibo(dest)` fetches latest release from GitHub API, selects platform-appropriate asset (`wibo-x86_64`, `wibo-i686`, `wibo-macos`), verifies SHA256 digest, `chmod +x`. Uses stdlib `urllib.request` (no extra deps).
- `find_wibo(project_root)`: checks PATH via `shutil.which`, then `project_root/tools/wibo`
- `ensure_wibo(project_root)`: find-or-download to `project_root/tools/wibo`
- `rebrew doctor`: new `check_runner()` validates wibo/wine availability
- `rebrew doctor --install-wibo`: downloads wibo to `tools/wibo` in one command

**Impact**: Zero-friction wibo adoption. Combined with the compile cache (#15), this makes the compile pipeline dramatically faster with no manual setup.

### 17. Match regression detection

**Pain**: When you modify a shared header, fix a struct layout, or update `base_cflags`, previously EXACT/RELOC functions can silently regress to MATCHING or worse. You only discover this by running a full `rebrew verify`, scanning the output, and mentally diffing it against what you remember. On a project with 200+ functions, regressions hide in noise.

**Proposed**: `rebrew verify --diff` (or `--regression`) that compares the current verify results against the last saved report in `db/verify_results.json`.

```
$ rebrew verify --diff
3 regressions detected:
  func_10003da0  EXACT → MATCHING  (delta: 4B)   ← struct change in types.h
  func_10006c00  RELOC → MATCHING  (delta: 12B)  ← base_cflags changed
  zlib_adler32   EXACT → COMPILE_ERROR            ← missing include

2 improvements:
  func_10008880  MATCHING → EXACT   ← flag sweep found /O2 /Gy
  func_1000a200  STUB → MATCHING    ← new implementation
```

Exit code 1 if any regressions exist (useful for CI/pre-commit hooks). `--json` for structured output. Optionally `--fail-on-regression` for strict mode.

**Impact**: Catches regressions immediately instead of discovering them days later. Low implementation effort — `verify.py` already saves JSON results, this just diffs two reports.

### 18. Batch promote

**Pain**: After `rebrew ga --flag-sweep --fix-cflags` updates CFLAGS annotations on several functions, or after a header fix resolves multiple compile errors, you need to promote each function individually: `rebrew promote src/target/func_a.c`, `rebrew promote src/target/func_b.c`, etc. Tedious and error-prone when 10+ functions changed.

**Proposed**: `rebrew promote --all` (or `--batch`) that discovers all promotable functions and promotes them in one pass.

```bash
rebrew promote --all                    # promote everything that verifies
rebrew promote --all --dry-run          # preview what would change
rebrew promote --dir src/server.dll/    # promote all in a directory
rebrew promote --origin ZLIB            # promote all ZLIB-origin functions
```

Under the hood: run `verify_entry()` on each candidate, compare result against current `// STATUS:`, update if improved (STUB→MATCHING, MATCHING→RELOC, RELOC→EXACT). Never demote — if a function regresses, skip it and warn (use `rebrew verify --diff` for regression tracking).

**Impact**: Turns a 10-minute manual promotion session into a single command. Pairs naturally with `rebrew ga --flag-sweep --fix-cflags` for a fully automated improve→promote pipeline.

### 19. Cross-function solution transfer

**Pain**: Many functions in the same binary share similar structure — same calling convention, same register pressure patterns, same optimization level. When GA solves one function (finds the exact flags + mutations), that knowledge is thrown away. The next similar function starts GA from scratch, re-discovering the same solution space.

**Proposed**: After GA matches a function, extract its "solution fingerprint" — the winning cflags, any source mutations applied, and structural characteristics (size, call count, local count). Store these in a solution database (`.rebrew/solutions.json`). When GA starts on a new function:

1. Find the K nearest solved functions by structural similarity (size, origin, call pattern)
2. Seed the initial GA population with their winning cflags and mutation patterns
3. Prioritize flag combinations that worked for similar functions in the sweep ordering

```bash
rebrew match src/target/func_b.c              # auto-seeds from similar solved functions
rebrew match src/target/func_b.c --no-seed    # disable seeding, start fresh
rebrew ga --seed-from-solved                  # batch mode uses solution DB
```

**Impact**: Reduces GA convergence time by starting near known-good solutions instead of random. Most impactful on projects with many same-origin functions (e.g. 50 GAME-origin functions all compiled with similar flags). Experimental, but the payoff compounds as more functions are solved.

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
