# Rebrew Tooling Improvement Ideas

Ideas collected during hands-on end-to-end workflow testing in guild-rebrew.

## High Priority

### 1. ~~`rebrew-test` should auto-read annotations from the `.c` file~~ ✅ ALREADY IMPLEMENTED
`rebrew-test path/to/file.c` already works with zero extra args! It auto-reads SYMBOL, VA (from FUNCTION/LIBRARY/STUB marker), SIZE, and CFLAGS from source annotations. The perceived issue was a wrapped BLOCKER annotation in `game_pool_free.c` that merged subsequent annotations onto one line.

**New idea**: `rebrew-lint` should validate annotation format — flag lines where multiple annotations are on the same line, or where annotations appear after non-annotation lines.

### 2. ~~`rebrew-match --diff-only` should also auto-read annotations~~ ✅ ALREADY IMPLEMENTED
`rebrew-match path/to/file.c --diff-only` already auto-reads symbol, cflags, VA, and size from annotations. Works with just the filename.

### 3. `rebrew-next` should show byte-delta for MATCHING functions
**Current pain**: `--improving` shows MATCHING functions but no indication of how close they are. A 2-byte diff is very different from a 40-byte diff.
**Proposed**: Add a `Delta` column showing `Xb/Yb` (X differing non-reloc bytes out of Y total). Could cache results from the last `rebrew-verify` run in the DB.
**Impact**: Prioritize functions that are closest to RELOC/EXACT — highest ROI for improvement effort.

### 4. Batch verify should produce a summary report / JSON
**Current pain**: `rebrew-verify` prints lines to stdout. Hard to track progress over time or compare runs.
**Proposed**: `rebrew-verify --json` writes structured results to `db/verify_results.json` with timestamps, so you can diff between runs and see what improved/regressed.
**Impact**: Enable CI-style tracking of decompilation progress.

## Medium Priority

### 5. `rebrew-skeleton` should include Ghidra decompilation inline
**Current pain**: After generating a skeleton, you have to manually look up the Ghidra decompilation, copy it, and adapt it into C89.
**Proposed**: If a Ghidra export is available (e.g. from `ghidra_functions.json` or a decompilation cache), embed it as a comment in the generated skeleton.
**Impact**: Saves a round-trip to Ghidra and gives the developer (or AI) immediate context.

### 6. ~~`rebrew-asm` should annotate calls with known function names~~ ✅ IMPLEMENTED
`rebrew-asm` now annotates `call` and `jmp` instructions with the target function name and match status from Ghidra JSON and existing `.c` files. Example: `call 0x10023812  ; strdup (RELOC)`. Use `--no-annotate` to disable.

### 7. Auto-detect `--cflags` from ORIGIN in rebrew-test
**Current pain**: GAME functions use `/O2 /Gd`, MSVCRT uses `/O1`, ZLIB uses `/O2`. This is already in `rebrew.toml` presets, but you still have to type it.
**Proposed**: If `--cflags` is omitted, `rebrew-test` should read the `// CFLAGS:` annotation (already partially implemented) or fall back to the preset for the detected origin.
**Impact**: One less flag to remember/type.

### 8. `rebrew-verify` should show a progress bar
**Current pain**: With parallel jobs + async output, it's hard to tell how far along the run is.
**Proposed**: Use `rich` or `tqdm` to show `[42/326] verifying...` progress counter.
**Impact**: Better UX for long runs.

## Lower Priority / Stretch

### 9. `rebrew-catalog --diff` to compare two verification runs
**Proposed**: Store verify results with timestamps and show what changed between runs (new matches, regressions, stale results).
**Impact**: CI/CD-style decompilation progress tracking.

### 10. Auto-GA on MATCHING functions in batch
**Proposed**: `rebrew-match --batch-improve` runs the GA on all MATCHING functions below a byte-delta threshold (e.g. <10 bytes difference), unattended.
**Impact**: Many MATCHING→RELOC promotions require only trivial mutations (operand swap, branch inversion) that the GA can find without human input.

### 11. CRT source cross-reference tool
**Proposed**: Given a VA, search the MSVC6 CRT source (`tools/MSVC600/VC98/CRT/SRC/`) for likely matches based on function size, call graph, and string references.
**Impact**: CRT functions are verbatim copies of the reference source. Automating the lookup saves significant manual research time.
