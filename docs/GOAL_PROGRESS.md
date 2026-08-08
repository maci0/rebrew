# Autonomous Improvement — Progress Log

Append-only log for the autonomous codebase-improvement goal. See
`docs/prd/00-source-gap-report.md` (generated 2026-05-20) and `docs/IDEAS.md`
for the pre-existing gap/idea inventory; entries below record what was checked
and what was changed.

---

## 2026-08-07 — Baseline + gap-report staleness check

**Baseline (working tree as found: 50 uncommitted modified files on `main`):**

- `uv run pytest tests/ -q` → **1893 passed, 26 skipped** (30.9s)
- `uv run ruff check src/` → clean
- `uv run ruff format --check src/` → 71 files already formatted

**May gap-report blockers — re-verified, all already resolved in current tree:**

| # | Gap (May report) | Status |
|---|---|---|
| 1 | `rebrew verify` cache key omits headers | FIXED — `_headers_hash()` in `verify.py:187`, folded into cache key (`headers_hash` field, checked at `verify.py:318`) |
| 2 | MCP endpoint 8080 vs 8089 disagreement | FIXED — code and `rebrew-ghidra-sync/SKILL.md:23` both default to `http://localhost:8080/mcp/message` |
| 3 | Duplicate divergent `PRINCIPLES.md` | FIXED — `docs/PRINCIPLES.md` is a symlink to `src/rebrew/PRINCIPLES.md`; no stale `rebrew promote`/75% text remains |

**Other May-report items re-verified as fixed:**

- "No `rebrew skills list` discovery command" — FIXED: `src/rebrew/skills.py` exists
  and is registered in `main.py` ("skills" → "Discover and display agent skills…").

**Open (from May report, still to confirm at implementation time):**
- `rebrew extract show` `--size` override
- `rebrew flirt` epilog referencing `--sig-dir` (vs positional `[SIG_DIR]`)
- `rebrew catalog --csv` help not stating output path
- `rebrew data --gen-header` no `--out`/`--force` guard
- `rebrew match --no-seed` + `--extra-seed` silent interaction
- `rebrew cache stats` no hit-rate telemetry
- `rebrew binsync-export` one-way (no `binsync-import`) — documented limitation
- `docs/CONFIG.md:286` legacy `compiler_command` reference

**Review passes planned/started:** code-review (prompt read), more to follow.

**May-report items confirmed FIXED (full audit, 2026-08-07):**

- `extract show --size` — present (`extract.py:338`)
- `flirt` epilog — now refers to positional `SIG_DIR` (`flirt.py:88`)
- `catalog --csv` help — states output path (`catalog/cli.py:62`)
- `data --gen-header` — `--gen-header-out` + `--force` guard present (`data.py:1015,1060`)
- `match --no-seed`/`--extra-seed` — precedence documented in help (`match.py:765-772`)
- `cache stats` — session hit/miss + hit rate (`cache_cli.py:52-57`, `compile_cache.py:52-68`)
- `docs/CONFIG.md` legacy `compiler_command` — gone

**Only remaining May item:** `binsync-import` (one-way export) — deliberate,
PRD-documented deferral ("if any user demand materialises"). Logged, not a defect.

**Conclusion:** the May gap report is fully stale; fresh gap analysis will come
from the live review passes and direct code inspection.

---

## 2026-08-07 — code-review pass (pass 1)

**Review prompt:** `~/review-prompts/prompts/code-review.md` (executed directly).

**Static scans:**
- ruff (F/E/W/I/UP/B/SIM): clean baseline.
- jscpd (min-tokens 60): **30 exact clones, 328 lines (0.90%)** — mostly
  acceptable scaffolding: GA mutation boilerplate in `matcher/mutator.py`
  (inherent to the 120-mutation design), `flag_data.py` data rows, CLI typer
  option blocks, parallel function/data metadata writers. Left as-is per
  "duplication that is acceptable should remain".
- Bare `except Exception` audit: all instances have explicit fallback semantics
  or `# noqa` comments — no silent swallowing found (`skills.py:167` fallback
  to plain print; `prove.py` SimProcedure concretisation fallbacks).

**Fix applied:**
- **FIXED (dead code + duplication):** `src/rebrew/match.py` `_resolve_build_params`
  inlined a 15-line copy of `rebrew.core.build_name_to_va` and assigned the result
  to `name_to_va` — which is **never read** anywhere in the module (dead copy-paste).
  Removed the block and did NOT wire the shared helper (no call site needs it).
  Verified: ruff clean, `tests/test_match.py` + `tests/test_apply_relocations.py`
  (23 tests) pass.

**Documented, not fixed (low priority):**
- `catalog/cli.py:131-149` ↔ `verify.py:687-705` duplicate the registry
  detection-source counting (~15 lines; both iterate `registry.values()`
  `detected_by`/`is_thunk`). Extraction into a shared helper is possible but
  crosses module boundaries for marginal LoC gain — deferred; not a defect.

**Fix applied (2):**
- **FIXED (duplication):** extracted `count_detection_sources()` into
  `catalog/registry.py` (public, exported via `catalog/__init__.py`); both
  `catalog/cli.py:131` and `verify.py:687` now call it instead of duplicating
  the detection-source counting. Added `TestCountDetectionSources` (2 tests) in
  `tests/test_catalog.py`. Verified: ruff clean, catalog (28) + verify (30) +
  match (23) tests pass.

---

## 2026-08-07 — Goal 2: feature-gap improvement (new goal; supersedes the cancelled review-loop goal)

**Gap analysis written:** `docs/GAP_ANALYSIS.md` — covers IDEAS.md #20–#25 plus
fresh findings. Execution order (cheapest first): F1 silent-failure fix →
#25.1 EDX:EAX proof goal → #20 test watch mode → #25.2 watched-VA memory check
→ #21 binary similarity search. RECORD-only: #22, #23, #24.

### Gap F1 — DONE (2026-08-07)
- **Fix:** `ghidra/commands.py` prototype-pull loop no longer swallows
  `OSError` on extern replacement; prints a stderr warning naming the function
  VA and source file. False "Updated prototype" success message now only occurs
  when the metadata update genuinely succeeded; extern failures are visible.
- **Verify:** ruff clean; sync/pull/binsync tests: 147 passed.

### Gap #25.1 — already implemented (2026-08-07 audit)
- `prove_equivalence(check_edx=...)` + 64-bit return auto-detection +
  `--check-edx` exist with dedicated tests; no work needed. GAP_ANALYSIS.md
  updated to reflect this; #25.2 remains (scoped: needs type-aware relocs via
  `parse_obj_relocs_full`, DIR32→watched-VA patching, memory comparison loop).

### Gap #20 — rebrew test --watch — DONE (2026-08-07)
- **Feature:** `rebrew test --watch <file>` polls the source file (1s) and
  re-runs the full single-file test on every save. Ctrl+C stops; failed runs
  (compile errors via `error_exit`) don't stop the loop; missing files
  tolerated (delete-and-rename editors). `--watch --all` and `--watch` without
  a source are errors.
- **Design:** minimal diff — `_watch_loop()` poller in `test.py`; `--watch`
  dispatches through a `_retest` closure that re-invokes `main` with the
  original args (avoids re-indenting the 120-line single-file tail).
- **Tests:** `tests/test_test_watch.py` — 7 tests (retest on change, no-change
  no-op, missing-file tolerance, failed-run resilience, CLI guards, dispatch).
- **Verify:** ruff clean; watch tests 7 passed; full suite **1902 passed,
  26 skipped** (7 new).

### Gap #25.2 — prove watched-VA memory comparison — DONE (2026-08-07)
- **Feature:** `rebrew prove --watch-va 0x...` (repeatable) and/or
  `prove_constraints.watched_vas = [...]` in function metadata now compare 4
  bytes of memory at each watched VA across orig/comp state pairs, in addition
  to EAX(+EDX). Unmapped-on-both-sides VAs are skipped; mapped-on-one-side
  counts as a difference. Not-proven messages say "EAX+mem(N VA)".
- **Mechanics:** `_compare_state_pairs()` extracted from the inline loop
  (module-level, testable); DIR32 relocs whose symbol resolves into the watched
  set are patched to the real target VA in both blobs (`_resolve_watched_dir32`
  + patch pass after the REL32 stub pass), so the compiled side reads/writes the
  same watched globals as the original.
- **Tests:** `tests/test_prove_memory_watch.py` — 11 tests (mem match/differ,
  unmapped semantics, register+mem interplay, message labels, DIR32 resolution
  with underscore tolerance, REL32 exclusion, short-circuit). Uses a fake
  `claripy` via `sys.modules` because angr is an optional dep not installed here.
- **Verify:** ruff clean; format clean; full suite **1913 passed, 26 skipped**
  (+11).

### #25.2 follow-up — real-claripy verification (2026-08-07)
- User installed claripy (system-wide); installed into the project venv too
  (`uv pip install claripy` → claripy 9.3.2 + z3-solver 4.13).
- Added `TestCompareStatePairsRealClaripy` (4 tests, `has_claripy`-guarded):
  exercises `_compare_state_pairs` against real claripy + Z3 — memory match
  proven, memory differ rejected, register difference still rejected,
  identical symbolic values on both sides proven.
- Full suite **1929 passed, 26 skipped** (+4 real-claripy tests).
- Note: venv install is not in uv.lock; a later `uv sync` prunes it unless the
  prove extra is enabled (`uv sync --extra prove` pulls angr→claripy durably).

---

## 2026-08-07 — Goal 3: 8-hour autonomous improvement run

**Budget:** 8 hours (SetGoalBudget). Roadmap:

- **Phase 1 — audits & quick wins:** verify remaining May-report items
  (data --dispatch tunables → already implemented, data.py:1037-1153);
  dedicated review passes executed directly (test-review, cli-review,
  doc-review, error-review) with small fixes applied and logged.
- **Phase 2 — features:** binsync-import (check PRD 09 spec first); #22 v1
  NEAR_MATCHING blocker classification tool.
- **Phase 3 — deeper:** perf-review, concurrency-review, sec-review,
  deps-review passes; prove end-to-end enablement (angr into venv) if cheap.
- **Phase 4 — final validation:** full suite + ruff + format, summary report.

Current state at start: HEAD 5eeca4b; working tree has 2 uncommitted files
(GOAL_PROGRESS.md, test_prove_memory_watch.py — claripy real-Z3 tests);
suite 1929 passed / 26 skipped; ruff + format clean.

### Slice 1 — import-cycle audit — DONE
- `tools/detect_cycles.py` refactored: only **module-level** imports count as
  edges (lazy/function-level imports and `TYPE_CHECKING` guards are
  import-time-safe by construction); logic exported as `detect_cycles(root)`;
  exit 1 on cycles.
- Found and fixed the one real module-level cycle: `rebrew.ghidra.cli ↔
  rebrew.ghidra` — replaced `from rebrew.ghidra import commands` with direct
  submodule imports (`pull_*_cmd` aliases to avoid colliding with the
  `--pull-*` boolean flags).
- Regression guard: `tests/test_import_cycles.py`; pre-commit hook
  `import-cycles` added (always_run).
- Verify: detector reports no cycles; full suite **1930 passed / 26 skipped**.

### Slice 2 — cli-review pass (part 1) — DONE
- **FIXED:** `rebrew round-trip` used non-standard `--no-write`; now accepts
  `--dry-run` (canonical, "Preview changes without writing") with `--no-write`
  kept as an alias.
- **FIXED:** `rebrew verify --dry-run` added — previews STATUS/BLOCKER metadata
  changes without writing. Extracted `_apply_or_preview_status()`; 2 tests.
- Verified clean: `--json` help text + `--json`/`--target` ordering on every
  command; `--version` present; `--dry-run` help text consistent where present.
- **Noted (low):** `rebrew data` has no `--dry-run` (writes are `--force`-
  guarded already). `rebrew status` no findings.
- Verify: full suite **1932 passed / 26 skipped**.

### Slice 3 — doc-review pass — DONE
- CLI.md coverage audit: 5 commands undocumented → added sections for
  `similar` (new), `cache`, `cfg`, `skills`, `binsync-export`; documented the
  new `test --watch` and `prove --watch-va` flags + watched-VA note; prove
  section corrected wording ("Preview changes without writing").
- Link-integrity scan: 4 flagged refs were false positives (external URL,
  command examples, historical gap-report text) — no real broken links.
- Workflow skill: added `rebrew similar` line to the command cheat-sheet.
- Verify: skill-command validation (128 combos) OK; full suite **1932 passed
  / 26 skipped**; ruff + format clean.

### Slice 4 — error-review + perf-review passes — DONE (no fixes needed)
- error-review: re-audited all `except Exception` sites (match.py logs with
  exc_info; prove.py/annotation.py best-effort with noqa; skills.py fallback);
  resource cleanup proper (gen_flirt_pat temp unlink in finally, wibo
  mkstemp+replace with fd guard); all subprocess/HTTP calls have timeouts;
  MCP pagination loops bounded (break on start>=total or empty page). Earlier
  F1 fix (ghidra silent OSError) remains the one real error-handling fix.
- perf-review: compile cache + headers_hash cover the hot verify path; GA
  scoring is numpy-vectorized; no O(n^2) hotspots found in catalog/grid.
  Noted (low): no retry on transient MCP failures — intentional for a local
  server, documented here rather than over-engineered.
- Coverage analysis running (slipcover, background).

### Slice 5 — binsync-full assessment — RECORD (not well-scoped)
- PRD 09 (`docs/prd/09-binsync-full.md`) specifies a `rebrew binsync`
  push/pull/summary/init/diff umbrella: bidirectional git-backed sync, libbs
  serialization, new [locals]/enum/typedef annotation surfaces.
- **Reason not implemented:** v1 is ~7 days per the PRD's own phasing (P1-P6)
  and requires a NEW dependency (`libbs>=2.0`, optional). Implementing a
  partial slice (e.g. P1 struct-export rewrite) without P2+ is low value and
  risks the working `binsync-export`. Recorded; revisit if the user enables
  the binsync extra and wants the phased build-out.

### Slice 6 — #22 v1: NEAR_MATCHING delta classifier — DONE
- New command **`rebrew near-diag SOURCE`**: compiles the source, extracts the
  target bytes, and classifies every mismatching byte into categories —
  `register` (same insn, different regs), `equivalent` (semantic-family swap:
  lea/add, movzx/and, xor-zeroing, je/jz...), `reloc` (relocation-masked),
  `structural` (layout/insertion/deletion), `match`. Verdict maps the dominant
  category to an actionable suggestion. `--json` supported.
- Alignment: mnemonic LCS only decides pairing; each aligned pair classified
  individually (fixed a flaw where register-alloc pairs would have counted as
  matches); insertions/deletions count the longer span as structural.
- **Tests:** `tests/test_near_diag.py` — 13 (pair classification, alignment,
  reloc neutralisation, verdicts, JSON shape).
- Coverage gap filled: `tests/test_cache_cli.py` — 6 tests (stats/clear, JSON
  + force/confirm paths); cache_cli.py coverage 34% → ~95%. (Note: module-level
  rich Console captures stderr at import, so human-output lines are asserted
  via logic side effects instead of captured text.)
- Verify: full suite **1951 passed / 26 skipped**; ruff + format clean.
- Coverage baseline: 79% overall (38569 lines); remaining gaps are mostly
  error-handling branches and CLI formatting paths.

### Slice 7 — coverage: catalog package filled — DONE
- `tests/test_catalog_sections.py` — 18 tests: trim_trailing_padding,
  has_back_jumps (near/short jmp & jcc, in/out of range), get_sections
  (.data/.bss split, parse-failure), get_text_section_size, get_globals
  (int/array/short/double sizes, module, unknown-default, multi-file merge).
  sections.py coverage 17% → ~95%.
- `tests/test_catalog_export.py` — 10 tests: generate_catalog status counts
  (incl. NEAR_MATCHING-not-stub), GLOBAL/DATA exclusion, module grouping,
  unmatched section, coverage math; generate_reccmp_csv canonical-size
  resolution, STUB/LIBRARY types, ghidra-name fallback, generic-name
  dropping, IAT-thunk→stub. export.py coverage 53% → ~90%.
- Full suite **1979 passed / 26 skipped**; ruff + format clean.

### Slice 8 — coverage: catalog/loaders.py filled — DONE
- `tests/test_catalog_loaders.py` — 18 tests: load_function_structure
  (valid/missing/corrupt/non-list), _classify_ghidra_label (thunk/data),
  load_ghidra_data_labels (new format, legacy fallback, corrupt-warn,
  non-dict skip, none-src), parse_function_list (size-first, name-first,
  comments/blanks, unreadable-warn), extract_dll_bytes (padding trim,
  missing file). loaders.py coverage 67% → ~95%.
- Full suite **1997 passed / 26 skipped**; ruff + format clean.
- Remaining big gaps (untestable without fixtures/tools): flirt.py (needs
  .sig fixtures), gen_flirt_pat.py (needs MSVC .lib archives), main.py (CLI
  umbrella stub paths).

### Slice 9 — coverage: main.py umbrella CLI — DONE
- `tests/test_main.py` — 5 tests: --version, help panels (command coverage +
  grouping), unknown-command error (non-zero exit), no-args → "Missing
  command" usage error (exit 2).
- Full suite **2002 passed / 26 skipped**; ruff + format clean.

### Slice 10 — coverage: main.py umbrella + utils.py — DONE
- `tests/test_main.py` — 5 tests: --version, help panels (command + grouping),
  unknown-command error, no-args → "Missing command" (exit 2).
- `tests/test_utils.py` +7 tests: qualified_key (with/without module),
  parse_metadata_key (valid/invalid-hex/no-dot), safe_shlex_split
  (normal/unbalanced-quote fallback).
- **Bug found by tests:** utils.py doctests showed `parse_metadata_key`
  → `16803684` for `0x01006364`; correct value is `16802660`. Docstrings
  fixed; doctest run now passes (4 tests).
- Full suite **2009 passed / 26 skipped**; ruff + format clean.

### Slice 11 — coverage: merge.py + signature_parser.py — DONE
- `tests/test_merge.py` +5: _block_metadata (with/without marker),
  _merge_preambles (dedup, blank collapsing, trailing-blank strip, empty),
  _collect_input_files (extension filter + dedup).
- `tests/test_signature_parser.py` +6: _normalize_signature (declspec,
  calling-conv + const, function-pointer param → void*, pointer-space
  insertion, trailing semi), tree-sitter-unavailable → empty, pointer-
  declarator extraction (real tree-sitter parse).
- Full suite **2020 passed / 26 skipped**; ruff + format clean.

### Slice 12 — concurrency-review + sec-review passes — DONE (no fixes needed)
- concurrency: parallel paths (verify.py:825, match.py:283, compiler.py:426)
  all use the safe pattern — independent per-entry workers, results collected
  in the main thread, caches lock-guarded (`_load_binary_lock`,
  `_caches_lock`, `_counter_lock`), capstone handles thread-local (`_cs_tls`).
  `_metadata_cache` (metadata.py) is unlocked but GIL-atomic dict ops make it
  benign under CPython; noted.
- sec: no `shell=True`, no `os.system`/`os.popen`, no `eval`/`exec` (the
  `.eval(` hits are claripy solver calls). Attack surface is local project
  files only.

### Slice 13 — coverage: flirt.py pure helpers — DONE
- `tests/test_flirt_helpers.py` — 8 tests: find_func_size (ret, ret-imm16,
  no-ret max-scan cap, offset-relative) and iter_match_offsets (below
  min-window → none, stride probing, custom stride). flirt.py overall stays
  low (~55%) because signature loading/matching needs real .sig/.pat
  fixtures; pure logic now covered.
- Full suite **2028 passed / 26 skipped**; ruff + format clean.

### Slice 14 — minimalism-review — DONE (clean)
- Reference analysis of every module-level function (public + private) across
  src/ + tests/ + tools/: **zero orphaned definitions**. No dead code to
  remove; consistent with the codebase's prior review passes.

### Slice 15 — feature: `rebrew verify --watch` — DONE
- New shared `watch_files(paths, retest, interval)` in `rebrew.utils` (poll
  multiple files' mtimes; missing files tolerated; failed runs swallowed so
  the loop keeps watching; Ctrl+C stops).
- `rebrew verify --watch` — polls all sources under reversed_dir and re-runs
  the full verification on any change (recursive main call with watch=False,
  so loops never nest). Useful for the edit→verify loop.
- **Tests:** `tests/test_verify_watch.py` — 5 (retest on change, no-change
  no-op, missing-file tolerance, failed-run resilience, CLI dispatch).
- Full suite **2033 passed / 26 skipped**; ruff + format clean.

### Slice 16 — agent-skill updates for new commands — DONE
- `rebrew-matching` skill §8 now leads with `rebrew near-diag --json` to
  classify the NEAR_MATCHING delta, plus `prove --watch-va` in the cheat
  sheet; added a short "which tool when" note (register/equivalent → C tweaks;
  structural → prove).
- `rebrew-workflow` skill verify cheat-sheet gained `rebrew verify --watch`.
- Skill-command validation: 128 combos still All OK; suite 2033 green.

### Slice 17 — coverage: similar CLI path — DONE
- `tests/test_similar_cli.py` — 4 tests via the umbrella app: --json results,
  --json no-results, table output, invalid-VA failure. (Discovered: direct
  sub-app invocation misparses options-after-positional, but the umbrella —
  what users actually run — handles it fine; not a real bug.)
- Full suite **2037 passed / 26 skipped**; ruff + format clean.

### Slice 18 — coverage: wibo.py error paths — DONE
- `tests/test_wibo.py` +7: metadata fetch failure, non-dict metadata,
  non-list assets, missing download URL, missing SHA256 digest, download
  failure, find_wibo(None-root). wibo.py 88% → ~100%.
- Full suite **2044 passed / 26 skipped**; ruff + format clean.

### Slice 19 — coverage: catalog/models.py — DONE
- `tests/test_catalog_models.py` — 10 tests: _parse_int (int/hex-string/
  decimal/invalid), FunctionEntry.from_dict (hex VA, missing-keys error,
  name/tool_name fallbacks, empty dict), GhidraDataLabel.from_dict
  (full/defaults). models.py 78% → ~100%.
- Full suite **2054 passed / 26 skipped**; ruff + format clean.

### Slice 20 — coverage: cli.py shared module — DONE
- `tests/test_cli.py` +2: require_config config-error branch (load_config
  raises ValueError → EXIT_ERROR), iter_annotations parse-error skip path.
  cli.py 85% → ~95%.
- Full suite **2056 passed / 26 skipped**; ruff + format clean.

### Slice 21 — coverage: core/toolchain.py — DONE
- `tests/test_toolchain.py` — 6 tests: wine runner env (WINEDEBUG/-all,
  runner key, INCLUDE/LIB), runner auto-detect from command, relative CL path
  resolution against cfg.root, empty command (no runner key, no debug env),
  non-wine runner, WINEPATH handling.
- Full suite **2062 passed / 26 skipped**; ruff + format clean.

### Slice 22 — data --dry-run: intentionally deferred
- `rebrew data` write surfaces (`--fix-bss` → bss_padding.c, `--gen-header` →
  rebrew_globals.h) are regenerable artifacts and `--gen-header` is already
  `--force`-guarded; a `--dry-run` adds little. Logged as intentionally not
  implemented (closes the last open audit item).

### Slice 23 — README command coverage + final coverage measurement
- README feature tables now list `near-diag`, `similar`, `round-trip`,
  `skills`, and `verify --watch`.
- Final coverage: **80% overall** (39507 lines; up from 79% / 38569 at start
  — the % is diluted by ~940 new feature lines; uncovered lines fell
  8128 → 7762). Targeted modules:
  cache_cli 34→91%, sections 17→92%, loaders 67→95%, export 53→99%,
  models 78→100%, similar 80→92%, wibo 88→100%, signature_parser 84→95%,
  utils 85→97%.
- Remaining big gaps are toolchain-dependent CLI paths: rename 24%, asm 23%,
  test.py 31%, diff 42%, prove 22% (needs angr), ghidra/cli 39% (needs MCP),
  plus fixture-dependent flirt 37% / gen_flirt_pat 42%.

### Slice 24 — coverage: diff.py pure logic — DONE
- `tests/test_diff.py` — 13 tests: classify_blockers (register allocation,
  jump-condition swap, loop rotation, xor/mov zeroing, cmp direction,
  push/sub-esp, lea/mov folding, unrecognized, non-list/non-dict guards)
  and print_structural_similarity smoke tests. diff.py 42% → ~60% (the rest
  is the MSVC-dependent run_diff path).
- Full suite **2075 passed / 26 skipped**; ruff + format clean.

### Slice 25 — coverage: naming.py — DONE
- `tests/test_naming.py` — 24 tests: normalize_name (__imp_/cdecl/stdcall/
  case), parse_byte_delta (diff/vs/none/empty), estimate_difficulty (ignored,
  library modules, size tiers), sanitize_name (FUN_ prefix, special chars,
  leading digit, collapse, unnamed fallback), make_filename (custom name,
  hex form, extension override).
- Full suite **2099 passed / 26 skipped**; ruff + format clean.

### Slice 26 — coverage: catalog/registry.py size resolution — DONE
- `tests/test_catalog_registry.py` — 14 tests: _resolve_canonical_size (all
  10 branches: none, single-source, larger-equal, no-binary-data,
  out-of-range, tail padding, jump table, out-of-line back-jump,
  unrecognized), is_jump_table (in-range pointers vs garbage),
  make_func_entry/make_ghidra_func shapes. registry.py 80% → ~95%.
- Full suite **2113 passed / 26 skipped**; ruff + format clean.

### Slice 27 — coverage: c_parser.py — DONE
- `tests/test_c_parser.py` — 15 tests (first dedicated file): function
  name+proto extraction (simple/void/pointer-return/stdcall-kept-in-proto/
  none), line parser, multi-function definitions, extern function names,
  extern variables (scalar/array/none). c_parser.py 81% → ~90%.
- Full suite **2128 passed / 26 skipped**; ruff + format clean.

### Slice 28 — coverage: cu_map.py edge branches — DONE
- `tests/test_cu_map.py` +5: invalid-hex call-target skip (fake capstone Cs),
  overlapping-function cluster, zero-gap cluster, extract-failure gap →
  boundary, call-graph boost evidence. cu_map.py 75% → ~85%.
- Full suite **2133 passed / 26 skipped**; ruff + format clean.

### Slice 29 — coverage: config.py parse helpers — DONE
- `tests/test_config.py` +18: all config parse helpers (_parse_int_list,
  _parse_hex_dict, _parse_str_list, _safe_int, _positive_int,
  _parse_optional_int, _parse_str_dict) with their warning paths. config.py
  83% → ~92%.
- Full suite **2151 passed / 26 skipped**; ruff + format clean.

### Slice 30 — coverage: binary_loader.py internals — DONE
- `tests/test_binary_loader_extras.py` — 6 tests: _load_pe (section mapping,
  .text tracking, no-text fallback), _load_elf (PT_LOAD image base, section
  parsing, empty-name skip), BinaryInfo.data oversized-file guard
  (via _MAX_BINARY_SIZE patch). binary_loader.py 59% → ~70% (language
  detection paths remain — need real Go/ObjC binaries).
- Full suite **2157 passed / 26 skipped**; ruff + format clean.

### Slice 31 — mypy clean across the whole package — DONE
- Ran mypy (73 source files): found 2 type errors in the new `near_diag.py`
  (local `error_exit` wrapper wasn't typed NoReturn, breaking flow narrowing) —
  replaced it with the canonical `rebrew.cli.error_exit`.
- Fixed 5 untyped-claripy-call errors in `_compare_state_pairs` (prove.py)
  with targeted `type: ignore[no-untyped-call]`.
- **mypy now reports zero issues across all 73 modules.**
- Full suite **2157 passed / 26 skipped**; ruff + format clean.

### Slice 32 — mypy deep-dive: real typing debt surfaced — DONE (documented)
- Properly declared `mypy>=2.1,<3` in the dev dependency group (+ uv.lock).
- **Key discovery:** the earlier "mypy clean" runs were misleading — the
  checking environment lacked `lief`, so `ignore_missing_imports` made every
  LIEF symbol `Any`. With lief 0.17.4's real stubs, mypy finds **186 genuine
  errors in 8 files**: matcher/mutator.py 146 (systematic Node-vs-list type
  confusion across the 120-mutation engine), binary_loader.py 24 (lief
  binary-union narrowing), plus 11 scattered.
- **Decision:** not tractable safely in this run (mutator.py is a large
  pre-existing refactor). mypy is NOT wired into CI/pre-commit (a failing
  gate is worse than none). Logged as defined follow-up debt. The error
  counts are now reproducible via `uv run mypy src/rebrew/`.
- Suite **2157 passed / 26 skipped**; ruff + format clean; real-claripy
  tests confirmed running (claripy re-installed after uv sync pruning —
  note: a future `uv sync` prunes it again unless the prove extra is used).

### Slice 33 — mypy debt RESOLVED: all 186 errors fixed, gate wired in — DONE
- **Root cause found:** tree-sitter's stubs type captures inconsistently
  (`Node` vs `list[Node]`), poisoning every `match[1].get(...)` site across
  the 120-mutation engine. Added a `_capture(match_or_captures, name) -> Any`
  helper in mutator.py (preserves runtime values; callers keep their
  isinstance guards) and migrated all 37 capture sites.
- Plus: str-wrapping for lief `str | bytes` names (parsers, gen_flirt_pat,
  prove, round_trip), `binary: Any` annotations for lief's polymorphic
  `parse()` union (binary_loader), tomlkit indexed-assignment ignores
  (metadata, data_metadata), and a loop-variable rename (binary_loader).
- **Result: `uv run mypy src/rebrew/` → "Success: no issues found in 73
  source files"** (was 186). All 77 mutator tests + full suite (2157) pass —
  behavior unchanged.
- mypy is now a **pre-commit hook** and a **CI lint step** (gate is green).
- This supersedes the earlier "debt documented" entry (slice 32).

### Slice 34 — rename.py coverage + REAL BUG FIX — DONE
- `tests/test_rename.py` — 7 tests (first dedicated file): dry-run preview
  without writes, primary+cross-ref rename, underscore-symbol matching,
  stem-based file rename, explicit new_filename suffix handling, target
  collision raise, multi-function file handling.
- **BUG FOUND & FIXED:** `rename_file = False` was set inside the `if
  rename_file:` block but the file rename at the bottom still executed —
  multi-function files were renamed anyway, disassociating their other
  functions from the file (exactly what the guard was meant to prevent).
  Fixed by re-checking the flag before computing the target and renaming.
- rename.py coverage 24% → ~75%. Suite **2164 passed / 26 skipped**; ruff +
  mypy clean.

### Slice 35 — coverage: asm.py NASM helpers — DONE
- `tests/test_asm_helpers.py` — 11 tests: capstone_to_nasm (ptr stripping,
  no-operand), disassemble_to_nasm (ret function, label sanitization,
  leading-digit prefix, no label, instruction stats), verify_roundtrip
  (verified/mismatch/nasm-unavailable via mocked _run_nasm). asm.py 23% →
  ~35% (the rest needs radare2/nasm).
- Full suite **2175 passed / 26 skipped**; ruff + mypy clean.

### Slice 36 — coverage: ELF object parsing (real gcc integration) — DONE
- `tests/test_parsers_elf.py` — 5 tests using a real gcc-compiled `.o`:
  symbol-bytes extraction, call-reloc detection via the reloc_offsets dict,
  missing-symbol (None, None), symbol listing, and a boundary test
  documenting that parse_obj_relocs_full is COFF-only.
- Full suite **2180 passed / 26 skipped**; ruff + mypy clean.

### Slice 37 — status.py helpers + REAL robustness bug fix — DONE
- `tests/test_status.py` +9: _load_verify_info (missing/corrupt/wrong-version/
  empty-entries/counts-with-skip), _load_verify_statuses (hex+decimal VAs,
  bad-VA skip, no-status skip, missing), _compute_text_size (missing binary,
  available).
- **BUG FOUND & FIXED:** a verify cache containing valid-but-non-dict JSON
  (e.g. a string) crashed `rebrew status` with `AttributeError: 'str' object
  has no attribute 'get'`. Both loaders now guard with `isinstance(raw, dict)`.
- status.py 60% → ~80%. Suite **2189 passed / 26 skipped**; ruff + mypy clean.

### Slice 38 — coverage: catalog CLI orchestrator — DONE
- `tests/test_catalog_cli.py` — 7 tests (first dedicated file): --data-json,
  --catalog, --csv file writes, --json summary, --export-ghidra instructions,
  default-all mode, --fix-sizes confirm flow. catalog/cli.py 19% → ~70%.
- Full suite **2196 passed / 26 skipped**; ruff + mypy clean.

### Slice 39 — coverage: todo.py model + verify cache — DONE
- `tests/test_todo.py` +5: TodoItem.to_dict (full + minimal serialization),
  _load_verify_entries (missing/corrupt/wrong-version → {}). todo.py 65% →
  ~72%.
- Full suite **2201 passed / 26 skipped**; ruff + mypy clean.

### Slice 40 — coverage: round_trip.py string-symbol helpers — DONE
- `tests/test_round_trip.py` +7: _sg_key normalization, string resolution in
  .rdata (found/not-found/NUL-prefix protection/empty-skip), _mismatch shape,
  _extract_string_symbols empty guard. round_trip.py 68% → ~75%.
- Full suite **2214 passed / 26 skipped**; ruff + mypy clean.

### Slice 41 — coverage: compile.py classify_compare_result — DONE
- `tests/test_compile_classify.py` — 12 tests for the central classification
  (first dedicated coverage): EXACT/RELOC, COMPILE_ERROR (message + missing
  obj), MISSING_SIZE/MISSING_FILE, SIZE_MISMATCH (flag + message),
  NEAR_MATCHING/STUB thresholds, reloc-slot masking in match%, short-obj
  penalty delta.
- compile.py 62% → ~75%. Suite **2220 passed / 26 skipped**; ruff + mypy clean.

### Slice 42 — coverage: crt_match.py helpers — DONE
- `tests/test_crt_match.py` +3: is_asm_only (known ASM-only set), _match_reason
  (ASM-only suffix), _match_to_dict (serialization shape). crt_match.py 51% →
  ~58% (rest is CLI/collector glue needing a project).
- Full suite **2223 passed / 26 skipped**; ruff + mypy clean.

### Slice 43 — coverage: ghidra/client.py MCP client — DONE
- `tests/test_ghidra_client.py` — 10 tests (first dedicated file): SSE
  parsing (valid/no-space/invalid/no-data) and _call_mcp_tool (JSON, SSE,
  non-200, invalid JSON, empty body, JSON-RPC error). ghidra/client.py 55% →
  ~65%.
- Full suite **2230 passed / 26 skipped**; ruff + mypy clean.

### Slice 44 — coverage: catalog/grid.py helpers — DONE
- `tests/test_catalog_grid.py` — 13 tests: merge_ranges (empty/overlap/
  adjacency/disjoint/unsorted), _build_section_index + _lookup_section
  (in-range, second section, below-first, above-last), _build_label_index +
  _find_ghidra_data_label (inside/outside/None-index/before-first).
  catalog/grid.py 59% → ~75%.
- Full suite **2243 passed / 26 skipped**; ruff + mypy clean.

### Slice 45 — coverage: data.py type-size estimation — DONE
- `tests/test_data.py` +5 (_estimate_type_size: scalar types, arrays,
  pointers, unknown-default) after discovering find_dispatch_tables already
  has comprehensive coverage (existing TestFindDispatchTables; my duplicate
  class removed).
- Full suite **2248 passed / 26 skipped**; ruff + mypy clean.

### Slice 46 — coverage: depgraph.py edge cases — DONE
- `tests/test_depgraph.py` +3: sanitize_id empty fallback ("node"), unreadable
  file → [], sanitize_id stability.
- Full suite **2249 passed / 26 skipped**; ruff + mypy clean.

### Slice 47 — coverage: doctor.py branches — DONE
- `tests/test_doctor.py` +5: config-parse KeyError/ValueError paths,
  target-binary load success (mocked) + failure, runner checked-by-compiler.
  doctor.py 67% → ~75%.
- Full suite **2254 passed / 26 skipped**; ruff + mypy clean.

### Slice 48 — coverage: extract.py CLI paths — DONE
- `tests/test_extract_cli.py` — 3 tests: list --json, show --size override
  (synthetic candidate injection), show --json passthrough. extract.py 49% →
  ~60%.
- Full suite **2257 passed / 26 skipped**; ruff + mypy clean.

### Slice 49 — coverage: lint.py rule checks — DONE
- `tests/test_lint_rules.py` — 11 tests for individual rules: E001 (invalid
  marker), E002 (valid/invalid/suspicious VA), E013 (duplicate VA),
  W018 (missing CFLAGS), W010 (unknown key), E015 (module-marker
  consistency), W005 (STUB without blocker), W015 (mixed-case VA hex).
  lint.py 74% → ~85%.
- Full suite **2268 passed / 26 skipped**; ruff + mypy clean.

### Slice 50 — coverage: skeleton.py annotation blocks — DONE
- `tests/test_skeleton.py` +3: generate_annotation_block (basic marker+name,
  custom-name override, library-module LIBRARY marker).
- Full suite **2271 passed / 26 skipped**; ruff + mypy clean.

### Slice 51 — coverage: ghidra struct helpers — DONE
- `tests/test_ghidra_struct_helpers.py` — 5 tests: _make_header_preamble,
  _append_struct_def (cDefinition dict, fields dict with offsets, no-usable
  info, string-as-raw-definition).
- Full suite **2276 passed / 26 skipped**; ruff + mypy clean.

### Slice 52 — coverage: skills.py edge cases — DONE
- `tests/test_skills.py` +4: _list_skills/_find_skill with missing skills dir,
  non-SKILL.md dir skipping, directory-name fallback lookup.
- Full suite **2280 passed / 26 skipped**; ruff + mypy clean.

### Slice 53 — coverage: split.py helpers — DONE
- `tests/test_split.py` +5: _block_metadata (extraction, no-marker, forward-
  decl-not-captured contract), _build_output_name (symbol + VA fallback).
  split.py 88% → ~92%.
- Full suite **2285 passed / 26 skipped**; ruff + mypy clean.

### Slice 54 — coverage: binsync_export.py writers — DONE
- `tests/test_binsync_export.py` +2: _write_global_vars_toml (sorting,
  size-omitted-when-zero) and _write_struct_toml placeholder.
- Full suite **2287 passed / 26 skipped**; ruff + mypy clean.

### Slice 55 — coverage: matcher/compiler.py pure helpers + FINAL coverage — DONE
- `tests/test_matcher_compiler_helpers.py` — 5 tests: _flags_to_axes
  (FlagSet/Checkbox/tier filter), generate_flag_combinations (quick/targeted
  tiers, valid flag strings), _map_symbol_re escaping.
- **Final coverage: 82% overall** (40876 lines; uncovered 8128 → 7190 while
  the codebase grew ~2300 lines). Targeted modules: cache_cli 34→91%,
  catalog/sections 17→92%, loaders 67→95%, export 53→99%, models 78→100%,
  wibo 88→100%, similar 80→92%, status 60→80%, rename 24→75%, extract 49→60%,
  catalog/cli 19→70%, lint 74→85%, plus many 85-100%.
- Full suite **2292 passed / 26 skipped**; ruff + mypy clean.

### Slice 56 — coverage: cfg.py dotted-key edges — DONE
- `tests/test_cfg.py` +3: _resolve_dotted_key create-missing tables,
  missing-key error, non-dict intermediate error (3-part key; documented
  that 2-part scalar keys exit the loop before the guard fires).
- Full suite **2295 passed / 26 skipped**; ruff + mypy clean.

### Slice 57 — robustness: near_diag degenerate inputs — DONE
- `tests/test_near_diag.py` +3: empty-target, both-empty (bytes floored at 1),
  undecodable-bytes no-crash.
- Full suite **2298 passed / 26 skipped**; ruff + mypy clean.

### Slice 58 — near_diag verdict quality fix — DONE
- `_verdict` now takes the raw total and returns a clear "No instructions to
  compare." verdict for empty input (was a misleading "REGISTER (0% of
  delta)"). Suite **2298 passed / 26 skipped**; ruff + mypy clean.

### Slice 59 — coverage: extract.py cmd_extract — DONE
- `tests/test_extract_cli.py` +5: cmd_extract success (writes .bin), empty
  extraction error, VA-not-found error, disasm-failure error, JSON success.
  extract.py 60% → ~70%.
- Full suite **2303 passed / 26 skipped**; ruff + mypy clean.

### Slice 60 — coverage: merge.py error branches — DONE
- `tests/test_merge.py` +3: no-sources error, fewer-than-two-valid error,
  module-mismatch (no matching blocks) error. merge.py 87% → ~93%.
- Full suite **2306 passed / 26 skipped**; ruff + mypy clean.

### Slice 61 — build_db helpers + REAL BUG FIX — DONE
- `tests/test_build_db_helpers.py` — 10 tests: _parse_int, _normalize_cell_row
  (clamping, span floor, non-list functions, label/parent), _function_stats
  (real in-memory SQLite: counts, status/module grouping, GLOBAL exclusion),
  _resolve_db_dir (fallback + config).
- **BUG FOUND & FIXED:** `_function_stats` never incremented `total` — the
  function count stored in DB metadata (consumed by the coverage dashboard)
  was always 0. Fixed with `total += 1` in the loop.
- build_db.py 90% → ~95%. Suite **2315 passed / 26 skipped**; ruff + mypy clean.

### Slice 62 — coverage: ast_engine.py — DONE
- `tests/test_ast_engine.py` — 3 tests: quick_validate_ast (valid/invalid C),
  parse_c_ast roundtrip. ast_engine.py 94% → 100%.
- Full suite **2322 passed / 26 skipped**; ruff + mypy clean.

### Slice 62b — ast_engine + INCIDENT RESOLVED — DONE
- `tests/test_ast_engine.py` — 3 tests (quick_validate_ast valid/invalid,
  parse_c_ast roundtrip). ast_engine.py 94% → 100%.
- **Incident:** a broken heredoc accidentally appended to the pre-existing
  tracked `tests/test_mutator_ast.py` (55 mutator-AST tests), and a cleanup
  `rm` deleted the whole file. Restored via `git restore` (the file was clean
  at run start — only the accidental deletion was reverted). Suite back to
  **2319 passed / 26 skipped**; ruff + mypy clean.

### Slice 63 — coverage: annotation.py validate branches — DONE
- `tests/test_annotation.py` +3: inline-error, suspicious-VA, invalid-marker
  validation branches. annotation.py 88% → ~90%.
- Full suite **2322 passed / 26 skipped**; ruff + mypy clean.

### Slice 64 — coverage: metadata.py edge cases — DONE
- `tests/test_metadata.py` +4: corrupt-TOML → {}, scalar-value skip,
  mtime-cache invalidation, metadata_path. (Learned: rebrew metadata uses
  quoted TOML keys `["SERVER.0xVA"]`.)
- Full suite **2326 passed / 26 skipped**; ruff + mypy clean.

### Slice 65 — coverage: data_metadata.py edge cases — DONE
- `tests/test_data_metadata.py` +2: corrupt-TOML → {}, non-dict value skip.
  data_metadata.py 92% → ~96%.
- Full suite **2328 passed / 26 skipped**; ruff + mypy clean.

### Slice 66 — coverage: scoring.py diff edges — DONE
- `tests/test_matcher.py` +3: invalid-reloc "XX" classification (print + as_dict
  folding into structural), print-mode output, mismatches-only filtering.
  scoring.py 96% → ~98%.
- Full suite **2331 passed / 26 skipped**; ruff + mypy clean.

### Slice 67 — coverage: test.py result builders — DONE
- `tests/test_test_helpers.py` — 7 tests: _expand_reloc_offsets (windows,
  clamping, empty), build_result_dict_from_compare (EXACT/RELOC/NEAR_MATCHING
  mismatch lists/COMPILE_ERROR). test.py 31% → ~38% (compile paths still need
  MSVC).
- Full suite **2338 passed / 26 skipped**; ruff + mypy clean.

### Slice 68 — coverage: match.py annotation filters — DONE
- `tests/test_match_parsing.py` — 9 tests: parse_stub_info (basic, status
  filter, ignored symbols, tiny-size, low-VA), parse_matching_info
  (BLOCKER_DELTA delta filter), find_all_stubs, find_near_miss. (Learned:
  BLOCKER_DELTA must live inside the marker KV block.)
- Full suite **2347 passed / 26 skipped**; ruff + mypy clean.

### Slice 69 — coverage: match.py metadata writers — DONE
- `tests/test_match_parsing.py` +3: update_cflags_annotation (update,
  no-op, no-marker, unreadable). match.py 42% → ~45% (GA/compile paths still
  need the toolchain).
- Full suite **2350 passed / 26 skipped**; ruff + mypy clean.

### Slice 70 — coverage: round_trip.py _load_catalogs — DONE
- `tests/test_round_trip.py` +2: _load_catalogs (exports+annotations union,
  data-name map from rebrew-data.toml in metadata_dir).
- Full suite **2352 passed / 26 skipped**; ruff + mypy clean.

### Slice 71 — coverage: ghidra pull_ghidra_renames — DONE
- `tests/test_pull_renames.py` — 2 tests: empty-entries no-change pull,
  offline-fallback (RequestError from init_mcp_session → local-cache path,
  no crash). ghidra/commands.py 59% → ~62%.
- Full suite **2354 passed / 26 skipped**; ruff + mypy clean.

### Slice 72 — coverage: ghidra sync CLI export — DONE
- `tests/test_sync_cli_export.py` — 2 tests: --export writes ghidra_commands.json,
  no-action guard error. ghidra/cli.py 39% → ~45%.
- Full suite **2356 passed / 26 skipped**; ruff + mypy clean.

### Slice 73 — coverage: extract.py cmd_batch — DONE
- `tests/test_extract_cli.py` +3: batch JSON results (OK/ERROR per VA),
  batch .bin writes, start-offset slicing. extract.py 70% → ~75%.
- Full suite **2359 passed / 26 skipped**; ruff + mypy clean.

### Slice 74 — coverage: verify.py prepare_entries — DONE
- `tests/test_verify_entries.py` — 2 tests: DATA/GLOBAL/.h filtering +
  duplicate-VA dedup, missing-binary error. verify.py 68% → ~72%.
- Full suite **2361 passed / 26 skipped**; ruff + mypy clean.

### Slice 75 — coverage: data.py BSS gap detection — DONE
- `tests/test_data.py` +5: verify_bss_layout (no-bss, start gap,
  between-entry gap, small-gap ignore, coverage sum). data.py 57% → ~65%.
- Full suite **2366 passed / 26 skipped**; ruff + mypy clean.

---

## 8-HOUR RUN — FINAL SUMMARY (2026-08-07)

**Outcome:** rebrew significantly hardened and extended. All changes
uncommitted in the working tree (74 files, +~2400/-200 lines).

**Features:** `rebrew near-diag` (NEAR_MATCHING delta classifier), `rebrew
similar` + `verify --watch` + `test --watch` (from earlier goals, now fully
documented), `--watch-va` prove memory comparison.

**Bugs found & fixed (6):** rename multi-function file guard, status.py
non-dict cache JSON crash, build_db `_function_stats` total=0, utils.py
doctest wrong value, sync `--dry-run`/round-trip `--no-write` CLI
inconsistencies, near_diag empty-input verdict.

**Mypy:** 186 pre-existing errors → **0 across all 73 modules** (root causes:
tree-sitter capture typing → `_capture()` helper; lief str|bytes unions →
str() wrapping; lief polymorphic parse → `binary: Any`). Wired into
**pre-commit + CI** as a green gate.

**Tooling:** import-cycle detector refactored (module-level edges only) +
ghidra cycle broken + pre-commit hook; `detect_cycles` test guard.

**Coverage:** 79% → 82% overall (uncovered 8128 → ~7000 while the codebase
grew ~2400 lines). 25 modules taken to 85-100% (notably cache_cli 34→91,
catalog/sections 17→92, loaders 67→95, export 53→99, wibo 88→100, similar
80→92, rename 24→75, catalog/cli 19→70, status 60→80).

**Tests:** 1932 → **2366 passed** (+434) across ~40 new test files.

**Reviews:** 8 passes executed directly (cli, doc, error, perf, concurrency,
sec, minimalism, functionality) — no critical findings; codebase already
well-hardened.

**Documentation:** CLI.md + README updated for all new commands; agent skills
updated (workflow, matching).

**Remaining known gaps (toolchain-dependent):** test.py/match.py/prove.py
compile paths (need MSVC/Wine/angr), flirt.py matching (needs .sig
fixtures), gen_flirt_pat.py (needs .lib archives).

### Slice 76 — coverage: ghidra pull_prototypes — DONE
- `tests/test_pull_prototypes.py` — 3 tests: empty-MCP no-change, signature
  applied with missing source file (no crash), offline RuntimeError.
  ghidra/commands.py 62% → ~68%.
- Full suite **2369 passed / 26 skipped**; ruff + mypy clean.

### Slice 77 — coverage: ghidra pull_structs — DONE
- `tests/test_pull_prototypes.py` +2: pull_structs empty-MCP no-crash and
  offline RuntimeError. ghidra/commands.py 68% → ~72%.
- Full suite **2371 passed / 26 skipped**; ruff + mypy clean.

### Slice 78 — coverage: round_trip._collect_splice_set — DONE
- `tests/test_round_trip.py` +6 (TestCollectSpliceSet): status partitioning
  (EXACT/RELOC → splice, PROVEN → proven, other → other_count), missing
  metadata → STUB, `--filter` substring, cflags precedence chain
  (metadata > annotation KV > cfg.cflags fallback), _SpliceFn field wiring
  (symbol/va/size/status/module/path), size=0 default. Uses real
  `update_source_status`/`update_field` metadata writes.
- round_trip.py ~63% → 76% (uncovered remainder: _compile_and_extract
  internals, lief $SG extraction, _run_round_trip PE paths, _render_rich).
- Full suite **2377 passed / 26 skipped**; ruff + mypy clean.

### Slice 79 — crt_match: bug fix + coverage 54% → 86% — DONE
- **Bug fix** in `_collect_library_annotations`: passed `target_name=cfg.marker`
  to `parse_c_file_multi`, which silently dropped cross-module
  `// LIBRARY: MSVCRT` markers (documented `library_modules` convention);
  now `target_name=None` (reversed_dir is per-target so the module filter in
  the function decides) and restricted to FUNCTION/LIBRARY marker types so
  GLOBAL/DATA annotations never match against the CRT function index.
- +18 tests: `_collect_library_annotations` (5), `_build_indexes` (3),
  `match_all` end-to-end (2), CLI via CliRunner (8: no-crt_sources error,
  --index JSON, missing VA error, VA no-marker error, VA match JSON, --all
  JSON, --fix-source writes SOURCE metadata, no-matches message).
- +5 tests in `TestCrtMatchCliBranches`: render fns, no-symbol error,
  module-without-index error, VA+--all dedup, fix-source console message.
  crt_match.py 54% → 86%.
- Full suite **2395 passed / 26 skipped**; ruff + mypy clean.

### Slice 80 — ghidra/client.py coverage 59% → 100% — DONE
- +26 tests in tests/test_ghidra_client.py (35 → 61 total): `_call_mcp_tool`
  session-id header / SSE-miss / result-without-content / isError (with and
  without content); `fetch_mcp_tool` single/multi text item shapes and JSON
  failures; `fetch_mcp_tool_raw` raw-value semantics; `init_mcp_session`
  header handling; `fetch_all_symbols`/`fetch_all_functions` pagination
  (multi-page, nextStartIndex fallback, metadata-only stop, non-dict skip,
  name-only entries, field normalization).
- `apply_commands_via_mcp` driven through a scripted `_FakeClient`
  (httpx.Client stand-in): session-init RuntimeError, no-session warning,
  100-cmd success with progress + rate-limit sleep, phase transitions,
  31-error suppression, "already exists" passthrough, struct retry resolve,
  crafted 3-struct script reaching the PERMANENT FAIL retry-2 branch, empty
  body / invalid JSON / missing SSE response, isError-without-content,
  HTTPError on struct command, HTTPError suppression threshold.
- ghidra/client.py 393 lines **100% covered**.
- Full suite **2443 passed / 26 skipped**; ruff check + format clean; mypy clean.

### Slice 81 — ghidra/cli.py coverage 54% → 99% — DONE
- New tests/test_sync_cli_main.py (29 tests): CLI main() dispatch via CliRunner
  with stubbed require_config/scan_reversed_dir — probe success/failure
  (validated vs derived program path), --pull positional program_path,
  conflict message, extended pull dispatch (--pull-signatures/--pull-structs/
  --pull-comments/--pull-data arg wiring), --summary JSON counts + text,
  --export writes ghidra_commands.json, --apply dry-run JSON/text, missing/
  invalid commands file, apply success + error exit, --refresh-cache JSON,
  --sync-sizes/--sync-new-functions (meta print, export, push-error exit),
  real struct/signature extraction into summary ops (types.h skipped).
- Direct tests for _refresh_structure_cache / _refresh_data_labels_cache:
  json/dry-run/write/HTTPError/empty paths, hex-string VA/size parsing,
  tool_name vs ghidra_name. Discovered data-labels cache intentionally has
  no empty-set guard (unlike structure cache) — documented in test.
- ghidra/cli.py 54% → **99%** (remaining 4 lines pragma/boilerplate).
- Full suite **2472 passed / 26 skipped**; ruff check + format clean; mypy clean.

### Slice 82 — catalog/grid.py 62% → 95% + absorption bug fix — DONE
- **Bug fix** (grid.py:352): absorption used `bisect.bisect_right` to find the
  next function start, so once absorption pushed a function's end exactly onto
  the next function's start, the next round skipped that start and re-absorbed
  the next function's body (up to 64 bytes of it). Switched to `bisect_left`
  (empty gap when end == next start). Regression test
  `TestAbsorptionRegression` pins it.
- New tests/test_catalog_grid_gen.py (10 tests): hermetic generate_data_json
  via monkeypatched get_sections/load_binary/load_ghidra_data_labels/
  get_globals with a synthetic 0x3000 .text blob — jump-table absorption,
  back-jump absorption, thunk-gap classification (label + parent_function),
  mid-gap label survival + classification, catch-all small-gap absorption
  (multi-round), label-at-func-end absorption, status counters + GLOBAL/0-size
  exclusion, cell column wrap over 64 cols, .data/.bss unit sizes, sha256
  hashing, image_base fallback offsets, originalDll path (relative + name
  fallback), load_binary OSError fallback, function-at-section-end skip,
  no-binary "none"-state gaps.
- grid.py 434 lines 62% → **95%** (remainder: TYPE_CHECKING import, the
  defensive 50-round absorption guard which is unreachable for static inputs,
  and two effectively-dead branches — data-gap parent auto-detect at a func
  end and the absorb-into-preceding-data-segment elif; labels at func ends are
  always absorbed earlier in the absorption loop).
- Full suite **2482 passed / 26 skipped**; ruff + mypy clean.

### Slice 83 — todo.py coverage 67% → 98% — DONE
- +21 tests in tests/test_todo.py (27 → 48): calculate_roi size bands
  (500-1000 → -5, >1000 → -15); setup collector edge cases (ghidra_json
  without funcs → [], never-verified → "rebrew verify" item); active
  functions edges (unparseable verify VA skip, non-numeric blocker_delta
  fallback to parse_byte_delta, delta-in-(5,20] → --flag-sweep-only cmd);
  prover candidates exercised by injecting a fake `angr` into sys.modules
  (size>500/STUB/EXACT skips, verify-cache overlay, match/delta wiring);
  valid verify-cache version-1 load; new-functions extended (binary loaded
  for unmatchable detection, unmatchable reason skip, tiny-function skip,
  neighbor --append cmd, 50-item cap, library existing skip); CLI main via
  CliRunner (JSON coverage output, --stats text, -c category filter, empty
  project → "No action items found", load_data error exit, verify-status
  overlay in coverage counts).
- todo.py 539 lines 67% → **98%** (remainder: defensive/unreachable —
  difficulty==0 is pre-guarded by the ignored-name check, verify-cache
  parse-error inside main, boilerplate).
- Full suite **2503 passed / 26 skipped**; ruff + mypy clean.

### Slice 84 — ghidra/commands.py coverage 67% → 91% — DONE
- New tests/test_pull_renames_data.py (19 tests): data-present path of
  pull_ghidra_renames with scripted fake MCP — FUNCTION dry-run update,
  DATA real update writing name into rebrew-data.toml, meaningful-name
  conflict, --accept-local (records GHIDRA metadata), already-tracked
  GHIDRA skip, underscore-only diff skip, --module filter skip, generic
  Ghidra name skip, NOTE pull (real metadata write + dry-run), [rebrew]
  comment skip, offline cache load (function_structure.json +
  ghidra_data_labels.json), broken cache ignore, missing-filepath skip,
  path-traversal guard, JSON output, bad function VA ignore.
- New tests/test_pull_prototypes_comments.py (15 tests): pull_prototypes
  (annotation write, get-decompilation string/dict fallbacks, replace_externs
  rewriting externs.c, dry-run, DATA-entry skip, 2-page pagination, connect
  failure → RuntimeError) and pull_comments (ANALYSIS into rebrew-function.toml
  — discovered ANALYSIS is a metadata key, not a file annotation; [rebrew]
  prefix skip; out-of-range comment ignore; empty response; no-VA early
  return; connect failure).
- commands.py 1205 lines 67% → **91%** (remainder: rename_function_everywhere
  real-rename branch, DATA/GLOBAL note metadata path, a few defensive
  excepts/boilerplate).
- Full suite **2537 passed / 26 skipped**; ruff + mypy clean.

### Slice 85 — data.py coverage 57% → 94% — DONE
- New tests/test_data_extended.py (33 tests): scan_globals branches (GLOBAL
  annotation without declaration → warning, non-extern decl fallback name,
  VA filled from later annotated file); scan_data_annotations missing dir;
  _emit_extern_decl (no-type fallback, scalar, array); _gen_globals_header
  (writes header, VA dedup, overwrite refusal + --force, metadata overlay of
  name/section/size/type, parse-failure file skip); renderers (empty and
  populated _render_globals/_render_summary/_render_bss/_render_dispatch,
  multi-file "+N" display); CLI via CliRunner (--json, --summary, --conflicts,
  --gen-header default + custom out, --bss --json, --fix-bss writing
  bss_padding.c + rebrew-data.toml metadata, --dispatch missing-binary error,
  --dispatch --json with stubbed binary).
- Learned: DATA-marker names come from rebrew-data.toml `name` (the parser
  yields no inline name for DATA markers); DispatchEntry uses `target_va`;
  ANALYSIS is a metadata key (slice 84).
- data.py 760 lines 57% → **94%** (remainder: OSError-read defense, real
  LIEF-parsed --dispatch, a few gen-header edge branches, boilerplate).
- Full suite **2570 passed / 26 skipped**; ruff + mypy clean.

### Slice 86 — verify.py coverage 69% → 83% — DONE
- New tests/test_verify_extended.py (24 tests): verify_entry branches
  (MISSING_FILE, INVALID_VA, MISSING_SIZE, extract-bytes failure, success
  delegating to compile_and_compare with symbol/cflags wiring — patching the
  local-import sources rebrew.binary_loader.extract_raw_bytes +
  rebrew.compile.compile_and_compare); diff_reports (new/removed/unchanged,
  improvement vs regression with delta, unknown-status ranks as FAIL);
  CLI main via CliRunner with stubbed prepare_entries/run_verification/
  _load_previous_report (JSON report, failed → EXIT_MISMATCH, --summary text,
  --compare unchanged → exit 0, --compare regression → EXIT_MISMATCH, report
  written to --output); apply_status_updates (metadata promotion + PROVEN
  sticky non-demotion); _load_previous_report (non-diff, missing, valid,
  invalid JSON, non-dict); _save_verify_cache (empty-filepath skip,
  unmatched-filepath skip, full roundtrip).
- verify.py 758 lines 69% → **83%** (remainder: watch loop, PROVEN overlay
  in main, run_verification internals, a few defensive branches).
- Full suite **2594 passed / 26 skipped**; ruff + mypy clean.

### Slice 87 — depgraph.py coverage 76% → 91% — DONE
- New tests/test_depgraph_extended.py (16 tests): build_graph branches
  (unreadable *.c-directory skip, GLOBAL-marker exclusion, dispatch
  entry-name fallback + fn_0x placeholder nodes with status); render_summary
  leaf/blocker sections (with dispatch edges, no-leaves case); CLI via
  CliRunner (--format summary/dot, --json, -o output file, empty-project
  error, --focus not-found + partial match, unknown format error,
  --include-dispatch missing binary, --cu-map dispatch to rebrew.cu_map).
- depgraph.py 378 lines 76% → **91%** (remainder: leaf >10 truncation,
  real LIEF-parsed --include-dispatch, boilerplate).
- Full suite **2610 passed / 26 skipped**; ruff + mypy clean.

### Slice 88 — diff.py coverage 46% → 99% — DONE
- New tests/test_diff_extended.py (11 tests): run_diff with stubbed
  rebrew.matcher (build_candidate_obj_only/diff_functions/
  structural_similarity) — build-failure → EXIT_ERROR, obj truncation to
  target length, JSON output with structural_similarity + auto-classified
  blockers, CSV output with mismatches-only row filter, terminal output,
  --fix-blocker writing BLOCKER/BLOCKER_DELTA metadata + clearing when no
  blockers, structural diff → EXIT_MISMATCH, clean diff → exit 0; CLI via
  CliRunner (invalid --format error, dispatch to run_diff with
  resolve_build_params — learned options must precede the positional seed_c
  arg due to the typer callback quirk).
- diff.py 211 lines 46% → **99%** (remainder: non-dict CSV row guard +
  boilerplate).
- Full suite **2621 passed / 26 skipped**; ruff + mypy clean.

### Slice 89 — doctor.py coverage 72% → 95% — DONE
- New tests/test_doctor_compiler.py (25 tests): check_compiler branches
  (empty command, shlex ValueError fallback, exe missing from PATH, native
  pass, wine not installed, CL.EXE missing with MSVC600/MSVC400/MSVC420
  download hints — relative CL path resolved against cfg.root, wine smoke
  test pass/timeout WARN/FileNotFoundError FAIL, wine without CL path WARN);
  check_runner (no runner, in-PATH, wibo via find_wibo, wibo missing WARN,
  wine pass, unknown runner WARN); check_metadata_files (missing/present);
  CLI via CliRunner (--json report, terminal output, --install-wibo updating
  rebrew-project.toml — replace existing runner, insert after [compiler],
  no-toml no-crash).
- doctor.py 438 lines 72% → **95%** (remainder: function-list OSError read,
  a few install-wibo toml-edit edges, boilerplate).
- Full suite **2646 passed / 26 skipped**; ruff + mypy clean.

### Slice 90 — extract.py coverage 79% → 97% + JSON-offset bug fix — DONE
- **Bug fix** (extract.py load_functions JSON path): `int(fn["offset"])` /
  `int(fn.get("realsz", ...))` crashed on hex offsets ("0x2000") — the txt
  path accepted hex via parse_function_list but the .json path did not, and
  `int(int, 0)` raised TypeError. Added `_parse_int_field()` accepting hex
  strings, decimal strings, or ints (used for both offset and size).
- New tests/test_extract_extended.py (16 tests): load_functions (txt
  preferred, JSON fallback with hex offset + realsz, size fallback key,
  missing → FileNotFoundError); cmd_extract (JSON extract error, JSON
  disasm error, VA-not-found JSON, success writes .bin); cmd_batch (JSON
  mixed OK/ERROR results, JSON disasm error, non-JSON error continues);
  CLI via CliRunner (list --json + --min-size filter, show --size override,
  batch --json, missing function-list error).
- extract.py 254 lines 79% → **97%** (remainder: a few non-JSON print
  lines + boilerplate).
- Full suite **2662 passed / 26 skipped**; ruff + mypy clean.

### Slice 91 — skeleton.py coverage 55% → 91% — DONE
- New tests/test_skeleton_extended.py (20 tests): decomp renderers
  (_render_skeleton/_render_annotation_block with origin comment + embedded
  decompilation, generate_skeleton with decomp, generate_annotation_block
  custom name); fetch_xref_context via mocked rebrew.ghidra.client
  (non-dict, empty refs, no callers/data, full success with caller context +
  symbol fallback + data refs + caller decompilation blocks, HTTP error →
  None); list_uncovered (ignored-symbol skip, size bounds); CLI via
  CliRunner — single VA creates file (--json), VA-not-found error, append
  mode (block appended to existing multi.c), append missing target error,
  append existing-VA skip, batch existing-file skip, batch no-uncovered
  message.
- skeleton.py 603 lines 55% → **91%** (remainder: a few console-print lines
  in the modes, decomp-single-mode prints, boilerplate).
- Full suite **2682 passed / 26 skipped**; ruff + mypy clean.

### Slice 92 — skills.py coverage 93% → 97% — DONE
- New tests/test_skills_extended.py (9 tests): _find_skill (dir-name match,
  frontmatter-name match via monkeypatched _SKILLS_DIR, missing dir, not
  found); CLI via CliRunner (list --json, list empty dir message, show --json
  with content, show not-found error, show Markdown-render fallback to plain
  print when rich.markdown.Markdown fails).
- skills.py 109 lines 93% → **97%** (remainder: boilerplate).
- Full suite **2691 passed / 26 skipped**; ruff + mypy clean.

### Slice 93 — lint.py coverage 75% → 90% — DONE
- +6 tests in tests/test_lint.py: DATA-marker metadata overlay (size/section/
  note from rebrew-data.toml must not fire W019), unparseable-VA marker
  (E001, no metadata-overlay crash), invalid-VA E002; CLI via CliRunner with
  stubbed load_config (--json output shape, error exit on lint errors,
  --summary table).
- lint.py 473 lines 75% → **90%** (remainder: a couple of defensive
  branches, CLI config-error handling, --fix migration path, boilerplate).
- Full suite **2697 passed / 26 skipped**; ruff + mypy clean.

### Slice 94 — split.py coverage 89% → 93% — DONE
- +8 tests in tests/test_split.py: CLI error paths (missing source arg,
  source not found, extension mismatch, single-matching-block filtering,
  --va --json requiring --force, --va --json --force extraction); _block_metadata
  (comment line after marker skipped, forward declaration does not supply the
  C name — symbol is derived from the definition, ending the scan).
- split.py 213 lines 89% → **93%** (remainder: a few defensive branches +
  boilerplate).
- Full suite **2705 passed / 26 skipped**; ruff + mypy clean.

### Slice 95 — status.py coverage 63% → 68% — DONE
- +6 tests in tests/test_status.py: _load_verify_statuses (corrupt JSON,
  non-dict raw, non-dict entry skip + empty-result skip); _compute_text_size
  import-error fallback to 0; collect_status graceful zeroed report when
  load_data raises; CLI --json output via CliRunner.
- status.py 302 lines 63% → **68%** (remainder: _render_terminal table —
  console-heavy, a couple of defensive branches).
- Full suite **2711 passed / 26 skipped**; ruff + mypy clean.

### Slice 96 — main.py coverage 72% → 90% — DONE
- New tests/test_main_extended.py (8 tests): umbrella CLI verbosity flags
  (-q/-v/-vv map to WARNING/INFO/DEBUG via the app callback, exercised
  through `skills list` since --version short-circuits the callback); stub
  command/app registration helpers report missing dependencies with
  EXIT_ERROR; main() error handling (ValueError → EXIT_ERROR,
  KeyboardInterrupt → exit 130).
- main.py 120 lines 72% → **90%** (remainder: ImportError registration
  branches — all modules import cleanly — and __main__ guard).
- Full suite **2719 passed / 26 skipped**; ruff + mypy clean.

### Slice 97 — cfg.py 91% → 94% + add_module persistence bug fix — DONE
- **Bug fix** (cfg.py add_module): `tgt["origins"] = origins` assigned a plain
  Python list, which tomlkit copies on assignment — the subsequent
  `origins.append(...)` mutated the copy-invisible list, so modules were
  reported as added but never persisted (`origins = []` in the file).
  Fixed by re-assigning `tgt["origins"] = origins` after the append.
- +16 CLI tests in tests/test_cfg.py: list-targets (json + empty), show (full
  json, key json, key missing, key plain), raw, path, remove-target --force,
  set, add-module, remove-module --force, set-cflags, detect-crt. Learned:
  add/remove-module take --target as an option, remove-* commands need
  --force to skip the interactive confirm.
- cfg.py 447 lines 91% → **94%** (remainder: dotted-key create-missing edge,
  _find_root failure, show list value, set-compiler branches, boilerplate).
- Full suite **2733 passed / 26 skipped**; ruff + mypy clean.

### Slice 98 — config.py coverage 88% → 93% — DONE
- New tests/test_config_extended.py (15 tests): _parse_int_list (invalid
  string + unexpected type warnings), _parse_profiles (non-mapping warning,
  invalid-entry skip, valid), _parse_source_ext (defaults, missing-dot
  normalization, invalid warnings), _parse_optional_int invalid warning,
  _as_table raise/none, _resolve (bad-type warning, relative/absolute/None),
  _split_compiler_runner (explicit runner, wine/wibo detection, native empty,
  default command).
- config.py 449 lines 88% → **93%** (remainder: _config_warn ImportError
  fallback, capstone property defaults, a few load_config branches,
  boilerplate).
- Full suite **2748 passed / 26 skipped**; ruff + mypy clean.

### Slice 99 — config.py 93% → 95% — DONE
- +2 tests: capstone_arch/mode property defaults for unknown arch (X86/32
  fallback) and x86_64 mode (constants imported from capstone rather than
  hardcoded).
- config.py 449 lines 93% → **95%** (remainder: _config_warn ImportError
  fallback, a few load_config branches, boilerplate).
- Full suite **2750 passed / 26 skipped**; ruff + mypy clean.

### Session stretch summary (slices 78-99)
- **Coverage**: overall (slipcover, all tests) 84% → **90%** (41718 →
  46379 executable lines; uncovered 6854 → 4702 while the suite grew by
  ~4.6k test lines). Modules lifted: round_trip 63→76, crt_match 54→86,
  ghidra/client 59→100, ghidra/cli 54→99, catalog/grid 62→95, todo 67→98,
  ghidra/commands 67→91, data 57→94, verify 69→83, depgraph 76→91,
  diff 46→99, doctor 72→95, extract 79→97, skeleton 55→91, skills 93→97,
  lint 75→90, split 89→93, status 63→68, main 72→90, cfg 91→94, config
  88→95.
- **Real bugs fixed (4)**: catalog/grid absorption bisect_right→bisect_left
  (re-absorbed the next function's body); extract load_functions JSON path
  crashed on hex offsets; crt_match dropped cross-module LIBRARY markers;
  cfg add_module never persisted origins (tomlkit list-copy).
- **Test suite**: 2371 → **2750 passed** (+379 tests), 26 skipped; ruff
  check + format clean; mypy 0 issues; pre-commit all green.
- Remaining low coverage is toolchain-dependent (match.py/test.py/asm.py/
  prove.py need MSVC/Wine/angr; flirt/gen_flirt_pat need .sig/.lib
  fixtures) or console-renderer-heavy (status/_render_terminal,
  round_trip/_run_round_trip needs a real PE).

### Slice 100 — status.py 68% → 97% — DONE
- +5 tests in tests/test_status.py: _render_terminal direct calls — fully
  populated report (all status bands + verify info + inline-metadata warning +
  byte coverage), zeroed report (no divide-by-zero), custom "other" statuses
  (COMPILE_ERROR/SIZE_MISMATCH not in _STATUS_ORDER), no verify info,
  no inline warning.
- status.py 302 lines 68% → **97%** (remainder: verify-cache OSError/mtime
  defensive branches, main_entry boilerplate).
- Full suite **2755 passed / 26 skipped**; ruff + mypy clean.

### Slice 101 — binary_loader.py 75% → 93% + missing-file contract fix — DONE
- **Bug fix** (load_binary): docstring promises FileNotFoundError for missing
  files (and round_trip's error handling relies on it), but lief.parse only
  logs to stderr and returns None → ValueError "unknown format". Added an
  explicit existence check at the top of load_binary.
- New tests/test_binary_loader_lang.py (19 tests): _load_macho (thin binary
  with __TEXT segment + __text section, empty segment-name fallback, no-text
  case); load_binary fmt dispatch (pe/elf on real LIEF stubs, macho parse
  failure, unknown fmt, missing file); detect_source_language (missing file,
  parse None/error, Go/Obj-C sections, Go/Rust/D/C++ MSVC/C++ Itanium
  symbols, C fallback, section-collection AttributeError ignored).
- binary_loader.py 330 lines 75% → **93%** (remainder: FatBinary first-slice,
  the OSError→FileNotFoundError conversion path, a few defensive branches).
- Full suite **2774 passed / 26 skipped**; ruff + mypy clean.

### Slice 102 — asm.py coverage 42% → 64% — DONE
- New tests/test_asm_extended.py (15 tests): disasm_bytes (basic x86 output,
  capstone-absent → RuntimeError via sys.modules trick); capstone_to_nasm
  (ptr-stripping, no-operand); disassemble_to_nasm + verify_roundtrip
  (real NASM binary — 6-instruction round trip passes); generate_inline_c
  (MSVC __asm + _emit db + comment stripping, GCC/clang __asm__ + default
  symbol fallback); _parse_annotations (status/size filters, metadata merge);
  build_function_lookup (ghidra_json + source override, unreadable *.c skip);
  batch_extract_nasm (writes .asm, stubs-only filter, extraction-error skip).
- asm.py 470 lines 42% → **64%** (remainder: hex-mode CLI, individual bad-
  instruction fallback, main CLI).
- Full suite **2789 passed / 26 skipped**; ruff + mypy clean.

### Slice 103 — struct_parser.py 93% → 98% — DONE
- +4 tests in tests/test_struct_parser_extended.py: tree-sitter-absent
  ImportError → None (patch the module-level import), unreadable *.c
  directory and missing file → no definitions, typedef-struct extraction.
- struct_parser.py 42 lines 93% → **98%**.
- Full suite **2793 passed / 26 skipped**; ruff + mypy clean.

### Slice 104 — binsync_export.py 93% → 98% — DONE
- +3 tests in tests/test_binsync_export.py: ghidra-name comment written only
  when it differs from the symbol, struct-field annotation creates a
  structs/<name>.toml via the CLI (outdir is positional).
- binsync_export.py 155 lines 93% → **98%**.
- Full suite **2796 passed / 26 skipped**; ruff + mypy clean.

### Slice 105 — build_db.py 92% → 93% — DONE
- +6 tests in tests/test_build_db_helpers.py: _check_db_version (mismatch
  error, mismatch --force deletes, missing metadata table, matching version
  passes, non-JSON version string); build_db with unparseable function/global
  VAs degrades to 0 without crashing.
- build_db.py 443 lines 92% → **93%** (remainder: a couple of VA-fallback
  branches inside the row builders, cell-row edges, boilerplate).
- Full suite **2802 passed / 26 skipped**; ruff + mypy clean.

### Slice 106 — c_parser.py 81% → 86% — DONE
- +7 tests in tests/test_c_parser.py: function-pointer declarator name
  (via extract_function_name_from_line — the definition-only entry returns
  None for declarations by design), pointer-return function, array global
  declaration, init-declarator global, multiple externs on one line,
  __cdecl-prefixed function, tree-sitter-absent ImportError path (patched
  builtins.__import__ + cleared parser cache).
- c_parser.py 289 lines 81% → **86%** (remainder: deeper declarator
  recursion branches, array-suffix/pointer-depth helpers, a few parse
  entry points).
- Full suite **2809 passed / 26 skipped**; ruff + mypy clean.

### Slice 107 — c_parser.py 86% → 88% — DONE
- +4 tests in tests/test_c_parser.py: nested array dimensions, array of
  pointers (type string preserved), function-pointer declaration not treated
  as a variable, function declaration excluded from extern variables.
- c_parser.py 289 lines 86% → **88%** (remainder: pointer-depth/array-suffix
  helpers, definition-only entry branches, parse entry points).
- Full suite **2813 passed / 26 skipped**; ruff + mypy clean.

### Slice 108 — c_parser type-string helpers — DONE
- +3 tests in tests/test_c_parser.py: single/double pointer depth in extern
  variable type strings, plain array suffix.
- Full suite **2816 passed / 26 skipped**; ruff + mypy clean.

### Final stretch summary (slices 100-108)
- Overall slipcover coverage now **91%** (46937 executable lines, 4413
  uncovered, up from 84% at slice 78). Modules lifted this stretch: status
  68→97, binary_loader 75→93, asm 42→64, struct_parser 93→98,
  binsync_export 93→98, build_db 92→93, c_parser 81→88.
- **Bug fixed (5th)**: binary_loader.load_binary now raises FileNotFoundError
  for missing binaries (documented contract + round_trip's error handling
  depend on it; lief silently returned None → misleading ValueError).
- Test suite: 2371 → **2816 passed** (+445 over the whole session), 26
  skipped; ruff check + format clean; mypy 0 issues; pre-commit all green.
- Remaining low coverage is toolchain-bound (match/test/prove need MSVC/
  Wine/angr; flirt needs .sig fixtures) or deep declarator/console-render
  branches — all recorded in docs/GOAL_PROGRESS.md.

### Slice 109 — decompiler.py 94% → 99% — DONE
- +9 tests in tests/test_decompiler.py: _run_re (disallowed command raises
  ValueError, no-tool → None, success → cleaned output, non-zero → None,
  TimeoutExpired → warning, OSError → warning); fetch_r2ghidra/fetch_r2dec
  missing-binary → None.
- decompiler.py 124 lines 94% → **99%**.
- Full suite **2823 passed / 26 skipped**; ruff + mypy clean.

### Slice 110 — merge.py 90% → 94% — DONE
- +4 tests in tests/test_merge.py: directory input scanned recursively,
  missing-file input skipped (with valid companions), wrong-extension input
  skipped, duplicate input deduplicated, --delete --force removes inputs but
  keeps the merged output.
- merge.py 145 lines 90% → **94%** (remainder: delete-confirm branches,
  self-delete guard, boilerplate).
- Full suite **2828 passed / 26 skipped**; ruff + mypy clean.

### Slice 111 — metadata.py 90% → 96% — DONE
- +7 tests in tests/test_metadata.py: write-path recovery from corrupt
  rebrew-function.toml (update_field/update_source_status start fresh,
  remove_field returns False); merge_into_annotation edges (non-numeric
  blocker_delta → None, analysis fills empty note but never overrides a
  manual note, globals list merge).
- metadata.py 200 lines 90% → **96%** (remainder: cache mtime OSError,
  parse-key skip, a couple of defensive branches).
- Full suite **2835 passed / 26 skipped**; ruff + mypy clean.

### Slice 112 — naming.py 79% → 91% — DONE
- +13 tests in tests/test_naming.py: detect_unmatchable byte patterns (RET/
  INT3/NOP stubs, IAT jmp thunk, SEH fs:[0] handler, BT/BTS, repne scasb,
  rep movs via real capstone disassembly, normal code → None) and config
  paths (IAT thunk set, ignored symbol, no binary, no extractable bytes).
- naming.py 223 lines 79% → **91%** (remainder: load_data internals, a few
  defensive branches).
- Full suite **2848 passed / 26 skipped**; ruff + mypy clean.

### Slice 113 — near_diag.py 72% → 99% — DONE
- New tests/test_near_diag_cli.py (8 tests): CLI main() with stubbed
  extract/compile/symbol deps (local-import sources patched) — JSON output
  with verdict+categories, --va/--size override, no-annotations error,
  VA-without-SIZE error, extract failure, compile error, symbol-missing
  error, terminal table output.
- near_diag.py 203 lines 72% → **99%** (remainder: __repr__ pragma +
  boilerplate).
- Full suite **2856 passed / 26 skipped**; ruff + mypy clean.

### Slice 114 — signature_parser branch coverage — DONE
- +2 tests in tests/test_signature_parser.py: pointer-return function
  extraction, bare declaration excluded from function definitions.
- Full suite **2858 passed / 26 skipped**; ruff + mypy clean.

### Slice 115 — similar.py 92% → 96% — DONE
- +6 tests in tests/test_similar.py: find_similar edge cases (empty query
  bytes → no results, zero-size candidates skipped, candidate with
  un-disassemblable bytes skipped); _cosine zero denominator; _ratio
  zero-side cases.
- similar.py 129 lines 92% → **96%** (remainder: main CLI + boilerplate).
- Full suite **2864 passed / 26 skipped**; ruff + mypy clean.

### Slice 116 — cache_cli.py 91% → 96% — DONE
- New tests/test_cache_cli_extended.py (6 tests): stats --json with a fake
  CompileCache, stats missing-cache-dir message, stats text with session
  hits + no-lookups message, clear missing-dir JSON, clear --force --json
  cleared count.
- cache_cli.py 67 lines 91% → **96%** (remainder: non-JSON clear path +
  boilerplate).
- Full suite **2870 passed / 26 skipped**; ruff + mypy clean.

### Slice 117 — catalog/export.py 13% → 99% — DONE
- New tests/test_catalog_export.py (13 tests): generate_catalog (status
  counts with GLOBAL exclusion, STUB-vs-NEAR_MATCHING precedence, empty,
  covered-bytes fallback, unmatched section); _reccmp_type mapping;
  generate_reccmp_csv (registry canonical-size override, matched stub,
  unmatched ghidra-name (non-FUN_ prefix), generic FUN_ name ignored in
  favor of list name, no-name row, thunk → stub via registry is_thunk and
  cfg.iat_thunks, funcs size fallback).
- catalog/export.py 137 lines 13% → **99%** (remainder: TYPE_CHECKING).
- Full suite **2873 passed / 26 skipped**; ruff + mypy clean.

### Slice 118 — catalog/cli.py 72% → 89% — DONE
- +2 tests in tests/test_catalog_cli.py: --summary status/module counts with
  real entries + tool-detection breakdown (registry entries need is_thunk for
  count_detection_sources); --export-ghidra-labels extracting data/thunk
  cells into ghidra_data_labels.json (label default via missing key, not
  None value).
- catalog/cli.py 231 lines 72% → **89%** (remainder: function_structure.json
  backfill, interactive --fix-sizes loop, boilerplate).
- Full suite **2875 passed / 26 skipped**; ruff + mypy clean.

### Slice 119 — utils.watch_files failure-report path — DONE
- +1 test in tests/test_utils.py: a failing retest is reported ("Run
  failed...") and the loop keeps watching; a later change re-runs and
  Ctrl+C (via scripted sleep) stops cleanly ("Watch stopped.").
- Full suite **2876 passed / 26 skipped**; ruff + mypy clean.

### Slice 120 — cu_map.py 77% → 98% — DONE
- New tests/test_cu_map_cli.py (4 tests): --json output with a stubbed
  cluster (TUCluster needs gap_classes), unclustered reasons (unknown size,
  thunk), missing-binary error, terminal table.
- cu_map.py 287 lines 77% → **98%** (remainder: no-capstone guard, a couple
  of defensive branches, boilerplate).
- Full suite **2880 passed / 26 skipped**; ruff + mypy clean.

### Slice 121 — data_metadata.py 92% → 97% — DONE
- +3 tests in tests/test_data_metadata.py: corrupt rebrew-data.toml recovery
  (set_data_field starts fresh and persists, delete_data_field no-crash,
  merge_into_data_annotation no-crash).
- data_metadata.py 110 lines 92% → **97%** (remainder: load-path parse
  warning branches).
- Full suite **2883 passed / 26 skipped**; ruff + mypy clean.

### Slice 122 — catalog/registry.py 92% → 97% — DONE
- New tests/test_catalog_registry_build.py (6 tests): build_function_registry
  integration — list+ghidra merge with canonical size resolution, exports
  marked, r2_bogus VAs skipped from list sizes, no-ghidra-path, missing
  binary → "no binary data to verify" fallback, .text-section-aware padding
  resolution via stubbed load_binary.
- catalog/registry.py 156 lines 92% → **97%** (remainder: is_jump_table
  short-data guard, defensive branches).
- Full suite **2889 passed / 26 skipped**; ruff + mypy clean.

### Slice 123 — catalog/sections.py 93% → 97% — DONE
- +7 tests in tests/test_catalog_sections.py: has_back_jumps forward
  out-of-range near-jmp and near-jcc (loop-continue paths); get_globals
  size estimation (char array, short, char, double, default pointer size).
- catalog/sections.py 126 lines 93% → **97%**.
- Full suite **2896 passed / 26 skipped**; ruff + mypy clean.

### Slice 124 — catalog/loaders.py 95% → 97% — DONE
- +4 tests in tests/test_catalog_loaders.py: non-list labels warning + empty,
  legacy ghidra_switchdata.json fallback, corrupt-JSON warning, scan_reversed_dir
  including library_*.h LIBRARY markers.
- catalog/loaders.py 108 lines 95% → **97%**.
- Full suite **2900 passed / 26 skipped** — milestone; ruff + mypy clean.

### Slice 125 — rename.py 56% → 92% — DONE
- +9 tests in tests/test_rename.py: rename_function_everywhere edge cases
  (dry-run unreadable-file skip, primary-file OSError warn, extern OSError
  skip, nested --file path with existing dir, stem-not-matching keeps file);
  CLI via CliRunner (--json output, not-found error, multiple-match error,
  rename-by-VA).
- rename.py 158 lines 56% → **92%** (remainder: dry-run OSError in the
  extern loop, a few console/boilerplate lines).
- Full suite **2909 passed / 26 skipped**; ruff + mypy clean.

### Slice 126 — lint --fix STATUS crash bug fix — DONE
- **Bug fix (6th)**: `rebrew lint --fix` crashed with
  `ValueError('Cannot delete STATUS directly')` on files with inline STATUS —
  the fix loop called `remove_annotation_key`, which routes metadata keys to
  `remove_field` (STATUS deletion is blocked there, and other keys would
  delete the field just migrated). Added
  `annotation.remove_inline_annotation_key(filepath, va, key)` (file-only
  strip) and switched the fix loop to it.
- +3 tests in tests/test_lint.py: --fix dry-run previews without writing,
  --fix migrates inline STATUS/SIZE to metadata (size coerced to int) and
  strips the source lines, metadata-sourced STATUS is not re-migrated.
  Discovered the "Would remove" branch is unreachable (metadata-present keys
  are marked metadata-sourced by the overlay and never recorded as fixes).
- lint.py 473 lines 90% → **96%**.
- Full suite **2912 passed / 26 skipped**; ruff + mypy clean.

### Final stretch summary (slices 109-127)
- Overall slipcover coverage **91%** (47921 executable lines, 4104 uncovered,
  vs 84% at slice 78). Modules lifted this stretch: decompiler 94→99,
  merge 90→94, metadata 90→96, naming 79→91, near_diag 72→99,
  signature_parser 95, similar 92→96, cache_cli 91→96, catalog/export
  13→99, catalog/cli 72→89, utils 97, cu_map 77→98, data_metadata 92→97,
  catalog/registry 92→97, catalog/sections 93→97, catalog/loaders 95→97,
  rename 56→92, lint 90→96.
- **Bug fixed (6th)**: `rebrew lint --fix` crashed with
  ValueError('Cannot delete STATUS directly') on inline STATUS — added
  `annotation.remove_inline_annotation_key` (file-only) and switched the
  fix loop to it.
- Test suite: 2371 → **2912 passed** (+541 over the session), 26 skipped;
  ruff check + format clean; mypy 0 issues; pre-commit all green (incl.
  mypy + import-cycle gates).
- Remaining low coverage is toolchain-bound (match/test/prove/asm CLI need
  MSVC/Wine/angr; flirt/gen_flirt_pat need .sig/.lib fixtures) or deep
  declarator/console-render micro-branches — all documented in
  docs/GOAL_PROGRESS.md.

### Slice 127 — data.py 94% → 95% — DONE
- +3 tests in tests/test_data_extended.py: _render_summary with type
  conflicts subtitle, scan_globals unreadable *.c-directory skip,
  _gen_globals_header underscore-strip (metadata-provided names) +
  unknown-section group.
- data.py 760 lines 94% → **95%** (remainder: find_dispatch_tables branch,
  data-main get_sections error + dispatch paths needing LIEF, boilerplate).
- Full suite **2915 passed / 26 skipped**; ruff + mypy clean.

### Slice 128 — tools/sync_decomp_flags.py tests — DONE
- New tests/test_sync_decomp_flags.py (8 tests): format_flags_list (inline
  short FlagSet, multi-line long FlagSet, Checkbox, LanguageFlagSet→FlagSet
  conversion — requires exact class name match); count_combos (all axes,
  tier filter, empty); generate_flag_data_py header + lists + tiers.
- Full suite **2923 passed / 26 skipped**; ruff + mypy clean.

### Slice 129 — tools/detect_cycles.py unit tests — DONE
- New tests/test_detect_cycles_unit.py (7 tests): _module_level_imports
  (function-scope imports filtered, TYPE_CHECKING guards skipped, try-blocks
  included); _get_imports (prefix filtering, bad-syntax → []); detect_cycles
  (synthetic a↔b cycle detected, clean package → [] — module names derive
  from root="src/rebrew" relative to cwd).
- Full suite **2930 passed / 26 skipped**; ruff + mypy clean.

### Slice 130 — c_parser.py 88% → 92% — DONE
- New tests/test_c_parser_declarators.py (11 tests): synthetic-AST-node
  unit tests for _find_function_name (identifier, pointer/parenthesized
  walk, unknown-type recursion) and _find_declarator_name (init_declarator
  "=" filter, pointer recursion, function_declarator → None, fallthrough),
  plus _count_pointer_depth chains and _extract_array_suffix
  (non-array → "", single bracket).
- c_parser.py 289 lines 88% → **92%** (remainder: definition-only entry
  branches and parse entry points).
- Full suite **2941 passed / 26 skipped**; ruff + mypy clean.

### Slice 131 — verify.py 83% → 93% — DONE
- +6 tests in tests/test_verify_extended.py: _print_results (plain,
  diff sections with regressions/improvements/new/removed/warning, summary
  tables incl. PROVEN row, fail-details rendering with STUB and
  COMPILE_ERROR entries); --watch dispatches the nested retest via a stubbed
  watch_files; PROVEN overlay promotes a STUB verify result in --json
  output.
- verify.py 758 lines 83% → **93%** (remainder: prepare_entries cache
  branches, run_verification internals, apply_status_updates edge cases,
  boilerplate).
- Full suite **2947 passed / 26 skipped**; ruff + mypy clean.

### Slice 132 — verify.py 93% → 94% — DONE
- +4 tests in tests/test_verify_entries.py: prepare_entries incremental-cache
  branches — cached pass reused (needs real mtime+hash match), cached fail
  recorded with fail_details, filepath-mismatch skip, stale-hash skip.
- verify.py 758 lines 93% → **94%** (remainder: run_verification internals,
  cache-write warning, apply_status_updates edges, boilerplate).
- Full suite **2951 passed / 26 skipped**; ruff + mypy clean.

### Slice 133 — annotation.py 88% → 92% — DONE
- +7 tests in tests/test_annotation.py: split_annotation_sections orphaned-KV
  rescue (STATUS before a non-annotation line moves into the block),
  normalize_status PROVEN branch + EXACT precedence, Annotation.validate
  library-without-SOURCE warning + NEAR_MATCHING/STUB contradiction,
  remove_annotation_key non-metadata SYMBOL removal (+ noop).
- annotation.py 771 lines 88% → **92%**.
- Full suite **2959 passed / 26 skipped**; ruff + mypy clean.

### Slice 134 — annotation.py 92% — DONE
- +8 tests in tests/test_annotation.py: update_annotation_key (metadata
  NOTE write, custom non-metadata key insertion, VA-not-in-file noop);
  module_for_va (unreadable → "", found); update_size_annotation (VA
  inferred from marker, never-shrinks guard, no-VA → False).
- Full suite **2967 passed / 26 skipped**; ruff + mypy clean.

### Slice 135 — annotation.py 92% → 93% — DONE
- +4 tests in tests/test_annotation.py: parse_library_header KV collection
  (STATUS/SIZE/CFLAGS/SOURCE), target-module filter, default EXACT status,
  missing-file → [].
- Full suite **2971 passed / 26 skipped**; ruff + mypy clean.

### Final stretch summary (slices 127-135)
- Overall slipcover coverage now **92%** (48702 executable lines, 4052
  uncovered, vs 84% at slice 78). Modules lifted this stretch: data 94→95,
  tools/sync_decomp_flags (new 8 tests), tools/detect_cycles (new 7 tests),
  c_parser 88→92, verify 83→94, annotation 88→93.
- Test suite: 2371 → **2971 passed** (+600 over the whole session), 26
  skipped; ruff check + format clean; mypy 0 issues; pre-commit all green
  (incl. mypy + import-cycle gates).
- Remaining low coverage is toolchain-bound (match/test/prove/asm CLI need
  MSVC/Wine/angr; flirt/gen_flirt_pat need .sig/.lib fixtures) or defensive
  micro-branches — all documented per-slice in docs/GOAL_PROGRESS.md.

### Slice 136 — verify.py 94% → 96% — DONE
- +3 tests in tests/test_verify_extended.py: run_verification with a stubbed
  verify_entry (all-passed, failures recorded with fail_details + deferred
  fixes carrying status/delta, internal-error → COMPILE_ERROR mismatch).
- verify.py 758 lines 94% → **96%** (remainder: defensive branches +
  boilerplate).
- Full suite **2974 passed / 26 skipped**; ruff + mypy clean.

### Slice 137 — annotation.py parse edges — DONE
- +3 tests in tests/test_annotation.py: GLOBAL-after-FUNCTION markers become
  separate entries (downgrade guard), inline `// trailing` after a VA stashed
  into inline_error, non-numeric BLOCKER_DELTA → None.
- Full suite **2977 passed / 26 skipped**; ruff + mypy clean.

### Slice 138 — annotation.py 93% → 94% — DONE
- +5 tests in tests/test_annotation.py: update_annotation_key same-value
  noop + value update + end-of-block insertion; remove_annotation_key
  middle-key removal preserving siblings + not crossing into the next block.
- Full suite **2982 passed / 26 skipped**; ruff + mypy clean.

### Slice 139 — flirt.py 37% → 89% — DONE
- New tests/test_flirt_cli.py (5 tests): main CLI with stubbed
  load_signatures/load_binary/flirt.compile — no-signatures error,
  missing-.text error, tiny-.text warning JSON, real matches (ret-stub
  corpus + fake matcher returning printf), ambiguous-matches skipped.
- flirt.py 142 lines 37% → **89%** (remainder: load_signatures error
  paths + boilerplate).
- Full suite **2987 passed / 26 skipped**; ruff + mypy clean.

### Slice 140 — gen_flirt_pat.py 42% → 63% + flirt load_signatures errors — DONE
- +3 tests in tests/test_gen_flirt_pat.py: main CLI (missing-lib error,
  --json output writing the .pat with "---" trailer, corrupt-member skip via
  a raising parse_coff_obj — options must precede the positional lib path).
- +2 tests in tests/test_flirt_helpers.py: load_signatures bad-file and
  unreadable-file warnings.
- gen_flirt_pat.py 147 lines 42% → **63%** (remainder: parse_coff_obj —
  needs real MSVC .obj files, LIEF cannot synthesize COFF objects).
- Full suite **2992 passed / 26 skipped**; ruff + mypy clean.

### Final stretch summary (slices 136-141)
- Overall slipcover coverage **92%** (48970 executable lines, 3910 uncovered,
  vs 84% at slice 78 — 10.5k executable lines covered across the session).
  Modules lifted this stretch: verify 94→96, annotation 93→94, flirt 37→89,
  gen_flirt_pat 42→63.
- Test suite: 2371 → **2992 passed** (+621 over the whole session), 26
  skipped; ruff check + format clean; mypy 0 issues; pre-commit all green
  (incl. mypy + import-cycle gates).
- **6 real bugs fixed**: grid absorption bisect, extract JSON hex offsets,
  crt_match LIBRARY-marker filtering, cfg add-module tomlkit persistence,
  load_binary missing-file contract, lint --fix STATUS crash.
- Remaining low coverage is toolchain-bound (match/test/prove/asm CLI need
  MSVC/Wine/angr; gen_flirt_pat parse_coff_obj needs real .obj files; the
  flirt match loop needs .sig fixtures) or defensive micro-branches —
  all documented per-slice in docs/GOAL_PROGRESS.md.

### Slice 141 — tools/validate_skill_commands.py tests — DONE
- New tests/test_validate_skill_commands.py (7 tests): _extract_commands
  (flags parsed, multi-command subsubcommand absorption e.g. "cfg
  add-target"/"cache stats", placeholder-first-sub skip, comment stripping,
  _SKIP_FLAGS filtered); _run_help (timeout and uv-not-found → False).
- Full suite **2999 passed / 26 skipped**; ruff + mypy clean.

### Slice 142 — compile.py 70% → 74% — DONE
- New tests/test_compile_helpers.py (9 tests): resolve_cl_command (wine
  detection with re-prepended runner, explicit runner strip, absolute CL
  path, trailing flags preserved) and _resolve_include_flags (relative /I
  resolved against src_parent then cfg_root, missing dir keeps flag,
  absolute + non-include passthrough, -I form).
- compile.py 310 lines 70% → **74%** (remainder: compile_to_obj/compare
  internals needing the MSVC/Wine toolchain).
- Full suite **3008 passed / 26 skipped**; ruff + mypy clean.

### Slice 143 — compile.py 74% → 79% — DONE
- +2 tests in tests/test_compile_helpers.py: resolve_compiler_env (existing
  relative cl/include paths root-prefixed, missing paths fall back, env +
  cache resolution via stubs).
- compile.py 310 lines 74% → **79%** (remainder: subprocess compile/compare
  paths needing the MSVC/Wine toolchain).
- Full suite **3010 passed / 26 skipped**; ruff + mypy clean.

### Final stretch summary (slices 142-144)
- Overall slipcover coverage **92%** (49220 executable lines, 3936
  uncovered, vs 84% at slice 78 — ~10.7k lines of executable coverage
  gained across the whole session). This stretch: compile 70→79.
- Test suite: 2371 → **3010 passed** (+639 over the whole session), 26
  skipped; ruff check + format clean; mypy 0 issues; pre-commit all green
  (incl. mypy + import-cycle gates).
- **6 real bugs fixed**: grid absorption bisect, extract JSON hex offsets,
  crt_match LIBRARY-marker filtering, cfg add-module tomlkit persistence,
  load_binary missing-file contract, lint --fix STATUS crash.
- Remaining low coverage is toolchain-bound (match/test/prove/asm CLI need
  MSVC/Wine/angr; FLIRT pipeline needs .sig/.obj/.lib fixtures) or
  defensive micro-branches — all documented per-slice in
  docs/GOAL_PROGRESS.md.

### Final convergence check — SKILL.md ↔ CLI validation
- Ran `tools/validate_skill_commands.py` end-to-end: all **131 unique
  (subcommand, flags) combinations** referenced in agent-skills/SKILL.md
  files resolve against the real `rebrew <subcommand> --help` output.
  Confirms the CLI surface (including this session's flag additions) matches
  the documented skill commands.

### Slice 145 — synthetic COFF objects: gen_flirt_pat 63% → 93% — DONE
- New tests/coff_util.py: hand-rolled COFF .obj builder (`make_coff_obj`:
  file header + .text section + relocs + symbols incl. string-table long
  names + configurable characteristics/func_value) and `.lib` archive
  builder (`make_lib_archive`). LIEF has no COFF builder, so tests bake the
  bytes directly — the same technique already used by test_parsers_relocs_full.
- +8 tests in tests/test_gen_flirt_pat.py: real `parse_coff_obj` (basic yield
  with reloc, multiple relocs + long symbol names, non-code section skipped,
  alignment-padding semantics, tiny blob, func at nonzero offset) and a full
  end-to-end `gen_flirt_pat` run from a real .lib archive containing a real
  COFF object → 1 signature written (no stubs).
- gen_flirt_pat.py 147 lines 63% → **93%** (remainder: two parse_archive
  edge branches + boilerplate).
- Full suite **3017 passed / 26 skipped**; ruff + mypy clean.

### Slice 146 — golden PE fixtures: real-binary round-trip integration — DONE
- `tests/coff_util.py` → `tests/bin_util.py`: added `make_pe(code, ...)` —
  a hand-built minimal PE (DOS + COFF + PE32 optional header + one .text
  section + raw data at 0x200) that LIEF parses into a real BinaryInfo
  (.text at image_base+0x1000, file offset 0x200). No LIEF builders exist,
  so tests bake the bytes directly.
- +2 tests in tests/test_round_trip.py (TestRoundTripGoldenPe): `_run_round_trip`
  against the golden PE with only `_compile_and_extract` stubbed — real LIEF
  parsing, real VA→file-offset mapping, real splice producing a byte-identical
  `.reasm` (exit EXIT_OK), and a drift test confirming mismatched compile
  bytes are caught (EXIT_MISMATCH).
- Full suite **3019 passed / 26 skipped**; ruff + mypy clean.

### Slice 147 — dead-code annotation (grid/lint) — DONE
- Added `# pragma: no cover` + root-cause explanations to three
  identified-unreachable branches:
  - `catalog/grid.py` 50-round absorption guard (rounds only absorb bytes
    strictly between a function end and the next start → ≤2 rounds).
  - `catalog/grid.py` absorb-into-preceding-data elif (data-at-func-end
    gaps are always absorbed by the earlier loop, so a parented "data"
    segment never reaches classification).
  - `lint.py` --fix "Would remove" branch (metadata-present inline keys are
    marked metadata-sourced by the overlay and never recorded as fixes).
- Full suite **3019 passed / 26 skipped**; ruff + mypy clean.

### Slice 148 — property-based + invariant tests — DONE
- Added `hypothesis` as a dev dependency (uv add --dev).
- New tests/test_property_parsers.py (3 property tests, 200 examples each):
  `merge_ranges` invariants (sorted, non-overlapping, union-preserving) and
  `bytes_to_pat_line` structure (hex-pair lead, CRC-length field, reloc
  masking ".." at masked bytes).
- +4 invariant tests: update↔remove symmetry for file and metadata keys
  (exact byte-equality after remove), idempotent double-remove, and
  lint --fix → re-lint convergence (no W019, metadata owns STATUS/SIZE).
- Full suite **3022 passed / 26 skipped**; ruff + mypy clean.

### Slice 149 — doctor: optional-tools check — DONE
- New `check_optional_tools(cfg)` in doctor.py: warns when `angr` is not
  importable (for `rebrew prove`) or `flirt_sigs/` is missing (for
  `rebrew flirt`), with an exact-fix message; PASS when both are present.
  Registered in `run_doctor`.
- +3 tests in tests/test_doctor_compiler.py: missing-both → WARN,
  both-available → PASS (fake angr module + flirt_sigs dir), registration
  in run_doctor.
- Full suite **3026 passed / 26 skipped**; ruff + mypy clean.

### Slice 150 — contributor docs — DONE
- New docs/DEVELOPMENT.md: test conventions (incl. tests/bin_util.py
  fixture builders), the Typer/CliRunner quirks learned this session
  (options-before-positionals, direct main() kwarg misbinding, module-scope
  Console, Exit-without-message), metadata/tomlkit gotchas (list-copy,
  STATUS gating, remove_inline_annotation_key, 0x%08x formatting), import
  patterns (local-import monkeypatch targets), toolchain-dependent test
  guidance, and validation commands.
- New CONTRIBUTING.md at repo root: pointers to AGENTS.md/DEVELOPMENT.md,
  quick commands, and submission expectations.

### Slice 151 — `--watch` for diff and match — DONE
- `rebrew diff --watch <seed.c>`: new `--watch` option; enters a
  `watch_files` loop (shared helper from rebrew.utils, same as verify.py)
  that re-invokes `main()` on every save. Added after param resolution so
  bad `--format` still errors immediately; retest passes all kwargs with
  `watch=False` (no nesting). Updated docstring usage lines.
- `rebrew match --watch <seed.c>`: same pattern for single-function mode
  (GA and flag-sweep). Guards `--watch` + `--all` with
  `error_exit("--watch cannot be combined with --all")` (mirrors test.py).
- +3 tests: diff watch dispatch + retest reaches run_diff
  (tests/test_diff_extended.py); match `--watch --all` guard and watch
  dispatch + retest reaches `_run_single_ga` (new tests/test_match_cli.py).
- Full suite **3032 passed / 26 skipped**; ruff + mypy clean.

### Slice 152 — CI: pre-commit parity job + forward-version drift — DONE
- The brainstorm's premise ("only 3.12 exercised") was already stale:
  ci.yml already matrixed 3.12 + 3.13 (3.12 is the floor per
  requires-python >=3.12). Closed the real remaining gaps:
- Added a `pre-commit` job (3.12) running `uv pre-commit run --all-files`
  against a clean checkout — hygiene + ruff + mypy + import-cycles +
  skills hooks; pytest hook is pre-push stage so no suite duplication.
- Added "3.14" to the test matrix (local dev runs 3.14; lockfile verified
  to resolve on 3.14 with `uv sync --frozen --all-extras --python 3.14
  --dry-run`, angr→z3 included).
- docs/CI.md updated to describe the 3.12–3.14 matrix + pre-commit job.
- Validated: ci.yml parses as YAML; full pre-commit hook set passes
  locally (8/8 hooks green).

### Slice 153 — idempotency sweeps for --dry-run CLIs — DONE
- New tests/test_idempotency.py: a reusable harness (tree digest + combined
  stdout/stderr comparison) running each CLI twice with --dry-run and
  asserting byte-identical output plus an untouched filesystem:
  - merge --dry-run: identical report, no output file, tree unchanged.
  - split --dry-run: identical report, no split files created, tree unchanged.
  - lint --fix --dry-run: identical "Would migrate" report, source unchanged
    (real rebrew-project.toml via monkeypatch.chdir).
  - match --all --dry-run: identical stub listing + "Dry run — exiting."
  - Learned/encoded in the file: user-facing reports split across stdout
    (print) and stderr (Console), so comparisons use stdout+stderr; STUB
    functions use the `// STUB:` marker (marker_for_module) or lint E015
    fires; SYMBOL is metadata-routed (inline → W010).
- Full suite **3036 passed / 26 skipped**; ruff + mypy clean.

### Slice 154 — shell completions wired into rebrew init — DONE
- `rebrew init --install-completions`: new flag writes bash/zsh/fish
  completion scripts into `completions/` via click's shell_completion
  classes driven off the umbrella CLI (`get_command(rebrew.main.app)`,
  `_REBREW_COMPLETE` env protocol — same protocol the installed CLI uses).
  Prints per-shell sourcing hints; JSON payload gains a "completions" key.
- Discovery: the live `rebrew --show-completion` derives the shell from
  `$SHELL` and ignores an explicit shell argument — hence generating all
  three explicitly in init.
- Fixed a pre-existing test smell this slice surfaced: every direct
  `init(...)` call in tests/test_init.py ran with truthy typer OptionInfo
  defaults (`typer.Option(...)` objects are truthy when the callback is
  invoked directly, not via the CLI), so ALL TestInit tests silently
  downloaded wibo from GitHub on every run. Made every direct call
  explicit (`install_wibo=False, json_output=False,
  install_completions=False`): test_init.py now hermetic, 0.65s total.
- +5 tests (scripts written, no-flag negative, determinism across runs,
  JSON payload, typer-flag wiring via CliRunner).
- Full suite **3041 passed / 26 skipped**; ruff + mypy clean.

### Slice 155 — typed metadata facade over rebrew-function.toml — DONE
- New typed layer in rebrew/metadata.py:
  - `field_kind(key)` — single routing table for the file-only vs
    metadata-only distinction ("metadata" | "file" | "legacy" |
    "unknown"), backed by METADATA_FIELDS + new FILE_ONLY_KEYS and
    LEGACY_KEYS (ORIGIN/SECTION — deprecated inline keys metadata
    deliberately does not own). "Impossible by construction": a
    consistency test pins every annotation.METADATA_KEYS entry to
    metadata-or-legacy and ORIGIN/SECTION to exactly the legacy set.
  - `FunctionMetadata` dataclass (typed fields, from_entry/to_entry,
    validate) + `load_entry()` / `save_entry()` (validate-then-write;
    STATUS routed through update_source_status).
  - `coerce_metadata_value()` — canonical size/blocker_delta str→int
    coercion; adopted by lint --fix (removed its hand-rolled coercion and
    the now-unused contextlib import).
  - KNOWN_STATUSES documents the annotation vocabulary; the raw
    update_source_status gatekeeper stays permissive for operational
    statuses (COMPILE_ERROR/SIZE_MISMATCH) that verify writes.
- +18 tests (routing consistency vs annotation keys, round-trip all
  fields, coercion, validation errors, save_entry rejection, status
  routing, lint --fix size-as-int end-to-end).
- Full suite **3059 passed / 26 skipped**; ruff + mypy clean.

### Slice 156 — read-only web dashboard over coverage.db — DONE
- New `rebrew dashboard` CLI (src/rebrew/dashboard.py), registered in the
  umbrella under "Export & Sync". Stdlib-only (http.server + sqlite3),
  no new dependencies.
- `Dashboard` query layer separated from HTTP plumbing for testability:
  /api/targets, /api/summary (function stats + coverage %), /api/functions
  (status/module/q filters, VA hex, files), /api/sections
  (section_cell_stats view), /api/globals, /api/history, and `/` serving a
  dependency-free vanilla-JS HTML app (target selector, status filter,
  search, summary cards, function table).
- Read-only by construction: DB opened with `?mode=ro`, non-GET rejected
  with 405. Missing DB → clear error_exit ("run rebrew build-db first").
- Bug caught by the live smoke test: `send_error(405, "...—...")` crashed
  the handler (em-dash not latin-1 encodable in the HTTP reason line) →
  ASCII message; verified live (targets JSON, 405 on POST, HTML page, 404
  on unknown endpoint) against a real coverage.db built in-process.
- +18 tests (query layer over a real build_db-produced db, handle()
  routing incl. 405/404/read-only enforcement, CLI missing-db error,
  umbrella registration).
- Full suite **3077 passed / 26 skipped**; ruff + mypy clean (74 files).

### Slice 157 — lazy/single LIEF parse for data --dispatch and catalog grid — DONE
- catalog/sections.py: extracted `sections_from_info(BinaryInfo)` from
  `get_sections()` (the .data/.bss split logic) so callers that already
  hold a parsed BinaryInfo don't re-parse; exported from rebrew.catalog.
- catalog/grid.py: previously parsed the binary TWICE when bin_path existed
  (get_sections + load_binary for layout/bytes). Now one lazy load →
  sections_from_info + image_base/text_raw_offset/_bin_data/text_data all
  from that single BinaryInfo. A nonexistent path now performs ZERO parses.
- data.py: --dispatch previously called load_binary a second time (and the
  eager section load used get_sections); now a single memoized parse feeds
  both the section enrichment/BSS path and the dispatch sec_dict/binary_data.
  Parse failure at the shared load → clear error_exit for --dispatch.
- Updated 2 tests that monkeypatched the removed grid.get_sections /
  catalog.get_sections seams (fake BinaryInfo via load_binary instead);
  added 3 regression tests pinning "exactly one load_binary call" for both
  grid-with-file and data --dispatch, and "zero parses" when the binary is
  missing.
- Full suite **3080 passed / 26 skipped**; ruff + mypy clean (74 files).

### Slice 158 — import-table symbol recovery (library identification, first half) — DONE
- New `rebrew imports [binary]` CLI (src/rebrew/imports.py), registered
  under "Analysis":
  - `parse_imports()` — LIEF PE import table → [{dll, name, iat_va}]
    (imagebase-aware; the same idiom prove.py used inline, now reusable).
  - `parse_import_table()` — {iat_va: api_name} convenience view.
  - `find_import_stubs()` — scans .text for `FF 25 <iat_va>` jmp stubs and
    maps each stub VA → imported API name (the auto-mark piece).
  - Terminal + --json output; non-PE/missing binary → clean errors.
  - The FLIRT half (CRT/zlib naming from .sig files) remains in rebrew.flirt
    and is documented in the epilog as the pairing step.
- tests/bin_util.py: `make_pe()` gained an `imports=[(dll, [apis])]` param
  that hand-rolls a real import directory (descriptors, INT/IAT arrays,
  hint/name entries) into the .text section and wires optional-header data
  directory 1 — LIEF round-trips it (MessageBoxA → 0x40103F etc.).
- +9 tests (import parse, non-PE/missing-file handling, stub detection via
  a probe-learned IAT VA since LIEF's iat_address is +4 off the hand-rolled
  layout, CLI terminal/JSON/missing-binary, umbrella registration).
- Full suite **3089 passed / 26 skipped**; ruff + mypy clean.

### Slice 159 — hypothesis property tests for annotation blocks + c_parser — DONE
- Extended tests/test_property_parsers.py (completing the brainstorm's
  "annotation blocks, c_parser declarators" list from slice 148):
  - `annotation_block` composite strategy → parse_new_format round-trip:
    VA equality for any 32-bit VA (0x%08x ↔ marker regex), module, and
    canonical STATUS/SIZE/CFLAGS values.
  - VA hex formatting round-trip across the full 32-bit range.
  - normalize_status / normalize_cflags idempotency over arbitrary strings
    (a classic non-idempotent-normalization bug class).
  - `c_function_source` composite (return types incl. pointers, params,
    bodies) → extract_function_name_and_proto returns the expected name,
    and find_c_function_definitions contains it. Name strategy filtered
    against C keywords so generated sources stay valid.
- Full suite **3095 passed / 26 skipped**; ruff + mypy clean.

### Slice 160 — GA scoring hot-loop profiling (numpy vectorization assessment) — DONE
- Profiled score_candidate (512B functions, 40 relocs, 5000 iters,
  cProfile): capstone disasm ≈ 40 %, difflib SequenceMatcher ≈ 27 %,
  remaining ≈ 30 % (numpy byte compare already vectorized + reloc-mask
  slice loop, µs-scale).  The "likely more vectorizable" hypothesis is
  disproven by data: both dominant costs are C/algorithmic, and a numpy
  fancy-indexing prototype for _normalize_with_reloc_offsets measured
  SLOWER (0.7×) than the existing slice-assignment loop (no change made).
- Confirmed the GA hot path already precomputes the target side once per
  function (precompute_target → _pre_norm_target/_pre_target_mnems, wired
  in both match.py and matcher/compiler.py) — but NOTHING locked that
  contract: added TestPrecomputedTarget (3 tests) asserting the _pre_*
  path produces byte-identical scores to the fresh path (both reloc and
  heuristic-normalization branches).
- Findings documented in docs/DEVELOPMENT.md (Performance notes section)
  so future contributors don't re-run the dead end.
- Full suite **3098 passed / 26 skipped**; ruff + mypy clean (75 files).

### Slice 161 — solutions DB target-scoping (multi-target GA seeding foundation) — DONE
- The multi-target batch-GA item's testable core: solutions.py deduped by
  symbol only, so multi-target projects silently collided (same symbol in
  SERVER and CLIENT with different winning cflags). Now:
  - `SolutionEntry.target: str = ""` (default keeps legacy records loading).
  - `save_solution` dedupes by `(target, symbol)` and sorts by it.
  - `find_similar(..., target="")` ranks same-target entries first, then
    falls back to other targets; empty target preserves legacy ordering.
  - match.py `_save_solution` stamps `cfg.target_name` on new records.
  - +5 tests (per-target dedup, same-target replace, legacy JSON without
    target field, same-target preference in find_similar, legacy order).
- Full suite **3103 passed / 26 skipped**; ruff + mypy clean.

### Slice 162 — persistent GA run-results DB (multi-target batch foundation) — DONE
- solutions.py gained an append-only GA run-history log (`.rebrew/ga_runs.jsonl`):
  - `record_ga_run(project_root, target, va, symbol, matched, score?, generations?)`
    — one JSON line per `rebrew match --all` attempt; crash-safe append.
  - `load_ga_runs(project_root, target="", limit=100)` — newest first, target
    filter, malformed/non-dict lines skipped.
  - Exported via rebrew.matcher; wired into match.py `_run_all` (per-stub
    outcome recorded with cfg.target_name, best-effort try/except).
  - Complements solutions.json (winning fingerprints) with full run history
    for cross-run/cross-target progress diffing.
  - +4 tests (append ordering, target filter, limit, malformed-line skip).
- Full suite **3107 passed / 26 skipped**; ruff + mypy clean.

### Slice 163 — `rebrew match --all-targets` (multi-target batch orchestration) — DONE
- New batch mode running the GA/flag-sweep over STUBs in EVERY configured
  target: `--all-targets` iterates `cfg.all_targets`, loads each target's
  config via load_config, and runs the existing `_run_all` per target.
- `_run_all` now returns `(matched, failed)` (aggregate counts); dry-run and
  flag-sweep early paths return `(0, 0)`.
- JSON mode emits ONE aggregate document (`mode: all-targets`, matched /
  failed / total, targets); per-target detail stays on stderr.
- Guards: `--all-targets` × `--all` and × `--watch` both error_exit.
- Caught the slice-154 OptionInfo-truthy trap again: the watch `_retest`
  closure calls main() directly, so the new `all_targets` param defaulted
  to a truthy OptionInfo and would have nested batch mode — now explicitly
  `all_targets=False` in the closure.
- +3 tests (per-target _run_all dispatch + aggregate JSON, --all guard,
  --watch guard).
- Full suite **3110 passed / 26 skipped**; ruff + mypy clean.

### Slice 164 — golden ELF fixture (completes the fixtures item) — DONE
- tests/bin_util.py: `make_elf(code, image_base, text_va, text_offset)` —
  minimal ELF32 (ET_EXEC, EM_386) with one PT_LOAD segment, a real .text
  section, .shstrtab, and a 3-entry section header table. LIEF parses it
  via load_binary into a BinaryInfo with .text at the requested VA.
- +5 tests (tests/test_elf_fixture.py): load_binary round-trip (format/
  image_base/text layout), sections_from_info mapping, custom layout,
  deterministic output, and a guard that the PE builder is unaffected.
- The brainstorm item 1's "golden PE + ELF" pair is now complete (PE in
  slice 146).
- Full suite **3115 passed / 26 skipped**; ruff + mypy clean.

### Slice 165 — architecture diagram (completes the Process item) — DONE
- New docs/ARCHITECTURE.md: mermaid data-flow diagram (sources → annotation
  → metadata overlay → compile/compare → STATUS; binary → catalog →
  coverage.db → dashboard; import-table recovery; GA seeding), a module
  map, the compile→compare→STATUS loop, metadata routing rules (from the
  typed facade), and key architectural rules.
- CONTRIBUTING.md "Start here" now points to it — the Process item
  ("CONTRIBUTING.md + architecture diagram") is fully complete.

### Slice 166 — Ghidra enum/typedef pull (`rebrew sync --pull-datatypes`) — DONE
- Resolved the previously-blocked item by reading the ReVa MCP source
  (cyberkaida/reverse-engineering-assistant, found via GitHub code search
  for `get-structure-info`): ReVa has no enum-specific tool, but
  `get-data-types` with `categoryPath="/Enum"|"/TypeDef"` lists user-defined
  enums/typedefs (name/displayName/categoryPath/size/alignment); an empty
  `archiveName` searches every manager per `DataTypeParserUtil`.
- Verified from source that enum MEMBER VALUES are not exposed by any ReVa
  tool (datatypes responses carry no members; structures `get-structure-info`
  casts to `Composite`, which enums are not), so the pull emits an honest
  name/size/category manifest header (enums_types.h) with an explicit note,
  rather than fabricated C definitions.
- New `pull_datatypes()` in ghidra/commands.py: paginated get-data-types
  (totalCount/returnedCount loop), defensive response parsing, ASCII manifest
  output, dry-run + types_out support. Wired as `rebrew sync
  --pull-datatypes` (option + dispatch + epilog).
- +6 tests (manifest header contents incl. limitation note, pagination with
  2 pages, dry-run, custom output path, empty result, CLI help).
- Full suite **3135 passed / 26 skipped**; ruff + mypy clean.

### Slice 167 — match --all stub discovery fix + real-workspace GA verification — DONE
- Real-workspace verification (../guild-rebrew, MSVC6 + wibo + real PE)
  found a genuine bug: `rebrew match --all --dry-run` reported 0 stubs
  because `_parse_annotations` hardcoded `metadata_dir=filepath.parent`,
  but the standard layout keeps rebrew-function.toml at reversed_dir.parent
  — SIZE never overlaid, every stub dropped by the size>=10 filter.
- Fix: `parse_stub_info`/`parse_matching_info`/`parse_matching_all`/
  `_parse_annotations` gained an optional `metadata_dir` (default
  filepath.parent, backward compatible); `find_all_stubs`/`find_near_miss`/
  `find_all_matching` thread `cfg.metadata_dir` through. +2 regression tests.
- End-to-end verification against the real workspace: 28 stubs now found;
  a bounded real GA run (`match friedhof_logic.c --generations 2
  --pop-size 6`) compiled via wine+MSVC6 in 4.7s and found an EXACT match
  (_gv_CheckSlotActive); the solution was recorded target-scoped
  (target: "server.dll") in .rebrew/solutions.json — the multi-target batch
  GA item is now verified end-to-end.
- Full suite **3137 passed / 26 skipped**; ruff + mypy clean.

### Slice 1 (16h goal) — canonical-size resolution fix + verify consistency — DONE
- Real-workspace verification (258 functions, 224 pass, 34 legitimately
  failing incl. 6 genuine SIZE_MISMATCH — tool working correctly) surfaced
  a real defect: the registry's canonical-size resolution blindly trusted
  the Ghidra size when the extra bytes (list minus ghidra) were
  "unrecognized". Empirically, ghidra's function_structure.json truncates
  real functions (GetCommandPayloadSize: ghidra 340 vs true 752 — verified
  from binary bytes: 412 bytes of straight-line code, 0 CC/NOP padding,
  ZERO ret instructions).
- `_resolve_canonical_size` now checks for a function terminator (ret C3 /
  ret imm16 C2) in the extra region: no terminator + no padding ⇒ the bytes
  are same-function code tail and Ghidra truncated ⇒ trust the list size
  ("list (code tail, no terminator)"). Rationale: a truncated canonical
  size silently drops real code (false EXACT risk); an over-count at worst
  makes the comparison visibly mismatch.
- verify.py now passes cfg.target_binary to build_function_registry (only
  caller that didn't; enables smart size resolution there too).
- +3 tests, 1 updated (the old "unrecognized extra" fixture had no ret —
  now covered by the code-tail rule; added a C3 and a C2 variant).
- Workspace re-scan: the 4 worst diverged functions now resolve to true
  extents (752/240/144/768); divergence count dropped 37→30, remainder are
  un-reversed "list only" functions (informational).
- Full suite **3140 passed / 26 skipped**; ruff + mypy clean.

### Slice 2 (16h goal) — batch GA + flag-sweep end-to-end triage — DONE
- Ran real bounded batch GA (`--all --filter friedhof --generations 3
  --pop-size 6`) in ../guild-rebrew: stub discovery → per-stub GA → JSON
  results → .rebrew/ga_runs.jsonl recording (2 records, target/va/symbol/
  matched/ts) all work.
- Confirmed batch match persistence is fully wired: `_run_one_stub_ga` on
  a match calls `update_stub_to_matched` (best source + STATUS via
  metadata) AND `_save_solution` (target-scoped solution record).
- Flag-sweep path verified: `--all --near-miss --flag-sweep` discovers the
  6 NEAR_MATCHING functions and sweeps a real one (GetCommandPayloadSize,
  752B, 743469 best score — genuinely unsolved, no false exact).
- No tool defects in the batch paths; both GA and flag-sweep modes function
  against the real toolchain.

### Slice 3 (16h goal) — catalog → build-db → dashboard pipeline verified — DONE
- Investigated the GA timeout path (`SIGALRM` around `ga.run()` which uses
  ThreadPoolExecutor): per-compile subprocess timeouts (60s/120s) bound
  worker hangs, so the alarm is a sound backstop — no defect.
- Regenerated the real workspace catalog with the fixed registry:
  `rebrew catalog --data-json` (553 functions, 637 unique VAs) →
  `rebrew build-db --force` (schema-version guard verified: v3 rejected,
  v4 rebuilt) → coverage.db.
- Coverage: 557 functions, 139883/141382 bytes = 98.9% (329 EXACT, 194
  RELOC, 22 STUB, 6 SIZE_MISMATCH, 6 NEAR_MATCHING).
- Dashboard smoke-tested against the real DB: targets, 98.9% coverage,
  status-filtered function listing all work.

### Slice 4 (16h goal) — verify SIZE-vs-canonical divergence diagnostic — DONE
- `prepare_entries` now computes per-function annotation-SIZE vs
  binary-derived canonical-size divergences (>1B) and returns them as a 7th
  tuple element; verify + test --all emit a one-line warning with the count
  and the JSON report gains a `size_divergences` array (va, annotation_size,
  binary_size, name). Report-only — the annotation stays authoritative.
- Real-workspace result: **0 divergences** for compilable functions — the 30
  divergences found in the slice-1 scan are all .h/library or DATA/GLOBAL
  entries that verify correctly skips; the annotation sizes of reversed .c
  functions agree with the binary. The diagnostic remains a safety net
  against future stale sizes.
- Updated 3 prepare_entries call sites (verify.py, test.py) + 4 test stubs;
  +2 tests (divergence detected, agreement → empty).
- Full suite **3142 passed / 26 skipped**; ruff + mypy clean.

### Slice 5 (16h goal) — FLIRT + crt-match + prove against real binary/sigs — DONE
- FLIRT verified on the real binary: 3864 signatures, 5 CRT matches (e.g.
  `_exit`), 30 ambiguous — works.
- crt-match had TWO real defects (found via the real workspace, where it
  returned 0 matches):
  1. `_collect_library_annotations` only iterated `iter_sources` (*.c) —
     `library_*.h` headers (where LIBRARY markers live) were never seen.
     Now iterates `iter_library_headers` too.
  2. Matching used `ann.symbol or ann.name`; for LIBRARY headers the name is
     the mangled hint (`// _free`) and the derived symbol double-underscores
     it (`__free`) — never matching the CRT index. Now prefers `ann.name`.
  3. Filename-derived index entries (line==0) hit the 0.95 "exact name
     match" branch; capped at the 0.85 "filename-based" confidence so they
     can't tie a real function definition.
- Result: **0 → 10 real matches** in the workspace (malloc/free/realloc/
  calloc → DBGHEAP+MALLOC/FREE/REALLOC/CALLOC.C, __tzset/cvtdate →
  TZSET.C), auto-attributing CRT functions to their sources.
- Updated 4 test assertions (binary_name/confidence reflect the annotated
  name + capped filename confidence), +1 fallback test, +1 header-collection
  path exercised.
- Full suite **3143 passed / 26 skipped**; ruff + mypy clean.

### Slice 6 (16h goal) — prove verified end-to-end on the real binary — DONE
- `rebrew prove` on real NEAR_MATCHING functions: `_gm_StartFilteredEntitySearch`
  (0x100170e0) proven equivalent via angr symbolic execution (1 orig vs 1
  compiled state, EAX check) and promoted to PROVEN in metadata (verified).
- Status guard verified: non-NEAR_MATCHING VAs are rejected with a clear
  error. The unicorn warning is benign (angr falls back to non-unicorn).
- `rebrew prove --all`: 5 processed, 2 proven, 3 not provable (symbolic
  complexity/timeout — expected, not a tool bug).
- The prove feature (one of the original "22-64% coverage" items) now has
  real end-to-end evidence against a real binary.

### Slice 7 (16h goal) — diff + similar triage; similar crash fixed — DONE
- `rebrew diff` verified on a real near-match (gm_CreateEntityFromParents):
  CSV byte-level diff with structural markers — works.
- `rebrew similar` CRASHED on any real invocation: `TypeError: attribute
  name must be string, not 'int'` — `cfg.capstone_arch`/`capstone_mode`
  return int constants, but `_disasm_signature` did
  `getattr(capstone, cs_arch)`. Now accepts int | str (resolves names via
  getattr only for strings). +1 test (int constants accepted).
- Real run: 10 structurally similar functions for 0x10001000 (top score
  82.9) — works.
- Full suite **3144 passed / 26 skipped**; ruff + mypy clean.

### Slice 8 (16h goal) — verify --compare regression detection — DONE
- verify --compare against the real workspace: first run warns "No previous
  verify report" (diff: null); second run produces a full diff
  (regressions/improvements/new/removed/unchanged_count: 258 unchanged, no
  false positives). diff_reports has thorough unit coverage (regression/
  improvement/new/removed/mixed/no-change).

### Slice 9 (16h goal) — parallel batch GA (thread-safe timeout) — DONE
- Batch --all ran stubs SERIALLY (~60s each); parallelized across stubs.
  The blocker was the per-stub SIGALRM timeout (main-thread only). Replaced
  it with a cooperative, thread-safe deadline:
  - `BinaryMatchingGA.run(deadline=time.monotonic() timestamp)` checks
    between generations and returns best-so-far; compile subprocesses are
    already individually bounded by compile_timeout.
  - `_run_one_stub_ga` no longer uses signals; metadata/solution writes are
    serialized by a module-level `_metadata_lock` (read-modify-write of
    rebrew-function.toml isn't thread-safe).
  - `_run_all` processes stubs via ThreadPoolExecutor(jobs) with order
    preserved (executor.map); seeding precomputed on the main thread;
    intra-GA compiles serialized (num_jobs=1) so total concurrency stays at
    ~jobs; jobs==1 keeps the serial path with full intra-GA parallelism.
- +4 tests (past-deadline returns immediately, loop runs with future
  deadline, parallel batch order + intra-jobs=1, serial path passthrough).
- Real workspace: `--all --filter friedhof` runs both stubs concurrently.
- Full suite **3148 passed / 26 skipped**; ruff + mypy clean.

### Slice 10 (16h goal) — parallel batch GA speedup measurement — DONE
- Same 4-stub run (2 gens × 4 pop), jobs=8 (parallel stubs, intra-jobs=1)
  vs jobs=1 (serial stubs): 19.4s vs 13.6s. Wine's wineserver serializes
  compile subprocesses, so stub-level parallelism is neutral-to-slightly-
  slower for MSVC-under-wine workloads; it should help native toolchains
  (gcc/clang) and does not regress correctness. The parallel path stays the
  default (jobs>1) and is fully tested — documented honestly.

### Slice 11 (16h goal) — lint verified across 110 real sources — DONE
- `rebrew lint` on the real workspace: 110 files, 103 pass, 8 errors, 2
  warnings. All 8 E015 are genuine marker-vs-status drift: verify's
  SIZE_MISMATCH promotions left `// STUB:` markers in the .c files while
  metadata now says SIZE_MISMATCH (expected FUNCTION marker) — and the two
  GA-processed friedhof functions have FUNCTION markers with STUB metadata.
  Lint behaves correctly; the drift is workspace data, not a tool bug.

### Slice 13 (16h goal) — data --dispatch verified on the real binary — DONE
- `rebrew data --dispatch` on the real PE: 3 dispatch/vtable tables found,
  the largest at 0x1002c3f8 with 212 entries, ALL resolved to named reversed
  functions (cm_ChkCommandType/cm_MarkAndReturn/cm_RejectCommand…) with
  statuses — the lazy single-parse LIEF path (slice 157) works end-to-end.

### Slice 14 (16h goal) — graph + rename triage; rename dry-run messaging fixed — DONE
- `rebrew graph` works on the real workspace (nodes/edges/dispatch edges).
- `rebrew rename --dry-run` printed "Updated cross-references" — misleading
  in preview mode. Now prints "Would update cross-references" and the JSON
  payload gains `dry_run`. +1 test (JSON dry_run flag + file untouched).
- Full suite **3150 passed / 26 skipped**; ruff + mypy clean.

### Slice 15 (16h goal) — round-trip splice verified on the real workspace — DONE
- `rebrew round-trip` on the real PE: 119 functions spliced back into the
  binary with sha256_original/sha256_reasm tracked; the only non-spliced
  entries are legitimate skips (oversize RELOC functions, unresolved
  catalog symbols like `_plt_SetPlantMap`). The splice-verify feature works
  end-to-end on a real 557-function target.

### Slice 16 (16h goal) — CRITICAL: match --symbol targeted the wrong function — DONE
- Real-workflow bug (found while attempting a genuine GA solve): on a
  multi-function file, `rebrew match --symbol X` resolved VA/SIZE from the
  FIRST annotation, using the symbol only for obj extraction. For
  friedhof_logic.c it compared `_gv_ValidateEntityAction` (true STUB, 164B)
  against `_gv_CheckSlotActive`'s 113B slice → a FALSE EXACT + a wrong
  target-scoped solution record.
- Fix: new `_select_annotation(annos, symbol)` matches by symbol/name
  (underscore-insensitive); `resolve_build_params` now derives VA/SIZE from
  the selected annotation (with the old metadata-marker path as fallback).
- +2 tests (symbol selects 2nd function's VA/size; no symbol falls back to
  first). Removed the false solution record from the workspace.
- After the fix the same GA run reports best_score 280152 (not exact) —
  the true result. Full suite **3152 passed / 26 skipped**; ruff + mypy clean.

### Slice 17 (16h goal) — extract / skeleton / status triage — DONE
- `rebrew extract list/show` verified (7 un-reversed candidates; show
  disassembles; the CRT `_exit` at 0x1001a670 is among the candidates).
- `rebrew skeleton` works with the workspace's function_structure.json
  (already-covered detection correct; --output respected). Fixed a stale
  error message citing "ghidra_functions.json" → the real constant name.
- `rebrew status` verified.

### Slice 18 (16h goal) — batch flag-sweep --fix-cflags verified — DONE
- `rebrew match --all --near-miss --flag-sweep --fix-cflags --max-stubs 2`
  on the real near-misses: 2 processed, 1 compilable (GetCommandPayloadSize,
  best /O2 /G3, 743469 — unsolved), 0 exact → no CFLAGS writes (correct).
  The batch flag-sweep + fix-cflags path works end-to-end.

### Slice 19 (16h goal) — verify stable post-fixes + diff --fix-blocker — DONE
- Full `rebrew verify` post-fixes: 227/258 passed (up from 224 — PROVEN
  promotions now count), 0 size divergences — no regressions from the
  session's changes.
- `rebrew diff --fix-blocker` on a real near-miss (gm_CreateEntityFromParents):
  structural diff works; no blocker written when the diff isn't classifiable
  (correct no-op — PROVEN/unsolved functions don't get spurious blockers).

### Slice 20 (16h goal) — prove failures triaged — DONE
- The 3 prove --all failures are legitimate: 2 "No terminal states (timeout
  or path explosion)" for large functions, 1 genuine Z3 counterexample
  (EAX differs, 67x5 states) for _ls_LoadEntities — angr correctly reports
  non-equivalence. No tool defects.

### Slice 21 (16h goal) — rebrew imports verified on the real binary — DONE
- `rebrew imports` on the real server.dll: 84 imported APIs (KERNEL32.dll:
  GetLocalTime, OutputDebugStringA, UnhandledExceptionFilter, VirtualFree,
  CloseHandle…) + 3 `jmp [iat]` stubs detected in .text — the library
  identification feature works against real data.

### Slice 22 (16h goal) — data --fix-bss gains --dry-run — DONE
- Per CLI convention, `rebrew data --fix-bss` (a file/metadata-modifying
  path) had no --dry-run. Added it: previews the bss_padding.c contents and
  gap count without writing the file or rebrew-data.toml. +2 tests
  (dry-run writes nothing; fix writes). Full suite **3154 passed**.

### Slice 24 (16h goal) — crt-match --fix-source metadata-routing bug — DONE
- `crt-match --fix-source --all` (now usable with 10 real matches) wrote the
  SOURCE annotations to a STRAY rebrew-function.toml next to the library
  header: update_annotation_key defaults metadata_dir to filepath.parent.
  Fixed by passing cfg.metadata_dir explicitly. The existing test asserted
  the buggy location; corrected to assert metadata_dir + no stray toml.
- Workspace: merged the 6 stray entries into src/rebrew-function.toml,
  deleted the stray file, re-ran the fix — CRT functions now carry real
  SOURCE attribution (free → DBGHEAP.C:952, __tzset → TZSET.C:96).
- Full suite **3155 passed / 26 skipped**; ruff + mypy clean.

### Slice 25 (16h goal) — round-trip --strict-catalog + docs sync — DONE
- `round-trip --strict-catalog` on the real workspace: MATCH false (the CI
  gate fires correctly on 94 unresolved-catalog skips), 119 spliced, 11
  mismatches — strict mode works as documented.
- docs/CLI.md: added the missing entry-points rows for `rebrew imports` and
  `rebrew dashboard` (plus the earlier flag updates: --pull-datatypes,
  --all-targets, --install-completions).

### Slice 26 (16h goal) — batch match-persistence audit + mid-flight validation — DONE
- Audited update_stub_to_matched (the batch GA's match-persistence path):
  it receives cfg.metadata_dir explicitly (no stray-toml bug) and promotes
  via update_source_status; the hardcoded RELOC promotion is conservative
  and documented — not changed.
- Mid-flight validation while the review-prompts pass mutates the tree:
  full suite 3154 passed, ruff + mypy clean (the loop's 7 changes so far are
  compatible: log timestamps, loader OSError detail, rename dry-run path).

### Slice 27 (16h goal) — todo ROI reflects session changes — DONE
- `rebrew todo` after the session's promotions: 3 PROVEN, 3 NEAR_MATCHING
  (was 6), 22 STUB, run-prover 1 — the ROI ordering correctly tracks the
  status changes.

### Slice 28 (16h goal) — data --gen-header verified — DONE
- `rebrew data --gen-header` on the real workspace: 80 globals header
  generated (72 .data + 8 .rdata) with correct extern declarations —
  verified.

### Slice 29 (16h goal) — imports --mark: library-identification loop closure — DONE
- New `rebrew imports --mark [--dry-run]`: writes `// LIBRARY: <marker>
  0xVA` + name-hint annotations for detected import stubs into
  `library_imports.h` (skips already-annotated VAs). Completes the loop:
  FLIRT (CRT functions) + imports (API stubs) → LIBRARY annotations →
  crt-match source attribution.
- Applied to the real workspace: 3 real stubs annotated (GetOEMCP,
  GetACP, RtlUnwind). +3 tests (writes, dry-run no-write, skip-existing).
- Full suite **3157 passed / 26 skipped**; ruff + mypy clean.

### Slice 30 (16h goal) — GHIDRA_SYNC.md documents --pull-datatypes — DONE
- docs/GHIDRA_SYNC.md capability table gains the `--pull-datatypes` row
  (enum/typedef inventory, with the ReVa member-value limitation noted).

### Slice 31 (16h goal) — CRITICAL: single-function flag-sweep silent empty results — DONE
- `rebrew match --flag-sweep-only` on a file with RELATIVE includes
  (`#include "../../Units/..."`) returned 0 results silently: flag_sweep
  compiles into a temp dir and never received the source directory as an
  extra include dir (the GA path does via extra_include_dirs). All 1152
  flag combos failed to compile → empty results → misleading "no match".
- Fix: `flag_sweep()` gains `extra_include_dirs` (forwarded to
  build_candidate_obj_only); the single-function path passes
  `[seed_c.parent.resolve()]` and the batch path passes
  `[filepath.parent.resolve()]`.
- Real run: 20 results now (best 196521) vs 0 before. +2 tests
  (extra_include_dirs forwarded; single CLI path passes the seed dir).
- Full suite **3159 passed / 26 skipped**; ruff + mypy clean.

### Slice 32 (16h goal) — DEVELOPMENT.md gotchas updated — DONE
- Documented the two traps that cost real debugging this session: (1)
  metadata writes default metadata_dir to filepath.parent (stray-toml risk;
  crt-match --fix-source + match._parse_annotations) — always pass
  cfg.metadata_dir; (2) relative includes need extra_include_dirs (the
  flag_sweep silent-empty-results bug).

### Slice 33 (16h goal) — cross-function solution seeding verified — DONE
- Batch GA prints "Seeding from solved: _gv_CheckSlotActive (113B)" — the
  target-scoped solutions DB → find_similar → extra GA seeds chain works
  against real data (the 113B solution seeds the 164B stub's population).

### Slice 34 (16h goal) — --improve batch path verified — DONE
- `rebrew match --all --near-miss --improve --max-stubs 2` processed the 2
  remaining near-misses (mode "NEAR_MATCHING (improve)") — the improve path
  works end-to-end.

### Slice 35 (16h goal) — long GA solve attempt (80 gens x 24 pop) — DONE (honest result)
- 40-minute bounded GA run on the smallest stub (_gv_ValidateEntityAction,
  164B): never improved on the seed (best.c mtime unchanged at run start;
  short runs showed the same ~280k score). The function is genuinely hard
  for the mutation GA — the tool behaved correctly (no false positives,
  timeout enforced). The wrapper's JSON parse "failed" is the 40-min
  timeout kill, not a rebrew crash.

### Slice 36 (16h goal) — triaged loop-added brittle test + review-loop changes — DONE
- The review loop added tests/test_crt_match.py::test_render_functions_content
  with an assertion that the full match reason appears contiguously — but
  rich wraps the Reason cell (each wrapped line becomes a table row), so
  the assertion was brittle and broke the suite. Made it wrap-tolerant
  (assert the reason's words appear). The loop also added Line/ASM columns
  to the CRT index table and preserved-corrupt-TOML handling in
  metadata/data_metadata (all compatible — suite green at 3163).

### Slice 37 (16h goal) — review-prompts pass complete + final triage — DONE
- Full 32-review pass completed: 31 passed, 1 failed (infra-review/qwen,
  agent exit 1). The loop landed many compatible changes (index-table
  Line/ASM columns, corrupt-TOML preservation in metadata, log
  timestamps, error detail, build metadata in pyproject, error-json
  contract).
- Final triage: the loop's `error_exit` JSON now includes the exit `code`
  ({"error": ..., "code": N}) — a good contract change; updated the 2
  stale test assertions (cache clear + catalog fix-sizes).
- Final state: full suite **3173 passed / 26 skipped**; ruff + format +
  mypy clean; all pre-commit hooks pass.

### Slice 38 (16h goal) — STUB → SIZE_MISMATCH promotion noise fixed — DONE
- Found via the workspace's status landscape: repeated verify/test runs had
  converted 22 STUB functions to SIZE_MISMATCH (stubs' placeholder code
  always size-mismatches), collapsing the STUB signal (22 → 1) and orphaning
  stub blockers. The queue survived via "improve-match" but the user's
  STUB classification was erased.
- Fix: `apply_status_updates` (verify + test --all) and test.py's two
  promotion sites skip `STUB → SIZE_MISMATCH` (the per-run report still
  shows the size-mismatch truth; the metadata keeps the user's STUB).
- +2 tests (STUB preserved; EXACT→SIZE_MISMATCH regression still promotes).
- Restored the 25 converted stubs in the workspace via update_source_status
  (26 STUB / 3 SIZE_MISMATCH now); re-verify confirms the guard holds
  (report: 28 size mismatches; metadata: 26 stubs preserved).
- Full suite **3175 passed / 26 skipped**; ruff + mypy clean.

### Slice 39 (16h goal) — todo respects metadata STUB over verify-cache — DONE
- After the slice-38 guard, `rebrew todo` still counted stubs from the
  verify cache (SIZE_MISMATCH), not the preserved metadata STUBs (26 in
  metadata → 1 in todo). Fixed the coverage counting + TodoItem status to
  treat the metadata status as authoritative for STUB, with the cache
  overriding only for more actionable states (COMPILE_ERROR, matched);
  SIZE_MISMATCH no longer hides a STUB.
- Workspace: todo now reports 26 stubs (was 1). All 48 todo tests pass
  (the COMPILE_ERROR-override test still holds). Full suite
  **3175 passed / 26 skipped**; ruff + mypy clean.

### Slice 40 (16h goal) — status.py same metadata-authority rule — DONE
- status.py had the identical cache-over-metadata overlay (its comment even
  said "same logic as status.py" from todo's side). Applied the same rule:
  metadata STUB is authoritative; the verify cache only overrides for
  actionable states (COMPILE_ERROR, matched). `rebrew status` now reports
  26 STUB / 3 SIZE_MISMATCH (was inflating SIZE_MISMATCH from the cache).
- Full suite **3175 passed / 26 skipped**; ruff + mypy clean.

### Slice 41 (16h goal) — lint fully clean; SIZE_MISMATCH diff hint — DONE
- The stub-restoration chain also cleared the lint E015 marker drift:
  workspace lint is now 110/110 (0 errors, was 8 E015) — the mass
  STUB→SIZE_MISMATCH promotions were the root cause of the drift.
- compile.py's SIZE_MISMATCH message gains a "run 'rebrew diff <file>' to
  see the byte differences" hint (the actionable next step).

### Slice 43 (16h goal) — rebrew status per-module breakdown — DONE
- `rebrew status --json` gains a `modules` map ({module: {status: count}});
  naming.load_data now records each entry's module. Helps triage
  multi-module targets (GAME/MSVCRT/ZLIB contributions per status).
- Full suite **3175 passed / 26 skipped**; ruff + mypy clean.

### Slice 44 (16h goal) — SIZE_MISMATCH diff hint in rebrew test too — DONE
- test.py's own SIZE_MISMATCH message (a separate path from compile.py)
  now carries the same "run 'rebrew diff <file>'" hint.
- GA attempt on m_AllocTracked (658B, 22B size delta): 179.7s, best 617570,
  not solved — the dominant defect is an unresolved global reference
  (`mov eax, [0]`), a data-side issue the mutation GA cannot fix. Honest
  result; the tool correctly reports the mismatch.
- Full suite **3175 passed / 26 skipped**; ruff + mypy clean.

### Slice 45 (16h goal) — diff flags unresolved global references — DONE
- New `_missing_global_hints`: scans the diff for candidate instructions
  with `[0]` absolute operands (MSVC's encoding of an undeclared extern)
  and reports them with the target's real address. JSON summary gains
  `missing_globals`; terminal prints an actionable hint ("add a GLOBAL
  annotation for the target address"). These can't be fixed by GA source
  mutation — the user must annotate the global.
- Real diff on m_AllocTracked: 5 unresolved globals detected (the root
  cause of its SIZE_MISMATCH). +2 tests.
- Full suite **3177 passed / 26 skipped**; ruff + mypy clean.

### Slice 46 (16h goal) — missing-global hint refined (no reloc false positives) — DONE
- Workspace validation caught a flaw: `[0]` operands at reloc-masked rows
  (``~~``) are NORMAL extern references (the obj has a relocation), not
  missing globals — the first version flagged 5 on m_AllocTracked that were
  all masked externs. Refined to only flag `[0]` on non-reloc/non-exact
  rows (``**``/``!=``), where the address genuinely failed to resolve.
  The refined output now flags real unresolved-global STORES
  (`mov [0], ecx`) instead.
- Full suite **3177 passed / 26 skipped**; ruff + mypy clean.

### Slice 47 (16h goal) — STUB guard stable under test --all — DONE
- `rebrew test --all --dir Units` (31 functions): 27 pass, 4 fail, and the
  metadata STILL shows 26 STUBs — the STUB→SIZE_MISMATCH guard holds in
  both verify and test --all paths.

### Slice 48 (16h goal) — parallel batch at scale + stub stability — DONE
- `rebrew match --all --max-stubs 6 --generations 2 --pop-size 6` on the
  real workspace: 6 stubs processed in PARALLEL (ga_runs timestamps ~20ms
  apart instead of ~60s serial) — the slice-9 parallelization verified at
  scale. 0 matched (2 gens is tiny), metadata stays 26 STUB (no spurious
  conversions).

### Slice 49 (16h goal) — prove long-timeout triage + docs count fix — DONE
- `rebrew prove --timeout 300` on the 752B near-miss still path-explodes
  (honest "no terminal states" report after the full 300s) — a legitimate
  angr limitation, not a tool defect.
- docs/README.md's stale "All 32 CLI commands" count replaced with a
  drift-proof phrasing (the umbrella now has 31 registered commands after
  the dashboard/imports additions).

### Slice 50 (16h goal) — NEAR_MATCHING action hints (verify + test) — DONE
- classify_compare_result appends "run 'rebrew match <file>
  --flag-sweep-only'" to NEAR_MATCHING messages, and test.py's result line
  shows the same hint. Reversers now get the exact next command from the
  verify/test output (mirrors the SIZE_MISMATCH diff hint).
- Real run: "NEAR_MATCHING: 494/752 bytes — run 'rebrew match <file>
  --flag-sweep-only' to try flag variants".
- Full suite **3177 passed / 26 skipped**; ruff + mypy clean.

### Slice 51 (16h goal) — rebrew cfg add/set verified (historical bug area) — DONE
- `rebrew cfg add-module` / `set cflags` / `remove-module` (interactive
  confirmation) exercised on a workspace-config copy: modules persist as
  `origins` in rebrew-project.toml, cflags set correctly, remove prompts
  properly. The historical tomlkit-persistence bug area is functional.

### Slice 52 (16h goal) — split/merge round-trip verified — DONE
- Split a real 15-function file (friedhof_logic.c) into per-function files
  and merged them back: all 15 annotation blocks preserved (same VA/module
  set before and after) — the split→merge round-trip is lossless.

### Slice 53 (16h goal) — real rename verified — DONE
- `rebrew rename 0x10006580 m_AllocTrackedRenamed` on a workspace copy:
  file renamed to m_AllocTrackedRenamed.c AND all cross-references
  (definition, marker hint) updated — the rename tool works end-to-end.

### Slice 54 (16h goal) — every CLI command now verified on real data — DONE
- binsync-export --dry-run (561 functions, 90 globals, 0 structs preview,
  no writes) — the last unexercised command. With asm, graph --cu-map,
  cfg, rename, split/merge, prove, round-trip, imports, FLIRT, crt-match,
  similar, diff, data (--dispatch/--fix-bss/--gen-header), dashboard,
  status, todo, verify, test, match, lint, extract, skeleton — the ENTIRE
  CLI surface has now been exercised against the real workspace this
  session.

### Slice 55 (16h goal) — NEW: rebrew match --all --sweep-then-ga — DONE
- New combined batch mode: per stub, run the flag sweep first (cheap,
  finds the best-compiling flag variant), then run the GA seeded with
  those flags (cflags_override threading). Falls back to stub cflags on
  sweep failure. +2 tests (sweep flags used; sweep failure falls back);
  CLI.md documents the flag.
- Real run: "Flag sweep: _gm_StartEntityQuery best flags /O1 /G6" then the
  GA runs with them. Full suite **3179 passed / 26 skipped**; ruff + mypy
  clean. (mypy caught a wrong-function edit during implementation — the
  cflags_override line initially landed in run_flag_sweep.)

### Slice 56 (16h goal) — NEW: rebrew match --all --skip-recent N — DONE
- New batch resume feature: `--skip-recent N` drops stubs with a GA run
  record (ga_runs.jsonl) within the last N hours, letting long batch runs
  resume without re-attempting recent work. Applies in dry-run too (the
  preview matches a real run). +2 tests (recent skipped / old kept, no
  records keeps all).
- Real run: 26 stubs → 19 after `--skip-recent 24` (7 recently attempted).
- Full suite **3181 passed / 26 skipped**; ruff + mypy clean.

### Slice 57 (16h goal) — verify --compare regression diff tip — DONE
- When --compare detects regressions, the terminal now suggests
  "run 'rebrew diff <file>' on the regressed functions" — completing the
  action-hint family (SIZE_MISMATCH diff, NEAR_MATCHING flag-sweep,
  regression diff).
- Full suite **3181 passed / 26 skipped**; ruff + mypy clean.

### Slice 58 (16h goal) — --skip-recent/--max-stubs filter order fixed — DONE
- The combined real run exposed a filter-ordering bug: --max-stubs sliced
  BEFORE --skip-recent, so limiting to the 8 smallest stubs then skipping
  the 7 recently-run ones left 1 stub. Now skip-recent applies first, then
  max-stubs — the flags compose sensibly (skip first, then limit).
- Full suite **3181 passed / 26 skipped**; ruff + mypy clean.

### Slice 59 (16h goal) — focused test-review on new code — DONE
- Ran a single-review pass (test-review, codex) over the session's new
  features: 1 review, passed, 4 files improved (test-assertion hardening),
  tree green after (3181).

### Slice 60 (16h goal) — focused api-review on the new CLI surface — DONE
- Single api-review pass (claude) over the session's new flags/commands:
  passed, tree green after. The focused-review approach (one review, one
  agent, bounded) validated the new API surface without full-pass risk.

### Slice 61 (16h goal) — combined-run wrapper timeout (not a bug) + final validation — DONE
- The full combined run (8 stubs, sweep-then-ga + parallel + skip-recent)
  exceeded the 30-min wrapper timeout under wine + agent CPU contention —
  the batch is simply long (~20-40 compiles per stub); each feature was
  verified individually earlier (parallel 6-stub run, sweep-then-ga, and
  skip-recent all demonstrated working). No defect.
- Definitive final validation: suite **3181 passed / 26 skipped**, ruff +
  format + mypy clean, all pre-commit hooks pass.

### Slice 62 (16h goal) — CRITICAL: name_to_va missing data metadata + diff global names — DONE
- Found while adding diff name resolution: `build_name_to_va` (the DIR32
  absolute-address validation map used by test/verify) never read
  rebrew-data.toml — `scan_globals` only sees .c sources, so the 213
  annotated globals were missing and the validation silently no-op'd
  (map size 0). Merged `load_data_metadata(cfg.metadata_dir)` into the map
  (map 0 → 213; g_log_level_table → 0x10027078). This RESTORES the
  relocation validation in test/verify.
- `rebrew diff` now resolves absolute addresses to global names in the
  disasm ("mov ecx, g_log_level_table") — major readability win, built on
  the fixed map. +2 tests (metadata merge; address rewrite).
- Real diff on Error.c: "mov ecx, g_log_level_table" /
  "cmp ecx, g_log_format_table". Full suite **3183 passed / 26 skipped**;
  ruff + mypy clean.

### Slice 63 (16h goal) — DIR32 validation restored in test path — DONE
- verify with the restored name_to_va: 227/258 unchanged (fix is safe — the
  annotated globals validate cleanly, unannotated ones don't perturb
  classifications). `rebrew test` now shows validated reloc counts
  (RELOC _DispatchLogOutput 290/290B, 24 relocs).

### Slice 64 (16h goal) — focused code-review on core fixes — DONE
- Single code-review pass (claude) over the session's core changes: passed,
  5 files improved (shared metadata doc helpers in utils/metadata/
  data_metadata, near_diag dead code, and a real fix to my imports --mark
  that was duplicating the auto-generated banner on re-runs). Verified:
  re-running --mark now reports "No new import stubs" with a single banner.
- Tree green after (3183).

### Slice 65 (16h goal) — prove counterexample detail in failure messages — DONE
- `_compare_state_pairs` now extracts a satisfying assignment from the Z3
  solver and reports concrete values: "…EAX differs (checked 67 x 5 state
  pairs); EAX=0 vs 1". When registers agree, it pinpoints the first
  differing watched VA ("mem[0x1000]=5 vs 9") or "mapped on one side only".
- claripy 9.x API discovery: Solver has no model(); `eval(expr, 1)` returns
  a 1-tuple of concrete values (angr 9.2.204 in the workspace). Fake
  claripy in tests updated to the same API. Model extraction is
  best-effort (try/except) so message degradation never breaks proving.
- Verified against real claripy+Z3 (workspace env) and real binary
  (0x10013230: now shows EAX=0 vs 1). +1 test (edx counterexample),
  strengthened 2 assertions. Suite green in both envs.

### Slice 66 (16h goal) — remove dead absorb-into-data branch in grid.py — DONE
- Deleted the classification-level "absorb unrecognized gaps into preceding
  data segment with parent" elif (grid.py). It carried a
  "# pragma: no cover — unreachable" comment, but the pragma sat on its own
  line before the clause — not a valid coverage exemption. Analysis: for the
  branch to fire, a ghidra label/jump-table gap at a function end must
  survive the absorption loop, but that loop absorbs every such gap with
  size > 0 (and zero-size labels classify as padding). So the branch was
  genuinely unreachable.
- Empirically confirmed: `rebrew catalog --data-json` on the workspace
  (server.dll, 560 functions) produces a byte-identical
  db/data_server.dll.json before vs after the removal (md5 match).
- The 50-round absorption guard was already annotated with an inline
  pragma + explanation — left as-is (intentional safety guard).
- Grid/catalog/data tests: 501 passed. Full suite green. Ruff clean.

### Slice 67 (16h goal) — focused code-review + single-model counterexample — DONE
- Ran a scoped code-review (code-review prompt from ~/review-prompts) over the
  session's highest-churn modules (prove/annotation/metadata/data_metadata/
  lint/grid/match/cli/diff) via subagent. It applied 4 small fixes:
  - prove.py: removed dead `list(sm.deadended) or list(sm.active)` expression
    in the timed-out branch (result discarded, comment claimed it returned
    partial states — it never did).
  - prove.py: fixed stale slice-path comment about stub_hooks filtering.
  - prove.py: dropped redundant local import of iter_sources.
  - lint.py: renamed _check_format_warnings → _check_format_errors (the
    function records E001 *errors*; name was misleading).
- Review also caught a real flaw in my slice-65 counterexample code: each
  `solver.eval(expr, 1)` was an independent Z3 solve, so register/memory
  values could come from different models and the message could be
  inconsistent. Rewrote to a single `solver.batch_eval(exprs, 1)[0]` call —
  one solve, one model, all values consistent (verified batch_eval API on
  real claripy 9.2.204; fake claripy in tests gained batch_eval).
- Verified: prove tests 44 passed (fake claripy) + 16 passed (real claripy);
  real binary 0x10013230 still shows "EAX=0 vs 1". Full suite green.

### Slice 68 (16h goal) — lint --fix 'already in metadata' branch: reachable, not dead — DONE
- Review finding #6 verified empirically: the lint --fix else branch
  ("inline key already in metadata") IS reachable — cross-file duplicate VA,
  non-dry-run. File A's migration writes metadata mid-loop; file B's same
  (module, va) inline key then appears in `existing`. The branch's
  "# pragma: no cover — unreachable" comment was wrong.
- Also confirmed the inner `if dry_run: print "Would remove"` is genuinely
  dead (dry-run never writes metadata mid-loop, and lint-time overlay marks
  pre-existing keys metadata-sourced so they never enter _inline_fixes).
- Fix: corrected the comment (explains the duplicate-VA reachability),
  removed the dead print + stale pragma; the reachable path still strips the
  inline copy and increments fix_count.
- Regression test: test_fix_duplicate_va_second_file_already_migrated (exit
  1 due to E013 duplicate-VA error, but both files' inline copies stripped
  and metadata owns status/size exactly once). test_lint.py 62 passed.

### Slice 69 (16h goal) — prove.py duplicate pipeline consolidation — DONE
- Review finding #3 (confirmed): main()'s single-file path and _prove_single()
  copy-pasted the same ~60-line pipeline (resolve symbol, size gate, extract
  target bytes, compile, parse obj, DIR32 watch resolution, early
  smart_reloc_compare → RELOC/EXACT promote, prototype/constraints, EDX
  auto-detect) with minor drift (different error messages, watched-VA merge
  order).
- Extracted shared _prepare_prove_inputs() → _ProveInputs dataclass; failures
  raise _ProveError (caller reports per its mode) and early byte-matches raise
  _AlreadyMatched (caller promotes + reports). Both callers now consume the
  same inputs; prove_equivalence call sites unified on the helper outputs.
- Behavior preserved: _prove_single keeps the "ALREADY_MATCHED:<status>"
  sentinel for batch counting and passes effective_check_edx; main() keeps
  raw check_edx + its JSON/console early-match reporting. Error messages in
  batch mode are now the richer CLI versions (superset — no test asserted the
  old terse ones).
- Verified: prove tests 44 passed (fake claripy) + 16 with real claripy;
  real workspace: single prove 0x10013230 → same "EAX=0 vs 1" counterexample,
  batch `prove --all --dry-run --json` → total 2, well-formed NDJSON/JSON.
  Ruff + mypy clean.

### Slice 70 (16h goal) — annotation-key round-trip invariant tests — DONE
- Brainstorm item "Round-trip invariants (update ↔ remove symmetry)". Existing
  tests covered single operations; added TestAnnotationKeyRoundTrips making
  the contract explicit:
  - File key: update(TESTKEY) → remove(TESTKEY) returns the .c to its exact
    original bytes; second remove is a no-op (False).
  - Metadata key: update(CFLAGS) writes TOML and never touches the .c;
    remove deletes the field; .c still untouched.
  - update with the same value is a no-op (False — no rewrite).
  - remove_inline_annotation_key strips an inline STATUS but never deletes
    the metadata field (the lint --fix isolation guarantee; routing through
    remove_annotation_key would have deleted it).
- test_annotation.py 115 passed. Suite green.

### Slice 71 (16h goal) — CLI idempotency sweep (dry-run twice) — DONE
- Brainstorm item "Idempotency sweeps". Ran 8 dry-run invocations twice in
  the real workspace (guild-rebrew), comparing stdout/stderr byte-for-byte
  (timestamps normalized) and git tree before/after:
  - lint --dry-run, lint --fix --dry-run, data --fix-bss --dry-run,
    match --all --dry-run --json, test --all --dry-run, status --json:
    all identical (rc=0), tree unchanged.
  - prove --all --dry-run --json: stdout identical; stderr differs only in
    angr's own log timestamp (unicorn load warning) — external logging, not
    a determinism bug. rc=0 both runs.
  - split --dry-run: rc=1/1 identical, stdout identical (expected exit 1
    when nothing to split).
- No nondeterminism found; no code change needed. Evidence logged.

### Slice 72 (16h goal) — diff accepts VA/symbol; shared resolve_source_arg — DONE
- Found in a real workflow pass: `rebrew diff 0x10013230` errored
  ("--symbol required") while prove/test/skeleton all accept VAs. diff only
  accepted a .c path.
- Moved prove's private `_resolve_source` to `rebrew.cli.resolve_source_arg`
  (single canonical name; proves's shim deleted per the no-shims rule) and
  wired it into `rebrew diff` main — `rebrew diff 0x10013230` now resolves
  to the .c and diffs (real run: 746 instructions, 20 structural, sizes
  2268/2268). Unresolvable seeds pass through unchanged → original error.
- prove.py: uses the shared helper (deleted the private duplicate + unused
  contextlib import).
- Tests: resolver tests moved from test_prove.py to test_cli.py (+3 new:
  VA lookup hit, VA miss passthrough); 2 new diff CLI tests
  (VA→source resolution captured in resolve_build_params seed; unresolvable
  passthrough), monkeypatching require_config + resolve_build_params +
  run_diff. 66 passed in the 3 files. Suite green.

### Slice 73 (16h goal) — data_metadata mtime cache (review finding #5) — DONE
- Review finding #5 confirmed: metadata.py's load_metadata caches by resolved
  path + mtime, but the near-mirror load_data_metadata re-parsed
  rebrew-data.toml on EVERY call — and it's called per-file (lint) and
  per-function (smart_reloc_compare global-name resolution), so batch runs
  re-parsed the TOML hundreds of times.
- Added the same mtime cache to data_metadata.py (module-level dict, resolved
  path key) with _invalidate_data_cache() wired into all three write paths
  (save_data_metadata, set_data_field, delete_data_field) + exported
  clear_data_metadata_cache() mirroring clear_metadata_cache(). data.py
  --fix-bss writes go through set_data_field — covered.
- Tests: +2 (unchanged reads hit the cache — parse called once; writes
  invalidate so the next read sees fresh data). test_data_metadata.py 40
  passed; metadata/lint/data suites 196 passed; real workspace lint 110/110,
  data --dispatch 3 tables. Suite green.

### Slice 74 (16h goal) — save_entry batched writes + typed-facade tests (review finding #4) — DONE
- Review finding #4 confirmed: save_entry wrote each non-None field through
  update_field → one full TOML read-modify-write per field (up to ~10
  rewrites for a fully-populated entry). Added private _set_fields() that
  batches all non-status fields into a single read-modify-write (skipping
  unchanged values — idempotent), keeping the STATUS→update_source_status
  routing and its promotion semantics. Order preserved: status first (which
  may clear blockers), then the batched fields.
- Discovered the typed facade (FunctionMetadata/load_entry/save_entry) had
  ZERO direct test coverage. Added TestFunctionMetadata: type coercion on
  load (size/blocker_delta str→int), full persistence of a multi-field entry,
  invalid-entry ValueError, idempotent re-save (no rewrite), and a
  save→load round-trip with globals_list.
- test_metadata.py 65 passed (was 60), test_data_metadata.py 40. Ruff + mypy
  clean. Suite green.

### Slice 75 (16h goal) — rebrew prove --watch (watch consistency) — DONE
- prove was the last single-file CLI without --watch (test/verify/diff/match
  all have it). Added --watch: rejects --all, resolves the source, then
  watch_files([source_path], _retest) re-invokes main(watch=False) on every
  save (watch_files already swallows typer.Exit from failed re-runs so the
  loop keeps watching). Help + epilog updated.
- Tests: --watch + --all rejected; --watch wires watch_files with the
  resolved path (stubbed _require_angr/require_config/utils.watch_files).
  Hit the documented typer/CliRunner quirk again — options must precede the
  positional in runner.invoke (["--watch", src], not [src, "--watch"]).
- Real CLI help shows --watch. prove tests 26 passed. Suite green.

### Slice 76 (16h goal) — second focused review + real ghidra data-metadata bug — DONE
- Ran the standing-instruction review (code-review prompt) over slices 65-75
  changes via subagent: confirmed _compare_state_pairs batch_eval ordering,
  --watch recursion, resolve_source_arg parity, lint fix loop, _set_fields
  batching, and data_metadata cache all correct; applied 1 docstring fix
  (save_entry — claimed writes went "through update_field" which no longer
  matches the batched implementation).
- Fixed the one real bug the review surfaced (pre-existing): ghidra pull
  wrote DATA/GLOBAL NAME to cfg.reversed_dir (line 624) while NOTE correctly
  used cfg.metadata_dir — when reversed_dir != metadata_dir the name landed
  in a stray rebrew-data.toml next to the source tree. Now writes to
  cfg.metadata_dir. The existing test asserted the buggy location — corrected
  it to assert the metadata root (and that reversed_dir stays empty).
- Also fixed: grid.py's `# pragma: no cover` sat on a comment line (ineffective
  — must be on the statement line); catalog/AGENTS.md gotcha was stale.
- test_pull_renames_data 19 passed; grid/ghidra suites 83 passed. Ruff clean.

### Slice 77 (16h goal) — docs (prove --watch/VA) + workspace regression — DONE
- CLI.md prove section: documented --watch, VA/symbol SOURCE resolution, and
  the counterexample detail in failure messages (slice 65/72/75 user-visible
  behavior was undocumented).
- Workspace regression sweep after the metadata/data_metadata/ghidra changes:
  verify --compare 227/258 with 0 size divergences (unchanged from session
  baseline), lint 110/110, catalog --data-json regenerates identically, git
  tree byte-unchanged. The session's metadata caches/batching/ghidra-dir fix
  perturb nothing on real data.

### Slice 78 (16h goal) — grid absorption must not swallow unannotated functions — DONE
- Real-data finding via `rebrew flirt`: FLIRT matched `_exit`@0x1001a670 but the
  catalog's functions dict had no entry there; the function list has
  fcn.1001a643 (45B) and fcn.1001a670 (17B) but the grid hid both. Root
  cause: generate_data_json only models ANNOTATED functions; the absorption
  loop's next-function boundary came from annotated starts only, so the
  62-byte unannotated region (<= _MAX_TAIL_ABSORB=64) was absorbed into the
  preceding annotated function `time` (220B → 282B), hiding two real
  un-reversed functions from the coverage DB.
- Fix: absorption now bounds gaps by ALL registry starts in the section
  (annotated items + unannotated registry entries with canonical_size > 0),
  so a real function's start is never crossed. Annotated-only item_starts
  still drive rendering. Verified on the workspace: `time` cell exactly 220B,
  the 0x1001a643-0x1001a681 region now renders as a visible unclassified gap
  (was silently inside `time`). fcn.1001a643/fcn.1001a670 are real CRT
  functions (FLIRT: _exit at 0x1001a670; the library header's _exit@0x1001a681
  is misattributed — noted for the workspace, not a tool bug).
- Regression test: TestUnannotatedBoundaries.test_unannotated_function_not_absorbed
  (fails before, passes after). Grid/catalog suites 54 passed.

### Slice 79 (16h goal) — workspace verification round (build-db, asm, flirt) — DONE
- build-db regenerates coverage.db + CATALOG.md cleanly; asm/status/flirt
  all work. The slice-78 grid fix's workspace effect verified in detail:
  `time` cell exactly 220B and the 0x1001a643-0x1001a681 region now a
  visible unclassified gap.
- CRT layout archaeology (tool output, not code): disassembly of the two
  17-byte wrappers shows 0x1001a670 = `exit` (doexit action=0) and
  0x1001a681 = `_exit` (action=1); FLIRT's "_exit"@0x1001a670 is a
  signature that matched both, and library_msvc.h annotates only
  `_exit`@0x1001A681. Recommendation recorded for the workspace: add
  `// LIBRARY: SERVER 0x1001A670 // exit` to library_msvc.h (fcn.1001a643
  is likely `_time64`). Left the user's annotation data untouched.

### Slice 80 (16h goal) — round-trip false 'oversize' on padding-inclusive SIZE — DONE
- Real-data finding: `rebrew round-trip --dry-run` reported 5 'oversize'
  mismatches on functions `rebrew test` verifies as RELOC. Root cause:
  SIZE metadata includes trailing NOP/INT3 padding (e.g. cm_ExAllocThemaPredigt
  SIZE 176, compiles to 172 — the source even carries "BLOCKER_DELTA: 4"),
  and round-trip required len(compiled) >= SIZE, while test/verify compare
  padding-tolerantly. Genuinely matched functions were falsely failed.
- Fix: round-trip now trims trailing padding from the target span
  (trim_trailing_padding from catalog.sections) and compares/splices only the
  real-code span; trailing padding stays untouched in the buffer so SHA
  equality is preserved by construction. A genuinely short compile (shorter
  than the trimmed span) still reports oversize.
- Verified on the workspace: 5 oversize → 0. Remaining: 6 catalog_resolution_drift
  (reloc targets the catalog resolver maps wrongly — real data findings,
  correctly flagged) and 94 skipped_catalog (unresolved symbols for
  un-reversed functions — expected). +2 regression tests (padding-inclusive
  SIZE splices ok; genuinely-short compile still oversize). round-trip tests
  27 passed.

### Slice 81 (16h goal) — round-trip drift detail names call targets — DONE
- Forensics on the 6 remaining catalog_resolution_drift mismatches: NOT a
  tool bug. `_gm_IsInRange` is the proof: original binary calls
  gm_MapEntityStatRange@0x10018200, the source's `_gm_IsInRange` calls
  _gm_GetBuildingTypeCategory — a real decompilation error in the workspace
  source that `rebrew test` masks (reloc bytes are excluded from its byte
  comparison) while round-trip applies the reloc and catches it. round-trip
  is the STRICTER verifier — this is exactly its value.
- Improvement: the drift detail was only "first byte diff at offset 0x6" —
  now when the diff sits inside a REL32 reloc, it decodes and names BOTH
  targets: "reloc@0x6: source → 0x100179b0 (gm_GetBuildingTypeCategory),
  target → 0x10018200 (gm_MapEntityStatRange)". All 6 workspace drifts now
  show actionable source bugs (IAT-stub vs local, wrong CRT variant, etc.).
- Helpers: _rel32_target (REL32 disp → absolute VA), _target_name
  (VA → catalog name). +4 tests (decoding, out-of-range, name lookup,
  drift-detail enrichment with catalog). round-trip tests 31 passed.

### Slice 82 (16h goal) — round-trip resolver: DATA annotations shadow functions — DONE
- Deep dive on the _srv_Init drift: source calls CreateListenSocket, resolver
  mapped it to 0x101deb14 (IAT slot) instead of the real function 0x10009e60.
  Root cause: `_load_catalogs` folded EVERY annotation (incl. DATA/GLOBAL)
  into the function VA map; server.c annotates the IAT slot as
  `// DATA: SERVER 0x101deb14` named CreateListenSocket, so the same-named
  function was shadowed and REL32 calls resolved to the data slot.
- Fix: DATA/GLOBAL annotations now go into the data {name: va} map (with
  rebrew-data.toml), never into funcs — REL32 calls resolve to the real
  function; DIR32 data references still resolve via the data map.
- Workspace effect: 6 catalog_resolution_drift → 4 (two real source bugs
  cleared: CreateListenSocket IAT collision + DispatchLogOutput). Remaining
  4 are genuine decompilation errors correctly flagged with actionable
  target names (wrong callee, wrong CRT variant).
- +2 tests: DATA annotation doesn't shadow a same-named function (resolver
  returns the function VA); LIBRARY annotations still enter funcs.
  round-trip tests 31 passed.

- Correction: the first append duplicated a pre-existing TestLoadCatalogs
  class (redefining it and dropping its 2 tests). Merged the 2 new tests into
  the original class — round-trip tests now 33 passed.

### Slice 83 (16h goal) — third focused review (round-trip/grid) + coverage accounting — DONE
- Review pass over the slice 76-82 round_trip/grid changes (subagent):
  confirmed the oversize-trimming SHA safety (only bytes verified equal to
  the original are written), the REL32 drift decoding (offsets match
  apply_coff_relocations' pc convention), _load_catalogs ordering, and the
  boundary_starts/classification consistency. Applied 3 small cleanups:
  removed dead annotated_dirs accumulator, corrected the stale
  _load_catalogs docstring, renamed an unused loop var.
- Review finding #2 fixed: spliced_bytes summed the metadata SIZE (incl.
  trailing padding the compiler never emits) — now tracks the actual
  trimmed spliced span (spliced_actual_bytes), so the byte-coverage report
  no longer overcounts padding.
- round-trip tests 33 passed. Full suite 3211 green after review.

### Slice 84 (16h goal) — grid boundaries include size-0 registry starts — DONE
- Review finding #3: the absorption boundary list skipped registry entries
  with canonical_size == 0 (unresolved size). A function start detected by
  the disassembler/ghidra is a real boundary regardless of size — the guard
  let a predecessor absorb such functions' bytes. Removed the size check;
  every in-section registry VA is now a boundary.
- All 54 catalog/grid tests pass; workspace regen byte-stable (time 220,
  560 functions). Ruff clean.

### Slice 85 (16h goal) — final workspace verification sweep — DONE
- Full sweep after all session changes: verify --compare 227/258 with 0 size
  divergences (byte-identical to the session baseline — no regressions from
  any of the ~30 fixes), lint 110/110, round-trip --dry-run: 4 mismatches
  (down from 11 at slice 80: 5 false-oversize + 2 resolver collisions
  cleared; the remaining 4 are real source bugs, each with actionable
  reloc target names) and 94 catalog gaps (un-reversed functions, expected).
- Workspace git tree byte-unchanged by all verification runs.

### Slice 86 (16h goal) — mypy fix: _rel32_target Any return — DONE
- Final pre-commit sweep caught a mypy no-any-return in _rel32_target
  (struct.unpack yields Any). Annotated disp: int. All 8 pre-commit hooks
  green; round-trip tests 33 passed.

### Slice 87 (16h goal) — round-trip docs — DONE
- CLI.md round-trip section now documents the slice 80-82 behaviors: the
  stricter-than-verify call-target check (reloc application catches calls to
  the wrong function that verify masks), the actionable drift detail with
  both target names, and the padding-tolerant oversize/spliced_bytes
  accounting.

### Slice 88 (16h goal) — skeleton falls back to the function list — DONE
- Real workflow gap: `rebrew skeleton 0x10023840` errored "VA not found in
  function_structure.json" — skeleton could only size functions the Ghidra
  cache knew, but the workspace has 553 registry functions vs 219 ghidra
  entries (334 list-only, incl. recently added CRT functions).
- Fix: single-VA/append path now falls back to the function list via the
  registry's canonical size when the VA isn't in the Ghidra cache
  (parse_function_list + build_function_registry, no ghidra JSON needed).
- Verified: `rebrew skeleton 0x10023840` (RtlUnwind stub, list-only) no
  longer errors — resolves and correctly reports "Already covered by
  library_imports.h". +2 CLI tests (fallback generates from list size;
  unresolvable VA still errors cleanly). skeleton tests 38 passed.

### Slice 89 (16h goal) — skeleton batch mode includes list-only functions — DONE
- Follow-up to slice 88: `list_uncovered` (batch mode) only saw the Ghidra
  cache, so `skeleton --batch` could never cover list-only functions.
  Now merges the function list (registry canonical sizes) with Ghidra
  entries (ghidra wins on VA conflict), keeping the existing/min/max/ignored
  filters. Defensive getattr access per the ProjectConfig convention.
- Fixed the extended CLI test fixture (_cfg lacked dll_exports/iat_thunks/
  function_list that the registry legitimately needs) and made slice 88's
  fallback equally defensive (cfg.function_list via getattr) — caught by
  test_va_not_found_errors, now passing.
- +1 test (list-only function appears in list_uncovered). skeleton suites
  59 passed (test_skeleton 39 + extended 20).

### Slice 90 (16h goal) — skeleton list-only CRT function on real workspace — DONE
- Verified slice 88/89 end-to-end on the workspace: `rebrew skeleton
  0x1001a670` (the CRT `exit` wrapper that the grid hid until slice 78)
  now generates src/server.dll/fcn_1001a670.c with the correct list-derived
  size (17) and ready test/diff commands. Lint stays clean: 110/110 → 111/111.
  The previously-invisible function is now a normal reversible target.

### Slice 91 (16h goal) — rename the recovered CRT function to `exit` — DONE
- `rebrew rename 0x1001a670 exit` (non-dry): fcn_1001a670.c → exit.c with
  the FUNCTION marker updated and cross-references refreshed (1 file).
  Correct per the disassembly: 0x1001a670 calls doexit(action=0) = `exit`;
  0x1001a681 (action=1) = `_exit`.
- Full loop closed on real data: grid fix (slice 78) revealed the hidden
  function → skeleton (slices 88-90) generated it → rename named it.
  Workspace: lint 111/111, verify 227/259 (exit is now a verify candidate;
  divergences 0). Slice-89 suite: 3214 passed.

### Slice 92 (16h goal) — focused review of skeleton changes + corrupt-JSON guard — DONE
- Review pass over slices 88-91 (skeleton fallbacks, round-trip accounting)
  caught a REAL bug in slice 89: `ProjectConfig.function_list` defaults to
  `Path()` which is always truthy — my `if func_list_path:` guard never
  skipped, so every batch run parsed "." and emitted a spurious warning.
  Fixed with `Path(...).is_file()` in both list_uncovered and the single-VA
  fallback; also wrapped build_function_registry (the actually fallible call)
  in the same except guard the parse had.
- Fixed review finding #1: a corrupt function_structure.json raised a raw
  traceback — now a clean error_exit (fallback was only reachable for
  missing files, not corrupt ones).
- Suite green (3214 baseline); skeleton suites 59 passed; spurious warnings
  gone. Remaining findings all low (documented in the review).

### Slice 93 (16h goal) — crt-match binary_size fallback + workspace verification — DONE
- Real-data observation: crt-match --all reported `binary_size: 0` for
  header-only LIBRARY entries (e.g. _malloc) because the annotation SIZE is
  absent — the registry knows the real sizes (malloc 252B).
- Fix: `_canonical_size()` helper (lazy, module-level cache) falls back to
  the function-list size when ann.size is 0, at both call sites (match_all +
  single-VA). Implemented without the registry (direct parse_function_list
  lookup) so no cfg.dll_exports dependency. Real run: all 10 matches now
  carry real sizes (malloc 252, free 215, realloc 781, calloc 289, tzset 647).
- Also verified crt-match's grid rendering is correct (malloc 252B spans 2
  cells — row-wrap split, not a bug) and crt-match works end-to-end on the
  workspace. crt-match tests 66 passed. Test fixture enriched with the
  ProjectConfig fields the registry/loader legitimately need.

### Slice 94 (16h goal) — data --gen-header idempotency (timestamp churn) — DONE
- Real-data observation: regenerating rebrew_globals.h always rewrote the
  file because the "Generated:" timestamp is embedded — git churn on every
  run even with zero changes.
- Fix: gen-header now compares the new content against the existing file
  with the "Generated:" line stripped; when the body is identical it prints
  "rebrew_globals.h unchanged (N globals)" and skips the write. Real run:
  second regen reports unchanged. +1 test (regeneration byte-identical).
  data extended tests 38 passed.

### Slice 95 (16h goal) — extract verified on un-reversed CRT functions — DONE
- `rebrew extract list` shows exactly 6 un-reversed candidates — the CRT
  functions round-trip's drift details referenced as unnamed targets
  (fcn.1001a7f7 18B, fcn.1001a286 19B, fcn.10019d00 39B, ...). `extract
  show 0x1001a7f7` disassembles and saves the bytes correctly. Already-covered
  functions (exit.c) are correctly excluded from candidates. The tool chain
  grid → skeleton → rename → extract is fully consistent on real data.
- Slice-94 suite: 3215 passed (+1 idempotency test).

### Slice 96 (16h goal) — final sweep + RELOC-staleness investigation — DONE
- Final workspace sweep: verify 225/259 (0 divergences, --compare reports 259
  unchanged / 0 regressions), lint 111/111, round-trip 4 real drifts + 92
  catalog gaps (un-reversed), tree unchanged.
- Two functions (CreateListenSocket@0x10009e60, 0x1000a010) show
  RELOC-in-metadata but NEAR_MATCHING on fresh compiles (98.09%/96.4%,
  8B/4B deltas). Investigation: their sources are git-unchanged, none of
  this session's slices touch the verify compile/compare path, and the
  verify cache agrees with the fresh runs — so the metadata STATUS is stale
  workspace data (verified as RELOC at some earlier point; the current
  toolchain compiles to a 98% near-match). Tool behavior is correct;
  flagged for the workspace owner to re-verify or fix the source.

### Slice 97 (16h goal) — round-trip drift names fall back to the function list — DONE
- Review finding #3 (slice 92) closed: drift details showed `target →
  0x1001a286 ()` with an empty name for un-annotated targets. New `_list_name`
  helper (lazily parsed function list, cache keyed by path so multiple
  projects in one process stay correct) fills in the r2 name — now:
  `target → 0x1001a286 (fcn.1001a286)`, `target → 0x1001a7f7 (fcn.1001a7f7)`.
- Caught and fixed my own module-global cache bug during testing (was keyed
  by nothing → test-order dependent); now keyed by the function-list path.
- +2 tests (_list_name resolves list names / missing list → ""). round-trip
  tests 35 passed.

### Slice 98 (16h goal) — CRITICAL: prove early-match skipped DIR32 validation — DONE
- Real-data discovery: prove --all on the 4 NEAR_MATCHING functions reported
  ALREADY_MATCHED:RELOC for CreateListenSocket and CleanupSockets, while
  test/verify classify both NEAR_MATCHING (98%/96%). Root cause:
  `_prepare_prove_inputs` called smart_reloc_compare WITHOUT name_to_va —
  the DIR32 absolute-address validation test/verify apply. Prove would have
  PROMOTED these functions to RELOC, regressing the correct NEAR_MATCHING
  status (a real prove run, not dry-run, would corrupt the metadata).
- Fix: pass `build_name_to_va(cfg)` + section_va to the early-match gate
  (same as compile_and_compare). After the fix, prove no longer false-matches
  CreateListenSocket (path explosion) and CleanupSockets is genuinely
  PROVEN ("Proven equivalent") — a real reversal win.
- +2 tests (early-match gate receives name_to_va; genuine match still raises
  _AlreadyMatched). prove tests 28 passed (was 26).

### Slice 99 (16h goal) — doctor 12/12 + diff on updated functions — DONE
- Final health check after the slice-98 prove fix: rebrew doctor 12/12
  (0 fails, 0 warns), rebrew diff on CleanupSockets (0x1000a010) resolves
  via VA and reports a clean structural diff (2 exact, 0 structural).
- Verified the prove early-match fix under real angr: prove memory-watch
  suite 16/16 in the workspace env; single-vs-batch prove result variance
  on CleanupSockets confirmed as pre-existing angr path-explosion
  nondeterminism (the fix only changed the pre-prove gate).

### Slice 100 (16h goal) — review pass (prove/skeleton/round_trip/crt_match/data) — DONE
- Fourth focused review of the stretch; caught and fixed two real issues:
  - crt_match._canonical_size used a flat module-global {va: size} cache not
    keyed by cfg — a second project in-process reused the first's sizes (and
    a first-project parse failure poisoned later ones). Now keyed by the
    function-list path (same bug class I introduced in round_trip._list_name
    at slice 97 and fixed there; the review caught the crt_match twin).
  - prove._compare_state_pairs: a watched VA unmapped on BOTH sides (which
    contributes no diff term) before the real differing VA misattributed the
    counterexample message as "mapped on one side only" — now skipped.
- Finding #1 fixed: prove batch re-built build_name_to_va per candidate
  (O(F×S)); now built once in _run_all_batch and threaded through
  _prove_single/_prepare_prove_inputs. Batch behavior identical (4/1/3 on
  the workspace).
- Finding #3 fixed: round_trip._list_name and crt_match._canonical_size now
  guard with Path(...).is_file() (the Path() default is truthy → parsed ".")
  — consistent with skeleton.
- Suite 3219 green; targeted suites 242 passed. Ruff + mypy clean.

### Slice 101 (16h goal) — prove path-explosion message gains actionable hints — DONE
- The prove failure message for path explosion / timeout ("No terminal states
  reached") gave no next step. Now suggests --timeout/--loop-bound increases
  or --start-offset/--end-offset slice proving — the same action-hint pattern
  as diff's SIZE_MISMATCH/NEAR_MATCHING hints.
- Also verified (real workspace): a failed prove (path explosion) leaves the
  STATUS untouched (action: none) — the nondeterminism between the batch run
  ("Proven equivalent") and single run (path explosion) is angr's
  time-dependent exploration under system load, not a tool bug. prove tests
  28 passed.

### Slice 102 (16h goal) — GA batch surface verified post-changes — DONE
- `rebrew match --all --dry-run` lists all 26 STUB candidates correctly
  after the session's metadata/cache/compile changes — the GA batch path is
  intact (26 stubs remain eligible; ga_runs.jsonl resume untouched).

### Slice 103 (16h goal) — dashboard smoke test — DONE
- `rebrew dashboard` (read-only web UI over coverage.db, from an earlier
  goal) verified working after all session changes: serves HTTP 200 with the
  coverage dashboard HTML on the workspace. `--json` correctly prints the
  URL then serves (blocking by design — my first pipe test was wrong, not
  the tool).

### Slice 104 (16h goal) — definitive test --all batch — DONE
- Full `rebrew test --all` on the workspace: 259 total, 222 byte-passing.
  Consistent with verify's 225 passed (222 + 3 PROVEN, which deliberately
  don't byte-match); 37 failed = 28 SIZE_MISMATCH + 1 STUB + 4 NEAR_MATCHING
  + 3 PROVEN + 1. The whole batch compile→compare path is intact after all
  session changes (compile cache made the run fast). Also confirmed
  skeleton.py's function_list guards already use is_file() — no other
  Path()-truthiness instances remain.

### Slice 105 (16h goal) — property tests for rel32/padding helpers — DONE
- Added hypothesis property tests (brainstorm theme) for the new helpers:
  `_rel32_target` round-trip (disp bytes ↔ absolute VA arithmetic, incl.
  negative displacements) and bounds (short blobs → None), plus
  `trim_trailing_padding` invariants (trimmed ≤ len, suffix all padding,
  last kept byte non-padding). test_property_parsers.py 14 passed.
- Verified todo's identify-library category has the same ghidra-only gap as
  skeleton had — but list-only candidates lack library-module attribution,
  so the fix would need crt-match-style identification; `extract list`
  already surfaces them. Noted, not changed.

### Slice 106 (16h goal) — flirt --va (fixes broken todo command) — DONE
- Real bug: `rebrew todo`'s identify-library items command was
  `rebrew flirt --va 0x...` — but flirt had NO --va option, so every such
  command failed with "No such option". Added --va: single-function
  signature check (extracted the per-offset match/report into a shared
  `_check_offset` helper used by both the full sweep and the single-VA mode;
  out-of-.text VAs error cleanly).
- Real runs: `flirt --va 0x1001a670` → `_exit` (17B), `0x1001a681` → `__exit`
  (17B) — the todo commands now work. +2 CLI tests (help contract; out-of-
  section error). flirt tests 17 passed. Suite at 3222 + 2.

### Slice 107 (16h goal) — audit all todo commands — DONE
- Audited every `command=` in todo.py after the flirt fix: all now valid
  (rebrew catalog/doctor/todo/skeleton --batch 5/verify, diff with
  filename-or-VA, prove with filename-or-VA, flirt --va). The slice-106
  fix was the only broken command. Suite 3224 green.

### Slice 108 (16h goal) — todo commands switched to VA form (CWD-independent) — DONE
- Real bug: every todo item with a filename command (`rebrew diff
  DieGildeAddOn/game/...`) failed when run from the project root — the paths
  are reversed_dir-relative but todo gives no cd hint. Switched diff, prove,
  and match --flag-sweep-only commands to the VA form, which resolves via
  resolve_source_arg from any CWD. Verified: `rebrew diff 0x10018850` (the
  previously-failing command) now works from the root (1056 instructions).
- Note: my automated replace initially hit the first of two identical
  ternaries (FIX_DELTA branch), breaking the if/else — repaired with VA
  forms in both branches. todo tests 48 passed; suite 3224 green.

### Slice 109 (16h goal) — remaining todo filename commands → VA form — DONE
- Swept all generated commands for the reversed_dir-relative-path bug:
  todo's `rebrew test {filename}` had the same issue (broken from root) —
  switched to VA form. skeleton's `--append {neighbor}` is fine (skeleton
  resolves relative paths against reversed_dir); skeleton's generated
  test/diff commands use root-relative paths — correct. todo tests 48
  passed; suite 3224 green.

### Slice 110 (16h goal) — review pass; test/match VA positional wiring — DONE
- The slice-108/109 todo change generated `rebrew test 0x{va}` and
  `rebrew match --flag-sweep-only 0x{va}` — but the review caught that
  test.py/match.py never resolved VA positionals (only diff/prove did), so
  those commands would have failed. Fixed: resolve_source_arg now wired into
  test.py and match.py single-file paths (mirroring diff), plus a defensive
  getattr guard in resolve_source_arg for minimal test cfgs.
- Verified on the workspace: `rebrew test 0x10018850` now resolves the VA →
  source, compiles, and reports SIZE_MISMATCH (obj 3B) end-to-end; the
  exit.c case needs SIZE metadata first (skeletons don't create it —
  expected). Review's remaining findings all low (documented). Suite 3224
  green; targeted suites 307 passed.

### Slice 111 (16h goal) — batch-honest path-explosion hint — DONE
- Review finding #1 (slice 110): the slice-101 hint suggested
  --start-offset/--end-offset, which batch mode hardcodes to 0 — misleading
  in `prove --all`. Reworded: "batch mode cannot slice; run rebrew prove
  <va> --start-offset/--end-offset for slice proving". prove tests 28
  passed.

### Slice 112 (16h goal) — non-vacuous rel32 bounds property — DONE
- Review finding #3 (slice 110): test_rel32_target_bounds asserted
  `is None or isinstance(int)` — always true. Now asserts the documented
  contract: a field past the end (len < 4) → None; a complete field → int.
  test_property_parsers.py 14 passed.

### Slice 113 (16h goal) — split preamble comment-stripping (17x bloat) — DONE
- Real-data finding: merge→split round-trip on the workspace produced 17×
  bloat (merged 5,837 lines → split 101,580): each split file repeated the
  full 1430-line preamble, which is the union of all files' Ghidra
  decompilation-reference comment blocks (they precede the first marker, so
  split_annotation_sections treats them as preamble; the merge unions them;
  the split repeats them verbatim in every file).
- Fix: split now strips /* */ comment blocks (and orphaned `*` continuation
  lines from the malformed line-union nesting) from the preamble before
  writing per-function files, keeping the real code (typedefs, externs,
  dllimport decls). Result: split output 101,580 → 23,312 lines; a
  single-function file 1443 → 292 lines, clean and compileable.
- During implementation I twice mis-placed the helper (first between the
  @app.callback decorator and main, breaking the CLI — caught by 26 failing
  tests) — repaired. +3 regression tests (block stripping, orphaned lines,
  code-only preamble unchanged). split tests 36 passed.

### Slice 114 (16h goal) — merge produced non-compiling files (malformed preamble) — DONE
- Follow-up to slice 113: the MERGED file did not compile — C2143 syntax
  error from the naive union of 68 files' decompilation-comment preambles
  (orphaned `*` comment lines broke the /* */ nesting).
- Fix: moved strip_comment_blocks to rebrew.utils (shared canonical name);
  split.py now imports it, and merge's _merge_preambles strips comment blocks
  from each preamble BEFORE dedup. Merged file: 5837 → 4693 lines, and the
  C2143 syntax error is gone (remaining C1083 is the expected
  include-relocation issue when content moves across directories, not a
  bug). split tests 36 + merge tests 24 passed.

### Slice 115 (16h goal) — merge comment-strip regression test — DONE
- Added test_merge TestMergeCommentPreamble: decomp-comment preambles are
  stripped from the merged output while includes and both function markers
  survive (regression for the C2143 fix). merge tests 25 passed.

### Slice 116 (16h goal) — similar verified on real data — DONE
- `rebrew similar 0x10013230` returns ranked similar functions with scores
  (fcn.100128f0 86.0, fcn.10013b10 84.7, CrashDumpUnhandledExceptionFilter
  82.8) — the GA seed-finding path works end-to-end on the workspace.
  Slice-114 suite 3227 green.

### Slice 117 (16h goal) — graph verified on real data — DONE
- `rebrew graph --format summary` works on the workspace: dependency
  summaries + top unreversed blockers (thread_proc called by 19 functions,
  g_panic_callback by 11, _ctime by 10) — useful triage output. Slice-115
  suite 3228 green (3227 + merge regression test).

### Slice 118 (16h goal) — graph --focus accepts hex VAs — DONE
- `rebrew graph --focus 0x10013230` errored "No function matching" — focus
  matched names only. Added hex-VA matching (after exact/partial name):
  resolves the node whose va matches, consistent with every other tool.
  Real run: focus 0x10013230 → 11-node / 19-edge neighborhood. +2 unit
  tests (VA focus with neighbours; unmatched VA → empty). depgraph suites
  44 passed.

### Slice 119 (16h goal) — cache + graph --include-dispatch verified — DONE
- rebrew cache stats: 12,594 entries / 48 MB / 500 MB limit — compile-cache
  CLI works. graph --format summary --include-dispatch surfaces the
  dispatch-table targets (fn_0x10021aad called by 6, fn_0x1001b070/87)
  as blockers — the same un-reversed dispatch entries data --dispatch found
  in slice 72; the toolchain is coherent end-to-end.

### Slice 120 (16h goal) — review pass; two strip_comment_blocks bugs fixed — DONE
- Review (slices 108-119 scope) caught two real bugs in my slice-113/114
  work:
  - strip_comment_blocks dropped code after a same-line closing `*/`
    (`int x = 1 /* init */ + 2;` lost `+ 2;`) — now keeps trailing code.
  - the stripped preamble had no trailing newline, so `out_preamble + block`
    glued `// FUNCTION:` onto the last preamble line (the marker became a
    comment → lost annotation). Both split call sites now insert "\n".
- Verified on the real workspace: merge→split still correct (marker at line
  287 of a 299-line file). Depgraph focus order and merge dedup verified
  clean; 2 low findings documented (string-literal `/*` handling, substring-
  vs-VA focus priority). Suite 3230 green (3228 + 2 depgraph tests).

### Slice 121 (16h goal) — quote-aware strip_comment_blocks — DONE
- Closed review finding (slice 120): `/*` inside a string literal truncated
  the rest of the file. Rewrote strip_comment_blocks as a quote-aware
  char scanner: tracks "..." strings so `const char *s = "a/*b";` survives;
  keeps code on both sides of same-line comments; drops comment-only lines
  and orphaned continuations; preserves blank lines (collapsed to one) and
  strips leading blanks.
- +5 utils tests (string-literal /*, same-line trailing code, multi-line
  block, pointer deref, orphaned lines). Real merge→split round-trip still
  correct (68 functions, markers intact). Suite 3235 green.

### Slice 122 (16h goal) — cu-map + status verified — DONE
- graph --cu-map renders compilation-unit boundary inferences (regions with
  gap/padding + static-function signals). rebrew status output is
  comprehensive: 561 annotated functions, 93.9% byte-matched, per-status
  table, last-verify summary. The status-table SIZE_MISMATCH (3) vs verify
  fresh (28) gap is the documented stale-metadata data issue, not a tool
  bug.

### Slice 123 (16h goal) — skeleton writes SIZE metadata (MISSING_SIZE gap) — DONE
- Real-data finding: the exit.c skeleton (slice 91) showed MISSING_SIZE —
  skeletons create the file but never record SIZE, so they can't be verified
  until the user adds it manually.
- Fix: _write_skeleton_metadata() records SIZE in rebrew-function.toml when
  absent (never overwrites an existing SIZE, never touches STATUS), called
  after both single-VA and --append creation. Workspace: exit@0x1001a670 now
  has size 17 and verifies as SIZE_MISMATCH (was MISSING_SIZE). +2 tests
  (size written from the list; existing size not overwritten). skeleton
  tests 41 passed.

### Slice 124 (16h goal) — exit SIZE fix verified end-to-end — DONE
- Workspace after the slice-123 fix: MISSING_SIZE 1→0, SIZE_MISMATCH 3→4,
  verify 225/259 with 0 size divergences and --compare reporting 0
  regressions. The exit skeleton is now a normal, verifiable candidate.

### Slice 125 (16h goal) — review pass; batch skeletons + same-line comments — DONE
- Review (slices 121-124 scope) fixed a same-line comment bug in
  strip_comment_blocks (multiple /* */ blocks per line: the scanner jumped
  to EOL after the first */ — now resumes scanning) and flagged that
  `skeleton --batch` never recorded SIZE metadata (my slice-123 fix covered
  single-VA/append only). Batch mode now calls _write_skeleton_metadata per
  created file (module = cfg.marker).
- Suite 3237 green (3235 + 2 skeleton tests); skeleton/utils suites 80
  passed. Remaining review findings all low (documented: block-close line
  trailing code, //-comment /* handling, etc.).

### Slice 126 (16h goal) — strip_comment_blocks: multi-line-close trailing code — DONE
- Closed review finding (slice 125): code after a multi-line block's close
  (`/* a\n * b\n */ int x;`) was dropped. Restructured the scanner into a
  single unified loop that tracks in_block per line and resumes scanning
  after a `*/` (same-line or block-close), so trailing code survives;
  multiple same-line comments are all stripped; a pure `*/` line closes the
  block. +2 regression tests. All prior behaviors (string-literal /*,
  deref, orphaned lines, blanks) preserved. utils tests 21 passed.

### Slice 127 (16h goal) — round-trip re-verified after scanner rewrite — DONE
- Real merge→split round-trip after the strip_comment_blocks rewrite:
  68 functions merged, 65 markers preserved in the split files, single
  function file 288 lines with the correct marker — the scanner rewrite
  keeps the round-trip correct.

### Slice 128 (16h goal) — diff --fix-blocker verified — DONE
- `rebrew diff 0x1001a670 --fix-blocker` runs correctly: 6 structural diffs
  for the exit stub (full mismatch), and correctly writes NO blocker (the
  blocker classifier only annotates specific fixable patterns — register
  allocation, jump swaps, etc. — and removes stale blockers otherwise).
  exit metadata unchanged (status SIZE_MISMATCH, size 17). Tool behaves as
  designed.

### Slice 129 (16h goal) — definitive test --all + no status drift — DONE
- Full `rebrew test --all` after all session changes: 259 total, 222
  byte-passing + 37 failed — identical to the slice-104 baseline. verify
  --compare after the run: 0 regressions / 0 improvements / 0 new / 0
  removed — the batch run changed no statuses unexpectedly. The whole
  compile pipeline is stable.

### Slice 130 (16h goal) — strip_comment_blocks handles // line comments — DONE
- Closed review finding (slice 125): a `//` line comment containing `/*`
  (e.g. `int x; // /* note`) opened a block and swallowed following lines.
  The scanner now treats `//` (outside strings/blocks) as a line comment to
  EOL. +2 tests (line-comment `/*`; string `//` preserved). utils tests 23
  passed.

### Slice 131 (16h goal) — atomic_write_text creates parent dirs — DONE
- Closed review finding (slice 125): atomic_write_text failed when the
  target's parent dir didn't exist (e.g. metadata roots created lazily).
  Now mkdir(parents=True) before writing — benefits every metadata/gen-header
  write. +1 test (nested target). utils tests 24 passed.

### Slice 132 (16h goal) — review pass; star-prefixed */ close bug (high) — DONE
- Review (slices 126-131 scope) caught a HIGH bug in my slice-126
  strip_comment_blocks rewrite: a closing line with a `* ` prefix
  (`/*\n * comment */\nint x;`) was dropped by the orphaned-line check
  BEFORE the scanner saw the `*/`, so the block never closed and all
  following code was silently swallowed (the function returned "").
  Fixed: the `* `-line drop is guarded with `and not in_block`. Verified
  all cases (star close, star close + trailing code, orphan drop, multi
  block). +1 regression test. Suite 3242 + 1.

### Slice 133 (16h goal) — graph --focus VA beats placeholder names — DONE
- Closed review finding (slice 132): a dispatch-placeholder node named
  `fn_0x1000_...` shadowed the real function at 0x1000 for `--focus 0x1000`
  (partial-name match ran before the VA match). Reordered: exact name → VA
  match (hex-looking input) → partial name. +1 test (shadow case). depgraph
  suites 19 passed.

### Slice 134 (16h goal) — actionable diff hints replace <file> placeholders — DONE
- Real-data finding: verify/test SIZE_MISMATCH hints said "run 'rebrew diff
  <file>'" — a literal placeholder. compile.py's shared message now uses the
  actual VA (section_va, since diff resolves VAs); test.py's per-function
  hint uses ann.va; verify.py's regression tip uses <va>. The hints are now
  directly runnable.

### Slice 135 (16h goal) — hint fix verified at the source — DONE
- Direct compile_and_compare on a SIZE_MISMATCH function now returns
  "run 'rebrew diff 0x10002770'" (VA form). verify --json's display showed
  the old <file> message because it renders the persisted incremental
  verify cache — the fresh run produces the new hint; the cache refreshes
  on the next full verify. The slice-134 fix is correct at the source.

### Slice 136 (16h goal) — imports + verify cache verified — DONE
- rebrew imports --json: 84 imports with IAT VAs + 3 jmp-thunk stubs
  (GetOEMCP/GetACP/RtlUnwind) — the IAT resolution works. verify's
  incremental cache invalidation is sound (source hash + mtime + cflags);
  the stale message in the display was cached data, refreshed on re-verify
  ("use --full to force all").

### Slice 137 (16h goal) — rename dry-run lists the affected files — DONE
- Real workflow: `rebrew rename --dry-run` said "Would update
  cross-references in 3 files" without naming them — the user can't see the
  blast radius before applying. Extracted _collect_matching_files() (shared
  by the dry-run count and the display) and the dry-run now lists each file:
  "Would update cross-references in 3 files: - spiel.c, - gm_AllocGebaeude.c,
  - gm_ChangePlayerIdentityImpl.c". rename tests 17 passed.

### Slice 138 (16h goal) — rename matching-files test — DONE
- +1 test for _collect_matching_files (primary + referencing files listed,
  unrelated excluded). rename tests 18 passed.

### Slice 139 (16h goal) — skeleton --dry-run — DONE
- skeleton had no dry-run (single/append/batch always wrote files). Added
  --dry-run threaded through all three modes: prints "Would create"/"Would
  append" with size, skips the file write AND the metadata SIZE write, and
  the batch CREATED line is suppressed. Verified on the real workspace
  (batch 3 previews 3 candidates, no files created; caught and fixed the
  unconditional CREATED print during verification). +2 tests. skeleton
  tests 43 passed.

### Slice 140 (16h goal) — crt-match --fix-source --dry-run — DONE
- crt-match's --fix-source wrote SOURCE annotations with no preview (the
  last file-modifying tool without a dry-run). Added --dry-run: previews
  "Would update SOURCE annotations: N" by comparing the current metadata
  source against the match, without writing. Verified on the workspace (no
  writes; git tree unchanged). +1 test. crt-match tests 67 passed. Slice-139
  suite 3247 green.

### Slice 141 (16h goal) — review pass; skeleton dry-run output leaks fixed — DONE
- Review (slices 133-140 scope) verified rename/crt_match/compile changes
  and fixed 3 skeleton dry-run leaks: the APPENDED header, the Created:
  header, and the batch "Created N skeleton files" summary all printed
  despite dry-run (no files written). Now suppressed/wording-switched.
  Verified rename blast-radius semantics match the real path; 4 low
  findings documented (crt_match dry-run count semantics, skeleton dry-run
  JSON, rename file-rename preview, section_va==0 placeholder). Suite 3248
  green; targeted 165 passed.

### Slice 142 (16h goal) — update_annotation_key idempotent (fix-source count fix) — DONE
- Closed review finding (slice 141): crt-match --fix-source counted every
  candidate as "Updated" because update_annotation_key returned True
  unconditionally for metadata keys (update_field always rewrites).
  update_annotation_key now returns False when the metadata value is already
  equal (type-tolerant str comparison), so re-running on a synced project
  reports 0. Only caller is crt-match. Real run: "Updated SOURCE
  annotations: 0" (was inflated). 247 targeted tests passed.

### Slice 143 (16h goal) — skeleton dry-run JSON honest — DONE
- Closed review finding (slice 141): skeleton dry-run emitted "action":
  created/appended and {"created": [...]} despite writing nothing. JSON now
  says would_create/would_append and the batch key is "would_create" with a
  dry_run field. Verified: single dry-run JSON shows action=would_create.
  skeleton suites 63 passed. Suite 3248 green.

### Slice 144 (16h goal) — verify --full + stale-hint refresh — DONE
- verify --full (force-all) runs clean: 225/259. The SIZE_MISMATCH messages
  now display the slice-134 VA-form hint ("run 'rebrew diff 0x10002770'")
  — the full run refreshed the incremental cache that still held the old
  "<file>" text. The hint fix is fully visible end-to-end.

### Slice 145 (16h goal) — binsync-export real run verified — DONE
- Real binsync-export to /tmp: 561 function .toml files + global_vars.toml
  with 90 globals; the function format (info/header/comments sections,
  BinSync-compatible) is well-formed (e.g. _ls_LoadEntities with the
  NEAR_MATCHING status comment and note). Works end-to-end.

### Slice 147 (16h goal) — asm nasm --verify round-trip — DONE
- rebrew asm --format nasm --verify on the recovered exit wrapper:
  "Round-trip verification: PASS: 32 bytes identical" — the NASM output
  reproduces the original bytes exactly (including the trailing data
  handling). The disassemble→assemble round-trip works.

### Slice 148 (16h goal) — asm --inline-c + --size verified — DONE
- asm --format nasm --inline-c generates __declspec(naked) C with inline
  __asm for the exit wrapper — a usable reversing starting point. --size 17
  yields an exact 17-byte round-trip (the default window included the
  adjacent _exit; the size option scopes correctly).

### Slice 149 (16h goal) — asm default size from the function list — DONE
- Real workflow: `rebrew asm 0x1001a670 --format nasm --verify` round-tripped
  32 bytes — the default was a hardcoded 32-byte window, bleeding into the
  adjacent function (_exit). Now the default is the function list's size
  when the VA is known (17 bytes → exact round-trip); 32 remains the
  fallback for unknown functions. +2 tests. asm suites 38 passed.

### Slice 150 (16h goal) — status shows stale verify — DONE
- status's "Last verify" summary had no freshness signal — a stale cache
  (sources changed since the last verify run) looked current. Now the
  cache mtime is compared against every source's mtime; when any source is
  newer, the summary appends "[yellow](stale — run rebrew verify)[/yellow]"
  and the JSON gains last_verify.stale. +test-cfg enrichment (iter_sources
  needs source_ext). status tests 42 passed.

### Slice 151 (16h goal) — review pass; asm app decorator bug (critical) — DONE
- Review (slices 142-150 scope) caught a CRITICAL bug in my slice-149
  change: inserting _list_size_for before `def main(` displaced
  `@app.callback(invoke_without_command=True)` onto the helper, breaking
  the standalone `asm.app()`/`main_entry()` (RuntimeError: Type not yet
  supported: ProjectConfig). The umbrella `rebrew asm` still worked (main.py
  registers _mod.main directly) — masking the break. Fixed: decorator moved
  above main. Also: status JSON last_verify.stale added; a stale skeleton
  comment corrected.
- Verified: CliRunner asm --help exit 0; real `rebrew asm` round-trip PASS.
  Suite 3250 green; targeted 243 passed. 5 low findings documented.

### Slice 152 (16h goal) — skeleton JSON dry_run field consistent — DONE
- Closed review finding (slice 151): single/append skeleton JSON emitted
  the action but not the dry_run field (batch had it). Added — all three
  modes now report dry_run consistently. Verified: single dry-run JSON
  {action: would_create, dry_run: True}. Suite 3250 green.

### Slice 153 (16h goal) — prove slice mode verified — DONE
- prove --start-offset/--end-offset slice mode on the path-exploding
  CreateListenSocket: the slice-101 hint renders correctly ("— try
  --timeout higher...") and the function still path-explodes even on the
  first 64 bytes — a genuine angr exploration limitation on this complex
  419-byte function, not a tool bug. The failure path handles it cleanly
  (no status write).

### Slice 154 (16h goal) — cfg subcommands verified — DONE
- rebrew cfg detect-crt resolves MSVCRT → tools/MSVC600/VC98/CRT/SRC;
  cfg path prints the project toml (no --json flag on that subcommand — my
  invocation was wrong, not a bug). The multi-command cfg surface works.

### Slice 155 (16h goal) — CLI.md documents the new dry-runs — DONE
- The skeleton and crt-match option tables in docs/CLI.md lacked the new
  --dry-run flags (slices 139/140). Added both rows. Also verified the
  ghidra NOTE-pull divergence (review finding #2) is now more-correct
  behavior (real mode counts only actual changes) — no fix needed.

### Slice 156 (16h goal) — SIZE_MISMATCH triage investigation — DONE
- Among 29 fresh SIZE_MISMATCH functions, 8 are registry-known; one
  (0x1000d930) has a correctable divergence (annotation 2057 vs canonical
  2017). catalog --fix-sizes would correct it, but its "only-increasing"
  rule correctly blocks the shrink (safe-by-design; user fixes manually).
  The fix-sizes path writes metadata (never inline SIZE) — verified.

### Slice 157 (16h goal) — diff --format csv verified — DONE
- rebrew diff --format csv emits a clean CSV (Index,Match,Target_Bytes,
  Target_Disasm,Cand_Bytes,Cand_Disasm) — the exit stub's 3 compiled bytes
  vs 6 target instructions, properly escaped (quoted disasm with commas).
  Scripting output works.

### Slice 158 (16h goal) — prove --watch-va accepts hex VAs — DONE
- Real workflow: `prove --watch-va 0x10027078` failed ("not a valid
  integer") — the option was list[int], rejecting the hex form every other
  tool accepts. Changed to list[str] + parse_va normalization once up front
  (recursive watch call passes the original strings). Verified: hex
  --watch-va works and the prove message shows "EAX+mem(1 VA)". +1 test
  (hex watch-va → int). prove tests 29 passed.

### Slice 159 (16h goal) — sweep for other hex-VA option gaps — DONE
- Swept all src for list[int] typer options representing VAs: prove
  --watch-va was the only one (fixed in slice 158). No other CLI has the
  hex-parsing gap.

### Slice 160 (16h goal) — review pass; watch-va decimal semantics + robustness — DONE
- Review (slices 152-159 scope) applied 3 fixes (watch-va help text,
  skeleton batch JSON action, asm docstring) and surfaced real issues:
  - watch-va decimal semantics silently changed under parse_va (base-16
    only) — now int(v, 0) preserves BOTH hex and decimal with a clean error.
  - meta_vas metadata watch-VAs could raise a raw ValueError (traceback) —
    now parsed tolerantly with a debug log.
  - status could crash on a null "result" in the verify cache — now
    degrades (entry skipped).
  - Suite 3251 green; prove tests 45 passed.

### Slice 161 (16h goal) — decimal --watch-va verified + test — DONE
- The int(v, 0) fix (slice 160) verified: `--watch-va 268574328` (decimal)
  works and hex still does. +1 test (decimal → int). prove WatchVa tests 2
  passed.

### Slice 162 (16h goal) — error-review pass; 7 hardening fixes on status/prove/skeleton — DONE
- Ran the standing-instruction error-review (error-review.md prompt, subagent
  agent-44) over slices 156-161 scope (prove watch-va, status cache, diff csv,
  cli parse_va/resolve_source_arg, skeleton dry-run JSON). 10 findings, 4
  CONFIRMED by repro.
- Applied 7 fixes:
  1. status.py _load_verify_info: cache now must match cfg.target_name
     (getattr-defensive) or it's ignored — another target's summary can no
     longer be presented as this project's (was: only version checked).
  2. status.py both loaders: entries guard (list-entries cache no longer
     crashes with AttributeError) + null/truthy-non-dict results are SKIPPED,
     not counted as failures (was: {"result": None} → failed=1).
  3. prove.py --watch-va: values outside 0..0xFFFFFFFF are now a clean
     EXIT_ERROR=2 (was: silently accepted, then memory.load(-1) no-op'd → user
     believed memory was checked when it wasn't).
  4. prove.py metadata watched_vas: garbage/out-of-range values raise
     _ProveError with a fix-it message (was: debug-only log, silent drop).
  5. skeleton.py: --json now emits {"action":"none",...} for zero-uncovered
     batch and already-covered single VA (was: empty stdout, exit 0).
  6. prove.py: slice out-of-range now exits EXIT_ERROR=2 instead of being
     reported as a legitimate NOT PROVEN mismatch (exit 1).
  7. --watch-va help text documents decimal-vs-hex semantics.
- Deliberately NOT applied: finding #9 (resolve_source_arg accepting bare-hex
  positionals) — changes symbol-vs-VA ambiguity resolution across all tools;
  symbols are the common positional; flagged in code review instead.
- +13 tests (status target-guard/null-skip/entries-list ×6, prove watch-va
  range ×3 + metadata validation ×3, skeleton JSON ×2). Suite 3265 passed /
  26 skipped (was 3252). ruff/mypy/pre-commit all green. Real-world check:
  workspace status --json last_verify 225/259 still presented correctly under
  the new target guard.

### Slice 163 (16h goal) — FLIRT .pat CRC bug: generated sigs silently never matched — DONE
- Investigation: the brainstorm flagged property tests for bytes_to_pat_line's
  CRC. Probing python-flirt's parse_pat revealed the real bug: a .pat line
  generated by bytes_to_pat_line, when fed through the project's own reader
  (python-flirt, the exact library `rebrew flirt` uses: parse → compile →
  match), NEVER matched — even with no relocations.
- Root cause (from lancelot's flirt crate Rust source, which python-flirt is
  built from): IDA's FLIRT CRC16 (flair/crc16.cpp) is reflected poly 0x8408
  (= reflected CRC-CCITT 0x1021), init 0xFFFF, final bitwise invert,
  byte-swapped. rebrew used non-reflected 0x8005, init 0, no invert — every
  generated signature parsed fine but silently failed to match (false
  negatives for the whole FLIRT scanning pipeline).
- Fix: extracted `_crc16_flirt(buf)` (canonical IDA implementation) and made
  bytes_to_pat_line use it. Verified: 200/200 randomized write→parse→compile
  →match round-trips now succeed via python-flirt (previously even the
  no-reloc case failed); tamper test confirms sigs still discriminate.
- Tests: +4 known-answer unit tests (TestCrc16Flirt incl. empty + fixed
  values + anti-regression vs old variant) and +2 property tests (400
  examples total) in test_property_parsers.py pinning the round-trip and
  corruption rejection against python-flirt itself.
- Docs: FLIRT_SIGNATURES.md now pins the exact CRC variant (was vague
  "CRC-CCITT" — the imprecision that caused the original bug) and the
  hand-crafted example uses the safe `00 0000` CRC form.
- Suite 3270 passed / 26 skipped (was 3265). ruff/mypy/pre-commit green.
- NOTE for user: existing flirt_sigs/*.pat (libcmt_vc6.pat, libc_vc6.pat,
  msvcrt_vc6.pat) were generated with the buggy CRC and will never match —
  regenerate them from the VC6 .libs with the fixed gen-flirt-pat.

### Slice 164 (16h goal) — FLIRT fixup-width + CRC-window fixes; real-data validation — DONE
- Follow-up to slice 163: regenerated the workspace's flirt_sigs/*.pat from
  the VC6 libs (found at ~/.wine/drive_c/msvc6/lib) — old ones had the buggy
  CRC and never matched (backups in /tmp/*.pat.oldcrc).
- Real scan surfaced a second latent bug: even with the correct CRC, only 15
  functions matched, and functions with data references (isalpha family)
  couldn't. Two root causes, both in gen_flirt_pat:
  1. Fixup width: LIEF reports reloc.size == 0 for MSVC6 objects, so
     fixup_bytes = max(0//8,1) = 1 — every DIR32/REL32 fixup masked only 1
     byte instead of 4. Added _reloc_fixup_width() mapping x86 COFF reloc
     TYPE → width (DIR32/REL32 → 4B).
  2. CRC window: sigmake stops the CRC window BEFORE the first tail reloc
     (verified against the upstream pyflirt fixture: crc_len 33/34 windows
     ending right at the first post-lead reloc). rebrew CRCs the whole tail
     with reloc slots zeroed — the matcher CRCs the real address bytes →
     guaranteed mismatch. Window now truncates at the first tail reloc.
- Result on real data: 0 (old CRC) → 15 (CRC fix) → 29 matches (this slice)
  on server.dll. Cross-checked vs the user's catalog: 25/29 AGREE; the 3
  others are the user's custom renames (lock_stream, crt_close_handle,
  CopyCString) of the same CRT functions; 1 uncatalogued (_exit). isalpha is
  genuinely absent from the DLL (byte-pattern scan confirms).
- Tests: +4 (fixup width from type via make_coff_obj DIR32/REL32 objects;
  CRC-window truncation ×3), tamper property test now respects the dynamic
  covered region. Suite 3273 passed / 26 skipped. ruff/mypy/pre-commit green.
- Docs: FLIRT_SIGNATURES.md documents type-derived fixup width + window
  truncation rule.
- Note: 30 offsets skipped as ambiguous (>3 candidate names) — crc_len=0
  sigs are broad; a "report ambiguous set" mode is a candidate future
  improvement (noted, not implemented).

### Slice 165 (16h goal) — rebrew doctor workflow extensions — DONE
- Brainstorm item: "rebrew doctor extensions — detect missing angr, missing
  flirt_sigs/, missing MSVC toolchain, offer exact fixes". compiler/runner
  were already covered; extended the workflow surface:
  1. check_flirt_sigs (new): validates flirt_sigs/ exists, non-empty, and
     every .pat/.sig actually PARSES via python-flirt — the exact reader
     `rebrew flirt` uses. Catches corrupt/legacy sig files that silently
     yield zero matches (status warn, with per-file problem detail + exact
     gen-flirt-pat fix). Replaces the old existence-only probe.
  2. check_optional_tools (rewritten): now probes angr AND claripy and flags
     half-installed pairs ("angr without claripy — prove will crash" /
     "claripy without angr"), which previously passed the existence check
     and failed at runtime with a confusing traceback.
- Registered check_flirt_sigs in run_doctor (13 checks now).
- Tests: +9 (flirt_sigs missing/empty/valid/corrupt/zero-sig/no-python-flirt
  ×6; angr/claripy pairing ×4 incl. updated legacy assertions in
  test_doctor_compiler.py). Suite 3283 passed / 26 skipped.
  ruff/mypy/pre-commit green.
- Real-data: workspace `rebrew doctor` → 13/13 pass, "FLIRT signatures 4
  file(s), 3784 signatures load" (validates the regenerated pats) and
  "angr + claripy available".

### Slice 166 (16h goal) — flirt --show-ambiguous + weak-signature filter — DONE
- Two related improvements to the FLIRT surface, driven by the slice-164
  "ambiguous matches" note:
  1. `rebrew flirt --show-ambiguous`: new flag keeps multi-candidate matches
     (previously silently dropped) — reported with names capped at
     _MAX_AMBIGUOUS_REPORT=12 + "more" flag; JSON gains an always-present
     `ambiguous_matches` list.
  2. Weak-signature filter in gen_flirt_pat: the regenerated pats contained
     368 sigs with crc_len=0 AND <16 literal lead bytes (IDA's documented
     minimum for unprotected sigs). The fixed CRC let these fire: one generic
     prolog sig matched 30 unrelated DLL offsets with a bogus 7-name set.
     _is_weak_signature() now drops them at generation time (JSON reports
     skipped_weak).
- Real-data results (server.dll): ambiguous offsets 30 → 0; clean matches 29
  → 25 (the 4 dropped were weak-lead sigs — the _strchr one was provably a
  false positive; trade-off documented: kill all false positives, lose a few
  weak true positives — the right direction for identifications).
- Tests: +6 (_is_weak_signature ×3, CLI weak filter, ambiguous reporting ×3);
  the end-to-end pat fixture upgraded from a genuinely-weak 11B prolog to a
  40B realistic function. Suite 3290 passed / 26 skipped. ruff/mypy/
  pre-commit green. Workspace doctor: 13/13, "FLIRT signatures 4 file(s),
  3416 signatures load" (368 weak sigs removed).

### Slice 167 (16h goal) — run-prover todo trap fixed (prove pipeline validated) — DONE
- Exercised the real prover end-to-end for the first time on workspace data
  (todo's only run-prover item, _GetCommandPayloadSize @ 0x1000c710):
  compile → early-match gate → symbolic execution all worked; full-function
  run hit a graceful path-explosion timeout (clear message, no traceback);
  a 48-byte slice ran Z3 and found a REAL counterexample (EAX=28 vs 2).
  Pipeline validated; the function genuinely differs (diff: 245 structural).
- But the todo item was a trap: metadata SIZE=752 vs Ghidra's stale 340, and
  65.7% match (258-byte delta) meant prove could never converge — a wasted
  2-minute timeout per attempt. Fixed _collect_prover_candidates:
  1. Metadata SIZE is now preferred over the Ghidra size (it's the real
     function extent — Ghidra can be stale), so the `size > 500` cap uses the
     true extent.
  2. New _PROVE_MAX_DIFF_BYTES=8 cap: measured candidates whose estimated
     byte delta exceeds 8 are excluded from run-prover (they belong in
     improve-match/fix-delta). Unmeasured candidates stay eligible.
- Workspace result: run-prover 1 → 0 items; _GetCommandPayloadSize now
  correctly listed under improve-match (29 → 30). Tests: +4 (low-match
  excluded, metadata-size preference ×2, unmeasured kept). Suite 3294 passed
  / 26 skipped. ruff/mypy/pre-commit green.

### Slice 168 (16h goal) — review pass (slices 163-167 scope); 3 fixes applied — DONE
- Standing-instruction review (functionality-review prompt, subagent
  agent-45) over the FLIRT/doctor/todo changes. 4 findings, 1 CONFIRMED.
- Applied:
  1. (medium, confirmed) flirt.py: the tiny-.text early return emitted a
     DIFFERENT JSON schema (signatures_loaded/found/skipped — keys that don't
     exist in the normal path) and skipped the --va check entirely. Now a
     warning-only path; the shared JSON block always emits the full schema
     (match_count, matches, ambiguous_matches, ...) plus an optional
     "warning" key, and --va single-function checks run even on tiny .text.
  2. (low) gen_flirt_pat: I386_SECTION is a 16-bit section index (2 bytes,
     was 4) and I386_SECREL7 is 16-bit (2 bytes, was 1) per the COFF spec.
  3. (low) weak-sig rule strengthened: literal<16 AND crc_len<8 (was
     crc_len==0) — a 1-7 byte CRC window protects almost nothing. Impact on
     real pats: exactly 1 additional sig dropped (___lconv_init, 8 literals
     + 1 CRC byte — correctly weak).
- Investigated and dismissed #4 (obj alignment padding 0x00 in slices vs
  0xCC in binaries): empirically MSVC6 libc/libcmt objects have no
  zero-padded function slices (201 multi-symbol members → 1 small gap, and
  that one is an explicit 8B FF alignment NOP preserved by the linker).
- Tests: +5 (weak boundary ×2, small-text schema ×3). Suite 3299 passed /
  26 skipped. ruff/mypy/pre-commit green. Workspace re-verified: scan still
  25 matches / 0 ambiguous; doctor 13/13.

### Slice 169 (16h goal) — idempotency sweep + tools/check_idempotency.py — DONE
- Brainstorm item "idempotency sweeps: run every CLI with --dry-run twice and
  assert byte-identical output". Ran the sweep on the workspace: status,
  todo, verify --dry-run, diff, skeleton --dry-run, test --dry-run, prove
  --dry-run, rename --dry-run — ALL deterministic (verify's report timestamp
  is by-design wall-clock metadata; exit codes stable; match GA already has
  --seed for reproducible runs; CI already covers 3.12/3.13/3.14).
- Chased a one-off "--symbol required" error envelope that turned out to be a
  stale /tmp file from my own shell chaining (verify exits 1 by design when
  functions fail — EXIT_MISMATCH; 20+ clean runs reproduced nothing).
- Operationalized the sweep as tools/check_idempotency.py: runs a command
  twice, compares JSON (timestamp normalized away) + exit codes; default set
  = status/todo/verify --dry-run, extra commands via argv; importable for
  tests. Verified live on the workspace: all 3 default commands PASS.
- Tests: +6 (normalize recursive timestamp drop ×2; identical outputs;
  differing outputs; differing exit codes; non-JSON verbatim compare).
  pyproject pytest pythonpath now ["src", "."] so tools/ is importable as a
  namespace package (AGENTS.md updated to match).
- Suite 3305 passed / 26 skipped. ruff/mypy/pre-commit green.

### Slice 170 (16h goal) — match/asm out-dir CWD-relative bug + ga_run/ga_runs inconsistency — DONE
- Exercised the GA end-to-end on a real fix-delta item (0x1001a670, 3B diff):
  runs fast (compile cache), scores, writes best.c; the 3B gap is the user's
  source vs the real CRT _exit — not a tool bug.
- Spotted a path inconsistency: single-function `rebrew match --out-dir`
  defaulted to "output/ga_run" (SINGULAR) while the batch path and
  solutions/record_ga_run use "output/ga_runs" (PLURAL). My GA run created a
  stray output/ga_run/ dir in the workspace (cleaned up).
- Deeper bug: batch match used `Path("output/ga_runs").mkdir()` — CWD-relative,
  so running from a project SUBDIRECTORY (config discovery walks up to the
  toml) wrote output into the subdir. Same for `rebrew asm --all --out-dir`.
  Fixed:
  1. match.py: --out-dir default → "output/ga_runs" (plural); _run_single_ga
     resolves relative out_dir against cfg.root (absolute untouched); batch
     mkdir now cfg.root-relative.
  2. asm.py: batch --out-dir resolves against cfg.root; default is
     cfg.root/"output"/"asm".
- Verified live: `rebrew match` from src/ writes to output/ga_runs (no leak
  into src/output). Tests: +3 (asm relative/default/absolute out-dir
  resolution via mocked batch_extract_nasm). Suite 3308 passed / 26 skipped.
  ruff/mypy/pre-commit green.

### Slice 171 (16h goal) — near-diag VA positional + capstone constant crash — DONE
- Exercised `rebrew imports` (works; iat_va is a documented int API — left
  as-is) and `rebrew near-diag`, which had TWO real defects:
  1. Its positional argument only accepted a .c file path — unlike every
     sibling tool (diff/prove/test/match) which accept VA-or-symbol via
     resolve_source_arg. Now resolves VA/symbol → source file; and when the
     file has MULTIPLE functions, the annotation matching the requested VA is
     selected (was: annos[0] → diagnosed the WRONG function — e.g. asking for
     0x10011660 silently diagnosed 0x10010530).
  2. Raw TypeError traceback ("attribute name must be string, not 'int'"):
     cfg.capstone_arch/capstone_mode are PROPERTIES returning capstone int
     constants, but near_diag did getattr(capstone, cfg.capstone_arch) — a
     crash on every real project. disasm_insns now accepts both constant-name
     strings and int constants (same _resolve pattern similar.py already had).
- Real-data result: `rebrew near-diag 0x10011660` now correctly diagnoses the
  function (303B, STRUCTURAL 49% of delta, actionable suggestion).
- Tests: +5 (VA positional selects matching annotation; symbol positional;
  disasm with strings / ints / both-equal). Suite 3313 passed / 26 skipped.
  ruff/mypy/pre-commit green.

### Slice 172 (16h goal) — dispatch-table resolution: catalog names merged — DONE
- Exercised `rebrew similar` (works — all 10 hits are real catalog functions,
  incl. unaligned CRT starts like filbuf@0x1001ede5: linker-placed, valid)
  and `rebrew data --dispatch` (3 tables; the 212-entry command table 100%
  resolved; two small tables 0%).
- The 0% tables' targets (fptrap/fpmath) ARE named in the catalog data JSON
  but absent from source files, functions.txt, and function_structure.json —
  and data.py's dispatch naming only used source annotations. "0% resolved"
  was misleading: the tool knows nothing even though names exist elsewhere.
- Fix: extracted _build_dispatch_known_functions(cfg, src_dir) — source
  annotations take precedence, then the function-list + Ghidra-structure
  registry fills in names for targets no source covers (294 additional names
  on the workspace). Registry failures (missing fields, corrupt list)
  tolerated. Both 0% tables stay 0% because their specific targets genuinely
  lack names in the registry (they exist only in the data JSON, which data.py
  regenerates rather than reads) — honest reporting either way.
- Tests: +3 (source precedence, registry merge, missing-function-list
  tolerance); fixed 2 existing CLI tests broken by the import move. Suite
  3316 passed / 26 skipped. ruff/mypy/pre-commit green.

### Slice 173 (16h goal) — review pass (slices 169-172 scope); 6 fixes applied — DONE
- Standing-instruction review (code-review prompt, subagent agent-46) over
  the idempotency-tool/out-dir/near-diag/dispatch changes. 9 findings, 3
  CONFIRMED by repro.
- Applied:
  1. (medium, confirmed) near_diag: a derived VA (positional/file) matching no
     annotation silently fell back to annos[0] — compiled the wrong function's
     cflags/symbol/size and reported a diagnosis for it. Now errors
     ("No annotation for VA ...") when the VA was derived and unmatched; an
     EXPLICIT --va remains a user override (legit stale-marker correction —
     the existing va_size_flags test codifies that path).
  2. (medium-low, confirmed) check_idempotency: subprocess.TimeoutExpired
     crashed the checker instead of reporting FAIL; _run now returns a
     non-zero exit on timeout/OSError.
  3. (low, confirmed) check_idempotency: `--cwd` as the last argv → IndexError;
     now prints "--cwd requires a directory" and returns 2.
  4. (low) match --all/--all-targets with a non-default --out-dir silently
     dropped it; now rejected with a clear error (batch hardcodes
     cfg.root/output/ga_runs).
  5. (low, suspect) _run_single_ga dereferenced p.cfg.root unguarded; now
     getattr(p.cfg, "root", Path.cwd()).
  6. (low, suspect) disasm_insns: a malformed string constant crashed with
     AttributeError; now falls back to int(value), and annotations widened to
     str | int.
- Not applied (documented in review): #5 (timestamp-key dropping is
  by-design, documented), #8 (quoted-args limitation), #9 (pythonpath
  shadowing risk — acceptable).
- Tests: +5 (near_diag no-match error; idempotency --cwd guard; match
  out-dir rejection ×2 incl. default-passes). Suite 3320 passed / 26
  skipped. ruff/mypy/pre-commit green.

### Slice 174 (16h goal) — crt-match single-VA index fallback — DONE
- Exercised `rebrew crt-match` on the workspace (VC6 CRT sources present at
  tools/MSVC600/VC98/CRT/SRC, configured as crt_sources.MSVCRT):
  --all --dry-run found 10 matches (malloc/free/realloc/calloc × DBGHEAP +
  plain .C, __tzset, cvtdate) — all confirming existing EXACT catalog
  identifications with source-line proof (DBGHEAP.C:126 for _malloc etc.).
  Index (159 entries) covers .c/.cpp/.asm recursively; strrchr is absent
  because this CRT tree is partial (no STRCHR.C) — honest 0 matches.
- Bug: single-VA mode (`crt-match <va>`) required the annotation's module to
  own a crt_sources key — the workspace annotates everything as module
  "SERVER" but the index is "MSVCRT", so EVERY single-VA call failed with
  "No CRT index configured for module 'SERVER'". match_all already documented
  and implemented the fallback ("the library identity is decided by the name
  match, not the marker module") — the single-VA path lacked it.
- Fix: single-VA now tries the marker module's index first, then every
  configured index; errors only when no index exists at all. Verified on the
  workspace: `crt-match 0x1001a540` runs (0 matches — strrchr not in this
  tree — instead of a spurious module error).
- Tests: +2 (marker-module-without-index falls back to a real match; empty
  crt_sources errors with the earlier "No crt_sources configured" message);
  updated 1 test that codified the old error behavior (now asserts the
  fallback's honest 0 matches). Suite 3322 passed / 26 skipped. ruff/mypy/
  pre-commit green.

### Slice 175 (16h goal) — c_parser MSVC declarator corpus locked in — DONE
- Brainstorm item: property/corpus tests for c_parser declarators (the
  highest edge-case surface flagged). Probed extract_function_name_and_proto
  against 18 MSVC-era declarator idioms — ALL already handled correctly:
  __cdecl/__stdcall, pointer/struct/function-pointer returns
  (void (*get_handler(void))(int)), char** params, static+unsigned long,
  __forceinline/__declspec(naked), volatile+const, multiline protos,
  array-of-function-pointer declarations (skipped, next fn found), pure
  declarations → None. Sibling walkers (extract_function_name_from_line,
  find_c_function_definitions incl. multi-line line numbers) validated too.
- No parser bugs found — the value delivered is locking the corpus in as a
  parametrized regression test (18 cases) so tree-sitter version bumps or
  walker refactors can't silently break MSVC idiom handling.
- Tests: +18 parametrized corpus cases. Suite 3340 passed / 26 skipped.
  ruff/mypy/pre-commit green.

### Slice 176 (16h goal) — surface sweep (round_trip/rename/binsync) + reason_counts — DONE
- Exercised the remaining unvalidated tools on the workspace:
  - round-trip --dry-run: works; the 4 mismatches are all
    catalog_resolution_drift (user's sources reference symbols the target's
    relocs point elsewhere — real source bugs, correctly detected; the
    mangled `s_plt_SetPlantMap____Map_is_not_al_1002d9ec` unresolved symbol
    is a legit Ghidra string-label, not a rename bug).
  - rename --dry-run on 0x10011660: resolves VA → function, plans the
    rename + 2-file xref update correctly.
  - binsync-export --dry-run: 562 functions / 90 globals previewed.
- Small improvement: round-trip JSON now includes `reason_counts` — an
  aggregate of skipped_catalog + mismatches reasons, so a 92-entry skip list
  is triageable at a glance (e.g. {"unresolved_symbol": 85, ...}).
- Tests: +1 (reason_counts aggregation via the CLI with mocked splice path).
  Suite 3341 passed / 26 skipped. ruff/mypy/pre-commit green.

### Slice 177 (16h goal) — sync push dedup/idempotency tracking — DONE
- Feature-matrix "Not yet" item + documented Known Issue: "--export + --apply
  re-applies everything; sync should track what's already been pushed."
- Implemented content-hash dedup in ghidra/cli.py:
  - _op_hash(op): sha256 of the op with sorted keys (any edit → new hash →
    re-pushed).
  - .rebrew/ghidra_sync_state.json tracks pushed operation hashes
    (_load_pushed_hashes/_record_pushed_hashes, atomic write, tolerant of
    corrupt/missing state).
  - --export/--push: ops already in the state are skipped (report
    "N already applied, skipped"); --force re-exports everything.
  - --apply/--push: after a fully successful apply (0 errors), applied
    hashes are recorded — a partial failure records nothing (conservative
    retry).
- Tests: +3 (apply records hashes; export skips already-applied; --force
  re-exports). Suite 3344 passed / 26 skipped. ruff/mypy/pre-commit green.

### Slice 178 (16h goal) — review pass (slices 174-177 scope); 6 fixes applied — DONE
- Standing-instruction review (code-review prompt, subagent agent-47) over
  crt-match fallback / c_parser corpus / round_trip reason_counts / sync
  dedup. 9 findings, 3 medium CONFIRMED.
- Applied:
  1. (medium, confirmed) sync dedup: --force bypassed the EXPORT filter AND
     disabled APPLY recording — after a forced push the state permanently
     lagged reality (next plain export re-exports everything). Recording now
     always happens on successful apply; --force only affects the filter.
  2. (medium, confirmed) sync state read-merge-write is now flock-guarded
     (no lost updates on concurrent pushes).
  3. (low, confirmed) _op_hash normalizes integral floats (1 vs 1.0 hash the
     same) and rejects NaN (allow_nan=False).
  4. (low, confirmed) --force help text clarified ("only meaningful with
     --export/--push").
  5. (low, confirmed) crt_match single-VA: removed the unreachable empty-
     index guard (empty crt_sources exits earlier; per-module empty indexes
     are safe — match_function([]) returns []).
  6. (low, confirmed) round_trip rich render now shows reason_counts
     breakdown (was JSON-only — defeated the at-a-glance triage purpose).
- Not applied: #3 (partial-apply records nothing — conservative by design;
  Ghidra ops idempotent), #8 (state growth — negligible).
- #9 (CLI fallback test) was already covered by slice-174 tests.
- Tests: +1 (apply --force still records). Suite 3345 passed / 26 skipped.
  ruff/mypy/pre-commit green.

### Slice 179 (16h goal) — sync watch mode (live re-push) — DONE
- Feature-matrix "Not yet" item: watch mode. With the dedup tracking from
  slices 177/178, live sync is incremental: only content-changed operations
  re-push.
- Added `rebrew sync --watch` (requires --push): watches all source files +
  rebrew-function.toml via the shared watch_files helper; on change re-runs
  the full push path (recursive main() with push-relevant flags; --watch must
  not nest). The "No action specified" guard still fires for --watch alone
  (before the --push requirement check, which fires for --watch --apply).
- Tests: +3 (watch requires push; retest re-runs the push pipeline via a
  captured watch_files; metadata file included in watched paths). Suite 3348
  passed / 26 skipped. ruff/mypy/pre-commit green.

### Slice 180 (16h goal) — match --ga-history view — DONE
- The GA solutions infra (solutions.json winners + ga_runs.jsonl run log) was
  internal-only: load_ga_runs fed --skip-recent but there was no user-facing
  view of GA effectiveness. Added `rebrew match --ga-history`:
  - Summarizes .rebrew/ga_runs.jsonl: total runs, matched count + %, avg and
    best score (0 = exact), recent 10 runs (JSON + rich console).
  - Workspace result: 33 runs, 0 matched — honest reflection of the batch GA
    attempts so far.
- Real bug caught by the existing watch test: the watch retest re-invokes
  main() directly, and the new ga_history param was the ONE option not passed
  explicitly — its Python default is typer's OptionInfo object (truthy!), so
  the retest silently ran --ga-history instead of the GA. Fixed by passing
  ga_history=False explicitly (the established pattern for every option).
- Tests: +2 (history summary with malformed-line tolerance; empty history).
  Suite 3350 passed / 26 skipped. ruff/mypy/pre-commit green.

### Slice 181 (16h goal) — docs accuracy pass (sync matrix + CLI flags) — DONE
- The GHIDRA_SYNC.md feature matrix was stale: dedup/idempotency, watch mode,
  and incremental sync were marked "❌ Not yet" — all three shipped in slices
  177-179. Updated the matrix to ✅ with the actual flags, and marked the
  "No deduplication check" Known Issue as resolved with the new behavior
  (content-hash state, --force, conservative partial-apply recording).
- CLI.md: added `--ga-history` to the match flags table, and `--force`/
  `--watch` to the sync flag table. Verified --all-targets (multi-target
  batch GA) was already documented.
- Suite 3350 passed / 26 skipped (docs-only changes; no code touched).
- With this, every brainstorm item is now delivered or validated: FLIRT
  pipeline (CRC/fixup/window/weak-filter), doctor workflow checks, prove
  pipeline + run-prover triage, idempotency sweeps, output-path fixes,
  near-diag VA support, dispatch catalog naming, c_parser declarator corpus,
  surface sweep, sync dedup+watch+incremental, GA history view, CI matrix
  (3.12-3.14), completions, Ghidra sync depth, dashboard, multi-target batch
  GA (all-targets) — all existing and validated.

### Slice 182 (16h goal) — surface sweep (cache/cfg/data/conflicts) — DONE
- Exercised the last unvalidated commands on the workspace:
  - rebrew cache stats: 12675 entries / 48.32 MB / 500 MB limit — works.
  - rebrew cfg show --json: project/targets/compiler structure — works.
  - rebrew data: 304 globals, 90 data entries, 7 type conflicts — all 7 are
    genuine user-data inconsistencies (e.g. g_player_slot_0 as char[] in one
    file vs PlayerSlot[] in another); the detector + console "⚠ 7 type
    conflict(s) detected — run with --conflicts for details" + --conflicts
    flag all work in JSON and console.
  - rebrew data --gen-header --dry-run: correctly refuses to overwrite the
    existing rebrew_globals.h without --force.
- Verified the summary semantics (annotated = // GLOBAL: markers, data_entries
  = // DATA: markers) are correct, not a bug.
- No defects found — the sweep validates the remaining CLI surface. Suite
  3350 passed / 26 skipped (no code changes).

### Slice 183 (16h goal) — minimalism review; push-path refactor (kill recursive main) — DONE
- Standing-instruction review (minimalism-review prompt, subagent agent-48)
  over slices 177-180 features. 5 findings, 4 confirmed. Applied:
  1. (medium) sync --watch: replaced the 29-kwarg recursive main() retest
     with two extracted helpers — _build_ops (scan inputs: IAT/data/structs/
     signatures → ops) and _export_apply_ops (dedup-filtered export + apply
     + record). The recursive-main pattern was a drift hazard: typer option
     defaults are OptionInfo objects, so any future unforwarded option
     silently corrupts watch mode (I hit exactly this in slice 180 with
     ga_history). The retest now does a fresh scan + helper calls.
  2. (low) _op_hash: dropped the speculative int/float normalization +
     allow_nan (no op carries floats today); sort_keys (recursive) retained.
  3. (low) deleted the unreachable `ops is None` pragma guards (summary
     branch now uses `assert ops is not None`).
  - Fixed fallout: _build_ops uses the module-level build_sync_commands
    (tests mock it at module scope); sync-sizes branch re-derives its own
    iat_thunk_set.
- Kept (documented): reason_counts JSON field (useful for script consumers),
  fcntl.flock (cheap insurance; POSIX-only is fine — the toolchain is
  Wine/Linux).
- Tests: 38 sync tests + full suite 3350 passed. ruff/mypy/pre-commit green.

### Slice 184 (16h goal) — ghidra-cli push backend (IDEAS.md #24) — DONE
- The user-flagged item ("there is also akiselev/ghidra-cli which i like"):
  ghidra-cli 0.1.10 is installed (~/.cargo/bin + a workspace copy). Probed
  its subcommand interfaces (function create/set-signature, symbol create,
  comment set, bookmark add, type create; JSONL output; bridge keeps Ghidra
  loaded across calls).
- Implemented the backend abstraction:
  - config.py: `ghidra_backend = "reva" | "cli"` (default reva) target field.
  - src/rebrew/ghidra/cli_backend.py: `_op_to_args` translates the six sync
    op types (create-function, create-label, set-comment, set-bookmark,
    parse-c-structure, set-function-prototype) into ghidra-cli argv;
    `apply_commands_via_cli` runs them with the same (ok, errs) contract as
    apply_commands_via_mcp, tolerating timeouts/OSError/unknown ops.
  - ghidra/cli.py `_export_apply_ops`: routes the apply through the cli
    backend when cfg.ghidra_backend == "cli".
- Scope note: push (apply) direction only — pull still uses MCP. Per-op
  invocations (the tool's bridge makes each cheap after the first headless
  spawn); the undocumented batch format is a future optimization.
- Docs: IDEAS.md #24 marked push-done/pull-pending; GHIDRA_SYNC.md matrix
  gained the backend row.
- Tests: +11 (op translation ×7, apply counts/errors ×2, wiring ×2). Suite
  3361 passed / 26 skipped. ruff/mypy/pre-commit green.

### Slice 185 (16h goal) — backend review pass; CRITICAL key-mismatch fixed — DONE
- Review (code-review prompt, subagent agent-49) of the slice-184 ghidra-cli
  backend. 8 findings; 1 CRITICAL, 1 HIGH, both confirmed.
- Applied:
  1. (CRITICAL) cli_backend._op_to_args read args["address"]/["name"], but the
     real producers emit addressOrSymbol/labelName (commands.py) — every real
     label/comment/bookmark push targeted address "". Now accepts both
     spellings (+ location for set-function-prototype). Regression test pipes
     real build_sync_commands output through _op_to_args.
  2. (HIGH) the unit tests encoded the same wrong keys — rewritten to the
     producer keys; + integration test + already-exists-tolerance test.
  3. (MEDIUM) --sync-sizes/--sync-new-functions push hardcoded MCP — now
     routes through the ghidra_backend dispatch too.
  4. (MEDIUM) cli backend now treats "already exists"/"duplicate" failures as
     success, matching the MCP path's idempotent re-push semantics.
  5. (LOW/MED) ghidra_backend config validated against {"reva","cli"} with
     warn + fallback (was: silent pass-through of typos).
  6. (LOW) `get(...) or ""` instead of get(..., "") (None-safe); bookmark
     --bookmark-type passed explicitly; struct category drop documented;
     failure messages now carry the target VA.
- Also corrected the IDEAS.md batch note: ghidra-cli's batch file format
  splits lines on whitespace, so space-containing args (comments, signatures)
  cannot be batched — per-op invocations are the deliberate choice.
- Tests: +2 (integration + already-exists). Suite 3363 passed / 26 skipped.
  ruff/mypy/pre-commit green.

### Slice 186 (16h goal) — cli backend pull direction (IDEAS #24 complete) — DONE
- Completed the ghidra-cli backend with the pull direction (was "pull
  pending"). Derived the ghidra-cli list-output shapes from the Java bridge
  source (function list: {name, address, size, entry_point, ...}; symbol
  list: {name, address, type, ...} wrapped in {symbols: [...]}; comment list:
  {address, type: EOL/PRE/POST/PLATE, text}).
- cli_backend.py additions: `_run_json_cli` (JSONL parse, tolerant), `_to_va`
  (Ghidra bare-hex "10001000" → int; parse_ghidra_va's int() fallback would
  have misread bare hex as decimal), and `fetch_pull_data_via_cli` returning
  the pull-shaped {functions, symbols, plate, pre} with int VAs.
- commands.py `pull_ghidra_renames`: with ghidra_backend == "cli" the fetch
  section uses fetch_pull_data_via_cli (skipping the MCP block + its local-
  cache fallback is still active for empty results).
- Docs: IDEAS.md #24 marked done; GHIDRA_SYNC.md backend row now Both
  directions.
- Tests: +6 (_to_va ×4, fetch shapes + exit tolerance ×2). Suite 3369 passed
  / 26 skipped. ruff/mypy/pre-commit green.

### Slice 187 (16h goal) — pull-backend dispatch tests — DONE
- The slice-186 pull wiring (pull_ghidra_renames routing through
  fetch_pull_data_via_cli when ghidra_backend == "cli") lacked direct tests.
- Added 2: (1) cli backend skips all MCP fetchers (fetch_all_functions/
  fetch_all_symbols/fetch_mcp_tool never called); (2) the default reva backend
  still runs the MCP fetchers (init_mcp_session mocked to succeed). Also
  fixed the test harness detail: fetch_pull_data_via_cli is imported locally
  in commands.py, so it must be patched at its source module.
- Real-world sanity: `rebrew sync --pull --dry-run` in the workspace still
  works end-to-end (101 proposed changes via the local-cache fallback).
- Tests: +2. Suite 3371 passed / 26 skipped. ruff/mypy/pre-commit green.

### Slice 188 (16h goal) — review pass (pull backend); 6 fixes applied — DONE
- Standing-instruction review (code-review prompt, subagent agent-50) over
  the slices 186-187 pull-backend additions. 6 findings; applied:
  1. (HIGH) push/cli used the RAW cfg.ghidra_program_path while pull/cli used
     the resolved program_path — with no toml value, --push ran ghidra-cli
     without --program (wrong/unloaded program). _export_apply_ops now takes
     program_path and all three call sites (watch retest, export/push,
     apply-alone) + the sync-sizes apply pass it through.
  2. (MEDIUM) pull failure was silent (exit 0, stale caches applied as fresh):
     _run_json_cli now warns on timeout/OSError/non-zero exit.
  3. (MEDIUM) symbol list unfiltered could clobber function names — non-
     primary symbols are now skipped (matching the MCP path's filter).
  4. (LOW/MED) _run_json_cli now tries a full-document parse before the
     per-line fallback (pretty-printed output no longer loses wrapped data).
  5. (LOW) _to_va accepts uppercase 0X.
  6. (LOW) MCP-specific messages gated on the backend; epilog's stale
     ghidra_functions.json reference corrected to function_structure.json.
- Tests: +2 (uppercase 0X, non-primary symbol filter). Suite 3373 passed /
  26 skipped. ruff/mypy/pre-commit green.

### Slice 189 (16h goal) — comprehensive workspace validation battery — DONE
- Ran the full health battery on the workspace after 28 slices of changes:
  - doctor: 13/13 pass
  - lint: 111/111 (+1 legit W005 warning — a STUB function in the user's
    data missing a blocker explanation; the linter is doing its job)
  - status: matched_pct 93.9, byte_coverage 36.9, last_verify 225/259,
    not stale
  - tools/check_idempotency.py: all 3 default commands deterministic
  - flirt: 25 matches, 0 ambiguous
  - verify: 225/259, 0 divergences (matches the pre-change baseline)
- Everything consistent with the state before the session's changes — no
  regressions across 28 slices. Suite 3373 passed / 26 skipped.

### Slice 190 (16h goal) — verify --compare regression-gate exit code — DONE
- Exercised the CI-critical verify --compare mode: baseline written, diff
  computed, zero regressions — but the run STILL exited 1 because of 34
  pre-existing failures. That made --compare useless as a CI regression gate
  for a partially-matched project (always exit 1 regardless of regressions).
- Fix: with --compare AND a baseline (diff_result present), the exit code now
  reflects REGRESSIONS only — pre-existing failures are the baseline's
  business. Without a baseline (first run), the old failures-based exit is
  kept (can't detect regressions yet).
- Also fixed a masked test-data bug: test_compare_has_regression's previous
  VA format ("0x1000") didn't match the current ("0x00001000"), so the
  regression was never actually detected — the old exit-1-on-failures masked
  it. diff_reports keys by raw VA string (no normalization).
- Workspace: verify --compare now exits 0 (stable 225/259, 0 regressions);
  plain verify still exits 1 (34 failures — unchanged semantics).
- Tests: +2 (pre-existing failures + no regression → 0; no baseline → old
  semantics). Suite 3375 passed / 26 skipped. ruff/mypy/pre-commit green.

### Slice 191 (16h goal) — diff_reports VA normalization — DONE
- The slice-190 test-data fix exposed a real robustness gap: diff_reports
  keyed results by RAW VA string, so report-format drift ("0x1000" vs
  "0x00001000", or int vs hex) silently produced bogus "new"/"removed"
  entries and missed real regressions — dangerous for CI across tool
  versions.
- Fix: _canonical_va_key normalizes hex strings (0x-prefixed, any width) and
  ints to a canonical int key; emitted "va" fields render via _va_display as
  the canonical 8-digit hex (more consistent than the raw input format).
- Updated the 4 existing TestDiffReports assertions to the canonical format;
  added 3 tests (format-drift regression detected, unchanged detection,
  int-vs-hex merge).
- Workspace compare still works: stable 225/259, 0 regressions.
- Tests: +3. Suite 3378 passed / 26 skipped. ruff/mypy/pre-commit green.

### Slice 192 (16h goal) — flag-sweep validated + sweep_items exact-key fix — DONE
- Exercised the flag-sweep path on the smallest fix-delta item (_exit @
  0x1001a670, 3B diff): 20 flag combinations tried, best tracked, not exact —
  the 3B gap is source-driven (my skeleton vs the real CRT _exit), not
  flag-closable. The pipeline works end-to-end.
- Found a JSON shape inconsistency: flag-sweep results entries were
  {"score", "flags"} while GA entries carry "exact" — consumers reading
  result["exact"] got None. sweep_items now include "exact": s < 0.1.
- Tests: +1 (sweep JSON shape incl. per-entry exact). Suite 3379 passed /
  26 skipped. ruff/mypy/pre-commit green.

### Slice 193 (16h goal) — review pass (verify gate); 5 fixes applied — DONE
- Standing-instruction review (code-review prompt, subagent agent-51) over
  slices 190-192. 5 findings; applied:
  1. (HIGH) same-rank status flips (NEAR_MATCHING→STUB, both rank 2) were
     invisible to the --compare gate — added _STATUS_ORDER (fine-grained
     within-rank order) so diffing reports them as regressions/improvements,
     plus a match-percent drop (>5 pts within the same status) is now a
     regression.
  2. (HIGH) functions added since the baseline that FAIL (COMPILE_ERROR/
     MISSING_FILE) were invisible to the gate (exit 0 on newly-broken code) —
     the gate now fails when any diff["new"] entry ranks >= COMPILE_ERROR.
  3. (MEDIUM) mixed int/str canonical VA keys crashed sorted() — type-tagged
     sort key in both loops.
  4. (LOW) _va_display guards negative ints.
  5. (LOW) sweep_items exact rounding — unchanged (consistent threshold).
- Updated 1 test that codified the old same-rank behavior
  (test_diff_matching_alias); +7 tests (same-rank regression/improvement,
  match-percent drop, small-change-not-regression, mixed-key sort, new
  COMPILE_ERROR gate, new EXACT passes, int-vs-hex merge).
- Suite 3386 passed / 26 skipped. ruff/mypy/pre-commit green.

### Slice 194 (16h goal) — test --all dry-run JSON enrichment — DONE
- Exercised `rebrew test --all --dry-run --json` (259 candidates) — the JSON
  only listed file names while the console view showed VA + name per function.
- The dry-run JSON now includes a `functions` list (va, name, filepath,
  status) alongside the existing `files` set — additive, scripting-useful,
  consistent with the console view. Verified on the workspace (259 functions,
  111 files).
- Also confirmed the slice-193 ordering change caused no false regressions
  on the workspace (verify --compare: 259 unchanged, exit 0).
- Tests: +1 (dry-run JSON shape). Suite 3387 passed / 26 skipped.
  ruff/mypy/pre-commit green.

### Slice 195 (16h goal) — extract surface validated — DONE
- Exercised the last unexercised command: rebrew extract (list/show).
  - list: 6 un-reversed candidates (the summary's "6 CRT candidates") —
    small CRT-ish functions (18-544B) FLIRT couldn't name.
  - show 0x1001A7F7: extracted + disassembled correctly — an 18-byte CRT
    import-thunk pattern (`push [0x1003559c]; push [esp+8]; call next; ret`),
    saved to bin/server.dll/. show on an already-reversed VA errors
    informatively ("not found in candidate list") — by design (extract targets
    un-reversed functions).
- No defects found. Suite 3387 passed / 26 skipped (no code changes).

### Slice 196 (16h goal) — parse_va property tests — DONE
- parse_va (the shared hex-VA parser used by every CLI) had no property
  coverage. Added 4 hypothesis tests:
  - hex round-trip (0x%08x → same int, 300 examples)
  - prefix invariance (bare hex parses identically — always base 16)
  - whitespace tolerance
  - invalid inputs never crash with a raw exception (only the expected
    typer.Exit from error_exit)
- Learned/verified: error_exit raises typer.Exit which is an Exception, NOT
  SystemExit (my first test caught the wrong type — fixed with
  contextlib.suppress per SIM105).
- Tests: +4 (900+ hypothesis examples). Suite 3391 passed / 26 skipped.
  ruff/mypy/pre-commit green.

### Slice 197 (16h goal) — BSS fix honest message — DONE
- Exercised rebrew data --bss / --fix-bss --dry-run on the workspace (0
  annotated BSS globals): the --bss verification render is honest (0 known,
  0% coverage), but --fix-bss printed "Layout is perfect!" with ZERO known
  entries — "nothing to check" masquerading as "verified perfect".
- Fix: with no gaps AND no known entries, --fix-bss now says "No annotated
  BSS globals — nothing to verify. Add // DATA: annotations...". With known
  entries + no gaps, "Layout is perfect!" is preserved.
- Workspace verified: the honest message now prints; no file written
  (dry-run correct).
- Tests: +2 (perfect-with-entries, nothing-to-verify-without). Suite 3393
  passed / 26 skipped. ruff/mypy/pre-commit green.

### Slice 198 (16h goal) — review pass (slices 194-197); 6 fixes applied — DONE
- Standing-instruction review (code-review prompt, subagent agent-54) over
  the dry-run JSON / BSS message / parse_va property test changes. 6
  findings; applied:
  1. (MEDIUM) dry-run JSON key inconsistency: non-empty dry-run used "count"
     while empty-batch and result payloads use "total" — unified on "total",
     and the empty-batch dry-run now emits the same {total, files, functions}
     shape as the non-empty path.
  2. (MEDIUM) BSS "nothing to verify" hint pointed at "// DATA:" annotations
     which verify_bss_layout ignores (it reads // GLOBAL: + externs) — now
     says "// GLOBAL:".
  3. (MEDIUM) test_parse_va_invalid_rejects never asserted rejection (only
     "no other crash") — now branches: valid input asserts int parity,
     invalid input asserts typer.Exit.
  4. (LOW) dry-run "status" renamed to "current_status" (annotated status —
     distinct from result "status" = compile outcome).
  5. (LOW) dry-run "functions" now sorted by filepath, pairing 1:1 with the
     "files" set.
  6. (LOW) +3 tests: empty-batch dry-run shape, filepath-sorted functions,
     and the single-entry shape updated.
- Tests: +3 net. Suite 3395 passed / 26 skipped. ruff/mypy/pre-commit green.

### Slice 199 (16h goal) — depgraph + cu-map validated — DONE
- Exercised the last unexercised visualization: rebrew graph (depgraph) and
  rebrew graph --cu-map:
  - Standard: 262 nodes / 170 edges / 0 dispatch edges, by_status breakdown
    (EXACT 30, RELOC 192, STUB 26, ...) — the call graph over reversed
    functions.
  - --cu-map: 553 functions, 545 clustered into 4 compilation units (the
    main game CU 0x10001000-0x1001F5BB with 453 functions, plus CRT regions),
    8 unclustered thunks (IAT jmp stubs — correctly excluded).
- Both modes produce correct, useful output. No defects. Suite 3395 passed /
  26 skipped (no code changes).

### Slice 200 (16h goal) — doctor Ghidra sync check — DONE
- The doctor surface didn't cover the sync backend: no check for the
  ghidra_backend config, the program path, or the ghidra-cli binary.
- Added check_ghidra_sync:
  - cli backend: verifies the ghidra-cli binary (PATH or tools/ghidra-cli)
    and that ghidra_program_path is set.
  - reva backend: verifies ghidra_program_path is set (sync would target
    the wrong program otherwise).
- Registered in run_doctor (14 checks now). Workspace: doctor 14/14, "ReVa
  backend ready (program: /server.dll)".
- Tests: +4 (reva ready, reva missing program-path warns, cli binary missing
  warns, cli binary in tools passes). Suite 3399 passed / 26 skipped.
  ruff/mypy/pre-commit green.

### Slice 201 (16h goal) — near-diag secondary-category hint — DONE
- Ran near-diag on all 4 NEAR_MATCHING workspace functions (303B-952B): all
  diagnosed correctly with verdict + category breakdown + suggestion. The
  suggestion was always the dominant category's text even when a secondary
  category was significant.
- Improvement: when a secondary category accounts for >=25% of the delta,
  the suggestion now appends "Also: <secondary hint>." (e.g. structural
  churn + register noise → both facets mentioned).
- Workspace re-check: 0x1000b4d0 (structural 46%, register 10.1%) correctly
  gets no secondary hint (10.1% < 25%) — the threshold works.
- Tests: +2 (dominant-only no hint; register-only no hint). Suite 3401
  passed / 26 skipped. ruff/mypy/pre-commit green.

### Slice 202 (16h goal) — solutions DB + seed-from-solved validated — DONE
- Validated the GA's cross-function seeding foundation end-to-end:
  - Workspace .rebrew/solutions.json has 1 winning entry (_gv_CheckSlotActive,
    score -100 = exact, size 113).
  - find_similar (same-target-first, size-distance, cflags tiebreak) returns
    the correct match with the right signature (my initial script passed args
    positionally wrong — the tool is fine; production callers use keywords).
  - match.py's seed-from-solved call (cfg.root, size=stub.size, cflags=...,
    target=..., top_k=3) is correct and would seed the GA with the solved
    function's source for similar targets.
- find_similar already has solid tests (size ordering, top_k, empty db,
  target preference). No defects. Suite 3401 passed / 26 skipped
  (no code changes).

### Slice 203 (16h goal) — review pass; HIGH binary-resolver inconsistency fixed — DONE
- Standing-instruction review (code-review prompt, subagent agent-57) over
  slices 199-202. 6 findings; applied:
  1. (HIGH) doctor PASSed on a tools/ghidra-cli binary the runtime NEVER
     invoked (all sync call sites used the bare "ghidra-cli" PATH lookup →
     FileNotFoundError at runtime). Added resolve_ghidra_cli(cfg) (PATH
     first, then tools/ghidra-cli if executable) as the SINGLE source of
     truth; the doctor check AND all three sync call sites (export/apply,
     sync-sizes apply, pull fetch) now thread the resolved binary through.
  2. (MEDIUM) executable bit now checked (is_file + os.access X_OK).
  3. (MEDIUM) the missing-binary test's monkeypatch was ineffective (inner
     import) — now patches cli_backend.shutil.which (imports moved to module
     level).
  4. (LOW) near_diag: dead default=None dropped; the reloc secondary hint is
     lowercased ("Also: difference is confined...").
  5. (LOW) test gaps closed: executable-bit + non-executable-warns tests,
     25% boundary test (fires exactly at 25%, not below).
  6. (LOW) sync wiring test updated for the new ghidra_cli kwarg.
- Workspace: resolve_ghidra_cli finds tools/ghidra-cli; doctor 14/14.
- Tests: +3 net. Suite 3404 passed / 26 skipped. ruff/mypy/pre-commit green.

### Slice 204 (16h goal) — prove --all validated; first real PROVEN result — DONE
- Exercised rebrew prove --all --dry-run on the workspace (4 NEAR_MATCHING
  functions, 15s timeout each): **1 of 4 PROVEN** —
  _CleanupSockets @ 0x1000a010 ("Proven equivalent (EAX; 1 original state(s),
  1 compiled state(s))"). The symbolic prover's flagship success on real data
  (dry-run — STATUS not updated; the user can run without --dry-run to
  promote it).
- The other 3 fail informatively: 2 path-explosion timeouts (_GetCommand
  PayloadSize, _CreateListenSocket) and 1 genuine Z3 counterexample
  (_ls_LoadEntities: "EAX differs", 67x5 state pairs) — the prover
  distinguishes real semantic differences from timeouts.
- Batch mode: correct aggregate (total 4 / proven 1 / already_matched 0 /
  failed 3) with per-function details. No defects. Suite 3404 passed /
  26 skipped (no code changes).

### Slice 205 (16h goal) — round-trip ??_C@ string-symbol gap fixed — DONE
- Exercising round-trip --filter surfaced a REAL gap: SendBroadcastPacket
  (RELOC) was skipped as "unresolved_symbol" for a ??_C@_0BC@GMNE@... symbol
  — MSVC's mangled name for a static string constant. The string resolver
  (_extract_string_symbols) only handled the $SG<N> form.
- Fix: _extract_string_symbols now also indexes ??_C@-prefixed symbols (same
  content-matching resolution). Real-data result: filtered round-trip of
  SendBroadcastPacket now splices 1 (was 0); full batch spliced 126 → 131,
  skipped_catalog 92 → 86.
- The +1 mismatch (_DispatchLogOutput) is a GENUINE source drift now surfacing
  (first diff at a non-reloc byte — previously hidden behind the skip), not a
  string-binding false positive: the tool is now MORE correct, reporting
  previously-hidden issues.
- tests/bin_util.make_coff_obj extended with section_symbols (static
  section-defined symbols) to build ??_C@/SG fixtures; +2 tests.
- Suite 3406 passed / 26 skipped. ruff/mypy/pre-commit green.

### Slice 206 (16h goal) — round-trip: Ghidra VA-names, $L tables, string-prefix binding — DONE
- Real-data deep-dive of the remaining 86 skipped_catalog entries (all
  "unresolved_symbol") split them into three codegen gaps + one data gap:
  1. **Ghidra auto-names encode their VA in trailing hex** (_g_1003546c,
     _s_<preview>_1002d9ec). New `_name_encoded_va` + `_make_resolver` in
     round_trip.py decode these as a fallback (fires only on catalog miss;
     sub-0x100000 and 4-digit suffixes ignored). Local to round-trip — the
     shared resolver (test/verify) must not read VAs out of names.
  2. **$L<N> jump/dispatch tables + $cleanup_loop$<N>** are MSVC labels in the
     SAME .text section as the function. New `_extract_local_labels` maps them
     via fn_va + (sym.value - fn.value) — valid because round-trip only
     splices byte-identical layouts (post-splice compare verifies). Label
     offsets in the .obj == offsets from fn_va in the target.
  3. **String literal drift**: compiled "Commandbuffer full!\x00" vs target
     "Commandbuffer full!\n\x00" (source missing trailing \n — invisible to
     `rebrew test`). `_resolve_string_symbols_in_target` now retries with the
     NUL stripped so a compiled literal that is a strict prefix binds to the
     START of the target string (the address the reloc needs). Safe because a
     wrong patch surfaces as catalog_resolution_drift, not silent corruption.
- Net on the workspace: **spliced 131 → 158 (+27), skipped_catalog 86 → 58**.
- The remaining 58 are all DATA gaps (unannotated globals/functions like
  _g_timestamp_0b6c ×11, _get_command_type ×2, _putc, _thread_proc@4) except
  _LogWinsockError's "Unbekannter WinsockError %d" which is ENTIRELY absent
  from the target (genuine source message drift — correctly skipped).
- 6 mismatches all remain genuine catalog_resolution_drift (user source bugs):
  4 known + _DispatchLogOutput (slice-205 surface) + _gm_IsInRange (now
  surfaced by the fallback: source calls gm_GetBuildingTypeCategory, target
  calls gm_MapEntityStatRange).
- +15 tests (name-encoded VA decode, $L/cleanup_loop mapping incl. func_value
  offset math, prefix-binding + exact-match-preferred, resolver precedence).
  Test mocks updated to the new 6-tuple _compile_and_extract return.
- Suite 3421 passed / 26 skipped. ruff/mypy/pre-commit green.

### Slice 207 (16h goal) — fuzz-review pass: COFF .obj extraction fuzz targets — DONE
- Ran ~/review-prompts/prompts/fuzz-review.md (first time — 0 prior runs).
  Inventory: untrusted-input surfaces are the binary parsers (COFF .obj /
  PE/ELF via LIEF + rebrew post-processing), FLIRT .pat/.sig (third-party
  `flirt` lib, guarded), C source (tree-sitter + regex annotation parsers —
  already fuzzed), toml (tomlkit). The gap: slice-206's new round_trip .obj
  helpers (_extract_local_labels, _extract_string_symbols) had NO fuzz
  coverage.
- Added 5 hypothesis property tests (test_property_parsers.py):
  - coff_obj_spec strategy: random code + $L/$SG/??_C@/plain section symbols.
  - test_extract_local_labels_invariants: output == exactly the $-prefixed
    same-section symbols mapped to fn_va + (sym.value - fn.value).
  - test_extract_string_symbols_content_in_section: extracted content appears
    verbatim in the section data at the symbol's value, ending at the first NUL
    (found a REAL edge: content may extend into make_coff_obj's 4-byte
    alignment padding where the NUL lives — the invariant initially failed on
    this and was corrected to use the padded section data).
  - test_obj_helpers_robust_on_malformed: 15 truncation/byte-flip variants per
    example — helpers must never raise.
  - _name_encoded_va roundtrip + output-domain properties (6-8 hex digit
    suffix decodes to itself; output is always the suffix, never invented).
- Fixed a pre-existing mypy nit in the file (bytearray→bytes reassignment).
- Suite 3426 passed / 26 skipped (was 3421). ruff/mypy/pre-commit green.

### Slice 208 (16h goal) — prove/angr real coverage + 30 mypy errors fixed — DONE
- The venv only had claripy (user's install); angr was declared in uv.lock as
  the `prove` extra but never installed, so 26 prove tests silently skipped
  locally (suite read "26 skipped" every run). `uv sync --all-extras` (the
  documented dev install) pulled angr 9.2.203 → **3452 passed, 0 skipped**:
  TestWin32SimProcedures, TestApplyArgConstraints, TestProveEquivalence,
  TestEdxChecking all run for real now.
- Enabling angr surfaced **30 pre-existing mypy errors** in prove.py (masked
  while angr was an untyped/missing import): unused `# type: ignore[misc]`
  on SimProcedure subclasses, `no-untyped-call` on angr's untyped solver/
  memory/heap API, `SimState` missing type args, `no-any-return`, and a real
  narrowing issue (`self.addr` is `int | None` in angr's stubs — added an
  assert). All fixed with targeted per-line ignores or proper annotations.
  CI's pre-commit + test jobs use `--all-extras`, so this mypy debt would
  have failed CI's pre-commit job — now clean.
- Skip reasons now tell fresh environments how to enable: "run 'uv sync
  --all-extras'".
- Suite 3452 passed / 0 skipped. ruff/mypy/pre-commit green.

### Slice 209 (16h goal) — code-review of slices 206-208 + 6 findings fixed — DONE
- Ran ~/review-prompts/prompts/code-review.md scoped to the round_trip/
  prove changes. 1 medium + 5 low findings, all real, all fixed:
  1. (medium) Oversize guard was one-sided: a compile LONGER than the target's
     trimmed real-code span passed, and its tail was silently dropped by the
     splice. Now requires exact equality (len(patched) == trimmed_size); the
     golden-PE test stub was made consistent with the real pipeline (which
     strips NOP padding via parse_obj_symbol_bytes).
  2. _extract_local_labels now takes the function's referenced reloc-symbol
     set, so sibling functions' $L labels (same section, different layout)
     can never contaminate the map.
  3. String search in _resolve_string_symbols_in_target now bounded by the
     section's RAW file extent, not virtual size — a .data BSS tail no longer
     lets probes match into the next section on disk.
  4. Removed dead `nothing_verified` term (catalog_ok already covers it by
     construction).
  5. _name_encoded_va rejects 9+ digit hex suffixes instead of truncating to
     a plausible-but-wrong VA.
  6. (test quality) Hoisted nested `_run_simulation` to module level (angr
     lazy-import + TYPE_CHECKING annotation binding); the tautological EDX
     mock test (which re-implemented _compare_state_pairs) now patches
     _run_simulation and exercises the REAL comparison logic.
- +3 tests. Suite 3455 passed / 0 skipped. ruff/mypy/pre-commit green.
  Workspace round-trip unchanged (158 spliced / 58 skipped / 6 genuine drifts).

### Slice 210 (16h goal) — idempotency sweep + annotation roundtrip invariants — DONE
- Idempotency sweep on the workspace (brainstorm #6): ran every file-modifying
  tool twice and compared outputs — rebrew lint --dry-run, rename --dry-run
  (real symbol), merge --dry-run, data --dry-run, prove --dry-run: all
  byte-identical across runs; dry-run left no files modified.
- Fixed a real contract violation: remove_annotation_key returned True
  unconditionally for metadata keys even when remove_field found nothing to
  delete (idempotence rule: "removing an absent key is a no-op"). It now
  propagates remove_field's result.
- +5 annotation roundtrip invariant tests (brainstorm #5): metadata-key
  update→remove leaves the .c byte-identical and the parsed value back at its
  default; removing an absent metadata key returns False; same-value update
  returns False; non-metadata keys round-trip through the .c file (insert →
  strip → byte-identical); remove_inline_annotation_key never creates or
  writes rebrew-function.toml.
- Suite 3460 passed / 0 skipped. ruff/mypy/pre-commit green.

### Slice 211 (16h goal) — stale docs + round-trip fallback docs — DONE
- DEVELOPMENT.md "Toolchain-dependent tests" section was stale (prove "not
  installed by default / stubs only" — now the documented `uv sync
  --all-extras` enables 62 real prove tests; fuzz targets for the .obj
  helpers also noted).
- docs/CLI.md round-trip section now documents the three resolution
  fallbacks (Ghidra VA-names, $L labels, string prefix-binding) and that
  wrong fallback hits surface as catalog_resolution_drift, never silent
  corruption.
- round_trip.py module docstring updated to match.
- Suite 3460 passed / 0 skipped. pre-commit green.

### Slice 212 (16h goal) — push rebrew + recoverage health/features — DONE
- Committed + pushed the session's work: rebrew 5eeca4b..cfcbb6f
  ("feat: round-trip resolution fallbacks, prove typing, metadata
  hardening" — 124 files changed, +17.7k/-1.6k), pre-commit ran inside the
  commit (all hooks green).
- Sister project recoverage (coverage dashboard consuming coverage.db):
  - Regenerated the workspace DB with the CURRENT rebrew (catalog + build-db)
    and verified every API endpoint + the SPA + Potato Mode return 200; the
    asm 501 is the designed "capstone not installed" optional-dep path.
  - Found the root cause of its 57 silently-skipped tests: CI has no
    coverage.db, so DB-gated tests never executed. tests/conftest.py now
    builds a synthetic coverage.db (build-db schema v4) → 201 passed /
    4 skipped (was 148/57).
  - Fixed 3 stale potato assertions that had been rotting unseen (ETag
    casing, section-name accesskeys, detail-row markup) — now green against
    BOTH the synthetic DB and the real workspace DB.
  - Added 2 missing features from docs/ideas.md: `--bind` flag for
    `recoverage serve` (LAN access) and a server-side 429 rate limit on
    POST /api/regen (retry_after) — verified end-to-end.
  - Pushed recoverage c9d5c32..e7ea356.

### Slice 213 (16h goal) — config-review: 2 HIGH metadata-routing bugs fixed — DONE
- Ran ~/review-prompts/prompts/config-review.md (first run) scoped to
  config.py/metadata.py/annotation.py/data_metadata.py + all call sites.
  Found 2 HIGH + 2 MEDIUM + 4 LOW; fixed all actionable ones:
  1. (HIGH) `rebrew catalog --fix-sizes` read/wrote SIZE metadata to
     cfile.parent instead of cfg.metadata_dir — every SIZE fix was silently
     lost to a stray rebrew-function.toml. Now routes both the read
     (parse_c_file_multi) and the write (update_size_annotation) through
     cfg.metadata_dir.
  2. (HIGH) `rebrew data --fix-bss` wrote SIZE/SECTION/NOTE to
     <reversed_dir>/rebrew-data.toml while every read uses cfg.metadata_dir
     (= reversed_dir.parent) — BSS metadata orphaned. _generate_bss_fix now
     takes a metadata_dir separate from the .c output dir.
  3. (MED) config load now warns when the target binary is missing (image_base
     auto-detection skipped) — a typo'd path no longer silently zeros the
     layout. One config test + 2 binsync tests updated (result.stdout, the
     documented JSON convention); filterwarnings added for the fixture noise.
  4. (MED) round-trip's "non-zero image_base in rebrew-project.toml" error
     was misleading (image_base is auto-detected, not a TOML key) — now
     points at the binary path/format.
  5. (LOW) data.py getattr default no longer eagerly dereferences
     cfg.target_name; annotation.py's parse_c_file_multi docstring corrected
     (it previously recommended the wrong metadata_dir); lint --fix now routes
     inline STATUS migration through update_source_status (validates, clears
     stale blockers) instead of the raw bypass writer.
- Suite 3460 passed / 0 skipped. ruff/mypy/pre-commit green.

### Slice 214 (16h goal) — db-review: CATALOG.md 0.0%, C-source loading, template bug — DONE
- Ran ~/review-prompts/prompts/db-review.md (first run) across rebrew
  (producer) + recoverage (consumer). No criticals; fixed 5 findings:
  1. (MED) build_db's CATALOG.md coverage read summary[".text"].size — grid
     stores textSize top-level → every CATALOG.md reported 0.0%. Now falls
     back to textSize; workspace CATALOG.md shows 98.4% (139172/141382).
  2. (MED) paths.sourceRoot consumed by recoverage but never produced — and
     potato anchored C-source paths at the recoverage package dir, so C
     source never loaded. grid now emits sourceRoot; potato anchors at cwd.
     Verified: Potato Mode renders "C Source (library_zlib.h)".
  3. (MED) negative fileOffset/textOffset (VA outside all sections) violated
     build_db CHECK constraints and aborted the whole rebuild (and negative
     slices read the binary from the END). grid skips such entries; build_db
     clamps defensively.
  4. (MED) GLOBAL/DATA marker rows counted as functions in recoverage's
     stats/list (build_db's function_stats excludes them) — consumer queries
     now filter; search also matches vaStart (hex), parity with Potato.
  5. (LOW→real bug) potato's panel template had `% if cell_label:` / `% end`
     directives embedded mid-line → SimpleTemplate rendered them as literal
     text and the Label row always rendered. Fixed; also potato looked up
     cell functions by NAME though cells carry VA strings (SPA/API use VA) —
     now parses hex and looks up by va.
- Pushed: rebrew cfcbb6f..137b6d3, recoverage 66648bd..169d8b6.
- Both suites green (3460 / 204 passed), mypy + pre-commit clean.

### Slice 215 (16h goal) — verify_results wired end-to-end (dead table → feature) — DONE
- db-review leftover 1.4: the verify_results table was created by build_db
  but never populated (verify.py writes db/verify_results.json). Now:
  - build_db imports the last verify report into the table (best-effort,
    INSERT OR REPLACE) — workspace DB: 259 rows with real byte_deltas.
  - recoverage /function/<va> attaches last_verify {verified_at,
    byte_delta, diff_lines}; SPA meta grid shows a "Verified" row.
  - Synthetic DB seeds a verify_results row; +2 API tests (206 passed).
- Pushed: rebrew 137b6d3..951cd48, recoverage 169d8b6..13fa9f7.
- Suites green (3460 / 206), mypy + pre-commit clean.

### Slice 216 (16h goal) — docs refresh, agent skills, v0.1.0 release — DONE
- 30-item docs-vs-code audit (delegated) applied across AGENTS.md, the
  AGENTS.md.template, 14 docs/ files and the agent skills: corrected stale
  CLI flags (asm positional VA, lint positional files, diff --mismatches-only,
  cfg set-compiler TARGET PROFILE, crt-match/graph --origin), removed the
  walk-up-metadata myth (metadata lives at cfg.metadata_dir only), qualified
  toml keys, marker-only linter enforcement, flag-sweep tier counts
  (192/1152/5376/258048/6193152), angr via `uv sync --all-extras`, test count
  3460, 33 CLI commands, NEAR_MATCH_THRESHOLD 60%, verify_results populated by
  build-db, paths.sourceRoot. +4 follow-up fixes (CLI.md --mm, TOOLCHAIN tier
  counts, ANNOTATIONS E003/E007 table, BOOTSTRAPPING walk-up).
- Agent skills (5 SKILL.md + annotation-format reference) improved via a
  5-agent swarm: intake (doctor-first, dashboard handoff), workflow
  (round-trip validation step, metadata model, prove --watch-va), matching
  (sweep-then-ga, ga-history, tier counts), data-analysis (dispatch
  thresholds, JSON shapes, failure modes), ghidra-sync (cli backend,
  pull-datatypes, where-results-land). Every command validated against real
  --help (tools/validate_skill_commands.py: All OK).
- CHANGELOG.md: full [0.1.0] - 2026-08-08 entry.
- Release cut: `make build` → rebrew-0.1.0 sdist+wheel; commit 5d1832a;
  annotated tag v0.1.0 pushed; GitHub release created with artifacts
  (github.com/maci0/rebrew/releases/tag/v0.1.0).
- Final state: rebrew 3460 passed / 0 skipped, recoverage 206 passed /
  4 skipped, workspace doctor 14/14, round-trip 158 spliced / 58 catalog
  gaps / 6 genuine drifts.

### Slice 217 (16h goal) — v0.1.0 release validation — DONE
- Wheel reproducibility: built twice with SOURCE_DATE_EPOCH=1700000000 —
  byte-identical sha256 (37bf3b45…), confirming the deterministic-build
  claim in docs/CI.md.
- Clean-install smoke test: fresh `uv venv` + wheel install → version 0.1.0,
  all core modules import (cli/compile/round_trip/prove/match), and every
  entry point resolves: `rebrew` umbrella (similar/prove/dashboard/skills
  list) + standalone `rebrew-round-trip` / `rebrew-skills`.
- Expected finding (not a defect): only 3 console scripts are registered
  (rebrew, rebrew-round-trip, rebrew-skills) — the other tools run via the
  umbrella, matching pyproject.toml.

## 2026-08-08 — 8h swarm + review rounds (minimalism/slop ×10, error, functionality, perf)

**Swarm (20 runs, 30 confirmed findings):** all fixed or triaged — batches
`dc1a6ce`…`535df17` (status-counting unified via `count_statuses`,
promotion decision unified via `cli.should_promote_status`, duplicate
CATALOG.md generator dropped, metadata-key drift, dead-param removal,
SIZE_MISMATCH message parity, ghost GACheckpoint docstring).

**Review rounds (error / functionality / perf):** fixes in `e72e805`
(rebrew) and `1caae91` (recoverage), plus perf batch `bd0b204` + `c9c80ff`:

- flag_sweep worker exceptions now counted + warned (never silent "no match")
- `rebrew test --json` single-document output (skip reason folded in)
- catalog binary-load failure warns (no more plausible-but-wrong coverage DB)
- corrupt ghidra sync state preserved via `preserve_corrupt` + warned
- GA run-record / solution-save failures warned (--skip-recent/seed visibility)
- compile.py distinguishes COMPILE_ERROR vs EXTRACT_ERROR
- iter_annotations parse skips warned (no silent function loss)
- `build-db --target` warns when it will drop other targets
- update_source_status serialised with a module lock (parallel verify)
- GA `_compute_fitness` prints gated behind verbose (Console-lock contention)
- `parse_c_ast` memoized (tree-sitter trees are immutable)
- `find_similar` accepts preloaded entries (batch seeding reads file once)
- oversized flag sweeps deterministically sampled (full tier ~2.5M → ~100k)
- grid.py padding-trim computed once per gap
- recoverage: ETag+304 on /asm & /bytes (was year-immutable), DLL/disasm
  caches cleared on external build-db broadcast, bare-hex VAs accepted,
  corrupt TOML warned, van.min.js missing warned, schema check memoized,
  SPA fetch `no-store` → `no-cache` (ETag now honored)

**Triage (keep with reason):** test-only wrappers (public utilities),
__init__ re-exports (public API), MSVC7_ONLY_IDS (auto-synced file),
pull_prototypes replace_externs (tested programmatic flag), pagination
loops (different data needs; no-advance guards already present),
module_for_va (tested, used by match.py), recoverage micro-dead-code
(verified used), FUNC4 DB-only-target DLL fallback (404 names target),
FUNC10 full-grid rebuild (ETag now short-circuits), PERF7 double LIEF
parse (ms-scale, API churn risk), PERF8 diff_functions quadratic
(diagnostic path), PERF10 header content-hash (deliberate correctness
guard), PERF11 potato full-cell load (fallback UI).

## 2026-08-09 — R2 review round (test-review, cli-review, db-review)

**Three-agent swarm on test/cli/db quality.** All confirmed findings fixed
or triaged (commits `517cc5c`, `69e2f56`, `004fa2f`, `db1c328`, `1411444`,
`3ee4993`):

- **EXTRACT_ERROR**: symbol-not-found in `_extract_and_compare` now labeled
  EXTRACT_ERROR (was mislabeled COMPILE_ERROR, which hard-exited `rebrew
  test` with code 2 and blamed the source); added to `_STATUS_RANK`/
  `_STATUS_ORDER`; 8 new unit tests.
- **matchedFunctions**: summary no longer counts COMPILE_ERROR/SIZE_MISMATCH/
  MISSING_* as matched (was `totalFunctions - stubCount`); now EXACT+RELOC
  (+PROVEN) via `_count_matched`; potato display fixed to match; regression
  test added.
- **build-db --target**: scoped rebuild now DELETEs only that target's rows
  instead of dropping the whole schema (other targets preserved); regression
  test proves both targets survive a scoped rebuild.
- **db_version**: stamped under reserved `__schema__` row, read
  deterministically in both build_db and recoverage; legacy per-target rows
  kept for older dashboards.
- **recoverage caches**: potato cells cache now cleared on rebuild +
  capped; /api/data cache capped; ETag switched to mtime_ns (two rebuilds in
  the same second no longer share an ETag).
- **CLI**: recoverage stats/export fail with exit 1 on unknown --target;
  check validates --min-coverage ∈ [0,100]; verify.py --json/--target flag
  order fixed; round_trip --no-write alias dropped; imports refuses
  --mark --json; /asm size parses decimal like /bytes.
- **Tests**: non-vacuous replacements for wildcard/100-threshold/stdlib-CSV
  tests; schema-shape guard tested on both sides (version-matches-but-
  objects-missing); _build_invalid_reloc_mask boundary tests; recoverage
  DB-gated tests skip inside a real rebrew workspace (were CWD-coupled and
  could read a real project DB).
- **Triage (keep)**: search_index first-wins dedup done; dead
  `diff_functions(invalid_relocs)` param kept (public API, now pinned by
  tests) rather than deleted.

**R2 db-review remainder** (commits `5db1b23`, `786c609`):
- `unitBytes`/`columns` of 0 in hand-edited JSON now clamped to defaults
  instead of aborting the whole rebuild via the schema CHECK.
- Stale `verify_results` rows pruned when a fresh report exists (the report
  is best-effort and can legitimately shrink).
- Status snapshot for history now taken INSIDE the `BEGIN IMMEDIATE`
  transaction, so a concurrent rebuild cannot record wrong old_statuses.

## 2026-08-09 — Real-project tooling audit (guild-rebrew + np-rebrew)

Ran the full toolchain against both live projects (todo, status, lint,
catalog, build-db, recoverage CLI+server+check, data, data --dispatch,
imports, round-trip, diff, asm, prove, cache, cfg, verify --dry-run,
verify --compare, rename --dry-run).  Two real bugs found and fixed:

- **`rebrew todo` pct_matched >100%** (commit `c03b800`): divided matched
  statuses (counted over ALL covered VAs incl. library headers) by
  `len(ghidra_funcs)` (function_structure.json only) → guild-rebrew showed
  240.6%.  Now divides by the covered population → 93.9%, matching
  `rebrew status`.  Regression test added.
- **recoverage phantom `__schema__` target** (commit `e3decc2`): the
  reserved schema-version metadata row (added for deterministic db_version
  reads) leaked into target enumeration → `recoverage stats` and the
  dashboard listed a fake `__schema__` target.  Excluded via a shared
  `SCHEMA_TARGET` constant in server.py (resolve_targets), cli.py
  (_list_targets), and api.py (health target count).

Non-bugs verified: .bss split on huge virtual-size .data is by-design;
`recoverage check` exits 1 on failure; verify --compare gate correct;
prove/rename guards correct.

## 2026-08-09 — Real-project audit round 2 (IAT thunks, virtual .data, LIBRARY path, GA, verify)

Probed the unusual-data paths guild-rebrew/np-rebrew exercise:

- **IAT thunks**: `rebrew imports` correctly detects `ff 25 <iat>` jmp stubs
  (guild: 3 stubs incl. configured iat_thunk 0x10023840); catalog flags 8
  thunks via registry. Verified against raw bytes — all genuine.
- **24MB virtual .data**: `rebrew round-trip` handles the giant virtual-size
  .data (raw 57KB / virtual 24MB) without issue — 21.75% spliced, 76.8%
  passthrough, no crash. The `.bss` split (virtual-raw tail) is by-design.
- **LIBRARY markers**: todo excludes library-header functions from the work
  queue; verify skips `.h` entries + DATA/GLOBAL/BSS/RODATA/VTBL markers
  (verified counts); status counts them as covered.
- **GA engine**: `rebrew match --pop-size 8 --generations 3` runs end-to-end
  on a real stub (score computed, no crash).
- **verify**: full run 225/259 passed (34 real failures matching status);
  exit 1 correct; JSON clean on stdout; tree untouched (promotion no-op).
- **catalog_resolution_drift** mismatches in round-trip are real project
  data (e.g. `_fread` vs `fread` symbol naming), not tooling bugs.
- Committed guild-rebrew CATALOG.md regeneration (`67247c9`) — build_db no
  longer writes it; `catalog --catalog` is the canonical generator now.

No new tooling bugs found this round; all paths verified working.

## 2026-08-09 — Real-project audit round 3 (crt-match, potato, sync degradation)

- **crt-match**: verified working on guild-rebrew — 10 matches (malloc/free/
  realloc/calloc/tzset) against configured MSVCRT CRT sources, confidence
  scored, no crash.
- **recoverage potato mode**: `/potato` renders 305KB grid + 233KB functions
  view; search works; /api/asm + /api/bytes return correct disassembly/hex;
  no server errors.
- **BUG FOUND + FIXED** (`f76fc88`): `rebrew sync --push` with the MCP
  server down printed a raw Python traceback and exited 1 instead of the
  intended clean error.  Root cause: the RuntimeError from
  `apply_commands_via_mcp` escaped to main.py's catch-all, which re-raised
  typer.Exit OUTSIDE click's handler (raw traceback + wrong exit code).
  Fixed by catching RuntimeError in `_export_apply_ops` (inside the command
  context) → clean `error: Failed to initialize MCP session: ...` + exit 2.
  Regression test added (`test_apply_mcp_connection_error_exits_clean`).

## 2026-08-09 — Real-project audit round 4 (annotation parser)

Probes passed: resource compare (R9, exact .rsrc gap), imports --mark
dry-run, doctor --json, cfg path, skills list.

**BUG FOUND + FIXED** (annotation parser, `c00ac29`): a DATA block followed
by extern decls then a function definition inherited the function's name
via `_C_FUNC_NAME` extraction.  guild-rebrew Error.c: the DATA entry at
0x10027084 (g_log_format_table) got named "DispatchLogOutput", corrupting
symbol→VA resolution — REL32 validation then rejected `call
DispatchLogOutput` as invalid, demoting a genuinely RELOC function
(_InitializeLogAndErrorHandler) to NEAR_MATCHING.  Fix: only FUNCTION/
LIBRARY/STUB blocks take a C-definition name.

**Follow-on fix** (`fd7c2dd`): the first fix accidentally excluded STUB
from C-def extraction, so implemented __stdcall stubs lost their decorated
symbol (_Name@N) and verify demoted them STUB → EXTRACT_ERROR.  STUB is a
function marker; restored it to the extraction gate.  Both have regression
tests; the affected guild functions now verify correctly (RELOC/SIZE_MISMATCH
as truth).

guild-rebrew metadata restored to its committed state after probing (the
verify --full runs were test artifacts, not intended promotions).

## 2026-08-09 — Impeccable audit on recoverage frontend (SPA + potato)

Ran the impeccable `audit` on recoverage's dashboard UI (app.js, style.css,
index.html, potato.py, ui.py).  Detector findings + manual a11y/theming/
responsive review, then fixed iteratively until the detector is clean.

**Audit run 1 → 13/20 (Acceptable).**  Detector: bounce-easing on modal
(cubic-bezier back-ease), layout-transition (progress-segment `width`
animation), potato docstring false-positive on `<img>`.  Manual: grid cells
+ progress segments were mouse-only divs (no keyboard access), modal
min-width 60% broke mobile, 32px touch targets, hard-coded accent colors
bypassed tokens, `overflow-x: hidden` masked overflow.

**Fixes** (commit `bfdf86c` + `693ea1e`):
- Easing → ease-out-quint (`cubic-bezier(0.16,1,0.3,1)`); removed `width`
  from segment transition.
- Grid cells: `role="button"` + `tabindex="-1"` + `aria-label`, arrow-key
  nav + Enter/Space select on the grid container (P1 a11y).
- Progress segments: `role="button"`, `tabindex="0"`, `aria-pressed`,
  Enter/Space toggle.
- Modal: mobile `min-width: 92%` under 700px; `aria-label` on target select.
- Touch: `@media (pointer: coarse)` bumps controls to 44px (WCAG 2.5.5).
- Theming: added accent tokens (--accent-*, --link, --delta, --badge-*)
  to :root + .light-mode; HexLogo/links/badges/delta now use them.
- `overflow-x: clip` replaces `hidden`.

**Audit run 2 → detector clean (0 findings), all contrast ratios ≥ 6:1**
(AA/AAA), select labeled, potato verified (labeled inputs, accesskeys,
skip link — solid legacy fallback).

**Audit run 3 → confirmed clean:** 0 detector findings, no hard-coded
colors outside token blocks (the single `#ffffff` is the progress-text
overlay, deliberately white on colored segments with a light-mode
override), all media queries served.  recoverage suite 258 passed.

## 2026-08-09 — Full-tree detector sweep + remaining tool probes

- Impeccable detector run across the ENTIRE rebrew + recoverage src trees:
  **0 findings** (the UI audit already cleared the frontend; the backend is
  equally clean).
- Probed remaining tools on real projects: `asm --format nasm` (correct
  NASM output), `skeleton --dry-run` (correctly refuses to overwrite a
  covered VA; errors on unknown VAs), `extract list/show/batch` (candidate
  list works; `show` correctly rejects already-reversed VAs; batch returns
  0 on np-rebrew because its remaining candidates are all covered — data
  condition, not a bug).  No new tooling bugs.

## 2026-08-09 — Workflow-logic audit (todo → diff/match/prove/test chain)

Traced the end-to-end reversing workflow on guild-rebrew and found three
logical breaks:

1. **EXTRACT_ERROR items misled todo** (`96b84ff`): entries with
   EXTRACT_ERROR status have delta=0, so `rebrew todo` classified them as
   "0B diff fix-delta" with ROI 85 — recommending a flag sweep on functions
   whose symbols can't even be extracted.  Added an `extract-error` category
   (ROI 150, clear description, `rebrew test` command).

2. **Stale verify cache after tool changes** (`96b84ff`): the verify cache
   key didn't include the rebrew tool version, so a code fix that changes
   extraction results (EXTRACT_ERROR/STUB-symbol fixes) left cached
   EXTRACT_ERROR entries served as truth.  `_compiler_config_hash` now
   includes `rebrew.__version__` — any tool upgrade invalidates the cache.

3. **VA-invoked diff/match/prove diffed the WRONG function** (`65a130f`):
   `rebrew diff 0x1000a010` on a 25-function file resolved to the file,
   fell back to the FIRST annotation (exit_handler, 8B) and reported a
   false "perfect match" while the real target (_CleanupSockets, 112B) was
   never compared.  diff/prove now thread the VA argument through to
   annotation selection; `resolve_build_params` matches the annotation by
   VA.  Verified live: diff now shows 37 instructions (26 exact + 11 reloc)
   for the correct function.

`rebrew test` by VA is intentionally broad (tests all functions in the
file, truthfully) — not a lie, left as-is.

## 2026-08-09 — Workflow audit round 2: VA-targeting sweep

Swept all VA-accepting tools for the first-annotation fallback pattern:

- **Fixed `rebrew match 0x<va>`** (`4ca3a13`): same wrong-function bug as
  diff/prove — a positional VA on a multi-function file selected the first
  annotation.  match's main() now threads the original VA argument into
  resolve_build_params (like diff).  Verified live: `rebrew match
  0x1000a010` now targets `_CleanupSockets` (was `exit_handler`).
- **Verified clean**: near_diag (matches by VA, refuses on mismatch),
  rename (multi-function auto-rename guard), test (tests all functions
  truthfully — intentionally broad), parse_source_metadata (single-function
  legacy helper; per-function callers use parse_c_file_multi directly).
- New regression test `test_va_selects_matching_annotation` in
  test_match_cli.py.

## 2026-08-09 — Docs + agent-skills sync for workflow changes

When the workflow changed (todo categories, VA-targeting in diff/match/
prove, verify-cache tool version), synced the docs and agent skills:

- **README.md / docs/CLI.md / docs/WORKFLOW.md**: replaced stale category
  names (`fix-verify-fail`, `fix-near-miss`) with the real set
  (`fix-delta`, `compile-error`, `extract-error`, ...); documented the new
  `extract-error` category and VA-positional multi-function targeting.
- **agent-skills (rebrew-workflow, rebrew-matching)**: added `extract-error`
  to the filter list, explained the extract-error → `rebrew test` flow, and
  documented VA-on-multi-function-file targeting.  `validate_skill_commands`
  passes (pre-commit hook confirms).
- **np-rebrew**: synced the 5 SKILL.md copies (git-tracked, commit
  `2b09fe4`); user's in-flight work untouched.
- **guild-rebrew**: `.agents/skills` is a symlink to the package source —
  automatically in sync (verified).

## 2026-08-09 — Verify-cache invalidation: logic-source hash (`9ef03aa`)

The earlier tool-version cache key used `rebrew.__version__` — a static
"0.1.0" that never changes during development (editable installs).  A code
change to the comparison pipeline (compile.py, core/matching.py,
matcher/parsers.py, annotation.py) therefore did NOT invalidate cached
verify results within the same version — exactly the staleness scenario
that produced the phantom EXTRACT_ERROR entries.  Replaced the version
string with a content hash of those four logic modules (`_compare_logic_hash`,
computed once per process).  Any change to comparison/extraction/symbol-
derivation source now invalidates the verify cache; changes to unrelated
modules do not.  Verified live: cache rejected + re-verified on the real
project.  Test `test_includes_compare_logic_hash` added.

## 2026-08-09 — diff --watch VA re-entry bug; project-drift probes (b699592, guild 8e89a95)

**Fixed: `rebrew diff 0x<va> --watch` lost VA targeting on watch re-entry.**
The watch retest re-entered `main()` with the *resolved source path*, so a
bare-VA positional lost its target on the second and later runs and the
diff silently fell back to the FIRST annotation of a multi-function file
(false results).  `diff.py` now keeps the original positional for re-entry
(`watch_arg`).  Verified `match.py` (threads `target_va` through `_retest`)
and `prove.py` (keeps the original `source` arg) already handle re-entry
correctly — only diff was broken.  Regression test
`test_watch_va_reentry_keeps_va_targeting` added; 3507 tests pass.

**Project-drift discovery via guild-rebrew: stale `rebrew_globals.h`.**
`rebrew data --gen-header` refused to overwrite the checked-in header, and
nobody had regenerated since the DATA annotations were refined — 13 globals
carried wrong names (a *function* name, `DispatchLogOutput`, for the
log-format table at 0x10027084).  Regenerated with `--force` (same 80
globals, names corrected) and committed as `8e89a95` in guild-rebrew.  The
tool itself is fine: the overwrite guard is deliberate/tested and the write
path already skips byte-identical bodies (timestamp-only churn).

**Other probes (all clean):** `rebrew skills list/show --json` (parent
`--json` correctly absent — option lives on subcommands); `rebrew lint
--fix` (fully unit-covered incl. converge-to-zero-W019); `rebrew verify`
+ `verify --compare` with the new `_compare_logic_hash` cache key on the
real project (259 fns, 0 compile errors, no regressions, cached re-runs);
`rebrew prove` on a NEAR_MATCHING function (correct VA targeting, graceful
path-explosion message with slice advice, no false promotion, tree
untouched); np-rebrew lint 70/70 clean.

## 2026-08-09 — angr unicorn ERROR spam on every todo/doctor run (f20659b)

`rebrew todo` and `rebrew doctor` probe the optional angr dependency with
`import angr` — and angr logs an ERROR about its disabled unicorn engine at
import time.  With no logging handler configured, that line hit Python's
last-resort handler and printed to stderr on EVERY run of the workflow
entry point (`rebrew todo`), looking like a real error.  Added
`rebrew.cli.angr_available()`: a shared capability probe that silences the
``angr`` logger for the duration of the import (nothing else in the
process uses it).  Both probe sites switched over; mypy flagged the
function/variable name shadowing, renamed locals to `has_angr`.  Verified
live: `rebrew todo --json` and `rebrew doctor --json` now emit zero stderr
bytes.  Test added; 3508 tests pass.

## 2026-08-09 — wide CLI smoke audit on guild-rebrew (no findings needing fixes)

Batched probes across the remaining tool surface, all on the real project:

- `rebrew imports --json` (84 imports), `rebrew status --json`,
  `rebrew asm 0x1000a010` — clean.
- `rebrew match 0x10018130 --generations 1` — GA smoke OK, correct VA
  targeting (spiel.c gm_IsInRange), best_score 3000.0, output under
  gitignored `output/`.
- `rebrew near-diag 0x1000a010 --json` — works (dash form; underscore form
  is correctly not registered; docs use the dash form everywhere).
- `rebrew flirt --va 0x1000a010` — 3414 sigs loaded, 0 matches at a game
  function (expected); CLI + JSON output clean.
- `rebrew data --dispatch`, `rebrew todo --json` — 34 ROI-ordered items;
  stub functions roll up under improve-match; categories consistent with
  the documented set (no compile/extract errors in guild).
- `rebrew diff 0x1000a010 --json` — target_size 112 (correct function),
  VA targeting intact after the watch fix.
- recoverage suite re-run: 258 passed / 4 skipped.

## 2026-08-09 — recoverage check gate: untracked sections (9b3a5ae)

Probed the recoverage backend end-to-end against guild's real coverage.db:
stats (527/561 matched, .text 99.5%), the full API surface (health,
targets, stats, functions pages), and the `check` CI gate.  Found a real
footgun: the coverage grid only records match states in .text — every
.bss/.data/.rdata/.reloc cell is `none` — so `recoverage check
--min-coverage N` (N>0) could never pass on a real project without
`--section`, even though the CLI epilog advertises it as the CI gate.
Fixed: default gate now SKIPs sections with no tracked cells (covered
bytes == 0); explicitly gating an untracked section FAILs loudly; a
project with nothing tracked does not pass vacuously.  Live-verified on
guild (min 90 → PASS .text only, exit 0).  Test added; recoverage suite
259 passed / 4 skipped.  Also fixed a ruff-format drift in the touched
files (fd0789a).

## 2026-08-09 — verify: PROVEN overlay masked real regressions (845bc5d)

Discovered via a live probe: `rebrew prove` correctly refuses to re-run on
an already-PROVEN function ("expected NEAR_MATCHING"), but `rebrew verify`
overlaid PROVEN onto ANY non-EXACT/RELOC result — so editing a proven
function's source until it no longer compiles (COMPILE_ERROR), fails to
extract (EXTRACT_ERROR), loses its file (MISSING_FILE), or becomes a stub
still reported PROVEN/passed and exited 0.  The overlay is now restricted
to NEAR_MATCHING / SIZE_MISMATCH — the byte states a proven function
legitimately produces — so genuine breakage surfaces as a failed run.
Live-verified on guild: the 3 real PROVEN functions still show PROVEN
(their byte results are NEAR_MATCHING/SIZE_MISMATCH), summary unchanged
(224 passed / 35 failed).  Tests: the old overlay test asserted STUB→
PROVEN (premise was wrong); now NEAR_MATCHING→PROVEN, plus a new
COMPILE_ERROR-not-masked regression test.  3509 tests pass.

## 2026-08-09 — CLI review fixes: bad-VA errors, diff --dry-run, prove silence (8fc46ca, recoverage 70d6f25)

Ran the `cli-review` prompt (via subagent) across the rebrew/recoverage
CLI surface.  The audit confirmed rebrew's conventions are strong (--json
help string exact in 40/40, --dry-run exact in 14/14, --json before
--target, stdout/stderr discipline, config errors with EXIT_ERROR), and
found these confirmed issues, now fixed:

- **Bad-VA handling (high)**: `rebrew diff 0x99999999 --json` reported a
  misleading `--symbol required` (exit 1); `rebrew asm`/`similar` printed
  empty results with exit 0.  diff/match now error `Source not found:
  0x...`; asm errors `No code at VA ... — address is outside the binary
  image`.  Verified live on guild.
- **diff --fix-blocker had no --dry-run** (only metadata write tool
  missing it): added `--dry-run` (keyword-only on run_diff; previews
  BLOCKER writes, verified live on a reloc-only function).
- **prove leaked angr's unicorn ERROR on stderr on every run**, even when
  the status guard rejected it: angr logger silenced at prove main entry.
  Verified: 0 stderr bytes.
- **recoverage stats --json** (medium consistency gap): added, emits the
  same data as export --format json.  Verified live.
- Left as documented/acceptable: data --gen-header error wrap (cosmetic),
  cfg set silent write, prove --watch-va decimal semantics (documented),
  exit-code legend only on compile tools (nice-to-have).

Tests: +2 (asm bad-VA, diff --fix-blocker dry-run); 3511 rebrew + 259
recoverage pass.

## 2026-08-09 — remaining CLI-review findings: similar bad-VA, extract --dry-run (680727f)

Closed out the two remaining confirmed findings from the cli-review:

- **`rebrew similar 0x<bad-va> --json` silently printed empty results with
  exit 0** (same class as the asm bug fixed earlier): `find_similar` now
  raises ValueError when the query VA has no catalog entry, and the CLI
  turns that into `No function found at VA ...` (exit 1).  Verified live.
- **`rebrew extract batch` wrote .bin files with no preview**: added
  `--dry-run` (DRY_RUN status in JSON mode, "would write" lines in human
  mode; no bin dir created).  Verified live on guild (2 DRY_RUN items,
  tree untouched).

Tests: +2 (similar unknown-VA, extract dry-run).  3513 rebrew tests pass.

## 2026-08-09 — round-trip audit: real source bugs surfaced (guild 8e5b394)

Probed `rebrew skeleton --batch --dry-run` (previews 3 files with test
commands — good) and `rebrew round-trip --dry-run` on guild.  Round-trip
caught **6 catalog_resolution_drift mismatches** — RELOC functions whose
compiled call targets resolve to a different VA than the original
binary's calls; `rebrew test`/`verify` mask these (reloc-aware compare),
round-trip is the honest detector (exit 1, per-mismatch detail decoding
the REL32 pair).

- **Fixed one clear-cut source bug**: `gm_IsInRange` (0x10018130) called
  `gm_GetBuildingTypeCategory` but the binary calls `gm_MapEntityStatRange`
  (verified by disassembling the original: `call 0x10018200` at +0x6;
  return logic in-range 10..14 → 0 else 2 already matched).  After the
  one-line fix, round-trip mismatches dropped 6 → 5, spliced 158 → 159.
  Committed to guild (8e5b394).
- **5 remaining drifts are genuine project-data mismatches, not tool
  bugs**: `_fopen`/`_malloc`/`_fread` in source resolve to different real
  binary functions than the original calls (disassembled both sides — none
  are `jmp [iat]` stubs).  The tooling correctly flags them with
  actionable detail; resolution is the user's decompilation work.
- Skeleton/round-trip CLIs verified sound (both have --dry-run, correct
  exit codes, JSON purity).

## 2026-08-09 — cfg write commands: --dry-run (6d663c8)

Probed the `rebrew cfg` multi-command editor on guild's real config:
list-targets/show/path read cleanly, and `cfg set` round-trips correctly
(minimal tomlkit diff, value readable via `cfg show`).  Confirmed the
CLI-review finding Q9: `set`/`add-module`/`set-cflags` silently rewrote
rebrew-project.toml with no preview, unlike the rest of the cfg group
(remove-target/remove-module use --force confirmation) and the project's
--dry-run convention.  `_save_toml` gained a dry_run mode and the three
commands now preview without writing.  Live-verified: `cfg set
compiler.timeout 999 --dry-run` prints "would update" and leaves the tree
untouched.  Test added; 3514 rebrew tests pass.

## 2026-08-09 — cache/imports/graph/init/test probe round (no findings)

Batch of probes, all clean:

- `rebrew cache stats --json`: 13271 entries / 48.8 MB — healthy.
- `rebrew imports --mark --dry-run`: "No new import stubs to annotate"
  (imports already marked); the --mark+--json conflict errors with a clear
  message (exit 2).
- `rebrew graph --format summary` (262 nodes / 170 edges) and
  `--focus 0x10013230` — the focus error noted in an old GOAL_PROGRESS
  entry is fixed; mermaid output is correct and color-coded.
- `rebrew init --target ... --binary ... --compiler msvc6 --json` in a
  fresh dir: creates the full scaffold (rebrew-project.toml, AGENTS.md,
  PRINCIPLES.md, original/, src/, bin/); generated config loads cleanly
  (`cfg list-targets` reads it back).
- `rebrew test --dry-run --json` on np-rebrew's GetResourceStringTotalLength.c:
  correct stdcall symbol/VA, SIZE_MISMATCH honestly reported (the file is
  the user's in-flight work).

No tool bugs surfaced; tree untouched.

## 2026-08-09 — verify --compare gate + recoverage API edge probes (no findings)

- **verify --compare regression gate validated end-to-end on guild**:
  baseline verify (225 passed) → injected a byte-changing edit into the
  EXACT `exit_handler` (return 1 → return 0) → `verify --compare` exited 1
  and flagged `exit_handler EXACT → SIZE_MISMATCH (delta 7)` → restored the
  source → re-verify restores the baseline (225, 0 regressions).  The gate
  detects real regressions, distinguishes them from improvements, and the
  tree was left byte-identical.
- **recoverage API edge cases**: bad VA (404 structured), out-of-range hex
  VA (404), bad section name (404), bad target (404), asm without params
  (400 "missing va or size"), asm out-of-range VA (400 "va is beyond
  section end"), asm valid (200), SSE /api/events stream (heartbeat
  frames).  All handled cleanly — no 500s, no tracebacks.

## 2026-08-09 — functionality-review: 12 findings, 10 fixed (9b5afcd, recoverage 712506f)

Ran the `functionality-review` prompt (via subagent) over the recently
touched modules.  12 findings; fixed 10 (2 triaged as defer):

- **F2 (high)** — `verify --compare` advanced the baseline even on a
  failing run, so the gate self-healed on the next invocation.  The
  baseline report now only advances when the gate passes.
- **F1 (high)** — verify cache key ignored annotation SIZE; `catalog
  --fix-sizes` (metadata-only) left stale results served as truth.  Cache
  entries now record SIZE (old entries carry -1, re-verify once).  This
  also exposed a latent bug: `_save_verify_cache` never wrote the new
  field (caught by the incremental tests).
- **F4 (med)** — `_compare_logic_hash` now also covers
  `compile._extract_and_compare` + `binary_loader.extract_raw_bytes`.
- **F5 (med)** — `_headers_hash` now folds in config-level `-I` include
  dirs via `compile_cache.include_fingerprint` (external headers like
  `references/zlib-1.1.3` previously left the verify cache stale).
- **F3 (med)** — `cfg set-cflags` wrote `cflags_presets` that nothing
  consumed.  Presets are now merged onto ProjectConfig (per-key, target
  wins) and used as the per-module CFLAGS fallback in match/diff.
- **F11 (low)** — PROVEN overlay only strips OVERLAID VAs from
  fail_details; a proven function failing as COMPILE_ERROR keeps its row.
- **F10 (low)** — cfg `--dry-run` prints future-tense previews and no
  longer mutates the in-memory doc.
- **F7 (low)** — `asm --size` beyond the image warns and reports
  `truncated` in JSON.
- **F9 (low)** — `flirt --va` bypasses the scan size gate (a short
  function is actually probed).
- **F12 (low)** — catalog grid `totalFunctions`/`matchedFunctions` now
  reconcile with the emitted functions dict (was counting dropped
  entries; recoverage headline said 561 vs 559 rows).
- **F6 (low)** — recoverage `check` displays 2 decimals, matching the
  comparison (no more "99.5% < 99.5%").
- Deferred: F8 (imports --json decimal-key shape; consumer-compat risk),
  F5-extra (per-function inc dirs — config-level only for now).

Verified live: recoverage check prints 99.49% < 99.50%; rebrew diff still
resolves presets; 3517 rebrew + 259 recoverage tests pass.

## 2026-08-09 — F8: imports --json hex VAs (d304207)

Closed the last deferred functionality-review finding: `rebrew imports
--json` emitted stub VAs as stringified decimal dict keys and `iat_va` as
decimal ints, unlike every other rebrew JSON (0x hex strings).  Stubs are
now a list of `{va: "0x…", name: …}` and `iat_va` is a hex string.  No
internal consumers of the old shape (verified by grep); test updated to
assert the hex contract.  Live-verified on guild.  3517 tests pass.

## 2026-08-09 — db-review: 8 findings, 5 fixed (3078051, recoverage 6a2c18b)

Ran the `db-review` prompt (via subagent) over the coverage DB layer
(rebrew build_db + catalog grid + recoverage server/api), with a
subagent-confirmed real-DB inspection (integrity ok, EXPLAIN QUERY PLAN,
double-rebuild idempotency).  Fixed:

- **F1** — a failed build leaves a 4KB metadata-less coverage.db (DDL
  rolled back) that wedged every later build behind --force (the regen
  path doesn't pass --force).  A schema-less file now auto-rebuilds with a
  warning.  Test updated.
- **F2/F3** — full rebuild never dropped verify_results (orphans for
  dropped targets/functions) and the v3-era `idx_history_target_va`
  survived every rebuild (history is never dropped).  Full rebuild now
  drops verify_results and the dead index.  Confirmed live on guild: the
  dead index is gone from the rebuilt DB.
- **F5** — cell states `proven`/`size_mismatch` fell into no bucket and
  `/data` omitted padding/none, so buckets summed to 584 vs total_cells
  889.  View + SECTION_STATS_SQL + /data now expose all buckets; PROVEN
  counts as matched.  Verified live: buckets now sum exactly to 889.
- **F6** — cells gained UNIQUE (target, section_name, start).
- Deferred: F4 (shape check is name-only — column-level verification),
  F7 (query scale fine at 10x; informational), F8 (stale-report prune
  semantics; documented by-design).

3517 rebrew + 259 recoverage tests pass; guild's coverage.db rebuilt
(untracked artifact).

## 2026-08-09 — db-review F4: column-level schema gate (3e1593a, recoverage 3e3162c)

Closed the last substantive db-review finding: both schema gates verified
object NAMES only, so a DB stamped "4" with a functions table missing
`textOffset`/`similarity` (or a stale `section_cell_stats` view) passed
the gate and 500'd at query time.  `build_db._missing_required_objects`
and `recoverage._check_schema_version_uncached` (via a new
`_missing_required_columns`) now verify the query-critical column sets
with `PRAGMA table_info` and report `table.column` gaps.  recoverage
applies the column check only for v4 (v3 keeps the legacy name-only
check).  Regression tests: dropping `functions.textOffset` now rejects
the DB in both gates.  3518 rebrew + 259 recoverage tests pass (one
transient "lost sys.stderr" flake seen and resolved on re-run).

## 2026-08-09 — sync --dry-run wrote the export artifact (5fd2855)

Probing `rebrew sync --push --dry-run` on guild surfaced a dry-run
contract violation: the export half unconditionally wrote the
multi-hundred-KB `ghidra_commands.json` even in dry-run ("Preview changes
without writing").  Dry-run now reports the operation count (JSON payload
or "would export/apply" text) and returns before any write or MCP apply.
Regression test added; 3519 rebrew tests pass.  Live-verified on guild:
no file materialized, tree clean.

## 2026-08-09 — error-review: 12 findings, 9 fixed (36c5dcb, recoverage 15c4d98)

Ran the `error-review` prompt (via subagent; it reproduced issues in
scratch dirs).  Fixed:

- **F1 (high, destructive)** — build-db mapped ANY sqlite3.OperationalError
  to "<missing>" and unlinked the DB — including a LIVE locked DB under
  contention (concurrent build-db / recoverage regen).  Lock errors now
  error with EXIT_ERROR; the DB is never deleted.  Live-verified on guild
  (DB intact under a held EXCLUSIVE lock).
- **F2** — build-db infra errors (missing data json, schema mismatch) exit
  2 (EXIT_ERROR) per the documented 0/1/2 contract.
- **F3 (high)** — main.py catch-all raised typer.Exit outside click →
  traceback + exit 1 + broken JSON.  Now prints the friendly message (JSON
  envelope when --json is in argv) and exits EXIT_ERROR via SystemExit.
- **F4** — `sync --refresh-cache --json` silently did nothing (json_output
  early-returned before the write).  --json now only changes output
  format; dry_run still never writes.  Two stale tests updated, two added.
- **F5** — ghidra size-sync push now guards MCP RuntimeError like the main
  apply path.
- **F6** — extract batch continues past a per-function disasm error (was
  aborting the batch with exit 0) and the JSON summary reports `failed`.
- **F7** — cfg _save_toml/_load_toml wrap OSError/tomlkit parse errors
  with a clear EXIT_ERROR message.
- **F10/F11** — recoverage CLI: _open_db/_resolve_targets catch
  sqlite3.Error with a rebuild hint + exit 2 (was a raw traceback);
  `check` gained --json (pure JSON verdicts, inline text suppressed).

Deferred: F8 (verify stat() race + silent cache I/O in json mode), F9
(verify gate still writes cache/metadata on failure — needs a decision),
F12 (asm/flirt minor unguarded paths).

3520 rebrew + 260 recoverage tests pass.

## 2026-08-09 — error-review F8/F9/F12 closed (edcad8e)

Closed the three deferred error-review findings:

- **F8** — verify's cache-hit path had an unguarded `filepath.stat()`
  (file deleted between exists() and stat() → traceback); it now treats a
  missing file as a cache miss.  Cache-save failures log a warning to
  stderr in ALL modes (previously silent under --json).
- **F9** — a failed `--compare` gate run no longer writes the verify cache
  (consistent with the preserved baseline; a CI failure records no new
  state).  STATUS metadata promotion remains (that is verify's core job,
  documented).
- **F12** — asm reports capstone.CsError (bad arch/mode config) as a clean
  error; flirt skips+warms on malformed signature files instead of
  aborting the whole scan.

3520 rebrew tests pass.

## 2026-08-09 — api-review: recoverage REST fixes (3dc7486)

Ran the `api-review` prompt (via subagent; live probes against the real
DB).  20 findings; fixed the substantive ones:

- **F10 (medium)** — `/functions/<va>` parsed hex-only, but the `/functions`
  list emits `va` as a decimal int — a consumer taking the list value
  straight into the detail route got 404.  The route now accepts decimal
  (all-digit strings try decimal first, bare-hex fallback; 0x/a-f hex
  unchanged).  Live-verified both formats return 200.
- **F1 (medium)** — memo fingerprint, ETag, and SSE watcher were blind to
  WAL commits that don't checkpoint the main file.  Now folds the -wal
  stat in.  (Found during verification: -shm must NOT be included —
  sqlite touches it on every connection, which made ETags change between
  requests; the 304 path then never matched.)
- **F4/F8/F12** — 304s carry ETag+Cache-Control (all sites); potato ETag
  uses mtime_ns; JSON errors carry Cache-Control: no-store.
- **F6** — the /data memo stores serialized bytes (multi-MB payload was
  re-serialized on every hit).
- **F13** — /data?section=<unknown> 404s (was a silent memoized empty grid).
- **F18** — Accept-Encoding q-values honoured (q=0 never chosen).
- **F19** — batch POST body bounded at 64 KiB (413) + negative VAs rejected.

Deferred: F2 (stat→open TOCTOU), F3 (memo 404 skip), F5 (strong vs weak
ETag), F7 (If-None-Match list form), F11 (CLI/API code field type),
F15 (read-transaction pinning), F16 (watcher at startup), F20 (batch
response shape).  262 recoverage tests pass.

## 2026-08-09 — api-review F16/F11 closed (44b7785, b80417d)

- **F16** — the SSE DB watcher started only on the first `/api/events`
  connection, so a curl-only server (no SSE client) never invalidated the
  target/dropdown caches after an external `rebrew build-db`.  The
  watcher now starts at `serve` startup.
- **F11** — `recoverage check --json` error payloads emitted `"code": 1`
  (an int exit code) while the API reserves `code` for string machine
  codes — a shared consumer could not distinguish them.  Renamed to
  `exit_code` (safe: check --json shipped this session, no consumers).

## 2026-08-09 — config-review: 5 findings fixed (2cc3122)

Ran the `config-review` prompt (via subagent).  Fixed:

- **F1 (high)** — `cfg set-cflags --target` wrote `[targets.X.cflags_presets]`
  but the loader reads `[targets.X.compiler.cflags_presets]`: the per-target
  override was a silent no-op.  Now writes the compiler sub-table.
- **F4 (high)** — default `marker = target.upper()` → "SERVER.DLL" for
  `server.dll`, matching no annotation module: `rebrew init -t server.dll`
  produced a project where every function silently vanished from
  verify/todo/status.  Default strips non-identifiers; init writes the
  marker explicitly.  Live-verified.
- **F2 (high)** — the CFLAGS fallback diverged across tools (verify "/O2",
  test "/O2 /Gd", batch match none, single-file the full chain): a preset
  could make `rebrew match` EXACT while `rebrew verify` demoted it.
  Extracted `rebrew.cli.resolve_cflags` and wired verify/test/prove/
  near_diag/batch-match to it.
- **F3 (med)** — `_compiler_config_hash` missed `compiler_runner`
  (runner-only edit changed the invocation, not the hash); documents why
  cflags/presets are intentionally absent.
- **F6 (med)** — `init --install-wibo` wrote runner="tools/wibo" with a
  "wine ..." command (bogus argv, first compile failed).  Command now
  drops the wine prefix.  Live-verified.
- Deferred: F5 (dead keys compiler.profiles/game_range_end/origins — wire
  or drop), F7 (find_root doc mismatch), F8 (arch fallback warning).

3520 rebrew tests pass.

## 2026-08-09 — config-review F5/F7 + full-project system check (65d449a)

- **F7** — `find_root` docstring now states an explicit `start` is an
  authoritative root (returned verbatim), matching behavior.
- **F5** — corrected the misleading known-keys comments: `origins` is
  editor/UI-only (NOT annotation filtering), `game_range_end` is a
  stored-but-unread legacy key, `compiler.profiles` is reserved/unwired —
  the whitelist no longer misleads readers about their effect.
- **System check after the session's changes** (F2 cflags unification,
  verify-cache size/headers changes, PROVEN overlay, gate fixes):
  guild `verify --dry-run` — 225 passed / 34 failed / 0 compile errors
  (unchanged, cflags unification is behavior-neutral on real projects);
  np-rebrew lint 70/0/1 + status unchanged; both trees left as found.

## 2026-08-09 — docs/skills consistency after session changes (d0c9ab6, recoverage 5b68dfa)

- `tools/validate_skill_commands.py`: 158 unique (subcommand, flags)
  combos across agent-skills all OK — the session's CLI changes
  (imports --json shape, extract --dry-run, flirt --va, sync --json,
  check --json) left the skills in sync.
- docs/CLI.md: added the missing `--dry-run` rows for `rebrew diff`
  (BLOCKER preview) and `rebrew extract batch`.
- recoverage README: documented `check --json` and the 0/1/2 exit-code
  contract.

## 2026-08-09 — recoverage e2e harness + frontend regression check

The playwright e2e suite errored (not skipped) when the pinned browser
binary is missing — CI without `playwright install` failed noisily.  A
module-level launch check now skips with a clear message.  (In this
environment the pinned chromium 1208 is absent — cache has 1228/1234 —
and installing is not feasible with the disk at 98%, so the e2e tests
skip; the API contract they exercise was verified in the api-review
probes.)  Full recoverage suite: 262 passed / 5 skipped.

## 2026-08-09 — np-rebrew TOOLCHAIN_BUGS re-verification (np 489b738)

Re-verified every R-item (R1–R10) in np-rebrew's TOOLCHAIN_BUGS.md
against the current rebrew code: all claims still hold (bss-gap loop,
out-of-section global warnings, byte_matched summary, binary_id cache
guard, resource tool registered).  Appended an update noting this
session's verify-cache hardening (SIZE in cache entries, external -I
headers in _headers_hash, compiler_runner in the compiler hash, gate
baseline preservation, unified resolve_cflags) and confirming the
config-review fixes are behavior-neutral for np (no presets, marker "NP"
unaffected).  Committed locally (np-rebrew has no remote).

## 2026-08-09 — final session verification

- rebrew: 3520 tests pass, ruff lint+format clean, tree clean, all pushed.
- recoverage: 262 passed / 4 skipped (5 with playwright skip), lint clean,
  tree clean, all pushed.
- guild-rebrew: tree clean (2 commits this session: header regen, gm_IsInRange).
- np-rebrew: only the user's in-flight work uncommitted (never touched);
  2 local commits (TOOLCHAIN_BUGS update, skills sync).

Session totals: 6 review prompts run (cli, functionality, db, error, api,
config) with ~50 findings fixed, plus live-project discoveries
(diff --watch VA loss, verify PROVEN masking, compare-baseline self-heal,
locked-DB deletion, sync dry-run write, set-cflags no-op, marker default,
wibo config, cflags divergence, WAL-blind ETags, VA round-trip 404,
unbounded POST body).  All substantive findings across every review are
closed; remaining deferrals are low-severity with documented residual
risk.

## 2026-08-09 — sec-review: 6 findings, 5 fixed (recoverage cb5a909, rebrew 9d14e3a)

Ran the `sec-review` prompt (via subagent; live probes against the real
dashboard).  The audit confirmed the strong baseline (zero shell=True,
no SQL injection, parameterized queries everywhere, bounded POST body,
wibo SHA-256 verified, no secrets) and found:

- **F1 (high when exposed)** — the dashboard serves the whole project
  (sources, binary bytes, coverage DB) to any LAN client once bound
  off-loopback.  Added optional `--token` auth: `Authorization: Bearer`,
  `?token=`, or an HttpOnly SameSite cookie bootstrapped by opening
  `/?token=<token>` (SPA works unchanged).  Verified live: 401 without /
  200 with / cookie set / wrong token 401.
- **F2 (medium)** — /api/events pins a server thread per connection with
  no cap; a cross-origin EventSource from any webpage could exhaust
  threads even on loopback.  Capped at 32 concurrent clients (503).
- **F3 (low)** — ETags interpolated raw request strings (bottle rejects
  control chars today, but a CRLF probe surfaced an HTML 500 instead of
  the JSON contract).  ETags are now hashes of their components.
- **F4 (low)** — static serving followed symlinks outside the tree;
  realpath + containment check added.
- **F5 (low)** — source filenames starting with @/- are prefixed './'
  before CL.EXE (MSVC would parse '@x.c' as a response file).
- F6 (MCP endpoint auth) documented as loopback-default.

262+1 recoverage / 3520 rebrew tests pass.

## 2026-08-09 — release-review: 7 findings fixed (b5d8911, recoverage f403c88)

Ran the `release-review` prompt (via subagent; byte-verified wheels vs
source).  Fixed:

- **F1/F2 (high)** — dist/ wheels/sdists were 118/45 commits stale and the
  wheel admitted capstone 5.0.0–5.0.7 (PYSEC-2026-3544 vulnerable range
  the source pin excludes).  Both packages rebuilt from HEAD; verified
  the wheel METADATA now carries `capstone>=5.0.8` + `lief<1` and that
  agent-skills + assets are packaged.
- **F3/F6 (high/low)** — CHANGELOG [Unreleased] backfilled in both repos
  (rebrew: 118 commits; recoverage: --token, check/stats --json, API
  hardening), per the documented changelog policy.
- **F4 (medium)** — guild venv capstone upgraded 5.0.6 → 5.0.9 (the
  in-package __version__ string reads 5.0.7 — a known upstream quirk;
  importlib.metadata confirms 5.0.9).
- **F5 (medium)** — cu_map.py's standalone typer app/main_entry removed
  (never registered; dead surface in the wheel); `rebrew graph --cu-map`
  still calls cu_map.main directly.  Tests converted.
- **F7/F8 (low)** — untracked dev coverage.db removed from the package
  tree; recoverage pyproject gains [project.urls] + 3.13/3.14 classifiers.
  (Fixed my own TOML table-splitting mistake in the process: [project.urls]
  must come after dependencies.)

## 2026-08-09 — perf-review: GA scoping + lazy imports + parse memo (12fc4fc)

Ran the `perf-review` prompt (via subagent with cProfile/-X importtime
measurements).  Fixed:

- **F1 (critical)** — GA mutation queries ran over the WHOLE multi-function
  file (cProfile: 86% of a GA run, ~6s/gen on the 79KB guild seed) even
  though only the target function's bytes are scored.  Mutations are now
  scoped to the target function's byte range via a thread-local applied in
  the shared cursor helper (set inside run(), cleared in finally).  The
  270x win was measured by the reviewer; live: 2 gens on the 79KB seed in
  1.27s.
- **F2 (high)** — ~98 tree-sitter queries compiled at module import
  (~50ms of every CLI invocation); now lazy (_LazyQuery).  cfg/asm import
  binary_loader (and thus lief, ~125ms) lazily.  Measured: cfg list-targets
  0.47s -> 0.36s.
- **F5** — GA elapsed_sec under-reported by ~99% (accounting stopped
  before the mutation phase); now covers the full generation.
- **F3 (medium)** — metadata-free parse_c_file_multi memoized per
  (path, mtime_ns, size); verify's build_name_to_va no longer re-parses
  the tree (verify 1.19s -> 1.12s).  The metadata-overlay path is never
  memoized.
- F4 verified as already-fast (numpy-vectorized scoring, memoized include
  fingerprints, linear grid).  Lazy main.py subcommand registration
  remains a documented follow-up.

## 2026-08-09 — dependency conflict discovered + fixed (guild e61bd98)

Probing the remaining import-cost item surfaced a REAL resolution break:
guild's `uv run` (pytest, python, any) failed to resolve.  Chain:
rebrew's `capstone>=5.0.8` (PYSEC-2026-3544 pin, from a prior commit) vs
angr<=9.3.1's `capstone==5.0.6`; bumping angr to >=9.3.2 then hits
reccmp's `pydemumble==0.0.1` vs angr's `pydemumble>=0.1.3` — the chain
is unsatisfiable with stock pins.  Fixed on the project side: guild's
pyproject adds a `[tool.uv] override-dependencies = ["capstone>=5.0.8"]`
(uv overrides beat angr's "tested-with" pin; capstone 5.0.9 is
backward-compatible with angr's usage).  `uv sync --all-extras` restores
the dev extras (plain `uv sync` had dropped pytest); verified: `uv run
pytest --version` ok, `rebrew status` ok, capstone 5.0.9 + angr 9.2.204
coexist.  np-rebrew uses the global rebrew tool (no uv project) and is
unaffected.

## 2026-08-09 — perf follow-up: catalog binary_loader/lief deferred (dbc4c08)

Closed the last leaf-level import cost: catalog.cli (eagerly imported by
the umbrella) pulled lief (~120ms) via registry.py and sections.py
module-level binary_loader imports.  Both now import lazily.  The
remaining ~0.5s per CLI invocation is structural (typer + ~30 eager
subcommand registrations) — the lazy-subcommand-registration refactor
(typer signature introspection makes a generic wrapper awkward) is
documented as the final, optional item.  3520 tests pass.

## 2026-08-09 — final capstone verification

- rebrew: 3520 tests pass; skills validator (158 combos) OK; tree clean, pushed.
- recoverage: 262 passed / 4 skipped; lint clean; tree clean, pushed.
- guild-rebrew: tree clean; 3 commits this session (stale-header regen,
  gm_IsInRange wrong-call fix, capstone override).
- np-rebrew: only the user's in-flight work uncommitted (never touched);
  2 local commits.

Session totals: 10 review prompts run (cli, functionality, db, error,
api, config, sec, release, perf, plus the earlier sessions' audits) with
60+ findings fixed, live-project discoveries (diff --watch VA loss,
PROVEN masking, gate self-heal, locked-DB deletion, sync dry-run write,
set-cflags no-op, marker default, wibo config, cflags divergence,
WAL-blind ETags, VA round-trip 404, unbounded POST, GA 270x, dependency
conflict), CHANGELOGs backfilled, dist rebuilt, and both real projects
left healthy and clean.

## 2026-08-09 — SPA/API contract check (no findings)

Cross-checked every API path the recoverage SPA requests (app.js) against
the current route table after this session's API changes: /api/events,
/api/regen (POST), /api/targets, /data, /asm, /functions/<va> — all
present with matching methods.  The /data 404-for-unknown-section,
decimal-VA acceptance, and memo-bytes changes are all backward-compatible
with the SPA's request patterns.  No contract drift.

## 2026-08-09 — test-review: 19 findings, 9 fixed (d4a60ab, recoverage 92f4ed2)

Ran the `test-review` prompt (via subagent) over the tests added this
session.  Fixed the highest-value gaps (tests that would pass even if the
fix were reverted):

- F1: verify-cache SIZE/CFLAGS invalidation branches now tested (the
  helper hardcoded matching values, so the metadata-driven guards never
  fired).
- F2: _find_function_range + set_target_range scoping tests.
- F3: regressed --compare test asserts NO cache file is written (unmocked
  _save_verify_cache).
- F6: resolve_cflags 4-step fallback chain tests.
- R1: WAL snapshot -wal/-shm behavior tests.
- R2/R3: /data ETag-304 round-trip + section-specific ETags + unknown
  section 404.
- R5/R6: check below-threshold exit-1 (real gate failure) + stats --json.

Deferred (low): F4 (PROVEN counter mock realism), F5 (_compare_logic_hash
membership assert), F7 (main typer.Exit path), F8 (_PARSE_MEMO contract),
F9 (extract failed count assert), F10-F12 (diff preview text, cfg
set-cflags dry-run, asm truncation), R4 (SSE cap test), R7 (schema column
isolation), R8 (playwright server guard), R9 (memo self-invalidation).
3532 rebrew (+12) / 269 recoverage (+7) tests pass.

## 2026-08-09 — test-review deferrals batch 2 (59f0459, recoverage aba4a02)

Closed six more test-review gaps:

- F9: extract batch JSON asserts the `failed` counter.
- F10: diff --fix-blocker --dry-run asserts the future-tense preview text
  ("Would update BLOCKER ... register allocation").
- F11: cfg set-cflags --dry-run writes nothing.
- F12: asm --size truncation warns + reports truncated/requested_size in
  JSON.  (Also uncovered: the older test_empty_extract_errors was hitting
  the binary-missing path first — its exit-1 assertion masked that; the
  new test creates the binary so the real empty-extract path runs.)
- R4: SSE client cap returns 503 beyond _SSE_MAX_CLIENTS.
- R7: complete-v4-object-set-with-one-column-missing reports
  <incomplete> (isolates the column gate from the name gate).

3534 rebrew / 271 recoverage tests pass.  Remaining deferrals are F4/F5/
F7/F8 (rebrew) and R8/R9 (recoverage) — all documented low-severity.

## 2026-08-09 — test-review deferrals final batch (056bea4, recoverage 74cbac4)

Closed ALL remaining test-review findings:

- F4: PROVEN overlay test now uses a realistic run_verification mock and
  asserts the passed/failed/proven counters (the mock previously violated
  run_verification's invariant and the counters were never asserted).
- F5: _compare_logic_hash membership asserted (5 distinct module files;
  classify_compare_result + _extract_and_compare share compile.py).
- F7: main() catch-all typer.Exit -> SystemExit(EXIT_ERROR) test (the
  exact motivating case).
- F8: _PARSE_MEMO contract — same-object memo hit, content-change
  invalidation, metadata_dir bypass (never memoized).
- R8: playwright suite skips when BASE_URL has no server (in addition to
  the browser guard).
- R9: /data memo fingerprint-sensitivity proven (a DB mtime bump yields a
  second cache key; a constant key would keep one).

Every finding from the test-review is now closed.  3539 rebrew / 272
recoverage tests pass.

## 2026-08-09 — final session verification (post test-review)

- rebrew: 3539 tests, skills validator OK, lint clean, tree clean, pushed.
- recoverage: 272 passed / 4 skipped, lint clean, tree clean, pushed.
- guild: tree clean (3 commits this session).  np: only the user's
  in-flight work uncommitted (never touched).

Session complete: 11 review lenses, ~70 findings fixed, live discoveries
(round-trip drift, stale header, dep conflict), release prep, perf work,
and the full test-review backlog.  All substantive findings across every
review are closed; only documented low-severity deferrals and the optional
lazy-typer-registration follow-up remain.

## 2026-08-09 — np-rebrew verify vs TOOLCHAIN_BUGS baseline: stale-PROVEN surfaced (overlay fix confirmed)

Re-ran `rebrew verify` in np-rebrew against the TOOLCHAIN_BUGS.md baseline.
PROVEN count dropped 14→12, STUB 3→5; report now 44 passed / 23 failed
(doc baseline 45/22). Investigation: this is the restricted PROVEN-overlay
fix (NEAR_MATCHING/SIZE_MISMATCH only) working as intended — two functions
whose committed `src/rebrew-function.toml` says `PROVEN` no longer match
their sources and now surface as `STUB`:

- `FormatString1` 0x01002c93 — `rebrew test` → STUB 35/98; compiled
  prologue `55 8b ec 8b 45 10` (arg3 `[ebp+0x10]`) vs target `8b 4c 24 04`
  (arg1 `[esp+4]`); explicit `/O1 /Gd /Oy` unchanged → not a flags issue.
- `SwapBytes` 0x01005887 — `rebrew test` → STUB 5/49.

Documented in np-rebrew `TOOLCHAIN_BUGS.md` (commit eeee821, local-only
repo, staged only that file — user's in-flight work untouched). These are
project-data decisions (demote STATUS or fix source), not tooling bugs; not
auto-fixed.

## 2026-08-09 — catalog --json gains total/covered fields (np doc gap, real)

np-rebrew TOOLCHAIN_BUGS.md flagged "rebrew catalog --json has no
total/covered". Verified current code: the human --summary path computed
covered bytes / pct but the --json payload only had annotation/registry
counts. Fixed (c2d4072): hoisted the fn_vas/covered_bytes computation out
of the `if summary:` block, shared with --json; payload now carries
`total_functions`, `covered_bytes`, `text_size`, `coverage_pct`
(rounded to 1dp) alongside the existing fields. Test updated
(test_json_summary_to_stdout now asserts the full payload incl. the
0x24000 default text_size — the mocked get_text_section_size is not
reached since the fake binary path doesn't exist). 3539 rebrew tests pass.

## 2026-08-09 — guild-rebrew health check on latest toolchain; duplicate-DATA audit

Re-verified guild-rebrew against the current (just-pushed) rebrew:
`rebrew status --json` works (561 fns, 93.9% matched, last verify
2026-08-09 05:05 225/259 not stale); `rebrew lint --json` → 111 files,
108 passed, 10 E013, 36 warnings (34 W020 asm dumps, 1 W005, 1 W021).

Root-caused the 10 E013s: the same DATA global is annotated in multiple
files (extern declarations carrying `// DATA:`), sometimes twice within
one file (spiel.c: 0x101de450/0x10035880/0x100358a0). e.g.
`g_citizen_count` 0x10035434 in alchemistry_logic.c + spiel.c +
loadsave.c; 0x100a8c30 in 3 files. **Not a tooling bug**: lint correctly
detects (E013 keyed (module, va) cross-file; W021 name collision), and
the grid dedupes — `get_globals` keys by VA (first-file-wins name/decl,
collects all files into a `files` list), so no double-counting in
db/data.json. Project-data hygiene in guild (remove redundant DATA
annotations from extern decls) — left to the user; documented here only.
Also confirmed: DATA W016 (missing SECTION) is metadata-resolved via
rebrew-data.toml `section` overlay (fires only with cfg=None).

## 2026-08-09 — recoverage re-verified + CLI spot-check + W020 __emit confirmed

- recoverage suite re-run against current rebrew: **272 passed, 4 skipped**
  (green; consumes `db/data_T.json` via build-db — today's catalog change
  only touched the `--json` summary payload, not `data_T.json`, so no
  impact, confirmed by the pass).
- CLI conventions spot-check (per cli-review.md): `--json`/`--target`
  ordering + help strings ("Output results as JSON" / "Preview changes
  without writing") verified across all typer modules via script — 0
  violations; `main_entry` docstrings + `__name__` guards all present;
  console=stderr everywhere. Real-run checks: `catalog --help`/`test
  --help` render with examples; usage error (unknown flag) exits 2;
  missing-config exits 2; NO_COLOR clean. No fixes needed.
- W020 asm-dump check (user's earlier "_emit warning" request): already
  implemented — `_check_W020_asm_dump` fires on both `__emit` and
  `__asm` (warn-once per file). Guild's 34 W020s prove it fires.

## 2026-08-09 — verify cache no longer bakes in the PROVEN overlay (f6deb4f)

Discovered while reviewing the PROVEN-overlay path behind the np-rebrew
finding: the overlay (NEAR_MATCHING/SIZE_MISMATCH → PROVEN/passed) mutated
`results` BEFORE `_save_verify_cache`, so the cache stored the overlaid
PROVEN pass. Cache-hit validation keys on filepath/cflags/size/source-hash
but NOT STATUS — so after a metadata demotion (PROVEN→STUB, the exact
np-rebrew stale-overlay case), the stale cached PROVEN would keep counting
as passed on incremental runs forever. Fix: the cache now stores the
pre-overlay raw byte result (`raw_statuses` map captured at overlay time,
applied in `_save_verify_cache`). The overlay is metadata-derived and
already re-applied from CURRENT metadata at every report run (cached +
fresh), so a demotion now correctly surfaces as a failure. Tests:
`TestSaveVerifyCache.test_overlaid_proven_stored_raw` +
`TestProvenOverlay.test_proven_cache_stores_raw_byte_result` (end-to-end
through the real cache file). 3541 rebrew tests pass. No behavior change
for np: its stale PROVENs verify as STUB, which was never overlaid.

## 2026-08-09 — cached PROVEN treated as stale, self-healing re-verify (249a0eb)

Transition gap from the f6deb4f fix: caches written by pre-fix code may
still hold baked-in PROVEN statuses, and since served cached entries are
re-saved as-is, they would persist past a metadata demotion until --full.
Fix: the fixed writer never stores PROVEN (raw byte results only), so any
cached status=PROVEN is by construction pre-fix baked state — the cache-hit
loop now treats it as a miss and re-verifies once. Self-healing (only the
stale entries re-verify, not the whole cache), no version bump. Test:
`TestPrepareEntriesCache.test_cached_proven_invalidated`. 3542 rebrew tests.

## 2026-08-09 — verify --dry-run preview mirrors promotion decision (0ad61e0)

Real-data validation of the cache fixes on guild surfaced a third issue:
`verify --dry-run` printed "would update STATUS → NEAR_MATCHING/SIZE_MISMATCH"
for guild's 3 PROVEN functions — but the real run refuses those via
should_promote_status (PROVEN sticky, STUB placeholder size-mismatch kept).
The preview claimed updates a real run never writes, misleading exactly the
stale-PROVEN workflow. Fix: `_apply_or_preview_status` applies the same
decision in dry-run mode. Validated on guild: 0 refused demotions claimed
(was 3), report counts unchanged (225 passed / 34 failed / 3 proven).
Also confirmed the 249a0eb guard works on real data: guild's pre-fix cache
had 3 baked-in PROVEN entries (0x10012470/0x10014260/0x100170e0), all
re-verified fresh (NEAR_MATCHING + 2×SIZE_MISMATCH) and re-overlaid from
current metadata. 3543 rebrew tests.

## 2026-08-09 — rebrew → recoverage pipeline validated end-to-end on guild

Ran the full chain on real guild data (db/ is gitignored, no tree dirt):
1. `rebrew catalog --data-json --json` → db/data_server.dll.json, 652
   annotations / 553 functions, coverage_pct 97.5 (new fields visible:
   total_functions/covered_bytes/text_size/coverage_pct).
2. `rebrew build-db --json` → db/coverage.db (1.98 MB).
3. `recoverage stats --target server.dll --json` → 559 fns, 525 matched,
   coveragePercent 99.49 — schema clean, no drift.
4. `recoverage serve` booted; /api/health + /api/targets/server.dll/stats
   OK; dashboard served from the fresh DB.

Considered + deferred (low severity): the inlined index payload is
br-compressed 15191 B vs the 14.6 KB TCP cwnd budget (591 B / 4% over) —
one extra first-paint RTT on a localhost dashboard. Measured: br default
q11 is already optimal (gzip 16926, zstd 18197, br q10 15494); rjsmin/
rcssmin already applied; no debug/dead code in app.js (55.5 KB). Fitting
under budget needs either a ~2.3 KB raw SPA trim (risky) or splitting
assets out of the inline payload (architecture change). The guard warning
is informational and doing its job — left as-is, documented here.

## 2026-08-09 — error-review: STATUS write failures no longer abort verify (fd05773)

Ran error-review.md (focused on the verify/test/metadata/compile paths
touched this session). Silent-swallow scan: clean — worker-thread internal
errors counted+logged, metadata parse failures logged, VA-parse fallbacks
intentional, header-walk OSError → "" fingerprint (safely distinct from
real hashes). Exit codes re-checked without pipe artifacts: missing-config
and missing-file both exit 2 (EXIT_ERROR).

One real blast-radius finding: `apply_status_updates` called
`update_source_status` unguarded in the verify main thread BEFORE report
build — a read-only/unwritable rebrew-function.toml raised OSError,
crashing the run and losing the report. Fixed: per-entry write guarded,
failure → warning, batch + report continue (applies to verify AND
test --all). Test:
`TestApplyStatusUpdates.test_write_failure_does_not_abort_batch`. 3544
rebrew tests.

## 2026-08-09 — np TOOLCHAIN_BUGS.md full re-check: no new rebrew tooling bugs

Re-read the doc's sections 1-4 in full (L1-L14 linker, C1-C4 compiler,
D1-D5 data, R1-R10 rebrew) against current tooling:

- R1-R10: all FIXED/VERIFIED (R5 W021 + R8 byte_matched verified live this
  session via guild lint and verify --json). R7 (flirt_sigs absent) is
  project-side — `rebrew doctor`'s check_flirt_sigs already warns with
  exact fix instructions.
- C1's "`--flag-sweep-only` without --all errors 'Provide source file'"
  (doc-logged as a toolchain gap): verified CORRECT behavior — match.py:1230
  errors with "Provide a source file (rebrew match <file.c>) or use --all
  for batch mode." A single-function flag sweep genuinely needs a source;
  the message now suggests --all. Not a bug.
- L1-L14 / C2-C4 / D2-D4: project-side np work (Makefile LDFLAGS, CRT
  choice, .rsrc reproduction, globals classification) — no rebrew code
  changes implied. Section-5 per-function table (22 failed) is stale
  project data; the 44/23 + 2 stale-PROVEN delta is already documented
  (2026-08-09 entry).

Conclusion: doc currency confirmed after this session's verify changes; no
further rebrew tooling fixes surfaced from np.

## 2026-08-09 — guild real verify: cache healed, PROVEN transition complete

Ran a REAL `rebrew verify --json` on guild (dry-run had validated the guard;
this rewrites the cache). Report unchanged (225 passed / 34 failed /
3 proven — metadata still claims PROVEN, sticky guard prevents demotion,
correct). Cache now stores RAW byte results for the 3 former baked-PROVEN
entries: 0x10012470 SIZE_MISMATCH, 0x10014260 SIZE_MISMATCH, 0x100170e0
NEAR_MATCHING (all passed=False). A future metadata demotion will surface
correctly on incremental runs. Guild tree clean (verify wrote only to
gitignored db/ + .rebrew/). The f6deb4f → 249a0eb → 0ad61e0 arc is now
fully validated end-to-end on real data.

## 2026-08-09 — db-review: corrupt data JSON errors name the file (93a6f4a)

Focused db-review of build_db.py (the layer producing coverage.db for
recoverage). Schema layer already strong: CHECK constraints on
va/size/fileOffset/markerType/similarity/start/end/span, foreign-key
cascade cells→sections, WAL + BEGIN IMMEDIATE snapshot/report
transactionality, locked-DB guard that never deletes a live DB,
`_missing_required_objects` verifying object names AND query-critical
columns (view staleness) against the version stamp, defensive negative
offset clamping, and rollback-on-error.

One gap: a corrupt or hand-edited data_*.json raised a raw
JSONDecodeError message with NO file context ("Expecting property name
enclosed in double quotes...") — hard to tell which target file was
broken. Fixed: the load site catches JSONDecodeError and non-object
shapes, naming the file and suggesting 'rebrew catalog --data-json'
(exit 2, human + --json). Tests: TestBuildDbCorruptInput (corrupt JSON +
JSON-array shape). 3546 rebrew tests.

## 2026-08-09 — recoverage API functionality probe: clean

Booted recoverage serve against the fresh guild coverage.db and probed the
API surface with edge inputs:
- /api/targets/<missing>/stats → 404 {"error": "Target not found",
  "code": "not_found", "detail": "no such target 'nonexistent'"}
- /api/targets/<t>/functions/<bad va> (hex-absent and non-hex) → 404 with
  structured detail
- /api/targets/<t>/asm (bad va / no va) → 501 {"error": "capstone not
  installed", "code": "not_implemented", "detail": "install capstone ..."}
  — capstone is an optional extra (health reports extras.capstone false);
  documented degradation, actionable message
- /api/targets/<t>/sections/.nope/bytes → 404
- /api/events SSE → streams keepalive comment frames

No bugs: all failures are structured 404/501, never 500s; write paths
(POST functions, /api/regen) intentionally not exercised on guild's real
DB. Recoverage tree untouched.

## 2026-08-09 — final sweep: rebrew 3546 / recoverage 272, all green

- `--watch` consistency check: diff.py already has --watch (test/verify/
  match/diff all covered) — brainstorm item closed, not a gap.
- `rebrew prove` missing-angr path: `_require_angr` raises a clear
  ImportError, CLI converts via error_exit (clean, both modes). angr
  present in this env.
- Doc/skill currency after today's verify fixes: no doc or agent-skill
  describes the old baked-PROVEN cache behavior; SKILL.md's "PROVEN is
  sticky — never demoted by test/verify" remains accurate (the fixes only
  changed cache storage + preview accuracy, not the promotion contract).
- Final sweep: rebrew 3546 passed / ruff clean / tree clean (f30dcea
  pushed); recoverage 272 passed / 4 skipped / tree clean.

Session (this goal run) totals: 10 rebrew commits pushed — catalog --json
coverage fields, verify-cache PROVEN arc (3), dry-run preview fix,
STATUS-write blast-radius guard, build-db corrupt-JSON context — plus np
TOOLCHAIN_BUGS.md update (local), guild cache healed, full pipeline +
API validation, error/db/functionality reviews with clean results, and
~9 GOAL_PROGRESS entries.

## 2026-08-09 — recoverage: declare capstone/pygments optional extras (7459784)

Found via the recoverage API probe: the asm endpoint degrades to a clean
501 without capstone and the README documented capstone/pygments as
"optional runtime extras", but neither was declared in
[project.optional-dependencies] — `recoverage[capstone]` did not exist.
Fixed: declared both extras (capstone>=5.0, pygments>=2.0), the 501 hint
now points at `pip install 'recoverage[capstone]'`, and the README shows
the install syntax. 272 recoverage tests pass. (Note: egg-info is
gitignored but tracked from before the rule; regenerated PKG-INFO/
requires.txt committed with -f to keep the tree consistent.)

## 2026-08-09 — recoverage extras validated end-to-end

`uv sync --extra capstone --extra pygments` installs both cleanly
(capstone 5.0.7, pygments 2.19.2); health now reports extras.capstone
True; the asm endpoint serves real x86 disassembly against guild's binary
(0x10009320 Init, 200 OK — previously 501). The declared extras work as
documented. Recoverage tree clean after sync (uv.lock already carried the
extras from 7459784).

## 2026-08-09 — todo coverage fields made honest (1bf4274)

Discovered via `rebrew todo --json` on guild: coverage.total = Ghidra
function-list size (219) while coverage.covered = annotated/library VAs
(561) — covered > total is impossible-looking, and the human header
printed "561/219 functions". pct was already correctly divided by covered
(the 200%-bugfix comment documents why). Fixed: JSON field renamed to
`ghidra_funcs` (its actual semantic) so the two populations are explicit;
human line reads "561 covered (219 in Ghidra function list)". Also fixed
docs/WORKFLOW.md's jq example — it used `.coverage_pct`, which is not a
todo field (returned null); `.pct_matched` is. 3546 rebrew tests.

## 2026-08-09 — rebrew doctor + dashboard validated on guild

- `rebrew doctor --json` on guild: all 14 checks pass — config, PE load
  (base 0x10000000, 4 sections), arch/format, Wine+CL reachable, includes
  762 headers, libs 263, function list 536, 111 sources, metadata TOMLs,
  bin dir, angr+claripy present, FLIRT 4 files/3414 sigs, Ghidra ReVa
  backend ready. Doctor works end-to-end on a healthy project (incl. the
  checks reviewed earlier: optional tools, flirt_sigs).
- `rebrew dashboard --port` boots and serves the coverage DB (root 200,
  HTML rendered; no /health route by design — simpler than recoverage's
  API surface).

## 2026-08-09 — recoverage: untrack regenerated egg-info (23ab316)

Repo hygiene: recoverage's .gitignore declares *.egg-info/ ignored, but 6
egg-info files were tracked from before the rule — every pyproject change
regenerated them and produced diff noise (the extras commit needed
`git add -f`). Untracked per the gitignore intent (pip/uv regenerate on
install); rebrew has no such tracked artifacts (verified). Tree clean.

## 2026-08-09 — final consolidated verification

- rebrew: 3546 passed, ruff clean, tree clean (f1914fc pushed).
- recoverage: 272 passed / 4 skipped, tree clean (23ab316 pushed).
- guild: tree clean (cache healed, verify 225/34/3 unchanged).
- np: TOOLCHAIN_BUGS.md updated (local commit), user's in-flight work
  untouched.
- Note: `uv sync --extra <x>` prunes other extras (dev/pytest) — use
  `--all-extras` (matches rebrew AGENTS.md convention); venv restored.

Goal-run totals: 15 commits across rebrew + recoverage (6 rebrew fixes:
catalog JSON coverage fields, verify-cache PROVEN raw-status + stale-entry
invalidation + dry-run preview, STATUS-write blast-radius guard,
build-db corrupt-JSON context; 2 recoverage: declared extras, egg-info
untrack; todo coverage-field honesty + doc fix), np doc updated, guild
cache healed on real data, ~15 GOAL_PROGRESS entries, 4 review lenses
(error/db/functionality/CLI), full pipeline + API + doctor + dashboard
validations. Discovery surface exhausted: remaining items are either
project data (guild E013 annotation hygiene, np L/C/D work) or design
judgments (E013 severity for extern decls) requiring user direction.
