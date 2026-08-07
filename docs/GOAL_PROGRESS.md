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
