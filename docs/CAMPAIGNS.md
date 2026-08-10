# Matching Campaigns

Record of systematic `rebrew match` runs across the corpus.  A campaign is a
bounded, repeatable batch: same flags, same seed, recorded before/after
counts.  Each entry links the tools that made it possible and any toolchain
blockers found.

## How to run a campaign

```bash
# One project, bounded batch, resume-aware, cross-project solutions seeding:
rebrew match --all --max-stubs 20 --generations 50 --pop-size 32 --jobs 4 \
    --seed-solutions ../<best-solved-project>/.rebrew/solutions.json --resume --json
```

Measure progress with `rebrew status --json` (matched_pct) and
`rebrew solutions --best --json` before/after.  The corpus-wide health gate
is `python tools/corpus_sweep.py --root ../ --rebrew <path>` (doctor, analyze,
identify-library, status, lint — documented SKIPPED/BLOCKED projects honored).

## Campaign 2026-08-10 — smygb (bounded smoke)

**Goal:** exercise the new matching pipeline end-to-end on a real project:
skeleton → single-function GA → bounded batch with `--resume`.

| Step | Command | Result |
|------|---------|--------|
| Intake state | `rebrew status --json` | 144 sources, 20 actionable items (16 improve-match, 3 start-function, 1 fix-delta) |
| Library pass | `rebrew identify-library --build-sigs` | 262 sig files generated; **28 library entries** written across 6 module headers (msvcrt, kernel32, ddraw, dinput, comdlg32, ctlfwr32); idempotent re-run writes 0 |
| Lint gate | `rebrew lint` | **144 passed, 0 errors** after the E015 marker-consistency fix (was 144 errors: E015 fired on the documented FUNCTION-marker + STUB-status convention) |
| Single function | `rebrew skeleton 0x00407480` → `rebrew match --generations 5 --pop-size 8` | Pipeline runs end-to-end under wine (best_score 65024, not yet a match — skeleton seed) |
| Bounded batch | `rebrew match --all --max-stubs 2 --resume --json` | see result JSON (matched/failed) |

**Toolchain blockers found:** none — the project's MSVC600 toolchain is
reachable (doctor all-pass); the matching ceiling is seed quality (skeleton
bodies need real decompilation before the GA can converge).

**Toolchain fixes this campaign:**
- E015 lint rule: FUNCTION marker + STUB status is the documented convention
  (status lives in rebrew-function.toml); E015 now only fires on library-
  module marker mismatches.  Fixes lint errors on every freshly-intaked
  corpus project (smygb: 144 errors → 0).
- `tools/corpus_sweep.py` now includes `lint --json` so this class of
  annotation drift is caught project-wide.

## Campaign 2026-08-10 — smygb vtable wrappers (matching sprint)

**Goal:** byte-match smygb's tiny "start-function" candidates from raw
disassembly (no decompiler backend available on the box).

**Finding (MSVC6 `if (g_flag)` codegen):** the same idiom compiles to ≥3
byte-different forms:
`cmp dword ptr [mem],0; je` (plain), `mov eax,[mem]; test eax,eax; je`
(pointer-typed/volatile load), and `xor ecx,ecx; cmp [mem],ecx; je`
(register-compare).  `volatile` loads materialize the value but do not
reliably pick the `mov/test` form.  These wrappers (vtable dispatch through
`0x4158a0`/`0x45d914`) are a genuine NEAR_MATCHING family — the GA's
`mut_toggle_volatile` / register-pressure mutators are the right lever.

**Tooling added:**
- `rebrew skeleton --decomp-body` — writes the decompiled C as the function
  BODY (renamed to the marker's function) instead of a comment block, so a
  decompiler-backed run starts the GA from real logic (K2; 4 tests).

## Campaign 2026-08-10 — smygb NEAR_MATCHING profile (register-only gap)

near-diag over the improve-match set found 0x401370 is a **register-only**
NEAR_MATCHING: 100% mnemonic match, 23 exact + 21 register + 7 structural.
80-120 GA generations (unseeded and extra-seeded) did not converge — the
mutator set lacked an operator producing the target's kept-live-pointer
scheme.  Added `mut_hoist_repeated_deref` (hoist repeated absolute derefs
into a local); the manual equivalent (obj-kept-live variant) cut the test
delta 13 → 6 bytes.  0x40e070 is the CRT `strrchr` inline (`repne scasb`
string instructions) — not reachable from a portable C loop; documented as a
CRT blocker (loop attempt 1/39 by test metric, wrong family).

## Next campaigns

1. **smygb full** — skeleton all 3 `start-function` candidates from Ghidra
   decompilation, then `--all --seed-solutions ../makehm-rebrew/... --resume`.
2. **nbench / makehm** — cross-project cflags transfer via `--seed-solutions`;
   measure matched_pct delta.
3. **bind (VC5)** — `--sweep-toolchain` per function to confirm the VC5 line.
