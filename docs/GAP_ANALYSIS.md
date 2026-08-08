# Gap / Missing-Feature Analysis

Fresh analysis (2026-08-07) for the autonomous improvement goal. Sources:
`docs/IDEAS.md` open backlog, a CLI-surface audit (commands vs. entry points vs.
agent-skill docs), and code inspection. Each gap lists scope, effort estimate,
and recommendation. Statuses: **IMPLEMENT** (well-scoped, existing deps),
**RECORD** (not viable under the goal's constraints — recorded with reason),
**DONE** (implemented by this goal).

---

## From `docs/IDEAS.md` open backlog

### #20 — `rebrew test --watch` (test watch mode)

- **Scope:** Add `--watch` to `rebrew test` that re-runs compile+compare on file
  save. No new dependency needed: a poll loop on file mtime/size (1s interval)
  over the target `.c` file(s) is sufficient; `watchdog` would be nicer but is
  out of scope (no new deps).
- **Effort:** Medium (0.5–1 day). CLI flag + poll loop + reuse of the existing
  test/compare path + tests with a synthetic file-change.
- **Recommendation:** **IMPLEMENT.** Clean QoL win, no external service, fits
  the existing `test.py` structure.

### #21 — Binary similarity search

- **Scope:** New command (e.g. `rebrew similar VA`) that disassembles a known
  function and ranks other functions in the binary by structural similarity
  (opcode histogram / basic-block shape / control-flow signature). Capstone and
  numpy are already dependencies (`matcher/scoring.py` does byte-level scoring;
  `asm.py`/`binary_loader.py` provide disasm + byte extraction).
- **Effort:** Medium–large (1–2 days). Needs a similarity metric + ranking +
  output formatting (table + `--json`).
- **Recommendation:** **IMPLEMENT.** Directly serves "which STUB to tackle
  next", complements `rebrew todo`.

### #22 — Deep NEAR_MATCHING analysis tooling

- **Scope:** A specialized diff tool that classifies *which* compiler choice
  (register allocation, loop rotation, instruction folding) blocks a
  NEAR_MATCHING function.
- **Effort:** Large (2–4 days); requires designing a classification taxonomy
  and mapping assembly patterns to compiler decisions.
- **Recommendation:** **RECORD.** Speculative; the taxonomy itself is a design
  project. Not well-scoped for this goal; could be a future PRD.

### #23 — LLM-assisted GA seed generation

- **Scope:** Optional LLM call in `rebrew match` that suggests C permutations
  from the NEAR_MATCHING asm diff.
- **Effort:** Medium, but requires an LLM API integration (external service,
  likely a new dependency or API-key plumbing).
- **Recommendation:** **RECORD.** Violates "no new dependency / no external
  service". Revisit if the user wants API-key support.

### #24 — Ghidra-CLI alternative transport

- **Scope:** Second sync backend over the external `ghidra-cli` tool
  (`cfg.ghidra_backend = "reva" | "cli"`), keeping the push/pull command set.
- **Effort:** Large; depends on an external third-party binary not present in
  the repo.
- **Recommendation:** **RECORD.** Requires an external tool the project does
  not ship; cannot be built or tested here.

### #25 — `rebrew prove` memory side effects (watched VAs)

- **Status:** Sub-part 1 (EDX:EAX pair check) is **already implemented and
  tested** (this audit, 2026-08-07): `prove_equivalence(check_edx=...)`
  (`prove.py:547`), auto-enabled for 64-bit return types (`prove.py:600`),
  `--check-edx` CLI flag, tests `test_identical_blobs_check_edx_proven` /
  `test_64bit_prototype_auto_enables_edx`. The IDEAS.md note predates this.
- **Remaining:** Sub-part 2 — **watched-VA memory comparison**. `prove.py:841`
  carries `TODO(E9 v2): also compare selected memory writes. Today we only
  check ...`. Plan: thread a small watched-VA list through
  `prove_equivalence` and compare `state.memory.load(va, 4)` across the
  orig/comp state pairs for each watched address (user-supplied via
  `prove_constraints` metadata or a `--watch-va` flag; keep the list small to
  avoid Z3 blowup).
- **Effort:** Medium (1–2 days).
- **Recommendation:** **IMPLEMENT** (sub-part 2 only).

---

## Fresh findings (this audit)

### F1 — Silent failure + false success in prototype pull (`ghidra/commands.py:990`)

- **Scope:** In the signature-pull loop, `except OSError: pass` swallows
  extern-replacement write failures, yet the code still prints
  `[green]Updated prototype[/green]` and increments the counter — the user is
  told the prototype was updated when the source-file rewrite silently failed.
- **Effort:** Small (30 min). Replace `pass` with a stderr warning naming the
  file and error; keep the metadata-update success message but make the extern
  failure visible.
- **Recommendation:** **FIX.** "A visible error is always better than a silent
  failure"; this is misleading behavior, not just cosmetic.

### F2 — CLI surface audit

- Commands in agent skills vs. registered commands vs. `pyproject` entry
  points: all present (verified `main.py` registration list; skill command
  validation already wired into pre-commit via `tools/validate_skill_commands.py`).
- `--json` support: present on every CLI module including `rebrew sync`
  (`ghidra/cli.py:181`).
- **Recommendation:** No gaps found. Documented here as an audited-clean area.

### F3 — Verify header-hash, MCP endpoint, PRINCIPLES dedup

- All three May gap-report blockers were re-verified fixed in the working tree
  (see `docs/GOAL_PROGRESS.md` 2026-08-07 baseline section). No action.

---

## Execution order (cheapest first)

1. **F1** — silent-failure fix in `ghidra/commands.py` (small, high value).
2. **#25 part 1** — EDX:EAX proof goal in `prove.py`.
3. **#20** — `rebrew test --watch`.
4. **#25 part 2** — watched-VA memory comparison (behind a flag).
5. **#21** — binary similarity search.

RECORD-only: #22, #23, #24 (reasons above).

---

## Status update — 2026-08-07 (8-hour autonomous run)

All IMPLEMENT items are now **DONE** (verified in this run):

- **F1** (sync silent-failure) — fixed; 147 sync tests.
- **#20** `test --watch` — done; also added **`verify --watch`** (multi-file
  poller in `rebrew.utils.watch_files`).
- **#25.1** — verified already-implemented; **#25.2** watched-VA memory
  comparison — done, verified against real claripy/Z3.
- **#21** `rebrew similar` — done. **#22** `rebrew near-diag` — v1 done
  (register/equivalent/reloc/structural classification).
- RECORD-only items unchanged: #23 (LLM service), #24 (external ghidra-cli),
  binsync-full (libbs dep, ~7-day PRD scope).

Plus (from the 8-hour run): mypy debt 186→0 (all 73 modules clean, gate wired
into CI + pre-commit), coverage 79%→82% overall with 25 modules taken to
85-100%, 6 real bugs found & fixed, 8 review passes, ~130 tests added.
