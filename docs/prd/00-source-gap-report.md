# Source-Side Gap Report

Generated: 2026-05-20

This report captures gaps where the source/CLI surface diverges from the PRDs
in this directory, OR where the existing user-facing docs / agent skills make a
claim the code does not back. The PRDs themselves were tuned to reality first;
the items below are work items for the code/docs side.

Severities:

- **blocker** — actively misleads users or causes wrong behaviour.
- **enhancement** — feature gap or rough edge; PRD already flags as a goal.
- **nit** — cosmetic / documentation only; safe to ignore short-term.

Shipped: The round-trip command implementation shipped in commits
`fd84782..4260a6c` (May 2026). PRD 05 now covers round-trip user surface,
workflows, and limitations.

---

## Feature: 01 — Project Onboarding

### Gap: PRD claims `cfg add-target` auto-detects format/arch from binary, but the binary may not exist at add time

- **Gap:** `rebrew cfg add-target NAME --binary FILE` calls `_detect_format_and_arch`
  on the binary path. If the binary isn't placed yet (likely on fresh projects), the
  detector silently falls back to defaults and the stanza is wrong-but-quiet.
- **Evidence:** `src/rebrew/cfg.py:162` `_detect_format_and_arch`, `src/rebrew/cfg.py:302` `add_target`.
- **Severity:** enhancement
- **Suggested fix (high level):** Warn loudly (or refuse without `--force`) when the
  binary file doesn't exist at the configured `original/` path, so users don't end up
  with a silently mis-formatted target stanza.

### Gap: PRD describes `rebrew doctor --install-wibo`, code accepts the flag but does not document scope clearly

- **Gap:** `rebrew doctor --install-wibo` downloads `tools/wibo` if missing. Help text
  doesn't make clear whether running it on a working project replaces the binary.
- **Evidence:** `uv run rebrew doctor --help` (see /tmp/rebrew_help.txt), `src/rebrew/wibo.py`.
- **Severity:** nit
- **Suggested fix:** Help text could clarify that `--install-wibo` only acts if
  `tools/wibo` is missing or executable bit unset (idempotent).

### Gap: Multi-target compiler override is undocumented

- **Gap:** PRD 01 notes that multi-target projects share one compiler profile and
  per-target overrides require manual TOML editing. The CLI does not have a
  `cfg set targets.<name>.compiler` short-hand; users must use dotted-key set.
- **Evidence:** `src/rebrew/cfg.py:450` `set_value` handles arbitrary dotted keys
  generically, but the `--help` text only shows scalar examples; no shortcut.
- **Severity:** enhancement
- **Suggested fix:** Add a worked example to `rebrew cfg set --help` for
  per-target compiler overrides, or a dedicated `cfg set-compiler TARGET PROFILE`
  helper.

---

## Feature: 02 — Function Catalog

### Gap: `rebrew extract show` lacks a `--size` override, despite skeletons / asm needing one

- **Gap:** `rebrew extract show VA` only accepts `--min-size`/`--max-size` as filters
  (not overrides). `rebrew asm VA --size N` and `rebrew skeleton VA --name` accept
  a `--size`, so the inconsistency surprises users.
- **Evidence:** `uv run rebrew extract show --help` (no `--size`),
  `src/rebrew/extract.py:335` `show_candidate`.
- **Severity:** enhancement
- **Suggested fix:** Add `--size N` to `extract show` so it can extract a single
  function with a known size override.

### Gap: `rebrew flirt` lacks a documented `--sig-dir` flag

- **Gap:** Help text says "Requires .sig/.pat signature files in the project or passed
  via `--sig-dir`," but the actual option is the positional `[SIG_DIR]` argument.
- **Evidence:** `uv run rebrew flirt --help` shows `SIG_DIR` as positional; epilog
  references non-existent `--sig-dir`.
- **Severity:** nit
- **Suggested fix:** Update the help epilog to refer to the positional argument, or
  add `--sig-dir` as an alias.

### Gap: `rebrew build-db` schema is not auto-migrated

- **Gap:** PRD acknowledges this. Schema version is stamped in metadata, but on
  mismatch the tool errors instead of recreating; users may not know to delete the file.
- **Evidence:** `src/rebrew/build_db.py` (schema version handling).
- **Severity:** enhancement
- **Suggested fix:** When the version mismatches, prompt to drop+recreate the DB or
  auto-recreate when `--force` is passed.

### Gap: `rebrew catalog --csv` output path is implicit

- **Gap:** Help text says `--csv` "Generate reccmp-compatible CSV" but doesn't tell
  users where it lands. Code writes next to data JSON (`db/`).
- **Evidence:** `src/rebrew/catalog/cli.py` `--csv` handling.
- **Severity:** nit
- **Suggested fix:** Help line should mention the output path.

---

## Feature: 03 — Skeleton & Iteration

### Gap: `rebrew skeleton --endpoint` default disagrees with the Ghidra-sync skill default

- **Gap:** `rebrew skeleton` defaults `--endpoint` to `http://localhost:8080/mcp/message`,
  but the `rebrew-ghidra-sync` skill documents `http://localhost:8089` as the default
  ReVa endpoint.
- **Evidence:** `src/rebrew/skeleton.py:723` (8080), `src/rebrew/agent-skills/rebrew-ghidra-sync/SKILL.md:23` (8089).
- **Severity:** blocker
- **Suggested fix:** Pick one canonical default (the codebase uses 8080/mcp/message),
  update the skill text, and consider centralising the constant in
  `rebrew.config` or `rebrew.ghidra.client`.

### Gap: `rebrew diff` exits with code 1 on a structural diff, masking true build failures in CI scripts

- **Gap:** `rebrew diff` exit codes are documented as 0 (no diff), 1 (structural
  diff), 2 (build failure). Many scripts treat non-zero as "compile broken"; the
  shared meaning of "1" for structural diff and "1" elsewhere (NEAR_MATCHING in
  `rebrew test`) can confuse pipelines.
- **Evidence:** `src/rebrew/diff.py` and `src/rebrew/test.py` epilogs.
- **Severity:** nit
- **Suggested fix:** Document the alignment between exit codes across `test` and
  `diff` in one place (e.g. `docs/CLI.md`).

### Gap: `rebrew lint --fix --dry-run` interaction not enforced in help text

- **Gap:** PRD says "`--fix --dry-run` is safe to suggest to humans." Help text
  describes `--fix` and `--dry-run` separately but doesn't show their combination.
- **Evidence:** `uv run rebrew lint --help`.
- **Severity:** nit
- **Suggested fix:** Add an example showing `--fix --dry-run` as the safe preview
  combination.

### Gap: `rebrew rename` does not document its safety semantics for macros / strings

- **Gap:** PRD documents the limitation. CLI help text doesn't.
- **Evidence:** `uv run rebrew rename --help` epilog only mentions FUNCTION markers,
  definitions, externs.
- **Severity:** nit
- **Suggested fix:** Add a one-line note that macro/string references are not
  rewritten, and recommend a follow-up `grep` for safety.

### Gap: `rebrew test --no-promote` auto-skip condition is undocumented

- **Gap:** PRD captures the behaviour: promotion auto-skipped for files outside the
  project. The CLI help also mentions it briefly, but users running on symlinked
  paths may be confused why STATUS didn't update.
- **Evidence:** `src/rebrew/test.py` (auto-skip logic).
- **Severity:** nit
- **Suggested fix:** Log a one-line message when STATUS is auto-skipped so the user
  isn't left guessing.

---

## Feature: 04 — Byte-Matching Engine

### Gap: `rebrew prove` only verifies EAX equivalence

- **Gap:** PRD acknowledges this. Functions returning a struct/longlong (EDX:EAX) or
  with relevant memory side effects may be incorrectly promoted to PROVEN.
- **Evidence:** `src/rebrew/prove.py` (EAX-only proof goal), and PRD 04 open
  questions section.
- **Severity:** enhancement
- **Suggested fix:** Extend proof goals to cover EDX:EAX pairs and selected memory
  locations referenced by the function, behind a flag.

### Gap: `rebrew match --no-seed` and `--extra-seed` interact silently

- **Gap:** Passing both `--no-seed` and `--extra-seed PATH` is accepted but their
  precedence isn't documented; current behaviour is `--no-seed` wins.
- **Evidence:** `src/rebrew/match.py` (typer option declarations).
- **Severity:** nit
- **Suggested fix:** Either error when both are supplied, or document that
  `--extra-seed` overrides `--no-seed`.

### Gap: Flag-sweep tier descriptions are CLI-only

- **Gap:** `quick|targeted|normal|thorough|full` tiers exist (`matcher/flag_data.py:74`)
  but the meaning of each tier and the time/flag-count tradeoff is not surfaced.
- **Evidence:** `src/rebrew/matcher/flag_data.py:74` sweep tiers; help text only
  lists the tier names.
- **Severity:** enhancement
- **Suggested fix:** Document tier sizes / runtime expectations either in
  `docs/CLI.md` or a new `docs/FLAG_SWEEP_TIERS.md`.

---

## Feature: 05 — Verification & Progress

### Gap: `rebrew verify` does not detect shared-header changes

- **Gap:** PRD explicitly lists this limitation. Users must run `rebrew verify --full`
  after any header edit; otherwise stale cache hits hide regressions.
- **Evidence:** `src/rebrew/verify.py` cache lookup uses the per-file cache key
  derived from compile flags + source bytes; headers are not in the key.
- **Severity:** blocker
- **Suggested fix:** Either hash the include-line fingerprint into the cache key, or
  invalidate the entire compile cache when any `.h` file under `reversed_dir`
  changes. Cheap option: add a watch/dependency file timestamp check on first run.

### Gap: `rebrew status` reads source files at runtime; no warning when annotations are stale relative to metadata

- **Gap:** Status reports STATUS from `rebrew-function.toml`, but if a user has
  inline STATUS markers (legacy), they will not match the displayed value.
- **Evidence:** `src/rebrew/status.py` and `src/rebrew/lint.py` W019 warning for
  inline metadata.
- **Severity:** enhancement
- **Suggested fix:** When `rebrew status` is invoked, run a quick lint
  (W019) and print a hint if inline metadata is present anywhere in the project.

### Gap: `rebrew graph` does not surface function-pointer call edges

- **Gap:** PRD captures the limitation. Indirect calls through vtables / dispatch
  tables don't appear in the graph, undercutting the visualisation's value for
  C++-heavy code.
- **Evidence:** `src/rebrew/depgraph.py` (string-match call detection).
- **Severity:** enhancement
- **Suggested fix:** Cross-reference `rebrew data --dispatch` results into the graph
  builder so dispatch-table edges appear (perhaps under a `--include-dispatch` flag).

### Gap: `rebrew cache` does not report hit rate

- **Gap:** `cache stats` prints size + entry count but no hit/miss telemetry.
- **Evidence:** `src/rebrew/cache_cli.py` (no hit-rate field).
- **Severity:** nit
- **Suggested fix:** Track a session-local hit/miss counter in `CompileCache` and
  print a 1-day rolling summary in `cache stats`.

---

## Feature: 06 — Data Section Analysis

### Gap: `rebrew data --fix-bss` writes to `rebrew-data.toml`, but the SKILL.md still mentions `rebrew-function.toml`

- **Gap:** Help epilogue mentions metadata writes; both the workflow skill and PRD
  reference `rebrew-function.toml`. The actual writes for DATA/GLOBAL metadata go to
  `rebrew-data.toml` (`DATA_METADATA_FILENAME` in `src/rebrew/data_metadata.py:64`).
- **Evidence:** `src/rebrew/data_metadata.py:21` says "All rebrew-specific metadata
  lives in `rebrew-data.toml`"; `src/rebrew/agent-skills/rebrew-data-analysis/SKILL.md`
  references `rebrew-data.toml` correctly, but PRD 03 / 05 broadly say "metadata in
  rebrew-function.toml" without distinguishing.
- **Severity:** nit
- **Suggested fix:** Audit the data-section docstrings + skill text to make the
  function-metadata vs data-metadata split explicit. (PRDs in this directory already
  call it out.)

### Gap: `rebrew data --dispatch` heuristic is not configurable

- **Gap:** The pointer-alignment heuristic is hard-coded; users can't tune the
  minimum table length or pointer range.
- **Evidence:** `src/rebrew/data.py:337` `find_dispatch_tables` constants.
- **Severity:** enhancement
- **Suggested fix:** Surface `--min-table-len` / `--max-pointer-stride` options.

### Gap: `rebrew data --gen-header` overwrites `rebrew_globals.h` without backup

- **Gap:** PRD notes the limitation. There's no `--out PATH` override and no
  prompt before clobbering hand-edits.
- **Evidence:** `src/rebrew/data.py:866` `_gen_globals_header`.
- **Severity:** enhancement
- **Suggested fix:** Add `--out PATH` and a `--force` guard; warn if the destination
  exists and was modified after the last `--gen-header` run.

---

## Feature: 07 — Ghidra Sync

### Gap: Default MCP endpoint differs between `rebrew sync`/`rebrew skeleton --endpoint` and the skill

- **Gap:** See blocker under PRD 03. Code default is
  `http://localhost:8080/mcp/message`; the `rebrew-ghidra-sync` SKILL text says
  `http://localhost:8089`.
- **Evidence:** `src/rebrew/ghidra/cli.py:164`, `src/rebrew/ghidra/client.py:301`,
  `src/rebrew/agent-skills/rebrew-ghidra-sync/SKILL.md:23`.
- **Severity:** blocker (duplicated from PRD 03)
- **Suggested fix:** Pick one default and align.

### Gap: `rebrew sync --pull-structs` writes a single `types.h` regardless of source module

- **Gap:** Multi-module projects get one merged `types.h`. Users wanting per-module
  isolation must edit the file by hand.
- **Evidence:** `src/rebrew/ghidra/commands.py:1003` `pull_structs`, output path
  `cfg.reversed_dir / "types.h"`.
- **Severity:** enhancement
- **Suggested fix:** Accept `--types-out PATH` and/or `--by-module` to split.

### Gap: Sync's offline fallback is partial

- **Gap:** PRD claims a fallback to cached JSON. In practice `--pull-signatures`,
  `--pull-structs`, `--pull-comments`, and `--pull-data` all require live MCP; only
  the `--pull` function-name path and `--summary` consult the cache.
- **Evidence:** `src/rebrew/ghidra/commands.py` (multiple pull functions assume live
  client).
- **Severity:** enhancement
- **Suggested fix:** Document explicitly which pull modes work offline, or extend the
  cache to store struct/signature/comment payloads for offline use.

### Gap: `rebrew binsync-export` is one-way

- **Gap:** PRD lists this as a known limitation. Today there is no `binsync-import`
  command.
- **Evidence:** `src/rebrew/binsync_export.py`.
- **Severity:** enhancement
- **Suggested fix:** Spec a `binsync-import` command if any user demand materialises.

### Gap: `rebrew sync --refresh-cache` doesn't refresh data labels

- **Gap:** `--refresh-cache` is documented to "Fetch all functions" but
  `ghidra_data_labels.json` (used by `rebrew catalog --export-ghidra-labels` and
  the data analysis skill) is not refreshed unless `--pull-data` is invoked.
- **Evidence:** `src/rebrew/ghidra/cli.py` `--refresh-cache` handling.
- **Severity:** enhancement
- **Suggested fix:** Refresh both caches when `--refresh-cache` is passed (or add a
  separate `--refresh-data-cache`).

---

## Feature: 08 — Agent Skills

### Gap: No `rebrew skills list` discovery command

- **Gap:** Agents must scan `src/rebrew/agent-skills/` manually. There's no CLI
  command to enumerate installed skills.
- **Evidence:** No subcommand registered for skills in `src/rebrew/main.py`.
- **Severity:** enhancement
- **Suggested fix:** Either ship a `rebrew skills list/show` subcommand or add a
  `docs/SKILLS.md` index that the agent loader can fetch first.

### Gap: SKILL.md examples are not lint-validated against the live CLI

- **Gap:** PRD captures this. Renames or removed flags can drift undetected.
- **Evidence:** Manual review only; no test asserts SKILL.md commands.
- **Severity:** enhancement
- **Suggested fix:** Add a pre-commit hook or pytest case that extracts command
  lines from SKILL.md (e.g. by fenced-block parsing) and runs `--help` on each to
  verify the flags resolve.

### Gap: `rebrew-intake` skill suggests `rebrew doctor` before catalog/FLIRT, but doesn't mandate `cfg detect-crt`

- **Gap:** Without `cfg detect-crt`, `rebrew crt-match --all` returns zero matches.
  The intake skill should chain it explicitly.
- **Evidence:** `src/rebrew/agent-skills/rebrew-intake/SKILL.md` intake procedure
  (no `cfg detect-crt` step).
- **Severity:** nit
- **Suggested fix:** Add `rebrew cfg detect-crt` between doctor and crt-match in the
  intake procedure.

### Gap: Skill descriptions claim default ReVa port that disagrees with code

- **Gap:** See blocker above. The `rebrew-ghidra-sync` skill says port 8089;
  the code defaults to 8080.
- **Severity:** blocker (duplicated)

---

## Project-wide / cross-feature

### Gap: Two copies of `PRINCIPLES.md` with divergent text

- **Gap:** `src/rebrew/PRINCIPLES.md` and `docs/PRINCIPLES.md` exist with subtly
  different framing of "the system must never make a function worse"; the in-tree
  copy is more conservative ("never make worse"), the docs copy mentions an
  unimplemented `rebrew promote` command and an explicit 75% threshold.
- **Evidence:** `diff src/rebrew/PRINCIPLES.md docs/PRINCIPLES.md` shows divergence
  starting on line 15.
- **Severity:** blocker
- **Suggested fix:** Pick one canonical location (probably `docs/PRINCIPLES.md`) and
  delete the other, or have `src/rebrew/PRINCIPLES.md` be a symlink. Resolve the
  factual divergence about `rebrew promote` (no such command exists today).

### Gap: `docs/metadata_format.md` exists but CLAUDE.md / external refs use `METADATA_FORMAT.md` casing

- **Gap:** CLAUDE.md and PRD scaffolding reference `docs/METADATA_FORMAT.md` (upper
  case); the on-disk file is `docs/metadata_format.md` (lower case).
- **Evidence:** `ls docs/` and CLAUDE.md "Existing user-facing docs" list.
- **Severity:** nit
- **Suggested fix:** Rename the file to match the conventional casing
  (`docs/METADATA_FORMAT.md`) or update the references.

### Gap: `docs/CONFIG.md` references `compiler_command` (legacy snake_case)

- **Gap:** `docs/CONFIG.md:286` lists `compiler_command` in the "what each tool
  reads" matrix. The actual TOML key is `compiler.command` (dotted) and the
  ProjectConfig attribute is `compiler_command`. Newcomers reading CONFIG.md may
  try `rebrew cfg set compiler_command "wine CL.EXE"` and fail.
- **Evidence:** `docs/CONFIG.md:286`, `src/rebrew/config.py:134`,
  `src/rebrew/cfg.py:192` (uses dotted form in example).
- **Severity:** nit
- **Suggested fix:** Re-emit CONFIG.md to use dotted keys consistently.

### Gap: `rebrew test` and `rebrew verify` overlap is documented inline but no high-level "which one to use" page

- **Gap:** The top-level `rebrew` epilog lists test-vs-verify-vs-match, but the
  decision criteria live there only. Users who skip the epilog miss the
  guidance.
- **Evidence:** `uv run rebrew --help` epilog includes the table; no companion in
  `docs/`.
- **Severity:** nit
- **Suggested fix:** Move the table into `docs/CLI.md` or `docs/WORKFLOW.md`.

---

## Summary

Distinct gaps (deduplicated across PRDs):

- blockers: 3
- enhancements: 17
- nits: 14

(The "MCP endpoint disagreement" gap is cited in PRDs 03, 07, and 08 but is
counted once. Total Severity lines in this file: 36.)

Top blockers (verbatim):

1. **Verify cache key omits headers.** `rebrew verify` does not detect
   shared-header changes — users must remember `--full` after any header
   edit or face stale cache hits hiding regressions.
   *(PRD 05; `src/rebrew/verify.py`.)*
2. **MCP endpoint disagreement.** `rebrew skeleton --endpoint` / `rebrew sync`
   default to `http://localhost:8080/mcp/message`, but the
   `rebrew-ghidra-sync` skill documents `http://localhost:8089`; pick one and
   align.
   *(PRDs 03/07/08; `src/rebrew/skeleton.py:723`,
   `src/rebrew/agent-skills/rebrew-ghidra-sync/SKILL.md:23`.)*
3. **Duplicate PRINCIPLES.md files.** `src/rebrew/PRINCIPLES.md` and
   `docs/PRINCIPLES.md` diverge; the docs copy references an unimplemented
   `rebrew promote` command and a 75% threshold rule that doesn't exist.
   *(`diff src/rebrew/PRINCIPLES.md docs/PRINCIPLES.md`.)*
