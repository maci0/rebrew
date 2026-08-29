# Tooling sweep — rebrew-projects fleet (round 2026-08-24)

Exercised the rebrew CLI across the `../rebrew-projects` fleet (~45
projects: win2k-* set, notepad/calc/pinball/skifree, the `test_*`
fixtures, bench/cpubench/dhrystone, errlook/guidgen/makehm/smygb,
16-bit skifree16/tc16).  Tools swept: `doctor`, `status`, `lint`,
`test` (single + `--all`), `verify` (single + `--json`),
`diff`, `match` (single + `--all`), `prove`, `skeleton` (batch),
`asm` (incl. `--imports/--strings/--hints`), `data`
(`--annotate`, `--dispatch`, `--bss`, `--gen-header`), `switch`
(single + `--all`), `imports`, `strings`, `xrefs`, `describe`,
`analyze`, `report`, `catalog`, `round-trip`, `gen-layout`,
`gen-link-stubs`, `gen-stubs`, `order-sources`, `inline-strings`,
`calibrate-bss`, `verify-placement`, `crt-match`, `build-db`,
`cache stats`, `toolchain detect/status`, `cfg`, `extract`
(list/batch), `fix`, `recover-structs`, `decompile`, `prove`.

## Bugs fixed (6, each with a regression test)

| # | Bug | Root cause | Fix | Test |
|---|-----|-----------|-----|------|
| 1 | Every load of win2k-cmd/explorer spewed LIEF delay-import noise to stderr | `binary_loader` never configured LIEF's logger; LIEF logs recoverable conditions ("Can't read delay_imports.names_table[0]") at CRITICAL | `lief.logging.disable()` at module init (guarded) | `test_binary_loader.py::TestLiefLoggingSilenced` |
| 2 | `rebrew diff` crashed with `CsError: Details are unavailable (CS_ERR_DETAIL)` on reloc'd functions (e.g. notepad `_AddDefaultExtension@4`) | reloc-offsets path disassembled with `detail=False` but the register-aware mask needs modrm/opcode detail attrs | use the detail disassembler when `register_aware` | `test_scoring.py::TestDiffRegisterAwareWithRelocs` |
| 3 | `rebrew gen-layout` crashed with an unhandled `StopIteration` on Win2K binaries lacking `.reloc`/`.rdata` (notepad/pinball: only .text/.data/.rsrc) | bare `next()` over the section table | clean `ValueError` naming the missing section (caught by gen-layout's `error_exit`) | `test_layout_meta.py` (3 tests) |
| 4 | `rebrew verify --json` emitted an empty `symbol` for every record (test fills it) | the batch result dict never set `symbol` | set `symbol` = annotation symbol or `_name` fallback | `test_verify_extended.py::TestVerifySymbolField` |
| 5 | doctor/analyze reported "MSVC 11.00.0" for VC 5.0-era binaries (cl 11.00 ≠ VC 11.0) | `_msvc_version_hint` printed the raw CL version without era mapping | era-prefix the hint: "MSVC 5.0 (cl 11.00.0)" | `test_toolchain_detect_version.py` (updated + new) |
| 6 | `rebrew extract list` returned 0 candidates on stale-`functions.txt` projects (smygb: 15 uncovered functions invisible) | extract's universe = `functions.txt` only; `rebrew status` uses `function_structure.json` | merge uncovered structure-cache VAs into candidates | `test_extract.py::TestSetupCandidatesStructureMerge` |

## Recorded gaps (not fixed — feature work, per scope)

- **gen-layout** hard-requires .text/.data/.rdata/.reloc — unusable on
  Win2K binaries that merge/omit those sections (now a clean error).
- **`rebrew extract list` counts STUBs as reversed** — stub-heavy
  projects show zero candidates even when every function is a stub
  (pre-skeleton state).
- **`rebrew data --annotate` is metadata-name-driven** — projects whose
  `rebrew-data.toml` lacks `name` fields get no markers (notepad's 31
  data symbols are all unnamed).
- **16-bit round-trip / NE splicing unsupported** — clean error, no
  crash (skifree16).
- **`rebrew status` total vs `extract` universe can diverge** when
  `functions.txt` is stale (functions.txt vs function_structure.json);
  partially addressed by fix #6 (extract now sees structure-cache VAs).

## Project-state findings (correctly reported by tools, not rebrew bugs)

- notepad-rebrew: profile `msvc6` but binary is VC 5.0 (linker 5.12,
  cl 11.00) — doctor correctly flags + suggests msvc5 profiles.
- skifree16-rebrew: configured Delphi but the binary is MSVC-style NE
  (C runtime strings "C RUNTIME ERROR", "Assertion Failed") — analyze
  correctly detects MSVC-style NE; project config question.
- test_error/test_sse2: all 664/519 functions are SIZE-less stubs —
  verify reports MISSING_SIZE correctly.
- hgb (BLOCKED toolchain), rt63/tcmd (SKIPPED): no rebrew-project.toml
  or skipped — doctor reports correctly.
- notepad `db/coverage.db` is schema v3 (old rebrew) — build-db refuses
  with a `--force` hint (pre-existing artifact, not touched).

## Runtime state from exercising the tools (documented, not pollution)

Running the tools legitimately updates project runtime state:
`.rebrew/compile_cache/cache.db`, `.rebrew/verify_cache.json`,
`rebrew-functions.toml.lock`, `db/coverage.db` (untouched), and
`status`-generated `CATALOG.md`/`function_structure.json`.  No tracked
project files were modified by this sweep; the one generated artifact
created during testing (`notepad/src/link_stubs.c` from
`gen-link-stubs`, `notepad/original/notepad.exe.reasm` from
`round-trip`, `AddDefaultExtension.c.fixed.c` from `fix`) was removed.

---

# Round 2 (2026-08-24) — targeted depth

Round 2 went deeper on the round-1 hot spots: the compile pipeline at
scale (`verify`/`match --all`/`test --all` on every real-content project,
multi-function files, `--fix-sizes`/`--fix-blocker` status writers on temp
copies), the 16-bit/DOSBox/NE paths (skifree16 + a synthetic msvc1.52
project, OMF relocs, delphi16), file-writing tools on temp copies only,
the linking family, and malformed-input edge cases.

## Bugs fixed (4, each with a regression test)

| # | Bug | Root cause | Fix | Test |
|---|-----|-----------|-----|------|
| 7 | `verify --fix-sizes` on errlook proposed writing `size = 8512` for a 6-byte thunk; the registry reported a bogus 8512-byte canonical size | `parse_function_list` accepted rizin afl alias lines (`0x00401040 -> 8512`) as functions — the `->` is an alias marker, the trailing number is not a size; `parse_rizin_afl` already skips them | skip `->`-named entries (both line formats) | `test_catalog_loaders.py::TestParseFunctionList::test_rizin_alias_arrow_skipped` |
| 8 | `rebrew verify-placement` errored `build/server.dll not found — build the project first` on any project whose built binary has another name (e.g. notepad's `np_recompiled.exe`), with no way to point at it | built-binary path hardcoded as `root / "build" / "server.dll"` | add `--built PATH` option (default unchanged); error now names the actual missing path | `test_verify_placement.py::TestVerifyPlacement::test_custom_built_path_honored` (+ `test_custom_built_missing_errors`) |
| 9 | `rebrew asm 0x<va> --size -5` errored `No code at VA ... outside the binary image` for a valid VA | negative size fed `extract_raw_bytes` → empty slice → misleading out-of-image error | validate `--size > 0` up front with a clear message | `test_asm_extended.py::TestStaleSizeWarning::test_negative_size_errors_cleanly` |
| 10 | `rebrew cfg set jobs 8` wrote `jobs = 8` as a TOP-LEVEL toml key; the config reader rejects it (`unrecognized top-level keys`) on every later tool run while `[project].jobs` stays untouched | bare project-scoped keys were not routed (only target-scoped ones were) | route bare keys from `_KNOWN_PROJECT_KEYS` to `[project]` (mirrors the target routing) | `test_cfg.py::TestSetScalarCLI::test_bare_project_scoped_key_routes_to_project` (+ `..._routes_name`) |

## Sweep results by area

1. **Compile pipeline at scale** — `verify --full` on notepad (44/67
   passed), smygb (54/155), bench (3/123), bind (1/97), rt63 (1/1),
   errlook (all MISSING_SIZE stubs) — no crashes; `test --all` on notepad
   temp (17 STUB→SIZE_MISMATCH promotions) and skifree16 (16-bit, 4
   promotions); `match --all` on makehm (all pre-skeleton STUBs, correctly
   skipped); multi-function `.c` files verified end-to-end (synthetic
   two-function project); gcc-pe native compile path exercised.  The
   `->`-alias bug (#7) surfaced precisely because `--fix-sizes` on errlook
   backfills *canonical* sizes into metadata — the wrong canonical size
   would have corrupted the project.
2. **16-bit / DOSBox / NE** — `test`/`diff`/`verify`/`imports`/`asm`/
   `switch`/`strings`/`analyze`/`describe`/`xrefs`/`round-trip` all run on
   skifree16's NE binary; a synthetic msvc1.52 project compiled a 16-bit
   function through DOSBox → OMF object → byte compare.  delphi16 has no
   fleet project (unit-tested only; the 6 tests pass).  `mini_ne.exe` is a
   degenerate 0-segment fixture (no code VAs) — fine for format-detection
   tests, unusable for end-to-end compile.
3. **File-writing tools (temp copies)** — `data --annotate` (3 markers
   inserted when the metadata has names AND the sources declare them),
   `data --fix-bss`, `gen-link-stubs` + `calibrate-bss` chain,
   `binsync-export` (+`binsync-import`/`binsync-diff` round trip),
   `report`, `order-sources`, `inline-strings` (0 use-sites by design),
   `gen-stubs`, `fix`, `rename` (xref updates), `round-trip` (splice +
   byte-verify), `verify --fix-sizes` (real metadata write, 103 sizes),
   `near-diag --fix-blocker` — all write correctly and idempotently.
4. **Linking family** — `gen-layout` works on cpubench/dhrystone/nbench/
   test_* (all four sections present); everything else in the family
   (`calibrate-bss`, `verify-placement`, `link-sweep`, `postlink` layout
   converge, `data_layout.link_objects`) hard-requires a **CMake build**
   (`build/CMakeFiles/*/objects*.rsp` + `link.txt`) and the fleet builds
   via Makefile/CMake-less flows — clean pre-condition errors, recorded as
   a gap (see below).  `postlink` itself ran (import-set guard refused a
   cross-project built/reference pair, correctly).
5. **Malformed-input edge cases** — battery across bad TOML, missing
   binary, truncated/garbage binaries, invalid VAs (`banana`, `0xZZZ`,
   out-of-image), negative/zero sizes, empty/comment-only `.c`, missing
   `functions.txt`, corrupt/empty `rebrew-functions.toml`, syntax-error
   sources, unknown targets, CLI misuse: every tool errors cleanly
   (JSON `{"error": ..., "code": 2}` in `--json` mode), zero tracebacks in
   a 32-invocation battery plus the fleet-wide diff sweep.

## Recorded gaps (round-1 gaps stand; new)

- **Linking family assumes a CMake layout** — `calibrate-bss`,
  `verify-placement`, `link-sweep`, and `postlink`'s layout converge all
  read `build/CMakeFiles/*/objects*.rsp`/`link.txt`; Makefile-built
  projects (notepad) cannot use them (clean errors, but the tools are
  unusable without a CMake build).
- **`switch` does not recognize `and reg, mask` index bounds** — the
  byte-tail dispatch in smygb's memcpy/memmove helper (`and eax, 3;
  jmp [eax*4+table]`) reports `entries: 0` because only `cmp reg, N`
  bounds checks are detected.  (The specific smygb instance is a
  degenerate data/code overlap where the table starts misaligned, so a
  mask-bounds fix alone would not decode it; recorded as a gap.)
- **`parse_function_list` does not accept `VA NAME` (no size) lines** —
  only `VA SIZE NAME` / `VA NAME SIZE`; a synthetic size-less list was
  silently ignored (fleet lists all carry sizes).
- **`rebrew cfg set` accepts arbitrary bare keys** — non-dotted, non
  target/project-scoped keys (e.g. `0x00401000`) are still written at the
  document top level where the reader warns; user error is reported, not
  silent.

## Project-state findings (correctly reported, not rebrew bugs)

- errlook's `functions.txt` carries two rizin alias lines
  (`0x00401040 -> 8512`, `0x004015e0 -> 618`) — stale extractor output;
  now harmlessly skipped by the parser instead of feeding garbage sizes.
- dhrystone's `db/coverage.db` is a 0-byte/corrupt file — `build-db`
  reports it ("no schema, likely a failed build") and offers to rebuild.
- win2k-*, test_* projects are pre-skeleton `// STUB:` files with no SIZE
  annotations — `verify` correctly reports MISSING_SIZE without
  compiling; no real content to sweep.
- skifree16 config vs binary: the project's AGENTS.md still says
  "pe, x86_32" while the toml (authoritative) says `ne, x86_16` — stale
  doc, tools behave correctly.

## Runtime state from round 2 (all under /tmp copies; fleet untouched)

Temp copies under `/tmp/r2-*` carried all file-writing runs (notepad,
dhrystone, smygb, errlook).  Fleet-side runtime state was limited to
compile caches/verify caches/lock files and `test`/`verify`-driven STATUS
auto-updates in the non-git projects (bench, skifree16 — the tools'
documented auto-write path, same class as the round-1 caches);
`output/ga_runs/best.c` was rewritten by the single-function GA run on
notepad (untracked).  No tracked fleet files modified.

---

# Round 3 (2026-08-25) — gaps + fresh depth

Round 3 worked two tracks: closing the gaps recorded in rounds 1+2, and
fresh-depth sweeps of areas the earlier rounds only touched at the surface
(GA/matcher internals, decompiler backends, the CMake bridge, binsync
workflows, toolchain CLI).  The round-3 goal bar was 20 fixes; the well
yielded 7 genuine bugs and then ran dry — a final full pass (bench diffs,
doctor/todo, skeleton batch, merge/split duplicates, data layout modes,
NE extract, `match --all` on real stubs, link-sweep, `decompile --named`,
imports/analyze on all win2k projects, rename --file, 16-bit batch
compile) surfaced no new actionable bug.  Reported well-dry at 7/20.

## Bugs fixed (7, each with a regression test)

| # | Bug | Root cause | Fix | Test |
|---|-----|-----------|-----|------|
| 11 | `verify-placement`/`data --layout-audit` errored "no build/CMakeFiles/*/objects*.rsp found — build the project first" on Makefile-built projects (notepad's `out/*.obj`) | `data_layout.link_objects` only read CMake rsp files | fall back to `out/`/`build/` objects sorted (GNU make links `$(wildcard)` in sorted order) | `test_data_layout.py` (4 tests) |
| 12 | MSVC memcpy/memmove byte-tail dispatches reported `entries: 0` — the `and reg, mask` bound was unrecognized AND the dead slot 0 (overlapping the preceding jmp, never dereferenced) broke the table walk | `switch` only scanned `cmp reg, N` bounds and broke at the first out-of-image entry | recognize power-of-two-minus-1 `and reg, mask` bounds; skip invalid entries within a known bound | `test_switch.py::TestMaskBoundedDispatch` (2 tests) |
| 13 | Size-less `VA NAME` function-list lines were silently dropped, hiding functions from the universe | `parse_function_list` required a trailing size | parse `VA NAME` as size-0 entries (bare `VA DIGITS` still rejected) | `test_catalog_loaders.py` (2 tests) |
| 14 | `extract list` reported 0 candidates on stub-only projects — every `// STUB:` pre-skeleton counted as "reversed" | `detect_reversed_vas` only excluded GLOBAL/DATA markers | exclude bare `// STUB:` placeholders (a `// FUNCTION:` file with STUB status stays reversed) | `test_batch.py` (2 tests) — win2k-notepad went 0 → 63 candidates |
| 15 | `data --annotate` silently no-oped on projects whose data metadata has no `name` fields (notepad's 31 data symbols) | unnamed entries skipped with zero feedback | return/report the skipped count ("N metadata entries skipped — no `name` field") | `test_data_annotate.py::test_annotate_reports_skipped_unnamed` |
| 16 | `binsync-export` fabricated `name = "<windows.h>"` / `type = "#include"` for a `// DATA:` marker above `#include` (notepad's 0xDEADBEEF link stub) | declaration scan accepted preprocessor directives and function-definition lines as declarations | skip `#` lines; require the extracted name to be a valid C identifier | `test_binsync_export.py::test_data_marker_above_include_not_misparsed` |
| 17 | `postlink X X` did not reproduce X — the data fixer zeroed the reference's own .text file padding (cpubench: vs 0x29d11 < raw 0x29e00, 239 bytes of 0xCC corrupted) | `.text` trim used the reference VirtualSize instead of its raw extent | trim to the reference's raw extent; keep its padding | `test_postlink.py::test_preserves_reference_text_padding` (+ `make_full_pe` `text_pad_byte`) |

## Sweep results by area

1. **Track A — recorded gaps.** Five of the recorded gaps turned out to be
   fixable bugs (#11-#15); the rest stayed recorded: gen-layout's
   4-section hard requirement and NE round-trip splicing (both clean
   errors, feature work), plus the round-3 discovery that MSVC memcpy's
   small-tail `jmp [ecx*4+table]` dispatches reference tables that overlap
   the handler region (decodes as garbage; `entries: 0` is honest — gap).
2. **GA/matcher internals** — all 121 mutation operators run clean over a
   real corpus (0 exceptions); `score_candidate`/`structural_similarity`/
   `diff_functions` handle empty/truncated/junk bytes and out-of-range
   reloc offsets; `generate_flag_combinations` across all tiers+profiles;
   `mutate_code`/`MutationLog` edge inputs; the flag sweep ran end-to-end
   (quick + targeted tiers, clean JSON); `match --all` on smygb's 98 sized
   stubs ran the batch GA without incident.
3. **Decompiler backends** — r2ghidra decompiles real functions
   (notepad's AddDefaultExtension, incl. `--named`); kuna/r2dec/ghidra
   error cleanly (backend unavailable); prove needs angr (not installed —
   guarded error).
4. **CMake bridge** — `cmake-toolchain` generates the msvc6 toolchain
   file; `rebrew-cmake-cl` compiles an in-project file through the docker
   translation; other profiles error cleanly (no tool_root / no image).
   Out-of-project paths surface as a raw wine-drive CL error (minor UX
   note, recorded).
5. **Binsync** — export/import/diff cycle clean (bug #16 fixed); the
   import conflict flags and dry-run paths behave.
6. **Toolchain CLI + library + skills** — `toolchain list/status/detect`
   correct (notepad's msvc6-vs-VC5 misalignment flagged); `library
   set/show/rm` round-trips; `skills list/show`; `lint --fix` migrates
   inline metadata.
7. **Linking family** — `postlink` fixers run on cpubench (bug #17 fixed;
   now byte-identical on `postlink X X`); `link-sweep` runs with a docker
   link command; round-trip splices byte-identically on notepad/bench/
   smygb; `data --layout-audit` works on the Makefile build via #11.
8. **16-bit/NE** — `extract list` on skifree16 now shows 136 candidates
   (via #14); `extract batch` disassembles NE functions; the msvc1.52
   DOSBox compile path works end-to-end (the synthetic tc16 project; the
   mini_ne fixture is degenerate — zero segments — so its `test --all`
   EXTRACT_ERROR is honest).

## Recorded gaps (rounds 1+2 stand; new)

- **`switch` can't decode MSVC memcpy small-tail dispatches** —
  `jmp [ecx*4 + table]` after `sub ecx, 4; jb` reads the handler region as
  a table (garbage); `entries: 0` is reported honestly.  The decodable
  byte-tail dispatches are fixed (#12).
- **Linking family still requires a CMake build for its link commands** —
  `calibrate-bss`, `link-sweep`, and postlink's converge path need
  `build/CMakeFiles/*/link.txt` or a `--link-cmd`; Makefile builds get
  objects inventory (via #11) but not the link template.
- **`rebrew crt-match` needs vendored CRT sources** — the rebrew-toolchains
  checkout carries Dockerfiles but not the `<version>/source` trees;
  projects have no `crt_sources` configured (clean error).
- **`rebrew prove` needs angr** (optional extra, not installed; guarded).
- **`data --annotate` is declaration-anchor-driven** — unnamed metadata
  entries can't be marked (now reported, #15); markers need a name in
  `rebrew-data.toml` or a matching declaration in source.
- **gen-layout / NE splicing / postlink-data-drift** — rounds 1+2 gaps
  stand (clean errors, feature work).

## Project-state findings (correctly reported, not rebrew bugs)

- notepad `rebrew-data.toml` entries are unnamed (31 symbols) — `data
  --annotate` now says so instead of a silent 0-marker no-op.
- notepad's `// DATA: NP 0xDEADBEEF` link-stub marker sits above
  `#include <windows.h>` — export now yields `g_deadbeef`, not the
  fabricated `<windows.h>`/`#include`.
- win2k-* / test_* remain pre-skeleton `// STUB:` files (no SIZE) —
  `verify` reports MISSING_SIZE without compiling; `extract list` now
  surfaces them (63+ candidates per project).
- smygb has 98 sized STUBs — a viable `match --all` batch target.
- `tests/fixtures/mini_ne.exe` has zero NE segments — fine for
  format-detection tests, unusable for end-to-end 16-bit compile
  comparisons (the tc16 EXTRACT_ERROR is a fixture artifact).
- cpubench `.text` VirtualSize (0x29d11) < raw size (0x29e00) with 0xCC
  padding — the layout postlink now preserves (bug #17).

## Runtime state from round 3 (fleet untouched)

All file-writing ran on `/tmp/r2-*` copies.  Fleet-side runtime state from
`match --all` on smygb: `.rebrew/ga_runs.jsonl` + `output/ga_runs/**`
(build caches, checkpoints, best.c) — untracked, same class as the
documented round-1/2 caches; no tracked fleet files modified.
