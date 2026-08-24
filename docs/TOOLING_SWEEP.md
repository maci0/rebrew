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
`rebrew-function.toml.lock`, `db/coverage.db` (untouched), and
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
   `functions.txt`, corrupt/empty `rebrew-function.toml`, syntax-error
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
