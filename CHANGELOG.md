## [Unreleased]
### Fixed
- **Dependency floors raised to close advisories (deps-review F1)**:
  `typer>=0.10` (the 0.9 floor admitted a version the CLI cannot start on —
  `rich_markup_mode` requires 0.10), `pytest>=9.0.3` (CVE-2025-71176
  `tmpdir`), and a declared `click>=8.3.3` (direct import in `init.py` shell
  completion; 8.3.3 fixes CVE-2025-6143/6144).  `uv audit` went from 35
  vulnerable packages to 2 (diskcache has no fixed release; its cache only
  stores compiled `.obj` bytes, documented in `pyproject.toml`).
- **`prove` extra now declares its own imports**: `claripy` (imported by
  `prove.py`/`doctor.py`) and `gitpython>=3.1.58` (angr's transitive dep with
  RCE-class advisories fixed in 3.1.58) — `uv pip install -e ".[prove]"` no
  longer relies on luck to pull them (deps-review F3).
- **`skills-ref` pre-commit hook fixed from a silent no-op**: the hook
  checked for a nonexistent `skills-ref` command and exited 0, so a broken
  SKILL.md passed CI.  The package's real binary is `agentskills`; the hook
  now runs `uv run agentskills validate` (infra-review F6).
- **CI drops the dead "Install wibo" step**: it swallowed download failures
  with `set +e` and no test consumed the binary (no wine on the ubuntu
  runner, vendored MSVC is gitignored).  The lint job now gates on
  `uv audit --locked` (exits 1 on vulnerable packages; diskcache's
  unfixed advisory is ignored only while no fix exists) (infra-review F5).
- **Pre-commit hygiene hooks added**: `end-of-file-fixer`,
  `check-merge-conflict`, `check-yaml`, `check-toml`, and
  `mixed-line-ending` (LF) — trailing-newline/conflict-marker/YAML/TOML
  breakage no longer lands silently (infra-review F6).
- **`prove` tests skip when angr is absent**: the CLI-status-guard and
  Win32-SimProcedure tests hard-failed with `ModuleNotFoundError` when the
  optional `prove` extra wasn't installed; they now honor the same
  `skipif(not has_angr)` guard as the rest of `test_prove.py`.
- **mypy is clean on 105 files (was 78 errors)**: the session's new code
  carried real type errors — `init.py` reused the `detected` variable for a
  `ToolchainInfo` after a tuple (renamed to `tc`), `binsync_export.py` typed
  `cfg` as `object` instead of `ProjectConfig` (4 signatures now typed) and
  shadowed the `warnings` module with a local list (renamed `warnings_list`),
  `verify.py` returned `Any` from a `bool`-typed helper, `compile.py` rebound
  `env` to `dict[str, str] | None`, and `binsync_diff.py`/`binsync_export.py`
  carried stale `# type: ignore` comments.  The remaining 35 prove.py errors
  were environmental — they vanish with angr installed.
- **CI lint job installs extras**: `uv sync --frozen --all-extras` — mypy
  only type-checks prove.py correctly with angr present (phantom
  unused-ignore / Any-subclass errors otherwise).  The lint mypy gate was
  red on every recent run for this reason.
- **CI audit gate corrected**: `uv audit --fail-on` doesn't exist in the
  pinned uv (0.12.2) — `uv audit` already exits 1 on vulnerable packages.
  The gate is now `uv audit --locked --ignore-until-fixed
  GHSA-w8v5-vhqr-4h9v`: diskcache's unsafe-pickle advisory is ignored only
  while unfixed, so a fixed release flips CI red.
- **CI test job installs nasm**: the NASM round-trip verification
  (`disassemble_to_nasm` stats) hard-failed with `nasm_ok == 0` — ubuntu
  runners don't ship nasm.
- **Toolchain-dependent tests skip without the vendored toolchains**
  (CI: `tools/` is gitignored): `test_msvc16.TestCompileC` skips without
  `tools/MSVC152`, `test_delphi16` without `tools/DELPHI10`,
  `test_doctor_compiler.test_watcom_vendored_passes` without
  `tools/WATCOM`; the GA msvc152 routing test now mocks
  `parse_obj_symbol_bytes` instead of relying on a vendored objconv; the
  doctor `--json` purity case accepts exit 1 (a failing check keeps stdout
  pure JSON).
- **CI pins the uv installer to the local version** (build-review): the
  workflow pinned uv 0.12.2 while the local toolchain runs 0.12.3 —
  against the pin's own "bump deliberately when upgrading" comment.  Now
  0.12.3.
- **CI gates wheel reproducibility** (build-review): the package job builds
  the wheel a second time with `--no-cache` into a fresh out-dir under the
  same `SOURCE_DATE_EPOCH` and fails if the sha256 differs.  The sdist stays
  excluded — setuptools (≤83) does not honor `SOURCE_DATE_EPOCH` for sdist
  tar entry mtimes / gzip header (verified: content identical, metadata
  varies); this is the documented Makefile limitation, and wheels are the
  reproducibility contract.
- **sdist no longer ships tests/** (pkg-review): setuptools' default sdist
  filelist pulled in all 185 test files (tests/ was the only dev tree that
  leaked).  A `MANIFEST.in` prunes `tests/`, `docs/`, `tools/`,
  `toolchain-images/` and excludes `*.py[cod]`/`__pycache__`; the wheel is
  unaffected (contents come from package-data, still byte-reproducible at
  the same `SOURCE_DATE_EPOCH`), and the pruned sdist still builds a
  complete wheel with `agent-skills` intact.
- **Release preflight gate** (release-review): `make release-check` verifies
  the CONTRIBUTING.md contract before tagging — `__version__` bumped past the
  last tag, clean tree, and a dated `[<version>]` changelog section — so a
  release cannot be tagged out of sync with the version or the notes.
- **Silent best-effort failures now log at debug** (o11y-review): 15
  swallowed `except Exception` sites in `binsync_diff.py` /
  `binsync_import.py` (both gained a module logger), `binary_loader.py` and
  `discover.py` now emit `logger.debug(..., exc_info=True)` with the VA
  context — `rebrew -v -v binsync-import …` shows *why* an entry was
  skipped instead of silently counting it.  The remaining silent fallbacks
  in the recon primitives (`analyze.py`, `asm.py`) are documented
  best-effort paths and are left untouched.  No sensitive data (LLM API
  keys, tokens) is ever logged.
- **Cross-process metadata lock regression test** (concurrency-review): the
  flock sidecar guarantee (error-review F6) was validated manually but never
  committed.  `test_metadata.py::TestCrossProcessMetadataLock` now spawns 4
  real processes × 20 unique STATUS promotions each and asserts all 80
  survive — an interleaved read-modify-write without the flock loses keys.
- **`lint --fix` outside a project warns instead of silently no-oping**
  (functionality-review): without a `rebrew-project.toml` the migration has
  nowhere to write, so `--fix` did nothing with zero explanation — a user
  outside the project dir saw no effect and no message.  It now prints
  `--fix needs a rebrew-project.toml — no config loaded, nothing migrated`
  and leaves the inline keys untouched (regression test added).
- **`init`/config resolve the MSVC toolchain layout instead of assuming the
  master** (error-review): `rebrew init --compiler msvc6|msvc7` and the
  config layer's default includes/libs pointed at `tools/MSVC600/VC98` /
  `tools/MSVC7`, which do not exist on machines that only vendor the
  compile-only mirrors (`tools/msvc6.6` / `msvc6.3` / `msvc7.0`) — a fresh
  project's first compile failed with wine `failed to open tools/MSVC600/...`
  (exit 53).  `rebrew init` now writes the best layout actually present
  (master → newest mirror → older mirror) and the config fallback resolves
  the same; verified end-to-end (the resolved `msvc6.6` and `msvc7.0`
  toolchains compile C → .obj).
- **`init --link-tools-from` accepts the compile-only mirrors** (error-review):
  the linker only looked for the master-named dir (`MSVC600` / `MSVC7`) and
  hard-failed on machines that only vendor `msvc6.3`/`msvc6.6`/`msvc7.0` —
  it now tries the mirrors in the same order as the config resolution and
  links whichever exists (regression test: mirror-only master dir).
- **`init` warns on compiler-family mismatch** (the detector's family now
  feeds init): a high-confidence detection that contradicts the chosen
  profile (e.g. a MinGW/Zig-built DLL initialized with `msvc6`) can never
  byte-match — init prints a warning naming the detected family and the
  counterpart profile (`--compiler gcc-pe`) instead of failing at the first
  verify.  `unknown`/low-confidence detections stay silent.
- **doctor/analyze show the detection backend by its real name**
  (error-review): the toolchain-alignment message leaked the internal
  backend id (`detected mingw … via die`); it now renders `via Detect It
  Easy (diec)` / `via PDB` / `via codegen heuristics` via a shared
  `backend_display_name` helper (unit-tested).
- **Toolchain-layout code deduplicated** (minimalism-review): the
  `--link-tools-from` candidate list in `init.py` duplicated the mirror
  table in `utils.py` (drift risk) — it is now derived from the same
  `_MSVC_LAYOUTS` source, and the unused `resolve_msvc6_toolchain`
  back-compat wrapper was deleted (no callers; the project forbids shims).
- **Grid-cell generation extracted + property-tested** (fuzz-review): the
  coverage-cell walk inside `generate_data_json` is now a pure
  `_build_cells` helper, with hypothesis tests asserting the invariants over
  random segment layouts — cells tile the section exactly (contiguous,
  gap-free, no overrun), `span == ceil(bytes / unit)` never exceeds the row
  width, and per-segment state is preserved.
- **Module boundary fixed** (arch-review): `init.py` reached into
  `utils._MSVC_LAYOUTS` (private data) to derive link candidates —
  replaced by a public `utils.toolchain_link_candidates(profile)` helper,
  which also removed the module-level derived dict.  `utils` stays a pure
  leaf module (no rebrew imports).
- **Toolchain directory naming made platform-explicit**: the vendored
  `tools/` subdirs were a mix of `MSVC152` (reads as "MSVC 152"),
  `MSVC420`/`MSVC500`, `DELPHI10`, `WATCOM` (uppercase, no version dots) and
  `msvc6.3`/`msvc6.6`/`msvc7.0` (lowercase) — none conveying that these are
  **Windows-targeting** toolchains run under Wine/DOSBox on Linux.  Renamed
  to a `compiler-version-target` scheme: `msvc-1.52-win16`, `msvc-4.2-win32`,
  `msvc-5.0-win32`, `msvc-6.0-win32` (master), `msvc-6.0-sp3-win32`,
  `msvc-6.0-sp6-win32`, `msvc-7.0-win32`, `delphi-1.0-win16`,
  `watcom-win32` — the same naming the OmniBlade mirror tarballs already
  use.  Every code/test/doc reference updated (~520), the CLI profile
  identifiers (`--compiler msvc6.3|msvc6.6`) are unchanged, and legacy dir
  names remain as symlinks so existing projects keep working (verified:
  mspaint corpus still verifies 251/251 through the `MSVC500` symlink).
- **Toolchain image folders aligned to the documented
  `<family>/<version>-<arch>` layout**: `toolchain-images/` used
  `msvc/6.0-linux-x64`-style names (the image *platform*), which said
  nothing about the compiled target and disagreed with the `tools/` scheme.
  Renamed to the layout docs/TOOLCHAIN.md already prescribed —
  `msvc/6.0-win32`, `msvc/1.52-win16`, `delphi/1.0-win16`,
  `watcom/2.0-win32` — and the image tags (`rebrew/msvc:6.0-win32`, …) and
  Dockerfile build/invoke comments updated (29 references).
- **Toolchains moved from `tools/` into a `toolchain/` folder structured like
  the docker images**: `toolchain/<family>/<version>-<arch>/` (e.g.
  `toolchain/msvc/6.0-sp6-win32/`, `toolchain/delphi/1.0-win16/`), with each
  dir's `Dockerfile` living alongside the toolchain it packages.  This is
  now the **default** — `rebrew init`, the config fallbacks, the GA
  toolchain sweep, the CRT-source detection and `--link-tools-from` all
  resolve `toolchain/…` paths (verified: fresh init writes
  `wine toolchain/msvc/6.0-sp6-win32/Bin/CL.EXE`; `docker build
  toolchain/msvc/6.0-win32` produces `rebrew/msvc:6.0-win32` which compiles
  C end-to-end).  `tools/` keeps the Linux-native helpers (diec, objconv,
  wibo) plus old-name symlinks so existing projects keep working (mspaint
  corpus still verifies 251/251).  `toolchain-images/` is gone (content
  merged into `toolchain/`).
- **Shared toolchain base image + common wrappers**: all toolchain
  Dockerfiles now inherit `FROM rebrew/base:1.0` (`toolchain/base/` — OS +
  wine + wine32 + dosbox + download tooling + common env), built
  automatically as a dependency by `rebrew toolchain build`.  The
  entrypoint wrappers (`cl`, `cl16`, `dcc`) share
  `toolchain/base/wrapper-common.sh` (`rebrew_pick_source` handles
  MSVC-style flags-first argv; `rebrew_dosbox_run` / `rebrew_copy_back`
  are one implementation instead of per-toolchain copies).  The vendored
  compiler trees sit at the top level of each
  `toolchain/<family>/<version>-<arch>/` dir so host and image share one
  layout.  Verified: all four images (`rebrew/msvc:6.0-win32`,
  `rebrew/msvc:1.52-win16`, `rebrew/delphi:1.0-win16`,
  `rebrew/watcom:2.0-win32`) compile C end-to-end from the base.
- **`recompile/` service skeleton** (recompile.online): a FastAPI
  compiler-as-a-service package that dispatches each compile into the
  matching toolchain container — `GET /api/v1/compilers` (catalog derived
  from the rebrew toolchain registry), `POST /api/v1/compile`
  (`{compiler, source, flags}` → status/artifact URL/compiler version/log,
  executed via `docker run` against the pinned image), and
  `GET /api/v1/artifacts/{id}` (path-traversal guarded).  Verified
  end-to-end: the API compiled C with `msvc6` (i386 COFF object served
  back) and `watcom`; unit tests cover the catalog, image resolution and
  the 400/404 error paths (no docker needed).
- **Toolchain zoo additions**: `borlandc55` (Borland C++ 5.5 free
  command-line tools — bcc32 under wine, OMF objects that parse via
  objconv; image `rebrew/borland:5.5-win32`) and `watcom16` (Open Watcom
  `wcc`, 16-bit DOS, native) — the detector's `borlandc`/`watcom` families
  now have profiles to byte-match with, and `rebrew init` warns on family
  mismatch with the correct counterpart.
- **Toolchain images are deterministic and self-contained**: every
  Dockerfile builds from a clean checkout with only docker — the base pins
  the debian digest, msvc6/watcom/borland downloads verify sha256 (the
  moving watcom tag is pinned by checksum), and msvc1.52 + delphi use
  committed in-repo tarballs (the archive.org en_vc152 RAR SFX extracts
  corrupt files under both 7z and unar; the Delphi RTL units have no
  public tarball).  7z extraction tolerates warning exits but verifies the
  compiler binary, so a bad extraction fails loudly.  All five images
  verified building + compiling.
- **`functions.similarity` documented as reserved**: the column was
  documented as a structural-similarity score but no catalog producer ever
  emitted it (it needs both target AND recompiled bytes, which only
  `rebrew match`/`diff` have) — every row was NULL and the doc's example
  showed a misleading `1.0` (db-review F14).  The doc now states it is
  reserved/always-NULL until a producer exists; recoverage displays it only
  when non-null, so no consumer is affected.
- **`history` table is retention-capped**: status-change rows were appended
  on every rebuild and never pruned — a long-lived project that regenerates
  often accumulated rows forever (db-review F7).  Only the newest 10,000
  rows per target now survive each rebuild (the dashboard pages the newest
  100, max 5000), bounding growth while preserving full history depth.
- **Removed the redundant `cells` index**: the `UNIQUE (target,
  section_name, start)` constraint already served the `(target,
  section_name)` prefix used by `section_cell_stats` and per-section
  queries — a separate `idx_cells_section` was paid for on every cell
  insert and never the only usable index (db-review F6).  Stale copies
  from older builds are dropped.
- **Unknown cell states warn instead of vanishing**: an out-of-set
  `cells.state` (a typo in hand-edited JSON) fell into the
  `section_cell_stats.other_count` bucket with no signal (db-review F4).
  `_normalize_cell_row` now logs a warning naming the state and the known
  set; the value is preserved so the count still reconciles.
- **Dashboard "coverage" now means matched bytes**: the headline `coverage_pct`
  summed EVERY function's size regardless of status — an all-STUB binary
  reported ~100% "coverage" (db-review F1).  It now uses matched bytes
  (EXACT/RELOC/PROVEN sizes) / text size, with a separate `identified_pct`
  ("fully documented", incl. stubs) stored alongside in `function_stats`.
  DB_FORMAT.md documents both definitions.
- **`verify_results` no longer dropped on full rebuild**: `rebrew build-db`
  wiped the table on every full rebuild (contradicting DB_FORMAT's "never
  dropped" promise), then re-imported only the last-verified target's rows —
  in multi-target projects every other target's verification history was
  silently lost (db-review F3).  The per-target `INSERT OR REPLACE` + prune
  now keeps it current without the drop.
- **`verify_results` prune no longer wipes on unparseable reports**: when a
  report's `va` values failed to parse, the prune built `va NOT IN ()` —
  which SQLite treats as vacuously TRUE, deleting the target's entire
  history (db-review F5).  The prune now guards on the parsed VAs.
- **`verify_results.diff_lines` is now populated**: the column was documented
  and recoverage-consumed but no producer ever emitted it — every row was
  NULL (db-review F2).  `rebrew verify` now computes the differing-
  disassembly-line count for unmatched functions (best-effort; matched
  functions skip the disassembly diff entirely, leaving NULL = 0 diffs).
- **`section_cell_stats` gained an `other_count` catch-all**: cells in
  states outside the counted buckets (compile_error, missing_*, skip,
  unknown) fell into no column, so `total_cells` never equaled the sum of
  the counted columns and per-section stats silently undercounted
  (db-review F4).
- **`rebrew` umbrella detects `--json` by exact token, not substring**: the
  uncaught-exception handler scanned `"--json" in sys.argv`, so any
  argument containing the literal (a file named `x--json.c`, or
  `--cflags "--json"`) switched the error envelope to JSON mode without
  the user passing `--json` (cli-review F11).  `_json_requested` now
  matches the exact `--json`/`--json=true` tokens.
- **`rebrew catalog --export-ghidra --json` is refused**: the export path
  prints interactive instructions and emits no JSON document — combining
  it with `--json` produced zero stdout, breaking the JSON contract
  (cli-review F9).  The combination now errors up front, like the existing
  `--fix-sizes --json` guard.
- **Malformed `[link]` version strings warn instead of silently no-op**: a
  typo'd `linker_version`/`os_version`/`subsystem_version` (e.g. `"5"` or
  `"abc"`) was swallowed by `except ValueError: pass` — `--fix-headers`
  skipped the field while the parity report showed an unexplained mismatch.
  A shared parser now warns on the malformed value (config-review F7).
- **GA run output honors `[project].output_dir`**: `rebrew match`'s GA
  checkpoints/resume paths hardcoded `output/ga_runs` while `rebrew report`
  used the config value — the same documented option behaved differently
  per tool.  All three sites now route through a shared helper honoring
  `cfg.output_dir` (default `output`, so existing projects are unchanged).
- **Reserved/no-op config keys warn at load**: `[compiler.profiles]` is
  documented as runtime-selectable but no tool consumes it, and
  `game_range_end` is a documented legacy no-op — both silently did
  nothing.  They now emit a load-time warning so a user configuring them
  sees the no-op instead of believing it works (config-review F5).
- **`cflags = ""` means "no default flags"**: an explicitly-empty
  `[compiler].cflags` silently compiled with the hardcoded `/O2 /Gd`
  fallback, indistinguishable from an absent key.  A presence flag
  (`cflags_explicit`) now distinguishes the two — the `/O2 /Gd` fallback
  applies only when the key is absent (config-review F5).
- **Verify cache invalidates on config-level CFLAGS changes**: the cache
  entry stored only the metadata CFLAGS, so a `rebrew cfg set-cflags` or
  `[compiler].cflags` edit changed the effective flags (via the config
  fallback chain) without changing the cache key or entry guard — stale
  EXACT/RELOC kept being served while `rebrew test --all` recompiled and
  demoted.  Entries now store the RESOLVED effective flags and the hit
  check compares the freshly-resolved value; the `_compiler_config_hash`
  comment claiming "verify never reads them" was false and is corrected.
- **`rebrew cfg set-compiler` writes the `profile` key**: it previously
  wrote only command/includes/libs, so the target's profile stayed at the
  default (msvc6) — compiling with a gcc command but MSVC-style `/I /Fo`
  routing, and never engaging the posix/toolchain branches
  (config-review F1).
- **`[llm]` config section is now parsed**: documented in CONFIG.md but
  never in the known top-level keys — a `[llm]` table warned
  "unrecognized" and `cfg.llm_endpoint` was always "" (only the env-var
  fallback worked), while `match --llm-seed`'s error message pointed users
  at the dead `[llm] endpoint` key.  The table now populates
  `cfg.llm_endpoint`/`cfg.llm_api_key`.
- **`compile_to_obj` routes POSIX flags through `cfg.posix_style`**: the
  local profile tuple duplicated the config property's "single source of
  truth" — adding a POSIX profile to one list but not the other silently
  switched flag routing and broke compiles.
- **Grid status counters count PROVEN as matched**: `count_statuses` had no
  PROVEN group, so a PROVEN annotation fell into no bucket and
  exact+reloc+near+stub could undercount `totalFunctions` — the catalog's
  "Matched: N/M" line lied for proven-but-not-byte-equal functions.
  PROVEN now ranks with RELOC, matching `_STATUS_RANK` everywhere else.
- **`_compile_cflags` no longer silently drops a `/c`-less base**: a
  `base_cflags` without `/c` (e.g. a bare `/MT`) was discarded in the glue
  branch — the same silent flag-loss class the function was consolidated to
  prevent.  It is now preserved alongside the `/nologo /c` glue (caught by
  the new unit tests for all five branches).
- **`rebrew catalog` no longer fabricates coverage from a missing binary**:
  a missing target binary fell back to a hardcoded `0x24000` (92160B)
  section, and coverage was reported against that made-up denominator —
  indistinguishable from a real measurement and ingested as truth by
  build-db/dashboards (code-review F9).  The size is now 0 (coverage 0%)
  with a warning on stderr and a `warning` field in the JSON payload.
- **`catalog --summary` help matches behavior**: it claimed "Print summary
  to stdout" but every summary line goes to stderr (the console).  Help
  text corrected.
- **Batch match runs honor the documented exit contract**: `rebrew match
  --all` / `--all-targets` always exited 0 even when every stub failed —
  a false green for CI gates against the epilog's "1 = no match found".
  Both batch paths now exit `EXIT_MISMATCH` when any stub failed (mirroring
  `rebrew test --all`); dry-run is unaffected.
- **`rebrew test <multi-function.c>` honors the exit contract**: the
  multi-annotation path printed results and always exited 0, so a file of
  all-STUB functions reported success.  It now exits 1 when any function is
  unmatched and 2 on tooling (EXTRACT_ERROR) failures, matching the
  single-function and `--all` paths.
- **`--dry-run --llm-seed` no longer runs the full GA**: when no LLM
  endpoint is configured, the warning printed and control fell through to
  `ga.run()` — hours of Wine compiles despite `--dry-run`'s "preview, no
  write" promise.  It now returns after the warning.
- **`--tier bogus` errors in every mode**: tier was only validated in sweep
  paths, so `rebrew match f.c --tier nonsense` silently succeeded in plain
  GA mode.  Now validated unconditionally at invocation time.
- **Usage errors exit 2 (EXIT_ERROR), not 1**: bad `--format` values
  (diff/asm), `--decomp-body` without `--decomp`, `--watch`+`--all`, and
  missing-source errors reported exit 1 = "needs code work" — violating
  cli.py's documented rule ("a bad argument is a usage error — exit 2") and
  typer's own convention.  All now exit 2.
- **`rebrew skeleton --append` refusal exits non-zero**: appending a VA
  already in the file printed a hint and exited 0 (success) with nothing
  appended — a false signal for automation.  It now errors via `error_exit`.
- **`rebrew verify` writes the default report in plain mode**: `--output`
  help promises "default: project db_dir/verify_results.json", but plain
  `rebrew verify` wrote nothing — so a first `--compare` run had no
  baseline and silently became one.  The report (already assembled) is now
  written in plain mode too.
- **`rebrew diff --fix-blocker --json` writes the blocker once**: the
  terminal-only write ran after the JSON branch had already written it —
  redoing metadata I/O and printing status chatter against the JSON
  contract.  Guarded with `not json_output`.
- **`rebrew diff` help no longer advertises nonexistent `--mm`/`--rr`**:
  the epilog and docstring examples used flags that don't exist (the real
  ones are `-m/--mismatches-only` and `-r/--register-aware`) — copying the
  documented example failed with "No such option".
- **Calling-convention inference uses the LAST jump**: `calling_convention`
  picked the first `jmp` for ret-less functions — the extent-padded window
  can bleed into the next function, and a jmp-table dispatcher followed by
  the next function's code produced several jmps with no ret.  The terminal
  jump is now used (matching the `rets[-1]` logic), so skeleton signatures
  no longer mis-derive from a mid-body switch dispatch.
- **`--sweep-toolchain` now validates reloc targets**: the per-toolchain
  match passed `name_to_va` via a `getattr(p, "name_to_va", None)` that
  never existed — every sweep ran with reloc validation disabled, so a
  wrong-callee source could tag "EXACT" (the same false-match class the GA
  and flag-sweep paths now guard against).  The catalog map and IAT region
  are computed once and threaded in.
- **`rebrew skeleton --append` now emits convention-aware stubs**: append
  mode (the common multi-function path) silently degraded to
  `int __cdecl f(void)` — the thiscall/stdcall stub work was
  single-file-only.  `generate_annotation_block` now computes and forwards
  the convention stub like `generate_skeleton` does.
- **`rebrew describe` convention inference is extent-based**: the dossier
  disassembled a flat 64-byte window — the exact bug skeleton.py already
  diagnosed (longer functions truncated mid-code → "unknown" → wrong
  cdecl default).  A shared `asm.calling_convention_at` helper (extent-
  derived window) now serves both.
- **verify's "once per process" logic hash actually caches**: the
  `lru_cache` decorated a nested `_hash()` re-created on every call, so the
  full-package source hash was recomputed on every verify run despite the
  docstring claim.  The decorator now sits on the outer function.
- **`rebrew data --fix-bss` is idempotent on re-run**: the generated
  `bss_padding.c`'s own `// DATA:` annotations close the gaps they fill, so
  a second run's gap scan reported fewer gaps — regenerating from scratch
  deleted the first run's arrays while `rebrew-data.toml` still claimed
  coverage (idempotency-review F4).  Existing auto-generated declarations
  are now merged with new gaps, and the file is written BEFORE its metadata
  so a crash between the two can never leave metadata claiming coverage the
  source does not declare.
- **`rebrew catalog` refreshes its own `function_structure.json`**: the
  compatibility export was written once (`not exists()` guard) and never
  refreshed, so re-discovery left a stale structure cache diverging from
  the freshly-written data JSON.  Catalog-generated entries are now stamped
  `_generated_by: "rebrew catalog"` and refreshed on re-run, while a REAL
  Ghidra export (no marker) is never overwritten.
- **`verify --watch` picks up files created during the session**: the
  watched set was captured once at startup, so a `.c` generated mid-session
  (e.g. `rebrew skeleton` for a newly discovered function) was never
  covered.  `watch_files` gains an optional `path_provider` that re-resolves
  the set every poll; verify passes one.
- **GA / flag-sweep "matches" are now validated like test/verify before
  promoting**: both the batch flag sweep and the GA splice promoted
  EXACT/RELOC on the reloc-masked score alone (`score_candidate` masks
  every reloc slot, so a candidate differing only in a call/mov
  displacement scored 0.0 without checking the reloc TARGET against the
  catalog).  A wrong-callee source could be promoted and immediately
  demoted by the next test/verify.  Each match is now confirmed with an
  authoritative `compile_and_compare` (with `name_to_va` + `section_va`)
  before STATUS is touched; unconfirmed sweeps report the flag and skip
  promotion.
- **`rebrew match` STATUS promotions now sync the verify cache**: the GA
  splice (STUB → RELOC) and batch flag-sweep EXACT promotion previously
  left `.rebrew/verify_cache.json` holding the stale pre-match entry, so
  `rebrew status`/`todo` contradicted the fresh metadata until the next
  full verify.  Both now call the shared `patch_verify_cache_entries`
  (identity-checked + cross-process locked), the same helper `rebrew test`
  uses — one implementation behind every promotion site.
- **`rebrew verify` labels pre-compile failures correctly**: an `INVALID_VA`
  (below the valid floor) was reported as COMPILE_ERROR — a bogus "compile
  error" in the summary that tripped the CI gate as if the source failed
  to build.  It now has its own `INVALID_VA` status (ranked with the
  MISSING_* annotation problems), and "Cannot extract DLL bytes" is
  `EXTRACT_ERROR` (the stage label compile.py already uses), so neither
  blames the `.c` file.
- **`rebrew skeleton --decomp-body` without `--decomp` is rejected**: the
  flag was accepted-but-inert, silently producing a plain stub.  It now
  fails with "requires --decomp" and writes nothing.
- **Legacy-encoded `.c` sources compile again**: sources are read with
  `decode("utf-8", errors="surrogateescape")` (lossless for cp1252/
  shift_jis bytes), but the compile-cache key re-encoded with strict
  `utf-8` — raising `UnicodeEncodeError` for any non-UTF-8 source, which
  `compile_and_compare` mislabeled as COMPILE_ERROR.  Every legacy-encoded
  file was permanently untestable and `verify` demoted its STATUS.  The
  digest now round-trips with `errors="surrogateescape"`.
- **`rebrew intake` on an existing project no longer resets the corpus**:
  re-discovery called `classify_all` with every function, writing
  STUB + auto-blocker for each — silently demoting EXACT/RELOC/
  NEAR_MATCHING back to STUB and clobbering user-written BLOCKERs
  (the `size` write already had a "never clobber" guard; status/blocker
  did not).  Non-STUB entries are now skipped and user blockers survive.
- **`rebrew test file.c --va X` promotes under the right module**: with
  `--symbol` given, the VA-based annotation selection was skipped entirely,
  so SIZE/CFLAGS/STATUS were written under the FIRST annotation's module —
  a phantom `(first_module, X)` key while the real entry stayed stale in
  multi-module files.  VA selection now happens unconditionally.
- **`rebrew split` (full mode) validates all outputs before writing any**:
  the interleaved check-then-write aborted mid-batch on the first existing
  output, leaving earlier blocks written — and every re-run then failed on
  block 1's now-existing file, so the split could never complete without
  `--force`.  Two-phase: every conflict is reported up front, nothing is
  written on any conflict (rename.py's pattern).
- **verify-cache patching is identity-checked and locked**: `rebrew test`
  patched `.rebrew/verify_cache.json` by VA only — in a multi-target
  project, `test -t CLIENT` could patch entries a `verify -t SERVER` wrote
  (and the next SERVER verify would serve CLIENT's status).  The patch now
  verifies the cache's target + compiler identity, and both the patch and
  `verify`'s save run under a shared cross-process lock (mirroring
  metadata.py's flock discipline).
- **`rebrew switch` stops at non-image table entries**: the case walk now
  halts at the first dispatch-table entry that is not a code address in the
  image, even when a bounds check suggests more — a misread/over-estimated
  `cmp reg, N` previously dragged garbage into the case list (observed on
  the mspaint corpus: a table with 7 real cases but a `cmp 0xb` bound).
- **`rebrew skeleton` warns on merged discovery entries**: a `functions.txt`
  entry that spans several functions (multiple ret-terminated epilogues
  within the declared size — e.g. the mspaint corpus's 53B entry covering
  three tiny functions) is flagged with "spans multiple functions — split
  into per-function files", so the user doesn't treat a merged region as
  one decomp target.  Single functions (including early-return bodies) are
  unaffected.
- **GA STATUS promotion runs only after the source write succeeds**: in
  `update_stub_to_matched` the `update_source_status(…, "RELOC")` call ran
  BEFORE `atomic_write_text` — a failed write (disk full, read-only dir)
  left `rebrew-function.toml` claiming RELOC on a `.c` whose body was still
  a stub, a false green until the next verify self-healed.  The promotion
  now happens after the write, matching the function's documented contract.
- **`rebrew verify` no longer counts tooling crashes as code regressions**:
  a worker exception now gets its own `INTERNAL_ERROR` status — excluded
  from the `--compare` regression/improvement classification and from the
  code-failure list, so a transient crash on a previously-EXACT function
  can never fail the CI gate as a false code regression.  The count is
  still surfaced in the run report.
- **`rebrew test` (multi-function) labels post-compile failures
  EXTRACT_ERROR instead of crashing the batch**: a LIEF raise on a
  malformed `.obj`, or a VA yielding no target bytes, previously aborted
  the whole file with a traceback (no JSON, wrong exit).  Each symbol now
  records an `EXTRACT_ERROR` row and the batch continues, mirroring
  `compile_and_compare`'s stage labeling.
- **`rebrew test` metadata writes are no longer silent**: the SIZE/CFLAGS
  persistence sites used `contextlib.suppress(Exception)` — a failed write
  (read-only metadata, corrupt TOML) was invisible while downstream
  `rebrew diff`/`verify` later failed with no link to the cause.  They now
  log a warning naming the VA and the consequence, matching `verify`'s
  metadata-write handling.
- **`iat_slot_vas` failures are surfaced**: the LIEF IAT scan swallowed
  every exception and returned `set()` — indistinguishable from "no IAT",
  which silently disabled IAT reloc masking and demoted true RELOC matches.
  A raised failure now logs a warning.
- **`rebrew verify` cache invalidation now covers the whole package**: the
  verify-cache logic hash was a hand-maintained list of six modules that had
  already drifted (reloc validation, IAT masking, flags, compiler env are
  all result-affecting but unlisted).  It now hashes the entire `rebrew`
  package source, so a fix to any comparison-affecting module invalidates
  caches written by the pre-fix build.
- **Batch GA degradations are visible**: flag-sweep failure (falling back to
  stub cflags), solution-list load failure (disabling `--seed-from-solved`),
  and per-stub seed lookup failure were logged at DEBUG — invisible in the
  headline `rebrew match --all` workflow.  All three now log at WARNING, so
  a run that was not sweep/seed-informed says so.
- **`build_name_to_va` scan failures are surfaced**: the global/function
  catalog scan returned `{}` on any failure — indistinguishable from
  "nothing to validate", so verify/test silently skipped reloc validation
  and wrong-callee calls could pass as RELOC.  The failure now logs a
  warning naming the cause.
- **`rebrew analyze` no longer aborts the whole dossier on an import record
  without `iat_va`**: the entry list did an unguarded `rec['iat_va']` —
  a KeyError/TypeError there escaped the per-section guards and the caller
  reported "Analyze failed", violating the module's contract that one
  broken backend never aborts the others.  The field now defaults to 0.
- **`rebrew verify` uses bounded pool submission**: it previously submitted
  every entry to the ThreadPoolExecutor up front — the exact pattern
  flag_sweep was deliberately changed away from (compiler.py).  It now
  submits `jobs` at a time and refills as each completes, so memory stays
  proportional to the worker count, not the corpus size (thousands of
  futures on large batches).  A regression test covers batches larger than
  the worker count.
- **`load_ga_runs` keeps only the newest `limit` records**: the GA-run log
  reader held the entire (unbounded, append-only) history in memory before
  trimming to `limit` — `--ga-history` and batch `--skip-recent` read it
  every run.  A bounded deque (applied after target filtering, so "limit"
  still means "up to limit records for this target") bounds memory without
  changing results.
- **`rebrew describe` scans `.text` once instead of twice**: the dossier
  ran `scan_references` for callers/globals/imports and then `string_refs`
  re-ran the same full-section disassembly for the strings section.  The
  string refs are now filtered from the already-computed reference pass
  (identical output, verified by an equivalence test) — a per-dossier
  full-`.text` disassembly saved on every `describe`/`analyze --function`
  call.

- **Tail-calling functions no longer misclassified as pure thunks**: a
  function whose jmp-terminated disassembly has a real body (>2 insns) is
  now classified `tail call` — a forwarding function — instead of
  `tail-call thunk` (the "implement as a naked asm tail-jump" note was
  wrong for it).  `rebrew skeleton` resolves the jmp target's decorated
  name (`name@N`, via the function lookup) to emit the correct
  `int __stdcall f(int a1, ...)` signature with a "N stack arg(s)
  forwarded" note; unresolved targets get a plain signature + guidance.
  Pure 1-2 insn thunks (`jmp [IAT]`, `mov ecx,imm; jmp`, `push; jmp`)
  keep the thunk classification.
- **Toolchain round-trip tests run ~14x faster with wibo**: the suite's
  compile tests hardcoded `wine`; they now prefer wibo when available
  (headless, no wine boot — the round-trip suite dropped 23.3 s → 1.6 s)
  and fall back to wine.  CI installs wibo best-effort before the test
  job, so the recommended runner is exercised in CI and the suite stays
  fast there.  `tools/wibo` is now gitignored.
- **Fresh skeletons classify as STUB, not a bare SIZE_MISMATCH**: a minimal
  candidate body (the skeleton's default `return 0`, ~3-8 bytes) against a
  much larger target is an unimplemented stub — `rebrew test` now reports
  STUB with a message naming both sizes ("the skeleton default was never
  implemented") instead of a confusing SIZE_MISMATCH.  Genuinely tiny
  functions byte-match (EXACT/RELOC) and never hit this path; near-size
  mismatches still report SIZE_MISMATCH.  `classify_compare_result` gained
  a `full_target_size` kwarg (the caller truncates the longer side before
  classifying, so the original lengths must be threaded explicitly).
- **`rebrew skeleton` warns on stale sizes**: the generated file's size (and
  the `--size N` in the suggested test command) comes from the Ghidra cache
  / function registry, which can hold a stale `functions.txt` entry.  When
  the disassembly extent runs past the resolved size, skeleton now warns
  with the real extent and points at `rebrew asm --size <extent>` /
  `rebrew test --fix-size` — previously the first `rebrew test` failed with
  SIZE_MISMATCH on a truncated size and the user had to rediscover the
  discrepancy by hand.  JSON output gains a `size_warning` field — in
  single-VA mode and per item in `--batch` mode (with a console warning
  line per stale function).
- **GA/flag-sweep never accepted RELOC matches**: `score_candidate`'s byte
  score counted relocation bytes as raw mismatches, so a candidate whose
  only diffs were at reloc sites (linker-determined call displacements)
  sat at a fitness floor of ~N×1000 and the `exact: score < 0.1` gate
  never fired — the GA kept mutating a byte-perfect candidate and flag /
  toolchain sweeps reported no match for RELOC-able functions.  The reloc
  mask now applies to the byte score too; a reloc-only match scores ~0 and
  is accepted.  Real mismatches outside reloc sites still count.
- **`rebrew asm` detects stale function-list sizes**: a size that truncates
  the function mid-code (stale `functions.txt` entry) now warns and extends
  the dump to the disassembly extent — previously the dump silently ended
  mid-instruction, which also broke the calling-convention inference
  (truncated window → "unknown" → wrong skeleton signature).  An explicit
  `--size` is honored (warn-only); the JSON report gains a `stale_size`
  field (`requested_size` keeps the pre-extension value).  x86-32 only —
  the extent walker is an x86 disassembler.
- **`rebrew skeleton` convention stub no longer truncates long functions**:
  the calling-convention window was a flat 48 bytes, so a function whose
  real body extended past it got the wrong default (`__cdecl` instead of a
  thiscall/stdcall shape — e.g. an MFC `ret 0x10` method with a 100+ byte
  body was emitted as `int __cdecl f(void)`).  The window is now the
  disassembly extent: exact when it terminated on a `ret`, padded past a
  mid-function branch-merge `jmp` (small ≤16 B jmp regions stay exact —
  they are real tail-call thunks).  `function_extent_from_disasm` gained a
  non-breaking `with_kind=True` returning `(extent, "ret"|"jmp")`.
- **Relative runner paths now anchor to the project root**: the config
  shape `rebrew init --install-wibo` writes (`runner = "tools/wibo"`,
  command without the runner prefix) previously broke under the temp
  compile workdir with "No such file or directory: 'tools/wibo'".  Both
  the `rebrew compile` path and the GA/flag-sweep path (via
  `REBREW_COMPILER_RUNNER`) resolve relative runner paths against the
  project root now, and `WINEDEBUG` is set by runner basename
  (`tools/wibo` is still wibo).
- **`rebrew doctor` false "CL.EXE not found"**: the Compiler check now
  honors the install-tools fallback used by `resolve_cl_command`, so
  projects without a local `tools/` symlink (fresh `rebrew init`, no
  `--link-tools-from`) report the compiler as reachable instead of a FAIL
  that contradicts working compiles.
- **`rebrew skeleton` emits calling-convention-aware stubs**: the generated
  skeleton now matches the target's convention instead of always being
  `int __cdecl f(void)` — `int __fastcall f(void *self)` for thiscall with
  no stack args, a `__declspec(naked)` template (with `ret N`) for
  thiscall-with-stack-args on MSVC 5.0 (no `__thiscall` keyword), and
  `int __stdcall f(int a1, ...)` for stdcall with N args.  Thunks get a
  note pointing at the naked tail-jump.  For MFC-heavy binaries (most
  functions are thiscall) this removes the per-function signature rewrite.
- **`rebrew asm` calling-convention inference**: both the hex dump and
  `--json` now report the function's calling convention (cdecl / stdcall /
  thiscall / thiscall-with-no-stack-args / ctor thunk / EH-guard thunk),
  derived from the epilogue (`ret` vs `ret N`) and this-pointer usage (ECX
  dereferenced or saved to a callee-saved register without a prior memory
  load).  This is the per-function answer that decides the C signature —
  `__stdcall`, `__fastcall` this-emulation, or naked asm for
  thiscall-with-stack-args on MSVC 5.0 — before writing any code; it was
  previously re-derived by hand from every function's epilogue.
- **MSVC optimization-level fingerprint**: `detect_toolchain` now inspects
  .text for wrapper-call codegen and reports the optimization level the
  binary was built with — `/O2` (load-first `mov eax,[esp+4]; push eax` +
  `add esp,N`) vs `/O1` (push-[mem] `push dword [esp+4]` + `pop ecx`), or
  `mixed` when both styles appear (per-file /O overrides, common in MS
  products).  `/O1` vs `/O2` change wrapper codegen, so the wrong level
  silently breaks byte-matching at every wrapper call site.  Surfaced in
  `rebrew analyze`, seeded into `rebrew init`'s compiler cflags, and
  checked by a new `rebrew doctor` Optimization-level check (warns on
  mismatch, suggests per-function flag sweeps for mixed builds).
- **`rebrew test --fix-size`**: corrects a stale SIZE annotation when ALL
  common bytes match — writes the compiled size into `rebrew-function.toml`
  and reclassifies as EXACT/RELOC (with promotion) in one command, instead
  of surfacing a `SIZE_MISMATCH` the user must resolve by hand.  Works in
  both the single-function and multi-function paths; `--dry-run` previews;
  file-scoped (batch repair stays `rebrew verify --fix-sizes`).  `CompareResult`
  gains `full_obj_size`/`full_obj_bytes` so the SIZE_MISMATCH path reports
  the real compiled length in JSON/display instead of the common-prefix
  slice, and the SIZE_MISMATCH hint now points at `--fix-size`.  The fix is
  gated on an evidence check: when the compiled function is longer than the
  annotated slice the binary is re-extracted at the compiled size and the
  newly visible bytes must match; when it is shorter the excess annotated
  bytes must be padding — a false fix (partial decompilation matched only
  over the prefix) would otherwise write a size that hides unreproduced
  code.  When those checks refuse (a discovery boundary merged the NEXT
  function into the annotation, so the excess bytes are real code), the
  gate falls back to the disassembly extent — the authoritative function
  end via `binary_loader.function_extent_from_disasm` — and fixes only if
  it agrees with the compiled size.  This automates the merged-boundary
  thunks (e.g. `mov ecx,X; jmp Y` ctor stubs) that previously needed a
  hand-supplied `--size`.
- **watcom is POSIX-style**: `ProjectConfig.posix_style` now includes
  watcom (wcc386 takes `-I`/`-fo=`/`-zq`).  Previously the flag routing
  treated it as MSVC-style and prepended `/nologo /c` glue — wcc386 then
  failed with "E1139: more than one file to compile" in `rebrew diff`
  (which also wasn't passing profile/cfg to the toolchain-backed compile
  runner).  diff/match/compile now route watcom through the shared
  `compile_to_obj` runner; verified test/diff/GA-sweep on a watcom
  project.
- **verify: 16-bit NE targets with the msvc1.52 profile now run the full
  pipeline** — the old gate short-circuited every NE target with a stale
  "16-bit matching is future work (ADR-001)" notice, silently hiding the
  DOSBox compile + omf16 object pipeline.  The skip now fires only when
  no 16-bit profile (`msvc1.52`) is configured, with a message naming the
  required profile.  Verified on the skifree16 NE project: 137 functions
  compile through DOSBox with 0 COMPILE_ERROR (was: skipped entirely).
- **IAT/jmp-stub reloc masking**: `build_iat_region` now also includes
  the configured `iat_thunks` (jmp-stub trampolines, `ff 25 <addr>` in
  `.text`) — functions calling *through* a stub dereference the stub
  address, not the IAT slot, so those DIR32 values must be masked too.
  `smart_reloc_compare` masks any DIR32 whose target lands in the merged
  region even when the catalog symbol maps elsewhere.
- **IAT-aware reloc masking**: `smart_reloc_compare` accepts an
  `iat_region` (the PE import-address slots, via new `build_iat_region`)
  and masks DIR32 relocs whose target value lands there even when the
  catalog maps the symbol to a different VA — swapped ordinal import
  names (e.g. WS2_32 WSAStartup/WSACleanup) no longer demote a RELOC
  match into a byte mismatch.  Fixes the guild-rebrew CreateListenSocket
  regression (NEAR_MATCHING → RELOC, 411/419 → 419/419).
- **Toolchain standardization (docker-first)**: `rebrew.toolchain` — a
  uniform spec registry + runner modeled on Godbolt's Compiler Explorer
  (one image per toolchain-version, wrapper inside the image, uniform
  `docker run <image> <compiler> <args>`; host-path/PATH fallback when
  docker or the image is unavailable), the `rebrew toolchain` CLI
  (`list`/`status`/`pull`), and `toolchain-images/<name>/Dockerfile` build
  specs.
- **Open Watcom profile**: Open Watcom 2.0 installed at `tools/WATCOM`
  (native Linux `wcc386`, verified compiling; emits OMF objects — the OMF
  parser is the documented enabling follow-up in `docs/OMF_NOTES.md` with
  the empirically-mapped record layout).
- **MSVC 1.52 (16-bit) profile**: `tools/MSVC152` (archive.org
  `en_vc152_202512`) + `rebrew.msvc16.compile_c` — the Phar Lap TNT
  CL.EXE runs headless under DOSBox via the new shared `rebrew.dosbox`
  runner (refactored out of `delphi16`), producing 16-bit OMF objects.
- **Detection hints**: Symantec C++ / Zortech C++ / Intel C++ families
  identified from runtime strings (dossier + blocker wording); Watcom
  family now aligns with the `watcom` profile in doctor; `msvc1.52` joins
  the msvc-compatible profile set.
- **Watcom flag sweep**: `generate_flag_combinations` supports the watcom
  profile (wcc386 `-`-style flags: opt/codegen/pack/flat axes) — the GA's
  `--flag-sweep` works for watcom projects.
- **doctor toolchain check**: generic `check_toolchain_backed` reports how
  the watcom/msvc1.52 toolchains resolve (vendored binary / pulled image)
  with a `rebrew toolchain pull` fix — no more misleading "not in PATH"
  for vendored compilers.
- **msvc1.52 compile-loop prefers the docker image** (cl16 wrapper) when
  pulled, falling back to the host DOSBox sandbox; FAT-uppercased .OBJ
  handled in compile_to_obj.
- **16-bit OMF parser** (`rebrew.matcher.omf16`): MSVC 1.52's OMF dialect
  (objconv crashes on it) decodes code from `0xA0` records + publics from
  MODEND — `parse_obj_symbol_and_relocs` extracts 16-bit function bytes
  (relocs `{}` pending 0x8C/0xB2 fixup decoding).
- **Symbol lookup across compiler conventions**: `parse_obj_symbol_and_relocs`
  tries `_name` / `name_` / `name` variants — the annotation layer derives
  MSVC-style leading-underscore symbols, but wcc386 emits trailing
  underscores (`callg_`); validated end-to-end with a watcom `rebrew test`.
- **Watcom usable in the compile loop**: `rebrew compile` routes the
  `watcom` profile through the toolchain runner (wcc386 `-fo=`/`-I` shape,
  docker image or vendored binary) and `msvc1.52` through
  `rebrew.msvc16` — `rebrew test`/`verify` now work for those targets.
- **Docker-first toolchain verified**: `rebrew/watcom:latest` image built
  from `toolchain-images/watcom/Dockerfile` (snapshot tarball — the
  installer SIGFPE workaround); `run_toolchain` compiles through it with
  byte-identical results to the host path (same reloc offsets).  Image
  entrypoint convention documented (`image_binary=None` = ENTRYPOINT is
  the compiler).
- **OMF support via objconv**: vendored `tools/objconv` (Agner Fog's
  object-file converter) converts OMF→COFF, so `parse_obj_symbol_and_relocs`
  now handles **Open Watcom 32-bit OMF** objects transparently (reloc
  offsets verified on the e8/a1 slots of a real wcc386 object).  objconv
  crashes on 16-bit OMF — MSVC 1.52 matching still needs the custom 16-bit
  parser (docs/OMF_NOTES.md).
- **ADR documentation**: architectural decisions now recorded in
  `docs/adr/` (Nygard format) — native NE parsing, NE function-enumeration
  conventions, the import-degradation policy, intake stale-stub pruning,
  and toolchain-detection ordering; the convention itself is in
  `AGENTS.md` so it stays maintained.
- **16-bit Windows NE support** — `holiday.exe` (Borland Delphi 1.0,
  NE 6.01) can now be onboarded and analyzed end-to-end:
  - `rebrew.ne_loader`: NE header/segment-table/resident-name/module-table
    parsing; segments map to `BinaryInfo` sections with synthetic flat VAs
    (`segment << 16 | offset`); a capstone probe classifies code vs data
    segments (Borland marks all segments identically).
  - `load_binary` parses NE natively (the old "16-bit not supported"
    rejection is gone); `x86_16` arch preset (CS_MODE_16) drives asm/similar/
    cu_map.
  - `enumerate_ne_functions`: Delphi 1.0 linear sweep (push bp / enter
    prologs, ret/retf epilogs) — 646 functions on holiday.exe.  `rebrew
    intake` uses it for NE targets instead of rizin.
  - `iter_strings`: NE targets scan data segments and recognize Pascal
    (length-prefixed) strings — holiday.exe yields 3739 strings (German UI).
  - `rebrew analyze` reports NE imports as module blocks and the toolchain
    family (delphi).
- `rebrew intake` fixes: skips `rebrew init` when the project already exists
  (idempotent re-runs), and `classify_all` batches its metadata writes
  (set_fields_batch + update_statuses_batch) — a 646-function intake dropped
  from ~5 minutes (timeout) to 3 seconds.
- `rebrew verify --fix-sizes` now backfills **missing** annotation SIZEs,
  not just stale ones: intake/documented stubs without a SIZE (which
  `rebrew test` refused with "Invalid SIZE: 0" and verify reported as
  MISSING_SIZE forever) get the binary-derived canonical size written into
  metadata.  Reported separately as `missing_sizes` in the JSON report.
- `rebrew intake` / `rebrew document-unmatched` record the
  disassembly-derived SIZE in metadata when documenting stubs, so newly
  documented functions are testable out of the box.
- `rebrew todo` no longer surfaces a MISSING_SIZE stub's vacuous 0-byte
  delta as a fake "0B diff" fix-delta quick-win — it classifies as
  missing-annotation with the `rebrew verify --fix-sizes` self-heal
  command.  IAT thunks / Delphi stubs (blocker-marked documented
  non-targets) move to a new audit-only `documented` category, hidden from
  the actionable list but visible via `rebrew todo -c documented` and
  counted in coverage stats / JSON.
- `rebrew analyze <binary>` now works **standalone outside a project** —
  the binary argument becomes required when no `rebrew-project.toml` is
  found. Project-scoped sections (FLIRT sigs, library headers, near-match
  metadata) degrade to `null`/`[]` instead of aborting, so the dossier is
  usable as the first intelligence step on an unknown binary (the use
  case it was built for). Clear error when neither a project nor a binary
  is given.
- `rebrew document-unmatched` — standalone version of intake's
  document-unmatched step: writes a STUB `.c` + BLOCKER/STATUS=STUB
  metadata for every function in the function list that isn't already
  documented (skips VAs with a `fcn_<va>.c` file or a FUNCTION/STUB
  marker; idempotent; `--dry-run`/`--json`).  Replaces the per-project
  classify scripts (bench/cpubench/makehm/openmiles) for re-discovery
  workflows.  The shared writers (`classify_all`/`blocker_reason`) were
  promoted to public in `rebrew.intake`.
- Vendored the Borland **Delphi 1.0 16-bit command-line toolchain**
  (`tools/DELPHI10/`, exact compiler family for 16-bit Delphi apps like
  `holiday.exe`): the `CMDLINE.PAK` tools plus the compiler symbol table
  `DELPHI.DSL` (required — without it DCC reports a phantom
  "SYSTEM.DCU not found" even though no such file ships anywhere in the
  product; System/WinTypes/WinProcs resolve from the built-in symbol
  table). Proven working: `DCC.EXE hello.dpr` compiles a real 16-bit NE
  6.01 Windows 3.10 GUI executable that runs under wine.
- `tools/DELPHI10/pak_extract.py` — a from-scratch, stdlib-only decoder
  for the **Quantum archive format** (David Stafford / Cinematronics
  1993-95; also a Microsoft CAB method) reverse-engineered from the
  Delphi 1.0 floppies: arithmetic-coded LZ77, 9 adaptive models, 2^10-2^21
  window, split-archive support (`.CA1`+`.CA2` concatenation). Validated
  byte-for-byte against the original Quantum GUI output (16/16 files) and
  the independent `unquantum` reimplementation.
- `rebrew match`'s no-match exit now guides the user to `rebrew prove`
  (register/structural gaps are often PROVEN-able) and
  `rebrew near-diag --fix-blocker` (classify + document) instead of
  exiting silently.
- smygb fully resolved: `prove --loop-bound 50` promoted the last
  NEAR_MATCHING (0x00401410, a loop 'no terminal states' failure) —
  the project now has ZERO NEAR_MATCHING functions (EXACT 17 / RELOC
  26 / PROVEN 7). The prove guidance documents the loop-bound retry.
- 16-bit Windows NE executables are detected explicitly
  (`binary_loader.is_ne`) and rejected with a clear format-specific message
  instead of a misleading "Failed to parse PE". The path to full 16-bit
  support (NE parser, x86-16 disasm, MSVC420 compile profile) is documented
  in docs/TOOLCHAIN.md.
- `rebrew near-diag`'s register verdict suggestion now leads with
  `rebrew prove` (register gaps are usually PROVEN-able without byte
  changes — validated on the corpus: 9 NEAR_MATCHING promoted to PROVEN).
- `rebrew near-diag` mutation guidance now includes a significant secondary
  category's operators (>=15% of the delta, e.g. the register component
  under a STRUCTURAL verdict) — the dominant-only list missed the register
  fix entirely for mixed deltas.
- `rebrew diff` reports a **missing_tail** summary when the compiled
  candidate is shorter than the target: how many target instructions are
  not yet decompiled + the first/last missing instruction (JSON
  `missing_tail`, terminal hint) — turns SIZE_MISMATCH triage into an
  actionable "write these next" list.
- `rebrew analyze` dossier gains a **NEAR_MATCHING (blocked)** section —
  every NEAR_MATCHING function with its blocker guidance (verdict + GA
  mutation operators) in JSON, Markdown, and terminal output.
- `rebrew report` function table gains a **Blocker** column — near-diag /
  diff-written blockers (with their GA mutation suggestions) now appear in
  the static HTML index page, making the project's documentation carry the
  same guidance as `rebrew todo`.
- `rebrew match --mutation-focus register|equivalent|structural|auto` — bias
  GA mutation selection toward a near-diag category: the category's suggested
  operators (from `rebrew.near_diag._MUTATION_SUGGESTIONS`) get 6x selection
  weight. `auto` derives the category from the function's BLOCKER metadata
  (single-function mode). Closes the classify → focus → GA loop: near-diag
  writes the blocker, todo surfaces the mutations, match acts on them.
- `rebrew todo` exposes the GA mutation operators suggested by a
  near-diag-written blocker as a structured `mutations` field (JSON output)
  and a `[try: ...]` terminal hint — an agent working from `todo --json`
  sees the next GA operators without re-running near-diag.
- `rebrew near-diag --fix-blocker` now writes the top GA mutation operators
  into the `BLOCKER` metadata (before the suggestion prose) — a reader
  acting on the blocker sees the actionable next step without re-running
  near-diag. The suggestion's first sentence survives when the 200-char
  metadata budget allows.
- `rebrew near-diag --all [--fix-blocker]` — classify (and optionally
  auto-document as `BLOCKER` metadata) every `NEAR_MATCHING` function in the
  project in one batch run; per-function compile/extract failures are recorded
  and the batch continues (mirrors `rebrew prove --all`).
- `rebrew discover-functions <binary>` — chained function enumeration: rizin
  `aaa` → `aa; aap` → a capstone linear sweep (post-padding starts, `push ebp;
  mov ebp, esp` prologues, direct-call targets), merged with boundary
  validation (interior candidates dropped) and gap-based sizes trimmed of
  padding — fixing both rizin's garbled `aaa` merges and its short sizes
  (e.g. 34 → real 36).
- `rebrew lint` W020 is now status-aware: an asm-dump body (`__asm`/`__emit`)
  with a non-stub `STATUS` claim (EXACT/RELOC/...) escalates to "cannot be a
  byte-match — fix the STATUS or mark BLOCKER", telling documented STUB
  placeholders apart from claimed matches at a glance.
- `rebrew analyze` dossier gains a **library** section — which VAs are
  library glue (via the identify-library backends), in JSON + Markdown.
- `rebrew prove --all --max-delta N` — bound the batch to near-misses whose
  recorded byte delta is ≤ N, focusing Z3 time on the closest matches.
- `rebrew match --all-targets` splits `--jobs` across targets (parallel
  targets, per-target determinism preserved) when there is more than one
  target and jobs to share.
- `tools/verify_baseline.py` — committed-baseline regression gate
  (`--snapshot` / `--check`) over `db/verify_results.json`; exits 1 when
  byte-matched drops below the committed baseline.
- `docs/CAMPAIGNS.md` — record of bounded corpus matching campaigns
  (first entry: smygb pipeline smoke: skeleton → single GA → batch
  `--resume`; library pass wrote 28 entries across 6 module headers).
- Property tests for the new parsers: `apply_param_names`/`param_names_from_proto`
  arity/named-preservation invariants and `_module_from_sig_file` attribution.
- `rebrew near-diag --fix-blocker` — writes the verdict as `BLOCKER` metadata
  (skipped on a match), closing the classify → document loop.  Live-verified
  on smygb 0x401370 (register-gap blocker auto-written).
- `rebrew near-diag`'s register-category suggestions now include
  `mut_hoist_repeated_deref` (the kept-live-local operator).
- GA mutation `mut_hoist_repeated_deref` — hoists a repeated absolute-pointer
  deref (`*(T*)0xADDR` used N times) into a kept-live local.  Campaign-driven:
  the register-only NEAR_MATCHING gap on smygb 0x401370 (100% mnemonic match,
  21 register diffs) needs exactly this shape; documented in
  `docs/GA_MUTATIONS.md`.
- `rebrew skeleton --decomp-body` — writes the decompiled C as the function
  BODY (renamed to the marker's function) instead of a comment block, giving
  the GA a real seed when a decompiler backend is available.
- decomp.me flag DB re-synced (`tools/sync_decomp_flags.py`): no semantic
  changes since the last sync; all vendored toolchains still pass
  `tests/test_toolchain_roundtrip.py` byte-exact.
- `rebrew near-diag` now suggests the specific `mut_*` GA operators most
  likely to fix each blocker category (register/equivalent/structural) —
  advisory mapping surfaced in terminal + JSON `mutations`, documented and
  enforced (every category has operators, every operator exists).
- `rebrew sync --pull-params` — pulls Ghidra parameter names (via
  `get-decompilation`) into unnamed parameters of local `.c` files,
  merge-safe: named params never overwritten, arity mismatch / function-
  pointer params skipped.  Local names already flow back via
  `set-function-prototype` (push covered by existing tests).
- `tools/corpus_sweep.py` — run doctor/analyze/identify-library/status across
  every `*-rebrew` project; documented SKIPPED/BLOCKED projects (per AGENTS.md)
  are honored.  Corpus run found + fixed: `msvc5` missing from the
  profile-compat table (bind doctor failure) and hgb's undocumented Delphi
  blocker.
- `rebrew identify-library --build-sigs [--lib-dir]` — generates
  `flirt_sigs/<lib>_vc6.pat` from the toolchain's `.lib` files (case-insensitive
  `.LIB` glob; one corrupt lib never aborts the batch).  Measured on smygb:
  262 sig files, identification yield **6 → 28 (4.7×)**.
- Per-sig-file module attribution for FLIRT hits (`msvcrt_vc6.pat` → MSVCRT,
  `zlib_vc6.pat` → ZLIB) plus a zlib name-prefix fallback (`deflate`,
  `inflate`, `crc32`, ...).
- `rebrew solutions [--symbol S] [--min-size N] [--max-size N] [--best]` —
  query the GA solutions database; `--best` shows the best-known GA outcome
  per function from the run history.
- `rebrew match --llm-seed --dry-run` — previews the exact LLM prompt and the
  validated-seed count without running the GA (`--dry-run` single-function is
  now allowed only with `--llm-seed`).
- `rebrew match --all --resume` — per-function GA checkpoints (`GACheckpoint`
  in matcher/core.py, written every generation to `output/ga_runs/.../
  checkpoints/`); interrupted batches continue from the checkpointed
  generation, rejected when source/params changed (args_hash).
- Corpus-driven fixes (found running the new tools on the smygb corpus
  project): `rebrew analyze` crashed on real binaries with dispatch tables
  (`DispatchTable` fields renamed) — now emits `entries`/`resolved`/`section`
  and is regression-tested; `rebrew identify-library` labeled DirectX imports
  as MSVCRT — import-stub modules now come from the import table's DLL
  (DDRAW → DDRAW, KERNEL32 → KERNEL32) with the name heuristic as fallback.
- Docs-hygiene meta-tests (`tests/test_docs_hygiene.py`): every lint code
  emitted by `lint.py` must be documented in `docs/ANNOTATIONS.md`, and every
  registered CLI command must have a `docs/CLI.md` section — drift is caught
  in CI.  Fixed the gaps it found (CLI.md gained `asm`/`imports`/`resource`/
  `status` sections) and refreshed `docs/IDEAS.md` (done items marked,
  completed backlog appended).
- Recoverage schema-parity contract test (`tests/test_recoverage_contract.py`):
  runs the real `catalog --data-json` → `build-db` pipeline on the fixture
  binary and asserts the SQLite schema has every table/column the recoverage
  dashboard queries (cells `label`/`parent_function`, `verify_results`,
  `section_cell_stats` view) — a rebrew change that would break the dashboard
  is caught in rebrew's own suite.
- GA scoring fast paths in `score_candidate` (behavior-identical): identical
  bytes skip candidate disassembly entirely; mnemonic-equality (the GA's
  common immediates-only-differ case) skips `SequenceMatcher`'s setup.  Measured
  1.76× faster on a realistic 5000-candidate mix; documented in
  `docs/PERFORMANCE.md` along with what was tried and rejected.
- Idempotency sweep extended: `tools/check_idempotency.py` now covers all 16
  offline `--json`/`--dry-run` commands (mirroring `tests/test_json_purity.py`),
  gains a `--fixture-dir` mode that assembles the checked-in fixture project,
  and runs as a CI step after the test suite.  (The CI test matrix already
  exercised 3.12/3.13/3.14.)
- `rebrew analyze --output report.md` — writes the dossier as a Markdown
  report; `--function 0xVA` drills into one function (callers, callees,
  strings, globals, imports via `describe`); `--output` + `--json` is an
  explicit error.
- Ghidra sync enum support: `struct_parser.extract_enums_from_file()` pulls
  `enum`/`typedef enum` definitions, `rebrew sync --sync-structs` pushes them
  through Ghidra's `parse-c-structure` CParser, and `--pull-datatypes` re-pull
  is now **merge-safe** (a user section between the marker and `#endif`
  survives regeneration) and byte-identical on re-pull.
- `rebrew identify-library` — combined library-identification pass: runs
  CRT source matching (strongest, with SOURCE metadata for ≥0.85 confidence),
  FLIRT signature scanning (ambiguous matches never guessed), and IAT
  import-stub detection, merges by VA with provenance ranking, and writes new
  `// LIBRARY:` entries to `library_<module>.h`.  Idempotent — VAs already
  annotated anywhere are skipped.  Also extracted a shared
  `flirt.match_text()` scan helper (used by `flirt`, `analyze`,
  `identify-library`).
- `rebrew match --all --seed-solutions <path>` — cross-project solutions
  seeding: merges another project's `.rebrew/solutions.json` (deduped by
  target+symbol, local wins) so same-size functions start from proven
  cflags when the source file doesn't resolve locally, and from the source
  file when it does.  Batch JSON reports `seeded_cflags`.
- Property-based round-trip tests for the typed metadata facade
  (`tests/test_metadata_model.py`): any valid field set survives
  `MetadataEntry.apply → load` exactly, and every known STATUS round-trips
  through the promotion gate — the "impossible by construction" proof for the
  field-routing bug class (add-module tomlkit persistence, lint `--fix` STATUS).
- `rebrew analyze [BINARY]` — one-shot intelligence dossier: binary layout
  and sections, layered toolchain detection (DIE → PDB → heuristics), string
  census with cross-reference counts, import table + IAT stubs, a
  code-reference profile, reversed-function coverage, dispatch-table
  detection, and FLIRT library identification (when the project has
  `flirt_sigs/`).  Every section is best-effort — a missing PDB, diec, or
  sigs dir skips only that part; `--json` stays pure JSON.
- `rebrew status` now surfaces the **effective status** overlay explicitly:
  terminal output reports how many functions the verify cache overrode and
  how many are stuck on `MISSING_SIZE` (set SIZE via metadata, re-verify);
  JSON gains `verify_cache: {overrides, missing_size}`.  The overlay rule
  (PROVEN wins, STUB is sticky, everything else follows the cache) is
  documented in `docs/ANNOTATIONS.md`.
- `rebrew init` ergonomics: `--binary original/bench.exe` no longer produces
  `original/original/bench.exe` (a leading `original/` prefix — either slash
  direction — is stripped), and the new `--link-tools-from <dir>` symlinks the
  profile's vendored toolchain (`tools/MSVC600`, `tools/msvc6.3`, ...) from a
  master toolchain directory in one step.
- `rebrew doctor` now knows how to fetch every profile toolchain: the
  missing-`CL.EXE` fix hints carry the decomp.me mirror URLs for
  msvc6.3/6.6/7.0, the archaic-msvc codeload URL for MSVC500, and the
  OmniBlade wcc tarball for Watcom.
- Toolchain detection now recognizes **Watcom C/C++** (`_TEXT`/`_DATA`/`_BSS`
  sections, runtime strings) and **Borland C/C++** (`CODE`/`DATA`/`BSS` +
  CW32/CC32/BORLNDMM runtime imports or Borland strings, without Delphi RTL
  markers) — DIE name mapping, version hints, and structural heuristics all
  extended.  `rebrew doctor` flags these families as blocker-documentation
  cases (no matching profile yet).
- Property tests for the catalog/grid edge-case parsers
  (`tests/test_property_parsers.py`): `_lookup_section`/`_build_section_index`
  and `_find_ghidra_data_label`/`_build_label_index` verified against a
  linear-scan reference over random non-overlapping sections/labels,
  `count_statuses` priority invariants, and `generate_data_json`
  reorder-invariance (shuffling the entries/funcs input must not change the
  coverage grid) — the last running end-to-end against the fixture PE.
- `tests/test_json_purity.py` — pins the ``--json`` stdout contract across
  the offline CLI surface (status/strings/imports/asm/describe/xrefs/verify/
  todo/lint/data/doctor/cache/cfg/flirt): stdout is exactly one JSON document,
  progress chatter ("Scanning...", LIEF logs, warnings) stays on stderr.
  Runs against the checked-in fixtures — no wine or toolchain needed (15 tests).
- Checked-in binary fixtures (`tests/fixtures/`, rebuilt by
  `tools/gen_fixtures.py`): a tiny synthetic COFF `.obj` (two functions,
  DIR32 + REL32 relocs), a matching PE and ELF32, and a `.lib` archive.  A
  freshness test regenerates them in-memory and asserts byte-identity, so the
  parse/compare/reloc paths — and the `gen_flirt_pat` → `flirt` pipeline —
  run end-to-end in CI without wine or a vendored toolchain (16 new tests).
- `rebrew match --sweep-toolchain` — compile the function with each vendored
  MSVC toolchain (point-version SPs) and report which byte-matches best,
  answering "which MSVC build produced this function" in one run.
- `rebrew pdb-info <binary>` — extract compiler version (S_COMPILE3 frontend/
  backend), the exact compiler flags (auto-writable to `[compiler] cflags` via
  `--write-cflags`), a Zig marker, and best-effort function names from a
  sibling PDB.  Gracefully reports unsupported formats (classic VC2–6 PDBs,
  llvm-pdbutil's VC7 crash) instead of failing.
- `rebrew intake <binary>` — one-shot binary onboarding: toolchain detection
  → init with a matching profile → copy binary → symlink vendored toolchain →
  rizin functions.txt (`aaa`/`aap` fallback) → document every function with a
  STUB .c + metadata blocker.  Produces a lint-clean project ready for the
  per-function decomp loop (consolidates the per-project classify scripts).
- `msvc5` compiler profile (VC 5.0) backed by the archaic-msvc toolchain
  (`tools/MSVC500`), validated byte-exact against a real Microsoft VC5.0
  binary (BIND.EXE table-walker → EXACT).
- `msvc420` profile now has a toolchain (archaic-msvc `tools/MSVC420`);
  both added to `tests/test_toolchain_roundtrip.py` (5/5 EXACT).
- `msvc6.3` and `msvc6.6` compiler profiles (decomp.me SP3/SP6 point-version
  toolchains — codegen differs across MSVC 6.x SP levels), and the `msvc7`
  profile now has a real toolchain (decomp.me `msvc7.0`).  Each is proven by
  `tests/test_toolchain_roundtrip.py` (compile → compare → EXACT).
- Config: an *explicitly empty* `compiler.includes`/`libs` is now allowed for
  any profile (decomp.me MSVC tarballs ship Bin+Include but no Lib); a missing
  key still falls back to the conventional default path.
- Toolchain detection (`rebrew doctor` "Toolchain alignment" check) —
  layered DIE (`diec`) / PDB (`llvm-pdbutil`) / structural-heuristics
  detection of the target's compiler family + version + (PDB) flags, with a
  fail/warn when the configured `[compiler] profile` cannot byte-match the
  detected family (e.g. Delphi binaries, Zig under gcc-pe).
- `gcc-pe` compiler profile — MinGW GCC (i686-w64-mingw32) for non-MSV C
  PE/x86_32 targets: POSIX-style flag routing (`-I`/`-c`/`-o`) in the
  compile/diff/match paths, PATH resolution of bare toolchain names, empty
  `includes`/`libs` allowed.  `rebrew init --compiler gcc-pe` sets it up.
- `rebrew cfg set <target-scoped-key>` now routes bare keys (e.g. `binary`,
  `marker`) to `[targets.<default>]` instead of silently writing a top-level
  key the config reader ignores.

- **16-bit NE support for MSVC-built targets** (the original 1991 SkiFree):
  `is_ne` read only the first 0x104 bytes, but the MSVC 16-bit linker places
  the NE header at `e_lfanew` = 0x400 (Borland uses 0x40) — NE binaries were
  silently misdetected as PE and enumerated by rizin into garbage.  `is_ne`
  now seeks to `e_lfanew`; `probe_is_code` skips the Borland `[index\x00]`
  marker only when it is actually present; `enumerate_ne_functions` treats a
  markerless segment's start as a function boundary (MSVC 16-bit entry code
  opens `push ds/pop ax/nop/inc bp`, not `push bp`), recovering the entry
  function (ski16.exe: 137 funcs vs 233 garbage; holiday.exe unchanged at
  1783).
- `rebrew intake` re-discovery (project already exists) now prunes
  auto-generated STUB files + metadata for functions absent from the new
  function list — a changed enumeration (rizin update, NE fix) previously
  left orphaned stubs that inflated `rebrew status` totals (233 stale stubs
  on the SkiFree NE re-onboarding).  Only exact auto-stub content is pruned;
  edited/renamed sources and progressed metadata are never touched.
- **NE import parsing no longer fabricates garbage**: the classic Win16
  import table does not exist in many binaries (MSVC-built NEs like the
  1991 SkiFree place the non-resident name table right after the entry
  table, and Borland binaries differ too) — the old parse read those bytes
  as counts and emitted tens of thousands of fake ordinal imports (holiday:
  WAVEMIX "18443 imports").  `parse_imports` now sanity-gates the count and
  validates by-name offsets, degrading to the module list only (KERNEL/GDI/
  USER on ski16), and `rebrew imports` reports module-level NE records so
  the DLL set stays visible.  Per-API Win16 imports (entry-table entries)
  remain future work.
- `rebrew intake` writes `format = "ne"` for 16-bit NE targets (was `"pe"`,
  cosmetic since `load_binary` auto-detects, but misleading in the config);
  `load_config` accepts `format = "ne"` without the unknown-format fallback
  warning, and `load_binary` reports "Not a 16-bit Windows NE executable"
  for `fmt="ne"` on a non-NE file instead of a generic format error.
- `rebrew verify` short-circuits 16-bit NE targets with a clear notice
  (no compile profile exists yet — ADR-001) instead of running every stub
  through the compile loop into COMPILE_ERROR rows.
- `rebrew data --dispatch` scans MSVC-style NE data segments from offset 0
  (the Borland `[index\x00]` skip is now conditional on the marker being
  present) — VMT/dispatch detection on the 1991 SkiFree was misaligned by
  2 bytes.
- `rebrew rename` accepts zero-padded hex VA identifiers (functions.txt
  writes `0x000100a0`; the strict string match rejected them while every
  other VA-taking tool accepts both forms).
- `rebrew discover-functions` routes 16-bit NE binaries through the native
  NE loader's linear sweep instead of rizin (whose NE output is garbage
  file-offset "functions" — the source of the original SkiFree 233-func
  false enumeration).
- `rebrew doctor` no longer fails 16-bit NE projects: the compiler + include
  checks downgrade to warnings for `x86_16` targets (no compile profile —
  ADR-001), and the toolchain-alignment check warns instead of failing for
  Delphi-family targets (documented-blocker, analysis-only).  Both NE corpus
  targets now report "Project looks healthy!".
- Property-based test for `bytes_to_pat_line` (hypothesis): lead masking,
  CRC-window truncation before the first tail relocation, size field, and
  determinism hold for arbitrary code bytes + reloc offsets.
- **`rebrew.delphi16.compile_ne`** — the ADR-001 16-bit compile foundation:
  a self-contained DOSBox sandbox (compiler trio + `RTM.EXE` + RTL units +
  staged `DCC.CFG`) compiles a `.dpr` headless and parses the resulting NE
  with the native loader.  Hard-won requirements documented: `RTM.EXE`
  (DPMI runtime — DCC silently fails without it) and a non-tmpfs mounted
  drive (DOSBox 0.74-3's shell breaks on tmpfs).  `hello.dpr` →
  `HELLO.EXE` → 15 functions enumerated.
- Property test for inline annotation update/remove symmetry: for arbitrary
  file-owned keys and printable values, `update_annotation_key` followed by
  `remove_annotation_key` restores the source file byte-for-byte.
- `rebrew analyze` `functions.total`/`total_bytes` were 0 for projects
  without a Ghidra export — the dossier now falls back to the project's
  own `functions.txt` via the canonical `parse_function_list`.
- `detect_toolchain` identifies 16-bit NE targets from their segment
  markers (Borland `[index\x00]` → `delphi`, markerless segments → `msvc`
  16-bit) and falls back to the Microsoft Linker version when diec misses
  the compiler record (explorer.exe on Win2K SP4 → "MSVC 5.0 (linker
  5.12.9049)").
- `rebrew verify --fix-sizes`: auto-corrects stale annotation SIZE from the
  binary-derived canonical size for every reported divergence (stale sizes
  cause false SIZE_MISMATCH / truncated byte extraction). `--dry-run`
  previews; JSON gains `sizes_fixed`. Validated on smygb: 3 stale sizes
  corrected (190→331, 235→217, 141→277), re-verify reports zero
  divergences. Extracted to `_apply_size_fixes` + unit-tested (writes,
  dry-run no-op, module fallback).
- Complete the standalone console scripts: every command module with a
  `main_entry()` now gets a `[project.scripts]` entry (43 total), making
  the documented "works both as rebrew-<cmd> and as a flat subcommand"
  pattern true for all 43 commands. Discovered via a clean-venv wheel
  smoke test: `rebrew-discover` / `rebrew-pdb-info` crashed with
  "Could not get a command for this Typer instance" because their
  `main()` lacked `@app.callback(invoke_without_command=True)` (the
  umbrella registration had masked the gap). Decorators added; a docs-
  hygiene test now guards that every scripted module wires a callback or
  subcommands.
- `rebrew prove` now persists a failed proof's Z3 counterexample as a
  metadata NOTE (`prove: Z3 found ... EAX=0 vs 4`) so the concrete
  register difference surfaces in `status`/`todo`/`describe` instead of
  being lost after the terminal output. Never clobbers a reverser's own
  note; timeout/path-explosion messages carry no note.
- `rebrew prove` CLI status-guard tests were **vacuous** — the
  source-first invocation made typer reject the call as "No such
  command", so every test passed regardless of the gate. Rewritten with
  options-first invocation + `chdir` + a real PE fixture: EXACT/STUB
  rejections and the SIZE_MISMATCH acceptance are now genuinely asserted.
- `rebrew prove` now accepts **SIZE_MISMATCH** functions (single + `--all`):
  a compiled size that differs structurally is exactly the "bytes differ
  but semantically equivalent" case the PROVEN status exists for, and the
  proof itself is what makes the promotion sound. Validated on smygb: both
  remaining SIZE_MISMATCH functions proved equivalent and promoted to
  PROVEN — the project now has ZERO SIZE_MISMATCH / ZERO NEAR_MATCHING
  (EXACT 17 / RELOC 26 / PROVEN 9 / STUB 103; coverage 87.1% -> 90.6%).
- `parse_function_list` (functions.txt reader, used by verify/todo/status/
  describe/document-unmatched) crashed with `UnicodeDecodeError` on
  legacy-encoded files — same bug class as the read_source_text fix (50/150
  fuzz inputs). Now reads via the tolerant `read_source_text`; 0/150 crash.
- `rebrew skeleton --append` read the target `.c` with a strict UTF-8 read
  and wrote back UTF-8 — a legacy-encoded source crashed the append and
  would have been re-encoded. Now reads with the tolerant reader and
  writes back in the file's own encoding (round-trip preserved).
- `rebrew.utils.read_source_text`: the CP1252 "universal fallback" was
  wrong — Windows-1252 has undefined bytes (0x81/0x8D/0x8F/0x90/0x9D), so
  reading a legacy-encoded source containing one crashed the core text
  reader (annotation parsing, lint, metadata) with `UnicodeDecodeError`.
  Found by fuzzing the annotation parser: 176/200 non-UTF-8 inputs
  crashed; now decode uses `errors="replace"` (those bytes are
  unrepresentable anyway) and 0/200 crash. Round-trip byte-for-byte
  behavior for all *defined* cp1252/Shift-JIS bytes is unchanged.
- `tools/DELPHI10/pak_extract.py` (Quantum archive decoder): hardened
  against malformed/truncated archives — header and name-table reads are
  now bounds-checked and raise a clean `ValueError` instead of crashing
  with `IndexError`/`struct.error` (fuzz regression: 67/200 header
  mutations crashed before; 0/200 after). Vendored the MIT reference
  archives as fixtures and pinned validity + no-crash contracts in
  `tests/test_pak_extract.py`.
- `rebrew prove`: end-to-end semantic-equivalence tests on synthetic
  x86-32 blobs (angr blob backend, no compiler/binary needed) — pins the
  core verdicts: equivalent implementations prove True (different
  encodings, register tricks, identity), differing constants prove False
  with Z3 finding the EAX difference.
- JSON-purity regression coverage extended to the session-era commands:
  `pdb-info`, `analyze --function`, `similar`, `identify-library --dry-run`,
  `discover-functions`, `binsync-export --dry-run`, `report`,
  `gen-flirt-pat` — every `--json` invocation (success AND error paths)
  must emit exactly one JSON document on stdout.
- `rebrew gen-flirt-pat` / `identify-library --build-sigs` emitted a
  **malformed .pat line for nameless COFF symbols** (empty/public names) —
  the line's trailing name field was empty, so signature parsers rejected
  the whole file as "corrupt" (212 of 262 generated sigs in the smygb
  project were affected). Nameless symbols are now skipped; the smygb sigs
  were regenerated and `rebrew analyze` reports zero corrupt-sig warnings.
- `rebrew pdb-info --help` rendered "into  cflags" — the `[compiler]`
  in the help text was consumed as rich markup and vanished.
- `rebrew intake` option order — `--json` is now declared before
  `--target` (last two options), matching the project's CLI convention.
- `rebrew diff` / `rebrew match` / `rebrew prove` invoked with a VA whose
  resolved source file does not annotate that VA now error
  ("No annotation for VA ... — the resolved file covers different functions")
  instead of silently falling back to the first annotation and diffing the
  wrong function against the requested address.  An explicit `--symbol` is a
  deliberate override and remains allowed.
- Toolchain detection now identifies 16-bit NE Delphi binaries from
  their embedded strings (full-file byte scan, beyond the 256-string cap) —
  holiday.exe (Borland Delphi 1.0, Windows 3.1) is reported `delphi` by
  doctor's alignment check instead of "unknown", matching the hgb case.
- `load_binary` robustness pinned: 7 curated garbage-byte cases +
  a 100-example hypothesis probe confirm arbitrary/truncated binary input
  never crashes — always a clean ValueError/FileNotFoundError or a usable
  BinaryInfo (LIEF's partial-header leniency is asserted usable).
- `docs/CONFIG.md` now documents the environment variables
  (`REBREW_LLM_ENDPOINT`, `REBREW_LLM_API_KEY`, `REBREW_GLOBALS_H`) and
  the config>env>default precedence — the LLM-seeding env vars were
  undocumented.
- Metadata writers are now fully serialised by the module lock —
  `set_field`/`update_field`/`remove_field`/`save_metadata` did unlocked
  read-modify-writes (only `update_source_status` locked), a latent
  lost-update race under concurrent workers. All writers lock now; two
  concurrency tests pin the behavior.
- CI test job now runs `tools/gen_fixtures.py --check` — a fixture-
  generator change without regenerating the checked-in fixtures now fails
  CI instead of passing silently.
- `test_docs_hygiene` command-coverage regex now matches commands
  registered as multi-line tuples — `analyze` + 15 others slipped past the
  "every command documented" check; their `docs/CLI.md` sections added
  (analyze, describe, discover-functions, gen-flirt-pat, identify-library,
  intake, pdb-info, report, strings, xrefs, dashboard).
- `rebrew test <file.c> --va 0xHEX` on a multi-function file now selects the
  annotation AT that VA (symbol + fallback size) — it used to derive the
  symbol from the file's FIRST annotation and silently test the wrong
  function at the requested address (e.g. `_exit_handler@12` instead of
  `_CreateListenSocket`).  Same VA-picks-its-function rule as
  `diff`/`prove`/`near-diag`; an explicit `--va` that matches no annotation
  still falls back to the first annotation as a user override.
- `rebrew near-diag` masks only relocation sites that survive the same
  DIR32/REL32 address validation as `rebrew test`/`rebrew verify` — invalid
  relocs (wrong call target / global address) now surface as real structural
  bytes instead of being hidden behind "RELOC-level". The RELOC verdict's
  suggestion is honest about leftover real bytes: it says
  "NEAR_MATCHING-level, not RELOC" when the canonical status would be
  NEAR_MATCHING (e.g. `_CreateListenSocket` in guild was reported RELOC-100%
  but `rebrew test` classifies it NEAR_MATCHING with 8 real bytes).
- The Annotation-level marker-consistency check (annotation.py `validate`)
  had the same FUNCTION+STUB bug as lint's E015 — a STUB-status function may
  keep its FUNCTION marker; only library-module mismatches warn.  Both checks
  now agree (4 regression tests).
- `params.py` deduplicated: the named-param detection rule is one shared
  `_param_name` helper (minimalism review).
- **E015 lint rule**: the marker-consistency check fired on every
  FUNCTION-marker + STUB-status file (the documented convention — status
  lives in rebrew-function.toml).  It now only fires on library-module
  marker mismatches, its actual intent.  smygb lint went from **144 errors →
  0**.  `tools/corpus_sweep.py` now includes `lint --json` so this class of
  drift is caught project-wide.
- `rebrew init` now emits profile-appropriate `base_cflags` (empty for
  gcc-pe/gcc/clang) — a fresh gcc-pe project no longer compiles with MSVC
  `/nologo /c /MT` flags (which mingw rejects).
- `posix_style` is now threaded through the GA / flag-sweep paths
  (`flag_sweep`, `BinaryMatchingGA`, match's sweep sim) — `rebrew match`
  on gcc-pe profiles emits `-I/-o/-c` instead of `/I//Fo//c`.
- New `ProjectConfig.posix_style` property — single source of truth for
  POSIX-vs-MSVC flag routing (replaces the 6x duplicated predicate).
- Toolchain detection: profile-compat table covers msvc6.3/6.6; codegen-era
  scan slices `.text` instead of the whole file; MSVC version hints
  corrected (13.10=7.1, 14.00=8.0); dead msvcp glob + unused lists removed.
- `rebrew cfg set` routes the remaining target-scoped keys
  (`ghidra_program_path`, `r2_bogus_vas`, `iat_thunks`, ...).
- `msvc7` init preset pointed at `Bin/CL.EXE`; the decomp.me VC7 tarball ships
  `Bin/cl.exe` (lowercase) — the preset now matches.
- `should_promote_status` and the `rebrew status`/`todo` verify-cache overlay
  no longer demote documented STUBs to `MISSING_SIZE` — a blocker-documented
  stub keeps its classification after `rebrew verify`.
- `rebrew diff --dry-run` — preview `--fix-blocker` metadata writes without
  touching `rebrew-function.toml`.
- `rebrew extract batch --dry-run` — preview which `.bin` files would be
  written (JSON: `DRY_RUN` status, plus a `failed` count in the summary).
- `rebrew cfg set` / `add-module` / `set-cflags` gained `--dry-run` with
  future-tense previews (no in-memory mutation).
- `rebrew cfg set-cflags --target` now actually takes effect — per-target
  presets are written under the target's `compiler` sub-table, where the
  loader reads them (previously a silent no-op).
- `recoverage check --json` and `recoverage stats --json` — machine-readable
  verdicts/output.
- Per-module CFLAGS presets (`cflags_presets`) are now consumed as the
  CFLAGS fallback across match/diff/verify/test/prove/near_diag
  (`rebrew.cli.resolve_cflags`).
- `rebrew sync --refresh-cache --json` now actually writes the cache (the
  flag previously made it a silent no-op).
- `rebrew init --install-wibo` writes a working config (wine prefix dropped
  from the command).
- `rebrew data --gen-header` / catalog warn on globals whose VA falls
  outside every PE section.
### Added
- **`rebrew asm --hints` flags the equality-boolean idiom**: `cmp reg,1;
  sbb reg,reg` (+ optional `inc`) is MSVC's `!x`/`x==0` lowering, which
  plain C under MSVC5 compiles to a different epilogue (`neg/sbb/neg/dec` /
  `setcc`) — the hint advises writing it in naked asm (a repeated mismatch
  in the mspaint corpus).
- **GA can now fix wrong constants**: new `mut_tweak_integer_literal`
  mutation operator adjusts numeric literals (field offsets, sizes, magic
  numbers) by small ±deltas, preserving hex/decimal radix.  Previously the
  GA had no way to change a literal — a function whose only defect was an
  off-by-N offset plateaued at its seed score forever (a broken field
  offset stuck at 5000 for 960 evals).  With the operator the same search
  converges to `exact: True`.
- **`rebrew describe` reports the function pattern + calling convention**:
  the dossier gains `pattern` (import thunk / EH-ctor / switch dispatch /
  IAT forwarder — the skip-vs-decompile decision from `rebrew asm --hints`
  at function level) and `convention` (rebrew asm's inference) fields, so a
  single `rebrew describe <va>` call shows the recognizer's verdict plus
  the callers/callees/strings/imports.  JSON contract updated.
- **`rebrew asm --hints` flags esp-relative disp8 in naked asm**: MASM
  folds `lea/cmp/mov [esp+X]` operands into short-form encodings that
  don't match MSVC's `8d 44 24 XX` disp8 forms — the hint warns to force
  the exact bytes with `_emit` (a recurring naked-asm mismatch).
- **`rebrew asm --hints` flags EH-ctor prologs**: a `call` preceded by
  `mov eax, imm32` (the compiler-generated `__eh_ctor` registration
  pattern — 58 functions in the mspaint corpus) is annotated as not
  C-reproducible, so the user skips/documents instead of decompiling.
- **`rebrew asm --hints` flags IAT forwarding stubs**: a call through an
  IAT slot preceded by ≥3 reversed `mov reg,[esp+X]; push reg` pairs is an
  N-arg forwarder to an imported (usually stdcall) function.  The hint
  names the forwarder and the lesson from matching one byte-for-byte: the
  forwarder itself is cdecl (plain `ret`) while the callee cleans — declare
  a `__stdcall` function pointer for the call or MSVC emits a spurious
  `add esp,N`.  (The backward scan is immune to the asm `--hints` lookbehind
  prefix, which previously broke the pattern.)
- **`rebrew skeleton --batch --skip-fragments`**: excludes discovery
  entries whose first bytes match none of the common function-start
  prefixes — data regions and misaligned fragments (a bad function-list
  boundary) that are not decompilable code.  Opt-in because the heuristic
  can misflag an unusual real function; on the mspaint corpus it filters
  the known data entries (e.g. 0x1001794) while leaving real functions
  untouched.  ~10% of discovery entries in that corpus are non-code.
- **`rebrew asm --hints` flags byte-compressed switches**: a two-level
  dispatch (index fetched from a byte table before the indirect jmp —
  MSVC's sparse-switch form) is annotated with a warning that a plain C
  switch often does not reproduce the lowering (the compiler may pick a
  direct table instead) plus the `rebrew switch <va>` decode command — so
  the user knows up front not to chase the structure difference.
- **`rebrew switch --all` — recon pass**: scans every function-list entry
  and reports the ones containing jump-table dispatches (dispatch/case
  counts + the exact decode command per function).  On the mspaint corpus
  it surfaces 28 switch-dispatch functions in one command.  Also fixes a
  `0x0x` double-prefix in the console VA display.
- **`rebrew asm --hints` flags switch dispatches**: an indirect jump-table
  dispatch (`jmp dword ptr [reg*4 + 0x...]`) is now annotated with
  `switch dispatch (jump table) — decode the case table with
  rebrew switch <va>` — the recon hint surfaces where the user already
  looks, and points at the new decoder.
- **`rebrew switch <VA>` — jump-table switch decoder**: locates the
  bounds-checked indirect dispatch (`jmp dword ptr [edx*4 + table]`) in a
  function, reads the dispatch table from the binary, and prints the case
  table (index → handler VA → known function name).  The entry count comes
  from the preceding `cmp reg, N` bounds check when found (any register —
  MSVC copies the index into the scaled register between the cmp and the
  jmp), else from walking the table until a non-image entry (capped at
  256).  This is the "jump-table switch" category of functions that manual
  decompilation has to untangle by hand — the structure is now visible
  before writing any C.  `--json` for machine-readable case tables.
- **`rebrew doctor` Runner advisory**: when the project runs `wine` but a
  wibo binary is already available (PATH or `tools/wibo`), the Runner check
  warns with the exact config switch (`runner = "tools/wibo"` + strip the
  `wine ` prefix) — wibo is a headless PE loader with no X dependency, so
  compiles get faster and fully headless.
- **Headless wine by default**: every `wine` compiler invocation (compile
  and link, both the `rebrew compile` path and the GA flag-sweep path)
  runs against a **persistent `Xvfb` virtual display** — spawned once per
  process and reused across the whole verify/GA batch, with live Xvfb
  servers from earlier runs reused rather than re-spawned.  No more
  virtual-desktop window popping on each compile, and bare wine now works
  under CI with no `DISPLAY`.  The per-invocation `xvfb-run` wrapper costs
  ~3 s per compile, so a persistent server is the difference between a
  4 s cold compile and ~0.5 s (the toolchain round-trip suite halved:
  48 s → 23 s).  Opt out per-run with `REBREW_WINE_HEADLESS=0`;
  falls back to `xvfb-run` then bare wine when no Xvfb binary exists.
  `rebrew doctor` notes the headless setup (or points at wibo) for wine
  runners.

### Changed
- **Breaking (JSON):** `rebrew imports --json` now emits stub VAs as hex
  strings (`{"va": "0x...", "name": ...}` list) and `iat_va` as hex, matching
  every other rebrew JSON (previously stringified decimal dict keys).
- **Breaking (CLI):** `rebrew verify --compare` no longer advances the
  baseline report on a failing (regressed) run, and a failed gate run no
  longer writes the verify cache — the CI gate can no longer self-heal.
- Verify cache now invalidates on annotation SIZE changes (metadata-only
  `catalog --fix-sizes`), external `-I` header edits, and
  `compiler.runner`-only config edits.
- `rebrew verify` PROVEN overlay no longer masks real regressions
  (COMPILE_ERROR / EXTRACT_ERROR / MISSING_FILE surface as failures).
- Bad-VA arguments to `rebrew diff`/`match`/`asm`/`similar` now produce
  accurate errors instead of misleading symbol errors or silent empty output.
- `rebrew sync --dry-run` no longer writes `ghidra_commands.json`.
- `rebrew build-db` never deletes a locked/valid database; schema-less
  debris files auto-rebuild; infrastructure errors exit 2 (EXIT_ERROR).
- Main-command catch-all exits cleanly (no traceback, JSON envelope when
  `--json`) with EXIT_ERROR.
- `rebrew cfg` write commands surface OSError/tomlkit parse errors as clean
  messages.
- `rebrew extract batch` continues past a per-function disassembly error
  instead of aborting the batch.
- `rebrew asm --size` beyond the image warns and reports `truncated`.
- `rebrew flirt --va` bypasses the scan size gate so short functions are
  actually probed.
- CFLAGS resolution unified across tools (per-function → preset →
  `[compiler].cflags` → `/O2 /Gd`).
- `rebrew diff 0x<VA> --watch` lost VA targeting on re-entry (diffed the
  wrong function in multi-function files).
- `rebrew verify` PROVEN overlay masked regressions in proven functions.
- angr's import-time unicorn ERROR leaked to stderr on every `todo`/`doctor`
  run (and prove's status-guard failures).
- `rebrew sync --push --dry-run` wrote the export artifact.
- Coverage DB: failed builds left an empty DB that wedged later builds;
  full rebuilds left orphan `verify_results` rows and a dead v3 index.
- Coverage DB schema gate now verifies query-critical columns, not just
  object names.
- Default `marker` for dotted target names (e.g. `server.dll`) no longer
  produces a marker that matches no annotation module.
- Source filenames starting with `@`/`-` are prefixed `./` before CL.EXE
  (MSVC response-file/option confusion).
- Recovered `cu_map`'s orphaned standalone CLI surface (reachable only via
  `rebrew graph --cu-map`).

### Performance
- **`score_candidate` GA hot loop ~3x faster**: mnemonic extraction now uses
  capstone's `disasm_lite` (tuple-returning, no per-instruction ctypes
  objects) instead of `disasm` — identical output, ~2.7x cheaper disassembly.
  With the explicit-reloc GA path (precomputed target + reloc mask) a 60-insn
  candidate scores in ~47µs instead of ~143µs.
- **`iat_slot_vas` memoized per binary path**: `compile_and_compare` calls
  it once per function even on compile-cache hits, so a full verify/test
  batch re-parsed the same immutable PE N times (0.05–0.3s each).  Now
  scanned once per resolved path (bounded dict + lock, mirroring the
  `load_binary` cache).
- **GA source-digest memoization actually works**: `_source_digest` was
  documented as lru_cached but had no decorator — every flag-sweep combo
  and GA candidate re-ran a full SHA-256 of the source (perf-review F3:
  1-8s per 258k-combo sweep).  The `@lru_cache` the docstring promised is
  now applied; the GA loop's per-candidate re-hash for log lines now reuses
  the same memoized digest.
- **GA fitness memoization fixed**: `BuildResult.fitness` was populated
  after the disk-cache `put()`, so every `cache.get()` returned a fresh
  unpickled object whose fitness was `None` — the warm-scoring fast path
  could never fire, even for elites persisting across generations.  A
  process-local `{src_hash: fitness}` dict now makes it real (no extra disk
  write); a fresh-pickle result with the same hash skips re-scoring.
- **Batch GA flushes solutions once**: `_save_solution` per matched stub
  re-read and rewrote the whole solutions file per match (O(matches × file
  size)); the batch driver now collects `SolutionEntry`s across stubs and
  calls `save_solutions` once, mirroring the batch flag-sweep path.

- GA/flag-sweep hot path: `score_candidate`'s no-reloc fallback now
  disassembles the candidate ONCE (merged normalization + mnemonic
  extraction, `_normalize_and_mnems_x86_32`) and threads the target's
  mnemonics from the same pass — 4 disassemblies per call down to 2
  (~1.14x on reloc-less candidates; byte-identical scores, verified
  against the precomputed hot path).

## [0.1.0] - 2026-08-08

First tagged release.  Rebrew is a compiler-in-the-loop decompilation
workbench: it compiles your C source with MSVC6 (under Wine/wibo), byte-compares
against the target binary, and drives the match loop with a GA engine,
symbolic proving, and a coverage database.

### Added

- **Matching**: `rebrew match` GA engine with flag sweeps (`--flag-sweep-only`,
  tiers quick/targeted/normal/thorough/full), solved-cflag seeding
  (`--seed-from-solved`), batch resume (`--skip-recent`, `--ga-history`,
  `--sweep-then-ga`), and `output/ga_runs` result storage.
- **Proving**: `rebrew prove` symbolic equivalence via angr — EDX/64-bit return
  checking (`--check-edx`), memory side-effect comparison (`--watch-va`), slice
  proving (`--start-offset/--end-offset`), and batch `--all` mode.
- **Round-trip**: `rebrew round-trip` splices every EXACT/RELOC function's
  compiled bytes back into a copy of the target PE and SHA-256 verifies the
  result.  Resolves MSVC `$SG<N>`/`??_C@` string constants by content, decodes
  Ghidra VA-encoded auto-names (`_g_1003546c`), maps `$L<N>`/`$cleanup_loop$<N>`
  jump tables from the .obj layout, and binds string literals that are strict
  prefixes of the target's copy.  Wrong fallbacks surface as
  `catalog_resolution_drift`, never silent corruption.
- **Similarity & triage**: `rebrew similar` (structurally similar functions),
  `rebrew near-diag` (structured diff diagnosis), `rebrew imports` (IAT
  introspection), `rebrew todo` (ROI-ranked action list).
- **Dashboard**: `rebrew dashboard` — read-only web dashboard over the
  coverage database (paired with the `recoverage` project).
- **Agent skills**: `rebrew skills` bundles five workflow skills
  (intake, workflow, matching, data-analysis, ghidra-sync) for AI agents.
- **Verification**: `rebrew verify --compare` detects regressions against the
  last saved report; `rebrew verify -o db/verify_results.json` feeds the
  coverage database (`build-db` imports it into the `verify_results` table).
- **Ghidra sync**: ReVa MCP sync plus a new `ghidra_backend = "cli"` backend;
  pull signatures/structs/datatypes/comments/data, size sync, bookmark sync.
- **Data analysis**: `rebrew data --dispatch`, `--bss`, `--fix-bss`,
  `--gen-header`, and configurable dispatch thresholds.
- **Catalog**: `rebrew catalog --data-json`, `--export-ghidra-labels`,
  `--fix-sizes`, `--csv`, CATALOG.md generation; `rebrew build-db` produces a
  versioned SQLite coverage DB (schema v4) with cell-level per-byte states.
- **Watch mode**: `--watch` on test/verify/diff/match/prove re-runs on source
  change.
- `rebrew doctor` extended with optional-tool (angr/claripy), FLIRT-signature,
  and Ghidra-sync health checks; `rebrew doctor --install-wibo` bootstraps the
  lightweight Wine replacement.
- **Metadata**: volatile per-function fields (STATUS, SIZE, CFLAGS, BLOCKER,
  NOTE, GHIDRA, …) live in `rebrew-function.toml`; per-directory data metadata
  in `rebrew-data.toml`; both under `cfg.metadata_dir`.  `rebrew lint --fix`
  migrates inline leftovers.
- **Property/fuzz tests**: hypothesis-based tests across parsers and the COFF
  .obj extraction helpers; the suite runs 3460 tests / 0 skipped with
  `uv sync --all-extras` (angr included).

### Changed

- **Breaking:** `coverage.db` schema is version `"4"` (normalized,
  range-checked cell rows; `cells` → `sections` foreign key with cascade
  delete).  `rebrew build-db` refuses to write into a version `"3"` database;
  rebuild it with `rebrew build-db --force`.  See `docs/DB_FORMAT.md`.
- **Breaking:** volatile annotation fields migrated out of `.c` headers into
  `rebrew-function.toml`; inline `// STATUS:` / `// SIZE:` are deprecated
  (lint W019) and no longer authoritative.
- angr is installed by the documented dev install (`uv sync --all-extras`);
  `rebrew prove` tests run for real instead of skipping.
- Ghidra MCP failure warnings name the failing endpoint and the fix.
- `rebrew catalog --fix-sizes` and `rebrew data --fix-bss` write metadata to
  `cfg.metadata_dir` (previously the source directory — fixes were silently
  lost).
- `rebrew build-db` emits `paths.sourceRoot` and imports the last
  `verify_results.json`; CATALOG.md coverage is computed from the real .text
  size.

### Fixed

- Round-trip oversize check now requires exact compiled size (a longer compile
  is no longer silently truncated); string search bounded by raw section
  extent.
- Negative section offsets (annotated VAs outside the binary) no longer abort
  the whole `build-db` rebuild (CHECK-constraint violation); grid skips them,
  build-db clamps defensively.
- `remove_annotation_key` no longer reports a write when nothing was removed;
  same-value writes are no-ops.
- 30 mypy errors in `rebrew prove` under real angr types; `SimState` typing,
  `self.addr` narrowing.
- Config load warns when the target binary is missing (image_base
  auto-detection skipped) instead of silently zeroing the layout.
- Ghidra auto-names with 9+ trailing hex digits are no longer mis-decoded as
  VAs.
