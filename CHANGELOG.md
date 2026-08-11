## [Unreleased]

### Added
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
- **doctor toolchain check**: generic `check_toolchain_backed` reports how
  the watcom/msvc1.52 toolchains resolve (vendored binary / pulled image)
  with a `rebrew toolchain pull` fix — no more misleading "not in PATH"
  for vendored compilers.
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

### Fixed
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
