# Rebrew ideas: features the guild-rebrew effort needed but lacked

Sourced from the 100% byte-identical `server.dll` campaign (MSVC6, x86-32).
Each entry: observed pain, proposed feature, evidence pointer in guild-rebrew.
This is a proposal/evidence ledger, not a command manual: example commands and
flags may be unshipped. Status `open` unless noted; observations describe the
campaign at the time recorded. Use [CLI.md](CLI.md) for shipped behavior and
promote scoped proposals to [ROADMAP.md](ROADMAP.md).

## Measure truth, not proxies

- [ ] **Link-residue as first-class metric (`rebrew build residue --json`).**
  Pain: object metrics (`matched`, `aligned`) pointed the wrong way ≥6 times;
  only `scripts/linktest.sh` + `split_link.sh` + `postlink_residual.py` told
  the truth, all out-of-tree. Feature: built-in command that relinks, applies
  postlink, prints per-function linked delta. Evidence: measure-traps §1–2.
- [ ] **Relocation-ceiling report (`rebrew test --show-ceiling`).**
  Pain: `matched` shortfall that is pure accounting (one-sided HIGHLOW,
  per-call REL32) looks like codegen work. Feature: compute ceiling from
  reference HIGHLOW count per window, show `matched / matched-reloc /
  ceiling` side by side; flag windows at ceiling as done. Evidence:
  measure-traps §3 (`cm_ExProdObjekt` 980/980, PCQ 624/624 at ceiling).
- [ ] **Gap-curve view built in (`gaptrace` in-tree).**
  Pain: residue number ≠ error size; only curve shape discriminates cascade
  vs frame-value vs distributed. Feature: promote `scripts/gaptrace.py` to
  `rebrew gaptrace <VA>` with no size argument (derives window itself).
  Evidence: measure-traps §4.
- [ ] **Two-ruler readout (`--ruler probe|test`).**
  Pain: probe reports padded COMDAT span, test reports real body; same object,
  different numbers, endless confusion. Feature: every size/match number
  labelled with its ruler; warn when comparing across rulers. Evidence:
  measure-traps §8.
- [ ] **COMDAT composition band check (`rebrew test --composition`).**
  Pain: wrong "real body must equal reference" rule discarded good candidates
  for rounds; true constraint is padded-COMDAT neutrality (or real-length
  binding when tables follow code). Feature: report real body, padded span,
  table-follows flag, and pass/fail per branch. Evidence: measure-traps §7.

## Allocate and steer

- [ ] **Slot-map probe generator (`rebrew slotmap <VA>`).**
  Pain: slot transpositions are colourer ties; only the sentinel-initial
  probe reads the map, hand-built each time. Feature: auto-generate the
  probe TU, compile, report reference-vs-object slot assignment per local.
  Evidence: codegen-walls §1, allocator Finding 60.
- [ ] **Volatile fixed-point sweep (`rebrew match run --volatile-sweep`).**
  Pain: volatile is per-variable fixed point, per-site wall; manual sweeps
  (1/8/17 sites) cost rounds. Feature: systematic per-variable qualify/
  dequalify sweep with link-residue ranking, respecting composition band.
  Evidence: codegen-walls §3.
- [ ] **Epilogue-merge detector.**
  Pain: reference keeps N epilogues, `/O2` folds to one; 8 spellings tried,
  all inert; recognised late as compiler wall. Feature: detect "N ref rets
  vs 1 obj ret with byte-identical bodies" in diff output, label as wall,
  stop the loop early. Evidence: codegen-walls §2, shapes §74.
- [ ] **Strength-reduction use-site hint.**
  Pain: `add R,R` vs `lea R,[R+R]` follows value uses, not spelling; probed
  blind. Feature: when diff shows add/lea mismatch, point at the value's
  use sites, not the emission site. Evidence: codegen-walls §4.

## Data round support

- [ ] **`rebrew data list` composition awareness.**
  Pain: data edits move `.text` cost unpredictably (AcceptConnections:
  local 0 diffs, gate `.text` +180 via COMDAT literal emission). Feature:
  data verify that also reports `.text` delta of the change, warning when a
  data-only edit churns code. Evidence: goal.md data-round notes (518/520).
- [ ] **Shared-type lift assistant.**
  Pain: manual promotion from `types.h` (Ghidra-pulled) to `rebrew_types.h` /
  `game_structs.h`, duplicate-definition LNK4006 as signal. Feature: flag
  identical layouts across TUs, propose lift target header, detect dupes
  pre-link. Evidence: goal.md types section.
- [ ] **String-to-owner attribution with push verification.**
  Pain: RevEng attribution wrong twice; manual `asm | grep push` confirmation
  each time. Feature: `rebrew binary strings --verify-push`; attribute `"<name>():
  ..."` strings, confirm each by disassembling the owner for the literal
  push, report unverified ones. Evidence: naming_conventions.md attested
  table method.

## Workflow safety

- [ ] **Serialized link-test queue.**
  Pain: agents cannot link-test (measurement serialised); object-metric
  ranking mispredicts; coordinator bottleneck. Feature: `rebrew linktest
  --queue` accepting candidate files, running one at a time, reporting
  deltas. Evidence: workflow-traps §1.
- [ ] **Agent file-ownership guard.**
  Pain: fan-out without ownership check broke two rounds. Feature: `rebrew
  agents --claim <files>` / pre-launch collision check, or at minimum a
  documented protocol in `rebrew-workflow` skill. Evidence: workflow-traps
  §1.
- [ ] **`src/` glob guard for probes.**
  Pain: probe dropped in `src/` compiled via GLOB_RECURSE, moved every
  symbol. Partially fixed (leading-`_` exclusion). Feature: refuse to test
  files matching probe patterns inside `src/`, or keep all probes in
  `.scratch/` by construction. Evidence: workflow-traps §1.
- [ ] **Named-paths commit helper.**
  Pain: `git add -A` swept unmeasured edits once. Feature: `rebrew commit
  --measured` staging only link-tested files. Evidence: workflow-traps §1.

- [ ] **`test`/`verify` must honour the CMake per-file toolchain pin.**
  Pain: `CMakeLists.txt` pins three files to `/REBREW_TOOLCHAIN:msvc-6.0-sp5-pp`
  and the real link applies it (confirmed in `build.make`), but `rebrew test`
  and `rebrew verify` compile those files with the project default (sp6) and
  never read the pin. So every per-function number for a pinned file in
  `rebrew-functions.toml` and in `verify` output describes a compile that does
  not ship: `gm_FindNextFilteredEntity` reads `obj 342`, SIZE_MISMATCH,
  delta 186 under verify, against `obj 346` (the reference's exact size),
  `match` 171/346 when compiled the way the link does. The whole-tree residue
  is unaffected (measured on the shipped bytes), but per-function claims are
  not. Feature: parse the `set_source_files_properties(... COMPILE_OPTIONS
  "/REBREW_TOOLCHAIN:...")` entries, or record the producing toolchain on the
  metadata entry so a stale number is detectable. Evidence: guild-rebrew
  `docs/TODO.md` round 842.

- [ ] **`test`/`verify` must read the CMake per-file flags, not just the metadata.**
  Pain: `CMakeLists.txt` sets per-file options for pinned files
  (`set_source_files_properties(... COMPILE_OPTIONS ...)`) and the real link honours
  them, but `rebrew test`/`verify` compile with the metadata's `cflags` only. For
  `ls_LoadBuildingEntityState` (`0x100128f0`) `build.make` shows
  `/O2 /Gd /Oa /Ow /REBREW_TOOLCHAIN:msvc-6.0-sp5-pp` while the metadata carries **no
  `cflags` field at all**, so every `test`/`verify` figure for that file describes a
  compile the build never performs. Round 842 found the same for the toolchain pin;
  round 877 confirmed it extends to the flags.
  **Worse, "fixing" it by persisting the flags breaks the build.** Running
  `rebrew test <file> --cflags "/O2 /Gd /Oa /Ow"` writes the field into
  `rebrew-functions.toml` (the tool owns that file and does this itself), after which
  `scripts/gate.sh` goes FAIL with **`fatal error C1001: INTERNAL COMPILER ERROR`**
  plus a C1083. The identical flag pair appended to the identical defaults compiles
  fine through the CMake path, so the two paths do not construct the same command
  line and only one works. That is a trap for anyone following the documented rule
  that the metadata is the source of truth for flags.
  Feature: have `test`/`verify` read the CMake per-file options (or refuse and say
  so), and make `--cflags` on a CMake-pinned file a loud error rather than a silent
  metadata write. Evidence: guild-rebrew `docs/measure-traps.md` §6e,
  `docs/TODO.md` rounds 842 / 877.

## Build hygiene

- [ ] **`postlink_residual.py` should refuse a build whose split state is stale
  instead of printing a number.** Pain: `cmake --build` deletes the deliverable
  and leaves `build/split_poc/` from the previous run, so residue reads 58,614
  or 116,814 when the truth is 8,634 -- a 13x error that looks like a
  catastrophic regression and survives a `git checkout` of the sources.
  `split_link.sh` already computes the tell, `exactly at their reference VA: N`,
  and `linktest.sh` already refuses to measure when it is 0, but
  `postlink_residual.py` has no such guard. Feature: have it compare the build
  artifact's mtime against the newest source, and if the artifact is missing or
  older, exit non-zero with "residue not measured" rather than printing a
  number. Evidence: guild-rebrew round 889, `docs/measure-traps.md` section 9.
- [ ] **`gate.sh` should print the split-alignment count next to the residue.**
  Pain: the residue line and the composition-collapse signal are produced by
  different tools, so a collapsed run reads as a normal regression line.
  Evidence: guild-rebrew round 889 -- the false readings above were only
  diagnosed after `linktest.sh` printed the collapse warning.

## Data

- [ ] **`lint --fix` W016 writes `section` but not `name`, so `verify --data`
  then reports the marker as unattributed.**
  Pain: a `DATA:` marker gains `section = ".data"` in `src/rebrew-data.toml`
  and stays `unknown` forever after. `scan_globals` needs `name` (or `type`)
  to attribute a marker -- the next source line is a *definition*, which
  tree-sitter returns only when it parses as a declaration-with-initialiser,
  so `char s_x[] = "..."` under the marker is not always picked up. The
  resulting warning reads like a source defect ("has no declaration on the
  following line") and sends the reader to the wrong file. Feature: W016's
  `--fix` should write `name`/`type`/`size` from the binary's data-symbol map
  the way `import-splat`'s `_write_data` does (`splat_config.py`), or the
  warning should name the missing *metadata* field explicitly.
  Evidence: guild-rebrew `src/rebrew-data.toml` `0x1002944c` / `0x100294a4`
  (section only, from TODO round 559), `docs/measure-traps.md` §9, round 882.

- [x] **`todo`'s `start-data` lane should exclude link-produced data.**
  Pain: a fresh project opens with the lane dominated by `__imp__*` IAT
  slots, which are linker output and can never be attributed to a source
  symbol no matter how much naming is done, so the lane can never empty and
  its size stops meaning "data work remaining". Feature: tag metadata
  entries whose VA falls in a linker-owned section (`.idata`) as
  `status = "SYNTHETIC"` (written by `verify --data`), and have
  `_collect_start_data` skip them. Evidence: guild-rebrew `rebrew todo` --
  224 of 226 remaining items are `start-data`, 18 of them `__imp__*`;
  IAT bytes confirmed identical to the reference at
  `0x10024000..0x10024044`; `docs/measure-traps.md` section 9, round 883.
  Applied (round 1078): `_collect_start_data` skips `__imp_` names,
  `section = ".idata"`, `section = ".bss"`, and any symbol whose extent runs
  past its section's `raw_size`. The lane went from 123 items to 0 on
  guild-rebrew, leaving only its 2 real `.text` carriers. Measured there:
  207 UNCHECKED entries, all 207 un-clearable, and all 207 independently
  confirmed already byte-correct (5 with file bytes identical, 111 in the
  zero-fill tail, 84 import slots, 7 sizeless).

- [x] **`verify --data` reports a pass over a subset and does not say so.**
  Pain: `rebrew verify --data` printed "data: 122 matched, 0 mismatched,
  0 missing" while the metadata held 329 symbols -- it had compared 122, or
  37%, and reported no coverage figure, so the summary read as "all data
  verified". Everything it cannot compare is invisible by design:
  `section_symbol_bytes` skips any symbol running past its section's
  `raw_size` (the zero-fill tail, no file bytes) and any symbol outside
  `.data`/`.rdata`. Those VAs never enter `ref_sizes`, so they can never be
  written back as VERIFIED, and they are exactly the entries that pile up in
  the `start-data` lane. Feature: report the denominator -- "122 of 329
  symbols compared (207 not comparable: N in the zero-fill tail, M outside
  .data/.rdata)" -- and either mark non-comparable entries with a distinct
  terminal status (`SYNTHETIC` / `NO_FILE_BYTES`) or list them as such, so
  the lane and the summary agree. Evidence: guild-rebrew round 1078 --
  `verify --data --json`'s `data` block carries `matched`/`mismatched`/
  `missing` but no total and no per-symbol list; `ref_sizes` was measured at
  exactly 122 across both images.
  Applied (round 1079, commit `3f7cefea`): the report now carries `total`,
  `compared`, `not_comparable` and `coverage`; the human summary prints
  "(122 of 329 symbols compared, 37%)" plus a line naming why the rest are
  not comparable, and `--json` passes all four fields through.

- [ ] **`function_extent_from_disasm` stops at the first `jmp`, so it cannot
  bound a function that branches internally.**
  Pain: the walk is conservative by design -- it stops at `ret`/`jmp`/`int3` --
  and that is correct for a thunk, but a large `switch`-heavy function ends on
  an inner `jmp` long before its real epilogue. On guild-rebrew,
  `CrashDumpUnhandledExceptionFilter` (`0x10002770`) is 2115 bytes and returns
  with `ret 4` at `0x10002e99`, but the walk stops at `0x10002a56` -- 742 bytes
  in, 35% of the function -- so callers that prefer the walk over the declared
  size (added in round 1084 to stop the dump swallowing `0x09` padding) cannot
  use it here and still over-report 724 instructions against the real 673.
  Feature: when the walk ends on `jmp`, follow the branch target and continue,
  or fall back to "keep walking until a `ret` in the same basic-block region",
  and return the extent with a distinct kind (`jmp-tail` vs `jmp-inner`) so
  callers can decide. A cheaper option: report both bounds and let the caller
  choose the smaller *credible* one.
  Evidence: guild-rebrew `docs/measure-traps.md` section 52, round 1084.
  **Attempted and reverted (round 1085).** A worklist walk that follows a
  forward `jmp` target and keeps going fixes this carrier (742 -> 1836) but
  breaks the contract the other five callers depend on, in three ways measured
  with the suite: a thunk that legitimately IS a tail jump is now followed out
  of the function (10 -> 3988), an unterminated buffer returns 4 instead of
  `None` because "walked some bytes" was conflated with "found an end", and the
  MIPS/16-bit walkers inherit both. It also overshoots this very function: the
  real epilogue is `ret 4` at `0x10002e99` (extent 1835) and the walk reported
  1836, having decoded a jump table as code. The distinguishing signal a fix
  needs is "is this `jmp` a tail call or an intra-function branch", which is
  exactly what the current conservative walk refuses to guess at -- and the six
  callers were written against that refusal. Fixing it means auditing all six
  and deciding the answer per caller, not changing the shared walker.

## Knowledge capture

- [ ] **Jev as a typed decision layer over `todo` / `near-diag` (out of tree).**
  Pain: agents pick the wrong next tool, reread 167 MSVC6 shapes, and spend
  codegen-LLM budget on library leftovers, stale blockers, and inverted
  briefs. Feature: a guild-rebrew script that sends `todo --json` +
  `near-diag --json` + blocker prose to TypeSafe Jev (Choice / Score /
  Noul) and confidence-gates the next command; no C generation, no
  rebrew package change. Keep only if it beats `todo` on a labeled
  NEAR_MATCHING slice. Evidence: [JEV.md](JEV.md); workflow-traps §1
  (inverted `volatile` brief); shapes / allocator catalogs.
- [ ] **Finding router (`rebrew note --finding`).**
  Pain: one finding, one home (shapes / allocator / codegen-walls /
  measure-traps / workflow-traps / TODO) enforced by discipline only.
  Feature: prompt for category on note capture, append with call-site and
  delta template, lint for missing evidence fields. Evidence: goal.md
  codegen section.

- **Build-tree integrity check belongs in rebrew, not in every consumer.**
  Pain: `build/` is gitignored, so a hand-edited `build.make` (or `flags.make`)
  is invisible to `git status`, to `rebrew lint`, to `rebrew verify --full`, and
  to `cmake --build`, while silently redefining what any consumer's measurement
  means. `rebrew build postlink` and `rebrew build cmake-flags` both read that tree. A round
  sweeping per-file toolchain pins hit this and left a tree reporting 58% residue
  with a 290,816-byte deliverable against the correct 286,720 / 8628.
  Feature: `rebrew build check` (and a `rebrew doctor` clause) comparing
  `build.make`'s compile lines against CMake's own `flags.make` records;
  shipped as `src/rebrew/build_check.py`.
  Evidence: guild-rebrew `docs/workflow-traps.md` §20.

- **Post-link failure messages should report the measurement, not one hypothesis.**
  Pain: `postlink._fix_imports` refused a build with "built .rdata prefix size
  does not match the reference; check the debug directory: builds with /debug
  carry an extra 0x1c-byte directory". The real discrepancy was +64 bytes with
  `DataDirectory[6] == 0` in both images. The message cost a wrong lead on a
  check every composition round hits.
  Feature: state *measured* vs *expected*, and give the test that separates the
  candidate causes (`== 0x1c` means /debug; anything else means the section
  length itself). Applied: see the diff to `src/rebrew/postlink.py`.
  Evidence: guild-rebrew `docs/workflow-traps.md` §21.

- **`rebrew verify`'s denominator should not be the annotation count alone.**
  Pain: `function_structure.json` (the discoverer's partition) is coarser than the
  annotations (543 entries against 283 annotated functions) and its entry sizes
  are gaps to the *next inventory entry*. Reading a size divergence as "missing
  functions" produced a four-round false lead in guild-rebrew, including a
  proposed tool fix for a defect that does not exist.
  Feature: have `verify` report the annotation count beside the inventory count,
  and label a size divergence as an inventory-coarseness fact rather than a
  coverage gap.
  Evidence: guild-rebrew `docs/workflow-traps.md` §17.

- **Data verdict write acknowledgment (shipped).**
  Current behavior: `verify --data` reports comparisons but suppresses stored
  verdict/evidence writes unless `--raw-link` or configured `raw_link` acknowledges
  the image. See [CLI.md](CLI.md#rebrew-verify). Original observation:
  Pain: running `rebrew verify --data --built build/split_poc.dll` (the raw link) to escape the
  "tautological" warning flipped 30 symbols' `status` from `VERIFIED` to `DRIFT` in the tool-owned
  `rebrew-data.toml`. The raw link's `.data` divergence is postlink-supplied (AMBIGUOUS-by-design), so the
  statuses it wrote were wrong and persistent; recovery needed `git checkout` plus a deliverable re-run.
  Feature: detect a raw-link artifact (e.g. `.data` differing above a threshold it can already measure, or
  an explicit `--raw-link` ack write-gate) and suppress both the status write-back and the DRIFT flips:
  report `mismatched` only.
  Evidence: guild-rebrew `docs/measure-traps.md` §56, round 1102.

- **`rebrew prove` should stub import thunks instead of failing with "No terminal states reached".**
  Pain: any function that calls an import thunk (GetTickCount, Sleep and friends via
  `call dword ptr [0x10024xxxx]`) cannot reach a terminal state in angr, because the thunk slot has
  no resolvable target in the loaded image. Measured in guild-rebrew on `ServerMainThread`
  (0x100093a0, 2434 B, 55 calls, 9 indirect): full function and every slice return "No terminal
  states reached" at timeouts 60/600/900 and loop-bounds 1/2, while the call-free control
  0x1001bdd0 proves in seconds and a 162-byte single-call function fails the same way despite
  being 15x smaller. The blocker is the harness, not the C.
  Feature: seed each import-thunk address with an unconstrained stub (return-symbolic or
  skip-and-continue) so calls through `[0x10024xxx]` do not dead-end the CFG; expose a
  `--stub-thunks` flag so runs that need real semantics can opt out.
  Evidence: guild-rebrew `src/server.dll/DieGildeAddOnServer/server_c/ServerMainThread.c` header,
  "PROVEN is NOT reachable for this function" block (rounds 6-9 probes).

- **`rebrew orphans prune` deletes metadata for block-comment `/* DATA: SERVER 0x... */` markers.**
  Pain: pruned 260 lines from `rebrew-data.toml` + 3 GOLDTL function entries, orphaning live source
  DATA markers (vfs4.c `0x1002944c..0x100294a0` range form, vfs_OpenStream.c `0x100294a4`) and
  tripping W016 ("DATA marker missing // SECTION") + W022. The orphan detector appears to match only
  the `// DATA:` line form, so a `/* DATA: ... */` block marker does not register as a live
  annotation and its metadata looks orphaned. Measured in guild-rebrew round 1282 (had to
  `git checkout` both TOMLs to recover).
  Feature: parse `/* DATA: ... */` and range `0x..0x` markers as live annotations before pruning;
  report (not delete) any entry whose marker form the detector did not recognize.
  Evidence: guild-rebrew `src/Develop/Units/vfs/vfs4.c` line 17 range marker.

- **`rebrew data list` needs a `--set-size` (data extent correction).**
  Pain: a stale `size` on a data symbol cannot be corrected by any CLI; `--set-type` writes only
  `type` (and preserves existing `size`), `annotation.py` only ever grows size, and `--fix-bss`
  writes sizes only for new gaps. When a range marker overstates an extent (`0x1002944c..0x100294a0`
  = 84 parsed onto a 4-byte `char s_rb[4]`), the extent gate fails and the only fix is calling
  `rebrew.data_metadata.set_data_field(dir, va, "size", n, module)` by hand.
  Feature: `rebrew data set --size 0xVA=N` (mirror `--set-type`) so extent corrections go through
  the sanctioned atomic writer.
  Evidence: guild-rebrew `src/rebrew-data.toml` s_rb_1002944c size 84 vs binary 4 (round 1282).

## Optimization level

- [ ] **Byte heuristics for opt flags other than MSVC `/O1` and `/O2`.**
  Pain: `detect_toolchain` seeds project `cflags` from wrapper-call counts, and that vote only
  separates `/O1` from `/O2` (three sites, two-to-one, else `mixed` or empty). `/Od`, `/Os`,
  `/Ot`, `/Og`, and `/Ox` stay on the flag sweep, and so do GCC/Clang/MinGW `-O`, Watcom
  `-od`/`-os`/`-ot`/`-ox`, Borland `-O`, and IDO `-O`.
  Feature: extend the codegen corpus (`docs/codegen/`, today `/O1` and `/O2` for MSVC) with the
  missing flag rows, then add a detector only for a pattern the matrix actually separates. No
  signature database covers this: Detect It Easy, RetDec, capa, IDA FLIRT, and Ghidra's Rich
  header name the compiler, not the flag. GCC/Clang classifiers (o-glassesX, Pizzolotto) emit a
  coarse `-O` class and are not an MSVC `cflags` source. When the record exists, read the command
  line instead: PDB `LF_BUILDINFO` argument 4, or GCC/Clang `.GCC.command.line` /
  `DW_AT_producer`. `S_COMPILE3` has no `/O` bits, and a VC 6 PDB was not shown to carry
  `LF_BUILDINFO`.
  Hold these until a compile shows them: do not score `/Ox` as `/O2` (`/Ox` is `/Ob2 /Oi /Ot /Oy`
  and drops `/GF` and `/Gy`); `/Os` and `/Ot` alone leave codegen debug-like; a missing GCC frame
  pointer means "not `-O0`" and does not separate `-O1`/`-O2`/`-O3`; a missing Watcom stack check
  means `-s` or `-ox`, not `-os` versus `-ot`; ReC98's Borland rules apply only once the compiler
  is Turbo C++ 4.0J; an IDO loop that did not unroll is not a lower `-O`. The verdict stays per
  function, and two styles clearing the bar stays `mixed`.
  Evidence: the guild-rebrew "Compiler opt level heuristics" report (not in this repo).

## Calling-convention evidence

- [ ] **Infer caller-cleaned stack arguments before generating skeleton signatures.**
  Pain: correcting local ECX definition tracking identifies server `m_pool_free`
  as cdecl, but a cdecl skeleton still defaults to `int f(void)` despite two
  observed arguments. A plain `ret` does not establish zero stack arguments.
  Feature: track ESP bias through saves and local allocation, report supported
  incoming stack slots, and corroborate arity with caller pushes/cleanup. Keep
  unknown counts and types explicit; do not manufacture a `self` parameter.
  Evidence: guild-rebrew `docs/msvc6-c-shapes.md` section 257, callee
  `0x10006e30` and callers `0x10008e2a` / `0x10009220` with `add esp,8`.

## Relocation evidence in shared-client checks

- [ ] **Expose unresolved relocation targets separately from validated RELOC slots.**
  Pain: the shared GOLD/TL `fcn_00401180` source calls the numeric GOLD symbol
  `fcn_00430bd0`; TL's original helper calls `vfs_ReadData` at `0x004306b0`.
  Both ordinary checks report RELOC because an uncatalogued REL32 target is
  deliberately masked in `coff_reloc._validate_rel32`. Those checks establish
  instruction agreement but do not establish the destination callee binding.
  Feature: report masked-unresolved and validated counts separately, with an
  optional strict catalog/linked-address check for shared-source promotion.
  Evidence: guild-rebrew `src/GOLD.fcn_00401180.c`, original helpers at
  `0x00401180`, `.scratch/goal-client-loop/test-gold-helper.json`,
  `.scratch/goal-client-loop/test-tl-return-in-loop.json`, and the target-scoped
  TL annotation in `src/Develop/Units/vfs/GOLDTL.vfs_ReadData.c`.


## References inside mixed-target translation units

- [ ] **Bind rename references to their annotated function/data owner inside a shared file.**
  Pain: target-aware rename can isolate independent same-name target functions,
  but a file containing both targets may place an unrelated reference in a
  common prototype, table initializer, or a different target's function body.
  Whole-file text replacement cannot decide which binding is meant. It now
  fails before writing rather than renaming both symbols.
  Feature: use C AST reference spans and target-scoped function/data identities,
  with explicit treatment of common declarations; keep unresolved references
  visible instead of inferring ownership from a filename or proximity.
  Evidence: guild-rebrew TL `0x00406510` rename dry run names `command7.c` and
  `alchemistry_logic3.c`; `.scratch/goal-rename/project-builder-preview.json`.
  `tests/test_rename.py::TestRenameTargetIsolation` covers the safe boundary.


## Skeleton append should offer reference-VA insertion

Pain: todo recommends `skeleton <VA> --append <neighbor.c>`, which appends a
lower-VA function after its higher-VA neighbor. W030 then reports that source
order disagrees with reference linker order. Literal append works as named;
the missing feature is ordered insertion with declarations left above both
functions. Proposed `--insert-by-va` (or a todo recommendation that requests
it), respecting each target's shared marker order and rejecting conflicting
multi-target order. Evidence: guild `.scratch/goal-character/lint-final.json`,
three W030 hits for TL 0x40df00, 0x40e110 and 0x405540. Source definitions are
reordered directly as ordinary source-tree repair; no warning is suppressed.


## Retire an erroneously reversed game body after a stock-library match

Pain: library identify deliberately never touches annotated functions; a later
whole-body archive hit therefore leaves an erroneous Game C implementation
and its failed verification history in the tree. Correcting classification
requires a manual source/header move, with separate accounting checks.
Proposed library adopt/retire command: accept an exact archive-match receipt,
preview incoming references and source/header changes, retain provenance and
failed prior measurements as history, retire the local body and annotate library
origin through locked writers. Do not infer a prebuilt build provider from an
archive hit alone, manufacture EXACT, or patch the archive.
Evidence: guild-rebrew GOLD0x5e3d3d, stock ___sbh_find_block in sbheap.obj;
.scratch/goal-crt-retirement/retirement.json and
.scratch/goal-shared-sound/gold-crt-recheck.json.

## Explicit related-import donor for evidenced structural twins (2026-10-04)

Pain: source import-related can restrict a destination (--va) but cannot name an
evidenced donor. TL mouse4117c0 and keyboard4117f0 share the same42-byte structural
shape. Native GUID/CreateDevice output proof identifies Gold410710 and410740, but
default gap refuses both and gap0 chooses the same source for both. Lowering a
threshold cannot communicate the proven identity.
Proposal: --source-va filters the EXACT/RELOC donor set before ordinary score/gap
matching and verification; invalid/unmatched donor addresses must be errors. Keep
thresholds, library exclusion, preview, and verification unchanged.
Evidence: guild-rebrew .scratch/goal-input-types/ambiguous-donors.json, bindings.json;
.scratch/goal-forward-ret/input-guid-cross-build.json and gold-input-init-asm.json.

### Consolidate an already-matched related destination

Pain: import-related --shared only considers unmatched destination functions. Native-proven TL420b70/Gold4247e0 reset has duplicate existing implementations; Gold EXACT37 is excluded before source-va matching, so normal import refuses with no unmatched functions. Proposed feature: explicit --consolidate-matched, preview both source owners and native binding proof, verify the shared replacement in both targets, and retire the superseded file atomically while preserving managed VA metadata/history. Existing unmatched import default should remain conservative. Evidence: guild-rebrew/.scratch/goal-net-stats/import-dryrun.json, native-bindings.json, before-GOLD.fcn_004247e0.c.

### Report native comparison scope in library-match output

Pain: library match --va chooses managed SIZE or a32-byte prefix, not the existing native inventory span. Un-sized LIBRARY markers for TL66080a/Gold5eaad6 therefore produce both strlwr/strupr candidates, while complete native308/158-byte comparisons uniquely identify strupr.obj (strlwr has7/4 fixed mismatches). Current JSON does not expose compared byte count or prefix-vs-complete provenance. Proposed --size and explicit compared_bytes/comparison_scope fields, with previewed inventory-size fallback. Keep prefix hits visibly provisional; report whole-body only after proving the extent. Evidence guild-rebrew/.scratch/goal-vfs-casefold/full-runtime-attribution.json and .scratch/goal-net-stats/next-helper*-library.json.

### 2026-10-04 — Native bindings for declaration-only game callees across targets

Pain: shared TL442c00/442cb0 and Gold4471b0/447260 callers refer to fcn_00450a00, but its body exists only for TL450a00. Gold calls a different native body at453890. FUNCTION parsing deliberately skips prototypes; the declaration alone cannot supply a target-scoped function binding. Unknown REL32 fallback can therefore mask a wrong or unmapped legacy callee name (TL40ec60 currently names Gold453890 while actually calling TL450a00). Adding a fake DATA owner or an empty C definition would misrepresent the tree. Proposed feature: a declaration-only native function binding, stored target-scoped through a supported CLI/API and attached to a canonical prototype, resolved for call validation/link planning without adding a reversed-function body or storage owner. Preview collisions and preserve distinction between build-specific bodies, DLL imports, and data. Evidence: guild-rebrew/.scratch/goal-client-call-api/jobs.json and helper-import-preview.json; .scratch/goal-small-extents/next-tl-40ec60-native.json; src/GOLDTL.fcn_00450a00.c and shared442c00/442cb0 callers. Independently bind native call operands until available; do not claim an unchanged Gold helper import.

### Batch function-extent reconciliation from native boundaries and padding

Pain: TL full gate57178 reports322 shorter SIZE_MISMATCH bodies with zero common-prefix differences;309 have native terminal ret/tailjmp and exclusively NOP tails. These discovery/alignment sizes make already recovered bodies appear unfinished. Existing `test --fix-sizes`, `verify --fix-sizes`, and catalog backfill address size repair; they do not provide the joint strict CFG, complete relocation/literal binding, negative-control, library-exclusion evidence preview described here. Proposed CLI preview/apply operation combining conservative native CFG/end evidence, retained padding/layout accounting, complete object/native binding validation, library exclusion, and target-scoped locked SIZE updates; never shorten solely from object length or a masked prefix score. Surface ambiguous branches/data separately and verify every affected/shared build. Evidence guild-rebrew/.scratch/goal-small-client-helpers/{zero-diff-candidates,native-extent-screen}.json. Current supported metadata APIs can apply individually evidenced repairs; no game-code padding or raw assembly workaround.


## Metadata-backed source split / extraction after marker migration

Landed: `rebrew source split` reads the function row when the file has no marker block. It slices that C definition, leaves file-scope storage in the original, refuses a static or preprocessor-wrapped dependency, and retargets every row that shares the definition. `--dry-run` writes nothing, and a failed retarget restores the source.

Observed 2026-10-04: `rebrew source split src/Develop/DieGildeAddOn/game/spiel622.c --va 0x1001a0d0 --dry-run --target server.dll --json` reported `No function block found` although the managed SERVER identity resolved to the existing gm_RandomMod definition. The CLI at that point only extracted inline marker blocks.

The landed path resolves the selected module and VA through the function store, identifies the C definition, and retargets every row that shares it. File-scope storage stays in the original. A static dependency or a definition inside a preprocessor conditional is refused. `--dry-run` writes nothing, and a failed retarget restores the source. The command does not write a marker line.

Evidence: guild-rebrew/.scratch/goal-random-helper/{split-server-preview.json,split-server-preview.log}. The marker path remains for unmigrated sources.

### Preserve library ancestry when marker inventories overlap C-source identities

A migrated library inventory and an existing FUNCTION C body can share a
(module, VA). Header and source migration currently overwrite the single
marker_type/name identity in order-dependent ways: two Gold runtime wrappers
(5deaf3,5e3a71) remained compiled but disappeared from library accounting and
acquired header hint display names. Preserve library ancestry separately from
the provider decision, keep the actual C provider symbol/name, and normalize
compiled-library paths to the established project-root contract. Exercise
both migration orders, minimal config roots, existing explicit bindings,
and migrated catalog/verification views; dry runs and repeated runs must not
change identities. Do not infer archive ownership from names or repair it by
reversing CRT code. Evidence: guild-rebrew/.scratch/goal-migration-revalidation/
full-native-rejected-comparison.json and after-native-all.json (15645 CLOSED2;
48 intended Gold byte gains remain unaccepted until classification is repaired).

### Lint explicit compiled-library paths after marker migration

Pain: library source bindings are project-root relative, but markerless lint checks only metadata-root-relative paths. Gold src/GOLD.fcn_005deaf3.c and src/GOLD.fcn_005e3a71.c resolve as actual compiled providers yet each receives E001 in every target after ancestry recovery. Proposed fix: let the shared metadata-backed-file predicate resolve explicit LIBRARY bindings against cfg.root with exact paths, without blessing unrelated files or changing ordinary function/data path rules. Evidence: guild-rebrew/.scratch/goal-migration-revalidation/lint-ancestry-all.json and gold-library-actual-provider-check.json.

### Scope migrated compiled-library bodies in CMake source selection

Pain: project-root LIBRARY bindings are discovered by verification/lint but parse_c_file_multi's metadata-relative lookup cannot see them. cmake-sources classifies the pure-C body as unannotated and includes it in every target. After Gold ancestry recovery, server wrongly selected GOLD.fcn_005deaf3.c and GOLD.fcn_005e3a71.c; the raw link fails on foreign _fcn_005e899f. Proposed fix: incorporate actual bound-library file identities for every module before the unannotated fallback, using the public library-source binder and exact resolved paths; retain ordinary helpers and per-target/shared ownership. Evidence guild-rebrew/.scratch/goal-random-helper/server-link/build.log and regenerated build/rebrew-sources-server.cmake. No source filtering workaround or library patch.


### Keep verified inline jump tables out of instruction-only diff summaries

Pain: GOLDTL0x004c3a50 has a348-byte code region plus103 four-byte inline
jump-table entries (760-byte recorded extent). `rebrew diff --json` reports
207 structural instructions after decoding pointer data as x86 code, although
the typed byte comparison isolates eight differing code bytes: independent
MOV/LEA setup instructions emitted in reverse order. Every native table
target agrees with the candidate COFF label value plus addend and function
base; the dispatch operand names the same table. This differs from the older
function-end walker proposal: the extent is already correct.

Proposed feature: expose proven code/table ranges and classify inline pointer
entries as typed relocations in structured diff output. Require COFF symbol,
relocation, dispatch, and bounded entry evidence; preserve comparison of the
entire recorded extent and every table target. Do not remove table bytes or
mask unknown storage to lower structural scores.

Evidence: guild-rebrew/.scratch/goal-tl-training/4c3a50-diff.json,
command-table-audit.log, command-table-differences.json (zero differing
table targets), and probe-command.json (eight code-byte differences in the
baseline). No upstream implementation change or verdict promotion.


## Strict mapped DIR32 proof alongside tolerant source agreement (2026-10-04)

Pain: the current catalog-limited DIR32 contract masks a mapped-symbol mismatch when the derived native address is absent from the catalog. This can give a RELOC result to a cross-imported body with the wrong table and array bound. Gold 0x004d0a30 compiled from the TL 768-record scan: fixed bytes and all six relocation spans aligned, but native Gold scans 32 records at 0x00930600, while the selected slot-table binding is 0x00770b80. Its two table operands implied different bases (0x00930600 and 0x008cf580) under the incorrect 768-record addend. Neither implied base was catalogued, so the wrong body passed.

Proposed feature: an explicit strict operand-proof mode, distinct from the current tolerant agreement contract, that requires every supplied mapped DIR32 identity to satisfy native_word == bound_va + COFF_addend, even when the competing native address is not catalogued. Report unbound references separately so a fully bound proof cannot silently claim them. Preserve explicit IAT policy and compiler-local jump-table resolution; compare complete code/table extents. Include a regression where the wrong actual address is deliberately absent from the catalog, a wrong array-end addend, and positive compiler-local/IAT controls. Do not silently change the documented tolerant contract without reviewing existing callers and fixtures.

Evidence: guild-rebrew/.scratch/goal-tl-callee-identities/{resolver-binding-conflicts-before,Gold-list-audit,Gold-list-applied}.json. The game repair uses its genuine target-specific C body (32 records, correct array), binds all six operands independently, and rejects every wrong-plus-four control with a correct-native-address sentinel. This is source/data proof and does not establish whole-file equality.
